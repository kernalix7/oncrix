// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Real-time scheduler (SCHED_FIFO and SCHED_RR).
//!
//! Implements POSIX real-time scheduling policies modelled after
//! Linux `kernel/sched/rt.c`:
//!
//! - **SCHED_FIFO**: First-in, first-out — runs until it yields,
//!   blocks, or is preempted by a higher-priority RT task.
//! - **SCHED_RR**: Round-robin with a configurable quantum — tasks
//!   at the same priority rotate after exhausting their timeslice.
//!
//! # Priority Model
//!
//! RT priorities 0-99, where 99 is the highest. Each priority level
//! has its own FIFO queue. A 100-bit bitmap tracks non-empty levels
//! for O(1) lookup of the highest-priority runnable task.
//!
//! # Bandwidth Throttling
//!
//! Prevents RT tasks from starving normal tasks. A runtime/period
//! pair caps RT CPU utilisation per run queue.

use oncrix_lib::{Error, Result};

// ======================================================================
// Constants
// ======================================================================

/// Number of RT priority levels (0..99).
const MAX_RT_PRIO: usize = 100;

/// Maximum tasks per priority level.
const MAX_TASKS_PER_PRIO: usize = 32;

/// Maximum CPUs.
const MAX_CPUS: usize = 64;

/// Default RR time quantum in nanoseconds (100 ms).
const _DEFAULT_RR_TIMESLICE_NS: u64 = 100_000_000;

/// Default RT bandwidth: 950 ms runtime per 1000 ms period.
const _DEFAULT_RT_RUNTIME_US: u64 = 950_000;

/// Default RT bandwidth period in microseconds.
const _DEFAULT_RT_PERIOD_US: u64 = 1_000_000;

// ======================================================================
// Types
// ======================================================================

/// RT scheduling policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RtPolicy {
    /// First-in, first-out (no time slicing within priority).
    SchedFifo,
    /// Round-robin (time-sliced within priority).
    SchedRr,
}

/// State of an RT task.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RtTaskState {
    /// Runnable (in the run queue).
    Runnable,
    /// Currently executing on a CPU.
    Running,
    /// Blocked (waiting for resource).
    Blocked,
    /// Stopped.
    Stopped,
}

/// An RT scheduling entity.
#[derive(Clone, Copy)]
pub struct RtTask {
    /// Task PID.
    pub pid: u64,
    /// RT priority (0-99).
    pub priority: u8,
    /// Scheduling policy.
    pub policy: RtPolicy,
    /// Task state.
    pub state: RtTaskState,
    /// Time quantum for SCHED_RR in nanoseconds.
    pub time_quantum_ns: u64,
    /// Remaining time in current quantum (SCHED_RR).
    pub remaining_ns: u64,
    /// Total execution time in nanoseconds.
    pub sum_exec_runtime: u64,
    /// Whether this slot is occupied.
    pub active: bool,
}

impl RtTask {
    /// Creates an inactive RT task slot.
    pub const fn new() -> Self {
        Self {
            pid: 0,
            priority: 0,
            policy: RtPolicy::SchedFifo,
            state: RtTaskState::Stopped,
            time_quantum_ns: _DEFAULT_RR_TIMESLICE_NS,
            remaining_ns: _DEFAULT_RR_TIMESLICE_NS,
            sum_exec_runtime: 0,
            active: false,
        }
    }
}

/// FIFO queue for a single priority level.
pub struct RtPrioQueue {
    /// Task indices into the per-CPU task array.
    entries: [u16; MAX_TASKS_PER_PRIO],
    /// Number of entries.
    count: usize,
}

impl RtPrioQueue {
    /// Creates an empty priority queue.
    pub const fn new() -> Self {
        Self {
            entries: [0u16; MAX_TASKS_PER_PRIO],
            count: 0,
        }
    }

    /// Pushes a task index to the back of the queue.
    pub fn push_back(&mut self, idx: u16) -> Result<()> {
        if self.count >= MAX_TASKS_PER_PRIO {
            return Err(Error::OutOfMemory);
        }
        self.entries[self.count] = idx;
        self.count += 1;
        Ok(())
    }

    /// Removes and returns the front task index.
    pub fn pop_front(&mut self) -> Option<u16> {
        if self.count == 0 {
            return None;
        }
        let front = self.entries[0];
        let mut i = 0;
        while i + 1 < self.count {
            self.entries[i] = self.entries[i + 1];
            i += 1;
        }
        self.count -= 1;
        Some(front)
    }

    /// Peeks at the front task index.
    pub fn front(&self) -> Option<u16> {
        if self.count > 0 {
            Some(self.entries[0])
        } else {
            None
        }
    }

    /// Removes a specific task index from the queue.
    pub fn remove(&mut self, idx: u16) -> bool {
        if let Some(pos) = self.entries[..self.count].iter().position(|&e| e == idx) {
            let mut j = pos;
            while j + 1 < self.count {
                self.entries[j] = self.entries[j + 1];
                j += 1;
            }
            self.count -= 1;
            true
        } else {
            false
        }
    }

    /// Returns `true` if the queue is empty.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
}

/// Per-CPU RT run queue with priority bitmap and per-priority FIFOs.
pub struct RtRunqueue {
    /// Task pool.
    tasks: [RtTask; MAX_RT_PRIO * 2],
    /// Number of allocated task slots.
    nr_tasks: usize,
    /// Per-priority FIFO queues.
    queues: [RtPrioQueue; MAX_RT_PRIO],
    /// Bitmap: bit `i` set if priority `i` has runnable tasks.
    /// Using two u64s to cover 100 bits.
    bitmap: [u64; 2],
    /// Number of runnable tasks.
    pub nr_running: u32,
    /// Currently running task index.
    pub current_idx: Option<u16>,
    /// RT bandwidth: runtime remaining in current period (us).
    pub rt_runtime_remaining_us: u64,
    /// RT bandwidth: period length (us).
    pub rt_period_us: u64,
    /// Whether throttled.
    pub throttled: bool,
}

impl RtRunqueue {
    /// Creates an empty RT run queue.
    pub const fn new() -> Self {
        Self {
            tasks: [const { RtTask::new() }; MAX_RT_PRIO * 2],
            nr_tasks: 0,
            queues: [const { RtPrioQueue::new() }; MAX_RT_PRIO],
            bitmap: [0u64; 2],
            nr_running: 0,
            current_idx: None,
            rt_runtime_remaining_us: _DEFAULT_RT_RUNTIME_US,
            rt_period_us: _DEFAULT_RT_PERIOD_US,
            throttled: false,
        }
    }

    /// Enqueues a new RT task. Returns the task slot index.
    pub fn enqueue_task(&mut self, pid: u64, priority: u8, policy: RtPolicy) -> Result<u16> {
        if priority >= MAX_RT_PRIO as u8 {
            return Err(Error::InvalidArgument);
        }

        // Find a free slot.
        let slot = self
            .tasks
            .iter()
            .position(|t| !t.active)
            .ok_or(Error::OutOfMemory)?;

        self.tasks[slot].pid = pid;
        self.tasks[slot].priority = priority;
        self.tasks[slot].policy = policy;
        self.tasks[slot].state = RtTaskState::Runnable;
        self.tasks[slot].active = true;
        self.tasks[slot].sum_exec_runtime = 0;
        if policy == RtPolicy::SchedRr {
            self.tasks[slot].remaining_ns = self.tasks[slot].time_quantum_ns;
        }

        self.queues[priority as usize].push_back(slot as u16)?;
        self.set_bitmap(priority as usize);
        self.nr_running += 1;
        self.nr_tasks += 1;

        Ok(slot as u16)
    }

    /// Dequeues an RT task by slot index.
    pub fn dequeue_task(&mut self, idx: u16) -> Result<()> {
        let i = idx as usize;
        if i >= self.tasks.len() || !self.tasks[i].active {
            return Err(Error::NotFound);
        }

        let prio = self.tasks[i].priority as usize;
        self.queues[prio].remove(idx);
        if self.queues[prio].is_empty() {
            self.clear_bitmap(prio);
        }
        self.tasks[i].active = false;
        self.tasks[i].state = RtTaskState::Stopped;
        self.nr_running = self.nr_running.saturating_sub(1);
        self.nr_tasks = self.nr_tasks.saturating_sub(1);

        if self.current_idx == Some(idx) {
            self.current_idx = None;
        }

        Ok(())
    }

    /// Picks the highest-priority runnable task.
    pub fn pick_next_task(&self) -> Option<u16> {
        if self.throttled || self.nr_running == 0 {
            return None;
        }
        let prio = self.find_highest_prio()?;
        self.queues[prio].front()
    }

    /// Handles a scheduler tick for SCHED_RR time-slice accounting.
    /// Returns `true` if a reschedule is needed.
    pub fn scheduler_tick(&mut self, delta_ns: u64) -> bool {
        let idx = match self.current_idx {
            Some(i) => i as usize,
            None => return false,
        };

        if idx >= self.tasks.len() || !self.tasks[idx].active {
            return false;
        }

        self.tasks[idx].sum_exec_runtime += delta_ns;

        // Only SCHED_RR has time slicing.
        if self.tasks[idx].policy != RtPolicy::SchedRr {
            return false;
        }

        if delta_ns >= self.tasks[idx].remaining_ns {
            self.tasks[idx].remaining_ns = self.tasks[idx].time_quantum_ns;
            // Move to back of its priority queue.
            let prio = self.tasks[idx].priority as usize;
            let task_idx = idx as u16;
            self.queues[prio].remove(task_idx);
            let _ = self.queues[prio].push_back(task_idx);
            return true;
        }

        self.tasks[idx].remaining_ns -= delta_ns;
        false
    }

    /// Charges RT bandwidth. Returns `true` if throttled.
    pub fn charge_bandwidth(&mut self, delta_us: u64) -> bool {
        if self.rt_period_us == 0 {
            return false;
        }
        if delta_us >= self.rt_runtime_remaining_us {
            self.rt_runtime_remaining_us = 0;
            self.throttled = true;
            true
        } else {
            self.rt_runtime_remaining_us -= delta_us;
            false
        }
    }

    /// Replenishes RT bandwidth at period boundaries.
    pub fn replenish_bandwidth(&mut self) {
        self.rt_runtime_remaining_us = _DEFAULT_RT_RUNTIME_US;
        self.throttled = false;
    }

    /// Returns task info by index.
    pub fn task(&self, idx: u16) -> Option<&RtTask> {
        let i = idx as usize;
        if i < self.tasks.len() && self.tasks[i].active {
            Some(&self.tasks[i])
        } else {
            None
        }
    }

    // ------------------------------------------------------------------
    // Bitmap helpers
    // ------------------------------------------------------------------

    fn set_bitmap(&mut self, prio: usize) {
        let word = prio / 64;
        let bit = prio % 64;
        self.bitmap[word] |= 1u64 << bit;
    }

    fn clear_bitmap(&mut self, prio: usize) {
        let word = prio / 64;
        let bit = prio % 64;
        self.bitmap[word] &= !(1u64 << bit);
    }

    fn find_highest_prio(&self) -> Option<usize> {
        // Check high word first (priorities 64-99).
        if self.bitmap[1] != 0 {
            let bit = 63 - self.bitmap[1].leading_zeros() as usize;
            return Some(64 + bit);
        }
        if self.bitmap[0] != 0 {
            let bit = 63 - self.bitmap[0].leading_zeros() as usize;
            return Some(bit);
        }
        None
    }
}

// ======================================================================
// RtScheduler — top-level
// ======================================================================

/// Top-level RT scheduler managing per-CPU run queues.
pub struct RtScheduler {
    /// Per-CPU RT run queues.
    rqs: [RtRunqueue; MAX_CPUS],
    /// Number of active CPUs.
    pub nr_cpus: u32,
    /// Global number of RT tasks.
    pub nr_rt_tasks: u64,
}

impl RtScheduler {
    /// Creates an RT scheduler.
    pub const fn new() -> Self {
        Self {
            rqs: [const { RtRunqueue::new() }; MAX_CPUS],
            nr_cpus: 1,
            nr_rt_tasks: 0,
        }
    }

    /// Enqueues an RT task on a specific CPU.
    pub fn enqueue_task(
        &mut self,
        cpu: u32,
        pid: u64,
        priority: u8,
        policy: RtPolicy,
    ) -> Result<u16> {
        let c = cpu as usize;
        if c >= MAX_CPUS {
            return Err(Error::InvalidArgument);
        }
        let idx = self.rqs[c].enqueue_task(pid, priority, policy)?;
        self.nr_rt_tasks += 1;
        Ok(idx)
    }

    /// Dequeues an RT task from a specific CPU.
    pub fn dequeue_task(&mut self, cpu: u32, idx: u16) -> Result<()> {
        let c = cpu as usize;
        if c >= MAX_CPUS {
            return Err(Error::InvalidArgument);
        }
        self.rqs[c].dequeue_task(idx)?;
        self.nr_rt_tasks = self.nr_rt_tasks.saturating_sub(1);
        Ok(())
    }

    /// Picks the next RT task on the given CPU.
    pub fn pick_next_task(&self, cpu: u32) -> Option<u16> {
        let c = cpu as usize;
        if c >= MAX_CPUS {
            return None;
        }
        self.rqs[c].pick_next_task()
    }

    /// Returns the run queue for a given CPU.
    pub fn runqueue(&self, cpu: u32) -> Option<&RtRunqueue> {
        let c = cpu as usize;
        if c < MAX_CPUS {
            Some(&self.rqs[c])
        } else {
            None
        }
    }

    /// Returns a mutable run queue for a given CPU.
    pub fn runqueue_mut(&mut self, cpu: u32) -> Option<&mut RtRunqueue> {
        let c = cpu as usize;
        if c < MAX_CPUS {
            Some(&mut self.rqs[c])
        } else {
            None
        }
    }

    /// Finds the best CPU for an RT task (fewest RT tasks running).
    pub fn find_lowest_rq(&self, _priority: u8) -> Option<u32> {
        let mut best_cpu = None;
        let mut min_running = u32::MAX;

        for c in 0..self.nr_cpus as usize {
            let nr = self.rqs[c].nr_running;
            if nr < min_running {
                min_running = nr;
                best_cpu = Some(c as u32);
            }
        }
        best_cpu
    }
}
