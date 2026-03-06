// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Real-time scheduling subsystem (SCHED_FIFO and SCHED_RR).
//!
//! Implements POSIX real-time scheduling policies modeled after the
//! Linux `kernel/sched/rt.c` design:
//!
//! - **SCHED_FIFO**: First-in, first-out scheduling without time
//!   slicing. A task runs until it voluntarily yields, blocks, or
//!   is preempted by a higher-priority RT task.
//! - **SCHED_RR**: Round-robin scheduling with a configurable
//!   timeslice. Tasks at the same priority level share CPU time
//!   in round-robin fashion.
//!
//! # Priority Model
//!
//! RT priorities range from 1 (lowest) to 99 (highest). Each
//! priority level has its own run queue. The scheduler always
//! selects the runnable task with the highest priority. Within
//! a priority level, SCHED_FIFO tasks run until completion while
//! SCHED_RR tasks rotate after exhausting their timeslice.
//!
//! # Bandwidth Throttling
//!
//! RT bandwidth throttling prevents RT tasks from starving
//! non-RT tasks. A configurable runtime/period pair limits the
//! fraction of CPU time RT tasks can consume.
//!
//! # Types
//!
//! - [`RtPolicy`] — FIFO or round-robin policy selection
//! - [`RtTask`] — a task registered with the RT scheduler
//! - [`RtRunQueue`] — per-priority FIFO queue of runnable tasks
//! - [`RtBandwidth`] — RT bandwidth throttling parameters
//! - [`RtStats`] — scheduling statistics
//! - [`RtScheduler`] — the global RT scheduler

use oncrix_lib::{Error, Result};

// ── Constants ──────────────────────────────────────────────────────

/// Minimum RT priority (lowest real-time priority).
const RT_PRIO_MIN: u8 = 1;

/// Maximum RT priority (highest real-time priority).
const RT_PRIO_MAX: u8 = 99;

/// Number of distinct RT priority levels.
const RT_PRIO_LEVELS: usize = 99;

/// Maximum number of tasks per priority run queue.
const MAX_TASKS_PER_QUEUE: usize = 16;

/// Maximum total number of RT tasks in the system.
const MAX_RT_TASKS: usize = 256;

/// Default round-robin timeslice in microseconds (100 ms).
const DEFAULT_RR_TIMESLICE_US: u64 = 100_000;

/// Minimum round-robin timeslice in microseconds (1 ms).
const _MIN_RR_TIMESLICE_US: u64 = 1_000;

/// Maximum round-robin timeslice in microseconds (1 s).
const _MAX_RR_TIMESLICE_US: u64 = 1_000_000;

/// Default RT bandwidth period in microseconds (1 s).
const DEFAULT_RT_PERIOD_US: u64 = 1_000_000;

/// Default RT bandwidth runtime in microseconds (950 ms, 95%).
const DEFAULT_RT_RUNTIME_US: u64 = 950_000;

/// RT runtime value meaning unlimited (no throttling).
const RT_RUNTIME_UNLIMITED: i64 = -1;

// ── RtPolicy ───────────────────────────────────────────────────────

/// Real-time scheduling policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RtPolicy {
    /// First-in, first-out: no timeslice, runs until yield/block.
    Fifo,
    /// Round-robin: rotates after timeslice expiration.
    RoundRobin,
}

impl Default for RtPolicy {
    fn default() -> Self {
        Self::Fifo
    }
}

// ── TaskState ──────────────────────────────────────────────────────

/// Current state of an RT task.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskState {
    /// Task is ready to run and in a run queue.
    Runnable,
    /// Task is currently executing on a CPU.
    Running,
    /// Task is blocked waiting for a resource.
    Blocked,
    /// Task has been stopped (e.g., by a signal).
    Stopped,
}

impl Default for TaskState {
    fn default() -> Self {
        Self::Runnable
    }
}

// ── RtTask ─────────────────────────────────────────────────────────

/// A task registered with the real-time scheduler.
///
/// Tracks scheduling policy, priority, timeslice state, and
/// cumulative runtime statistics.
#[derive(Debug, Clone, Copy)]
pub struct RtTask {
    /// Process ID.
    pub pid: u64,
    /// RT scheduling policy (FIFO or RR).
    pub policy: RtPolicy,
    /// RT priority (1-99, higher = more important).
    pub priority: u8,
    /// Current task state.
    pub state: TaskState,
    /// Configured timeslice in microseconds (RR only).
    pub timeslice_us: u64,
    /// Remaining timeslice in the current round (RR only).
    pub remaining_us: u64,
    /// Total CPU time consumed in microseconds.
    pub total_runtime_us: u64,
    /// Number of times this task has been scheduled.
    pub schedule_count: u64,
    /// Number of times this task was preempted.
    pub preempt_count: u64,
    /// Whether this task slot is in use.
    pub in_use: bool,
}

impl RtTask {
    /// Creates an empty (inactive) task slot.
    const fn empty() -> Self {
        Self {
            pid: 0,
            policy: RtPolicy::Fifo,
            priority: 0,
            state: TaskState::Runnable,
            timeslice_us: DEFAULT_RR_TIMESLICE_US,
            remaining_us: DEFAULT_RR_TIMESLICE_US,
            total_runtime_us: 0,
            schedule_count: 0,
            preempt_count: 0,
            in_use: false,
        }
    }

    /// Resets the remaining timeslice to the configured value.
    pub fn replenish_timeslice(&mut self) {
        self.remaining_us = self.timeslice_us;
    }

    /// Charges CPU time to this task and decrements the remaining
    /// timeslice for RR tasks.
    ///
    /// Returns `true` if the timeslice has expired (RR only).
    pub fn charge_time(&mut self, usec: u64) -> bool {
        self.total_runtime_us = self.total_runtime_us.saturating_add(usec);

        if self.policy == RtPolicy::RoundRobin {
            if usec >= self.remaining_us {
                self.remaining_us = 0;
                return true;
            }
            self.remaining_us -= usec;
        }

        false
    }
}

// ── RtRunQueue ─────────────────────────────────────────────────────

/// Per-priority FIFO run queue.
///
/// Tasks at the same priority level are queued in FIFO order.
/// For SCHED_RR, a task whose timeslice expires is moved to
/// the tail of its priority queue.
#[derive(Debug, Clone, Copy)]
pub struct RtRunQueue {
    /// PIDs of runnable tasks in FIFO order.
    tasks: [u64; MAX_TASKS_PER_QUEUE],
    /// Number of tasks in this queue.
    count: usize,
    /// Priority level this queue serves (1-99).
    priority: u8,
}

impl RtRunQueue {
    /// Creates an empty run queue for the given priority level.
    const fn new(priority: u8) -> Self {
        Self {
            tasks: [0u64; MAX_TASKS_PER_QUEUE],
            count: 0,
            priority,
        }
    }

    /// Enqueues a task PID at the tail of this run queue.
    ///
    /// # Errors
    ///
    /// - `Error::AlreadyExists` — PID is already in this queue.
    /// - `Error::OutOfMemory` — queue is full.
    pub fn enqueue(&mut self, pid: u64) -> Result<()> {
        if self.tasks[..self.count].contains(&pid) {
            return Err(Error::AlreadyExists);
        }
        if self.count >= MAX_TASKS_PER_QUEUE {
            return Err(Error::OutOfMemory);
        }
        self.tasks[self.count] = pid;
        self.count += 1;
        Ok(())
    }

    /// Dequeues the task at the head of this run queue.
    ///
    /// Returns `None` if the queue is empty.
    pub fn dequeue(&mut self) -> Option<u64> {
        if self.count == 0 {
            return None;
        }

        let pid = self.tasks[0];

        // Shift remaining tasks forward.
        let mut i = 0;
        while i + 1 < self.count {
            self.tasks[i] = self.tasks[i + 1];
            i += 1;
        }
        self.tasks[self.count.saturating_sub(1)] = 0;
        self.count = self.count.saturating_sub(1);

        Some(pid)
    }

    /// Removes a specific PID from this run queue.
    ///
    /// Returns `true` if the PID was found and removed.
    pub fn remove(&mut self, pid: u64) -> bool {
        let pos = self.tasks[..self.count].iter().position(|&p| p == pid);

        if let Some(pos) = pos {
            let mut i = pos;
            while i + 1 < self.count {
                self.tasks[i] = self.tasks[i + 1];
                i += 1;
            }
            self.tasks[self.count.saturating_sub(1)] = 0;
            self.count = self.count.saturating_sub(1);
            true
        } else {
            false
        }
    }

    /// Returns the PID at the head of the queue without removing it.
    pub fn peek(&self) -> Option<u64> {
        if self.count > 0 {
            Some(self.tasks[0])
        } else {
            None
        }
    }

    /// Returns the number of tasks in this queue.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Returns `true` if this queue is empty.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Returns the priority level of this queue.
    pub fn priority(&self) -> u8 {
        self.priority
    }
}

// ── RtBandwidth ────────────────────────────────────────────────────

/// RT bandwidth throttling parameters.
///
/// Controls the maximum fraction of CPU time that RT tasks may
/// consume. A `runtime_us` of `-1` disables throttling.
#[derive(Debug, Clone, Copy)]
pub struct RtBandwidth {
    /// Maximum RT runtime per period in microseconds.
    /// `-1` means unlimited.
    pub runtime_us: i64,
    /// Period length in microseconds.
    pub period_us: u64,
    /// Accumulated RT runtime in the current period.
    pub used_us: u64,
    /// Number of periods that were throttled.
    pub throttled_periods: u64,
    /// Whether RT tasks are currently throttled.
    pub throttled: bool,
}

impl Default for RtBandwidth {
    fn default() -> Self {
        Self {
            runtime_us: DEFAULT_RT_RUNTIME_US as i64,
            period_us: DEFAULT_RT_PERIOD_US,
            used_us: 0,
            throttled_periods: 0,
            throttled: false,
        }
    }
}

impl RtBandwidth {
    /// Creates unlimited bandwidth (no throttling).
    pub const fn unlimited() -> Self {
        Self {
            runtime_us: RT_RUNTIME_UNLIMITED,
            period_us: DEFAULT_RT_PERIOD_US,
            used_us: 0,
            throttled_periods: 0,
            throttled: false,
        }
    }

    /// Checks whether the bandwidth limit has been reached.
    pub fn is_exhausted(&self) -> bool {
        if self.runtime_us == RT_RUNTIME_UNLIMITED {
            return false;
        }
        self.used_us >= self.runtime_us as u64
    }

    /// Charges RT runtime and updates the throttle state.
    ///
    /// Returns `true` if the charge caused throttling to activate.
    pub fn charge(&mut self, usec: u64) -> bool {
        if self.runtime_us == RT_RUNTIME_UNLIMITED {
            return false;
        }

        self.used_us = self.used_us.saturating_add(usec);

        if !self.throttled && self.is_exhausted() {
            self.throttled = true;
            self.throttled_periods = self.throttled_periods.saturating_add(1);
            return true;
        }

        false
    }

    /// Resets the period accounting counters.
    pub fn reset_period(&mut self) {
        self.used_us = 0;
        self.throttled = false;
    }
}

// ── RtStats ────────────────────────────────────────────────────────

/// Global RT scheduling statistics.
#[derive(Debug, Clone, Copy, Default)]
pub struct RtStats {
    /// Total number of context switches performed by the RT
    /// scheduler.
    pub context_switches: u64,
    /// Total number of timeslice expirations (RR tasks only).
    pub timeslice_expirations: u64,
    /// Total number of preemptions.
    pub preemptions: u64,
    /// Total CPU time consumed by RT tasks (microseconds).
    pub total_runtime_us: u64,
    /// Number of times the RT bandwidth was throttled.
    pub bandwidth_throttles: u64,
    /// Current number of runnable RT tasks.
    pub nr_running: u32,
}

// ── RtScheduler ────────────────────────────────────────────────────

/// The global real-time scheduler.
///
/// Manages per-priority run queues, RT task state, bandwidth
/// throttling, and scheduling decisions. The scheduler always
/// picks the runnable task with the highest priority (highest
/// numeric value). Within a priority level, SCHED_FIFO tasks
/// run until they yield or block; SCHED_RR tasks rotate after
/// their timeslice expires.
pub struct RtScheduler {
    /// Per-priority run queues (index 0 = priority 1).
    queues: [RtRunQueue; RT_PRIO_LEVELS],
    /// Global task pool indexed by slot.
    tasks: [RtTask; MAX_RT_TASKS],
    /// Number of registered RT tasks.
    task_count: usize,
    /// PID of the currently running RT task (0 = none).
    current_pid: u64,
    /// RT bandwidth throttling parameters.
    bandwidth: RtBandwidth,
    /// Global RT scheduling statistics.
    stats: RtStats,
}

impl Default for RtScheduler {
    fn default() -> Self {
        Self::new()
    }
}

impl RtScheduler {
    /// Creates a new RT scheduler with default settings.
    pub const fn new() -> Self {
        const EMPTY_TASK: RtTask = RtTask::empty();

        // Build per-priority run queues. Index 0 = priority 1.
        // Use a helper to create the array since we need varying
        // priority values.
        let queues = Self::init_queues();

        Self {
            queues,
            tasks: [EMPTY_TASK; MAX_RT_TASKS],
            task_count: 0,
            current_pid: 0,
            bandwidth: RtBandwidth {
                runtime_us: DEFAULT_RT_RUNTIME_US as i64,
                period_us: DEFAULT_RT_PERIOD_US,
                used_us: 0,
                throttled_periods: 0,
                throttled: false,
            },
            stats: RtStats {
                context_switches: 0,
                timeslice_expirations: 0,
                preemptions: 0,
                total_runtime_us: 0,
                bandwidth_throttles: 0,
                nr_running: 0,
            },
        }
    }

    /// Helper to initialize per-priority run queues at compile time.
    const fn init_queues() -> [RtRunQueue; RT_PRIO_LEVELS] {
        let mut queues = [RtRunQueue::new(0); RT_PRIO_LEVELS];
        let mut i = 0;
        while i < RT_PRIO_LEVELS {
            queues[i] = RtRunQueue::new((i + 1) as u8);
            i += 1;
        }
        queues
    }

    /// Registers a new RT task with the scheduler.
    ///
    /// The task is added to the appropriate priority run queue.
    ///
    /// # Errors
    ///
    /// - `Error::InvalidArgument` — priority is out of range (1-99).
    /// - `Error::AlreadyExists` — a task with this PID already
    ///   exists.
    /// - `Error::OutOfMemory` — task pool is full.
    pub fn add_task(&mut self, pid: u64, policy: RtPolicy, priority: u8) -> Result<()> {
        if !(RT_PRIO_MIN..=RT_PRIO_MAX).contains(&priority) {
            return Err(Error::InvalidArgument);
        }

        // Check for duplicate PID.
        if self.find_task(pid).is_some() {
            return Err(Error::AlreadyExists);
        }

        // Find a free task slot.
        let slot = self
            .tasks
            .iter()
            .position(|t| !t.in_use)
            .ok_or(Error::OutOfMemory)?;

        let task = &mut self.tasks[slot];
        *task = RtTask::empty();
        task.pid = pid;
        task.policy = policy;
        task.priority = priority;
        task.state = TaskState::Runnable;
        task.in_use = true;

        if policy == RtPolicy::RoundRobin {
            task.timeslice_us = DEFAULT_RR_TIMESLICE_US;
            task.remaining_us = DEFAULT_RR_TIMESLICE_US;
        }

        // Add to the appropriate priority run queue.
        let queue_idx = (priority - 1) as usize;
        self.queues[queue_idx].enqueue(pid)?;

        self.task_count += 1;
        self.stats.nr_running += 1;

        Ok(())
    }

    /// Removes an RT task from the scheduler.
    ///
    /// # Errors
    ///
    /// Returns `Error::NotFound` if no task with the given PID
    /// exists.
    pub fn remove_task(&mut self, pid: u64) -> Result<()> {
        let slot = self.find_task(pid).ok_or(Error::NotFound)?;

        let priority = self.tasks[slot].priority;
        let state = self.tasks[slot].state;

        // Remove from run queue if still queued.
        if state == TaskState::Runnable || state == TaskState::Running {
            let queue_idx = (priority - 1) as usize;
            self.queues[queue_idx].remove(pid);
            self.stats.nr_running = self.stats.nr_running.saturating_sub(1);
        }

        if self.current_pid == pid {
            self.current_pid = 0;
        }

        self.tasks[slot] = RtTask::empty();
        self.task_count = self.task_count.saturating_sub(1);

        Ok(())
    }

    /// Changes the scheduling policy and priority of an existing
    /// task.
    ///
    /// The task is moved to the new priority's run queue.
    ///
    /// # Errors
    ///
    /// - `Error::NotFound` — no task with the given PID exists.
    /// - `Error::InvalidArgument` — priority is out of range.
    pub fn set_policy(&mut self, pid: u64, policy: RtPolicy, priority: u8) -> Result<()> {
        if !(RT_PRIO_MIN..=RT_PRIO_MAX).contains(&priority) {
            return Err(Error::InvalidArgument);
        }

        let slot = self.find_task(pid).ok_or(Error::NotFound)?;

        let old_priority = self.tasks[slot].priority;

        // Remove from old queue and add to new queue if runnable.
        if self.tasks[slot].state == TaskState::Runnable {
            let old_idx = (old_priority - 1) as usize;
            self.queues[old_idx].remove(pid);

            let new_idx = (priority - 1) as usize;
            self.queues[new_idx].enqueue(pid)?;
        }

        self.tasks[slot].policy = policy;
        self.tasks[slot].priority = priority;

        if policy == RtPolicy::RoundRobin {
            self.tasks[slot].replenish_timeslice();
        }

        Ok(())
    }

    /// Sets the round-robin timeslice for a task.
    ///
    /// Only meaningful for SCHED_RR tasks.
    ///
    /// # Errors
    ///
    /// - `Error::NotFound` — no task with the given PID exists.
    /// - `Error::InvalidArgument` — timeslice is zero.
    pub fn set_timeslice(&mut self, pid: u64, timeslice_us: u64) -> Result<()> {
        if timeslice_us == 0 {
            return Err(Error::InvalidArgument);
        }

        let slot = self.find_task(pid).ok_or(Error::NotFound)?;

        self.tasks[slot].timeslice_us = timeslice_us;

        Ok(())
    }

    /// Selects the next RT task to run.
    ///
    /// Returns the PID of the highest-priority runnable task, or
    /// `None` if no RT tasks are runnable or bandwidth is
    /// throttled.
    pub fn pick_next(&mut self) -> Option<u64> {
        // Check bandwidth throttling.
        if self.bandwidth.throttled {
            return None;
        }

        // Scan from highest priority (99) to lowest (1).
        let mut prio_idx = RT_PRIO_LEVELS;
        while prio_idx > 0 {
            prio_idx -= 1;
            if let Some(pid) = self.queues[prio_idx].peek() {
                return Some(pid);
            }
        }

        None
    }

    /// Performs a scheduling decision: dequeues and activates the
    /// next task.
    ///
    /// If a task is currently running, it is preempted only if
    /// the candidate has strictly higher priority.
    ///
    /// Returns the PID of the newly scheduled task, or `None` if
    /// no switch occurred.
    pub fn schedule(&mut self) -> Option<u64> {
        let candidate = self.pick_next()?;

        // If we already have a running task, check preemption.
        if self.current_pid != 0 {
            if let Some(cur_slot) = self.find_task(self.current_pid) {
                let cur_prio = self.tasks[cur_slot].priority;

                // Find candidate priority.
                if let Some(cand_slot) = self.find_task(candidate) {
                    let cand_prio = self.tasks[cand_slot].priority;
                    if cand_prio <= cur_prio {
                        // No preemption needed.
                        return None;
                    }

                    // Preempt current task.
                    self.tasks[cur_slot].state = TaskState::Runnable;
                    self.tasks[cur_slot].preempt_count =
                        self.tasks[cur_slot].preempt_count.saturating_add(1);
                    self.stats.preemptions = self.stats.preemptions.saturating_add(1);

                    // Re-enqueue current task at its priority.
                    let cur_q = (cur_prio - 1) as usize;
                    let _ = self.queues[cur_q].enqueue(self.current_pid);
                }
            }
        }

        // Dequeue and activate the candidate.
        if let Some(cand_slot) = self.find_task(candidate) {
            let cand_prio = self.tasks[cand_slot].priority;
            let cand_q = (cand_prio - 1) as usize;
            self.queues[cand_q].dequeue();

            self.tasks[cand_slot].state = TaskState::Running;
            self.tasks[cand_slot].schedule_count =
                self.tasks[cand_slot].schedule_count.saturating_add(1);
            self.current_pid = candidate;

            self.stats.context_switches = self.stats.context_switches.saturating_add(1);

            return Some(candidate);
        }

        None
    }

    /// Timer tick handler for the RT scheduler.
    ///
    /// Called periodically (e.g., every 1 ms). Charges CPU time to
    /// the running task, checks for timeslice expiration (RR), and
    /// manages bandwidth throttling.
    ///
    /// Returns `true` if a reschedule is needed.
    pub fn tick(&mut self, elapsed_us: u64) -> bool {
        let mut need_resched = false;

        // Charge bandwidth.
        if self.bandwidth.charge(elapsed_us) {
            self.stats.bandwidth_throttles = self.stats.bandwidth_throttles.saturating_add(1);
            need_resched = true;
        }

        // Charge the currently running task.
        if self.current_pid != 0 {
            if let Some(slot) = self.find_task(self.current_pid) {
                self.stats.total_runtime_us =
                    self.stats.total_runtime_us.saturating_add(elapsed_us);

                let expired = self.tasks[slot].charge_time(elapsed_us);

                if expired && self.tasks[slot].policy == RtPolicy::RoundRobin {
                    // Timeslice expired — rotate to tail of queue.
                    self.stats.timeslice_expirations =
                        self.stats.timeslice_expirations.saturating_add(1);

                    let prio = self.tasks[slot].priority;
                    let queue_idx = (prio - 1) as usize;

                    self.tasks[slot].state = TaskState::Runnable;
                    self.tasks[slot].replenish_timeslice();
                    let _ = self.queues[queue_idx].enqueue(self.current_pid);
                    self.current_pid = 0;

                    need_resched = true;
                }
            }
        }

        // Check for period reset.
        if self.bandwidth.used_us >= self.bandwidth.period_us {
            self.bandwidth.reset_period();
        }

        need_resched
    }

    /// Yields the current RT task voluntarily.
    ///
    /// The task moves to the tail of its priority run queue.
    ///
    /// # Errors
    ///
    /// Returns `Error::NotFound` if no task is currently running.
    pub fn yield_current(&mut self) -> Result<()> {
        if self.current_pid == 0 {
            return Err(Error::NotFound);
        }

        let slot = self.find_task(self.current_pid).ok_or(Error::NotFound)?;

        let prio = self.tasks[slot].priority;
        let queue_idx = (prio - 1) as usize;

        self.tasks[slot].state = TaskState::Runnable;

        if self.tasks[slot].policy == RtPolicy::RoundRobin {
            self.tasks[slot].replenish_timeslice();
        }

        let _ = self.queues[queue_idx].enqueue(self.current_pid);
        self.current_pid = 0;

        Ok(())
    }

    /// Blocks the current RT task (e.g., waiting for I/O).
    ///
    /// The task is removed from the run queue until explicitly
    /// woken.
    ///
    /// # Errors
    ///
    /// Returns `Error::NotFound` if no task is currently running.
    pub fn block_current(&mut self) -> Result<()> {
        if self.current_pid == 0 {
            return Err(Error::NotFound);
        }

        let slot = self.find_task(self.current_pid).ok_or(Error::NotFound)?;

        self.tasks[slot].state = TaskState::Blocked;
        self.stats.nr_running = self.stats.nr_running.saturating_sub(1);
        self.current_pid = 0;

        Ok(())
    }

    /// Wakes a blocked RT task, making it runnable again.
    ///
    /// # Errors
    ///
    /// Returns `Error::NotFound` if the task does not exist or is
    /// not blocked.
    pub fn wake_task(&mut self, pid: u64) -> Result<()> {
        let slot = self.find_task(pid).ok_or(Error::NotFound)?;

        if self.tasks[slot].state != TaskState::Blocked {
            return Err(Error::InvalidArgument);
        }

        let prio = self.tasks[slot].priority;
        let queue_idx = (prio - 1) as usize;

        self.tasks[slot].state = TaskState::Runnable;
        self.queues[queue_idx].enqueue(pid)?;
        self.stats.nr_running += 1;

        Ok(())
    }

    /// Sets RT bandwidth throttling parameters.
    ///
    /// # Errors
    ///
    /// - `Error::InvalidArgument` — runtime is zero or a negative
    ///   value other than `-1`, or period is zero.
    pub fn set_bandwidth(&mut self, runtime_us: i64, period_us: u64) -> Result<()> {
        if runtime_us != RT_RUNTIME_UNLIMITED && runtime_us <= 0 {
            return Err(Error::InvalidArgument);
        }
        if period_us == 0 {
            return Err(Error::InvalidArgument);
        }

        self.bandwidth.runtime_us = runtime_us;
        self.bandwidth.period_us = period_us;
        self.bandwidth.reset_period();

        Ok(())
    }

    /// Returns the PID of the currently running RT task.
    pub fn current_pid(&self) -> u64 {
        self.current_pid
    }

    /// Returns the number of registered RT tasks.
    pub fn task_count(&self) -> usize {
        self.task_count
    }

    /// Returns a reference to the global RT statistics.
    pub fn get_stats(&self) -> &RtStats {
        &self.stats
    }

    /// Returns a reference to the RT bandwidth parameters.
    pub fn get_bandwidth(&self) -> &RtBandwidth {
        &self.bandwidth
    }

    /// Returns an immutable reference to an RT task by PID.
    pub fn get_task(&self, pid: u64) -> Option<&RtTask> {
        self.find_task(pid).map(|slot| &self.tasks[slot])
    }

    /// Returns the number of tasks at a given priority level.
    ///
    /// Returns `0` if the priority is out of range.
    pub fn tasks_at_priority(&self, priority: u8) -> usize {
        if !(RT_PRIO_MIN..=RT_PRIO_MAX).contains(&priority) {
            return 0;
        }
        let queue_idx = (priority - 1) as usize;
        self.queues[queue_idx].len()
    }

    // ── Internal helpers ───────────────────────────────────────────

    /// Finds a task by PID and returns its slot index.
    fn find_task(&self, pid: u64) -> Option<usize> {
        self.tasks.iter().position(|t| t.in_use && t.pid == pid)
    }
}
