// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! SCHED_IDLE scheduler class.
//!
//! Implements the idle-priority scheduling class for background tasks
//! that should only run when no other schedulable work exists. SCHED_IDLE
//! tasks have the lowest scheduling priority in the system — below CFS
//! normal tasks, below SCHED_BATCH, and below all real-time policies.
//!
//! # Design
//!
//! The idle class maintains a per-CPU run queue of idle-priority tasks.
//! The scheduler selects an idle task only when all higher-priority
//! classes (RT, deadline, CFS) have no runnable work. Within the idle
//! class, tasks are scheduled in round-robin order with a generous
//! timeslice to minimize context-switch overhead.
//!
//! # Use Cases
//!
//! - Background maintenance (defragmentation, scrubbing)
//! - Speculative prefetching
//! - Non-critical monitoring agents
//! - Folding@home / BOINC style volunteer computing
//!
//! # Priority Model
//!
//! Idle tasks run at a fixed priority below all CFS nice levels.
//! Within the idle class, tasks can have a secondary weight (0-100)
//! that influences selection order, but this is best-effort.
//!
//! # Reference
//!
//! Linux kernel `kernel/sched/idle.c`.

use oncrix_lib::{Error, Result};

// ── Constants ─────────────────────────────────────────────────────────────────

/// Maximum number of CPUs supported.
const MAX_CPUS: usize = 64;

/// Maximum number of idle tasks per CPU.
const MAX_TASKS_PER_CPU: usize = 32;

/// Maximum total idle tasks in the system.
const MAX_TOTAL_TASKS: usize = MAX_CPUS * MAX_TASKS_PER_CPU;

/// Default timeslice for idle tasks in microseconds (1 second).
///
/// Generous timeslice because idle tasks are low priority and we
/// want to minimize context-switch overhead.
const DEFAULT_TIMESLICE_US: u64 = 1_000_000;

/// Minimum timeslice in microseconds (100 ms).
const MIN_TIMESLICE_US: u64 = 100_000;

/// Maximum timeslice in microseconds (10 seconds).
const _MAX_TIMESLICE_US: u64 = 10_000_000;

/// Default weight for idle tasks (range 0-100).
const DEFAULT_WEIGHT: u32 = 50;

/// Maximum weight value.
const MAX_WEIGHT: u32 = 100;

/// Task ID representing no task.
const NO_TASK: u64 = u64::MAX;

// ── IdleTaskState ─────────────────────────────────────────────────────────────

/// State of a SCHED_IDLE task.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum IdleTaskState {
    /// Task is runnable (waiting for CPU).
    #[default]
    Runnable,
    /// Task is currently running on a CPU.
    Running,
    /// Task is blocked (sleeping / waiting on I/O).
    Blocked,
    /// Task has yielded voluntarily.
    Yielded,
}

// ── IdleTask ──────────────────────────────────────────────────────────────────

/// A task registered with the SCHED_IDLE scheduler class.
#[derive(Debug, Clone, Copy)]
pub struct IdleTask {
    /// Task/thread identifier.
    task_id: u64,
    /// CPU this task is assigned to (for affinity).
    cpu: u32,
    /// Weight (0-100) for selection preference.
    weight: u32,
    /// Current state.
    state: IdleTaskState,
    /// Remaining timeslice in microseconds.
    remaining_us: u64,
    /// Total runtime in microseconds.
    total_runtime_us: u64,
    /// Number of times this task has been scheduled.
    schedule_count: u64,
    /// Number of voluntary yields.
    yield_count: u64,
    /// Whether this slot is active.
    active: bool,
}

impl IdleTask {
    /// Create an empty (inactive) idle task.
    pub const fn new() -> Self {
        Self {
            task_id: NO_TASK,
            cpu: 0,
            weight: DEFAULT_WEIGHT,
            state: IdleTaskState::Runnable,
            remaining_us: DEFAULT_TIMESLICE_US,
            total_runtime_us: 0,
            schedule_count: 0,
            yield_count: 0,
            active: false,
        }
    }

    /// Create an active idle task.
    pub const fn with_id(task_id: u64, cpu: u32) -> Self {
        Self {
            task_id,
            cpu,
            weight: DEFAULT_WEIGHT,
            state: IdleTaskState::Runnable,
            remaining_us: DEFAULT_TIMESLICE_US,
            total_runtime_us: 0,
            schedule_count: 0,
            yield_count: 0,
            active: true,
        }
    }

    /// Get the task ID.
    pub const fn task_id(&self) -> u64 {
        self.task_id
    }

    /// Get the assigned CPU.
    pub const fn cpu(&self) -> u32 {
        self.cpu
    }

    /// Get the weight.
    pub const fn weight(&self) -> u32 {
        self.weight
    }

    /// Get the current state.
    pub const fn state(&self) -> IdleTaskState {
        self.state
    }

    /// Get the remaining timeslice.
    pub const fn remaining_us(&self) -> u64 {
        self.remaining_us
    }

    /// Get total runtime.
    pub const fn total_runtime_us(&self) -> u64 {
        self.total_runtime_us
    }

    /// Get schedule count.
    pub const fn schedule_count(&self) -> u64 {
        self.schedule_count
    }

    /// Get yield count.
    pub const fn yield_count(&self) -> u64 {
        self.yield_count
    }

    /// Set the weight.
    pub fn set_weight(&mut self, weight: u32) -> Result<()> {
        if weight > MAX_WEIGHT {
            return Err(Error::InvalidArgument);
        }
        self.weight = weight;
        Ok(())
    }

    /// Consume timeslice (called on timer tick).
    ///
    /// Returns true if the timeslice is exhausted.
    pub fn tick(&mut self, elapsed_us: u64) -> bool {
        if self.state != IdleTaskState::Running {
            return false;
        }
        self.total_runtime_us = self.total_runtime_us.saturating_add(elapsed_us);
        self.remaining_us = self.remaining_us.saturating_sub(elapsed_us);
        self.remaining_us == 0
    }

    /// Reset the timeslice for a new scheduling quantum.
    pub fn reset_timeslice(&mut self) {
        self.remaining_us = DEFAULT_TIMESLICE_US;
    }

    /// Mark the task as running.
    pub fn set_running(&mut self) {
        self.state = IdleTaskState::Running;
        self.schedule_count += 1;
    }

    /// Mark the task as runnable (preempted or timeslice expired).
    pub fn set_runnable(&mut self) {
        self.state = IdleTaskState::Runnable;
    }

    /// Mark the task as blocked.
    pub fn set_blocked(&mut self) {
        self.state = IdleTaskState::Blocked;
    }

    /// Mark the task as having yielded.
    pub fn set_yielded(&mut self) {
        self.state = IdleTaskState::Yielded;
        self.yield_count += 1;
    }
}

impl Default for IdleTask {
    fn default() -> Self {
        Self::new()
    }
}

// ── IdleRunQueue ──────────────────────────────────────────────────────────────

/// Per-CPU run queue for SCHED_IDLE tasks.
///
/// Tasks are stored in a fixed-size array and selected in weighted
/// round-robin order.
#[derive(Debug)]
pub struct IdleRunQueue {
    /// CPU index this run queue belongs to.
    cpu: u32,
    /// Tasks on this run queue.
    tasks: [IdleTask; MAX_TASKS_PER_CPU],
    /// Number of tasks (active slots).
    count: usize,
    /// Index of the currently running task (NO_TASK if none).
    current_idx: usize,
    /// Round-robin cursor for pick_next.
    rr_cursor: usize,
    /// Total number of context switches on this CPU.
    context_switches: u64,
}

impl IdleRunQueue {
    /// Create an empty run queue for a CPU.
    pub const fn new(cpu: u32) -> Self {
        Self {
            cpu,
            tasks: [const { IdleTask::new() }; MAX_TASKS_PER_CPU],
            count: 0,
            current_idx: usize::MAX,
            rr_cursor: 0,
            context_switches: 0,
        }
    }

    /// Get the CPU index.
    pub const fn cpu(&self) -> u32 {
        self.cpu
    }

    /// Number of active tasks.
    pub fn active_count(&self) -> usize {
        let mut n = 0;
        for i in 0..self.count {
            if self.tasks[i].active {
                n += 1;
            }
        }
        n
    }

    /// Number of runnable tasks.
    pub fn runnable_count(&self) -> usize {
        let mut n = 0;
        for i in 0..self.count {
            if self.tasks[i].active
                && (self.tasks[i].state == IdleTaskState::Runnable
                    || self.tasks[i].state == IdleTaskState::Yielded)
            {
                n += 1;
            }
        }
        n
    }

    /// Enqueue a task.
    pub fn enqueue(&mut self, task_id: u64) -> Result<()> {
        // Check duplicate.
        for i in 0..self.count {
            if self.tasks[i].active && self.tasks[i].task_id == task_id {
                // Task already in queue — just set runnable.
                self.tasks[i].set_runnable();
                return Ok(());
            }
        }

        let slot = self.find_free_slot()?;
        self.tasks[slot] = IdleTask::with_id(task_id, self.cpu);
        if slot >= self.count {
            self.count = slot + 1;
        }
        Ok(())
    }

    /// Dequeue a task (remove from this run queue).
    pub fn dequeue(&mut self, task_id: u64) -> Result<()> {
        for i in 0..self.count {
            if self.tasks[i].active && self.tasks[i].task_id == task_id {
                self.tasks[i].active = false;
                if self.current_idx == i {
                    self.current_idx = usize::MAX;
                }
                return Ok(());
            }
        }
        Err(Error::NotFound)
    }

    /// Pick the next task to run.
    ///
    /// Selects the highest-weight runnable task in round-robin order.
    /// Returns the task ID or None if no task is runnable.
    pub fn pick_next_task(&mut self) -> Option<u64> {
        if self.count == 0 {
            return None;
        }

        let mut best_idx = None;
        let mut best_weight = 0u32;
        let start = self.rr_cursor;
        let len = self.count;

        for offset in 0..len {
            let i = (start + offset) % len;
            let task = &self.tasks[i];
            if task.active
                && (task.state == IdleTaskState::Runnable || task.state == IdleTaskState::Yielded)
            {
                if best_idx.is_none() || task.weight > best_weight {
                    best_idx = Some(i);
                    best_weight = task.weight;
                }
            }
        }

        if let Some(idx) = best_idx {
            // Put the previous task back to runnable.
            if self.current_idx < self.count
                && self.tasks[self.current_idx].active
                && self.tasks[self.current_idx].state == IdleTaskState::Running
            {
                self.tasks[self.current_idx].set_runnable();
            }

            self.tasks[idx].set_running();
            self.tasks[idx].reset_timeslice();
            self.current_idx = idx;
            self.rr_cursor = (idx + 1) % self.count.max(1);
            self.context_switches += 1;
            return Some(self.tasks[idx].task_id);
        }

        None
    }

    /// Handle a timer tick for the currently running task.
    ///
    /// Returns true if a reschedule is needed (timeslice expired).
    pub fn tick(&mut self, elapsed_us: u64) -> bool {
        if self.current_idx >= self.count {
            return false;
        }
        if !self.tasks[self.current_idx].active {
            return false;
        }
        self.tasks[self.current_idx].tick(elapsed_us)
    }

    /// Handle a voluntary yield from the current task.
    pub fn yield_current(&mut self) -> Result<()> {
        if self.current_idx >= self.count || !self.tasks[self.current_idx].active {
            return Err(Error::NotFound);
        }
        self.tasks[self.current_idx].set_yielded();
        self.current_idx = usize::MAX;
        Ok(())
    }

    /// Get the currently running task ID.
    pub fn current_task(&self) -> Option<u64> {
        if self.current_idx < self.count
            && self.tasks[self.current_idx].active
            && self.tasks[self.current_idx].state == IdleTaskState::Running
        {
            Some(self.tasks[self.current_idx].task_id)
        } else {
            None
        }
    }

    /// Get a reference to a task by ID.
    pub fn get_task(&self, task_id: u64) -> Option<&IdleTask> {
        for i in 0..self.count {
            if self.tasks[i].active && self.tasks[i].task_id == task_id {
                return Some(&self.tasks[i]);
            }
        }
        None
    }

    /// Set weight for a task.
    pub fn set_task_weight(&mut self, task_id: u64, weight: u32) -> Result<()> {
        for i in 0..self.count {
            if self.tasks[i].active && self.tasks[i].task_id == task_id {
                return self.tasks[i].set_weight(weight);
            }
        }
        Err(Error::NotFound)
    }

    /// Block a task (e.g., waiting on I/O).
    pub fn block_task(&mut self, task_id: u64) -> Result<()> {
        for i in 0..self.count {
            if self.tasks[i].active && self.tasks[i].task_id == task_id {
                self.tasks[i].set_blocked();
                if self.current_idx == i {
                    self.current_idx = usize::MAX;
                }
                return Ok(());
            }
        }
        Err(Error::NotFound)
    }

    /// Wake a blocked task (make it runnable again).
    pub fn wake_task(&mut self, task_id: u64) -> Result<()> {
        for i in 0..self.count {
            if self.tasks[i].active && self.tasks[i].task_id == task_id {
                if self.tasks[i].state != IdleTaskState::Blocked {
                    return Err(Error::InvalidArgument);
                }
                self.tasks[i].set_runnable();
                return Ok(());
            }
        }
        Err(Error::NotFound)
    }

    /// Get context switch count.
    pub const fn context_switches(&self) -> u64 {
        self.context_switches
    }

    /// Find a free task slot.
    fn find_free_slot(&self) -> Result<usize> {
        for i in 0..self.count {
            if !self.tasks[i].active {
                return Ok(i);
            }
        }
        if self.count < MAX_TASKS_PER_CPU {
            return Ok(self.count);
        }
        Err(Error::OutOfMemory)
    }
}

// ── IdleSchedulerStats ────────────────────────────────────────────────────────

/// Aggregate idle scheduler statistics.
#[derive(Debug, Clone, Copy)]
pub struct IdleSchedulerStats {
    /// Total idle tasks in the system.
    pub total_tasks: usize,
    /// Total runnable idle tasks.
    pub runnable_tasks: usize,
    /// Total blocked idle tasks.
    pub blocked_tasks: usize,
    /// Total context switches across all CPUs.
    pub total_context_switches: u64,
    /// Total runtime of all idle tasks (microseconds).
    pub total_runtime_us: u64,
}

impl IdleSchedulerStats {
    /// Create zeroed stats.
    pub const fn new() -> Self {
        Self {
            total_tasks: 0,
            runnable_tasks: 0,
            blocked_tasks: 0,
            total_context_switches: 0,
            total_runtime_us: 0,
        }
    }
}

impl Default for IdleSchedulerStats {
    fn default() -> Self {
        Self::new()
    }
}

// ── IdleScheduler ─────────────────────────────────────────────────────────────

/// Global SCHED_IDLE scheduler.
///
/// Manages per-CPU idle run queues and provides load balancing
/// between CPUs.
pub struct IdleScheduler {
    /// Per-CPU run queues.
    run_queues: [IdleRunQueue; MAX_CPUS],
    /// Number of active CPUs.
    nr_cpus: usize,
    /// Global timeslice setting.
    timeslice_us: u64,
}

impl IdleScheduler {
    /// Create a new idle scheduler.
    pub fn new(nr_cpus: usize) -> Self {
        let capped = nr_cpus.min(MAX_CPUS);
        let mut sched = Self {
            run_queues: [const { IdleRunQueue::new(0) }; MAX_CPUS],
            nr_cpus: capped,
            timeslice_us: DEFAULT_TIMESLICE_US,
        };
        for i in 0..capped {
            sched.run_queues[i] = IdleRunQueue::new(i as u32);
        }
        sched
    }

    /// Number of active CPUs.
    pub const fn nr_cpus(&self) -> usize {
        self.nr_cpus
    }

    /// Enqueue a task on a specific CPU.
    pub fn enqueue(&mut self, cpu: usize, task_id: u64) -> Result<()> {
        if cpu >= self.nr_cpus {
            return Err(Error::InvalidArgument);
        }
        self.run_queues[cpu].enqueue(task_id)
    }

    /// Dequeue a task from a specific CPU.
    pub fn dequeue(&mut self, cpu: usize, task_id: u64) -> Result<()> {
        if cpu >= self.nr_cpus {
            return Err(Error::InvalidArgument);
        }
        self.run_queues[cpu].dequeue(task_id)
    }

    /// Pick the next idle task on a specific CPU.
    pub fn pick_next_task(&mut self, cpu: usize) -> Option<u64> {
        if cpu >= self.nr_cpus {
            return None;
        }
        self.run_queues[cpu].pick_next_task()
    }

    /// Handle timer tick on a CPU.
    ///
    /// Returns true if a reschedule is needed.
    pub fn tick(&mut self, cpu: usize, elapsed_us: u64) -> bool {
        if cpu >= self.nr_cpus {
            return false;
        }
        self.run_queues[cpu].tick(elapsed_us)
    }

    /// Yield the current task on a CPU.
    pub fn yield_cpu(&mut self, cpu: usize) -> Result<()> {
        if cpu >= self.nr_cpus {
            return Err(Error::InvalidArgument);
        }
        self.run_queues[cpu].yield_current()
    }

    /// Balance load across CPUs.
    ///
    /// Finds the most-loaded and least-loaded CPUs and migrates
    /// one task if the imbalance exceeds a threshold.
    pub fn balance(&mut self) -> Option<(usize, usize, u64)> {
        if self.nr_cpus < 2 {
            return None;
        }

        // Find most-loaded and least-loaded CPUs.
        let mut max_cpu = 0;
        let mut max_count = 0usize;
        let mut min_cpu = 0;
        let mut min_count = usize::MAX;

        for i in 0..self.nr_cpus {
            let c = self.run_queues[i].runnable_count();
            if c > max_count {
                max_count = c;
                max_cpu = i;
            }
            if c < min_count {
                min_count = c;
                min_cpu = i;
            }
        }

        // Threshold: at least 2 more tasks on max than min.
        if max_cpu == min_cpu || max_count < min_count + 2 {
            return None;
        }

        // Find a runnable (non-running) task to migrate.
        let mut migrate_id = None;
        for i in 0..self.run_queues[max_cpu].count {
            let task = &self.run_queues[max_cpu].tasks[i];
            if task.active && task.state == IdleTaskState::Runnable {
                migrate_id = Some(task.task_id);
                break;
            }
        }

        let task_id = migrate_id?;

        // Dequeue from source, enqueue on destination.
        if self.run_queues[max_cpu].dequeue(task_id).is_ok()
            && self.run_queues[min_cpu].enqueue(task_id).is_ok()
        {
            return Some((max_cpu, min_cpu, task_id));
        }

        None
    }

    /// Get aggregate statistics.
    pub fn stats(&self) -> IdleSchedulerStats {
        let mut s = IdleSchedulerStats::new();
        for i in 0..self.nr_cpus {
            let rq = &self.run_queues[i];
            for j in 0..rq.count {
                let t = &rq.tasks[j];
                if !t.active {
                    continue;
                }
                s.total_tasks += 1;
                s.total_runtime_us += t.total_runtime_us;
                match t.state {
                    IdleTaskState::Runnable | IdleTaskState::Yielded => {
                        s.runnable_tasks += 1;
                    }
                    IdleTaskState::Blocked => {
                        s.blocked_tasks += 1;
                    }
                    IdleTaskState::Running => {
                        // Running tasks are counted as runnable.
                        s.runnable_tasks += 1;
                    }
                }
            }
            s.total_context_switches += rq.context_switches;
        }
        s
    }

    /// Get a reference to a CPU's run queue.
    pub fn run_queue(&self, cpu: usize) -> Result<&IdleRunQueue> {
        if cpu >= self.nr_cpus {
            return Err(Error::InvalidArgument);
        }
        Ok(&self.run_queues[cpu])
    }

    /// Get a mutable reference to a CPU's run queue.
    pub fn run_queue_mut(&mut self, cpu: usize) -> Result<&mut IdleRunQueue> {
        if cpu >= self.nr_cpus {
            return Err(Error::InvalidArgument);
        }
        Ok(&mut self.run_queues[cpu])
    }

    /// Set the global timeslice.
    pub fn set_timeslice(&mut self, us: u64) -> Result<()> {
        if us < MIN_TIMESLICE_US {
            return Err(Error::InvalidArgument);
        }
        self.timeslice_us = us;
        Ok(())
    }

    /// Get the global timeslice.
    pub const fn timeslice_us(&self) -> u64 {
        self.timeslice_us
    }
}

impl Default for IdleScheduler {
    fn default() -> Self {
        Self::new(1)
    }
}
