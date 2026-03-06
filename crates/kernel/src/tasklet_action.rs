// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Tasklet action processing — executing scheduled tasklet callbacks.
//!
//! Tasklets run in softirq context and provide a simpler deferred
//! execution mechanism than work queues.  Each tasklet is guaranteed
//! to run on only one CPU at a time, simplifying synchronization.
//!
//! # Reference
//!
//! Linux `kernel/softirq.c` (tasklet_action, tasklet_hi_action).

use oncrix_lib::{Error, Result};

const MAX_TASKLETS: usize = 256;
const MAX_CPUS: usize = 64;

/// State of a tasklet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum TaskletState {
    /// Slot is free.
    Free = 0,
    /// Tasklet is registered but not scheduled.
    Idle = 1,
    /// Tasklet is scheduled and pending execution.
    Scheduled = 2,
    /// Tasklet is currently running.
    Running = 3,
    /// Tasklet is disabled (will not run even if scheduled).
    Disabled = 4,
}

/// Priority of a tasklet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum TaskletPriority {
    /// Normal priority (TASKLET_SOFTIRQ).
    Normal = 0,
    /// High priority (HI_SOFTIRQ).
    High = 1,
}

/// Tasklet callback function.
pub type TaskletFn = fn(u64);

/// A registered tasklet.
#[derive(Debug, Clone, Copy)]
pub struct TaskletEntry {
    /// Tasklet identifier.
    pub tasklet_id: u64,
    /// Callback function.
    pub handler: Option<TaskletFn>,
    /// Opaque data passed to the handler.
    pub data: u64,
    /// Current state.
    pub state: TaskletState,
    /// Priority.
    pub priority: TaskletPriority,
    /// CPU the tasklet is bound to (-1 = any).
    pub bound_cpu: i16,
    /// Number of times the tasklet has run.
    pub run_count: u64,
    /// Disable count (tasklet runs only when 0).
    pub disable_count: u32,
}

impl TaskletEntry {
    const fn empty() -> Self {
        Self {
            tasklet_id: 0,
            handler: None,
            data: 0,
            state: TaskletState::Free,
            priority: TaskletPriority::Normal,
            bound_cpu: -1,
            run_count: 0,
            disable_count: 0,
        }
    }

    /// Returns `true` if the tasklet is registered.
    pub const fn is_active(&self) -> bool {
        !matches!(self.state, TaskletState::Free)
    }
}

/// Per-CPU tasklet queue.
#[derive(Debug, Clone, Copy)]
pub struct PerCpuQueue {
    /// Indices of scheduled tasklets for this CPU.
    pub queue: [u16; 64],
    /// Number of tasklets in the queue.
    pub count: usize,
    /// Total tasklets processed.
    pub processed: u64,
}

impl PerCpuQueue {
    const fn new() -> Self {
        Self {
            queue: [0u16; 64],
            count: 0,
            processed: 0,
        }
    }
}

/// Statistics for tasklet actions.
#[derive(Debug, Clone, Copy)]
pub struct TaskletActionStats {
    /// Total tasklets scheduled.
    pub total_scheduled: u64,
    /// Total tasklets executed.
    pub total_executed: u64,
    /// Total tasklets skipped (disabled).
    pub total_skipped: u64,
    /// Total scheduling conflicts.
    pub total_conflicts: u64,
}

impl TaskletActionStats {
    const fn new() -> Self {
        Self {
            total_scheduled: 0,
            total_executed: 0,
            total_skipped: 0,
            total_conflicts: 0,
        }
    }
}

/// Top-level tasklet action subsystem.
pub struct TaskletActionProcessor {
    /// Registered tasklets.
    tasklets: [TaskletEntry; MAX_TASKLETS],
    /// Per-CPU queues.
    per_cpu: [PerCpuQueue; MAX_CPUS],
    /// Statistics.
    stats: TaskletActionStats,
    /// Next tasklet ID.
    next_id: u64,
    /// Whether the subsystem is initialised.
    initialised: bool,
}

impl Default for TaskletActionProcessor {
    fn default() -> Self {
        Self::new()
    }
}

impl TaskletActionProcessor {
    /// Create a new tasklet action processor.
    pub const fn new() -> Self {
        Self {
            tasklets: [const { TaskletEntry::empty() }; MAX_TASKLETS],
            per_cpu: [const { PerCpuQueue::new() }; MAX_CPUS],
            stats: TaskletActionStats::new(),
            next_id: 1,
            initialised: false,
        }
    }

    /// Initialise the subsystem.
    pub fn init(&mut self) -> Result<()> {
        if self.initialised {
            return Err(Error::AlreadyExists);
        }
        self.initialised = true;
        Ok(())
    }

    /// Register a tasklet.
    pub fn register(
        &mut self,
        handler: TaskletFn,
        data: u64,
        priority: TaskletPriority,
    ) -> Result<u64> {
        let slot = self
            .tasklets
            .iter()
            .position(|t| matches!(t.state, TaskletState::Free))
            .ok_or(Error::OutOfMemory)?;

        let tasklet_id = self.next_id;
        self.next_id += 1;

        self.tasklets[slot] = TaskletEntry {
            tasklet_id,
            handler: Some(handler),
            data,
            state: TaskletState::Idle,
            priority,
            bound_cpu: -1,
            run_count: 0,
            disable_count: 0,
        };
        Ok(tasklet_id)
    }

    /// Schedule a tasklet for execution.
    pub fn schedule(&mut self, tasklet_id: u64, cpu: usize) -> Result<()> {
        if cpu >= MAX_CPUS {
            return Err(Error::InvalidArgument);
        }
        let slot = self.find_tasklet(tasklet_id)?;

        if matches!(
            self.tasklets[slot].state,
            TaskletState::Scheduled | TaskletState::Running
        ) {
            self.stats.total_conflicts += 1;
            return Ok(());
        }

        self.tasklets[slot].state = TaskletState::Scheduled;

        let queue_idx = self.per_cpu[cpu].count;
        if queue_idx < 64 {
            self.per_cpu[cpu].queue[queue_idx] = slot as u16;
            self.per_cpu[cpu].count += 1;
        }

        self.stats.total_scheduled += 1;
        Ok(())
    }

    /// Process all pending tasklets on a CPU.
    pub fn process(&mut self, cpu: usize) -> Result<usize> {
        if cpu >= MAX_CPUS {
            return Err(Error::InvalidArgument);
        }

        let count = self.per_cpu[cpu].count;
        let mut executed = 0usize;

        for i in 0..count {
            let slot = self.per_cpu[cpu].queue[i] as usize;
            if slot >= MAX_TASKLETS {
                continue;
            }

            if self.tasklets[slot].disable_count > 0 {
                self.stats.total_skipped += 1;
                self.tasklets[slot].state = TaskletState::Disabled;
                continue;
            }

            if !matches!(self.tasklets[slot].state, TaskletState::Scheduled) {
                continue;
            }

            self.tasklets[slot].state = TaskletState::Running;
            if let Some(handler) = self.tasklets[slot].handler {
                let data = self.tasklets[slot].data;
                handler(data);
            }
            self.tasklets[slot].run_count += 1;
            self.tasklets[slot].state = TaskletState::Idle;
            executed += 1;
        }

        self.per_cpu[cpu].count = 0;
        self.per_cpu[cpu].processed += executed as u64;
        self.stats.total_executed += executed as u64;
        Ok(executed)
    }

    /// Disable a tasklet (increment disable count).
    pub fn disable(&mut self, tasklet_id: u64) -> Result<()> {
        let slot = self.find_tasklet(tasklet_id)?;
        self.tasklets[slot].disable_count += 1;
        Ok(())
    }

    /// Enable a tasklet (decrement disable count).
    pub fn enable(&mut self, tasklet_id: u64) -> Result<()> {
        let slot = self.find_tasklet(tasklet_id)?;
        self.tasklets[slot].disable_count = self.tasklets[slot].disable_count.saturating_sub(1);
        if self.tasklets[slot].disable_count == 0
            && matches!(self.tasklets[slot].state, TaskletState::Disabled)
        {
            self.tasklets[slot].state = TaskletState::Idle;
        }
        Ok(())
    }

    /// Return statistics.
    pub fn stats(&self) -> TaskletActionStats {
        self.stats
    }

    /// Return the number of registered tasklets.
    pub fn registered_count(&self) -> usize {
        self.tasklets.iter().filter(|t| t.is_active()).count()
    }

    fn find_tasklet(&self, tasklet_id: u64) -> Result<usize> {
        self.tasklets
            .iter()
            .position(|t| t.is_active() && t.tasklet_id == tasklet_id)
            .ok_or(Error::NotFound)
    }
}
