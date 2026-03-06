// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Softirq-tasklet bridge — manages tasklets scheduled via softirq.
//!
//! Tasklets are lightweight deferred functions scheduled through the
//! softirq mechanism. Unlike workqueues, tasklets run in softirq
//! context (not process context) and are serialised per-tasklet
//! (a given tasklet never runs concurrently on multiple CPUs).
//!
//! # Architecture
//!
//! ```text
//! TaskletScheduler
//!  ├── tasklets[MAX_TASKLETS]
//!  │    ├── id, func_id, data
//!  │    ├── state: TaskletState
//!  │    └── run_count, scheduled_cpu
//!  ├── per_cpu_pending[MAX_CPUS] (bitmask of pending tasklets)
//!  └── stats: TaskletSchedStats
//! ```
//!
//! # Reference
//!
//! Linux `kernel/softirq.c` — `tasklet_action()`.

use oncrix_lib::{Error, Result};

// ══════════════════════════════════════════════════════════════
// Constants
// ══════════════════════════════════════════════════════════════

/// Maximum registered tasklets.
const MAX_TASKLETS: usize = 128;

/// Maximum CPUs.
const MAX_CPUS: usize = 64;

// ══════════════════════════════════════════════════════════════
// TaskletState
// ══════════════════════════════════════════════════════════════

/// State of a tasklet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum TaskletState {
    /// Slot is free.
    Free = 0,
    /// Registered but not scheduled.
    Idle = 1,
    /// Scheduled (pending execution in softirq).
    Scheduled = 2,
    /// Currently executing.
    Running = 3,
    /// Disabled (will not run even if scheduled).
    Disabled = 4,
}

// ══════════════════════════════════════════════════════════════
// TaskletEntry
// ══════════════════════════════════════════════════════════════

/// A registered tasklet.
#[derive(Debug, Clone, Copy)]
pub struct TaskletEntry {
    /// Tasklet identifier.
    pub id: u32,
    /// Callback function identifier.
    pub func_id: u64,
    /// Callback data argument.
    pub data: u64,
    /// Current state.
    pub state: TaskletState,
    /// CPU this tasklet is scheduled on (-1 = none).
    pub scheduled_cpu: i32,
    /// Disable count (tasklet runs only when this is 0).
    pub disable_count: u32,
    /// Number of times this tasklet has run.
    pub run_count: u64,
    /// Whether this is a hi-priority tasklet.
    pub hi_priority: bool,
}

impl TaskletEntry {
    /// Create a free tasklet slot.
    const fn empty() -> Self {
        Self {
            id: 0,
            func_id: 0,
            data: 0,
            state: TaskletState::Free,
            scheduled_cpu: -1,
            disable_count: 0,
            run_count: 0,
            hi_priority: false,
        }
    }
}

// ══════════════════════════════════════════════════════════════
// PerCpuPending
// ══════════════════════════════════════════════════════════════

/// Per-CPU pending tasklet tracking.
#[derive(Debug, Clone, Copy)]
pub struct PerCpuPending {
    /// Number of pending normal-priority tasklets.
    pub normal_pending: u32,
    /// Number of pending hi-priority tasklets.
    pub hi_pending: u32,
    /// Total tasklets executed on this CPU.
    pub total_executed: u64,
}

impl PerCpuPending {
    /// Create a zeroed per-CPU entry.
    const fn new() -> Self {
        Self {
            normal_pending: 0,
            hi_pending: 0,
            total_executed: 0,
        }
    }
}

// ══════════════════════════════════════════════════════════════
// TaskletSchedStats
// ══════════════════════════════════════════════════════════════

/// Tasklet scheduler statistics.
#[derive(Debug, Clone, Copy)]
pub struct TaskletSchedStats {
    /// Total tasklets registered.
    pub total_registered: u64,
    /// Total schedule calls.
    pub total_scheduled: u64,
    /// Total tasklet runs.
    pub total_runs: u64,
    /// Total skipped runs (disabled tasklets).
    pub total_skipped: u64,
}

impl TaskletSchedStats {
    /// Create zeroed stats.
    const fn new() -> Self {
        Self {
            total_registered: 0,
            total_scheduled: 0,
            total_runs: 0,
            total_skipped: 0,
        }
    }
}

// ══════════════════════════════════════════════════════════════
// TaskletScheduler
// ══════════════════════════════════════════════════════════════

/// Manages tasklet registration, scheduling, and execution.
pub struct TaskletScheduler {
    /// Registered tasklets.
    tasklets: [TaskletEntry; MAX_TASKLETS],
    /// Per-CPU pending state.
    per_cpu: [PerCpuPending; MAX_CPUS],
    /// Next tasklet ID.
    next_id: u32,
    /// Statistics.
    stats: TaskletSchedStats,
}

impl TaskletScheduler {
    /// Create a new tasklet scheduler.
    pub const fn new() -> Self {
        Self {
            tasklets: [const { TaskletEntry::empty() }; MAX_TASKLETS],
            per_cpu: [const { PerCpuPending::new() }; MAX_CPUS],
            next_id: 1,
            stats: TaskletSchedStats::new(),
        }
    }

    /// Register a new tasklet.
    pub fn register(&mut self, func_id: u64, data: u64, hi_priority: bool) -> Result<u32> {
        let slot = self
            .tasklets
            .iter()
            .position(|t| matches!(t.state, TaskletState::Free))
            .ok_or(Error::OutOfMemory)?;
        let id = self.next_id;
        self.next_id += 1;
        self.tasklets[slot] = TaskletEntry {
            id,
            func_id,
            data,
            state: TaskletState::Idle,
            hi_priority,
            ..TaskletEntry::empty()
        };
        self.stats.total_registered += 1;
        Ok(id)
    }

    /// Schedule a tasklet to run on the given CPU.
    pub fn schedule(&mut self, tasklet_id: u32, cpu: u32) -> Result<()> {
        let slot = self.find_tasklet(tasklet_id)?;
        let c = cpu as usize;
        if c >= MAX_CPUS {
            return Err(Error::InvalidArgument);
        }
        if matches!(self.tasklets[slot].state, TaskletState::Disabled) {
            self.stats.total_skipped += 1;
            return Ok(());
        }
        self.tasklets[slot].state = TaskletState::Scheduled;
        self.tasklets[slot].scheduled_cpu = cpu as i32;
        if self.tasklets[slot].hi_priority {
            self.per_cpu[c].hi_pending += 1;
        } else {
            self.per_cpu[c].normal_pending += 1;
        }
        self.stats.total_scheduled += 1;
        Ok(())
    }

    /// Run all pending tasklets on a CPU. Returns run count.
    pub fn run_tasklets(&mut self, cpu: u32) -> Result<u32> {
        let c = cpu as usize;
        if c >= MAX_CPUS {
            return Err(Error::InvalidArgument);
        }
        let mut count = 0u32;
        for tasklet in &mut self.tasklets {
            if !matches!(tasklet.state, TaskletState::Scheduled) {
                continue;
            }
            if tasklet.scheduled_cpu != cpu as i32 {
                continue;
            }
            if tasklet.disable_count > 0 {
                continue;
            }
            tasklet.state = TaskletState::Running;
            tasklet.run_count += 1;
            count += 1;
            // After execution, return to idle.
            tasklet.state = TaskletState::Idle;
            tasklet.scheduled_cpu = -1;
        }
        self.per_cpu[c].normal_pending = 0;
        self.per_cpu[c].hi_pending = 0;
        self.per_cpu[c].total_executed += count as u64;
        self.stats.total_runs += count as u64;
        Ok(count)
    }

    /// Disable a tasklet (increment disable count).
    pub fn disable(&mut self, tasklet_id: u32) -> Result<()> {
        let slot = self.find_tasklet(tasklet_id)?;
        self.tasklets[slot].disable_count += 1;
        if self.tasklets[slot].disable_count == 1 {
            self.tasklets[slot].state = TaskletState::Disabled;
        }
        Ok(())
    }

    /// Enable a tasklet (decrement disable count).
    pub fn enable(&mut self, tasklet_id: u32) -> Result<()> {
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
    pub fn stats(&self) -> TaskletSchedStats {
        self.stats
    }

    // ── Internal ─────────────────────────────────────────────

    fn find_tasklet(&self, id: u32) -> Result<usize> {
        self.tasklets
            .iter()
            .position(|t| !matches!(t.state, TaskletState::Free) && t.id == id)
            .ok_or(Error::NotFound)
    }
}
