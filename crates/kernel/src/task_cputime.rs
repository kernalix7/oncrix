// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Per-task CPU time accounting.
//!
//! Tracks user, system, and guest CPU time consumed by individual tasks.
//! Provides the backing data for:
//! - `getrusage(2)` — per-process resource usage
//! - `times(2)` — process and child times
//! - `/proc/[pid]/stat` — per-task CPU time fields
//! - `clock_gettime(CLOCK_THREAD_CPUTIME_ID)` — thread CPU clock
//!
//! # Architecture
//!
//! ```text
//! ┌───────────────────────────────────────────────────────────────┐
//! │                  CpuTimeAccounting                            │
//! │                                                               │
//! │  [TaskCpuTime; MAX_TASKS]  — per-task time records            │
//! │  ┌─────────────────────────────────────────────────────────┐  │
//! │  │  CpuTimeStats — user / system / guest / irq / softirq   │  │
//! │  │  last_update_ns — timestamp of last accounting update    │  │
//! │  │  AccountingState — lifecycle state                       │  │
//! │  └─────────────────────────────────────────────────────────┘  │
//! │                                                               │
//! │  AccountingStats — global counters                            │
//! └───────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Time Units
//!
//! All times are tracked in nanoseconds. Callers that need
//! microseconds or clock ticks must convert.
//!
//! # Reference
//!
//! POSIX.1-2024 §times(), §getrusage(), §clock_gettime();
//! Linux `kernel/sched/cputime.c`.

use oncrix_lib::{Error, Result};

// ── Constants ────────────────────────────────────────────────────────────────

/// Maximum tasks tracked concurrently.
const MAX_TASKS: usize = 256;

/// Nanoseconds per microsecond.
const _NANOS_PER_USEC: u64 = 1_000;

/// Nanoseconds per millisecond.
const _NANOS_PER_MSEC: u64 = 1_000_000;

/// Nanoseconds per second.
const NANOS_PER_SEC: u64 = 1_000_000_000;

/// Assumed clock ticks per second for `times()` emulation.
const TICKS_PER_SEC: u64 = 100;

// ── CpuTimeCategory ─────────────────────────────────────────────────────────

/// Category of CPU time being accounted.
///
/// Determines which counter to increment when the scheduler
/// charges time to a task.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CpuTimeCategory {
    /// User-space execution (non-guest).
    User,
    /// Kernel execution on behalf of this task.
    System,
    /// Running a virtual CPU for a guest OS.
    Guest,
    /// Servicing a hardware interrupt attributed to this task.
    Irq,
    /// Servicing a software interrupt attributed to this task.
    SoftIrq,
}

impl Default for CpuTimeCategory {
    fn default() -> Self {
        Self::User
    }
}

// ── AccountingState ─────────────────────────────────────────────────────────

/// Lifecycle state of a per-task accounting record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccountingState {
    /// Slot is free.
    Free,
    /// Task is being tracked.
    Active,
    /// Task has exited; times are final but retained for
    /// parent retrieval via `wait`.
    Exited,
}

impl Default for AccountingState {
    fn default() -> Self {
        Self::Free
    }
}

// ── CpuTimeStats ────────────────────────────────────────────────────────────

/// Accumulated CPU time broken down by category for a single task.
#[derive(Debug, Clone, Copy, Default)]
pub struct CpuTimeStats {
    /// Nanoseconds spent executing in user mode.
    pub user_ns: u64,
    /// Nanoseconds spent executing in kernel mode.
    pub system_ns: u64,
    /// Nanoseconds spent executing guest code.
    pub guest_ns: u64,
    /// Nanoseconds spent in hardware interrupt handlers.
    pub irq_ns: u64,
    /// Nanoseconds spent in software interrupt handlers.
    pub softirq_ns: u64,
    /// Voluntary context switches.
    pub voluntary_switches: u64,
    /// Involuntary context switches (preemption).
    pub involuntary_switches: u64,
}

impl CpuTimeStats {
    /// Total CPU time across all categories.
    pub fn total_ns(&self) -> u64 {
        self.user_ns
            .saturating_add(self.system_ns)
            .saturating_add(self.guest_ns)
            .saturating_add(self.irq_ns)
            .saturating_add(self.softirq_ns)
    }

    /// User + system time in nanoseconds (for `getrusage`).
    pub fn utime_stime_ns(&self) -> (u64, u64) {
        (self.user_ns, self.system_ns)
    }

    /// Convert user time to clock ticks (for `times()`).
    pub fn user_ticks(&self) -> u64 {
        self.user_ns / (NANOS_PER_SEC / TICKS_PER_SEC)
    }

    /// Convert system time to clock ticks (for `times()`).
    pub fn system_ticks(&self) -> u64 {
        self.system_ns / (NANOS_PER_SEC / TICKS_PER_SEC)
    }

    /// Add another stats record into this one (for child aggregation).
    pub fn accumulate(&mut self, other: &CpuTimeStats) {
        self.user_ns = self.user_ns.saturating_add(other.user_ns);
        self.system_ns = self.system_ns.saturating_add(other.system_ns);
        self.guest_ns = self.guest_ns.saturating_add(other.guest_ns);
        self.irq_ns = self.irq_ns.saturating_add(other.irq_ns);
        self.softirq_ns = self.softirq_ns.saturating_add(other.softirq_ns);
        self.voluntary_switches = self
            .voluntary_switches
            .saturating_add(other.voluntary_switches);
        self.involuntary_switches = self
            .involuntary_switches
            .saturating_add(other.involuntary_switches);
    }

    /// Charge `delta_ns` nanoseconds to the specified category.
    pub fn charge(&mut self, category: CpuTimeCategory, delta_ns: u64) {
        match category {
            CpuTimeCategory::User => {
                self.user_ns = self.user_ns.saturating_add(delta_ns);
            }
            CpuTimeCategory::System => {
                self.system_ns = self.system_ns.saturating_add(delta_ns);
            }
            CpuTimeCategory::Guest => {
                self.guest_ns = self.guest_ns.saturating_add(delta_ns);
            }
            CpuTimeCategory::Irq => {
                self.irq_ns = self.irq_ns.saturating_add(delta_ns);
            }
            CpuTimeCategory::SoftIrq => {
                self.softirq_ns = self.softirq_ns.saturating_add(delta_ns);
            }
        }
    }
}

// ── TaskCpuTime ─────────────────────────────────────────────────────────────

/// Per-task CPU time accounting record.
///
/// Tracks the task's own CPU consumption and accumulated child times
/// (reported via `wait` after child exit).
#[derive(Debug, Clone, Copy)]
pub struct TaskCpuTime {
    /// Task identifier.
    pub task_id: u64,
    /// Parent task identifier (for child-time rollup).
    pub parent_id: u64,
    /// The task's own CPU times.
    pub self_times: CpuTimeStats,
    /// Accumulated child CPU times (updated when children exit).
    pub child_times: CpuTimeStats,
    /// Timestamp (ns since boot) of the last accounting update.
    pub last_update_ns: u64,
    /// Timestamp (ns since boot) when the task was created.
    pub start_time_ns: u64,
    /// Accounting state.
    pub state: AccountingState,
    /// CPU on which the task is currently running (or last ran).
    pub current_cpu: u32,
    /// Category of time currently being accumulated.
    pub current_category: CpuTimeCategory,
}

impl Default for TaskCpuTime {
    fn default() -> Self {
        Self {
            task_id: 0,
            parent_id: 0,
            self_times: CpuTimeStats::default(),
            child_times: CpuTimeStats::default(),
            last_update_ns: 0,
            start_time_ns: 0,
            state: AccountingState::Free,
            current_cpu: 0,
            current_category: CpuTimeCategory::User,
        }
    }
}

// ── AccountingStats ─────────────────────────────────────────────────────────

/// Global statistics for the CPU time accounting subsystem.
#[derive(Debug, Clone, Copy, Default)]
pub struct AccountingStats {
    /// Number of active task records.
    pub active_tasks: u64,
    /// Total charge operations performed.
    pub charge_ops: u64,
    /// Total nanoseconds charged across all tasks.
    pub total_charged_ns: u64,
    /// Total task registrations.
    pub registrations: u64,
    /// Total task unregistrations.
    pub unregistrations: u64,
    /// Total child-time rollups.
    pub child_rollups: u64,
}

// ── CpuTimeAccounting ───────────────────────────────────────────────────────

/// System-wide per-task CPU time accounting subsystem.
///
/// Maintains a fixed-size table of [`TaskCpuTime`] records and exposes
/// operations used by the scheduler to charge time to tasks.
pub struct CpuTimeAccounting {
    /// Per-task time records.
    tasks: [TaskCpuTime; MAX_TASKS],
    /// Number of active records.
    active_count: usize,
    /// Global statistics.
    stats: AccountingStats,
}

impl Default for CpuTimeAccounting {
    fn default() -> Self {
        Self::new()
    }
}

impl CpuTimeAccounting {
    /// Create a new, empty accounting subsystem.
    pub const fn new() -> Self {
        const EMPTY: TaskCpuTime = TaskCpuTime {
            task_id: 0,
            parent_id: 0,
            self_times: CpuTimeStats {
                user_ns: 0,
                system_ns: 0,
                guest_ns: 0,
                irq_ns: 0,
                softirq_ns: 0,
                voluntary_switches: 0,
                involuntary_switches: 0,
            },
            child_times: CpuTimeStats {
                user_ns: 0,
                system_ns: 0,
                guest_ns: 0,
                irq_ns: 0,
                softirq_ns: 0,
                voluntary_switches: 0,
                involuntary_switches: 0,
            },
            last_update_ns: 0,
            start_time_ns: 0,
            state: AccountingState::Free,
            current_cpu: 0,
            current_category: CpuTimeCategory::User,
        };
        Self {
            tasks: [EMPTY; MAX_TASKS],
            active_count: 0,
            stats: AccountingStats {
                active_tasks: 0,
                charge_ops: 0,
                total_charged_ns: 0,
                registrations: 0,
                unregistrations: 0,
                child_rollups: 0,
            },
        }
    }

    /// Register a new task for CPU time tracking.
    ///
    /// # Errors
    ///
    /// - [`Error::OutOfMemory`] if the table is full.
    /// - [`Error::AlreadyExists`] if `task_id` is already registered.
    pub fn register(&mut self, task_id: u64, parent_id: u64, now_ns: u64) -> Result<()> {
        if self.find_index(task_id).is_some() {
            return Err(Error::AlreadyExists);
        }
        let idx = self.find_free_slot()?;
        self.tasks[idx] = TaskCpuTime {
            task_id,
            parent_id,
            self_times: CpuTimeStats::default(),
            child_times: CpuTimeStats::default(),
            last_update_ns: now_ns,
            start_time_ns: now_ns,
            state: AccountingState::Active,
            current_cpu: 0,
            current_category: CpuTimeCategory::User,
        };
        self.active_count += 1;
        self.stats.active_tasks = self.active_count as u64;
        self.stats.registrations += 1;
        Ok(())
    }

    /// Unregister a task and roll its times into its parent's
    /// child-time accumulator.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] if `task_id` is not registered.
    pub fn unregister(&mut self, task_id: u64) -> Result<()> {
        let idx = self.find_index(task_id).ok_or(Error::NotFound)?;

        let record = self.tasks[idx];

        // Roll up self-times into parent's child-times.
        if let Some(parent_idx) = self.find_index(record.parent_id) {
            self.tasks[parent_idx]
                .child_times
                .accumulate(&record.self_times);
            self.stats.child_rollups += 1;
        }

        self.tasks[idx] = TaskCpuTime::default();
        self.active_count -= 1;
        self.stats.active_tasks = self.active_count as u64;
        self.stats.unregistrations += 1;
        Ok(())
    }

    /// Charge CPU time to `task_id`.
    ///
    /// Called by the scheduler on timer ticks or context switches.
    /// `now_ns` is the current monotonic time. The delta since the last
    /// update is charged to the task's current accounting category.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] if `task_id` is not registered.
    pub fn charge(&mut self, task_id: u64, now_ns: u64) -> Result<u64> {
        let idx = self.find_index(task_id).ok_or(Error::NotFound)?;
        let record = &mut self.tasks[idx];

        let delta = now_ns.saturating_sub(record.last_update_ns);
        record.self_times.charge(record.current_category, delta);
        record.last_update_ns = now_ns;

        self.stats.charge_ops += 1;
        self.stats.total_charged_ns = self.stats.total_charged_ns.saturating_add(delta);

        Ok(delta)
    }

    /// Switch the accounting category for `task_id`.
    ///
    /// Flushes accumulated time under the old category before switching.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] if `task_id` is not registered.
    pub fn switch_category(
        &mut self,
        task_id: u64,
        now_ns: u64,
        new_category: CpuTimeCategory,
    ) -> Result<()> {
        self.charge(task_id, now_ns)?;
        let idx = self.find_index(task_id).ok_or(Error::NotFound)?;
        self.tasks[idx].current_category = new_category;
        Ok(())
    }

    /// Record a voluntary context switch for `task_id`.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] if `task_id` is not registered.
    pub fn record_voluntary_switch(&mut self, task_id: u64) -> Result<()> {
        let idx = self.find_index(task_id).ok_or(Error::NotFound)?;
        self.tasks[idx].self_times.voluntary_switches += 1;
        Ok(())
    }

    /// Record an involuntary context switch for `task_id`.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] if `task_id` is not registered.
    pub fn record_involuntary_switch(&mut self, task_id: u64) -> Result<()> {
        let idx = self.find_index(task_id).ok_or(Error::NotFound)?;
        self.tasks[idx].self_times.involuntary_switches += 1;
        Ok(())
    }

    /// Set the CPU on which `task_id` is running.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] if `task_id` is not registered.
    pub fn set_current_cpu(&mut self, task_id: u64, cpu: u32) -> Result<()> {
        let idx = self.find_index(task_id).ok_or(Error::NotFound)?;
        self.tasks[idx].current_cpu = cpu;
        Ok(())
    }

    /// Query the self-times for `task_id`.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] if `task_id` is not registered.
    pub fn get_self_times(&self, task_id: u64) -> Result<&CpuTimeStats> {
        let idx = self.find_index(task_id).ok_or(Error::NotFound)?;
        Ok(&self.tasks[idx].self_times)
    }

    /// Query the child-times for `task_id`.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] if `task_id` is not registered.
    pub fn get_child_times(&self, task_id: u64) -> Result<&CpuTimeStats> {
        let idx = self.find_index(task_id).ok_or(Error::NotFound)?;
        Ok(&self.tasks[idx].child_times)
    }

    /// Query the wall-clock elapsed time since task creation.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] if `task_id` is not registered.
    pub fn elapsed_ns(&self, task_id: u64, now_ns: u64) -> Result<u64> {
        let idx = self.find_index(task_id).ok_or(Error::NotFound)?;
        Ok(now_ns.saturating_sub(self.tasks[idx].start_time_ns))
    }

    /// Return a snapshot of global accounting statistics.
    pub fn stats(&self) -> &AccountingStats {
        &self.stats
    }

    /// Return the number of active task records.
    pub fn active_count(&self) -> usize {
        self.active_count
    }

    // ── Private helpers ──────────────────────────────────────────

    /// Find the table index for `task_id`.
    fn find_index(&self, task_id: u64) -> Option<usize> {
        self.tasks
            .iter()
            .position(|t| t.state != AccountingState::Free && t.task_id == task_id)
    }

    /// Find a free slot in the table.
    fn find_free_slot(&self) -> Result<usize> {
        self.tasks
            .iter()
            .position(|t| t.state == AccountingState::Free)
            .ok_or(Error::OutOfMemory)
    }
}
