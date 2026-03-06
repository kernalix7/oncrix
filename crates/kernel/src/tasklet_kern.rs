// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Tasklet deferred work mechanism.
//!
//! Tasklets are a lightweight deferred-work mechanism built on top
//! of softirqs. Unlike softirqs, a given tasklet is guaranteed to
//! run on only one CPU at a time (serialised), making them easier
//! to use for device driver bottom halves.
//!
//! # State Machine
//!
//! ```text
//! IDLE ──schedule()──→ SCHED ──softirq fires──→ RUN ──done──→ IDLE
//!                         │                        │
//!                         └── already SCHED? skip ─┘
//! ```
//!
//! # Priority
//!
//! - `tasklet_schedule()` — uses TASKLET_SOFTIRQ (normal priority)
//! - `tasklet_hi_schedule()` — uses HI_SOFTIRQ (high priority)
//!
//! # Usage
//!
//! ```ignore
//! let mut mgr = TaskletManager::new();
//! mgr.init()?;
//! let id = mgr.create(my_handler, 42)?;
//! mgr.schedule(id, 0)?;       // Queue on CPU 0
//! mgr.process_tasklets(0)?;   // Run pending tasklets on CPU 0
//! ```
//!
//! # Reference
//!
//! Linux `kernel/softirq.c` (tasklet_action/tasklet_hi_action),
//! `include/linux/interrupt.h`.

use oncrix_lib::{Error, Result};

// ── Constants ────────────────────────────────────────────────

/// Maximum number of tasklets.
const MAX_TASKLETS: usize = 256;

/// Maximum per-CPU pending list size.
const MAX_PER_CPU_PENDING: usize = 64;

/// Maximum number of CPUs.
const MAX_CPUS: usize = 32;

// ── TaskletState ────────────────────────────────────────────

/// State of a tasklet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TaskletState {
    /// Tasklet is idle (not scheduled).
    #[default]
    Idle,
    /// Tasklet is scheduled but not yet running.
    Scheduled,
    /// Tasklet is currently running on a CPU.
    Running,
    /// Tasklet is disabled (will not run even if scheduled).
    Disabled,
}

// ── TaskletPriority ─────────────────────────────────────────

/// Priority level of a tasklet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TaskletPriority {
    /// Normal priority (TASKLET_SOFTIRQ).
    #[default]
    Normal,
    /// High priority (HI_SOFTIRQ).
    High,
}

impl TaskletPriority {
    /// Human-readable name.
    pub fn name(self) -> &'static str {
        match self {
            Self::Normal => "normal",
            Self::High => "high",
        }
    }
}

// ── TaskletFn ───────────────────────────────────────────────

/// Callback function type for tasklets.
///
/// The `u64` parameter is an opaque data value set at creation.
pub type TaskletFn = fn(u64);

// ── TaskletStruct ───────────────────────────────────────────

/// A tasklet registration.
#[derive(Clone, Copy)]
pub struct TaskletStruct {
    /// Unique tasklet ID.
    id: u32,
    /// Callback function.
    func: Option<TaskletFn>,
    /// Opaque data passed to the callback.
    data: u64,
    /// Current state.
    state: TaskletState,
    /// Priority level.
    priority: TaskletPriority,
    /// Disable count (>0 means disabled).
    disable_count: u32,
    /// Number of times this tasklet has run.
    run_count: u64,
    /// CPU it was last scheduled on.
    last_cpu: u32,
    /// Whether this slot is active.
    active: bool,
}

impl core::fmt::Debug for TaskletStruct {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("TaskletStruct")
            .field("id", &self.id)
            .field("state", &self.state)
            .field("priority", &self.priority)
            .field("disable_count", &self.disable_count)
            .field("run_count", &self.run_count)
            .finish()
    }
}

impl TaskletStruct {
    /// Create an empty tasklet.
    const fn empty() -> Self {
        Self {
            id: 0,
            func: None,
            data: 0,
            state: TaskletState::Idle,
            priority: TaskletPriority::Normal,
            disable_count: 0,
            run_count: 0,
            last_cpu: 0,
            active: false,
        }
    }

    /// Tasklet ID.
    pub fn id(&self) -> u32 {
        self.id
    }

    /// Current state.
    pub fn state(&self) -> TaskletState {
        self.state
    }

    /// Priority.
    pub fn priority(&self) -> TaskletPriority {
        self.priority
    }

    /// Number of times run.
    pub fn run_count(&self) -> u64 {
        self.run_count
    }

    /// Whether the tasklet is disabled.
    pub fn is_disabled(&self) -> bool {
        self.disable_count > 0
    }

    /// Whether the tasklet can run now.
    pub fn can_run(&self) -> bool {
        self.state == TaskletState::Scheduled && self.disable_count == 0
    }
}

// ── PerCpuTaskletList ───────────────────────────────────────

/// Per-CPU list of pending tasklet IDs.
struct PerCpuTaskletList {
    /// Normal-priority pending tasklet IDs.
    normal: [u32; MAX_PER_CPU_PENDING],
    /// Number of normal-priority pending.
    normal_count: usize,
    /// High-priority pending tasklet IDs.
    high: [u32; MAX_PER_CPU_PENDING],
    /// Number of high-priority pending.
    high_count: usize,
    /// Whether initialized.
    initialized: bool,
}

impl PerCpuTaskletList {
    /// Create an empty list.
    const fn new() -> Self {
        Self {
            normal: [0; MAX_PER_CPU_PENDING],
            normal_count: 0,
            high: [0; MAX_PER_CPU_PENDING],
            high_count: 0,
            initialized: false,
        }
    }

    /// Add a tasklet to the normal list.
    fn add_normal(&mut self, tasklet_id: u32) -> Result<()> {
        if self.normal_count >= MAX_PER_CPU_PENDING {
            return Err(Error::OutOfMemory);
        }
        self.normal[self.normal_count] = tasklet_id;
        self.normal_count += 1;
        Ok(())
    }

    /// Add a tasklet to the high-priority list.
    fn add_high(&mut self, tasklet_id: u32) -> Result<()> {
        if self.high_count >= MAX_PER_CPU_PENDING {
            return Err(Error::OutOfMemory);
        }
        self.high[self.high_count] = tasklet_id;
        self.high_count += 1;
        Ok(())
    }

    /// Take all normal-priority tasklet IDs.
    fn take_normal(&mut self, out: &mut [u32]) -> usize {
        let count = self.normal_count.min(out.len());
        out[..count].copy_from_slice(&self.normal[..count]);
        self.normal_count = 0;
        count
    }

    /// Take all high-priority tasklet IDs.
    fn take_high(&mut self, out: &mut [u32]) -> usize {
        let count = self.high_count.min(out.len());
        out[..count].copy_from_slice(&self.high[..count]);
        self.high_count = 0;
        count
    }
}

// ── TaskletStats ────────────────────────────────────────────

/// Tasklet subsystem statistics.
#[derive(Debug, Clone, Copy, Default)]
pub struct TaskletStats {
    /// Total tasklets created.
    pub created: u64,
    /// Total tasklets destroyed.
    pub destroyed: u64,
    /// Total schedule calls.
    pub scheduled: u64,
    /// Total high-priority schedule calls.
    pub hi_scheduled: u64,
    /// Total tasklet executions.
    pub executed: u64,
    /// Total skipped (disabled or already running).
    pub skipped: u64,
}

impl TaskletStats {
    /// Create zeroed stats.
    pub const fn new() -> Self {
        Self {
            created: 0,
            destroyed: 0,
            scheduled: 0,
            hi_scheduled: 0,
            executed: 0,
            skipped: 0,
        }
    }
}

// ── TaskletManager ──────────────────────────────────────────

/// Central tasklet manager.
pub struct TaskletManager {
    /// All tasklets.
    tasklets: [TaskletStruct; MAX_TASKLETS],
    /// Per-CPU pending lists.
    per_cpu: [PerCpuTaskletList; MAX_CPUS],
    /// Number of active tasklets.
    tasklet_count: usize,
    /// Next tasklet ID.
    next_id: u32,
    /// Statistics.
    stats: TaskletStats,
    /// Whether initialized.
    initialized: bool,
}

impl TaskletManager {
    /// Create a new tasklet manager.
    pub const fn new() -> Self {
        Self {
            tasklets: [TaskletStruct::empty(); MAX_TASKLETS],
            per_cpu: [const { PerCpuTaskletList::new() }; MAX_CPUS],
            tasklet_count: 0,
            next_id: 1,
            stats: TaskletStats::new(),
            initialized: false,
        }
    }

    /// Initialize the manager.
    pub fn init(&mut self) -> Result<()> {
        if self.initialized {
            return Err(Error::AlreadyExists);
        }
        self.initialized = true;
        Ok(())
    }

    /// Register a CPU.
    pub fn register_cpu(&mut self, cpu_id: u32) -> Result<()> {
        let idx = cpu_id as usize;
        if idx >= MAX_CPUS {
            return Err(Error::InvalidArgument);
        }
        self.per_cpu[idx].initialized = true;
        Ok(())
    }

    /// Create a new tasklet. Returns the tasklet ID.
    pub fn create(&mut self, func: TaskletFn, data: u64) -> Result<u32> {
        let slot = self
            .tasklets
            .iter()
            .position(|t| !t.active)
            .ok_or(Error::OutOfMemory)?;

        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);

        self.tasklets[slot] = TaskletStruct {
            id,
            func: Some(func),
            data,
            state: TaskletState::Idle,
            priority: TaskletPriority::Normal,
            disable_count: 0,
            run_count: 0,
            last_cpu: 0,
            active: true,
        };
        self.tasklet_count += 1;
        self.stats.created += 1;
        Ok(id)
    }

    /// Create a high-priority tasklet.
    pub fn create_hi(&mut self, func: TaskletFn, data: u64) -> Result<u32> {
        let id = self.create(func, data)?;
        if let Some(t) = self.find_mut(id) {
            t.priority = TaskletPriority::High;
        }
        Ok(id)
    }

    /// Destroy a tasklet.
    pub fn destroy(&mut self, tasklet_id: u32) -> Result<()> {
        let t = self
            .tasklets
            .iter_mut()
            .find(|t| t.active && t.id == tasklet_id)
            .ok_or(Error::NotFound)?;
        if t.state == TaskletState::Running {
            return Err(Error::Busy);
        }
        t.active = false;
        self.tasklet_count = self.tasklet_count.saturating_sub(1);
        self.stats.destroyed += 1;
        Ok(())
    }

    /// Schedule a tasklet on a CPU (normal priority).
    pub fn schedule(&mut self, tasklet_id: u32, cpu: u32) -> Result<()> {
        let cpu_idx = cpu as usize;
        if cpu_idx >= MAX_CPUS || !self.per_cpu[cpu_idx].initialized {
            return Err(Error::InvalidArgument);
        }

        let t = self
            .tasklets
            .iter_mut()
            .find(|t| t.active && t.id == tasklet_id)
            .ok_or(Error::NotFound)?;

        if t.state == TaskletState::Scheduled || t.state == TaskletState::Running {
            return Ok(()); // Already scheduled or running.
        }

        t.state = TaskletState::Scheduled;
        t.last_cpu = cpu;

        match t.priority {
            TaskletPriority::Normal => {
                self.per_cpu[cpu_idx].add_normal(tasklet_id)?;
                self.stats.scheduled += 1;
            }
            TaskletPriority::High => {
                self.per_cpu[cpu_idx].add_high(tasklet_id)?;
                self.stats.hi_scheduled += 1;
            }
        }
        Ok(())
    }

    /// Schedule a high-priority tasklet on a CPU.
    pub fn hi_schedule(&mut self, tasklet_id: u32, cpu: u32) -> Result<()> {
        let cpu_idx = cpu as usize;
        if cpu_idx >= MAX_CPUS || !self.per_cpu[cpu_idx].initialized {
            return Err(Error::InvalidArgument);
        }

        let t = self
            .tasklets
            .iter_mut()
            .find(|t| t.active && t.id == tasklet_id)
            .ok_or(Error::NotFound)?;

        if t.state == TaskletState::Scheduled || t.state == TaskletState::Running {
            return Ok(());
        }

        t.state = TaskletState::Scheduled;
        t.last_cpu = cpu;
        self.per_cpu[cpu_idx].add_high(tasklet_id)?;
        self.stats.hi_scheduled += 1;
        Ok(())
    }

    /// Process pending tasklets on a CPU.
    ///
    /// Runs all high-priority tasklets first, then normal-priority.
    /// Returns the number of tasklets executed.
    pub fn process_tasklets(&mut self, cpu: u32) -> Result<u32> {
        let cpu_idx = cpu as usize;
        if cpu_idx >= MAX_CPUS || !self.per_cpu[cpu_idx].initialized {
            return Err(Error::InvalidArgument);
        }

        let mut executed = 0u32;

        // Process high-priority tasklets.
        let mut hi_ids = [0u32; MAX_PER_CPU_PENDING];
        let hi_count = self.per_cpu[cpu_idx].take_high(&mut hi_ids);
        for &tid in &hi_ids[..hi_count] {
            executed += self.run_tasklet(tid);
        }

        // Process normal-priority tasklets.
        let mut norm_ids = [0u32; MAX_PER_CPU_PENDING];
        let norm_count = self.per_cpu[cpu_idx].take_normal(&mut norm_ids);
        for &tid in &norm_ids[..norm_count] {
            executed += self.run_tasklet(tid);
        }

        Ok(executed)
    }

    /// Disable a tasklet (increments disable count).
    pub fn disable(&mut self, tasklet_id: u32) -> Result<()> {
        let t = self
            .tasklets
            .iter_mut()
            .find(|t| t.active && t.id == tasklet_id)
            .ok_or(Error::NotFound)?;
        t.disable_count = t.disable_count.saturating_add(1);
        if t.state == TaskletState::Idle {
            t.state = TaskletState::Disabled;
        }
        Ok(())
    }

    /// Enable a tasklet (decrements disable count).
    pub fn enable(&mut self, tasklet_id: u32) -> Result<()> {
        let t = self
            .tasklets
            .iter_mut()
            .find(|t| t.active && t.id == tasklet_id)
            .ok_or(Error::NotFound)?;
        if t.disable_count > 0 {
            t.disable_count -= 1;
        }
        if t.disable_count == 0 && t.state == TaskletState::Disabled {
            t.state = TaskletState::Idle;
        }
        Ok(())
    }

    /// Get a tasklet by ID.
    pub fn get(&self, tasklet_id: u32) -> Result<&TaskletStruct> {
        self.tasklets
            .iter()
            .find(|t| t.active && t.id == tasklet_id)
            .ok_or(Error::NotFound)
    }

    /// Return statistics.
    pub fn stats(&self) -> &TaskletStats {
        &self.stats
    }

    /// Number of active tasklets.
    pub fn tasklet_count(&self) -> usize {
        self.tasklet_count
    }

    // ── Internal helpers ────────────────────────────────────

    /// Run a single tasklet by ID. Returns 1 if executed, 0 if skipped.
    fn run_tasklet(&mut self, tasklet_id: u32) -> u32 {
        let t = match self.find_mut(tasklet_id) {
            Some(t) => t,
            None => return 0,
        };

        if t.disable_count > 0 || t.state == TaskletState::Running {
            self.stats.skipped += 1;
            return 0;
        }

        let func = match t.func {
            Some(f) => f,
            None => return 0,
        };
        let data = t.data;

        t.state = TaskletState::Running;
        // Execute callback.
        func(data);

        // Mark complete.
        if let Some(t) = self.find_mut(tasklet_id) {
            t.state = TaskletState::Idle;
            t.run_count += 1;
        }

        self.stats.executed += 1;
        1
    }

    /// Find a mutable tasklet by ID.
    fn find_mut(&mut self, tasklet_id: u32) -> Option<&mut TaskletStruct> {
        self.tasklets
            .iter_mut()
            .find(|t| t.active && t.id == tasklet_id)
    }
}

impl Default for TaskletManager {
    fn default() -> Self {
        Self::new()
    }
}
