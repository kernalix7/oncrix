// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Extensible scheduler framework (sched_ext).
//!
//! Provides a pluggable scheduling interface that allows BPF programs
//! (or statically linked policies) to override the kernel's default
//! scheduling decisions. Modeled after Linux's sched_ext subsystem
//! (`kernel/sched/ext.c`).
//!
//! # Design
//!
//! The framework defines a [`SchedExtOps`] trait with hooks that are
//! called at each scheduling decision point. A concrete implementation
//! can be registered at runtime via [`SchedExtManager::register`],
//! replacing the active scheduling policy without reboot.
//!
//! Per-CPU dispatch queues ([`DispatchQueue`]) hold tasks that are
//! ready to run. The `dispatch` hook selects which task to run next.
//!
//! # Components
//!
//! - [`SchedExtOps`] — trait defining scheduler extension hooks
//! - [`DefaultSchedOps`] — built-in FIFO fallback implementation
//! - [`DispatchQueue`] — per-CPU fixed-size ready queue
//! - [`SchedExtTask`] — task metadata for the ext scheduler
//! - [`SchedExtStats`] — per-scheduler statistics
//! - [`SchedExtManager`] — top-level manager handling registration,
//!   hotswap, and dispatch delegation
//!
//! Reference: Linux `kernel/sched/ext.c`,
//! `include/linux/sched/ext.h`.

use oncrix_lib::{Error, Result};

// ── Constants ──────────────────────────────────────────────────────

/// Maximum tasks per dispatch queue.
const MAX_QUEUE_LEN: usize = 64;

/// Maximum CPUs.
const MAX_CPUS: usize = 64;

/// Maximum length of a scheduler name.
const MAX_NAME_LEN: usize = 64;

/// Maximum tasks the ext scheduler can track globally.
const MAX_TASKS: usize = 256;

/// Maximum number of registered scheduler implementations.
const MAX_SCHEDULERS: usize = 8;

// ── SchedExtFlags ─────────────────────────────────────────────────

/// Bitfield flags for ext-scheduler configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SchedExtFlags(u32);

impl SchedExtFlags {
    /// No special behavior.
    pub const NONE: Self = Self(0);
    /// Scheduler wants per-CPU dispatch (no global queue).
    pub const PER_CPU_DISPATCH: Self = Self(1 << 0);
    /// Scheduler wants to receive tick callbacks.
    pub const WANTS_TICK: Self = Self(1 << 1);
    /// Scheduler supports CPU hotplug events.
    pub const CPU_HOTPLUG: Self = Self(1 << 2);
    /// Scheduler supports task migration between CPUs.
    pub const MIGRATE: Self = Self(1 << 3);

    /// Create from raw value.
    pub const fn from_raw(val: u32) -> Self {
        Self(val)
    }

    /// Raw value.
    pub const fn as_raw(self) -> u32 {
        self.0
    }

    /// Test if a flag is set.
    pub const fn contains(self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }
}

// ── TaskState ─────────────────────────────────────────────────────

/// Scheduling state of a task managed by sched_ext.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TaskState {
    /// Task is not known to the ext scheduler.
    #[default]
    Unknown,
    /// Task is queued and waiting for dispatch.
    Queued,
    /// Task is currently running on a CPU.
    Running,
    /// Task has been dispatched but not yet picked up.
    Dispatched,
    /// Task voluntarily yielded its time slice.
    Yielded,
    /// Task has been stopped or is exiting.
    Stopped,
}

// ── SchedExtTask ──────────────────────────────────────────────────

/// Metadata for a task managed by the ext scheduler.
#[derive(Debug, Clone, Copy)]
pub struct SchedExtTask {
    /// Task (PID) identifier.
    pub pid: u64,
    /// CPU the task is assigned to (or was last on).
    pub cpu: u16,
    /// Current state.
    pub state: TaskState,
    /// Static priority (0 = highest).
    pub priority: u16,
    /// Weight used for proportional scheduling.
    pub weight: u32,
    /// Cumulative runtime in ticks.
    pub runtime_ticks: u64,
    /// Number of times this task was dispatched.
    pub dispatch_count: u64,
    /// Opaque scheduler-private data.
    pub ext_data: u64,
    /// Whether this slot is in use.
    pub active: bool,
}

impl SchedExtTask {
    /// Empty task slot.
    const fn empty() -> Self {
        Self {
            pid: 0,
            cpu: 0,
            state: TaskState::Unknown,
            priority: 0,
            weight: 1,
            runtime_ticks: 0,
            dispatch_count: 0,
            ext_data: 0,
            active: false,
        }
    }
}

// ── DispatchQueue ─────────────────────────────────────────────────

/// Per-CPU dispatch queue holding tasks ready to run.
///
/// Implemented as a simple ring buffer of PIDs.
pub struct DispatchQueue {
    /// PIDs of tasks in the queue.
    pids: [u64; MAX_QUEUE_LEN],
    /// Head index (next to dequeue).
    head: usize,
    /// Tail index (next insertion point).
    tail: usize,
    /// Number of items currently in the queue.
    len: usize,
}

impl DispatchQueue {
    /// Create an empty dispatch queue.
    pub const fn new() -> Self {
        Self {
            pids: [0u64; MAX_QUEUE_LEN],
            head: 0,
            tail: 0,
            len: 0,
        }
    }

    /// Enqueue a task PID. Returns error if full.
    pub fn enqueue(&mut self, pid: u64) -> Result<()> {
        if self.len >= MAX_QUEUE_LEN {
            return Err(Error::OutOfMemory);
        }
        self.pids[self.tail] = pid;
        self.tail = (self.tail + 1) % MAX_QUEUE_LEN;
        self.len += 1;
        Ok(())
    }

    /// Dequeue the next task PID.
    pub fn dequeue(&mut self) -> Option<u64> {
        if self.len == 0 {
            return None;
        }
        let pid = self.pids[self.head];
        self.head = (self.head + 1) % MAX_QUEUE_LEN;
        self.len -= 1;
        Some(pid)
    }

    /// Number of tasks in the queue.
    pub const fn len(&self) -> usize {
        self.len
    }

    /// Whether the queue is empty.
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Remove a specific PID from anywhere in the queue.
    ///
    /// Returns true if the PID was found and removed.
    pub fn remove(&mut self, pid: u64) -> bool {
        let mut idx = self.head;
        for i in 0..self.len {
            if self.pids[idx] == pid {
                // Shift remaining items.
                let mut cur = idx;
                for _ in i..self.len - 1 {
                    let next = (cur + 1) % MAX_QUEUE_LEN;
                    self.pids[cur] = self.pids[next];
                    cur = next;
                }
                self.tail = if self.tail == 0 {
                    MAX_QUEUE_LEN - 1
                } else {
                    self.tail - 1
                };
                self.len -= 1;
                return true;
            }
            idx = (idx + 1) % MAX_QUEUE_LEN;
        }
        false
    }
}

// ── SchedExtOps ───────────────────────────────────────────────────

/// Trait defining the hooks for a pluggable scheduler extension.
///
/// An implementation overrides these methods to customise scheduling
/// behavior. The manager calls these hooks at the appropriate points
/// in the scheduling path.
pub trait SchedExtOps {
    /// Select which CPU a newly enqueued task should run on.
    ///
    /// `prev_cpu` is the CPU the task last ran on. Returns the
    /// selected CPU index.
    fn select_cpu(&self, task: &SchedExtTask, prev_cpu: u16) -> u16;

    /// Called when a task becomes runnable and needs to be enqueued.
    fn enqueue(&self, task: &SchedExtTask, queues: &mut [DispatchQueue; MAX_CPUS]) -> Result<()>;

    /// Called when a task is removed from its dispatch queue.
    fn dequeue(&self, task: &SchedExtTask, queues: &mut [DispatchQueue; MAX_CPUS]) -> Result<()>;

    /// Select the next task to dispatch on the given CPU.
    ///
    /// Returns the PID of the selected task, or `None` for idle.
    fn dispatch(&self, cpu: u16, queues: &mut [DispatchQueue; MAX_CPUS]) -> Option<u64>;

    /// Periodic tick callback. Called each timer tick for the
    /// currently running task.
    fn tick(&self, task: &SchedExtTask);

    /// Called when a task is created and enters the ext domain.
    fn task_init(&self, task: &mut SchedExtTask);

    /// Called when a task exits the ext domain (exit or migration).
    fn task_exit(&self, task: &SchedExtTask);
}

// ── DefaultSchedOps ───────────────────────────────────────────────

/// Built-in FIFO scheduler used when no extension is registered.
pub struct DefaultSchedOps;

impl SchedExtOps for DefaultSchedOps {
    fn select_cpu(&self, _task: &SchedExtTask, prev_cpu: u16) -> u16 {
        prev_cpu
    }

    fn enqueue(&self, task: &SchedExtTask, queues: &mut [DispatchQueue; MAX_CPUS]) -> Result<()> {
        let cpu = task.cpu as usize;
        if cpu >= MAX_CPUS {
            return Err(Error::InvalidArgument);
        }
        queues[cpu].enqueue(task.pid)
    }

    fn dequeue(&self, task: &SchedExtTask, queues: &mut [DispatchQueue; MAX_CPUS]) -> Result<()> {
        let cpu = task.cpu as usize;
        if cpu >= MAX_CPUS {
            return Err(Error::InvalidArgument);
        }
        queues[cpu].remove(task.pid);
        Ok(())
    }

    fn dispatch(&self, cpu: u16, queues: &mut [DispatchQueue; MAX_CPUS]) -> Option<u64> {
        let idx = cpu as usize;
        if idx >= MAX_CPUS {
            return None;
        }
        queues[idx].dequeue()
    }

    fn tick(&self, _task: &SchedExtTask) {
        // Default: nothing special on tick.
    }

    fn task_init(&self, task: &mut SchedExtTask) {
        task.weight = 1;
        task.ext_data = 0;
    }

    fn task_exit(&self, _task: &SchedExtTask) {
        // Default: nothing on exit.
    }
}

// ── SchedExtEntry ─────────────────────────────────────────────────

/// Metadata for a registered scheduler implementation.
#[derive(Debug, Clone, Copy)]
pub struct SchedExtEntry {
    /// Human-readable name.
    pub name: [u8; MAX_NAME_LEN],
    /// Valid length of name.
    pub name_len: usize,
    /// Configuration flags.
    pub flags: SchedExtFlags,
    /// Whether this slot is active.
    pub active: bool,
    /// Whether this is the currently selected scheduler.
    pub selected: bool,
}

impl SchedExtEntry {
    /// Empty entry.
    const fn empty() -> Self {
        Self {
            name: [0u8; MAX_NAME_LEN],
            name_len: 0,
            flags: SchedExtFlags::NONE,
            active: false,
            selected: false,
        }
    }
}

// ── SchedExtStats ─────────────────────────────────────────────────

/// Runtime statistics for the ext scheduler.
#[derive(Debug, Clone, Copy)]
pub struct SchedExtStats {
    /// Total enqueue operations.
    pub enqueues: u64,
    /// Total dequeue operations.
    pub dequeues: u64,
    /// Total dispatch operations.
    pub dispatches: u64,
    /// Total tick callbacks.
    pub ticks: u64,
    /// Total scheduler hotswap operations.
    pub hotswaps: u64,
    /// Total tasks initialised.
    pub tasks_init: u64,
    /// Total tasks exited.
    pub tasks_exit: u64,
}

impl SchedExtStats {
    /// Zero statistics.
    const fn new() -> Self {
        Self {
            enqueues: 0,
            dequeues: 0,
            dispatches: 0,
            ticks: 0,
            hotswaps: 0,
            tasks_init: 0,
            tasks_exit: 0,
        }
    }
}

// ── SchedExtManager ───────────────────────────────────────────────

/// Top-level manager for the extensible scheduler.
///
/// Maintains the task table, per-CPU dispatch queues, registered
/// scheduler entries, and delegates scheduling operations to the
/// active scheduler implementation.
pub struct SchedExtManager {
    /// Task table (indexed by slot, not PID).
    tasks: [SchedExtTask; MAX_TASKS],
    /// Number of active tasks.
    task_count: usize,
    /// Per-CPU dispatch queues.
    queues: [DispatchQueue; MAX_CPUS],
    /// Registered scheduler metadata.
    schedulers: [SchedExtEntry; MAX_SCHEDULERS],
    /// Number of registered schedulers.
    sched_count: usize,
    /// Index of the currently active scheduler in `schedulers`.
    active_sched: usize,
    /// Aggregate statistics.
    stats: SchedExtStats,
    /// Whether the ext scheduler is enabled.
    enabled: bool,
}

impl SchedExtManager {
    /// Create a new manager with default (FIFO) scheduling.
    pub const fn new() -> Self {
        const EMPTY_QUEUE: DispatchQueue = DispatchQueue::new();
        Self {
            tasks: [SchedExtTask::empty(); MAX_TASKS],
            task_count: 0,
            queues: [EMPTY_QUEUE; MAX_CPUS],
            schedulers: [SchedExtEntry::empty(); MAX_SCHEDULERS],
            sched_count: 0,
            active_sched: 0,
            stats: SchedExtStats::new(),
            enabled: true,
        }
    }

    /// Register a new scheduler implementation.
    ///
    /// Returns the scheduler index. The first registered scheduler
    /// becomes active by default.
    pub fn register(&mut self, name: &[u8], flags: SchedExtFlags) -> Result<usize> {
        if self.sched_count >= MAX_SCHEDULERS {
            return Err(Error::OutOfMemory);
        }
        let idx = self.sched_count;
        let copy_len = name.len().min(MAX_NAME_LEN);
        self.schedulers[idx].name[..copy_len].copy_from_slice(&name[..copy_len]);
        self.schedulers[idx].name_len = copy_len;
        self.schedulers[idx].flags = flags;
        self.schedulers[idx].active = true;
        if self.sched_count == 0 {
            self.schedulers[idx].selected = true;
            self.active_sched = idx;
        }
        self.sched_count += 1;
        Ok(idx)
    }

    /// Hot-swap the active scheduler to the one at `index`.
    pub fn hotswap(&mut self, index: usize) -> Result<()> {
        if index >= self.sched_count || !self.schedulers[index].active {
            return Err(Error::NotFound);
        }
        if self.active_sched < self.sched_count {
            self.schedulers[self.active_sched].selected = false;
        }
        self.schedulers[index].selected = true;
        self.active_sched = index;
        self.stats.hotswaps += 1;
        Ok(())
    }

    /// Add a task to the ext scheduler domain.
    pub fn add_task(
        &mut self,
        pid: u64,
        cpu: u16,
        priority: u16,
        ops: &dyn SchedExtOps,
    ) -> Result<usize> {
        if self.task_count >= MAX_TASKS {
            return Err(Error::OutOfMemory);
        }
        // Find a free slot.
        let slot = self.tasks.iter().position(|t| !t.active);
        let slot = match slot {
            Some(s) => s,
            None => return Err(Error::OutOfMemory),
        };
        self.tasks[slot] = SchedExtTask {
            pid,
            cpu,
            state: TaskState::Queued,
            priority,
            weight: 1,
            runtime_ticks: 0,
            dispatch_count: 0,
            ext_data: 0,
            active: true,
        };
        ops.task_init(&mut self.tasks[slot]);
        self.task_count += 1;
        self.stats.tasks_init += 1;
        Ok(slot)
    }

    /// Remove a task from the ext scheduler domain.
    pub fn remove_task(&mut self, pid: u64, ops: &dyn SchedExtOps) -> Result<()> {
        let slot = self.find_task(pid)?;
        ops.task_exit(&self.tasks[slot]);
        // Remove from dispatch queue if present.
        let cpu = self.tasks[slot].cpu as usize;
        if cpu < MAX_CPUS {
            self.queues[cpu].remove(pid);
        }
        self.tasks[slot].active = false;
        self.tasks[slot].state = TaskState::Stopped;
        self.task_count -= 1;
        self.stats.tasks_exit += 1;
        Ok(())
    }

    /// Enqueue a task (make it runnable).
    pub fn enqueue(&mut self, pid: u64, ops: &dyn SchedExtOps) -> Result<()> {
        let slot = self.find_task(pid)?;
        let selected_cpu = ops.select_cpu(&self.tasks[slot], self.tasks[slot].cpu);
        self.tasks[slot].cpu = selected_cpu;
        self.tasks[slot].state = TaskState::Queued;
        ops.enqueue(&self.tasks[slot], &mut self.queues)?;
        self.stats.enqueues += 1;
        Ok(())
    }

    /// Dequeue a task (remove from ready queue).
    pub fn dequeue(&mut self, pid: u64, ops: &dyn SchedExtOps) -> Result<()> {
        let slot = self.find_task(pid)?;
        ops.dequeue(&self.tasks[slot], &mut self.queues)?;
        self.tasks[slot].state = TaskState::Stopped;
        self.stats.dequeues += 1;
        Ok(())
    }

    /// Dispatch the next task on a given CPU.
    ///
    /// Returns the PID of the dispatched task.
    pub fn dispatch(&mut self, cpu: u16, ops: &dyn SchedExtOps) -> Option<u64> {
        if !self.enabled {
            return None;
        }
        let pid = ops.dispatch(cpu, &mut self.queues)?;
        if let Ok(slot) = self.find_task(pid) {
            self.tasks[slot].state = TaskState::Running;
            self.tasks[slot].dispatch_count += 1;
        }
        self.stats.dispatches += 1;
        Some(pid)
    }

    /// Timer tick for the currently running task on a CPU.
    pub fn tick(&mut self, cpu: u16, ops: &dyn SchedExtOps) {
        // Find the running task on this CPU.
        let running = self
            .tasks
            .iter_mut()
            .find(|t| t.active && t.cpu == cpu && t.state == TaskState::Running);
        if let Some(task) = running {
            task.runtime_ticks += 1;
            ops.tick(task);
        }
        self.stats.ticks += 1;
    }

    /// Enable or disable the ext scheduler.
    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }

    /// Whether ext scheduling is enabled.
    pub const fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Number of active tasks.
    pub const fn task_count(&self) -> usize {
        self.task_count
    }

    /// Number of registered schedulers.
    pub const fn sched_count(&self) -> usize {
        self.sched_count
    }

    /// Index of the active scheduler.
    pub const fn active_sched(&self) -> usize {
        self.active_sched
    }

    /// Aggregate statistics.
    pub const fn stats(&self) -> &SchedExtStats {
        &self.stats
    }

    /// Look up a task slot by PID.
    fn find_task(&self, pid: u64) -> Result<usize> {
        self.tasks
            .iter()
            .position(|t| t.active && t.pid == pid)
            .ok_or(Error::NotFound)
    }
}
