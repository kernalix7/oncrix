// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Preemption notifier chain.
//!
//! Provides a notification mechanism for subsystems that need to
//! be informed when a task is about to be preempted (scheduled
//! out) or has just been scheduled in. Used by virtualization
//! (KVM), performance monitoring, and other subsystems that
//! maintain per-task hardware state.

use oncrix_lib::{Error, Result};

/// Maximum number of registered notifiers.
const MAX_NOTIFIERS: usize = 64;

/// Maximum number of per-task notifier registrations.
const MAX_TASK_NOTIFIERS: usize = 256;

/// Preemption event type.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum PreemptEvent {
    /// Task is about to be scheduled out.
    SchedOut,
    /// Task has just been scheduled in.
    SchedIn,
}

/// Priority levels for notifier ordering.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum NotifierPriority {
    /// Highest priority — called first on sched_out.
    Critical = 0,
    /// High priority.
    High = 1,
    /// Normal priority.
    Normal = 2,
    /// Low priority — called last on sched_out.
    Low = 3,
}

/// A registered preemption notifier.
#[derive(Clone, Copy)]
pub struct PreemptNotifier {
    /// Unique notifier identifier.
    id: u32,
    /// Subsystem that registered this notifier.
    subsystem_id: u32,
    /// Priority for ordering.
    priority: NotifierPriority,
    /// Whether this notifier is active.
    active: bool,
    /// Number of times sched_out was called.
    sched_out_count: u64,
    /// Number of times sched_in was called.
    sched_in_count: u64,
    /// Total time spent in callbacks (nanoseconds).
    total_callback_time_ns: u64,
}

impl PreemptNotifier {
    /// Creates a new preemption notifier.
    pub const fn new() -> Self {
        Self {
            id: 0,
            subsystem_id: 0,
            priority: NotifierPriority::Normal,
            active: false,
            sched_out_count: 0,
            sched_in_count: 0,
            total_callback_time_ns: 0,
        }
    }

    /// Creates a notifier with the given subsystem and priority.
    pub const fn with_params(id: u32, subsystem_id: u32, priority: NotifierPriority) -> Self {
        Self {
            id,
            subsystem_id,
            priority,
            active: true,
            sched_out_count: 0,
            sched_in_count: 0,
            total_callback_time_ns: 0,
        }
    }

    /// Returns the notifier identifier.
    pub const fn id(&self) -> u32 {
        self.id
    }

    /// Returns the subsystem identifier.
    pub const fn subsystem_id(&self) -> u32 {
        self.subsystem_id
    }

    /// Returns the priority.
    pub const fn priority(&self) -> NotifierPriority {
        self.priority
    }

    /// Returns whether this notifier is active.
    pub const fn is_active(&self) -> bool {
        self.active
    }

    /// Returns the sched_out invocation count.
    pub const fn sched_out_count(&self) -> u64 {
        self.sched_out_count
    }

    /// Returns the sched_in invocation count.
    pub const fn sched_in_count(&self) -> u64 {
        self.sched_in_count
    }

    /// Deactivates this notifier.
    pub fn deactivate(&mut self) {
        self.active = false;
    }

    /// Records a notification event.
    pub fn record_event(&mut self, event: PreemptEvent, duration_ns: u64) {
        match event {
            PreemptEvent::SchedOut => self.sched_out_count += 1,
            PreemptEvent::SchedIn => self.sched_in_count += 1,
        }
        self.total_callback_time_ns += duration_ns;
    }
}

impl Default for PreemptNotifier {
    fn default() -> Self {
        Self::new()
    }
}

/// Per-task notifier registration.
#[derive(Clone, Copy)]
pub struct TaskNotifierReg {
    /// Task identifier.
    task_id: u64,
    /// Notifier identifier.
    notifier_id: u32,
    /// Whether this registration is active.
    active: bool,
}

impl TaskNotifierReg {
    /// Creates a new task notifier registration.
    pub const fn new() -> Self {
        Self {
            task_id: 0,
            notifier_id: 0,
            active: false,
        }
    }

    /// Returns the task identifier.
    pub const fn task_id(&self) -> u64 {
        self.task_id
    }

    /// Returns the notifier identifier.
    pub const fn notifier_id(&self) -> u32 {
        self.notifier_id
    }
}

impl Default for TaskNotifierReg {
    fn default() -> Self {
        Self::new()
    }
}

/// Preemption notifier chain manager.
pub struct PreemptNotifierChain {
    /// Registered notifiers.
    notifiers: [PreemptNotifier; MAX_NOTIFIERS],
    /// Number of registered notifiers.
    notifier_count: usize,
    /// Per-task registrations.
    task_regs: [TaskNotifierReg; MAX_TASK_NOTIFIERS],
    /// Number of task registrations.
    task_reg_count: usize,
    /// Next notifier ID.
    next_id: u32,
    /// Whether the chain is enabled.
    enabled: bool,
}

impl PreemptNotifierChain {
    /// Creates a new preemption notifier chain.
    pub const fn new() -> Self {
        Self {
            notifiers: [const { PreemptNotifier::new() }; MAX_NOTIFIERS],
            notifier_count: 0,
            task_regs: [const { TaskNotifierReg::new() }; MAX_TASK_NOTIFIERS],
            task_reg_count: 0,
            next_id: 1,
            enabled: true,
        }
    }

    /// Registers a new preemption notifier.
    pub fn register(&mut self, subsystem_id: u32, priority: NotifierPriority) -> Result<u32> {
        if self.notifier_count >= MAX_NOTIFIERS {
            return Err(Error::OutOfMemory);
        }
        let id = self.next_id;
        self.next_id += 1;
        self.notifiers[self.notifier_count] =
            PreemptNotifier::with_params(id, subsystem_id, priority);
        self.notifier_count += 1;
        Ok(id)
    }

    /// Unregisters a preemption notifier.
    pub fn unregister(&mut self, id: u32) -> Result<()> {
        for i in 0..self.notifier_count {
            if self.notifiers[i].id == id {
                self.notifiers[i].deactivate();
                return Ok(());
            }
        }
        Err(Error::NotFound)
    }

    /// Associates a notifier with a task.
    pub fn register_task(&mut self, task_id: u64, notifier_id: u32) -> Result<()> {
        // Verify notifier exists
        let found = self.notifiers[..self.notifier_count]
            .iter()
            .any(|n| n.id == notifier_id && n.active);
        if !found {
            return Err(Error::NotFound);
        }
        if self.task_reg_count >= MAX_TASK_NOTIFIERS {
            return Err(Error::OutOfMemory);
        }
        self.task_regs[self.task_reg_count] = TaskNotifierReg {
            task_id,
            notifier_id,
            active: true,
        };
        self.task_reg_count += 1;
        Ok(())
    }

    /// Fires notifications for a task preemption event.
    pub fn notify(&mut self, task_id: u64, event: PreemptEvent, duration_ns: u64) -> usize {
        if !self.enabled {
            return 0;
        }
        let mut notified = 0usize;

        // Collect notifier IDs for this task
        let mut notifier_ids = [0u32; MAX_NOTIFIERS];
        let mut nid_count = 0;
        for i in 0..self.task_reg_count {
            if self.task_regs[i].task_id == task_id && self.task_regs[i].active {
                if nid_count < MAX_NOTIFIERS {
                    notifier_ids[nid_count] = self.task_regs[i].notifier_id;
                    nid_count += 1;
                }
            }
        }

        // Fire notifications
        for nid_idx in 0..nid_count {
            let nid = notifier_ids[nid_idx];
            for i in 0..self.notifier_count {
                if self.notifiers[i].id == nid && self.notifiers[i].active {
                    self.notifiers[i].record_event(event, duration_ns);
                    notified += 1;
                }
            }
        }
        notified
    }

    /// Returns the number of active notifiers.
    pub fn active_count(&self) -> usize {
        self.notifiers[..self.notifier_count]
            .iter()
            .filter(|n| n.active)
            .count()
    }

    /// Enables or disables the notification chain.
    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }

    /// Returns the total number of registered notifiers.
    pub const fn notifier_count(&self) -> usize {
        self.notifier_count
    }
}

impl Default for PreemptNotifierChain {
    fn default() -> Self {
        Self::new()
    }
}
