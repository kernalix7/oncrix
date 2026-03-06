// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Tasklet-based softirq dispatch.
//!
//! Tasklets are a mechanism for deferring work from interrupt context
//! into softirq context. Each tasklet runs on the CPU that scheduled
//! it and is serialized against itself (a given tasklet never runs
//! concurrently on multiple CPUs).

use oncrix_lib::{Error, Result};

// ── Constants ────────────────────────────────────────────────────────

/// Maximum number of tasklet softirq vectors.
const MAX_TASKLET_VECTORS: usize = 32;

/// Maximum pending tasklets per vector.
const MAX_PENDING_PER_VECTOR: usize = 256;

/// Tasklet priority levels.
const TASKLET_PRIORITY_NORMAL: u8 = 0;
const TASKLET_PRIORITY_HI: u8 = 1;

/// Tasklet state flags.
const TASKLET_STATE_SCHED: u32 = 1 << 0;
const TASKLET_STATE_RUN: u32 = 1 << 1;
const TASKLET_STATE_DISABLED: u32 = 1 << 2;

// ── Types ────────────────────────────────────────────────────────────

/// Identifies a softirq vector slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SoftirqVectorId(u32);

impl SoftirqVectorId {
    /// Creates a new softirq vector identifier.
    pub const fn new(id: u32) -> Self {
        Self(id)
    }

    /// Returns the raw identifier value.
    pub const fn as_u32(self) -> u32 {
        self.0
    }
}

/// Describes a single tasklet registered for softirq dispatch.
#[derive(Debug, Clone)]
pub struct TaskletSoftirqEntry {
    /// Unique tasklet identifier.
    tasklet_id: u64,
    /// Vector this tasklet is registered on.
    vector_id: SoftirqVectorId,
    /// Priority level (0 = normal, 1 = high).
    priority: u8,
    /// Current state flags.
    state: u32,
    /// Number of times this tasklet has been executed.
    execution_count: u64,
    /// CPU on which this tasklet was scheduled.
    scheduled_cpu: u32,
    /// Disable depth counter (enabled when zero).
    disable_count: u32,
}

impl TaskletSoftirqEntry {
    /// Creates a new tasklet softirq entry.
    pub const fn new(tasklet_id: u64, vector_id: SoftirqVectorId, priority: u8) -> Self {
        Self {
            tasklet_id,
            vector_id,
            priority,
            state: 0,
            execution_count: 0,
            scheduled_cpu: 0,
            disable_count: 0,
        }
    }

    /// Returns whether this tasklet is currently disabled.
    pub const fn is_disabled(&self) -> bool {
        self.disable_count > 0
    }

    /// Returns the current execution count.
    pub const fn execution_count(&self) -> u64 {
        self.execution_count
    }
}

/// Per-vector pending list for tasklet dispatch.
#[derive(Debug)]
pub struct TaskletPendingList {
    /// Entries waiting to be dispatched.
    entries: [Option<u64>; MAX_PENDING_PER_VECTOR],
    /// Number of currently pending entries.
    count: usize,
    /// Vector identifier.
    vector_id: SoftirqVectorId,
}

impl TaskletPendingList {
    /// Creates a new empty pending list.
    pub const fn new(vector_id: SoftirqVectorId) -> Self {
        Self {
            entries: [None; MAX_PENDING_PER_VECTOR],
            count: 0,
            vector_id,
        }
    }

    /// Returns the number of pending tasklets.
    pub const fn len(&self) -> usize {
        self.count
    }

    /// Returns whether the pending list is empty.
    pub const fn is_empty(&self) -> bool {
        self.count == 0
    }
}

/// Statistics for softirq vector dispatch.
#[derive(Debug, Clone)]
pub struct SoftirqVectorStats {
    /// Vector identifier.
    vector_id: SoftirqVectorId,
    /// Total dispatches on this vector.
    total_dispatches: u64,
    /// Total tasklets executed.
    total_executed: u64,
    /// Maximum pending depth observed.
    max_pending_depth: u32,
    /// Number of times dispatch was deferred.
    deferred_count: u64,
}

impl SoftirqVectorStats {
    /// Creates zeroed statistics for a vector.
    pub const fn new(vector_id: SoftirqVectorId) -> Self {
        Self {
            vector_id,
            total_dispatches: 0,
            total_executed: 0,
            max_pending_depth: 0,
            deferred_count: 0,
        }
    }

    /// Returns total dispatches for this vector.
    pub const fn total_dispatches(&self) -> u64 {
        self.total_dispatches
    }
}

/// Central tasklet softirq dispatcher.
#[derive(Debug)]
pub struct TaskletSoftirqDispatcher {
    /// Registered tasklet entries.
    tasklets: [Option<TaskletSoftirqEntry>; MAX_PENDING_PER_VECTOR],
    /// Number of registered tasklets.
    tasklet_count: usize,
    /// Per-vector statistics.
    stats: [SoftirqVectorStats; MAX_TASKLET_VECTORS],
    /// Whether the dispatcher is currently active.
    active: bool,
    /// Global generation counter for ordering.
    generation: u64,
}

impl Default for TaskletSoftirqDispatcher {
    fn default() -> Self {
        Self::new()
    }
}

impl TaskletSoftirqDispatcher {
    /// Creates a new tasklet softirq dispatcher.
    pub const fn new() -> Self {
        Self {
            tasklets: [const { None }; MAX_PENDING_PER_VECTOR],
            tasklet_count: 0,
            stats: [const { SoftirqVectorStats::new(SoftirqVectorId::new(0)) };
                MAX_TASKLET_VECTORS],
            active: false,
            generation: 0,
        }
    }

    /// Registers a tasklet for softirq dispatch.
    pub fn register_tasklet(
        &mut self,
        tasklet_id: u64,
        vector_id: SoftirqVectorId,
        priority: u8,
    ) -> Result<()> {
        if (vector_id.as_u32() as usize) >= MAX_TASKLET_VECTORS {
            return Err(Error::InvalidArgument);
        }
        if self.tasklet_count >= MAX_PENDING_PER_VECTOR {
            return Err(Error::OutOfMemory);
        }
        // Check for duplicate registration.
        for slot in self.tasklets.iter().flatten() {
            if slot.tasklet_id == tasklet_id {
                return Err(Error::AlreadyExists);
            }
        }
        let entry = TaskletSoftirqEntry::new(tasklet_id, vector_id, priority);
        if let Some(slot) = self.tasklets.iter_mut().find(|s| s.is_none()) {
            *slot = Some(entry);
            self.tasklet_count += 1;
            Ok(())
        } else {
            Err(Error::OutOfMemory)
        }
    }

    /// Schedules a tasklet for execution on the current CPU.
    pub fn schedule_tasklet(&mut self, tasklet_id: u64, cpu: u32) -> Result<()> {
        let entry = self
            .tasklets
            .iter_mut()
            .flatten()
            .find(|e| e.tasklet_id == tasklet_id)
            .ok_or(Error::NotFound)?;
        if entry.is_disabled() {
            return Err(Error::Busy);
        }
        if entry.state & TASKLET_STATE_SCHED != 0 {
            return Ok(());
        }
        entry.state |= TASKLET_STATE_SCHED;
        entry.scheduled_cpu = cpu;
        self.generation += 1;
        Ok(())
    }

    /// Dispatches all pending tasklets on a given vector.
    pub fn dispatch_vector(&mut self, vector_id: SoftirqVectorId) -> Result<u32> {
        let vec_idx = vector_id.as_u32() as usize;
        if vec_idx >= MAX_TASKLET_VECTORS {
            return Err(Error::InvalidArgument);
        }
        let mut executed = 0u32;
        for slot in self.tasklets.iter_mut().flatten() {
            if slot.vector_id != vector_id {
                continue;
            }
            if slot.state & TASKLET_STATE_SCHED == 0 {
                continue;
            }
            if slot.is_disabled() {
                self.stats[vec_idx].deferred_count += 1;
                continue;
            }
            slot.state |= TASKLET_STATE_RUN;
            slot.state &= !TASKLET_STATE_SCHED;
            slot.execution_count += 1;
            slot.state &= !TASKLET_STATE_RUN;
            executed += 1;
        }
        self.stats[vec_idx].total_dispatches += 1;
        self.stats[vec_idx].total_executed += executed as u64;
        Ok(executed)
    }

    /// Disables a tasklet, incrementing its disable counter.
    pub fn disable_tasklet(&mut self, tasklet_id: u64) -> Result<()> {
        let entry = self
            .tasklets
            .iter_mut()
            .flatten()
            .find(|e| e.tasklet_id == tasklet_id)
            .ok_or(Error::NotFound)?;
        entry.disable_count += 1;
        entry.state |= TASKLET_STATE_DISABLED;
        Ok(())
    }

    /// Enables a tasklet, decrementing its disable counter.
    pub fn enable_tasklet(&mut self, tasklet_id: u64) -> Result<()> {
        let entry = self
            .tasklets
            .iter_mut()
            .flatten()
            .find(|e| e.tasklet_id == tasklet_id)
            .ok_or(Error::NotFound)?;
        if entry.disable_count == 0 {
            return Err(Error::InvalidArgument);
        }
        entry.disable_count -= 1;
        if entry.disable_count == 0 {
            entry.state &= !TASKLET_STATE_DISABLED;
        }
        Ok(())
    }

    /// Removes a tasklet from the dispatcher.
    pub fn unregister_tasklet(&mut self, tasklet_id: u64) -> Result<()> {
        let slot = self
            .tasklets
            .iter_mut()
            .find(|s| s.as_ref().map_or(false, |e| e.tasklet_id == tasklet_id))
            .ok_or(Error::NotFound)?;
        *slot = None;
        self.tasklet_count -= 1;
        Ok(())
    }

    /// Returns statistics for a given vector.
    pub fn vector_stats(&self, vector_id: SoftirqVectorId) -> Result<&SoftirqVectorStats> {
        let idx = vector_id.as_u32() as usize;
        if idx >= MAX_TASKLET_VECTORS {
            return Err(Error::InvalidArgument);
        }
        Ok(&self.stats[idx])
    }

    /// Returns the total number of registered tasklets.
    pub const fn tasklet_count(&self) -> usize {
        self.tasklet_count
    }
}
