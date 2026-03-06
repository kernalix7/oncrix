// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! High-priority workqueue subsystem.
//!
//! Provides a workqueue with elevated scheduling priority for
//! latency-sensitive deferred work (e.g., block I/O completion,
//! crypto operations, network fast-path). Work items submitted
//! to this queue are processed before normal-priority items.
//!
//! # Architecture
//!
//! ```text
//! HighPrioWorkqueue
//!  ├── items[MAX_ITEMS]
//!  │    ├── id, callback_id, data
//!  │    ├── state: WorkState
//!  │    └── priority, submit_time
//!  └── stats: HpwqStats
//! ```
//!
//! # Reference
//!
//! Linux `kernel/workqueue.c` — `WQ_HIGHPRI` flag.

use oncrix_lib::{Error, Result};

// ══════════════════════════════════════════════════════════════
// Constants
// ══════════════════════════════════════════════════════════════

/// Maximum pending high-priority work items.
const MAX_ITEMS: usize = 256;

/// Maximum data payload per work item (u64 words).
const MAX_DATA_WORDS: usize = 4;

// ══════════════════════════════════════════════════════════════
// WorkState
// ══════════════════════════════════════════════════════════════

/// State of a work item.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum WorkState {
    /// Slot is free.
    Free = 0,
    /// Queued and waiting for execution.
    Pending = 1,
    /// Currently executing.
    Running = 2,
    /// Completed successfully.
    Done = 3,
    /// Cancelled before execution.
    Cancelled = 4,
}

// ══════════════════════════════════════════════════════════════
// WorkItem
// ══════════════════════════════════════════════════════════════

/// A high-priority work item.
#[derive(Debug, Clone, Copy)]
pub struct WorkItem {
    /// Unique work item identifier.
    pub id: u64,
    /// Callback function identifier.
    pub callback_id: u64,
    /// Work item data payload.
    pub data: [u64; MAX_DATA_WORDS],
    /// Number of data words used.
    pub data_len: u8,
    /// Priority within the high-priority queue (lower = higher).
    pub priority: u32,
    /// Submission timestamp (monotonic ns).
    pub submit_time: u64,
    /// Completion timestamp.
    pub complete_time: u64,
    /// Target CPU (-1 = any).
    pub target_cpu: i32,
    /// Current state.
    pub state: WorkState,
}

impl WorkItem {
    /// Create a free work item slot.
    const fn empty() -> Self {
        Self {
            id: 0,
            callback_id: 0,
            data: [0u64; MAX_DATA_WORDS],
            data_len: 0,
            priority: u32::MAX,
            submit_time: 0,
            complete_time: 0,
            target_cpu: -1,
            state: WorkState::Free,
        }
    }
}

// ══════════════════════════════════════════════════════════════
// HpwqStats
// ══════════════════════════════════════════════════════════════

/// High-priority workqueue statistics.
#[derive(Debug, Clone, Copy)]
pub struct HpwqStats {
    /// Total items submitted.
    pub total_submitted: u64,
    /// Total items executed.
    pub total_executed: u64,
    /// Total items cancelled.
    pub total_cancelled: u64,
    /// Maximum queue depth observed.
    pub max_depth: u32,
    /// Current queue depth.
    pub current_depth: u32,
}

impl HpwqStats {
    /// Create zeroed stats.
    const fn new() -> Self {
        Self {
            total_submitted: 0,
            total_executed: 0,
            total_cancelled: 0,
            max_depth: 0,
            current_depth: 0,
        }
    }
}

// ══════════════════════════════════════════════════════════════
// HighPrioWorkqueue
// ══════════════════════════════════════════════════════════════

/// High-priority workqueue.
pub struct HighPrioWorkqueue {
    /// Work item table.
    items: [WorkItem; MAX_ITEMS],
    /// Next work item ID.
    next_id: u64,
    /// Statistics.
    stats: HpwqStats,
    /// Whether the workqueue is active.
    active: bool,
}

impl HighPrioWorkqueue {
    /// Create a new high-priority workqueue.
    pub const fn new() -> Self {
        Self {
            items: [const { WorkItem::empty() }; MAX_ITEMS],
            next_id: 1,
            stats: HpwqStats::new(),
            active: false,
        }
    }

    /// Activate the workqueue.
    pub fn activate(&mut self) -> Result<()> {
        if self.active {
            return Err(Error::AlreadyExists);
        }
        self.active = true;
        Ok(())
    }

    /// Submit a work item.
    ///
    /// # Errors
    ///
    /// - `NotImplemented` if the workqueue is not active.
    /// - `OutOfMemory` if no free slots.
    pub fn submit(
        &mut self,
        callback_id: u64,
        data: &[u64],
        priority: u32,
        target_cpu: i32,
        now_ns: u64,
    ) -> Result<u64> {
        if !self.active {
            return Err(Error::NotImplemented);
        }
        if data.len() > MAX_DATA_WORDS {
            return Err(Error::InvalidArgument);
        }
        let slot = self
            .items
            .iter()
            .position(|w| matches!(w.state, WorkState::Free))
            .ok_or(Error::OutOfMemory)?;
        let id = self.next_id;
        self.next_id += 1;
        self.items[slot] = WorkItem {
            id,
            callback_id,
            data_len: data.len() as u8,
            priority,
            submit_time: now_ns,
            target_cpu,
            state: WorkState::Pending,
            ..WorkItem::empty()
        };
        self.items[slot].data[..data.len()].copy_from_slice(data);
        self.stats.total_submitted += 1;
        self.stats.current_depth += 1;
        if self.stats.current_depth > self.stats.max_depth {
            self.stats.max_depth = self.stats.current_depth;
        }
        Ok(id)
    }

    /// Dequeue the highest-priority pending work item.
    ///
    /// Returns the slot index of the item now in `Running` state.
    pub fn dequeue(&mut self) -> Option<usize> {
        let mut best_slot: Option<usize> = None;
        let mut best_prio = u32::MAX;
        for (i, item) in self.items.iter().enumerate() {
            if matches!(item.state, WorkState::Pending) && item.priority < best_prio {
                best_prio = item.priority;
                best_slot = Some(i);
            }
        }
        if let Some(slot) = best_slot {
            self.items[slot].state = WorkState::Running;
        }
        best_slot
    }

    /// Mark a work item as completed.
    pub fn complete(&mut self, slot: usize, now_ns: u64) -> Result<()> {
        if slot >= MAX_ITEMS {
            return Err(Error::InvalidArgument);
        }
        if !matches!(self.items[slot].state, WorkState::Running) {
            return Err(Error::InvalidArgument);
        }
        self.items[slot].state = WorkState::Done;
        self.items[slot].complete_time = now_ns;
        self.stats.total_executed += 1;
        self.stats.current_depth = self.stats.current_depth.saturating_sub(1);
        Ok(())
    }

    /// Cancel a pending work item.
    pub fn cancel(&mut self, work_id: u64) -> Result<()> {
        let slot = self
            .items
            .iter()
            .position(|w| matches!(w.state, WorkState::Pending) && w.id == work_id)
            .ok_or(Error::NotFound)?;
        self.items[slot].state = WorkState::Cancelled;
        self.stats.total_cancelled += 1;
        self.stats.current_depth = self.stats.current_depth.saturating_sub(1);
        Ok(())
    }

    /// Reclaim completed/cancelled slots.
    pub fn reclaim(&mut self) -> u32 {
        let mut count = 0u32;
        for item in &mut self.items {
            if matches!(item.state, WorkState::Done | WorkState::Cancelled) {
                *item = WorkItem::empty();
                count += 1;
            }
        }
        count
    }

    /// Return statistics.
    pub fn stats(&self) -> HpwqStats {
        self.stats
    }
}
