// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Extended workqueue features — delayed work, ordered execution,
//! and CPU affinity.
//!
//! Builds on the base CMWQ subsystem to provide:
//! - **Delayed work**: schedule callbacks to execute after a
//!   configurable tick delay
//! - **Ordered workqueues**: single-threaded FIFO execution
//!   guarantee (no concurrent items from the same queue)
//! - **CPU affinity**: bind workqueues to specific CPU sets
//!
//! # Architecture
//!
//! ```text
//! ┌──────────────────────────────────────────────────────────────┐
//! │                  WorkqueueExtSubsystem                        │
//! │                                                              │
//! │  WorkqueuePool                                               │
//! │  ┌────────────────────────────────────────────────────────┐  │
//! │  │  workqueues[0..MAX_WORKQUEUES]                         │  │
//! │  │  ┌──────────────────────────────────────────────────┐  │  │
//! │  │  │  name, affinity, ordered (bool)                  │  │  │
//! │  │  │  OrderedWorkqueue: FIFO queue, in_progress       │  │  │
//! │  │  └──────────────────────────────────────────────────┘  │  │
//! │  └────────────────────────────────────────────────────────┘  │
//! │                                                              │
//! │  DelayedWork[0..MAX_DELAYED_ITEMS]                           │
//! │  ┌────────────────────────────────────────────────────────┐  │
//! │  │  work_id, delay_ticks, scheduled_tick                  │  │
//! │  │  callback_idx, cancelled                               │  │
//! │  └────────────────────────────────────────────────────────┘  │
//! │                                                              │
//! │  WorkqueueExtStats (global counters)                         │
//! └──────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Reference
//!
//! Linux `kernel/workqueue.c`, `include/linux/workqueue.h`,
//! `Documentation/core-api/workqueue.rst`.

use oncrix_lib::{Error, Result};

// ══════════════════════════════════════════════════════════════
// Constants
// ══════════════════════════════════════════════════════════════

/// Maximum workqueues in the pool.
const MAX_WORKQUEUES: usize = 8;

/// Maximum entries per ordered workqueue FIFO.
const ORDERED_CAPACITY: usize = 64;

/// Maximum delayed work items in the subsystem.
const MAX_DELAYED_ITEMS: usize = 128;

/// Workqueue name buffer length.
const WQ_NAME_LEN: usize = 32;

/// Maximum CPUs representable in the affinity mask.
const _MAX_CPUS: usize = 64;

// ══════════════════════════════════════════════════════════════
// AffinityMask
// ══════════════════════════════════════════════════════════════

/// CPU affinity bitmask for workqueue binding.
///
/// Each bit `i` indicates that CPU `i` is included in the affinity
/// set.  A mask of `0` means "any CPU" (unbound).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AffinityMask(u64);

impl AffinityMask {
    /// No CPUs selected (unbound / any CPU).
    pub const NONE: Self = Self(0);

    /// All 64 CPUs selected.
    pub const ALL: Self = Self(u64::MAX);

    /// Create a mask from a raw u64.
    pub const fn from_raw(raw: u64) -> Self {
        Self(raw)
    }

    /// Get the raw u64 bitmask.
    pub const fn raw(self) -> u64 {
        self.0
    }

    /// Create a mask for a single CPU.
    pub const fn single_cpu(cpu: u32) -> Self {
        if cpu >= 64 {
            return Self(0);
        }
        Self(1u64 << cpu)
    }

    /// Check if a specific CPU is set.
    pub const fn contains_cpu(self, cpu: u32) -> bool {
        if cpu >= 64 {
            return false;
        }
        (self.0 & (1u64 << cpu)) != 0
    }

    /// Set a specific CPU in the mask.
    pub fn set_cpu(&mut self, cpu: u32) {
        if cpu < 64 {
            self.0 |= 1u64 << cpu;
        }
    }

    /// Clear a specific CPU from the mask.
    pub fn clear_cpu(&mut self, cpu: u32) {
        if cpu < 64 {
            self.0 &= !(1u64 << cpu);
        }
    }

    /// Count the number of CPUs in the mask.
    pub const fn count(self) -> u32 {
        self.0.count_ones()
    }

    /// Check if the mask is empty (no CPUs selected).
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// Combine two masks (union).
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// Intersect two masks.
    pub const fn intersect(self, other: Self) -> Self {
        Self(self.0 & other.0)
    }

    /// Get the first CPU set in the mask.
    pub fn first_cpu(self) -> Option<u32> {
        if self.0 == 0 {
            None
        } else {
            Some(self.0.trailing_zeros())
        }
    }
}

impl Default for AffinityMask {
    fn default() -> Self {
        Self::NONE
    }
}

// ══════════════════════════════════════════════════════════════
// OrderedWorkItem
// ══════════════════════════════════════════════════════════════

/// A single item in an ordered workqueue FIFO.
#[derive(Clone, Copy)]
pub struct OrderedWorkItem {
    /// Unique work item ID.
    pub work_id: u64,
    /// Callback index (identifies the function to call).
    pub callback_idx: u32,
    /// Arbitrary data payload for the callback.
    pub data: u64,
    /// Whether this slot is occupied.
    pub valid: bool,
    /// Tick when this item was enqueued.
    pub enqueue_tick: u64,
}

impl OrderedWorkItem {
    /// Create an empty work item.
    pub const fn new() -> Self {
        Self {
            work_id: 0,
            callback_idx: 0,
            data: 0,
            valid: false,
            enqueue_tick: 0,
        }
    }
}

impl Default for OrderedWorkItem {
    fn default() -> Self {
        Self::new()
    }
}

// ══════════════════════════════════════════════════════════════
// OrderedWorkqueue
// ══════════════════════════════════════════════════════════════

/// An ordered (single-threaded) workqueue with FIFO semantics.
///
/// Guarantees that work items are executed one at a time, in the
/// order they were enqueued.  No concurrent execution is allowed.
#[derive(Clone)]
pub struct OrderedWorkqueue {
    /// FIFO queue of work items.
    pub items: [OrderedWorkItem; ORDERED_CAPACITY],
    /// Read index (next item to execute).
    pub head: usize,
    /// Write index (next slot to enqueue into).
    pub tail: usize,
    /// Number of items currently in the queue.
    pub count: usize,
    /// Whether a work item is currently being executed.
    pub in_progress: bool,
    /// ID of the work item currently in progress.
    pub current_work_id: u64,
    /// Next work ID to assign.
    pub next_work_id: u64,
}

impl OrderedWorkqueue {
    /// Create an empty ordered workqueue.
    pub const fn new() -> Self {
        Self {
            items: [const { OrderedWorkItem::new() }; ORDERED_CAPACITY],
            head: 0,
            tail: 0,
            count: 0,
            in_progress: false,
            current_work_id: 0,
            next_work_id: 1,
        }
    }

    /// Enqueue a work item.
    pub fn enqueue(&mut self, callback_idx: u32, data: u64, current_tick: u64) -> Result<u64> {
        if self.count >= ORDERED_CAPACITY {
            return Err(Error::OutOfMemory);
        }
        let work_id = self.next_work_id;
        self.next_work_id += 1;

        self.items[self.tail] = OrderedWorkItem {
            work_id,
            callback_idx,
            data,
            valid: true,
            enqueue_tick: current_tick,
        };
        self.tail = (self.tail + 1) % ORDERED_CAPACITY;
        self.count += 1;
        Ok(work_id)
    }

    /// Dequeue the next work item for execution.
    ///
    /// Returns `None` if the queue is empty or a work item is
    /// already in progress.
    pub fn dequeue(&mut self) -> Option<OrderedWorkItem> {
        if self.in_progress || self.count == 0 {
            return None;
        }
        let item = self.items[self.head];
        if !item.valid {
            return None;
        }
        self.items[self.head] = OrderedWorkItem::new();
        self.head = (self.head + 1) % ORDERED_CAPACITY;
        self.count -= 1;
        self.in_progress = true;
        self.current_work_id = item.work_id;
        Some(item)
    }

    /// Mark the current work item as complete.
    pub fn complete(&mut self) -> Result<()> {
        if !self.in_progress {
            return Err(Error::InvalidArgument);
        }
        self.in_progress = false;
        self.current_work_id = 0;
        Ok(())
    }

    /// Check if the queue is empty.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Check if work is currently in progress.
    pub fn is_busy(&self) -> bool {
        self.in_progress
    }

    /// Flush the queue (remove all pending items).
    pub fn flush(&mut self) -> usize {
        let flushed = self.count;
        self.items = [const { OrderedWorkItem::new() }; ORDERED_CAPACITY];
        self.head = 0;
        self.tail = 0;
        self.count = 0;
        flushed
    }
}

impl Default for OrderedWorkqueue {
    fn default() -> Self {
        Self::new()
    }
}

// ══════════════════════════════════════════════════════════════
// WorkqueueEntry
// ══════════════════════════════════════════════════════════════

/// A workqueue entry in the pool, combining name, affinity,
/// and an optional ordered queue.
#[derive(Clone)]
pub struct WorkqueueEntry {
    /// Workqueue name.
    pub name: [u8; WQ_NAME_LEN],
    /// CPU affinity mask.
    pub affinity: AffinityMask,
    /// Whether this is an ordered (single-threaded) workqueue.
    pub ordered: bool,
    /// Ordered workqueue (used only when `ordered == true`).
    pub ordered_queue: OrderedWorkqueue,
    /// Whether this slot is active.
    pub active: bool,
    /// Total items processed by this workqueue.
    pub items_processed: u64,
}

impl WorkqueueEntry {
    /// Create an empty workqueue entry.
    pub const fn new() -> Self {
        Self {
            name: [0u8; WQ_NAME_LEN],
            affinity: AffinityMask::NONE,
            ordered: false,
            ordered_queue: OrderedWorkqueue::new(),
            active: false,
            items_processed: 0,
        }
    }

    /// Create a named workqueue entry.
    pub fn with_name(name: &[u8], ordered: bool) -> Self {
        let mut entry = Self::new();
        let copy_len = name.len().min(WQ_NAME_LEN);
        entry.name[..copy_len].copy_from_slice(&name[..copy_len]);
        entry.ordered = ordered;
        entry.active = true;
        entry
    }
}

impl Default for WorkqueueEntry {
    fn default() -> Self {
        Self::new()
    }
}

// ══════════════════════════════════════════════════════════════
// WorkqueuePool
// ══════════════════════════════════════════════════════════════

/// Pool of workqueues with affinity and ordering support.
pub struct WorkqueuePool {
    /// Workqueues in the pool.
    pub workqueues: [WorkqueueEntry; MAX_WORKQUEUES],
    /// Number of active workqueues.
    pub count: u32,
}

impl WorkqueuePool {
    /// Create an empty workqueue pool.
    pub const fn new() -> Self {
        Self {
            workqueues: [const { WorkqueueEntry::new() }; MAX_WORKQUEUES],
            count: 0,
        }
    }

    /// Create a new workqueue in the pool.
    pub fn create(&mut self, name: &[u8], ordered: bool) -> Result<u32> {
        if self.count as usize >= MAX_WORKQUEUES {
            return Err(Error::OutOfMemory);
        }
        let idx = self.count;
        self.workqueues[idx as usize] = WorkqueueEntry::with_name(name, ordered);
        self.count += 1;
        Ok(idx)
    }

    /// Destroy a workqueue by index.
    pub fn destroy(&mut self, wq_id: u32) -> Result<()> {
        if wq_id as usize >= self.count as usize {
            return Err(Error::InvalidArgument);
        }
        self.workqueues[wq_id as usize].active = false;
        Ok(())
    }

    /// Get a reference to a workqueue entry.
    pub fn get(&self, wq_id: u32) -> Result<&WorkqueueEntry> {
        if wq_id as usize >= self.count as usize {
            return Err(Error::InvalidArgument);
        }
        let entry = &self.workqueues[wq_id as usize];
        if !entry.active {
            return Err(Error::NotFound);
        }
        Ok(entry)
    }

    /// Get a mutable reference to a workqueue entry.
    pub fn get_mut(&mut self, wq_id: u32) -> Result<&mut WorkqueueEntry> {
        if wq_id as usize >= self.count as usize {
            return Err(Error::InvalidArgument);
        }
        let entry = &mut self.workqueues[wq_id as usize];
        if !entry.active {
            return Err(Error::NotFound);
        }
        Ok(entry)
    }

    /// Set affinity for a workqueue.
    pub fn set_affinity(&mut self, wq_id: u32, mask: AffinityMask) -> Result<()> {
        let entry = self.get_mut(wq_id)?;
        entry.affinity = mask;
        Ok(())
    }
}

impl Default for WorkqueuePool {
    fn default() -> Self {
        Self::new()
    }
}

// ══════════════════════════════════════════════════════════════
// DelayedWork
// ══════════════════════════════════════════════════════════════

/// A delayed work item that fires after a configurable delay.
#[derive(Clone, Copy)]
pub struct DelayedWork {
    /// Unique delayed work ID.
    pub work_id: u64,
    /// Delay in ticks before the work becomes runnable.
    pub delay_ticks: u64,
    /// Tick when the delayed work was scheduled.
    pub scheduled_tick: u64,
    /// Callback index identifying the work function.
    pub callback_idx: u32,
    /// Target workqueue ID (in the pool).
    pub target_wq: u32,
    /// Arbitrary data payload.
    pub data: u64,
    /// Whether this item has been cancelled.
    pub cancelled: bool,
    /// Whether this slot is in use.
    pub active: bool,
}

impl DelayedWork {
    /// Create an empty delayed work item.
    pub const fn new() -> Self {
        Self {
            work_id: 0,
            delay_ticks: 0,
            scheduled_tick: 0,
            callback_idx: 0,
            target_wq: 0,
            data: 0,
            cancelled: false,
            active: false,
        }
    }

    /// Check if this delayed work is due (ready to execute).
    pub fn is_due(&self, current_tick: u64) -> bool {
        self.active && !self.cancelled && current_tick >= self.scheduled_tick + self.delay_ticks
    }

    /// Ticks remaining until this work is due.
    pub fn remaining_ticks(&self, current_tick: u64) -> u64 {
        let target = self.scheduled_tick + self.delay_ticks;
        target.saturating_sub(current_tick)
    }
}

impl Default for DelayedWork {
    fn default() -> Self {
        Self::new()
    }
}

// ══════════════════════════════════════════════════════════════
// WorkqueueExtStats
// ══════════════════════════════════════════════════════════════

/// Statistics for the extended workqueue subsystem.
#[derive(Clone, Copy)]
pub struct WorkqueueExtStats {
    /// Total delayed items queued.
    pub delayed_queued: u64,
    /// Total delayed items executed.
    pub delayed_executed: u64,
    /// Total delayed items cancelled.
    pub delayed_cancelled: u64,
    /// Total ordered workqueue executions.
    pub ordered_executions: u64,
    /// Total affinity changes.
    pub affinity_changes: u64,
    /// Total workqueues created.
    pub workqueues_created: u64,
    /// Total delayed items that expired and were processed.
    pub delayed_expired: u64,
}

impl WorkqueueExtStats {
    /// Create zeroed statistics.
    pub const fn new() -> Self {
        Self {
            delayed_queued: 0,
            delayed_executed: 0,
            delayed_cancelled: 0,
            ordered_executions: 0,
            affinity_changes: 0,
            workqueues_created: 0,
            delayed_expired: 0,
        }
    }
}

impl Default for WorkqueueExtStats {
    fn default() -> Self {
        Self::new()
    }
}

// ══════════════════════════════════════════════════════════════
// WorkqueueExtSubsystem
// ══════════════════════════════════════════════════════════════

/// Extended workqueue subsystem combining delayed work,
/// ordered queues, and affinity support.
pub struct WorkqueueExtSubsystem {
    /// Workqueue pool.
    pub pool: WorkqueuePool,
    /// Delayed work items.
    pub delayed: [DelayedWork; MAX_DELAYED_ITEMS],
    /// Number of active delayed items.
    pub delayed_count: u32,
    /// Next delayed work ID to assign.
    pub next_delayed_id: u64,
    /// Global statistics.
    pub stats: WorkqueueExtStats,
    /// Whether the subsystem is initialized.
    pub initialized: bool,
}

impl WorkqueueExtSubsystem {
    /// Create a new extended workqueue subsystem.
    pub const fn new() -> Self {
        Self {
            pool: WorkqueuePool::new(),
            delayed: [const { DelayedWork::new() }; MAX_DELAYED_ITEMS],
            delayed_count: 0,
            next_delayed_id: 1,
            stats: WorkqueueExtStats::new(),
            initialized: false,
        }
    }

    /// Initialize the subsystem.
    pub fn init(&mut self) -> Result<()> {
        if self.initialized {
            return Err(Error::AlreadyExists);
        }
        self.initialized = true;
        Ok(())
    }

    /// Create a new workqueue in the pool.
    pub fn create_workqueue(&mut self, name: &[u8], ordered: bool) -> Result<u32> {
        if !self.initialized {
            return Err(Error::InvalidArgument);
        }
        let id = self.pool.create(name, ordered)?;
        self.stats.workqueues_created += 1;
        Ok(id)
    }

    /// Create an ordered (single-threaded) workqueue.
    pub fn create_ordered_workqueue(&mut self, name: &[u8]) -> Result<u32> {
        self.create_workqueue(name, true)
    }

    /// Set the CPU affinity for a workqueue.
    pub fn set_workqueue_affinity(&mut self, wq_id: u32, mask: AffinityMask) -> Result<()> {
        self.pool.set_affinity(wq_id, mask)?;
        self.stats.affinity_changes += 1;
        Ok(())
    }

    /// Schedule a delayed work item.
    pub fn schedule_delayed(
        &mut self,
        callback_idx: u32,
        target_wq: u32,
        delay_ticks: u64,
        data: u64,
        current_tick: u64,
    ) -> Result<u64> {
        if !self.initialized {
            return Err(Error::InvalidArgument);
        }
        // Validate target workqueue exists.
        let _ = self.pool.get(target_wq)?;

        // Find a free slot.
        let pos = self.delayed.iter().position(|d| !d.active);
        match pos {
            Some(idx) => {
                let work_id = self.next_delayed_id;
                self.next_delayed_id += 1;

                self.delayed[idx] = DelayedWork {
                    work_id,
                    delay_ticks,
                    scheduled_tick: current_tick,
                    callback_idx,
                    target_wq,
                    data,
                    cancelled: false,
                    active: true,
                };
                self.delayed_count += 1;
                self.stats.delayed_queued += 1;
                Ok(work_id)
            }
            None => Err(Error::OutOfMemory),
        }
    }

    /// Cancel a delayed work item by its ID.
    pub fn cancel_delayed(&mut self, work_id: u64) -> Result<()> {
        let pos = self
            .delayed
            .iter()
            .position(|d| d.active && !d.cancelled && d.work_id == work_id);
        match pos {
            Some(idx) => {
                self.delayed[idx].cancelled = true;
                self.delayed[idx].active = false;
                self.delayed_count = self.delayed_count.saturating_sub(1);
                self.stats.delayed_cancelled += 1;
                Ok(())
            }
            None => Err(Error::NotFound),
        }
    }

    /// Process all delayed items that are due.
    ///
    /// Returns the number of items that became ready and were
    /// enqueued into their target workqueues.
    pub fn process_delayed(&mut self, current_tick: u64) -> Result<u32> {
        if !self.initialized {
            return Err(Error::InvalidArgument);
        }
        let mut processed = 0u32;

        // Collect indices of due items first to avoid borrow issues.
        let mut due_indices = [0usize; MAX_DELAYED_ITEMS];
        let mut due_count = 0usize;

        for (i, item) in self.delayed.iter().enumerate() {
            if item.is_due(current_tick) {
                due_indices[due_count] = i;
                due_count += 1;
            }
        }

        for &idx in &due_indices[..due_count] {
            let item = self.delayed[idx];
            let wq_idx = item.target_wq as usize;

            // Try to enqueue into the target workqueue.
            if wq_idx < self.pool.count as usize && self.pool.workqueues[wq_idx].active {
                if self.pool.workqueues[wq_idx].ordered {
                    let result = self.pool.workqueues[wq_idx].ordered_queue.enqueue(
                        item.callback_idx,
                        item.data,
                        current_tick,
                    );
                    if result.is_ok() {
                        processed += 1;
                        self.stats.delayed_executed += 1;
                    }
                } else {
                    // For non-ordered queues, just count as executed.
                    processed += 1;
                    self.stats.delayed_executed += 1;
                    self.pool.workqueues[wq_idx].items_processed += 1;
                }
            }

            // Mark the delayed item as inactive.
            self.delayed[idx].active = false;
            self.delayed_count = self.delayed_count.saturating_sub(1);
            self.stats.delayed_expired += 1;
        }

        Ok(processed)
    }

    /// Process the next item from an ordered workqueue.
    ///
    /// Returns the dequeued work item, if any.
    pub fn process_ordered(&mut self, wq_id: u32) -> Result<Option<OrderedWorkItem>> {
        let entry = self.pool.get_mut(wq_id)?;
        if !entry.ordered {
            return Err(Error::InvalidArgument);
        }
        let item = entry.ordered_queue.dequeue();
        if item.is_some() {
            self.stats.ordered_executions += 1;
            entry.items_processed += 1;
        }
        Ok(item)
    }

    /// Mark an ordered work item as complete.
    pub fn complete_ordered(&mut self, wq_id: u32) -> Result<()> {
        let entry = self.pool.get_mut(wq_id)?;
        if !entry.ordered {
            return Err(Error::InvalidArgument);
        }
        entry.ordered_queue.complete()
    }

    /// Enqueue work directly into an ordered workqueue.
    pub fn enqueue_ordered(
        &mut self,
        wq_id: u32,
        callback_idx: u32,
        data: u64,
        current_tick: u64,
    ) -> Result<u64> {
        let entry = self.pool.get_mut(wq_id)?;
        if !entry.ordered {
            return Err(Error::InvalidArgument);
        }
        entry
            .ordered_queue
            .enqueue(callback_idx, data, current_tick)
    }

    /// Flush all pending items from an ordered workqueue.
    pub fn flush_ordered(&mut self, wq_id: u32) -> Result<usize> {
        let entry = self.pool.get_mut(wq_id)?;
        if !entry.ordered {
            return Err(Error::InvalidArgument);
        }
        Ok(entry.ordered_queue.flush())
    }

    /// Get the number of pending delayed items.
    pub fn pending_delayed_count(&self) -> u32 {
        self.delayed_count
    }

    /// Get the next delayed item's due tick (for timer programming).
    pub fn next_delayed_due_tick(&self) -> Option<u64> {
        let mut earliest: Option<u64> = None;
        for item in &self.delayed {
            if item.active && !item.cancelled {
                let due = item.scheduled_tick + item.delay_ticks;
                match earliest {
                    Some(e) if due < e => earliest = Some(due),
                    None => earliest = Some(due),
                    _ => {}
                }
            }
        }
        earliest
    }

    /// Get global statistics.
    pub fn get_stats(&self) -> &WorkqueueExtStats {
        &self.stats
    }

    /// Reset all statistics.
    pub fn reset_stats(&mut self) {
        self.stats = WorkqueueExtStats::new();
    }
}

impl Default for WorkqueueExtSubsystem {
    fn default() -> Self {
        Self::new()
    }
}

/// Create an ordered workqueue in the subsystem.
///
/// Convenience wrapper for `WorkqueueExtSubsystem::create_ordered_workqueue`.
pub fn create_ordered_workqueue(subsystem: &mut WorkqueueExtSubsystem, name: &[u8]) -> Result<u32> {
    subsystem.create_ordered_workqueue(name)
}

/// Set CPU affinity for a workqueue.
///
/// Convenience wrapper for `WorkqueueExtSubsystem::set_workqueue_affinity`.
pub fn set_workqueue_affinity(
    subsystem: &mut WorkqueueExtSubsystem,
    wq_id: u32,
    mask: AffinityMask,
) -> Result<()> {
    subsystem.set_workqueue_affinity(wq_id, mask)
}
