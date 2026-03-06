// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Workqueue infrastructure.
//!
//! Workqueues provide a generic mechanism for deferring work to
//! process context. Unlike softirqs and tasklets, workqueue
//! handlers run in a kernel thread and may sleep.
//!
//! # Architecture
//!
//! ```text
//! WorkqueueSubsystem
//! ├── workqueues: [WorkQueue; MAX_WORKQUEUES]
//! │   ├── name, flags, max_active
//! │   └── work_items: [WorkStruct; MAX_WORK_ITEMS]
//! ├── worker_pools: [WorkerPool; MAX_POOLS]
//! │   └── workers: [Worker; MAX_WORKERS_PER_POOL]
//! └── stats: WorkqueueStats
//! ```
//!
//! # Workqueue Types
//!
//! | Type | Description |
//! |------|-------------|
//! | Bound | Workers bound to a specific CPU |
//! | Unbound | Workers can run on any CPU |
//! | Ordered | Work items executed sequentially |
//! | HighPriority | Higher scheduling priority |
//!
//! # Reference
//!
//! Linux `kernel/workqueue.c`, `include/linux/workqueue.h`.

use oncrix_lib::{Error, Result};

// ── Constants ────────────────────────────────────────────────

/// Maximum number of workqueues.
const MAX_WORKQUEUES: usize = 64;

/// Maximum work items per workqueue.
const MAX_WORK_ITEMS: usize = 128;

/// Maximum number of worker pools.
const MAX_POOLS: usize = 32;

/// Maximum workers per pool.
const MAX_WORKERS_PER_POOL: usize = 16;

/// Maximum workqueue name length.
const MAX_NAME_LEN: usize = 32;

// ── WorkFlags ───────────────────────────────────────────────

/// Workqueue creation flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WqFlags(u32);

impl WqFlags {
    /// Default (bound, per-CPU).
    pub const DEFAULT: Self = Self(0);
    /// Unbound — workers can migrate across CPUs.
    pub const UNBOUND: Self = Self(1 << 0);
    /// Freezable — work pauses during system suspend.
    pub const FREEZABLE: Self = Self(1 << 1);
    /// Ordered — work items execute one at a time.
    pub const ORDERED: Self = Self(1 << 2);
    /// High priority — uses higher-priority worker threads.
    pub const HIGHPRI: Self = Self(1 << 3);

    /// Test flag.
    pub const fn contains(self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }

    /// Set flag.
    pub const fn set(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// Raw value.
    pub const fn raw(self) -> u32 {
        self.0
    }
}

// ── WorkState ───────────────────────────────────────────────

/// State of a work item.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum WorkState {
    /// Slot is free.
    #[default]
    Free,
    /// Queued and waiting for a worker.
    Pending,
    /// Currently being executed by a worker.
    Running,
    /// Completed.
    Completed,
    /// Cancelled.
    Cancelled,
}

// ── WorkFn ──────────────────────────────────────────────────

/// Work callback function type.
pub type WorkFn = fn(u64);

// ── WorkStruct ──────────────────────────────────────────────

/// A single work item.
#[derive(Clone, Copy)]
pub struct WorkStruct {
    /// Unique work ID.
    id: u32,
    /// Callback function.
    func: Option<WorkFn>,
    /// Opaque data.
    data: u64,
    /// Current state.
    state: WorkState,
    /// Priority (for ordering within the queue).
    priority: u32,
    /// Sequence number.
    seq: u64,
}

impl core::fmt::Debug for WorkStruct {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("WorkStruct")
            .field("id", &self.id)
            .field("state", &self.state)
            .field("priority", &self.priority)
            .field("seq", &self.seq)
            .finish()
    }
}

impl WorkStruct {
    /// Create an empty work item.
    const fn empty() -> Self {
        Self {
            id: 0,
            func: None,
            data: 0,
            state: WorkState::Free,
            priority: 0,
            seq: 0,
        }
    }

    /// Work item ID.
    pub fn id(&self) -> u32 {
        self.id
    }

    /// Current state.
    pub fn state(&self) -> WorkState {
        self.state
    }

    /// Whether this item is pending.
    pub fn is_pending(&self) -> bool {
        self.state == WorkState::Pending
    }
}

// ── WorkerState ─────────────────────────────────────────────

/// State of a worker thread.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum WorkerState {
    /// Worker is idle (waiting for work).
    #[default]
    Idle,
    /// Worker is executing a work item.
    Busy,
    /// Worker is being shut down.
    Dying,
}

// ── Worker ──────────────────────────────────────────────────

/// A worker thread in a worker pool.
#[derive(Debug, Clone, Copy)]
pub struct Worker {
    /// Worker ID.
    id: u32,
    /// Current state.
    state: WorkerState,
    /// CPU this worker is bound to (u32::MAX if unbound).
    cpu: u32,
    /// Number of work items processed.
    processed: u64,
    /// Whether active.
    active: bool,
}

impl Worker {
    /// Create an empty worker.
    const fn empty() -> Self {
        Self {
            id: 0,
            state: WorkerState::Idle,
            cpu: u32::MAX,
            processed: 0,
            active: false,
        }
    }

    /// Worker state.
    pub fn state(&self) -> WorkerState {
        self.state
    }

    /// Items processed.
    pub fn processed(&self) -> u64 {
        self.processed
    }
}

// ── WorkerPool ──────────────────────────────────────────────

/// A pool of worker threads.
struct WorkerPool {
    /// Pool ID.
    id: u32,
    /// Workers.
    workers: [Worker; MAX_WORKERS_PER_POOL],
    /// Number of active workers.
    worker_count: u32,
    /// CPU affinity (u32::MAX if unbound).
    cpu: u32,
    /// Whether active.
    active: bool,
    /// Next worker ID.
    next_worker_id: u32,
}

impl WorkerPool {
    /// Create an empty pool.
    const fn empty() -> Self {
        Self {
            id: 0,
            workers: [Worker::empty(); MAX_WORKERS_PER_POOL],
            worker_count: 0,
            cpu: u32::MAX,
            active: false,
            next_worker_id: 1,
        }
    }

    /// Create a worker in this pool.
    fn create_worker(&mut self, cpu: u32) -> Result<u32> {
        let slot = self
            .workers
            .iter()
            .position(|w| !w.active)
            .ok_or(Error::OutOfMemory)?;

        let wid = self.next_worker_id;
        self.next_worker_id = self.next_worker_id.wrapping_add(1);

        self.workers[slot] = Worker {
            id: wid,
            state: WorkerState::Idle,
            cpu,
            processed: 0,
            active: true,
        };
        self.worker_count += 1;
        Ok(wid)
    }

    /// Find an idle worker.
    fn find_idle_worker(&mut self) -> Option<&mut Worker> {
        self.workers
            .iter_mut()
            .find(|w| w.active && w.state == WorkerState::Idle)
    }
}

// ── WorkQueue ───────────────────────────────────────────────

/// A workqueue that holds work items.
struct WorkQueue {
    /// Workqueue ID.
    id: u32,
    /// Name.
    name: [u8; MAX_NAME_LEN],
    /// Name length.
    name_len: usize,
    /// Flags.
    flags: WqFlags,
    /// Maximum concurrent active work items.
    max_active: u32,
    /// Current active count.
    active_count: u32,
    /// Work items.
    items: [WorkStruct; MAX_WORK_ITEMS],
    /// Number of pending items.
    pending_count: usize,
    /// Total items queued.
    total_queued: u64,
    /// Total items processed.
    total_processed: u64,
    /// Associated pool ID.
    pool_id: u32,
    /// Next work item sequence.
    next_seq: u64,
    /// Next work item ID.
    next_work_id: u32,
    /// Whether active.
    active: bool,
}

impl WorkQueue {
    /// Create an empty workqueue.
    const fn empty() -> Self {
        Self {
            id: 0,
            name: [0u8; MAX_NAME_LEN],
            name_len: 0,
            flags: WqFlags::DEFAULT,
            max_active: 0,
            active_count: 0,
            items: [WorkStruct::empty(); MAX_WORK_ITEMS],
            pending_count: 0,
            total_queued: 0,
            total_processed: 0,
            pool_id: 0,
            next_seq: 1,
            next_work_id: 1,
            active: false,
        }
    }

    /// Queue a work item. Returns the work ID.
    fn queue_work(&mut self, func: WorkFn, data: u64, priority: u32) -> Result<u32> {
        let slot = self
            .items
            .iter()
            .position(|w| w.state == WorkState::Free)
            .ok_or(Error::OutOfMemory)?;

        let wid = self.next_work_id;
        self.next_work_id = self.next_work_id.wrapping_add(1);
        let seq = self.next_seq;
        self.next_seq += 1;

        self.items[slot] = WorkStruct {
            id: wid,
            func: Some(func),
            data,
            state: WorkState::Pending,
            priority,
            seq,
        };
        self.pending_count += 1;
        self.total_queued += 1;
        Ok(wid)
    }

    /// Dequeue the next pending work item.
    fn dequeue(&mut self) -> Option<(WorkFn, u64, usize)> {
        // Find highest-priority pending item.
        let mut best: Option<usize> = None;
        let mut best_seq = u64::MAX;

        for (i, item) in self.items.iter().enumerate() {
            if item.state == WorkState::Pending && item.seq < best_seq {
                best = Some(i);
                best_seq = item.seq;
            }
        }

        let idx = best?;
        let func = self.items[idx].func?;
        let data = self.items[idx].data;
        self.items[idx].state = WorkState::Running;
        self.pending_count = self.pending_count.saturating_sub(1);
        self.active_count += 1;
        Some((func, data, idx))
    }

    /// Mark a work item as completed.
    fn complete_work(&mut self, idx: usize) {
        if idx < MAX_WORK_ITEMS {
            self.items[idx].state = WorkState::Completed;
            self.active_count = self.active_count.saturating_sub(1);
            self.total_processed += 1;
        }
    }

    /// Flush: process all pending work items.
    fn flush(&mut self) -> u32 {
        let mut processed = 0u32;
        while let Some((func, data, idx)) = self.dequeue() {
            func(data);
            self.complete_work(idx);
            processed += 1;
        }
        processed
    }

    /// Cancel a specific work item.
    fn cancel_work(&mut self, work_id: u32) -> Result<()> {
        let item = self
            .items
            .iter_mut()
            .find(|w| w.id == work_id && w.state == WorkState::Pending)
            .ok_or(Error::NotFound)?;
        item.state = WorkState::Cancelled;
        self.pending_count = self.pending_count.saturating_sub(1);
        Ok(())
    }

    /// Return the name.
    fn name_str(&self) -> &str {
        let len = self.name_len.min(MAX_NAME_LEN);
        core::str::from_utf8(&self.name[..len]).unwrap_or("<invalid>")
    }
}

// ── WorkqueueStats ──────────────────────────────────────────

/// Global workqueue statistics.
#[derive(Debug, Clone, Copy, Default)]
pub struct WorkqueueStats {
    /// Total workqueues created.
    pub wq_created: u64,
    /// Total workqueues destroyed.
    pub wq_destroyed: u64,
    /// Total work items queued.
    pub total_queued: u64,
    /// Total work items processed.
    pub total_processed: u64,
    /// Total work items cancelled.
    pub total_cancelled: u64,
    /// Total flushes.
    pub total_flushes: u64,
}

// ── WorkqueueSubsystem ──────────────────────────────────────

/// Global workqueue subsystem.
pub struct WorkqueueSubsystem {
    /// Workqueues.
    workqueues: [WorkQueue; MAX_WORKQUEUES],
    /// Worker pools.
    pools: [WorkerPool; MAX_POOLS],
    /// Number of active workqueues.
    wq_count: usize,
    /// Number of active pools.
    pool_count: usize,
    /// Next WQ ID.
    next_wq_id: u32,
    /// Next pool ID.
    next_pool_id: u32,
    /// Statistics.
    stats: WorkqueueStats,
    /// Whether initialized.
    initialized: bool,
}

impl WorkqueueSubsystem {
    /// Create a new workqueue subsystem.
    pub const fn new() -> Self {
        Self {
            workqueues: [const { WorkQueue::empty() }; MAX_WORKQUEUES],
            pools: [const { WorkerPool::empty() }; MAX_POOLS],
            wq_count: 0,
            pool_count: 0,
            next_wq_id: 1,
            next_pool_id: 1,
            stats: WorkqueueStats {
                wq_created: 0,
                wq_destroyed: 0,
                total_queued: 0,
                total_processed: 0,
                total_cancelled: 0,
                total_flushes: 0,
            },
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

    /// Create a workqueue. Returns the workqueue ID.
    pub fn create_workqueue(&mut self, name: &str, flags: WqFlags, max_active: u32) -> Result<u32> {
        if !self.initialized {
            return Err(Error::InvalidArgument);
        }
        let slot = self
            .workqueues
            .iter()
            .position(|wq| !wq.active)
            .ok_or(Error::OutOfMemory)?;

        let wq_id = self.next_wq_id;
        self.next_wq_id = self.next_wq_id.wrapping_add(1);

        // Create an associated worker pool.
        let pool_id = self.create_pool(if flags.contains(WqFlags::UNBOUND) {
            u32::MAX
        } else {
            0
        })?;

        self.workqueues[slot] = WorkQueue::empty();
        self.workqueues[slot].id = wq_id;
        self.workqueues[slot].flags = flags;
        self.workqueues[slot].max_active = max_active.max(1);
        self.workqueues[slot].pool_id = pool_id;
        self.workqueues[slot].active = true;

        let copy_len = name.len().min(MAX_NAME_LEN);
        self.workqueues[slot].name[..copy_len].copy_from_slice(&name.as_bytes()[..copy_len]);
        self.workqueues[slot].name_len = copy_len;

        self.wq_count += 1;
        self.stats.wq_created += 1;
        Ok(wq_id)
    }

    /// Destroy a workqueue.
    pub fn destroy_workqueue(&mut self, wq_id: u32) -> Result<()> {
        let wq = self
            .workqueues
            .iter_mut()
            .find(|wq| wq.active && wq.id == wq_id)
            .ok_or(Error::NotFound)?;

        if wq.pending_count > 0 || wq.active_count > 0 {
            return Err(Error::Busy);
        }

        wq.active = false;
        self.wq_count = self.wq_count.saturating_sub(1);
        self.stats.wq_destroyed += 1;
        Ok(())
    }

    /// Queue work on a workqueue.
    pub fn queue_work(&mut self, wq_id: u32, func: WorkFn, data: u64) -> Result<u32> {
        let wq = self
            .workqueues
            .iter_mut()
            .find(|wq| wq.active && wq.id == wq_id)
            .ok_or(Error::NotFound)?;

        let work_id = wq.queue_work(func, data, 0)?;
        self.stats.total_queued += 1;
        Ok(work_id)
    }

    /// Queue work with a priority hint.
    pub fn queue_work_priority(
        &mut self,
        wq_id: u32,
        func: WorkFn,
        data: u64,
        priority: u32,
    ) -> Result<u32> {
        let wq = self
            .workqueues
            .iter_mut()
            .find(|wq| wq.active && wq.id == wq_id)
            .ok_or(Error::NotFound)?;

        let work_id = wq.queue_work(func, data, priority)?;
        self.stats.total_queued += 1;
        Ok(work_id)
    }

    /// Cancel a pending work item.
    pub fn cancel_work(&mut self, wq_id: u32, work_id: u32) -> Result<()> {
        let wq = self
            .workqueues
            .iter_mut()
            .find(|wq| wq.active && wq.id == wq_id)
            .ok_or(Error::NotFound)?;
        wq.cancel_work(work_id)?;
        self.stats.total_cancelled += 1;
        Ok(())
    }

    /// Flush a workqueue (process all pending work).
    pub fn flush_workqueue(&mut self, wq_id: u32) -> Result<u32> {
        let wq = self
            .workqueues
            .iter_mut()
            .find(|wq| wq.active && wq.id == wq_id)
            .ok_or(Error::NotFound)?;

        let processed = wq.flush();
        self.stats.total_processed += processed as u64;
        self.stats.total_flushes += 1;
        Ok(processed)
    }

    /// Process one pending work item from a workqueue.
    pub fn process_one(&mut self, wq_id: u32) -> Result<bool> {
        let wq = self
            .workqueues
            .iter_mut()
            .find(|wq| wq.active && wq.id == wq_id)
            .ok_or(Error::NotFound)?;

        if let Some((func, data, idx)) = wq.dequeue() {
            func(data);
            wq.complete_work(idx);
            self.stats.total_processed += 1;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Find a workqueue by name.
    pub fn find_by_name(&self, name: &str) -> Option<u32> {
        self.workqueues
            .iter()
            .find(|wq| wq.active && wq.name_str() == name)
            .map(|wq| wq.id)
    }

    /// Return the number of active workqueues.
    pub fn wq_count(&self) -> usize {
        self.wq_count
    }

    /// Return statistics.
    pub fn stats(&self) -> &WorkqueueStats {
        &self.stats
    }

    // ── Internal ────────────────────────────────────────────

    /// Create a worker pool.
    fn create_pool(&mut self, cpu: u32) -> Result<u32> {
        let slot = self
            .pools
            .iter()
            .position(|p| !p.active)
            .ok_or(Error::OutOfMemory)?;

        let pid = self.next_pool_id;
        self.next_pool_id = self.next_pool_id.wrapping_add(1);

        self.pools[slot] = WorkerPool::empty();
        self.pools[slot].id = pid;
        self.pools[slot].cpu = cpu;
        self.pools[slot].active = true;
        // Create an initial worker.
        self.pools[slot].create_worker(cpu)?;
        self.pool_count += 1;
        Ok(pid)
    }
}

impl Default for WorkqueueSubsystem {
    fn default() -> Self {
        Self::new()
    }
}
