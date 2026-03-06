// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Concurrency Managed Work Queues (CMWQ).
//!
//! An enhanced per-CPU workqueue system modeled after Linux's CMWQ
//! (`kernel/workqueue.c`). Each [`CmWorkqueue`] maintains per-CPU
//! worker pools plus an unbound pool for work that is not
//! CPU-affine. A global [`CmwqRegistry`] manages multiple named
//! workqueues.
//!
//! Key features:
//! - Per-CPU worker pools with configurable concurrency limits
//! - Unbound pool for non-CPU-affine work
//! - Priority-based scheduling (High, Normal, Low, Unbound)
//! - Work cancellation and flush support
//! - Congestion detection
//!
//! All structures use fixed-size arrays with no heap allocation,
//! suitable for `#![no_std]` kernel environments.

use core::fmt;

use oncrix_lib::{Error, Result};

// ======================================================================
// Constants
// ======================================================================

/// Maximum work items per worker pool.
const POOL_CAPACITY: usize = 64;

/// Maximum CPUs supported.
const MAX_CPUS: usize = 8;

/// Maximum workqueues in the global registry.
const MAX_QUEUES: usize = 16;

/// Maximum length of a workqueue name.
const WQ_NAME_LEN: usize = 32;

/// Congestion threshold: a pool is congested when it exceeds 75% capacity.
const CONGESTION_THRESHOLD: usize = POOL_CAPACITY * 3 / 4;

/// Default maximum active work items per pool.
const DEFAULT_MAX_ACTIVE: u32 = 16;

// ======================================================================
// Work flags
// ======================================================================

/// Flag: work may run on any CPU (not pinned).
pub const WQ_UNBOUND: u32 = 1;

/// Flag: workqueue participates in system freeze.
pub const WQ_FREEZABLE: u32 = 2;

/// Flag: high-priority worker pool.
pub const WQ_HIGHPRI: u32 = 4;

/// Flag: CPU-intensive work — does not count against concurrency limit.
pub const WQ_CPU_INTENSIVE: u32 = 8;

// ======================================================================
// WorkPriority
// ======================================================================

/// Priority level for a CMWQ [`WorkItem`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum WorkPriority {
    /// Processed first — latency-sensitive deferred work.
    High,
    /// Default priority for most deferred work.
    #[default]
    Normal,
    /// Processed last — background housekeeping.
    Low,
    /// Not CPU-affine — routed to the unbound pool.
    Unbound,
}

impl WorkPriority {
    /// Numeric rank where **lower is higher priority**.
    const fn rank(self) -> u8 {
        match self {
            Self::High => 0,
            Self::Normal => 1,
            Self::Low => 2,
            Self::Unbound => 3,
        }
    }
}

// ======================================================================
// WorkItem
// ======================================================================

/// A single unit of deferred work in a CMWQ pool.
#[derive(Debug, Clone, Copy)]
pub struct WorkItem {
    /// Unique identifier assigned at scheduling time.
    pub id: u64,
    /// Identifies the handler function to invoke.
    pub func_id: u64,
    /// Opaque data passed to the handler.
    pub data: u64,
    /// Scheduling priority.
    pub priority: WorkPriority,
    /// CPU this item is bound to (ignored for unbound work).
    pub cpu_id: u32,
    /// Whether this item is pending execution.
    pub pending: bool,
    /// Whether this item is currently being executed.
    pub running: bool,
    /// Whether this item has been cancelled.
    pub cancelled: bool,
}

impl WorkItem {
    /// Create an empty (inactive) work item for array initialisation.
    const fn empty() -> Self {
        Self {
            id: 0,
            func_id: 0,
            data: 0,
            priority: WorkPriority::Normal,
            cpu_id: 0,
            pending: false,
            running: false,
            cancelled: false,
        }
    }
}

impl Default for WorkItem {
    fn default() -> Self {
        Self::empty()
    }
}

// ======================================================================
// WorkerPool
// ======================================================================

/// A per-CPU (or unbound) pool of work items with ring-buffer storage.
pub struct WorkerPool {
    /// CPU this pool is associated with (u32::MAX for unbound).
    pub cpu_id: u32,
    /// Ring-buffer storage for work items.
    items: [WorkItem; POOL_CAPACITY],
    /// Ring-buffer head (next dequeue position).
    head: usize,
    /// Ring-buffer tail (next enqueue position).
    tail: usize,
    /// Number of pending items in the ring buffer.
    count: usize,
    /// Number of workers currently running items from this pool.
    pub nr_running: u32,
    /// Maximum number of concurrently active items.
    pub max_active: u32,
    /// Workqueue flags inherited from the parent [`CmWorkqueue`].
    pub flags: u32,
}

impl WorkerPool {
    /// Create a new, empty worker pool for the given CPU.
    const fn new(cpu_id: u32) -> Self {
        Self {
            cpu_id,
            items: [WorkItem::empty(); POOL_CAPACITY],
            head: 0,
            tail: 0,
            count: 0,
            nr_running: 0,
            max_active: DEFAULT_MAX_ACTIVE,
            flags: 0,
        }
    }

    /// Enqueue a work item into this pool.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the pool is full.
    pub fn enqueue(&mut self, item: WorkItem) -> Result<()> {
        if self.count >= POOL_CAPACITY {
            return Err(Error::OutOfMemory);
        }
        self.items[self.tail] = item;
        self.tail = (self.tail + 1) % POOL_CAPACITY;
        self.count = self.count.saturating_add(1);
        Ok(())
    }

    /// Dequeue the highest-priority pending work item.
    ///
    /// Scans the ring buffer for the pending item with the highest
    /// priority (lowest rank). Among equal-priority items the one
    /// closest to the head wins (FIFO within a priority level).
    ///
    /// Returns `None` if the pool has no pending items.
    pub fn dequeue(&mut self) -> Option<WorkItem> {
        if self.count == 0 {
            return None;
        }

        let mut best_idx: Option<usize> = None;
        let mut best_rank: u8 = u8::MAX;

        let mut pos = self.head;
        for _ in 0..self.count {
            if self.items[pos].pending && !self.items[pos].cancelled {
                let rank = self.items[pos].priority.rank();
                if rank < best_rank {
                    best_rank = rank;
                    best_idx = Some(pos);
                    if best_rank == 0 {
                        break;
                    }
                }
            }
            pos = (pos + 1) % POOL_CAPACITY;
        }

        let idx = best_idx?;
        let mut item = self.items[idx];
        item.pending = false;
        item.running = true;
        self.items[idx].pending = false;
        self.items[idx].running = true;

        // Compact: shift items to fill the gap, maintaining ring order.
        self.remove_at(idx);
        self.nr_running = self.nr_running.saturating_add(1);

        Some(item)
    }

    /// Cancel a pending work item by its ID.
    ///
    /// Returns `Ok(true)` if the item was found and cancelled,
    /// `Ok(false)` if no matching pending item was found.
    pub fn cancel(&mut self, work_id: u64) -> Result<bool> {
        let mut pos = self.head;
        for _ in 0..self.count {
            if self.items[pos].id == work_id && self.items[pos].pending {
                self.items[pos].cancelled = true;
                self.items[pos].pending = false;
                self.remove_at(pos);
                return Ok(true);
            }
            pos = (pos + 1) % POOL_CAPACITY;
        }
        Ok(false)
    }

    /// Return the number of pending (not yet dequeued) items.
    pub fn pending_count(&self) -> usize {
        self.count
    }

    /// Return `true` if this pool is congested (above threshold).
    pub fn is_congested(&self) -> bool {
        self.count > CONGESTION_THRESHOLD
    }

    /// Remove the item at the given ring-buffer index and compact.
    fn remove_at(&mut self, idx: usize) {
        // Shift subsequent items backward to fill the gap.
        let mut cur = idx;
        loop {
            let next = (cur + 1) % POOL_CAPACITY;
            if next == self.tail {
                break;
            }
            self.items[cur] = self.items[next];
            cur = next;
        }
        // Move tail backward.
        if self.tail == 0 {
            self.tail = POOL_CAPACITY - 1;
        } else {
            self.tail -= 1;
        }
        self.count = self.count.saturating_sub(1);
    }
}

impl Default for WorkerPool {
    fn default() -> Self {
        Self::new(0)
    }
}

impl fmt::Debug for WorkerPool {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WorkerPool")
            .field("cpu_id", &self.cpu_id)
            .field("count", &self.count)
            .field("nr_running", &self.nr_running)
            .field("max_active", &self.max_active)
            .finish()
    }
}

// ======================================================================
// CmWorkqueue
// ======================================================================

/// A concurrency-managed workqueue with per-CPU and unbound pools.
///
/// Each workqueue has up to [`MAX_CPUS`] per-CPU pools and one
/// unbound pool. Work is routed based on priority: [`Unbound`]
/// priority goes to the unbound pool; all others go to the
/// specified (or current) CPU's pool.
///
/// [`Unbound`]: WorkPriority::Unbound
pub struct CmWorkqueue {
    /// Human-readable name (fixed buffer, NUL-padded).
    name: [u8; WQ_NAME_LEN],
    /// Valid length of `name` in bytes.
    name_len: usize,
    /// Per-CPU worker pools.
    pools: [WorkerPool; MAX_CPUS],
    /// Pool for unbound (non-CPU-affine) work.
    unbound_pool: WorkerPool,
    /// Workqueue flags (combination of `WQ_*` constants).
    pub flags: u32,
    /// Maximum active items per pool.
    pub max_active: u32,
    /// Monotonically increasing work ID counter.
    next_id: u64,
    /// Whether this workqueue slot is in use.
    pub in_use: bool,
}

impl CmWorkqueue {
    /// Create a new, inactive workqueue for array initialisation.
    const fn empty() -> Self {
        Self {
            name: [0u8; WQ_NAME_LEN],
            name_len: 0,
            pools: [
                WorkerPool::new(0),
                WorkerPool::new(1),
                WorkerPool::new(2),
                WorkerPool::new(3),
                WorkerPool::new(4),
                WorkerPool::new(5),
                WorkerPool::new(6),
                WorkerPool::new(7),
            ],
            unbound_pool: WorkerPool::new(u32::MAX),
            flags: 0,
            max_active: DEFAULT_MAX_ACTIVE,
            next_id: 1,
            in_use: false,
        }
    }

    /// Return the workqueue name as a `&str`.
    pub fn name_str(&self) -> &str {
        let len = self.name_len.min(WQ_NAME_LEN);
        core::str::from_utf8(&self.name[..len]).unwrap_or("<invalid>")
    }

    /// Allocate the next work ID.
    fn alloc_id(&mut self) -> u64 {
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);
        id
    }

    /// Schedule work on the appropriate pool based on priority.
    ///
    /// For [`WorkPriority::Unbound`] the work goes to the unbound pool.
    /// For all other priorities, CPU 0 is used as the default target.
    ///
    /// Returns the assigned work ID on success.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if the workqueue is not in use.
    /// Returns [`Error::OutOfMemory`] if the target pool is full.
    pub fn schedule_work(
        &mut self,
        func_id: u64,
        data: u64,
        priority: WorkPriority,
    ) -> Result<u64> {
        if !self.in_use {
            return Err(Error::InvalidArgument);
        }

        let id = self.alloc_id();

        if priority == WorkPriority::Unbound || self.flags & WQ_UNBOUND != 0 {
            let item = WorkItem {
                id,
                func_id,
                data,
                priority,
                cpu_id: u32::MAX,
                pending: true,
                running: false,
                cancelled: false,
            };
            self.unbound_pool.enqueue(item)?;
        } else {
            let item = WorkItem {
                id,
                func_id,
                data,
                priority,
                cpu_id: 0,
                pending: true,
                running: false,
                cancelled: false,
            };
            self.pools[0].enqueue(item)?;
        }

        Ok(id)
    }

    /// Schedule work on a specific CPU's pool.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if the workqueue is not in use.
    /// Returns [`Error::InvalidArgument`] if `cpu_id` is out of range.
    /// Returns [`Error::OutOfMemory`] if the target pool is full.
    pub fn schedule_on_cpu(&mut self, func_id: u64, data: u64, cpu_id: u32) -> Result<u64> {
        if !self.in_use {
            return Err(Error::InvalidArgument);
        }
        if cpu_id as usize >= MAX_CPUS {
            return Err(Error::InvalidArgument);
        }

        let id = self.alloc_id();
        let item = WorkItem {
            id,
            func_id,
            data,
            priority: WorkPriority::Normal,
            cpu_id,
            pending: true,
            running: false,
            cancelled: false,
        };
        self.pools[cpu_id as usize].enqueue(item)?;
        Ok(id)
    }

    /// Cancel a pending work item by its ID.
    ///
    /// Searches all pools (per-CPU and unbound). Returns `Ok(true)` if
    /// the item was found and cancelled, `Ok(false)` otherwise.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if the workqueue is not in use.
    pub fn cancel_work(&mut self, work_id: u64) -> Result<bool> {
        if !self.in_use {
            return Err(Error::InvalidArgument);
        }

        for pool in &mut self.pools {
            if pool.cancel(work_id)? {
                return Ok(true);
            }
        }
        self.unbound_pool.cancel(work_id)
    }

    /// Flush all pending work by processing every pool.
    ///
    /// This is a synchronous drain: all pending items across all pools
    /// are dequeued (but not executed — execution is the caller's
    /// responsibility via the returned items). The pools are left empty.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if the workqueue is not in use.
    pub fn flush(&mut self) -> Result<()> {
        if !self.in_use {
            return Err(Error::InvalidArgument);
        }

        for pool in &mut self.pools {
            while pool.dequeue().is_some() {}
        }
        while self.unbound_pool.dequeue().is_some() {}
        Ok(())
    }

    /// Process pending work items for a specific CPU.
    ///
    /// Dequeues and marks items as processed, respecting the pool's
    /// `max_active` concurrency limit. Returns the number of items
    /// processed.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if the workqueue is not in use.
    /// Returns [`Error::InvalidArgument`] if `cpu_id` is out of range.
    pub fn process_cpu(&mut self, cpu_id: u32) -> Result<u32> {
        if !self.in_use {
            return Err(Error::InvalidArgument);
        }
        if cpu_id as usize >= MAX_CPUS {
            return Err(Error::InvalidArgument);
        }

        let pool = &mut self.pools[cpu_id as usize];
        let mut processed: u32 = 0;

        while pool.nr_running < pool.max_active {
            if pool.dequeue().is_some() {
                processed = processed.saturating_add(1);
                // In a real implementation the dequeued item would be
                // dispatched to a worker thread. Here we simply count
                // it and mark nr_running as decremented (work "done").
                pool.nr_running = pool.nr_running.saturating_sub(1);
            } else {
                break;
            }
        }

        Ok(processed)
    }

    /// Process pending work items from the unbound pool.
    ///
    /// Returns the number of items processed.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if the workqueue is not in use.
    pub fn process_unbound(&mut self) -> Result<u32> {
        if !self.in_use {
            return Err(Error::InvalidArgument);
        }

        let pool = &mut self.unbound_pool;
        let mut processed: u32 = 0;

        while pool.nr_running < pool.max_active {
            if pool.dequeue().is_some() {
                processed = processed.saturating_add(1);
                pool.nr_running = pool.nr_running.saturating_sub(1);
            } else {
                break;
            }
        }

        Ok(processed)
    }

    /// Return the total number of pending items across all pools.
    pub fn pending_all(&self) -> usize {
        let cpu_pending: usize = self.pools.iter().map(|p| p.pending_count()).sum();
        cpu_pending.saturating_add(self.unbound_pool.pending_count())
    }
}

impl Default for CmWorkqueue {
    fn default() -> Self {
        Self::empty()
    }
}

impl fmt::Debug for CmWorkqueue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CmWorkqueue")
            .field("name", &self.name_str())
            .field("flags", &self.flags)
            .field("max_active", &self.max_active)
            .field("pending", &self.pending_all())
            .field("in_use", &self.in_use)
            .finish()
    }
}

// ======================================================================
// CmwqRegistry
// ======================================================================

/// Global registry of concurrency-managed workqueues.
///
/// Manages up to [`MAX_QUEUES`] named workqueues, each identified by
/// its array index.
pub struct CmwqRegistry {
    /// Workqueue slots.
    queues: [CmWorkqueue; MAX_QUEUES],
    /// Number of active workqueues.
    count: usize,
}

impl CmwqRegistry {
    /// Create a new, empty registry.
    pub const fn new() -> Self {
        Self {
            queues: [
                CmWorkqueue::empty(),
                CmWorkqueue::empty(),
                CmWorkqueue::empty(),
                CmWorkqueue::empty(),
                CmWorkqueue::empty(),
                CmWorkqueue::empty(),
                CmWorkqueue::empty(),
                CmWorkqueue::empty(),
                CmWorkqueue::empty(),
                CmWorkqueue::empty(),
                CmWorkqueue::empty(),
                CmWorkqueue::empty(),
                CmWorkqueue::empty(),
                CmWorkqueue::empty(),
                CmWorkqueue::empty(),
                CmWorkqueue::empty(),
            ],
            count: 0,
        }
    }

    /// Create a new workqueue with the given name, flags, and max active.
    ///
    /// Returns the queue ID (slot index) on success.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if all slots are occupied.
    pub fn create(&mut self, name: &str, flags: u32, max_active: u32) -> Result<u64> {
        let slot = self
            .queues
            .iter()
            .position(|q| !q.in_use)
            .ok_or(Error::OutOfMemory)?;

        let mut name_buf = [0u8; WQ_NAME_LEN];
        let copy_len = name.len().min(WQ_NAME_LEN);
        name_buf[..copy_len].copy_from_slice(&name.as_bytes()[..copy_len]);

        let wq = &mut self.queues[slot];
        wq.name = name_buf;
        wq.name_len = copy_len;
        wq.flags = flags;
        wq.max_active = if max_active == 0 {
            DEFAULT_MAX_ACTIVE
        } else {
            max_active
        };
        wq.in_use = true;
        wq.next_id = 1;

        // Propagate max_active and flags to all pools.
        for (i, pool) in wq.pools.iter_mut().enumerate() {
            pool.cpu_id = i as u32;
            pool.max_active = wq.max_active;
            pool.flags = flags;
        }
        wq.unbound_pool.max_active = wq.max_active;
        wq.unbound_pool.flags = flags;

        self.count = self.count.saturating_add(1);
        Ok(slot as u64)
    }

    /// Destroy a workqueue, freeing its slot for reuse.
    ///
    /// Any pending work in the queue is discarded.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `id` is out of range.
    /// Returns [`Error::NotFound`] if the slot is not in use.
    pub fn destroy(&mut self, id: u64) -> Result<()> {
        let wq = self.get_mut(id)?;
        *wq = CmWorkqueue::empty();
        self.count = self.count.saturating_sub(1);
        Ok(())
    }

    /// Schedule work on the given workqueue.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `queue_id` is out of range.
    /// Returns [`Error::NotFound`] if the slot is not in use.
    /// Returns [`Error::OutOfMemory`] if the target pool is full.
    pub fn schedule(
        &mut self,
        queue_id: u64,
        func_id: u64,
        data: u64,
        priority: WorkPriority,
    ) -> Result<u64> {
        let wq = self.get_mut(queue_id)?;
        wq.schedule_work(func_id, data, priority)
    }

    /// Process work for the given CPU across all active workqueues.
    ///
    /// Returns the total number of items processed.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `cpu_id` is out of range.
    pub fn tick(&mut self, cpu_id: u32) -> Result<u32> {
        if cpu_id as usize >= MAX_CPUS {
            return Err(Error::InvalidArgument);
        }

        let mut total: u32 = 0;
        for wq in &mut self.queues {
            if !wq.in_use {
                continue;
            }
            if let Ok(n) = wq.process_cpu(cpu_id) {
                total = total.saturating_add(n);
            }
        }
        Ok(total)
    }

    /// Return a shared reference to a workqueue by ID.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `id` is out of range.
    /// Returns [`Error::NotFound`] if the slot is not in use.
    pub fn get(&self, id: u64) -> Result<&CmWorkqueue> {
        let idx = id as usize;
        if idx >= MAX_QUEUES {
            return Err(Error::InvalidArgument);
        }
        if !self.queues[idx].in_use {
            return Err(Error::NotFound);
        }
        Ok(&self.queues[idx])
    }

    /// Return the number of active workqueues.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Return `true` if the registry has no active workqueues.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Return a mutable reference to a workqueue, validating the ID.
    fn get_mut(&mut self, id: u64) -> Result<&mut CmWorkqueue> {
        let idx = id as usize;
        if idx >= MAX_QUEUES {
            return Err(Error::InvalidArgument);
        }
        if !self.queues[idx].in_use {
            return Err(Error::NotFound);
        }
        Ok(&mut self.queues[idx])
    }
}

impl Default for CmwqRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for CmwqRegistry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CmwqRegistry")
            .field("count", &self.count)
            .field("capacity", &MAX_QUEUES)
            .finish()
    }
}
