// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Kthread worker infrastructure for deferred kernel work.
//!
//! Provides a dedicated kernel-thread work execution framework,
//! distinct from general workqueues.  Each kthread worker owns a
//! private queue and processes work items in priority order,
//! ensuring isolation between subsystems.
//!
//! # Components
//!
//! - [`KthreadWork`]: a single deferred work item with priority
//!   and retry semantics.
//! - [`KthreadQueue`]: per-worker priority queue.
//! - [`KthreadWorker`]: a kernel thread bound to a queue.
//! - [`KthreadWorkerPool`]: a managed group of workers with
//!   dynamic scaling and CPU affinity.
//! - [`KthreadController`]: system-wide manager.
//!
//! # Delayed Work
//!
//! [`DelayedKthreadWork`] schedules a work item for future
//! execution.  When the delay expires the item is promoted into
//! the worker's regular queue.
//!
//! Reference: Linux `kernel/kthread.c`,
//! `include/linux/kthread.h`.

use oncrix_lib::{Error, Result};

// ── Constants ──────────────────────────────────────────────────────

/// Maximum worker pools.
const MAX_POOLS: usize = 16;

/// Maximum workers per pool.
const MAX_WORKERS_PER_POOL: usize = 16;

/// Maximum total workers system-wide.
const MAX_TOTAL_WORKERS: usize = 64;

/// Maximum work items per queue.
const MAX_WORK_ITEMS: usize = 256;

/// Maximum delayed work entries.
const MAX_DELAYED: usize = 128;

/// Name buffer length.
const MAX_NAME_LEN: usize = 64;

/// Maximum retries per work item.
const MAX_RETRIES: u8 = 5;

/// Default priority.
const DEFAULT_PRIORITY: u8 = 120;

// ── WorkState ──────────────────────────────────────────────────────

/// State of a work item.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkState {
    /// Slot is free.
    Idle,
    /// Item is queued and waiting for execution.
    Pending,
    /// Item is currently executing.
    Running,
    /// Item completed successfully.
    Done,
    /// Item failed and may be retried.
    Failed,
    /// Item was cancelled before execution.
    Cancelled,
}

// ── WorkerState ────────────────────────────────────────────────────

/// State of a kthread worker.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkerState {
    /// Slot is free.
    Idle,
    /// Worker is running and processing items.
    Active,
    /// Worker is parked (no work pending).
    Parked,
    /// Worker is being drained (no new work accepted).
    Draining,
    /// Worker has been stopped.
    Stopped,
}

// ── PoolState ──────────────────────────────────────────────────────

/// State of a worker pool.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PoolState {
    /// Not initialised.
    Uninit,
    /// Pool is active and accepting work.
    Active,
    /// Pool is being drained.
    Draining,
    /// Pool has been shut down.
    Shutdown,
}

// ── KthreadWork ────────────────────────────────────────────────────

/// A single unit of deferred work.
#[derive(Clone, Copy)]
pub struct KthreadWork {
    /// Unique work identifier.
    id: u64,
    /// Priority (lower = higher priority).
    priority: u8,
    /// Current state.
    state: WorkState,
    /// Opaque context data.
    data: u64,
    /// Number of retries attempted.
    retries: u8,
    /// Maximum allowed retries.
    max_retries: u8,
    /// Timestamp when enqueued (ticks).
    enqueue_tick: u64,
    /// Timestamp when started (ticks).
    start_tick: u64,
    /// Timestamp when completed (ticks).
    end_tick: u64,
    /// Whether the slot is occupied.
    occupied: bool,
}

impl KthreadWork {
    /// Creates an empty work slot.
    pub const fn new() -> Self {
        Self {
            id: 0,
            priority: DEFAULT_PRIORITY,
            state: WorkState::Idle,
            data: 0,
            retries: 0,
            max_retries: MAX_RETRIES,
            enqueue_tick: 0,
            start_tick: 0,
            end_tick: 0,
            occupied: false,
        }
    }

    /// Returns the work identifier.
    pub const fn id(&self) -> u64 {
        self.id
    }

    /// Returns the priority.
    pub const fn priority(&self) -> u8 {
        self.priority
    }

    /// Returns the current state.
    pub const fn state(&self) -> WorkState {
        self.state
    }

    /// Returns the data payload.
    pub const fn data(&self) -> u64 {
        self.data
    }

    /// Returns the number of retries attempted.
    pub const fn retries(&self) -> u8 {
        self.retries
    }
}

// ── KthreadQueue ───────────────────────────────────────────────────

/// Per-worker priority queue of work items.
pub struct KthreadQueue {
    /// Work items.
    items: [KthreadWork; MAX_WORK_ITEMS],
    /// Number of pending items.
    nr_pending: usize,
    /// Total items ever processed.
    total_processed: u64,
}

impl KthreadQueue {
    /// Creates an empty queue.
    pub const fn new() -> Self {
        Self {
            items: [const { KthreadWork::new() }; MAX_WORK_ITEMS],
            nr_pending: 0,
            total_processed: 0,
        }
    }

    /// Enqueues a new work item.
    pub fn enqueue(&mut self, id: u64, priority: u8, data: u64, now_tick: u64) -> Result<()> {
        let slot = self
            .items
            .iter()
            .position(|w| !w.occupied)
            .ok_or(Error::OutOfMemory)?;

        self.items[slot] = KthreadWork {
            id,
            priority,
            state: WorkState::Pending,
            data,
            retries: 0,
            max_retries: MAX_RETRIES,
            enqueue_tick: now_tick,
            start_tick: 0,
            end_tick: 0,
            occupied: true,
        };
        self.nr_pending += 1;
        Ok(())
    }

    /// Dequeues the highest-priority pending item.
    pub fn dequeue(&mut self, now_tick: u64) -> Option<u64> {
        let mut best_idx: Option<usize> = None;
        let mut best_prio = u8::MAX;
        for (i, w) in self.items.iter().enumerate() {
            if w.occupied && w.state == WorkState::Pending && w.priority < best_prio {
                best_prio = w.priority;
                best_idx = Some(i);
            }
        }
        if let Some(idx) = best_idx {
            self.items[idx].state = WorkState::Running;
            self.items[idx].start_tick = now_tick;
            self.nr_pending = self.nr_pending.saturating_sub(1);
            Some(self.items[idx].id)
        } else {
            None
        }
    }

    /// Marks a work item as completed.
    pub fn complete(&mut self, id: u64, now_tick: u64) -> Result<()> {
        let idx = self
            .items
            .iter()
            .position(|w| w.occupied && w.id == id && w.state == WorkState::Running)
            .ok_or(Error::NotFound)?;

        self.items[idx].state = WorkState::Done;
        self.items[idx].end_tick = now_tick;
        self.items[idx].occupied = false;
        self.total_processed += 1;
        Ok(())
    }

    /// Marks a work item as failed, retrying if possible.
    pub fn fail(&mut self, id: u64) -> Result<bool> {
        let idx = self
            .items
            .iter()
            .position(|w| w.occupied && w.id == id && w.state == WorkState::Running)
            .ok_or(Error::NotFound)?;

        let w = &mut self.items[idx];
        w.retries += 1;
        if w.retries < w.max_retries {
            w.state = WorkState::Pending;
            self.nr_pending += 1;
            Ok(true) // will retry
        } else {
            w.state = WorkState::Failed;
            w.occupied = false;
            Ok(false) // exhausted retries
        }
    }

    /// Cancels a pending work item.
    pub fn cancel(&mut self, id: u64) -> Result<()> {
        let idx = self
            .items
            .iter()
            .position(|w| w.occupied && w.id == id && w.state == WorkState::Pending)
            .ok_or(Error::NotFound)?;

        self.items[idx].state = WorkState::Cancelled;
        self.items[idx].occupied = false;
        self.nr_pending = self.nr_pending.saturating_sub(1);
        Ok(())
    }

    /// Returns the number of pending items.
    pub const fn nr_pending(&self) -> usize {
        self.nr_pending
    }

    /// Returns the total items processed.
    pub const fn total_processed(&self) -> u64 {
        self.total_processed
    }
}

// ── KthreadWorker ──────────────────────────────────────────────────

/// A single kthread worker with its own queue.
pub struct KthreadWorker {
    /// Worker identifier.
    worker_id: u32,
    /// Work queue.
    queue: KthreadQueue,
    /// Current state.
    state: WorkerState,
    /// CPU affinity mask (bit per CPU, up to 64 CPUs).
    affinity: u64,
    /// Name.
    name: [u8; MAX_NAME_LEN],
    /// Name length.
    name_len: usize,
    /// Pool this worker belongs to.
    pool_id: u32,
}

impl KthreadWorker {
    /// Creates an idle worker.
    pub const fn new() -> Self {
        Self {
            worker_id: 0,
            queue: KthreadQueue::new(),
            state: WorkerState::Idle,
            affinity: u64::MAX,
            name: [0u8; MAX_NAME_LEN],
            name_len: 0,
            pool_id: 0,
        }
    }

    /// Returns the worker identifier.
    pub const fn worker_id(&self) -> u32 {
        self.worker_id
    }

    /// Returns the current state.
    pub const fn state(&self) -> WorkerState {
        self.state
    }

    /// Returns the CPU affinity mask.
    pub const fn affinity(&self) -> u64 {
        self.affinity
    }

    /// Returns the number of pending items.
    pub const fn nr_pending(&self) -> usize {
        self.queue.nr_pending()
    }

    /// Returns the pool identifier.
    pub const fn pool_id(&self) -> u32 {
        self.pool_id
    }
}

// ── DelayedKthreadWork ─────────────────────────────────────────────

/// A work item scheduled for future execution.
#[derive(Clone, Copy)]
pub struct DelayedKthreadWork {
    /// Work identifier (matches a `KthreadWork` id).
    work_id: u64,
    /// Target worker id.
    worker_id: u32,
    /// Tick at which this should be promoted to the queue.
    fire_tick: u64,
    /// Priority when promoted.
    priority: u8,
    /// Data payload.
    data: u64,
    /// Whether this slot is active.
    active: bool,
}

impl DelayedKthreadWork {
    /// Creates an empty delayed work slot.
    pub const fn new() -> Self {
        Self {
            work_id: 0,
            worker_id: 0,
            fire_tick: 0,
            priority: DEFAULT_PRIORITY,
            data: 0,
            active: false,
        }
    }
}

// ── KthreadWorkerPool ──────────────────────────────────────────────

/// A managed group of kthread workers.
pub struct KthreadWorkerPool {
    /// Pool identifier.
    pool_id: u32,
    /// Pool state.
    state: PoolState,
    /// Workers in this pool.
    workers: [KthreadWorker; MAX_WORKERS_PER_POOL],
    /// Number of active workers.
    nr_workers: usize,
    /// Pool name.
    name: [u8; MAX_NAME_LEN],
    /// Name length.
    name_len: usize,
    /// CPU affinity for the pool.
    affinity: u64,
}

impl KthreadWorkerPool {
    /// Creates an uninitialised pool.
    pub const fn new() -> Self {
        Self {
            pool_id: 0,
            state: PoolState::Uninit,
            workers: [const { KthreadWorker::new() }; MAX_WORKERS_PER_POOL],
            nr_workers: 0,
            name: [0u8; MAX_NAME_LEN],
            name_len: 0,
            affinity: u64::MAX,
        }
    }

    /// Returns the pool identifier.
    pub const fn pool_id(&self) -> u32 {
        self.pool_id
    }

    /// Returns the pool state.
    pub const fn state(&self) -> PoolState {
        self.state
    }

    /// Returns the number of active workers.
    pub const fn nr_workers(&self) -> usize {
        self.nr_workers
    }
}

// ── KthreadController ──────────────────────────────────────────────

/// System-wide kthread worker controller.
pub struct KthreadController {
    /// Worker pools.
    pools: [KthreadWorkerPool; MAX_POOLS],
    /// Number of active pools.
    nr_pools: usize,
    /// Delayed work entries.
    delayed: [DelayedKthreadWork; MAX_DELAYED],
    /// Next worker identifier.
    next_worker_id: u32,
    /// Next pool identifier.
    next_pool_id: u32,
    /// Next work identifier.
    next_work_id: u64,
    /// Total work items submitted.
    total_submitted: u64,
    /// Total work items completed.
    total_completed: u64,
}

impl KthreadController {
    /// Creates a new controller.
    pub const fn new() -> Self {
        Self {
            pools: [const { KthreadWorkerPool::new() }; MAX_POOLS],
            nr_pools: 0,
            delayed: [const { DelayedKthreadWork::new() }; MAX_DELAYED],
            next_worker_id: 1,
            next_pool_id: 1,
            next_work_id: 1,
            total_submitted: 0,
            total_completed: 0,
        }
    }

    /// Creates a new worker pool.
    pub fn create_pool(&mut self, name: &[u8], nr_workers: usize, affinity: u64) -> Result<u32> {
        if nr_workers == 0 || nr_workers > MAX_WORKERS_PER_POOL {
            return Err(Error::InvalidArgument);
        }
        let slot = self
            .pools
            .iter()
            .position(|p| p.state == PoolState::Uninit)
            .ok_or(Error::OutOfMemory)?;

        let pool_id = self.next_pool_id;
        self.next_pool_id += 1;

        let pool = &mut self.pools[slot];
        pool.pool_id = pool_id;
        pool.state = PoolState::Active;
        pool.affinity = affinity;
        let len = name.len().min(MAX_NAME_LEN);
        pool.name[..len].copy_from_slice(&name[..len]);
        pool.name_len = len;

        // Create workers.
        for i in 0..nr_workers {
            let wid = self.next_worker_id;
            self.next_worker_id += 1;
            pool.workers[i].worker_id = wid;
            pool.workers[i].state = WorkerState::Active;
            pool.workers[i].affinity = affinity;
            pool.workers[i].pool_id = pool_id;
        }
        pool.nr_workers = nr_workers;
        self.nr_pools += 1;

        Ok(pool_id)
    }

    /// Submits work to a pool, selecting the least-loaded worker.
    pub fn submit_work(
        &mut self,
        pool_id: u32,
        priority: u8,
        data: u64,
        now_tick: u64,
    ) -> Result<u64> {
        let pool_idx = self.find_pool(pool_id)?;
        let pool = &self.pools[pool_idx];
        if pool.state != PoolState::Active {
            return Err(Error::Busy);
        }

        // Find least-loaded active worker.
        let mut best: Option<usize> = None;
        let mut best_load = usize::MAX;
        for (i, w) in pool.workers.iter().enumerate() {
            if w.state == WorkerState::Active && w.queue.nr_pending() < best_load {
                best_load = w.queue.nr_pending();
                best = Some(i);
            }
        }
        let widx = best.ok_or(Error::Busy)?;

        let work_id = self.next_work_id;
        self.next_work_id += 1;

        self.pools[pool_idx].workers[widx]
            .queue
            .enqueue(work_id, priority, data, now_tick)?;
        self.total_submitted += 1;
        Ok(work_id)
    }

    /// Processes the next work item on a specific worker.
    pub fn process_next(
        &mut self,
        pool_id: u32,
        worker_id: u32,
        now_tick: u64,
    ) -> Result<Option<u64>> {
        let pool_idx = self.find_pool(pool_id)?;
        let widx = self.find_worker(pool_idx, worker_id)?;
        Ok(self.pools[pool_idx].workers[widx].queue.dequeue(now_tick))
    }

    /// Marks a work item as completed.
    pub fn complete_work(
        &mut self,
        pool_id: u32,
        worker_id: u32,
        work_id: u64,
        now_tick: u64,
    ) -> Result<()> {
        let pool_idx = self.find_pool(pool_id)?;
        let widx = self.find_worker(pool_idx, worker_id)?;
        self.pools[pool_idx].workers[widx]
            .queue
            .complete(work_id, now_tick)?;
        self.total_completed += 1;
        Ok(())
    }

    /// Schedules delayed work for future execution.
    pub fn schedule_delayed(
        &mut self,
        pool_id: u32,
        worker_id: u32,
        priority: u8,
        data: u64,
        fire_tick: u64,
    ) -> Result<u64> {
        let _ = self.find_pool(pool_id)?;
        let slot = self
            .delayed
            .iter()
            .position(|d| !d.active)
            .ok_or(Error::OutOfMemory)?;

        let work_id = self.next_work_id;
        self.next_work_id += 1;

        self.delayed[slot] = DelayedKthreadWork {
            work_id,
            worker_id,
            fire_tick,
            priority,
            data,
            active: true,
        };
        Ok(work_id)
    }

    /// Promotes delayed work items whose fire time has passed.
    pub fn tick_delayed(&mut self, now_tick: u64) -> u32 {
        let mut promoted = 0u32;
        for i in 0..MAX_DELAYED {
            if !self.delayed[i].active {
                continue;
            }
            if self.delayed[i].fire_tick > now_tick {
                continue;
            }
            let dw = self.delayed[i];
            self.delayed[i].active = false;

            // Find the pool containing this worker.
            for pool in &mut self.pools {
                if pool.state != PoolState::Active {
                    continue;
                }
                for w in &mut pool.workers {
                    if w.worker_id == dw.worker_id && w.state == WorkerState::Active {
                        let _ = w.queue.enqueue(dw.work_id, dw.priority, dw.data, now_tick);
                        self.total_submitted += 1;
                        promoted += 1;
                    }
                }
            }
        }
        promoted
    }

    /// Initiates pool drain (rejects new work, finishes queued).
    pub fn drain_pool(&mut self, pool_id: u32) -> Result<()> {
        let idx = self.find_pool(pool_id)?;
        if self.pools[idx].state != PoolState::Active {
            return Err(Error::InvalidArgument);
        }
        self.pools[idx].state = PoolState::Draining;
        for w in &mut self.pools[idx].workers {
            if w.state == WorkerState::Active {
                w.state = WorkerState::Draining;
            }
        }
        Ok(())
    }

    /// Shuts down a drained pool.
    pub fn shutdown_pool(&mut self, pool_id: u32) -> Result<()> {
        let idx = self.find_pool(pool_id)?;
        if self.pools[idx].state != PoolState::Draining {
            return Err(Error::InvalidArgument);
        }
        // Verify all queues are empty.
        for w in &self.pools[idx].workers {
            if w.queue.nr_pending() > 0 {
                return Err(Error::Busy);
            }
        }
        for w in &mut self.pools[idx].workers {
            w.state = WorkerState::Stopped;
        }
        self.pools[idx].state = PoolState::Shutdown;
        Ok(())
    }

    /// Returns the number of active pools.
    pub const fn nr_pools(&self) -> usize {
        self.nr_pools
    }

    /// Returns the total work submitted.
    pub const fn total_submitted(&self) -> u64 {
        self.total_submitted
    }

    /// Returns the total work completed.
    pub const fn total_completed(&self) -> u64 {
        self.total_completed
    }

    // ── internal helpers ───────────────────────────────────────────

    fn find_pool(&self, pool_id: u32) -> Result<usize> {
        self.pools
            .iter()
            .position(|p| p.state != PoolState::Uninit && p.pool_id == pool_id)
            .ok_or(Error::NotFound)
    }

    fn find_worker(&self, pool_idx: usize, worker_id: u32) -> Result<usize> {
        self.pools[pool_idx]
            .workers
            .iter()
            .position(|w| w.state != WorkerState::Idle && w.worker_id == worker_id)
            .ok_or(Error::NotFound)
    }
}
