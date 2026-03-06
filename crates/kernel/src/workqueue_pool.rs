// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Worker pool management for the workqueue subsystem.
//!
//! Each workqueue is backed by one or more worker pools. A pool owns
//! a set of kernel threads (workers) that execute work items from the
//! pool's run queue. Pools are either per-CPU (bound) or unbound
//! (shared across CPUs with configurable NUMA affinity).
//!
//! # Pool Types
//!
//! - **Bound / per-CPU** — one pool per CPU, workers are pinned.
//!   Used for latency-sensitive work.
//! - **Unbound** — shared pools whose workers may run on any CPU
//!   in an allowed set. Used for long-running or I/O-bound work.
//! - **Ordered** — unbound pool with max concurrency of 1 (FIFO).
//!
//! # Architecture
//!
//! ```text
//! PoolManager
//!  ├── pools: [WorkerPool; MAX_POOLS]
//!  ├── nr_pools: usize
//!  └── stats: PoolStats
//!
//! WorkerPool
//!  ├── workers: [Worker; MAX_WORKERS_PER_POOL]
//!  ├── work_items: [WorkItem; MAX_ITEMS]
//!  └── pool_type: PoolType
//! ```

use oncrix_lib::{Error, Result};

// ======================================================================
// Constants
// ======================================================================

/// Maximum worker pools system-wide.
const MAX_POOLS: usize = 128;

/// Maximum workers per pool.
const MAX_WORKERS_PER_POOL: usize = 16;

/// Maximum pending work items per pool.
const MAX_ITEMS_PER_POOL: usize = 256;

// ======================================================================
// Types
// ======================================================================

/// Pool type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PoolType {
    /// Bound per-CPU pool.
    Bound,
    /// Unbound pool (may span CPUs).
    Unbound,
    /// Ordered pool (max concurrency = 1).
    Ordered,
}

impl Default for PoolType {
    fn default() -> Self {
        Self::Bound
    }
}

/// Worker state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkerState {
    /// Worker is idle, waiting for work.
    Idle,
    /// Worker is executing a work item.
    Busy,
    /// Worker thread has been stopped.
    Stopped,
}

impl Default for WorkerState {
    fn default() -> Self {
        Self::Idle
    }
}

/// A worker thread in a pool.
#[derive(Debug, Clone, Copy)]
pub struct Worker {
    /// Worker identifier within the pool.
    pub id: u16,
    /// Kernel thread PID.
    pub kthread_pid: u64,
    /// Current state.
    pub state: WorkerState,
    /// ID of the work item being executed (0 if idle).
    pub current_item: u64,
    /// Total work items completed by this worker.
    pub completed: u64,
    /// Whether this slot is occupied.
    pub active: bool,
}

impl Worker {
    /// Creates an empty worker.
    pub const fn new() -> Self {
        Self {
            id: 0,
            kthread_pid: 0,
            state: WorkerState::Idle,
            current_item: 0,
            completed: 0,
            active: false,
        }
    }
}

impl Default for Worker {
    fn default() -> Self {
        Self::new()
    }
}

/// A pending work item.
#[derive(Debug, Clone, Copy)]
pub struct WorkItem {
    /// Unique item identifier.
    pub id: u64,
    /// Function pointer hash (for identification).
    pub func_hash: u64,
    /// Data payload.
    pub data: u64,
    /// Whether this item is active.
    pub active: bool,
    /// Whether this item has been claimed by a worker.
    pub claimed: bool,
}

impl WorkItem {
    /// Creates an empty work item.
    pub const fn new() -> Self {
        Self {
            id: 0,
            func_hash: 0,
            data: 0,
            active: false,
            claimed: false,
        }
    }
}

impl Default for WorkItem {
    fn default() -> Self {
        Self::new()
    }
}

/// A worker pool.
pub struct WorkerPool {
    /// Pool identifier.
    pool_id: u32,
    /// Pool type.
    pool_type: PoolType,
    /// CPU this pool is bound to (only for Bound pools).
    cpu_id: u32,
    /// Maximum concurrency (number of simultaneous workers).
    max_active: u16,
    /// Workers in this pool.
    workers: [Worker; MAX_WORKERS_PER_POOL],
    /// Number of active workers.
    nr_workers: u16,
    /// Pending work items.
    items: [WorkItem; MAX_ITEMS_PER_POOL],
    /// Number of pending items.
    nr_items: usize,
    /// Next work item ID.
    next_item_id: u64,
    /// Whether this pool is active.
    active: bool,
}

impl WorkerPool {
    /// Creates a new empty worker pool.
    pub const fn new() -> Self {
        Self {
            pool_id: 0,
            pool_type: PoolType::Bound,
            cpu_id: 0,
            max_active: MAX_WORKERS_PER_POOL as u16,
            workers: [Worker::new(); MAX_WORKERS_PER_POOL],
            nr_workers: 0,
            items: [WorkItem::new(); MAX_ITEMS_PER_POOL],
            nr_items: 0,
            next_item_id: 1,
            active: false,
        }
    }

    /// Returns the pool identifier.
    pub fn pool_id(&self) -> u32 {
        self.pool_id
    }

    /// Returns the pool type.
    pub fn pool_type(&self) -> PoolType {
        self.pool_type
    }

    /// Returns the number of active workers.
    pub fn nr_workers(&self) -> u16 {
        self.nr_workers
    }

    /// Returns the number of pending work items.
    pub fn nr_items(&self) -> usize {
        self.nr_items
    }

    /// Returns whether the pool is active.
    pub fn is_active(&self) -> bool {
        self.active
    }
}

impl Default for WorkerPool {
    fn default() -> Self {
        Self::new()
    }
}

/// Pool management statistics.
#[derive(Debug, Clone, Copy)]
pub struct PoolStats {
    /// Total work items queued.
    pub items_queued: u64,
    /// Total work items completed.
    pub items_completed: u64,
    /// Workers created.
    pub workers_created: u64,
    /// Workers destroyed.
    pub workers_destroyed: u64,
    /// Pool creation count.
    pub pools_created: u64,
}

impl PoolStats {
    /// Creates zeroed statistics.
    pub const fn new() -> Self {
        Self {
            items_queued: 0,
            items_completed: 0,
            workers_created: 0,
            workers_destroyed: 0,
            pools_created: 0,
        }
    }
}

impl Default for PoolStats {
    fn default() -> Self {
        Self::new()
    }
}

/// Manages all worker pools in the system.
pub struct PoolManager {
    /// Array of worker pools.
    pools: [WorkerPool; MAX_POOLS],
    /// Number of active pools.
    nr_pools: usize,
    /// Next pool ID.
    next_pool_id: u32,
    /// Statistics.
    stats: PoolStats,
}

impl PoolManager {
    /// Creates a new pool manager.
    pub const fn new() -> Self {
        Self {
            pools: [const { WorkerPool::new() }; MAX_POOLS],
            nr_pools: 0,
            next_pool_id: 1,
            stats: PoolStats::new(),
        }
    }

    /// Creates a new worker pool.
    pub fn create_pool(
        &mut self,
        pool_type: PoolType,
        cpu_id: u32,
        max_active: u16,
    ) -> Result<u32> {
        if self.nr_pools >= MAX_POOLS {
            return Err(Error::OutOfMemory);
        }
        if max_active == 0 || (max_active as usize) > MAX_WORKERS_PER_POOL {
            return Err(Error::InvalidArgument);
        }
        let pid = self.next_pool_id;
        self.next_pool_id += 1;

        for pool in &mut self.pools {
            if !pool.active {
                pool.pool_id = pid;
                pool.pool_type = pool_type;
                pool.cpu_id = cpu_id;
                pool.max_active = max_active;
                pool.active = true;
                self.nr_pools += 1;
                self.stats.pools_created += 1;
                return Ok(pid);
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Destroys a worker pool.
    pub fn destroy_pool(&mut self, pool_id: u32) -> Result<()> {
        let idx = self.find_pool(pool_id).ok_or(Error::NotFound)?;
        if self.pools[idx].nr_items > 0 {
            return Err(Error::Busy);
        }
        self.pools[idx].active = false;
        self.nr_pools = self.nr_pools.saturating_sub(1);
        Ok(())
    }

    /// Queues a work item in a pool.
    pub fn queue_work(&mut self, pool_id: u32, func_hash: u64, data: u64) -> Result<u64> {
        let idx = self.find_pool(pool_id).ok_or(Error::NotFound)?;
        let pool = &mut self.pools[idx];
        if pool.nr_items >= MAX_ITEMS_PER_POOL {
            return Err(Error::OutOfMemory);
        }
        let item_id = pool.next_item_id;
        pool.next_item_id += 1;

        for item in &mut pool.items {
            if !item.active {
                *item = WorkItem {
                    id: item_id,
                    func_hash,
                    data,
                    active: true,
                    claimed: false,
                };
                pool.nr_items += 1;
                self.stats.items_queued += 1;
                return Ok(item_id);
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Adds a worker to a pool.
    pub fn add_worker(&mut self, pool_id: u32, kthread_pid: u64) -> Result<u16> {
        let idx = self.find_pool(pool_id).ok_or(Error::NotFound)?;
        let pool = &mut self.pools[idx];
        if pool.nr_workers >= pool.max_active {
            return Err(Error::OutOfMemory);
        }
        for (w_id, worker) in pool.workers.iter_mut().enumerate() {
            if !worker.active {
                worker.id = w_id as u16;
                worker.kthread_pid = kthread_pid;
                worker.state = WorkerState::Idle;
                worker.active = true;
                pool.nr_workers += 1;
                self.stats.workers_created += 1;
                return Ok(w_id as u16);
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Returns the number of active pools.
    pub fn nr_pools(&self) -> usize {
        self.nr_pools
    }

    /// Returns pool statistics.
    pub fn stats(&self) -> &PoolStats {
        &self.stats
    }

    // ------------------------------------------------------------------
    // Internal
    // ------------------------------------------------------------------

    fn find_pool(&self, pool_id: u32) -> Option<usize> {
        self.pools
            .iter()
            .position(|p| p.active && p.pool_id == pool_id)
    }
}

impl Default for PoolManager {
    fn default() -> Self {
        Self::new()
    }
}
