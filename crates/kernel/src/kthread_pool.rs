// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Kernel thread pool — manages a pool of reusable kernel threads.
//!
//! Instead of creating and destroying kernel threads for each task,
//! the pool maintains a set of idle threads that can be dispatched
//! to execute work functions, reducing thread creation overhead.
//!
//! # Architecture
//!
//! ```text
//! KthreadPool
//!  ├── threads[MAX_POOL_THREADS]
//!  │    ├── tid, state: PoolThreadState
//!  │    ├── current_work: u64
//!  │    └── tasks_completed
//!  ├── work_queue[MAX_PENDING_WORK]
//!  └── stats: PoolStats
//! ```
//!
//! # Reference
//!
//! Linux `kernel/kthread.c` — `kthread_worker` / `kthread_work`.

use oncrix_lib::{Error, Result};

// ══════════════════════════════════════════════════════════════
// Constants
// ══════════════════════════════════════════════════════════════

/// Maximum threads in the pool.
const MAX_POOL_THREADS: usize = 32;

/// Maximum pending work items in the queue.
const MAX_PENDING_WORK: usize = 128;

// ══════════════════════════════════════════════════════════════
// PoolThreadState
// ══════════════════════════════════════════════════════════════

/// State of a pool thread.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PoolThreadState {
    /// Slot is empty (no thread).
    Empty = 0,
    /// Thread is idle, waiting for work.
    Idle = 1,
    /// Thread is executing a work item.
    Busy = 2,
    /// Thread is being shut down.
    Exiting = 3,
}

// ══════════════════════════════════════════════════════════════
// PoolThread
// ══════════════════════════════════════════════════════════════

/// A thread in the pool.
#[derive(Debug, Clone, Copy)]
pub struct PoolThread {
    /// Thread identifier.
    pub tid: u64,
    /// Bound CPU (-1 = unbound).
    pub bound_cpu: i32,
    /// Current state.
    pub state: PoolThreadState,
    /// ID of the currently executing work item (0 = none).
    pub current_work: u64,
    /// Number of tasks completed by this thread.
    pub tasks_completed: u64,
    /// Total busy time in nanoseconds.
    pub busy_ns: u64,
}

impl PoolThread {
    /// Create an empty thread slot.
    const fn empty() -> Self {
        Self {
            tid: 0,
            bound_cpu: -1,
            state: PoolThreadState::Empty,
            current_work: 0,
            tasks_completed: 0,
            busy_ns: 0,
        }
    }
}

// ══════════════════════════════════════════════════════════════
// PendingWork
// ══════════════════════════════════════════════════════════════

/// A pending work item in the queue.
#[derive(Debug, Clone, Copy)]
pub struct PendingWork {
    /// Work item identifier.
    pub work_id: u64,
    /// Callback function identifier.
    pub func_id: u64,
    /// Argument data.
    pub arg: u64,
    /// Whether this slot is used.
    pub active: bool,
}

impl PendingWork {
    /// Create an inactive work slot.
    const fn empty() -> Self {
        Self {
            work_id: 0,
            func_id: 0,
            arg: 0,
            active: false,
        }
    }
}

// ══════════════════════════════════════════════════════════════
// PoolStats
// ══════════════════════════════════════════════════════════════

/// Thread pool statistics.
#[derive(Debug, Clone, Copy)]
pub struct PoolStats {
    /// Total work items submitted.
    pub total_submitted: u64,
    /// Total work items completed.
    pub total_completed: u64,
    /// Total threads created.
    pub threads_created: u32,
    /// Total threads destroyed.
    pub threads_destroyed: u32,
    /// Peak concurrent busy threads.
    pub peak_busy: u32,
}

impl PoolStats {
    /// Create zeroed stats.
    const fn new() -> Self {
        Self {
            total_submitted: 0,
            total_completed: 0,
            threads_created: 0,
            threads_destroyed: 0,
            peak_busy: 0,
        }
    }
}

// ══════════════════════════════════════════════════════════════
// KthreadPool
// ══════════════════════════════════════════════════════════════

/// Kernel thread pool.
pub struct KthreadPool {
    /// Pool threads.
    threads: [PoolThread; MAX_POOL_THREADS],
    /// Pending work queue.
    work_queue: [PendingWork; MAX_PENDING_WORK],
    /// Next work item ID.
    next_work_id: u64,
    /// Next thread ID.
    next_tid: u64,
    /// Statistics.
    stats: PoolStats,
    /// Whether the pool is active.
    active: bool,
}

impl KthreadPool {
    /// Create a new kernel thread pool.
    pub const fn new() -> Self {
        Self {
            threads: [const { PoolThread::empty() }; MAX_POOL_THREADS],
            work_queue: [const { PendingWork::empty() }; MAX_PENDING_WORK],
            next_work_id: 1,
            next_tid: 1,
            stats: PoolStats::new(),
            active: false,
        }
    }

    /// Initialise the pool and create initial threads.
    pub fn init(&mut self, initial_threads: u32) -> Result<()> {
        if self.active {
            return Err(Error::AlreadyExists);
        }
        self.active = true;
        let count = (initial_threads as usize).min(MAX_POOL_THREADS);
        for i in 0..count {
            self.threads[i].tid = self.next_tid;
            self.next_tid += 1;
            self.threads[i].state = PoolThreadState::Idle;
            self.stats.threads_created += 1;
        }
        Ok(())
    }

    /// Submit work to the pool.
    pub fn submit_work(&mut self, func_id: u64, arg: u64) -> Result<u64> {
        if !self.active {
            return Err(Error::NotImplemented);
        }
        let slot = self
            .work_queue
            .iter()
            .position(|w| !w.active)
            .ok_or(Error::OutOfMemory)?;
        let work_id = self.next_work_id;
        self.next_work_id += 1;
        self.work_queue[slot] = PendingWork {
            work_id,
            func_id,
            arg,
            active: true,
        };
        self.stats.total_submitted += 1;
        Ok(work_id)
    }

    /// Dispatch pending work to idle threads.
    /// Returns the number of work items dispatched.
    pub fn dispatch(&mut self) -> u32 {
        let mut dispatched = 0u32;
        for work in &mut self.work_queue {
            if !work.active {
                continue;
            }
            // Find an idle thread.
            if let Some(thread) = self
                .threads
                .iter_mut()
                .find(|t| matches!(t.state, PoolThreadState::Idle))
            {
                thread.state = PoolThreadState::Busy;
                thread.current_work = work.work_id;
                work.active = false;
                dispatched += 1;
            } else {
                break;
            }
        }
        // Update peak busy.
        let busy = self
            .threads
            .iter()
            .filter(|t| matches!(t.state, PoolThreadState::Busy))
            .count() as u32;
        if busy > self.stats.peak_busy {
            self.stats.peak_busy = busy;
        }
        dispatched
    }

    /// Mark a thread's current work as complete.
    pub fn complete_work(&mut self, tid: u64) -> Result<()> {
        let thread = self
            .threads
            .iter_mut()
            .find(|t| t.tid == tid && matches!(t.state, PoolThreadState::Busy))
            .ok_or(Error::NotFound)?;
        thread.state = PoolThreadState::Idle;
        thread.current_work = 0;
        thread.tasks_completed += 1;
        self.stats.total_completed += 1;
        Ok(())
    }

    /// Return the number of idle threads.
    pub fn idle_count(&self) -> u32 {
        self.threads
            .iter()
            .filter(|t| matches!(t.state, PoolThreadState::Idle))
            .count() as u32
    }

    /// Return the number of busy threads.
    pub fn busy_count(&self) -> u32 {
        self.threads
            .iter()
            .filter(|t| matches!(t.state, PoolThreadState::Busy))
            .count() as u32
    }

    /// Return statistics.
    pub fn stats(&self) -> PoolStats {
        self.stats
    }
}
