// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Kernel mutex.
//!
//! The `KernMutex` provides mutual exclusion with an optional wait
//! queue for contended acquisition. Unlike a spinlock, a mutex
//! allows the waiting thread to sleep, reducing CPU waste under
//! high contention.
//!
//! # Design
//!
//! ```text
//!   +------------+
//!   | KernMutex  |
//!   |------------|     +--------+--------+
//!   | owner      |     | wait_0 | wait_1 | ...
//!   | locked     |     |  tid   |  tid   |
//!   | wait_count |     | state  | state  |
//!   +------------+     +--------+--------+
//! ```
//!
//! # Features
//!
//! - `lock()` / `unlock()` — blocking acquire and release.
//! - `trylock()` — non-blocking attempt.
//! - `is_locked()` — check lock state.
//! - `lock_nested(depth)` — for lockdep annotation of nested
//!   locking.
//! - Optimistic spinning stub (ready for architecture-specific
//!   implementation).
//!
//! # Reference
//!
//! Linux `kernel/locking/mutex.c`,
//! `include/linux/mutex.h`.

use oncrix_lib::{Error, Result};

// ======================================================================
// Constants
// ======================================================================

/// Maximum waiters per mutex.
const MAX_WAITERS: usize = 64;

/// Maximum managed mutexes.
const MAX_MUTEXES: usize = 512;

/// No owner sentinel.
const NO_OWNER: u64 = 0;

/// Maximum nesting depth for `lock_nested`.
const MAX_NEST_DEPTH: u32 = 8;

/// Optimistic spin iterations before queueing.
const _OPTIMISTIC_SPIN_ITERS: u32 = 100;

// ======================================================================
// MutexWaiterState
// ======================================================================

/// State of a mutex waiter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MutexWaiterState {
    /// Waiting for the mutex.
    Waiting,
    /// Woken up and ready to acquire.
    Woken,
    /// Cancelled (timeout or signal).
    Cancelled,
}

// ======================================================================
// MutexWaiter
// ======================================================================

/// A waiter in the mutex wait queue.
#[derive(Debug, Clone, Copy)]
pub struct MutexWaiter {
    /// Task ID of the waiter.
    task_id: u64,
    /// Current state.
    state: MutexWaiterState,
    /// Whether this slot is occupied.
    occupied: bool,
    /// Enqueue timestamp (ns).
    enqueue_ns: u64,
    /// Nest depth (for lockdep).
    nest_depth: u32,
}

impl MutexWaiter {
    /// Creates a new empty waiter slot.
    pub const fn new() -> Self {
        Self {
            task_id: 0,
            state: MutexWaiterState::Waiting,
            occupied: false,
            enqueue_ns: 0,
            nest_depth: 0,
        }
    }

    /// Returns the task ID.
    pub fn task_id(&self) -> u64 {
        self.task_id
    }

    /// Returns the waiter state.
    pub fn state(&self) -> MutexWaiterState {
        self.state
    }

    /// Returns whether this slot is occupied.
    pub fn is_occupied(&self) -> bool {
        self.occupied
    }

    /// Returns the nest depth.
    pub fn nest_depth(&self) -> u32 {
        self.nest_depth
    }
}

// ======================================================================
// KernMutex
// ======================================================================

/// Kernel mutex with wait queue and lockdep support.
pub struct KernMutex {
    /// Task ID of the current owner (0 = unlocked).
    owner: u64,
    /// Whether the mutex is locked.
    locked: bool,
    /// Wait queue.
    wait_list: [MutexWaiter; MAX_WAITERS],
    /// Number of waiters.
    wait_count: usize,
    /// Current nest depth (for lockdep).
    nest_depth: u32,
    /// Generation counter.
    generation: u64,
    /// Statistics: total acquisitions.
    stats_acquires: u64,
    /// Statistics: total contentions.
    stats_contentions: u64,
    /// Statistics: total optimistic spin attempts.
    stats_spin_attempts: u64,
}

impl KernMutex {
    /// Creates a new unlocked mutex.
    pub const fn new() -> Self {
        Self {
            owner: NO_OWNER,
            locked: false,
            wait_list: [const { MutexWaiter::new() }; MAX_WAITERS],
            wait_count: 0,
            nest_depth: 0,
            generation: 0,
            stats_acquires: 0,
            stats_contentions: 0,
            stats_spin_attempts: 0,
        }
    }

    /// Acquires the mutex.
    ///
    /// If the mutex is held, the caller is enqueued. In a real
    /// kernel this would block; here we record the waiter.
    pub fn lock(&mut self, task_id: u64) -> Result<()> {
        if task_id == NO_OWNER {
            return Err(Error::InvalidArgument);
        }
        // Detect recursive locking.
        if self.locked && self.owner == task_id {
            return Err(Error::Busy);
        }
        if !self.locked {
            self.locked = true;
            self.owner = task_id;
            self.stats_acquires += 1;
            self.generation += 1;
            return Ok(());
        }
        // Contended — try optimistic spinning stub, then queue.
        self.stats_spin_attempts += 1;
        self.stats_contentions += 1;
        self.enqueue_waiter(task_id, 0)?;
        Ok(())
    }

    /// Releases the mutex.
    pub fn unlock(&mut self) -> Result<()> {
        if !self.locked {
            return Err(Error::InvalidArgument);
        }
        self.locked = false;
        self.owner = NO_OWNER;
        self.nest_depth = 0;
        self.generation += 1;
        // Wake the first waiter.
        self.wake_first_waiter()?;
        Ok(())
    }

    /// Tries to acquire the mutex without blocking.
    ///
    /// Returns `Ok(true)` if acquired, `Ok(false)` otherwise.
    pub fn trylock(&mut self, task_id: u64) -> Result<bool> {
        if task_id == NO_OWNER {
            return Err(Error::InvalidArgument);
        }
        if !self.locked {
            self.locked = true;
            self.owner = task_id;
            self.stats_acquires += 1;
            self.generation += 1;
            Ok(true)
        } else {
            self.stats_contentions += 1;
            Ok(false)
        }
    }

    /// Returns whether the mutex is locked.
    pub fn is_locked(&self) -> bool {
        self.locked
    }

    /// Acquires the mutex with a nested depth annotation.
    ///
    /// Used for lockdep validation of nested locking patterns.
    pub fn lock_nested(&mut self, task_id: u64, depth: u32) -> Result<()> {
        if depth > MAX_NEST_DEPTH {
            return Err(Error::InvalidArgument);
        }
        self.lock(task_id)?;
        self.nest_depth = depth;
        Ok(())
    }

    /// Returns the current owner task ID.
    pub fn owner(&self) -> u64 {
        self.owner
    }

    /// Returns the number of waiters.
    pub fn wait_count(&self) -> usize {
        self.wait_count
    }

    /// Returns the nest depth.
    pub fn nest_depth(&self) -> u32 {
        self.nest_depth
    }

    /// Returns the generation counter.
    pub fn generation(&self) -> u64 {
        self.generation
    }

    /// Returns total acquisitions.
    pub fn stats_acquires(&self) -> u64 {
        self.stats_acquires
    }

    /// Returns total contentions.
    pub fn stats_contentions(&self) -> u64 {
        self.stats_contentions
    }

    // ------------------------------------------------------------------
    // Internal helpers
    // ------------------------------------------------------------------

    /// Enqueues a waiter.
    fn enqueue_waiter(&mut self, task_id: u64, depth: u32) -> Result<()> {
        if self.wait_count >= MAX_WAITERS {
            return Err(Error::OutOfMemory);
        }
        self.wait_list[self.wait_count] = MutexWaiter {
            task_id,
            state: MutexWaiterState::Waiting,
            occupied: true,
            enqueue_ns: self.generation,
            nest_depth: depth,
        };
        self.wait_count += 1;
        Ok(())
    }

    /// Wakes the first waiter and grants the mutex.
    fn wake_first_waiter(&mut self) -> Result<()> {
        if self.wait_count == 0 {
            return Ok(());
        }
        let task_id = self.wait_list[0].task_id;
        // Shift remaining waiters.
        let mut i = 0;
        while i + 1 < self.wait_count {
            self.wait_list.swap(i, i + 1);
            i += 1;
        }
        self.wait_list[self.wait_count - 1] = MutexWaiter::new();
        self.wait_count -= 1;
        self.locked = true;
        self.owner = task_id;
        self.stats_acquires += 1;
        Ok(())
    }
}

// ======================================================================
// MutexTable — global registry
// ======================================================================

/// Global table of kernel mutexes.
pub struct MutexTable {
    /// Mutex entries.
    entries: [MutexEntry; MAX_MUTEXES],
    /// Number of allocated mutexes.
    count: usize,
}

/// An entry in the mutex table.
struct MutexEntry {
    /// The mutex.
    mtx: KernMutex,
    /// Whether this slot is allocated.
    allocated: bool,
    /// Name (for debugging).
    name: [u8; 32],
    /// Length of the name.
    name_len: usize,
}

impl MutexEntry {
    const fn new() -> Self {
        Self {
            mtx: KernMutex::new(),
            allocated: false,
            name: [0u8; 32],
            name_len: 0,
        }
    }
}

impl MutexTable {
    /// Creates a new empty table.
    pub const fn new() -> Self {
        Self {
            entries: [const { MutexEntry::new() }; MAX_MUTEXES],
            count: 0,
        }
    }

    /// Allocates a new mutex.
    pub fn alloc(&mut self, name: &[u8]) -> Result<usize> {
        if self.count >= MAX_MUTEXES {
            return Err(Error::OutOfMemory);
        }
        let idx = self.find_free_slot()?;
        self.entries[idx].allocated = true;
        self.entries[idx].mtx = KernMutex::new();
        let copy_len = name.len().min(32);
        self.entries[idx].name[..copy_len].copy_from_slice(&name[..copy_len]);
        self.entries[idx].name_len = copy_len;
        self.count += 1;
        Ok(idx)
    }

    /// Frees a mutex by index.
    pub fn free(&mut self, idx: usize) -> Result<()> {
        if idx >= MAX_MUTEXES || !self.entries[idx].allocated {
            return Err(Error::NotFound);
        }
        self.entries[idx] = MutexEntry::new();
        self.count -= 1;
        Ok(())
    }

    /// Returns a reference to the mutex at `idx`.
    pub fn get(&self, idx: usize) -> Result<&KernMutex> {
        if idx >= MAX_MUTEXES || !self.entries[idx].allocated {
            return Err(Error::NotFound);
        }
        Ok(&self.entries[idx].mtx)
    }

    /// Returns a mutable reference to the mutex at `idx`.
    pub fn get_mut(&mut self, idx: usize) -> Result<&mut KernMutex> {
        if idx >= MAX_MUTEXES || !self.entries[idx].allocated {
            return Err(Error::NotFound);
        }
        Ok(&mut self.entries[idx].mtx)
    }

    /// Returns the number of allocated mutexes.
    pub fn count(&self) -> usize {
        self.count
    }

    /// Finds the first free slot.
    fn find_free_slot(&self) -> Result<usize> {
        self.entries
            .iter()
            .position(|e| !e.allocated)
            .ok_or(Error::OutOfMemory)
    }
}
