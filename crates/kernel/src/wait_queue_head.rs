// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Wait queue.
//!
//! Wait queues allow kernel threads to sleep until a condition is
//! met, then be woken by another thread or an interrupt handler.
//! This is the fundamental mechanism for blocking I/O, process
//! synchronization, and event notification in the kernel.
//!
//! # Design
//!
//! ```text
//!   +----------------+
//!   | WaitQueueHead  |
//!   |----------------|     +----------+----------+
//!   | count          |     | entry[0] | entry[1] | ...
//!   | generation     |     | task_id  | task_id  |
//!   +----------------+     | flags    | flags    |
//!                          +----------+----------+
//! ```
//!
//! # Flags
//!
//! - `WQ_FLAG_EXCLUSIVE` — only one exclusive waiter is woken
//!   per `wake_up` call.
//! - `WQ_FLAG_INTERRUPTIBLE` — waiter can be interrupted by
//!   signals.
//!
//! # Reference
//!
//! Linux `include/linux/wait.h`,
//! `kernel/sched/wait.c`.

use oncrix_lib::{Error, Result};

// ======================================================================
// Constants
// ======================================================================

/// Maximum entries per wait queue.
const MAX_ENTRIES: usize = 64;

/// Maximum managed wait queues.
const MAX_WAIT_QUEUES: usize = 512;

/// Flag: exclusive waiter.
pub const WQ_FLAG_EXCLUSIVE: u32 = 1 << 0;

/// Flag: interruptible wait.
pub const WQ_FLAG_INTERRUPTIBLE: u32 = 1 << 1;

/// Flag: waiter has been woken.
pub const WQ_FLAG_WOKEN: u32 = 1 << 2;

/// Flag: waiter removed itself.
pub const WQ_FLAG_REMOVED: u32 = 1 << 3;

// ======================================================================
// WaitQueueState
// ======================================================================

/// State of a wait queue entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WaitQueueState {
    /// Not active.
    Idle,
    /// Waiting on the queue.
    Waiting,
    /// Woken up.
    Woken,
    /// Interrupted by a signal.
    Interrupted,
}

// ======================================================================
// WaitQueueEntry
// ======================================================================

/// A single entry in a wait queue.
#[derive(Debug, Clone, Copy)]
pub struct WaitQueueEntry {
    /// Task ID.
    task_id: u64,
    /// Flags (WQ_FLAG_*).
    flags: u32,
    /// Current state.
    state: WaitQueueState,
    /// Whether this slot is occupied.
    occupied: bool,
    /// Priority (lower = higher priority).
    priority: u32,
    /// Enqueue timestamp (ns).
    enqueue_ns: u64,
}

impl WaitQueueEntry {
    /// Creates a new empty entry.
    pub const fn new() -> Self {
        Self {
            task_id: 0,
            flags: 0,
            state: WaitQueueState::Idle,
            occupied: false,
            priority: u32::MAX,
            enqueue_ns: 0,
        }
    }

    /// Returns the task ID.
    pub fn task_id(&self) -> u64 {
        self.task_id
    }

    /// Returns the flags.
    pub fn flags(&self) -> u32 {
        self.flags
    }

    /// Returns the current state.
    pub fn state(&self) -> WaitQueueState {
        self.state
    }

    /// Returns whether this slot is occupied.
    pub fn is_occupied(&self) -> bool {
        self.occupied
    }

    /// Returns whether this is an exclusive waiter.
    pub fn is_exclusive(&self) -> bool {
        self.flags & WQ_FLAG_EXCLUSIVE != 0
    }

    /// Returns whether this is an interruptible waiter.
    pub fn is_interruptible(&self) -> bool {
        self.flags & WQ_FLAG_INTERRUPTIBLE != 0
    }
}

// ======================================================================
// WaitQueueHead
// ======================================================================

/// Head of a wait queue.
///
/// Manages a list of entries, supports waking one, all, or
/// interruptible waiters.
pub struct WaitQueueHead {
    /// Wait queue entries.
    entries: [WaitQueueEntry; MAX_ENTRIES],
    /// Number of active entries.
    count: usize,
    /// Generation counter.
    generation: u64,
    /// Statistics: total wake_up calls.
    stats_wakeups: u64,
    /// Statistics: total adds.
    stats_adds: u64,
}

impl WaitQueueHead {
    /// Creates a new empty wait queue.
    pub const fn new() -> Self {
        Self {
            entries: [const { WaitQueueEntry::new() }; MAX_ENTRIES],
            count: 0,
            generation: 0,
            stats_wakeups: 0,
            stats_adds: 0,
        }
    }

    /// Adds a wait queue entry.
    pub fn add_wait_queue(&mut self, task_id: u64, flags: u32) -> Result<()> {
        if self.count >= MAX_ENTRIES {
            return Err(Error::OutOfMemory);
        }
        self.entries[self.count] = WaitQueueEntry {
            task_id,
            flags,
            state: WaitQueueState::Waiting,
            occupied: true,
            priority: u32::MAX,
            enqueue_ns: self.generation,
        };
        self.count += 1;
        self.stats_adds += 1;
        self.generation += 1;
        Ok(())
    }

    /// Removes a wait queue entry by task ID.
    pub fn remove_wait_queue(&mut self, task_id: u64) -> Result<()> {
        let pos = self.entries[..self.count]
            .iter()
            .position(|e| e.occupied && e.task_id == task_id);
        match pos {
            Some(idx) => {
                self.remove_entry(idx);
                self.generation += 1;
                Ok(())
            }
            None => Err(Error::NotFound),
        }
    }

    /// Wakes up one waiter (the first non-exclusive, or the
    /// first exclusive).
    ///
    /// Returns the task ID of the woken waiter, if any.
    pub fn wake_up(&mut self) -> Result<Option<u64>> {
        self.stats_wakeups += 1;
        self.generation += 1;
        // Wake non-exclusive waiters first, then stop at first
        // exclusive.
        for i in 0..self.count {
            if self.entries[i].occupied && self.entries[i].state == WaitQueueState::Waiting {
                let tid = self.entries[i].task_id;
                let exclusive = self.entries[i].is_exclusive();
                self.entries[i].state = WaitQueueState::Woken;
                self.entries[i].flags |= WQ_FLAG_WOKEN;
                if exclusive {
                    return Ok(Some(tid));
                }
                return Ok(Some(tid));
            }
        }
        Ok(None)
    }

    /// Wakes all waiters.
    ///
    /// Returns the number of waiters woken.
    pub fn wake_up_all(&mut self) -> Result<u32> {
        self.stats_wakeups += 1;
        self.generation += 1;
        let mut woken = 0u32;
        for i in 0..self.count {
            if self.entries[i].occupied && self.entries[i].state == WaitQueueState::Waiting {
                self.entries[i].state = WaitQueueState::Woken;
                self.entries[i].flags |= WQ_FLAG_WOKEN;
                woken += 1;
            }
        }
        Ok(woken)
    }

    /// Wakes interruptible waiters only.
    ///
    /// Returns the number of waiters woken.
    pub fn wake_up_interruptible(&mut self) -> Result<u32> {
        self.stats_wakeups += 1;
        self.generation += 1;
        let mut woken = 0u32;
        for i in 0..self.count {
            if self.entries[i].occupied
                && self.entries[i].state == WaitQueueState::Waiting
                && self.entries[i].is_interruptible()
            {
                self.entries[i].state = WaitQueueState::Woken;
                self.entries[i].flags |= WQ_FLAG_WOKEN;
                woken += 1;
            }
        }
        Ok(woken)
    }

    /// Prepares a task for waiting (sets state to Waiting).
    pub fn prepare_to_wait(&mut self, task_id: u64, flags: u32) -> Result<()> {
        // Check if already in the queue.
        for i in 0..self.count {
            if self.entries[i].occupied && self.entries[i].task_id == task_id {
                self.entries[i].state = WaitQueueState::Waiting;
                self.entries[i].flags = flags;
                return Ok(());
            }
        }
        // Not found — add new.
        self.add_wait_queue(task_id, flags)
    }

    /// Finishes waiting — removes the entry and returns its
    /// final state.
    pub fn finish_wait(&mut self, task_id: u64) -> Result<WaitQueueState> {
        let pos = self.entries[..self.count]
            .iter()
            .position(|e| e.occupied && e.task_id == task_id);
        match pos {
            Some(idx) => {
                let state = self.entries[idx].state;
                self.remove_entry(idx);
                self.generation += 1;
                Ok(state)
            }
            None => Err(Error::NotFound),
        }
    }

    /// Returns the number of active entries.
    pub fn count(&self) -> usize {
        self.count
    }

    /// Returns whether the queue is empty.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Returns the generation counter.
    pub fn generation(&self) -> u64 {
        self.generation
    }

    /// Returns total wakeup calls.
    pub fn stats_wakeups(&self) -> u64 {
        self.stats_wakeups
    }

    /// Returns total add operations.
    pub fn stats_adds(&self) -> u64 {
        self.stats_adds
    }

    // ------------------------------------------------------------------
    // Internal helpers
    // ------------------------------------------------------------------

    /// Removes an entry at `idx` by shifting.
    fn remove_entry(&mut self, idx: usize) {
        if idx < self.count {
            let mut i = idx;
            while i + 1 < self.count {
                self.entries.swap(i, i + 1);
                i += 1;
            }
            self.entries[self.count - 1] = WaitQueueEntry::new();
            self.count -= 1;
        }
    }
}

// ======================================================================
// WaitQueueTable — global registry
// ======================================================================

/// Global table of wait queues.
pub struct WaitQueueTable {
    /// Entries.
    heads: [WaitQueueTableEntry; MAX_WAIT_QUEUES],
    /// Number of allocated queues.
    count: usize,
}

/// Entry in the wait queue table.
struct WaitQueueTableEntry {
    /// The wait queue head.
    head: WaitQueueHead,
    /// Whether allocated.
    allocated: bool,
    /// Name (debugging).
    name: [u8; 32],
    /// Name length.
    name_len: usize,
}

impl WaitQueueTableEntry {
    const fn new() -> Self {
        Self {
            head: WaitQueueHead::new(),
            allocated: false,
            name: [0u8; 32],
            name_len: 0,
        }
    }
}

impl WaitQueueTable {
    /// Creates a new empty table.
    pub const fn new() -> Self {
        Self {
            heads: [const { WaitQueueTableEntry::new() }; MAX_WAIT_QUEUES],
            count: 0,
        }
    }

    /// Allocates a new wait queue.
    pub fn alloc(&mut self, name: &[u8]) -> Result<usize> {
        if self.count >= MAX_WAIT_QUEUES {
            return Err(Error::OutOfMemory);
        }
        let idx = self.find_free_slot()?;
        self.heads[idx].allocated = true;
        self.heads[idx].head = WaitQueueHead::new();
        let copy_len = name.len().min(32);
        self.heads[idx].name[..copy_len].copy_from_slice(&name[..copy_len]);
        self.heads[idx].name_len = copy_len;
        self.count += 1;
        Ok(idx)
    }

    /// Frees a wait queue by index.
    pub fn free(&mut self, idx: usize) -> Result<()> {
        if idx >= MAX_WAIT_QUEUES || !self.heads[idx].allocated {
            return Err(Error::NotFound);
        }
        self.heads[idx] = WaitQueueTableEntry::new();
        self.count -= 1;
        Ok(())
    }

    /// Returns a reference to the wait queue at `idx`.
    pub fn get(&self, idx: usize) -> Result<&WaitQueueHead> {
        if idx >= MAX_WAIT_QUEUES || !self.heads[idx].allocated {
            return Err(Error::NotFound);
        }
        Ok(&self.heads[idx].head)
    }

    /// Returns a mutable reference to the wait queue at `idx`.
    pub fn get_mut(&mut self, idx: usize) -> Result<&mut WaitQueueHead> {
        if idx >= MAX_WAIT_QUEUES || !self.heads[idx].allocated {
            return Err(Error::NotFound);
        }
        Ok(&mut self.heads[idx].head)
    }

    /// Returns the number of allocated queues.
    pub fn count(&self) -> usize {
        self.count
    }

    /// Finds the first free slot.
    fn find_free_slot(&self) -> Result<usize> {
        self.heads
            .iter()
            .position(|e| !e.allocated)
            .ok_or(Error::OutOfMemory)
    }
}
