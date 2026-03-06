// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Read-write semaphore.
//!
//! A read-write semaphore (`RwSem`) allows multiple concurrent
//! readers or a single exclusive writer. Unlike a plain mutex,
//! this primitive distinguishes between shared (read) and
//! exclusive (write) access, enabling higher concurrency for
//! read-heavy workloads.
//!
//! # Design
//!
//! ```text
//!   +----------+
//!   |  RwSem   |
//!   |----------|     +-----------+-----------+
//!   | owner    |     | waiter[0] | waiter[1] | ...
//!   | rd_count |     |  kind=RD  |  kind=WR  |
//!   | wr_lock  |     |  task_id  |  task_id  |
//!   | nr_wait  |     +-----------+-----------+
//!   +----------+
//! ```
//!
//! # Rules
//!
//! - Multiple readers may hold the semaphore simultaneously.
//! - A writer requires exclusive access (no readers, no other
//!   writers).
//! - Waiters are served in FIFO order with writer preference
//!   when the wait queue is not empty.
//! - `downgrade_write()` converts a write lock to a read lock
//!   atomically, waking any queued readers.
//!
//! # Reference
//!
//! Linux `kernel/locking/rwsem.c`,
//! `include/linux/rwsem.h`.

use oncrix_lib::{Error, Result};

// ======================================================================
// Constants
// ======================================================================

/// Maximum number of concurrent readers.
const MAX_READERS: usize = 128;

/// Maximum number of waiters in the queue.
const MAX_WAITERS: usize = 64;

/// Maximum number of managed `RwSem` instances.
const MAX_RWSEMS: usize = 256;

/// No owner sentinel.
const NO_OWNER: u64 = 0;

/// Bias value for writer-held state.
const _WRITER_BIAS: u64 = 0x8000_0000;

/// Bias value for the active-reader count.
const _READER_BIAS: u64 = 1;

// ======================================================================
// Waiter kind
// ======================================================================

/// Kind of a waiter in the semaphore queue.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RwSemWaiterKind {
    /// Waiting for shared (read) access.
    Reader,
    /// Waiting for exclusive (write) access.
    Writer,
}

// ======================================================================
// RwSemWaiter
// ======================================================================

/// A waiter queued on an `RwSem`.
#[derive(Debug, Clone, Copy)]
pub struct RwSemWaiter {
    /// Task ID of the waiter.
    task_id: u64,
    /// Kind (reader or writer).
    kind: RwSemWaiterKind,
    /// Whether this slot is occupied.
    occupied: bool,
    /// Timestamp when the waiter was enqueued (ns).
    enqueue_ns: u64,
}

impl RwSemWaiter {
    /// Creates a new empty waiter slot.
    pub const fn new() -> Self {
        Self {
            task_id: 0,
            kind: RwSemWaiterKind::Reader,
            occupied: false,
            enqueue_ns: 0,
        }
    }

    /// Returns the task ID of this waiter.
    pub fn task_id(&self) -> u64 {
        self.task_id
    }

    /// Returns the waiter kind.
    pub fn kind(&self) -> RwSemWaiterKind {
        self.kind
    }

    /// Returns whether this slot is occupied.
    pub fn is_occupied(&self) -> bool {
        self.occupied
    }

    /// Returns the enqueue timestamp.
    pub fn enqueue_ns(&self) -> u64 {
        self.enqueue_ns
    }
}

// ======================================================================
// RwSem
// ======================================================================

/// Read-write semaphore.
///
/// Supports multiple concurrent readers or a single exclusive
/// writer. Waiters are queued in FIFO order.
pub struct RwSem {
    /// Task ID of the current write owner (0 = none).
    owner: u64,
    /// Number of active readers.
    read_count: u32,
    /// Whether the write lock is held.
    write_locked: bool,
    /// Waiter queue.
    waiters: [RwSemWaiter; MAX_WAITERS],
    /// Number of active waiters.
    nr_waiters: usize,
    /// Generation counter for state transitions.
    generation: u64,
    /// Statistics: total read acquisitions.
    stats_read_acquires: u64,
    /// Statistics: total write acquisitions.
    stats_write_acquires: u64,
    /// Statistics: total contentions (failed trylocks).
    stats_contentions: u64,
}

impl RwSem {
    /// Creates a new read-write semaphore.
    pub const fn new() -> Self {
        Self {
            owner: NO_OWNER,
            read_count: 0,
            write_locked: false,
            waiters: [const { RwSemWaiter::new() }; MAX_WAITERS],
            nr_waiters: 0,
            generation: 0,
            stats_read_acquires: 0,
            stats_write_acquires: 0,
            stats_contentions: 0,
        }
    }

    /// Acquires the semaphore for reading (shared access).
    ///
    /// If a writer holds the lock, the caller is queued.
    pub fn down_read(&mut self, task_id: u64) -> Result<()> {
        if task_id == NO_OWNER {
            return Err(Error::InvalidArgument);
        }
        // If no writer holds the lock and no writers are waiting,
        // grant immediately.
        if !self.write_locked && !self.has_writer_waiter() {
            self.read_count = self.read_count.checked_add(1).ok_or(Error::OutOfMemory)?;
            self.stats_read_acquires += 1;
            self.generation += 1;
            return Ok(());
        }
        // Otherwise, queue the reader.
        self.enqueue_waiter(task_id, RwSemWaiterKind::Reader)?;
        Ok(())
    }

    /// Releases a read lock.
    pub fn up_read(&mut self) -> Result<()> {
        if self.read_count == 0 {
            return Err(Error::InvalidArgument);
        }
        self.read_count -= 1;
        self.generation += 1;
        // If no more readers, try to wake a queued writer.
        if self.read_count == 0 {
            self.wake_first_writer()?;
        }
        Ok(())
    }

    /// Acquires the semaphore for writing (exclusive access).
    ///
    /// If any reader or writer holds the lock, the caller is
    /// queued.
    pub fn down_write(&mut self, task_id: u64) -> Result<()> {
        if task_id == NO_OWNER {
            return Err(Error::InvalidArgument);
        }
        if !self.write_locked && self.read_count == 0 {
            self.write_locked = true;
            self.owner = task_id;
            self.stats_write_acquires += 1;
            self.generation += 1;
            return Ok(());
        }
        self.enqueue_waiter(task_id, RwSemWaiterKind::Writer)?;
        Ok(())
    }

    /// Releases the write lock.
    pub fn up_write(&mut self) -> Result<()> {
        if !self.write_locked {
            return Err(Error::InvalidArgument);
        }
        self.write_locked = false;
        self.owner = NO_OWNER;
        self.generation += 1;
        // Wake queued readers or the next writer.
        self.wake_waiters_after_write()?;
        Ok(())
    }

    /// Tries to acquire the read lock without blocking.
    ///
    /// Returns `Ok(true)` if acquired, `Ok(false)` if contended.
    pub fn down_read_trylock(&mut self, task_id: u64) -> Result<bool> {
        if task_id == NO_OWNER {
            return Err(Error::InvalidArgument);
        }
        if !self.write_locked && !self.has_writer_waiter() {
            self.read_count = self.read_count.checked_add(1).ok_or(Error::OutOfMemory)?;
            self.stats_read_acquires += 1;
            self.generation += 1;
            Ok(true)
        } else {
            self.stats_contentions += 1;
            Ok(false)
        }
    }

    /// Tries to acquire the write lock without blocking.
    ///
    /// Returns `Ok(true)` if acquired, `Ok(false)` if contended.
    pub fn down_write_trylock(&mut self, task_id: u64) -> Result<bool> {
        if task_id == NO_OWNER {
            return Err(Error::InvalidArgument);
        }
        if !self.write_locked && self.read_count == 0 {
            self.write_locked = true;
            self.owner = task_id;
            self.stats_write_acquires += 1;
            self.generation += 1;
            Ok(true)
        } else {
            self.stats_contentions += 1;
            Ok(false)
        }
    }

    /// Downgrades a write lock to a read lock atomically.
    ///
    /// After this call the semaphore is held for reading (shared),
    /// and any queued readers are woken.
    pub fn downgrade_write(&mut self) -> Result<()> {
        if !self.write_locked {
            return Err(Error::InvalidArgument);
        }
        self.write_locked = false;
        self.owner = NO_OWNER;
        self.read_count = self.read_count.checked_add(1).ok_or(Error::OutOfMemory)?;
        self.generation += 1;
        // Wake all queued readers (they can share with us).
        self.wake_queued_readers()?;
        Ok(())
    }

    /// Returns whether the write lock is held.
    pub fn is_write_locked(&self) -> bool {
        self.write_locked
    }

    /// Returns the number of active readers.
    pub fn read_count(&self) -> u32 {
        self.read_count
    }

    /// Returns the current write owner task ID.
    pub fn owner(&self) -> u64 {
        self.owner
    }

    /// Returns the number of queued waiters.
    pub fn nr_waiters(&self) -> usize {
        self.nr_waiters
    }

    /// Returns the generation counter.
    pub fn generation(&self) -> u64 {
        self.generation
    }

    /// Returns total read acquisition count.
    pub fn stats_read_acquires(&self) -> u64 {
        self.stats_read_acquires
    }

    /// Returns total write acquisition count.
    pub fn stats_write_acquires(&self) -> u64 {
        self.stats_write_acquires
    }

    /// Returns total contention count.
    pub fn stats_contentions(&self) -> u64 {
        self.stats_contentions
    }

    // ------------------------------------------------------------------
    // Internal helpers
    // ------------------------------------------------------------------

    /// Checks whether there is a writer in the wait queue.
    fn has_writer_waiter(&self) -> bool {
        self.waiters[..self.nr_waiters]
            .iter()
            .any(|w| w.occupied && w.kind == RwSemWaiterKind::Writer)
    }

    /// Enqueues a waiter.
    fn enqueue_waiter(&mut self, task_id: u64, kind: RwSemWaiterKind) -> Result<()> {
        if self.nr_waiters >= MAX_WAITERS {
            return Err(Error::OutOfMemory);
        }
        self.waiters[self.nr_waiters] = RwSemWaiter {
            task_id,
            kind,
            occupied: true,
            enqueue_ns: self.generation,
        };
        self.nr_waiters += 1;
        Ok(())
    }

    /// Wakes the first queued writer (if any).
    fn wake_first_writer(&mut self) -> Result<()> {
        let pos = self.waiters[..self.nr_waiters]
            .iter()
            .position(|w| w.occupied && w.kind == RwSemWaiterKind::Writer);
        if let Some(idx) = pos {
            let task_id = self.waiters[idx].task_id;
            self.remove_waiter(idx);
            self.write_locked = true;
            self.owner = task_id;
            self.stats_write_acquires += 1;
        }
        Ok(())
    }

    /// Wakes all queued readers.
    fn wake_queued_readers(&mut self) -> Result<()> {
        let mut i = 0;
        while i < self.nr_waiters {
            if self.waiters[i].occupied && self.waiters[i].kind == RwSemWaiterKind::Reader {
                self.remove_waiter(i);
                self.read_count = self.read_count.checked_add(1).ok_or(Error::OutOfMemory)?;
                self.stats_read_acquires += 1;
                // Don't increment i since remove shifted elements.
            } else {
                i += 1;
            }
        }
        Ok(())
    }

    /// After a write unlock, wakes pending readers or the next
    /// writer.
    fn wake_waiters_after_write(&mut self) -> Result<()> {
        if self.nr_waiters == 0 {
            return Ok(());
        }
        // If the first waiter is a reader, wake all leading readers.
        if self.waiters[0].occupied && self.waiters[0].kind == RwSemWaiterKind::Reader {
            self.wake_queued_readers()?;
        } else {
            self.wake_first_writer()?;
        }
        Ok(())
    }

    /// Removes a waiter at `idx` by shifting remaining entries.
    fn remove_waiter(&mut self, idx: usize) {
        if idx < self.nr_waiters {
            let mut i = idx;
            while i + 1 < self.nr_waiters {
                self.waiters.swap(i, i + 1);
                i += 1;
            }
            self.waiters[self.nr_waiters - 1] = RwSemWaiter::new();
            self.nr_waiters -= 1;
        }
    }
}

// ======================================================================
// RwSemTable — global registry
// ======================================================================

/// Global table of read-write semaphores.
pub struct RwSemTable {
    /// Semaphore entries.
    entries: [RwSemEntry; MAX_RWSEMS],
    /// Number of registered semaphores.
    count: usize,
}

/// An entry in the global semaphore table.
struct RwSemEntry {
    /// The semaphore.
    sem: RwSem,
    /// Whether this slot is allocated.
    allocated: bool,
    /// Name (for debugging).
    name: [u8; 32],
    /// Length of the name.
    name_len: usize,
}

impl RwSemEntry {
    const fn new() -> Self {
        Self {
            sem: RwSem::new(),
            allocated: false,
            name: [0u8; 32],
            name_len: 0,
        }
    }
}

impl RwSemTable {
    /// Creates a new empty table.
    pub const fn new() -> Self {
        Self {
            entries: [const { RwSemEntry::new() }; MAX_RWSEMS],
            count: 0,
        }
    }

    /// Allocates a new read-write semaphore.
    ///
    /// Returns the index (handle) of the new semaphore.
    pub fn alloc(&mut self, name: &[u8]) -> Result<usize> {
        if self.count >= MAX_RWSEMS {
            return Err(Error::OutOfMemory);
        }
        let idx = self.find_free_slot()?;
        self.entries[idx].allocated = true;
        self.entries[idx].sem = RwSem::new();
        let copy_len = name.len().min(32);
        self.entries[idx].name[..copy_len].copy_from_slice(&name[..copy_len]);
        self.entries[idx].name_len = copy_len;
        self.count += 1;
        Ok(idx)
    }

    /// Frees a semaphore by index.
    pub fn free(&mut self, idx: usize) -> Result<()> {
        if idx >= MAX_RWSEMS || !self.entries[idx].allocated {
            return Err(Error::NotFound);
        }
        self.entries[idx] = RwSemEntry::new();
        self.count -= 1;
        Ok(())
    }

    /// Returns a reference to the semaphore at `idx`.
    pub fn get(&self, idx: usize) -> Result<&RwSem> {
        if idx >= MAX_RWSEMS || !self.entries[idx].allocated {
            return Err(Error::NotFound);
        }
        Ok(&self.entries[idx].sem)
    }

    /// Returns a mutable reference to the semaphore at `idx`.
    pub fn get_mut(&mut self, idx: usize) -> Result<&mut RwSem> {
        if idx >= MAX_RWSEMS || !self.entries[idx].allocated {
            return Err(Error::NotFound);
        }
        Ok(&mut self.entries[idx].sem)
    }

    /// Returns the number of allocated semaphores.
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
