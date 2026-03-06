// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Per-address-space mmap read-write lock.
//!
//! Every process's `mm_struct` (address space) is protected by an
//! mmap lock that serializes VMA modifications while allowing
//! concurrent reads. This module provides the lock abstraction with
//! read/write acquire, release, trylock, and downgrade operations.
//!
//! The lock supports:
//!
//! - **Multiple concurrent readers** — page faults, `/proc/pid/maps`
//! - **Exclusive writer** — `mmap()`, `munmap()`, `mprotect()`
//! - **Trylock** — non-blocking acquisition for speculative paths
//! - **Downgrade** — convert write lock to read lock without release
//!
//! This module manages a table of 256 locks, one per mm (address
//! space), indexed by mm identifier.
//!
//! - [`MmapLockState`] — current lock state
//! - [`MmapLock`] — a single lock instance
//! - [`MmapLockTable`] — table of per-mm locks
//! - [`MmapLockStats`] — aggregate statistics
//!
//! Reference: Linux `include/linux/mmap_lock.h`,
//! `mm/mmap_lock.c`.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Maximum number of address spaces (mm_structs) tracked.
const MAX_MM_LOCKS: usize = 256;

/// Maximum number of concurrent readers before overflow protection.
const MAX_READERS: u32 = 65535;

/// Process ID indicating no writer.
const NO_WRITER: u32 = 0;

// -------------------------------------------------------------------
// MmapLockState
// -------------------------------------------------------------------

/// Current state of an mmap lock.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum MmapLockState {
    /// Lock is not held by anyone.
    #[default]
    Unlocked,
    /// Lock is held by one or more readers.
    ReadLocked(u32),
    /// Lock is held exclusively by a writer.
    WriteLocked,
}

// -------------------------------------------------------------------
// MmapLock
// -------------------------------------------------------------------

/// A single per-mm read-write lock.
///
/// Tracks the current state, writer identity, reader count, and
/// contention statistics.
#[derive(Debug, Clone, Copy)]
pub struct MmapLock {
    /// Current lock state.
    pub state: MmapLockState,
    /// PID of the current write lock holder (0 if none).
    pub writer_pid: u32,
    /// Number of active readers (redundant with ReadLocked(n),
    /// kept for quick access).
    pub read_count: u32,
    /// Number of times acquisition was contended.
    pub contention_count: u64,
    /// Memory space identifier this lock protects.
    pub mm_id: u32,
    /// Whether this lock slot is allocated.
    pub allocated: bool,
    /// Total read acquisitions.
    pub total_reads: u64,
    /// Total write acquisitions.
    pub total_writes: u64,
    /// Total downgrades from write to read.
    pub total_downgrades: u64,
}

impl MmapLock {
    /// Creates an empty, unallocated lock.
    const fn empty() -> Self {
        Self {
            state: MmapLockState::Unlocked,
            writer_pid: NO_WRITER,
            read_count: 0,
            contention_count: 0,
            mm_id: 0,
            allocated: false,
            total_reads: 0,
            total_writes: 0,
            total_downgrades: 0,
        }
    }

    /// Returns `true` if the lock is currently unlocked.
    pub fn is_unlocked(&self) -> bool {
        matches!(self.state, MmapLockState::Unlocked)
    }

    /// Returns `true` if the lock is held for reading.
    pub fn is_read_locked(&self) -> bool {
        matches!(self.state, MmapLockState::ReadLocked(_))
    }

    /// Returns `true` if the lock is held for writing.
    pub fn is_write_locked(&self) -> bool {
        matches!(self.state, MmapLockState::WriteLocked)
    }
}

// -------------------------------------------------------------------
// MmapLockStats
// -------------------------------------------------------------------

/// Aggregate statistics for all mmap locks.
#[derive(Debug, Clone, Copy, Default)]
pub struct MmapLockStats {
    /// Total read lock acquisitions across all locks.
    pub read_acquires: u64,
    /// Total write lock acquisitions across all locks.
    pub write_acquires: u64,
    /// Total contention events across all locks.
    pub contentions: u64,
    /// Total downgrade operations across all locks.
    pub downgrades: u64,
    /// Number of allocated lock slots.
    pub allocated_locks: usize,
    /// Total read trylock failures.
    pub read_trylock_failures: u64,
    /// Total write trylock failures.
    pub write_trylock_failures: u64,
}

// -------------------------------------------------------------------
// MmapLockTable
// -------------------------------------------------------------------

/// Table of per-address-space mmap locks.
///
/// Manages up to 256 locks, one per mm (memory descriptor).
/// Provides acquire, release, trylock, and downgrade operations.
pub struct MmapLockTable {
    /// Array of mmap locks.
    locks: [MmapLock; MAX_MM_LOCKS],
    /// Number of allocated lock slots.
    allocated_count: usize,
    /// Aggregate contention count.
    total_contentions: u64,
    /// Aggregate read trylock failures.
    read_trylock_failures: u64,
    /// Aggregate write trylock failures.
    write_trylock_failures: u64,
}

impl Default for MmapLockTable {
    fn default() -> Self {
        Self::new()
    }
}

impl MmapLockTable {
    /// Creates a new empty lock table.
    pub const fn new() -> Self {
        Self {
            locks: [MmapLock::empty(); MAX_MM_LOCKS],
            allocated_count: 0,
            total_contentions: 0,
            read_trylock_failures: 0,
            write_trylock_failures: 0,
        }
    }

    /// Allocates a lock for the given mm_id.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the lock table is full.
    /// Returns [`Error::AlreadyExists`] if a lock for this mm_id
    /// already exists.
    pub fn alloc_lock(&mut self, mm_id: u32) -> Result<usize> {
        // Check if already allocated.
        if self.find_lock(mm_id).is_ok() {
            return Err(Error::AlreadyExists);
        }
        if self.allocated_count >= MAX_MM_LOCKS {
            return Err(Error::OutOfMemory);
        }

        let idx = self.find_free_slot()?;
        self.locks[idx] = MmapLock {
            state: MmapLockState::Unlocked,
            writer_pid: NO_WRITER,
            read_count: 0,
            contention_count: 0,
            mm_id,
            allocated: true,
            total_reads: 0,
            total_writes: 0,
            total_downgrades: 0,
        };
        self.allocated_count += 1;
        Ok(idx)
    }

    /// Frees a lock for the given mm_id.
    ///
    /// The lock must be unlocked before freeing.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if no lock for this mm_id exists.
    /// Returns [`Error::Busy`] if the lock is currently held.
    pub fn free_lock(&mut self, mm_id: u32) -> Result<()> {
        let idx = self.find_lock(mm_id)?;
        if !self.locks[idx].is_unlocked() {
            return Err(Error::Busy);
        }
        self.locks[idx] = MmapLock::empty();
        self.allocated_count -= 1;
        Ok(())
    }

    /// Acquires a read lock on the given mm_id.
    ///
    /// Multiple readers can hold the lock concurrently. Blocks
    /// conceptually if a writer holds the lock (returns
    /// `WouldBlock` in this non-blocking implementation).
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if no lock for this mm_id exists.
    /// Returns [`Error::WouldBlock`] if a writer holds the lock.
    pub fn acquire_read(&mut self, mm_id: u32) -> Result<()> {
        let idx = self.find_lock(mm_id)?;

        match self.locks[idx].state {
            MmapLockState::Unlocked => {
                self.locks[idx].state = MmapLockState::ReadLocked(1);
                self.locks[idx].read_count = 1;
                self.locks[idx].total_reads += 1;
                Ok(())
            }
            MmapLockState::ReadLocked(n) => {
                if n >= MAX_READERS {
                    return Err(Error::OutOfMemory);
                }
                self.locks[idx].state = MmapLockState::ReadLocked(n + 1);
                self.locks[idx].read_count = n + 1;
                self.locks[idx].total_reads += 1;
                Ok(())
            }
            MmapLockState::WriteLocked => {
                self.locks[idx].contention_count += 1;
                self.total_contentions += 1;
                Err(Error::WouldBlock)
            }
        }
    }

    /// Releases a read lock on the given mm_id.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if no lock for this mm_id exists.
    /// Returns [`Error::InvalidArgument`] if the lock is not read-locked.
    pub fn release_read(&mut self, mm_id: u32) -> Result<()> {
        let idx = self.find_lock(mm_id)?;

        match self.locks[idx].state {
            MmapLockState::ReadLocked(n) => {
                if n <= 1 {
                    self.locks[idx].state = MmapLockState::Unlocked;
                    self.locks[idx].read_count = 0;
                } else {
                    self.locks[idx].state = MmapLockState::ReadLocked(n - 1);
                    self.locks[idx].read_count = n - 1;
                }
                Ok(())
            }
            _ => Err(Error::InvalidArgument),
        }
    }

    /// Acquires a write lock on the given mm_id.
    ///
    /// The write lock is exclusive: no readers or other writers may
    /// hold the lock.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if no lock for this mm_id exists.
    /// Returns [`Error::Busy`] if any lock is held (read or write).
    pub fn acquire_write(&mut self, mm_id: u32, writer_pid: u32) -> Result<()> {
        let idx = self.find_lock(mm_id)?;

        match self.locks[idx].state {
            MmapLockState::Unlocked => {
                self.locks[idx].state = MmapLockState::WriteLocked;
                self.locks[idx].writer_pid = writer_pid;
                self.locks[idx].total_writes += 1;
                Ok(())
            }
            MmapLockState::ReadLocked(_) => {
                self.locks[idx].contention_count += 1;
                self.total_contentions += 1;
                Err(Error::Busy)
            }
            MmapLockState::WriteLocked => {
                self.locks[idx].contention_count += 1;
                self.total_contentions += 1;
                Err(Error::Busy)
            }
        }
    }

    /// Releases a write lock on the given mm_id.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if no lock for this mm_id exists.
    /// Returns [`Error::InvalidArgument`] if the lock is not write-locked.
    pub fn release_write(&mut self, mm_id: u32) -> Result<()> {
        let idx = self.find_lock(mm_id)?;

        if !self.locks[idx].is_write_locked() {
            return Err(Error::InvalidArgument);
        }

        self.locks[idx].state = MmapLockState::Unlocked;
        self.locks[idx].writer_pid = NO_WRITER;
        Ok(())
    }

    /// Attempts to acquire a read lock without blocking.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if no lock for this mm_id exists.
    /// Returns [`Error::WouldBlock`] if a writer holds the lock.
    pub fn mmap_read_trylock(&mut self, mm_id: u32) -> Result<()> {
        let result = self.acquire_read(mm_id);
        if result.is_err() {
            self.read_trylock_failures += 1;
        }
        result
    }

    /// Attempts to acquire a write lock without blocking.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if no lock for this mm_id exists.
    /// Returns [`Error::Busy`] if any lock is held.
    pub fn mmap_write_trylock(&mut self, mm_id: u32, writer_pid: u32) -> Result<()> {
        let result = self.acquire_write(mm_id, writer_pid);
        if result.is_err() {
            self.write_trylock_failures += 1;
        }
        result
    }

    /// Downgrades a write lock to a read lock.
    ///
    /// The caller must hold the write lock. After downgrade, other
    /// readers can acquire the lock concurrently.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if no lock for this mm_id exists.
    /// Returns [`Error::InvalidArgument`] if the lock is not write-locked.
    pub fn mmap_write_downgrade(&mut self, mm_id: u32) -> Result<()> {
        let idx = self.find_lock(mm_id)?;

        if !self.locks[idx].is_write_locked() {
            return Err(Error::InvalidArgument);
        }

        self.locks[idx].state = MmapLockState::ReadLocked(1);
        self.locks[idx].read_count = 1;
        self.locks[idx].writer_pid = NO_WRITER;
        self.locks[idx].total_downgrades += 1;

        Ok(())
    }

    /// Returns the current state of the lock for the given mm_id.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if no lock for this mm_id exists.
    pub fn lock_state(&self, mm_id: u32) -> Result<MmapLockState> {
        let idx = self.find_lock(mm_id)?;
        Ok(self.locks[idx].state)
    }

    /// Returns a copy of the lock descriptor for the given mm_id.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if no lock for this mm_id exists.
    pub fn get_lock(&self, mm_id: u32) -> Result<MmapLock> {
        let idx = self.find_lock(mm_id)?;
        Ok(self.locks[idx])
    }

    /// Returns the number of allocated locks.
    pub fn len(&self) -> usize {
        self.allocated_count
    }

    /// Returns `true` if no locks are allocated.
    pub fn is_empty(&self) -> bool {
        self.allocated_count == 0
    }

    /// Returns aggregate statistics.
    pub fn stats(&self) -> MmapLockStats {
        let mut total_reads = 0_u64;
        let mut total_writes = 0_u64;
        let mut total_downgrades = 0_u64;

        for i in 0..MAX_MM_LOCKS {
            if self.locks[i].allocated {
                total_reads += self.locks[i].total_reads;
                total_writes += self.locks[i].total_writes;
                total_downgrades += self.locks[i].total_downgrades;
            }
        }

        MmapLockStats {
            read_acquires: total_reads,
            write_acquires: total_writes,
            contentions: self.total_contentions,
            downgrades: total_downgrades,
            allocated_locks: self.allocated_count,
            read_trylock_failures: self.read_trylock_failures,
            write_trylock_failures: self.write_trylock_failures,
        }
    }

    /// Finds the index of a lock by mm_id.
    fn find_lock(&self, mm_id: u32) -> Result<usize> {
        for i in 0..MAX_MM_LOCKS {
            if self.locks[i].allocated && self.locks[i].mm_id == mm_id {
                return Ok(i);
            }
        }
        Err(Error::NotFound)
    }

    /// Finds the first free (unallocated) slot.
    fn find_free_slot(&self) -> Result<usize> {
        for i in 0..MAX_MM_LOCKS {
            if !self.locks[i].allocated {
                return Ok(i);
            }
        }
        Err(Error::OutOfMemory)
    }
}

// -------------------------------------------------------------------
// Convenience functions
// -------------------------------------------------------------------

/// Attempts a non-blocking read lock acquisition.
///
/// This is a convenience wrapper around [`MmapLockTable::mmap_read_trylock`].
pub fn mmap_read_trylock(table: &mut MmapLockTable, mm_id: u32) -> Result<()> {
    table.mmap_read_trylock(mm_id)
}

/// Attempts a non-blocking write lock acquisition.
///
/// This is a convenience wrapper around [`MmapLockTable::mmap_write_trylock`].
pub fn mmap_write_trylock(table: &mut MmapLockTable, mm_id: u32, writer_pid: u32) -> Result<()> {
    table.mmap_write_trylock(mm_id, writer_pid)
}

/// Downgrades a write lock to a read lock.
///
/// This is a convenience wrapper around [`MmapLockTable::mmap_write_downgrade`].
pub fn mmap_write_downgrade(table: &mut MmapLockTable, mm_id: u32) -> Result<()> {
    table.mmap_write_downgrade(mm_id)
}
