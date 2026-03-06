// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! VMA-level locking.
//!
//! Implements per-VMA fine-grained locking to improve scalability of
//! `mmap_lock`. Instead of holding a single `mmap_lock` for the entire
//! address space, individual VMAs can be locked for read or write
//! operations. This uses a sequence counter pattern: readers check the
//! sequence before and after; writers increment it.
//!
//! - [`VmaLock`] — per-VMA lock state
//! - [`VmaLockGuard`] — RAII guard for VMA locks
//! - [`VmaLockManager`] — manages locks for multiple VMAs
//! - [`VmaLockStats`] — lock contention statistics
//!
//! Reference: `.kernelORG/` — `include/linux/mm_types.h` (struct vma_lock).

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Maximum number of VMA locks.
const MAX_VMA_LOCKS: usize = 512;

/// Lock state: unlocked.
const LOCK_UNLOCKED: u64 = 0;

/// Lock state bit: write locked.
const LOCK_WRITE_BIT: u64 = 1;

/// Sequence number increment per write.
const SEQ_INCREMENT: u64 = 2;

/// Maximum read retry count.
const MAX_READ_RETRIES: u32 = 100;

// -------------------------------------------------------------------
// VmaLock
// -------------------------------------------------------------------

/// Per-VMA lock using a sequence counter.
///
/// The sequence number is even when unlocked, odd when write-locked.
/// Readers sample the sequence before and after their critical section;
/// if it changed, they retry.
#[derive(Debug, Clone, Copy)]
pub struct VmaLock {
    /// Sequence counter.
    sequence: u64,
    /// Whether write-locked.
    write_locked: bool,
    /// Number of active readers.
    reader_count: u32,
    /// VMA identifier (start address).
    vma_start: u64,
    /// VMA end address.
    vma_end: u64,
    /// Whether this lock slot is active.
    active: bool,
}

impl VmaLock {
    /// Creates a new unlocked VMA lock.
    pub fn new(vma_start: u64, vma_end: u64) -> Self {
        Self {
            sequence: LOCK_UNLOCKED,
            write_locked: false,
            reader_count: 0,
            vma_start,
            vma_end,
            active: true,
        }
    }

    /// Initializes the lock (reset to unlocked state).
    pub fn init(&mut self) {
        self.sequence = LOCK_UNLOCKED;
        self.write_locked = false;
        self.reader_count = 0;
    }

    /// Returns the current sequence number.
    pub fn sequence(&self) -> u64 {
        self.sequence
    }

    /// Returns true if write-locked.
    pub fn is_write_locked(&self) -> bool {
        self.write_locked
    }

    /// Returns the number of active readers.
    pub fn reader_count(&self) -> u32 {
        self.reader_count
    }

    /// Returns the VMA start address.
    pub fn vma_start(&self) -> u64 {
        self.vma_start
    }

    /// Returns the VMA end address.
    pub fn vma_end(&self) -> u64 {
        self.vma_end
    }

    /// Attempts to start a read.
    ///
    /// Returns the sequence number to check after the read.
    /// Returns `Err` if the lock is write-held.
    pub fn start_read(&mut self) -> Result<u64> {
        if self.write_locked {
            return Err(Error::Busy);
        }
        let seq = self.sequence;
        if seq & LOCK_WRITE_BIT != 0 {
            return Err(Error::Busy);
        }
        self.reader_count += 1;
        Ok(seq)
    }

    /// Ends a read, validating the sequence number.
    ///
    /// Returns true if the read was consistent (no intervening write).
    pub fn end_read(&mut self, start_seq: u64) -> bool {
        self.reader_count = self.reader_count.saturating_sub(1);
        self.sequence == start_seq
    }

    /// Starts a write lock.
    ///
    /// Returns `Err(Busy)` if already write-locked or has active readers.
    pub fn start_write(&mut self) -> Result<()> {
        if self.write_locked {
            return Err(Error::Busy);
        }
        if self.reader_count > 0 {
            return Err(Error::Busy);
        }
        self.write_locked = true;
        self.sequence |= LOCK_WRITE_BIT;
        Ok(())
    }

    /// Ends a write lock.
    pub fn end_write(&mut self) {
        self.write_locked = false;
        // Advance sequence past the odd (locked) value.
        self.sequence = (self.sequence | LOCK_WRITE_BIT) + 1;
    }
}

impl Default for VmaLock {
    fn default() -> Self {
        Self {
            sequence: LOCK_UNLOCKED,
            write_locked: false,
            reader_count: 0,
            vma_start: 0,
            vma_end: 0,
            active: false,
        }
    }
}

// -------------------------------------------------------------------
// VmaLockGuard
// -------------------------------------------------------------------

/// RAII-style information about a lock acquisition.
///
/// Note: In a real kernel, this would hold a reference and auto-unlock
/// on drop. Here it records the lock state for explicit unlock calls.
#[derive(Debug, Clone, Copy)]
pub struct VmaLockGuard {
    /// Lock index in the manager.
    pub lock_idx: usize,
    /// Whether this is a read or write guard.
    pub is_write: bool,
    /// Sequence number at acquisition (for reads).
    pub start_seq: u64,
    /// Whether the guard is still active.
    pub active: bool,
}

impl VmaLockGuard {
    /// Creates a read guard.
    pub fn read(lock_idx: usize, start_seq: u64) -> Self {
        Self {
            lock_idx,
            is_write: false,
            start_seq,
            active: true,
        }
    }

    /// Creates a write guard.
    pub fn write(lock_idx: usize) -> Self {
        Self {
            lock_idx,
            is_write: true,
            start_seq: 0,
            active: true,
        }
    }
}

// -------------------------------------------------------------------
// VmaLockStats
// -------------------------------------------------------------------

/// Lock contention statistics.
#[derive(Debug, Clone, Copy, Default)]
pub struct VmaLockStats {
    /// Total read acquisitions.
    pub reads: u64,
    /// Total write acquisitions.
    pub writes: u64,
    /// Read retries due to write interference.
    pub read_retries: u64,
    /// Write failures due to contention.
    pub write_contentions: u64,
    /// Sequence validation failures.
    pub seq_mismatches: u64,
}

impl VmaLockStats {
    /// Resets all statistics.
    pub fn reset(&mut self) {
        *self = Self::default();
    }
}

// -------------------------------------------------------------------
// VmaLockManager
// -------------------------------------------------------------------

/// Manages per-VMA locks.
///
/// Provides lock acquisition and release for VMAs identified by
/// their address range. Tracks contention statistics.
pub struct VmaLockManager {
    /// VMA locks.
    locks: [VmaLock; MAX_VMA_LOCKS],
    /// Number of active locks.
    nr_locks: usize,
    /// Statistics.
    stats: VmaLockStats,
}

impl VmaLockManager {
    /// Creates a new lock manager.
    pub fn new() -> Self {
        Self {
            locks: [VmaLock::default(); MAX_VMA_LOCKS],
            nr_locks: 0,
            stats: VmaLockStats::default(),
        }
    }

    /// Registers a VMA lock.
    pub fn register(&mut self, vma_start: u64, vma_end: u64) -> Result<usize> {
        if self.nr_locks >= MAX_VMA_LOCKS {
            return Err(Error::OutOfMemory);
        }
        // Find a free slot.
        for (i, lock) in self.locks.iter_mut().enumerate() {
            if !lock.active {
                *lock = VmaLock::new(vma_start, vma_end);
                self.nr_locks += 1;
                return Ok(i);
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Unregisters a VMA lock.
    pub fn unregister(&mut self, idx: usize) -> Result<()> {
        if idx >= MAX_VMA_LOCKS || !self.locks[idx].active {
            return Err(Error::NotFound);
        }
        self.locks[idx] = VmaLock::default();
        self.nr_locks = self.nr_locks.saturating_sub(1);
        Ok(())
    }

    /// Acquires a read lock on a VMA.
    pub fn vma_start_read(&mut self, idx: usize) -> Result<VmaLockGuard> {
        if idx >= MAX_VMA_LOCKS || !self.locks[idx].active {
            return Err(Error::NotFound);
        }
        let seq = self.locks[idx].start_read()?;
        self.stats.reads += 1;
        Ok(VmaLockGuard::read(idx, seq))
    }

    /// Releases a read lock and validates the sequence.
    pub fn vma_end_read(&mut self, guard: &mut VmaLockGuard) -> bool {
        if !guard.active || guard.is_write {
            return false;
        }
        guard.active = false;
        let valid = self.locks[guard.lock_idx].end_read(guard.start_seq);
        if !valid {
            self.stats.seq_mismatches += 1;
        }
        valid
    }

    /// Acquires a write lock on a VMA.
    pub fn vma_start_write(&mut self, idx: usize) -> Result<VmaLockGuard> {
        if idx >= MAX_VMA_LOCKS || !self.locks[idx].active {
            return Err(Error::NotFound);
        }
        self.locks[idx].start_write().map_err(|_| {
            self.stats.write_contentions += 1;
            Error::Busy
        })?;
        self.stats.writes += 1;
        Ok(VmaLockGuard::write(idx))
    }

    /// Releases a write lock.
    pub fn vma_end_write(&mut self, guard: &mut VmaLockGuard) {
        if !guard.active || !guard.is_write {
            return;
        }
        guard.active = false;
        self.locks[guard.lock_idx].end_write();
    }

    /// Finds the lock index for a VMA containing the given address.
    pub fn find_lock(&self, addr: u64) -> Option<usize> {
        self.locks
            .iter()
            .position(|l| l.active && addr >= l.vma_start && addr < l.vma_end)
    }

    /// Returns the lock at the given index.
    pub fn get_lock(&self, idx: usize) -> Option<&VmaLock> {
        if idx >= MAX_VMA_LOCKS || !self.locks[idx].active {
            return None;
        }
        Some(&self.locks[idx])
    }

    /// Returns statistics.
    pub fn stats(&self) -> &VmaLockStats {
        &self.stats
    }

    /// Returns the number of active locks.
    pub fn nr_locks(&self) -> usize {
        self.nr_locks
    }
}

impl Default for VmaLockManager {
    fn default() -> Self {
        Self::new()
    }
}
