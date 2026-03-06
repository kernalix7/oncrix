// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! mmap lock contention tracking.
//!
//! Implements a reader-writer lock for the `mm_struct` mmap lock,
//! with contention statistics. In a real kernel, this would be backed
//! by an `rwsem`; here we track the logical state and gather metrics
//! on lock hold times and contention counts.
//!
//! - [`MmapSemState`] — lock state enum (Unlocked/ReadLocked/WriteLocked)
//! - [`ContentionStats`] — per-lock contention counters
//! - [`MmapSem`] — the mmap read-write lock with stats
//! - [`MmapSemPool`] — pool of mmap locks (one per mm_struct)
//!
//! Reference: `.kernelORG/` — `mm/mmap_lock.c`, `include/linux/mmap_lock.h`.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Maximum number of concurrent readers.
const MAX_READERS: u32 = 256;

/// Maximum number of mmap locks in the pool.
const MAX_MM_LOCKS: usize = 64;

/// Maximum contention wait time (ns) before we consider it a
/// long wait.
const LONG_WAIT_THRESHOLD_NS: u64 = 1_000_000; // 1 ms

// -------------------------------------------------------------------
// MmapSemState
// -------------------------------------------------------------------

/// Logical state of the mmap lock.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum MmapSemState {
    /// Lock is free.
    #[default]
    Unlocked,
    /// One or more readers hold the lock.
    ReadLocked,
    /// A single writer holds the lock.
    WriteLocked,
}

// -------------------------------------------------------------------
// ContentionStats
// -------------------------------------------------------------------

/// Contention counters for a single mmap lock.
#[derive(Debug, Clone, Copy, Default)]
pub struct ContentionStats {
    /// Number of successful read-lock acquisitions.
    pub read_locks: u64,
    /// Number of successful write-lock acquisitions.
    pub write_locks: u64,
    /// Number of failed trylock attempts (read).
    pub read_contentions: u64,
    /// Number of failed trylock attempts (write).
    pub write_contentions: u64,
    /// Cumulative wait time (ns) for read locks.
    pub read_wait_ns: u64,
    /// Cumulative wait time (ns) for write locks.
    pub write_wait_ns: u64,
    /// Number of long waits (> LONG_WAIT_THRESHOLD_NS).
    pub long_waits: u64,
    /// Maximum observed wait time (ns).
    pub max_wait_ns: u64,
    /// Number of unlock operations.
    pub unlocks: u64,
}

impl ContentionStats {
    /// Resets all counters.
    pub fn reset(&mut self) {
        *self = Self::default();
    }

    /// Records a read contention event.
    fn record_read_contention(&mut self, wait_ns: u64) {
        self.read_contentions += 1;
        self.read_wait_ns += wait_ns;
        if wait_ns > self.max_wait_ns {
            self.max_wait_ns = wait_ns;
        }
        if wait_ns > LONG_WAIT_THRESHOLD_NS {
            self.long_waits += 1;
        }
    }

    /// Records a write contention event.
    fn record_write_contention(&mut self, wait_ns: u64) {
        self.write_contentions += 1;
        self.write_wait_ns += wait_ns;
        if wait_ns > self.max_wait_ns {
            self.max_wait_ns = wait_ns;
        }
        if wait_ns > LONG_WAIT_THRESHOLD_NS {
            self.long_waits += 1;
        }
    }
}

// -------------------------------------------------------------------
// MmapSem
// -------------------------------------------------------------------

/// The mmap read-write lock with contention tracking.
///
/// Tracks the logical lock state and reader count, plus accumulated
/// contention statistics. The owner field identifies the writer (when
/// write-locked).
pub struct MmapSem {
    /// Current lock state.
    state: MmapSemState,
    /// Number of active readers (when ReadLocked).
    reader_count: u32,
    /// Owner ID (writer's thread/CPU id, 0 if no writer).
    owner: u64,
    /// Contention statistics.
    stats: ContentionStats,
    /// Lock identifier (e.g., mm_struct address).
    lock_id: u64,
}

impl Default for MmapSem {
    fn default() -> Self {
        Self {
            state: MmapSemState::Unlocked,
            reader_count: 0,
            owner: 0,
            stats: ContentionStats::default(),
            lock_id: 0,
        }
    }
}

impl MmapSem {
    /// Creates a new mmap lock with the given identifier.
    pub fn new(lock_id: u64) -> Self {
        Self {
            lock_id,
            ..Self::default()
        }
    }

    /// Returns the current lock state.
    pub fn state(&self) -> MmapSemState {
        self.state
    }

    /// Returns the reader count.
    pub fn reader_count(&self) -> u32 {
        self.reader_count
    }

    /// Returns the writer owner ID.
    pub fn owner(&self) -> u64 {
        self.owner
    }

    /// Returns a reference to the contention statistics.
    pub fn stats(&self) -> &ContentionStats {
        &self.stats
    }

    /// Returns the lock identifier.
    pub fn lock_id(&self) -> u64 {
        self.lock_id
    }

    /// Acquires a read lock.
    ///
    /// Fails if a writer already holds the lock.
    pub fn read_lock(&mut self) -> Result<()> {
        match self.state {
            MmapSemState::WriteLocked => Err(Error::Busy),
            MmapSemState::ReadLocked => {
                if self.reader_count >= MAX_READERS {
                    return Err(Error::OutOfMemory);
                }
                self.reader_count += 1;
                self.stats.read_locks += 1;
                Ok(())
            }
            MmapSemState::Unlocked => {
                self.state = MmapSemState::ReadLocked;
                self.reader_count = 1;
                self.stats.read_locks += 1;
                Ok(())
            }
        }
    }

    /// Tries to acquire a read lock without blocking.
    pub fn read_trylock(&mut self) -> Result<bool> {
        match self.state {
            MmapSemState::WriteLocked => {
                self.stats.record_read_contention(0);
                Ok(false)
            }
            MmapSemState::ReadLocked => {
                if self.reader_count >= MAX_READERS {
                    return Ok(false);
                }
                self.reader_count += 1;
                self.stats.read_locks += 1;
                Ok(true)
            }
            MmapSemState::Unlocked => {
                self.state = MmapSemState::ReadLocked;
                self.reader_count = 1;
                self.stats.read_locks += 1;
                Ok(true)
            }
        }
    }

    /// Acquires a write lock.
    ///
    /// Fails if any reader or writer already holds the lock.
    pub fn write_lock(&mut self, caller: u64) -> Result<()> {
        match self.state {
            MmapSemState::Unlocked => {
                self.state = MmapSemState::WriteLocked;
                self.owner = caller;
                self.stats.write_locks += 1;
                Ok(())
            }
            _ => Err(Error::Busy),
        }
    }

    /// Tries to acquire a write lock without blocking.
    pub fn write_trylock(&mut self, caller: u64) -> Result<bool> {
        match self.state {
            MmapSemState::Unlocked => {
                self.state = MmapSemState::WriteLocked;
                self.owner = caller;
                self.stats.write_locks += 1;
                Ok(true)
            }
            MmapSemState::ReadLocked => {
                self.stats.record_write_contention(0);
                Ok(false)
            }
            MmapSemState::WriteLocked => {
                self.stats.record_write_contention(0);
                Ok(false)
            }
        }
    }

    /// Releases the lock (read or write).
    pub fn unlock(&mut self) -> Result<()> {
        match self.state {
            MmapSemState::ReadLocked => {
                if self.reader_count == 0 {
                    return Err(Error::InvalidArgument);
                }
                self.reader_count -= 1;
                if self.reader_count == 0 {
                    self.state = MmapSemState::Unlocked;
                }
                self.stats.unlocks += 1;
                Ok(())
            }
            MmapSemState::WriteLocked => {
                self.state = MmapSemState::Unlocked;
                self.owner = 0;
                self.stats.unlocks += 1;
                Ok(())
            }
            MmapSemState::Unlocked => Err(Error::InvalidArgument),
        }
    }

    /// Downgrades a write lock to a read lock.
    pub fn downgrade(&mut self) -> Result<()> {
        if self.state != MmapSemState::WriteLocked {
            return Err(Error::InvalidArgument);
        }
        self.state = MmapSemState::ReadLocked;
        self.reader_count = 1;
        self.owner = 0;
        Ok(())
    }

    /// Records a contention event with the given wait time.
    pub fn record_contention(&mut self, is_write: bool, wait_ns: u64) {
        if is_write {
            self.stats.record_write_contention(wait_ns);
        } else {
            self.stats.record_read_contention(wait_ns);
        }
    }

    /// Resets contention statistics.
    pub fn reset_stats(&mut self) {
        self.stats.reset();
    }
}

// -------------------------------------------------------------------
// MmapSemPool
// -------------------------------------------------------------------

/// Pool of mmap locks, one per mm_struct.
pub struct MmapSemPool {
    /// Lock storage.
    locks: [MmapSem; MAX_MM_LOCKS],
    /// Number of active locks.
    count: usize,
}

impl Default for MmapSemPool {
    fn default() -> Self {
        Self {
            locks: [const {
                MmapSem {
                    state: MmapSemState::Unlocked,
                    reader_count: 0,
                    owner: 0,
                    stats: ContentionStats {
                        read_locks: 0,
                        write_locks: 0,
                        read_contentions: 0,
                        write_contentions: 0,
                        read_wait_ns: 0,
                        write_wait_ns: 0,
                        long_waits: 0,
                        max_wait_ns: 0,
                        unlocks: 0,
                    },
                    lock_id: 0,
                }
            }; MAX_MM_LOCKS],
            count: 0,
        }
    }
}

impl MmapSemPool {
    /// Creates a new pool.
    pub fn new() -> Self {
        Self::default()
    }

    /// Allocates a new mmap lock with the given ID.
    pub fn alloc(&mut self, lock_id: u64) -> Result<usize> {
        if self.count >= MAX_MM_LOCKS {
            return Err(Error::OutOfMemory);
        }
        let idx = self.count;
        self.locks[idx] = MmapSem::new(lock_id);
        self.count += 1;
        Ok(idx)
    }

    /// Returns a reference to the lock at the given index.
    pub fn get(&self, index: usize) -> Option<&MmapSem> {
        if index < self.count {
            Some(&self.locks[index])
        } else {
            None
        }
    }

    /// Returns a mutable reference to the lock at the given index.
    pub fn get_mut(&mut self, index: usize) -> Option<&mut MmapSem> {
        if index < self.count {
            Some(&mut self.locks[index])
        } else {
            None
        }
    }

    /// Returns the number of active locks.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Returns `true` if the pool is empty.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Aggregates contention stats across all locks.
    pub fn aggregate_stats(&self) -> ContentionStats {
        let mut total = ContentionStats::default();
        for i in 0..self.count {
            let s = &self.locks[i].stats;
            total.read_locks += s.read_locks;
            total.write_locks += s.write_locks;
            total.read_contentions += s.read_contentions;
            total.write_contentions += s.write_contentions;
            total.read_wait_ns += s.read_wait_ns;
            total.write_wait_ns += s.write_wait_ns;
            total.long_waits += s.long_waits;
            total.unlocks += s.unlocks;
            if s.max_wait_ns > total.max_wait_ns {
                total.max_wait_ns = s.max_wait_ns;
            }
        }
        total
    }
}
