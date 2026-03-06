// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Read-write semaphore (rwsem) implementation.
//!
//! Provides a sleeping reader-writer lock where multiple readers can
//! hold the lock concurrently, but writers have exclusive access.
//! Includes writer-priority to prevent writer starvation.
//!
//! # Architecture
//!
//! ```text
//! RwSemManager
//!  ├── semaphores[MAX_RWSEMS]
//!  │    ├── count: i32   (>0 readers, -1 writer, 0 free)
//!  │    ├── writer_owner: u64
//!  │    ├── waiters: u32
//!  │    └── flags: RwSemFlags
//!  └── stats: RwSemStats
//! ```
//!
//! # Reference
//!
//! Linux `kernel/locking/rwsem.c`.

use oncrix_lib::{Error, Result};

// ══════════════════════════════════════════════════════════════
// Constants
// ══════════════════════════════════════════════════════════════

/// Maximum managed rwsems.
const MAX_RWSEMS: usize = 256;

/// Count value indicating a writer holds the lock.
const RWSEM_WRITER_LOCKED: i32 = -1;

// ══════════════════════════════════════════════════════════════
// RwSemFlags
// ══════════════════════════════════════════════════════════════

/// Configuration flags for an rwsem.
#[derive(Debug, Clone, Copy)]
pub struct RwSemFlags {
    /// Whether writer-priority is enabled.
    pub writer_priority: bool,
    /// Whether optimistic spinning is enabled.
    pub optimistic_spin: bool,
}

impl RwSemFlags {
    /// Default flags.
    const fn default_flags() -> Self {
        Self {
            writer_priority: true,
            optimistic_spin: true,
        }
    }
}

// ══════════════════════════════════════════════════════════════
// RwSemEntry
// ══════════════════════════════════════════════════════════════

/// A single read-write semaphore.
#[derive(Debug, Clone, Copy)]
pub struct RwSemEntry {
    /// Semaphore identifier.
    pub id: u32,
    /// Reader/writer count (>0 = readers, -1 = writer, 0 = free).
    pub count: i32,
    /// Task ID of the current writer (0 if no writer).
    pub writer_owner: u64,
    /// Number of tasks waiting for the lock.
    pub waiters: u32,
    /// Number of waiting writers.
    pub writer_waiters: u32,
    /// Configuration flags.
    pub flags: RwSemFlags,
    /// Total read acquisitions.
    pub read_acquires: u64,
    /// Total write acquisitions.
    pub write_acquires: u64,
    /// Total contentions (failed immediate acquires).
    pub contentions: u64,
    /// Whether this entry is active.
    pub active: bool,
}

impl RwSemEntry {
    /// Create an inactive entry.
    const fn empty() -> Self {
        Self {
            id: 0,
            count: 0,
            writer_owner: 0,
            waiters: 0,
            writer_waiters: 0,
            flags: RwSemFlags::default_flags(),
            read_acquires: 0,
            write_acquires: 0,
            contentions: 0,
            active: false,
        }
    }

    /// Returns `true` if the lock is free.
    pub fn is_free(&self) -> bool {
        self.count == 0
    }

    /// Returns `true` if a writer holds the lock.
    pub fn is_write_locked(&self) -> bool {
        self.count == RWSEM_WRITER_LOCKED
    }

    /// Returns `true` if readers hold the lock.
    pub fn is_read_locked(&self) -> bool {
        self.count > 0
    }
}

// ══════════════════════════════════════════════════════════════
// RwSemStats
// ══════════════════════════════════════════════════════════════

/// Global rwsem statistics.
#[derive(Debug, Clone, Copy)]
pub struct RwSemStats {
    /// Total semaphores created.
    pub total_created: u64,
    /// Total read acquisitions.
    pub total_reads: u64,
    /// Total write acquisitions.
    pub total_writes: u64,
    /// Total contentions.
    pub total_contentions: u64,
}

impl RwSemStats {
    /// Create zeroed stats.
    const fn new() -> Self {
        Self {
            total_created: 0,
            total_reads: 0,
            total_writes: 0,
            total_contentions: 0,
        }
    }
}

// ══════════════════════════════════════════════════════════════
// RwSemManager
// ══════════════════════════════════════════════════════════════

/// Manages read-write semaphores.
pub struct RwSemManager {
    /// Semaphore table.
    sems: [RwSemEntry; MAX_RWSEMS],
    /// Next semaphore ID.
    next_id: u32,
    /// Statistics.
    stats: RwSemStats,
}

impl RwSemManager {
    /// Create a new rwsem manager.
    pub const fn new() -> Self {
        Self {
            sems: [const { RwSemEntry::empty() }; MAX_RWSEMS],
            next_id: 1,
            stats: RwSemStats::new(),
        }
    }

    /// Initialise a new rwsem.
    pub fn init_rwsem(&mut self, flags: RwSemFlags) -> Result<u32> {
        let slot = self
            .sems
            .iter()
            .position(|s| !s.active)
            .ok_or(Error::OutOfMemory)?;
        let id = self.next_id;
        self.next_id += 1;
        self.sems[slot] = RwSemEntry {
            id,
            flags,
            active: true,
            ..RwSemEntry::empty()
        };
        self.stats.total_created += 1;
        Ok(id)
    }

    /// Acquire the rwsem for reading.
    ///
    /// # Errors
    ///
    /// - `WouldBlock` if a writer holds the lock or writer-priority
    ///   waiters are pending.
    pub fn down_read(&mut self, id: u32) -> Result<()> {
        let slot = self.find_sem(id)?;
        let sem = &mut self.sems[slot];
        // Block if a writer holds the lock.
        if sem.is_write_locked() {
            sem.contentions += 1;
            sem.waiters += 1;
            self.stats.total_contentions += 1;
            return Err(Error::WouldBlock);
        }
        // Block if writer-priority and writers are waiting.
        if sem.flags.writer_priority && sem.writer_waiters > 0 {
            sem.contentions += 1;
            sem.waiters += 1;
            self.stats.total_contentions += 1;
            return Err(Error::WouldBlock);
        }
        sem.count += 1;
        sem.read_acquires += 1;
        self.stats.total_reads += 1;
        Ok(())
    }

    /// Release the rwsem from reading.
    pub fn up_read(&mut self, id: u32) -> Result<()> {
        let slot = self.find_sem(id)?;
        if self.sems[slot].count <= 0 {
            return Err(Error::InvalidArgument);
        }
        self.sems[slot].count -= 1;
        Ok(())
    }

    /// Acquire the rwsem for writing.
    ///
    /// # Errors
    ///
    /// - `WouldBlock` if the lock is held by readers or another writer.
    pub fn down_write(&mut self, id: u32, task_id: u64) -> Result<()> {
        let slot = self.find_sem(id)?;
        let sem = &mut self.sems[slot];
        if !sem.is_free() {
            sem.contentions += 1;
            sem.waiters += 1;
            sem.writer_waiters += 1;
            self.stats.total_contentions += 1;
            return Err(Error::WouldBlock);
        }
        sem.count = RWSEM_WRITER_LOCKED;
        sem.writer_owner = task_id;
        sem.write_acquires += 1;
        self.stats.total_writes += 1;
        Ok(())
    }

    /// Release the rwsem from writing.
    pub fn up_write(&mut self, id: u32) -> Result<()> {
        let slot = self.find_sem(id)?;
        if !self.sems[slot].is_write_locked() {
            return Err(Error::InvalidArgument);
        }
        self.sems[slot].count = 0;
        self.sems[slot].writer_owner = 0;
        Ok(())
    }

    /// Destroy an rwsem.
    pub fn destroy(&mut self, id: u32) -> Result<()> {
        let slot = self.find_sem(id)?;
        if !self.sems[slot].is_free() {
            return Err(Error::Busy);
        }
        self.sems[slot] = RwSemEntry::empty();
        Ok(())
    }

    /// Return rwsem entry.
    pub fn get(&self, id: u32) -> Result<&RwSemEntry> {
        let slot = self.find_sem(id)?;
        Ok(&self.sems[slot])
    }

    /// Return statistics.
    pub fn stats(&self) -> RwSemStats {
        self.stats
    }

    // ── Internal ─────────────────────────────────────────────

    fn find_sem(&self, id: u32) -> Result<usize> {
        self.sems
            .iter()
            .position(|s| s.active && s.id == id)
            .ok_or(Error::NotFound)
    }
}
