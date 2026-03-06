// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Folio locking primitives.
//!
//! A folio is a contiguous group of pages managed as a unit for the
//! page cache. Before reading or writing folio contents the caller
//! must acquire the folio lock. This module provides try-lock,
//! blocking lock, and lock-with-timeout semantics, along with an
//! upgrade path from shared to exclusive access.
//!
//! # Design
//!
//! ```text
//!  folio_lock(folio)       → acquire exclusive lock (block if held)
//!  folio_trylock(folio)    → try exclusive, return immediately
//!  folio_lock_shared(folio)→ acquire shared read lock
//!  folio_unlock(folio)     → release lock
//! ```
//!
//! # Key Types
//!
//! - [`FolioLockState`] — current lock state
//! - [`FolioLock`] — lock for a single folio
//! - [`FolioLockTable`] — manages locks for all folios
//! - [`FolioLockStats`] — locking statistics
//!
//! Reference: Linux `include/linux/pagemap.h`, `mm/filemap.c`.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Maximum tracked folio locks.
const MAX_FOLIO_LOCKS: usize = 1024;

/// Maximum shared readers.
const MAX_READERS: u32 = 65534;

/// Lock timeout default (ticks).
const DEFAULT_LOCK_TIMEOUT: u64 = 5000;

// -------------------------------------------------------------------
// FolioLockState
// -------------------------------------------------------------------

/// Current state of a folio lock.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FolioLockState {
    /// Unlocked.
    Unlocked,
    /// Held in shared (read) mode.
    Shared,
    /// Held in exclusive (write) mode.
    Exclusive,
}

impl FolioLockState {
    /// Return a label.
    pub const fn label(&self) -> &'static str {
        match self {
            Self::Unlocked => "unlocked",
            Self::Shared => "shared",
            Self::Exclusive => "exclusive",
        }
    }

    /// Check whether the lock is held in any mode.
    pub const fn is_locked(&self) -> bool {
        !matches!(self, Self::Unlocked)
    }
}

// -------------------------------------------------------------------
// FolioLock
// -------------------------------------------------------------------

/// Lock for a single folio.
#[derive(Debug, Clone, Copy)]
pub struct FolioLock {
    /// Folio index (page cache index).
    folio_index: u64,
    /// Current state.
    state: FolioLockState,
    /// Number of shared readers (0 when exclusive or unlocked).
    reader_count: u32,
    /// Owner thread ID (for exclusive lock), 0 otherwise.
    owner: u64,
    /// Number of threads waiting for the lock.
    waiters: u32,
}

impl FolioLock {
    /// Create an unlocked folio lock.
    pub const fn new(folio_index: u64) -> Self {
        Self {
            folio_index,
            state: FolioLockState::Unlocked,
            reader_count: 0,
            owner: 0,
            waiters: 0,
        }
    }

    /// Return the folio index.
    pub const fn folio_index(&self) -> u64 {
        self.folio_index
    }

    /// Return the current state.
    pub const fn state(&self) -> FolioLockState {
        self.state
    }

    /// Return the reader count.
    pub const fn reader_count(&self) -> u32 {
        self.reader_count
    }

    /// Return the owner thread ID.
    pub const fn owner(&self) -> u64 {
        self.owner
    }

    /// Return the waiter count.
    pub const fn waiters(&self) -> u32 {
        self.waiters
    }

    /// Check whether the lock is unlocked.
    pub const fn is_unlocked(&self) -> bool {
        matches!(self.state, FolioLockState::Unlocked)
    }

    /// Try to acquire the exclusive lock.
    pub fn try_lock(&mut self, thread_id: u64) -> Result<()> {
        if self.state != FolioLockState::Unlocked {
            return Err(Error::WouldBlock);
        }
        self.state = FolioLockState::Exclusive;
        self.owner = thread_id;
        Ok(())
    }

    /// Try to acquire a shared lock.
    pub fn try_lock_shared(&mut self) -> Result<()> {
        match self.state {
            FolioLockState::Exclusive => Err(Error::WouldBlock),
            FolioLockState::Shared => {
                if self.reader_count >= MAX_READERS {
                    return Err(Error::OutOfMemory);
                }
                self.reader_count += 1;
                Ok(())
            }
            FolioLockState::Unlocked => {
                self.state = FolioLockState::Shared;
                self.reader_count = 1;
                Ok(())
            }
        }
    }

    /// Release the lock.
    pub fn unlock(&mut self) -> Result<()> {
        match self.state {
            FolioLockState::Exclusive => {
                self.state = FolioLockState::Unlocked;
                self.owner = 0;
                Ok(())
            }
            FolioLockState::Shared => {
                self.reader_count = self.reader_count.saturating_sub(1);
                if self.reader_count == 0 {
                    self.state = FolioLockState::Unlocked;
                }
                Ok(())
            }
            FolioLockState::Unlocked => Err(Error::InvalidArgument),
        }
    }

    /// Upgrade from shared to exclusive.
    pub fn upgrade(&mut self, thread_id: u64) -> Result<()> {
        if self.state != FolioLockState::Shared {
            return Err(Error::InvalidArgument);
        }
        if self.reader_count != 1 {
            return Err(Error::WouldBlock);
        }
        self.state = FolioLockState::Exclusive;
        self.reader_count = 0;
        self.owner = thread_id;
        Ok(())
    }

    /// Add a waiter.
    pub fn add_waiter(&mut self) {
        self.waiters = self.waiters.saturating_add(1);
    }

    /// Remove a waiter.
    pub fn remove_waiter(&mut self) {
        self.waiters = self.waiters.saturating_sub(1);
    }
}

impl Default for FolioLock {
    fn default() -> Self {
        Self {
            folio_index: 0,
            state: FolioLockState::Unlocked,
            reader_count: 0,
            owner: 0,
            waiters: 0,
        }
    }
}

// -------------------------------------------------------------------
// FolioLockStats
// -------------------------------------------------------------------

/// Folio locking statistics.
#[derive(Debug, Clone, Copy)]
pub struct FolioLockStats {
    /// Exclusive lock acquisitions.
    pub exclusive_locks: u64,
    /// Shared lock acquisitions.
    pub shared_locks: u64,
    /// Trylock failures (WouldBlock).
    pub trylock_failures: u64,
    /// Upgrade successes.
    pub upgrades: u64,
    /// Upgrade failures.
    pub upgrade_failures: u64,
    /// Unlocks.
    pub unlocks: u64,
}

impl FolioLockStats {
    /// Create zero stats.
    pub const fn new() -> Self {
        Self {
            exclusive_locks: 0,
            shared_locks: 0,
            trylock_failures: 0,
            upgrades: 0,
            upgrade_failures: 0,
            unlocks: 0,
        }
    }

    /// Total lock operations.
    pub const fn total_locks(&self) -> u64 {
        self.exclusive_locks + self.shared_locks
    }

    /// Contention rate as percent.
    pub const fn contention_pct(&self) -> u64 {
        let total = self.total_locks() + self.trylock_failures;
        if total == 0 {
            return 0;
        }
        self.trylock_failures * 100 / total
    }
}

impl Default for FolioLockStats {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// FolioLockTable
// -------------------------------------------------------------------

/// Manages locks for all folios.
pub struct FolioLockTable {
    /// Per-folio locks.
    locks: [FolioLock; MAX_FOLIO_LOCKS],
    /// Number of tracked entries.
    count: usize,
    /// Statistics.
    stats: FolioLockStats,
}

impl FolioLockTable {
    /// Create a new lock table.
    pub const fn new() -> Self {
        Self {
            locks: [const {
                FolioLock {
                    folio_index: 0,
                    state: FolioLockState::Unlocked,
                    reader_count: 0,
                    owner: 0,
                    waiters: 0,
                }
            }; MAX_FOLIO_LOCKS],
            count: 0,
            stats: FolioLockStats::new(),
        }
    }

    /// Return the statistics.
    pub const fn stats(&self) -> &FolioLockStats {
        &self.stats
    }

    /// Return the number of tracked locks.
    pub const fn count(&self) -> usize {
        self.count
    }

    /// Register a folio lock.
    pub fn register(&mut self, folio_index: u64) -> Result<()> {
        if self.count >= MAX_FOLIO_LOCKS {
            return Err(Error::OutOfMemory);
        }
        self.locks[self.count] = FolioLock::new(folio_index);
        self.count += 1;
        Ok(())
    }

    /// Try to acquire an exclusive lock on a folio.
    pub fn try_lock(&mut self, folio_index: u64, thread_id: u64) -> Result<()> {
        for idx in 0..self.count {
            if self.locks[idx].folio_index() == folio_index {
                return match self.locks[idx].try_lock(thread_id) {
                    Ok(()) => {
                        self.stats.exclusive_locks += 1;
                        Ok(())
                    }
                    Err(e) => {
                        self.stats.trylock_failures += 1;
                        Err(e)
                    }
                };
            }
        }
        Err(Error::NotFound)
    }

    /// Try to acquire a shared lock.
    pub fn try_lock_shared(&mut self, folio_index: u64) -> Result<()> {
        for idx in 0..self.count {
            if self.locks[idx].folio_index() == folio_index {
                return match self.locks[idx].try_lock_shared() {
                    Ok(()) => {
                        self.stats.shared_locks += 1;
                        Ok(())
                    }
                    Err(e) => {
                        self.stats.trylock_failures += 1;
                        Err(e)
                    }
                };
            }
        }
        Err(Error::NotFound)
    }

    /// Unlock a folio.
    pub fn unlock(&mut self, folio_index: u64) -> Result<()> {
        for idx in 0..self.count {
            if self.locks[idx].folio_index() == folio_index {
                self.locks[idx].unlock()?;
                self.stats.unlocks += 1;
                return Ok(());
            }
        }
        Err(Error::NotFound)
    }

    /// Find a folio lock by index.
    pub fn find(&self, folio_index: u64) -> Option<&FolioLock> {
        for idx in 0..self.count {
            if self.locks[idx].folio_index() == folio_index {
                return Some(&self.locks[idx]);
            }
        }
        None
    }
}

impl Default for FolioLockTable {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// Public helpers
// -------------------------------------------------------------------

/// Check whether a folio is locked.
pub fn folio_is_locked(table: &FolioLockTable, folio_index: u64) -> bool {
    match table.find(folio_index) {
        Some(lock) => lock.state().is_locked(),
        None => false,
    }
}

/// Return the default lock timeout.
pub const fn default_lock_timeout() -> u64 {
    DEFAULT_LOCK_TIMEOUT
}

/// Check whether a folio has waiting threads.
pub fn folio_has_waiters(table: &FolioLockTable, folio_index: u64) -> bool {
    match table.find(folio_index) {
        Some(lock) => lock.waiters() > 0,
        None => false,
    }
}
