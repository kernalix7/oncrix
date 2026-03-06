// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Page locking primitives.
//!
//! Certain operations on a page (writeback, reclaim, migration) require
//! exclusive access. The page lock ensures only one subsystem modifies
//! a page at a time. This module provides a PFN-indexed lock table and
//! lock/unlock/trylock operations.
//!
//! # Design
//!
//! ```text
//!  lock_page(pfn)
//!       │
//!       ├─ lock available? → acquire, return Ok
//!       └─ lock held?      → return WouldBlock (trylock)
//!                           or spin/wait (lock)
//!
//!  unlock_page(pfn)
//!       └─ release lock, wake waiters
//! ```
//!
//! # Key Types
//!
//! - [`PageLockEntry`] — per-page lock state
//! - [`PageLockTable`] — table of page locks indexed by PFN
//! - [`LockToken`] — proof of lock ownership
//!
//! Reference: Linux `include/linux/pagemap.h` (`lock_page`, `unlock_page`).

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Maximum pages tracked in the lock table.
const MAX_LOCKED_PAGES: usize = 4096;

/// Hash table size for PFN lookup.
const HASH_BUCKETS: usize = 1024;

// -------------------------------------------------------------------
// PageLockEntry
// -------------------------------------------------------------------

/// Lock state for a single page.
#[derive(Debug, Clone, Copy)]
pub struct PageLockEntry {
    /// Page frame number.
    pfn: u64,
    /// Owner identifier (0 = unlocked).
    owner: u32,
    /// Whether the lock is held.
    locked: bool,
    /// Number of waiters.
    waiters: u32,
    /// Timestamp when locked.
    locked_at: u64,
    /// Whether this entry is in use.
    in_use: bool,
}

impl PageLockEntry {
    /// Create an empty entry.
    pub const fn empty() -> Self {
        Self {
            pfn: 0,
            owner: 0,
            locked: false,
            waiters: 0,
            locked_at: 0,
            in_use: false,
        }
    }

    /// Return the PFN.
    pub const fn pfn(&self) -> u64 {
        self.pfn
    }

    /// Return the owner ID.
    pub const fn owner(&self) -> u32 {
        self.owner
    }

    /// Check whether the page is locked.
    pub const fn is_locked(&self) -> bool {
        self.locked
    }

    /// Return the number of waiters.
    pub const fn waiters(&self) -> u32 {
        self.waiters
    }

    /// Check whether this entry is in use.
    pub const fn is_in_use(&self) -> bool {
        self.in_use
    }
}

impl Default for PageLockEntry {
    fn default() -> Self {
        Self::empty()
    }
}

// -------------------------------------------------------------------
// LockToken
// -------------------------------------------------------------------

/// Proof that a page lock is held. Must be passed to unlock.
#[derive(Debug, Clone, Copy)]
pub struct LockToken {
    /// PFN of the locked page.
    pfn: u64,
    /// Owner who holds the lock.
    owner: u32,
}

impl LockToken {
    /// Return the PFN.
    pub const fn pfn(&self) -> u64 {
        self.pfn
    }

    /// Return the owner.
    pub const fn owner(&self) -> u32 {
        self.owner
    }
}

// -------------------------------------------------------------------
// PageLockTable
// -------------------------------------------------------------------

/// Table of page locks.
pub struct PageLockTable {
    /// Lock entries.
    entries: [PageLockEntry; MAX_LOCKED_PAGES],
    /// Number of active entries.
    active: usize,
    /// Total lock acquisitions.
    total_locks: u64,
    /// Total lock contentions (trylock failures).
    total_contentions: u64,
    /// Current timestamp counter.
    timestamp: u64,
}

impl PageLockTable {
    /// Create a new empty lock table.
    pub const fn new() -> Self {
        Self {
            entries: [const { PageLockEntry::empty() }; MAX_LOCKED_PAGES],
            active: 0,
            total_locks: 0,
            total_contentions: 0,
            timestamp: 0,
        }
    }

    /// Return the number of currently held locks.
    pub const fn active_locks(&self) -> usize {
        self.active
    }

    /// Return total lock acquisitions.
    pub const fn total_locks(&self) -> u64 {
        self.total_locks
    }

    /// Return total contentions.
    pub const fn total_contentions(&self) -> u64 {
        self.total_contentions
    }

    /// Hash a PFN to a bucket index.
    fn hash(pfn: u64) -> usize {
        ((pfn ^ (pfn >> 12)) as usize) % HASH_BUCKETS
    }

    /// Find an entry for a PFN, or an empty slot.
    fn find_or_alloc(&mut self, pfn: u64) -> Option<usize> {
        // Search for existing entry.
        for idx in 0..self.active {
            if self.entries[idx].in_use && self.entries[idx].pfn == pfn {
                return Some(idx);
            }
        }
        // Allocate new.
        if self.active >= MAX_LOCKED_PAGES {
            return None;
        }
        let idx = self.active;
        self.entries[idx] = PageLockEntry {
            pfn,
            owner: 0,
            locked: false,
            waiters: 0,
            locked_at: 0,
            in_use: true,
        };
        self.active += 1;
        Some(idx)
    }

    /// Find an entry for a PFN.
    fn find(&self, pfn: u64) -> Option<usize> {
        for idx in 0..self.active {
            if self.entries[idx].in_use && self.entries[idx].pfn == pfn {
                return Some(idx);
            }
        }
        None
    }

    /// Try to acquire a lock on a page.
    pub fn trylock(&mut self, pfn: u64, owner: u32) -> Result<LockToken> {
        self.timestamp += 1;
        let idx = self.find_or_alloc(pfn).ok_or(Error::OutOfMemory)?;

        if self.entries[idx].locked {
            self.total_contentions += 1;
            self.entries[idx].waiters += 1;
            return Err(Error::WouldBlock);
        }

        self.entries[idx].locked = true;
        self.entries[idx].owner = owner;
        self.entries[idx].locked_at = self.timestamp;
        self.total_locks += 1;

        Ok(LockToken { pfn, owner })
    }

    /// Unlock a page using the token.
    pub fn unlock(&mut self, token: LockToken) -> Result<()> {
        let idx = self.find(token.pfn).ok_or(Error::NotFound)?;

        if !self.entries[idx].locked {
            return Err(Error::InvalidArgument);
        }
        if self.entries[idx].owner != token.owner {
            return Err(Error::PermissionDenied);
        }

        self.entries[idx].locked = false;
        self.entries[idx].owner = 0;
        if self.entries[idx].waiters > 0 {
            self.entries[idx].waiters -= 1;
        }

        Ok(())
    }

    /// Check whether a page is locked.
    pub fn is_locked(&self, pfn: u64) -> bool {
        self.find(pfn)
            .map(|idx| self.entries[idx].locked)
            .unwrap_or(false)
    }

    /// Return the lock entry for a PFN (if any).
    pub fn get_entry(&self, pfn: u64) -> Option<&PageLockEntry> {
        self.find(pfn).map(|idx| &self.entries[idx])
    }

    /// Force-unlock a page (for error recovery).
    pub fn force_unlock(&mut self, pfn: u64) -> Result<()> {
        let idx = self.find(pfn).ok_or(Error::NotFound)?;
        self.entries[idx].locked = false;
        self.entries[idx].owner = 0;
        Ok(())
    }
}

impl Default for PageLockTable {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// LockStats
// -------------------------------------------------------------------

/// Statistics about page locking.
#[derive(Debug, Clone, Copy)]
pub struct LockStats {
    /// Number of currently held locks.
    pub active: usize,
    /// Total acquisitions.
    pub total_locks: u64,
    /// Total contentions.
    pub contentions: u64,
    /// Contention rate (percent).
    pub contention_rate: u64,
}

// -------------------------------------------------------------------
// Public helpers
// -------------------------------------------------------------------

/// Get lock statistics from a table.
pub fn lock_stats(table: &PageLockTable) -> LockStats {
    let rate = if table.total_locks() > 0 {
        table.total_contentions() * 100 / table.total_locks()
    } else {
        0
    };
    LockStats {
        active: table.active_locks(),
        total_locks: table.total_locks(),
        contentions: table.total_contentions(),
        contention_rate: rate,
    }
}

/// Try to lock a page, returning a token on success.
pub fn try_lock_page(table: &mut PageLockTable, pfn: u64, owner: u32) -> Result<LockToken> {
    table.trylock(pfn, owner)
}

/// Unlock a page using its token.
pub fn unlock_page(table: &mut PageLockTable, token: LockToken) -> Result<()> {
    table.unlock(token)
}
