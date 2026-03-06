// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Swap migration entry management.
//!
//! During page migration the kernel temporarily replaces PTE entries
//! with "migration entries" — special swap-like entries that encode
//! the migration target rather than a swap slot. When a fault occurs
//! on a migration entry the faulting thread blocks until migration
//! completes, then the real PTE is installed. This module manages
//! migration entries and the wait mechanism.
//!
//! # Design
//!
//! ```text
//!  migrate_page(old_pfn, new_pfn)
//!       │
//!       ├─ for each PTE pointing to old_pfn:
//!       │   └─ replace PTE with migration entry(new_pfn)
//!       │
//!       ├─ copy page contents: old_pfn → new_pfn
//!       │
//!       └─ for each migration entry:
//!           └─ install real PTE pointing to new_pfn
//!           └─ wake any threads blocked on the entry
//! ```
//!
//! # Key Types
//!
//! - [`MigrationEntry`] — a single migration swap entry
//! - [`MigrationEntryTable`] — tracks active migration entries
//! - [`MigrationWaiter`] — a thread waiting on migration
//! - [`MigrationStats`] — migration entry statistics
//!
//! Reference: Linux `mm/migrate.c`, `include/linux/swapops.h`.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Maximum active migration entries.
const MAX_ENTRIES: usize = 512;

/// Maximum waiters per entry.
const MAX_WAITERS: usize = 8;

/// Migration entry type marker (in the swap entry encoding).
const MIGRATION_TYPE: u64 = 0xDEAD_0000_0000_0000;

/// Write migration entry marker.
const MIGRATION_WRITE: u64 = 1 << 0;

// -------------------------------------------------------------------
// MigrationDirection
// -------------------------------------------------------------------

/// Direction of page migration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MigrationDirection {
    /// Read-only migration entry.
    Read,
    /// Writable migration entry (CoW source was writable).
    Write,
}

impl MigrationDirection {
    /// Return a label.
    pub const fn label(&self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Write => "write",
        }
    }
}

// -------------------------------------------------------------------
// MigrationState
// -------------------------------------------------------------------

/// State of a migration entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MigrationState {
    /// PTE replaced with migration entry, copy in progress.
    InProgress,
    /// Copy complete, real PTE being installed.
    Installing,
    /// Migration complete, entry removed.
    Complete,
    /// Migration aborted (revert to original PTE).
    Aborted,
}

impl MigrationState {
    /// Return a label.
    pub const fn label(&self) -> &'static str {
        match self {
            Self::InProgress => "in_progress",
            Self::Installing => "installing",
            Self::Complete => "complete",
            Self::Aborted => "aborted",
        }
    }

    /// Check whether migration is done.
    pub const fn is_done(&self) -> bool {
        matches!(self, Self::Complete | Self::Aborted)
    }
}

// -------------------------------------------------------------------
// MigrationWaiter
// -------------------------------------------------------------------

/// A thread waiting on a migration entry.
#[derive(Debug, Clone, Copy)]
pub struct MigrationWaiter {
    /// Thread identifier.
    thread_id: u64,
    /// Whether this waiter has been woken.
    woken: bool,
    /// Whether this entry is valid.
    valid: bool,
}

impl MigrationWaiter {
    /// Create a new waiter.
    pub const fn new(thread_id: u64) -> Self {
        Self {
            thread_id,
            woken: false,
            valid: true,
        }
    }

    /// Return the thread ID.
    pub const fn thread_id(&self) -> u64 {
        self.thread_id
    }

    /// Check whether the waiter has been woken.
    pub const fn is_woken(&self) -> bool {
        self.woken
    }

    /// Wake this waiter.
    pub fn wake(&mut self) {
        self.woken = true;
        self.valid = false;
    }
}

impl Default for MigrationWaiter {
    fn default() -> Self {
        Self {
            thread_id: 0,
            woken: false,
            valid: false,
        }
    }
}

// -------------------------------------------------------------------
// MigrationEntry
// -------------------------------------------------------------------

/// A single migration swap entry.
pub struct MigrationEntry {
    /// Old PFN (source page).
    old_pfn: u64,
    /// New PFN (destination page).
    new_pfn: u64,
    /// Virtual address where the migration entry is installed.
    vaddr: u64,
    /// Process ID owning the mapping.
    pid: u64,
    /// Migration direction.
    direction: MigrationDirection,
    /// Current state.
    state: MigrationState,
    /// Threads waiting on this entry.
    waiters: [MigrationWaiter; MAX_WAITERS],
    /// Number of valid waiters.
    waiter_count: usize,
}

impl MigrationEntry {
    /// Create a new migration entry.
    pub const fn new(
        old_pfn: u64,
        new_pfn: u64,
        vaddr: u64,
        pid: u64,
        direction: MigrationDirection,
    ) -> Self {
        Self {
            old_pfn,
            new_pfn,
            vaddr,
            pid,
            direction,
            state: MigrationState::InProgress,
            waiters: [const {
                MigrationWaiter {
                    thread_id: 0,
                    woken: false,
                    valid: false,
                }
            }; MAX_WAITERS],
            waiter_count: 0,
        }
    }

    /// Return the old PFN.
    pub const fn old_pfn(&self) -> u64 {
        self.old_pfn
    }

    /// Return the new PFN.
    pub const fn new_pfn(&self) -> u64 {
        self.new_pfn
    }

    /// Return the virtual address.
    pub const fn vaddr(&self) -> u64 {
        self.vaddr
    }

    /// Return the process ID.
    pub const fn pid(&self) -> u64 {
        self.pid
    }

    /// Return the direction.
    pub const fn direction(&self) -> MigrationDirection {
        self.direction
    }

    /// Return the current state.
    pub const fn state(&self) -> MigrationState {
        self.state
    }

    /// Return the number of waiters.
    pub const fn waiter_count(&self) -> usize {
        self.waiter_count
    }

    /// Encode as a swap entry value.
    pub const fn encode(&self) -> u64 {
        let dir_bit = match self.direction {
            MigrationDirection::Write => MIGRATION_WRITE,
            MigrationDirection::Read => 0,
        };
        MIGRATION_TYPE | self.new_pfn | dir_bit
    }

    /// Transition to installing state.
    pub fn set_installing(&mut self) {
        self.state = MigrationState::Installing;
    }

    /// Complete the migration, wake all waiters.
    pub fn complete(&mut self) -> usize {
        self.state = MigrationState::Complete;
        let mut woken = 0;
        for idx in 0..MAX_WAITERS {
            if self.waiters[idx].valid {
                self.waiters[idx].wake();
                woken += 1;
            }
        }
        self.waiter_count = 0;
        woken
    }

    /// Abort the migration, wake all waiters.
    pub fn abort(&mut self) -> usize {
        self.state = MigrationState::Aborted;
        let mut woken = 0;
        for idx in 0..MAX_WAITERS {
            if self.waiters[idx].valid {
                self.waiters[idx].wake();
                woken += 1;
            }
        }
        self.waiter_count = 0;
        woken
    }

    /// Add a waiter.
    pub fn add_waiter(&mut self, thread_id: u64) -> Result<()> {
        if self.waiter_count >= MAX_WAITERS {
            return Err(Error::OutOfMemory);
        }
        for idx in 0..MAX_WAITERS {
            if !self.waiters[idx].valid {
                self.waiters[idx] = MigrationWaiter::new(thread_id);
                self.waiter_count += 1;
                return Ok(());
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Check whether the migration is done.
    pub const fn is_done(&self) -> bool {
        self.state.is_done()
    }
}

impl Default for MigrationEntry {
    fn default() -> Self {
        Self {
            old_pfn: 0,
            new_pfn: 0,
            vaddr: 0,
            pid: 0,
            direction: MigrationDirection::Read,
            state: MigrationState::Complete,
            waiters: [const {
                MigrationWaiter {
                    thread_id: 0,
                    woken: false,
                    valid: false,
                }
            }; MAX_WAITERS],
            waiter_count: 0,
        }
    }
}

// -------------------------------------------------------------------
// MigrationStats
// -------------------------------------------------------------------

/// Migration entry statistics.
#[derive(Debug, Clone, Copy)]
pub struct MigrationStats {
    /// Total migration entries created.
    pub created: u64,
    /// Migrations completed.
    pub completed: u64,
    /// Migrations aborted.
    pub aborted: u64,
    /// Total waiters that were woken.
    pub waiters_woken: u64,
    /// Currently active entries.
    pub active: u64,
}

impl MigrationStats {
    /// Create zero stats.
    pub const fn new() -> Self {
        Self {
            created: 0,
            completed: 0,
            aborted: 0,
            waiters_woken: 0,
            active: 0,
        }
    }

    /// Success rate as percent.
    pub const fn success_rate(&self) -> u64 {
        let total = self.completed + self.aborted;
        if total == 0 {
            return 100;
        }
        self.completed * 100 / total
    }
}

impl Default for MigrationStats {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// MigrationEntryTable
// -------------------------------------------------------------------

/// Tracks all active migration entries.
pub struct MigrationEntryTable {
    /// Active entries.
    entries: [MigrationEntry; MAX_ENTRIES],
    /// Number of entries.
    count: usize,
    /// Statistics.
    stats: MigrationStats,
}

impl MigrationEntryTable {
    /// Create a new table.
    pub fn new() -> Self {
        Self {
            entries: core::array::from_fn(|_| MigrationEntry::default()),
            count: 0,
            stats: MigrationStats::new(),
        }
    }

    /// Return the count.
    pub const fn count(&self) -> usize {
        self.count
    }

    /// Return the statistics.
    pub const fn stats(&self) -> &MigrationStats {
        &self.stats
    }

    /// Create a migration entry.
    pub fn create(
        &mut self,
        old_pfn: u64,
        new_pfn: u64,
        vaddr: u64,
        pid: u64,
        direction: MigrationDirection,
    ) -> Result<usize> {
        if self.count >= MAX_ENTRIES {
            return Err(Error::OutOfMemory);
        }
        let idx = self.count;
        self.entries[idx] = MigrationEntry::new(old_pfn, new_pfn, vaddr, pid, direction);
        self.count += 1;
        self.stats.created += 1;
        self.stats.active += 1;
        Ok(idx)
    }

    /// Complete a migration entry by index.
    pub fn complete(&mut self, index: usize) -> Result<usize> {
        if index >= self.count {
            return Err(Error::InvalidArgument);
        }
        let woken = self.entries[index].complete();
        self.stats.completed += 1;
        self.stats.active = self.stats.active.saturating_sub(1);
        self.stats.waiters_woken += woken as u64;
        Ok(woken)
    }

    /// Abort a migration entry by index.
    pub fn abort(&mut self, index: usize) -> Result<usize> {
        if index >= self.count {
            return Err(Error::InvalidArgument);
        }
        let woken = self.entries[index].abort();
        self.stats.aborted += 1;
        self.stats.active = self.stats.active.saturating_sub(1);
        self.stats.waiters_woken += woken as u64;
        Ok(woken)
    }

    /// Get an entry by index.
    pub fn get(&self, index: usize) -> Result<&MigrationEntry> {
        if index >= self.count {
            return Err(Error::InvalidArgument);
        }
        Ok(&self.entries[index])
    }
}

impl Default for MigrationEntryTable {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// Public helpers
// -------------------------------------------------------------------

/// Check whether a swap entry value is a migration entry.
pub const fn is_migration_entry(entry: u64) -> bool {
    entry & MIGRATION_TYPE == MIGRATION_TYPE
}

/// Check whether a migration entry is writable.
pub const fn is_write_migration(entry: u64) -> bool {
    entry & MIGRATION_WRITE != 0
}

/// Extract the target PFN from a migration entry encoding.
pub const fn migration_entry_pfn(entry: u64) -> u64 {
    entry & !(MIGRATION_TYPE | MIGRATION_WRITE)
}
