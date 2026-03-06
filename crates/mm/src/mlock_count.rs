// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Mlock accounting and limit enforcement.
//!
//! Each process has a limit on the number of pages it may lock into
//! physical memory via `mlock(2)` / `mlockall(2)`. This module tracks
//! per-process locked-page counts, enforces `RLIMIT_MEMLOCK`, and
//! provides the accounting needed for `munlock(2)` to correctly
//! decrement counts.
//!
//! # Design
//!
//! ```text
//!  mlock(addr, len)
//!     │
//!     ├─ compute page count
//!     ├─ check process lock count + pages ≤ RLIMIT_MEMLOCK
//!     ├─ fault in pages, set VM_LOCKED on VMA
//!     └─ update lock count
//!
//!  munlock(addr, len)
//!     │
//!     ├─ clear VM_LOCKED on VMA
//!     └─ decrement lock count
//! ```
//!
//! # Key Types
//!
//! - [`MlockAccount`] — per-process mlock accounting
//! - [`MlockAccountTable`] — tracks accounts for all processes
//! - [`MlockAccountStats`] — global mlock statistics
//!
//! Reference: Linux `mm/mlock.c`, POSIX `mlock(2)`.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Maximum tracked processes.
const MAX_PROCESSES: usize = 1024;

/// Default RLIMIT_MEMLOCK in pages (64 KiB = 16 pages).
const DEFAULT_LIMIT_PAGES: u64 = 16;

/// Page size.
const PAGE_SIZE: u64 = 4096;

/// Unlimited mlock sentinel value.
const UNLIMITED: u64 = u64::MAX;

// -------------------------------------------------------------------
// MlockAccount
// -------------------------------------------------------------------

/// Per-process mlock accounting.
#[derive(Debug, Clone, Copy)]
pub struct MlockAccount {
    /// Process ID.
    pid: u64,
    /// Current locked pages.
    locked_pages: u64,
    /// Maximum locked pages (RLIMIT_MEMLOCK / PAGE_SIZE).
    limit_pages: u64,
    /// Total mlock calls.
    lock_calls: u64,
    /// Total munlock calls.
    unlock_calls: u64,
    /// Denied lock attempts (over limit).
    denied: u64,
    /// Whether mlockall is active.
    mlockall_active: bool,
}

impl MlockAccount {
    /// Create a new mlock account.
    pub const fn new(pid: u64, limit_pages: u64) -> Self {
        Self {
            pid,
            locked_pages: 0,
            limit_pages,
            lock_calls: 0,
            unlock_calls: 0,
            denied: 0,
            mlockall_active: false,
        }
    }

    /// Return the PID.
    pub const fn pid(&self) -> u64 {
        self.pid
    }

    /// Return the current locked page count.
    pub const fn locked_pages(&self) -> u64 {
        self.locked_pages
    }

    /// Return the limit in pages.
    pub const fn limit_pages(&self) -> u64 {
        self.limit_pages
    }

    /// Return the locked bytes.
    pub const fn locked_bytes(&self) -> u64 {
        self.locked_pages * PAGE_SIZE
    }

    /// Return the limit in bytes.
    pub const fn limit_bytes(&self) -> u64 {
        if self.limit_pages == UNLIMITED {
            return UNLIMITED;
        }
        self.limit_pages * PAGE_SIZE
    }

    /// Return the lock call count.
    pub const fn lock_calls(&self) -> u64 {
        self.lock_calls
    }

    /// Return the unlock call count.
    pub const fn unlock_calls(&self) -> u64 {
        self.unlock_calls
    }

    /// Return the denied count.
    pub const fn denied(&self) -> u64 {
        self.denied
    }

    /// Check whether mlockall is active.
    pub const fn mlockall_active(&self) -> bool {
        self.mlockall_active
    }

    /// Check whether locking additional pages is allowed.
    pub const fn can_lock(&self, pages: u64) -> bool {
        if self.limit_pages == UNLIMITED {
            return true;
        }
        self.locked_pages + pages <= self.limit_pages
    }

    /// Lock pages (checked).
    pub fn lock_pages(&mut self, pages: u64) -> Result<()> {
        if !self.can_lock(pages) {
            self.denied += 1;
            return Err(Error::PermissionDenied);
        }
        self.locked_pages += pages;
        self.lock_calls += 1;
        Ok(())
    }

    /// Unlock pages.
    pub fn unlock_pages(&mut self, pages: u64) -> Result<()> {
        if pages > self.locked_pages {
            return Err(Error::InvalidArgument);
        }
        self.locked_pages -= pages;
        self.unlock_calls += 1;
        Ok(())
    }

    /// Set the limit.
    pub fn set_limit(&mut self, limit_pages: u64) {
        self.limit_pages = limit_pages;
    }

    /// Activate mlockall.
    pub fn activate_mlockall(&mut self) {
        self.mlockall_active = true;
    }

    /// Deactivate mlockall.
    pub fn deactivate_mlockall(&mut self) {
        self.mlockall_active = false;
    }

    /// Utilization as percent of limit.
    pub const fn utilization_pct(&self) -> u64 {
        if self.limit_pages == 0 || self.limit_pages == UNLIMITED {
            return 0;
        }
        self.locked_pages * 100 / self.limit_pages
    }
}

impl Default for MlockAccount {
    fn default() -> Self {
        Self {
            pid: 0,
            locked_pages: 0,
            limit_pages: DEFAULT_LIMIT_PAGES,
            lock_calls: 0,
            unlock_calls: 0,
            denied: 0,
            mlockall_active: false,
        }
    }
}

// -------------------------------------------------------------------
// MlockAccountStats
// -------------------------------------------------------------------

/// Global mlock statistics.
#[derive(Debug, Clone, Copy)]
pub struct MlockAccountStats {
    /// Total lock calls across all processes.
    pub total_locks: u64,
    /// Total unlock calls.
    pub total_unlocks: u64,
    /// Total denied attempts.
    pub total_denied: u64,
    /// Total locked pages system-wide.
    pub total_locked_pages: u64,
}

impl MlockAccountStats {
    /// Create zero stats.
    pub const fn new() -> Self {
        Self {
            total_locks: 0,
            total_unlocks: 0,
            total_denied: 0,
            total_locked_pages: 0,
        }
    }
}

impl Default for MlockAccountStats {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// MlockAccountTable
// -------------------------------------------------------------------

/// Tracks mlock accounts for all processes.
pub struct MlockAccountTable {
    /// Per-process accounts.
    accounts: [MlockAccount; MAX_PROCESSES],
    /// Number of accounts.
    count: usize,
    /// Statistics.
    stats: MlockAccountStats,
}

impl MlockAccountTable {
    /// Create a new table.
    pub const fn new() -> Self {
        Self {
            accounts: [const {
                MlockAccount {
                    pid: 0,
                    locked_pages: 0,
                    limit_pages: DEFAULT_LIMIT_PAGES,
                    lock_calls: 0,
                    unlock_calls: 0,
                    denied: 0,
                    mlockall_active: false,
                }
            }; MAX_PROCESSES],
            count: 0,
            stats: MlockAccountStats::new(),
        }
    }

    /// Return the statistics.
    pub const fn stats(&self) -> &MlockAccountStats {
        &self.stats
    }

    /// Return the number of tracked processes.
    pub const fn count(&self) -> usize {
        self.count
    }

    /// Register a process.
    pub fn register(&mut self, pid: u64, limit_pages: u64) -> Result<()> {
        if self.count >= MAX_PROCESSES {
            return Err(Error::OutOfMemory);
        }
        self.accounts[self.count] = MlockAccount::new(pid, limit_pages);
        self.count += 1;
        Ok(())
    }

    /// Lock pages for a process.
    pub fn lock_pages(&mut self, pid: u64, pages: u64) -> Result<()> {
        for idx in 0..self.count {
            if self.accounts[idx].pid() == pid {
                self.accounts[idx].lock_pages(pages)?;
                self.stats.total_locks += 1;
                self.stats.total_locked_pages += pages;
                return Ok(());
            }
        }
        Err(Error::NotFound)
    }

    /// Unlock pages for a process.
    pub fn unlock_pages(&mut self, pid: u64, pages: u64) -> Result<()> {
        for idx in 0..self.count {
            if self.accounts[idx].pid() == pid {
                self.accounts[idx].unlock_pages(pages)?;
                self.stats.total_unlocks += 1;
                self.stats.total_locked_pages = self.stats.total_locked_pages.saturating_sub(pages);
                return Ok(());
            }
        }
        Err(Error::NotFound)
    }

    /// Find an account by PID.
    pub fn find(&self, pid: u64) -> Option<&MlockAccount> {
        for idx in 0..self.count {
            if self.accounts[idx].pid() == pid {
                return Some(&self.accounts[idx]);
            }
        }
        None
    }

    /// Total locked pages across all processes.
    pub fn total_locked_pages(&self) -> u64 {
        let mut total: u64 = 0;
        for idx in 0..self.count {
            total += self.accounts[idx].locked_pages();
        }
        total
    }
}

impl Default for MlockAccountTable {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// Public helpers
// -------------------------------------------------------------------

/// Return the default mlock limit in pages.
pub const fn default_limit_pages() -> u64 {
    DEFAULT_LIMIT_PAGES
}

/// Return the default mlock limit in bytes.
pub const fn default_limit_bytes() -> u64 {
    DEFAULT_LIMIT_PAGES * PAGE_SIZE
}

/// Compute pages needed for a byte range.
pub const fn pages_for_bytes(bytes: u64) -> u64 {
    (bytes + PAGE_SIZE - 1) / PAGE_SIZE
}
