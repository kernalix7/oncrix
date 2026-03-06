// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Hardware memory poisoning subsystem.
//!
//! When a hardware memory error (ECC uncorrectable) is detected, the
//! affected page must be isolated and processes mapped to it notified.
//! This module tracks poisoned pages, handles recovery actions, and
//! provides the `hwpoison` interface for memory error handling.
//!
//! # Design
//!
//! ```text
//!  MCE / CMCI interrupt
//!     │
//!     ├─ look up PFN of bad page
//!     ├─ mark page HWPoison in page flags
//!     ├─ unmap from all address spaces (via rmap)
//!     ├─ send SIGBUS to affected processes
//!     └─ add to poison list for offline tracking
//! ```
//!
//! # Key Types
//!
//! - [`PoisonAction`] — action to take on a poisoned page
//! - [`PoisonedPage`] — record of a single poisoned page
//! - [`HwPoisonTable`] — tracks all poisoned pages
//! - [`HwPoisonStats`] — poisoning statistics
//!
//! Reference: Linux `mm/memory-failure.c`, `include/linux/mm.h`.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Maximum tracked poisoned pages.
const MAX_POISONED_PAGES: usize = 4096;

/// Page size in bytes.
const PAGE_SIZE: u64 = 4096;

/// Soft-offline threshold before hard-offline.
const SOFT_OFFLINE_THRESHOLD: u32 = 3;

/// Maximum processes per affected page for notification.
const MAX_AFFECTED_PROCS: usize = 64;

// -------------------------------------------------------------------
// PoisonAction
// -------------------------------------------------------------------

/// Action to take on a poisoned page.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PoisonAction {
    /// Soft offline: migrate data and mark page as reserved.
    SoftOffline,
    /// Hard offline: page is unusable, send SIGBUS.
    HardOffline,
    /// Unpoison: page recovered, can be reused.
    Unpoison,
    /// Ignore: page already handled or not in use.
    Ignore,
}

impl PoisonAction {
    /// Return a label string.
    pub const fn label(&self) -> &'static str {
        match self {
            Self::SoftOffline => "soft-offline",
            Self::HardOffline => "hard-offline",
            Self::Unpoison => "unpoison",
            Self::Ignore => "ignore",
        }
    }

    /// Check whether the page will be permanently removed.
    pub const fn is_permanent(&self) -> bool {
        matches!(self, Self::HardOffline)
    }
}

// -------------------------------------------------------------------
// PoisonedPage
// -------------------------------------------------------------------

/// Record of a single poisoned page.
#[derive(Debug, Clone, Copy)]
pub struct PoisonedPage {
    /// Physical frame number.
    pfn: u64,
    /// Physical address (pfn * PAGE_SIZE).
    phys_addr: u64,
    /// Action taken.
    action: PoisonAction,
    /// Number of soft-offline attempts before this.
    soft_offline_count: u32,
    /// Number of processes that were mapping this page.
    affected_processes: u32,
    /// Timestamp (tick count) when poisoned.
    timestamp: u64,
    /// Whether the page was in page cache.
    in_page_cache: bool,
    /// Whether the page was anonymous.
    anonymous: bool,
    /// Whether recovery was attempted.
    recovery_attempted: bool,
    /// Whether recovery succeeded.
    recovery_ok: bool,
}

impl PoisonedPage {
    /// Create a new poisoned page record.
    pub const fn new(pfn: u64, action: PoisonAction, timestamp: u64) -> Self {
        Self {
            pfn,
            phys_addr: pfn * PAGE_SIZE,
            action,
            soft_offline_count: 0,
            affected_processes: 0,
            timestamp,
            in_page_cache: false,
            anonymous: false,
            recovery_attempted: false,
            recovery_ok: false,
        }
    }

    /// Return the PFN.
    pub const fn pfn(&self) -> u64 {
        self.pfn
    }

    /// Return the physical address.
    pub const fn phys_addr(&self) -> u64 {
        self.phys_addr
    }

    /// Return the action taken.
    pub const fn action(&self) -> PoisonAction {
        self.action
    }

    /// Return the soft-offline count.
    pub const fn soft_offline_count(&self) -> u32 {
        self.soft_offline_count
    }

    /// Return the number of affected processes.
    pub const fn affected_processes(&self) -> u32 {
        self.affected_processes
    }

    /// Return the timestamp.
    pub const fn timestamp(&self) -> u64 {
        self.timestamp
    }

    /// Check whether the page was in page cache.
    pub const fn in_page_cache(&self) -> bool {
        self.in_page_cache
    }

    /// Check whether the page was anonymous.
    pub const fn anonymous(&self) -> bool {
        self.anonymous
    }

    /// Check whether recovery was attempted.
    pub const fn recovery_attempted(&self) -> bool {
        self.recovery_attempted
    }

    /// Check whether recovery succeeded.
    pub const fn recovery_ok(&self) -> bool {
        self.recovery_ok
    }

    /// Set page cache flag.
    pub fn set_in_page_cache(&mut self, val: bool) {
        self.in_page_cache = val;
    }

    /// Set anonymous flag.
    pub fn set_anonymous(&mut self, val: bool) {
        self.anonymous = val;
    }

    /// Set affected process count.
    pub fn set_affected_processes(&mut self, count: u32) {
        self.affected_processes = count;
    }

    /// Record a soft-offline attempt.
    pub fn record_soft_offline(&mut self) {
        self.soft_offline_count = self.soft_offline_count.saturating_add(1);
    }

    /// Record recovery result.
    pub fn record_recovery(&mut self, success: bool) {
        self.recovery_attempted = true;
        self.recovery_ok = success;
    }

    /// Check whether this page should be hard-offlined.
    pub const fn should_hard_offline(&self) -> bool {
        self.soft_offline_count >= SOFT_OFFLINE_THRESHOLD
    }
}

impl Default for PoisonedPage {
    fn default() -> Self {
        Self {
            pfn: 0,
            phys_addr: 0,
            action: PoisonAction::Ignore,
            soft_offline_count: 0,
            affected_processes: 0,
            timestamp: 0,
            in_page_cache: false,
            anonymous: false,
            recovery_attempted: false,
            recovery_ok: false,
        }
    }
}

// -------------------------------------------------------------------
// HwPoisonStats
// -------------------------------------------------------------------

/// Hardware poison statistics.
#[derive(Debug, Clone, Copy)]
pub struct HwPoisonStats {
    /// Total poison events.
    pub total_events: u64,
    /// Soft-offline events.
    pub soft_offlines: u64,
    /// Hard-offline events.
    pub hard_offlines: u64,
    /// Unpoison events.
    pub unpoisons: u64,
    /// Failed recoveries.
    pub failed_recoveries: u64,
    /// Successful recoveries.
    pub successful_recoveries: u64,
    /// Total affected processes.
    pub affected_processes: u64,
}

impl HwPoisonStats {
    /// Create zero stats.
    pub const fn new() -> Self {
        Self {
            total_events: 0,
            soft_offlines: 0,
            hard_offlines: 0,
            unpoisons: 0,
            failed_recoveries: 0,
            successful_recoveries: 0,
            affected_processes: 0,
        }
    }

    /// Total offline events.
    pub const fn total_offlines(&self) -> u64 {
        self.soft_offlines + self.hard_offlines
    }

    /// Recovery success rate as percent.
    pub const fn recovery_rate_pct(&self) -> u64 {
        let total = self.successful_recoveries + self.failed_recoveries;
        if total == 0 {
            return 0;
        }
        self.successful_recoveries * 100 / total
    }
}

impl Default for HwPoisonStats {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// HwPoisonTable
// -------------------------------------------------------------------

/// Tracks all poisoned pages in the system.
pub struct HwPoisonTable {
    /// Poisoned page records.
    pages: [PoisonedPage; MAX_POISONED_PAGES],
    /// Number of entries.
    count: usize,
    /// Statistics.
    stats: HwPoisonStats,
}

impl HwPoisonTable {
    /// Create a new empty table.
    pub const fn new() -> Self {
        Self {
            pages: [const {
                PoisonedPage {
                    pfn: 0,
                    phys_addr: 0,
                    action: PoisonAction::Ignore,
                    soft_offline_count: 0,
                    affected_processes: 0,
                    timestamp: 0,
                    in_page_cache: false,
                    anonymous: false,
                    recovery_attempted: false,
                    recovery_ok: false,
                }
            }; MAX_POISONED_PAGES],
            count: 0,
            stats: HwPoisonStats::new(),
        }
    }

    /// Return the statistics.
    pub const fn stats(&self) -> &HwPoisonStats {
        &self.stats
    }

    /// Return the number of tracked poisoned pages.
    pub const fn count(&self) -> usize {
        self.count
    }

    /// Check whether a PFN is poisoned.
    pub fn is_poisoned(&self, pfn: u64) -> bool {
        for idx in 0..self.count {
            if self.pages[idx].pfn() == pfn {
                return !matches!(self.pages[idx].action(), PoisonAction::Unpoison);
            }
        }
        false
    }

    /// Look up a poisoned page by PFN.
    pub fn find(&self, pfn: u64) -> Option<&PoisonedPage> {
        for idx in 0..self.count {
            if self.pages[idx].pfn() == pfn {
                return Some(&self.pages[idx]);
            }
        }
        None
    }

    /// Record a soft-offline event.
    pub fn soft_offline(&mut self, pfn: u64, timestamp: u64) -> Result<PoisonAction> {
        // Check for existing entry.
        for idx in 0..self.count {
            if self.pages[idx].pfn() == pfn {
                self.pages[idx].record_soft_offline();
                if self.pages[idx].should_hard_offline() {
                    self.pages[idx].action = PoisonAction::HardOffline;
                    self.stats.hard_offlines += 1;
                    return Ok(PoisonAction::HardOffline);
                }
                self.stats.soft_offlines += 1;
                return Ok(PoisonAction::SoftOffline);
            }
        }

        // New entry.
        if self.count >= MAX_POISONED_PAGES {
            return Err(Error::OutOfMemory);
        }
        self.pages[self.count] = PoisonedPage::new(pfn, PoisonAction::SoftOffline, timestamp);
        self.pages[self.count].record_soft_offline();
        self.count += 1;
        self.stats.total_events += 1;
        self.stats.soft_offlines += 1;
        Ok(PoisonAction::SoftOffline)
    }

    /// Record a hard-offline event.
    pub fn hard_offline(&mut self, pfn: u64, timestamp: u64) -> Result<()> {
        // Update existing or create new.
        for idx in 0..self.count {
            if self.pages[idx].pfn() == pfn {
                self.pages[idx].action = PoisonAction::HardOffline;
                self.stats.hard_offlines += 1;
                self.stats.total_events += 1;
                return Ok(());
            }
        }

        if self.count >= MAX_POISONED_PAGES {
            return Err(Error::OutOfMemory);
        }
        self.pages[self.count] = PoisonedPage::new(pfn, PoisonAction::HardOffline, timestamp);
        self.count += 1;
        self.stats.total_events += 1;
        self.stats.hard_offlines += 1;
        Ok(())
    }

    /// Unpoison a page (recovery succeeded).
    pub fn unpoison(&mut self, pfn: u64) -> Result<()> {
        for idx in 0..self.count {
            if self.pages[idx].pfn() == pfn {
                self.pages[idx].action = PoisonAction::Unpoison;
                self.pages[idx].record_recovery(true);
                self.stats.unpoisons += 1;
                self.stats.successful_recoveries += 1;
                return Ok(());
            }
        }
        Err(Error::NotFound)
    }

    /// Record affected processes for a PFN.
    pub fn set_affected_processes(&mut self, pfn: u64, count: u32) -> Result<()> {
        for idx in 0..self.count {
            if self.pages[idx].pfn() == pfn {
                self.pages[idx].set_affected_processes(count);
                self.stats.affected_processes += count as u64;
                return Ok(());
            }
        }
        Err(Error::NotFound)
    }

    /// Count hard-offlined pages.
    pub fn hard_offline_count(&self) -> usize {
        let mut n = 0;
        for idx in 0..self.count {
            if matches!(self.pages[idx].action(), PoisonAction::HardOffline) {
                n += 1;
            }
        }
        n
    }

    /// Total memory lost to hard-offline (in bytes).
    pub fn memory_lost_bytes(&self) -> u64 {
        self.hard_offline_count() as u64 * PAGE_SIZE
    }
}

impl Default for HwPoisonTable {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// Public helpers
// -------------------------------------------------------------------

/// Check whether a physical address is in a poisoned page.
pub fn addr_is_poisoned(table: &HwPoisonTable, phys_addr: u64) -> bool {
    let pfn = phys_addr / PAGE_SIZE;
    table.is_poisoned(pfn)
}

/// Return the maximum affected processes per page.
pub const fn max_affected_processes() -> usize {
    MAX_AFFECTED_PROCS
}

/// Return the soft-offline threshold.
pub const fn soft_offline_threshold() -> u32 {
    SOFT_OFFLINE_THRESHOLD
}

/// Return the maximum number of tracked poisoned pages.
pub const fn max_poisoned_pages() -> usize {
    MAX_POISONED_PAGES
}
