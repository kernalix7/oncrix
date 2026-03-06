// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Page reference freezing for safe page operations.
//!
//! Implements the page reference freeze/unfreeze mechanism used to
//! safely perform operations that require exclusive page access
//! (migration, splitting, compaction). A frozen page has its
//! reference count temporarily set to zero, preventing new
//! references from being taken.
//!
//! - [`FreezeState`] — page freeze lifecycle
//! - [`FrozenPage`] — a frozen page descriptor
//! - [`PageRefFreezeStats`] — freeze statistics
//! - [`PageRefFreeze`] — the freeze manager
//!
//! Reference: Linux `mm/internal.h` (folio_freeze_refs, folio_unfreeze_refs).

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Maximum frozen pages.
const MAX_FROZEN: usize = 256;

/// Freeze sentinel value (replaces refcount).
const FREEZE_SENTINEL: u32 = 0;

// -------------------------------------------------------------------
// FreezeState
// -------------------------------------------------------------------

/// Page freeze lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum FreezeState {
    /// Page is not frozen.
    #[default]
    Normal,
    /// Page is frozen (refcount saved, set to zero).
    Frozen,
    /// Page is being thawed (restoring refcount).
    Thawing,
}

// -------------------------------------------------------------------
// FrozenPage
// -------------------------------------------------------------------

/// A frozen page descriptor.
#[derive(Debug, Clone, Copy, Default)]
pub struct FrozenPage {
    /// Page frame number.
    pub pfn: u64,
    /// Saved reference count before freezing.
    pub saved_refcount: u32,
    /// Current freeze state.
    pub state: FreezeState,
    /// Reason for freezing.
    pub reason: FreezeReason,
    /// Timestamp when frozen (nanoseconds).
    pub frozen_ns: u64,
    /// Whether this entry is active.
    pub active: bool,
}

// -------------------------------------------------------------------
// FreezeReason
// -------------------------------------------------------------------

/// Reason for freezing a page.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum FreezeReason {
    /// Page migration.
    #[default]
    Migration,
    /// Transparent huge page split.
    ThpSplit,
    /// Compaction.
    Compaction,
    /// Page isolation.
    Isolation,
}

// -------------------------------------------------------------------
// PageRefFreezeStats
// -------------------------------------------------------------------

/// Page reference freeze statistics.
#[derive(Debug, Clone, Copy, Default)]
pub struct PageRefFreezeStats {
    /// Total freeze operations.
    pub freezes: u64,
    /// Total unfreeze operations.
    pub unfreezes: u64,
    /// Failed freeze attempts (refcount not stable).
    pub freeze_failures: u64,
    /// Pages frozen for migration.
    pub migration_freezes: u64,
    /// Pages frozen for THP split.
    pub thp_freezes: u64,
    /// Currently frozen pages.
    pub currently_frozen: u64,
}

impl PageRefFreezeStats {
    /// Resets all counters.
    pub fn reset(&mut self) {
        *self = Self::default();
    }
}

// -------------------------------------------------------------------
// PageRefFreeze
// -------------------------------------------------------------------

/// The page reference freeze manager.
pub struct PageRefFreeze {
    /// Frozen page entries.
    pages: [FrozenPage; MAX_FROZEN],
    /// Number of entries.
    count: usize,
    /// Statistics.
    stats: PageRefFreezeStats,
}

impl Default for PageRefFreeze {
    fn default() -> Self {
        Self {
            pages: [FrozenPage::default(); MAX_FROZEN],
            count: 0,
            stats: PageRefFreezeStats::default(),
        }
    }
}

impl PageRefFreeze {
    /// Creates a new freeze manager.
    pub fn new() -> Self {
        Self::default()
    }

    /// Freezes a page's reference count.
    pub fn freeze(
        &mut self,
        pfn: u64,
        current_refcount: u32,
        reason: FreezeReason,
        timestamp_ns: u64,
    ) -> Result<usize> {
        if current_refcount == FREEZE_SENTINEL {
            self.stats.freeze_failures += 1;
            return Err(Error::Busy);
        }
        if self.count >= MAX_FROZEN {
            return Err(Error::OutOfMemory);
        }

        // Check if already frozen.
        for i in 0..self.count {
            if self.pages[i].active
                && self.pages[i].pfn == pfn
                && self.pages[i].state == FreezeState::Frozen
            {
                self.stats.freeze_failures += 1;
                return Err(Error::Busy);
            }
        }

        let idx = self.count;
        self.pages[idx] = FrozenPage {
            pfn,
            saved_refcount: current_refcount,
            state: FreezeState::Frozen,
            reason,
            frozen_ns: timestamp_ns,
            active: true,
        };
        self.count += 1;

        self.stats.freezes += 1;
        self.stats.currently_frozen += 1;
        match reason {
            FreezeReason::Migration => self.stats.migration_freezes += 1,
            FreezeReason::ThpSplit => self.stats.thp_freezes += 1,
            _ => {}
        }
        Ok(idx)
    }

    /// Unfreezes a page, restoring its reference count.
    pub fn unfreeze(&mut self, pfn: u64) -> Result<u32> {
        for i in 0..self.count {
            if self.pages[i].active
                && self.pages[i].pfn == pfn
                && self.pages[i].state == FreezeState::Frozen
            {
                let saved = self.pages[i].saved_refcount;
                self.pages[i].state = FreezeState::Normal;
                self.pages[i].active = false;
                self.stats.unfreezes += 1;
                if self.stats.currently_frozen > 0 {
                    self.stats.currently_frozen -= 1;
                }
                return Ok(saved);
            }
        }
        Err(Error::NotFound)
    }

    /// Checks if a page is frozen.
    pub fn is_frozen(&self, pfn: u64) -> bool {
        for i in 0..self.count {
            if self.pages[i].active
                && self.pages[i].pfn == pfn
                && self.pages[i].state == FreezeState::Frozen
            {
                return true;
            }
        }
        false
    }

    /// Returns the saved refcount for a frozen page.
    pub fn saved_refcount(&self, pfn: u64) -> Option<u32> {
        for i in 0..self.count {
            if self.pages[i].active
                && self.pages[i].pfn == pfn
                && self.pages[i].state == FreezeState::Frozen
            {
                return Some(self.pages[i].saved_refcount);
            }
        }
        None
    }

    /// Returns the number of currently frozen pages.
    pub fn frozen_count(&self) -> usize {
        self.pages[..self.count]
            .iter()
            .filter(|p| p.active && p.state == FreezeState::Frozen)
            .count()
    }

    /// Returns statistics.
    pub fn stats(&self) -> &PageRefFreezeStats {
        &self.stats
    }

    /// Resets statistics.
    pub fn reset_stats(&mut self) {
        self.stats.reset();
    }
}
