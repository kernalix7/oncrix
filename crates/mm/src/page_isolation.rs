// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Page isolation for migration and compaction.
//!
//! Implements the page isolation mechanism that removes pages from
//! the LRU lists so they can be migrated (moved) to a different
//! physical location. This is the first step in both compaction and
//! NUMA balancing page migration.
//!
//! - [`IsolateMode`] — flags controlling which pages to isolate
//! - [`IsolateResult`] — outcome of an isolation attempt
//! - [`IsolatedPage`] — metadata for an isolated page
//! - [`IsolationList`] — list of isolated pages pending migration
//! - [`PageIsolation`] — the main isolation engine
//! - [`IsolationStats`] — aggregate statistics
//!
//! Reference: `.kernelORG/` — `mm/page_isolation.c`, `mm/vmscan.c`
//! (`isolate_lru_page`).

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Maximum number of pages that can be isolated at once.
const MAX_ISOLATED_PAGES: usize = 256;

/// Maximum number of LRU entries.
const MAX_LRU_ENTRIES: usize = 512;

/// Standard page size (4 KiB).
const _PAGE_SIZE: u64 = 4096;

// -------------------------------------------------------------------
// IsolateMode
// -------------------------------------------------------------------

/// Flags controlling which pages to isolate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct IsolateMode {
    /// Raw flag bits.
    bits: u32,
}

impl IsolateMode {
    /// Only isolate pages that are not mapped by any process.
    pub const UNMAPPED: u32 = 1 << 0;
    /// Allow asynchronous isolation (don't wait for writeback).
    pub const ASYNC: u32 = 1 << 1;
    /// Allow isolating unevictable pages.
    pub const UNEVICTABLE: u32 = 1 << 2;

    /// Creates a mode with no flags.
    pub fn empty() -> Self {
        Self { bits: 0 }
    }

    /// Creates from raw bits.
    pub fn from_bits(bits: u32) -> Self {
        Self { bits }
    }

    /// Returns the raw bits.
    pub fn bits(self) -> u32 {
        self.bits
    }

    /// Tests if a flag is set.
    pub fn contains(self, flag: u32) -> bool {
        self.bits & flag == flag
    }

    /// Sets a flag.
    pub fn set(self, flag: u32) -> Self {
        Self {
            bits: self.bits | flag,
        }
    }
}

// -------------------------------------------------------------------
// IsolateResult
// -------------------------------------------------------------------

/// Outcome of an isolation attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum IsolateResult {
    /// Page successfully isolated.
    #[default]
    Success,
    /// Page is pinned and cannot be isolated.
    Pinned,
    /// Page is under writeback (async mode doesn't wait).
    Writeback,
    /// Page is unevictable and mode does not allow it.
    Unevictable,
    /// Page was not found on the LRU.
    NotOnLru,
    /// Isolation list is full.
    ListFull,
}

// -------------------------------------------------------------------
// LruEntry
// -------------------------------------------------------------------

/// A page on the LRU list.
#[derive(Debug, Clone, Copy, Default)]
pub struct LruEntry {
    /// Page frame number.
    pub pfn: u64,
    /// Whether the page is mapped.
    pub mapped: bool,
    /// Whether the page is under writeback.
    pub writeback: bool,
    /// Whether the page is unevictable.
    pub unevictable: bool,
    /// Reference count (pin count).
    pub refcount: u32,
    /// Whether this slot is active.
    pub active: bool,
}

// -------------------------------------------------------------------
// IsolatedPage
// -------------------------------------------------------------------

/// Metadata for an isolated page.
#[derive(Debug, Clone, Copy, Default)]
pub struct IsolatedPage {
    /// Page frame number.
    pub pfn: u64,
    /// Original LRU index (for putback).
    pub lru_index: usize,
    /// Whether the page was active before isolation.
    pub was_active: bool,
    /// Whether this page is a movable non-LRU page.
    pub is_movable: bool,
}

// -------------------------------------------------------------------
// IsolationList
// -------------------------------------------------------------------

/// List of isolated pages pending migration.
pub struct IsolationList {
    /// Isolated page entries.
    pages: [IsolatedPage; MAX_ISOLATED_PAGES],
    /// Number of isolated pages.
    count: usize,
}

impl Default for IsolationList {
    fn default() -> Self {
        Self {
            pages: [IsolatedPage::default(); MAX_ISOLATED_PAGES],
            count: 0,
        }
    }
}

impl IsolationList {
    /// Creates a new empty isolation list.
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds an isolated page.
    pub fn add(&mut self, page: IsolatedPage) -> Result<()> {
        if self.count >= MAX_ISOLATED_PAGES {
            return Err(Error::OutOfMemory);
        }
        self.pages[self.count] = page;
        self.count += 1;
        Ok(())
    }

    /// Removes and returns the last isolated page.
    pub fn pop(&mut self) -> Option<IsolatedPage> {
        if self.count == 0 {
            return None;
        }
        self.count -= 1;
        Some(self.pages[self.count])
    }

    /// Returns the number of isolated pages.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Returns `true` if empty.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Gets the page at the given index.
    pub fn get(&self, index: usize) -> Option<&IsolatedPage> {
        if index < self.count {
            Some(&self.pages[index])
        } else {
            None
        }
    }

    /// Clears the list.
    pub fn clear(&mut self) {
        self.count = 0;
    }
}

// -------------------------------------------------------------------
// IsolationStats
// -------------------------------------------------------------------

/// Aggregate isolation statistics.
#[derive(Debug, Clone, Copy, Default)]
pub struct IsolationStats {
    /// Total isolation attempts.
    pub attempts: u64,
    /// Successful isolations.
    pub success: u64,
    /// Failed: page was pinned.
    pub failed_pinned: u64,
    /// Failed: page under writeback.
    pub failed_writeback: u64,
    /// Failed: page is unevictable.
    pub failed_unevictable: u64,
    /// Failed: page not on LRU.
    pub failed_not_on_lru: u64,
    /// Total putback operations.
    pub putbacks: u64,
    /// Movable (non-LRU) page isolations.
    pub movable_isolated: u64,
}

impl IsolationStats {
    /// Resets all counters.
    pub fn reset(&mut self) {
        *self = Self::default();
    }
}

// -------------------------------------------------------------------
// PageIsolation
// -------------------------------------------------------------------

/// The main page isolation engine.
///
/// Manages LRU entries and provides isolation/putback operations.
pub struct PageIsolation {
    /// Simulated LRU list.
    lru: [LruEntry; MAX_LRU_ENTRIES],
    /// Number of active LRU entries.
    lru_count: usize,
    /// Isolation list for pending migrations.
    isolated: IsolationList,
    /// Statistics.
    stats: IsolationStats,
}

impl Default for PageIsolation {
    fn default() -> Self {
        Self {
            lru: [LruEntry::default(); MAX_LRU_ENTRIES],
            lru_count: 0,
            isolated: IsolationList::new(),
            stats: IsolationStats::default(),
        }
    }
}

impl PageIsolation {
    /// Creates a new page isolation engine.
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a page to the LRU list.
    pub fn add_to_lru(&mut self, entry: LruEntry) -> Result<usize> {
        if self.lru_count >= MAX_LRU_ENTRIES {
            return Err(Error::OutOfMemory);
        }
        let idx = self.lru_count;
        self.lru[idx] = entry;
        self.lru_count += 1;
        Ok(idx)
    }

    /// Isolates a page from the LRU by its index.
    pub fn isolate_lru_page(&mut self, lru_index: usize, mode: IsolateMode) -> IsolateResult {
        self.stats.attempts += 1;

        if lru_index >= self.lru_count || !self.lru[lru_index].active {
            self.stats.failed_not_on_lru += 1;
            return IsolateResult::NotOnLru;
        }

        let entry = self.lru[lru_index];

        // Check pinned.
        if entry.refcount > 1 {
            self.stats.failed_pinned += 1;
            return IsolateResult::Pinned;
        }

        // Check writeback.
        if entry.writeback && mode.contains(IsolateMode::ASYNC) {
            self.stats.failed_writeback += 1;
            return IsolateResult::Writeback;
        }

        // Check unevictable.
        if entry.unevictable && !mode.contains(IsolateMode::UNEVICTABLE) {
            self.stats.failed_unevictable += 1;
            return IsolateResult::Unevictable;
        }

        // Check mapped (if UNMAPPED mode).
        if entry.mapped && mode.contains(IsolateMode::UNMAPPED) {
            self.stats.failed_pinned += 1;
            return IsolateResult::Pinned;
        }

        // Add to isolation list.
        let isolated_page = IsolatedPage {
            pfn: entry.pfn,
            lru_index,
            was_active: entry.active,
            is_movable: false,
        };

        if self.isolated.add(isolated_page).is_err() {
            return IsolateResult::ListFull;
        }

        // Mark LRU slot as inactive.
        self.lru[lru_index].active = false;
        self.stats.success += 1;
        IsolateResult::Success
    }

    /// Puts an isolated page back onto the LRU.
    pub fn putback_lru_page(&mut self, pfn: u64) -> Result<()> {
        // Find the isolated page.
        let mut found_idx = None;
        for i in 0..self.isolated.len() {
            if let Some(p) = self.isolated.get(i) {
                if p.pfn == pfn {
                    found_idx = Some(i);
                    break;
                }
            }
        }

        let idx = found_idx.ok_or(Error::NotFound)?;
        let page = *self.isolated.get(idx).ok_or(Error::NotFound)?;

        // Restore LRU entry.
        if page.lru_index < self.lru_count {
            self.lru[page.lru_index].active = true;
        }

        // Remove from isolation list by swapping with last.
        let last = self.isolated.len() - 1;
        if idx != last {
            if let Some(last_page) = self.isolated.get(last) {
                let lp = *last_page;
                self.isolated.pages[idx] = lp;
            }
        }
        self.isolated.count -= 1;

        self.stats.putbacks += 1;
        Ok(())
    }

    /// Isolates a movable (non-LRU) page.
    pub fn isolate_movable_page(&mut self, pfn: u64) -> IsolateResult {
        self.stats.attempts += 1;

        let isolated_page = IsolatedPage {
            pfn,
            lru_index: usize::MAX,
            was_active: false,
            is_movable: true,
        };

        if self.isolated.add(isolated_page).is_err() {
            return IsolateResult::ListFull;
        }

        self.stats.success += 1;
        self.stats.movable_isolated += 1;
        IsolateResult::Success
    }

    /// Returns the isolation list.
    pub fn isolated_list(&self) -> &IsolationList {
        &self.isolated
    }

    /// Returns the number of LRU entries.
    pub fn lru_count(&self) -> usize {
        self.lru_count
    }

    /// Returns statistics.
    pub fn stats(&self) -> &IsolationStats {
        &self.stats
    }

    /// Clears the isolation list.
    pub fn clear_isolated(&mut self) {
        self.isolated.clear();
    }

    /// Resets statistics.
    pub fn reset_stats(&mut self) {
        self.stats.reset();
    }
}
