// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! VM scanner LRU list management.
//!
//! Implements the LRU list infrastructure used by the page reclaim
//! scanner (vmscan). Manages active/inactive lists for anonymous
//! and file-backed pages, handles page aging, and implements the
//! two-list clock algorithm for page replacement.
//!
//! - [`LruListType`] — LRU list classification
//! - [`LruPage`] — a page on an LRU list
//! - [`LruList`] — a single LRU list
//! - [`LruStats`] — per-list statistics
//! - [`VmscanLru`] — the combined LRU subsystem
//!
//! Reference: Linux `mm/vmscan.c`, `include/linux/mmzone.h`.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Maximum pages per LRU list.
const MAX_LRU_PAGES: usize = 512;

/// Default scan batch size.
const DEFAULT_SCAN_BATCH: usize = 32;

// -------------------------------------------------------------------
// LruListType
// -------------------------------------------------------------------

/// LRU list classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum LruListType {
    /// Inactive anonymous pages.
    #[default]
    InactiveAnon,
    /// Active anonymous pages.
    ActiveAnon,
    /// Inactive file-backed pages.
    InactiveFile,
    /// Active file-backed pages.
    ActiveFile,
    /// Unevictable pages.
    Unevictable,
}

// -------------------------------------------------------------------
// LruPage
// -------------------------------------------------------------------

/// A page tracked on an LRU list.
#[derive(Debug, Clone, Copy, Default)]
pub struct LruPage {
    /// Page frame number.
    pub pfn: u64,
    /// Reference bit (set on access).
    pub referenced: bool,
    /// Whether the page is dirty.
    pub dirty: bool,
    /// Whether the page is locked.
    pub locked: bool,
    /// Age (number of scans survived).
    pub age: u32,
    /// Whether this slot is active.
    pub active: bool,
}

impl LruPage {
    /// Creates a new LRU page.
    pub fn new(pfn: u64) -> Self {
        Self {
            pfn,
            referenced: false,
            dirty: false,
            locked: false,
            age: 0,
            active: true,
        }
    }
}

// -------------------------------------------------------------------
// LruList
// -------------------------------------------------------------------

/// A single LRU list.
pub struct LruList {
    /// Pages on this list.
    pages: [LruPage; MAX_LRU_PAGES],
    /// Number of pages.
    count: usize,
    /// List type.
    list_type: LruListType,
}

impl LruList {
    /// Creates a new empty LRU list.
    pub fn new(list_type: LruListType) -> Self {
        Self {
            pages: [LruPage::default(); MAX_LRU_PAGES],
            count: 0,
            list_type,
        }
    }

    /// Adds a page to the list.
    pub fn add(&mut self, page: LruPage) -> Result<()> {
        if self.count >= MAX_LRU_PAGES {
            return Err(Error::OutOfMemory);
        }
        self.pages[self.count] = page;
        self.count += 1;
        Ok(())
    }

    /// Removes a page by index. Returns the removed page.
    pub fn remove(&mut self, idx: usize) -> Result<LruPage> {
        if idx >= self.count || !self.pages[idx].active {
            return Err(Error::NotFound);
        }
        let page = self.pages[idx];
        self.pages[idx].active = false;
        Ok(page)
    }

    /// Scans the list and returns indices of reclaimable pages.
    pub fn scan(&mut self, batch: usize) -> (usize, usize) {
        let batch = batch.min(self.count);
        let mut scanned = 0usize;
        let mut reclaimable = 0usize;

        for i in 0..self.count {
            if scanned >= batch {
                break;
            }
            if !self.pages[i].active {
                continue;
            }
            scanned += 1;
            self.pages[i].age = self.pages[i].age.saturating_add(1);

            if self.pages[i].referenced {
                self.pages[i].referenced = false;
                continue;
            }
            if self.pages[i].locked {
                continue;
            }
            reclaimable += 1;
        }
        (scanned, reclaimable)
    }

    /// Returns the number of pages.
    pub fn count(&self) -> usize {
        self.count
    }

    /// Returns the list type.
    pub fn list_type(&self) -> LruListType {
        self.list_type
    }
}

// -------------------------------------------------------------------
// LruStats
// -------------------------------------------------------------------

/// LRU scanning statistics.
#[derive(Debug, Clone, Copy, Default)]
pub struct LruStats {
    /// Total pages scanned.
    pub pages_scanned: u64,
    /// Pages found reclaimable.
    pub pages_reclaimable: u64,
    /// Pages promoted (inactive → active).
    pub pages_promoted: u64,
    /// Pages demoted (active → inactive).
    pub pages_demoted: u64,
    /// Pages reclaimed.
    pub pages_reclaimed: u64,
    /// Scan passes.
    pub scan_passes: u64,
}

impl LruStats {
    /// Resets all counters.
    pub fn reset(&mut self) {
        *self = Self::default();
    }
}

// -------------------------------------------------------------------
// VmscanLru
// -------------------------------------------------------------------

/// The combined LRU subsystem managing all LRU lists.
pub struct VmscanLru {
    /// Inactive anonymous list.
    inactive_anon: LruList,
    /// Active anonymous list.
    active_anon: LruList,
    /// Inactive file list.
    inactive_file: LruList,
    /// Active file list.
    active_file: LruList,
    /// Scan batch size.
    scan_batch: usize,
    /// Statistics.
    stats: LruStats,
}

impl Default for VmscanLru {
    fn default() -> Self {
        Self {
            inactive_anon: LruList::new(LruListType::InactiveAnon),
            active_anon: LruList::new(LruListType::ActiveAnon),
            inactive_file: LruList::new(LruListType::InactiveFile),
            active_file: LruList::new(LruListType::ActiveFile),
            scan_batch: DEFAULT_SCAN_BATCH,
            stats: LruStats::default(),
        }
    }
}

impl VmscanLru {
    /// Creates a new vmscan LRU subsystem.
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a page to the appropriate inactive list.
    pub fn add_page(&mut self, pfn: u64, is_anon: bool) -> Result<()> {
        let page = LruPage::new(pfn);
        if is_anon {
            self.inactive_anon.add(page)
        } else {
            self.inactive_file.add(page)
        }
    }

    /// Scans inactive anonymous pages.
    pub fn scan_inactive_anon(&mut self) -> (usize, usize) {
        let (scanned, reclaimable) = self.inactive_anon.scan(self.scan_batch);
        self.stats.pages_scanned += scanned as u64;
        self.stats.pages_reclaimable += reclaimable as u64;
        self.stats.scan_passes += 1;
        (scanned, reclaimable)
    }

    /// Scans inactive file pages.
    pub fn scan_inactive_file(&mut self) -> (usize, usize) {
        let (scanned, reclaimable) = self.inactive_file.scan(self.scan_batch);
        self.stats.pages_scanned += scanned as u64;
        self.stats.pages_reclaimable += reclaimable as u64;
        self.stats.scan_passes += 1;
        (scanned, reclaimable)
    }

    /// Returns total pages across all lists.
    pub fn total_pages(&self) -> usize {
        self.inactive_anon.count()
            + self.active_anon.count()
            + self.inactive_file.count()
            + self.active_file.count()
    }

    /// Returns statistics.
    pub fn stats(&self) -> &LruStats {
        &self.stats
    }

    /// Resets statistics.
    pub fn reset_stats(&mut self) {
        self.stats.reset();
    }
}
