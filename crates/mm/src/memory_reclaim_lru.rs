// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! LRU-based page reclaim.
//!
//! Implements the multi-list LRU (Least Recently Used) framework for
//! page reclaim. Pages are sorted into five lists based on their type
//! and activity: active/inactive anonymous, active/inactive file, and
//! unevictable. The reclaim engine scans inactive lists, moves pages
//! between lists based on access patterns, and selects victims for
//! eviction.
//!
//! - [`LruListType`] — the five LRU list categories
//! - [`LruPage`] — page metadata for LRU tracking
//! - [`LruList`] — a single LRU list with FIFO scan order
//! - [`LruSet`] — all five LRU lists for a zone/memcg
//! - [`ReclaimStats`] — aggregate reclaim statistics
//! - [`LruReclaimer`] — the main reclaim engine
//!
//! Reference: `.kernelORG/` — `mm/vmscan.c`, `include/linux/mmzone.h`.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Maximum entries per LRU list.
const MAX_LRU_ENTRIES: usize = 256;

/// Number of LRU list types.
const NR_LRU_LISTS: usize = 5;

/// Default scan batch size.
const DEFAULT_SCAN_BATCH: usize = 32;

/// Ratio of active to inactive list (2:1 target).
const ACTIVE_INACTIVE_RATIO: usize = 2;

// -------------------------------------------------------------------
// LruListType
// -------------------------------------------------------------------

/// The five LRU list categories.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum LruListType {
    /// Inactive anonymous pages (swap candidates).
    #[default]
    InactiveAnon = 0,
    /// Active anonymous pages (recently accessed).
    ActiveAnon = 1,
    /// Inactive file-backed pages (reclaim candidates).
    InactiveFile = 2,
    /// Active file-backed pages (recently accessed).
    ActiveFile = 3,
    /// Unevictable pages (mlocked, ramfs, etc.).
    Unevictable = 4,
}

impl LruListType {
    /// Returns `true` if this is an active list.
    pub fn is_active(self) -> bool {
        matches!(self, LruListType::ActiveAnon | LruListType::ActiveFile)
    }

    /// Returns `true` if this is a file-backed list.
    pub fn is_file(self) -> bool {
        matches!(self, LruListType::InactiveFile | LruListType::ActiveFile)
    }

    /// Returns `true` if this is an anonymous list.
    pub fn is_anon(self) -> bool {
        matches!(self, LruListType::InactiveAnon | LruListType::ActiveAnon)
    }

    /// Returns the corresponding inactive list for an active list.
    pub fn to_inactive(self) -> Self {
        match self {
            LruListType::ActiveAnon => LruListType::InactiveAnon,
            LruListType::ActiveFile => LruListType::InactiveFile,
            _ => self,
        }
    }
}

// -------------------------------------------------------------------
// LruPage
// -------------------------------------------------------------------

/// Page metadata for LRU tracking.
#[derive(Debug, Clone, Copy, Default)]
pub struct LruPage {
    /// Page frame number.
    pub pfn: u64,
    /// Whether the page has been referenced (accessed bit).
    pub referenced: bool,
    /// Whether the page is dirty.
    pub dirty: bool,
    /// Whether the page is mapped by at least one process.
    pub mapped: bool,
    /// Whether the page is under writeback.
    pub writeback: bool,
    /// Reference count.
    pub refcount: u32,
    /// Whether this slot is in use.
    pub active: bool,
}

// -------------------------------------------------------------------
// LruList
// -------------------------------------------------------------------

/// A single LRU list with FIFO scan order.
///
/// New pages are added at the tail; scanning starts from the head.
pub struct LruList {
    /// Page entries.
    entries: [LruPage; MAX_LRU_ENTRIES],
    /// Number of pages in this list.
    count: usize,
    /// List type.
    list_type: LruListType,
}

impl Default for LruList {
    fn default() -> Self {
        Self {
            entries: [LruPage::default(); MAX_LRU_ENTRIES],
            count: 0,
            list_type: LruListType::InactiveAnon,
        }
    }
}

impl LruList {
    /// Creates a new LRU list of the given type.
    fn new(list_type: LruListType) -> Self {
        Self {
            list_type,
            ..Self::default()
        }
    }

    /// Adds a page to the tail of the list.
    pub fn add(&mut self, page: LruPage) -> Result<()> {
        if self.count >= MAX_LRU_ENTRIES {
            return Err(Error::OutOfMemory);
        }
        self.entries[self.count] = page;
        self.count += 1;
        Ok(())
    }

    /// Removes the page at the head of the list (oldest page).
    pub fn remove_head(&mut self) -> Option<LruPage> {
        if self.count == 0 {
            return None;
        }
        let page = self.entries[0];
        // Shift left.
        for i in 0..self.count - 1 {
            self.entries[i] = self.entries[i + 1];
        }
        self.count -= 1;
        Some(page)
    }

    /// Removes a page by PFN.
    pub fn remove_by_pfn(&mut self, pfn: u64) -> Option<LruPage> {
        for i in 0..self.count {
            if self.entries[i].pfn == pfn {
                let page = self.entries[i];
                for j in i..self.count - 1 {
                    self.entries[j] = self.entries[j + 1];
                }
                self.count -= 1;
                return Some(page);
            }
        }
        None
    }

    /// Returns the number of pages.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Returns `true` if empty.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Returns the list type.
    pub fn list_type(&self) -> LruListType {
        self.list_type
    }

    /// Gets the page at the given index.
    pub fn get(&self, index: usize) -> Option<&LruPage> {
        if index < self.count {
            Some(&self.entries[index])
        } else {
            None
        }
    }

    /// Rotates the head page to the tail (give it a second chance).
    pub fn rotate(&mut self) {
        if self.count < 2 {
            return;
        }
        let head = self.entries[0];
        for i in 0..self.count - 1 {
            self.entries[i] = self.entries[i + 1];
        }
        self.entries[self.count - 1] = head;
    }
}

// -------------------------------------------------------------------
// LruSet
// -------------------------------------------------------------------

/// All five LRU lists for a zone or memcg.
pub struct LruSet {
    /// The five LRU lists.
    lists: [LruList; NR_LRU_LISTS],
}

impl Default for LruSet {
    fn default() -> Self {
        Self {
            lists: [const {
                LruList {
                    entries: [LruPage {
                        pfn: 0,
                        referenced: false,
                        dirty: false,
                        mapped: false,
                        writeback: false,
                        refcount: 0,
                        active: false,
                    }; MAX_LRU_ENTRIES],
                    count: 0,
                    list_type: LruListType::InactiveAnon,
                }
            }; NR_LRU_LISTS],
        }
    }
}

impl LruSet {
    /// Creates a new LRU set with properly typed lists.
    pub fn new() -> Self {
        let mut set = Self::default();
        set.lists[0] = LruList::new(LruListType::InactiveAnon);
        set.lists[1] = LruList::new(LruListType::ActiveAnon);
        set.lists[2] = LruList::new(LruListType::InactiveFile);
        set.lists[3] = LruList::new(LruListType::ActiveFile);
        set.lists[4] = LruList::new(LruListType::Unevictable);
        set
    }

    /// Adds a page to the specified list.
    pub fn lru_add(&mut self, list: LruListType, page: LruPage) -> Result<()> {
        self.lists[list as usize].add(page)
    }

    /// Removes a page by PFN from the specified list.
    pub fn lru_del(&mut self, list: LruListType, pfn: u64) -> Option<LruPage> {
        self.lists[list as usize].remove_by_pfn(pfn)
    }

    /// Activates a page: moves it from inactive to active list.
    pub fn activate_page(&mut self, pfn: u64, is_file: bool) -> Result<()> {
        let from = if is_file {
            LruListType::InactiveFile
        } else {
            LruListType::InactiveAnon
        };
        let to = if is_file {
            LruListType::ActiveFile
        } else {
            LruListType::ActiveAnon
        };

        let from_idx = from as usize;
        let to_idx = to as usize;

        // Find and remove from inactive.
        let page = self.lists[from_idx]
            .remove_by_pfn(pfn)
            .ok_or(Error::NotFound)?;

        // Add to active.
        self.lists[to_idx].add(page)?;
        Ok(())
    }

    /// Deactivates a page: moves it from active to inactive list.
    pub fn deactivate_page(&mut self, pfn: u64, is_file: bool) -> Result<()> {
        let from = if is_file {
            LruListType::ActiveFile
        } else {
            LruListType::ActiveAnon
        };
        let to = from.to_inactive();

        let from_idx = from as usize;
        let to_idx = to as usize;

        let page = self.lists[from_idx]
            .remove_by_pfn(pfn)
            .ok_or(Error::NotFound)?;
        self.lists[to_idx].add(page)?;
        Ok(())
    }

    /// Rotates the head of a reclaimable (inactive) list.
    pub fn rotate_reclaimable(&mut self, is_file: bool) {
        let list = if is_file {
            LruListType::InactiveFile
        } else {
            LruListType::InactiveAnon
        };
        self.lists[list as usize].rotate();
    }

    /// Returns the count for a specific list.
    pub fn count(&self, list: LruListType) -> usize {
        self.lists[list as usize].len()
    }

    /// Returns the total page count across all lists.
    pub fn total_count(&self) -> usize {
        self.lists.iter().map(|l| l.len()).sum()
    }

    /// Returns a reference to a specific list.
    pub fn list(&self, list: LruListType) -> &LruList {
        &self.lists[list as usize]
    }
}

// -------------------------------------------------------------------
// ReclaimStats
// -------------------------------------------------------------------

/// Aggregate reclaim statistics.
#[derive(Debug, Clone, Copy, Default)]
pub struct ReclaimStats {
    /// Pages scanned from inactive anonymous list.
    pub scanned_inactive_anon: u64,
    /// Pages scanned from inactive file list.
    pub scanned_inactive_file: u64,
    /// Pages scanned from active anonymous list.
    pub scanned_active_anon: u64,
    /// Pages scanned from active file list.
    pub scanned_active_file: u64,
    /// Pages reclaimed (evicted).
    pub reclaimed: u64,
    /// Pages activated (moved from inactive to active).
    pub activated: u64,
    /// Pages rotated (given second chance).
    pub rotated: u64,
    /// Pages skipped due to writeback.
    pub skipped_writeback: u64,
    /// Pages skipped due to being mapped.
    pub skipped_mapped: u64,
}

impl ReclaimStats {
    /// Resets all counters.
    pub fn reset(&mut self) {
        *self = Self::default();
    }
}

// -------------------------------------------------------------------
// LruReclaimer
// -------------------------------------------------------------------

/// The main LRU-based reclaim engine.
pub struct LruReclaimer {
    /// LRU lists.
    lru_set: LruSet,
    /// Scan batch size.
    scan_batch: usize,
    /// Reclaim statistics.
    stats: ReclaimStats,
}

impl Default for LruReclaimer {
    fn default() -> Self {
        Self {
            lru_set: LruSet::new(),
            scan_batch: DEFAULT_SCAN_BATCH,
            stats: ReclaimStats::default(),
        }
    }
}

impl LruReclaimer {
    /// Creates a new reclaimer.
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the scan batch size.
    pub fn set_scan_batch(&mut self, batch: usize) {
        self.scan_batch = batch;
    }

    /// Adds a page to the appropriate LRU list.
    pub fn add_page(&mut self, page: LruPage, list: LruListType) -> Result<()> {
        self.lru_set.lru_add(list, page)
    }

    /// Shrinks the inactive list by scanning and reclaiming pages.
    ///
    /// Returns the number of pages reclaimed.
    pub fn shrink_inactive_list(&mut self, is_file: bool, nr_to_scan: usize) -> usize {
        let list_type = if is_file {
            LruListType::InactiveFile
        } else {
            LruListType::InactiveAnon
        };
        let stat_field = is_file;

        let mut reclaimed = 0;
        let mut scanned = 0;
        let to_scan = nr_to_scan.min(self.scan_batch);

        while scanned < to_scan {
            let page = self.lru_set.lists[list_type as usize].remove_head();
            let page = match page {
                Some(p) => p,
                None => break,
            };
            scanned += 1;

            // Referenced pages get a second chance → activate.
            if page.referenced {
                let mut activated = page;
                activated.referenced = false;
                let active = if is_file {
                    LruListType::ActiveFile
                } else {
                    LruListType::ActiveAnon
                };
                let _ = self.lru_set.lists[active as usize].add(activated);
                self.stats.activated += 1;
                continue;
            }

            // Writeback pages are skipped.
            if page.writeback {
                let _ = self.lru_set.lists[list_type as usize].add(page);
                self.stats.skipped_writeback += 1;
                continue;
            }

            // Mapped pages may be skipped.
            if page.mapped && page.refcount > 0 {
                let _ = self.lru_set.lists[list_type as usize].add(page);
                self.stats.skipped_mapped += 1;
                continue;
            }

            // Reclaim this page.
            reclaimed += 1;
        }

        if stat_field {
            self.stats.scanned_inactive_file += scanned as u64;
        } else {
            self.stats.scanned_inactive_anon += scanned as u64;
        }
        self.stats.reclaimed += reclaimed as u64;
        reclaimed
    }

    /// Shrinks the active list by deactivating pages that have not
    /// been referenced recently.
    ///
    /// Returns the number of pages deactivated.
    pub fn shrink_active_list(&mut self, is_file: bool, nr_to_scan: usize) -> usize {
        let active_type = if is_file {
            LruListType::ActiveFile
        } else {
            LruListType::ActiveAnon
        };
        let inactive_type = active_type.to_inactive();

        let mut deactivated = 0;
        let mut scanned = 0;
        let to_scan = nr_to_scan.min(self.scan_batch);

        while scanned < to_scan {
            let page = self.lru_set.lists[active_type as usize].remove_head();
            let page = match page {
                Some(p) => p,
                None => break,
            };
            scanned += 1;

            if page.referenced {
                // Still referenced — keep active, clear reference.
                let mut kept = page;
                kept.referenced = false;
                let _ = self.lru_set.lists[active_type as usize].add(kept);
                self.stats.rotated += 1;
                continue;
            }

            // Not referenced — deactivate.
            let _ = self.lru_set.lists[inactive_type as usize].add(page);
            deactivated += 1;
        }

        if is_file {
            self.stats.scanned_active_file += scanned as u64;
        } else {
            self.stats.scanned_active_anon += scanned as u64;
        }
        deactivated
    }

    /// Returns the LRU set.
    pub fn lru_set(&self) -> &LruSet {
        &self.lru_set
    }

    /// Returns reclaim statistics.
    pub fn stats(&self) -> &ReclaimStats {
        &self.stats
    }

    /// Checks if the active list is too large relative to inactive.
    pub fn should_shrink_active(&self, is_file: bool) -> bool {
        let active = if is_file {
            self.lru_set.count(LruListType::ActiveFile)
        } else {
            self.lru_set.count(LruListType::ActiveAnon)
        };
        let inactive = if is_file {
            self.lru_set.count(LruListType::InactiveFile)
        } else {
            self.lru_set.count(LruListType::InactiveAnon)
        };
        active > inactive * ACTIVE_INACTIVE_RATIO
    }

    /// Resets statistics.
    pub fn reset_stats(&mut self) {
        self.stats.reset();
    }
}
