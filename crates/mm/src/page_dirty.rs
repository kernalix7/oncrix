// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Page dirty tracking.
//!
//! Implements dirty page tracking for the memory management subsystem.
//! When a page is written, it must be marked dirty so that the writeback
//! subsystem knows to flush it to backing store. This module provides
//! the core dirty bit manipulation, accounting, and dirty throttling
//! infrastructure.
//!
//! - [`PageDirtyFlags`] — per-page dirty state
//! - [`DirtyAccounting`] — system-wide dirty page accounting
//! - [`DirtyThrottleConfig`] — dirty page throttle parameters
//! - [`DirtyTracker`] — the main dirty page tracker
//!
//! Reference: `.kernelORG/` — `mm/page-writeback.c`, `include/linux/writeback.h`.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Page size (4 KiB).
const PAGE_SIZE: u64 = 4096;

/// Default dirty background ratio (percentage of total memory).
const DEFAULT_DIRTY_BACKGROUND_RATIO: u32 = 10;

/// Default dirty ratio (percentage of total memory).
const DEFAULT_DIRTY_RATIO: u32 = 20;

/// Maximum dirty pages before hard throttle.
const DEFAULT_DIRTY_WRITEBACK_INTERVAL: u64 = 500; // centiseconds

/// Maximum tracked pages.
const MAX_TRACKED_PAGES: usize = 4096;

/// Dirty expire interval (centiseconds).
const DIRTY_EXPIRE_INTERVAL: u64 = 3000;

// -------------------------------------------------------------------
// PageDirtyFlags
// -------------------------------------------------------------------

/// Dirty state flags for a single page.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PageDirtyFlags {
    /// Page is dirty (needs writeback).
    pub dirty: bool,
    /// Page has been written back but not yet completed.
    pub writeback: bool,
    /// Dirty bit has been tested and set atomically.
    pub test_set: bool,
    /// Page is being reclaimed.
    pub reclaim: bool,
}

impl PageDirtyFlags {
    /// Creates clean flags.
    pub fn clean() -> Self {
        Self::default()
    }

    /// Creates dirty flags.
    pub fn dirty() -> Self {
        Self {
            dirty: true,
            ..Self::default()
        }
    }

    /// Returns true if the page needs writeback.
    pub fn needs_writeback(&self) -> bool {
        self.dirty && !self.writeback
    }
}

// -------------------------------------------------------------------
// DirtyPage
// -------------------------------------------------------------------

/// A tracked dirty page.
#[derive(Debug, Clone, Copy, Default)]
struct DirtyPage {
    /// Page frame number.
    pfn: u64,
    /// Mapping identifier (file inode or anon VMA).
    mapping_id: u64,
    /// Dirty flags.
    flags: PageDirtyFlags,
    /// Timestamp when dirtied (tick counter).
    dirty_time: u64,
    /// Whether this slot is in use.
    in_use: bool,
}

// -------------------------------------------------------------------
// DirtyAccounting
// -------------------------------------------------------------------

/// System-wide dirty page accounting.
#[derive(Debug, Clone, Copy, Default)]
pub struct DirtyAccounting {
    /// Number of dirty pages.
    pub nr_dirty: u64,
    /// Number of pages under writeback.
    pub nr_writeback: u64,
    /// Total reclaimable pages.
    pub nr_reclaimable: u64,
    /// Total pages in the system.
    pub total_pages: u64,
    /// Pages dirtied since last reset.
    pub pages_dirtied: u64,
    /// Pages cleaned (written back).
    pub pages_cleaned: u64,
}

impl DirtyAccounting {
    /// Creates new accounting with the given total pages.
    pub fn new(total_pages: u64) -> Self {
        Self {
            total_pages,
            ..Self::default()
        }
    }

    /// Returns the dirty ratio (0-100).
    pub fn dirty_ratio(&self) -> u64 {
        if self.total_pages == 0 {
            return 0;
        }
        self.nr_dirty * 100 / self.total_pages
    }

    /// Returns the writeback ratio (0-100).
    pub fn writeback_ratio(&self) -> u64 {
        if self.total_pages == 0 {
            return 0;
        }
        self.nr_writeback * 100 / self.total_pages
    }

    /// Returns the combined dirty + writeback ratio.
    pub fn combined_ratio(&self) -> u64 {
        if self.total_pages == 0 {
            return 0;
        }
        (self.nr_dirty + self.nr_writeback) * 100 / self.total_pages
    }
}

// -------------------------------------------------------------------
// DirtyThrottleConfig
// -------------------------------------------------------------------

/// Configuration for dirty page throttling.
#[derive(Debug, Clone, Copy)]
pub struct DirtyThrottleConfig {
    /// Background dirty ratio (percentage). Writeback starts here.
    pub dirty_background_ratio: u32,
    /// Hard dirty ratio (percentage). Processes are throttled here.
    pub dirty_ratio: u32,
    /// Writeback interval (centiseconds).
    pub writeback_interval: u64,
    /// Dirty expiry (centiseconds).
    pub expire_interval: u64,
}

impl DirtyThrottleConfig {
    /// Creates default throttle configuration.
    pub fn new() -> Self {
        Self {
            dirty_background_ratio: DEFAULT_DIRTY_BACKGROUND_RATIO,
            dirty_ratio: DEFAULT_DIRTY_RATIO,
            writeback_interval: DEFAULT_DIRTY_WRITEBACK_INTERVAL,
            expire_interval: DIRTY_EXPIRE_INTERVAL,
        }
    }

    /// Returns the background dirty threshold in pages.
    pub fn background_threshold(&self, total_pages: u64) -> u64 {
        total_pages * self.dirty_background_ratio as u64 / 100
    }

    /// Returns the hard dirty threshold in pages.
    pub fn hard_threshold(&self, total_pages: u64) -> u64 {
        total_pages * self.dirty_ratio as u64 / 100
    }
}

impl Default for DirtyThrottleConfig {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// ThrottleDecision
// -------------------------------------------------------------------

/// Throttling decision for a dirtying process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThrottleDecision {
    /// No throttling needed.
    None,
    /// Background writeback should start.
    BackgroundWriteback,
    /// Process should be throttled (sleep).
    Throttle,
    /// Hard limit reached; block until writeback completes.
    Block,
}

// -------------------------------------------------------------------
// DirtyTracker
// -------------------------------------------------------------------

/// Dirty page tracker.
///
/// Tracks which pages are dirty, provides dirty/clean operations,
/// and makes throttling decisions based on the dirty ratio.
pub struct DirtyTracker {
    /// Tracked dirty pages.
    pages: [DirtyPage; MAX_TRACKED_PAGES],
    /// Number of tracked pages.
    nr_tracked: usize,
    /// Dirty accounting.
    accounting: DirtyAccounting,
    /// Throttle configuration.
    config: DirtyThrottleConfig,
    /// Current tick counter (for timestamping).
    current_tick: u64,
}

impl DirtyTracker {
    /// Creates a new dirty tracker.
    pub fn new(total_pages: u64, config: DirtyThrottleConfig) -> Self {
        Self {
            pages: [DirtyPage::default(); MAX_TRACKED_PAGES],
            nr_tracked: 0,
            accounting: DirtyAccounting::new(total_pages),
            config,
            current_tick: 0,
        }
    }

    /// Marks a page as dirty.
    ///
    /// If the page has a mapping, notifies the mapping (stub).
    pub fn set_page_dirty(&mut self, pfn: u64, mapping_id: u64) -> Result<()> {
        // Check if already tracked.
        for page in &mut self.pages {
            if page.in_use && page.pfn == pfn {
                if !page.flags.dirty {
                    page.flags.dirty = true;
                    page.dirty_time = self.current_tick;
                    self.accounting.nr_dirty += 1;
                    self.accounting.pages_dirtied += 1;
                }
                return Ok(());
            }
        }

        // Add new entry.
        self.add_tracked_page(pfn, mapping_id)
    }

    /// Marks a page dirty (simple variant without mapping notify).
    pub fn mark_page_dirty(&mut self, pfn: u64) -> Result<()> {
        self.set_page_dirty(pfn, 0)
    }

    /// Clears the dirty bit for I/O (page is about to be written).
    pub fn clear_page_dirty_for_io(&mut self, pfn: u64) -> Result<bool> {
        for page in &mut self.pages {
            if page.in_use && page.pfn == pfn {
                let was_dirty = page.flags.dirty;
                if was_dirty {
                    page.flags.dirty = false;
                    page.flags.writeback = true;
                    self.accounting.nr_dirty = self.accounting.nr_dirty.saturating_sub(1);
                    self.accounting.nr_writeback += 1;
                }
                return Ok(was_dirty);
            }
        }
        Err(Error::NotFound)
    }

    /// Tests and sets the dirty bit atomically.
    ///
    /// Returns true if the page was already dirty.
    pub fn test_set_page_dirty(&mut self, pfn: u64) -> Result<bool> {
        for page in &mut self.pages {
            if page.in_use && page.pfn == pfn {
                let was_dirty = page.flags.dirty;
                page.flags.dirty = true;
                page.flags.test_set = true;
                if !was_dirty {
                    page.dirty_time = self.current_tick;
                    self.accounting.nr_dirty += 1;
                    self.accounting.pages_dirtied += 1;
                }
                return Ok(was_dirty);
            }
        }
        Err(Error::NotFound)
    }

    /// Accounts a page dirtied event.
    pub fn account_page_dirtied(&mut self) {
        self.accounting.nr_dirty += 1;
        self.accounting.pages_dirtied += 1;
    }

    /// Accounts a page cleaned event.
    pub fn account_page_cleaned(&mut self, pfn: u64) {
        for page in &mut self.pages {
            if page.in_use && page.pfn == pfn {
                page.flags.writeback = false;
                self.accounting.nr_writeback = self.accounting.nr_writeback.saturating_sub(1);
                self.accounting.pages_cleaned += 1;
                break;
            }
        }
    }

    /// Evaluates dirty page throttling.
    pub fn balance_dirty_pages(&self) -> ThrottleDecision {
        let bg_thresh = self
            .config
            .background_threshold(self.accounting.total_pages);
        let hard_thresh = self.config.hard_threshold(self.accounting.total_pages);
        let dirty = self.accounting.nr_dirty + self.accounting.nr_writeback;

        if dirty >= hard_thresh {
            ThrottleDecision::Block
        } else if dirty >= hard_thresh * 9 / 10 {
            ThrottleDecision::Throttle
        } else if dirty >= bg_thresh {
            ThrottleDecision::BackgroundWriteback
        } else {
            ThrottleDecision::None
        }
    }

    /// Removes a page from tracking (page freed).
    pub fn remove_page(&mut self, pfn: u64) {
        for page in &mut self.pages {
            if page.in_use && page.pfn == pfn {
                if page.flags.dirty {
                    self.accounting.nr_dirty = self.accounting.nr_dirty.saturating_sub(1);
                }
                if page.flags.writeback {
                    self.accounting.nr_writeback = self.accounting.nr_writeback.saturating_sub(1);
                }
                page.in_use = false;
                self.nr_tracked -= 1;
                break;
            }
        }
    }

    /// Advances the tick counter.
    pub fn tick(&mut self, ticks: u64) {
        self.current_tick += ticks;
    }

    /// Returns the dirty accounting.
    pub fn accounting(&self) -> &DirtyAccounting {
        &self.accounting
    }

    /// Returns the throttle configuration.
    pub fn config(&self) -> &DirtyThrottleConfig {
        &self.config
    }

    /// Updates the throttle configuration.
    pub fn set_config(&mut self, config: DirtyThrottleConfig) {
        self.config = config;
    }

    /// Adds a new tracked page.
    fn add_tracked_page(&mut self, pfn: u64, mapping_id: u64) -> Result<()> {
        for page in &mut self.pages {
            if !page.in_use {
                page.pfn = pfn;
                page.mapping_id = mapping_id;
                page.flags = PageDirtyFlags::dirty();
                page.dirty_time = self.current_tick;
                page.in_use = true;
                self.nr_tracked += 1;
                self.accounting.nr_dirty += 1;
                self.accounting.pages_dirtied += 1;
                return Ok(());
            }
        }
        Err(Error::OutOfMemory)
    }
}
