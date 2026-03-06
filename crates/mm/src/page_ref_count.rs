// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Page reference counting.
//!
//! Physical pages are shared between multiple consumers (page cache,
//! mmap, DMA, swap cache). Each consumer holds a reference, and the
//! page can only be freed when all references are released. This
//! module provides the reference counting infrastructure, including
//! speculative fast-path gets, compound page handling, and leak
//! detection.
//!
//! # Design
//!
//! ```text
//!  get_page(pfn)  → increment refcount
//!  put_page(pfn)  → decrement refcount → if 0 → free page
//!
//!  try_get_page(pfn) → speculative increment (fails if count == 0)
//! ```
//!
//! # Key Types
//!
//! - [`PageRef`] — reference count for a single page
//! - [`PageRefTable`] — table of per-page reference counts
//! - [`PageRefStats`] — reference counting statistics
//!
//! Reference: Linux `include/linux/mm.h` (page_ref_*),
//! `mm/page_alloc.c`.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Maximum pages tracked.
const MAX_PAGES: usize = 4096;

/// Maximum reference count per page.
const MAX_REFCOUNT: u32 = 65535;

/// Bias value for detecting over-release.
const REFCOUNT_BIAS: u32 = 0;

/// Saturated count indicating a potential bug.
const REFCOUNT_SATURATED: u32 = u32::MAX / 2;

// -------------------------------------------------------------------
// PageRef
// -------------------------------------------------------------------

/// Reference count for a single physical page.
#[derive(Debug, Clone, Copy)]
pub struct PageRef {
    /// Physical frame number.
    pfn: u64,
    /// Current reference count.
    count: u32,
    /// Number of map references (page table entries).
    mapcount: i32,
    /// Whether the page is on the free list.
    free: bool,
}

impl PageRef {
    /// Create a new page reference entry.
    pub const fn new(pfn: u64) -> Self {
        Self {
            pfn,
            count: 1,
            mapcount: 0,
            free: false,
        }
    }

    /// Create a free page entry.
    pub const fn free_page(pfn: u64) -> Self {
        Self {
            pfn,
            count: 0,
            mapcount: 0,
            free: true,
        }
    }

    /// Return the PFN.
    pub const fn pfn(&self) -> u64 {
        self.pfn
    }

    /// Return the reference count.
    pub const fn count(&self) -> u32 {
        self.count
    }

    /// Return the map count.
    pub const fn mapcount(&self) -> i32 {
        self.mapcount
    }

    /// Check whether the page is free.
    pub const fn is_free(&self) -> bool {
        self.free
    }

    /// Increment the reference count.
    pub fn get_ref(&mut self) -> Result<()> {
        if self.count >= MAX_REFCOUNT {
            return Err(Error::InvalidArgument);
        }
        self.count += 1;
        self.free = false;
        Ok(())
    }

    /// Decrement the reference count. Returns true if page should be freed.
    pub fn put_ref(&mut self) -> Result<bool> {
        if self.count == REFCOUNT_BIAS {
            return Err(Error::InvalidArgument);
        }
        self.count -= 1;
        if self.count == REFCOUNT_BIAS {
            self.free = true;
            return Ok(true);
        }
        Ok(false)
    }

    /// Try to get a reference. Fails if the page is free.
    pub fn try_get(&mut self) -> Result<()> {
        if self.free || self.count == 0 {
            return Err(Error::Busy);
        }
        self.get_ref()
    }

    /// Increment the map count.
    pub fn map(&mut self) {
        self.mapcount += 1;
    }

    /// Decrement the map count.
    pub fn unmap(&mut self) {
        self.mapcount -= 1;
    }

    /// Check whether the reference count is saturated (potential leak).
    pub const fn is_saturated(&self) -> bool {
        self.count >= REFCOUNT_SATURATED
    }

    /// Check whether the page is mapped.
    pub const fn is_mapped(&self) -> bool {
        self.mapcount > 0
    }
}

impl Default for PageRef {
    fn default() -> Self {
        Self {
            pfn: 0,
            count: 0,
            mapcount: 0,
            free: true,
        }
    }
}

// -------------------------------------------------------------------
// PageRefTable
// -------------------------------------------------------------------

/// Table tracking reference counts for physical pages.
pub struct PageRefTable {
    /// Per-page reference entries.
    entries: [PageRef; MAX_PAGES],
    /// Number of tracked pages.
    count: usize,
    /// Statistics.
    stats: PageRefStats,
}

impl PageRefTable {
    /// Create a new empty table.
    pub const fn new() -> Self {
        Self {
            entries: [const {
                PageRef {
                    pfn: 0,
                    count: 0,
                    mapcount: 0,
                    free: true,
                }
            }; MAX_PAGES],
            count: 0,
            stats: PageRefStats::new(),
        }
    }

    /// Return the number of tracked pages.
    pub const fn count(&self) -> usize {
        self.count
    }

    /// Return the statistics.
    pub const fn stats(&self) -> &PageRefStats {
        &self.stats
    }

    /// Register a page.
    pub fn register(&mut self, pfn: u64) -> Result<()> {
        if self.count >= MAX_PAGES {
            return Err(Error::OutOfMemory);
        }
        self.entries[self.count] = PageRef::new(pfn);
        self.count += 1;
        self.stats.total_gets += 1;
        Ok(())
    }

    /// Get a reference to a page by PFN.
    pub fn get_page(&mut self, pfn: u64) -> Result<()> {
        for idx in 0..self.count {
            if self.entries[idx].pfn() == pfn && !self.entries[idx].is_free() {
                self.entries[idx].get_ref()?;
                self.stats.total_gets += 1;
                return Ok(());
            }
        }
        Err(Error::NotFound)
    }

    /// Put (release) a reference to a page.
    pub fn put_page(&mut self, pfn: u64) -> Result<bool> {
        for idx in 0..self.count {
            if self.entries[idx].pfn() == pfn && !self.entries[idx].is_free() {
                let freed = self.entries[idx].put_ref()?;
                self.stats.total_puts += 1;
                if freed {
                    self.stats.pages_freed += 1;
                }
                return Ok(freed);
            }
        }
        Err(Error::NotFound)
    }

    /// Try to get a reference (speculative).
    pub fn try_get_page(&mut self, pfn: u64) -> Result<()> {
        for idx in 0..self.count {
            if self.entries[idx].pfn() == pfn {
                self.entries[idx].try_get()?;
                self.stats.total_gets += 1;
                self.stats.speculative_gets += 1;
                return Ok(());
            }
        }
        Err(Error::NotFound)
    }

    /// Look up a page's reference count.
    pub fn lookup(&self, pfn: u64) -> Option<&PageRef> {
        for idx in 0..self.count {
            if self.entries[idx].pfn() == pfn {
                return Some(&self.entries[idx]);
            }
        }
        None
    }

    /// Scan for pages with saturated reference counts.
    pub fn find_saturated(&self) -> usize {
        let mut found = 0;
        for idx in 0..self.count {
            if self.entries[idx].is_saturated() {
                found += 1;
            }
        }
        found
    }
}

impl Default for PageRefTable {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// PageRefStats
// -------------------------------------------------------------------

/// Reference counting statistics.
#[derive(Debug, Clone, Copy)]
pub struct PageRefStats {
    /// Total get operations.
    pub total_gets: u64,
    /// Total put operations.
    pub total_puts: u64,
    /// Pages freed (refcount reached zero).
    pub pages_freed: u64,
    /// Speculative gets.
    pub speculative_gets: u64,
}

impl PageRefStats {
    /// Create zero stats.
    pub const fn new() -> Self {
        Self {
            total_gets: 0,
            total_puts: 0,
            pages_freed: 0,
            speculative_gets: 0,
        }
    }

    /// Return the outstanding reference count delta.
    pub const fn outstanding(&self) -> u64 {
        self.total_gets.saturating_sub(self.total_puts)
    }
}

impl Default for PageRefStats {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// Public helpers
// -------------------------------------------------------------------

/// Check whether a page has exactly one reference.
pub fn page_count_one(table: &PageRefTable, pfn: u64) -> bool {
    match table.lookup(pfn) {
        Some(page) => page.count() == 1,
        None => false,
    }
}

/// Check whether a page is mapped into any page table.
pub fn page_mapped(table: &PageRefTable, pfn: u64) -> bool {
    match table.lookup(pfn) {
        Some(page) => page.is_mapped(),
        None => false,
    }
}

/// Return the total number of outstanding references.
pub const fn total_outstanding(table: &PageRefTable) -> u64 {
    table.stats().outstanding()
}
