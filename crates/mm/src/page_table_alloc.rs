// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Page table page allocation.
//!
//! Manages allocation and freeing of pages used for page tables
//! themselves. Each level of the x86_64 4-level page table (PGD, PUD,
//! PMD, PTE) requires a dedicated page to hold entries. This module
//! provides a cache of pre-allocated pages, per-mm accounting, and
//! constructor/destructor hooks.
//!
//! - [`PtLevel`] — page table level
//! - [`PgdCache`] — pre-allocated PGD page cache
//! - [`PageTableAllocator`] — the main allocator
//! - [`PtAllocStats`] — allocation statistics
//!
//! Reference: `.kernelORG/` — `mm/pgtable-generic.c`, `arch/x86/mm/pgtable.c`.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Page size (4 KiB).
const PAGE_SIZE: u64 = 4096;

/// Entries per PGD (4-level, 512 entries).
pub const PTRS_PER_PGD: usize = 512;

/// Entries per PUD.
pub const PTRS_PER_PUD: usize = 512;

/// Entries per PMD.
pub const PTRS_PER_PMD: usize = 512;

/// Entries per PTE.
pub const PTRS_PER_PTE: usize = 512;

/// Number of page table levels.
const NR_PT_LEVELS: usize = 4;

/// Maximum cached PGD pages.
const MAX_PGD_CACHE: usize = 32;

/// Maximum page table pages tracked.
const MAX_PT_PAGES: usize = 1024;

/// Maximum tracked mm structs.
const MAX_MM_STRUCTS: usize = 128;

// -------------------------------------------------------------------
// PtLevel
// -------------------------------------------------------------------

/// Page table level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PtLevel {
    /// PGD (Page Global Directory) — level 4.
    #[default]
    Pgd = 0,
    /// PUD (Page Upper Directory) — level 3.
    Pud = 1,
    /// PMD (Page Middle Directory) — level 2.
    Pmd = 2,
    /// PTE (Page Table Entry) — level 1.
    Pte = 3,
}

impl PtLevel {
    /// Returns the index for this level.
    pub fn as_index(self) -> usize {
        self as usize
    }

    /// Returns the number of entries per page at this level.
    pub fn entries_per_page(self) -> usize {
        match self {
            PtLevel::Pgd => PTRS_PER_PGD,
            PtLevel::Pud => PTRS_PER_PUD,
            PtLevel::Pmd => PTRS_PER_PMD,
            PtLevel::Pte => PTRS_PER_PTE,
        }
    }

    /// Returns the size of virtual address space covered by one entry.
    pub fn entry_coverage(self) -> u64 {
        match self {
            PtLevel::Pgd => 512 * 1024 * 1024 * 1024, // 512 GiB
            PtLevel::Pud => 1024 * 1024 * 1024,       // 1 GiB
            PtLevel::Pmd => 2 * 1024 * 1024,          // 2 MiB
            PtLevel::Pte => PAGE_SIZE,                // 4 KiB
        }
    }

    /// Returns the human-readable name.
    pub fn name(self) -> &'static str {
        match self {
            PtLevel::Pgd => "PGD",
            PtLevel::Pud => "PUD",
            PtLevel::Pmd => "PMD",
            PtLevel::Pte => "PTE",
        }
    }
}

// -------------------------------------------------------------------
// PtPage
// -------------------------------------------------------------------

/// A page used for page table entries.
#[derive(Debug, Clone, Copy, Default)]
struct PtPage {
    /// Physical frame number of this page table page.
    pfn: u64,
    /// Which level this page is used for.
    level: PtLevel,
    /// mm struct ID owning this page.
    mm_id: u32,
    /// Whether this page is in use.
    in_use: bool,
    /// Reference count.
    refcount: u32,
}

// -------------------------------------------------------------------
// PgdCache
// -------------------------------------------------------------------

/// Cache of pre-allocated PGD pages.
///
/// PGD pages are frequently allocated and freed (one per process),
/// so keeping a small cache avoids repeated allocator calls.
pub struct PgdCache {
    /// Cached PGD page PFNs.
    pages: [u64; MAX_PGD_CACHE],
    /// Number of cached pages.
    count: usize,
    /// Total pages allocated through this cache.
    total_allocs: u64,
    /// Total pages freed through this cache.
    total_frees: u64,
}

impl PgdCache {
    /// Creates a new empty PGD cache.
    pub fn new() -> Self {
        Self {
            pages: [0u64; MAX_PGD_CACHE],
            count: 0,
            total_allocs: 0,
            total_frees: 0,
        }
    }

    /// Allocates a PGD page from the cache.
    pub fn alloc(&mut self) -> Option<u64> {
        if self.count == 0 {
            return None;
        }
        self.count -= 1;
        self.total_allocs += 1;
        Some(self.pages[self.count])
    }

    /// Returns a PGD page to the cache.
    pub fn free(&mut self, pfn: u64) -> bool {
        if self.count >= MAX_PGD_CACHE {
            return false;
        }
        self.pages[self.count] = pfn;
        self.count += 1;
        self.total_frees += 1;
        true
    }

    /// Fills the cache with pages.
    pub fn fill(&mut self, pfns: &[u64]) -> usize {
        let mut added = 0;
        for &pfn in pfns {
            if self.count >= MAX_PGD_CACHE {
                break;
            }
            self.pages[self.count] = pfn;
            self.count += 1;
            added += 1;
        }
        added
    }

    /// Returns the number of cached pages.
    pub fn count(&self) -> usize {
        self.count
    }

    /// Returns true if the cache is empty.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
}

impl Default for PgdCache {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// MmPtCount
// -------------------------------------------------------------------

/// Per-mm page table page accounting.
#[derive(Debug, Clone, Copy, Default)]
pub struct MmPtCount {
    /// mm struct ID.
    pub mm_id: u32,
    /// Number of page table pages per level.
    pub counts: [u32; NR_PT_LEVELS],
    /// Total page table pages.
    pub total: u32,
    /// Whether active.
    pub active: bool,
}

impl MmPtCount {
    /// Creates a new per-mm counter.
    pub fn new(mm_id: u32) -> Self {
        Self {
            mm_id,
            counts: [0; NR_PT_LEVELS],
            total: 0,
            active: true,
        }
    }

    /// Increments the count for a level.
    pub fn inc(&mut self, level: PtLevel) {
        self.counts[level.as_index()] += 1;
        self.total += 1;
    }

    /// Decrements the count for a level.
    pub fn dec(&mut self, level: PtLevel) {
        let idx = level.as_index();
        if self.counts[idx] > 0 {
            self.counts[idx] -= 1;
            self.total = self.total.saturating_sub(1);
        }
    }

    /// Returns the count for a level.
    pub fn level_count(&self, level: PtLevel) -> u32 {
        self.counts[level.as_index()]
    }

    /// Returns total memory used by page tables (in bytes).
    pub fn memory_bytes(&self) -> u64 {
        self.total as u64 * PAGE_SIZE
    }
}

// -------------------------------------------------------------------
// PtAllocStats
// -------------------------------------------------------------------

/// Page table allocation statistics.
#[derive(Debug, Clone, Copy, Default)]
pub struct PtAllocStats {
    /// Allocations per level.
    pub allocs: [u64; NR_PT_LEVELS],
    /// Frees per level.
    pub frees: [u64; NR_PT_LEVELS],
    /// PGD cache hits.
    pub cache_hits: u64,
    /// PGD cache misses.
    pub cache_misses: u64,
    /// Total pages currently allocated.
    pub total_allocated: u64,
}

impl PtAllocStats {
    /// Resets all statistics.
    pub fn reset(&mut self) {
        *self = Self::default();
    }
}

// -------------------------------------------------------------------
// PageTableAllocator
// -------------------------------------------------------------------

/// Page table page allocator.
///
/// Manages allocation and freeing of pages used for page tables.
/// Uses a PGD cache for fast PGD allocation and tracks per-mm
/// page table page counts.
pub struct PageTableAllocator {
    /// PGD cache.
    pgd_cache: PgdCache,
    /// Allocated page table pages.
    pages: [PtPage; MAX_PT_PAGES],
    /// Number of allocated pages.
    nr_pages: usize,
    /// Per-mm counters.
    mm_counts: [MmPtCount; MAX_MM_STRUCTS],
    /// Number of active mm structs.
    nr_mm: usize,
    /// Next PFN to allocate.
    next_pfn: u64,
    /// Statistics.
    stats: PtAllocStats,
}

impl PageTableAllocator {
    /// Creates a new page table allocator.
    pub fn new() -> Self {
        Self {
            pgd_cache: PgdCache::new(),
            pages: [PtPage::default(); MAX_PT_PAGES],
            nr_pages: 0,
            mm_counts: [MmPtCount::default(); MAX_MM_STRUCTS],
            nr_mm: 0,
            next_pfn: 0x100_0000, // Start at 16 MiB.
            stats: PtAllocStats::default(),
        }
    }

    /// Allocates a page table page.
    pub fn alloc_page_table(&mut self, level: PtLevel, mm_id: u32) -> Result<u64> {
        // For PGD, try the cache first.
        if level == PtLevel::Pgd {
            if let Some(pfn) = self.pgd_cache.alloc() {
                self.stats.cache_hits += 1;
                self.record_alloc(pfn, level, mm_id);
                return Ok(pfn);
            }
            self.stats.cache_misses += 1;
        }

        // Allocate a new page.
        if self.nr_pages >= MAX_PT_PAGES {
            return Err(Error::OutOfMemory);
        }

        let pfn = self.next_pfn;
        self.next_pfn += 1;

        // Constructor: zero-fill the page (conceptual).
        self.record_alloc(pfn, level, mm_id);

        Ok(pfn)
    }

    /// Frees a page table page.
    pub fn free_page_table(&mut self, pfn: u64, level: PtLevel, mm_id: u32) -> Result<()> {
        // Find and remove the page.
        let mut found = false;
        for page in &mut self.pages {
            if page.in_use && page.pfn == pfn {
                page.in_use = false;
                page.refcount = 0;
                self.nr_pages = self.nr_pages.saturating_sub(1);
                found = true;
                break;
            }
        }

        if !found {
            return Err(Error::NotFound);
        }

        self.stats.frees[level.as_index()] += 1;
        self.stats.total_allocated = self.stats.total_allocated.saturating_sub(1);

        // Update mm counter.
        self.dec_mm_count(mm_id, level);

        // For PGD, return to cache if possible.
        if level == PtLevel::Pgd {
            self.pgd_cache.free(pfn);
        }

        Ok(())
    }

    /// Records an allocation.
    fn record_alloc(&mut self, pfn: u64, level: PtLevel, mm_id: u32) {
        for page in &mut self.pages {
            if !page.in_use {
                page.pfn = pfn;
                page.level = level;
                page.mm_id = mm_id;
                page.in_use = true;
                page.refcount = 1;
                self.nr_pages += 1;
                break;
            }
        }
        self.stats.allocs[level.as_index()] += 1;
        self.stats.total_allocated += 1;
        self.inc_mm_count(mm_id, level);
    }

    /// Increments the per-mm counter.
    fn inc_mm_count(&mut self, mm_id: u32, level: PtLevel) {
        for mc in &mut self.mm_counts {
            if mc.active && mc.mm_id == mm_id {
                mc.inc(level);
                return;
            }
        }
        // Create new entry.
        for mc in &mut self.mm_counts {
            if !mc.active {
                *mc = MmPtCount::new(mm_id);
                mc.inc(level);
                self.nr_mm += 1;
                return;
            }
        }
    }

    /// Decrements the per-mm counter.
    fn dec_mm_count(&mut self, mm_id: u32, level: PtLevel) {
        for mc in &mut self.mm_counts {
            if mc.active && mc.mm_id == mm_id {
                mc.dec(level);
                return;
            }
        }
    }

    /// Returns per-mm page table accounting.
    pub fn mm_pt_count(&self, mm_id: u32) -> Option<&MmPtCount> {
        self.mm_counts
            .iter()
            .find(|mc| mc.active && mc.mm_id == mm_id)
    }

    /// Returns the PGD cache.
    pub fn pgd_cache(&self) -> &PgdCache {
        &self.pgd_cache
    }

    /// Returns a mutable reference to the PGD cache.
    pub fn pgd_cache_mut(&mut self) -> &mut PgdCache {
        &mut self.pgd_cache
    }

    /// Returns statistics.
    pub fn stats(&self) -> &PtAllocStats {
        &self.stats
    }

    /// Returns the number of allocated page table pages.
    pub fn nr_allocated(&self) -> usize {
        self.nr_pages
    }
}

impl Default for PageTableAllocator {
    fn default() -> Self {
        Self::new()
    }
}
