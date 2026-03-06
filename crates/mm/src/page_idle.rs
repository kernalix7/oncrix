// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Page idle tracking subsystem.
//!
//! Tracks which physical pages have been accessed over a given period,
//! enabling working set estimation and proactive reclaim decisions.
//! The kernel exposes a per-page "idle" flag: user space (or kswapd)
//! marks all pages idle, waits, then checks which pages were
//! re-accessed (and thus cleared their idle flag via the hardware
//! Accessed bit).
//!
//! # Design
//!
//! A bitmap-based tracker covers up to [`MAX_TRACKED_PAGES`] physical
//! page frame numbers. Each bit in the idle bitmap indicates whether
//! the corresponding PFN is considered idle (1 = idle, 0 = accessed).
//!
//! - [`IdleBitmap`] — compact bitmap with word-level operations
//! - [`PageIdleFlags`] — per-page idle state
//! - [`IdlePageEntry`] — per-page metadata (PFN, access counter,
//!   generation, flags)
//! - [`IdleScanConfig`] — tunables for the idle scanner
//! - [`WorkingSetEstimate`] — result of a working-set measurement
//! - [`IdleScanStats`] — aggregate scanning statistics
//! - [`PageIdleTracker`] — top-level tracker combining bitmap, page
//!   table, config, and statistics
//!
//! # Usage
//!
//! 1. Register PFNs via [`PageIdleTracker::register_page`].
//! 2. Call [`PageIdleTracker::mark_all_idle`] to set every tracked
//!    page's idle flag.
//! 3. After a measurement interval, call
//!    [`PageIdleTracker::scan_accessed`] to harvest hardware Accessed
//!    bits: pages that were touched will have their idle flag cleared.
//! 4. Query results via [`PageIdleTracker::estimate_working_set`] or
//!    per-page with [`PageIdleTracker::is_page_idle`].
//!
//! Reference: Linux `mm/page_idle.c`, `include/linux/page_idle.h`.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Maximum number of pages the idle tracker can manage.
const MAX_TRACKED_PAGES: usize = 32768;

/// Number of bits per word in the idle bitmap.
const BITS_PER_WORD: usize = 64;

/// Number of words required for the idle bitmap.
const BITMAP_WORDS: usize = MAX_TRACKED_PAGES / BITS_PER_WORD;

/// Standard page size in bytes (4 KiB).
const PAGE_SIZE: u64 = 4096;

/// Maximum number of NUMA nodes for per-node statistics.
const MAX_NUMA_NODES: usize = 4;

/// Default scan batch size (pages per scan pass).
const DEFAULT_SCAN_BATCH: usize = 256;

/// Default idle threshold (generations without access before
/// considered cold).
const DEFAULT_IDLE_THRESHOLD: u32 = 3;

/// Maximum generation counter value before wrap-around.
const MAX_GENERATION: u64 = u64::MAX;

// -------------------------------------------------------------------
// PageIdleFlags
// -------------------------------------------------------------------

/// Per-page idle tracking flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PageIdleFlags(u8);

impl PageIdleFlags {
    /// Page is currently marked idle (not accessed since last mark).
    pub const IDLE: Self = Self(1 << 0);
    /// Page was recently accessed (hardware Accessed bit seen).
    pub const YOUNG: Self = Self(1 << 1);
    /// Page is registered for idle tracking.
    pub const TRACKED: Self = Self(1 << 2);
    /// Page is pinned (excluded from idle-based reclaim).
    pub const PINNED: Self = Self(1 << 3);
    /// Page belongs to a huge page (2 MiB).
    pub const HUGE: Self = Self(1 << 4);

    /// Empty flag set.
    pub const fn empty() -> Self {
        Self(0)
    }

    /// Check whether the given flag is set.
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    /// Set the given flag.
    pub const fn insert(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// Clear the given flag.
    pub const fn remove(self, other: Self) -> Self {
        Self(self.0 & !other.0)
    }
}

impl Default for PageIdleFlags {
    fn default() -> Self {
        Self::empty()
    }
}

// -------------------------------------------------------------------
// IdlePageEntry
// -------------------------------------------------------------------

/// Per-page metadata tracked by the idle scanner.
#[derive(Debug, Clone, Copy)]
pub struct IdlePageEntry {
    /// Physical page frame number.
    pub pfn: u64,
    /// Number of consecutive scans where the page was found idle.
    pub idle_count: u32,
    /// Number of times the page was found accessed.
    pub access_count: u64,
    /// Generation when this page was last found accessed.
    pub last_access_generation: u64,
    /// Generation when this page was first registered.
    pub registered_generation: u64,
    /// NUMA node that owns this page.
    pub numa_node: u8,
    /// Current flags for this page.
    pub flags: PageIdleFlags,
}

impl Default for IdlePageEntry {
    fn default() -> Self {
        Self {
            pfn: 0,
            idle_count: 0,
            access_count: 0,
            last_access_generation: 0,
            registered_generation: 0,
            numa_node: 0,
            flags: PageIdleFlags::empty(),
        }
    }
}

// -------------------------------------------------------------------
// IdleBitmap
// -------------------------------------------------------------------

/// Compact bitmap for tracking idle status of up to
/// [`MAX_TRACKED_PAGES`] pages.
///
/// Each bit position corresponds to a slot index in the page table
/// (not directly to a PFN). Bit = 1 means the page is idle.
pub struct IdleBitmap {
    /// Bitmap words.
    words: [u64; BITMAP_WORDS],
}

impl IdleBitmap {
    /// Create a new zeroed bitmap (all pages considered accessed).
    pub const fn new() -> Self {
        Self {
            words: [0u64; BITMAP_WORDS],
        }
    }

    /// Set a bit (mark page idle).
    pub fn set(&mut self, index: usize) {
        if index < MAX_TRACKED_PAGES {
            let word = index / BITS_PER_WORD;
            let bit = index % BITS_PER_WORD;
            self.words[word] |= 1u64 << bit;
        }
    }

    /// Clear a bit (mark page accessed).
    pub fn clear(&mut self, index: usize) {
        if index < MAX_TRACKED_PAGES {
            let word = index / BITS_PER_WORD;
            let bit = index % BITS_PER_WORD;
            self.words[word] &= !(1u64 << bit);
        }
    }

    /// Test whether a bit is set (page is idle).
    pub fn test(&self, index: usize) -> bool {
        if index < MAX_TRACKED_PAGES {
            let word = index / BITS_PER_WORD;
            let bit = index % BITS_PER_WORD;
            (self.words[word] >> bit) & 1 == 1
        } else {
            false
        }
    }

    /// Set all bits (mark all tracked pages idle).
    pub fn set_all(&mut self) {
        for w in &mut self.words {
            *w = u64::MAX;
        }
    }

    /// Clear all bits (mark all tracked pages accessed).
    pub fn clear_all(&mut self) {
        for w in &mut self.words {
            *w = 0;
        }
    }

    /// Count the number of set bits (idle pages).
    pub fn count_idle(&self) -> usize {
        let mut total = 0usize;
        for &w in &self.words {
            total += w.count_ones() as usize;
        }
        total
    }

    /// Count the number of clear bits within the first `limit` bits.
    pub fn count_accessed(&self, limit: usize) -> usize {
        let effective = if limit > MAX_TRACKED_PAGES {
            MAX_TRACKED_PAGES
        } else {
            limit
        };
        let full_words = effective / BITS_PER_WORD;
        let remaining = effective % BITS_PER_WORD;
        let mut idle = 0usize;
        for i in 0..full_words {
            idle += self.words[i].count_ones() as usize;
        }
        if remaining > 0 && full_words < BITMAP_WORDS {
            let mask = (1u64 << remaining) - 1;
            idle += (self.words[full_words] & mask).count_ones() as usize;
        }
        effective.saturating_sub(idle)
    }
}

impl Default for IdleBitmap {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// IdleScanConfig
// -------------------------------------------------------------------

/// Configuration for the idle page scanner.
#[derive(Debug, Clone, Copy)]
pub struct IdleScanConfig {
    /// Number of pages to scan per batch.
    pub batch_size: usize,
    /// Number of idle generations before a page is considered cold.
    pub idle_threshold: u32,
    /// Whether to include huge pages in the scan.
    pub scan_huge_pages: bool,
    /// Whether to skip pinned pages during scanning.
    pub skip_pinned: bool,
    /// Minimum PFN to scan (inclusive).
    pub min_pfn: u64,
    /// Maximum PFN to scan (exclusive, 0 = no limit).
    pub max_pfn: u64,
}

impl Default for IdleScanConfig {
    fn default() -> Self {
        Self {
            batch_size: DEFAULT_SCAN_BATCH,
            idle_threshold: DEFAULT_IDLE_THRESHOLD,
            scan_huge_pages: true,
            skip_pinned: true,
            min_pfn: 0,
            max_pfn: 0,
        }
    }
}

// -------------------------------------------------------------------
// WorkingSetEstimate
// -------------------------------------------------------------------

/// Result of a working-set size estimation.
#[derive(Debug, Clone, Copy, Default)]
pub struct WorkingSetEstimate {
    /// Total number of tracked pages.
    pub total_tracked: usize,
    /// Number of pages found accessed during the measurement window.
    pub accessed_pages: usize,
    /// Number of pages found idle (not accessed).
    pub idle_pages: usize,
    /// Estimated working set size in bytes.
    pub working_set_bytes: u64,
    /// Estimated idle memory in bytes.
    pub idle_bytes: u64,
    /// Generation number when this estimate was computed.
    pub generation: u64,
    /// Per-NUMA-node accessed page counts.
    pub per_node_accessed: [usize; MAX_NUMA_NODES],
}

// -------------------------------------------------------------------
// IdleScanStats
// -------------------------------------------------------------------

/// Aggregate statistics from the idle scanner.
#[derive(Debug, Clone, Copy, Default)]
pub struct IdleScanStats {
    /// Number of full scan cycles completed.
    pub scans_completed: u64,
    /// Total pages examined across all scans.
    pub pages_scanned: u64,
    /// Total pages found accessed across all scans.
    pub pages_found_accessed: u64,
    /// Total pages found idle across all scans.
    pub pages_found_idle: u64,
    /// Number of pages promoted from idle to accessed.
    pub promotions: u64,
    /// Number of pages demoted from accessed to idle.
    pub demotions: u64,
    /// Number of pages that exceeded the cold threshold.
    pub cold_pages_detected: u64,
    /// Number of huge pages encountered.
    pub huge_pages_scanned: u64,
    /// Number of pinned pages skipped.
    pub pinned_skipped: u64,
    /// Number of pages registered.
    pub total_registered: u64,
    /// Number of pages unregistered.
    pub total_unregistered: u64,
}

// -------------------------------------------------------------------
// PageIdleTracker
// -------------------------------------------------------------------

/// Top-level page idle tracking subsystem.
///
/// Manages the idle bitmap, per-page metadata, scan configuration,
/// and accumulated statistics. Pages are registered by PFN and
/// assigned to bitmap slots via a simple linear scan of the page
/// table.
pub struct PageIdleTracker {
    /// Idle bitmap: bit set = page idle.
    bitmap: IdleBitmap,
    /// Per-page metadata array.
    pages: [IdlePageEntry; MAX_TRACKED_PAGES],
    /// Number of pages currently registered.
    page_count: usize,
    /// Monotonic generation counter incremented on each scan.
    generation: u64,
    /// Scanner configuration.
    config: IdleScanConfig,
    /// Accumulated statistics.
    stats: IdleScanStats,
    /// Whether the tracker is currently enabled.
    enabled: bool,
}

impl PageIdleTracker {
    /// Create a new idle tracker with default configuration.
    pub fn new() -> Self {
        Self {
            bitmap: IdleBitmap::new(),
            pages: [IdlePageEntry::default(); MAX_TRACKED_PAGES],
            page_count: 0,
            generation: 0,
            config: IdleScanConfig::default(),
            stats: IdleScanStats::default(),
            enabled: false,
        }
    }

    /// Create a new idle tracker with custom configuration.
    pub fn with_config(config: IdleScanConfig) -> Self {
        Self {
            bitmap: IdleBitmap::new(),
            pages: [IdlePageEntry::default(); MAX_TRACKED_PAGES],
            page_count: 0,
            generation: 0,
            config,
            stats: IdleScanStats::default(),
            enabled: false,
        }
    }

    /// Enable the idle tracker.
    pub fn enable(&mut self) {
        self.enabled = true;
    }

    /// Disable the idle tracker.
    pub fn disable(&mut self) {
        self.enabled = false;
    }

    /// Return whether the tracker is enabled.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Return the current generation counter.
    pub fn generation(&self) -> u64 {
        self.generation
    }

    /// Return the number of registered pages.
    pub fn page_count(&self) -> usize {
        self.page_count
    }

    /// Return a reference to the current configuration.
    pub fn config(&self) -> &IdleScanConfig {
        &self.config
    }

    /// Update the scanner configuration.
    pub fn set_config(&mut self, config: IdleScanConfig) {
        self.config = config;
    }

    /// Return a snapshot of the accumulated statistics.
    pub fn stats(&self) -> IdleScanStats {
        self.stats
    }

    /// Register a page for idle tracking.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the page table is full.
    /// Returns [`Error::AlreadyExists`] if the PFN is already
    /// registered.
    /// Returns [`Error::InvalidArgument`] if `pfn` is zero.
    pub fn register_page(&mut self, pfn: u64, numa_node: u8) -> Result<usize> {
        if pfn == 0 {
            return Err(Error::InvalidArgument);
        }
        if self.page_count >= MAX_TRACKED_PAGES {
            return Err(Error::OutOfMemory);
        }
        // Check for duplicate PFN.
        for i in 0..self.page_count {
            if self.pages[i].pfn == pfn {
                return Err(Error::AlreadyExists);
            }
        }
        let slot = self.page_count;
        self.pages[slot] = IdlePageEntry {
            pfn,
            idle_count: 0,
            access_count: 0,
            last_access_generation: self.generation,
            registered_generation: self.generation,
            numa_node,
            flags: PageIdleFlags::TRACKED,
        };
        self.page_count += 1;
        self.stats.total_registered += 1;
        Ok(slot)
    }

    /// Unregister a page by its PFN.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the PFN is not registered.
    pub fn unregister_page(&mut self, pfn: u64) -> Result<()> {
        let pos = self.find_page(pfn).ok_or(Error::NotFound)?;
        // Swap-remove.
        self.bitmap.clear(pos);
        if pos < self.page_count - 1 {
            let last = self.page_count - 1;
            self.pages[pos] = self.pages[last];
            // Move the bitmap bit for the swapped entry.
            if self.bitmap.test(last) {
                self.bitmap.set(pos);
            }
            self.bitmap.clear(last);
        }
        self.page_count -= 1;
        self.stats.total_unregistered += 1;
        Ok(())
    }

    /// Mark all registered pages as idle.
    ///
    /// This sets every tracked page's idle flag in the bitmap. After
    /// waiting a measurement interval, call [`scan_accessed`] to
    /// determine which pages were actually touched.
    pub fn mark_all_idle(&mut self) {
        for i in 0..self.page_count {
            self.bitmap.set(i);
            self.pages[i].flags = self.pages[i].flags.insert(PageIdleFlags::IDLE);
        }
    }

    /// Mark a single page as idle by PFN.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the PFN is not registered.
    pub fn mark_idle(&mut self, pfn: u64) -> Result<()> {
        let pos = self.find_page(pfn).ok_or(Error::NotFound)?;
        self.bitmap.set(pos);
        self.pages[pos].flags = self.pages[pos].flags.insert(PageIdleFlags::IDLE);
        Ok(())
    }

    /// Clear the idle flag for a page (mark it as accessed).
    ///
    /// Called when a hardware Accessed bit is observed for this PFN.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the PFN is not registered.
    pub fn mark_accessed(&mut self, pfn: u64) -> Result<()> {
        let pos = self.find_page(pfn).ok_or(Error::NotFound)?;
        self.bitmap.clear(pos);
        self.pages[pos].flags = self.pages[pos]
            .flags
            .remove(PageIdleFlags::IDLE)
            .insert(PageIdleFlags::YOUNG);
        self.pages[pos].access_count += 1;
        self.pages[pos].last_access_generation = self.generation;
        self.pages[pos].idle_count = 0;
        Ok(())
    }

    /// Query whether a page is currently idle.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the PFN is not registered.
    pub fn is_page_idle(&self, pfn: u64) -> Result<bool> {
        let pos = self.find_page(pfn).ok_or(Error::NotFound)?;
        Ok(self.bitmap.test(pos))
    }

    /// Set the pinned flag for a page, excluding it from idle-based
    /// reclaim.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the PFN is not registered.
    pub fn pin_page(&mut self, pfn: u64) -> Result<()> {
        let pos = self.find_page(pfn).ok_or(Error::NotFound)?;
        self.pages[pos].flags = self.pages[pos].flags.insert(PageIdleFlags::PINNED);
        Ok(())
    }

    /// Clear the pinned flag for a page.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the PFN is not registered.
    pub fn unpin_page(&mut self, pfn: u64) -> Result<()> {
        let pos = self.find_page(pfn).ok_or(Error::NotFound)?;
        self.pages[pos].flags = self.pages[pos].flags.remove(PageIdleFlags::PINNED);
        Ok(())
    }

    /// Mark a page as belonging to a huge page.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the PFN is not registered.
    pub fn set_huge(&mut self, pfn: u64) -> Result<()> {
        let pos = self.find_page(pfn).ok_or(Error::NotFound)?;
        self.pages[pos].flags = self.pages[pos].flags.insert(PageIdleFlags::HUGE);
        Ok(())
    }

    /// Perform a scan pass: check each tracked page's bitmap state,
    /// update idle counts, and detect promotions/demotions.
    ///
    /// A simulated hardware Accessed bit is represented by the
    /// `accessed_pfns` slice: PFNs in this list are treated as having
    /// been accessed since the last scan.
    ///
    /// Returns the number of pages found accessed during this scan.
    pub fn scan_accessed(&mut self, accessed_pfns: &[u64]) -> usize {
        if !self.enabled {
            return 0;
        }

        // Build a local set of accessed PFNs for O(n) lookup by
        // marking in a temporary bitmap.
        let mut accessed_set = [false; MAX_TRACKED_PAGES];
        for &pfn in accessed_pfns {
            if let Some(pos) = self.find_page(pfn) {
                accessed_set[pos] = true;
            }
        }

        let mut found_accessed = 0usize;
        let batch = if self.config.batch_size == 0 {
            self.page_count
        } else {
            self.config.batch_size.min(self.page_count)
        };

        for i in 0..batch {
            if i >= self.page_count {
                break;
            }
            let entry = &self.pages[i];
            if self.config.skip_pinned && entry.flags.contains(PageIdleFlags::PINNED) {
                self.stats.pinned_skipped += 1;
                continue;
            }
            if !self.config.scan_huge_pages && entry.flags.contains(PageIdleFlags::HUGE) {
                continue;
            }
            if entry.flags.contains(PageIdleFlags::HUGE) {
                self.stats.huge_pages_scanned += 1;
            }

            if accessed_set[i] {
                // Page was accessed: clear idle flag.
                self.bitmap.clear(i);
                let was_idle = self.pages[i].flags.contains(PageIdleFlags::IDLE);
                self.pages[i].flags = self.pages[i]
                    .flags
                    .remove(PageIdleFlags::IDLE)
                    .insert(PageIdleFlags::YOUNG);
                self.pages[i].access_count += 1;
                self.pages[i].last_access_generation = self.generation;
                self.pages[i].idle_count = 0;
                if was_idle {
                    self.stats.promotions += 1;
                }
                found_accessed += 1;
                self.stats.pages_found_accessed += 1;
            } else {
                // Page was not accessed: stays idle.
                self.bitmap.set(i);
                let was_young = self.pages[i].flags.contains(PageIdleFlags::YOUNG);
                self.pages[i].flags = self.pages[i]
                    .flags
                    .insert(PageIdleFlags::IDLE)
                    .remove(PageIdleFlags::YOUNG);
                self.pages[i].idle_count = self.pages[i].idle_count.saturating_add(1);
                if was_young {
                    self.stats.demotions += 1;
                }
                if self.pages[i].idle_count >= self.config.idle_threshold {
                    self.stats.cold_pages_detected += 1;
                }
                self.stats.pages_found_idle += 1;
            }
            self.stats.pages_scanned += 1;
        }

        self.generation = self.generation.wrapping_add(1);
        self.stats.scans_completed += 1;
        found_accessed
    }

    /// Estimate the current working set size.
    ///
    /// Counts the number of accessed (non-idle) pages across all
    /// tracked pages and returns a [`WorkingSetEstimate`].
    pub fn estimate_working_set(&self) -> WorkingSetEstimate {
        let mut accessed = 0usize;
        let mut idle = 0usize;
        let mut per_node = [0usize; MAX_NUMA_NODES];

        for i in 0..self.page_count {
            if self.bitmap.test(i) {
                idle += 1;
            } else {
                accessed += 1;
                let node = self.pages[i].numa_node as usize;
                if node < MAX_NUMA_NODES {
                    per_node[node] += 1;
                }
            }
        }

        WorkingSetEstimate {
            total_tracked: self.page_count,
            accessed_pages: accessed,
            idle_pages: idle,
            working_set_bytes: (accessed as u64) * PAGE_SIZE,
            idle_bytes: (idle as u64) * PAGE_SIZE,
            generation: self.generation,
            per_node_accessed: per_node,
        }
    }

    /// Return a list of cold PFNs — pages whose idle count exceeds
    /// the configured threshold.
    ///
    /// Fills `out` with up to `out.len()` cold PFNs and returns the
    /// number written.
    pub fn collect_cold_pages(&self, out: &mut [u64]) -> usize {
        let mut written = 0;
        for i in 0..self.page_count {
            if written >= out.len() {
                break;
            }
            if self.pages[i].idle_count >= self.config.idle_threshold
                && !self.pages[i].flags.contains(PageIdleFlags::PINNED)
            {
                out[written] = self.pages[i].pfn;
                written += 1;
            }
        }
        written
    }

    /// Collect PFNs suitable for kswapd reclaim: cold and non-pinned.
    ///
    /// Returns the number of candidate PFNs written to `out`.
    pub fn collect_reclaim_candidates(&self, out: &mut [u64], min_idle_generations: u32) -> usize {
        let threshold = if min_idle_generations == 0 {
            self.config.idle_threshold
        } else {
            min_idle_generations
        };
        let mut written = 0;
        for i in 0..self.page_count {
            if written >= out.len() {
                break;
            }
            let entry = &self.pages[i];
            if entry.flags.contains(PageIdleFlags::PINNED) {
                continue;
            }
            if entry.idle_count >= threshold && self.bitmap.test(i) {
                out[written] = entry.pfn;
                written += 1;
            }
        }
        written
    }

    /// Return per-page metadata for a given PFN.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the PFN is not registered.
    pub fn get_page_info(&self, pfn: u64) -> Result<&IdlePageEntry> {
        let pos = self.find_page(pfn).ok_or(Error::NotFound)?;
        Ok(&self.pages[pos])
    }

    /// Return the PFN-to-physical-address mapping for a given PFN.
    pub fn pfn_to_phys(pfn: u64) -> u64 {
        pfn * PAGE_SIZE
    }

    /// Return the PFN from a physical address.
    pub fn phys_to_pfn(phys: u64) -> u64 {
        phys / PAGE_SIZE
    }

    /// Reset all statistics counters.
    pub fn reset_stats(&mut self) {
        self.stats = IdleScanStats::default();
    }

    /// Reset the entire tracker: unregister all pages, clear bitmap,
    /// reset generation and stats.
    pub fn reset(&mut self) {
        self.bitmap.clear_all();
        self.pages = [IdlePageEntry::default(); MAX_TRACKED_PAGES];
        self.page_count = 0;
        self.generation = 0;
        self.stats = IdleScanStats::default();
    }

    /// Look up the slot index for a given PFN.
    fn find_page(&self, pfn: u64) -> Option<usize> {
        for i in 0..self.page_count {
            if self.pages[i].pfn == pfn {
                return Some(i);
            }
        }
        None
    }
}

impl Default for PageIdleTracker {
    fn default() -> Self {
        Self::new()
    }
}
