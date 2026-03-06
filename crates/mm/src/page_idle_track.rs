// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Page idle tracking.
//!
//! The idle page tracking feature exposes `/sys/kernel/mm/page_idle/`
//! which allows user space to mark pages as idle and later query which
//! pages have been accessed since the mark. This is used for
//! working-set estimation and memory advisor tools (e.g., DAMON).
//!
//! # Design
//!
//! ```text
//!  1. User marks pages idle via /sys/kernel/mm/page_idle/bitmap
//!     → clear PTE accessed bit for each page
//!
//!  2. Wait for some time interval
//!
//!  3. User reads bitmap
//!     → if PTE accessed bit is set → page was accessed (not idle)
//!     → if PTE accessed bit is clear → page is idle
//! ```
//!
//! # Key Types
//!
//! - [`IdleBitmapEntry`] — idle/accessed state for a block of 64 pages
//! - [`PageIdleTracker`] — manages idle tracking
//! - [`PageIdleTrackStats`] — tracking statistics
//!
//! Reference: Linux `mm/page_idle.c`, `Documentation/admin-guide/mm/idle_page_tracking.rst`.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Pages per bitmap entry (64 bits per u64).
const PAGES_PER_ENTRY: usize = 64;

/// Maximum bitmap entries.
const MAX_BITMAP_ENTRIES: usize = 4096;

/// Maximum total trackable pages.
const MAX_TRACKABLE_PAGES: usize = MAX_BITMAP_ENTRIES * PAGES_PER_ENTRY;

/// Page size.
const PAGE_SIZE: u64 = 4096;

// -------------------------------------------------------------------
// IdleBitmapEntry
// -------------------------------------------------------------------

/// Idle/accessed state for a block of 64 pages.
#[derive(Debug, Clone, Copy)]
pub struct IdleBitmapEntry {
    /// Start PFN for this block.
    base_pfn: u64,
    /// Bitmap: bit set = page is idle.
    idle_bits: u64,
    /// Bitmap: bit set = page was accessed since marking idle.
    accessed_bits: u64,
}

impl IdleBitmapEntry {
    /// Create a new entry.
    pub const fn new(base_pfn: u64) -> Self {
        Self {
            base_pfn,
            idle_bits: 0,
            accessed_bits: 0,
        }
    }

    /// Return the base PFN.
    pub const fn base_pfn(&self) -> u64 {
        self.base_pfn
    }

    /// Return the idle bitmap.
    pub const fn idle_bits(&self) -> u64 {
        self.idle_bits
    }

    /// Return the accessed bitmap.
    pub const fn accessed_bits(&self) -> u64 {
        self.accessed_bits
    }

    /// Mark a page as idle (by bit position).
    pub fn mark_idle(&mut self, bit: usize) {
        if bit < PAGES_PER_ENTRY {
            self.idle_bits |= 1u64 << bit;
            self.accessed_bits &= !(1u64 << bit);
        }
    }

    /// Mark all 64 pages as idle.
    pub fn mark_all_idle(&mut self) {
        self.idle_bits = u64::MAX;
        self.accessed_bits = 0;
    }

    /// Record that a page was accessed.
    pub fn record_access(&mut self, bit: usize) {
        if bit < PAGES_PER_ENTRY {
            self.accessed_bits |= 1u64 << bit;
            self.idle_bits &= !(1u64 << bit);
        }
    }

    /// Check whether a specific page is idle.
    pub const fn is_idle(&self, bit: usize) -> bool {
        if bit >= PAGES_PER_ENTRY {
            return false;
        }
        (self.idle_bits >> bit) & 1 == 1
    }

    /// Check whether a specific page was accessed.
    pub const fn was_accessed(&self, bit: usize) -> bool {
        if bit >= PAGES_PER_ENTRY {
            return false;
        }
        (self.accessed_bits >> bit) & 1 == 1
    }

    /// Count idle pages.
    pub const fn idle_count(&self) -> u32 {
        self.idle_bits.count_ones()
    }

    /// Count accessed pages.
    pub const fn accessed_count(&self) -> u32 {
        self.accessed_bits.count_ones()
    }

    /// Clear all state.
    pub fn clear(&mut self) {
        self.idle_bits = 0;
        self.accessed_bits = 0;
    }
}

impl Default for IdleBitmapEntry {
    fn default() -> Self {
        Self {
            base_pfn: 0,
            idle_bits: 0,
            accessed_bits: 0,
        }
    }
}

// -------------------------------------------------------------------
// PageIdleTrackStats
// -------------------------------------------------------------------

/// Tracking statistics.
#[derive(Debug, Clone, Copy)]
pub struct PageIdleTrackStats {
    /// Total pages marked idle.
    pub pages_marked_idle: u64,
    /// Total pages found accessed.
    pub pages_accessed: u64,
    /// Total pages still idle after check.
    pub pages_still_idle: u64,
    /// Total scan cycles.
    pub scan_cycles: u64,
    /// Total bitmap entries used.
    pub entries_used: u64,
}

impl PageIdleTrackStats {
    /// Create zero stats.
    pub const fn new() -> Self {
        Self {
            pages_marked_idle: 0,
            pages_accessed: 0,
            pages_still_idle: 0,
            scan_cycles: 0,
            entries_used: 0,
        }
    }

    /// Idle ratio as percent.
    pub const fn idle_ratio_pct(&self) -> u64 {
        let total = self.pages_accessed + self.pages_still_idle;
        if total == 0 {
            return 0;
        }
        self.pages_still_idle * 100 / total
    }
}

impl Default for PageIdleTrackStats {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// PageIdleTracker
// -------------------------------------------------------------------

/// Manages page idle tracking.
pub struct PageIdleTracker {
    /// Bitmap entries.
    entries: [IdleBitmapEntry; MAX_BITMAP_ENTRIES],
    /// Number of active entries.
    count: usize,
    /// Whether tracking is enabled.
    enabled: bool,
    /// Statistics.
    stats: PageIdleTrackStats,
}

impl PageIdleTracker {
    /// Create a new tracker.
    pub const fn new() -> Self {
        Self {
            entries: [const {
                IdleBitmapEntry {
                    base_pfn: 0,
                    idle_bits: 0,
                    accessed_bits: 0,
                }
            }; MAX_BITMAP_ENTRIES],
            count: 0,
            enabled: false,
            stats: PageIdleTrackStats::new(),
        }
    }

    /// Return the statistics.
    pub const fn stats(&self) -> &PageIdleTrackStats {
        &self.stats
    }

    /// Return the entry count.
    pub const fn count(&self) -> usize {
        self.count
    }

    /// Check whether enabled.
    pub const fn enabled(&self) -> bool {
        self.enabled
    }

    /// Enable tracking.
    pub fn enable(&mut self) {
        self.enabled = true;
    }

    /// Disable tracking.
    pub fn disable(&mut self) {
        self.enabled = false;
    }

    /// Register a PFN range for tracking.
    pub fn register_range(&mut self, base_pfn: u64, page_count: u64) -> Result<()> {
        if !self.enabled {
            return Err(Error::PermissionDenied);
        }
        let entries_needed = ((page_count as usize) + PAGES_PER_ENTRY - 1) / PAGES_PER_ENTRY;
        if self.count + entries_needed > MAX_BITMAP_ENTRIES {
            return Err(Error::OutOfMemory);
        }
        for idx in 0..entries_needed {
            let entry_pfn = base_pfn + (idx * PAGES_PER_ENTRY) as u64;
            self.entries[self.count] = IdleBitmapEntry::new(entry_pfn);
            self.count += 1;
        }
        self.stats.entries_used += entries_needed as u64;
        Ok(())
    }

    /// Mark a PFN range as idle.
    pub fn mark_idle(&mut self, start_pfn: u64, page_count: u64) {
        for idx in 0..self.count {
            let base = self.entries[idx].base_pfn();
            for bit in 0..PAGES_PER_ENTRY {
                let pfn = base + bit as u64;
                if pfn >= start_pfn && pfn < start_pfn + page_count {
                    self.entries[idx].mark_idle(bit);
                    self.stats.pages_marked_idle += 1;
                }
            }
        }
    }

    /// Record that a PFN was accessed.
    pub fn record_access(&mut self, pfn: u64) {
        for idx in 0..self.count {
            let base = self.entries[idx].base_pfn();
            if pfn >= base && pfn < base + PAGES_PER_ENTRY as u64 {
                let bit = (pfn - base) as usize;
                self.entries[idx].record_access(bit);
                self.stats.pages_accessed += 1;
                return;
            }
        }
    }

    /// Scan and count idle pages.
    pub fn scan_idle(&mut self) -> u64 {
        self.stats.scan_cycles += 1;
        let mut idle: u64 = 0;
        for idx in 0..self.count {
            idle += self.entries[idx].idle_count() as u64;
        }
        self.stats.pages_still_idle = idle;
        idle
    }

    /// Get an entry by index.
    pub fn get_entry(&self, index: usize) -> Option<&IdleBitmapEntry> {
        if index < self.count {
            Some(&self.entries[index])
        } else {
            None
        }
    }

    /// Total trackable pages.
    pub const fn total_trackable(&self) -> usize {
        self.count * PAGES_PER_ENTRY
    }

    /// Idle memory estimate in bytes.
    pub fn idle_bytes(&self) -> u64 {
        let mut idle: u64 = 0;
        for idx in 0..self.count {
            idle += self.entries[idx].idle_count() as u64;
        }
        idle * PAGE_SIZE
    }
}

impl Default for PageIdleTracker {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// Public helpers
// -------------------------------------------------------------------

/// Return the pages per bitmap entry.
pub const fn pages_per_entry() -> usize {
    PAGES_PER_ENTRY
}

/// Return the maximum bitmap entries.
pub const fn max_bitmap_entries() -> usize {
    MAX_BITMAP_ENTRIES
}

/// Return the maximum trackable pages.
pub const fn max_trackable_pages() -> usize {
    MAX_TRACKABLE_PAGES
}
