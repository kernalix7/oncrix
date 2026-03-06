// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Mincore page-residency scanning.
//!
//! The `mincore(2)` syscall reports which pages of a mapping are
//! resident in physical memory. This module scans page tables for a
//! given virtual address range and populates a residency vector
//! indicating which pages are in core, swapped, or unmapped.
//!
//! # Design
//!
//! ```text
//!  mincore(addr, length, vec)
//!     │
//!     ├─ align addr/length to page boundaries
//!     ├─ walk page tables for [addr, addr+length)
//!     │   └─ for each page: check PTE present bit
//!     └─ fill vec[i] = 1 if resident, 0 if not
//! ```
//!
//! # Key Types
//!
//! - [`PageResidency`] — residency status of a single page
//! - [`MincoreScan`] — a scan over an address range
//! - [`MincoreResult`] — result buffer for a scan
//! - [`MincoreScanStats`] — scanning statistics
//!
//! Reference: Linux `mm/mincore.c`, POSIX `mincore(2)`.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Maximum pages per scan.
const MAX_SCAN_PAGES: usize = 8192;

/// Page size.
const PAGE_SIZE: u64 = 4096;

// -------------------------------------------------------------------
// PageResidency
// -------------------------------------------------------------------

/// Residency status of a single page.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PageResidency {
    /// Page is resident in physical memory.
    Resident,
    /// Page is swapped out.
    Swapped,
    /// Page is not mapped (no PTE).
    Unmapped,
    /// Page is in page cache but not mapped.
    InCache,
}

impl PageResidency {
    /// Return a label string.
    pub const fn label(&self) -> &'static str {
        match self {
            Self::Resident => "resident",
            Self::Swapped => "swapped",
            Self::Unmapped => "unmapped",
            Self::InCache => "in-cache",
        }
    }

    /// Check whether the page is in physical memory.
    pub const fn is_in_core(&self) -> bool {
        matches!(self, Self::Resident | Self::InCache)
    }

    /// Return the mincore(2) byte value.
    pub const fn to_byte(&self) -> u8 {
        match self {
            Self::Resident | Self::InCache => 1,
            Self::Swapped | Self::Unmapped => 0,
        }
    }
}

// -------------------------------------------------------------------
// MincoreResult
// -------------------------------------------------------------------

/// Result buffer for a mincore scan.
#[derive(Debug, Clone)]
pub struct MincoreResult {
    /// Per-page residency status.
    entries: [PageResidency; MAX_SCAN_PAGES],
    /// Number of valid entries.
    count: usize,
    /// Start virtual address.
    start_addr: u64,
}

impl MincoreResult {
    /// Create an empty result.
    pub const fn new(start_addr: u64) -> Self {
        Self {
            entries: [PageResidency::Unmapped; MAX_SCAN_PAGES],
            count: 0,
            start_addr,
        }
    }

    /// Return the number of entries.
    pub const fn count(&self) -> usize {
        self.count
    }

    /// Return the start address.
    pub const fn start_addr(&self) -> u64 {
        self.start_addr
    }

    /// Get a residency entry by index.
    pub fn get(&self, index: usize) -> Option<PageResidency> {
        if index < self.count {
            Some(self.entries[index])
        } else {
            None
        }
    }

    /// Push a residency entry.
    pub fn push(&mut self, status: PageResidency) -> Result<()> {
        if self.count >= MAX_SCAN_PAGES {
            return Err(Error::OutOfMemory);
        }
        self.entries[self.count] = status;
        self.count += 1;
        Ok(())
    }

    /// Count resident pages.
    pub fn resident_count(&self) -> usize {
        let mut n = 0;
        for idx in 0..self.count {
            if self.entries[idx].is_in_core() {
                n += 1;
            }
        }
        n
    }

    /// Residency ratio as percent.
    pub fn residency_pct(&self) -> u64 {
        if self.count == 0 {
            return 0;
        }
        (self.resident_count() as u64) * 100 / self.count as u64
    }
}

// -------------------------------------------------------------------
// MincoreScanStats
// -------------------------------------------------------------------

/// Scanning statistics.
#[derive(Debug, Clone, Copy)]
pub struct MincoreScanStats {
    /// Total scans performed.
    pub total_scans: u64,
    /// Total pages checked.
    pub total_pages: u64,
    /// Pages found resident.
    pub resident_pages: u64,
    /// Pages found swapped.
    pub swapped_pages: u64,
    /// Pages found unmapped.
    pub unmapped_pages: u64,
    /// Pages found in cache.
    pub cached_pages: u64,
}

impl MincoreScanStats {
    /// Create zero stats.
    pub const fn new() -> Self {
        Self {
            total_scans: 0,
            total_pages: 0,
            resident_pages: 0,
            swapped_pages: 0,
            unmapped_pages: 0,
            cached_pages: 0,
        }
    }

    /// Overall residency ratio as percent.
    pub const fn residency_pct(&self) -> u64 {
        if self.total_pages == 0 {
            return 0;
        }
        self.resident_pages * 100 / self.total_pages
    }
}

impl Default for MincoreScanStats {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// MincoreScan
// -------------------------------------------------------------------

/// A mincore scan over an address range.
pub struct MincoreScan {
    /// Results of completed scans.
    results: [MincoreResult; 16],
    /// Number of completed scans.
    result_count: usize,
    /// Statistics.
    stats: MincoreScanStats,
}

impl MincoreScan {
    /// Create a new scanner.
    pub const fn new() -> Self {
        Self {
            results: [const {
                MincoreResult {
                    entries: [PageResidency::Unmapped; MAX_SCAN_PAGES],
                    count: 0,
                    start_addr: 0,
                }
            }; 16],
            result_count: 0,
            stats: MincoreScanStats::new(),
        }
    }

    /// Return the statistics.
    pub const fn stats(&self) -> &MincoreScanStats {
        &self.stats
    }

    /// Return the number of completed scans.
    pub const fn result_count(&self) -> usize {
        self.result_count
    }

    /// Perform a scan for a given address range.
    pub fn scan(
        &mut self,
        start_addr: u64,
        page_count: usize,
        residencies: &[PageResidency],
    ) -> Result<()> {
        if (start_addr % PAGE_SIZE) != 0 {
            return Err(Error::InvalidArgument);
        }
        if page_count == 0 || page_count > MAX_SCAN_PAGES {
            return Err(Error::InvalidArgument);
        }
        if residencies.len() < page_count {
            return Err(Error::InvalidArgument);
        }
        if self.result_count >= 16 {
            return Err(Error::OutOfMemory);
        }

        let mut result = MincoreResult::new(start_addr);
        for idx in 0..page_count {
            let status = residencies[idx];
            result.push(status)?;
            match status {
                PageResidency::Resident => self.stats.resident_pages += 1,
                PageResidency::Swapped => self.stats.swapped_pages += 1,
                PageResidency::Unmapped => self.stats.unmapped_pages += 1,
                PageResidency::InCache => self.stats.cached_pages += 1,
            }
            self.stats.total_pages += 1;
        }

        self.results[self.result_count] = result;
        self.result_count += 1;
        self.stats.total_scans += 1;
        Ok(())
    }

    /// Get a scan result by index.
    pub fn get_result(&self, index: usize) -> Option<&MincoreResult> {
        if index < self.result_count {
            Some(&self.results[index])
        } else {
            None
        }
    }
}

impl Default for MincoreScan {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// Public helpers
// -------------------------------------------------------------------

/// Return the maximum pages per scan.
pub const fn max_scan_pages() -> usize {
    MAX_SCAN_PAGES
}

/// Compute the number of pages for a byte range.
pub const fn pages_for_range(length: u64) -> u64 {
    (length + PAGE_SIZE - 1) / PAGE_SIZE
}

/// Align an address down to page boundary.
pub const fn page_align_down(addr: u64) -> u64 {
    addr & !(PAGE_SIZE - 1)
}

/// Align an address up to page boundary.
pub const fn page_align_up(addr: u64) -> u64 {
    (addr + PAGE_SIZE - 1) & !(PAGE_SIZE - 1)
}
