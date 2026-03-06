// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Free page reporting.
//!
//! In virtualized environments, the guest can report free pages to the
//! hypervisor so that the host can reclaim the backing memory. This
//! module collects free page ranges from the buddy allocator and
//! reports them via the virtio-balloon free-page-reporting interface.
//!
//! # Design
//!
//! ```text
//!  page_reporting_cycle()
//!     │
//!     ├─ scan buddy free lists for order ≥ threshold
//!     ├─ collect (pfn, order) pairs into scatter-gather list
//!     ├─ report to hypervisor via virtio
//!     └─ mark reported pages (avoid re-reporting)
//! ```
//!
//! # Key Types
//!
//! - [`FreePageRange`] — a contiguous free page range
//! - [`FreePageReporter`] — collects and reports free pages
//! - [`FreePageReportStats`] — reporting statistics
//!
//! Reference: Linux `mm/page_reporting.c`.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Maximum ranges per report batch.
const MAX_RANGES: usize = 512;

/// Minimum order to report (skip tiny free blocks).
const MIN_REPORT_ORDER: u32 = 5; // 128 KiB

/// Page size.
const PAGE_SIZE: u64 = 4096;

/// Reporting delay in milliseconds.
const REPORT_DELAY_MS: u64 = 2000;

// -------------------------------------------------------------------
// FreePageRange
// -------------------------------------------------------------------

/// A contiguous free page range.
#[derive(Debug, Clone, Copy)]
pub struct FreePageRange {
    /// Start PFN.
    pfn: u64,
    /// Order (log2 of page count).
    order: u32,
    /// Whether this range has been reported.
    reported: bool,
    /// Zone index.
    zone: u32,
}

impl FreePageRange {
    /// Create a new range.
    pub const fn new(pfn: u64, order: u32, zone: u32) -> Self {
        Self {
            pfn,
            order,
            reported: false,
            zone,
        }
    }

    /// Return the PFN.
    pub const fn pfn(&self) -> u64 {
        self.pfn
    }

    /// Return the order.
    pub const fn order(&self) -> u32 {
        self.order
    }

    /// Check whether the range has been reported.
    pub const fn reported(&self) -> bool {
        self.reported
    }

    /// Return the zone index.
    pub const fn zone(&self) -> u32 {
        self.zone
    }

    /// Return the page count.
    pub const fn page_count(&self) -> u64 {
        1u64 << self.order
    }

    /// Return the size in bytes.
    pub const fn size_bytes(&self) -> u64 {
        self.page_count() * PAGE_SIZE
    }

    /// Mark as reported.
    pub fn mark_reported(&mut self) {
        self.reported = true;
    }

    /// Check whether the order meets the minimum threshold.
    pub const fn meets_threshold(&self) -> bool {
        self.order >= MIN_REPORT_ORDER
    }
}

impl Default for FreePageRange {
    fn default() -> Self {
        Self {
            pfn: 0,
            order: 0,
            reported: false,
            zone: 0,
        }
    }
}

// -------------------------------------------------------------------
// FreePageReportStats
// -------------------------------------------------------------------

/// Reporting statistics.
#[derive(Debug, Clone, Copy)]
pub struct FreePageReportStats {
    /// Total reporting cycles.
    pub total_cycles: u64,
    /// Total ranges reported.
    pub ranges_reported: u64,
    /// Total pages reported.
    pub pages_reported: u64,
    /// Total bytes reported.
    pub bytes_reported: u64,
    /// Skipped ranges (below threshold).
    pub ranges_skipped: u64,
}

impl FreePageReportStats {
    /// Create zero stats.
    pub const fn new() -> Self {
        Self {
            total_cycles: 0,
            ranges_reported: 0,
            pages_reported: 0,
            bytes_reported: 0,
            ranges_skipped: 0,
        }
    }

    /// Average pages per cycle.
    pub const fn avg_pages_per_cycle(&self) -> u64 {
        if self.total_cycles == 0 {
            return 0;
        }
        self.pages_reported / self.total_cycles
    }
}

impl Default for FreePageReportStats {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// FreePageReporter
// -------------------------------------------------------------------

/// Collects and reports free pages to the hypervisor.
pub struct FreePageReporter {
    /// Collected ranges.
    ranges: [FreePageRange; MAX_RANGES],
    /// Number of ranges.
    count: usize,
    /// Whether reporting is enabled.
    enabled: bool,
    /// Statistics.
    stats: FreePageReportStats,
}

impl FreePageReporter {
    /// Create a new reporter.
    pub const fn new() -> Self {
        Self {
            ranges: [const {
                FreePageRange {
                    pfn: 0,
                    order: 0,
                    reported: false,
                    zone: 0,
                }
            }; MAX_RANGES],
            count: 0,
            enabled: false,
            stats: FreePageReportStats::new(),
        }
    }

    /// Return the statistics.
    pub const fn stats(&self) -> &FreePageReportStats {
        &self.stats
    }

    /// Return the number of collected ranges.
    pub const fn count(&self) -> usize {
        self.count
    }

    /// Check whether reporting is enabled.
    pub const fn enabled(&self) -> bool {
        self.enabled
    }

    /// Enable reporting.
    pub fn enable(&mut self) {
        self.enabled = true;
    }

    /// Disable reporting.
    pub fn disable(&mut self) {
        self.enabled = false;
    }

    /// Add a free range.
    pub fn add_range(&mut self, pfn: u64, order: u32, zone: u32) -> Result<()> {
        if !self.enabled {
            return Ok(());
        }
        if order < MIN_REPORT_ORDER {
            self.stats.ranges_skipped += 1;
            return Ok(());
        }
        if self.count >= MAX_RANGES {
            return Err(Error::OutOfMemory);
        }
        self.ranges[self.count] = FreePageRange::new(pfn, order, zone);
        self.count += 1;
        Ok(())
    }

    /// Report all collected ranges.
    pub fn report(&mut self) -> u64 {
        if !self.enabled {
            return 0;
        }
        self.stats.total_cycles += 1;
        let mut total_pages: u64 = 0;

        for idx in 0..self.count {
            if !self.ranges[idx].reported() && self.ranges[idx].meets_threshold() {
                self.ranges[idx].mark_reported();
                let pages = self.ranges[idx].page_count();
                total_pages += pages;
                self.stats.ranges_reported += 1;
                self.stats.pages_reported += pages;
                self.stats.bytes_reported += self.ranges[idx].size_bytes();
            }
        }
        total_pages
    }

    /// Clear all ranges (after reporting).
    pub fn clear(&mut self) {
        self.count = 0;
    }

    /// Get a range by index.
    pub fn get_range(&self, index: usize) -> Option<&FreePageRange> {
        if index < self.count {
            Some(&self.ranges[index])
        } else {
            None
        }
    }
}

impl Default for FreePageReporter {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// Public helpers
// -------------------------------------------------------------------

/// Return the maximum ranges.
pub const fn max_ranges() -> usize {
    MAX_RANGES
}

/// Return the minimum report order.
pub const fn min_report_order() -> u32 {
    MIN_REPORT_ORDER
}

/// Return the reporting delay in milliseconds.
pub const fn report_delay_ms() -> u64 {
    REPORT_DELAY_MS
}
