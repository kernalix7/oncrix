// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Page poison pattern checking.
//!
//! When `CONFIG_PAGE_POISONING` is enabled, freed pages are filled
//! with a known poison pattern (0xAA) and checked on allocation. If
//! the pattern is corrupted, a use-after-free bug has modified the
//! page. This module implements the poison/check cycle and reports
//! detected corruptions.
//!
//! # Design
//!
//! ```text
//!  free_page(page)
//!     │
//!     └─ fill page with 0xAA (poison)
//!
//!  alloc_page()
//!     │
//!     ├─ check page contents == 0xAA (verify poison)
//!     ├─ if corrupt → report corruption
//!     └─ clear page, return to caller
//! ```
//!
//! # Key Types
//!
//! - [`PoisonPattern`] — poison pattern configuration
//! - [`CorruptionReport`] — a detected corruption
//! - [`PagePoisonChecker`] — manages poison checking
//! - [`PoisonCheckStats`] — checking statistics
//!
//! Reference: Linux `mm/page_poison.c`, `include/linux/page_poison.h`.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Default poison byte.
const POISON_BYTE: u8 = 0xAA;

/// Freed (un-poisoned) byte for verification.
const CLEAN_BYTE: u8 = 0x00;

/// Page size.
const PAGE_SIZE: usize = 4096;

/// Maximum corruption reports stored.
const MAX_REPORTS: usize = 512;

/// Maximum bytes to check per scan before sampling.
const FULL_CHECK_THRESHOLD: usize = 4096;

// -------------------------------------------------------------------
// PoisonPattern
// -------------------------------------------------------------------

/// Poison pattern configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PoisonPattern {
    /// Byte value used for poisoning.
    poison_byte: u8,
    /// Whether poisoning is enabled.
    enabled: bool,
    /// Whether to check on alloc.
    check_on_alloc: bool,
    /// Whether to poison on free.
    poison_on_free: bool,
}

impl PoisonPattern {
    /// Create default poison pattern.
    pub const fn new() -> Self {
        Self {
            poison_byte: POISON_BYTE,
            enabled: true,
            check_on_alloc: true,
            poison_on_free: true,
        }
    }

    /// Return the poison byte.
    pub const fn poison_byte(&self) -> u8 {
        self.poison_byte
    }

    /// Check whether poisoning is enabled.
    pub const fn enabled(&self) -> bool {
        self.enabled
    }

    /// Check whether alloc-time checking is enabled.
    pub const fn check_on_alloc(&self) -> bool {
        self.check_on_alloc
    }

    /// Check whether free-time poisoning is enabled.
    pub const fn poison_on_free(&self) -> bool {
        self.poison_on_free
    }

    /// Enable or disable.
    pub fn set_enabled(&mut self, val: bool) {
        self.enabled = val;
    }
}

impl Default for PoisonPattern {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// CorruptionReport
// -------------------------------------------------------------------

/// A detected corruption in a poisoned page.
#[derive(Debug, Clone, Copy)]
pub struct CorruptionReport {
    /// Physical frame number of the corrupted page.
    pfn: u64,
    /// Offset within page where first corruption was found.
    offset: u32,
    /// Expected byte value.
    expected: u8,
    /// Actual byte value found.
    actual: u8,
    /// Number of corrupted bytes in the page.
    corrupt_bytes: u32,
    /// Timestamp of detection.
    timestamp: u64,
}

impl CorruptionReport {
    /// Create a new report.
    pub const fn new(
        pfn: u64,
        offset: u32,
        expected: u8,
        actual: u8,
        corrupt_bytes: u32,
        timestamp: u64,
    ) -> Self {
        Self {
            pfn,
            offset,
            expected,
            actual,
            corrupt_bytes,
            timestamp,
        }
    }

    /// Return the PFN.
    pub const fn pfn(&self) -> u64 {
        self.pfn
    }

    /// Return the offset.
    pub const fn offset(&self) -> u32 {
        self.offset
    }

    /// Return the expected byte.
    pub const fn expected(&self) -> u8 {
        self.expected
    }

    /// Return the actual byte.
    pub const fn actual(&self) -> u8 {
        self.actual
    }

    /// Return the number of corrupted bytes.
    pub const fn corrupt_bytes(&self) -> u32 {
        self.corrupt_bytes
    }

    /// Return the timestamp.
    pub const fn timestamp(&self) -> u64 {
        self.timestamp
    }

    /// Corruption rate as percent of page.
    pub const fn corruption_pct(&self) -> u32 {
        if PAGE_SIZE == 0 {
            return 0;
        }
        self.corrupt_bytes * 100 / PAGE_SIZE as u32
    }
}

impl Default for CorruptionReport {
    fn default() -> Self {
        Self {
            pfn: 0,
            offset: 0,
            expected: POISON_BYTE,
            actual: 0,
            corrupt_bytes: 0,
            timestamp: 0,
        }
    }
}

// -------------------------------------------------------------------
// PoisonCheckStats
// -------------------------------------------------------------------

/// Poison checking statistics.
#[derive(Debug, Clone, Copy)]
pub struct PoisonCheckStats {
    /// Pages poisoned.
    pub pages_poisoned: u64,
    /// Pages checked.
    pub pages_checked: u64,
    /// Corruptions detected.
    pub corruptions: u64,
    /// Clean pages (no corruption).
    pub clean_pages: u64,
}

impl PoisonCheckStats {
    /// Create zero stats.
    pub const fn new() -> Self {
        Self {
            pages_poisoned: 0,
            pages_checked: 0,
            corruptions: 0,
            clean_pages: 0,
        }
    }

    /// Corruption rate as percent.
    pub const fn corruption_rate_pct(&self) -> u64 {
        if self.pages_checked == 0 {
            return 0;
        }
        self.corruptions * 100 / self.pages_checked
    }
}

impl Default for PoisonCheckStats {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// PagePoisonChecker
// -------------------------------------------------------------------

/// Manages page poison checking.
pub struct PagePoisonChecker {
    /// Pattern configuration.
    pattern: PoisonPattern,
    /// Corruption reports.
    reports: [CorruptionReport; MAX_REPORTS],
    /// Number of reports.
    report_count: usize,
    /// Statistics.
    stats: PoisonCheckStats,
}

impl PagePoisonChecker {
    /// Create a new checker.
    pub const fn new() -> Self {
        Self {
            pattern: PoisonPattern::new(),
            reports: [const {
                CorruptionReport {
                    pfn: 0,
                    offset: 0,
                    expected: POISON_BYTE,
                    actual: 0,
                    corrupt_bytes: 0,
                    timestamp: 0,
                }
            }; MAX_REPORTS],
            report_count: 0,
            stats: PoisonCheckStats::new(),
        }
    }

    /// Return the pattern configuration.
    pub const fn pattern(&self) -> &PoisonPattern {
        &self.pattern
    }

    /// Return the statistics.
    pub const fn stats(&self) -> &PoisonCheckStats {
        &self.stats
    }

    /// Return the number of reports.
    pub const fn report_count(&self) -> usize {
        self.report_count
    }

    /// Record a page poisoning (on free).
    pub fn record_poison(&mut self, _pfn: u64) {
        self.stats.pages_poisoned += 1;
    }

    /// Check a page (on alloc) and report corruption.
    pub fn check_page(&mut self, pfn: u64, page_data: &[u8], timestamp: u64) -> Result<bool> {
        if !self.pattern.enabled() || !self.pattern.check_on_alloc() {
            return Ok(true);
        }
        if page_data.len() < PAGE_SIZE {
            return Err(Error::InvalidArgument);
        }

        self.stats.pages_checked += 1;
        let expected = self.pattern.poison_byte();

        let mut first_offset: Option<u32> = None;
        let mut first_actual: u8 = 0;
        let mut corrupt_count: u32 = 0;

        for idx in 0..PAGE_SIZE {
            if page_data[idx] != expected {
                if first_offset.is_none() {
                    first_offset = Some(idx as u32);
                    first_actual = page_data[idx];
                }
                corrupt_count += 1;
            }
        }

        if corrupt_count == 0 {
            self.stats.clean_pages += 1;
            return Ok(true);
        }

        self.stats.corruptions += 1;
        if self.report_count < MAX_REPORTS {
            let fo = match first_offset {
                Some(v) => v,
                None => 0,
            };
            self.reports[self.report_count] =
                CorruptionReport::new(pfn, fo, expected, first_actual, corrupt_count, timestamp);
            self.report_count += 1;
        }
        Ok(false)
    }

    /// Get a report by index.
    pub fn get_report(&self, index: usize) -> Option<&CorruptionReport> {
        if index < self.report_count {
            Some(&self.reports[index])
        } else {
            None
        }
    }

    /// Enable or disable the checker.
    pub fn set_enabled(&mut self, val: bool) {
        self.pattern.set_enabled(val);
    }
}

impl Default for PagePoisonChecker {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// Public helpers
// -------------------------------------------------------------------

/// Return the default poison byte.
pub const fn poison_byte() -> u8 {
    POISON_BYTE
}

/// Return the clean byte.
pub const fn clean_byte() -> u8 {
    CLEAN_BYTE
}

/// Return the full check threshold.
pub const fn full_check_threshold() -> usize {
    FULL_CHECK_THRESHOLD
}

/// Return the maximum reports.
pub const fn max_reports() -> usize {
    MAX_REPORTS
}
