// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Page poisoning subsystem for memory debugging.
//!
//! Detects use-after-free and uninitialised-read bugs by filling
//! freed pages with a known poison pattern and verifying that pattern
//! before the page is reused.  Any corruption indicates a write to
//! freed memory — a critical memory safety violation.
//!
//! Inspired by the Linux `CONFIG_PAGE_POISON` / `mm/page_poison.c`
//! facility.  This implementation adds a per-page metadata tracker,
//! a quarantine ring to delay reuse, and detailed corruption reports.
//!
//! Key components:
//! - [`PoisonPattern`] — available fill patterns
//! - [`PagePoisonState`] — lifecycle state of a tracked page
//! - [`PagePoisonEntry`] — metadata for one tracked page
//! - [`CorruptionReport`] — details of detected corruption
//! - [`PoisonQuarantine`] — ring buffer delaying page reuse
//! - [`PagePoisonStats`] — aggregate statistics
//! - [`PagePoisonManager`] — top-level manager for poisoning ops
//!
//! Reference: Linux `mm/page_poison.c`, `include/linux/page_poison.h`.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Standard page size in bytes (4 KiB).
const PAGE_SIZE: usize = 4096;

/// Maximum number of pages tracked by the poison subsystem.
const MAX_TRACKED_PAGES: usize = 1024;

/// Maximum number of corruption reports retained.
const MAX_CORRUPTION_REPORTS: usize = 64;

/// Quarantine ring buffer capacity.
const QUARANTINE_CAPACITY: usize = 128;

/// Default poison byte value (0xAA pattern).
const POISON_BYTE_DEFAULT: u8 = 0xAA;

/// Freed-page poison byte (0x6B — matches Linux POISON_FREE).
const POISON_BYTE_FREE: u8 = 0x6B;

/// Allocated-page poison byte (0x5A — uninitialised fill).
const POISON_BYTE_ALLOC: u8 = 0x5A;

/// Pattern used for guard/red-zone bytes.
const POISON_BYTE_GUARD: u8 = 0xCC;

/// Minimum quarantine hold time in nanoseconds (50 ms).
const MIN_QUARANTINE_HOLD_NS: u64 = 50_000_000;

/// Maximum number of bytes to report per corruption.
const MAX_CORRUPT_BYTES_REPORT: usize = 32;

/// Maximum number of scan passes retained in history.
const MAX_SCAN_HISTORY: usize = 16;

// -------------------------------------------------------------------
// PoisonPattern
// -------------------------------------------------------------------

/// Predefined fill patterns for poisoned pages.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PoisonPattern {
    /// 0xAA — default pattern, easy to spot in dumps.
    #[default]
    Default,
    /// 0x6B — freed page (matches Linux `POISON_FREE`).
    Free,
    /// 0x5A — freshly allocated, not yet initialised.
    Alloc,
    /// 0xCC — guard/red-zone between objects.
    Guard,
    /// User-specified single-byte pattern.
    Custom(u8),
}

impl PoisonPattern {
    /// Return the byte value for this pattern.
    pub const fn byte_value(self) -> u8 {
        match self {
            Self::Default => POISON_BYTE_DEFAULT,
            Self::Free => POISON_BYTE_FREE,
            Self::Alloc => POISON_BYTE_ALLOC,
            Self::Guard => POISON_BYTE_GUARD,
            Self::Custom(b) => b,
        }
    }
}

// -------------------------------------------------------------------
// PagePoisonState
// -------------------------------------------------------------------

/// Lifecycle state of a page tracked by the poison subsystem.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PagePoisonState {
    /// Page is not tracked.
    #[default]
    Untracked,
    /// Page is poisoned (freed, filled with pattern).
    Poisoned,
    /// Page is in quarantine (poisoned + held before reuse).
    Quarantined,
    /// Page has been verified clean and returned to allocator.
    Verified,
    /// Page failed verification (corruption detected).
    Corrupted,
}

// -------------------------------------------------------------------
// PagePoisonEntry
// -------------------------------------------------------------------

/// Metadata for a single page tracked by the poison subsystem.
#[derive(Debug, Clone, Copy)]
pub struct PagePoisonEntry {
    /// Page frame number.
    pfn: u64,
    /// Current state of this page.
    state: PagePoisonState,
    /// Pattern used to poison this page.
    pattern: PoisonPattern,
    /// Allocation order (0 = single 4 KiB page).
    order: u8,
    /// Timestamp (nanoseconds) when page was poisoned.
    poison_timestamp_ns: u64,
    /// Timestamp when verification was last performed.
    verify_timestamp_ns: u64,
    /// Number of times this page has been poisoned.
    poison_count: u32,
    /// Whether this entry is in use.
    active: bool,
}

impl PagePoisonEntry {
    /// Create an inactive entry.
    const fn empty() -> Self {
        Self {
            pfn: 0,
            state: PagePoisonState::Untracked,
            pattern: PoisonPattern::Default,
            order: 0,
            poison_timestamp_ns: 0,
            verify_timestamp_ns: 0,
            poison_count: 0,
            active: false,
        }
    }
}

// -------------------------------------------------------------------
// CorruptByte
// -------------------------------------------------------------------

/// A single corrupted byte within a page.
#[derive(Debug, Clone, Copy)]
pub struct CorruptByte {
    /// Offset within the page (0..PAGE_SIZE).
    pub offset: usize,
    /// Expected byte value (the poison pattern).
    pub expected: u8,
    /// Actual byte value found.
    pub found: u8,
}

impl CorruptByte {
    /// Create a new corrupt byte record.
    const fn new(offset: usize, expected: u8, found: u8) -> Self {
        Self {
            offset,
            expected,
            found,
        }
    }
}

// -------------------------------------------------------------------
// CorruptionReport
// -------------------------------------------------------------------

/// Details of a page corruption detection event.
#[derive(Debug, Clone, Copy)]
pub struct CorruptionReport {
    /// Page frame number of the corrupted page.
    pub pfn: u64,
    /// Expected poison pattern.
    pub expected_pattern: PoisonPattern,
    /// Allocation order of the page.
    pub order: u8,
    /// Number of bytes that differ from the expected pattern.
    pub corrupt_byte_count: usize,
    /// First N corrupt bytes (for diagnostics).
    pub corrupt_bytes: [CorruptByte; MAX_CORRUPT_BYTES_REPORT],
    /// How many entries in `corrupt_bytes` are valid.
    pub corrupt_bytes_valid: usize,
    /// Timestamp of the poisoning (nanoseconds).
    pub poison_timestamp_ns: u64,
    /// Timestamp of the verification (nanoseconds).
    pub verify_timestamp_ns: u64,
    /// Whether the corruption is contiguous (single run).
    pub contiguous: bool,
    /// Start offset of the first corrupted byte.
    pub first_corrupt_offset: usize,
    /// End offset of the last corrupted byte.
    pub last_corrupt_offset: usize,
}

impl CorruptionReport {
    /// Create an empty report for the given PFN.
    fn new(pfn: u64, pattern: PoisonPattern, order: u8) -> Self {
        Self {
            pfn,
            expected_pattern: pattern,
            order,
            corrupt_byte_count: 0,
            corrupt_bytes: [CorruptByte::new(0, 0, 0); MAX_CORRUPT_BYTES_REPORT],
            corrupt_bytes_valid: 0,
            poison_timestamp_ns: 0,
            verify_timestamp_ns: 0,
            contiguous: true,
            first_corrupt_offset: 0,
            last_corrupt_offset: 0,
        }
    }

    /// Record a corrupt byte in this report.
    fn record_byte(&mut self, offset: usize, expected: u8, found: u8) {
        if self.corrupt_byte_count == 0 {
            self.first_corrupt_offset = offset;
        } else if offset != self.last_corrupt_offset + 1 {
            self.contiguous = false;
        }
        self.last_corrupt_offset = offset;
        self.corrupt_byte_count += 1;
        if self.corrupt_bytes_valid < MAX_CORRUPT_BYTES_REPORT {
            self.corrupt_bytes[self.corrupt_bytes_valid] =
                CorruptByte::new(offset, expected, found);
            self.corrupt_bytes_valid += 1;
        }
    }
}

// -------------------------------------------------------------------
// QuarantineEntry
// -------------------------------------------------------------------

/// An entry in the quarantine ring buffer.
#[derive(Debug, Clone, Copy)]
struct QuarantineEntry {
    /// Page frame number.
    pfn: u64,
    /// Allocation order.
    order: u8,
    /// Pattern the page was poisoned with.
    pattern: PoisonPattern,
    /// Timestamp when page entered quarantine (nanoseconds).
    enter_ns: u64,
    /// Whether this slot is occupied.
    occupied: bool,
}

impl QuarantineEntry {
    const fn empty() -> Self {
        Self {
            pfn: 0,
            order: 0,
            pattern: PoisonPattern::Default,
            enter_ns: 0,
            occupied: false,
        }
    }
}

// -------------------------------------------------------------------
// PoisonQuarantine
// -------------------------------------------------------------------

/// Ring buffer that holds poisoned pages before reuse.
///
/// Pages remain in quarantine for at least
/// [`MIN_QUARANTINE_HOLD_NS`] nanoseconds so that delayed
/// use-after-free writes have more time to corrupt the pattern and
/// be detected.
#[derive(Debug)]
pub struct PoisonQuarantine {
    /// Ring buffer storage.
    entries: [QuarantineEntry; QUARANTINE_CAPACITY],
    /// Write head (next slot to fill).
    head: usize,
    /// Number of occupied entries.
    count: usize,
    /// Total pages that have passed through quarantine.
    total_quarantined: u64,
    /// Total pages released from quarantine.
    total_released: u64,
}

impl PoisonQuarantine {
    /// Create an empty quarantine.
    const fn new() -> Self {
        Self {
            entries: [const { QuarantineEntry::empty() }; QUARANTINE_CAPACITY],
            head: 0,
            count: 0,
            total_quarantined: 0,
            total_released: 0,
        }
    }

    /// Number of pages currently in quarantine.
    pub const fn len(&self) -> usize {
        self.count
    }

    /// Whether the quarantine is empty.
    pub const fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Whether the quarantine is full.
    pub const fn is_full(&self) -> bool {
        self.count == QUARANTINE_CAPACITY
    }

    /// Add a page to quarantine.
    fn enqueue(&mut self, pfn: u64, order: u8, pattern: PoisonPattern, now_ns: u64) -> Result<()> {
        if self.is_full() {
            return Err(Error::Busy);
        }
        // Find the next free slot starting from head.
        let mut idx = self.head;
        for _ in 0..QUARANTINE_CAPACITY {
            if !self.entries[idx].occupied {
                self.entries[idx] = QuarantineEntry {
                    pfn,
                    order,
                    pattern,
                    enter_ns: now_ns,
                    occupied: true,
                };
                self.head = (idx + 1) % QUARANTINE_CAPACITY;
                self.count += 1;
                self.total_quarantined += 1;
                return Ok(());
            }
            idx = (idx + 1) % QUARANTINE_CAPACITY;
        }
        Err(Error::Busy)
    }

    /// Release all pages whose hold time has expired.
    ///
    /// Returns the number of released pages.
    fn release_expired(&mut self, now_ns: u64) -> usize {
        let mut released = 0usize;
        for entry in &mut self.entries {
            if entry.occupied && now_ns.saturating_sub(entry.enter_ns) >= MIN_QUARANTINE_HOLD_NS {
                entry.occupied = false;
                self.count = self.count.saturating_sub(1);
                self.total_released += 1;
                released += 1;
            }
        }
        released
    }

    /// Drain all pages regardless of hold time.
    fn drain(&mut self) -> usize {
        let drained = self.count;
        for entry in &mut self.entries {
            entry.occupied = false;
        }
        self.total_released += drained as u64;
        self.count = 0;
        self.head = 0;
        drained
    }
}

// -------------------------------------------------------------------
// ScanResult
// -------------------------------------------------------------------

/// Outcome of a page scan pass.
#[derive(Debug, Clone, Copy, Default)]
pub struct ScanResult {
    /// Number of pages scanned.
    pub scanned: usize,
    /// Number of clean (uncorrupted) pages found.
    pub clean: usize,
    /// Number of corrupted pages found.
    pub corrupted: usize,
    /// Timestamp of the scan (nanoseconds).
    pub timestamp_ns: u64,
}

// -------------------------------------------------------------------
// PagePoisonStats
// -------------------------------------------------------------------

/// Aggregate statistics for the page poison subsystem.
#[derive(Debug, Clone, Copy, Default)]
pub struct PagePoisonStats {
    /// Total pages poisoned since init.
    pub total_poisoned: u64,
    /// Total pages verified since init.
    pub total_verified: u64,
    /// Total corruptions detected.
    pub total_corruptions: u64,
    /// Total pages quarantined.
    pub total_quarantined: u64,
    /// Total pages released from quarantine.
    pub total_released: u64,
    /// Pages currently tracked.
    pub current_tracked: usize,
    /// Pages currently in quarantine.
    pub current_quarantined: usize,
    /// Corruption reports stored.
    pub reports_stored: usize,
    /// Scan passes completed.
    pub scans_completed: u64,
}

// -------------------------------------------------------------------
// PoisonConfig
// -------------------------------------------------------------------

/// Configuration for the page poison subsystem.
#[derive(Debug, Clone, Copy)]
pub struct PoisonConfig {
    /// Whether poisoning is enabled.
    pub enabled: bool,
    /// Default pattern for freed pages.
    pub free_pattern: PoisonPattern,
    /// Default pattern for freshly allocated pages.
    pub alloc_pattern: PoisonPattern,
    /// Whether to use quarantine.
    pub quarantine_enabled: bool,
    /// Whether to verify on allocation (pre-alloc check).
    pub verify_on_alloc: bool,
    /// Whether to verify on free (post-free scan).
    pub verify_on_free: bool,
    /// Whether to perform periodic background scans.
    pub periodic_scan: bool,
    /// Scan interval in nanoseconds.
    pub scan_interval_ns: u64,
}

impl Default for PoisonConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            free_pattern: PoisonPattern::Free,
            alloc_pattern: PoisonPattern::Alloc,
            quarantine_enabled: true,
            verify_on_alloc: true,
            verify_on_free: false,
            periodic_scan: false,
            scan_interval_ns: 1_000_000_000, // 1 second
        }
    }
}

// -------------------------------------------------------------------
// PagePoisonManager
// -------------------------------------------------------------------

/// Top-level manager for the page-poisoning debug facility.
///
/// Tracks page metadata, fills pages with poison patterns on free,
/// verifies integrity before reuse, and reports corruption.
///
/// # Example (conceptual)
///
/// ```ignore
/// let mut mgr = PagePoisonManager::new();
/// mgr.poison_page(42, 0, PoisonPattern::Free, 1000)?;
/// let report = mgr.verify_page(42, &[0x6B; 4096], 2000)?;
/// assert!(report.is_none()); // no corruption
/// ```
pub struct PagePoisonManager {
    /// Per-page tracking entries.
    pages: [PagePoisonEntry; MAX_TRACKED_PAGES],
    /// Quarantine ring buffer.
    quarantine: PoisonQuarantine,
    /// Corruption reports.
    reports: [Option<CorruptionReport>; MAX_CORRUPTION_REPORTS],
    /// Number of stored reports.
    report_count: usize,
    /// Scan history (most recent scans).
    scan_history: [ScanResult; MAX_SCAN_HISTORY],
    /// Number of recorded scans.
    scan_count: usize,
    /// Subsystem configuration.
    config: PoisonConfig,
    /// Aggregate stats.
    stats: PagePoisonStats,
}

impl PagePoisonManager {
    /// Create a new page poison manager with default configuration.
    pub fn new() -> Self {
        Self {
            pages: [const { PagePoisonEntry::empty() }; MAX_TRACKED_PAGES],
            quarantine: PoisonQuarantine::new(),
            reports: [const { None }; MAX_CORRUPTION_REPORTS],
            report_count: 0,
            scan_history: [const {
                ScanResult {
                    scanned: 0,
                    clean: 0,
                    corrupted: 0,
                    timestamp_ns: 0,
                }
            }; MAX_SCAN_HISTORY],
            scan_count: 0,
            config: PoisonConfig::default(),
            stats: PagePoisonStats {
                total_poisoned: 0,
                total_verified: 0,
                total_corruptions: 0,
                total_quarantined: 0,
                total_released: 0,
                current_tracked: 0,
                current_quarantined: 0,
                reports_stored: 0,
                scans_completed: 0,
            },
        }
    }

    /// Create a manager with custom configuration.
    pub fn with_config(config: PoisonConfig) -> Self {
        let mut mgr = Self::new();
        mgr.config = config;
        mgr
    }

    /// Return the current configuration.
    pub const fn config(&self) -> &PoisonConfig {
        &self.config
    }

    /// Update the configuration.
    pub fn set_config(&mut self, config: PoisonConfig) {
        self.config = config;
    }

    /// Return aggregate statistics.
    pub fn stats(&self) -> PagePoisonStats {
        let mut s = self.stats;
        s.current_tracked = self.tracked_count();
        s.current_quarantined = self.quarantine.len();
        s.reports_stored = self.report_count;
        s
    }

    // ── tracking helpers ─────────────────────────────────────────

    /// Number of actively tracked pages.
    fn tracked_count(&self) -> usize {
        self.pages.iter().filter(|p| p.active).count()
    }

    /// Find an entry by PFN.
    fn find_entry(&self, pfn: u64) -> Option<usize> {
        self.pages.iter().position(|p| p.active && p.pfn == pfn)
    }

    /// Find or allocate a tracking slot for `pfn`.
    fn find_or_alloc(&mut self, pfn: u64) -> Result<usize> {
        if let Some(idx) = self.find_entry(pfn) {
            return Ok(idx);
        }
        // Allocate a free slot.
        let idx = self
            .pages
            .iter()
            .position(|p| !p.active)
            .ok_or(Error::OutOfMemory)?;
        self.pages[idx] = PagePoisonEntry::empty();
        self.pages[idx].pfn = pfn;
        self.pages[idx].active = true;
        Ok(idx)
    }

    // ── poison / verify ──────────────────────────────────────────

    /// Poison a page that has been freed.
    ///
    /// Marks the page with the given `pattern`, records metadata,
    /// and optionally places it in quarantine.
    ///
    /// The caller is responsible for actually writing the pattern
    /// to the physical page; this method only updates bookkeeping.
    pub fn poison_page(
        &mut self,
        pfn: u64,
        order: u8,
        pattern: PoisonPattern,
        now_ns: u64,
    ) -> Result<()> {
        if !self.config.enabled {
            return Ok(());
        }
        let idx = self.find_or_alloc(pfn)?;
        let entry = &mut self.pages[idx];
        entry.state = PagePoisonState::Poisoned;
        entry.pattern = pattern;
        entry.order = order;
        entry.poison_timestamp_ns = now_ns;
        entry.poison_count += 1;
        self.stats.total_poisoned += 1;

        if self.config.quarantine_enabled {
            self.quarantine.enqueue(pfn, order, pattern, now_ns)?;
            entry.state = PagePoisonState::Quarantined;
            self.stats.total_quarantined += 1;
        }
        Ok(())
    }

    /// Verify a poisoned page against its expected pattern.
    ///
    /// `page_data` must be a slice of length `PAGE_SIZE << order`.
    /// Returns `Some(report)` if corruption was detected, or `None`
    /// if the page is clean.
    pub fn verify_page(
        &mut self,
        pfn: u64,
        page_data: &[u8],
        now_ns: u64,
    ) -> Result<Option<CorruptionReport>> {
        if !self.config.enabled {
            return Ok(None);
        }
        let idx = self.find_entry(pfn).ok_or(Error::NotFound)?;
        let entry = &self.pages[idx];
        let expected = entry.pattern.byte_value();
        let expected_len = PAGE_SIZE << entry.order;
        if page_data.len() < expected_len {
            return Err(Error::InvalidArgument);
        }

        let mut report = CorruptionReport::new(pfn, entry.pattern, entry.order);
        report.poison_timestamp_ns = entry.poison_timestamp_ns;
        report.verify_timestamp_ns = now_ns;

        for (i, &byte) in page_data.iter().enumerate().take(expected_len) {
            if byte != expected {
                report.record_byte(i, expected, byte);
            }
        }

        self.pages[idx].verify_timestamp_ns = now_ns;
        self.stats.total_verified += 1;

        if report.corrupt_byte_count > 0 {
            self.pages[idx].state = PagePoisonState::Corrupted;
            self.stats.total_corruptions += 1;
            self.store_report(report);
            Ok(Some(report))
        } else {
            self.pages[idx].state = PagePoisonState::Verified;
            Ok(None)
        }
    }

    /// Store a corruption report, evicting the oldest if full.
    fn store_report(&mut self, report: CorruptionReport) {
        if self.report_count < MAX_CORRUPTION_REPORTS {
            self.reports[self.report_count] = Some(report);
            self.report_count += 1;
        } else {
            // Shift left to make room.
            for i in 1..MAX_CORRUPTION_REPORTS {
                self.reports[i - 1] = self.reports[i];
            }
            self.reports[MAX_CORRUPTION_REPORTS - 1] = Some(report);
        }
    }

    // ── quarantine management ────────────────────────────────────

    /// Release quarantined pages whose hold time has expired.
    ///
    /// Returns the number of pages released.
    pub fn release_quarantine(&mut self, now_ns: u64) -> usize {
        let released = self.quarantine.release_expired(now_ns);
        self.stats.total_released += released as u64;
        released
    }

    /// Drain the entire quarantine (e.g., on memory pressure).
    pub fn drain_quarantine(&mut self) -> usize {
        let drained = self.quarantine.drain();
        self.stats.total_released += drained as u64;
        drained
    }

    // ── batch operations ─────────────────────────────────────────

    /// Poison multiple pages at once.
    pub fn poison_batch(
        &mut self,
        pfns: &[u64],
        order: u8,
        pattern: PoisonPattern,
        now_ns: u64,
    ) -> Result<usize> {
        let mut count = 0usize;
        for &pfn in pfns {
            match self.poison_page(pfn, order, pattern, now_ns) {
                Ok(()) => count += 1,
                Err(Error::OutOfMemory) => break,
                Err(Error::Busy) => continue,
                Err(e) => return Err(e),
            }
        }
        Ok(count)
    }

    /// Verify all currently poisoned/quarantined pages.
    ///
    /// This is a metadata-only scan that checks state consistency.
    /// Actual byte-level verification requires `verify_page` with
    /// the physical page data.
    pub fn scan_all(&mut self, now_ns: u64) -> ScanResult {
        let mut result = ScanResult {
            scanned: 0,
            clean: 0,
            corrupted: 0,
            timestamp_ns: now_ns,
        };
        for entry in &self.pages {
            if !entry.active {
                continue;
            }
            result.scanned += 1;
            match entry.state {
                PagePoisonState::Corrupted => {
                    result.corrupted += 1;
                }
                PagePoisonState::Poisoned
                | PagePoisonState::Quarantined
                | PagePoisonState::Verified => {
                    result.clean += 1;
                }
                PagePoisonState::Untracked => {}
            }
        }
        // Store in scan history.
        let idx = self.scan_count % MAX_SCAN_HISTORY;
        self.scan_history[idx] = result;
        self.scan_count += 1;
        self.stats.scans_completed += 1;
        result
    }

    // ── page lifecycle ───────────────────────────────────────────

    /// Mark a page as allocated (remove from poison tracking).
    ///
    /// If `verify_on_alloc` is set in config, this will return
    /// an error if the page was previously marked corrupted.
    pub fn on_alloc(&mut self, pfn: u64) -> Result<()> {
        if !self.config.enabled {
            return Ok(());
        }
        if let Some(idx) = self.find_entry(pfn) {
            if self.config.verify_on_alloc && self.pages[idx].state == PagePoisonState::Corrupted {
                return Err(Error::IoError);
            }
            self.pages[idx].active = false;
            self.pages[idx].state = PagePoisonState::Untracked;
        }
        Ok(())
    }

    /// Mark a page as freed and poison it.
    ///
    /// Convenience wrapper around `poison_page` using the
    /// configured free pattern.
    pub fn on_free(&mut self, pfn: u64, order: u8, now_ns: u64) -> Result<()> {
        self.poison_page(pfn, order, self.config.free_pattern, now_ns)
    }

    // ── queries ──────────────────────────────────────────────────

    /// Get the state of a tracked page.
    pub fn page_state(&self, pfn: u64) -> Option<PagePoisonState> {
        self.find_entry(pfn).map(|i| self.pages[i].state)
    }

    /// Get the most recent corruption report.
    pub fn last_report(&self) -> Option<&CorruptionReport> {
        if self.report_count == 0 {
            return None;
        }
        self.reports[self.report_count - 1].as_ref()
    }

    /// Get all stored corruption reports.
    pub fn reports(&self) -> impl Iterator<Item = &CorruptionReport> {
        self.reports
            .iter()
            .take(self.report_count)
            .filter_map(|r| r.as_ref())
    }

    /// Number of stored corruption reports.
    pub const fn report_count(&self) -> usize {
        self.report_count
    }

    /// Get the most recent scan result.
    pub fn last_scan(&self) -> Option<&ScanResult> {
        if self.scan_count == 0 {
            return None;
        }
        let idx = (self.scan_count - 1) % MAX_SCAN_HISTORY;
        Some(&self.scan_history[idx])
    }

    /// Clear all corruption reports.
    pub fn clear_reports(&mut self) {
        for slot in &mut self.reports {
            *slot = None;
        }
        self.report_count = 0;
    }

    /// Reset the manager, releasing all tracked pages.
    pub fn reset(&mut self) {
        for entry in &mut self.pages {
            *entry = PagePoisonEntry::empty();
        }
        self.quarantine.drain();
        self.clear_reports();
        self.scan_count = 0;
        self.stats = PagePoisonStats::default();
    }

    /// Check whether page poisoning is enabled.
    pub const fn is_enabled(&self) -> bool {
        self.config.enabled
    }

    /// Enable or disable page poisoning.
    pub fn set_enabled(&mut self, enabled: bool) {
        self.config.enabled = enabled;
    }

    /// Return the number of pages currently in quarantine.
    pub const fn quarantine_len(&self) -> usize {
        self.quarantine.len()
    }

    /// Fill a buffer with the poison pattern for the given page.
    ///
    /// This is a helper the caller can use to actually write the
    /// pattern to physical memory.
    pub fn fill_pattern(pattern: PoisonPattern, buf: &mut [u8]) {
        let byte = pattern.byte_value();
        for b in buf.iter_mut() {
            *b = byte;
        }
    }

    /// Check whether a buffer matches the expected pattern.
    pub fn check_pattern(pattern: PoisonPattern, buf: &[u8]) -> bool {
        let byte = pattern.byte_value();
        buf.iter().all(|&b| b == byte)
    }
}

impl Default for PagePoisonManager {
    fn default() -> Self {
        Self::new()
    }
}
