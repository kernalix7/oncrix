// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Free page reporting.
//!
//! Implements the kernel facility that reports free pages to a
//! hypervisor or device so that the host can reclaim the backing
//! physical memory. This is the mechanism behind VirtIO balloon
//! free-page hints and similar host-informed memory management.
//!
//! # Design
//!
//! The reporter periodically scans the buddy allocator's free lists
//! and batches contiguous free pages into reports. Reports are only
//! generated for orders at or above a configurable minimum order
//! (default: order 9 = 2 MiB on 4 KiB pages) to limit reporting
//! overhead.
//!
//! A rate limiter prevents excessive reporting during memory churn
//! by enforcing a minimum interval between reporting cycles.
//!
//! # Key types
//!
//! - [`PageReportingOrder`] — minimum buddy order for reporting
//! - [`FreePageReport`] — a single batch of free pages to report
//! - [`ReportingConfig`] — rate limiting and batch configuration
//! - [`PageReportingStats`] — aggregate statistics
//! - [`PageReportingManager`] — the reporting state machine
//!
//! # Reference
//!
//! Linux `mm/page_reporting.c`, `include/linux/page_reporting.h`.

use oncrix_lib::{Error, Result};

// ── Constants ─────────────────────────────────────────────────────

/// Standard page size in bytes.
const PAGE_SIZE: u64 = 4096;

/// Maximum buddy order (order 10 = 4 MiB on 4 KiB pages).
const MAX_ORDER: u32 = 10;

/// Default minimum order for reporting (order 9 = 2 MiB).
const DEFAULT_MIN_ORDER: u32 = 9;

/// Maximum number of reports in a single batch.
const MAX_BATCH_REPORTS: usize = 64;

/// Maximum number of pending report batches.
const MAX_PENDING_BATCHES: usize = 16;

/// Maximum number of NUMA zones tracked.
const MAX_ZONES: usize = 16;

/// Default minimum interval between reporting cycles (ms).
const DEFAULT_MIN_INTERVAL_MS: u64 = 500;

/// Default maximum pages per batch.
const DEFAULT_MAX_PAGES_PER_BATCH: u64 = 512;

// ── PageReportingOrder ────────────────────────────────────────────

/// Minimum buddy order threshold for free page reporting.
///
/// Only free blocks at this order or higher are reported. Lower
/// orders produce too many small reports and waste host resources.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PageReportingOrder(u32);

impl PageReportingOrder {
    /// Create a new reporting order threshold.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `order` exceeds
    /// [`MAX_ORDER`].
    pub fn new(order: u32) -> Result<Self> {
        if order > MAX_ORDER {
            return Err(Error::InvalidArgument);
        }
        Ok(Self(order))
    }

    /// The raw order value.
    pub const fn as_u32(self) -> u32 {
        self.0
    }

    /// Number of contiguous pages at this order (2^order).
    pub const fn pages(self) -> u64 {
        1u64 << self.0
    }

    /// Size in bytes at this order.
    pub const fn size_bytes(self) -> u64 {
        self.pages() * PAGE_SIZE
    }
}

impl Default for PageReportingOrder {
    fn default() -> Self {
        Self(DEFAULT_MIN_ORDER)
    }
}

// ── FreePageReport ────────────────────────────────────────────────

/// A single free page report entry.
///
/// Represents a contiguous block of free pages that can be reported
/// to the hypervisor or device.
#[derive(Debug, Clone, Copy)]
pub struct FreePageReport {
    /// Physical frame number of the first page.
    pub pfn: u64,
    /// Buddy order of this free block.
    pub order: u32,
    /// NUMA zone index.
    pub zone: u32,
    /// Whether this report has been delivered.
    pub delivered: bool,
    /// Whether this slot is active.
    pub active: bool,
}

impl FreePageReport {
    /// Creates an empty, inactive report.
    const fn empty() -> Self {
        Self {
            pfn: 0,
            order: 0,
            zone: 0,
            delivered: false,
            active: false,
        }
    }

    /// Number of contiguous pages in this report.
    pub const fn page_count(&self) -> u64 {
        1u64 << self.order
    }

    /// Size in bytes.
    pub const fn size_bytes(&self) -> u64 {
        self.page_count() * PAGE_SIZE
    }
}

// ── ReportBatch ───────────────────────────────────────────────────

/// A batch of free page reports ready for delivery.
#[derive(Debug, Clone, Copy)]
pub struct ReportBatch {
    /// Reports in this batch.
    reports: [FreePageReport; MAX_BATCH_REPORTS],
    /// Number of active reports.
    count: usize,
    /// Total pages in this batch.
    total_pages: u64,
    /// Batch sequence number.
    sequence: u64,
    /// Whether this batch is active.
    active: bool,
}

impl ReportBatch {
    /// Creates an empty, inactive batch.
    const fn empty() -> Self {
        Self {
            reports: [FreePageReport::empty(); MAX_BATCH_REPORTS],
            count: 0,
            total_pages: 0,
            sequence: 0,
            active: false,
        }
    }

    /// Number of reports in this batch.
    pub fn report_count(&self) -> usize {
        self.count
    }

    /// Total pages covered by this batch.
    pub fn total_pages(&self) -> u64 {
        self.total_pages
    }

    /// Batch sequence number.
    pub fn sequence(&self) -> u64 {
        self.sequence
    }

    /// Iterate over active reports in this batch.
    pub fn reports(&self) -> impl Iterator<Item = &FreePageReport> {
        self.reports[..self.count].iter().filter(|r| r.active)
    }
}

// ── ZoneFreeSummary ───────────────────────────────────────────────

/// Per-zone summary of free pages by order.
#[derive(Debug, Clone, Copy)]
pub struct ZoneFreeSummary {
    /// Zone index.
    pub zone_id: u32,
    /// Free block counts per order (index = order).
    pub free_counts: [u64; (MAX_ORDER + 1) as usize],
    /// Whether this zone is active.
    pub active: bool,
}

impl ZoneFreeSummary {
    /// Creates an empty, inactive zone summary.
    const fn empty() -> Self {
        Self {
            zone_id: 0,
            free_counts: [0; (MAX_ORDER + 1) as usize],
            active: false,
        }
    }

    /// Total free pages across all orders in this zone.
    pub fn total_free_pages(&self) -> u64 {
        let mut total: u64 = 0;
        let mut order: u32 = 0;
        while order <= MAX_ORDER {
            total = total
                .saturating_add(self.free_counts[order as usize].saturating_mul(1u64 << order));
            order += 1;
        }
        total
    }

    /// Free pages at or above a given order.
    pub fn free_pages_above_order(&self, min_order: u32) -> u64 {
        let mut total: u64 = 0;
        let start = if min_order > MAX_ORDER {
            return 0;
        } else {
            min_order
        };
        let mut order = start;
        while order <= MAX_ORDER {
            total = total
                .saturating_add(self.free_counts[order as usize].saturating_mul(1u64 << order));
            order += 1;
        }
        total
    }
}

// ── ReportingConfig ───────────────────────────────────────────────

/// Configuration for the page reporting subsystem.
#[derive(Debug, Clone, Copy)]
pub struct ReportingConfig {
    /// Minimum buddy order for reporting.
    pub min_order: PageReportingOrder,
    /// Minimum interval between reporting cycles (ms).
    pub min_interval_ms: u64,
    /// Maximum pages per batch.
    pub max_pages_per_batch: u64,
    /// Whether reporting is enabled.
    pub enabled: bool,
}

impl Default for ReportingConfig {
    fn default() -> Self {
        Self {
            min_order: PageReportingOrder::default(),
            min_interval_ms: DEFAULT_MIN_INTERVAL_MS,
            max_pages_per_batch: DEFAULT_MAX_PAGES_PER_BATCH,
            enabled: true,
        }
    }
}

impl ReportingConfig {
    /// Create a new configuration.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `min_order` exceeds
    /// [`MAX_ORDER`].
    pub fn new(min_order: u32, min_interval_ms: u64, max_pages_per_batch: u64) -> Result<Self> {
        Ok(Self {
            min_order: PageReportingOrder::new(min_order)?,
            min_interval_ms,
            max_pages_per_batch,
            enabled: true,
        })
    }
}

// ── PageReportingStats ────────────────────────────────────────────

/// Aggregate statistics for the page reporting subsystem.
#[derive(Debug, Clone, Copy, Default)]
pub struct PageReportingStats {
    /// Total reporting cycles executed.
    pub cycles: u64,
    /// Total batches created.
    pub batches_created: u64,
    /// Total batches delivered.
    pub batches_delivered: u64,
    /// Total individual reports generated.
    pub reports_generated: u64,
    /// Total pages reported.
    pub pages_reported: u64,
    /// Cycles skipped due to rate limiting.
    pub rate_limited: u64,
    /// Cycles with nothing to report.
    pub empty_cycles: u64,
    /// Zones scanned.
    pub zones_scanned: u64,
}

// ── PageReportingManager ──────────────────────────────────────────

/// The page reporting state machine.
///
/// Scans zone free lists, batches contiguous free blocks at or above
/// the minimum order, and delivers reports. Rate limiting prevents
/// excessive host notification during memory churn.
pub struct PageReportingManager {
    /// Configuration.
    config: ReportingConfig,
    /// Per-zone free page summaries.
    zones: [ZoneFreeSummary; MAX_ZONES],
    /// Number of active zones.
    zone_count: usize,
    /// Pending report batches.
    batches: [ReportBatch; MAX_PENDING_BATCHES],
    /// Next batch sequence number.
    next_sequence: u64,
    /// Timestamp of the last reporting cycle (ms since boot).
    last_cycle_ms: u64,
    /// Statistics.
    stats: PageReportingStats,
}

impl Default for PageReportingManager {
    fn default() -> Self {
        Self::new()
    }
}

impl PageReportingManager {
    /// Creates a new manager with default configuration.
    pub const fn new() -> Self {
        Self {
            config: ReportingConfig {
                min_order: PageReportingOrder(DEFAULT_MIN_ORDER),
                min_interval_ms: DEFAULT_MIN_INTERVAL_MS,
                max_pages_per_batch: DEFAULT_MAX_PAGES_PER_BATCH,
                enabled: true,
            },
            zones: [ZoneFreeSummary::empty(); MAX_ZONES],
            zone_count: 0,
            batches: [ReportBatch::empty(); MAX_PENDING_BATCHES],
            next_sequence: 0,
            last_cycle_ms: 0,
            stats: PageReportingStats {
                cycles: 0,
                batches_created: 0,
                batches_delivered: 0,
                reports_generated: 0,
                pages_reported: 0,
                rate_limited: 0,
                empty_cycles: 0,
                zones_scanned: 0,
            },
        }
    }

    /// Creates a new manager with custom configuration.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if the config is invalid.
    pub fn with_config(config: ReportingConfig) -> Result<Self> {
        // Validate min_order through PageReportingOrder::new.
        let _ = PageReportingOrder::new(config.min_order.as_u32())?;
        let mut mgr = Self::new();
        mgr.config = config;
        Ok(mgr)
    }

    // ── Zone management ───────────────────────────────────────────

    /// Register a NUMA zone for free page scanning.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the zone table is full.
    /// Returns [`Error::AlreadyExists`] if the zone is registered.
    pub fn register_zone(&mut self, zone_id: u32) -> Result<()> {
        if self.zones.iter().any(|z| z.active && z.zone_id == zone_id) {
            return Err(Error::AlreadyExists);
        }
        let slot = self
            .zones
            .iter_mut()
            .find(|z| !z.active)
            .ok_or(Error::OutOfMemory)?;
        *slot = ZoneFreeSummary::empty();
        slot.zone_id = zone_id;
        slot.active = true;
        self.zone_count += 1;
        Ok(())
    }

    /// Unregister a zone.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the zone is not registered.
    pub fn unregister_zone(&mut self, zone_id: u32) -> Result<()> {
        let slot = self
            .zones
            .iter_mut()
            .find(|z| z.active && z.zone_id == zone_id)
            .ok_or(Error::NotFound)?;
        slot.active = false;
        self.zone_count = self.zone_count.saturating_sub(1);
        Ok(())
    }

    /// Update the free block counts for a zone.
    ///
    /// `counts` is indexed by buddy order. Entries beyond
    /// `MAX_ORDER` are ignored.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the zone is not registered.
    pub fn update_zone_free_counts(&mut self, zone_id: u32, counts: &[u64]) -> Result<()> {
        let zone = self
            .zones
            .iter_mut()
            .find(|z| z.active && z.zone_id == zone_id)
            .ok_or(Error::NotFound)?;

        // Reset and copy available counts.
        zone.free_counts = [0; (MAX_ORDER + 1) as usize];
        let copy_len = counts.len().min((MAX_ORDER + 1) as usize);
        zone.free_counts[..copy_len].copy_from_slice(&counts[..copy_len]);
        Ok(())
    }

    // ── Reporting cycle ───────────────────────────────────────────

    /// Execute a reporting cycle.
    ///
    /// Scans all zones for free blocks at or above the minimum
    /// order, batches them into reports, and queues them for
    /// delivery.
    ///
    /// # Arguments
    ///
    /// - `now_ms` — current timestamp in milliseconds since boot.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Busy`] if reporting is disabled or
    /// rate limited.
    /// Returns [`Error::OutOfMemory`] if the batch queue is full.
    pub fn run_cycle(&mut self, now_ms: u64) -> Result<u64> {
        if !self.config.enabled {
            return Err(Error::Busy);
        }

        // Rate limiting.
        if now_ms
            < self
                .last_cycle_ms
                .saturating_add(self.config.min_interval_ms)
        {
            self.stats.rate_limited += 1;
            return Err(Error::Busy);
        }

        self.stats.cycles += 1;
        self.last_cycle_ms = now_ms;

        let min_order = self.config.min_order.as_u32();
        let max_pages = self.config.max_pages_per_batch;

        // Find a free batch slot.
        let batch_idx = self
            .batches
            .iter()
            .position(|b| !b.active)
            .ok_or(Error::OutOfMemory)?;

        let seq = self.next_sequence;
        self.next_sequence += 1;

        self.batches[batch_idx] = ReportBatch::empty();
        self.batches[batch_idx].sequence = seq;
        self.batches[batch_idx].active = true;

        let mut report_count: usize = 0;
        let mut total_pages: u64 = 0;

        // Scan each zone.
        for zone_idx in 0..MAX_ZONES {
            if !self.zones[zone_idx].active {
                continue;
            }
            self.stats.zones_scanned += 1;

            let zone_id = self.zones[zone_idx].zone_id;

            // Scan orders from min_order to MAX_ORDER.
            let mut order = min_order;
            while order <= MAX_ORDER {
                let free_blocks = self.zones[zone_idx].free_counts[order as usize];

                let mut block = 0u64;
                while block < free_blocks {
                    if report_count >= MAX_BATCH_REPORTS {
                        break;
                    }
                    let block_pages = 1u64 << order;
                    if total_pages.saturating_add(block_pages) > max_pages {
                        break;
                    }

                    // Generate a synthetic PFN based on zone, order,
                    // and block index for identification.
                    let pfn = (zone_id as u64)
                        .saturating_mul(1 << 20)
                        .saturating_add((order as u64).saturating_mul(1 << 16))
                        .saturating_add(block.saturating_mul(block_pages));

                    self.batches[batch_idx].reports[report_count] = FreePageReport {
                        pfn,
                        order,
                        zone: zone_id,
                        delivered: false,
                        active: true,
                    };
                    report_count += 1;
                    total_pages += block_pages;
                    self.stats.reports_generated += 1;

                    block += 1;
                }

                if report_count >= MAX_BATCH_REPORTS || total_pages >= max_pages {
                    break;
                }
                order += 1;
            }

            if report_count >= MAX_BATCH_REPORTS || total_pages >= max_pages {
                break;
            }
        }

        if report_count == 0 {
            // Nothing to report — deactivate the batch.
            self.batches[batch_idx].active = false;
            self.stats.empty_cycles += 1;
            return Ok(0);
        }

        self.batches[batch_idx].count = report_count;
        self.batches[batch_idx].total_pages = total_pages;
        self.stats.batches_created += 1;
        self.stats.pages_reported += total_pages;

        Ok(total_pages)
    }

    /// Mark a batch as delivered.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if no batch with the given
    /// sequence exists.
    pub fn mark_delivered(&mut self, sequence: u64) -> Result<()> {
        let batch = self
            .batches
            .iter_mut()
            .find(|b| b.active && b.sequence == sequence)
            .ok_or(Error::NotFound)?;

        for report in batch.reports[..batch.count].iter_mut() {
            report.delivered = true;
        }
        self.stats.batches_delivered += 1;
        Ok(())
    }

    /// Discard a delivered batch to free the slot.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if no batch with the given
    /// sequence exists.
    /// Returns [`Error::InvalidArgument`] if the batch has not
    /// been delivered yet.
    pub fn discard_batch(&mut self, sequence: u64) -> Result<()> {
        let batch = self
            .batches
            .iter_mut()
            .find(|b| b.active && b.sequence == sequence)
            .ok_or(Error::NotFound)?;

        // Only allow discarding delivered batches.
        let all_delivered = batch.reports[..batch.count]
            .iter()
            .all(|r| !r.active || r.delivered);
        if !all_delivered {
            return Err(Error::InvalidArgument);
        }

        batch.active = false;
        Ok(())
    }

    /// Discard all delivered batches.
    pub fn discard_delivered(&mut self) {
        for batch in self.batches.iter_mut() {
            if !batch.active {
                continue;
            }
            let all_delivered = batch.reports[..batch.count]
                .iter()
                .all(|r| !r.active || r.delivered);
            if all_delivered {
                batch.active = false;
            }
        }
    }

    // ── Configuration ─────────────────────────────────────────────

    /// Update the minimum reporting order.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `order` exceeds
    /// [`MAX_ORDER`].
    pub fn set_min_order(&mut self, order: u32) -> Result<()> {
        self.config.min_order = PageReportingOrder::new(order)?;
        Ok(())
    }

    /// Update the minimum interval between cycles.
    pub fn set_min_interval_ms(&mut self, ms: u64) {
        self.config.min_interval_ms = ms;
    }

    /// Update the maximum pages per batch.
    pub fn set_max_pages_per_batch(&mut self, pages: u64) {
        self.config.max_pages_per_batch = pages;
    }

    /// Enable or disable reporting.
    pub fn set_enabled(&mut self, enabled: bool) {
        self.config.enabled = enabled;
    }

    // ── Accessors ─────────────────────────────────────────────────

    /// Current configuration.
    pub fn config(&self) -> &ReportingConfig {
        &self.config
    }

    /// Aggregate statistics.
    pub fn stats(&self) -> &PageReportingStats {
        &self.stats
    }

    /// Number of active zones.
    pub fn zone_count(&self) -> usize {
        self.zone_count
    }

    /// Number of pending (undelivered) batches.
    pub fn pending_batch_count(&self) -> usize {
        self.batches.iter().filter(|b| b.active).count()
    }

    /// Look up a zone summary by ID.
    pub fn zone_summary(&self, zone_id: u32) -> Option<&ZoneFreeSummary> {
        self.zones.iter().find(|z| z.active && z.zone_id == zone_id)
    }

    /// Look up a pending batch by sequence number.
    pub fn batch_by_sequence(&self, sequence: u64) -> Option<&ReportBatch> {
        self.batches
            .iter()
            .find(|b| b.active && b.sequence == sequence)
    }

    /// Iterate over all pending batches.
    pub fn pending_batches(&self) -> impl Iterator<Item = &ReportBatch> {
        self.batches.iter().filter(|b| b.active)
    }

    /// Total reportable free pages across all zones.
    pub fn total_reportable_pages(&self) -> u64 {
        let min = self.config.min_order.as_u32();
        self.zones
            .iter()
            .filter(|z| z.active)
            .map(|z| z.free_pages_above_order(min))
            .sum()
    }
}
