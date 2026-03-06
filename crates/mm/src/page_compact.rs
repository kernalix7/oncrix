// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Memory compaction engine for defragmenting physical memory.
//!
//! Compaction moves allocated pages from sparse regions into dense
//! regions, creating large contiguous free blocks for higher-order
//! allocations (huge pages, DMA buffers).
//!
//! # Design
//!
//! Uses dual-scanner approach per zone:
//! - **Free scanner**: scans backwards from zone end, finding free pages
//! - **Migrate scanner**: scans forward from zone start, finding
//!   movable pages
//! - When both scanners meet, compaction for that zone is complete
//!
//! # Subsystems
//!
//! - [`CompactPriority`] — async / sync_light / sync_full
//! - [`CompactControl`] — per-zone scanner state
//! - [`IsolatedPage`] — page isolated for migration
//! - [`CompactZoneState`] — zone compaction status
//! - [`CompactEngine`] — main compaction engine
//! - [`CompactStats`] — aggregate statistics
//!
//! Reference: Linux `mm/compaction.c`, `include/linux/compaction.h`.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Standard page size (4 KiB).
const PAGE_SIZE: u64 = 4096;

/// Maximum pages to isolate per scanner pass.
const MAX_ISOLATE_BATCH: usize = 64;

/// Maximum zones managed by the engine.
const MAX_ZONES: usize = 4;

/// Maximum pages tracked per isolation batch.
const MAX_ISOLATED_PAGES: usize = 256;

/// Minimum order worth compacting for.
const MIN_COMPACT_ORDER: u32 = 1;

/// Maximum order for compaction targets.
const MAX_COMPACT_ORDER: u32 = 10;

/// Pages to scan before yielding (async mode).
const SCAN_YIELD_PAGES: u64 = 128;

// -------------------------------------------------------------------
// CompactPriority
// -------------------------------------------------------------------

/// Compaction priority / synchronization mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CompactPriority {
    /// Asynchronous — skip locked pages, don't block.
    #[default]
    Async,
    /// Light synchronous — wait briefly for locks.
    SyncLight,
    /// Full synchronous — block as needed for migration.
    SyncFull,
}

impl CompactPriority {
    /// Returns whether this priority allows blocking.
    pub const fn may_block(self) -> bool {
        matches!(self, Self::SyncFull)
    }

    /// Returns whether this priority should skip locked pages.
    pub const fn skip_locked(self) -> bool {
        matches!(self, Self::Async)
    }
}

// -------------------------------------------------------------------
// CompactResult
// -------------------------------------------------------------------

/// Result of a compaction attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CompactResult {
    /// Not attempted.
    #[default]
    NotAttempted,
    /// Compaction succeeded — enough contiguous memory available.
    Success,
    /// Compaction ran but did not create enough contiguous space.
    Incomplete,
    /// Scanners have met — zone is fully compacted.
    Complete,
    /// Skipped due to sufficient free memory already.
    Skipped,
    /// Failed — no movable pages found.
    NoMovable,
}

// -------------------------------------------------------------------
// IsolatedPage
// -------------------------------------------------------------------

/// A page isolated for migration during compaction.
#[derive(Debug, Clone, Copy)]
pub struct IsolatedPage {
    /// Physical frame number of the page.
    pfn: u64,
    /// Whether the page is movable.
    movable: bool,
    /// Whether the page is an LRU page.
    lru: bool,
    /// Whether the page is a slab page.
    slab: bool,
    /// Migration type (unmovable, reclaimable, movable).
    migrate_type: u8,
}

impl IsolatedPage {
    /// Creates a new isolated page descriptor.
    pub const fn new(pfn: u64) -> Self {
        Self {
            pfn,
            movable: true,
            lru: false,
            slab: false,
            migrate_type: 0,
        }
    }

    /// Returns the PFN.
    pub const fn pfn(&self) -> u64 {
        self.pfn
    }

    /// Returns whether this page is movable.
    pub const fn is_movable(&self) -> bool {
        self.movable
    }

    /// Returns the physical address.
    pub const fn phys_addr(&self) -> u64 {
        self.pfn * PAGE_SIZE
    }
}

impl Default for IsolatedPage {
    fn default() -> Self {
        Self::new(0)
    }
}

// -------------------------------------------------------------------
// CompactControl
// -------------------------------------------------------------------

/// Per-zone compaction scanner state.
#[derive(Debug, Clone, Copy)]
pub struct CompactControl {
    /// Zone identifier.
    zone_id: u32,
    /// Current free scanner PFN (scans backward).
    free_pfn: u64,
    /// Current migrate scanner PFN (scans forward).
    migrate_pfn: u64,
    /// Zone start PFN.
    zone_start: u64,
    /// Zone end PFN (exclusive).
    zone_end: u64,
    /// Target allocation order.
    target_order: u32,
    /// Compaction priority.
    priority: CompactPriority,
    /// Number of free pages isolated this pass.
    nr_freepages: u64,
    /// Number of migrate pages isolated this pass.
    nr_migratepages: u64,
    /// Total pages scanned by free scanner.
    total_free_scanned: u64,
    /// Total pages scanned by migrate scanner.
    total_migrate_scanned: u64,
    /// Whether scanners have met.
    scanners_met: bool,
}

impl CompactControl {
    /// Creates a new compaction control for a zone.
    pub const fn new(
        zone_id: u32,
        zone_start: u64,
        zone_end: u64,
        target_order: u32,
        priority: CompactPriority,
    ) -> Self {
        Self {
            zone_id,
            free_pfn: zone_end,
            migrate_pfn: zone_start,
            zone_start,
            zone_end,
            target_order,
            priority,
            nr_freepages: 0,
            nr_migratepages: 0,
            total_free_scanned: 0,
            total_migrate_scanned: 0,
            scanners_met: false,
        }
    }

    /// Returns the zone identifier.
    pub const fn zone_id(&self) -> u32 {
        self.zone_id
    }

    /// Returns the target allocation order.
    pub const fn target_order(&self) -> u32 {
        self.target_order
    }

    /// Returns whether the scanners have met.
    pub const fn scanners_met(&self) -> bool {
        self.scanners_met
    }

    /// Resets the scanners for a new pass.
    pub fn reset(&mut self) {
        self.free_pfn = self.zone_end;
        self.migrate_pfn = self.zone_start;
        self.nr_freepages = 0;
        self.nr_migratepages = 0;
        self.scanners_met = false;
    }

    /// Advances the free scanner, isolating free pages.
    ///
    /// Returns the number of free pages found in this batch.
    pub fn isolate_freepages(&mut self, free_bitmap: &[bool]) -> usize {
        let mut found = 0;
        let mut pfn = self.free_pfn;

        while pfn > self.migrate_pfn && found < MAX_ISOLATE_BATCH {
            pfn = pfn.saturating_sub(1);
            let idx = (pfn - self.zone_start) as usize;
            if idx < free_bitmap.len() && free_bitmap[idx] {
                found += 1;
            }
            self.total_free_scanned += 1;
        }

        self.free_pfn = pfn;
        self.nr_freepages += found as u64;

        // Check if scanners have met
        if self.free_pfn <= self.migrate_pfn {
            self.scanners_met = true;
        }

        found
    }

    /// Advances the migrate scanner, isolating movable pages.
    ///
    /// Returns the number of movable pages found in this batch.
    pub fn isolate_migratepages(&mut self, movable_bitmap: &[bool]) -> usize {
        let mut found = 0;
        let mut pfn = self.migrate_pfn;

        while pfn < self.free_pfn && found < MAX_ISOLATE_BATCH {
            let idx = (pfn - self.zone_start) as usize;
            if idx < movable_bitmap.len() && movable_bitmap[idx] {
                found += 1;
            }
            pfn += 1;
            self.total_migrate_scanned += 1;
        }

        self.migrate_pfn = pfn;
        self.nr_migratepages += found as u64;

        if self.migrate_pfn >= self.free_pfn {
            self.scanners_met = true;
        }

        found
    }
}

impl Default for CompactControl {
    fn default() -> Self {
        Self::new(0, 0, 0, 0, CompactPriority::Async)
    }
}

// -------------------------------------------------------------------
// CompactZoneState
// -------------------------------------------------------------------

/// Overall compaction state for a zone.
#[derive(Debug, Clone, Copy)]
pub struct CompactZoneState {
    /// Zone identifier.
    pub zone_id: u32,
    /// Zone start PFN.
    pub zone_start: u64,
    /// Zone end PFN.
    pub zone_end: u64,
    /// Last compaction result.
    pub last_result: CompactResult,
    /// Minimum order that triggers compaction.
    pub compact_order_threshold: u32,
    /// Number of compaction passes run.
    pub passes: u64,
    /// Number of pages migrated.
    pub pages_migrated: u64,
    /// Number of pages that failed to migrate.
    pub migrate_failures: u64,
    /// Whether compaction is deferred for this zone.
    pub deferred: bool,
    /// Deferred counter (compaction retries before re-enabling).
    pub defer_count: u32,
}

impl CompactZoneState {
    /// Creates a new zone state.
    pub const fn new(zone_id: u32, zone_start: u64, zone_end: u64) -> Self {
        Self {
            zone_id,
            zone_start,
            zone_end,
            last_result: CompactResult::NotAttempted,
            compact_order_threshold: MIN_COMPACT_ORDER,
            passes: 0,
            pages_migrated: 0,
            migrate_failures: 0,
            deferred: false,
            defer_count: 0,
        }
    }

    /// Returns the zone size in pages.
    pub const fn zone_pages(&self) -> u64 {
        self.zone_end - self.zone_start
    }

    /// Defers compaction for this zone.
    pub fn defer(&mut self) {
        self.deferred = true;
        self.defer_count += 1;
    }

    /// Un-defers compaction.
    pub fn undefer(&mut self) {
        self.deferred = false;
        self.defer_count = 0;
    }
}

impl Default for CompactZoneState {
    fn default() -> Self {
        Self::new(0, 0, 0)
    }
}

// -------------------------------------------------------------------
// CompactStats
// -------------------------------------------------------------------

/// Aggregate compaction statistics.
#[derive(Debug, Clone, Copy, Default)]
pub struct CompactStats {
    /// Total compaction passes.
    pub total_passes: u64,
    /// Total pages migrated.
    pub total_migrated: u64,
    /// Total pages that failed migration.
    pub total_failed: u64,
    /// Total pages scanned by free scanner.
    pub free_scanned: u64,
    /// Total pages scanned by migrate scanner.
    pub migrate_scanned: u64,
    /// Number of compactions that succeeded.
    pub successes: u64,
    /// Number of compactions that completed (scanners met).
    pub completions: u64,
}

impl CompactStats {
    /// Creates new zeroed statistics.
    pub const fn new() -> Self {
        Self {
            total_passes: 0,
            total_migrated: 0,
            total_failed: 0,
            free_scanned: 0,
            migrate_scanned: 0,
            successes: 0,
            completions: 0,
        }
    }
}

// -------------------------------------------------------------------
// CompactEngine
// -------------------------------------------------------------------

/// Main memory compaction engine managing multiple zones.
pub struct CompactEngine {
    /// Per-zone compaction state.
    zones: [CompactZoneState; MAX_ZONES],
    /// Number of active zones.
    nr_zones: usize,
    /// Aggregate statistics.
    stats: CompactStats,
    /// Default priority for proactive compaction.
    default_priority: CompactPriority,
    /// Whether the engine is enabled.
    enabled: bool,
}

impl CompactEngine {
    /// Creates a new compaction engine.
    pub const fn new() -> Self {
        Self {
            zones: [const { CompactZoneState::new(0, 0, 0) }; MAX_ZONES],
            nr_zones: 0,
            stats: CompactStats::new(),
            default_priority: CompactPriority::Async,
            enabled: true,
        }
    }

    /// Registers a zone for compaction.
    pub fn add_zone(&mut self, zone_id: u32, start_pfn: u64, end_pfn: u64) -> Result<()> {
        if self.nr_zones >= MAX_ZONES {
            return Err(Error::OutOfMemory);
        }
        if start_pfn >= end_pfn {
            return Err(Error::InvalidArgument);
        }
        self.zones[self.nr_zones] = CompactZoneState::new(zone_id, start_pfn, end_pfn);
        self.nr_zones += 1;
        Ok(())
    }

    /// Runs compaction on a specific zone.
    ///
    /// This is the main entry point. Callers must provide bitmaps
    /// indicating which pages are free and which are movable.
    pub fn compact_zone(
        &mut self,
        zone_idx: usize,
        target_order: u32,
        priority: CompactPriority,
        free_bitmap: &[bool],
        movable_bitmap: &[bool],
    ) -> Result<CompactResult> {
        if zone_idx >= self.nr_zones {
            return Err(Error::InvalidArgument);
        }
        if target_order < MIN_COMPACT_ORDER || target_order > MAX_COMPACT_ORDER {
            return Err(Error::InvalidArgument);
        }

        let zone = &self.zones[zone_idx];
        if zone.deferred {
            return Ok(CompactResult::Skipped);
        }

        let mut control = CompactControl::new(
            zone.zone_id,
            zone.zone_start,
            zone.zone_end,
            target_order,
            priority,
        );

        let mut pages_migrated: u64 = 0;

        // Main compaction loop
        while !control.scanners_met() {
            // Step 1: isolate free pages
            let free_found = control.isolate_freepages(free_bitmap);

            // Step 2: isolate movable pages
            let migrate_found = control.isolate_migratepages(movable_bitmap);

            // Step 3: migrate (simulated — actual copy done by caller)
            let migrated = free_found.min(migrate_found);
            pages_migrated += migrated as u64;

            // Yield point for async mode
            if priority == CompactPriority::Async
                && control.total_migrate_scanned > SCAN_YIELD_PAGES
            {
                break;
            }
        }

        // Update zone state
        let result = if control.scanners_met() {
            CompactResult::Complete
        } else if pages_migrated > 0 {
            CompactResult::Success
        } else {
            CompactResult::NoMovable
        };

        self.zones[zone_idx].last_result = result;
        self.zones[zone_idx].passes += 1;
        self.zones[zone_idx].pages_migrated += pages_migrated;

        // Update global stats
        self.stats.total_passes += 1;
        self.stats.total_migrated += pages_migrated;
        self.stats.free_scanned += control.total_free_scanned;
        self.stats.migrate_scanned += control.total_migrate_scanned;
        if result == CompactResult::Success {
            self.stats.successes += 1;
        }
        if result == CompactResult::Complete {
            self.stats.completions += 1;
        }

        Ok(result)
    }

    /// Compacts all zones for the target order.
    pub fn compact_all(
        &mut self,
        target_order: u32,
        free_bitmaps: &[&[bool]],
        movable_bitmaps: &[&[bool]],
    ) -> Result<usize> {
        let mut successes = 0;
        let nr = self
            .nr_zones
            .min(free_bitmaps.len())
            .min(movable_bitmaps.len());
        for i in 0..nr {
            let result = self.compact_zone(
                i,
                target_order,
                self.default_priority,
                free_bitmaps[i],
                movable_bitmaps[i],
            )?;
            if result == CompactResult::Success || result == CompactResult::Complete {
                successes += 1;
            }
        }
        Ok(successes)
    }

    /// Sets the default priority for proactive compaction.
    pub fn set_default_priority(&mut self, priority: CompactPriority) {
        self.default_priority = priority;
    }

    /// Sets the compact order threshold for a zone.
    pub fn set_order_threshold(&mut self, zone_idx: usize, order: u32) -> Result<()> {
        if zone_idx >= self.nr_zones {
            return Err(Error::InvalidArgument);
        }
        self.zones[zone_idx].compact_order_threshold = order;
        Ok(())
    }

    /// Returns a reference to the aggregate statistics.
    pub const fn stats(&self) -> &CompactStats {
        &self.stats
    }

    /// Returns the number of active zones.
    pub const fn nr_zones(&self) -> usize {
        self.nr_zones
    }

    /// Returns a reference to a zone's state.
    pub fn zone(&self, idx: usize) -> Result<&CompactZoneState> {
        if idx >= self.nr_zones {
            return Err(Error::InvalidArgument);
        }
        Ok(&self.zones[idx])
    }

    /// Enables or disables the engine.
    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }
}

impl Default for CompactEngine {
    fn default() -> Self {
        Self::new()
    }
}
