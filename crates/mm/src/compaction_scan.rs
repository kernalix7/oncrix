// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Memory compaction scanner.
//!
//! Memory compaction defragments physical memory by moving used pages
//! to create larger contiguous free regions. The scanner has two
//! cursors: a migration scanner that finds movable pages (scanning
//! from the bottom of the zone) and a free scanner that finds free
//! pages (scanning from the top). When they meet, compaction for that
//! zone is complete.
//!
//! # Design
//!
//! ```text
//!  Zone memory layout:
//!   [used][free][used][used][free][free][used][free]
//!      ↑ migrate scanner                   ↑ free scanner
//!      → scans right                       ← scans left
//!
//!  When cursors meet → zone is compacted
//! ```
//!
//! # Key Types
//!
//! - [`CompactionScanner`] — the dual-cursor scanner
//! - [`ScanResult`] — outcome of a scan pass
//! - [`CompactionZoneState`] — per-zone compaction state
//! - [`CompactionController`] — manages compaction across zones
//!
//! Reference: Linux `mm/compaction.c`, `include/linux/compaction.h`.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Maximum zones.
const MAX_ZONES: usize = 8;

/// Maximum PFNs per zone (simplified).
const MAX_PFNS_PER_ZONE: u64 = 1 << 20;

/// Pages scanned per pass.
const SCAN_BATCH: u64 = 64;

/// Minimum order to compact for.
const MIN_COMPACT_ORDER: u8 = 1;

// -------------------------------------------------------------------
// CompactionMode
// -------------------------------------------------------------------

/// Mode of compaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompactionMode {
    /// Synchronous — block until done.
    Sync,
    /// Asynchronous — yield periodically.
    Async,
    /// Light — only compact if cheap.
    Light,
}

impl Default for CompactionMode {
    fn default() -> Self {
        Self::Async
    }
}

// -------------------------------------------------------------------
// ScanResult
// -------------------------------------------------------------------

/// Outcome of a compaction scan pass.
#[derive(Debug, Clone, Copy)]
pub struct ScanResult {
    /// Pages migrated in this pass.
    pub migrated: u64,
    /// Free pages found for landing.
    pub free_found: u64,
    /// Whether the cursors have met.
    pub complete: bool,
    /// Largest free order achieved.
    pub max_order: u8,
}

impl ScanResult {
    /// Create an empty result.
    pub const fn empty() -> Self {
        Self {
            migrated: 0,
            free_found: 0,
            complete: false,
            max_order: 0,
        }
    }
}

// -------------------------------------------------------------------
// CompactionScanner
// -------------------------------------------------------------------

/// Dual-cursor compaction scanner for a single zone.
pub struct CompactionScanner {
    /// Zone start PFN.
    zone_start: u64,
    /// Zone end PFN.
    zone_end: u64,
    /// Migration scanner position (scans upward).
    migrate_pfn: u64,
    /// Free scanner position (scans downward).
    free_pfn: u64,
    /// Target allocation order.
    target_order: u8,
    /// Total pages migrated.
    total_migrated: u64,
    /// Total passes performed.
    total_passes: u64,
    /// Whether compaction is complete for this zone.
    complete: bool,
}

impl CompactionScanner {
    /// Create a new scanner for a zone.
    pub const fn new(zone_start: u64, zone_end: u64, target_order: u8) -> Self {
        Self {
            zone_start,
            zone_end,
            migrate_pfn: zone_start,
            free_pfn: zone_end,
            target_order,
            total_migrated: 0,
            total_passes: 0,
            complete: false,
        }
    }

    /// Return the zone start PFN.
    pub const fn zone_start(&self) -> u64 {
        self.zone_start
    }

    /// Return the zone end PFN.
    pub const fn zone_end(&self) -> u64 {
        self.zone_end
    }

    /// Return the migration cursor position.
    pub const fn migrate_pfn(&self) -> u64 {
        self.migrate_pfn
    }

    /// Return the free cursor position.
    pub const fn free_pfn(&self) -> u64 {
        self.free_pfn
    }

    /// Return the target order.
    pub const fn target_order(&self) -> u8 {
        self.target_order
    }

    /// Check whether compaction is complete.
    pub const fn is_complete(&self) -> bool {
        self.complete
    }

    /// Return total pages migrated.
    pub const fn total_migrated(&self) -> u64 {
        self.total_migrated
    }

    /// Return total passes.
    pub const fn total_passes(&self) -> u64 {
        self.total_passes
    }

    /// Reset the scanner to scan again.
    pub fn reset(&mut self) {
        self.migrate_pfn = self.zone_start;
        self.free_pfn = self.zone_end;
        self.complete = false;
    }

    /// Perform one scan pass.
    pub fn scan_pass(&mut self) -> ScanResult {
        if self.complete || self.migrate_pfn >= self.free_pfn {
            self.complete = true;
            return ScanResult {
                migrated: 0,
                free_found: 0,
                complete: true,
                max_order: self.target_order,
            };
        }

        self.total_passes += 1;
        // Advance migration scanner.
        let migrate_end = (self.migrate_pfn + SCAN_BATCH).min(self.free_pfn);
        // Simulate finding movable pages.
        let movable = (migrate_end - self.migrate_pfn) / 4;
        self.migrate_pfn = migrate_end;

        // Advance free scanner.
        let free_start = if self.free_pfn >= SCAN_BATCH {
            (self.free_pfn - SCAN_BATCH).max(self.migrate_pfn)
        } else {
            self.migrate_pfn
        };
        let free_found = (self.free_pfn - free_start) / 4;
        self.free_pfn = free_start;

        // Migrate as many as possible.
        let migrated = movable.min(free_found);
        self.total_migrated += migrated;

        if self.migrate_pfn >= self.free_pfn {
            self.complete = true;
        }

        ScanResult {
            migrated,
            free_found,
            complete: self.complete,
            max_order: self.target_order,
        }
    }

    /// Return progress as a percentage.
    pub fn progress_pct(&self) -> u64 {
        let total = self.zone_end - self.zone_start;
        if total == 0 {
            return 100;
        }
        let scanned = (self.migrate_pfn - self.zone_start) + (self.zone_end - self.free_pfn);
        (scanned * 100 / total).min(100)
    }
}

impl Default for CompactionScanner {
    fn default() -> Self {
        Self::new(0, MAX_PFNS_PER_ZONE, MIN_COMPACT_ORDER)
    }
}

// -------------------------------------------------------------------
// CompactionZoneState
// -------------------------------------------------------------------

/// Per-zone compaction state.
#[derive(Debug, Clone, Copy)]
pub struct CompactionZoneState {
    /// Zone identifier.
    pub zone_id: u32,
    /// Whether compaction is needed.
    pub needs_compaction: bool,
    /// Highest order allocation that would succeed.
    pub max_avail_order: u8,
    /// Number of compaction runs.
    pub run_count: u64,
    /// Whether this zone is active.
    pub active: bool,
}

impl CompactionZoneState {
    /// Create a new zone state.
    pub const fn new(zone_id: u32) -> Self {
        Self {
            zone_id,
            needs_compaction: false,
            max_avail_order: 0,
            run_count: 0,
            active: true,
        }
    }
}

impl Default for CompactionZoneState {
    fn default() -> Self {
        Self::new(0)
    }
}

// -------------------------------------------------------------------
// CompactionController
// -------------------------------------------------------------------

/// Manages compaction across all zones.
pub struct CompactionController {
    /// Per-zone state.
    zones: [CompactionZoneState; MAX_ZONES],
    /// Number of active zones.
    zone_count: usize,
    /// Total pages migrated across all zones.
    total_migrated: u64,
    /// Current compaction mode.
    mode: CompactionMode,
}

impl CompactionController {
    /// Create a new controller.
    pub const fn new() -> Self {
        Self {
            zones: [const { CompactionZoneState::new(0) }; MAX_ZONES],
            zone_count: 0,
            total_migrated: 0,
            mode: CompactionMode::Async,
        }
    }

    /// Add a zone.
    pub fn add_zone(&mut self, zone_id: u32) -> Result<()> {
        if self.zone_count >= MAX_ZONES {
            return Err(Error::OutOfMemory);
        }
        self.zones[self.zone_count] = CompactionZoneState::new(zone_id);
        self.zone_count += 1;
        Ok(())
    }

    /// Return the number of zones.
    pub const fn zone_count(&self) -> usize {
        self.zone_count
    }

    /// Return total migrated pages.
    pub const fn total_migrated(&self) -> u64 {
        self.total_migrated
    }

    /// Set the compaction mode.
    pub fn set_mode(&mut self, mode: CompactionMode) {
        self.mode = mode;
    }

    /// Return the current mode.
    pub const fn mode(&self) -> CompactionMode {
        self.mode
    }

    /// Check whether any zone needs compaction.
    pub fn any_needs_compaction(&self) -> bool {
        for idx in 0..self.zone_count {
            if self.zones[idx].needs_compaction && self.zones[idx].active {
                return true;
            }
        }
        false
    }

    /// Mark a zone as needing compaction.
    pub fn request_compaction(&mut self, zone_id: u32) -> Result<()> {
        for idx in 0..self.zone_count {
            if self.zones[idx].zone_id == zone_id {
                self.zones[idx].needs_compaction = true;
                return Ok(());
            }
        }
        Err(Error::NotFound)
    }

    /// Record migrated pages for a zone.
    pub fn record_migration(&mut self, zone_id: u32, pages: u64) {
        self.total_migrated += pages;
        for idx in 0..self.zone_count {
            if self.zones[idx].zone_id == zone_id {
                self.zones[idx].run_count += 1;
            }
        }
    }
}

impl Default for CompactionController {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// Public helpers
// -------------------------------------------------------------------

/// Create a scanner and run to completion.
pub fn compact_zone(zone_start: u64, zone_end: u64, target_order: u8) -> u64 {
    let mut scanner = CompactionScanner::new(zone_start, zone_end, target_order);
    while !scanner.is_complete() {
        scanner.scan_pass();
    }
    scanner.total_migrated()
}

/// Check whether compaction would help satisfy an allocation.
pub fn should_compact(free_pages: u64, total_pages: u64, order: u8) -> bool {
    if order < MIN_COMPACT_ORDER {
        return false;
    }
    // Heuristic: compact if we have enough free pages but fragmented.
    let needed = 1u64 << order;
    free_pages >= needed && (free_pages * 100 / total_pages) < 30
}

/// Return a summary of compaction state.
pub fn compaction_summary(controller: &CompactionController) -> &'static str {
    if controller.zone_count() == 0 {
        "compaction: no zones"
    } else if controller.any_needs_compaction() {
        "compaction: needed"
    } else {
        "compaction: idle"
    }
}
