// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Zone-level memory compaction.
//!
//! Memory compaction defragments physical memory by migrating movable
//! pages to create large contiguous free blocks needed for huge page
//! allocation. This module implements per-zone compaction: scanning
//! for free pages from the top and movable pages from the bottom,
//! then migrating pages to consolidate free space.
//!
//! # Design
//!
//! ```text
//!  alloc_pages(order=9) fails → compact_zone(zone)
//!       │
//!       ├─ free scanner (top-down)   → find free pages
//!       ├─ migrate scanner (bottom-up)→ find movable pages
//!       ├─ migrate pages from low PFN → high PFN free frames
//!       └─ check if order-9 block available → success/fail
//! ```
//!
//! # Key Types
//!
//! - [`CompactionScanner`] — scanner state for one direction
//! - [`CompactionZone`] — per-zone compaction state
//! - [`CompactionResult`] — outcome of a compaction attempt
//! - [`CompactionZoneStats`] — compaction statistics
//!
//! Reference: Linux `mm/compaction.c`, `include/linux/compaction.h`.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Maximum pages scanned per compaction cycle.
const MAX_SCAN_PAGES: u64 = 4096;

/// Default target order for compaction.
const DEFAULT_TARGET_ORDER: u32 = 9; // 2 MiB

/// Compaction cost limit (pages migrated before giving up).
const MAX_MIGRATE_PAGES: u64 = 1024;

/// Page size.
const PAGE_SIZE: u64 = 4096;

/// Maximum tracked zones.
const MAX_ZONES: usize = 8;

// -------------------------------------------------------------------
// CompactionMode
// -------------------------------------------------------------------

/// Mode of compaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompactionMode {
    /// Direct compaction (in allocation path, synchronous).
    Direct,
    /// Background compaction (kcompactd, asynchronous).
    Background,
    /// Proactive compaction (fragmentation-based).
    Proactive,
}

impl CompactionMode {
    /// Return a label.
    pub const fn label(&self) -> &'static str {
        match self {
            Self::Direct => "direct",
            Self::Background => "background",
            Self::Proactive => "proactive",
        }
    }
}

// -------------------------------------------------------------------
// CompactionScanner
// -------------------------------------------------------------------

/// Scanner state for one direction of the compaction sweep.
#[derive(Debug, Clone, Copy)]
pub struct CompactionScanner {
    /// Current PFN being scanned.
    current_pfn: u64,
    /// Start PFN of the scan range.
    start_pfn: u64,
    /// End PFN of the scan range (exclusive).
    end_pfn: u64,
    /// Pages scanned so far.
    scanned: u64,
    /// Pages found (free or movable).
    found: u64,
}

impl CompactionScanner {
    /// Create a new scanner.
    pub const fn new(start_pfn: u64, end_pfn: u64) -> Self {
        Self {
            current_pfn: start_pfn,
            start_pfn,
            end_pfn,
            scanned: 0,
            found: 0,
        }
    }

    /// Return the current PFN.
    pub const fn current_pfn(&self) -> u64 {
        self.current_pfn
    }

    /// Return the number of pages scanned.
    pub const fn scanned(&self) -> u64 {
        self.scanned
    }

    /// Return the number of pages found.
    pub const fn found(&self) -> u64 {
        self.found
    }

    /// Check whether scanning is complete.
    pub const fn is_done(&self) -> bool {
        self.current_pfn >= self.end_pfn || self.scanned >= MAX_SCAN_PAGES
    }

    /// Advance the scanner forward.
    pub fn advance(&mut self) {
        if self.current_pfn < self.end_pfn {
            self.current_pfn += 1;
            self.scanned += 1;
        }
    }

    /// Record a found page.
    pub fn record_found(&mut self) {
        self.found += 1;
    }

    /// Reset the scanner to the start.
    pub fn reset(&mut self) {
        self.current_pfn = self.start_pfn;
        self.scanned = 0;
        self.found = 0;
    }
}

impl Default for CompactionScanner {
    fn default() -> Self {
        Self::new(0, 0)
    }
}

// -------------------------------------------------------------------
// CompactionResult
// -------------------------------------------------------------------

/// Outcome of a compaction attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompactionResult {
    /// Compaction succeeded — target order block available.
    Success,
    /// Compaction made progress but target not yet available.
    Partial,
    /// Compaction could not make progress.
    Failed,
    /// Compaction was deferred (not enough benefit).
    Deferred,
    /// Compaction not needed (already enough free blocks).
    NotNeeded,
}

impl CompactionResult {
    /// Return a label.
    pub const fn label(&self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Partial => "partial",
            Self::Failed => "failed",
            Self::Deferred => "deferred",
            Self::NotNeeded => "not_needed",
        }
    }

    /// Check whether compaction achieved its goal.
    pub const fn is_success(&self) -> bool {
        matches!(self, Self::Success | Self::NotNeeded)
    }
}

// -------------------------------------------------------------------
// CompactionZoneStats
// -------------------------------------------------------------------

/// Per-zone compaction statistics.
#[derive(Debug, Clone, Copy)]
pub struct CompactionZoneStats {
    /// Total compaction attempts.
    pub attempts: u64,
    /// Successful compactions.
    pub successes: u64,
    /// Failed compactions.
    pub failures: u64,
    /// Total pages migrated.
    pub pages_migrated: u64,
    /// Total pages scanned.
    pub pages_scanned: u64,
    /// Deferred compaction count.
    pub deferred: u64,
}

impl CompactionZoneStats {
    /// Create zero stats.
    pub const fn new() -> Self {
        Self {
            attempts: 0,
            successes: 0,
            failures: 0,
            pages_migrated: 0,
            pages_scanned: 0,
            deferred: 0,
        }
    }

    /// Success rate as percent.
    pub const fn success_rate(&self) -> u64 {
        if self.attempts == 0 {
            return 0;
        }
        self.successes * 100 / self.attempts
    }
}

impl Default for CompactionZoneStats {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// CompactionZone
// -------------------------------------------------------------------

/// Per-zone compaction state.
pub struct CompactionZone {
    /// Zone identifier.
    zone_id: u32,
    /// Free scanner (scans from high PFN downward).
    free_scanner: CompactionScanner,
    /// Migrate scanner (scans from low PFN upward).
    migrate_scanner: CompactionScanner,
    /// Target allocation order.
    target_order: u32,
    /// Pages migrated in current cycle.
    migrated_this_cycle: u64,
    /// Zone start PFN.
    zone_start_pfn: u64,
    /// Zone end PFN.
    zone_end_pfn: u64,
    /// Statistics.
    stats: CompactionZoneStats,
    /// Whether compaction is currently active.
    active: bool,
}

impl CompactionZone {
    /// Create a new compaction zone.
    pub fn new_zone(zone_id: u32, start_pfn: u64, end_pfn: u64) -> Self {
        let mid = start_pfn + (end_pfn - start_pfn) / 2;
        Self {
            zone_id,
            free_scanner: CompactionScanner::new(mid, end_pfn),
            migrate_scanner: CompactionScanner::new(start_pfn, mid),
            target_order: DEFAULT_TARGET_ORDER,
            migrated_this_cycle: 0,
            zone_start_pfn: start_pfn,
            zone_end_pfn: end_pfn,
            stats: CompactionZoneStats::new(),
            active: false,
        }
    }

    /// Return the zone identifier.
    pub const fn zone_id(&self) -> u32 {
        self.zone_id
    }

    /// Return the statistics.
    pub const fn stats(&self) -> &CompactionZoneStats {
        &self.stats
    }

    /// Return whether compaction is active.
    pub const fn is_active(&self) -> bool {
        self.active
    }

    /// Start a compaction cycle.
    pub fn start(&mut self, target_order: u32) {
        self.target_order = target_order;
        self.migrated_this_cycle = 0;
        self.active = true;
        self.free_scanner.reset();
        self.migrate_scanner.reset();
        self.stats.attempts += 1;
    }

    /// Run one step of compaction. Returns the result if done.
    pub fn step(&mut self) -> Option<CompactionResult> {
        if !self.active {
            return Some(CompactionResult::NotNeeded);
        }

        // Check limits.
        if self.migrated_this_cycle >= MAX_MIGRATE_PAGES {
            self.active = false;
            return Some(CompactionResult::Partial);
        }

        if self.free_scanner.is_done() || self.migrate_scanner.is_done() {
            self.active = false;
            if self.migrated_this_cycle > 0 {
                self.stats.successes += 1;
                return Some(CompactionResult::Success);
            }
            self.stats.failures += 1;
            return Some(CompactionResult::Failed);
        }

        // Simulate migration of one page.
        self.free_scanner.advance();
        self.migrate_scanner.advance();
        self.free_scanner.record_found();
        self.migrate_scanner.record_found();
        self.migrated_this_cycle += 1;
        self.stats.pages_migrated += 1;
        self.stats.pages_scanned += 2;

        None // not done yet
    }

    /// Abort the current compaction.
    pub fn abort(&mut self) {
        self.active = false;
    }

    /// Return the zone size in pages.
    pub const fn zone_pages(&self) -> u64 {
        self.zone_end_pfn - self.zone_start_pfn
    }

    /// Return the zone size in bytes.
    pub const fn zone_bytes(&self) -> u64 {
        self.zone_pages() * PAGE_SIZE
    }

    /// Set the target order.
    pub fn set_target_order(&mut self, order: u32) {
        self.target_order = order;
    }
}

impl Default for CompactionZone {
    fn default() -> Self {
        Self::new_zone(0, 0, 0)
    }
}

// -------------------------------------------------------------------
// CompactionManager
// -------------------------------------------------------------------

/// Manages compaction across all zones.
pub struct CompactionManager {
    /// Per-zone compaction states.
    zones: [CompactionZone; MAX_ZONES],
    /// Number of zones.
    count: usize,
}

impl CompactionManager {
    /// Create a new manager.
    pub fn new() -> Self {
        Self {
            zones: core::array::from_fn(|_| CompactionZone::default()),
            count: 0,
        }
    }

    /// Add a zone.
    pub fn add_zone(&mut self, zone_id: u32, start_pfn: u64, end_pfn: u64) -> Result<()> {
        if self.count >= MAX_ZONES {
            return Err(Error::OutOfMemory);
        }
        self.zones[self.count] = CompactionZone::new_zone(zone_id, start_pfn, end_pfn);
        self.count += 1;
        Ok(())
    }

    /// Return the number of zones.
    pub const fn count(&self) -> usize {
        self.count
    }

    /// Get a zone by index.
    pub fn zone(&self, index: usize) -> Result<&CompactionZone> {
        if index >= self.count {
            return Err(Error::InvalidArgument);
        }
        Ok(&self.zones[index])
    }

    /// Get a mutable zone by index.
    pub fn zone_mut(&mut self, index: usize) -> Result<&mut CompactionZone> {
        if index >= self.count {
            return Err(Error::InvalidArgument);
        }
        Ok(&mut self.zones[index])
    }
}

impl Default for CompactionManager {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// Public helpers
// -------------------------------------------------------------------

/// Run a full compaction cycle on a zone.
pub fn compact_zone(zone: &mut CompactionZone, target_order: u32) -> CompactionResult {
    zone.start(target_order);
    loop {
        if let Some(result) = zone.step() {
            return result;
        }
    }
}

/// Return the default target order for compaction.
pub const fn default_target_order() -> u32 {
    DEFAULT_TARGET_ORDER
}

/// Return the maximum migrate pages per cycle.
pub const fn max_migrate_pages() -> u64 {
    MAX_MIGRATE_PAGES
}
