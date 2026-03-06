// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Memory compaction (defragmentation) subsystem.
//!
//! Implements Linux-style memory compaction by scanning zones with
//! dual scanners: a migrate scanner (from start) finds movable
//! pages, and a free scanner (from end) finds free target pages.
//! Pages are then migrated to consolidate free memory into
//! higher-order contiguous blocks.
//!
//! - [`Compactor`] — main compaction engine with zone management
//! - [`CompactZone`] — per-zone scanner state and statistics
//! - [`MigratePage`] — individual page migration descriptor
//! - [`CompactResult`] — outcome of a compaction attempt
//! - [`CompactStats`] — aggregate compaction statistics

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Maximum number of pages to migrate in one compaction pass.
const MAX_MIGRATE_PAGES: usize = 256;

/// Standard page size in bytes (4 KiB).
const PAGE_SIZE: u64 = 4096;

/// Maximum number of zones the compactor can manage.
const MAX_COMPACT_ZONES: usize = 4;

/// Compaction priority: fully synchronous migration.
const _COMPACT_PRIO_SYNC_FULL: u8 = 0;

/// Compaction priority: light synchronous migration.
const _COMPACT_PRIO_SYNC_LIGHT: u8 = 1;

/// Compaction priority: asynchronous migration.
const _COMPACT_PRIO_ASYNC: u8 = 2;

// -------------------------------------------------------------------
// CompactResult
// -------------------------------------------------------------------

/// Outcome of a compaction attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CompactResult {
    /// Compaction completed successfully.
    #[default]
    Ok,
    /// Compaction was deferred for later.
    Deferred,
    /// No suitable free page was found for migration.
    NoSuitablePage,
    /// Zone is not suitable for compaction.
    NotSuitable,
    /// Compaction was skipped entirely.
    Skipped,
}

// -------------------------------------------------------------------
// MigratePage
// -------------------------------------------------------------------

/// Descriptor for a single page migration operation.
#[derive(Debug, Clone, Copy)]
pub struct MigratePage {
    /// Source page frame number.
    pub source_pfn: u64,
    /// Destination page frame number.
    pub dest_pfn: u64,
    /// Allocation order of the page.
    pub order: u8,
    /// Whether this page has been successfully migrated.
    pub migrated: bool,
    /// Whether this page is pinned and cannot be migrated.
    pub pinned: bool,
}

impl MigratePage {
    /// Creates a new zeroed migration descriptor.
    const fn empty() -> Self {
        Self {
            source_pfn: 0,
            dest_pfn: 0,
            order: 0,
            migrated: false,
            pinned: false,
        }
    }
}

// -------------------------------------------------------------------
// CompactZone
// -------------------------------------------------------------------

/// Per-zone compaction state with dual scanner positions.
#[derive(Debug, Clone, Copy)]
pub struct CompactZone {
    /// Zone identifier.
    pub zone_id: u8,
    /// First PFN in this zone.
    pub start_pfn: u64,
    /// Last PFN (exclusive) in this zone.
    pub end_pfn: u64,
    /// Free-page scanner position (scans from end toward start).
    pub free_scanner_pfn: u64,
    /// Migrate scanner position (scans from start toward end).
    pub migrate_scanner_pfn: u64,
    /// Number of free pages in this zone.
    pub free_pages: u64,
    /// Total number of pages in this zone.
    pub total_pages: u64,
    /// Target allocation order for compaction.
    pub compact_order: u8,
    /// Whether this zone is actively being compacted.
    pub active: bool,
}

impl CompactZone {
    /// Creates a new inactive zone with all fields zeroed.
    const fn empty() -> Self {
        Self {
            zone_id: 0,
            start_pfn: 0,
            end_pfn: 0,
            free_scanner_pfn: 0,
            migrate_scanner_pfn: 0,
            free_pages: 0,
            total_pages: 0,
            compact_order: 0,
            active: false,
        }
    }
}

// -------------------------------------------------------------------
// CompactStats
// -------------------------------------------------------------------

/// Aggregate compaction statistics.
#[derive(Debug, Clone, Copy, Default)]
pub struct CompactStats {
    /// Total pages scanned by both scanners.
    pub pages_scanned: u64,
    /// Pages successfully migrated.
    pub pages_migrated: u64,
    /// Pages that failed migration.
    pub pages_failed: u64,
    /// Number of times compaction stalled.
    pub compact_stall: u64,
    /// Number of successful compaction runs.
    pub compact_success: u64,
}

// -------------------------------------------------------------------
// Compactor
// -------------------------------------------------------------------

/// Memory compaction engine.
///
/// Manages zones and performs page migration to defragment
/// physical memory, enabling higher-order allocations to succeed.
pub struct Compactor {
    /// Registered compaction zones.
    zones: [CompactZone; MAX_COMPACT_ZONES],
    /// Number of active zones.
    zone_count: usize,
    /// Pending page migration list.
    migrate_list: [MigratePage; MAX_MIGRATE_PAGES],
    /// Number of entries in the migrate list.
    migrate_count: usize,
    /// Total pages scanned across all compaction runs.
    pages_scanned: u64,
    /// Total pages successfully migrated.
    pages_migrated: u64,
    /// Total pages that failed migration.
    pages_failed: u64,
    /// Number of times compaction stalled.
    compact_stall: u64,
    /// Number of successful compaction runs.
    compact_success: u64,
}

impl Default for Compactor {
    fn default() -> Self {
        Self::new()
    }
}

impl Compactor {
    /// Creates a new compactor with no zones registered.
    pub const fn new() -> Self {
        Self {
            zones: [CompactZone::empty(); MAX_COMPACT_ZONES],
            zone_count: 0,
            migrate_list: [MigratePage::empty(); MAX_MIGRATE_PAGES],
            migrate_count: 0,
            pages_scanned: 0,
            pages_migrated: 0,
            pages_failed: 0,
            compact_stall: 0,
            compact_success: 0,
        }
    }

    /// Registers a new zone for compaction.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the maximum number of
    /// zones has been reached, or [`Error::InvalidArgument`] if
    /// `start >= end`.
    pub fn add_zone(&mut self, id: u8, start: u64, end: u64, free: u64) -> Result<()> {
        if start >= end {
            return Err(Error::InvalidArgument);
        }
        if self.zone_count >= MAX_COMPACT_ZONES {
            return Err(Error::OutOfMemory);
        }
        let total = (end - start) / PAGE_SIZE;
        let zone = &mut self.zones[self.zone_count];
        zone.zone_id = id;
        zone.start_pfn = start / PAGE_SIZE;
        zone.end_pfn = end / PAGE_SIZE;
        zone.free_scanner_pfn = end / PAGE_SIZE;
        zone.migrate_scanner_pfn = start / PAGE_SIZE;
        zone.free_pages = free;
        zone.total_pages = total;
        zone.compact_order = 0;
        zone.active = false;
        self.zone_count += 1;
        Ok(())
    }

    /// Compacts a specific zone to satisfy an allocation of the
    /// given order.
    ///
    /// Scans the zone with dual scanners, builds a migration list,
    /// and executes page migrations. Returns the compaction outcome.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the zone ID is not registered.
    pub fn compact_zone(&mut self, zone_id: u8, order: u8) -> Result<CompactResult> {
        let idx = self.find_zone(zone_id)?;

        if !self.should_compact(zone_id, order) {
            return Ok(CompactResult::Skipped);
        }

        self.zones[idx].compact_order = order;
        self.zones[idx].active = true;

        // Phase 1: isolate movable pages from the migrate scanner.
        let migrate_found = self.isolate_migratepages(zone_id, MAX_MIGRATE_PAGES);
        if migrate_found == 0 {
            self.zones[idx].active = false;
            self.compact_stall += 1;
            return Ok(CompactResult::NoSuitablePage);
        }

        // Phase 2: isolate free pages from the free scanner.
        let free_found = self.isolate_freepages(zone_id, migrate_found);
        if free_found == 0 {
            self.migrate_count = 0;
            self.zones[idx].active = false;
            self.compact_stall += 1;
            return Ok(CompactResult::NotSuitable);
        }

        // Phase 3: pair sources with destinations and migrate.
        let pairs = if migrate_found < free_found {
            migrate_found
        } else {
            free_found
        };
        // Assign destination PFNs to the first `pairs` entries.
        let free_start = self.zones[idx].free_scanner_pfn;
        for i in 0..pairs {
            if i < self.migrate_count {
                self.migrate_list[i].dest_pfn = free_start + i as u64;
            }
        }

        let (success, fail) = self.migrate_pages();

        self.zones[idx].active = false;

        if success > 0 {
            self.compact_success += 1;
            Ok(CompactResult::Ok)
        } else if fail > 0 {
            Ok(CompactResult::NotSuitable)
        } else {
            Ok(CompactResult::Deferred)
        }
    }

    /// Attempts compaction across all registered zones for the
    /// given allocation order.
    ///
    /// Returns the best result achieved across zones.
    pub fn try_to_compact(&mut self, order: u8) -> CompactResult {
        let mut best = CompactResult::Skipped;

        for i in 0..self.zone_count {
            let zid = self.zones[i].zone_id;
            if let Ok(result) = self.compact_zone(zid, order) {
                if result == CompactResult::Ok {
                    return CompactResult::Ok;
                }
                // Prefer more actionable results.
                if best == CompactResult::Skipped {
                    best = result;
                }
            }
        }

        best
    }

    /// Finds movable pages starting from the migrate scanner
    /// position, advancing it forward. Returns the number of
    /// candidate pages added to the migrate list.
    pub fn isolate_migratepages(&mut self, zone_id: u8, count: usize) -> usize {
        let idx = match self.find_zone(zone_id) {
            Ok(i) => i,
            Err(_) => return 0,
        };

        let start = self.zones[idx].migrate_scanner_pfn;
        let end = self.zones[idx].end_pfn;
        let limit = if count > MAX_MIGRATE_PAGES {
            MAX_MIGRATE_PAGES
        } else {
            count
        };

        let mut found = 0_usize;
        let mut pfn = start;

        while pfn < end && found < limit {
            // Stub: simulate every 4th page as movable.
            if pfn % 4 == 0 {
                self.migrate_list[found] = MigratePage {
                    source_pfn: pfn,
                    dest_pfn: 0,
                    order: self.zones[idx].compact_order,
                    migrated: false,
                    pinned: false,
                };
                found += 1;
            }
            pfn += 1;
            self.pages_scanned += 1;
        }

        self.zones[idx].migrate_scanner_pfn = pfn;
        self.migrate_count = found;
        found
    }

    /// Finds free pages starting from the free scanner position,
    /// scanning backward toward the zone start. Returns the number
    /// of free pages found.
    pub fn isolate_freepages(&mut self, zone_id: u8, count: usize) -> usize {
        let idx = match self.find_zone(zone_id) {
            Ok(i) => i,
            Err(_) => return 0,
        };

        let start = self.zones[idx].start_pfn;
        let scanner = self.zones[idx].free_scanner_pfn;

        if scanner <= start {
            return 0;
        }

        let mut found = 0_usize;
        let mut pfn = scanner;

        while pfn > start && found < count {
            pfn -= 1;
            // Stub: simulate every 3rd page as free.
            if pfn % 3 == 0 {
                found += 1;
            }
            self.pages_scanned += 1;
        }

        self.zones[idx].free_scanner_pfn = pfn;
        found
    }

    /// Executes pending page migrations from the migrate list.
    ///
    /// Returns `(success_count, fail_count)`.
    pub fn migrate_pages(&mut self) -> (usize, usize) {
        let mut success = 0_usize;
        let mut fail = 0_usize;

        for i in 0..self.migrate_count {
            let page = &mut self.migrate_list[i];
            if page.pinned {
                fail += 1;
                self.pages_failed += 1;
                continue;
            }
            if page.dest_pfn == 0 {
                fail += 1;
                self.pages_failed += 1;
                continue;
            }
            // Stub: mark migration as successful.
            page.migrated = true;
            success += 1;
            self.pages_migrated += 1;
        }

        self.migrate_count = 0;
        (success, fail)
    }

    /// Resets the dual scanners for a zone to their initial
    /// positions.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the zone ID is not registered.
    pub fn reset_scanners(&mut self, zone_id: u8) -> Result<()> {
        let idx = self.find_zone(zone_id)?;
        self.zones[idx].migrate_scanner_pfn = self.zones[idx].start_pfn;
        self.zones[idx].free_scanner_pfn = self.zones[idx].end_pfn;
        Ok(())
    }

    /// Determines whether compaction should be attempted for a
    /// zone at the given order.
    ///
    /// Uses a fragmentation heuristic: compaction is worthwhile
    /// when the zone has enough free pages but they are scattered
    /// (i.e., free pages exceed twice the requested block size
    /// but the scanners have not yet met).
    pub fn should_compact(&self, zone_id: u8, order: u8) -> bool {
        let idx = match self.find_zone(zone_id) {
            Ok(i) => i,
            Err(_) => return false,
        };

        let zone = &self.zones[idx];
        let needed = 1_u64 << order;

        // Not worth compacting if fewer free pages than needed.
        if zone.free_pages < needed {
            return false;
        }

        // Scanners have met — zone already fully scanned.
        if zone.migrate_scanner_pfn >= zone.free_scanner_pfn {
            return false;
        }

        // Heuristic: compact if free pages are at least twice the
        // requested block but total fragmentation is high.
        zone.free_pages >= needed * 2
    }

    /// Returns aggregate compaction statistics.
    pub fn stats(&self) -> CompactStats {
        CompactStats {
            pages_scanned: self.pages_scanned,
            pages_migrated: self.pages_migrated,
            pages_failed: self.pages_failed,
            compact_stall: self.compact_stall,
            compact_success: self.compact_success,
        }
    }

    /// Returns the number of registered zones.
    pub fn len(&self) -> usize {
        self.zone_count
    }

    /// Returns `true` if no zones are registered.
    pub fn is_empty(&self) -> bool {
        self.zone_count == 0
    }

    /// Finds the index of a zone by its ID.
    fn find_zone(&self, zone_id: u8) -> Result<usize> {
        for i in 0..self.zone_count {
            if self.zones[i].zone_id == zone_id {
                return Ok(i);
            }
        }
        Err(Error::NotFound)
    }
}
