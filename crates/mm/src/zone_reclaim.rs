// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Per-zone memory reclaim.
//!
//! Implements zone-local memory reclaim policies. When a zone's free
//! pages drop below the low watermark, the reclaim engine scans the
//! zone's LRU lists to free pages. This avoids triggering global
//! reclaim (kswapd) for localised pressure, which is important on
//! NUMA systems where remote reclaim is expensive.
//!
//! # Design
//!
//! ```text
//!  alloc fails (zone low)
//!       │
//!       ▼
//!  ┌──────────────────┐
//!  │  ZoneReclaimer    │
//!  │  scan inactive    │──▶ clean page? → free it
//!  │  scan active      │──▶ dirty page? → writeback queue
//!  │  scan slab caches │──▶ shrinkable? → shrink
//!  └──────────────────┘
//!       │
//!       ▼
//!  return nr_reclaimed
//! ```
//!
//! # Key Types
//!
//! - [`ZoneWatermarks`] — min/low/high watermark levels
//! - [`ZoneReclaimState`] — per-zone reclaim state
//! - [`ZoneReclaimer`] — the reclaim engine
//! - [`ReclaimResult`] — result of a reclaim pass
//!
//! Reference: Linux `mm/vmscan.c` (shrink_zone), `mm/page_alloc.c`.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Maximum zones.
const MAX_ZONES: usize = 8;

/// Maximum LRU entries per zone (simplified).
const MAX_LRU_ENTRIES: usize = 2048;

/// Scan batch size (pages scanned per pass).
const SCAN_BATCH: usize = 32;

// -------------------------------------------------------------------
// ZoneWatermarks
// -------------------------------------------------------------------

/// Watermark levels for a memory zone.
#[derive(Debug, Clone, Copy)]
pub struct ZoneWatermarks {
    /// Minimum watermark (below = OOM territory).
    pub min: u64,
    /// Low watermark (below = start reclaim).
    pub low: u64,
    /// High watermark (above = stop reclaim).
    pub high: u64,
}

impl ZoneWatermarks {
    /// Creates new watermarks.
    pub const fn new(min: u64, low: u64, high: u64) -> Self {
        Self { min, low, high }
    }

    /// Validates watermark ordering.
    pub fn validate(&self) -> Result<()> {
        if self.min > self.low || self.low > self.high {
            return Err(Error::InvalidArgument);
        }
        Ok(())
    }

    /// Returns `true` if free pages are below the low watermark.
    pub const fn needs_reclaim(&self, free: u64) -> bool {
        free < self.low
    }

    /// Returns `true` if free pages are above the high watermark.
    pub const fn reclaim_complete(&self, free: u64) -> bool {
        free >= self.high
    }
}

impl Default for ZoneWatermarks {
    fn default() -> Self {
        Self::new(16, 64, 256)
    }
}

// -------------------------------------------------------------------
// LruEntry
// -------------------------------------------------------------------

/// A simplified LRU list entry (page reference).
#[derive(Debug, Clone, Copy)]
struct LruEntry {
    /// Physical frame number.
    pfn: u64,
    /// Whether the page is active.
    active: bool,
    /// Whether the page is dirty.
    dirty: bool,
    /// Whether the page has been accessed recently.
    accessed: bool,
    /// Whether this slot is in use.
    in_use: bool,
}

impl LruEntry {
    const fn new() -> Self {
        Self {
            pfn: 0,
            active: false,
            dirty: false,
            accessed: false,
            in_use: false,
        }
    }
}

// -------------------------------------------------------------------
// ZoneReclaimState
// -------------------------------------------------------------------

/// Per-zone reclaim state and LRU lists.
pub struct ZoneReclaimState {
    /// Zone identifier.
    zone_id: u32,
    /// Watermarks.
    watermarks: ZoneWatermarks,
    /// Current free pages.
    free_pages: u64,
    /// LRU entries.
    lru: [LruEntry; MAX_LRU_ENTRIES],
    /// Number of LRU entries.
    lru_count: usize,
    /// Total pages reclaimed from this zone.
    total_reclaimed: u64,
    /// Number of reclaim passes.
    reclaim_passes: u64,
}

impl ZoneReclaimState {
    /// Creates a new zone reclaim state.
    pub const fn new(zone_id: u32) -> Self {
        Self {
            zone_id,
            watermarks: ZoneWatermarks::new(16, 64, 256),
            free_pages: 0,
            lru: [const { LruEntry::new() }; MAX_LRU_ENTRIES],
            lru_count: 0,
            total_reclaimed: 0,
            reclaim_passes: 0,
        }
    }

    /// Returns the zone ID.
    pub const fn zone_id(&self) -> u32 {
        self.zone_id
    }

    /// Returns current free pages.
    pub const fn free_pages(&self) -> u64 {
        self.free_pages
    }

    /// Returns total reclaimed pages.
    pub const fn total_reclaimed(&self) -> u64 {
        self.total_reclaimed
    }

    /// Sets the watermarks.
    pub fn set_watermarks(&mut self, wm: ZoneWatermarks) -> Result<()> {
        wm.validate()?;
        self.watermarks = wm;
        Ok(())
    }

    /// Adds a page to the LRU.
    pub fn add_lru(&mut self, pfn: u64, active: bool, dirty: bool) -> Result<()> {
        if self.lru_count >= MAX_LRU_ENTRIES {
            return Err(Error::OutOfMemory);
        }
        self.lru[self.lru_count] = LruEntry {
            pfn,
            active,
            dirty,
            accessed: false,
            in_use: true,
        };
        self.lru_count += 1;
        Ok(())
    }

    /// Returns `true` if reclaim is needed.
    pub const fn needs_reclaim(&self) -> bool {
        self.watermarks.needs_reclaim(self.free_pages)
    }
}

impl Default for ZoneReclaimState {
    fn default() -> Self {
        Self::new(0)
    }
}

// -------------------------------------------------------------------
// ReclaimResult
// -------------------------------------------------------------------

/// Result of a zone reclaim pass.
#[derive(Debug, Clone, Copy)]
pub struct ReclaimResult {
    /// Pages scanned.
    pub scanned: usize,
    /// Pages reclaimed.
    pub reclaimed: usize,
    /// Dirty pages encountered (queued for writeback).
    pub dirty_skipped: usize,
    /// Active pages encountered (demoted to inactive).
    pub demoted: usize,
}

impl ReclaimResult {
    /// Creates an empty result.
    pub const fn new() -> Self {
        Self {
            scanned: 0,
            reclaimed: 0,
            dirty_skipped: 0,
            demoted: 0,
        }
    }

    /// Returns the reclaim efficiency (reclaimed/scanned, 0..100).
    pub const fn efficiency(&self) -> usize {
        if self.scanned == 0 {
            return 0;
        }
        self.reclaimed * 100 / self.scanned
    }
}

impl Default for ReclaimResult {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// ZoneReclaimer
// -------------------------------------------------------------------

/// Per-zone memory reclaim engine.
pub struct ZoneReclaimer {
    /// Zone states.
    zones: [ZoneReclaimState; MAX_ZONES],
    /// Number of active zones.
    nr_zones: usize,
}

impl ZoneReclaimer {
    /// Creates a new reclaimer.
    pub const fn new() -> Self {
        Self {
            zones: [const { ZoneReclaimState::new(0) }; MAX_ZONES],
            nr_zones: 0,
        }
    }

    /// Returns the number of zones.
    pub const fn nr_zones(&self) -> usize {
        self.nr_zones
    }

    /// Registers a zone.
    pub fn register_zone(
        &mut self,
        zone_id: u32,
        free_pages: u64,
        watermarks: ZoneWatermarks,
    ) -> Result<()> {
        if self.nr_zones >= MAX_ZONES {
            return Err(Error::OutOfMemory);
        }
        watermarks.validate()?;
        let idx = self.nr_zones;
        self.zones[idx] = ZoneReclaimState::new(zone_id);
        self.zones[idx].free_pages = free_pages;
        self.zones[idx].watermarks = watermarks;
        self.nr_zones += 1;
        Ok(())
    }

    /// Runs a reclaim pass on the specified zone.
    pub fn reclaim_zone(&mut self, zone_idx: usize) -> Result<ReclaimResult> {
        if zone_idx >= self.nr_zones {
            return Err(Error::InvalidArgument);
        }

        let zone = &mut self.zones[zone_idx];
        if !zone.needs_reclaim() {
            return Ok(ReclaimResult::new());
        }

        let mut result = ReclaimResult::new();
        let scan_end = if zone.lru_count < SCAN_BATCH {
            zone.lru_count
        } else {
            SCAN_BATCH
        };

        let mut i = 0;
        while i < scan_end && i < zone.lru_count {
            if !zone.lru[i].in_use {
                i += 1;
                continue;
            }
            result.scanned += 1;

            if zone.lru[i].active {
                // Demote active to inactive.
                zone.lru[i].active = false;
                result.demoted += 1;
            } else if zone.lru[i].dirty {
                // Skip dirty pages.
                result.dirty_skipped += 1;
            } else {
                // Reclaim clean inactive page.
                zone.lru[i].in_use = false;
                zone.free_pages = zone.free_pages.saturating_add(1);
                result.reclaimed += 1;
            }
            i += 1;
        }

        zone.total_reclaimed = zone.total_reclaimed.saturating_add(result.reclaimed as u64);
        zone.reclaim_passes = zone.reclaim_passes.saturating_add(1);
        Ok(result)
    }

    /// Runs reclaim on all zones that need it.
    pub fn reclaim_all(&mut self) -> ReclaimResult {
        let mut total = ReclaimResult::new();
        for i in 0..self.nr_zones {
            let zone_needs = self.zones[i].needs_reclaim();
            if zone_needs {
                if let Ok(r) = self.reclaim_zone(i) {
                    total.scanned += r.scanned;
                    total.reclaimed += r.reclaimed;
                    total.dirty_skipped += r.dirty_skipped;
                    total.demoted += r.demoted;
                }
            }
        }
        total
    }
}

impl Default for ZoneReclaimer {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// Public helpers
// -------------------------------------------------------------------

/// Creates a zone reclaimer and registers initial zones.
pub fn create_reclaimer() -> ZoneReclaimer {
    ZoneReclaimer::new()
}

/// Runs a reclaim pass on a specific zone.
pub fn reclaim_zone(reclaimer: &mut ZoneReclaimer, zone_idx: usize) -> Result<ReclaimResult> {
    reclaimer.reclaim_zone(zone_idx)
}

/// Returns whether any registered zone needs reclaim.
pub fn any_zone_needs_reclaim(reclaimer: &ZoneReclaimer) -> bool {
    for i in 0..reclaimer.nr_zones() {
        if reclaimer.zones[i].needs_reclaim() {
            return true;
        }
    }
    false
}
