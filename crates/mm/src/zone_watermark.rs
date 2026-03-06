// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Zone watermark management.
//!
//! Each memory zone (DMA, DMA32, Normal, HighMem) maintains three
//! watermark levels — min, low, and high — that control when page
//! reclaim is triggered. This module computes watermarks from the
//! total zone size, checks allocation feasibility against watermarks,
//! and adjusts watermarks dynamically based on memory pressure.
//!
//! # Design
//!
//! ```text
//!  free pages in zone
//!     │
//!     │  HIGH ──── kswapd sleeps
//!     │  LOW  ──── kswapd wakes
//!     │  MIN  ──── direct reclaim
//!     │  0    ──── OOM
//! ```
//!
//! # Key Types
//!
//! - [`ZoneType`] — the zone classification
//! - [`WatermarkLevel`] — min / low / high watermarks for a zone
//! - [`ZoneWatermark`] — per-zone watermark and free page state
//! - [`WatermarkManager`] — manages watermarks for all zones
//!
//! Reference: Linux `mm/page_alloc.c`, `include/linux/mmzone.h`.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Maximum zones.
const MAX_ZONES: usize = 8;

/// Default min watermark fraction (1/128 of zone pages).
const MIN_FRACTION: u64 = 128;

/// Low watermark is min * 5/4.
const LOW_FACTOR_NUM: u64 = 5;
/// Low watermark denominator.
const LOW_FACTOR_DEN: u64 = 4;

/// High watermark is min * 3/2.
const HIGH_FACTOR_NUM: u64 = 3;
/// High watermark denominator.
const HIGH_FACTOR_DEN: u64 = 2;

/// Extra pages reserved for high-priority allocations.
const LOWMEM_RESERVE_RATIO: u64 = 256;

// -------------------------------------------------------------------
// ZoneType
// -------------------------------------------------------------------

/// Memory zone classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ZoneType {
    /// DMA zone (below 16 MiB on x86).
    Dma,
    /// DMA32 zone (below 4 GiB).
    Dma32,
    /// Normal zone.
    Normal,
    /// High memory zone (not directly mapped on 32-bit).
    HighMem,
    /// Movable zone (for memory hotplug).
    Movable,
}

impl ZoneType {
    /// Return a label.
    pub const fn label(&self) -> &'static str {
        match self {
            Self::Dma => "DMA",
            Self::Dma32 => "DMA32",
            Self::Normal => "Normal",
            Self::HighMem => "HighMem",
            Self::Movable => "Movable",
        }
    }

    /// Return the priority (lower = higher priority for fallback).
    pub const fn priority(&self) -> u8 {
        match self {
            Self::Dma => 0,
            Self::Dma32 => 1,
            Self::Normal => 2,
            Self::HighMem => 3,
            Self::Movable => 4,
        }
    }
}

// -------------------------------------------------------------------
// WatermarkLevel
// -------------------------------------------------------------------

/// Watermark levels for a single zone.
#[derive(Debug, Clone, Copy)]
pub struct WatermarkLevel {
    /// Minimum free pages (direct reclaim threshold).
    pub min: u64,
    /// Low free pages (kswapd wake threshold).
    pub low: u64,
    /// High free pages (kswapd sleep threshold).
    pub high: u64,
}

impl WatermarkLevel {
    /// Compute watermarks from total zone pages.
    pub const fn from_zone_pages(total: u64) -> Self {
        let min = total / MIN_FRACTION;
        let low = min * LOW_FACTOR_NUM / LOW_FACTOR_DEN;
        let high = min * HIGH_FACTOR_NUM / HIGH_FACTOR_DEN;
        Self { min, low, high }
    }

    /// Create zero watermarks.
    pub const fn zero() -> Self {
        Self {
            min: 0,
            low: 0,
            high: 0,
        }
    }

    /// Boost watermarks by a factor (for memory pressure).
    pub fn boost(&mut self, factor: u64) {
        self.min = self.min.saturating_mul(factor);
        self.low = self.low.saturating_mul(factor);
        self.high = self.high.saturating_mul(factor);
    }
}

impl Default for WatermarkLevel {
    fn default() -> Self {
        Self::zero()
    }
}

// -------------------------------------------------------------------
// ZoneWatermark
// -------------------------------------------------------------------

/// Per-zone watermark and free page state.
#[derive(Debug, Clone, Copy)]
pub struct ZoneWatermark {
    /// Zone type.
    zone_type: ZoneType,
    /// Total pages in the zone.
    total_pages: u64,
    /// Current free pages.
    free_pages: u64,
    /// Watermark levels.
    watermarks: WatermarkLevel,
    /// Low memory reserve (pages reserved for higher-priority zones).
    lowmem_reserve: u64,
    /// Whether kswapd is active for this zone.
    kswapd_active: bool,
}

impl ZoneWatermark {
    /// Create a new zone watermark from zone parameters.
    pub const fn new(zone_type: ZoneType, total_pages: u64) -> Self {
        Self {
            zone_type,
            total_pages,
            free_pages: total_pages,
            watermarks: WatermarkLevel::from_zone_pages(total_pages),
            lowmem_reserve: total_pages / LOWMEM_RESERVE_RATIO,
            kswapd_active: false,
        }
    }

    /// Return the zone type.
    pub const fn zone_type(&self) -> ZoneType {
        self.zone_type
    }

    /// Return total pages.
    pub const fn total_pages(&self) -> u64 {
        self.total_pages
    }

    /// Return current free pages.
    pub const fn free_pages(&self) -> u64 {
        self.free_pages
    }

    /// Return the watermark levels.
    pub const fn watermarks(&self) -> &WatermarkLevel {
        &self.watermarks
    }

    /// Check whether an allocation of `count` pages is feasible.
    pub const fn can_alloc(&self, count: u64) -> bool {
        self.free_pages >= count + self.watermarks.min + self.lowmem_reserve
    }

    /// Check whether kswapd should wake.
    pub const fn kswapd_should_wake(&self) -> bool {
        self.free_pages < self.watermarks.low
    }

    /// Check whether kswapd should sleep.
    pub const fn kswapd_should_sleep(&self) -> bool {
        self.free_pages >= self.watermarks.high
    }

    /// Check whether direct reclaim is needed.
    pub const fn needs_direct_reclaim(&self) -> bool {
        self.free_pages < self.watermarks.min
    }

    /// Update free page count after allocation.
    pub fn alloc_pages(&mut self, count: u64) -> Result<()> {
        if self.free_pages < count {
            return Err(Error::OutOfMemory);
        }
        self.free_pages -= count;
        if self.kswapd_should_wake() {
            self.kswapd_active = true;
        }
        Ok(())
    }

    /// Update free page count after free.
    pub fn free_pages_back(&mut self, count: u64) {
        self.free_pages = self.free_pages.saturating_add(count);
        if self.free_pages > self.total_pages {
            self.free_pages = self.total_pages;
        }
        if self.kswapd_should_sleep() {
            self.kswapd_active = false;
        }
    }

    /// Check whether kswapd is active.
    pub const fn is_kswapd_active(&self) -> bool {
        self.kswapd_active
    }

    /// Recalculate watermarks (e.g. after memory hotplug).
    pub fn recalculate(&mut self) {
        self.watermarks = WatermarkLevel::from_zone_pages(self.total_pages);
        self.lowmem_reserve = self.total_pages / LOWMEM_RESERVE_RATIO;
    }
}

impl Default for ZoneWatermark {
    fn default() -> Self {
        Self {
            zone_type: ZoneType::Normal,
            total_pages: 0,
            free_pages: 0,
            watermarks: WatermarkLevel::zero(),
            lowmem_reserve: 0,
            kswapd_active: false,
        }
    }
}

// -------------------------------------------------------------------
// WatermarkManager
// -------------------------------------------------------------------

/// Manages watermarks for all memory zones.
pub struct WatermarkManager {
    /// Per-zone watermarks.
    zones: [ZoneWatermark; MAX_ZONES],
    /// Number of active zones.
    count: usize,
}

impl WatermarkManager {
    /// Create a new manager.
    pub const fn new() -> Self {
        Self {
            zones: [const {
                ZoneWatermark {
                    zone_type: ZoneType::Normal,
                    total_pages: 0,
                    free_pages: 0,
                    watermarks: WatermarkLevel {
                        min: 0,
                        low: 0,
                        high: 0,
                    },
                    lowmem_reserve: 0,
                    kswapd_active: false,
                }
            }; MAX_ZONES],
            count: 0,
        }
    }

    /// Add a zone.
    pub fn add_zone(&mut self, zone_type: ZoneType, total_pages: u64) -> Result<()> {
        if self.count >= MAX_ZONES {
            return Err(Error::OutOfMemory);
        }
        self.zones[self.count] = ZoneWatermark::new(zone_type, total_pages);
        self.count += 1;
        Ok(())
    }

    /// Return the number of zones.
    pub const fn count(&self) -> usize {
        self.count
    }

    /// Find the best zone for an allocation.
    pub fn find_zone(&self, count: u64) -> Option<usize> {
        for idx in 0..self.count {
            if self.zones[idx].can_alloc(count) {
                return Some(idx);
            }
        }
        None
    }

    /// Get a zone by index.
    pub fn zone(&self, index: usize) -> Result<&ZoneWatermark> {
        if index >= self.count {
            return Err(Error::InvalidArgument);
        }
        Ok(&self.zones[index])
    }

    /// Get a mutable zone by index.
    pub fn zone_mut(&mut self, index: usize) -> Result<&mut ZoneWatermark> {
        if index >= self.count {
            return Err(Error::InvalidArgument);
        }
        Ok(&mut self.zones[index])
    }

    /// Recalculate all zone watermarks.
    pub fn recalculate_all(&mut self) {
        for idx in 0..self.count {
            self.zones[idx].recalculate();
        }
    }

    /// Check whether any zone needs direct reclaim.
    pub fn any_needs_reclaim(&self) -> bool {
        for idx in 0..self.count {
            if self.zones[idx].needs_direct_reclaim() {
                return true;
            }
        }
        false
    }
}

impl Default for WatermarkManager {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// Public helpers
// -------------------------------------------------------------------

/// Return the total free pages across all zones.
pub fn total_free_pages(mgr: &WatermarkManager) -> u64 {
    let mut total = 0u64;
    for idx in 0..mgr.count() {
        if let Ok(z) = mgr.zone(idx) {
            total += z.free_pages();
        }
    }
    total
}

/// Return the total system pages across all zones.
pub fn total_system_pages(mgr: &WatermarkManager) -> u64 {
    let mut total = 0u64;
    for idx in 0..mgr.count() {
        if let Ok(z) = mgr.zone(idx) {
            total += z.total_pages();
        }
    }
    total
}

/// Check whether the system is under overall memory pressure.
pub fn system_under_pressure(mgr: &WatermarkManager) -> bool {
    mgr.any_needs_reclaim()
}
