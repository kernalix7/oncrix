// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Page allocation fallback.
//!
//! Implements the zone fallback mechanism for the page allocator. When
//! the preferred zone cannot satisfy an allocation, the allocator walks
//! a fallback chain of alternative zones. This module manages fallback
//! ordering, watermark adjustments during fallback, and GFP flag handling
//! for `__GFP_THISNODE`, `__GFP_NOFAIL`, and `__GFP_RETRY_MAYFAIL`.
//!
//! - [`ZoneId`] — zone identification
//! - [`FallbackEntry`] — single entry in a fallback chain
//! - [`FallbackOrder`] — per-zone fallback list
//! - [`FallbackConfig`] — global fallback configuration
//! - [`FallbackAllocator`] — main fallback allocation logic
//! - [`FallbackStats`] — allocation fallback statistics
//!
//! Reference: `.kernelORG/` — `mm/page_alloc.c`, `include/linux/gfp.h`.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Standard page size (4 KiB).
const PAGE_SIZE: u64 = 4096;

/// Maximum allocation order (2^MAX_ORDER pages).
const MAX_ORDER: usize = 11;

/// Maximum number of zones in the system.
const MAX_ZONES: usize = 6;

/// Maximum fallback chain length per zone.
const MAX_FALLBACK_CHAIN: usize = 6;

/// Maximum number of NUMA nodes.
const MAX_NODES: usize = 8;

/// Default low watermark pages.
const DEFAULT_LOW_WMARK: u64 = 256;

/// Default high watermark pages.
const DEFAULT_HIGH_WMARK: u64 = 512;

/// GFP flag: allocate only from the specified node.
const GFP_THISNODE: u32 = 1 << 0;

/// GFP flag: allocation must not fail (loop forever).
const GFP_NOFAIL: u32 = 1 << 1;

/// GFP flag: retry allocation, but may ultimately fail.
const GFP_RETRY_MAYFAIL: u32 = 1 << 2;

/// GFP flag: allow reclaim during allocation.
const GFP_RECLAIM: u32 = 1 << 3;

/// GFP flag: high priority allocation.
const GFP_HIGH: u32 = 1 << 4;

/// GFP flag: allow allocation from movable zone.
const GFP_MOVABLE: u32 = 1 << 5;

/// Maximum retry count for RETRY_MAYFAIL.
const MAX_RETRY_MAYFAIL: u32 = 16;

/// Watermark adjustment factor during fallback (shift right by this).
const WMARK_ADJUST_SHIFT: u32 = 2;

// -------------------------------------------------------------------
// ZoneId
// -------------------------------------------------------------------

/// Identifies a memory zone.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ZoneId {
    /// DMA zone: first 16 MiB (ISA DMA).
    Dma = 0,
    /// DMA32 zone: first 4 GiB (32-bit DMA).
    Dma32 = 1,
    /// Normal zone: all directly mapped memory.
    #[default]
    Normal = 2,
    /// HighMem zone: memory above direct mapping.
    HighMem = 3,
    /// Movable zone: for hotplug and CMA.
    Movable = 4,
    /// Device zone: device-specific memory.
    Device = 5,
}

impl ZoneId {
    /// Returns zone index.
    pub fn as_index(self) -> usize {
        self as usize
    }

    /// Converts index to zone ID.
    pub fn from_index(idx: usize) -> Result<Self> {
        match idx {
            0 => Ok(ZoneId::Dma),
            1 => Ok(ZoneId::Dma32),
            2 => Ok(ZoneId::Normal),
            3 => Ok(ZoneId::HighMem),
            4 => Ok(ZoneId::Movable),
            5 => Ok(ZoneId::Device),
            _ => Err(Error::InvalidArgument),
        }
    }
}

// -------------------------------------------------------------------
// FallbackEntry
// -------------------------------------------------------------------

/// A single entry in a zone fallback chain.
#[derive(Debug, Clone, Copy)]
pub struct FallbackEntry {
    /// Target zone to try.
    pub zone: ZoneId,
    /// NUMA node for this zone.
    pub node: u16,
    /// Priority (lower = preferred).
    pub priority: u8,
    /// Watermark adjustment factor for this fallback level.
    pub wmark_adjust: u8,
}

impl FallbackEntry {
    /// Creates a new fallback entry.
    pub fn new(zone: ZoneId, node: u16, priority: u8, wmark_adjust: u8) -> Self {
        Self {
            zone,
            node,
            priority,
            wmark_adjust,
        }
    }
}

impl Default for FallbackEntry {
    fn default() -> Self {
        Self {
            zone: ZoneId::Normal,
            node: 0,
            priority: 0,
            wmark_adjust: 0,
        }
    }
}

// -------------------------------------------------------------------
// FallbackOrder
// -------------------------------------------------------------------

/// Per-zone fallback ordering.
///
/// Each zone has a list of alternative zones to try when the preferred
/// zone cannot satisfy an allocation.
#[derive(Debug)]
pub struct FallbackOrder {
    /// Fallback chain entries.
    entries: [FallbackEntry; MAX_FALLBACK_CHAIN],
    /// Number of valid entries.
    len: usize,
    /// The preferred zone this fallback list is for.
    preferred_zone: ZoneId,
}

impl FallbackOrder {
    /// Creates a new empty fallback order for the given zone.
    pub fn new(preferred_zone: ZoneId) -> Self {
        Self {
            entries: [FallbackEntry::default(); MAX_FALLBACK_CHAIN],
            len: 0,
            preferred_zone,
        }
    }

    /// Adds an entry to the fallback chain.
    pub fn push(&mut self, entry: FallbackEntry) -> Result<()> {
        if self.len >= MAX_FALLBACK_CHAIN {
            return Err(Error::OutOfMemory);
        }
        self.entries[self.len] = entry;
        self.len += 1;
        Ok(())
    }

    /// Returns the fallback chain as a slice.
    pub fn entries(&self) -> &[FallbackEntry] {
        &self.entries[..self.len]
    }

    /// Returns the preferred zone.
    pub fn preferred_zone(&self) -> ZoneId {
        self.preferred_zone
    }

    /// Returns the number of fallback entries.
    pub fn len(&self) -> usize {
        self.len
    }

    /// Returns true if the fallback order is empty.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Builds the default fallback order for a zone.
    pub fn build_default(zone: ZoneId) -> Self {
        let mut order = Self::new(zone);
        match zone {
            ZoneId::Dma => {
                let _ = order.push(FallbackEntry::new(ZoneId::Dma, 0, 0, 0));
            }
            ZoneId::Dma32 => {
                let _ = order.push(FallbackEntry::new(ZoneId::Dma32, 0, 0, 0));
                let _ = order.push(FallbackEntry::new(ZoneId::Dma, 0, 1, 1));
            }
            ZoneId::Normal => {
                let _ = order.push(FallbackEntry::new(ZoneId::Normal, 0, 0, 0));
                let _ = order.push(FallbackEntry::new(ZoneId::Dma32, 0, 1, 1));
                let _ = order.push(FallbackEntry::new(ZoneId::Dma, 0, 2, 2));
            }
            ZoneId::HighMem => {
                let _ = order.push(FallbackEntry::new(ZoneId::HighMem, 0, 0, 0));
                let _ = order.push(FallbackEntry::new(ZoneId::Normal, 0, 1, 1));
                let _ = order.push(FallbackEntry::new(ZoneId::Dma32, 0, 2, 2));
                let _ = order.push(FallbackEntry::new(ZoneId::Dma, 0, 3, 3));
            }
            ZoneId::Movable => {
                let _ = order.push(FallbackEntry::new(ZoneId::Movable, 0, 0, 0));
                let _ = order.push(FallbackEntry::new(ZoneId::Normal, 0, 1, 1));
                let _ = order.push(FallbackEntry::new(ZoneId::Dma32, 0, 2, 2));
            }
            ZoneId::Device => {
                let _ = order.push(FallbackEntry::new(ZoneId::Device, 0, 0, 0));
            }
        }
        order
    }
}

// -------------------------------------------------------------------
// ZoneWatermark
// -------------------------------------------------------------------

/// Watermark levels for a zone.
#[derive(Debug, Clone, Copy, Default)]
pub struct ZoneWatermark {
    /// Minimum free pages (allocation triggers direct reclaim below this).
    pub min: u64,
    /// Low watermark (background reclaim starts).
    pub low: u64,
    /// High watermark (reclaim stops).
    pub high: u64,
}

impl ZoneWatermark {
    /// Creates new watermarks.
    pub fn new(min: u64, low: u64, high: u64) -> Self {
        Self { min, low, high }
    }

    /// Adjusts watermark for fallback (raise thresholds).
    pub fn adjusted(&self, level: u8) -> Self {
        let factor = 1u64 << (level.min(3) as u32);
        Self {
            min: self.min.saturating_mul(factor),
            low: self.low.saturating_mul(factor),
            high: self.high.saturating_mul(factor),
        }
    }

    /// Checks if free pages are above the given watermark level.
    pub fn above_wmark(&self, free_pages: u64, wmark: WatermarkLevel) -> bool {
        match wmark {
            WatermarkLevel::Min => free_pages > self.min,
            WatermarkLevel::Low => free_pages > self.low,
            WatermarkLevel::High => free_pages > self.high,
        }
    }
}

/// Which watermark level to check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WatermarkLevel {
    /// Minimum watermark.
    Min,
    /// Low watermark.
    Low,
    /// High watermark.
    High,
}

// -------------------------------------------------------------------
// ZoneState
// -------------------------------------------------------------------

/// State of a single zone for fallback decisions.
#[derive(Debug, Clone, Copy, Default)]
pub struct ZoneState {
    /// Zone identifier.
    pub zone: ZoneId,
    /// NUMA node.
    pub node: u16,
    /// Current free pages.
    pub free_pages: u64,
    /// Total managed pages.
    pub managed_pages: u64,
    /// Watermark levels.
    pub watermarks: ZoneWatermark,
    /// Whether the zone is active.
    pub active: bool,
}

impl ZoneState {
    /// Creates a new zone state.
    pub fn new(zone: ZoneId, node: u16, managed_pages: u64) -> Self {
        let min = managed_pages / 256;
        let low = min + min / 2;
        let high = min * 2;
        Self {
            zone,
            node,
            free_pages: managed_pages,
            managed_pages,
            watermarks: ZoneWatermark::new(min, low, high),
            active: true,
        }
    }

    /// Checks if the zone can satisfy an order-N allocation at the given
    /// watermark.
    pub fn can_alloc(&self, order: usize, wmark: WatermarkLevel) -> bool {
        if !self.active {
            return false;
        }
        let needed = 1u64 << order;
        if self.free_pages < needed {
            return false;
        }
        self.watermarks.above_wmark(self.free_pages - needed, wmark)
    }
}

// -------------------------------------------------------------------
// FallbackConfig
// -------------------------------------------------------------------

/// Global fallback configuration.
#[derive(Debug)]
pub struct FallbackConfig {
    /// Per-zone fallback orders.
    orders: [FallbackOrder; MAX_ZONES],
    /// Number of configured zones.
    nr_zones: usize,
    /// Whether NUMA-aware fallback is enabled.
    numa_aware: bool,
    /// Distance matrix for NUMA fallback (node x node).
    numa_distances: [[u8; MAX_NODES]; MAX_NODES],
    /// Number of NUMA nodes.
    nr_nodes: usize,
}

impl FallbackConfig {
    /// Creates a default fallback configuration.
    pub fn new() -> Self {
        let orders = [
            FallbackOrder::build_default(ZoneId::Dma),
            FallbackOrder::build_default(ZoneId::Dma32),
            FallbackOrder::build_default(ZoneId::Normal),
            FallbackOrder::build_default(ZoneId::HighMem),
            FallbackOrder::build_default(ZoneId::Movable),
            FallbackOrder::build_default(ZoneId::Device),
        ];
        let mut distances = [[255u8; MAX_NODES]; MAX_NODES];
        for (i, row) in distances.iter_mut().enumerate() {
            row[i] = 10; // local distance
        }
        Self {
            orders,
            nr_zones: MAX_ZONES,
            numa_aware: false,
            numa_distances: distances,
            nr_nodes: 1,
        }
    }

    /// Returns the fallback order for a zone.
    pub fn get_order(&self, zone: ZoneId) -> &FallbackOrder {
        &self.orders[zone.as_index()]
    }

    /// Enables NUMA-aware fallback.
    pub fn enable_numa(&mut self, nr_nodes: usize) {
        self.numa_aware = true;
        self.nr_nodes = nr_nodes.min(MAX_NODES);
    }

    /// Sets NUMA distance between two nodes.
    pub fn set_numa_distance(&mut self, from: usize, to: usize, distance: u8) {
        if from < MAX_NODES && to < MAX_NODES {
            self.numa_distances[from][to] = distance;
            self.numa_distances[to][from] = distance;
        }
    }

    /// Returns NUMA distance between two nodes.
    pub fn numa_distance(&self, from: usize, to: usize) -> u8 {
        if from < MAX_NODES && to < MAX_NODES {
            self.numa_distances[from][to]
        } else {
            255
        }
    }

    /// Returns whether NUMA is enabled.
    pub fn is_numa_aware(&self) -> bool {
        self.numa_aware
    }
}

impl Default for FallbackConfig {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// FallbackStats
// -------------------------------------------------------------------

/// Allocation fallback statistics.
#[derive(Debug, Clone, Copy, Default)]
pub struct FallbackStats {
    /// Total allocation attempts.
    pub total_attempts: u64,
    /// Allocations satisfied from preferred zone.
    pub preferred_hits: u64,
    /// Allocations that used fallback.
    pub fallback_hits: u64,
    /// Allocations that failed entirely.
    pub failures: u64,
    /// NOFAIL retries.
    pub nofail_retries: u64,
    /// RETRY_MAYFAIL retries.
    pub retry_mayfail_attempts: u64,
    /// Watermark adjustments during fallback.
    pub wmark_adjustments: u64,
    /// THISNODE allocations.
    pub thisnode_attempts: u64,
}

impl FallbackStats {
    /// Creates new statistics.
    pub fn new() -> Self {
        Self::default()
    }

    /// Resets all statistics.
    pub fn reset(&mut self) {
        *self = Self::default();
    }

    /// Returns the fallback ratio (0-100).
    pub fn fallback_ratio(&self) -> u64 {
        if self.total_attempts == 0 {
            return 0;
        }
        self.fallback_hits * 100 / self.total_attempts
    }

    /// Returns the failure ratio (0-100).
    pub fn failure_ratio(&self) -> u64 {
        if self.total_attempts == 0 {
            return 0;
        }
        self.failures * 100 / self.total_attempts
    }
}

// -------------------------------------------------------------------
// AllocationResult
// -------------------------------------------------------------------

/// Result of a fallback allocation attempt.
#[derive(Debug, Clone, Copy)]
pub struct AllocationResult {
    /// The allocated page frame number (0 if failed).
    pub pfn: u64,
    /// Which zone satisfied the allocation.
    pub zone: ZoneId,
    /// Which NUMA node.
    pub node: u16,
    /// Whether fallback was used.
    pub used_fallback: bool,
    /// Number of retries performed.
    pub retries: u32,
}

impl AllocationResult {
    /// Creates a successful result.
    pub fn success(pfn: u64, zone: ZoneId, node: u16, used_fallback: bool) -> Self {
        Self {
            pfn,
            zone,
            node,
            used_fallback,
            retries: 0,
        }
    }

    /// Creates a failed result.
    pub fn failure() -> Self {
        Self {
            pfn: 0,
            zone: ZoneId::Normal,
            node: 0,
            used_fallback: false,
            retries: 0,
        }
    }
}

// -------------------------------------------------------------------
// FallbackAllocator
// -------------------------------------------------------------------

/// Page allocator with zone fallback support.
///
/// When the preferred zone is exhausted, walks the fallback chain
/// defined in [`FallbackConfig`] and adjusts watermarks at each
/// fallback level.
pub struct FallbackAllocator {
    /// Zone states.
    zones: [ZoneState; MAX_ZONES],
    /// Number of active zones.
    nr_zones: usize,
    /// Fallback configuration.
    config: FallbackConfig,
    /// Statistics.
    stats: FallbackStats,
}

impl FallbackAllocator {
    /// Creates a new fallback allocator.
    pub fn new(config: FallbackConfig) -> Self {
        Self {
            zones: [ZoneState::default(); MAX_ZONES],
            nr_zones: 0,
            config,
            stats: FallbackStats::new(),
        }
    }

    /// Registers a zone with the allocator.
    pub fn register_zone(&mut self, state: ZoneState) -> Result<()> {
        let idx = state.zone.as_index();
        if idx >= MAX_ZONES {
            return Err(Error::InvalidArgument);
        }
        self.zones[idx] = state;
        if idx >= self.nr_zones {
            self.nr_zones = idx + 1;
        }
        Ok(())
    }

    /// Attempts to allocate pages with fallback.
    ///
    /// Tries the preferred zone first, then walks the fallback chain.
    /// Handles `GFP_THISNODE`, `GFP_NOFAIL`, and `GFP_RETRY_MAYFAIL`.
    pub fn alloc_pages_fallback(
        &mut self,
        preferred: ZoneId,
        order: usize,
        gfp_flags: u32,
    ) -> Result<AllocationResult> {
        if order >= MAX_ORDER {
            return Err(Error::InvalidArgument);
        }

        self.stats.total_attempts += 1;

        let thisnode = gfp_flags & GFP_THISNODE != 0;
        let nofail = gfp_flags & GFP_NOFAIL != 0;
        let retry_mayfail = gfp_flags & GFP_RETRY_MAYFAIL != 0;
        let high_prio = gfp_flags & GFP_HIGH != 0;

        if thisnode {
            self.stats.thisnode_attempts += 1;
        }

        let wmark = if high_prio {
            WatermarkLevel::Min
        } else {
            WatermarkLevel::Low
        };

        // Try preferred zone first.
        if let Some(result) = self.try_zone(preferred, order, wmark, 0) {
            self.stats.preferred_hits += 1;
            return Ok(result);
        }

        // If THISNODE is set, do not fall back to other zones.
        if thisnode {
            if nofail {
                return self.nofail_loop(preferred, order, wmark);
            }
            self.stats.failures += 1;
            return Err(Error::OutOfMemory);
        }

        // Walk the fallback chain — copy entries to break the borrow on self.config.
        let fallback_entries = {
            let fb = self.config.get_order(preferred);
            let mut buf = [FallbackEntry::default(); MAX_FALLBACK_CHAIN];
            let len = fb.entries().len().min(MAX_FALLBACK_CHAIN);
            buf[..len].copy_from_slice(&fb.entries()[..len]);
            (buf, len)
        };
        for i in 0..fallback_entries.1 {
            let entry = &fallback_entries.0[i];
            if entry.zone == preferred {
                continue; // Already tried.
            }
            let adjusted_wmark = if entry.wmark_adjust > 0 {
                self.stats.wmark_adjustments += 1;
                WatermarkLevel::Min
            } else {
                wmark
            };
            if let Some(mut result) = self.try_zone(entry.zone, order, adjusted_wmark, 0) {
                result.used_fallback = true;
                self.stats.fallback_hits += 1;
                return Ok(result);
            }
        }

        // Retry logic.
        if retry_mayfail {
            if let Some(result) = self.retry_mayfail(preferred, order) {
                return Ok(result);
            }
        }

        if nofail {
            return self.nofail_loop(preferred, order, wmark);
        }

        self.stats.failures += 1;
        Err(Error::OutOfMemory)
    }

    /// Tries to allocate from a specific zone.
    fn try_zone(
        &mut self,
        zone: ZoneId,
        order: usize,
        wmark: WatermarkLevel,
        _node_hint: u16,
    ) -> Option<AllocationResult> {
        let idx = zone.as_index();
        if idx >= MAX_ZONES {
            return None;
        }
        if !self.zones[idx].can_alloc(order, wmark) {
            return None;
        }
        let pages = 1u64 << order;
        let pfn = self.zones[idx].managed_pages - self.zones[idx].free_pages;
        let node = self.zones[idx].node;
        self.zones[idx].free_pages -= pages;
        Some(AllocationResult::success(pfn, zone, node, false))
    }

    /// Retry with RETRY_MAYFAIL semantics.
    fn retry_mayfail(&mut self, preferred: ZoneId, order: usize) -> Option<AllocationResult> {
        self.stats.retry_mayfail_attempts += 1;
        for _retry in 0..MAX_RETRY_MAYFAIL {
            // Try with minimum watermark.
            if let Some(result) = self.try_zone(preferred, order, WatermarkLevel::Min, 0) {
                return Some(result);
            }
            // Walk fallback with minimum watermarks.
            let entries: [FallbackEntry; MAX_FALLBACK_CHAIN] = {
                let fallback = self.config.get_order(preferred);
                let mut buf = [FallbackEntry::default(); MAX_FALLBACK_CHAIN];
                let len = fallback.len().min(MAX_FALLBACK_CHAIN);
                buf[..len].copy_from_slice(&fallback.entries()[..len]);
                buf
            };
            for entry in &entries {
                if entry.priority == 0 && entry.zone == preferred {
                    continue;
                }
                if let Some(result) = self.try_zone(entry.zone, order, WatermarkLevel::Min, 0) {
                    return Some(result);
                }
            }
        }
        None
    }

    /// NOFAIL loop: keep trying until allocation succeeds.
    fn nofail_loop(
        &mut self,
        zone: ZoneId,
        order: usize,
        wmark: WatermarkLevel,
    ) -> Result<AllocationResult> {
        // In a real kernel this would trigger reclaim and wait.
        // Here we model it as a bounded loop with relaxed watermarks.
        self.stats.nofail_retries += 1;
        for _i in 0..1024 {
            if let Some(result) = self.try_zone(zone, order, WatermarkLevel::Min, 0) {
                return Ok(result);
            }
        }
        // Even NOFAIL must eventually give up in our stub.
        let _ = wmark;
        self.stats.failures += 1;
        Err(Error::OutOfMemory)
    }

    /// Frees pages back to a zone.
    pub fn free_pages(&mut self, zone: ZoneId, order: usize) -> Result<()> {
        if order >= MAX_ORDER {
            return Err(Error::InvalidArgument);
        }
        let idx = zone.as_index();
        if idx >= MAX_ZONES {
            return Err(Error::InvalidArgument);
        }
        let pages = 1u64 << order;
        self.zones[idx].free_pages = self.zones[idx]
            .free_pages
            .saturating_add(pages)
            .min(self.zones[idx].managed_pages);
        Ok(())
    }

    /// Returns the zone state for a given zone.
    pub fn zone_state(&self, zone: ZoneId) -> &ZoneState {
        &self.zones[zone.as_index()]
    }

    /// Returns statistics.
    pub fn stats(&self) -> &FallbackStats {
        &self.stats
    }

    /// Resets statistics.
    pub fn reset_stats(&mut self) {
        self.stats.reset();
    }

    /// Returns the fallback configuration.
    pub fn config(&self) -> &FallbackConfig {
        &self.config
    }

    /// Updates zone free page count (e.g., after reclaim).
    pub fn update_zone_free(&mut self, zone: ZoneId, free_pages: u64) {
        let idx = zone.as_index();
        if idx < MAX_ZONES {
            self.zones[idx].free_pages = free_pages.min(self.zones[idx].managed_pages);
        }
    }
}
