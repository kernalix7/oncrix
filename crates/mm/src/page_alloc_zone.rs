// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Zone-based page allocation.
//!
//! Implements the Linux-style zone allocator where physical memory is
//! divided into zones (DMA, DMA32, Normal, HighMem, Movable), each
//! with its own free page pool and watermark thresholds. Allocation
//! requests specify a preferred zone and fall back through a defined
//! zone list when the preferred zone is exhausted.
//!
//! - [`ZoneType`] — memory zone classification
//! - [`ZoneWatermarks`] — min/low/high watermark levels
//! - [`Zone`] — per-zone state (free pages, managed pages, watermarks)
//! - [`ZoneFreeList`] — per-order free list within a zone
//! - [`ZoneAllocator`] — the main zone-based page allocator
//! - [`AllocStats`] — allocation statistics
//!
//! Reference: `.kernelORG/` — `mm/page_alloc.c`, `include/linux/mmzone.h`.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Standard page size (4 KiB).
const PAGE_SIZE: u64 = 4096;

/// Maximum allocation order (2^MAX_ORDER pages = 4 MiB).
const MAX_ORDER: usize = 11;

/// Number of zone types.
const NR_ZONES: usize = 5;

/// Maximum pages tracked per free list order.
const MAX_FREE_PER_ORDER: usize = 128;

/// Default minimum free kbytes.
const DEFAULT_MIN_FREE_KBYTES: u64 = 16384;

// -------------------------------------------------------------------
// ZoneType
// -------------------------------------------------------------------

/// Memory zone classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ZoneType {
    /// DMA zone: first 16 MiB (ISA DMA).
    Dma = 0,
    /// DMA32 zone: first 4 GiB (32-bit DMA).
    Dma32 = 1,
    /// Normal zone: all directly mapped memory.
    #[default]
    Normal = 2,
    /// HighMem zone: memory above direct mapping (32-bit only).
    HighMem = 3,
    /// Movable zone: for memory hotplug and CMA.
    Movable = 4,
}

impl ZoneType {
    /// Returns the zone fallback order for allocation.
    ///
    /// When a preferred zone is exhausted, try these zones in order.
    fn fallback_list(self) -> &'static [ZoneType] {
        match self {
            ZoneType::Dma => &[ZoneType::Dma],
            ZoneType::Dma32 => &[ZoneType::Dma32, ZoneType::Dma],
            ZoneType::Normal => &[ZoneType::Normal, ZoneType::Dma32, ZoneType::Dma],
            ZoneType::HighMem => &[
                ZoneType::HighMem,
                ZoneType::Normal,
                ZoneType::Dma32,
                ZoneType::Dma,
            ],
            ZoneType::Movable => &[ZoneType::Movable, ZoneType::Normal, ZoneType::Dma32],
        }
    }
}

// -------------------------------------------------------------------
// ZoneWatermarks
// -------------------------------------------------------------------

/// Watermark levels for a zone (in pages).
#[derive(Debug, Clone, Copy, Default)]
pub struct ZoneWatermarks {
    /// Minimum watermark — below this, only emergency allocs.
    pub min: u64,
    /// Low watermark — kswapd wakes up.
    pub low: u64,
    /// High watermark — kswapd sleeps.
    pub high: u64,
    /// Boost amount applied temporarily after compaction.
    pub boost: u64,
}

impl ZoneWatermarks {
    /// Computes watermarks from min_free_kbytes and managed pages.
    pub fn compute(min_free_kbytes: u64, managed_pages: u64) -> Self {
        let min_pages = min_free_kbytes * 1024 / PAGE_SIZE;
        let fraction = if managed_pages > 0 {
            min_pages.min(managed_pages / 4)
        } else {
            0
        };
        Self {
            min: fraction,
            low: fraction + fraction / 4,
            high: fraction + fraction / 2,
            boost: 0,
        }
    }
}

// -------------------------------------------------------------------
// ZoneFreeList
// -------------------------------------------------------------------

/// Per-order free list within a zone.
///
/// Stores PFNs of free page blocks of a given order.
#[derive(Debug)]
pub struct ZoneFreeList {
    /// Free PFNs for this order.
    pfns: [u64; MAX_FREE_PER_ORDER],
    /// Number of free blocks.
    nr_free: usize,
    /// Allocation order (0 = single page, 1 = 2 pages, …).
    order: usize,
}

impl Default for ZoneFreeList {
    fn default() -> Self {
        Self {
            pfns: [0u64; MAX_FREE_PER_ORDER],
            nr_free: 0,
            order: 0,
        }
    }
}

impl ZoneFreeList {
    /// Creates a free list for the given order.
    fn new(order: usize) -> Self {
        Self {
            order,
            ..Self::default()
        }
    }

    /// Adds a free block (PFN) to the list.
    pub fn add(&mut self, pfn: u64) -> Result<()> {
        if self.nr_free >= MAX_FREE_PER_ORDER {
            return Err(Error::OutOfMemory);
        }
        self.pfns[self.nr_free] = pfn;
        self.nr_free += 1;
        Ok(())
    }

    /// Removes and returns a free block.
    pub fn remove(&mut self) -> Option<u64> {
        if self.nr_free == 0 {
            return None;
        }
        self.nr_free -= 1;
        Some(self.pfns[self.nr_free])
    }

    /// Returns the number of free blocks.
    pub fn count(&self) -> usize {
        self.nr_free
    }

    /// Returns `true` if empty.
    pub fn is_empty(&self) -> bool {
        self.nr_free == 0
    }

    /// Returns the order.
    pub fn order(&self) -> usize {
        self.order
    }
}

// -------------------------------------------------------------------
// Zone
// -------------------------------------------------------------------

/// Per-zone state.
pub struct Zone {
    /// Zone type.
    zone_type: ZoneType,
    /// Number of free pages in this zone.
    free_pages: u64,
    /// Total managed pages.
    managed_pages: u64,
    /// Present (physically existing) pages.
    present_pages: u64,
    /// Watermark thresholds.
    watermarks: ZoneWatermarks,
    /// Per-order free lists.
    free_lists: [ZoneFreeList; MAX_ORDER],
    /// Zone start PFN.
    start_pfn: u64,
    /// Whether zone is initialised.
    initialised: bool,
}

impl Default for Zone {
    fn default() -> Self {
        Self {
            zone_type: ZoneType::Normal,
            free_pages: 0,
            managed_pages: 0,
            present_pages: 0,
            watermarks: ZoneWatermarks::default(),
            free_lists: [const {
                ZoneFreeList {
                    pfns: [0u64; MAX_FREE_PER_ORDER],
                    nr_free: 0,
                    order: 0,
                }
            }; MAX_ORDER],
            start_pfn: 0,
            initialised: false,
        }
    }
}

impl Zone {
    /// Creates a new zone.
    pub fn new(zone_type: ZoneType, start_pfn: u64, present_pages: u64) -> Self {
        let mut zone = Self {
            zone_type,
            present_pages,
            managed_pages: present_pages,
            start_pfn,
            initialised: true,
            ..Self::default()
        };
        for i in 0..MAX_ORDER {
            zone.free_lists[i] = ZoneFreeList::new(i);
        }
        zone.watermarks = ZoneWatermarks::compute(DEFAULT_MIN_FREE_KBYTES, present_pages);
        zone
    }

    /// Returns the zone type.
    pub fn zone_type(&self) -> ZoneType {
        self.zone_type
    }

    /// Returns free page count.
    pub fn free_pages(&self) -> u64 {
        self.free_pages
    }

    /// Returns managed page count.
    pub fn managed_pages(&self) -> u64 {
        self.managed_pages
    }

    /// Returns the watermarks.
    pub fn watermarks(&self) -> &ZoneWatermarks {
        &self.watermarks
    }

    /// Checks if the zone is above the given watermark level.
    pub fn watermark_ok(&self, level: u64) -> bool {
        self.free_pages >= level + self.watermarks.boost
    }

    /// Fast watermark check (just min).
    pub fn watermark_fast(&self) -> bool {
        self.free_pages > self.watermarks.min
    }

    /// Adds a free page block of the given order.
    pub fn free_block(&mut self, pfn: u64, order: usize) -> Result<()> {
        if order >= MAX_ORDER {
            return Err(Error::InvalidArgument);
        }
        self.free_lists[order].add(pfn)?;
        self.free_pages += 1u64 << order;
        Ok(())
    }

    /// Allocates a page block of the given order.
    pub fn alloc_block(&mut self, order: usize) -> Result<u64> {
        if order >= MAX_ORDER {
            return Err(Error::InvalidArgument);
        }
        // Try exact order first.
        if let Some(pfn) = self.free_lists[order].remove() {
            self.free_pages = self.free_pages.saturating_sub(1u64 << order);
            return Ok(pfn);
        }
        // Try splitting a higher-order block.
        for higher in (order + 1)..MAX_ORDER {
            if let Some(pfn) = self.free_lists[higher].remove() {
                // Split: return pages from [order+1..higher] back.
                let mut split_pfn = pfn + ((1u64 << order) as u64);
                for split_order in order..higher {
                    let _ = self.free_lists[split_order].add(split_pfn);
                    split_pfn += 1u64 << split_order;
                }
                self.free_pages = self.free_pages.saturating_sub(1u64 << order);
                return Ok(pfn);
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Updates watermarks from min_free_kbytes.
    pub fn setup_watermarks(&mut self, min_free_kbytes: u64) {
        self.watermarks = ZoneWatermarks::compute(min_free_kbytes, self.managed_pages);
    }

    /// Sets a temporary watermark boost.
    pub fn set_watermark_boost(&mut self, boost: u64) {
        self.watermarks.boost = boost;
    }
}

// -------------------------------------------------------------------
// AllocStats
// -------------------------------------------------------------------

/// Zone allocator statistics.
#[derive(Debug, Clone, Copy, Default)]
pub struct AllocStats {
    /// Total allocation attempts.
    pub alloc_attempts: u64,
    /// Successful allocations.
    pub alloc_success: u64,
    /// Failed allocations (OOM).
    pub alloc_failures: u64,
    /// Fallback allocations (from non-preferred zone).
    pub fallback_allocs: u64,
    /// Total free operations.
    pub free_ops: u64,
    /// Higher-order splits performed.
    pub splits: u64,
}

impl AllocStats {
    /// Resets all counters.
    pub fn reset(&mut self) {
        *self = Self::default();
    }
}

// -------------------------------------------------------------------
// ZoneAllocator
// -------------------------------------------------------------------

/// Zone-based page allocator managing all memory zones.
pub struct ZoneAllocator {
    /// Per-zone state.
    zones: [Zone; NR_ZONES],
    /// Allocation statistics.
    stats: AllocStats,
    /// Global min_free_kbytes setting.
    min_free_kbytes: u64,
}

impl Default for ZoneAllocator {
    fn default() -> Self {
        Self {
            zones: [const {
                Zone {
                    zone_type: ZoneType::Normal,
                    free_pages: 0,
                    managed_pages: 0,
                    present_pages: 0,
                    watermarks: ZoneWatermarks {
                        min: 0,
                        low: 0,
                        high: 0,
                        boost: 0,
                    },
                    free_lists: [const {
                        ZoneFreeList {
                            pfns: [0u64; MAX_FREE_PER_ORDER],
                            nr_free: 0,
                            order: 0,
                        }
                    }; MAX_ORDER],
                    start_pfn: 0,
                    initialised: false,
                }
            }; NR_ZONES],
            stats: AllocStats::default(),
            min_free_kbytes: DEFAULT_MIN_FREE_KBYTES,
        }
    }
}

impl ZoneAllocator {
    /// Creates a new zone allocator.
    pub fn new() -> Self {
        Self::default()
    }

    /// Initialises a zone.
    pub fn init_zone(&mut self, zone_type: ZoneType, start_pfn: u64, present_pages: u64) {
        let idx = zone_type as usize;
        if idx < NR_ZONES {
            self.zones[idx] = Zone::new(zone_type, start_pfn, present_pages);
        }
    }

    /// Allocates pages of the given order from the preferred zone,
    /// falling back through the zone list.
    pub fn alloc_pages(&mut self, order: usize, preferred: ZoneType) -> Result<u64> {
        self.stats.alloc_attempts += 1;
        let fallback = preferred.fallback_list();
        let mut tried_fallback = false;

        for &zt in fallback {
            let idx = zt as usize;
            if idx >= NR_ZONES || !self.zones[idx].initialised {
                continue;
            }
            if !self.zones[idx].watermark_fast() {
                continue;
            }
            match self.zones[idx].alloc_block(order) {
                Ok(pfn) => {
                    self.stats.alloc_success += 1;
                    if tried_fallback {
                        self.stats.fallback_allocs += 1;
                    }
                    return Ok(pfn);
                }
                Err(_) => {
                    tried_fallback = true;
                }
            }
        }

        self.stats.alloc_failures += 1;
        Err(Error::OutOfMemory)
    }

    /// Frees a page block back to the specified zone.
    pub fn free_pages(&mut self, zone_type: ZoneType, pfn: u64, order: usize) -> Result<()> {
        let idx = zone_type as usize;
        if idx >= NR_ZONES {
            return Err(Error::InvalidArgument);
        }
        self.zones[idx].free_block(pfn, order)?;
        self.stats.free_ops += 1;
        Ok(())
    }

    /// Returns a reference to a zone.
    pub fn zone(&self, zone_type: ZoneType) -> &Zone {
        &self.zones[zone_type as usize]
    }

    /// Returns allocation statistics.
    pub fn stats(&self) -> &AllocStats {
        &self.stats
    }

    /// Sets min_free_kbytes and recomputes all zone watermarks.
    pub fn set_min_free_kbytes(&mut self, kbytes: u64) {
        self.min_free_kbytes = kbytes;
        for zone in &mut self.zones {
            if zone.initialised {
                zone.setup_watermarks(kbytes);
            }
        }
    }

    /// Returns total free pages across all zones.
    pub fn total_free_pages(&self) -> u64 {
        self.zones
            .iter()
            .filter(|z| z.initialised)
            .map(|z| z.free_pages)
            .sum()
    }
}
