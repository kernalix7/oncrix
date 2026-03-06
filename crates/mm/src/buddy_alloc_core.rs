// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Buddy allocator core operations.
//!
//! Implements split/coalesce of free blocks by order, per-zone free
//! area management, fallback migration types, per-CPU page (PCP) drain,
//! and watermark checking. This is the core allocation engine beneath
//! the higher-level `__alloc_pages` path.
//!
//! # Key Types
//!
//! - [`MigrateType`] — page mobility classification
//! - [`FreeArea`] — per-order free list with migration-type buckets
//! - [`PcpList`] — per-CPU page list (hot/cold pages)
//! - [`ZoneInfo`] — per-zone metadata and free areas
//! - [`AllocFlags`] — allocation request flags
//! - [`WatermarkLevel`] — watermark thresholds
//! - [`BuddyAllocCore`] — the core allocator engine
//! - [`BuddyCoreStats`] — aggregate statistics
//!
//! Reference: Linux `mm/page_alloc.c` (`__alloc_pages`,
//! `__free_one_page`, `rmqueue`, `free_pcppages_bulk`).

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Standard page size (4 KiB).
const PAGE_SIZE: u64 = 4096;

/// Maximum allocation order (2^10 = 1024 pages = 4 MiB).
const MAX_ORDER: usize = 10;

/// Number of order levels.
const NR_ORDERS: usize = MAX_ORDER + 1;

/// Maximum PFNs per free-area bucket.
const MAX_FREE_PER_BUCKET: usize = 256;

/// Number of migration types.
const NR_MIGRATE_TYPES: usize = 4;

/// Maximum zones.
const MAX_ZONES: usize = 4;

/// Per-CPU page list capacity.
const PCP_CAPACITY: usize = 128;

/// PCP batch size for drain/refill.
const PCP_BATCH: usize = 16;

/// Maximum number of CPUs.
const MAX_CPUS: usize = 8;

/// Watermark min fraction (1/32 of zone pages).
const WM_MIN_FRAC: u64 = 32;

/// Watermark low fraction (1/16 of zone pages).
const WM_LOW_FRAC: u64 = 16;

/// Watermark high fraction (1/8 of zone pages).
const WM_HIGH_FRAC: u64 = 8;

/// Fallback migration order (used when preferred type is exhausted).
const FALLBACK_ORDER: [MigrateType; NR_MIGRATE_TYPES] = [
    MigrateType::Unmovable,
    MigrateType::Movable,
    MigrateType::Reclaimable,
    MigrateType::HighAtomic,
];

// -------------------------------------------------------------------
// MigrateType
// -------------------------------------------------------------------

/// Page mobility classification for anti-fragmentation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum MigrateType {
    /// Pages that cannot be migrated (kernel allocations).
    #[default]
    Unmovable = 0,
    /// Pages that can be migrated (user pages, page cache).
    Movable = 1,
    /// Pages that can be reclaimed (slab, page cache).
    Reclaimable = 2,
    /// Reserved for high-priority atomic allocations.
    HighAtomic = 3,
}

impl MigrateType {
    /// Returns the array index for this type.
    fn idx(self) -> usize {
        self as usize
    }
}

// -------------------------------------------------------------------
// FreeAreaBucket
// -------------------------------------------------------------------

/// A single migration-type bucket within a free area.
struct FreeAreaBucket {
    /// PFNs of free blocks.
    pfns: [u64; MAX_FREE_PER_BUCKET],
    /// Number of valid entries.
    count: usize,
}

impl FreeAreaBucket {
    /// Creates an empty bucket.
    const fn new() -> Self {
        Self {
            pfns: [0u64; MAX_FREE_PER_BUCKET],
            count: 0,
        }
    }

    /// Pushes a PFN onto the bucket.
    fn push(&mut self, pfn: u64) -> bool {
        if self.count >= MAX_FREE_PER_BUCKET {
            return false;
        }
        self.pfns[self.count] = pfn;
        self.count += 1;
        true
    }

    /// Pops a PFN from the bucket.
    fn pop(&mut self) -> Option<u64> {
        if self.count == 0 {
            return None;
        }
        self.count -= 1;
        Some(self.pfns[self.count])
    }

    /// Removes a specific PFN. Returns true if found.
    fn remove(&mut self, pfn: u64) -> bool {
        for i in 0..self.count {
            if self.pfns[i] == pfn {
                self.pfns[i] = self.pfns[self.count - 1];
                self.count -= 1;
                return true;
            }
        }
        false
    }

    /// Checks if a PFN is in this bucket.
    fn contains(&self, pfn: u64) -> bool {
        for i in 0..self.count {
            if self.pfns[i] == pfn {
                return true;
            }
        }
        false
    }
}

// -------------------------------------------------------------------
// FreeArea
// -------------------------------------------------------------------

/// Per-order free area with migration-type buckets.
///
/// Each order level maintains separate free lists per migration
/// type, enabling anti-fragmentation grouping.
pub struct FreeArea {
    /// Buckets indexed by migration type.
    buckets: [FreeAreaBucket; NR_MIGRATE_TYPES],
    /// Order this free area represents.
    order: usize,
}

impl FreeArea {
    /// Creates an empty free area for the given order.
    const fn new(order: usize) -> Self {
        Self {
            buckets: [
                FreeAreaBucket::new(),
                FreeAreaBucket::new(),
                FreeAreaBucket::new(),
                FreeAreaBucket::new(),
            ],
            order,
        }
    }

    /// Adds a free block of the given migration type.
    pub fn add(&mut self, pfn: u64, migrate: MigrateType) -> bool {
        self.buckets[migrate.idx()].push(pfn)
    }

    /// Removes a block of the given migration type.
    pub fn remove(&mut self, pfn: u64, migrate: MigrateType) -> bool {
        self.buckets[migrate.idx()].remove(pfn)
    }

    /// Pops a block from the preferred migration type.
    /// Falls back to other types if empty.
    pub fn pop_with_fallback(&mut self, preferred: MigrateType) -> Option<(u64, MigrateType)> {
        // Try preferred first.
        if let Some(pfn) = self.buckets[preferred.idx()].pop() {
            return Some((pfn, preferred));
        }
        // Fallback.
        for &mt in &FALLBACK_ORDER {
            if mt == preferred {
                continue;
            }
            if let Some(pfn) = self.buckets[mt.idx()].pop() {
                return Some((pfn, mt));
            }
        }
        None
    }

    /// Total free blocks across all migration types at this order.
    pub fn total_free(&self) -> usize {
        let mut total = 0;
        for b in &self.buckets {
            total += b.count;
        }
        total
    }

    /// Free blocks of a specific migration type.
    pub fn free_count(&self, migrate: MigrateType) -> usize {
        self.buckets[migrate.idx()].count
    }

    /// Checks if a PFN is free at this order (any migration type).
    pub fn is_free(&self, pfn: u64) -> bool {
        for b in &self.buckets {
            if b.contains(pfn) {
                return true;
            }
        }
        false
    }
}

// -------------------------------------------------------------------
// PcpList
// -------------------------------------------------------------------

/// Per-CPU page list for order-0 hot/cold pages.
///
/// Hot pages (recently freed, likely in cache) are at the tail.
/// Cold pages are at the head.
pub struct PcpList {
    /// PFNs.
    pfns: [u64; PCP_CAPACITY],
    /// Number of valid entries.
    count: usize,
    /// CPU this list belongs to.
    cpu_id: u32,
    /// High watermark: drain when above this.
    high: usize,
    /// Batch size for drain operations.
    batch: usize,
}

impl PcpList {
    /// Creates an empty PCP list for the given CPU.
    const fn new(cpu_id: u32) -> Self {
        Self {
            pfns: [0u64; PCP_CAPACITY],
            count: 0,
            cpu_id,
            high: PCP_CAPACITY * 3 / 4,
            batch: PCP_BATCH,
        }
    }

    /// Allocates a hot page (from tail).
    pub fn alloc_hot(&mut self) -> Option<u64> {
        if self.count == 0 {
            return None;
        }
        self.count -= 1;
        Some(self.pfns[self.count])
    }

    /// Allocates a cold page (from head).
    pub fn alloc_cold(&mut self) -> Option<u64> {
        if self.count == 0 {
            return None;
        }
        let pfn = self.pfns[0];
        // Shift remaining entries left.
        for i in 0..self.count - 1 {
            self.pfns[i] = self.pfns[i + 1];
        }
        self.count -= 1;
        Some(pfn)
    }

    /// Frees a page as hot (push to tail).
    pub fn free_hot(&mut self, pfn: u64) -> bool {
        if self.count >= PCP_CAPACITY {
            return false;
        }
        self.pfns[self.count] = pfn;
        self.count += 1;
        true
    }

    /// Returns `true` if the PCP list needs draining.
    pub fn needs_drain(&self) -> bool {
        self.count > self.high
    }

    /// Drains a batch of pages into the provided slice.
    /// Returns the number of pages drained.
    pub fn drain_batch(&mut self, out: &mut [u64]) -> usize {
        let to_drain = self.batch.min(self.count).min(out.len());
        for i in 0..to_drain {
            self.count -= 1;
            out[i] = self.pfns[self.count];
        }
        to_drain
    }

    /// Returns the number of pages in the PCP list.
    pub fn count(&self) -> usize {
        self.count
    }

    /// Returns the CPU ID.
    pub fn cpu_id(&self) -> u32 {
        self.cpu_id
    }
}

// -------------------------------------------------------------------
// WatermarkLevel
// -------------------------------------------------------------------

/// Watermark thresholds for a zone.
#[derive(Debug, Clone, Copy, Default)]
pub struct WatermarkLevel {
    /// Minimum watermark (pages).
    pub min: u64,
    /// Low watermark (pages).
    pub low: u64,
    /// High watermark (pages).
    pub high: u64,
}

impl WatermarkLevel {
    /// Computes watermarks from zone total pages.
    pub fn from_zone_pages(total: u64) -> Self {
        Self {
            min: total / WM_MIN_FRAC,
            low: total / WM_LOW_FRAC,
            high: total / WM_HIGH_FRAC,
        }
    }

    /// Checks if `free` pages are above the given watermark.
    pub fn check(&self, free: u64, level: WmCheck) -> bool {
        match level {
            WmCheck::Min => free > self.min,
            WmCheck::Low => free > self.low,
            WmCheck::High => free > self.high,
        }
    }
}

/// Which watermark to check against.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WmCheck {
    /// Check against minimum watermark.
    Min,
    /// Check against low watermark.
    Low,
    /// Check against high watermark.
    High,
}

// -------------------------------------------------------------------
// AllocFlags
// -------------------------------------------------------------------

/// Allocation request flags.
pub struct AllocFlags;

impl AllocFlags {
    /// Allow waiting/sleeping for memory.
    pub const WAIT: u32 = 1 << 0;
    /// High-priority allocation.
    pub const HIGH: u32 = 1 << 1;
    /// Atomic allocation (no sleep).
    pub const ATOMIC: u32 = 1 << 2;
    /// DMA zone allocation.
    pub const DMA: u32 = 1 << 3;
    /// Movable allocation.
    pub const MOVABLE: u32 = 1 << 4;
    /// Zero the page after allocation.
    pub const ZERO: u32 = 1 << 5;
    /// Cold page preferred.
    pub const COLD: u32 = 1 << 6;
}

// -------------------------------------------------------------------
// ZoneInfo
// -------------------------------------------------------------------

/// Per-zone metadata and free areas.
pub struct ZoneInfo {
    /// Zone index.
    pub zone_idx: u8,
    /// Whether the zone is active.
    pub active: bool,
    /// Start PFN.
    pub start_pfn: u64,
    /// Total pages.
    pub total_pages: u64,
    /// Free pages.
    pub free_pages: u64,
    /// Per-order free areas.
    free_areas: [FreeArea; NR_ORDERS],
    /// Watermark thresholds.
    pub watermarks: WatermarkLevel,
    /// Total allocations.
    pub alloc_count: u64,
    /// Total frees.
    pub free_count: u64,
    /// Total splits.
    pub split_count: u64,
    /// Total coalesces.
    pub coalesce_count: u64,
}

impl ZoneInfo {
    /// Creates an uninitialised zone.
    const fn empty(idx: u8) -> Self {
        Self {
            zone_idx: idx,
            active: false,
            start_pfn: 0,
            total_pages: 0,
            free_pages: 0,
            free_areas: [
                FreeArea::new(0),
                FreeArea::new(1),
                FreeArea::new(2),
                FreeArea::new(3),
                FreeArea::new(4),
                FreeArea::new(5),
                FreeArea::new(6),
                FreeArea::new(7),
                FreeArea::new(8),
                FreeArea::new(9),
                FreeArea::new(10),
            ],
            watermarks: WatermarkLevel {
                min: 0,
                low: 0,
                high: 0,
            },
            alloc_count: 0,
            free_count: 0,
            split_count: 0,
            coalesce_count: 0,
        }
    }

    /// Initialises the zone.
    pub fn init(&mut self, start_pfn: u64, total_pages: u64) {
        self.start_pfn = start_pfn;
        self.total_pages = total_pages;
        self.free_pages = 0;
        self.watermarks = WatermarkLevel::from_zone_pages(total_pages);
        self.active = true;
    }

    /// Returns `true` if the PFN belongs to this zone.
    pub fn contains_pfn(&self, pfn: u64) -> bool {
        pfn >= self.start_pfn && pfn < self.start_pfn + self.total_pages
    }
}

// -------------------------------------------------------------------
// BuddyCoreStats
// -------------------------------------------------------------------

/// Aggregate buddy allocator statistics.
#[derive(Debug, Clone, Copy, Default)]
pub struct BuddyCoreStats {
    /// Total pages across all zones.
    pub total_pages: u64,
    /// Total free pages.
    pub total_free: u64,
    /// Total allocations.
    pub total_allocs: u64,
    /// Total frees.
    pub total_frees: u64,
    /// Total block splits.
    pub total_splits: u64,
    /// Total coalesces.
    pub total_coalesces: u64,
    /// Failed allocations.
    pub failed_allocs: u64,
    /// PCP drain events.
    pub pcp_drains: u64,
    /// Active zones.
    pub active_zones: usize,
}

// -------------------------------------------------------------------
// BuddyAllocCore
// -------------------------------------------------------------------

/// Core buddy allocator engine.
///
/// Manages per-zone free areas with migration-type grouping,
/// per-CPU page lists, watermark enforcement, and buddy
/// split/coalesce operations.
pub struct BuddyAllocCore {
    /// Per-zone information.
    zones: [ZoneInfo; MAX_ZONES],
    /// Number of active zones.
    nr_zones: usize,
    /// Per-CPU page lists (one per CPU per zone 0 = Normal).
    pcp: [PcpList; MAX_CPUS],
    /// Total failed allocations.
    failed_allocs: u64,
    /// PCP drain count.
    pcp_drains: u64,
}

impl BuddyAllocCore {
    /// Creates a new, uninitialised allocator.
    pub const fn new() -> Self {
        Self {
            zones: [
                ZoneInfo::empty(0),
                ZoneInfo::empty(1),
                ZoneInfo::empty(2),
                ZoneInfo::empty(3),
            ],
            nr_zones: 0,
            pcp: [
                PcpList::new(0),
                PcpList::new(1),
                PcpList::new(2),
                PcpList::new(3),
                PcpList::new(4),
                PcpList::new(5),
                PcpList::new(6),
                PcpList::new(7),
            ],
            failed_allocs: 0,
            pcp_drains: 0,
        }
    }

    /// Adds a zone to the allocator.
    pub fn add_zone(&mut self, start_pfn: u64, total_pages: u64) -> Result<usize> {
        if self.nr_zones >= MAX_ZONES {
            return Err(Error::OutOfMemory);
        }
        let idx = self.nr_zones;
        self.zones[idx].init(start_pfn, total_pages);
        self.nr_zones += 1;
        Ok(idx)
    }

    /// Frees a range of pages into a zone at the highest fitting order.
    pub fn free_range(
        &mut self,
        zone_idx: usize,
        start_pfn: u64,
        nr_pages: u64,
        migrate: MigrateType,
    ) -> Result<()> {
        if zone_idx >= self.nr_zones {
            return Err(Error::InvalidArgument);
        }
        let mut pfn = start_pfn;
        let end = start_pfn + nr_pages;
        while pfn < end {
            let mut order = 0usize;
            while order < MAX_ORDER {
                let next = order + 1;
                let block_pages = 1u64 << next;
                if pfn % block_pages != 0 || pfn + block_pages > end {
                    break;
                }
                order = next;
            }
            self.zones[zone_idx].free_areas[order].add(pfn, migrate);
            self.zones[zone_idx].free_pages += 1u64 << order;
            pfn += 1u64 << order;
        }
        Ok(())
    }

    /// Allocates pages of the given order from the specified zone.
    ///
    /// Uses the buddy split algorithm: search from the requested
    /// order upward, split higher-order blocks as needed.
    pub fn alloc_pages(
        &mut self,
        zone_idx: usize,
        order: usize,
        migrate: MigrateType,
        flags: u32,
    ) -> Result<u64> {
        if zone_idx >= self.nr_zones || order > MAX_ORDER {
            return Err(Error::InvalidArgument);
        }

        // Order-0 with PCP: try per-CPU list first.
        if order == 0 && flags & AllocFlags::ATOMIC == 0 {
            // Use CPU 0 as default (real impl uses current CPU).
            let cpu = 0usize;
            if cpu < MAX_CPUS {
                let page = if flags & AllocFlags::COLD != 0 {
                    self.pcp[cpu].alloc_cold()
                } else {
                    self.pcp[cpu].alloc_hot()
                };
                if let Some(pfn) = page {
                    self.zones[zone_idx].alloc_count += 1;
                    return Ok(pfn);
                }
            }
        }

        // Watermark check.
        let wm_level = if flags & AllocFlags::ATOMIC != 0 {
            WmCheck::Min
        } else {
            WmCheck::Low
        };
        let pages_needed = 1u64 << order;
        let zone = &self.zones[zone_idx];
        if !zone
            .watermarks
            .check(zone.free_pages.saturating_sub(pages_needed), wm_level)
        {
            self.failed_allocs += 1;
            return Err(Error::OutOfMemory);
        }

        // Search from requested order upward.
        let mut found_order = None;
        for o in order..NR_ORDERS {
            if self.zones[zone_idx].free_areas[o].total_free() > 0 {
                found_order = Some(o);
                break;
            }
        }

        let fo = found_order.ok_or_else(|| {
            self.failed_allocs += 1;
            Error::OutOfMemory
        })?;

        let (pfn, _actual_mt) = self.zones[zone_idx].free_areas[fo]
            .pop_with_fallback(migrate)
            .ok_or_else(|| {
                self.failed_allocs += 1;
                Error::OutOfMemory
            })?;

        self.zones[zone_idx].free_pages -= 1u64 << fo;

        // Split down to requested order.
        let mut current_order = fo;
        while current_order > order {
            current_order -= 1;
            let buddy_pfn = pfn + (1u64 << current_order);
            self.zones[zone_idx].free_areas[current_order].add(buddy_pfn, migrate);
            self.zones[zone_idx].free_pages += 1u64 << current_order;
            self.zones[zone_idx].split_count += 1;
        }

        self.zones[zone_idx].alloc_count += 1;
        Ok(pfn)
    }

    /// Frees a block at `pfn` of the given order, coalescing buddies.
    pub fn free_one_page(&mut self, pfn: u64, order: usize, migrate: MigrateType) -> Result<()> {
        let zone_idx = self.find_zone(pfn).ok_or(Error::InvalidArgument)?;

        // Order-0: return to PCP list.
        if order == 0 {
            let cpu = 0usize;
            if cpu < MAX_CPUS && self.pcp[cpu].free_hot(pfn) {
                // Drain if PCP is over high watermark.
                if self.pcp[cpu].needs_drain() {
                    self.drain_pcp(cpu, zone_idx, migrate);
                }
                self.zones[zone_idx].free_count += 1;
                return Ok(());
            }
        }

        self.coalesce_and_free(zone_idx, pfn, order, migrate)
    }

    /// Coalesces a block with its buddy and places on the free list.
    fn coalesce_and_free(
        &mut self,
        zone_idx: usize,
        pfn: u64,
        order: usize,
        migrate: MigrateType,
    ) -> Result<()> {
        let mut current_pfn = pfn;
        let mut current_order = order;

        while current_order < MAX_ORDER {
            let buddy_pfn = current_pfn ^ (1u64 << current_order);
            if !self.zones[zone_idx].contains_pfn(buddy_pfn) {
                break;
            }
            if !self.zones[zone_idx].free_areas[current_order].is_free(buddy_pfn) {
                break;
            }
            // Remove buddy from free list.
            self.zones[zone_idx].free_areas[current_order].remove(buddy_pfn, migrate);
            self.zones[zone_idx].free_pages -= 1u64 << current_order;

            current_pfn = core::cmp::min(current_pfn, buddy_pfn);
            current_order += 1;
            self.zones[zone_idx].coalesce_count += 1;
        }

        self.zones[zone_idx].free_areas[current_order].add(current_pfn, migrate);
        self.zones[zone_idx].free_pages += 1u64 << current_order;
        self.zones[zone_idx].free_count += 1;
        Ok(())
    }

    /// Drains a PCP batch back into the zone's free areas.
    fn drain_pcp(&mut self, cpu: usize, zone_idx: usize, migrate: MigrateType) {
        let mut buf = [0u64; PCP_BATCH];
        let drained = self.pcp[cpu].drain_batch(&mut buf);
        for i in 0..drained {
            let _ = self.coalesce_and_free(zone_idx, buf[i], 0, migrate);
        }
        self.pcp_drains += 1;
    }

    /// Drains all PCP lists for all CPUs.
    pub fn drain_all_pcp(&mut self, migrate: MigrateType) {
        for cpu in 0..MAX_CPUS {
            if self.pcp[cpu].count() > 0 {
                // Drain into zone 0 (Normal).
                let zone_idx = if self.nr_zones > 0 { 0 } else { continue };
                self.drain_pcp(cpu, zone_idx, migrate);
            }
        }
    }

    /// Finds the zone containing a PFN.
    fn find_zone(&self, pfn: u64) -> Option<usize> {
        for i in 0..self.nr_zones {
            if self.zones[i].active && self.zones[i].contains_pfn(pfn) {
                return Some(i);
            }
        }
        None
    }

    /// Returns zone info by index.
    pub fn zone(&self, idx: usize) -> Result<&ZoneInfo> {
        if idx >= self.nr_zones {
            return Err(Error::InvalidArgument);
        }
        Ok(&self.zones[idx])
    }

    /// Returns aggregate statistics.
    pub fn stats(&self) -> BuddyCoreStats {
        let mut s = BuddyCoreStats::default();
        for i in 0..self.nr_zones {
            if self.zones[i].active {
                s.total_pages += self.zones[i].total_pages;
                s.total_free += self.zones[i].free_pages;
                s.total_allocs += self.zones[i].alloc_count;
                s.total_frees += self.zones[i].free_count;
                s.total_splits += self.zones[i].split_count;
                s.total_coalesces += self.zones[i].coalesce_count;
                s.active_zones += 1;
            }
        }
        s.failed_allocs = self.failed_allocs;
        s.pcp_drains = self.pcp_drains;
        s
    }

    /// Returns the number of active zones.
    pub fn nr_zones(&self) -> usize {
        self.nr_zones
    }
}

impl Default for BuddyAllocCore {
    fn default() -> Self {
        Self::new()
    }
}
