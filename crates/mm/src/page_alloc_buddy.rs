// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Buddy allocator for page frames.
//!
//! Implements a classic power-of-two buddy system for physical page
//! allocation. Pages are grouped into blocks of 2^order contiguous
//! frames. When a request cannot be satisfied at the desired order,
//! a higher-order block is split. When adjacent buddies are freed
//! they are coalesced back into a larger block.
//!
//! # Types
//!
//! - [`BuddyOrder`] — allocation order (0 = 4 KiB, MAX = 4 MiB)
//! - [`BuddyBlockState`] — free / allocated / split
//! - [`BuddyBlock`] — metadata for one contiguous block
//! - [`FreeList`] — per-order free list
//! - [`BuddyZoneType`] — DMA / Normal / HighMem zone type
//! - [`BuddyZone`] — a single physical memory zone
//! - [`BuddyWatermarks`] — zone watermark thresholds
//! - [`BuddyAllocRequest`] — allocation request parameters
//! - [`BuddyAllocResult`] — result of a successful allocation
//! - [`BuddyAllocator`] — top-level buddy allocator
//! - [`BuddyFragInfo`] — fragmentation snapshot
//! - [`BuddyStats`] — aggregate statistics
//!
//! # Buddy Algorithm
//!
//! **Allocation** of order `k`:
//! 1. Search free lists from order `k` upward in the target zone.
//! 2. If a block of order `j >= k` is found, remove it from the free
//!    list and split it (j - k) times, placing the upper halves back
//!    on their respective free lists.
//! 3. Return the lower half as the allocated block.
//!
//! **Free** of order `k` block at PFN `p`:
//! 1. Compute the buddy PFN: `buddy = p ^ (1 << k)`.
//! 2. If the buddy is free at order `k`, remove it and merge into
//!    order `k + 1`. Repeat until no buddy is free or MAX_ORDER.
//! 3. Place the merged block on its order's free list.
//!
//! Reference: Linux `mm/page_alloc.c`.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Maximum allocation order (2^MAX_ORDER pages = 4 MiB).
pub const MAX_ORDER: usize = 10;

/// Number of order levels (0..=MAX_ORDER inclusive).
pub const ORDER_LEVELS: usize = MAX_ORDER + 1;

/// Standard page size in bytes (4 KiB).
pub const PAGE_SIZE: u64 = 4096;

/// Maximum blocks tracked per free list (per order).
const MAX_BLOCKS_PER_LIST: usize = 512;

/// Maximum number of zones.
pub const MAX_ZONES: usize = 3;

/// Maximum total blocks tracked across all zones.
const MAX_TOTAL_BLOCKS: usize = 4096;

/// Default min-watermark fraction (1/32 of zone size).
const WATERMARK_MIN_FRAC: u64 = 32;

/// Default low-watermark fraction (1/16 of zone size).
const WATERMARK_LOW_FRAC: u64 = 16;

/// Default high-watermark fraction (1/8 of zone size).
const WATERMARK_HIGH_FRAC: u64 = 8;

/// Maximum number of allocation requests to log.
const MAX_ALLOC_LOG: usize = 64;

// -------------------------------------------------------------------
// BuddyOrder
// -------------------------------------------------------------------

/// Allocation order — the log2 of the number of pages.
///
/// Order 0 = 1 page (4 KiB), order 10 = 1024 pages (4 MiB).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct BuddyOrder(pub u32);

impl BuddyOrder {
    /// Creates a new order, clamped to `MAX_ORDER`.
    pub const fn new(order: u32) -> Self {
        if order as usize > MAX_ORDER {
            Self(MAX_ORDER as u32)
        } else {
            Self(order)
        }
    }

    /// Returns the number of pages in a block of this order.
    pub const fn nr_pages(self) -> u64 {
        1u64 << self.0
    }

    /// Returns the size in bytes of a block of this order.
    pub const fn size_bytes(self) -> u64 {
        self.nr_pages() * PAGE_SIZE
    }

    /// Returns the order as a `usize` index.
    pub const fn as_usize(self) -> usize {
        self.0 as usize
    }
}

impl Default for BuddyOrder {
    fn default() -> Self {
        Self(0)
    }
}

// -------------------------------------------------------------------
// BuddyBlockState
// -------------------------------------------------------------------

/// State of a buddy block.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum BuddyBlockState {
    /// Block is free and on the free list.
    #[default]
    Free,
    /// Block is allocated.
    Allocated,
    /// Block has been split into two smaller blocks.
    Split,
}

// -------------------------------------------------------------------
// BuddyBlock
// -------------------------------------------------------------------

/// Metadata for a single buddy block.
#[derive(Debug, Clone, Copy)]
pub struct BuddyBlock {
    /// Page frame number (PFN) of the first page.
    pub pfn: u64,
    /// Allocation order of this block.
    pub order: BuddyOrder,
    /// Current state.
    pub state: BuddyBlockState,
    /// Zone index this block belongs to.
    pub zone_idx: u8,
    /// Whether this block is on the free list.
    pub on_free_list: bool,
    /// Allocation tag for debugging.
    pub alloc_tag: u32,
}

impl BuddyBlock {
    /// Creates an empty block.
    const fn empty() -> Self {
        Self {
            pfn: 0,
            order: BuddyOrder(0),
            state: BuddyBlockState::Free,
            zone_idx: 0,
            on_free_list: false,
            alloc_tag: 0,
        }
    }

    /// Returns the PFN of this block's buddy at the same order.
    pub const fn buddy_pfn(&self) -> u64 {
        self.pfn ^ (1u64 << self.order.0)
    }

    /// Returns the number of pages in this block.
    pub const fn nr_pages(&self) -> u64 {
        self.order.nr_pages()
    }

    /// Returns the physical address of the first page.
    pub const fn phys_addr(&self) -> u64 {
        self.pfn * PAGE_SIZE
    }
}

impl Default for BuddyBlock {
    fn default() -> Self {
        Self::empty()
    }
}

// -------------------------------------------------------------------
// FreeList
// -------------------------------------------------------------------

/// Per-order free list holding free blocks of a given order.
#[derive(Clone)]
pub struct FreeList {
    /// PFNs of free blocks at this order.
    pfns: [u64; MAX_BLOCKS_PER_LIST],
    /// Number of valid entries.
    count: usize,
    /// Order level this list represents.
    order: u32,
}

impl FreeList {
    /// Creates an empty free list for the given order.
    const fn new(order: u32) -> Self {
        Self {
            pfns: [0; MAX_BLOCKS_PER_LIST],
            count: 0,
            order,
        }
    }

    /// Returns the number of free blocks at this order.
    pub const fn count(&self) -> usize {
        self.count
    }

    /// Returns true if the list is empty.
    pub const fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Returns the total free pages represented by this list.
    pub const fn free_pages(&self) -> u64 {
        (self.count as u64) << self.order
    }

    /// Adds a PFN to the free list.
    fn push(&mut self, pfn: u64) -> Result<()> {
        if self.count >= MAX_BLOCKS_PER_LIST {
            return Err(Error::OutOfMemory);
        }
        self.pfns[self.count] = pfn;
        self.count += 1;
        Ok(())
    }

    /// Removes and returns the last PFN on the free list.
    fn pop(&mut self) -> Option<u64> {
        if self.count == 0 {
            return None;
        }
        self.count -= 1;
        Some(self.pfns[self.count])
    }

    /// Removes a specific PFN from the free list.
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

    /// Checks whether a PFN is on this free list.
    fn contains(&self, pfn: u64) -> bool {
        for i in 0..self.count {
            if self.pfns[i] == pfn {
                return true;
            }
        }
        false
    }
}

impl Default for FreeList {
    fn default() -> Self {
        Self::new(0)
    }
}

// -------------------------------------------------------------------
// BuddyZoneType
// -------------------------------------------------------------------

/// Memory zone classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum BuddyZoneType {
    /// DMA zone — first 16 MiB, for legacy ISA DMA.
    Dma,
    /// Normal zone — regular kernel memory.
    #[default]
    Normal,
    /// High memory zone — memory above direct-map ceiling.
    HighMem,
}

// -------------------------------------------------------------------
// BuddyWatermarks
// -------------------------------------------------------------------

/// Watermark thresholds for a zone.
///
/// - **min**: emergency reserve; only atomic/memalloc contexts.
/// - **low**: wakeup threshold for kswapd.
/// - **high**: back-off threshold for kswapd.
#[derive(Debug, Clone, Copy, Default)]
pub struct BuddyWatermarks {
    /// Minimum watermark in pages.
    pub min: u64,
    /// Low watermark in pages.
    pub low: u64,
    /// High watermark in pages.
    pub high: u64,
}

impl BuddyWatermarks {
    /// Computes watermarks from zone total pages.
    pub const fn from_zone_pages(total_pages: u64) -> Self {
        Self {
            min: total_pages / WATERMARK_MIN_FRAC,
            low: total_pages / WATERMARK_LOW_FRAC,
            high: total_pages / WATERMARK_HIGH_FRAC,
        }
    }

    /// Returns true if `free_pages` is above the min watermark.
    pub const fn above_min(&self, free_pages: u64) -> bool {
        free_pages > self.min
    }

    /// Returns true if `free_pages` is above the low watermark.
    pub const fn above_low(&self, free_pages: u64) -> bool {
        free_pages > self.low
    }

    /// Returns true if `free_pages` is above the high watermark.
    pub const fn above_high(&self, free_pages: u64) -> bool {
        free_pages > self.high
    }
}

// -------------------------------------------------------------------
// BuddyZone
// -------------------------------------------------------------------

/// A single physical memory zone with per-order free lists.
pub struct BuddyZone {
    /// Zone type.
    pub zone_type: BuddyZoneType,
    /// Start PFN of this zone.
    pub start_pfn: u64,
    /// Total pages managed.
    pub total_pages: u64,
    /// Currently free pages.
    pub free_pages: u64,
    /// Per-order free lists.
    free_lists: [FreeList; ORDER_LEVELS],
    /// Watermark thresholds.
    pub watermarks: BuddyWatermarks,
    /// Whether the zone is initialised.
    pub active: bool,
    /// Total allocations from this zone.
    pub alloc_count: u64,
    /// Total frees to this zone.
    pub free_count: u64,
    /// Total splits performed.
    pub split_count: u64,
    /// Total coalesces performed.
    pub coalesce_count: u64,
}

impl BuddyZone {
    /// Creates an uninitialised zone.
    const fn empty() -> Self {
        Self {
            zone_type: BuddyZoneType::Normal,
            start_pfn: 0,
            total_pages: 0,
            free_pages: 0,
            free_lists: [
                FreeList::new(0),
                FreeList::new(1),
                FreeList::new(2),
                FreeList::new(3),
                FreeList::new(4),
                FreeList::new(5),
                FreeList::new(6),
                FreeList::new(7),
                FreeList::new(8),
                FreeList::new(9),
                FreeList::new(10),
            ],
            watermarks: BuddyWatermarks {
                min: 0,
                low: 0,
                high: 0,
            },
            active: false,
            alloc_count: 0,
            free_count: 0,
            split_count: 0,
            coalesce_count: 0,
        }
    }

    /// Initialises this zone with the given parameters.
    pub fn init(&mut self, zone_type: BuddyZoneType, start_pfn: u64, total_pages: u64) {
        self.zone_type = zone_type;
        self.start_pfn = start_pfn;
        self.total_pages = total_pages;
        self.free_pages = 0;
        self.watermarks = BuddyWatermarks::from_zone_pages(total_pages);
        self.active = true;
    }

    /// Returns the end PFN (exclusive) of this zone.
    pub const fn end_pfn(&self) -> u64 {
        self.start_pfn + self.total_pages
    }

    /// Returns whether `pfn` falls within this zone.
    pub const fn contains_pfn(&self, pfn: u64) -> bool {
        pfn >= self.start_pfn && pfn < self.start_pfn + self.total_pages
    }

    /// Adds a free block of the given order at `pfn`.
    fn add_free_block(&mut self, pfn: u64, order: usize) -> Result<()> {
        if order >= ORDER_LEVELS {
            return Err(Error::InvalidArgument);
        }
        self.free_lists[order].push(pfn)?;
        self.free_pages += 1u64 << order;
        Ok(())
    }

    /// Removes a free block of the given order at `pfn`.
    fn remove_free_block(&mut self, pfn: u64, order: usize) -> bool {
        if order >= ORDER_LEVELS {
            return false;
        }
        if self.free_lists[order].remove(pfn) {
            let pages = 1u64 << order;
            if self.free_pages >= pages {
                self.free_pages -= pages;
            }
            true
        } else {
            false
        }
    }

    /// Checks whether a block at `pfn` of the given order is on the
    /// free list.
    fn is_free_at_order(&self, pfn: u64, order: usize) -> bool {
        if order >= ORDER_LEVELS {
            return false;
        }
        self.free_lists[order].contains(pfn)
    }

    /// Allocates a block of the requested order from this zone.
    ///
    /// Searches from `order` upward; splits higher-order blocks as
    /// needed.
    fn alloc_pages(&mut self, order: usize, atomic: bool) -> Result<u64> {
        if !self.active {
            return Err(Error::NotFound);
        }
        let pages_needed = 1u64 << order;
        if !atomic
            && !self
                .watermarks
                .above_low(self.free_pages.saturating_sub(pages_needed))
        {
            return Err(Error::OutOfMemory);
        }
        if atomic
            && !self
                .watermarks
                .above_min(self.free_pages.saturating_sub(pages_needed))
        {
            return Err(Error::OutOfMemory);
        }
        // Search from requested order upward.
        let mut found_order = None;
        for o in order..ORDER_LEVELS {
            if !self.free_lists[o].is_empty() {
                found_order = Some(o);
                break;
            }
        }
        let found = found_order.ok_or(Error::OutOfMemory)?;
        let pfn = self.free_lists[found].pop().ok_or(Error::OutOfMemory)?;
        let found_pages = 1u64 << found;
        if self.free_pages >= found_pages {
            self.free_pages -= found_pages;
        }
        // Split down to requested order.
        let mut current_order = found;
        let current_pfn = pfn;
        while current_order > order {
            current_order -= 1;
            let buddy_pfn = current_pfn + (1u64 << current_order);
            self.free_lists[current_order].push(buddy_pfn)?;
            self.free_pages += 1u64 << current_order;
            self.split_count += 1;
        }
        self.alloc_count += 1;
        Ok(current_pfn)
    }

    /// Frees a block at `pfn` of the given order, coalescing with
    /// buddies.
    fn free_pages_at(&mut self, pfn: u64, order: usize) -> Result<()> {
        if !self.active || !self.contains_pfn(pfn) {
            return Err(Error::InvalidArgument);
        }
        let mut current_pfn = pfn;
        let mut current_order = order;
        // Attempt to coalesce with buddy.
        while current_order < MAX_ORDER {
            let buddy_pfn = current_pfn ^ (1u64 << current_order);
            if !self.contains_pfn(buddy_pfn) {
                break;
            }
            if !self.is_free_at_order(buddy_pfn, current_order) {
                break;
            }
            self.remove_free_block(buddy_pfn, current_order);
            current_pfn = core::cmp::min(current_pfn, buddy_pfn);
            current_order += 1;
            self.coalesce_count += 1;
        }
        self.add_free_block(current_pfn, current_order)?;
        self.free_count += 1;
        Ok(())
    }

    /// Returns a fragmentation snapshot for this zone.
    pub fn frag_info(&self) -> BuddyFragInfo {
        let mut free_per_order = [0u64; ORDER_LEVELS];
        for i in 0..ORDER_LEVELS {
            free_per_order[i] = self.free_lists[i].count() as u64;
        }
        let total_free_blocks: u64 = free_per_order.iter().sum();
        let fragmentation_pct = if self.total_pages == 0 {
            0
        } else if total_free_blocks == 0 {
            0
        } else {
            let small = free_per_order[0] + free_per_order[1];
            (small * 100) / total_free_blocks
        };
        BuddyFragInfo {
            zone_type: self.zone_type,
            free_per_order,
            total_free_pages: self.free_pages,
            fragmentation_pct,
        }
    }
}

impl Default for BuddyZone {
    fn default() -> Self {
        Self::empty()
    }
}

// -------------------------------------------------------------------
// BuddyAllocRequest
// -------------------------------------------------------------------

/// Parameters for a buddy allocation request.
#[derive(Debug, Clone, Copy)]
pub struct BuddyAllocRequest {
    /// Desired allocation order.
    pub order: BuddyOrder,
    /// Preferred zone type.
    pub zone_pref: BuddyZoneType,
    /// Whether this is an atomic (no-sleep) allocation.
    pub atomic: bool,
    /// Allow fallback to other zones if preferred is exhausted.
    pub allow_fallback: bool,
    /// Caller tag for debugging.
    pub tag: u32,
}

impl Default for BuddyAllocRequest {
    fn default() -> Self {
        Self {
            order: BuddyOrder(0),
            zone_pref: BuddyZoneType::Normal,
            atomic: false,
            allow_fallback: true,
            tag: 0,
        }
    }
}

// -------------------------------------------------------------------
// BuddyAllocResult
// -------------------------------------------------------------------

/// Result of a successful buddy allocation.
#[derive(Debug, Clone, Copy)]
pub struct BuddyAllocResult {
    /// PFN of the allocated block.
    pub pfn: u64,
    /// Physical address of the first page.
    pub phys_addr: u64,
    /// Actual order allocated.
    pub order: BuddyOrder,
    /// Zone the allocation came from.
    pub zone_type: BuddyZoneType,
    /// Zone index.
    pub zone_idx: usize,
}

// -------------------------------------------------------------------
// BuddyFragInfo
// -------------------------------------------------------------------

/// Fragmentation snapshot for a single zone.
#[derive(Debug, Clone, Copy)]
pub struct BuddyFragInfo {
    /// Zone type.
    pub zone_type: BuddyZoneType,
    /// Free block count per order.
    pub free_per_order: [u64; ORDER_LEVELS],
    /// Total free pages.
    pub total_free_pages: u64,
    /// Fragmentation percentage (0..100).
    pub fragmentation_pct: u64,
}

impl Default for BuddyFragInfo {
    fn default() -> Self {
        Self {
            zone_type: BuddyZoneType::Normal,
            free_per_order: [0; ORDER_LEVELS],
            total_free_pages: 0,
            fragmentation_pct: 0,
        }
    }
}

// -------------------------------------------------------------------
// BuddyStats
// -------------------------------------------------------------------

/// Aggregate statistics across all zones.
#[derive(Debug, Clone, Copy, Default)]
pub struct BuddyStats {
    /// Total managed pages across all zones.
    pub total_pages: u64,
    /// Total free pages across all zones.
    pub total_free: u64,
    /// Total allocations.
    pub total_allocs: u64,
    /// Total frees.
    pub total_frees: u64,
    /// Total splits.
    pub total_splits: u64,
    /// Total coalesces.
    pub total_coalesces: u64,
    /// Number of active zones.
    pub active_zones: usize,
    /// Number of failed allocations.
    pub failed_allocs: u64,
}

// -------------------------------------------------------------------
// AllocationLog
// -------------------------------------------------------------------

/// Record of a single allocation event.
#[derive(Debug, Clone, Copy, Default)]
struct AllocLogEntry {
    /// PFN of the allocation.
    pfn: u64,
    /// Order requested.
    order: u32,
    /// Zone index.
    zone_idx: u8,
    /// Tag from the request.
    tag: u32,
    /// Whether this was a free (true) or alloc (false).
    is_free: bool,
}

// -------------------------------------------------------------------
// BuddyAllocator
// -------------------------------------------------------------------

/// Top-level buddy allocator managing multiple physical memory zones.
///
/// Provides allocation, free, and zone management for the physical
/// page allocator. Supports DMA, Normal, and HighMem zones with
/// watermark enforcement and automatic buddy coalescing.
pub struct BuddyAllocator {
    /// Memory zones.
    zones: [BuddyZone; MAX_ZONES],
    /// Number of initialised zones.
    nr_zones: usize,
    /// Block tracking array (for external lookup).
    blocks: [BuddyBlock; MAX_TOTAL_BLOCKS],
    /// Number of tracked blocks.
    nr_blocks: usize,
    /// Next allocation tag.
    next_tag: u32,
    /// Allocation log.
    alloc_log: [AllocLogEntry; MAX_ALLOC_LOG],
    /// Current log position.
    log_pos: usize,
    /// Total failed allocation count.
    failed_allocs: u64,
}

impl BuddyAllocator {
    /// Creates a new, uninitialised buddy allocator.
    pub const fn new() -> Self {
        Self {
            zones: [BuddyZone::empty(), BuddyZone::empty(), BuddyZone::empty()],
            nr_zones: 0,
            blocks: [BuddyBlock::empty(); MAX_TOTAL_BLOCKS],
            nr_blocks: 0,
            next_tag: 1,
            alloc_log: [AllocLogEntry {
                pfn: 0,
                order: 0,
                zone_idx: 0,
                tag: 0,
                is_free: false,
            }; MAX_ALLOC_LOG],
            log_pos: 0,
            failed_allocs: 0,
        }
    }

    /// Adds a new zone to the allocator.
    pub fn add_zone(
        &mut self,
        zone_type: BuddyZoneType,
        start_pfn: u64,
        total_pages: u64,
    ) -> Result<usize> {
        if self.nr_zones >= MAX_ZONES {
            return Err(Error::OutOfMemory);
        }
        let idx = self.nr_zones;
        self.zones[idx].init(zone_type, start_pfn, total_pages);
        self.nr_zones += 1;
        Ok(idx)
    }

    /// Marks a range of pages as free in the given zone.
    ///
    /// Pages are added as order-0 blocks initially. The caller can
    /// invoke [`compact_zone`] afterwards to coalesce.
    pub fn free_range(&mut self, zone_idx: usize, start_pfn: u64, nr_pages: u64) -> Result<()> {
        if zone_idx >= self.nr_zones {
            return Err(Error::InvalidArgument);
        }
        let mut pfn = start_pfn;
        let end = start_pfn + nr_pages;
        while pfn < end {
            // Find the largest order that aligns at this PFN and fits.
            let mut order = 0;
            while order < MAX_ORDER {
                let next_order = order + 1;
                let block_pages = 1u64 << next_order;
                if pfn % block_pages != 0 || pfn + block_pages > end {
                    break;
                }
                order = next_order;
            }
            self.zones[zone_idx].add_free_block(pfn, order)?;
            pfn += 1u64 << order;
        }
        Ok(())
    }

    /// Allocates pages according to the given request.
    pub fn alloc(&mut self, req: &BuddyAllocRequest) -> Result<BuddyAllocResult> {
        let order = req.order.as_usize();
        if order > MAX_ORDER {
            return Err(Error::InvalidArgument);
        }
        // Try preferred zone first.
        let pref_idx = self.find_zone(req.zone_pref);
        if let Some(idx) = pref_idx {
            if let Ok(pfn) = self.zones[idx].alloc_pages(order, req.atomic) {
                self.log_alloc(pfn, order as u32, idx as u8, req.tag, false);
                self.record_block(pfn, req.order, idx as u8, req.tag);
                return Ok(BuddyAllocResult {
                    pfn,
                    phys_addr: pfn * PAGE_SIZE,
                    order: req.order,
                    zone_type: self.zones[idx].zone_type,
                    zone_idx: idx,
                });
            }
        }
        // Fallback to other zones if allowed.
        if req.allow_fallback {
            for idx in 0..self.nr_zones {
                if Some(idx) == pref_idx {
                    continue;
                }
                if let Ok(pfn) = self.zones[idx].alloc_pages(order, req.atomic) {
                    self.log_alloc(pfn, order as u32, idx as u8, req.tag, false);
                    self.record_block(pfn, req.order, idx as u8, req.tag);
                    return Ok(BuddyAllocResult {
                        pfn,
                        phys_addr: pfn * PAGE_SIZE,
                        order: req.order,
                        zone_type: self.zones[idx].zone_type,
                        zone_idx: idx,
                    });
                }
            }
        }
        self.failed_allocs += 1;
        Err(Error::OutOfMemory)
    }

    /// Allocates a single page (order 0) from the Normal zone.
    pub fn alloc_page(&mut self) -> Result<BuddyAllocResult> {
        self.alloc(&BuddyAllocRequest::default())
    }

    /// Frees a previously allocated block.
    pub fn free(&mut self, pfn: u64, order: BuddyOrder) -> Result<()> {
        let zone_idx = self.find_zone_for_pfn(pfn).ok_or(Error::InvalidArgument)?;
        self.zones[zone_idx].free_pages_at(pfn, order.as_usize())?;
        self.log_alloc(pfn, order.0, zone_idx as u8, 0, true);
        self.remove_block(pfn);
        Ok(())
    }

    /// Frees a single page (order 0).
    pub fn free_page(&mut self, pfn: u64) -> Result<()> {
        self.free(pfn, BuddyOrder(0))
    }

    /// Returns the zone index for a given zone type.
    fn find_zone(&self, zone_type: BuddyZoneType) -> Option<usize> {
        for i in 0..self.nr_zones {
            if self.zones[i].zone_type == zone_type && self.zones[i].active {
                return Some(i);
            }
        }
        None
    }

    /// Returns the zone index containing a given PFN.
    fn find_zone_for_pfn(&self, pfn: u64) -> Option<usize> {
        for i in 0..self.nr_zones {
            if self.zones[i].active && self.zones[i].contains_pfn(pfn) {
                return Some(i);
            }
        }
        None
    }

    /// Records a block allocation in the block table.
    fn record_block(&mut self, pfn: u64, order: BuddyOrder, zone_idx: u8, tag: u32) {
        if self.nr_blocks < MAX_TOTAL_BLOCKS {
            self.blocks[self.nr_blocks] = BuddyBlock {
                pfn,
                order,
                state: BuddyBlockState::Allocated,
                zone_idx,
                on_free_list: false,
                alloc_tag: tag,
            };
            self.nr_blocks += 1;
        }
    }

    /// Removes a block record by PFN.
    fn remove_block(&mut self, pfn: u64) {
        for i in 0..self.nr_blocks {
            if self.blocks[i].pfn == pfn {
                self.blocks[i] = self.blocks[self.nr_blocks - 1];
                self.nr_blocks -= 1;
                return;
            }
        }
    }

    /// Logs an allocation or free event.
    fn log_alloc(&mut self, pfn: u64, order: u32, zone_idx: u8, tag: u32, is_free: bool) {
        self.alloc_log[self.log_pos] = AllocLogEntry {
            pfn,
            order,
            zone_idx,
            tag,
            is_free,
        };
        self.log_pos = (self.log_pos + 1) % MAX_ALLOC_LOG;
    }

    /// Returns fragmentation info for a zone.
    pub fn zone_frag_info(&self, zone_idx: usize) -> Result<BuddyFragInfo> {
        if zone_idx >= self.nr_zones {
            return Err(Error::InvalidArgument);
        }
        Ok(self.zones[zone_idx].frag_info())
    }

    /// Returns the watermarks for a zone.
    pub fn zone_watermarks(&self, zone_idx: usize) -> Result<BuddyWatermarks> {
        if zone_idx >= self.nr_zones {
            return Err(Error::InvalidArgument);
        }
        Ok(self.zones[zone_idx].watermarks)
    }

    /// Updates watermarks for a zone.
    pub fn set_zone_watermarks(
        &mut self,
        zone_idx: usize,
        watermarks: BuddyWatermarks,
    ) -> Result<()> {
        if zone_idx >= self.nr_zones {
            return Err(Error::InvalidArgument);
        }
        self.zones[zone_idx].watermarks = watermarks;
        Ok(())
    }

    /// Returns aggregate statistics.
    pub fn stats(&self) -> BuddyStats {
        let mut s = BuddyStats::default();
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
        s
    }

    /// Returns the number of active zones.
    pub const fn nr_zones(&self) -> usize {
        self.nr_zones
    }

    /// Returns the total number of tracked allocated blocks.
    pub const fn nr_blocks(&self) -> usize {
        self.nr_blocks
    }

    /// Returns zone information by index.
    pub fn zone_info(&self, zone_idx: usize) -> Result<(BuddyZoneType, u64, u64, u64)> {
        if zone_idx >= self.nr_zones {
            return Err(Error::InvalidArgument);
        }
        let z = &self.zones[zone_idx];
        Ok((z.zone_type, z.start_pfn, z.total_pages, z.free_pages))
    }

    /// Compacts a zone by attempting to coalesce adjacent free blocks.
    ///
    /// Iterates order 0 through MAX_ORDER - 1, checking for buddy
    /// pairs that can be merged.
    pub fn compact_zone(&mut self, zone_idx: usize) -> Result<u64> {
        if zone_idx >= self.nr_zones {
            return Err(Error::InvalidArgument);
        }
        let mut merges = 0u64;
        for order in 0..MAX_ORDER {
            let mut i = 0;
            loop {
                if i >= self.zones[zone_idx].free_lists[order].count {
                    break;
                }
                let pfn = self.zones[zone_idx].free_lists[order].pfns[i];
                let buddy = pfn ^ (1u64 << order);
                if self.zones[zone_idx].free_lists[order].contains(buddy) {
                    // Remove both blocks.
                    self.zones[zone_idx].free_lists[order].remove(pfn);
                    self.zones[zone_idx].free_lists[order].remove(buddy);
                    let merged_pfn = core::cmp::min(pfn, buddy);
                    let pages_removed = 2u64 << order;
                    if self.zones[zone_idx].free_pages >= pages_removed {
                        self.zones[zone_idx].free_pages -= pages_removed;
                    }
                    let _ = self.zones[zone_idx].add_free_block(merged_pfn, order + 1);
                    merges += 1;
                    // Restart scan at this order (list changed).
                    i = 0;
                } else {
                    i += 1;
                }
            }
        }
        Ok(merges)
    }

    /// Resets all allocator state. Used during testing or reinit.
    pub fn reset(&mut self) {
        *self = Self::new();
    }
}

impl Default for BuddyAllocator {
    fn default() -> Self {
        Self::new()
    }
}
