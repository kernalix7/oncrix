// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Buddy page allocator.
//!
//! Implements the classic buddy system allocator for physical memory management.
//! Physical frames are organised into per-zone free lists indexed by allocation
//! order (order 0 = one 4 KiB page, order 10 = 1024 contiguous pages = 4 MiB).
//!
//! # Design
//!
//! - [`GfpFlags`] — get-free-pages flags (GFP_KERNEL, GFP_ATOMIC, GFP_DMA, …)
//! - [`ZoneType`] — memory zone classification (DMA, Normal, HighMem)
//! - [`WatermarkLevel`] — zone watermarks (min / low / high)
//! - [`ZoneWatermarks`] — per-zone watermark thresholds
//! - [`AllocOrder`] — allocation order type (0..=MAX_ORDER)
//! - [`BuddyBlock`] — a free contiguous run of 2^order pages
//! - [`FreeArea`] — per-order free list within a zone
//! - [`BuddyZone`] — a contiguous physical memory zone
//! - [`ZoneFragInfo`] — per-zone fragmentation snapshot
//! - [`BuddyStats`] — aggregate allocator statistics
//! - [`BuddyAllocator`] — top-level allocator managing up to [`MAX_ZONES`] zones
//!
//! # Buddy Algorithm
//!
//! **Allocation** of order `k`:
//! 1. Consult GFP flags to determine the allowed zone list and watermark.
//! 2. For each eligible zone, scan free areas from order `k` upward.
//! 3. If a block of order `j > k` is found, split it repeatedly: the high half
//!    is placed on the order-`j-1` free area; the low half is reduced by one
//!    order. Repeat until order `k` is reached.
//! 4. Check that allocating would leave free pages above the configured
//!    watermark (skipped for `GFP_ATOMIC` / `__GFP_MEMALLOC`).
//!
//! **Free** of order `k` block at PFN `p`:
//! 1. Compute buddy PFN: `buddy = p ^ (1 << k)`.
//! 2. If the buddy is on the order-`k` free area and within zone bounds, remove
//!    it, merge into an order-`k+1` block, and repeat.
//! 3. Place the final block on its free area.
//!
//! # Zone Watermarks
//!
//! Each zone has three watermarks:
//! - **min**: last-resort reserve; only `GFP_ATOMIC` / memalloc contexts allowed.
//! - **low**: kswapd wakeup threshold.
//! - **high**: kswapd back-off threshold.
//!
//! Normal allocations succeed only when free pages would remain above `low`
//! after the allocation.  The watermarks are set proportionally to zone size
//! via [`ZoneWatermarks::from_zone_pages`].

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

/// Maximum blocks tracked per free area (per order, per zone).
///
/// 512 blocks × order-0 = 512 pages × 4 KiB = 2 MiB per zone.
/// Higher orders hold fewer but larger blocks.
const MAX_BLOCKS_PER_AREA: usize = 512;

/// Maximum number of zones the allocator manages simultaneously.
pub const MAX_ZONES: usize = 3;

/// Default min-watermark as a fraction of zone size (1/32 = ~3 %).
const WATERMARK_MIN_FRAC: u64 = 32;
/// Default low-watermark as a fraction of zone size (1/16 = ~6 %).
const WATERMARK_LOW_FRAC: u64 = 16;
/// Default high-watermark as a fraction of zone size (1/8 = ~12 %).
const WATERMARK_HIGH_FRAC: u64 = 8;

// -------------------------------------------------------------------
// GfpFlags
// -------------------------------------------------------------------

/// Get-free-pages flags controlling allocation behaviour.
///
/// These flags mirror the semantics of Linux's `gfp_t` type.
/// Individual flags are combined with bitwise OR.
///
/// # Common combinations
///
/// | Combination | Meaning |
/// |-------------|---------|
/// | `GFP_KERNEL` | Normal kernel allocation; may sleep. |
/// | `GFP_ATOMIC` | Interrupt-safe; no sleep; uses min reserve. |
/// | `GFP_DMA`    | Must come from the DMA zone. |
/// | `GFP_HIGHUSER` | User allocation from HighMem if possible. |
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct GfpFlags(pub u32);

impl GfpFlags {
    // ------ Zone modifiers ------

    /// Allow allocation from DMA zone only.
    pub const GFP_DMA: Self = Self(1 << 0);
    /// Allow allocation from Normal zone (default).
    pub const GFP_KERNEL: Self = Self(1 << 1);
    /// Prefer HighMem zone for user-space pages.
    pub const GFP_HIGHMEM: Self = Self(1 << 2);

    // ------ Behaviour modifiers ------

    /// Interrupt-safe allocation; never sleeps; may dip below min watermark.
    pub const GFP_ATOMIC: Self = Self(1 << 3);
    /// Zero the allocated page(s) before returning.
    pub const GFP_ZERO: Self = Self(1 << 4);
    /// Allow allocation to use the memory reserve (below min watermark).
    pub const __GFP_MEMALLOC: Self = Self(1 << 5);
    /// Disable reclaim — fail immediately if no free pages.
    pub const __GFP_NORETRY: Self = Self(1 << 6);
    /// Caller can tolerate allocation failure.
    pub const __GFP_NOWARN: Self = Self(1 << 7);
    /// High-user allocation: HighMem preferred, Normal fallback.
    pub const GFP_HIGHUSER: Self = Self::combine(Self::GFP_KERNEL, Self::GFP_HIGHMEM);
    /// Combined DMA+kernel flags.
    pub const GFP_DMA32: Self = Self::combine(Self::GFP_KERNEL, Self::GFP_DMA);

    /// Combine two flag sets.
    pub const fn combine(a: Self, b: Self) -> Self {
        Self(a.0 | b.0)
    }

    /// Test whether `other` flags are all set in `self`.
    pub fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    /// Return true if this is an atomic allocation (no watermark respect).
    pub fn is_atomic(self) -> bool {
        self.contains(Self::GFP_ATOMIC) || self.contains(Self::__GFP_MEMALLOC)
    }

    /// Return true if pages must come from the DMA zone.
    pub fn requires_dma(self) -> bool {
        self.contains(Self::GFP_DMA) || self.contains(Self::GFP_DMA32)
    }

    /// Return true if HighMem is preferred.
    pub fn prefers_highmem(self) -> bool {
        self.contains(Self::GFP_HIGHMEM)
    }
}

// -------------------------------------------------------------------
// ZoneType
// -------------------------------------------------------------------

/// Classification of physical memory zones.
///
/// Zones partition physical memory into regions with different access
/// characteristics. Device drivers that cannot address all memory must
/// allocate from lower zones.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ZoneType {
    /// DMA zone: first 16 MiB, accessible by legacy ISA DMA controllers.
    Dma,
    /// Normal zone: 16 MiB – 4 GiB, directly mapped in kernel address space.
    Normal,
    /// HighMem zone: above 4 GiB (32-bit systems only; unused on x86_64).
    HighMem,
}

impl ZoneType {
    /// Zone priority for fallback ordering (lower = more restrictive).
    pub fn priority(self) -> u8 {
        match self {
            ZoneType::Dma => 0,
            ZoneType::Normal => 1,
            ZoneType::HighMem => 2,
        }
    }
}

// -------------------------------------------------------------------
// WatermarkLevel
// -------------------------------------------------------------------

/// Zone watermark level.
///
/// Watermarks guard physical memory reserves and trigger reclaim when
/// free memory falls below configured thresholds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum WatermarkLevel {
    /// Absolute minimum reserve; only emergency / atomic allocations allowed.
    Min,
    /// Low threshold: kswapd is woken when free pages drop below this.
    Low,
    /// High threshold: kswapd stops reclaiming when free pages exceed this.
    High,
}

// -------------------------------------------------------------------
// ZoneWatermarks
// -------------------------------------------------------------------

/// Per-zone watermark thresholds in pages.
///
/// Normal allocations succeed only when the post-allocation free count
/// would remain at or above [`low`](Self::low).  Atomic allocations may
/// dip to [`min`](Self::min).
#[derive(Debug, Clone, Copy)]
pub struct ZoneWatermarks {
    /// Minimum reserve (pages).
    pub min: u64,
    /// Low-water mark (pages).
    pub low: u64,
    /// High-water mark (pages).
    pub high: u64,
}

impl ZoneWatermarks {
    /// Derive watermarks proportionally from total zone pages.
    ///
    /// Uses the fractions defined by [`WATERMARK_MIN_FRAC`],
    /// [`WATERMARK_LOW_FRAC`], and [`WATERMARK_HIGH_FRAC`].
    pub fn from_zone_pages(total: u64) -> Self {
        let min = (total / WATERMARK_MIN_FRAC).max(1);
        let low = (total / WATERMARK_LOW_FRAC).max(min + 1);
        let high = (total / WATERMARK_HIGH_FRAC).max(low + 1);
        Self { min, low, high }
    }

    /// Return the threshold corresponding to a [`WatermarkLevel`].
    pub fn threshold(self, level: WatermarkLevel) -> u64 {
        match level {
            WatermarkLevel::Min => self.min,
            WatermarkLevel::Low => self.low,
            WatermarkLevel::High => self.high,
        }
    }

    /// Check whether `free_pages` is above the given watermark level.
    pub fn above(self, level: WatermarkLevel, free_pages: u64) -> bool {
        free_pages > self.threshold(level)
    }
}

// -------------------------------------------------------------------
// AllocOrder
// -------------------------------------------------------------------

/// Allocation order for the buddy allocator.
///
/// An order of `n` represents a contiguous block of `2^n` pages.
/// Valid range: `0..=MAX_ORDER`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct AllocOrder(pub u8);

impl AllocOrder {
    /// Order 0: a single 4 KiB page.
    pub const ZERO: Self = Self(0);
    /// Maximum supported order (order 10 = 1024 pages = 4 MiB).
    pub const MAX: Self = Self(MAX_ORDER as u8);

    /// Create a new [`AllocOrder`], clamped to [`MAX_ORDER`].
    pub fn new(order: u8) -> Self {
        Self(order.min(MAX_ORDER as u8))
    }

    /// Number of pages in a block of this order.
    pub fn pages(self) -> u64 {
        1u64 << self.0
    }

    /// Size in bytes of a block of this order.
    pub fn size_bytes(self) -> u64 {
        self.pages() * PAGE_SIZE
    }

    /// The index into order-level arrays.
    pub fn index(self) -> usize {
        self.0 as usize
    }

    /// Return the order one level higher, or `None` at `MAX_ORDER`.
    pub fn next(self) -> Option<Self> {
        if self.0 < MAX_ORDER as u8 {
            Some(Self(self.0 + 1))
        } else {
            None
        }
    }
}

// -------------------------------------------------------------------
// BuddyBlock
// -------------------------------------------------------------------

/// A free block tracked in a buddy free area.
///
/// The block spans `2^order` pages starting at physical frame number `pfn`.
#[derive(Debug, Clone, Copy)]
pub struct BuddyBlock {
    /// Physical frame number of the first page in this block.
    pub pfn: u64,
    /// Allocation order of this block.
    pub order: AllocOrder,
}

impl BuddyBlock {
    /// Compute the PFN of this block's buddy at the same order.
    ///
    /// The buddy of block at PFN `p` with order `k` is at `p ^ (1 << k)`.
    pub fn buddy_pfn(self) -> u64 {
        self.pfn ^ self.order.pages()
    }

    /// Physical start address of this block.
    pub fn start_addr(self) -> u64 {
        self.pfn * PAGE_SIZE
    }

    /// Physical end address (exclusive) of this block.
    pub fn end_addr(self) -> u64 {
        self.start_addr() + self.order.size_bytes()
    }

    /// Return the merged block one order higher, or `None` at `MAX_ORDER`.
    ///
    /// The merged block starts at the naturally aligned PFN for the higher order.
    pub fn merged(self) -> Option<BuddyBlock> {
        let higher = self.order.next()?;
        let merged_pfn = self.pfn & !(self.order.pages() - 1);
        Some(BuddyBlock {
            pfn: merged_pfn,
            order: higher,
        })
    }
}

// -------------------------------------------------------------------
// FreeArea
// -------------------------------------------------------------------

/// Per-order free list within a zone (the "free area" in Linux parlance).
///
/// Tracks free blocks of exactly `2^order` pages. All operations are
/// O(1) except buddy removal which is O(n) in list length.
struct FreeArea {
    blocks: [BuddyBlock; MAX_BLOCKS_PER_AREA],
    len: usize,
    /// Number of splits that produced blocks landing here.
    split_count: u64,
    /// Number of merges that consumed two blocks from here.
    merge_count: u64,
    /// Cumulative blocks allocated from this area.
    alloc_count: u64,
    /// Cumulative blocks freed into this area.
    free_count: u64,
}

impl FreeArea {
    const fn new() -> Self {
        Self {
            blocks: [BuddyBlock {
                pfn: 0,
                order: AllocOrder::ZERO,
            }; MAX_BLOCKS_PER_AREA],
            len: 0,
            split_count: 0,
            merge_count: 0,
            alloc_count: 0,
            free_count: 0,
        }
    }

    /// Push a block onto the free area.  Returns `Err(OutOfMemory)` if full.
    fn push(&mut self, block: BuddyBlock) -> Result<()> {
        if self.len >= MAX_BLOCKS_PER_AREA {
            return Err(Error::OutOfMemory);
        }
        self.blocks[self.len] = block;
        self.len += 1;
        Ok(())
    }

    /// Pop the most-recently-pushed block (LIFO, O(1)).
    fn pop(&mut self) -> Option<BuddyBlock> {
        if self.len == 0 {
            return None;
        }
        self.len -= 1;
        Some(self.blocks[self.len])
    }

    /// Remove the block with `pfn`, returning it if found.  O(n).
    fn remove_by_pfn(&mut self, pfn: u64) -> Option<BuddyBlock> {
        let pos = self.blocks[..self.len].iter().position(|b| b.pfn == pfn)?;
        let block = self.blocks[pos];
        self.len -= 1;
        if pos < self.len {
            self.blocks[pos] = self.blocks[self.len];
        }
        Some(block)
    }

    /// Return `true` if a block with the given PFN is in this area.
    fn contains_pfn(&self, pfn: u64) -> bool {
        self.blocks[..self.len].iter().any(|b| b.pfn == pfn)
    }

    /// Number of free blocks in this area.
    fn len(&self) -> usize {
        self.len
    }

    /// Number of free pages represented by all blocks in this area.
    fn free_pages(&self, order: AllocOrder) -> u64 {
        self.len as u64 * order.pages()
    }
}

// -------------------------------------------------------------------
// BuddyZone
// -------------------------------------------------------------------

/// A contiguous physical memory zone managed by the buddy system.
///
/// Each zone has its own per-order free areas and watermark thresholds.
/// All PFNs satisfy `base_pfn <= pfn < base_pfn + total_pages`.
pub struct BuddyZone {
    /// Zone classification.
    pub zone_type: ZoneType,
    /// First physical frame number in this zone.
    pub base_pfn: u64,
    /// Total number of 4 KiB pages in this zone.
    pub total_pages: u64,
    /// Number of currently free pages (kept in sync with free areas).
    free_pages: u64,
    /// Per-order free areas.
    free_areas: [FreeArea; ORDER_LEVELS],
    /// Watermark thresholds for this zone.
    pub watermarks: ZoneWatermarks,
    /// Whether this zone slot has been initialised.
    active: bool,
    /// Cumulative allocations satisfied by this zone.
    alloc_success: u64,
    /// Cumulative allocation attempts rejected (watermark or OOM).
    alloc_fail: u64,
}

impl BuddyZone {
    /// Create an inactive placeholder zone.
    const fn inactive() -> Self {
        Self {
            zone_type: ZoneType::Normal,
            base_pfn: 0,
            total_pages: 0,
            free_pages: 0,
            free_areas: [
                FreeArea::new(),
                FreeArea::new(),
                FreeArea::new(),
                FreeArea::new(),
                FreeArea::new(),
                FreeArea::new(),
                FreeArea::new(),
                FreeArea::new(),
                FreeArea::new(),
                FreeArea::new(),
                FreeArea::new(),
            ],
            watermarks: ZoneWatermarks {
                min: 0,
                low: 0,
                high: 0,
            },
            active: false,
            alloc_success: 0,
            alloc_fail: 0,
        }
    }

    /// Initialise this zone.
    ///
    /// All pages are placed into the highest-order free areas that fit,
    /// following the natural alignment of `base_pfn`. Watermarks are
    /// derived automatically from `total_pages`.
    pub fn init(&mut self, zone_type: ZoneType, base_pfn: u64, total_pages: u64) {
        self.zone_type = zone_type;
        self.base_pfn = base_pfn;
        self.total_pages = total_pages;
        self.free_pages = 0;
        self.active = true;
        self.watermarks = ZoneWatermarks::from_zone_pages(total_pages);

        // Walk from base_pfn, placing the largest naturally-aligned block
        // that still fits in the remaining range.
        let mut remaining = total_pages;
        let mut pfn = base_pfn;
        let mut order = MAX_ORDER as u8;
        while remaining > 0 {
            let block_pages = 1u64 << order;
            if block_pages <= remaining && pfn % block_pages == 0 {
                let block = BuddyBlock {
                    pfn,
                    order: AllocOrder(order),
                };
                let _ = self.free_areas[order as usize].push(block);
                self.free_pages += block_pages;
                pfn += block_pages;
                remaining -= block_pages;
                // Try the largest order again from the new position.
                order = MAX_ORDER as u8;
            } else if order > 0 {
                order -= 1;
            } else {
                break;
            }
        }
    }

    // --- Watermark helpers ---

    /// Return `true` if the zone currently has free pages above `level`.
    pub fn above_watermark(&self, level: WatermarkLevel) -> bool {
        self.watermarks.above(level, self.free_pages)
    }

    /// Return `true` if allocating `pages` would leave the zone above `level`.
    pub fn would_be_above(&self, pages: u64, level: WatermarkLevel) -> bool {
        self.watermarks
            .above(level, self.free_pages.saturating_sub(pages))
    }

    // --- Core allocation ---

    /// Attempt to allocate a block of `order` from this zone.
    ///
    /// Respects the watermark specified by `gfp`: atomic allocations use
    /// `WatermarkLevel::Min`; all others use `WatermarkLevel::Low`.
    /// Returns `Err(OutOfMemory)` if no suitable block exists or the
    /// watermark check fails.
    pub fn allocate(&mut self, order: AllocOrder, gfp: GfpFlags) -> Result<BuddyBlock> {
        // Watermark check.
        let wm = if gfp.is_atomic() {
            WatermarkLevel::Min
        } else {
            WatermarkLevel::Low
        };
        if !self.would_be_above(order.pages(), wm) {
            self.alloc_fail += 1;
            return Err(Error::OutOfMemory);
        }

        // Find the lowest available order >= requested.
        let found_order = (order.index()..ORDER_LEVELS)
            .find(|&o| self.free_areas[o].len() > 0)
            .ok_or(Error::OutOfMemory)?;

        let mut block = self.free_areas[found_order]
            .pop()
            .ok_or(Error::OutOfMemory)?;
        self.free_areas[found_order].alloc_count += 1;

        // Split down to the requested order.
        // Each iteration: halve the block, put the high buddy on the lower area.
        while block.order.index() > order.index() {
            let lower = AllocOrder(block.order.0 - 1);
            let high_pfn = block.pfn + lower.pages();
            let high_buddy = BuddyBlock {
                pfn: high_pfn,
                order: lower,
            };
            block = BuddyBlock {
                pfn: block.pfn,
                order: lower,
            };
            self.free_areas[lower.index()].push(high_buddy)?;
            self.free_areas[lower.index()].split_count += 1;
            self.free_pages += lower.pages(); // high half goes back as free
        }

        self.free_pages = self.free_pages.saturating_sub(order.pages());
        self.alloc_success += 1;
        Ok(block)
    }

    // --- Core free ---

    /// Return a block to the zone, merging with its buddy if possible.
    ///
    /// Returns `Err(InvalidArgument)` if the block's PFN is outside zone bounds.
    pub fn free(&mut self, block: BuddyBlock) -> Result<()> {
        // Validate the block belongs to this zone.
        if block.pfn < self.base_pfn || block.pfn >= self.base_pfn + self.total_pages {
            return Err(Error::InvalidArgument);
        }

        let mut current = block;

        loop {
            let buddy_pfn = current.buddy_pfn();
            // Stop if buddy is outside zone or already at maximum order.
            if buddy_pfn < self.base_pfn
                || buddy_pfn >= self.base_pfn + self.total_pages
                || current.order >= AllocOrder::MAX
            {
                break;
            }
            // Attempt to find and merge with the buddy.
            if let Some(merged_buddy) =
                self.free_areas[current.order.index()].remove_by_pfn(buddy_pfn)
            {
                // Buddy was free — merge.
                let _ = merged_buddy; // consumed
                self.free_areas[current.order.index()].merge_count += 1;
                self.free_pages = self.free_pages.saturating_sub(current.order.pages()); // buddy removed
                let next_order = match current.order.next() {
                    Some(o) => o,
                    None => break,
                };
                current = BuddyBlock {
                    pfn: current.pfn.min(buddy_pfn),
                    order: next_order,
                };
            } else {
                break;
            }
        }

        self.free_areas[current.order.index()].push(current)?;
        self.free_areas[current.order.index()].free_count += 1;
        self.free_pages += current.order.pages();
        Ok(())
    }

    // --- Introspection ---

    /// Number of free pages in this zone.
    pub fn free_pages(&self) -> u64 {
        self.free_pages
    }

    /// Total pages managed by this zone.
    pub fn total_pages(&self) -> u64 {
        self.total_pages
    }

    /// Fragmentation snapshot: free block count at each order.
    pub fn frag_info(&self) -> ZoneFragInfo {
        let mut blocks = [0usize; ORDER_LEVELS];
        let mut pages = [0u64; ORDER_LEVELS];
        for o in 0..ORDER_LEVELS {
            blocks[o] = self.free_areas[o].len();
            pages[o] = self.free_areas[o].free_pages(AllocOrder(o as u8));
        }
        ZoneFragInfo {
            zone_type: self.zone_type,
            base_pfn: self.base_pfn,
            total_pages: self.total_pages,
            free_pages: self.free_pages,
            free_blocks_per_order: blocks,
            free_pages_per_order: pages,
            watermarks: self.watermarks,
        }
    }

    /// Cumulative split/merge counts for debugging.
    pub fn split_merge_counts(&self) -> (u64, u64) {
        let splits: u64 = self.free_areas.iter().map(|a| a.split_count).sum();
        let merges: u64 = self.free_areas.iter().map(|a| a.merge_count).sum();
        (splits, merges)
    }

    /// Zone-level allocation success/fail counters.
    pub fn zone_alloc_counts(&self) -> (u64, u64) {
        (self.alloc_success, self.alloc_fail)
    }
}

// -------------------------------------------------------------------
// ZoneFragInfo
// -------------------------------------------------------------------

/// Fragmentation snapshot for a single zone.
///
/// Produced by [`BuddyZone::frag_info`] and aggregated by
/// [`BuddyAllocator::frag_info`].
#[derive(Debug, Clone, Copy)]
pub struct ZoneFragInfo {
    /// Zone classification.
    pub zone_type: ZoneType,
    /// First PFN of this zone.
    pub base_pfn: u64,
    /// Total pages in this zone.
    pub total_pages: u64,
    /// Currently free pages.
    pub free_pages: u64,
    /// Free block count per order.
    pub free_blocks_per_order: [usize; ORDER_LEVELS],
    /// Free page count per order.
    pub free_pages_per_order: [u64; ORDER_LEVELS],
    /// Current watermarks.
    pub watermarks: ZoneWatermarks,
}

impl ZoneFragInfo {
    /// Fragmentation score: ratio of free pages in order-0 blocks to all free
    /// pages (0 = perfectly contiguous, 100 = maximally fragmented).
    pub fn fragmentation_score(&self) -> u64 {
        if self.free_pages == 0 {
            return 0;
        }
        self.free_pages_per_order[0] * 100 / self.free_pages
    }

    /// Return `true` if the zone is above its high-water mark.
    pub fn above_high_watermark(&self) -> bool {
        self.watermarks.above(WatermarkLevel::High, self.free_pages)
    }
}

// -------------------------------------------------------------------
// BuddyStats
// -------------------------------------------------------------------

/// Aggregate statistics for the buddy allocator.
#[derive(Debug, Default, Clone, Copy)]
pub struct BuddyStats {
    /// Total physical pages managed across all zones.
    pub total_pages: u64,
    /// Currently free pages across all zones.
    pub free_pages: u64,
    /// Successful allocations since boot.
    pub alloc_success: u64,
    /// Failed allocations since boot.
    pub alloc_failed: u64,
    /// Successful frees since boot.
    pub free_success: u64,
    /// Failed frees (bad PFN / double-free) since boot.
    pub free_failed: u64,
    /// Total block splits performed.
    pub total_splits: u64,
    /// Total buddy merges performed.
    pub total_merges: u64,
    /// Allocations rejected by watermark check.
    pub watermark_failures: u64,
    /// Allocations satisfied from the DMA zone.
    pub dma_allocs: u64,
    /// Allocations satisfied from the Normal zone.
    pub normal_allocs: u64,
    /// Allocations satisfied from the HighMem zone.
    pub highmem_allocs: u64,
}

impl BuddyStats {
    /// Percentage of memory currently free (0–100).
    pub fn free_percent(&self) -> u64 {
        if self.total_pages == 0 {
            0
        } else {
            self.free_pages * 100 / self.total_pages
        }
    }

    /// Allocation success rate as a percentage (0–100).
    pub fn success_rate(&self) -> u64 {
        let total = self.alloc_success + self.alloc_failed;
        if total == 0 {
            100
        } else {
            self.alloc_success * 100 / total
        }
    }
}

// -------------------------------------------------------------------
// AllocResult
// -------------------------------------------------------------------

/// Result of a successful page allocation.
///
/// Carries the allocated block and the zone it came from.
#[derive(Debug, Clone, Copy)]
pub struct AllocResult {
    /// The allocated physical block.
    pub block: BuddyBlock,
    /// The zone the block was taken from.
    pub zone_type: ZoneType,
    /// Whether the pages were zeroed (as requested by `GFP_ZERO`).
    pub zeroed: bool,
}

// -------------------------------------------------------------------
// BuddyAllocator
// -------------------------------------------------------------------

/// Top-level buddy page allocator managing up to [`MAX_ZONES`] memory zones.
///
/// Zones are searched in declaration order; `GfpFlags` narrow the eligible
/// zone list and control watermark behaviour.
///
/// # Zone search order
///
/// GFP flags determine which zones are eligible:
/// - `GFP_DMA` / `GFP_DMA32` → DMA only.
/// - `GFP_HIGHMEM` → HighMem first, then Normal, then DMA.
/// - `GFP_KERNEL` (default) → Normal first, then DMA.
///
/// Within the eligible set, zones are tried in registration order.
///
/// # Example
///
/// ```rust,ignore
/// let mut alloc = BuddyAllocator::new();
/// alloc.add_zone(ZoneType::Normal, base_pfn, total_pages)?;
/// let result = alloc.alloc_pages(AllocOrder::ZERO, GfpFlags::GFP_KERNEL)?;
/// alloc.free_pages(result.block)?;
/// ```
pub struct BuddyAllocator {
    zones: [BuddyZone; MAX_ZONES],
    zone_count: usize,
    stats: BuddyStats,
}

impl BuddyAllocator {
    /// Create a new allocator with no zones configured.
    pub const fn new() -> Self {
        Self {
            zones: [
                BuddyZone::inactive(),
                BuddyZone::inactive(),
                BuddyZone::inactive(),
            ],
            zone_count: 0,
            stats: BuddyStats {
                total_pages: 0,
                free_pages: 0,
                alloc_success: 0,
                alloc_failed: 0,
                free_success: 0,
                free_failed: 0,
                total_splits: 0,
                total_merges: 0,
                watermark_failures: 0,
                dma_allocs: 0,
                normal_allocs: 0,
                highmem_allocs: 0,
            },
        }
    }

    // --- Zone management ---

    /// Register a new physical memory zone.
    ///
    /// `base_pfn` is the first page frame number; `total_pages` is the
    /// number of 4 KiB pages in the zone.  Watermarks are computed
    /// automatically.  Returns an error when the maximum zone count is reached.
    pub fn add_zone(&mut self, zone_type: ZoneType, base_pfn: u64, total_pages: u64) -> Result<()> {
        if self.zone_count >= MAX_ZONES {
            return Err(Error::Busy);
        }
        let idx = self.zone_count;
        self.zones[idx].init(zone_type, base_pfn, total_pages);
        self.stats.total_pages += total_pages;
        self.stats.free_pages += self.zones[idx].free_pages();
        self.zone_count += 1;
        Ok(())
    }

    /// Register a zone and override the default watermarks.
    ///
    /// Useful for low-memory systems where the default proportional
    /// watermarks would be too aggressive.
    pub fn add_zone_with_watermarks(
        &mut self,
        zone_type: ZoneType,
        base_pfn: u64,
        total_pages: u64,
        watermarks: ZoneWatermarks,
    ) -> Result<()> {
        self.add_zone(zone_type, base_pfn, total_pages)?;
        // Override the watermarks set by init().
        let idx = self.zone_count - 1;
        self.zones[idx].watermarks = watermarks;
        Ok(())
    }

    // --- Allocation ---

    /// Allocate a contiguous block of `2^order` pages with the given GFP flags.
    ///
    /// Searches eligible zones (determined by `gfp`) from most-preferred to
    /// least-preferred.  Returns an [`AllocResult`] carrying the block and
    /// the zone it came from.
    pub fn alloc_pages(&mut self, order: AllocOrder, gfp: GfpFlags) -> Result<AllocResult> {
        let zone_order = self.zone_search_order(gfp);

        for &zi in &zone_order {
            if zi >= self.zone_count || !self.zones[zi].active {
                continue;
            }
            if !self.zone_eligible(zi, gfp) {
                continue;
            }
            let (splits_before, merges_before) = self.zones[zi].split_merge_counts();
            match self.zones[zi].allocate(order, gfp) {
                Ok(block) => {
                    let (splits_after, merges_after) = self.zones[zi].split_merge_counts();
                    self.stats.total_splits += splits_after - splits_before;
                    self.stats.total_merges += merges_after - merges_before;
                    self.stats.free_pages = self.stats.free_pages.saturating_sub(order.pages());
                    self.stats.alloc_success += 1;
                    self.record_zone_alloc(zi);
                    return Ok(AllocResult {
                        block,
                        zone_type: self.zones[zi].zone_type,
                        zeroed: gfp.contains(GfpFlags::GFP_ZERO),
                    });
                }
                Err(Error::OutOfMemory) => {
                    self.stats.watermark_failures += 1;
                    continue;
                }
                Err(e) => return Err(e),
            }
        }

        self.stats.alloc_failed += 1;
        Err(Error::OutOfMemory)
    }

    /// Allocate a single 4 KiB page with `GFP_KERNEL` flags.
    pub fn alloc_page(&mut self) -> Result<AllocResult> {
        self.alloc_pages(AllocOrder::ZERO, GfpFlags::GFP_KERNEL)
    }

    /// Allocate a single 4 KiB page with `GFP_ATOMIC` (interrupt-safe).
    pub fn alloc_page_atomic(&mut self) -> Result<AllocResult> {
        self.alloc_pages(AllocOrder::ZERO, GfpFlags::GFP_ATOMIC)
    }

    /// Allocate a single 4 KiB page from the DMA zone.
    pub fn alloc_page_dma(&mut self) -> Result<AllocResult> {
        self.alloc_pages(AllocOrder::ZERO, GfpFlags::GFP_DMA)
    }

    // --- Free ---

    /// Return a block to the allocator.
    ///
    /// Locates the owning zone by PFN, then frees the block and performs
    /// buddy merging.  Returns `Err(InvalidArgument)` if the PFN does not
    /// belong to any registered zone.
    pub fn free_pages(&mut self, block: BuddyBlock) -> Result<()> {
        for i in 0..self.zone_count {
            if !self.zones[i].active {
                continue;
            }
            let base = self.zones[i].base_pfn;
            let top = base + self.zones[i].total_pages;
            if block.pfn >= base && block.pfn < top {
                let (splits_before, merges_before) = self.zones[i].split_merge_counts();
                self.zones[i].free(block)?;
                let (splits_after, merges_after) = self.zones[i].split_merge_counts();
                self.stats.total_splits += splits_after - splits_before;
                self.stats.total_merges += merges_after - merges_before;
                self.stats.free_pages += block.order.pages();
                self.stats.free_success += 1;
                return Ok(());
            }
        }
        self.stats.free_failed += 1;
        Err(Error::InvalidArgument)
    }

    // --- Statistics & introspection ---

    /// Return a snapshot of aggregate allocator statistics.
    ///
    /// `free_pages` is recomputed from live zone state for accuracy.
    pub fn stats(&self) -> BuddyStats {
        let mut s = self.stats;
        s.free_pages = self.total_free_pages();
        s
    }

    /// Total free pages across all active zones.
    pub fn free_pages_count(&self) -> u64 {
        self.total_free_pages()
    }

    /// Total pages across all registered zones.
    pub fn total_pages(&self) -> u64 {
        self.stats.total_pages
    }

    /// Return the fragmentation snapshot for zone `zone_idx`.
    ///
    /// Returns `None` if the index is out of range or the zone is inactive.
    pub fn zone_frag_info(&self, zone_idx: usize) -> Option<ZoneFragInfo> {
        if zone_idx >= self.zone_count || !self.zones[zone_idx].active {
            return None;
        }
        Some(self.zones[zone_idx].frag_info())
    }

    /// Fragmentation snapshots for all active zones.
    ///
    /// Returns a fixed-size array; active zones fill the first `zone_count`
    /// entries; the rest are `None`.
    pub fn frag_info(&self) -> [Option<ZoneFragInfo>; MAX_ZONES] {
        let mut out = [None; MAX_ZONES];
        for i in 0..self.zone_count {
            if self.zones[i].active {
                out[i] = Some(self.zones[i].frag_info());
            }
        }
        out
    }

    /// Return the current watermarks for zone `zone_idx`.
    pub fn zone_watermarks(&self, zone_idx: usize) -> Option<ZoneWatermarks> {
        if zone_idx >= self.zone_count || !self.zones[zone_idx].active {
            return None;
        }
        Some(self.zones[zone_idx].watermarks)
    }

    /// Update watermarks for zone `zone_idx`.
    pub fn set_zone_watermarks(
        &mut self,
        zone_idx: usize,
        watermarks: ZoneWatermarks,
    ) -> Result<()> {
        if zone_idx >= self.zone_count || !self.zones[zone_idx].active {
            return Err(Error::NotFound);
        }
        self.zones[zone_idx].watermarks = watermarks;
        Ok(())
    }

    /// Return `true` if zone `zone_idx` is above the given watermark level.
    pub fn zone_above_watermark(&self, zone_idx: usize, level: WatermarkLevel) -> bool {
        if zone_idx >= self.zone_count || !self.zones[zone_idx].active {
            return false;
        }
        self.zones[zone_idx].above_watermark(level)
    }

    /// Number of active zones.
    pub fn zone_count(&self) -> usize {
        self.zone_count
    }

    // --- Internal helpers ---

    /// Total free pages across all active zones (live recount).
    fn total_free_pages(&self) -> u64 {
        let mut total = 0u64;
        for i in 0..self.zone_count {
            if self.zones[i].active {
                total += self.zones[i].free_pages();
            }
        }
        total
    }

    /// Determine the zone search order based on GFP flags.
    ///
    /// Returns an array of zone indices in preference order.
    /// Unused entries are filled with `MAX_ZONES` (sentinel).
    fn zone_search_order(&self, gfp: GfpFlags) -> [usize; MAX_ZONES] {
        // Build preference list: preferred zone type first, then fallbacks.
        let preference = if gfp.requires_dma() {
            [ZoneType::Dma, ZoneType::Dma, ZoneType::Dma]
        } else if gfp.prefers_highmem() {
            [ZoneType::HighMem, ZoneType::Normal, ZoneType::Dma]
        } else {
            [ZoneType::Normal, ZoneType::Dma, ZoneType::HighMem]
        };

        let mut order = [MAX_ZONES; MAX_ZONES];
        let mut out_idx = 0;
        for pref_type in preference {
            for zi in 0..self.zone_count {
                if self.zones[zi].active && self.zones[zi].zone_type == pref_type {
                    // Avoid duplicates.
                    let already = order[..out_idx].iter().any(|&x| x == zi);
                    if !already && out_idx < MAX_ZONES {
                        order[out_idx] = zi;
                        out_idx += 1;
                    }
                }
            }
        }
        order
    }

    /// Return `true` if zone `zi` is eligible given `gfp`.
    fn zone_eligible(&self, zi: usize, gfp: GfpFlags) -> bool {
        let zt = self.zones[zi].zone_type;
        if gfp.requires_dma() {
            // DMA allocations must use the DMA zone.
            return zt == ZoneType::Dma;
        }
        // GFP_KERNEL forbids HighMem (kernel space can't directly access it).
        if gfp.contains(GfpFlags::GFP_KERNEL) && !gfp.prefers_highmem() {
            return zt != ZoneType::HighMem;
        }
        true
    }

    /// Update per-zone-type allocation counters.
    fn record_zone_alloc(&mut self, zi: usize) {
        match self.zones[zi].zone_type {
            ZoneType::Dma => self.stats.dma_allocs += 1,
            ZoneType::Normal => self.stats.normal_allocs += 1,
            ZoneType::HighMem => self.stats.highmem_allocs += 1,
        }
    }
}

impl Default for BuddyAllocator {
    fn default() -> Self {
        Self::new()
    }
}
