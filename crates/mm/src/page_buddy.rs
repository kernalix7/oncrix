// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Buddy system page allocator.
//!
//! Implements the classic buddy allocation algorithm for managing
//! physical page frames. Pages are grouped into blocks of power-of-two
//! sizes (order 0 = 1 page, order 1 = 2 pages, ..., order MAX = 2^MAX
//! pages). When a block of order N is freed and its buddy is also free,
//! the two are coalesced into an order N+1 block.
//!
//! # Design
//!
//! ```text
//! Order 0:  [1] [1] [1] [1] [1] [1] [1] [1]  ← single pages
//! Order 1:  [  2  ] [  2  ] [  2  ] [  2  ]  ← 2-page blocks
//! Order 2:  [    4    ]     [    4    ]       ← 4-page blocks
//! Order 3:  [        8        ]               ← 8-page blocks
//! ```
//!
//! # Key Types
//!
//! - [`BuddyOrder`] — allocation order (0..MAX_ORDER)
//! - [`BuddyBlock`] — metadata for a free block at a given order
//! - [`BuddyAllocator`] — the allocator managing free lists per order
//! - [`BuddyStats`] — allocation statistics
//!
//! Reference: Linux `mm/page_alloc.c`, buddy allocator.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Maximum allocation order.
const MAX_ORDER: usize = 11;

/// Page size.
const PAGE_SIZE: usize = 4096;

/// Maximum blocks per free list (per order).
const MAX_BLOCKS_PER_ORDER: usize = 512;

// -------------------------------------------------------------------
// BuddyOrder
// -------------------------------------------------------------------

/// An allocation order (0..MAX_ORDER).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct BuddyOrder(u32);

impl BuddyOrder {
    /// Order 0 (single page).
    pub const ZERO: Self = Self(0);

    /// Creates a new order value.
    pub const fn new(order: u32) -> Self {
        Self(order)
    }

    /// Returns the order value.
    pub const fn value(self) -> u32 {
        self.0
    }

    /// Returns the number of pages for this order.
    pub const fn nr_pages(self) -> usize {
        1 << self.0
    }

    /// Returns the block size in bytes.
    pub const fn block_size(self) -> usize {
        self.nr_pages() * PAGE_SIZE
    }

    /// Returns `true` if this is a valid order.
    pub const fn is_valid(self) -> bool {
        (self.0 as usize) < MAX_ORDER
    }
}

impl Default for BuddyOrder {
    fn default() -> Self {
        Self::ZERO
    }
}

// -------------------------------------------------------------------
// BuddyBlock
// -------------------------------------------------------------------

/// A free block descriptor.
#[derive(Debug, Clone, Copy)]
pub struct BuddyBlock {
    /// Physical frame number of the first page in the block.
    pfn: u64,
    /// Order of the block.
    order: BuddyOrder,
    /// Whether this slot is in use.
    in_use: bool,
}

impl BuddyBlock {
    /// Creates an empty block descriptor.
    pub const fn new() -> Self {
        Self {
            pfn: 0,
            order: BuddyOrder::ZERO,
            in_use: false,
        }
    }

    /// Returns the PFN.
    pub const fn pfn(&self) -> u64 {
        self.pfn
    }

    /// Returns the order.
    pub const fn order(&self) -> BuddyOrder {
        self.order
    }

    /// Returns the buddy PFN for this block.
    pub const fn buddy_pfn(&self) -> u64 {
        self.pfn ^ (1u64 << self.order.value())
    }
}

impl Default for BuddyBlock {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// BuddyStats
// -------------------------------------------------------------------

/// Buddy allocator statistics.
#[derive(Debug, Clone, Copy)]
pub struct BuddyStats {
    /// Free blocks per order.
    pub free_count: [usize; MAX_ORDER],
    /// Total allocations.
    pub total_allocs: u64,
    /// Total frees.
    pub total_frees: u64,
    /// Total coalesces (buddy merges).
    pub total_coalesces: u64,
    /// Total splits.
    pub total_splits: u64,
}

impl BuddyStats {
    /// Creates empty statistics.
    pub const fn new() -> Self {
        Self {
            free_count: [0; MAX_ORDER],
            total_allocs: 0,
            total_frees: 0,
            total_coalesces: 0,
            total_splits: 0,
        }
    }

    /// Returns total free pages across all orders.
    pub const fn total_free_pages(&self) -> usize {
        let mut total = 0;
        let mut i = 0;
        while i < MAX_ORDER {
            total += self.free_count[i] * (1 << i);
            i += 1;
        }
        total
    }
}

impl Default for BuddyStats {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// FreeList
// -------------------------------------------------------------------

/// A free list for a single order.
#[derive(Debug)]
struct FreeList {
    blocks: [BuddyBlock; MAX_BLOCKS_PER_ORDER],
    count: usize,
}

impl FreeList {
    const fn new() -> Self {
        Self {
            blocks: [const { BuddyBlock::new() }; MAX_BLOCKS_PER_ORDER],
            count: 0,
        }
    }

    fn push(&mut self, pfn: u64, order: BuddyOrder) -> Result<()> {
        if self.count >= MAX_BLOCKS_PER_ORDER {
            return Err(Error::OutOfMemory);
        }
        self.blocks[self.count] = BuddyBlock {
            pfn,
            order,
            in_use: true,
        };
        self.count += 1;
        Ok(())
    }

    fn pop(&mut self) -> Option<u64> {
        if self.count == 0 {
            return None;
        }
        self.count -= 1;
        self.blocks[self.count].in_use = false;
        Some(self.blocks[self.count].pfn)
    }

    fn remove_buddy(&mut self, buddy_pfn: u64) -> bool {
        for i in 0..self.count {
            if self.blocks[i].pfn == buddy_pfn {
                // Swap with last.
                self.count -= 1;
                if i < self.count {
                    self.blocks[i] = self.blocks[self.count];
                }
                self.blocks[self.count].in_use = false;
                return true;
            }
        }
        false
    }
}

// -------------------------------------------------------------------
// BuddyAllocator
// -------------------------------------------------------------------

/// The buddy system page allocator.
pub struct BuddyAllocator {
    /// Free lists indexed by order.
    free_lists: [FreeList; MAX_ORDER],
    /// Statistics.
    stats: BuddyStats,
}

impl BuddyAllocator {
    /// Creates an empty buddy allocator.
    pub const fn new() -> Self {
        Self {
            free_lists: [const { FreeList::new() }; MAX_ORDER],
            stats: BuddyStats::new(),
        }
    }

    /// Returns current statistics.
    pub fn stats(&self) -> BuddyStats {
        let mut s = self.stats;
        for i in 0..MAX_ORDER {
            s.free_count[i] = self.free_lists[i].count;
        }
        s
    }

    /// Adds a block of pages to the free lists.
    pub fn add_free_block(&mut self, pfn: u64, order: BuddyOrder) -> Result<()> {
        if !order.is_valid() {
            return Err(Error::InvalidArgument);
        }
        self.free_lists[order.value() as usize].push(pfn, order)
    }

    /// Allocates a block of 2^order pages.
    pub fn alloc(&mut self, order: BuddyOrder) -> Result<u64> {
        if !order.is_valid() {
            return Err(Error::InvalidArgument);
        }
        let target = order.value() as usize;

        // Find the smallest order with a free block.
        let mut found_order = MAX_ORDER;
        for o in target..MAX_ORDER {
            if self.free_lists[o].count > 0 {
                found_order = o;
                break;
            }
        }

        if found_order >= MAX_ORDER {
            return Err(Error::OutOfMemory);
        }

        // Pop from found order.
        let pfn = self.free_lists[found_order]
            .pop()
            .ok_or(Error::OutOfMemory)?;

        // Split down to the target order.
        let mut current_order = found_order;
        while current_order > target {
            current_order -= 1;
            let buddy_pfn = pfn + (1u64 << current_order);
            let _ = self.free_lists[current_order]
                .push(buddy_pfn, BuddyOrder::new(current_order as u32));
            self.stats.total_splits = self.stats.total_splits.saturating_add(1);
        }

        self.stats.total_allocs = self.stats.total_allocs.saturating_add(1);
        Ok(pfn)
    }

    /// Frees a block, coalescing with its buddy if possible.
    pub fn free(&mut self, pfn: u64, order: BuddyOrder) -> Result<()> {
        if !order.is_valid() {
            return Err(Error::InvalidArgument);
        }

        let mut current_pfn = pfn;
        let mut current_order = order.value() as usize;

        // Try to coalesce with buddies up the order chain.
        while current_order + 1 < MAX_ORDER {
            let buddy = current_pfn ^ (1u64 << current_order);
            if self.free_lists[current_order].remove_buddy(buddy) {
                // Merge: take the lower PFN.
                if buddy < current_pfn {
                    current_pfn = buddy;
                }
                current_order += 1;
                self.stats.total_coalesces = self.stats.total_coalesces.saturating_add(1);
            } else {
                break;
            }
        }

        self.free_lists[current_order].push(current_pfn, BuddyOrder::new(current_order as u32))?;
        self.stats.total_frees = self.stats.total_frees.saturating_add(1);
        Ok(())
    }
}

impl Default for BuddyAllocator {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// Public helpers
// -------------------------------------------------------------------

/// Creates a new buddy allocator.
pub fn create_allocator() -> BuddyAllocator {
    BuddyAllocator::new()
}

/// Allocates pages of the given order.
pub fn buddy_alloc(alloc: &mut BuddyAllocator, order: u32) -> Result<u64> {
    alloc.alloc(BuddyOrder::new(order))
}

/// Frees pages back to the buddy allocator.
pub fn buddy_free(alloc: &mut BuddyAllocator, pfn: u64, order: u32) -> Result<()> {
    alloc.free(pfn, BuddyOrder::new(order))
}
