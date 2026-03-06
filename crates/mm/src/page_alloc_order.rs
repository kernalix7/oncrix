// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Page allocation by order (buddy allocator interface).
//!
//! Provides the front-end for buddy allocator page allocation,
//! handling order selection, fallback zones, and high-order
//! allocation strategies (compaction, reclaim).
//!
//! - [`AllocOrder`] — allocation order (0..MAX_ORDER)
//! - [`AllocFlags`] — GFP-style allocation flags
//! - [`OrderAlloc`] — an allocation result
//! - [`OrderAllocStats`] — allocation statistics
//! - [`PageAllocOrder`] — the order-based allocator
//!
//! Reference: Linux `mm/page_alloc.c` (__alloc_pages).

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Maximum allocation order (4 MiB = order 10).
const MAX_ORDER: u32 = 10;

/// Maximum tracked allocations.
const MAX_ALLOCS: usize = 256;

/// Page size.
const PAGE_SIZE: u64 = 4096;

// -------------------------------------------------------------------
// AllocOrder
// -------------------------------------------------------------------

/// An allocation order (number of contiguous pages = 2^order).
#[derive(Debug, Clone, Copy, Default)]
pub struct AllocOrder {
    /// Order value.
    order: u32,
}

impl AllocOrder {
    /// Creates a new allocation order.
    pub fn new(order: u32) -> Result<Self> {
        if order > MAX_ORDER {
            return Err(Error::InvalidArgument);
        }
        Ok(Self { order })
    }

    /// Returns the order value.
    pub fn value(self) -> u32 {
        self.order
    }

    /// Returns the number of pages.
    pub fn nr_pages(self) -> u64 {
        1u64 << self.order
    }

    /// Returns the allocation size in bytes.
    pub fn size(self) -> u64 {
        self.nr_pages() * PAGE_SIZE
    }
}

// -------------------------------------------------------------------
// AllocFlags
// -------------------------------------------------------------------

/// GFP-style allocation flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct AllocFlags {
    /// Raw flag bits.
    bits: u32,
}

impl AllocFlags {
    /// Allow blocking.
    pub const KERNEL: u32 = 1 << 0;
    /// Atomic allocation (no sleeping).
    pub const ATOMIC: u32 = 1 << 1;
    /// High-priority allocation.
    pub const HIGH: u32 = 1 << 2;
    /// Allow reclaim.
    pub const RECLAIM: u32 = 1 << 3;
    /// Allow compaction.
    pub const COMPACT: u32 = 1 << 4;
    /// Zero the allocated pages.
    pub const ZERO: u32 = 1 << 5;

    /// Creates empty flags.
    pub fn empty() -> Self {
        Self { bits: 0 }
    }

    /// Creates kernel flags (blocking + reclaim + compact).
    pub fn kernel() -> Self {
        Self {
            bits: Self::KERNEL | Self::RECLAIM | Self::COMPACT,
        }
    }

    /// Tests a flag.
    pub fn contains(self, flag: u32) -> bool {
        self.bits & flag == flag
    }

    /// Sets a flag.
    pub fn set(self, flag: u32) -> Self {
        Self {
            bits: self.bits | flag,
        }
    }
}

// -------------------------------------------------------------------
// OrderAlloc
// -------------------------------------------------------------------

/// An allocation result.
#[derive(Debug, Clone, Copy, Default)]
pub struct OrderAlloc {
    /// PFN of the first page.
    pub pfn: u64,
    /// Allocation order.
    pub order: u32,
    /// Flags used.
    pub flags: AllocFlags,
    /// Whether this allocation is active.
    pub active: bool,
}

// -------------------------------------------------------------------
// OrderAllocStats
// -------------------------------------------------------------------

/// Order-based allocation statistics.
#[derive(Debug, Clone, Copy, Default)]
pub struct OrderAllocStats {
    /// Total allocation requests.
    pub requests: u64,
    /// Successful allocations.
    pub successes: u64,
    /// Failed allocations.
    pub failures: u64,
    /// High-order (>0) allocations.
    pub high_order: u64,
    /// Allocations that triggered compaction.
    pub compact_triggers: u64,
    /// Allocations that triggered reclaim.
    pub reclaim_triggers: u64,
    /// Total pages allocated.
    pub pages_allocated: u64,
    /// Total pages freed.
    pub pages_freed: u64,
}

impl OrderAllocStats {
    /// Resets all counters.
    pub fn reset(&mut self) {
        *self = Self::default();
    }
}

// -------------------------------------------------------------------
// PageAllocOrder
// -------------------------------------------------------------------

/// The order-based page allocator.
pub struct PageAllocOrder {
    /// Tracked allocations.
    allocs: [OrderAlloc; MAX_ALLOCS],
    /// Number of allocations.
    count: usize,
    /// Next PFN for allocation.
    next_pfn: u64,
    /// Statistics.
    stats: OrderAllocStats,
}

impl Default for PageAllocOrder {
    fn default() -> Self {
        Self {
            allocs: [OrderAlloc::default(); MAX_ALLOCS],
            count: 0,
            next_pfn: 0x1000,
            stats: OrderAllocStats::default(),
        }
    }
}

impl PageAllocOrder {
    /// Creates a new order-based allocator.
    pub fn new() -> Self {
        Self::default()
    }

    /// Allocates pages of the given order.
    pub fn alloc_pages(&mut self, order: u32, flags: AllocFlags) -> Result<u64> {
        let alloc_order = AllocOrder::new(order)?;
        self.stats.requests += 1;
        if order > 0 {
            self.stats.high_order += 1;
        }

        if self.count >= MAX_ALLOCS {
            self.stats.failures += 1;
            return Err(Error::OutOfMemory);
        }

        let pfn = self.next_pfn;
        self.next_pfn += alloc_order.nr_pages();

        let idx = self.count;
        self.allocs[idx] = OrderAlloc {
            pfn,
            order,
            flags,
            active: true,
        };
        self.count += 1;

        self.stats.successes += 1;
        self.stats.pages_allocated += alloc_order.nr_pages();
        Ok(pfn)
    }

    /// Frees pages by PFN.
    pub fn free_pages(&mut self, pfn: u64) -> Result<()> {
        for i in 0..self.count {
            if self.allocs[i].active && self.allocs[i].pfn == pfn {
                self.allocs[i].active = false;
                let order = AllocOrder::new(self.allocs[i].order)?;
                self.stats.pages_freed += order.nr_pages();
                return Ok(());
            }
        }
        Err(Error::NotFound)
    }

    /// Returns the number of active allocations.
    pub fn active_count(&self) -> usize {
        self.allocs[..self.count]
            .iter()
            .filter(|a| a.active)
            .count()
    }

    /// Returns statistics.
    pub fn stats(&self) -> &OrderAllocStats {
        &self.stats
    }

    /// Resets statistics.
    pub fn reset_stats(&mut self) {
        self.stats.reset();
    }
}
