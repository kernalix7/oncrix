// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Huge memory management (compound page operations).
//!
//! Provides core operations for managing huge (compound) pages that
//! span multiple base pages. Handles compound page metadata, head/tail
//! page relationships, and splitting/compounding operations.
//!
//! - [`CompoundOrder`] — supported compound page orders
//! - [`CompoundPage`] — a compound page descriptor
//! - [`HugePagePool`] — pre-allocated pool of huge pages
//! - [`HugeMemoryStats`] — aggregate statistics
//!
//! Reference: Linux `mm/huge_memory.c`.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Page size (4 KiB).
const PAGE_SIZE: u64 = 4096;

/// Maximum compound order (2 MiB = order 9).
const MAX_COMPOUND_ORDER: u32 = 9;

/// Maximum huge pages in the pool.
const MAX_POOL_PAGES: usize = 128;

// -------------------------------------------------------------------
// CompoundOrder
// -------------------------------------------------------------------

/// Supported compound page orders.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CompoundOrder {
    /// Standard 4 KiB page (order 0).
    #[default]
    Base,
    /// 8 KiB (order 1).
    Order1,
    /// 64 KiB (order 4).
    Order4,
    /// 2 MiB (order 9, huge page).
    Order9,
}

impl CompoundOrder {
    /// Returns the order value.
    pub fn order(self) -> u32 {
        match self {
            Self::Base => 0,
            Self::Order1 => 1,
            Self::Order4 => 4,
            Self::Order9 => 9,
        }
    }

    /// Returns the number of base pages in this compound order.
    pub fn nr_pages(self) -> u64 {
        1u64 << self.order()
    }

    /// Returns the total size in bytes.
    pub fn size(self) -> u64 {
        self.nr_pages() * PAGE_SIZE
    }

    /// Creates from a raw order value.
    pub fn from_order(order: u32) -> Result<Self> {
        match order {
            0 => Ok(Self::Base),
            1 => Ok(Self::Order1),
            4 => Ok(Self::Order4),
            9 => Ok(Self::Order9),
            _ => Err(Error::InvalidArgument),
        }
    }
}

// -------------------------------------------------------------------
// CompoundPageFlags
// -------------------------------------------------------------------

/// Flags for compound page state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CompoundPageFlags {
    /// Raw flag bits.
    bits: u32,
}

impl CompoundPageFlags {
    /// Page is the head of a compound page.
    pub const HEAD: u32 = 1 << 0;
    /// Page is a tail of a compound page.
    pub const TAIL: u32 = 1 << 1;
    /// Page is mapped (has PTEs pointing to it).
    pub const MAPPED: u32 = 1 << 2;
    /// Page is pinned (cannot be migrated/split).
    pub const PINNED: u32 = 1 << 3;
    /// Page has been split from a larger compound page.
    pub const SPLIT: u32 = 1 << 4;

    /// Creates empty flags.
    pub fn empty() -> Self {
        Self { bits: 0 }
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

    /// Clears a flag.
    pub fn clear(self, flag: u32) -> Self {
        Self {
            bits: self.bits & !flag,
        }
    }
}

// -------------------------------------------------------------------
// CompoundPage
// -------------------------------------------------------------------

/// A compound page descriptor.
#[derive(Debug, Clone, Copy, Default)]
pub struct CompoundPage {
    /// Page frame number of the head page.
    pub head_pfn: u64,
    /// Compound order.
    pub order: CompoundOrder,
    /// Reference count.
    pub refcount: u32,
    /// Map count (number of PTEs mapping this page).
    pub mapcount: i32,
    /// Flags.
    pub flags: CompoundPageFlags,
    /// Whether this slot is active.
    pub active: bool,
}

impl CompoundPage {
    /// Creates a new compound page.
    pub fn new(head_pfn: u64, order: CompoundOrder) -> Self {
        Self {
            head_pfn,
            order,
            refcount: 1,
            mapcount: 0,
            flags: CompoundPageFlags::empty().set(CompoundPageFlags::HEAD),
            active: true,
        }
    }

    /// Returns the number of base pages.
    pub fn nr_pages(&self) -> u64 {
        self.order.nr_pages()
    }

    /// Returns the total size in bytes.
    pub fn size(&self) -> u64 {
        self.order.size()
    }

    /// Increments the reference count.
    pub fn get_page(&mut self) {
        self.refcount = self.refcount.saturating_add(1);
    }

    /// Decrements the reference count. Returns `true` if it dropped
    /// to zero.
    pub fn put_page(&mut self) -> bool {
        self.refcount = self.refcount.saturating_sub(1);
        self.refcount == 0
    }

    /// Returns `true` if the page can be split.
    pub fn can_split(&self) -> bool {
        self.active && self.order.order() > 0 && !self.flags.contains(CompoundPageFlags::PINNED)
    }
}

// -------------------------------------------------------------------
// HugeMemoryStats
// -------------------------------------------------------------------

/// Aggregate huge memory statistics.
#[derive(Debug, Clone, Copy, Default)]
pub struct HugeMemoryStats {
    /// Total huge pages allocated.
    pub allocated: u64,
    /// Total huge pages freed.
    pub freed: u64,
    /// Total split operations.
    pub splits: u64,
    /// Failed split attempts.
    pub split_failures: u64,
    /// Total compound operations.
    pub compounds: u64,
    /// Current active huge pages.
    pub active_count: u64,
}

impl HugeMemoryStats {
    /// Resets all counters.
    pub fn reset(&mut self) {
        *self = Self::default();
    }
}

// -------------------------------------------------------------------
// HugePagePool
// -------------------------------------------------------------------

/// Pre-allocated pool of huge pages.
pub struct HugePagePool {
    /// Page storage.
    pages: [CompoundPage; MAX_POOL_PAGES],
    /// Number of pages in the pool.
    count: usize,
    /// Next PFN for allocation.
    next_pfn: u64,
    /// Statistics.
    stats: HugeMemoryStats,
}

impl Default for HugePagePool {
    fn default() -> Self {
        Self {
            pages: [CompoundPage::default(); MAX_POOL_PAGES],
            count: 0,
            next_pfn: 0x1_0000,
            stats: HugeMemoryStats::default(),
        }
    }
}

impl HugePagePool {
    /// Creates a new huge page pool.
    pub fn new() -> Self {
        Self::default()
    }

    /// Allocates a compound page of the given order.
    pub fn alloc(&mut self, order: CompoundOrder) -> Result<usize> {
        if order.order() > MAX_COMPOUND_ORDER {
            return Err(Error::InvalidArgument);
        }
        if self.count >= MAX_POOL_PAGES {
            return Err(Error::OutOfMemory);
        }
        let pfn = self.next_pfn;
        self.next_pfn += order.nr_pages();
        let idx = self.count;
        self.pages[idx] = CompoundPage::new(pfn, order);
        self.count += 1;
        self.stats.allocated += 1;
        self.stats.active_count += 1;
        Ok(idx)
    }

    /// Frees a compound page.
    pub fn free(&mut self, idx: usize) -> Result<()> {
        if idx >= self.count || !self.pages[idx].active {
            return Err(Error::NotFound);
        }
        self.pages[idx].active = false;
        self.stats.freed += 1;
        if self.stats.active_count > 0 {
            self.stats.active_count -= 1;
        }
        Ok(())
    }

    /// Splits a compound page into base pages (conceptually).
    pub fn split(&mut self, idx: usize) -> Result<()> {
        if idx >= self.count || !self.pages[idx].active {
            return Err(Error::NotFound);
        }
        if !self.pages[idx].can_split() {
            self.stats.split_failures += 1;
            return Err(Error::Busy);
        }
        self.pages[idx].flags = self.pages[idx].flags.set(CompoundPageFlags::SPLIT);
        self.pages[idx].order = CompoundOrder::Base;
        self.stats.splits += 1;
        Ok(())
    }

    /// Returns a reference to a page.
    pub fn get(&self, idx: usize) -> Option<&CompoundPage> {
        if idx < self.count && self.pages[idx].active {
            Some(&self.pages[idx])
        } else {
            None
        }
    }

    /// Returns the pool count.
    pub fn count(&self) -> usize {
        self.count
    }

    /// Returns statistics.
    pub fn stats(&self) -> &HugeMemoryStats {
        &self.stats
    }

    /// Resets statistics.
    pub fn reset_stats(&mut self) {
        self.stats.reset();
    }
}
