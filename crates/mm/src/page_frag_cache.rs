// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Page fragment caching.
//!
//! Network subsystems and other hot paths need small, variable-sized
//! allocations from pages. A page fragment cache carves a single page
//! into variable-sized fragments without per-fragment metadata
//! overhead. When the page is exhausted, a new page is allocated.
//!
//! # Design
//!
//! ```text
//!  page_frag_alloc(cache, size)
//!     │
//!     ├─ current page has room? → bump offset, return pointer
//!     └─ exhausted → alloc new page, reset offset
//!
//!  page_frag_free(frag)
//!     │
//!     └─ decrement page refcount → 0? free page
//! ```
//!
//! # Key Types
//!
//! - [`FragPage`] — a page used for fragment allocation
//! - [`PageFragCacheSlot`] — per-CPU fragment cache
//! - [`PageFragCacheManager`] — manages all caches
//! - [`PageFragCacheStats`] — cache statistics
//!
//! Reference: Linux `mm/page_frag_cache.c`, `include/linux/page_frag_cache.h`.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Maximum CPUs / cache slots.
const MAX_CACHE_SLOTS: usize = 256;

/// Page size.
const PAGE_SIZE: u32 = 4096;

/// Minimum fragment size.
const MIN_FRAG_SIZE: u32 = 16;

/// Maximum fragment size.
const MAX_FRAG_SIZE: u32 = PAGE_SIZE;

// -------------------------------------------------------------------
// FragPage
// -------------------------------------------------------------------

/// A page used for fragment allocation.
#[derive(Debug, Clone, Copy)]
pub struct FragPage {
    /// Physical frame number.
    pfn: u64,
    /// Current offset (next free byte).
    offset: u32,
    /// Reference count (number of outstanding fragments).
    refcount: u32,
    /// Whether this page is active.
    active: bool,
}

impl FragPage {
    /// Create a new fragment page.
    pub const fn new(pfn: u64) -> Self {
        Self {
            pfn,
            offset: 0,
            refcount: 0,
            active: true,
        }
    }

    /// Return the PFN.
    pub const fn pfn(&self) -> u64 {
        self.pfn
    }

    /// Return the current offset.
    pub const fn offset(&self) -> u32 {
        self.offset
    }

    /// Return the reference count.
    pub const fn refcount(&self) -> u32 {
        self.refcount
    }

    /// Available bytes.
    pub const fn available(&self) -> u32 {
        PAGE_SIZE - self.offset
    }

    /// Check whether a fragment of the given size fits.
    pub const fn can_fit(&self, size: u32) -> bool {
        self.active && self.available() >= size
    }

    /// Allocate a fragment. Returns the offset within the page.
    pub fn alloc_frag(&mut self, size: u32) -> Result<u32> {
        if !self.can_fit(size) {
            return Err(Error::OutOfMemory);
        }
        let frag_offset = self.offset;
        self.offset += size;
        self.refcount += 1;
        Ok(frag_offset)
    }

    /// Free a fragment (decrement refcount).
    pub fn free_frag(&mut self) -> bool {
        self.refcount = self.refcount.saturating_sub(1);
        self.refcount == 0 && self.offset > 0
    }

    /// Check whether the page is fully freed.
    pub const fn is_freeable(&self) -> bool {
        self.refcount == 0 && self.offset > 0
    }

    /// Reset for reuse.
    pub fn reset(&mut self, new_pfn: u64) {
        self.pfn = new_pfn;
        self.offset = 0;
        self.refcount = 0;
        self.active = true;
    }
}

impl Default for FragPage {
    fn default() -> Self {
        Self {
            pfn: 0,
            offset: 0,
            refcount: 0,
            active: false,
        }
    }
}

// -------------------------------------------------------------------
// PageFragCacheSlot
// -------------------------------------------------------------------

/// Per-CPU fragment cache slot.
#[derive(Debug, Clone, Copy)]
pub struct PageFragCacheSlot {
    /// CPU ID.
    cpu_id: u32,
    /// Current fragment page.
    current: FragPage,
    /// Total allocations.
    alloc_count: u64,
    /// Total frees.
    free_count: u64,
    /// Pages consumed.
    pages_consumed: u64,
}

impl PageFragCacheSlot {
    /// Create a new cache slot.
    pub const fn new(cpu_id: u32) -> Self {
        Self {
            cpu_id,
            current: FragPage {
                pfn: 0,
                offset: 0,
                refcount: 0,
                active: false,
            },
            alloc_count: 0,
            free_count: 0,
            pages_consumed: 0,
        }
    }

    /// Return the CPU ID.
    pub const fn cpu_id(&self) -> u32 {
        self.cpu_id
    }

    /// Return the current page.
    pub const fn current(&self) -> &FragPage {
        &self.current
    }

    /// Return the allocation count.
    pub const fn alloc_count(&self) -> u64 {
        self.alloc_count
    }

    /// Allocate a fragment.
    pub fn alloc(&mut self, size: u32, new_pfn: u64) -> Result<(u64, u32)> {
        if size < MIN_FRAG_SIZE || size > MAX_FRAG_SIZE {
            return Err(Error::InvalidArgument);
        }
        if !self.current.can_fit(size) {
            // Need a new page.
            self.current.reset(new_pfn);
            self.pages_consumed += 1;
        }
        let offset = self.current.alloc_frag(size)?;
        self.alloc_count += 1;
        Ok((self.current.pfn(), offset))
    }

    /// Free a fragment on the current page.
    pub fn free_frag(&mut self) {
        self.current.free_frag();
        self.free_count += 1;
    }
}

impl Default for PageFragCacheSlot {
    fn default() -> Self {
        Self::new(0)
    }
}

// -------------------------------------------------------------------
// PageFragCacheStats
// -------------------------------------------------------------------

/// Cache statistics.
#[derive(Debug, Clone, Copy)]
pub struct PageFragCacheStats {
    /// Total allocations.
    pub total_allocs: u64,
    /// Total frees.
    pub total_frees: u64,
    /// Total pages consumed.
    pub total_pages: u64,
}

impl PageFragCacheStats {
    /// Create zero stats.
    pub const fn new() -> Self {
        Self {
            total_allocs: 0,
            total_frees: 0,
            total_pages: 0,
        }
    }
}

impl Default for PageFragCacheStats {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// PageFragCacheManager
// -------------------------------------------------------------------

/// Manages all per-CPU fragment caches.
pub struct PageFragCacheManager {
    /// Per-CPU slots.
    slots: [PageFragCacheSlot; MAX_CACHE_SLOTS],
    /// Number of active slots.
    slot_count: usize,
    /// Statistics.
    stats: PageFragCacheStats,
}

impl PageFragCacheManager {
    /// Create a new manager.
    pub const fn new() -> Self {
        Self {
            slots: [const {
                PageFragCacheSlot {
                    cpu_id: 0,
                    current: FragPage {
                        pfn: 0,
                        offset: 0,
                        refcount: 0,
                        active: false,
                    },
                    alloc_count: 0,
                    free_count: 0,
                    pages_consumed: 0,
                }
            }; MAX_CACHE_SLOTS],
            slot_count: 0,
            stats: PageFragCacheStats::new(),
        }
    }

    /// Return the statistics.
    pub const fn stats(&self) -> &PageFragCacheStats {
        &self.stats
    }

    /// Return the slot count.
    pub const fn slot_count(&self) -> usize {
        self.slot_count
    }

    /// Initialize CPUs.
    pub fn init_cpus(&mut self, count: usize) -> Result<()> {
        if count > MAX_CACHE_SLOTS {
            return Err(Error::InvalidArgument);
        }
        for idx in 0..count {
            self.slots[idx] = PageFragCacheSlot::new(idx as u32);
        }
        self.slot_count = count;
        Ok(())
    }

    /// Allocate a fragment on a CPU.
    pub fn alloc(&mut self, cpu: usize, size: u32, new_pfn: u64) -> Result<(u64, u32)> {
        if cpu >= self.slot_count {
            return Err(Error::InvalidArgument);
        }
        let result = self.slots[cpu].alloc(size, new_pfn)?;
        self.stats.total_allocs += 1;
        Ok(result)
    }

    /// Get a slot.
    pub fn get_slot(&self, cpu: usize) -> Option<&PageFragCacheSlot> {
        if cpu < self.slot_count {
            Some(&self.slots[cpu])
        } else {
            None
        }
    }
}

impl Default for PageFragCacheManager {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// Public helpers
// -------------------------------------------------------------------

/// Return the minimum fragment size.
pub const fn min_frag_size() -> u32 {
    MIN_FRAG_SIZE
}

/// Return the maximum fragment size.
pub const fn max_frag_size() -> u32 {
    MAX_FRAG_SIZE
}

/// Return the maximum cache slots.
pub const fn max_cache_slots() -> usize {
    MAX_CACHE_SLOTS
}
