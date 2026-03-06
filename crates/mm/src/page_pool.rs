// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Pre-allocated page pool management.
//!
//! Provides a pool-based page allocator that manages a fixed set of
//! pre-allocated physical pages. Each [`PagePool`] tracks page state,
//! reference counts, and supports contiguous multi-page (buddy-order)
//! allocations up to 2^[`POOL_ORDER_MAX`] pages.
//!
//! The [`PagePoolRegistry`] holds up to [`MAX_POOLS`] named pools and
//! offers lookup, registration, and automatic pool selection when free
//! pages are needed.
//!
//! Reference: `.kernelORG/` — `mm/page_alloc.c`, `mm/mempool.c`.

use oncrix_lib::{Error, Result};

/// Size of a single page in bytes (4 KiB).
pub const PAGE_SIZE: usize = 4096;

/// Maximum number of pages a single pool can manage.
pub const MAX_POOL_PAGES: usize = 2048;

/// Maximum number of pools in the system registry.
pub const MAX_POOLS: usize = 8;

/// Maximum allocation order (2^4 = 16 contiguous pages).
pub const POOL_ORDER_MAX: u8 = 4;

// ── PageState ──────────────────────────────────────────────────────

/// State of a page within a pool.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PageState {
    /// Page is available for allocation.
    #[default]
    Free,
    /// Page has been allocated to a consumer.
    Allocated,
    /// Page is reserved and cannot be allocated or freed.
    Reserved,
    /// Page is managed by the buddy sub-allocator.
    Buddy,
}

// ── PoolPage ───────────────────────────────────────────────────────

/// Metadata for a single page managed by a [`PagePool`].
#[derive(Debug, Clone, Copy)]
pub struct PoolPage {
    /// Physical frame number.
    pub pfn: u64,
    /// Current state of the page.
    pub state: PageState,
    /// Buddy order (0 = single page).
    pub order: u8,
    /// Reference count.
    pub ref_count: u16,
    /// Per-page flags (pool-specific).
    pub flags: u16,
    /// Owning pool identifier.
    pub pool_id: u8,
}

impl Default for PoolPage {
    fn default() -> Self {
        Self {
            pfn: 0,
            state: PageState::Free,
            order: 0,
            ref_count: 0,
            flags: 0,
            pool_id: 0,
        }
    }
}

// ── PoolStats ──────────────────────────────────────────────────────

/// Snapshot of pool statistics.
#[derive(Debug, Clone, Copy, Default)]
pub struct PoolStats {
    /// Total pages managed by this pool.
    pub total: usize,
    /// Number of free pages.
    pub free_count: usize,
    /// Number of allocated pages.
    pub allocated: usize,
    /// High watermark threshold.
    pub high_wm: usize,
    /// Low watermark threshold.
    pub low_wm: usize,
    /// Cumulative successful allocations.
    pub alloc_count: u64,
    /// Cumulative successful frees.
    pub free_op_count: u64,
}

// ── PagePool ───────────────────────────────────────────────────────

/// A fixed-capacity pool of pre-allocated pages.
///
/// Pages are identified by their physical frame number (PFN) and
/// tracked via an inline array.  The pool supports single-page and
/// contiguous multi-page allocations up to 2^[`POOL_ORDER_MAX`]
/// pages, as well as reference-counted sharing.
pub struct PagePool {
    /// Pool identifier.
    id: u8,
    /// Human-readable name stored inline.
    name: [u8; 32],
    /// Valid length of `name`.
    name_len: usize,
    /// Per-page metadata.
    pages: [PoolPage; MAX_POOL_PAGES],
    /// Number of pages actually managed (≤ `MAX_POOL_PAGES`).
    total: usize,
    /// Current number of free pages.
    free_count: usize,
    /// High watermark — pool is considered "full enough" above this.
    high_watermark: usize,
    /// Low watermark — pool is considered "running low" below this.
    low_watermark: usize,
    /// Total successful allocations since creation.
    alloc_count: u64,
    /// Total successful free operations since creation.
    free_op_count: u64,
    /// Whether this pool is active and usable.
    active: bool,
}

impl PagePool {
    /// Create a new page pool.
    ///
    /// `id` is the pool identifier, `name` is a human-readable label
    /// (truncated to 32 bytes), and `total` is the number of pages
    /// the pool manages (capped at [`MAX_POOL_PAGES`]).
    ///
    /// Pages are initialised as [`PageState::Free`] with sequential
    /// PFNs starting from 0.
    pub fn new(id: u8, name: &[u8], total: usize) -> Self {
        let capped = if total > MAX_POOL_PAGES {
            MAX_POOL_PAGES
        } else {
            total
        };

        let mut pool_name = [0u8; 32];
        let copy_len = if name.len() > 32 { 32 } else { name.len() };
        let mut i = 0;
        while i < copy_len {
            pool_name[i] = name[i];
            i += 1;
        }

        let mut pages = [PoolPage::default(); MAX_POOL_PAGES];
        let mut idx = 0;
        while idx < capped {
            pages[idx].pfn = idx as u64;
            pages[idx].pool_id = id;
            idx += 1;
        }

        // Default watermarks: low = 12.5%, high = 87.5%.
        let low = capped / 8;
        let high = capped - (capped / 8);

        Self {
            id,
            name: pool_name,
            name_len: copy_len,
            pages,
            total: capped,
            free_count: capped,
            high_watermark: high,
            low_watermark: low,
            alloc_count: 0,
            free_op_count: 0,
            active: true,
        }
    }

    /// Allocate a single free page and return its PFN.
    ///
    /// Returns [`Error::OutOfMemory`] when no free pages remain.
    pub fn alloc_page(&mut self) -> Result<u64> {
        let mut i = 0;
        while i < self.total {
            if self.pages[i].state == PageState::Free {
                self.pages[i].state = PageState::Allocated;
                self.pages[i].ref_count = 1;
                self.pages[i].order = 0;
                self.free_count -= 1;
                self.alloc_count += 1;
                return Ok(self.pages[i].pfn);
            }
            i += 1;
        }
        Err(Error::OutOfMemory)
    }

    /// Allocate 2^`order` contiguous free pages.
    ///
    /// Returns the PFN of the first page in the block.
    /// Fails with [`Error::InvalidArgument`] if `order` exceeds
    /// [`POOL_ORDER_MAX`], or [`Error::OutOfMemory`] if a suitable
    /// contiguous run cannot be found.
    pub fn alloc_pages(&mut self, order: u8) -> Result<u64> {
        if order > POOL_ORDER_MAX {
            return Err(Error::InvalidArgument);
        }

        let count = 1usize << (order as usize);
        if count > self.free_count {
            return Err(Error::OutOfMemory);
        }

        // Scan for a contiguous run of `count` free pages.
        let mut start = 0usize;
        while start + count <= self.total {
            let mut ok = true;
            let mut j = 0;
            while j < count {
                if self.pages[start + j].state != PageState::Free {
                    ok = false;
                    break;
                }
                j += 1;
            }
            if ok {
                // Mark all pages in the run.
                let mut j = 0;
                while j < count {
                    let p = &mut self.pages[start + j];
                    p.state = PageState::Allocated;
                    p.ref_count = 1;
                    p.order = order;
                    j += 1;
                }
                self.free_count -= count;
                self.alloc_count += 1;
                return Ok(self.pages[start].pfn);
            }
            start += 1;
        }

        Err(Error::OutOfMemory)
    }

    /// Free a single previously-allocated page by PFN.
    ///
    /// Returns [`Error::NotFound`] if the PFN does not belong to
    /// this pool, or [`Error::InvalidArgument`] if the page is not
    /// in the [`PageState::Allocated`] state.
    pub fn free_page(&mut self, pfn: u64) -> Result<()> {
        let idx = self.index_of(pfn)?;
        if self.pages[idx].state != PageState::Allocated {
            return Err(Error::InvalidArgument);
        }
        self.pages[idx].state = PageState::Free;
        self.pages[idx].ref_count = 0;
        self.pages[idx].order = 0;
        self.free_count += 1;
        self.free_op_count += 1;
        Ok(())
    }

    /// Free a contiguous 2^`order` block starting at `pfn`.
    ///
    /// Every page in the range must be [`PageState::Allocated`]
    /// with a matching `order`.
    pub fn free_pages(&mut self, pfn: u64, order: u8) -> Result<()> {
        if order > POOL_ORDER_MAX {
            return Err(Error::InvalidArgument);
        }

        let start = self.index_of(pfn)?;
        let count = 1usize << (order as usize);

        if start + count > self.total {
            return Err(Error::InvalidArgument);
        }

        // Validate all pages first.
        let mut j = 0;
        while j < count {
            let p = &self.pages[start + j];
            if p.state != PageState::Allocated || p.order != order {
                return Err(Error::InvalidArgument);
            }
            j += 1;
        }

        // Release them.
        let mut j = 0;
        while j < count {
            let p = &mut self.pages[start + j];
            p.state = PageState::Free;
            p.ref_count = 0;
            p.order = 0;
            j += 1;
        }

        self.free_count += count;
        self.free_op_count += 1;
        Ok(())
    }

    /// Return the current reference count for the page at `pfn`.
    pub fn get_ref(&self, pfn: u64) -> Result<u16> {
        let idx = self.index_of(pfn)?;
        Ok(self.pages[idx].ref_count)
    }

    /// Increment the reference count and return the new value.
    ///
    /// The page must be in [`PageState::Allocated`] state.
    pub fn inc_ref(&mut self, pfn: u64) -> Result<u16> {
        let idx = self.index_of(pfn)?;
        if self.pages[idx].state != PageState::Allocated {
            return Err(Error::InvalidArgument);
        }
        self.pages[idx].ref_count = self.pages[idx].ref_count.saturating_add(1);
        Ok(self.pages[idx].ref_count)
    }

    /// Decrement the reference count and return the new value.
    ///
    /// If the count reaches zero the page is automatically freed.
    /// The page must be in [`PageState::Allocated`] state.
    pub fn dec_ref(&mut self, pfn: u64) -> Result<u16> {
        let idx = self.index_of(pfn)?;
        if self.pages[idx].state != PageState::Allocated {
            return Err(Error::InvalidArgument);
        }
        let new = self.pages[idx].ref_count.saturating_sub(1);
        self.pages[idx].ref_count = new;
        if new == 0 {
            self.pages[idx].state = PageState::Free;
            self.pages[idx].order = 0;
            self.free_count += 1;
            self.free_op_count += 1;
        }
        Ok(new)
    }

    /// Number of free pages in this pool.
    pub fn free_count(&self) -> usize {
        self.free_count
    }

    /// Returns `true` when free pages are below the low watermark.
    pub fn is_low(&self) -> bool {
        self.free_count < self.low_watermark
    }

    /// Returns `true` when free pages are above the high watermark.
    pub fn is_high(&self) -> bool {
        self.free_count > self.high_watermark
    }

    /// Pool identifier.
    pub fn id(&self) -> u8 {
        self.id
    }

    /// Pool name as a byte slice.
    pub fn name(&self) -> &[u8] {
        &self.name[..self.name_len]
    }

    /// Snapshot the pool's current statistics.
    pub fn stats(&self) -> PoolStats {
        PoolStats {
            total: self.total,
            free_count: self.free_count,
            allocated: self.total - self.free_count,
            high_wm: self.high_watermark,
            low_wm: self.low_watermark,
            alloc_count: self.alloc_count,
            free_op_count: self.free_op_count,
        }
    }

    // ── helpers ────────────────────────────────────────────────────

    /// Resolve a PFN to an index within `self.pages`.
    fn index_of(&self, pfn: u64) -> Result<usize> {
        let mut i = 0;
        while i < self.total {
            if self.pages[i].pfn == pfn {
                return Ok(i);
            }
            i += 1;
        }
        Err(Error::NotFound)
    }
}

// ── PagePoolRegistry ───────────────────────────────────────────────

/// System-wide registry of page pools.
///
/// Holds up to [`MAX_POOLS`] pools and provides lookup and
/// automatic pool selection.
pub struct PagePoolRegistry {
    /// Registered pools.
    pools: [Option<PagePool>; MAX_POOLS],
    /// Number of pools currently registered.
    count: usize,
}

impl Default for PagePoolRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl PagePoolRegistry {
    /// Create an empty registry.
    pub const fn new() -> Self {
        const NONE: Option<PagePool> = None;
        Self {
            pools: [NONE; MAX_POOLS],
            count: 0,
        }
    }

    /// Register a pool in the first available slot.
    ///
    /// Returns the slot index on success, or
    /// [`Error::OutOfMemory`] if all slots are occupied.
    pub fn register(&mut self, pool: PagePool) -> Result<usize> {
        let mut i = 0;
        while i < MAX_POOLS {
            if self.pools[i].is_none() {
                self.pools[i] = Some(pool);
                self.count += 1;
                return Ok(i);
            }
            i += 1;
        }
        Err(Error::OutOfMemory)
    }

    /// Get an immutable reference to the pool at `index`.
    pub fn get(&self, index: usize) -> Result<&PagePool> {
        if index >= MAX_POOLS {
            return Err(Error::InvalidArgument);
        }
        self.pools[index].as_ref().ok_or(Error::NotFound)
    }

    /// Get a mutable reference to the pool at `index`.
    pub fn get_mut(&mut self, index: usize) -> Result<&mut PagePool> {
        if index >= MAX_POOLS {
            return Err(Error::InvalidArgument);
        }
        self.pools[index].as_mut().ok_or(Error::NotFound)
    }

    /// Find the first active pool that has free pages.
    pub fn find_available(&mut self) -> Result<&mut PagePool> {
        let mut i = 0;
        while i < MAX_POOLS {
            if let Some(ref p) = self.pools[i] {
                if p.active && p.free_count > 0 {
                    // Re-borrow mutably after the check.
                    return self.pools[i].as_mut().ok_or(Error::NotFound);
                }
            }
            i += 1;
        }
        Err(Error::OutOfMemory)
    }

    /// Number of registered pools.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Returns `true` when no pools are registered.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
}
