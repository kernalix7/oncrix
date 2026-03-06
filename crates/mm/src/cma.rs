// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Contiguous Memory Allocator (CMA).
//!
//! Provides a pool of reserved physical memory regions from which
//! large, physically contiguous allocations can be satisfied.
//! CMA regions use a bitmap to track per-page allocation state
//! and support power-of-2 aligned contiguous allocations — critical
//! for DMA buffers, huge-page backing, and device framebuffers.
//!
//! - [`CmaRegion`] — single contiguous reserved region with bitmap
//! - [`CmaAllocator`] — per-region contiguous alloc/free operations
//! - [`CmaPool`] — system-wide pool of up to [`MAX_CMA_REGIONS`]
//!   regions with best-fit selection
//! - [`CmaStats`] — aggregate allocation statistics

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Maximum number of pages a single CMA region can manage.
const MAX_CMA_PAGES: usize = 1024;

/// Number of `u64` words needed for the bitmap (1024 / 64).
const CMA_BITMAP_WORDS: usize = MAX_CMA_PAGES / 64;

/// Maximum number of CMA regions in the system pool.
const MAX_CMA_REGIONS: usize = 8;

/// Maximum length of a region name in bytes.
const CMA_NAME_LEN: usize = 32;

// -------------------------------------------------------------------
// CmaRegion
// -------------------------------------------------------------------

/// A single CMA reserved region.
///
/// Tracks `size_pages` contiguous physical pages starting at
/// `base_pfn` using a 1024-bit bitmap. Bit 0 = free, bit 1 = used.
#[derive(Clone, Copy)]
pub struct CmaRegion {
    /// First page frame number of this region.
    pub base_pfn: u64,
    /// Number of pages in this region (at most [`MAX_CMA_PAGES`]).
    pub size_pages: usize,
    /// Allocation bitmap — one bit per page.
    pub bitmap: [u64; CMA_BITMAP_WORDS],
    /// Human-readable name (truncated to [`CMA_NAME_LEN`] bytes).
    pub name: [u8; CMA_NAME_LEN],
    /// Valid length of `name`.
    name_len: usize,
    /// Whether this region is active.
    active: bool,
}

impl core::fmt::Debug for CmaRegion {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("CmaRegion")
            .field("base_pfn", &self.base_pfn)
            .field("size_pages", &self.size_pages)
            .field("active", &self.active)
            .finish()
    }
}

impl CmaRegion {
    /// Creates an empty, inactive CMA region.
    const fn empty() -> Self {
        Self {
            base_pfn: 0,
            size_pages: 0,
            bitmap: [0u64; CMA_BITMAP_WORDS],
            name: [0u8; CMA_NAME_LEN],
            name_len: 0,
            active: false,
        }
    }

    /// Creates a new CMA region.
    ///
    /// `base_pfn` is the starting page frame number, `size_pages`
    /// is capped at [`MAX_CMA_PAGES`], and `name` is truncated
    /// to [`CMA_NAME_LEN`] bytes.
    pub fn new(base_pfn: u64, size_pages: usize, name: &[u8]) -> Self {
        let capped = if size_pages > MAX_CMA_PAGES {
            MAX_CMA_PAGES
        } else {
            size_pages
        };

        let mut region_name = [0u8; CMA_NAME_LEN];
        let copy_len = if name.len() > CMA_NAME_LEN {
            CMA_NAME_LEN
        } else {
            name.len()
        };
        let mut i = 0;
        while i < copy_len {
            region_name[i] = name[i];
            i += 1;
        }

        Self {
            base_pfn,
            size_pages: capped,
            bitmap: [0u64; CMA_BITMAP_WORDS],
            name: region_name,
            name_len: copy_len,
            active: true,
        }
    }

    /// Returns the region name as a byte slice.
    pub fn name(&self) -> &[u8] {
        &self.name[..self.name_len]
    }

    /// Returns `true` if this region is active.
    pub fn is_active(&self) -> bool {
        self.active
    }

    /// Returns the number of free pages in this region.
    pub fn free_pages(&self) -> usize {
        let mut free = 0_usize;
        for i in 0..self.size_pages {
            let word = i / 64;
            let bit = i % 64;
            if self.bitmap[word] & (1u64 << bit) == 0 {
                free += 1;
            }
        }
        free
    }

    /// Returns the number of allocated pages.
    pub fn used_pages(&self) -> usize {
        self.size_pages - self.free_pages()
    }

    /// Returns the size of the largest contiguous free range.
    pub fn largest_free_range(&self) -> usize {
        let mut max_run = 0_usize;
        let mut current_run = 0_usize;
        for i in 0..self.size_pages {
            let word = i / 64;
            let bit = i % 64;
            if self.bitmap[word] & (1u64 << bit) == 0 {
                current_run += 1;
                if current_run > max_run {
                    max_run = current_run;
                }
            } else {
                current_run = 0;
            }
        }
        max_run
    }
}

// -------------------------------------------------------------------
// CmaAllocator
// -------------------------------------------------------------------

/// Per-region contiguous allocation engine.
///
/// Operates on a [`CmaRegion`] to allocate and free contiguous
/// runs of pages with power-of-2 alignment.
pub struct CmaAllocator;

impl CmaAllocator {
    /// Allocates `count` contiguous pages from `region` with
    /// power-of-2 alignment.
    ///
    /// Uses a first-fit scan that respects alignment: the starting
    /// page index within the region must be a multiple of the
    /// smallest power of 2 >= `count`.
    ///
    /// Returns the PFN of the first allocated page.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `count` is 0 or exceeds
    /// the region size, or [`Error::OutOfMemory`] if no suitably
    /// aligned contiguous range is available.
    pub fn alloc_contiguous(region: &mut CmaRegion, count: usize) -> Result<u64> {
        if count == 0 || count > region.size_pages {
            return Err(Error::InvalidArgument);
        }

        let align = count.next_power_of_two();
        let start = Self::find_free_range(region, count, align)?;

        // Mark pages as allocated.
        for i in start..start + count {
            let word = i / 64;
            let bit = i % 64;
            region.bitmap[word] |= 1u64 << bit;
        }

        Ok(region.base_pfn + start as u64)
    }

    /// Frees `count` contiguous pages starting at `pfn` back to
    /// `region`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if the range falls outside
    /// the region or any page is not currently allocated.
    pub fn free_contiguous(region: &mut CmaRegion, pfn: u64, count: usize) -> Result<()> {
        if pfn < region.base_pfn {
            return Err(Error::InvalidArgument);
        }
        let offset = (pfn - region.base_pfn) as usize;
        if offset + count > region.size_pages {
            return Err(Error::InvalidArgument);
        }

        // Verify all pages are allocated before freeing.
        for i in offset..offset + count {
            let word = i / 64;
            let bit = i % 64;
            if region.bitmap[word] & (1u64 << bit) == 0 {
                return Err(Error::InvalidArgument);
            }
        }

        // Clear the bits.
        for i in offset..offset + count {
            let word = i / 64;
            let bit = i % 64;
            region.bitmap[word] &= !(1u64 << bit);
        }

        Ok(())
    }

    /// Finds a contiguous free range of `count` pages with the
    /// given alignment (must be a power of 2).
    ///
    /// Uses first-fit: scans from index 0, stepping by `align`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if no suitable range exists.
    pub fn find_free_range(region: &CmaRegion, count: usize, align: usize) -> Result<usize> {
        let align = if align == 0 { 1 } else { align };
        let mut start = 0_usize;

        while start + count <= region.size_pages {
            let mut all_free = true;
            for i in start..start + count {
                let word = i / 64;
                let bit = i % 64;
                if region.bitmap[word] & (1u64 << bit) != 0 {
                    all_free = false;
                    break;
                }
            }
            if all_free {
                return Ok(start);
            }
            start += align;
        }

        Err(Error::OutOfMemory)
    }
}

// -------------------------------------------------------------------
// CmaStats
// -------------------------------------------------------------------

/// Aggregate CMA allocation statistics.
#[derive(Debug, Clone, Copy, Default)]
pub struct CmaStats {
    /// Total pages across all regions.
    pub total_pages: u64,
    /// Free pages across all regions.
    pub free_pages: u64,
    /// Successful contiguous allocations.
    pub alloc_count: u64,
    /// Successful contiguous frees.
    pub free_count: u64,
    /// Failed allocation attempts.
    pub alloc_fail_count: u64,
    /// Largest contiguous free range across all regions.
    pub largest_free_range: u64,
}

// -------------------------------------------------------------------
// CmaPool
// -------------------------------------------------------------------

/// System-wide pool of CMA regions.
///
/// Holds up to [`MAX_CMA_REGIONS`] regions and supports
/// registration, removal, best-fit allocation, and freeing.
pub struct CmaPool {
    /// Registered regions.
    regions: [CmaRegion; MAX_CMA_REGIONS],
    /// Number of active regions.
    region_count: usize,
    /// Successful allocations.
    alloc_count: u64,
    /// Successful frees.
    free_count: u64,
    /// Failed allocation attempts.
    alloc_fail_count: u64,
}

impl Default for CmaPool {
    fn default() -> Self {
        Self::new()
    }
}

impl CmaPool {
    /// Creates an empty CMA pool.
    pub const fn new() -> Self {
        Self {
            regions: [CmaRegion::empty(); MAX_CMA_REGIONS],
            region_count: 0,
            alloc_count: 0,
            free_count: 0,
            alloc_fail_count: 0,
        }
    }

    /// Adds a region to the pool.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if all region slots are full.
    pub fn add_region(&mut self, region: CmaRegion) -> Result<usize> {
        if self.region_count >= MAX_CMA_REGIONS {
            return Err(Error::OutOfMemory);
        }
        let idx = self.region_count;
        self.regions[idx] = region;
        self.region_count += 1;
        Ok(idx)
    }

    /// Removes the region at `index` by swapping with the last.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `index` is out of range.
    pub fn remove_region(&mut self, index: usize) -> Result<()> {
        if index >= self.region_count {
            return Err(Error::InvalidArgument);
        }
        self.region_count -= 1;
        if index < self.region_count {
            self.regions[index] = self.regions[self.region_count];
        }
        self.regions[self.region_count] = CmaRegion::empty();
        Ok(())
    }

    /// Allocates `count` contiguous pages from the best-fit region.
    ///
    /// Best-fit is the active region with the smallest remaining
    /// free space that can still satisfy the allocation.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if no region can satisfy the
    /// request.
    pub fn alloc(&mut self, count: usize) -> Result<u64> {
        let idx = self.find_region_for_alloc(count)?;
        match CmaAllocator::alloc_contiguous(&mut self.regions[idx], count) {
            Ok(pfn) => {
                self.alloc_count += 1;
                Ok(pfn)
            }
            Err(e) => {
                self.alloc_fail_count += 1;
                Err(e)
            }
        }
    }

    /// Frees `count` contiguous pages starting at `pfn`.
    ///
    /// Searches all regions to find the one containing `pfn`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if `pfn` does not belong to any
    /// region, or propagates errors from [`CmaAllocator::free_contiguous`].
    pub fn free(&mut self, pfn: u64, count: usize) -> Result<()> {
        for i in 0..self.region_count {
            let r = &self.regions[i];
            if !r.active {
                continue;
            }
            let end_pfn = r.base_pfn + r.size_pages as u64;
            if pfn >= r.base_pfn && pfn + count as u64 <= end_pfn {
                CmaAllocator::free_contiguous(&mut self.regions[i], pfn, count)?;
                self.free_count += 1;
                return Ok(());
            }
        }
        Err(Error::NotFound)
    }

    /// Finds the best-fit region index for an allocation of `count`
    /// contiguous pages.
    ///
    /// Best-fit selects the active region with the smallest free
    /// space that is still >= `count`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if no region qualifies.
    pub fn find_region_for_alloc(&self, count: usize) -> Result<usize> {
        let mut best_idx: Option<usize> = None;
        let mut best_free = usize::MAX;

        for i in 0..self.region_count {
            let r = &self.regions[i];
            if !r.active {
                continue;
            }
            let free = r.free_pages();
            if free >= count && free < best_free {
                // Verify that a contiguous range actually exists.
                let align = count.next_power_of_two();
                if CmaAllocator::find_free_range(r, count, align).is_ok() {
                    best_free = free;
                    best_idx = Some(i);
                }
            }
        }

        best_idx.ok_or(Error::OutOfMemory)
    }

    /// Returns aggregate statistics across all regions.
    pub fn stats(&self) -> CmaStats {
        let mut s = CmaStats {
            total_pages: 0,
            free_pages: 0,
            alloc_count: self.alloc_count,
            free_count: self.free_count,
            alloc_fail_count: self.alloc_fail_count,
            largest_free_range: 0,
        };

        for i in 0..self.region_count {
            let r = &self.regions[i];
            if !r.active {
                continue;
            }
            s.total_pages += r.size_pages as u64;
            s.free_pages += r.free_pages() as u64;
            let lfr = r.largest_free_range() as u64;
            if lfr > s.largest_free_range {
                s.largest_free_range = lfr;
            }
        }

        s
    }

    /// Returns the number of registered regions.
    pub fn len(&self) -> usize {
        self.region_count
    }

    /// Returns `true` if no regions are registered.
    pub fn is_empty(&self) -> bool {
        self.region_count == 0
    }

    /// Returns a shared reference to the region at `index`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `index` is out of range.
    pub fn get_region(&self, index: usize) -> Result<&CmaRegion> {
        if index >= self.region_count {
            return Err(Error::InvalidArgument);
        }
        Ok(&self.regions[index])
    }
}
