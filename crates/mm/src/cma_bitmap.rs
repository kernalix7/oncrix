// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! CMA (Contiguous Memory Allocator) bitmap management.
//!
//! Implements the CMA bitmap allocator for allocating physically
//! contiguous memory regions. CMA reserves a region of memory at
//! boot and uses a bitmap to track which page blocks are allocated.
//! The allocator enforces alignment constraints and supports
//! variable-sized allocations.
//!
//! - [`CmaAreaInfo`] — metadata about a CMA region
//! - [`CmaBitmap`] — bitmap tracking allocated blocks
//! - [`CmaRegion`] — a CMA region with allocation support
//! - [`CmaAllocResult`] — result of an allocation attempt
//! - [`CmaManager`] — manages multiple CMA regions
//! - [`CmaStats`] — aggregate statistics
//!
//! Reference: `.kernelORG/` — `mm/cma.c`, `include/linux/cma.h`.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Maximum number of CMA regions.
const MAX_CMA_REGIONS: usize = 8;

/// Maximum bitmap size (in u64 words). Each word tracks 64 blocks.
const MAX_BITMAP_WORDS: usize = 64;

/// Maximum blocks per CMA region (64 * 64 = 4096 blocks).
const MAX_CMA_BLOCKS: usize = MAX_BITMAP_WORDS * 64;

/// Default order per bit (0 = each bit = 1 page).
const DEFAULT_ORDER_PER_BIT: u32 = 0;

/// Page size (4 KiB).
const PAGE_SIZE: u64 = 4096;

// -------------------------------------------------------------------
// CmaAreaInfo
// -------------------------------------------------------------------

/// Metadata about a CMA region.
#[derive(Debug, Clone, Copy, Default)]
pub struct CmaAreaInfo {
    /// Region name/identifier.
    pub region_id: u64,
    /// Base page frame number of the region.
    pub base_pfn: u64,
    /// Total number of blocks (pages at order_per_bit).
    pub count: usize,
    /// Pages per block (2^order_per_bit).
    pub order_per_bit: u32,
    /// Total pages in the region.
    pub total_pages: u64,
    /// Pages currently allocated.
    pub allocated_pages: u64,
}

// -------------------------------------------------------------------
// CmaBitmap
// -------------------------------------------------------------------

/// Bitmap tracking allocated blocks in a CMA region.
///
/// Each bit represents one block (which may be 1 or more pages
/// depending on `order_per_bit`). 1 = allocated, 0 = free.
#[derive(Debug)]
pub struct CmaBitmap {
    /// Bitmap words (each u64 = 64 blocks).
    words: [u64; MAX_BITMAP_WORDS],
    /// Total number of blocks tracked.
    total_blocks: usize,
    /// Number of allocated blocks.
    allocated_blocks: usize,
}

impl Default for CmaBitmap {
    fn default() -> Self {
        Self {
            words: [0u64; MAX_BITMAP_WORDS],
            total_blocks: 0,
            allocated_blocks: 0,
        }
    }
}

impl CmaBitmap {
    /// Creates a new bitmap for the given number of blocks.
    pub fn new(total_blocks: usize) -> Self {
        Self {
            total_blocks: total_blocks.min(MAX_CMA_BLOCKS),
            ..Self::default()
        }
    }

    /// Tests if a block is allocated.
    pub fn is_allocated(&self, block: usize) -> bool {
        if block >= self.total_blocks {
            return false;
        }
        let word = block / 64;
        let bit = block % 64;
        self.words[word] & (1u64 << bit) != 0
    }

    /// Sets a block as allocated.
    fn set(&mut self, block: usize) {
        if block < self.total_blocks {
            let word = block / 64;
            let bit = block % 64;
            self.words[word] |= 1u64 << bit;
            self.allocated_blocks += 1;
        }
    }

    /// Clears a block (marks as free).
    fn clear(&mut self, block: usize) {
        if block < self.total_blocks {
            let word = block / 64;
            let bit = block % 64;
            if self.words[word] & (1u64 << bit) != 0 {
                self.words[word] &= !(1u64 << bit);
                self.allocated_blocks = self.allocated_blocks.saturating_sub(1);
            }
        }
    }

    /// Finds a free range of `count` consecutive blocks,
    /// aligned to `alignment` blocks.
    pub fn find_free_range(&self, count: usize, alignment: usize) -> Option<usize> {
        if count == 0 || count > self.total_blocks {
            return None;
        }
        let align = if alignment == 0 { 1 } else { alignment };

        let mut start = 0;
        while start + count <= self.total_blocks {
            // Align start.
            if start % align != 0 {
                start = ((start / align) + 1) * align;
                continue;
            }

            // Check if range is free.
            let mut all_free = true;
            for i in 0..count {
                if self.is_allocated(start + i) {
                    // Skip past the allocated block.
                    start = start + i + 1;
                    all_free = false;
                    break;
                }
            }

            if all_free {
                return Some(start);
            }
        }
        None
    }

    /// Allocates a range of consecutive blocks.
    pub fn alloc_range(&mut self, start: usize, count: usize) -> Result<()> {
        if start + count > self.total_blocks {
            return Err(Error::InvalidArgument);
        }
        for i in 0..count {
            if self.is_allocated(start + i) {
                return Err(Error::AlreadyExists);
            }
        }
        for i in 0..count {
            self.set(start + i);
        }
        Ok(())
    }

    /// Releases a range of blocks.
    pub fn release_range(&mut self, start: usize, count: usize) -> Result<()> {
        if start + count > self.total_blocks {
            return Err(Error::InvalidArgument);
        }
        for i in 0..count {
            self.clear(start + i);
        }
        Ok(())
    }

    /// Returns the number of free blocks.
    pub fn free_blocks(&self) -> usize {
        self.total_blocks - self.allocated_blocks
    }

    /// Returns the total number of blocks.
    pub fn total_blocks(&self) -> usize {
        self.total_blocks
    }

    /// Returns the number of allocated blocks.
    pub fn allocated_blocks(&self) -> usize {
        self.allocated_blocks
    }
}

// -------------------------------------------------------------------
// CmaAllocResult
// -------------------------------------------------------------------

/// Result of a CMA allocation.
#[derive(Debug, Clone, Copy, Default)]
pub struct CmaAllocResult {
    /// Base PFN of the allocated region.
    pub base_pfn: u64,
    /// Number of pages allocated.
    pub nr_pages: u64,
    /// Block start index in the bitmap.
    pub block_start: usize,
    /// Number of blocks allocated.
    pub nr_blocks: usize,
}

// -------------------------------------------------------------------
// CmaRegion
// -------------------------------------------------------------------

/// A CMA region with allocation support.
pub struct CmaRegion {
    /// Area metadata.
    pub info: CmaAreaInfo,
    /// Allocation bitmap.
    bitmap: CmaBitmap,
    /// Whether this region is initialised.
    initialised: bool,
}

impl Default for CmaRegion {
    fn default() -> Self {
        Self {
            info: CmaAreaInfo::default(),
            bitmap: CmaBitmap::default(),
            initialised: false,
        }
    }
}

impl CmaRegion {
    /// Initialises a CMA region.
    pub fn init(region_id: u64, base_pfn: u64, total_pages: u64, order_per_bit: u32) -> Self {
        let pages_per_block = 1u64 << order_per_bit;
        let count = (total_pages / pages_per_block) as usize;
        let clamped = count.min(MAX_CMA_BLOCKS);

        Self {
            info: CmaAreaInfo {
                region_id,
                base_pfn,
                count: clamped,
                order_per_bit,
                total_pages,
                allocated_pages: 0,
            },
            bitmap: CmaBitmap::new(clamped),
            initialised: true,
        }
    }

    /// Allocates `nr_pages` contiguous pages, aligned to
    /// `alignment_pages`.
    pub fn cma_alloc(&mut self, nr_pages: u64, alignment_pages: u64) -> Result<CmaAllocResult> {
        if !self.initialised {
            return Err(Error::InvalidArgument);
        }

        let pages_per_block = 1u64 << self.info.order_per_bit;
        let blocks_needed = ((nr_pages + pages_per_block - 1) / pages_per_block) as usize;
        let align_blocks = ((alignment_pages + pages_per_block - 1) / pages_per_block) as usize;

        let start = self
            .bitmap
            .find_free_range(blocks_needed, align_blocks)
            .ok_or(Error::OutOfMemory)?;

        self.bitmap.alloc_range(start, blocks_needed)?;

        let actual_pages = blocks_needed as u64 * pages_per_block;
        self.info.allocated_pages += actual_pages;

        Ok(CmaAllocResult {
            base_pfn: self.info.base_pfn + (start as u64 * pages_per_block),
            nr_pages: actual_pages,
            block_start: start,
            nr_blocks: blocks_needed,
        })
    }

    /// Releases a previously allocated CMA region.
    pub fn cma_release(&mut self, block_start: usize, nr_blocks: usize) -> Result<()> {
        if !self.initialised {
            return Err(Error::InvalidArgument);
        }

        self.bitmap.release_range(block_start, nr_blocks)?;

        let pages_per_block = 1u64 << self.info.order_per_bit;
        let released_pages = nr_blocks as u64 * pages_per_block;
        self.info.allocated_pages = self.info.allocated_pages.saturating_sub(released_pages);

        Ok(())
    }

    /// Returns the area info.
    pub fn area_info(&self) -> &CmaAreaInfo {
        &self.info
    }

    /// Returns the number of free blocks.
    pub fn free_blocks(&self) -> usize {
        self.bitmap.free_blocks()
    }

    /// Returns whether the region is initialised.
    pub fn is_initialised(&self) -> bool {
        self.initialised
    }
}

// -------------------------------------------------------------------
// CmaStats
// -------------------------------------------------------------------

/// Aggregate CMA statistics.
#[derive(Debug, Clone, Copy, Default)]
pub struct CmaStats {
    /// Total allocation attempts.
    pub alloc_attempts: u64,
    /// Successful allocations.
    pub alloc_success: u64,
    /// Failed allocations.
    pub alloc_failures: u64,
    /// Total release operations.
    pub release_ops: u64,
    /// Total pages allocated.
    pub pages_allocated: u64,
    /// Total pages released.
    pub pages_released: u64,
}

impl CmaStats {
    /// Resets all counters.
    pub fn reset(&mut self) {
        *self = Self::default();
    }
}

// -------------------------------------------------------------------
// CmaManager
// -------------------------------------------------------------------

/// Manages multiple CMA regions.
pub struct CmaManager {
    /// CMA regions.
    regions: [CmaRegion; MAX_CMA_REGIONS],
    /// Number of initialised regions.
    region_count: usize,
    /// Aggregate statistics.
    stats: CmaStats,
}

impl Default for CmaManager {
    fn default() -> Self {
        Self {
            regions: [const {
                CmaRegion {
                    info: CmaAreaInfo {
                        region_id: 0,
                        base_pfn: 0,
                        count: 0,
                        order_per_bit: 0,
                        total_pages: 0,
                        allocated_pages: 0,
                    },
                    bitmap: CmaBitmap {
                        words: [0u64; MAX_BITMAP_WORDS],
                        total_blocks: 0,
                        allocated_blocks: 0,
                    },
                    initialised: false,
                }
            }; MAX_CMA_REGIONS],
            region_count: 0,
            stats: CmaStats::default(),
        }
    }
}

impl CmaManager {
    /// Creates a new CMA manager.
    pub fn new() -> Self {
        Self::default()
    }

    /// Initialises a new CMA region.
    pub fn init_reserved_mem(
        &mut self,
        region_id: u64,
        base_pfn: u64,
        total_pages: u64,
        order_per_bit: u32,
    ) -> Result<usize> {
        if self.region_count >= MAX_CMA_REGIONS {
            return Err(Error::OutOfMemory);
        }
        let idx = self.region_count;
        self.regions[idx] = CmaRegion::init(region_id, base_pfn, total_pages, order_per_bit);
        self.region_count += 1;
        Ok(idx)
    }

    /// Allocates from a specific CMA region.
    pub fn alloc(
        &mut self,
        region_idx: usize,
        nr_pages: u64,
        alignment: u64,
    ) -> Result<CmaAllocResult> {
        if region_idx >= self.region_count {
            return Err(Error::InvalidArgument);
        }
        self.stats.alloc_attempts += 1;

        match self.regions[region_idx].cma_alloc(nr_pages, alignment) {
            Ok(result) => {
                self.stats.alloc_success += 1;
                self.stats.pages_allocated += result.nr_pages;
                Ok(result)
            }
            Err(e) => {
                self.stats.alloc_failures += 1;
                Err(e)
            }
        }
    }

    /// Releases an allocation.
    pub fn release(
        &mut self,
        region_idx: usize,
        block_start: usize,
        nr_blocks: usize,
    ) -> Result<()> {
        if region_idx >= self.region_count {
            return Err(Error::InvalidArgument);
        }
        let pages_per_block = 1u64 << self.regions[region_idx].info.order_per_bit;
        let pages = nr_blocks as u64 * pages_per_block;

        self.regions[region_idx].cma_release(block_start, nr_blocks)?;
        self.stats.release_ops += 1;
        self.stats.pages_released += pages;
        Ok(())
    }

    /// Returns the number of regions.
    pub fn region_count(&self) -> usize {
        self.region_count
    }

    /// Returns a reference to a region.
    pub fn region(&self, index: usize) -> Option<&CmaRegion> {
        if index < self.region_count {
            Some(&self.regions[index])
        } else {
            None
        }
    }

    /// Returns aggregate statistics.
    pub fn stats(&self) -> &CmaStats {
        &self.stats
    }

    /// Resets statistics.
    pub fn reset_stats(&mut self) {
        self.stats.reset();
    }
}
