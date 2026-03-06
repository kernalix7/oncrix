// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Swap extent management.
//!
//! A swap area is backed by a file or partition whose blocks may not be
//! contiguous on disk. Swap extents map logical swap offsets to physical
//! disk blocks so that the swap I/O path can translate swap slots to
//! disk addresses efficiently. This module manages the extent list and
//! provides O(log n) lookup via binary search.
//!
//! # Design
//!
//! ```text
//!  swapon("/dev/sda2")
//!       │
//!       ├─ scan partition/file blocks
//!       ├─ build extent list: [(swap_offset, block, nr_pages)]
//!       └─ sort by swap_offset
//!
//!  swap_writepage(slot)
//!       └─ SwapExtentMap::lookup(slot) → disk block address
//! ```
//!
//! # Key Types
//!
//! - [`SwapExtent`] — a single contiguous extent
//! - [`SwapExtentMap`] — the sorted extent list
//! - [`SwapExtentStats`] — extent statistics
//!
//! Reference: Linux `mm/swapfile.c` (setup_swap_extents).

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Maximum extents per swap area.
const MAX_EXTENTS: usize = 512;

/// Page size in disk sectors (4096 / 512 = 8).
const SECTORS_PER_PAGE: u64 = 8;

/// Maximum swap area size in pages.
const MAX_SWAP_PAGES: u64 = 1 << 24; // 64 GiB at 4 KiB pages

// -------------------------------------------------------------------
// SwapExtent
// -------------------------------------------------------------------

/// A single contiguous region in the swap area.
#[derive(Debug, Clone, Copy)]
pub struct SwapExtent {
    /// Starting swap offset (in pages).
    swap_offset: u64,
    /// Starting disk block number.
    start_block: u64,
    /// Number of pages in this extent.
    nr_pages: u64,
}

impl SwapExtent {
    /// Create a new swap extent.
    pub const fn new(swap_offset: u64, start_block: u64, nr_pages: u64) -> Self {
        Self {
            swap_offset,
            start_block,
            nr_pages,
        }
    }

    /// Return the starting swap offset.
    pub const fn swap_offset(&self) -> u64 {
        self.swap_offset
    }

    /// Return the starting disk block.
    pub const fn start_block(&self) -> u64 {
        self.start_block
    }

    /// Return the number of pages.
    pub const fn nr_pages(&self) -> u64 {
        self.nr_pages
    }

    /// Return the ending swap offset (exclusive).
    pub const fn end_offset(&self) -> u64 {
        self.swap_offset + self.nr_pages
    }

    /// Check whether a swap offset falls within this extent.
    pub const fn contains(&self, offset: u64) -> bool {
        offset >= self.swap_offset && offset < self.end_offset()
    }

    /// Map a swap offset to a disk block.
    pub const fn to_block(&self, offset: u64) -> u64 {
        self.start_block + (offset - self.swap_offset) * SECTORS_PER_PAGE
    }

    /// Return the size in disk sectors.
    pub const fn sector_count(&self) -> u64 {
        self.nr_pages * SECTORS_PER_PAGE
    }
}

impl Default for SwapExtent {
    fn default() -> Self {
        Self {
            swap_offset: 0,
            start_block: 0,
            nr_pages: 0,
        }
    }
}

// -------------------------------------------------------------------
// SwapExtentStats
// -------------------------------------------------------------------

/// Statistics about the extent map.
#[derive(Debug, Clone, Copy)]
pub struct SwapExtentStats {
    /// Number of extents.
    pub extent_count: u32,
    /// Total pages covered.
    pub total_pages: u64,
    /// Average extent size in pages.
    pub avg_extent_pages: u64,
    /// Largest extent in pages.
    pub max_extent_pages: u64,
    /// Fragmentation score (0 = single extent, higher = more fragmented).
    pub fragmentation: u32,
}

impl SwapExtentStats {
    /// Create zero stats.
    pub const fn new() -> Self {
        Self {
            extent_count: 0,
            total_pages: 0,
            avg_extent_pages: 0,
            max_extent_pages: 0,
            fragmentation: 0,
        }
    }
}

impl Default for SwapExtentStats {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// SwapExtentMap
// -------------------------------------------------------------------

/// Sorted list of swap extents for a swap area.
pub struct SwapExtentMap {
    /// Extents sorted by swap_offset.
    extents: [SwapExtent; MAX_EXTENTS],
    /// Number of valid extents.
    count: usize,
    /// Total pages covered.
    total_pages: u64,
}

impl SwapExtentMap {
    /// Create an empty extent map.
    pub const fn new() -> Self {
        Self {
            extents: [const {
                SwapExtent {
                    swap_offset: 0,
                    start_block: 0,
                    nr_pages: 0,
                }
            }; MAX_EXTENTS],
            count: 0,
            total_pages: 0,
        }
    }

    /// Return the number of extents.
    pub const fn count(&self) -> usize {
        self.count
    }

    /// Return the total pages.
    pub const fn total_pages(&self) -> u64 {
        self.total_pages
    }

    /// Add an extent. Extents must be added in sorted order.
    pub fn add(&mut self, extent: SwapExtent) -> Result<()> {
        if self.count >= MAX_EXTENTS {
            return Err(Error::OutOfMemory);
        }
        if self.total_pages + extent.nr_pages() > MAX_SWAP_PAGES {
            return Err(Error::InvalidArgument);
        }
        // Verify ordering.
        if self.count > 0 {
            let last = &self.extents[self.count - 1];
            if extent.swap_offset() < last.end_offset() {
                return Err(Error::InvalidArgument);
            }
        }
        self.extents[self.count] = extent;
        self.count += 1;
        self.total_pages += extent.nr_pages();
        Ok(())
    }

    /// Look up the disk block for a swap offset using binary search.
    pub fn lookup(&self, offset: u64) -> Result<u64> {
        if self.count == 0 {
            return Err(Error::NotFound);
        }

        let mut lo = 0usize;
        let mut hi = self.count;
        while lo < hi {
            let mid = lo + (hi - lo) / 2;
            if offset < self.extents[mid].swap_offset() {
                hi = mid;
            } else if offset >= self.extents[mid].end_offset() {
                lo = mid + 1;
            } else {
                return Ok(self.extents[mid].to_block(offset));
            }
        }
        Err(Error::NotFound)
    }

    /// Get an extent by index.
    pub fn get(&self, index: usize) -> Result<&SwapExtent> {
        if index >= self.count {
            return Err(Error::InvalidArgument);
        }
        Ok(&self.extents[index])
    }

    /// Compute statistics about the extent map.
    pub fn compute_stats(&self) -> SwapExtentStats {
        if self.count == 0 {
            return SwapExtentStats::new();
        }

        let mut max_pages = 0u64;
        for idx in 0..self.count {
            let pages = self.extents[idx].nr_pages();
            if pages > max_pages {
                max_pages = pages;
            }
        }

        SwapExtentStats {
            extent_count: self.count as u32,
            total_pages: self.total_pages,
            avg_extent_pages: self.total_pages / self.count as u64,
            max_extent_pages: max_pages,
            fragmentation: if self.count <= 1 {
                0
            } else {
                (self.count - 1) as u32
            },
        }
    }

    /// Check whether the map covers all pages from 0..total_pages
    /// with no gaps.
    pub fn is_contiguous(&self) -> bool {
        if self.count == 0 {
            return true;
        }
        if self.extents[0].swap_offset() != 0 {
            return false;
        }
        for idx in 1..self.count {
            let prev_end = self.extents[idx - 1].end_offset();
            if self.extents[idx].swap_offset() != prev_end {
                return false;
            }
        }
        true
    }
}

impl Default for SwapExtentMap {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// Public helpers
// -------------------------------------------------------------------

/// Build an extent map from a contiguous swap partition.
pub fn build_contiguous_map(start_block: u64, nr_pages: u64) -> Result<SwapExtentMap> {
    let mut map = SwapExtentMap::new();
    map.add(SwapExtent::new(0, start_block, nr_pages))?;
    Ok(map)
}

/// Return the disk sector for a swap offset.
pub fn swap_offset_to_sector(map: &SwapExtentMap, offset: u64) -> Result<u64> {
    map.lookup(offset)
}

/// Check whether the swap area is contiguous on disk.
pub fn is_swap_contiguous(map: &SwapExtentMap) -> bool {
    map.is_contiguous() && map.count() <= 1
}
