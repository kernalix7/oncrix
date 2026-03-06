// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Btrfs free space cache management.
//!
//! Tracks free space within a block group using two complementary
//! representations:
//!
//! - **Extent entries**: a sorted array of `(start, length)` intervals used
//!   for large contiguous free regions and best-fit allocation.
//! - **Bitmap entries**: bit-per-block bitmaps for densely fragmented regions.
//!
//! The design mirrors `fs/btrfs/free-space-cache.c` and the free space tree
//! (cache v2) described in the Btrfs on-disk format documentation.
//!
//! # Cluster allocation
//!
//! A cluster is a contiguous run of free blocks that is pre-reserved for a
//! single allocator (e.g. data or metadata). Once a cluster is allocated it
//! is consumed linearly, reducing fragmentation.
//!
//! # References
//!
//! - Linux `fs/btrfs/free-space-cache.c`
//! - Btrfs wiki: <https://btrfs.wiki.kernel.org/index.php/Free_space_cache>

use oncrix_lib::{Error, Result};

// ── Constants ────────────────────────────────────────────────────────────────

/// Maximum number of extent-based free space entries per block group.
pub const MAX_EXTENT_ENTRIES: usize = 512;

/// Maximum number of bitmap-based free space entries per block group.
pub const MAX_BITMAP_ENTRIES: usize = 64;

/// Number of bits (blocks) covered by a single bitmap entry.
pub const BITMAP_BITS: usize = 128;

/// Maximum number of simultaneously active clusters.
pub const MAX_CLUSTERS: usize = 8;

/// Minimum free blocks required to form a cluster.
pub const CLUSTER_MIN_BLOCKS: u64 = 4;

// ── FreeSpaceExtent ───────────────────────────────────────────────────────────

/// A contiguous free region described by its logical start and block count.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FreeSpaceExtent {
    /// Logical start block of the free region.
    pub start: u64,
    /// Number of free blocks in this region.
    pub len: u64,
    /// Whether this slot is occupied.
    pub active: bool,
}

impl FreeSpaceExtent {
    /// Returns the exclusive end of the extent.
    pub const fn end(&self) -> u64 {
        self.start + self.len
    }
}

// ── BitmapEntry ──────────────────────────────────────────────────────────────

/// A bitmap covering [`BITMAP_BITS`] consecutive blocks.
///
/// Each bit represents one block; 1 = free, 0 = allocated.
#[derive(Debug, Clone, Copy)]
pub struct BitmapEntry {
    /// Logical start block of the first bit in this bitmap.
    pub start: u64,
    /// Bit array (1 = free).
    bits: [u64; 2], // 2 × 64 = 128 bits
    /// Whether this slot is occupied.
    pub active: bool,
}

impl Default for BitmapEntry {
    fn default() -> Self {
        Self {
            start: 0,
            bits: [0u64; 2],
            active: false,
        }
    }
}

impl BitmapEntry {
    /// Returns `true` if the block at position `offset` (relative to
    /// `self.start`) is free.
    pub fn is_free(&self, offset: usize) -> bool {
        if offset >= BITMAP_BITS {
            return false;
        }
        let word = offset / 64;
        let bit = offset % 64;
        self.bits[word] & (1u64 << bit) != 0
    }

    /// Marks `offset` as free (sets the bit).
    pub fn mark_free(&mut self, offset: usize) {
        if offset < BITMAP_BITS {
            self.bits[offset / 64] |= 1u64 << (offset % 64);
        }
    }

    /// Marks `offset` as allocated (clears the bit).
    pub fn mark_alloc(&mut self, offset: usize) {
        if offset < BITMAP_BITS {
            self.bits[offset / 64] &= !(1u64 << (offset % 64));
        }
    }

    /// Counts the total number of free blocks in this bitmap.
    pub fn free_count(&self) -> u64 {
        (self.bits[0].count_ones() + self.bits[1].count_ones()) as u64
    }

    /// Finds the first run of `count` consecutive free blocks, returning the
    /// offset of the first block or `None` if no such run exists.
    pub fn find_run(&self, count: usize) -> Option<usize> {
        let mut run_start = 0usize;
        let mut run_len = 0usize;
        for i in 0..BITMAP_BITS {
            if self.is_free(i) {
                if run_len == 0 {
                    run_start = i;
                }
                run_len += 1;
                if run_len >= count {
                    return Some(run_start);
                }
            } else {
                run_len = 0;
            }
        }
        None
    }
}

// ── FreeSpaceCluster ──────────────────────────────────────────────────────────

/// A pre-reserved cluster of contiguous free blocks.
#[derive(Debug, Clone, Copy, Default)]
pub struct FreeSpaceCluster {
    /// Logical start block of the cluster.
    pub start: u64,
    /// Total blocks in the cluster.
    pub len: u64,
    /// Next block within the cluster to hand out.
    pub cursor: u64,
    /// Whether this cluster is active.
    pub active: bool,
}

impl FreeSpaceCluster {
    /// Returns the number of blocks remaining in the cluster.
    pub const fn remaining(&self) -> u64 {
        if self.cursor < self.start + self.len {
            self.start + self.len - self.cursor
        } else {
            0
        }
    }

    /// Allocates `count` blocks from the cluster.
    ///
    /// Returns the starting block or [`Error::WouldBlock`] if the cluster is
    /// exhausted.
    pub fn alloc(&mut self, count: u64) -> Result<u64> {
        if self.remaining() < count {
            return Err(Error::WouldBlock);
        }
        let start = self.cursor;
        self.cursor += count;
        Ok(start)
    }
}

// ── BlockGroupFreeSpace ───────────────────────────────────────────────────────

/// Free space cache for a single Btrfs block group.
///
/// Manages both extent-based and bitmap-based free space entries together with
/// a small set of pre-allocated clusters.
pub struct BlockGroupFreeSpace {
    /// Logical start of the block group.
    pub bg_start: u64,
    /// Total capacity of the block group (blocks).
    pub bg_len: u64,
    /// Extent-based free entries, sorted by `start`.
    extents: [FreeSpaceExtent; MAX_EXTENT_ENTRIES],
    /// Number of active extent entries.
    extent_count: usize,
    /// Bitmap-based free entries.
    bitmaps: [BitmapEntry; MAX_BITMAP_ENTRIES],
    /// Number of active bitmap entries.
    bitmap_count: usize,
    /// Active clusters.
    clusters: [FreeSpaceCluster; MAX_CLUSTERS],
    /// Total tracked free blocks (extents + bitmaps).
    free_total: u64,
    /// Generation counter incremented on every cache modification.
    generation: u64,
}

impl Default for BlockGroupFreeSpace {
    fn default() -> Self {
        Self {
            bg_start: 0,
            bg_len: 0,
            extents: [FreeSpaceExtent::default(); MAX_EXTENT_ENTRIES],
            extent_count: 0,
            bitmaps: [BitmapEntry::default(); MAX_BITMAP_ENTRIES],
            bitmap_count: 0,
            clusters: [FreeSpaceCluster::default(); MAX_CLUSTERS],
            free_total: 0,
            generation: 0,
        }
    }
}

impl BlockGroupFreeSpace {
    /// Creates a new, fully-free cache for a block group of `len` blocks
    /// starting at logical address `start`.
    pub fn new(start: u64, len: u64) -> Self {
        let mut cache = Self {
            bg_start: start,
            bg_len: len,
            extents: [FreeSpaceExtent::default(); MAX_EXTENT_ENTRIES],
            extent_count: 0,
            bitmaps: [BitmapEntry::default(); MAX_BITMAP_ENTRIES],
            bitmap_count: 0,
            clusters: [FreeSpaceCluster::default(); MAX_CLUSTERS],
            free_total: 0,
            generation: 0,
        };
        // Add the whole group as one free extent.
        let _ = cache.add_free_extent(start, len);
        cache
    }

    /// Returns the total number of free blocks tracked.
    pub const fn free_total(&self) -> u64 {
        self.free_total
    }

    /// Returns the current generation counter.
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    // ── Extent operations ─────────────────────────────────────────────────────

    /// Adds a free extent `[start, start+len)` to the cache.
    ///
    /// Adjacent extents are merged automatically.
    pub fn add_free_extent(&mut self, start: u64, len: u64) -> Result<()> {
        if len == 0 {
            return Ok(());
        }
        // Try to merge with an existing extent.
        for i in 0..self.extent_count {
            let e = &mut self.extents[i];
            if !e.active {
                continue;
            }
            if e.end() == start {
                e.len += len;
                self.free_total += len;
                self.generation += 1;
                return Ok(());
            }
            if start + len == e.start {
                e.start = start;
                e.len += len;
                self.free_total += len;
                self.generation += 1;
                return Ok(());
            }
        }
        // No merge possible — insert new slot.
        if self.extent_count >= MAX_EXTENT_ENTRIES {
            return Err(Error::OutOfMemory);
        }
        self.extents[self.extent_count] = FreeSpaceExtent {
            start,
            len,
            active: true,
        };
        self.extent_count += 1;
        self.free_total += len;
        self.generation += 1;
        self.sort_extents();
        Ok(())
    }

    /// Removes (allocates) `[start, start+len)` from the free space cache.
    ///
    /// The target range must be fully covered by one or more free extents.
    /// Returns [`Error::NotFound`] if the range is not free.
    pub fn remove_free_extent(&mut self, start: u64, len: u64) -> Result<()> {
        if len == 0 {
            return Ok(());
        }
        let end = start + len;
        let pos = self.extents[..self.extent_count]
            .iter()
            .position(|e| e.active && e.start <= start && e.end() >= end)
            .ok_or(Error::NotFound)?;

        let e_start = self.extents[pos].start;
        let e_len = self.extents[pos].len;
        let e_end = e_start + e_len;

        self.free_total = self.free_total.saturating_sub(len);
        self.generation += 1;

        if e_start == start && e_end == end {
            // Exact match — remove entry.
            self.extents[pos] = self.extents[self.extent_count - 1];
            self.extents[self.extent_count - 1] = FreeSpaceExtent::default();
            self.extent_count -= 1;
        } else if e_start == start {
            // Trim from left.
            self.extents[pos].start += len;
            self.extents[pos].len -= len;
        } else if e_end == end {
            // Trim from right.
            self.extents[pos].len -= len;
        } else {
            // Split.
            if self.extent_count >= MAX_EXTENT_ENTRIES {
                return Err(Error::OutOfMemory);
            }
            let right_start = end;
            let right_len = e_end - end;
            self.extents[pos].len = start - e_start;
            self.extents[self.extent_count] = FreeSpaceExtent {
                start: right_start,
                len: right_len,
                active: true,
            };
            self.extent_count += 1;
        }
        Ok(())
    }

    // ── Bitmap operations ─────────────────────────────────────────────────────

    /// Adds free space in the bitmap layer for the range `[start, start+len)`.
    pub fn add_free_bitmap(&mut self, start: u64, len: u64) -> Result<()> {
        let bm_start = start & !(BITMAP_BITS as u64 - 1);
        let bm_idx = self.find_or_create_bitmap(bm_start)?;
        let offset = (start - self.bitmaps[bm_idx].start) as usize;
        for i in 0..(len as usize).min(BITMAP_BITS - offset) {
            self.bitmaps[bm_idx].mark_free(offset + i);
        }
        self.free_total += len;
        self.generation += 1;
        Ok(())
    }

    /// Allocates `count` blocks from the bitmap layer.
    ///
    /// Returns the logical start block of the allocated range or
    /// [`Error::NotFound`] if no sufficient run exists.
    pub fn alloc_from_bitmap(&mut self, count: usize) -> Result<u64> {
        for i in 0..self.bitmap_count {
            if !self.bitmaps[i].active {
                continue;
            }
            if let Some(offset) = self.bitmaps[i].find_run(count) {
                let start = self.bitmaps[i].start + offset as u64;
                for j in 0..count {
                    self.bitmaps[i].mark_alloc(offset + j);
                }
                self.free_total = self.free_total.saturating_sub(count as u64);
                self.generation += 1;
                return Ok(start);
            }
        }
        Err(Error::NotFound)
    }

    // ── Best-fit allocation ───────────────────────────────────────────────────

    /// Finds the smallest free extent that is at least `count` blocks long
    /// (best-fit strategy) and removes it from the cache.
    ///
    /// Returns the logical start block of the allocated region.
    pub fn alloc_best_fit(&mut self, count: u64) -> Result<u64> {
        let mut best: Option<usize> = None;
        for i in 0..self.extent_count {
            if !self.extents[i].active || self.extents[i].len < count {
                continue;
            }
            match best {
                None => best = Some(i),
                Some(b) if self.extents[i].len < self.extents[b].len => best = Some(i),
                _ => {}
            }
        }
        let idx = best.ok_or(Error::NotFound)?;
        let start = self.extents[idx].start;
        self.remove_free_extent(start, count)?;
        Ok(start)
    }

    // ── Cluster allocation ────────────────────────────────────────────────────

    /// Reserves a cluster of `count` blocks from the extent pool.
    ///
    /// Stores the cluster internally and returns its index.
    pub fn alloc_cluster(&mut self, count: u64) -> Result<usize> {
        if count < CLUSTER_MIN_BLOCKS {
            return Err(Error::InvalidArgument);
        }
        let free_slot = self
            .clusters
            .iter()
            .position(|c| !c.active)
            .ok_or(Error::OutOfMemory)?;
        let start = self.alloc_best_fit(count)?;
        self.clusters[free_slot] = FreeSpaceCluster {
            start,
            len: count,
            cursor: start,
            active: true,
        };
        Ok(free_slot)
    }

    /// Allocates `count` blocks from the cluster identified by `cluster_idx`.
    pub fn alloc_from_cluster(&mut self, cluster_idx: usize, count: u64) -> Result<u64> {
        if cluster_idx >= MAX_CLUSTERS {
            return Err(Error::InvalidArgument);
        }
        let cluster = &mut self.clusters[cluster_idx];
        if !cluster.active {
            return Err(Error::NotFound);
        }
        let result = cluster.alloc(count)?;
        if cluster.remaining() == 0 {
            cluster.active = false;
        }
        Ok(result)
    }

    /// Returns a reference to the cluster at `index`.
    pub fn cluster(&self, index: usize) -> Option<&FreeSpaceCluster> {
        self.clusters.get(index).filter(|c| c.active)
    }

    // ── Free space tree (cache v2) lookup ─────────────────────────────────────

    /// Looks up whether any free space is available starting at or after
    /// `search_start`. Returns the logical start of the first free extent
    /// at or after `search_start`, or [`Error::NotFound`].
    pub fn lookup_free_space_tree(&self, search_start: u64) -> Result<u64> {
        let mut best: Option<u64> = None;
        for e in &self.extents[..self.extent_count] {
            if !e.active {
                continue;
            }
            if e.end() > search_start {
                let start = e.start.max(search_start);
                match best {
                    None => best = Some(start),
                    Some(b) if start < b => best = Some(start),
                    _ => {}
                }
            }
        }
        best.ok_or(Error::NotFound)
    }

    // ── Private helpers ───────────────────────────────────────────────────────

    /// Sorts the extent table by `start` (insertion sort; table is small).
    fn sort_extents(&mut self) {
        for i in 1..self.extent_count {
            let mut j = i;
            while j > 0 && self.extents[j - 1].start > self.extents[j].start {
                self.extents.swap(j - 1, j);
                j -= 1;
            }
        }
    }

    /// Finds or creates a bitmap entry whose `start` equals `bm_start`.
    fn find_or_create_bitmap(&mut self, bm_start: u64) -> Result<usize> {
        if let Some(i) = self.bitmaps[..self.bitmap_count]
            .iter()
            .position(|b| b.active && b.start == bm_start)
        {
            return Ok(i);
        }
        if self.bitmap_count >= MAX_BITMAP_ENTRIES {
            return Err(Error::OutOfMemory);
        }
        let idx = self.bitmap_count;
        self.bitmaps[idx] = BitmapEntry {
            start: bm_start,
            bits: [0u64; 2],
            active: true,
        };
        self.bitmap_count += 1;
        Ok(idx)
    }
}
