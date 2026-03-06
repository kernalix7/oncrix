// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! F2FS extent cache and on-disk extent tree.
//!
//! F2FS maintains a per-inode extent cache to avoid repeated node-page lookups
//! for contiguous logical block ranges.  This module implements the extent
//! record format, the LRU-eviction extent cache, and the on-disk extent-tree
//! node structures used for large files.

use oncrix_lib::{Error, Result};

/// F2FS block address.
pub type F2fsBlk = u32;

/// Logical file block.
pub type F2fsLblk = u32;

/// Sentinel block address (no allocation).
pub const F2FS_NULL_ADDR: F2fsBlk = 0;

/// Maximum number of extents in the in-memory extent cache.
pub const F2FS_EXTENT_CACHE_SIZE: usize = 128;

/// A single F2FS extent: maps [fofs, fofs+len) → [blkaddr, blkaddr+len).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct F2fsExtent {
    /// Logical file offset (in blocks).
    pub fofs: F2fsLblk,
    /// Physical block address.
    pub blkaddr: F2fsBlk,
    /// Length in blocks.
    pub len: u32,
}

impl F2fsExtent {
    /// Create a new extent.
    pub fn new(fofs: F2fsLblk, blkaddr: F2fsBlk, len: u32) -> Self {
        Self { fofs, blkaddr, len }
    }

    /// Last logical block in this extent (inclusive).
    pub fn last_fofs(&self) -> F2fsLblk {
        self.fofs + self.len - 1
    }

    /// Whether `lblock` is within this extent.
    pub fn contains(&self, lblock: F2fsLblk) -> bool {
        lblock >= self.fofs && lblock <= self.last_fofs()
    }

    /// Physical block for a given logical block.
    pub fn phys_block(&self, lblock: F2fsLblk) -> Option<F2fsBlk> {
        if self.contains(lblock) {
            Some(self.blkaddr + (lblock - self.fofs))
        } else {
            None
        }
    }

    /// Whether this extent is adjacent to `other` (and they can be merged).
    pub fn is_adjacent_to(&self, other: &Self) -> bool {
        self.last_fofs() + 1 == other.fofs && self.blkaddr + self.len == other.blkaddr
    }
}

/// F2FS extent cache entry (extent + LRU age).
#[derive(Debug, Clone, Copy)]
struct CacheEntry {
    ext: F2fsExtent,
    /// Access timestamp (logical counter; higher = more recent).
    age: u64,
}

/// In-memory extent cache for one F2FS inode.
pub struct F2fsExtentCache {
    entries: [Option<CacheEntry>; F2FS_EXTENT_CACHE_SIZE],
    count: usize,
    /// Monotonic access counter.
    clock: u64,
    /// Total cache hits.
    pub hits: u64,
    /// Total cache misses.
    pub misses: u64,
}

impl F2fsExtentCache {
    /// Create an empty cache.
    pub const fn new() -> Self {
        Self {
            entries: [const { None }; F2FS_EXTENT_CACHE_SIZE],
            count: 0,
            clock: 0,
            hits: 0,
            misses: 0,
        }
    }

    /// Look up `lblock` in the cache.
    pub fn lookup(&mut self, lblock: F2fsLblk) -> Option<F2fsExtent> {
        self.clock += 1;
        let now = self.clock;
        for slot in &mut self.entries[..self.count] {
            if let Some(entry) = slot.as_mut() {
                if entry.ext.contains(lblock) {
                    entry.age = now;
                    self.hits += 1;
                    return Some(entry.ext);
                }
            }
        }
        self.misses += 1;
        None
    }

    /// Insert an extent into the cache, evicting the LRU entry if full.
    pub fn insert(&mut self, ext: F2fsExtent) {
        self.clock += 1;
        let now = self.clock;
        // Check for an existing overlapping entry to update.
        for slot in &mut self.entries[..self.count] {
            if let Some(entry) = slot.as_mut() {
                if entry.ext.fofs == ext.fofs {
                    *entry = CacheEntry { ext, age: now };
                    return;
                }
            }
        }
        if self.count < F2FS_EXTENT_CACHE_SIZE {
            self.entries[self.count] = Some(CacheEntry { ext, age: now });
            self.count += 1;
        } else {
            // Evict LRU.
            let mut lru_idx = 0;
            let mut lru_age = u64::MAX;
            for (i, slot) in self.entries.iter().enumerate() {
                if let Some(e) = slot {
                    if e.age < lru_age {
                        lru_age = e.age;
                        lru_idx = i;
                    }
                }
            }
            self.entries[lru_idx] = Some(CacheEntry { ext, age: now });
        }
    }

    /// Invalidate all extents that overlap the range [start, start+len).
    pub fn invalidate_range(&mut self, start: F2fsLblk, len: u32) {
        let end = start + len;
        for slot in &mut self.entries[..self.count] {
            if let Some(entry) = slot.as_ref() {
                if entry.ext.fofs < end && entry.ext.last_fofs() >= start {
                    *slot = None;
                }
            }
        }
        // Compact.
        let mut write = 0;
        for read in 0..self.count {
            if self.entries[read].is_some() {
                if read != write {
                    self.entries[write] = self.entries[read].take();
                }
                write += 1;
            }
        }
        self.count = write;
    }

    /// Number of cached extents.
    pub fn count(&self) -> usize {
        self.count
    }
}

impl Default for F2fsExtentCache {
    fn default() -> Self {
        Self::new()
    }
}

/// On-disk F2FS extent tree node (used for very large files).
///
/// Each node covers a range of logical blocks and is stored in a node page.
pub const F2FS_ET_ENTRIES: usize = 126;

/// On-disk extent tree internal node entry.
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct F2fsEtEntry {
    pub fofs: F2fsLblk,
    pub blkaddr: F2fsBlk,
    pub len: u32,
}

/// On-disk extent tree node.
pub struct F2fsEtNode {
    pub entries: [F2fsEtEntry; F2FS_ET_ENTRIES],
    pub count: u16,
}

impl F2fsEtNode {
    /// Create an empty extent tree node.
    pub fn new() -> Self {
        Self {
            entries: [F2fsEtEntry {
                fofs: 0,
                blkaddr: 0,
                len: 0,
            }; F2FS_ET_ENTRIES],
            count: 0,
        }
    }

    /// Binary search for `lblock`.
    pub fn lookup(&self, lblock: F2fsLblk) -> Option<F2fsExtent> {
        let count = self.count as usize;
        let mut lo = 0;
        let mut hi = count;
        while lo < hi {
            let mid = lo + (hi - lo) / 2;
            if self.entries[mid].fofs > lblock {
                hi = mid;
            } else {
                lo = mid + 1;
            }
        }
        if lo == 0 {
            return None;
        }
        let e = &self.entries[lo - 1];
        let ext = F2fsExtent {
            fofs: e.fofs,
            blkaddr: e.blkaddr,
            len: e.len,
        };
        if ext.contains(lblock) {
            Some(ext)
        } else {
            None
        }
    }

    /// Insert an extent in sorted order.
    pub fn insert(&mut self, ext: F2fsExtent) -> Result<()> {
        let count = self.count as usize;
        if count >= F2FS_ET_ENTRIES {
            return Err(Error::OutOfMemory);
        }
        let pos = self.entries[..count].partition_point(|e| e.fofs < ext.fofs);
        if pos < count {
            self.entries.copy_within(pos..count, pos + 1);
        }
        self.entries[pos] = F2fsEtEntry {
            fofs: ext.fofs,
            blkaddr: ext.blkaddr,
            len: ext.len,
        };
        self.count += 1;
        Ok(())
    }
}

impl Default for F2fsEtNode {
    fn default() -> Self {
        Self::new()
    }
}
