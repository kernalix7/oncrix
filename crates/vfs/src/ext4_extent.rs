// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Ext4 extent tree operations.
//!
//! Implements the in-memory representation of ext4 extent trees and the
//! core algorithms: lookup, insert, split, and merge.  The extent tree
//! replaces the old block-map scheme and allows a single extent to describe
//! a contiguous run of up to 2^15 blocks.

use oncrix_lib::{Error, Result};

/// Maximum depth of an ext4 extent tree (0 = leaf node in the inode itself).
pub const EXT4_EXTENT_MAX_DEPTH: usize = 5;

/// Maximum number of extents per leaf node stored in this module.
pub const EXT4_EXTENTS_PER_BLOCK: usize = 340;

/// Ext4 extent header magic.
pub const EXT4_EXT_MAGIC: u16 = 0xf30a;

/// On-disk ext4 extent header.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct Ext4ExtentHeader {
    /// Magic number `EXT4_EXT_MAGIC`.
    pub magic: u16,
    /// Number of valid entries following the header.
    pub entries: u16,
    /// Maximum number of entries that can follow this header.
    pub max_entries: u16,
    /// Depth of this node in the tree (0 = leaf).
    pub depth: u16,
    /// Generation number (used by NFS).
    pub generation: u32,
}

impl Ext4ExtentHeader {
    /// Create a leaf-node header.
    pub fn leaf(max_entries: u16, generation: u32) -> Self {
        Self {
            magic: EXT4_EXT_MAGIC,
            entries: 0,
            max_entries,
            depth: 0,
            generation,
        }
    }

    /// Create an internal-node header at the given depth.
    pub fn internal(depth: u16, max_entries: u16, generation: u32) -> Self {
        Self {
            magic: EXT4_EXT_MAGIC,
            entries: 0,
            max_entries,
            depth,
            generation,
        }
    }

    /// Validate the header magic.
    pub fn is_valid(&self) -> bool {
        self.magic == EXT4_EXT_MAGIC
    }
}

/// A single ext4 leaf extent: maps logical blocks [block … block+len-1]
/// to physical blocks [start_hi:start_lo … ].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct Ext4Extent {
    /// First logical block covered by this extent.
    pub block: u32,
    /// Number of blocks: low 15 bits = length; bit 15 = initialized flag.
    pub len: u16,
    /// High 16 bits of the physical start block.
    pub start_hi: u16,
    /// Low 32 bits of the physical start block.
    pub start_lo: u32,
}

impl Ext4Extent {
    /// Create a new initialized extent.
    pub fn new(block: u32, len: u16, phys: u64) -> Self {
        Self {
            block,
            len: len & 0x7fff, // bit 15 = 0 → initialized
            start_hi: ((phys >> 32) as u16),
            start_lo: (phys & 0xffff_ffff) as u32,
        }
    }

    /// Physical start block (48-bit).
    pub fn phys_block(&self) -> u64 {
        ((self.start_hi as u64) << 32) | (self.start_lo as u64)
    }

    /// Number of blocks in this extent (mask off uninitialized bit).
    pub fn block_count(&self) -> u16 {
        self.len & 0x7fff
    }

    /// Whether this extent is initialized (not pre-allocated).
    pub fn is_initialized(&self) -> bool {
        self.len & 0x8000 == 0
    }

    /// Last logical block covered by this extent (inclusive).
    pub fn last_block(&self) -> u32 {
        self.block + self.block_count() as u32 - 1
    }

    /// Whether the given logical block falls within this extent.
    pub fn contains(&self, lblock: u32) -> bool {
        lblock >= self.block && lblock <= self.last_block()
    }
}

/// Internal-node index entry pointing to a child extent block.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct Ext4ExtentIdx {
    /// First logical block covered by the sub-tree rooted at this index.
    pub block: u32,
    /// Low 32 bits of the child physical block number.
    pub leaf_lo: u32,
    /// High 16 bits of the child physical block number.
    pub leaf_hi: u16,
    pub _unused: u16,
}

impl Ext4ExtentIdx {
    /// Physical block number of the child node.
    pub fn child_block(&self) -> u64 {
        ((self.leaf_hi as u64) << 32) | (self.leaf_lo as u64)
    }
}

/// In-memory extent node (leaf or internal).
pub struct ExtentNode {
    pub header: Ext4ExtentHeader,
    pub extents: [Ext4Extent; EXT4_EXTENTS_PER_BLOCK],
}

impl ExtentNode {
    /// Create an empty leaf node.
    pub fn new_leaf(generation: u32) -> Self {
        Self {
            header: Ext4ExtentHeader::leaf(EXT4_EXTENTS_PER_BLOCK as u16, generation),
            extents: [Ext4Extent {
                block: 0,
                len: 0,
                start_hi: 0,
                start_lo: 0,
            }; EXT4_EXTENTS_PER_BLOCK],
        }
    }

    /// Lookup the extent containing `lblock`.
    ///
    /// Returns the index into `extents` and the matching extent, or
    /// `Err(NotFound)` if `lblock` is not mapped.
    pub fn lookup(&self, lblock: u32) -> Result<(usize, Ext4Extent)> {
        let count = self.header.entries as usize;
        // Binary search over sorted extents.
        let mut lo = 0usize;
        let mut hi = count;
        while lo < hi {
            let mid = lo + (hi - lo) / 2;
            if self.extents[mid].block > lblock {
                hi = mid;
            } else {
                lo = mid + 1;
            }
        }
        // `lo` is now the first index whose `.block > lblock`, so check lo-1.
        if lo == 0 {
            return Err(Error::NotFound);
        }
        let candidate = self.extents[lo - 1];
        if candidate.contains(lblock) {
            Ok((lo - 1, candidate))
        } else {
            Err(Error::NotFound)
        }
    }

    /// Insert a new extent into this leaf node in sorted order.
    ///
    /// Returns `Err(OutOfMemory)` if the node is full.
    pub fn insert(&mut self, ext: Ext4Extent) -> Result<()> {
        let count = self.header.entries as usize;
        if count >= EXT4_EXTENTS_PER_BLOCK {
            return Err(Error::OutOfMemory);
        }
        // Find insertion point.
        let pos = self.extents[..count].partition_point(|e| e.block < ext.block);
        // Shift right to make room.
        if pos < count {
            self.extents.copy_within(pos..count, pos + 1);
        }
        self.extents[pos] = ext;
        self.header.entries += 1;
        Ok(())
    }

    /// Remove the extent at index `idx`.
    pub fn remove(&mut self, idx: usize) -> Result<Ext4Extent> {
        let count = self.header.entries as usize;
        if idx >= count {
            return Err(Error::InvalidArgument);
        }
        let removed = self.extents[idx];
        self.extents.copy_within(idx + 1..count, idx);
        self.extents[count - 1] = Ext4Extent {
            block: 0,
            len: 0,
            start_hi: 0,
            start_lo: 0,
        };
        self.header.entries -= 1;
        Ok(removed)
    }

    /// Try to merge adjacent extents (combine if physically contiguous).
    ///
    /// Returns the number of merges performed.
    pub fn try_merge_adjacent(&mut self) -> usize {
        let mut merges = 0;
        let mut i = 0;
        let mut count = self.header.entries as usize;
        while i + 1 < count {
            let a = self.extents[i];
            let b = self.extents[i + 1];
            let a_phys_end = a.phys_block() + a.block_count() as u64;
            let adjacent_logical = b.block == a.block + a.block_count() as u32;
            let adjacent_phys = b.phys_block() == a_phys_end;
            let combined_len = a.block_count() as u32 + b.block_count() as u32;
            if adjacent_logical && adjacent_phys && combined_len <= 0x7fff {
                // Merge b into a.
                self.extents[i].len = combined_len as u16;
                self.extents.copy_within(i + 2..count, i + 1);
                self.extents[count - 1] = Ext4Extent {
                    block: 0,
                    len: 0,
                    start_hi: 0,
                    start_lo: 0,
                };
                count -= 1;
                self.header.entries -= 1;
                merges += 1;
            } else {
                i += 1;
            }
        }
        merges
    }

    /// Whether this node is a leaf.
    #[inline]
    pub fn is_leaf(&self) -> bool {
        self.header.depth == 0
    }

    /// Number of valid extents.
    #[inline]
    pub fn count(&self) -> usize {
        self.header.entries as usize
    }
}
