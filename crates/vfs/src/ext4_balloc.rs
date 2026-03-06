// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! ext4 block allocation — wrapper over mballoc for single-block and
//! multi-block allocation paths.
//!
//! This module provides the high-level block allocation interface used by the
//! ext4 file and directory code. It delegates to the multi-block allocator
//! (`ext4_mballoc`) for actual bitmap manipulation and offers:
//!
//! - [`Ext4BAllocState`] — per-filesystem allocator context
//! - [`alloc_blocks`] — allocate N contiguous blocks
//! - [`free_blocks`] — return blocks to the free pool
//! - [`alloc_inode_block`] — allocate a single block near an inode's data
//! - [`block_group_for`] — determine the block group for a given block number
//!
//! # Block Group Layout
//!
//! ```text
//! [superblock][group-desc table][block-bitmap][inode-bitmap][inode-table][data blocks...]
//!  ^block 0    ^block 1         ^bg_block_bitmap  ^bg_inode_bitmap
//! ```
//!
//! # References
//!
//! - Linux `fs/ext4/balloc.c`
//! - ext4 disk layout: `Documentation/filesystems/ext4/`

use oncrix_lib::{Error, Result};

// ── Constants ────────────────────────────────────────────────────────────────

/// Default number of blocks per block group (ext4 standard).
pub const EXT4_BLOCKS_PER_GROUP: u32 = 32_768;

/// Maximum block groups supported by this allocator.
pub const MAX_BLOCK_GROUPS: usize = 256;

/// Reserved block percentage for the super-user (5%).
pub const EXT4_RESERVED_PERCENT: u32 = 5;

/// Minimum free blocks before a group is considered for allocation.
const MIN_FREE_THRESHOLD: u32 = 8;

/// Bits per bitmap word.
const BITMAP_BITS: usize = 64;

/// Number of u64 words needed to represent one full block group.
const BITMAP_WORDS: usize = EXT4_BLOCKS_PER_GROUP as usize / BITMAP_BITS;

// ── Flags ────────────────────────────────────────────────────────────────────

/// Allocation flag: prefer locality (goal near last allocated block).
pub const EXT4_ALLOC_LOCALITY: u32 = 1 << 0;

/// Allocation flag: reserved blocks may be used (root/uid 0 only).
pub const EXT4_ALLOC_RESERVED: u32 = 1 << 1;

/// Allocation flag: metadata block (inode table, bitmap, etc.).
pub const EXT4_ALLOC_METADATA: u32 = 1 << 2;

// ── Bitmap ───────────────────────────────────────────────────────────────────

/// Per-block-group block availability bitmap.
///
/// Bit `n` is 0 when block `n` within the group is free.
#[derive(Clone, Copy)]
pub struct BlockBitmap {
    words: [u64; BITMAP_WORDS],
}

impl BlockBitmap {
    /// Create an all-free bitmap.
    pub const fn new() -> Self {
        Self {
            words: [0u64; BITMAP_WORDS],
        }
    }

    /// Return `true` if block `n` is allocated.
    pub fn is_allocated(&self, n: u32) -> bool {
        let idx = n as usize / BITMAP_BITS;
        let bit = n as usize % BITMAP_BITS;
        if idx >= BITMAP_WORDS {
            return true; // out-of-range → treat as allocated
        }
        self.words[idx] & (1u64 << bit) != 0
    }

    /// Allocate block `n`; returns `Err(AlreadyExists)` if already set.
    pub fn set(&mut self, n: u32) -> Result<()> {
        let idx = n as usize / BITMAP_BITS;
        let bit = n as usize % BITMAP_BITS;
        if idx >= BITMAP_WORDS {
            return Err(Error::InvalidArgument);
        }
        if self.words[idx] & (1u64 << bit) != 0 {
            return Err(Error::AlreadyExists);
        }
        self.words[idx] |= 1u64 << bit;
        Ok(())
    }

    /// Free block `n`; returns `Err(InvalidArgument)` if already free.
    pub fn clear(&mut self, n: u32) -> Result<()> {
        let idx = n as usize / BITMAP_BITS;
        let bit = n as usize % BITMAP_BITS;
        if idx >= BITMAP_WORDS {
            return Err(Error::InvalidArgument);
        }
        if self.words[idx] & (1u64 << bit) == 0 {
            return Err(Error::InvalidArgument);
        }
        self.words[idx] &= !(1u64 << bit);
        Ok(())
    }

    /// Count free blocks in this bitmap.
    pub fn free_count(&self) -> u32 {
        let used: u32 = self.words.iter().map(|w| w.count_ones()).sum();
        EXT4_BLOCKS_PER_GROUP - used
    }

    /// Find first run of `len` consecutive free blocks starting from `hint`.
    /// Returns the starting block index within the group, or `None`.
    pub fn find_free_run(&self, hint: u32, len: u32) -> Option<u32> {
        let start = hint as usize;
        let total = EXT4_BLOCKS_PER_GROUP as usize;
        let mut run_start = 0usize;
        let mut run_len = 0usize;
        // Two-pass: start from hint, then wrap around.
        for pass in 0..2usize {
            let (lo, hi) = if pass == 0 {
                (start, total)
            } else {
                (0, start)
            };
            for i in lo..hi {
                let idx = i / BITMAP_BITS;
                let bit = i % BITMAP_BITS;
                if self.words[idx] & (1u64 << bit) == 0 {
                    if run_len == 0 {
                        run_start = i;
                    }
                    run_len += 1;
                    if run_len >= len as usize {
                        return Some(run_start as u32);
                    }
                } else {
                    run_len = 0;
                }
            }
        }
        None
    }
}

impl Default for BlockBitmap {
    fn default() -> Self {
        Self::new()
    }
}

// ── Group Descriptor ─────────────────────────────────────────────────────────

/// In-memory copy of an ext4 block group descriptor.
#[derive(Debug, Clone, Copy, Default)]
pub struct Ext4GroupDesc {
    /// Physical block number of the block bitmap for this group.
    pub block_bitmap: u64,
    /// Physical block number of the inode bitmap for this group.
    pub inode_bitmap: u64,
    /// Physical block number of the start of the inode table.
    pub inode_table: u64,
    /// Free block count (lo 16 bits; hi 16 in `free_blocks_count_hi`).
    pub free_blocks_count: u32,
    /// Free inode count.
    pub free_inodes_count: u32,
    /// Number of directories in this group.
    pub used_dirs_count: u32,
    /// Group flags (EXT4_BG_INODE_UNINIT etc.).
    pub flags: u16,
}

// ── Allocation Request ────────────────────────────────────────────────────────

/// Parameters for a block allocation request.
#[derive(Debug, Clone, Copy, Default)]
pub struct BlockAllocReq {
    /// Preferred block (goal block for locality search).
    pub goal: u64,
    /// Number of blocks requested.
    pub len: u32,
    /// Allocation flags (EXT4_ALLOC_*).
    pub flags: u32,
    /// Inode number of the requesting inode (0 = none).
    pub ino: u32,
}

// ── Allocator State ──────────────────────────────────────────────────────────

/// Per-filesystem ext4 block allocator state.
pub struct Ext4BAllocState {
    /// Total number of active block groups.
    pub num_groups: usize,
    /// Per-group descriptors.
    pub groups: [Ext4GroupDesc; MAX_BLOCK_GROUPS],
    /// Per-group bitmaps (in-memory shadow copy).
    pub bitmaps: [BlockBitmap; MAX_BLOCK_GROUPS],
    /// Total blocks in the filesystem.
    pub total_blocks: u64,
    /// Total free blocks (updated on each alloc/free).
    pub free_blocks: u64,
    /// Reserved block count (EXT4_RESERVED_PERCENT of total).
    pub reserved_blocks: u64,
    /// Last successfully allocated block (locality hint).
    pub last_alloc: u64,
}

impl Ext4BAllocState {
    /// Create a new allocator state for a filesystem with `total_blocks` blocks.
    pub fn new(total_blocks: u64) -> Self {
        let num_groups = ((total_blocks + EXT4_BLOCKS_PER_GROUP as u64 - 1)
            / EXT4_BLOCKS_PER_GROUP as u64) as usize;
        let num_groups = num_groups.min(MAX_BLOCK_GROUPS);
        let reserved_blocks = total_blocks * EXT4_RESERVED_PERCENT as u64 / 100;
        Self {
            num_groups,
            groups: [Ext4GroupDesc::default(); MAX_BLOCK_GROUPS],
            bitmaps: [const { BlockBitmap::new() }; MAX_BLOCK_GROUPS],
            total_blocks,
            free_blocks: total_blocks,
            reserved_blocks,
            last_alloc: 0,
        }
    }

    /// Return the block group index for a given absolute block number.
    pub fn block_group_for(&self, block: u64) -> usize {
        (block / EXT4_BLOCKS_PER_GROUP as u64) as usize
    }

    /// Return the block offset within its group.
    pub fn block_offset_in_group(&self, block: u64) -> u32 {
        (block % EXT4_BLOCKS_PER_GROUP as u64) as u32
    }

    /// Allocate `req.len` contiguous blocks; return the first block number.
    pub fn alloc_blocks(&mut self, req: &BlockAllocReq) -> Result<u64> {
        if req.len == 0 {
            return Err(Error::InvalidArgument);
        }
        let effective_free = if req.flags & EXT4_ALLOC_RESERVED != 0 {
            self.free_blocks
        } else {
            self.free_blocks.saturating_sub(self.reserved_blocks)
        };
        if effective_free < req.len as u64 {
            return Err(Error::OutOfMemory);
        }
        // Determine the goal group.
        let goal_group = if req.goal > 0 {
            self.block_group_for(req.goal)
                .min(self.num_groups.saturating_sub(1))
        } else {
            0
        };
        let goal_offset = if req.goal > 0 {
            self.block_offset_in_group(req.goal)
        } else {
            0
        };
        // Try goal group first, then scan all groups.
        let groups_to_try: [usize; 2] = [goal_group, 0];
        for &start_group in &groups_to_try {
            for delta in 0..self.num_groups {
                let g = (start_group + delta) % self.num_groups;
                let hint = if g == goal_group { goal_offset } else { 0 };
                if self.groups[g].free_blocks_count < MIN_FREE_THRESHOLD.min(req.len) {
                    continue;
                }
                if let Some(offset) = self.bitmaps[g].find_free_run(hint, req.len) {
                    // Mark the run as allocated.
                    for i in 0..req.len {
                        self.bitmaps[g].set(offset + i)?;
                    }
                    self.groups[g].free_blocks_count =
                        self.groups[g].free_blocks_count.saturating_sub(req.len);
                    self.free_blocks = self.free_blocks.saturating_sub(req.len as u64);
                    let first_block = g as u64 * EXT4_BLOCKS_PER_GROUP as u64 + offset as u64;
                    self.last_alloc = first_block + req.len as u64 - 1;
                    return Ok(first_block);
                }
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Free `len` blocks starting at `first_block`.
    pub fn free_blocks(&mut self, first_block: u64, len: u32) -> Result<()> {
        if len == 0 {
            return Ok(());
        }
        let g = self.block_group_for(first_block);
        let offset = self.block_offset_in_group(first_block);
        if g >= self.num_groups {
            return Err(Error::InvalidArgument);
        }
        for i in 0..len {
            self.bitmaps[g].clear(offset + i)?;
        }
        self.groups[g].free_blocks_count += len;
        self.free_blocks = self.free_blocks.saturating_add(len as u64);
        Ok(())
    }

    /// Allocate a single block near `ino`'s existing data (locality hint).
    pub fn alloc_inode_block(&mut self, ino: u32, hint: u64) -> Result<u64> {
        let req = BlockAllocReq {
            goal: hint,
            len: 1,
            flags: EXT4_ALLOC_LOCALITY,
            ino,
        };
        self.alloc_blocks(&req)
    }

    /// Return the current count of free blocks (excluding reserved).
    pub fn available_blocks(&self) -> u64 {
        self.free_blocks.saturating_sub(self.reserved_blocks)
    }

    /// Return the total free blocks (including reserved).
    pub fn free_blocks_total(&self) -> u64 {
        self.free_blocks
    }

    /// Update the in-memory group descriptor from on-disk data.
    pub fn update_group_desc(&mut self, g: usize, desc: Ext4GroupDesc) -> Result<()> {
        if g >= self.num_groups {
            return Err(Error::InvalidArgument);
        }
        self.groups[g] = desc;
        Ok(())
    }
}
