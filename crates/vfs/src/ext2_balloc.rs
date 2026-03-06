// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! ext2 block allocator.
//!
//! Implements goal-oriented block allocation and deallocation for ext2/ext3.
//! Blocks are organised into block groups; each group has a bitmap and a
//! group descriptor tracking free block counts.
//!
//! # Design
//!
//! - [`BlockGroupDesc`] — in-memory group descriptor
//! - [`BlockBitmap`] — per-group block availability bitmap (512 blocks/group)
//! - [`Ext2Balloc`] — allocator state: group descriptors + bitmaps
//! - Goal-oriented allocation: tries to allocate near the goal block first
//!
//! # References
//!
//! - Linux `fs/ext2/balloc.c`
//! - ext2 disk layout specification

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum block groups supported.
pub const MAX_BLOCK_GROUPS: usize = 128;

/// Blocks per block group.
pub const BLOCKS_PER_GROUP: usize = 512;

/// Bitmap words per group (512 bits / 64 bits per u64).
pub const BITMAP_WORDS: usize = BLOCKS_PER_GROUP / 64;

/// Reserved blocks percentage (simplification: 5% reserved).
pub const RESERVED_PERCENT: u64 = 5;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// In-memory block group descriptor.
#[derive(Debug, Clone, Copy, Default)]
pub struct BlockGroupDesc {
    /// Block number of the block bitmap.
    pub block_bitmap: u64,
    /// Block number of the inode bitmap.
    pub inode_bitmap: u64,
    /// Block number of the inode table start.
    pub inode_table: u64,
    /// Number of free blocks in this group.
    pub free_blocks_count: u32,
    /// Number of free inodes in this group.
    pub free_inodes_count: u32,
    /// Number of directories in this group.
    pub used_dirs_count: u32,
    /// Padding / flags.
    pub flags: u16,
}

/// Block availability bitmap for a single block group.
#[derive(Clone, Copy)]
pub struct BlockBitmap {
    /// Each bit represents one block; 1 = allocated, 0 = free.
    pub words: [u64; BITMAP_WORDS],
}

impl BlockBitmap {
    /// Create an all-free bitmap.
    pub const fn free() -> Self {
        Self {
            words: [0u64; BITMAP_WORDS],
        }
    }

    /// Test whether block `bit` (0-based within group) is allocated.
    pub fn test(&self, bit: usize) -> bool {
        debug_assert!(bit < BLOCKS_PER_GROUP);
        let word = bit / 64;
        let offset = bit % 64;
        self.words[word] & (1u64 << offset) != 0
    }

    /// Set block `bit` as allocated.
    pub fn set(&mut self, bit: usize) {
        debug_assert!(bit < BLOCKS_PER_GROUP);
        let word = bit / 64;
        let offset = bit % 64;
        self.words[word] |= 1u64 << offset;
    }

    /// Clear block `bit` as free.
    pub fn clear(&mut self, bit: usize) {
        debug_assert!(bit < BLOCKS_PER_GROUP);
        let word = bit / 64;
        let offset = bit % 64;
        self.words[word] &= !(1u64 << offset);
    }

    /// Find the first free bit at or after `start`. Returns `None` if full.
    pub fn find_free_from(&self, start: usize) -> Option<usize> {
        let start_word = start / 64;
        for w in start_word..BITMAP_WORDS {
            let free_mask = !self.words[w];
            if free_mask == 0 {
                continue;
            }
            let bit_in_word = free_mask.trailing_zeros() as usize;
            let candidate = w * 64 + bit_in_word;
            if candidate >= start && candidate < BLOCKS_PER_GROUP {
                return Some(candidate);
            }
            // Bit may be before `start` in first word.
            if w == start_word {
                let masked = free_mask & !((1u64 << (start % 64)) - 1);
                if masked != 0 {
                    return Some(w * 64 + masked.trailing_zeros() as usize);
                }
            }
        }
        None
    }

    /// Count the number of free blocks in this bitmap.
    pub fn free_count(&self) -> u32 {
        let mut count = 0u32;
        for &w in &self.words {
            count += (!w).count_ones();
        }
        count
    }
}

/// The ext2 block allocator.
pub struct Ext2Balloc {
    /// Group descriptors.
    pub groups: [BlockGroupDesc; MAX_BLOCK_GROUPS],
    /// Per-group block bitmaps.
    pub bitmaps: [BlockBitmap; MAX_BLOCK_GROUPS],
    /// Number of active block groups.
    pub group_count: usize,
    /// Total blocks in the filesystem.
    pub total_blocks: u64,
    /// Total free blocks.
    pub free_blocks: u64,
    /// Reserved block count (not given to non-root).
    pub reserved_blocks: u64,
    /// Blocks per group.
    pub blocks_per_group: u64,
    /// First data block (usually 0 for 4K blocks, 1 for 1K blocks).
    pub first_data_block: u64,
}

impl Ext2Balloc {
    /// Create a new allocator for `group_count` block groups.
    pub fn new(group_count: usize, blocks_per_group: u64, first_data_block: u64) -> Result<Self> {
        if group_count > MAX_BLOCK_GROUPS || group_count == 0 {
            return Err(Error::InvalidArgument);
        }
        let total_blocks = group_count as u64 * blocks_per_group;
        let reserved_blocks = total_blocks * RESERVED_PERCENT / 100;
        let mut alloc = Self {
            groups: [BlockGroupDesc::default(); MAX_BLOCK_GROUPS],
            bitmaps: [BlockBitmap::free(); MAX_BLOCK_GROUPS],
            group_count,
            total_blocks,
            free_blocks: total_blocks - reserved_blocks,
            reserved_blocks,
            blocks_per_group,
            first_data_block,
        };
        // Initialise group descriptors.
        for i in 0..group_count {
            alloc.groups[i].free_blocks_count = blocks_per_group as u32;
            alloc.groups[i].block_bitmap = first_data_block + i as u64 * blocks_per_group;
            alloc.groups[i].inode_table = first_data_block + i as u64 * blocks_per_group + 1;
        }
        Ok(alloc)
    }
}

// ---------------------------------------------------------------------------
// Operations
// ---------------------------------------------------------------------------

/// Allocate a single block, trying to allocate near `goal`.
///
/// Returns the absolute block number, or `Err(OutOfMemory)`.
pub fn alloc_block(balloc: &mut Ext2Balloc, goal: u64) -> Result<u64> {
    if balloc.free_blocks == 0 {
        return Err(Error::OutOfMemory);
    }
    // Determine goal group and offset within group.
    let goal_group = ((goal - balloc.first_data_block) / balloc.blocks_per_group) as usize;
    let goal_offset = ((goal - balloc.first_data_block) % balloc.blocks_per_group) as usize;

    // Try goal group first.
    let groups_to_try = [goal_group];
    for g in groups_to_try.iter().copied().chain(0..balloc.group_count) {
        if g >= balloc.group_count {
            continue;
        }
        if balloc.groups[g].free_blocks_count == 0 {
            continue;
        }
        let start = if g == goal_group { goal_offset } else { 0 };
        if let Some(bit) = balloc.bitmaps[g].find_free_from(start) {
            balloc.bitmaps[g].set(bit);
            balloc.groups[g].free_blocks_count =
                balloc.groups[g].free_blocks_count.saturating_sub(1);
            balloc.free_blocks = balloc.free_blocks.saturating_sub(1);
            let block = balloc.first_data_block + g as u64 * balloc.blocks_per_group + bit as u64;
            return Ok(block);
        }
    }

    // Linear scan over all groups.
    for g in 0..balloc.group_count {
        if balloc.groups[g].free_blocks_count == 0 {
            continue;
        }
        if let Some(bit) = balloc.bitmaps[g].find_free_from(0) {
            balloc.bitmaps[g].set(bit);
            balloc.groups[g].free_blocks_count =
                balloc.groups[g].free_blocks_count.saturating_sub(1);
            balloc.free_blocks = balloc.free_blocks.saturating_sub(1);
            let block = balloc.first_data_block + g as u64 * balloc.blocks_per_group + bit as u64;
            return Ok(block);
        }
    }

    Err(Error::OutOfMemory)
}

/// Allocate `count` contiguous blocks near `goal`.
///
/// Returns the starting block number of the allocated extent.
pub fn alloc_blocks(balloc: &mut Ext2Balloc, goal: u64, count: usize) -> Result<u64> {
    // Simple implementation: allocate one at a time from goal-region.
    // For simplicity, ensure they're all in the same group.
    if count == 0 {
        return Err(Error::InvalidArgument);
    }
    if balloc.free_blocks < count as u64 {
        return Err(Error::OutOfMemory);
    }
    let first = alloc_block(balloc, goal)?;
    for i in 1..count {
        let next = alloc_block(balloc, first + i as u64)?;
        if next != first + i as u64 {
            // Not contiguous — release and fail.
            let _ = free_block(balloc, next);
            for j in 0..i {
                let _ = free_block(balloc, first + j as u64);
            }
            return Err(Error::OutOfMemory);
        }
    }
    Ok(first)
}

/// Free a single block.
pub fn free_block(balloc: &mut Ext2Balloc, block: u64) -> Result<()> {
    if block < balloc.first_data_block {
        return Err(Error::InvalidArgument);
    }
    let offset = block - balloc.first_data_block;
    let group = (offset / balloc.blocks_per_group) as usize;
    let bit = (offset % balloc.blocks_per_group) as usize;

    if group >= balloc.group_count || bit >= BLOCKS_PER_GROUP {
        return Err(Error::InvalidArgument);
    }
    if !balloc.bitmaps[group].test(bit) {
        return Err(Error::InvalidArgument);
    }
    balloc.bitmaps[group].clear(bit);
    balloc.groups[group].free_blocks_count =
        balloc.groups[group].free_blocks_count.saturating_add(1);
    balloc.free_blocks = balloc.free_blocks.saturating_add(1);
    Ok(())
}

/// Reserve `count` blocks (subtract from free count without marking bitmap).
///
/// Used for metadata reservations.
pub fn reserve_blocks(balloc: &mut Ext2Balloc, count: u64) -> Result<()> {
    if balloc.free_blocks < count {
        return Err(Error::OutOfMemory);
    }
    balloc.free_blocks -= count;
    balloc.reserved_blocks += count;
    Ok(())
}

/// Unreserve `count` previously reserved blocks.
pub fn unreserve_blocks(balloc: &mut Ext2Balloc, count: u64) {
    let actual = count.min(balloc.reserved_blocks);
    balloc.reserved_blocks -= actual;
    balloc.free_blocks += actual;
}

/// Return the total number of free blocks.
pub fn free_block_count(balloc: &Ext2Balloc) -> u64 {
    balloc.free_blocks
}

/// Return the group that contains `block`.
pub fn block_group(balloc: &Ext2Balloc, block: u64) -> Option<usize> {
    if block < balloc.first_data_block {
        return None;
    }
    let offset = block - balloc.first_data_block;
    let group = (offset / balloc.blocks_per_group) as usize;
    if group < balloc.group_count {
        Some(group)
    } else {
        None
    }
}

/// Resync group descriptor free counts from bitmaps.
pub fn resync_group_descs(balloc: &mut Ext2Balloc) {
    for g in 0..balloc.group_count {
        balloc.groups[g].free_blocks_count = balloc.bitmaps[g].free_count();
    }
    balloc.free_blocks = balloc.groups[..balloc.group_count]
        .iter()
        .map(|g| g.free_blocks_count as u64)
        .sum();
}
