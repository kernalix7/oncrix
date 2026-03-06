// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! ext4 online filesystem resize support.
//!
//! Implements online resize for ext4 filesystems, allowing the filesystem
//! to grow while mounted. Supports:
//!
//! - Growing the group descriptor table (meta-block groups)
//! - Extending the last block group's bitmap
//! - Adding new block groups to the filesystem
//! - Updating the superblock block count
//!
//! # Reference
//!
//! Linux `fs/ext4/resize.c` and ext4 disk layout documentation.

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum block groups supported.
const MAX_BLOCK_GROUPS: usize = 256;

/// Blocks per group (default).
const BLOCKS_PER_GROUP: u64 = 32768;

/// Size of a block group descriptor (64-byte for 64-bit feature).
const GDT_ENTRY_SIZE: usize = 64;

/// Maximum number of reserved GDT blocks for online resize.
const MAX_RESERVED_GDT: u32 = 1024;

/// Superblock magic for ext4.
const EXT4_MAGIC: u16 = 0xEF53;

/// Maximum resize operations in one call.
const MAX_NEW_GROUPS: usize = 64;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Information about a block group.
#[derive(Debug, Clone, Copy)]
pub struct BlockGroupInfo {
    /// First block in this group.
    pub first_block: u64,
    /// Block bitmap block number.
    pub block_bitmap: u64,
    /// Inode bitmap block number.
    pub inode_bitmap: u64,
    /// Inode table starting block.
    pub inode_table: u64,
    /// Number of free blocks.
    pub free_blocks: u32,
    /// Number of free inodes.
    pub free_inodes: u32,
    /// Flags (initialized, inode uninit, etc.).
    pub flags: u16,
}

impl BlockGroupInfo {
    /// Creates a new uninitialized block group.
    pub const fn new(first_block: u64) -> Self {
        Self {
            first_block,
            block_bitmap: 0,
            inode_bitmap: 0,
            inode_table: 0,
            free_blocks: 0,
            free_inodes: 0,
            flags: 0,
        }
    }

    /// Returns whether this group has been initialized.
    pub fn is_initialized(&self) -> bool {
        self.flags & 0x0004 == 0
    }
}

/// Resize information describing the target layout.
#[derive(Debug, Clone, Copy)]
pub struct ResizeInfo {
    /// Old total block count.
    pub old_block_count: u64,
    /// New total block count (must be > old).
    pub new_block_count: u64,
    /// Old number of block groups.
    pub old_group_count: u32,
    /// New number of block groups after resize.
    pub new_group_count: u32,
    /// Blocks per group.
    pub blocks_per_group: u64,
    /// Inodes per group.
    pub inodes_per_group: u32,
    /// Whether 64-bit feature is enabled.
    pub feature_64bit: bool,
}

impl ResizeInfo {
    /// Validates resize parameters.
    pub fn validate(&self) -> Result<()> {
        if self.new_block_count <= self.old_block_count {
            return Err(Error::InvalidArgument);
        }
        if self.blocks_per_group == 0 {
            return Err(Error::InvalidArgument);
        }
        if self.new_group_count <= self.old_group_count {
            return Err(Error::InvalidArgument);
        }
        if self.new_group_count as usize > MAX_BLOCK_GROUPS {
            return Err(Error::InvalidArgument);
        }
        Ok(())
    }

    /// Computes the number of blocks in the last (possibly partial) group.
    pub fn last_group_blocks(&self) -> u64 {
        let remainder = self.new_block_count % self.blocks_per_group;
        if remainder == 0 {
            self.blocks_per_group
        } else {
            remainder
        }
    }
}

/// In-memory representation of an ext4 superblock (subset).
#[derive(Debug)]
pub struct Ext4Superblock {
    /// Total block count (lower 32 bits).
    pub blocks_count_lo: u32,
    /// Total block count (upper 32 bits, 64-bit feature).
    pub blocks_count_hi: u32,
    /// Number of block groups.
    pub group_count: u32,
    /// Blocks per group.
    pub blocks_per_group: u32,
    /// Inodes per group.
    pub inodes_per_group: u32,
    /// Filesystem magic.
    pub magic: u16,
    /// Reserved GDT blocks for online resize.
    pub reserved_gdt_blocks: u16,
    /// Inode size in bytes.
    pub inode_size: u16,
    /// Feature compat flags.
    pub feature_compat: u32,
    /// Feature incompat flags.
    pub feature_incompat: u32,
    /// Free blocks (lo).
    pub free_blocks_count_lo: u32,
}

impl Ext4Superblock {
    /// Returns the total 64-bit block count.
    pub fn total_blocks(&self) -> u64 {
        (self.blocks_count_hi as u64) << 32 | self.blocks_count_lo as u64
    }

    /// Sets the total 64-bit block count.
    pub fn set_total_blocks(&mut self, count: u64) {
        self.blocks_count_lo = count as u32;
        self.blocks_count_hi = (count >> 32) as u32;
    }

    /// Returns whether 64-bit feature is enabled.
    pub fn has_64bit(&self) -> bool {
        self.feature_incompat & 0x80 != 0
    }

    /// Returns whether resize_inode feature is enabled.
    pub fn has_resize_inode(&self) -> bool {
        self.feature_compat & 0x10 != 0
    }
}

/// Ext4 filesystem resize state machine.
pub struct Ext4Resize {
    /// Superblock reference.
    superblock: Ext4Superblock,
    /// Block group descriptors.
    groups: [BlockGroupInfo; MAX_BLOCK_GROUPS],
    /// Current group count.
    group_count: usize,
}

impl Ext4Resize {
    /// Creates a new resize context with the given superblock.
    pub fn new(sb: Ext4Superblock) -> Self {
        let group_count = sb.group_count as usize;
        Self {
            superblock: sb,
            groups: [BlockGroupInfo::new(0); MAX_BLOCK_GROUPS],
            group_count,
        }
    }

    /// Returns the current superblock.
    pub fn superblock(&self) -> &Ext4Superblock {
        &self.superblock
    }

    /// Grows the group descriptor table to accommodate new groups.
    ///
    /// This adds new group descriptors for each block group in `info.new_group_count`,
    /// updating the internal GDT array. Reserved GDT blocks limit how many new
    /// groups can be added without unmounting.
    pub fn grow_group_table(&mut self, info: &ResizeInfo) -> Result<()> {
        info.validate()?;

        let reserved = self.superblock.reserved_gdt_blocks as u32;
        let max_online =
            self.superblock.blocks_per_group as u64 * (reserved as u64 / GDT_ENTRY_SIZE as u64 + 1);
        let new_blocks = info.new_block_count - info.old_block_count;

        if !self.superblock.has_resize_inode() && new_blocks > max_online {
            return Err(Error::InvalidArgument);
        }

        let new_count = info.new_group_count as usize;
        if new_count > MAX_BLOCK_GROUPS {
            return Err(Error::OutOfMemory);
        }

        // Initialize new group descriptor entries.
        for g in self.group_count..new_count {
            let first = g as u64 * info.blocks_per_group;
            self.groups[g] = BlockGroupInfo::new(first);
            // Block bitmap: first block of group (simplified).
            self.groups[g].block_bitmap = first;
            // Inode bitmap: second block.
            self.groups[g].inode_bitmap = first + 1;
            // Inode table: third block.
            self.groups[g].inode_table = first + 2;
            // Mark as uninitialized (flags bit 0x0001 = inode uninit, 0x0002 = block uninit).
            self.groups[g].flags = 0x0003;
            // Set free blocks to all blocks minus overhead.
            let overhead = 3u32; // bitmap + inode table simplified
            self.groups[g].free_blocks = (info.blocks_per_group as u32).saturating_sub(overhead);
            self.groups[g].free_inodes = info.inodes_per_group;
        }

        self.group_count = new_count;
        Ok(())
    }

    /// Extends the bitmap of the last existing block group.
    ///
    /// When the new size doesn't add a full group, the last group's block
    /// bitmap must be updated to reflect the additional blocks.
    pub fn extend_last_group_bitmap(&mut self, info: &ResizeInfo) -> Result<()> {
        if self.group_count == 0 {
            return Err(Error::InvalidArgument);
        }

        let last = self.group_count - 1;
        let old_last_blocks = info.old_block_count - (last as u64 * info.blocks_per_group);
        let new_last_blocks = if info.new_group_count == info.old_group_count {
            // Same group count: the last group grew.
            info.new_block_count - (last as u64 * info.blocks_per_group)
        } else {
            // New groups added: last old group is full.
            info.blocks_per_group
        };

        if new_last_blocks <= old_last_blocks {
            return Ok(()); // Nothing to do.
        }

        let additional = new_last_blocks - old_last_blocks;
        self.groups[last].free_blocks = self.groups[last]
            .free_blocks
            .saturating_add(additional as u32);
        // Clear the uninitialized block bitmap flag.
        self.groups[last].flags &= !0x0002;
        Ok(())
    }

    /// Performs a full online resize of the filesystem.
    ///
    /// Steps:
    /// 1. Validate resize parameters.
    /// 2. Extend the last group's bitmap if needed.
    /// 3. Grow the group descriptor table.
    /// 4. Update the superblock block count.
    pub fn resize_fs(&mut self, info: &ResizeInfo) -> Result<()> {
        info.validate()?;

        if self.superblock.magic != EXT4_MAGIC {
            return Err(Error::InvalidArgument);
        }

        // Step 1: extend last group bitmap if it wasn't full.
        let old_last_partial = info.old_block_count % info.blocks_per_group != 0;
        if old_last_partial {
            self.extend_last_group_bitmap(info)?;
        }

        // Step 2: grow group table for new groups.
        if info.new_group_count > info.old_group_count {
            self.grow_group_table(info)?;
        }

        // Step 3: update superblock.
        self.superblock.set_total_blocks(info.new_block_count);
        self.superblock.group_count = info.new_group_count;

        Ok(())
    }

    /// Returns the block group info for a given group index.
    pub fn group_info(&self, index: usize) -> Result<&BlockGroupInfo> {
        if index >= self.group_count {
            return Err(Error::NotFound);
        }
        Ok(&self.groups[index])
    }

    /// Returns the current group count.
    pub fn group_count(&self) -> usize {
        self.group_count
    }

    /// Computes resize info for growing from `old_blocks` to `new_blocks`.
    pub fn compute_resize_info(&self, new_block_count: u64) -> Result<ResizeInfo> {
        let old = self.superblock.total_blocks();
        if new_block_count <= old {
            return Err(Error::InvalidArgument);
        }
        let bpg = self.superblock.blocks_per_group as u64;
        if bpg == 0 {
            return Err(Error::InvalidArgument);
        }
        let old_groups = self.superblock.group_count;
        let new_groups = ((new_block_count + bpg - 1) / bpg) as u32;
        Ok(ResizeInfo {
            old_block_count: old,
            new_block_count,
            old_group_count: old_groups,
            new_group_count: new_groups,
            blocks_per_group: bpg,
            inodes_per_group: self.superblock.inodes_per_group,
            feature_64bit: self.superblock.has_64bit(),
        })
    }
}

/// Applies a resize using the provided resize info. Returns number of groups added.
pub fn resize_fs(resize: &mut Ext4Resize, new_block_count: u64) -> Result<u32> {
    let info = resize.compute_resize_info(new_block_count)?;
    let old_groups = info.old_group_count;
    resize.resize_fs(&info)?;
    Ok(info.new_group_count - old_groups)
}

/// Validates that a resize would not exceed platform limits.
pub fn validate_resize_limits(info: &ResizeInfo) -> Result<()> {
    if info.new_group_count as usize > MAX_BLOCK_GROUPS {
        return Err(Error::InvalidArgument);
    }
    if info.new_group_count as usize - info.old_group_count as usize > MAX_NEW_GROUPS {
        return Err(Error::InvalidArgument);
    }
    Ok(())
}

/// Returns the minimum number of blocks for a filesystem with `group_count` groups.
pub fn min_blocks_for_groups(group_count: u32, blocks_per_group: u64) -> u64 {
    group_count as u64 * blocks_per_group
}

/// Estimates the number of new groups needed to accommodate `additional_blocks`.
pub fn groups_needed(additional_blocks: u64, blocks_per_group: u64) -> u32 {
    if blocks_per_group == 0 {
        return 0;
    }
    ((additional_blocks + blocks_per_group - 1) / blocks_per_group) as u32
}
