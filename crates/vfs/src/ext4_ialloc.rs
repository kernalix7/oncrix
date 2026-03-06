// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! ext4 inode allocation and deallocation.
//!
//! Manages the per-block-group inode bitmaps and provides:
//!
//! - [`InodeBitmap`] — per-group inode availability bitmap
//! - [`Ext4IAllocState`] — per-filesystem inode allocator
//! - [`alloc_inode`] — allocate a new inode, preferring the goal group
//! - [`free_inode`] — return an inode number to the free pool
//! - [`inode_group_for`] — block group containing a given inode
//!
//! # Inode Numbering
//!
//! ext4 inodes are 1-based. Inode 1 is the bad-blocks inode,
//! inode 2 is the root directory, inodes 3–10 are reserved for
//! lost+found and other special files.
//!
//! # Block-group allocation policy
//!
//! - Directories are spread across groups (Orlov allocator hint).
//! - Regular files prefer the group containing the parent directory.
//!
//! # References
//!
//! - Linux `fs/ext4/ialloc.c`
//! - ext4 on-disk format: `Documentation/filesystems/ext4/`

use oncrix_lib::{Error, Result};

// ── Constants ────────────────────────────────────────────────────────────────

/// Default inodes per block group (ext4 tunable; we use the standard 8192).
pub const EXT4_INODES_PER_GROUP: u32 = 8_192;

/// Maximum block groups handled by this allocator.
pub const MAX_GROUPS: usize = 256;

/// First non-reserved inode number.
pub const EXT4_FIRST_INO: u32 = 11;

/// Inode number of the root directory.
pub const EXT4_ROOT_INO: u32 = 2;

/// Bits per bitmap word.
const BITS: usize = 64;

/// Bitmap words per group.
const BITMAP_WORDS: usize = EXT4_INODES_PER_GROUP as usize / BITS;

// ── Inode Type Hints ─────────────────────────────────────────────────────────

/// Allocation hint: regular file.
pub const INODE_REGULAR: u8 = 0;

/// Allocation hint: directory (triggers Orlov spreading).
pub const INODE_DIR: u8 = 1;

/// Allocation hint: symlink.
pub const INODE_SYMLINK: u8 = 2;

// ── Bitmap ───────────────────────────────────────────────────────────────────

/// Per-group inode bitmap (one bit per inode, set = allocated).
#[derive(Clone, Copy)]
pub struct InodeBitmap {
    words: [u64; BITMAP_WORDS],
}

impl InodeBitmap {
    /// Create an all-free bitmap with reserved inodes pre-marked.
    pub fn new_with_reserved() -> Self {
        let mut bm = Self {
            words: [0u64; BITMAP_WORDS],
        };
        // Mark inodes 1 through EXT4_FIRST_INO-1 as reserved.
        for i in 1..EXT4_FIRST_INO {
            let _ = bm.set(i); // ignore error on fresh bitmap
        }
        bm
    }

    /// Mark inode `ino` (1-based within group, 1..=EXT4_INODES_PER_GROUP).
    pub fn set(&mut self, ino: u32) -> Result<()> {
        if ino == 0 || ino > EXT4_INODES_PER_GROUP {
            return Err(Error::InvalidArgument);
        }
        let i = (ino - 1) as usize;
        let idx = i / BITS;
        let bit = i % BITS;
        if self.words[idx] & (1u64 << bit) != 0 {
            return Err(Error::AlreadyExists);
        }
        self.words[idx] |= 1u64 << bit;
        Ok(())
    }

    /// Free inode `ino`.
    pub fn clear(&mut self, ino: u32) -> Result<()> {
        if ino == 0 || ino > EXT4_INODES_PER_GROUP {
            return Err(Error::InvalidArgument);
        }
        let i = (ino - 1) as usize;
        let idx = i / BITS;
        let bit = i % BITS;
        if self.words[idx] & (1u64 << bit) == 0 {
            return Err(Error::InvalidArgument);
        }
        self.words[idx] &= !(1u64 << bit);
        Ok(())
    }

    /// Return `true` if `ino` is allocated.
    pub fn is_set(&self, ino: u32) -> bool {
        if ino == 0 || ino > EXT4_INODES_PER_GROUP {
            return true;
        }
        let i = (ino - 1) as usize;
        let idx = i / BITS;
        let bit = i % BITS;
        self.words[idx] & (1u64 << bit) != 0
    }

    /// Find the first free inode at or after `start` (1-based).
    pub fn find_free(&self, start: u32) -> Option<u32> {
        let s = start.saturating_sub(1) as usize;
        for i in s..EXT4_INODES_PER_GROUP as usize {
            let idx = i / BITS;
            let bit = i % BITS;
            if self.words[idx] & (1u64 << bit) == 0 {
                return Some((i + 1) as u32);
            }
        }
        None
    }

    /// Count free inodes in this bitmap.
    pub fn free_count(&self) -> u32 {
        let used: u32 = self.words.iter().map(|w| w.count_ones()).sum();
        EXT4_INODES_PER_GROUP - used
    }
}

impl Default for InodeBitmap {
    fn default() -> Self {
        Self::new_with_reserved()
    }
}

// ── Group Descriptor ─────────────────────────────────────────────────────────

/// Inode-related fields of an ext4 block group descriptor.
#[derive(Debug, Clone, Copy, Default)]
pub struct IGroupDesc {
    /// Free inode count for this group.
    pub free_inodes_count: u32,
    /// Number of directories in this group (used by Orlov).
    pub used_dirs_count: u32,
    /// Checksum of the group descriptor.
    pub checksum: u16,
}

// ── Allocator State ──────────────────────────────────────────────────────────

/// Per-filesystem ext4 inode allocator.
pub struct Ext4IAllocState {
    /// Total block groups.
    pub num_groups: usize,
    /// Per-group inode bitmaps.
    pub bitmaps: [InodeBitmap; MAX_GROUPS],
    /// Per-group descriptors (inode-relevant fields).
    pub groups: [IGroupDesc; MAX_GROUPS],
    /// Total inodes in the filesystem.
    pub total_inodes: u64,
    /// Total free inodes.
    pub free_inodes: u64,
    /// Group used for the last directory allocation (Orlov state).
    pub last_dir_group: usize,
}

impl Ext4IAllocState {
    /// Create a new allocator for a filesystem with `total_inodes` inodes.
    pub fn new(total_inodes: u64) -> Self {
        let num_groups = ((total_inodes + EXT4_INODES_PER_GROUP as u64 - 1)
            / EXT4_INODES_PER_GROUP as u64) as usize;
        let num_groups = num_groups.min(MAX_GROUPS);
        // Each group starts with EXT4_FIRST_INO-1 reserved inodes.
        let reserved_per_group = (EXT4_FIRST_INO - 1) as u64;
        let free_inodes = total_inodes.saturating_sub(reserved_per_group * num_groups as u64);
        let mut bitmaps = [const {
            InodeBitmap {
                words: [0u64; BITMAP_WORDS],
            }
        }; MAX_GROUPS];
        for bm in bitmaps.iter_mut() {
            *bm = InodeBitmap::new_with_reserved();
        }
        Self {
            num_groups,
            bitmaps,
            groups: [IGroupDesc::default(); MAX_GROUPS],
            total_inodes,
            free_inodes,
            last_dir_group: 0,
        }
    }

    /// Return the block group index for a given inode number (1-based).
    pub fn inode_group_for(&self, ino: u32) -> usize {
        if ino == 0 {
            return 0;
        }
        ((ino - 1) / EXT4_INODES_PER_GROUP) as usize
    }

    /// Return the inode index within its group (1-based, 1..=inodes_per_group).
    pub fn inode_local(&self, ino: u32) -> u32 {
        if ino == 0 {
            return 1;
        }
        ((ino - 1) % EXT4_INODES_PER_GROUP) + 1
    }

    /// Allocate a new inode, preferring `goal_group`.
    ///
    /// Returns the global inode number (1-based).
    pub fn alloc_inode(&mut self, goal_group: usize, kind: u8) -> Result<u32> {
        if self.free_inodes == 0 {
            return Err(Error::OutOfMemory);
        }
        // Directories use Orlov spreading: round-robin across groups.
        let start_group = if kind == INODE_DIR {
            (self.last_dir_group + 1) % self.num_groups
        } else {
            goal_group.min(self.num_groups.saturating_sub(1))
        };

        for delta in 0..self.num_groups {
            let g = (start_group + delta) % self.num_groups;
            let start_local = if g == goal_group || delta == 0 {
                EXT4_FIRST_INO // start after reserved
            } else {
                1
            };
            if let Some(local) = self.bitmaps[g].find_free(start_local) {
                self.bitmaps[g].set(local)?;
                self.groups[g].free_inodes_count =
                    self.groups[g].free_inodes_count.saturating_sub(1);
                if kind == INODE_DIR {
                    self.groups[g].used_dirs_count += 1;
                    self.last_dir_group = g;
                }
                self.free_inodes = self.free_inodes.saturating_sub(1);
                let global_ino = g as u32 * EXT4_INODES_PER_GROUP + local;
                return Ok(global_ino);
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Free the inode with global number `ino`.
    pub fn free_inode(&mut self, ino: u32, was_dir: bool) -> Result<()> {
        if ino < EXT4_FIRST_INO {
            return Err(Error::InvalidArgument); // never free reserved inodes
        }
        let g = self.inode_group_for(ino);
        let local = self.inode_local(ino);
        if g >= self.num_groups {
            return Err(Error::InvalidArgument);
        }
        self.bitmaps[g].clear(local)?;
        self.groups[g].free_inodes_count += 1;
        if was_dir {
            self.groups[g].used_dirs_count = self.groups[g].used_dirs_count.saturating_sub(1);
        }
        self.free_inodes = self.free_inodes.saturating_add(1);
        Ok(())
    }

    /// Return `true` if the given inode number is allocated.
    pub fn is_allocated(&self, ino: u32) -> bool {
        let g = self.inode_group_for(ino);
        let local = self.inode_local(ino);
        if g >= self.num_groups {
            return false;
        }
        self.bitmaps[g].is_set(local)
    }

    /// Return the total free inode count.
    pub fn free_inodes(&self) -> u64 {
        self.free_inodes
    }
}
