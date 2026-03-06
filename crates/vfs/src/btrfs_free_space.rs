// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Btrfs free space cache management.
//!
//! Btrfs maintains a free space cache to accelerate block allocation.
//! The cache stores free extents and free bitmaps for each block group.
//! When allocating space, the allocator searches the cache before falling
//! back to the slower on-disk free space tree.
//!
//! # Cache Formats
//!
//! Two free space entry formats exist:
//! - **Extent entries**: Each entry records the offset and length of a
//!   contiguous free region within a block group.
//! - **Bitmap entries**: A 512-byte bitmap where each bit represents one
//!   Btrfs sector (typically 4096 bytes / 512 = 8 sectors per bit range).
//!
//! # Block Group States
//!
//! Each block group can be in one of several states:
//! - **Active**: The block group is available for allocation.
//! - **Full**: No free space remains.
//! - **Read-only**: The group is being relocated or scrubbed.
//! - **Discard**: Free regions are being discarded (TRIM).

use oncrix_lib::{Error, Result};

/// Maximum number of free space extents tracked per block group.
pub const FREE_SPACE_MAX_EXTENTS: usize = 256;

/// Block group flags identifying the storage type.
pub mod bg_flags {
    pub const BTRFS_BLOCK_GROUP_DATA: u64 = 1 << 0;
    pub const BTRFS_BLOCK_GROUP_SYSTEM: u64 = 1 << 1;
    pub const BTRFS_BLOCK_GROUP_METADATA: u64 = 1 << 2;
    pub const BTRFS_BLOCK_GROUP_RAID0: u64 = 1 << 3;
    pub const BTRFS_BLOCK_GROUP_RAID1: u64 = 1 << 4;
    pub const BTRFS_BLOCK_GROUP_DUP: u64 = 1 << 5;
    pub const BTRFS_BLOCK_GROUP_RAID10: u64 = 1 << 6;
}

/// A single free space extent within a block group.
#[derive(Clone, Copy, Default, Debug)]
pub struct FreeSpaceExtent {
    /// Byte offset within the block group.
    pub offset: u64,
    /// Length of the free region in bytes.
    pub length: u64,
}

impl FreeSpaceExtent {
    /// Returns `true` if this extent can satisfy a request of `len` bytes.
    pub const fn can_satisfy(&self, len: u64) -> bool {
        self.length >= len
    }

    /// Returns `true` if this extent overlaps with `[other_off, other_off + other_len)`.
    pub const fn overlaps(&self, other_off: u64, other_len: u64) -> bool {
        self.offset < other_off + other_len && other_off < self.offset + self.length
    }
}

/// In-memory free space cache for a single Btrfs block group.
pub struct FreeSpaceCache {
    /// Block group start byte on the volume.
    pub bg_start: u64,
    /// Block group size in bytes.
    pub bg_size: u64,
    /// Block group type flags.
    pub bg_flags: u64,
    /// Free space extents (sorted by offset).
    extents: [FreeSpaceExtent; FREE_SPACE_MAX_EXTENTS],
    /// Number of valid extents.
    count: usize,
    /// Total free bytes (sum of all extent lengths).
    total_free: u64,
    /// Whether the cache is valid (populated from disk).
    valid: bool,
}

impl Default for FreeSpaceCache {
    fn default() -> Self {
        Self {
            bg_start: 0,
            bg_size: 0,
            bg_flags: 0,
            extents: [FreeSpaceExtent::default(); FREE_SPACE_MAX_EXTENTS],
            count: 0,
            total_free: 0,
            valid: false,
        }
    }
}

impl FreeSpaceCache {
    /// Creates a new empty free space cache for a block group.
    pub fn new(bg_start: u64, bg_size: u64, bg_flags: u64) -> Self {
        let mut cache = Self::default();
        cache.bg_start = bg_start;
        cache.bg_size = bg_size;
        cache.bg_flags = bg_flags;
        cache
    }

    /// Adds a free extent to the cache (extents must be non-overlapping).
    pub fn add_free(&mut self, offset: u64, length: u64) -> Result<()> {
        if self.count >= FREE_SPACE_MAX_EXTENTS {
            return Err(Error::OutOfMemory);
        }
        if offset + length > self.bg_size {
            return Err(Error::InvalidArgument);
        }
        self.extents[self.count] = FreeSpaceExtent { offset, length };
        self.count += 1;
        self.total_free += length;
        self.valid = true;
        Ok(())
    }

    /// Allocates `len` bytes from the first fitting free extent (first-fit).
    ///
    /// Returns the byte offset within the block group on success.
    pub fn alloc(&mut self, len: u64, align: u64) -> Result<u64> {
        if !self.valid {
            return Err(Error::NotFound);
        }
        let align = align.max(1);
        for i in 0..self.count {
            let ext = &self.extents[i];
            // Align the start offset.
            let aligned_start = (ext.offset + align - 1) & !(align - 1);
            if aligned_start >= ext.offset + ext.length {
                continue;
            }
            let available = ext.offset + ext.length - aligned_start;
            if available >= len {
                let alloc_off = aligned_start;
                let remaining_before = aligned_start - ext.offset;
                let remaining_after = available - len;

                // Update or remove the extent.
                self.total_free = self
                    .total_free
                    .saturating_sub(ext.length - remaining_before - remaining_after);
                // Shrink the existing extent to the "before" part.
                self.extents[i].length = remaining_before;
                if remaining_before == 0 {
                    // Remove this extent.
                    self.count -= 1;
                    self.extents[i] = self.extents[self.count];
                    self.extents[self.count] = FreeSpaceExtent::default();
                }
                // Add the "after" fragment if any.
                if remaining_after > 0 {
                    let after_off = aligned_start + len;
                    // Don't check errors; if the table is full, lose the fragment.
                    let _ = self.add_free(after_off, remaining_after);
                }
                return Ok(self.bg_start + alloc_off);
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Releases `len` bytes at `offset` back to the free space cache.
    pub fn free(&mut self, offset: u64, length: u64) -> Result<()> {
        if offset < self.bg_start || offset - self.bg_start + length > self.bg_size {
            return Err(Error::InvalidArgument);
        }
        let rel_offset = offset - self.bg_start;
        self.add_free(rel_offset, length)
    }

    /// Returns the total free bytes in this block group's cache.
    pub const fn free_bytes(&self) -> u64 {
        self.total_free
    }

    /// Returns `true` if the cache is populated.
    pub const fn is_valid(&self) -> bool {
        self.valid
    }

    /// Marks the cache as invalid (needs refresh from disk).
    pub fn invalidate(&mut self) {
        self.valid = false;
        self.count = 0;
        self.total_free = 0;
    }
}
