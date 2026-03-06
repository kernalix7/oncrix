// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! File range cloning (reflink) support for the ONCRIX VFS.
//!
//! Implements the `FICLONE` / `FICLONERANGE` ioctls and the underlying VFS
//! `clone_file_range` operation used by copy-on-write filesystems such as
//! btrfs, APFS, and XFS to share data blocks between files without copying.

use oncrix_lib::{Error, Result};

/// ioctl number for FICLONE (clone entire file).
pub const FICLONE_IOCTL: u32 = 0x40049409;

/// ioctl number for FICLONERANGE (clone a byte range).
pub const FICLONERANGE_IOCTL: u32 = 0x4020940d;

/// Maximum number of clone entries tracked per inode.
pub const CLONE_MAX_ENTRIES: usize = 64;

/// A single reflink mapping: one source extent shared with one destination.
#[derive(Debug, Clone, Copy, Default)]
pub struct CloneEntry {
    /// Inode number of the source file.
    pub src_ino: u64,
    /// Byte offset within the source file.
    pub src_offset: u64,
    /// Byte offset within the destination file.
    pub dst_offset: u64,
    /// Length of the shared extent in bytes.
    pub length: u64,
    /// Number of files currently sharing this extent (reference count).
    pub refcount: u32,
    /// Whether this entry is active.
    pub active: bool,
}

impl CloneEntry {
    /// Create a new clone entry with a reference count of 2.
    pub const fn new(src_ino: u64, src_offset: u64, dst_offset: u64, length: u64) -> Self {
        Self {
            src_ino,
            src_offset,
            dst_offset,
            length,
            refcount: 2,
            active: true,
        }
    }

    /// Return `true` if the destination range `[offset, offset+len)` overlaps this entry.
    pub fn dst_overlaps(&self, offset: u64, len: u64) -> bool {
        if !self.active {
            return false;
        }
        let end = offset + len;
        self.dst_offset < end && self.dst_offset + self.length > offset
    }

    /// Increment the reference count.
    pub fn inc_ref(&mut self) {
        self.refcount = self.refcount.saturating_add(1);
    }

    /// Decrement the reference count, returning `true` if the entry should be freed.
    pub fn dec_ref(&mut self) -> bool {
        if self.refcount > 0 {
            self.refcount -= 1;
        }
        self.refcount == 0
    }
}

/// Arguments for the `FICLONERANGE` ioctl.
#[derive(Debug, Clone, Copy, Default)]
pub struct FileCloneRange {
    /// File descriptor of the source file.
    pub src_fd: i64,
    /// Starting offset in the source file (must be block-aligned).
    pub src_offset: u64,
    /// Length to clone (0 means until end of source file).
    pub src_length: u64,
    /// Starting offset in the destination file (must be block-aligned).
    pub dest_offset: u64,
}

impl FileCloneRange {
    /// Construct a new clone range descriptor.
    pub const fn new(src_fd: i64, src_offset: u64, src_length: u64, dest_offset: u64) -> Self {
        Self {
            src_fd,
            src_offset,
            src_length,
            dest_offset,
        }
    }

    /// Validate that all offsets and lengths are block-aligned (4 KiB).
    pub fn validate(&self) -> Result<()> {
        const BLOCK_MASK: u64 = 4095;
        if self.src_offset & BLOCK_MASK != 0 {
            return Err(Error::InvalidArgument);
        }
        if self.dest_offset & BLOCK_MASK != 0 {
            return Err(Error::InvalidArgument);
        }
        if self.src_length & BLOCK_MASK != 0 && self.src_length != 0 {
            return Err(Error::InvalidArgument);
        }
        if self.src_fd < 0 {
            return Err(Error::InvalidArgument);
        }
        Ok(())
    }
}

/// Per-inode table of reflink clone entries.
pub struct CloneTable {
    entries: [CloneEntry; CLONE_MAX_ENTRIES],
    count: usize,
}

impl CloneTable {
    /// Create an empty clone table.
    pub const fn new() -> Self {
        Self {
            entries: [CloneEntry {
                src_ino: 0,
                src_offset: 0,
                dst_offset: 0,
                length: 0,
                refcount: 0,
                active: false,
            }; CLONE_MAX_ENTRIES],
            count: 0,
        }
    }

    /// Record a new clone entry. Returns `OutOfMemory` if the table is full.
    pub fn insert(&mut self, entry: CloneEntry) -> Result<usize> {
        if self.count >= CLONE_MAX_ENTRIES {
            return Err(Error::OutOfMemory);
        }
        let idx = self.count;
        self.entries[idx] = entry;
        self.count += 1;
        Ok(idx)
    }

    /// Find a clone entry covering `dst_offset` in this inode.
    pub fn find_dst(&self, dst_offset: u64) -> Option<usize> {
        for i in 0..self.count {
            let e = &self.entries[i];
            if e.active && dst_offset >= e.dst_offset && dst_offset < e.dst_offset + e.length {
                return Some(i);
            }
        }
        None
    }

    /// Break a clone entry at index `idx` (copy-on-write trigger).
    ///
    /// Decrements the refcount; if it reaches 1 the entry is deactivated
    /// (the data is now exclusive to this inode).
    pub fn break_cow(&mut self, idx: usize) -> Result<()> {
        if idx >= self.count {
            return Err(Error::InvalidArgument);
        }
        let e = &mut self.entries[idx];
        if e.dec_ref() || e.refcount <= 1 {
            e.active = false;
        }
        Ok(())
    }

    /// Return the number of active clone entries.
    pub fn active_count(&self) -> usize {
        self.entries[..self.count]
            .iter()
            .filter(|e| e.active)
            .count()
    }

    /// Return whether the byte at `dst_offset` is a shared (cloned) block.
    pub fn is_shared(&self, dst_offset: u64) -> bool {
        self.find_dst(dst_offset).is_some()
    }
}

impl Default for CloneTable {
    fn default() -> Self {
        Self::new()
    }
}

/// Clone status returned by a `stat`-like query on a file.
#[derive(Debug, Clone, Copy, Default)]
pub struct CloneStatus {
    /// Number of extents currently shared with other files.
    pub shared_extents: u32,
    /// Total bytes covered by shared extents.
    pub shared_bytes: u64,
    /// Number of private (unshared) extents.
    pub private_extents: u32,
}

/// Validate that `src_offset`, `dest_offset`, and `length` are block-aligned.
pub fn validate_clone_args(src_offset: u64, dest_offset: u64, length: u64) -> Result<()> {
    const BLOCK_MASK: u64 = 4095;
    if src_offset & BLOCK_MASK != 0 || dest_offset & BLOCK_MASK != 0 {
        return Err(Error::InvalidArgument);
    }
    if length != 0 && length & BLOCK_MASK != 0 {
        return Err(Error::InvalidArgument);
    }
    Ok(())
}

/// Check whether two inodes belong to the same filesystem (required for cloning).
pub fn same_filesystem(src_fsid: u64, dst_fsid: u64) -> Result<()> {
    if src_fsid != dst_fsid {
        return Err(Error::InvalidArgument);
    }
    Ok(())
}
