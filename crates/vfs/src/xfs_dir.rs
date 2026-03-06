// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! XFS directory operations.
//!
//! XFS supports four directory formats, each chosen based on the number of
//! entries and block occupancy:
//!
//! | Format     | When used                                    |
//! |------------|----------------------------------------------|
//! | Shortform  | Very small directories fitting in the inode  |
//! | Block      | Single block directories                      |
//! | Leaf       | Multi-block with a separate leaf index        |
//! | Node / B+tree | Large directories with a full B+tree index |
//!
//! This module models the shortform and block formats used for small directories
//! and provides common directory entry types shared across all formats.
//!
//! # References
//!
//! - Linux `fs/xfs/libxfs/xfs_dir2.c`, `xfs_dir2_sf.c`, `xfs_dir2_block.c`
//! - XFS Filesystem Structure: `https://mirrors.edge.kernel.org/pub/linux/utils/fs/xfs/docs/`

use oncrix_lib::{Error, Result};

/// Maximum filename length in XFS (POSIX NAME_MAX).
pub const XFS_NAME_MAX: usize = 255;
/// Maximum entries in the shortform format.
pub const SF_MAX_ENTRIES: usize = 32;
/// Maximum entries in the block format (single-block directory).
pub const BLOCK_MAX_ENTRIES: usize = 256;

/// A directory entry name (inline storage, no heap).
#[derive(Debug, Clone, Copy)]
pub struct XfsDirName {
    buf: [u8; XFS_NAME_MAX],
    len: u8,
}

impl XfsDirName {
    /// Create from a byte slice. Returns `InvalidArgument` if too long.
    pub fn new(name: &[u8]) -> Result<Self> {
        if name.is_empty() || name.len() > XFS_NAME_MAX {
            return Err(Error::InvalidArgument);
        }
        let mut buf = [0u8; XFS_NAME_MAX];
        buf[..name.len()].copy_from_slice(name);
        Ok(Self {
            buf,
            len: name.len() as u8,
        })
    }

    /// Return the name as a byte slice.
    pub fn as_bytes(&self) -> &[u8] {
        &self.buf[..self.len as usize]
    }

    /// Length of the name in bytes.
    pub fn len(&self) -> usize {
        self.len as usize
    }

    /// Returns true if the name is empty (should not happen after `new()`).
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

/// A single directory entry (inode number + name).
#[derive(Debug, Clone, Copy)]
pub struct XfsDirEntry {
    /// Inode number this entry points to.
    pub ino: u64,
    /// File type hint (`DT_*` constants, 0 = unknown).
    pub ftype: u8,
    /// Entry name.
    pub name: XfsDirName,
}

impl XfsDirEntry {
    /// Create a new directory entry.
    pub fn new(ino: u64, ftype: u8, name: &[u8]) -> Result<Self> {
        Ok(Self {
            ino,
            ftype,
            name: XfsDirName::new(name)?,
        })
    }

    /// Returns `true` if `name_bytes` matches this entry's name.
    pub fn name_matches(&self, name_bytes: &[u8]) -> bool {
        self.name.as_bytes() == name_bytes
    }
}

/// Shortform directory — fits entirely within the inode's data fork.
pub struct XfsDirShortform {
    /// The inode number of `.` (this directory).
    pub dot_ino: u64,
    /// The inode number of `..` (parent directory).
    pub dotdot_ino: u64,
    entries: [Option<XfsDirEntry>; SF_MAX_ENTRIES],
    count: usize,
}

impl XfsDirShortform {
    /// Create a new shortform directory.
    pub fn new(dot_ino: u64, dotdot_ino: u64) -> Self {
        Self {
            dot_ino,
            dotdot_ino,
            entries: [const { None }; SF_MAX_ENTRIES],
            count: 0,
        }
    }

    /// Add an entry. Returns `AlreadyExists` if the name is taken.
    pub fn add(&mut self, ino: u64, ftype: u8, name: &[u8]) -> Result<()> {
        if self.lookup(name).is_some() {
            return Err(Error::AlreadyExists);
        }
        if self.count >= SF_MAX_ENTRIES {
            return Err(Error::OutOfMemory);
        }
        let entry = XfsDirEntry::new(ino, ftype, name)?;
        self.entries[self.count] = Some(entry);
        self.count += 1;
        Ok(())
    }

    /// Remove an entry by name. Returns `NotFound` if absent.
    pub fn remove(&mut self, name: &[u8]) -> Result<()> {
        let pos = self.entries[..self.count]
            .iter()
            .position(|e| e.as_ref().map(|e| e.name_matches(name)).unwrap_or(false));
        match pos {
            None => Err(Error::NotFound),
            Some(idx) => {
                self.count -= 1;
                self.entries[idx] = self.entries[self.count].take();
                Ok(())
            }
        }
    }

    /// Lookup an entry by name, returning its inode number.
    pub fn lookup(&self, name: &[u8]) -> Option<u64> {
        // Handle dot and dotdot.
        if name == b"." {
            return Some(self.dot_ino);
        }
        if name == b".." {
            return Some(self.dotdot_ino);
        }
        self.entries[..self.count]
            .iter()
            .filter_map(|e| e.as_ref())
            .find(|e| e.name_matches(name))
            .map(|e| e.ino)
    }

    /// Number of non-dot entries.
    pub fn count(&self) -> usize {
        self.count
    }

    /// Iterate all entries (not including `.` and `..`).
    pub fn iter(&self) -> impl Iterator<Item = &XfsDirEntry> {
        self.entries[..self.count].iter().filter_map(|e| e.as_ref())
    }

    /// Whether the directory could be promoted to block format.
    pub fn needs_upgrade(&self) -> bool {
        self.count >= SF_MAX_ENTRIES
    }
}

/// Block-format directory — single filesystem block with a free-space tail.
pub struct XfsDirBlock {
    /// Inode number of this directory.
    pub dot_ino: u64,
    /// Inode number of the parent directory.
    pub dotdot_ino: u64,
    entries: [Option<XfsDirEntry>; BLOCK_MAX_ENTRIES],
    count: usize,
    /// Simulated free space in bytes (block_size - used).
    free_bytes: u32,
    /// Total block size in bytes.
    block_size: u32,
}

impl XfsDirBlock {
    /// Create a new block-format directory with the given block size.
    pub fn new(dot_ino: u64, dotdot_ino: u64, block_size: u32) -> Result<Self> {
        if block_size < 512 {
            return Err(Error::InvalidArgument);
        }
        Ok(Self {
            dot_ino,
            dotdot_ino,
            entries: [const { None }; BLOCK_MAX_ENTRIES],
            count: 0,
            free_bytes: block_size,
            block_size,
        })
    }

    /// Byte size of one directory entry on disk (name + fixed overhead).
    fn entry_disk_size(name_len: usize) -> u32 {
        // Fixed fields: ino(8) + ftype(1) + namlen(1) + pad alignment.
        let raw = 10 + name_len as u32;
        // Round up to 8-byte boundary.
        (raw + 7) & !7
    }

    /// Add an entry. Returns `AlreadyExists` if the name exists or `OutOfMemory`
    /// if insufficient free space.
    pub fn add(&mut self, ino: u64, ftype: u8, name: &[u8]) -> Result<()> {
        if self.lookup(name).is_some() {
            return Err(Error::AlreadyExists);
        }
        if self.count >= BLOCK_MAX_ENTRIES {
            return Err(Error::OutOfMemory);
        }
        let needed = Self::entry_disk_size(name.len());
        if needed > self.free_bytes {
            return Err(Error::OutOfMemory);
        }
        let entry = XfsDirEntry::new(ino, ftype, name)?;
        self.entries[self.count] = Some(entry);
        self.count += 1;
        self.free_bytes -= needed;
        Ok(())
    }

    /// Remove an entry by name. Returns `NotFound` if absent.
    pub fn remove(&mut self, name: &[u8]) -> Result<()> {
        if name == b"." || name == b".." {
            return Err(Error::InvalidArgument);
        }
        let pos = self.entries[..self.count]
            .iter()
            .position(|e| e.as_ref().map(|e| e.name_matches(name)).unwrap_or(false));
        match pos {
            None => Err(Error::NotFound),
            Some(idx) => {
                let freed = Self::entry_disk_size(self.entries[idx].as_ref().unwrap().name.len());
                self.count -= 1;
                self.entries[idx] = self.entries[self.count].take();
                self.free_bytes += freed;
                Ok(())
            }
        }
    }

    /// Lookup an entry by name.
    pub fn lookup(&self, name: &[u8]) -> Option<u64> {
        if name == b"." {
            return Some(self.dot_ino);
        }
        if name == b".." {
            return Some(self.dotdot_ino);
        }
        self.entries[..self.count]
            .iter()
            .filter_map(|e| e.as_ref())
            .find(|e| e.name_matches(name))
            .map(|e| e.ino)
    }

    /// Number of non-dot entries.
    pub fn count(&self) -> usize {
        self.count
    }

    /// Free bytes remaining in the block.
    pub fn free_bytes(&self) -> u32 {
        self.free_bytes
    }

    /// Iterate all entries (excluding `.` and `..`).
    pub fn iter(&self) -> impl Iterator<Item = &XfsDirEntry> {
        self.entries[..self.count].iter().filter_map(|e| e.as_ref())
    }
}

/// Directory format discriminant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XfsDirFormat {
    /// Fits in inode data fork.
    Shortform,
    /// Single filesystem block.
    Block,
    /// Multi-block with separate leaf.
    Leaf,
    /// Full B+tree index.
    Node,
}

/// Determine the appropriate directory format based on entry count and size.
///
/// This is a simplified heuristic matching the Linux kernel's upgrade logic.
pub fn select_dir_format(entry_count: usize, total_name_bytes: usize) -> XfsDirFormat {
    // Shortform: fits in ~240 bytes of inode data fork.
    if entry_count <= 10 && total_name_bytes <= 200 {
        return XfsDirFormat::Shortform;
    }
    // Block: single block (typically 4096 bytes).
    if entry_count <= 200 {
        return XfsDirFormat::Block;
    }
    // Leaf: multiple data blocks with one leaf index block.
    if entry_count <= 65536 {
        return XfsDirFormat::Leaf;
    }
    XfsDirFormat::Node
}
