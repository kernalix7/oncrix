// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Minix filesystem (v1, v2, v3).
//!
//! Minix is a simple, educational Unix-style filesystem used in early Linux
//! kernels and still shipped as a fallback rootfs format. Three versions exist:
//!
//! | Version | Max name | Max file size | Block size |
//! |---------|----------|---------------|------------|
//! | v1      | 14 bytes | 64 MiB        | 1024 B     |
//! | v2      | 30 bytes | 2 GiB         | 1024 B     |
//! | v3      | 60 bytes | 2 GiB         | configurable (1K–16K) |
//!
//! # On-disk Layout (v1/v2)
//!
//! ```text
//! [boot block][superblock][inode bitmap][zone bitmap][inodes...][data zones...]
//! ```
//!
//! # References
//!
//! - Linux `fs/minix/`
//! - Minix FS specification by Andrew Tanenbaum

use oncrix_lib::{Error, Result};

/// Maximum inodes for any version (hard cap for in-memory table).
pub const MAX_INODES: usize = 4096;
/// Maximum directory entries per directory (in-memory cap).
pub const MAX_DIR_ENTRIES: usize = 256;

/// Minix filesystem version.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MinixVersion {
    V1,
    V2,
    V3,
}

impl MinixVersion {
    /// Maximum filename length for this version.
    pub fn name_max(self) -> usize {
        match self {
            MinixVersion::V1 => 14,
            MinixVersion::V2 => 30,
            MinixVersion::V3 => 60,
        }
    }

    /// Maximum file size in bytes.
    pub fn max_file_size(self) -> u64 {
        match self {
            MinixVersion::V1 => 64 * 1024 * 1024,
            MinixVersion::V2 | MinixVersion::V3 => 2 * 1024 * 1024 * 1024,
        }
    }
}

/// Inode type bits (stored in `i_mode`).
pub const S_IFMT: u16 = 0o170000;
pub const S_IFREG: u16 = 0o100000;
pub const S_IFDIR: u16 = 0o040000;
pub const S_IFLNK: u16 = 0o120000;

/// Simplified in-memory Minix inode.
#[derive(Debug, Clone, Copy)]
pub struct MinixInode {
    /// Inode number (1-based).
    pub ino: u32,
    /// File mode bits (type + permissions).
    pub mode: u16,
    /// Owner UID.
    pub uid: u16,
    /// File size in bytes.
    pub size: u32,
    /// Modification time (Unix seconds).
    pub mtime: u32,
    /// Hard link count.
    pub nlinks: u16,
    /// Direct zone (block) pointers (up to 7 for v1, 9 for v2/v3).
    pub zones: [u32; 9],
}

impl MinixInode {
    /// Create a zeroed inode.
    pub fn new(ino: u32, mode: u16) -> Self {
        Self {
            ino,
            mode,
            uid: 0,
            size: 0,
            mtime: 0,
            nlinks: 1,
            zones: [0u32; 9],
        }
    }

    /// True if this inode represents a directory.
    pub fn is_dir(&self) -> bool {
        self.mode & S_IFMT == S_IFDIR
    }

    /// True if this inode represents a regular file.
    pub fn is_reg(&self) -> bool {
        self.mode & S_IFMT == S_IFREG
    }

    /// True if this inode represents a symbolic link.
    pub fn is_symlink(&self) -> bool {
        self.mode & S_IFMT == S_IFLNK
    }
}

/// A directory entry in Minix (fixed-size, name padded with NUL).
#[derive(Debug, Clone, Copy)]
pub struct MinixDirEntry {
    /// Target inode number (0 = deleted entry).
    pub ino: u32,
    /// Name bytes (NUL-terminated, padded).
    name: [u8; 60],
    /// Actual name length.
    name_len: u8,
}

impl MinixDirEntry {
    /// Create a directory entry.
    pub fn new(ino: u32, name: &[u8], version: MinixVersion) -> Result<Self> {
        let max_len = version.name_max();
        if name.is_empty() || name.len() > max_len {
            return Err(Error::InvalidArgument);
        }
        let mut buf = [0u8; 60];
        buf[..name.len()].copy_from_slice(name);
        Ok(Self {
            ino,
            name: buf,
            name_len: name.len() as u8,
        })
    }

    /// Return the entry name as a byte slice.
    pub fn name(&self) -> &[u8] {
        &self.name[..self.name_len as usize]
    }

    /// True if name matches `other`.
    pub fn name_matches(&self, other: &[u8]) -> bool {
        self.name() == other
    }

    /// True if the entry is deleted (inode 0).
    pub fn is_deleted(&self) -> bool {
        self.ino == 0
    }
}

/// In-memory Minix inode table.
pub struct MinixInodeTable {
    inodes: [Option<MinixInode>; MAX_INODES],
    count: usize,
    next_ino: u32,
}

impl MinixInodeTable {
    /// Create a new inode table.
    pub const fn new() -> Self {
        Self {
            inodes: [const { None }; MAX_INODES],
            count: 0,
            next_ino: 1,
        }
    }

    /// Allocate a new inode with `mode`.
    pub fn alloc(&mut self, mode: u16) -> Result<u32> {
        if self.count >= MAX_INODES {
            return Err(Error::OutOfMemory);
        }
        let ino = self.next_ino;
        self.next_ino += 1;
        self.inodes[self.count] = Some(MinixInode::new(ino, mode));
        self.count += 1;
        Ok(ino)
    }

    /// Get an inode by number.
    pub fn get(&self, ino: u32) -> Option<&MinixInode> {
        self.inodes[..self.count]
            .iter()
            .filter_map(|i| i.as_ref())
            .find(|i| i.ino == ino)
    }

    /// Get an inode mutably.
    pub fn get_mut(&mut self, ino: u32) -> Option<&mut MinixInode> {
        self.inodes[..self.count]
            .iter_mut()
            .filter_map(|i| i.as_mut())
            .find(|i| i.ino == ino)
    }

    /// Free an inode.
    pub fn free(&mut self, ino: u32) -> Result<()> {
        let pos = self.inodes[..self.count]
            .iter()
            .position(|i| i.as_ref().map(|i| i.ino == ino).unwrap_or(false));
        match pos {
            None => Err(Error::NotFound),
            Some(idx) => {
                self.count -= 1;
                self.inodes[idx] = self.inodes[self.count].take();
                Ok(())
            }
        }
    }

    /// Number of allocated inodes.
    pub fn count(&self) -> usize {
        self.count
    }
}

impl Default for MinixInodeTable {
    fn default() -> Self {
        Self::new()
    }
}

/// An in-memory Minix directory.
pub struct MinixDir {
    /// Inode of this directory.
    pub ino: u32,
    entries: [Option<MinixDirEntry>; MAX_DIR_ENTRIES],
    count: usize,
    version: MinixVersion,
}

impl MinixDir {
    /// Create a new directory inode.
    pub fn new(ino: u32, parent_ino: u32, version: MinixVersion) -> Result<Self> {
        let mut dir = Self {
            ino,
            entries: [const { None }; MAX_DIR_ENTRIES],
            count: 0,
            version,
        };
        dir.add(ino, b".")?;
        dir.add(parent_ino, b"..")?;
        Ok(dir)
    }

    /// Add a directory entry `(ino, name)`.
    pub fn add(&mut self, ino: u32, name: &[u8]) -> Result<()> {
        if self.lookup(name).is_some() {
            return Err(Error::AlreadyExists);
        }
        if self.count >= MAX_DIR_ENTRIES {
            return Err(Error::OutOfMemory);
        }
        let entry = MinixDirEntry::new(ino, name, self.version)?;
        self.entries[self.count] = Some(entry);
        self.count += 1;
        Ok(())
    }

    /// Remove an entry by name.
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
                self.count -= 1;
                self.entries[idx] = self.entries[self.count].take();
                Ok(())
            }
        }
    }

    /// Look up an entry by name; returns inode number or `None`.
    pub fn lookup(&self, name: &[u8]) -> Option<u32> {
        self.entries[..self.count]
            .iter()
            .filter_map(|e| e.as_ref())
            .find(|e| e.name_matches(name))
            .map(|e| e.ino)
    }

    /// Iterate entries (excluding `.` and `..`).
    pub fn iter_user_entries(&self) -> impl Iterator<Item = &MinixDirEntry> {
        self.entries[..self.count]
            .iter()
            .filter_map(|e| e.as_ref())
            .filter(|e| e.name() != b"." && e.name() != b"..")
    }
}

/// Minix superblock (in-memory representation).
#[derive(Debug, Clone, Copy)]
pub struct MinixSuperblock {
    /// Filesystem version.
    pub version: MinixVersion,
    /// Total number of inodes.
    pub ninodes: u32,
    /// Total number of zones (blocks).
    pub nzones: u32,
    /// Number of inode bitmap blocks.
    pub imap_blocks: u16,
    /// Number of zone bitmap blocks.
    pub zmap_blocks: u16,
    /// First data zone.
    pub firstdatazone: u16,
    /// Log2 of zone size / block size.
    pub log_zone_size: u16,
    /// Maximum file size.
    pub max_size: u32,
    /// Block size (v3 only; v1/v2 always 1024).
    pub block_size: u32,
    /// Magic number.
    pub magic: u16,
    /// Filesystem state (0 = clean).
    pub state: u16,
}

impl MinixSuperblock {
    /// Magic numbers for each version.
    pub const MAGIC_V1: u16 = 0x137F;
    pub const MAGIC_V2: u16 = 0x2468;
    pub const MAGIC_V3: u16 = 0x4D5A;

    /// Create a default superblock for `version`.
    pub fn new(version: MinixVersion, nzones: u32) -> Self {
        let magic = match version {
            MinixVersion::V1 => Self::MAGIC_V1,
            MinixVersion::V2 => Self::MAGIC_V2,
            MinixVersion::V3 => Self::MAGIC_V3,
        };
        let block_size = 1024u32;
        let ninodes = nzones / 4;
        Self {
            version,
            ninodes,
            nzones,
            imap_blocks: ((ninodes + 8191) / 8192) as u16,
            zmap_blocks: ((nzones + 8191) / 8192) as u16,
            firstdatazone: 2,
            log_zone_size: 0,
            max_size: version.max_file_size().min(u32::MAX as u64) as u32,
            block_size,
            magic,
            state: 0,
        }
    }

    /// Validate magic number.
    pub fn is_valid(&self) -> bool {
        matches!(self.magic, Self::MAGIC_V1 | Self::MAGIC_V2 | Self::MAGIC_V3)
    }
}
