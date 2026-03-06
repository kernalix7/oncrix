// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! SquashFS inode structures and parsing.
//!
//! SquashFS stores inodes in a compressed metadata area.  Each inode type
//! has a different on-disk size.  This module implements the common inode
//! header, per-type inode structures, and the inode lookup table.

use oncrix_lib::{Error, Result};

/// SquashFS super block magic.
pub const SQUASHFS_MAGIC: u32 = 0x7371_7368;

/// Maximum number of inodes in the inode table cache.
pub const SQUASHFS_INODE_CACHE: usize = 4096;

/// SquashFS inode types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum SquashfsInodeType {
    Dir = 1,
    File = 2,
    Symlink = 3,
    BlockDev = 4,
    CharDev = 5,
    Fifo = 6,
    Socket = 7,
    /// Extended variants (type + 7).
    LDir = 8,
    LFile = 9,
    LSymlink = 10,
    LBlockDev = 11,
    LCharDev = 12,
    LFifo = 13,
    LSocket = 14,
}

impl SquashfsInodeType {
    /// Parse from on-disk u16.
    pub fn from_u16(v: u16) -> Result<Self> {
        match v {
            1 => Ok(Self::Dir),
            2 => Ok(Self::File),
            3 => Ok(Self::Symlink),
            4 => Ok(Self::BlockDev),
            5 => Ok(Self::CharDev),
            6 => Ok(Self::Fifo),
            7 => Ok(Self::Socket),
            8 => Ok(Self::LDir),
            9 => Ok(Self::LFile),
            10 => Ok(Self::LSymlink),
            11 => Ok(Self::LBlockDev),
            12 => Ok(Self::LCharDev),
            13 => Ok(Self::LFifo),
            14 => Ok(Self::LSocket),
            _ => Err(Error::InvalidArgument),
        }
    }
}

/// Common inode header (present in all SquashFS inode types).
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct SquashfsInodeHeader {
    pub inode_type: u16,
    pub mode: u16,
    pub uid: u16,
    pub gid: u16,
    pub mtime: u32,
    /// Unique inode number.
    pub inode_number: u32,
}

impl SquashfsInodeHeader {
    /// Parse inode type.
    pub fn inode_type(&self) -> Result<SquashfsInodeType> {
        SquashfsInodeType::from_u16(self.inode_type)
    }
}

/// SquashFS basic file inode.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct SquashfsRegInode {
    pub common: SquashfsInodeHeader,
    /// Start block of the file data.
    pub start_block: u32,
    /// Fragment index (0xffffffff = no fragment).
    pub fragment: u32,
    /// Offset within the fragment.
    pub offset: u32,
    /// Uncompressed file size.
    pub file_size: u32,
}

/// SquashFS extended file inode (supports files > 4 GiB).
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct SquashfsLregInode {
    pub common: SquashfsInodeHeader,
    /// Start block of the file data.
    pub start_block: u64,
    /// File size (64-bit).
    pub file_size: u64,
    /// Sparse bytes (unused in simple implementations).
    pub sparse: u64,
    /// Hard link count.
    pub nlink: u32,
    /// Fragment index.
    pub fragment: u32,
    /// Offset within the fragment.
    pub offset: u32,
    /// X-attributes index.
    pub xattr: u32,
}

/// SquashFS directory inode.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct SquashfsDirInode {
    pub common: SquashfsInodeHeader,
    /// Block containing directory headers.
    pub start_block: u32,
    /// Hard link count.
    pub nlink: u32,
    /// Uncompressed size of the directory listing.
    pub file_size: u16,
    /// Offset within the metadata block.
    pub offset: u16,
    /// Inode of parent directory.
    pub parent_inode: u32,
}

/// In-memory SquashFS inode (union of all types).
#[derive(Debug, Clone)]
pub enum SquashfsInode {
    Regular(SquashfsRegInode),
    LargeRegular(SquashfsLregInode),
    Directory(SquashfsDirInode),
    Other { common: SquashfsInodeHeader },
}

impl SquashfsInode {
    /// Common header.
    pub fn header(&self) -> &SquashfsInodeHeader {
        match self {
            Self::Regular(r) => &r.common,
            Self::LargeRegular(r) => &r.common,
            Self::Directory(d) => &d.common,
            Self::Other { common } => common,
        }
    }

    /// File size in bytes (0 for non-regular inodes).
    pub fn file_size(&self) -> u64 {
        match self {
            Self::Regular(r) => r.file_size as u64,
            Self::LargeRegular(r) => r.file_size,
            _ => 0,
        }
    }

    /// Inode number.
    pub fn ino(&self) -> u32 {
        self.header().inode_number
    }
}

/// Inode reference: (metadata block index, byte offset within block).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InodeRef {
    pub block: u32,
    pub offset: u16,
}

impl InodeRef {
    /// Encode as a u64 (block << 16 | offset) as stored in directory entries.
    pub fn encode(&self) -> u64 {
        ((self.block as u64) << 16) | (self.offset as u64)
    }

    /// Decode from the packed u64 format.
    pub fn decode(v: u64) -> Self {
        Self {
            block: (v >> 16) as u32,
            offset: (v & 0xffff) as u16,
        }
    }
}

/// In-memory inode lookup table entry.
#[derive(Debug, Clone, Copy)]
pub struct InodeLookupEntry {
    pub ino: u32,
    pub iref: InodeRef,
}

/// Fixed-capacity inode lookup table.
pub struct SquashfsInodeTable {
    entries: [Option<InodeLookupEntry>; SQUASHFS_INODE_CACHE],
    count: usize,
}

impl SquashfsInodeTable {
    /// Create an empty inode table.
    pub const fn new() -> Self {
        Self {
            entries: [const { None }; SQUASHFS_INODE_CACHE],
            count: 0,
        }
    }

    /// Insert an entry.
    pub fn insert(&mut self, ino: u32, iref: InodeRef) -> Result<()> {
        if self.count >= SQUASHFS_INODE_CACHE {
            return Err(Error::OutOfMemory);
        }
        for slot in &mut self.entries {
            if slot.is_none() {
                *slot = Some(InodeLookupEntry { ino, iref });
                self.count += 1;
                return Ok(());
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Look up an inode reference by inode number.
    pub fn lookup(&self, ino: u32) -> Option<InodeRef> {
        self.entries
            .iter()
            .filter_map(|s| s.as_ref())
            .find(|e| e.ino == ino)
            .map(|e| e.iref)
    }

    /// Number of cached entries.
    pub fn count(&self) -> usize {
        self.count
    }
}

impl Default for SquashfsInodeTable {
    fn default() -> Self {
        Self::new()
    }
}
