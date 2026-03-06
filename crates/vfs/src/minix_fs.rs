// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Minix filesystem support (V1, V2, V3).
//!
//! The Minix filesystem was the original filesystem used by the Minix OS
//! (and by early Linux).  This module implements V1 (16-bit blocks, 14-char
//! names), V2 (32-bit blocks, 30-char names), and V3 (configurable block
//! size and 60-char names).

use oncrix_lib::{Error, Result};

/// Minix V1 magic number.
pub const MINIX_V1_MAGIC1: u16 = 0x137f;
/// Minix V1 magic number (30-char names).
pub const MINIX_V1_MAGIC2: u16 = 0x138f;
/// Minix V2 magic number.
pub const MINIX_V2_MAGIC1: u16 = 0x2468;
/// Minix V2 magic number (30-char names).
pub const MINIX_V2_MAGIC2: u16 = 0x2478;
/// Minix V3 magic number.
pub const MINIX_V3_MAGIC: u16 = 0x4d5a;

/// Maximum name length for V1.
pub const MINIX_V1_NAME_LEN: usize = 14;
/// Maximum name length for V2/V3.
pub const MINIX_V2_NAME_LEN: usize = 30;

/// Minix version discriminator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MinixVersion {
    V1,
    V2,
    V3,
}

/// Number of direct block pointers in a Minix V1 inode.
pub const MINIX_V1_NDZONE: usize = 9;
/// Number of direct block pointers in a Minix V2 inode.
pub const MINIX_V2_NDZONE: usize = 10;

/// Minix V1 on-disk inode.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct MinixV1Inode {
    pub mode: u16,
    pub uid: u16,
    pub size: u32,
    pub time: u32,
    pub gid: u8,
    pub nlinks: u8,
    /// Direct zones + 1 single-indirect + 1 double-indirect.
    pub zone: [u16; MINIX_V1_NDZONE],
}

impl MinixV1Inode {
    /// File type from mode.
    pub fn file_type(&self) -> u16 {
        self.mode & 0o170000
    }

    /// Whether this is a directory.
    pub fn is_dir(&self) -> bool {
        self.file_type() == 0o040000
    }
}

/// Minix V2 on-disk inode (larger zones, more timestamps).
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct MinixV2Inode {
    pub mode: u16,
    pub nlinks: u16,
    pub uid: u16,
    pub gid: u16,
    pub size: u32,
    pub atime: u32,
    pub mtime: u32,
    pub ctime: u32,
    /// Direct zones + indirect + double-indirect.
    pub zone: [u32; MINIX_V2_NDZONE],
}

impl MinixV2Inode {
    /// File type from mode bits.
    pub fn file_type(&self) -> u16 {
        self.mode & 0o170000
    }

    /// Whether this is a regular file.
    pub fn is_regular(&self) -> bool {
        self.file_type() == 0o100000
    }
}

/// On-disk Minix superblock (V1/V2 layout; V3 extends this).
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct MinixSuperblockDisk {
    /// Number of inodes.
    pub ninodes: u16,
    /// Number of data zones (V1) or padding (V2/V3).
    pub nzones: u16,
    /// Number of inode bitmap blocks.
    pub imap_blocks: u16,
    /// Number of zone bitmap blocks.
    pub zmap_blocks: u16,
    /// First data zone block number.
    pub first_data_zone: u16,
    /// Log2 of block size relative to 1 KiB.
    pub log_zone_size: u16,
    /// Maximum file size in bytes.
    pub max_size: u32,
    /// Magic number.
    pub magic: u16,
    /// Filesystem state (0 = valid, 1 = errors).
    pub state: u16,
    /// Number of zones (V2/V3).
    pub zones: u32,
}

impl MinixSuperblockDisk {
    /// Determine the Minix version from the magic number.
    pub fn version(&self) -> Result<MinixVersion> {
        match self.magic {
            MINIX_V1_MAGIC1 | MINIX_V1_MAGIC2 => Ok(MinixVersion::V1),
            MINIX_V2_MAGIC1 | MINIX_V2_MAGIC2 => Ok(MinixVersion::V2),
            MINIX_V3_MAGIC => Ok(MinixVersion::V3),
            _ => Err(Error::InvalidArgument),
        }
    }

    /// Filesystem block size in bytes.
    pub fn block_size(&self, version: MinixVersion) -> usize {
        match version {
            MinixVersion::V3 => 1024usize << self.log_zone_size,
            _ => 1024,
        }
    }

    /// Whether long (30-char) names are used.
    pub fn long_names(&self) -> bool {
        matches!(self.magic, MINIX_V1_MAGIC2 | MINIX_V2_MAGIC2)
    }
}

/// In-memory Minix superblock.
#[derive(Debug, Clone)]
pub struct MinixSuperblock {
    pub version: MinixVersion,
    pub block_size: usize,
    pub total_inodes: u32,
    pub total_zones: u32,
    pub first_data_zone: u32,
    pub imap_blocks: u16,
    pub zmap_blocks: u16,
    pub max_file_size: u32,
    pub long_names: bool,
    pub name_len: usize,
}

impl MinixSuperblock {
    /// Parse from the on-disk superblock.
    pub fn parse(disk: &MinixSuperblockDisk) -> Result<Self> {
        let version = disk.version()?;
        let block_size = disk.block_size(version);
        let long_names = disk.long_names();
        let name_len = if long_names {
            MINIX_V2_NAME_LEN
        } else {
            MINIX_V1_NAME_LEN
        };
        let total_zones = match version {
            MinixVersion::V1 => disk.nzones as u32,
            _ => disk.zones,
        };
        Ok(Self {
            version,
            block_size,
            total_inodes: disk.ninodes as u32,
            total_zones,
            first_data_zone: disk.first_data_zone as u32,
            imap_blocks: disk.imap_blocks,
            zmap_blocks: disk.zmap_blocks,
            max_file_size: disk.max_size,
            long_names,
            name_len,
        })
    }

    /// Inode bitmap start block (always block 2 in Minix).
    pub fn imap_start(&self) -> u32 {
        2
    }

    /// Zone bitmap start block.
    pub fn zmap_start(&self) -> u32 {
        2 + self.imap_blocks as u32
    }

    /// Inode table start block.
    pub fn inode_table_start(&self) -> u32 {
        self.zmap_start() + self.zmap_blocks as u32
    }
}

/// Minix V1 directory entry.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct MinixDirEntryV1 {
    pub ino: u16,
    pub name: [u8; MINIX_V1_NAME_LEN],
}

impl MinixDirEntryV1 {
    /// Whether this entry is valid (inode != 0).
    pub fn is_valid(&self) -> bool {
        self.ino != 0
    }

    /// Name length (position of first NUL or full length).
    pub fn name_len(&self) -> usize {
        self.name
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(MINIX_V1_NAME_LEN)
    }

    /// Name as a byte slice.
    pub fn name_bytes(&self) -> &[u8] {
        &self.name[..self.name_len()]
    }
}

/// Minix V2/V3 directory entry (30-byte names).
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct MinixDirEntryV2 {
    pub ino: u32,
    pub name: [u8; MINIX_V2_NAME_LEN],
}

impl MinixDirEntryV2 {
    /// Whether this entry is valid.
    pub fn is_valid(&self) -> bool {
        self.ino != 0
    }

    /// Name length.
    pub fn name_len(&self) -> usize {
        self.name
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(MINIX_V2_NAME_LEN)
    }

    /// Name as a byte slice.
    pub fn name_bytes(&self) -> &[u8] {
        &self.name[..self.name_len()]
    }
}

/// Bitmap helper for the inode and zone bitmaps.
pub struct MinixBitmap {
    /// Raw bitmap data (one bit per inode/zone).
    data: [u8; 8192],
    /// Total number of bits.
    total: u32,
    /// Number of free bits.
    free_count: u32,
}

impl MinixBitmap {
    /// Create an all-free bitmap.
    pub fn new(total: u32) -> Self {
        Self {
            data: [0u8; 8192],
            total,
            free_count: total,
        }
    }

    /// Allocate the lowest free bit. Returns the bit index or `Err(OutOfMemory)`.
    pub fn alloc(&mut self) -> Result<u32> {
        for byte_idx in 0..(self.total as usize + 7) / 8 {
            if byte_idx >= self.data.len() {
                break;
            }
            let byte = self.data[byte_idx];
            if byte != 0xff {
                for bit in 0..8u32 {
                    let idx = byte_idx as u32 * 8 + bit;
                    if idx >= self.total {
                        return Err(Error::OutOfMemory);
                    }
                    if byte & (1 << bit) == 0 {
                        self.data[byte_idx] |= 1 << bit;
                        self.free_count -= 1;
                        return Ok(idx);
                    }
                }
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Free a bit.
    pub fn free(&mut self, idx: u32) -> Result<()> {
        if idx >= self.total {
            return Err(Error::InvalidArgument);
        }
        let byte = (idx / 8) as usize;
        let bit = idx % 8;
        if self.data[byte] & (1 << bit) == 0 {
            return Err(Error::InvalidArgument); // double-free
        }
        self.data[byte] &= !(1 << bit);
        self.free_count += 1;
        Ok(())
    }

    /// Number of free entries.
    pub fn free_count(&self) -> u32 {
        self.free_count
    }
}
