// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! EROFS superblock and filesystem initialization.
//!
//! EROFS (Enhanced Read-Only File System) is a compressed, read-only filesystem
//! designed for embedded systems and container images.  This module parses the
//! on-disk superblock, validates the layout, and provides the top-level
//! superblock descriptor used by the rest of the EROFS implementation.

use oncrix_lib::{Error, Result};

/// EROFS magic number stored at offset 0 in the superblock.
pub const EROFS_MAGIC: u32 = 0xe0f5_e1e2;

/// Superblock is always located at block 0, byte offset 1024.
pub const EROFS_SUPER_OFFSET: usize = 1024;

/// Minimum superblock size (bytes).
pub const EROFS_SUPER_SIZE: usize = 128;

/// Default EROFS block size (may vary by version).
pub const EROFS_BLOCK_SIZE: usize = 4096;

/// Feature flags (lo word).
pub mod feature_lo {
    pub const LZ4_0PADDING: u32 = 0x0001;
    pub const COMPR_CFGS: u32 = 0x0002;
    pub const BIG_PCLUSTER: u32 = 0x0004;
    pub const CHUNKED_FILE: u32 = 0x0008;
    pub const DEVICE_TABLE: u32 = 0x0010;
    pub const COMPR_HEAD2: u32 = 0x0020;
    pub const INLINE_PCLUSTER: u32 = 0x0040;
    pub const ZTAILPACKING: u32 = 0x0080;
    pub const FRAGMENTS: u32 = 0x0100;
}

/// On-disk EROFS superblock layout.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct ErofsSuperblockDisk {
    /// Magic number (must equal `EROFS_MAGIC`).
    pub magic: u32,
    /// CRC32 of the superblock (optional, 0 if not used).
    pub checksum: u32,
    /// Feature compatibility flags (lo).
    pub feature_compat: u32,
    /// Log2 of the block size.
    pub blkszbits: u8,
    /// Superblock extension size in units of 16 bytes.
    pub sb_extslots: u8,
    /// Root inode number (NID).
    pub root_nid: u16,
    /// Total number of inodes.
    pub inos: u64,
    /// Build timestamp (UNIX seconds).
    pub build_time: u64,
    /// Nanosecond component of build timestamp.
    pub build_time_nsec: u32,
    /// Total number of blocks.
    pub blocks: u32,
    /// Block number of the metadata start (after the superblock).
    pub meta_blkaddr: u32,
    /// Block number of the xattr metadata area.
    pub xattr_blkaddr: u32,
    /// UUID (16 bytes).
    pub uuid: [u8; 16],
    /// Volume label (16 bytes, NUL-padded).
    pub volume_name: [u8; 16],
    /// Feature incompatibility flags.
    pub feature_incompat: u32,
    /// Union: compression or chunk bits.
    pub compression_or_chunk: u16,
    /// Extra device table count.
    pub extra_devices: u16,
    /// Offset of the device table relative to the superblock.
    pub devt_slotoff: u16,
    /// Log2 of directory block size (0 = same as block size).
    pub dirblkbits: u8,
    /// XAttr prefix count.
    pub xattr_prefix_count: u8,
    /// XAttr prefix start offset.
    pub xattr_prefix_start: u32,
    /// Total packed (compressed) inode count.
    pub packed_nid: u64,
    pub _reserved: [u8; 24],
}

/// In-memory EROFS superblock descriptor.
#[derive(Debug, Clone)]
pub struct ErofsSuperblock {
    /// Block size in bytes (derived from `blkszbits`).
    pub block_size: usize,
    /// Root inode NID.
    pub root_nid: u64,
    /// Total inodes on the filesystem.
    pub total_inodes: u64,
    /// Total blocks.
    pub total_blocks: u64,
    /// Block address of the metadata area.
    pub meta_blkaddr: u32,
    /// Block address of the xattr area (0 = none).
    pub xattr_blkaddr: u32,
    /// Feature-compat flags.
    pub feature_compat: u32,
    /// Feature-incompat flags.
    pub feature_incompat: u32,
    /// Volume label (NUL-terminated, up to 16 chars).
    pub volume_name: [u8; 16],
    /// UUID bytes.
    pub uuid: [u8; 16],
    /// Build timestamp.
    pub build_time: u64,
    /// Extra device count.
    pub extra_devices: u16,
    /// Whether the packed-inode feature is enabled.
    pub packed_inode_enabled: bool,
}

impl ErofsSuperblock {
    /// Parse and validate an on-disk superblock.
    ///
    /// `data` must point to at least `EROFS_SUPER_SIZE` bytes at offset
    /// `EROFS_SUPER_OFFSET` within the first block.
    pub fn parse(disk: &ErofsSuperblockDisk) -> Result<Self> {
        if disk.magic != EROFS_MAGIC {
            return Err(Error::InvalidArgument);
        }
        if disk.blkszbits < 9 || disk.blkszbits > 15 {
            return Err(Error::InvalidArgument);
        }
        let block_size = 1usize << disk.blkszbits;
        Ok(Self {
            block_size,
            root_nid: disk.root_nid as u64,
            total_inodes: disk.inos,
            total_blocks: disk.blocks as u64,
            meta_blkaddr: disk.meta_blkaddr,
            xattr_blkaddr: disk.xattr_blkaddr,
            feature_compat: disk.feature_compat,
            feature_incompat: disk.feature_incompat,
            volume_name: disk.volume_name,
            uuid: disk.uuid,
            build_time: disk.build_time,
            extra_devices: disk.extra_devices,
            packed_inode_enabled: disk.packed_nid != 0,
        })
    }

    /// Whether a compat feature is enabled.
    pub fn has_compat(&self, flag: u32) -> bool {
        self.feature_compat & flag != 0
    }

    /// Whether an incompat feature is enabled.
    pub fn has_incompat(&self, flag: u32) -> bool {
        self.feature_incompat & flag != 0
    }

    /// Convert a block address to a byte offset.
    pub fn blkaddr_to_offset(&self, blkaddr: u32) -> u64 {
        (blkaddr as u64) * (self.block_size as u64)
    }

    /// Convert the root NID to a byte offset within the metadata area.
    pub fn nid_to_offset(&self, nid: u64) -> u64 {
        self.blkaddr_to_offset(self.meta_blkaddr) + (nid << 5)
    }

    /// Volume label as a str slice (truncated at first NUL).
    pub fn volume_label(&self) -> &[u8] {
        let len = self.volume_name.iter().position(|&b| b == 0).unwrap_or(16);
        &self.volume_name[..len]
    }
}

/// Compression algorithms supported by EROFS.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErofsCompressor {
    /// No compression (or storage-only chunks).
    None,
    /// LZ4 block compression.
    Lz4,
    /// LZ4HC (high compression) variant.
    Lz4Hc,
    /// LZMA compression (EROFS v1.3+).
    Lzma,
    /// Deflate (zlib-compatible).
    Deflate,
    /// Zstd compression.
    Zstd,
}

impl ErofsCompressor {
    /// Derive the compressor from the on-disk algorithm tag.
    pub fn from_tag(tag: u16) -> Result<Self> {
        match tag {
            0 => Ok(Self::Lz4),
            1 => Ok(Self::Lz4Hc),
            2 => Ok(Self::Lzma),
            3 => Ok(Self::Deflate),
            4 => Ok(Self::Zstd),
            _ => Err(Error::NotImplemented),
        }
    }
}

/// EROFS compression configuration attached to a superblock.
#[derive(Debug, Clone)]
pub struct ErofsCompressConfig {
    pub algorithm: ErofsCompressor,
    /// Log2 of the maximum cluster size.
    pub log2_max_pcluster_sz: u8,
    /// Whether head-2 compression is used.
    pub head2: bool,
}

impl ErofsCompressConfig {
    /// Default (LZ4, 4 KiB clusters).
    pub fn default_lz4() -> Self {
        Self {
            algorithm: ErofsCompressor::Lz4,
            log2_max_pcluster_sz: 12,
            head2: false,
        }
    }
}
