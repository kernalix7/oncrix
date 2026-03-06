// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! JFS (Journaled File System) superblock and aggregate structures.
//!
//! JFS is IBM's journaled filesystem, originally developed for AIX and ported
//! to Linux. This module implements the on-disk superblock layout and basic
//! filesystem initialization checks.
//!
//! # JFS Aggregate
//!
//! JFS uses the concept of an "aggregate" — a single block device partitioned
//! into multiple logical filesystems (called "filesets"). The aggregate superblock
//! is stored at a fixed location on disk.
//!
//! # Superblock Location
//!
//! The primary superblock is at sector 64 (32 KiB). A backup copy is at the
//! last 64 sectors of the aggregate.

use oncrix_lib::{Error, Result};

/// JFS magic number (ASCII "JFS1" little-endian).
pub const JFS_MAGIC: u32 = 0x3153464A;

/// Sector offset of the primary superblock.
pub const JFS_SB_SECTOR: u64 = 64;

/// Size of a JFS disk block (4096 bytes standard, or 512/1024/2048).
pub const JFS_DEFAULT_BLOCK_SIZE: u32 = 4096;

/// JFS feature flags.
pub mod features {
    /// Volume is a character case-insensitive aggregate.
    pub const JFS_INCOMPAT_CASE_INSENSITIVE: u32 = 0x00000001;
    /// Volume uses full integrity journaling.
    pub const JFS_INCOMPAT_INTEGRITY: u32 = 0x00000004;
}

/// JFS on-disk superblock (simplified — full struct is 512 bytes).
#[derive(Clone, Copy, Default)]
pub struct JfsSuperblock {
    /// Magic number (must be JFS_MAGIC).
    pub magic: u32,
    /// Filesystem version (1 or 2).
    pub version: u32,
    /// Total size of the aggregate in filesystem blocks.
    pub size: u64,
    /// Log2 of the block size.
    pub l2bsize: u32,
    /// Block size in bytes.
    pub bsize: u32,
    /// Number of inodes in the aggregate.
    pub ninode: u32,
    /// LBA of the aggregate inode (AIT) map.
    pub ait2: u64,
    /// Number of AGs (allocation groups).
    pub num_ags: u32,
    /// Incompatible feature flags.
    pub incompat_features: u32,
    /// Aggregate state flags.
    pub state: u32,
    /// Filesystem label (null-terminated, up to 11 bytes).
    pub label: [u8; 16],
    /// UUID (16 bytes).
    pub uuid: [u8; 16],
}

/// JFS aggregate states.
pub mod state {
    /// Filesystem is clean.
    pub const FM_CLEAN: u32 = 0x00000000;
    /// Filesystem is dirty (mounted read-write).
    pub const FM_DIRTY: u32 = 0x00000001;
    /// Filesystem is being recovered.
    pub const FM_LOGREDO: u32 = 0x00000004;
}

impl JfsSuperblock {
    /// Parses a JFS superblock from a 512-byte raw sector.
    pub fn from_bytes(b: &[u8]) -> Result<Self> {
        if b.len() < 512 {
            return Err(Error::InvalidArgument);
        }
        let magic = u32::from_le_bytes([b[0], b[1], b[2], b[3]]);
        if magic != JFS_MAGIC {
            return Err(Error::InvalidArgument);
        }
        let mut label = [0u8; 16];
        label.copy_from_slice(&b[80..96]);
        let mut uuid = [0u8; 16];
        uuid.copy_from_slice(&b[96..112]);
        Ok(Self {
            magic,
            version: u32::from_le_bytes([b[4], b[5], b[6], b[7]]),
            size: u64::from_le_bytes([b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]]),
            l2bsize: u32::from_le_bytes([b[16], b[17], b[18], b[19]]),
            bsize: u32::from_le_bytes([b[20], b[21], b[22], b[23]]),
            ninode: u32::from_le_bytes([b[24], b[25], b[26], b[27]]),
            ait2: u64::from_le_bytes([b[32], b[33], b[34], b[35], b[36], b[37], b[38], b[39]]),
            num_ags: u32::from_le_bytes([b[40], b[41], b[42], b[43]]),
            incompat_features: u32::from_le_bytes([b[56], b[57], b[58], b[59]]),
            state: u32::from_le_bytes([b[60], b[61], b[62], b[63]]),
            label,
            uuid,
        })
    }

    /// Returns `true` if the filesystem was cleanly unmounted.
    pub const fn is_clean(&self) -> bool {
        self.state == state::FM_CLEAN
    }

    /// Returns the filesystem label as a byte slice (strips trailing nulls).
    pub fn label_str(&self) -> &[u8] {
        let end = self.label.iter().position(|&b| b == 0).unwrap_or(16);
        &self.label[..end]
    }

    /// Returns the block size as a power of 2 (e.g., 12 for 4096).
    pub const fn log2_block_size(&self) -> u32 {
        self.l2bsize
    }
}
