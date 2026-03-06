// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! bcachefs inode record parsing and management.
//!
//! bcachefs stores inode metadata as values in the `Inodes` B-tree.
//! Unlike traditional filesystems, there is no fixed-size inode table;
//! inodes are variable-length records looked up by inode number.
//!
//! # Inode Fields
//!
//! bcachefs inodes store the standard POSIX stat fields plus additional
//! bcachefs-specific fields for compression, checksums, and encryption.
//!
//! # Inode Generations
//!
//! The combination of `(inode_number, snapshot_id)` uniquely identifies
//! a specific version of an inode across snapshots.

use oncrix_lib::{Error, Result};

/// bcachefs inode type codes.
pub mod inode_type {
    /// Regular file.
    pub const FILE: u16 = 0x8000;
    /// Directory.
    pub const DIR: u16 = 0x4000;
    /// Symbolic link.
    pub const SYMLINK: u16 = 0xA000;
    /// Character device.
    pub const CHARDEV: u16 = 0x2000;
    /// Block device.
    pub const BLKDEV: u16 = 0x6000;
    /// Named pipe (FIFO).
    pub const FIFO: u16 = 0x1000;
    /// Unix socket.
    pub const SOCK: u16 = 0xC000;
}

/// bcachefs inode flags.
pub mod inode_flags {
    /// Inode uses inline data.
    pub const BI_UNWRITTEN: u64 = 1 << 0;
    /// Inode has no data to hash.
    pub const BI_HASH_SEED: u64 = 1 << 1;
    /// Inode data is compressed.
    pub const BI_COMPRESSION: u64 = 1 << 2;
    /// Inode checksums are disabled.
    pub const BI_NOCOW: u64 = 1 << 3;
}

/// A bcachefs inode (bch_inode_unpacked).
#[derive(Clone, Copy, Default)]
pub struct BcachefsInode {
    /// Inode number.
    pub bi_inum: u64,
    /// Hash seed (for directory hash table).
    pub bi_hash_seed: u64,
    /// Inode flags.
    pub bi_flags: u64,
    /// POSIX mode (type + permissions).
    pub bi_mode: u16,
    /// Owner UID.
    pub bi_uid: u32,
    /// Owner GID.
    pub bi_gid: u32,
    /// Number of hard links (or subdirectory count for dirs).
    pub bi_nlink: u32,
    /// Device number (for device files).
    pub bi_dev: u64,
    /// File data size in bytes.
    pub bi_size: u64,
    /// Number of 512-byte sectors allocated.
    pub bi_sectors: u64,
    /// Last access time (nanoseconds since epoch).
    pub bi_atime: u64,
    /// Creation time.
    pub bi_ctime: u64,
    /// Modification time.
    pub bi_mtime: u64,
    /// Inode change time.
    pub bi_otime: u64,
    /// Generation number.
    pub bi_generation: u32,
}

impl BcachefsInode {
    /// Parses a bcachefs inode from a byte slice (minimum 128 bytes).
    pub fn from_bytes(b: &[u8]) -> Result<Self> {
        if b.len() < 128 {
            return Err(Error::InvalidArgument);
        }
        Ok(Self {
            bi_inum: u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]),
            bi_hash_seed: u64::from_le_bytes([
                b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15],
            ]),
            bi_flags: u64::from_le_bytes([b[16], b[17], b[18], b[19], b[20], b[21], b[22], b[23]]),
            bi_mode: u16::from_le_bytes([b[24], b[25]]),
            bi_uid: u32::from_le_bytes([b[26], b[27], b[28], b[29]]),
            bi_gid: u32::from_le_bytes([b[30], b[31], b[32], b[33]]),
            bi_nlink: u32::from_le_bytes([b[34], b[35], b[36], b[37]]),
            bi_dev: u64::from_le_bytes([b[38], b[39], b[40], b[41], b[42], b[43], b[44], b[45]]),
            bi_size: u64::from_le_bytes([b[46], b[47], b[48], b[49], b[50], b[51], b[52], b[53]]),
            bi_sectors: u64::from_le_bytes([
                b[54], b[55], b[56], b[57], b[58], b[59], b[60], b[61],
            ]),
            bi_atime: u64::from_le_bytes([b[62], b[63], b[64], b[65], b[66], b[67], b[68], b[69]]),
            bi_ctime: u64::from_le_bytes([b[70], b[71], b[72], b[73], b[74], b[75], b[76], b[77]]),
            bi_mtime: u64::from_le_bytes([b[78], b[79], b[80], b[81], b[82], b[83], b[84], b[85]]),
            bi_otime: u64::from_le_bytes([b[86], b[87], b[88], b[89], b[90], b[91], b[92], b[93]]),
            bi_generation: u32::from_le_bytes([b[94], b[95], b[96], b[97]]),
        })
    }

    /// Returns `true` if this inode is a regular file.
    pub const fn is_regular(&self) -> bool {
        self.bi_mode & 0xF000 == inode_type::FILE
    }

    /// Returns `true` if this inode is a directory.
    pub const fn is_dir(&self) -> bool {
        self.bi_mode & 0xF000 == inode_type::DIR
    }

    /// Returns `true` if this inode is a symbolic link.
    pub const fn is_symlink(&self) -> bool {
        self.bi_mode & 0xF000 == inode_type::SYMLINK
    }

    /// Returns the file type bits (upper 4 bits of mode).
    pub const fn file_type(&self) -> u16 {
        self.bi_mode & 0xF000
    }

    /// Returns `true` if this inode uses copy-on-write.
    pub const fn uses_cow(&self) -> bool {
        self.bi_flags & inode_flags::BI_NOCOW == 0
    }
}
