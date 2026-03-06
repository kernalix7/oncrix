// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Stat operations — `stat(2)`, `fstat(2)`, `lstat(2)`, `statx(2)` semantics.
//!
//! Provides VFS-level inode attribute structures and the `StatOps` trait that
//! filesystems implement to expose file metadata to user space.

use oncrix_lib::{Error, Result};

/// File type constants for `mode` field (upper bits).
pub mod ftype {
    pub const SOCK: u32 = 0o140_000;
    pub const LNK: u32 = 0o120_000;
    pub const REG: u32 = 0o100_000;
    pub const BLK: u32 = 0o060_000;
    pub const DIR: u32 = 0o040_000;
    pub const CHR: u32 = 0o020_000;
    pub const FIFO: u32 = 0o010_000;
}

/// Permission bit constants.
pub mod perm {
    pub const SUID: u32 = 0o004_000;
    pub const SGID: u32 = 0o002_000;
    pub const SVTX: u32 = 0o001_000;
    pub const RWXU: u32 = 0o000_700;
    pub const RWXG: u32 = 0o000_070;
    pub const RWXO: u32 = 0o000_007;
}

/// Inode attributes returned by `stat(2)` — corresponds to `struct stat`.
#[derive(Debug, Clone, Copy, Default)]
pub struct InodeStat {
    /// Device ID of the containing block device.
    pub dev: u64,
    /// Inode number.
    pub ino: u64,
    /// File type and permission bits.
    pub mode: u32,
    /// Hard link count.
    pub nlink: u32,
    /// Owner user ID.
    pub uid: u32,
    /// Owner group ID.
    pub gid: u32,
    /// Device ID (for device files).
    pub rdev: u64,
    /// File size in bytes.
    pub size: i64,
    /// Preferred I/O block size.
    pub blksize: u32,
    /// Number of 512-byte blocks allocated.
    pub blocks: u64,
    /// Last access time (seconds).
    pub atime: i64,
    /// Last access time (nanoseconds fraction).
    pub atime_nsec: u32,
    /// Last modification time (seconds).
    pub mtime: i64,
    /// Last modification time (nanoseconds fraction).
    pub mtime_nsec: u32,
    /// Last status-change time (seconds).
    pub ctime: i64,
    /// Last status-change time (nanoseconds fraction).
    pub ctime_nsec: u32,
}

impl InodeStat {
    /// Return `true` if this entry is a regular file.
    pub const fn is_file(&self) -> bool {
        (self.mode & 0o170_000) == ftype::REG
    }

    /// Return `true` if this entry is a directory.
    pub const fn is_dir(&self) -> bool {
        (self.mode & 0o170_000) == ftype::DIR
    }

    /// Return `true` if this entry is a symbolic link.
    pub const fn is_symlink(&self) -> bool {
        (self.mode & 0o170_000) == ftype::LNK
    }

    /// Return the permission bits (lower 12 bits of mode).
    pub const fn permissions(&self) -> u32 {
        self.mode & 0o007_777
    }
}

/// Extended attribute mask for `statx(2)`.
#[derive(Debug, Clone, Copy, Default)]
pub struct StatxMask(pub u32);

impl StatxMask {
    pub const TYPE: u32 = 1 << 0;
    pub const MODE: u32 = 1 << 1;
    pub const NLINK: u32 = 1 << 2;
    pub const UID: u32 = 1 << 3;
    pub const GID: u32 = 1 << 4;
    pub const ATIME: u32 = 1 << 5;
    pub const MTIME: u32 = 1 << 6;
    pub const CTIME: u32 = 1 << 7;
    pub const INO: u32 = 1 << 8;
    pub const SIZE: u32 = 1 << 9;
    pub const BLOCKS: u32 = 1 << 10;
    pub const BTIME: u32 = 1 << 11; // Birth time.
    pub const ALL: u32 = 0x0FFF;

    /// Test whether a field is requested.
    pub const fn has(self, field: u32) -> bool {
        (self.0 & field) != 0
    }
}

/// Extended stat attributes returned by `statx(2)`.
#[derive(Debug, Clone, Copy, Default)]
pub struct InodeStatx {
    /// Bitmask of fields that were filled in.
    pub mask: u32,
    /// Inode attributes (STATX_ATTR_*).
    pub attributes: u64,
    /// Attribute mask indicating which `attributes` bits are valid.
    pub attributes_mask: u64,
    /// Base stat fields.
    pub stat: InodeStat,
    /// Birth (creation) time seconds (0 if unsupported).
    pub btime: i64,
    /// Birth time nanoseconds fraction.
    pub btime_nsec: u32,
    /// Mount ID where the file resides.
    pub mnt_id: u64,
}

/// Stat operations trait that filesystems implement.
pub trait StatOps {
    /// Return metadata for the inode at `(sb_id, ino)`.
    fn getattr(&self, sb_id: u64, ino: u64) -> Result<InodeStat>;

    /// Return extended metadata via `statx`.
    fn statx(&self, sb_id: u64, ino: u64, mask: StatxMask) -> Result<InodeStatx> {
        let stat = self.getattr(sb_id, ino)?;
        Ok(InodeStatx {
            mask: mask.0 & StatxMask::ALL,
            attributes: 0,
            attributes_mask: 0,
            stat,
            btime: 0,
            btime_nsec: 0,
            mnt_id: sb_id,
        })
    }

    /// Update inode metadata (chown / chmod).
    fn setattr(&mut self, sb_id: u64, ino: u64, attr: &SetAttr) -> Result<()>;
}

/// Inode attribute update specification for `setattr`.
#[derive(Debug, Clone, Copy, Default)]
pub struct SetAttr {
    /// Bitmask of fields to change.
    pub valid: SetAttrValid,
    /// New mode (only permission bits; type bits must be zero).
    pub mode: u32,
    /// New owner UID.
    pub uid: u32,
    /// New owner GID.
    pub gid: u32,
    /// New file size (for truncation via setattr).
    pub size: i64,
    /// New atime (seconds).
    pub atime: i64,
    /// New mtime (seconds).
    pub mtime: i64,
}

/// Bitmask of fields being set via `setattr`.
#[derive(Debug, Clone, Copy, Default)]
pub struct SetAttrValid(pub u32);

impl SetAttrValid {
    pub const MODE: u32 = 1 << 0;
    pub const UID: u32 = 1 << 1;
    pub const GID: u32 = 1 << 2;
    pub const SIZE: u32 = 1 << 3;
    pub const ATIME: u32 = 1 << 4;
    pub const MTIME: u32 = 1 << 5;

    /// Test whether a field is being set.
    pub const fn has(self, flag: u32) -> bool {
        (self.0 & flag) != 0
    }
}

/// Validate a `setattr` request for semantic correctness.
pub fn validate_setattr(attr: &SetAttr, caller_uid: u32, caller_privileged: bool) -> Result<()> {
    // Only root or file owner can change ownership.
    if attr.valid.has(SetAttrValid::UID) || attr.valid.has(SetAttrValid::GID) {
        if !caller_privileged && caller_uid != 0 {
            return Err(Error::PermissionDenied);
        }
    }
    // Mode change: only owner or root.
    if attr.valid.has(SetAttrValid::MODE) {
        // Top bits (file type) must not be set.
        if (attr.mode & 0o170_000) != 0 {
            return Err(Error::InvalidArgument);
        }
    }
    Ok(())
}
