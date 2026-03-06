// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! XFS disk quota (dquot) structures and management.
//!
//! XFS implements POSIX-compatible quota management for user, group, and
//! project (directory tree) quotas. Quota information is stored in special
//! files within the filesystem: `//quota.user`, `//quota.group`, `//quota.proj`.
//!
//! # Dquot Structure
//!
//! Each quota entry (dquot) records:
//! - Current disk and inode usage.
//! - Hard and soft limits for both disk blocks and inodes.
//! - Grace period timers for soft-limit violations.
//!
//! # Block Accounting
//!
//! XFS counts quota in fundamental filesystem blocks (usually 4 KiB).
//! The `d_bcount` field is in 512-byte units (POSIX `struct dqblk` convention).

use oncrix_lib::{Error, Result};

/// XFS quota types.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u32)]
pub enum QuotaType {
    /// User quota.
    User = 0,
    /// Group quota.
    Group = 1,
    /// Project (directory-tree) quota.
    Project = 2,
}

impl Default for QuotaType {
    fn default() -> Self {
        Self::User
    }
}

impl QuotaType {
    /// Parses from u32.
    pub fn from_u32(v: u32) -> Result<Self> {
        match v {
            0 => Ok(Self::User),
            1 => Ok(Self::Group),
            2 => Ok(Self::Project),
            _ => Err(Error::InvalidArgument),
        }
    }
}

/// Quota warning levels.
#[derive(Clone, Copy, Default, Debug)]
pub struct QuotaWarnings {
    /// Number of soft-block-limit warnings issued.
    pub block_warns: u8,
    /// Number of soft-inode-limit warnings issued.
    pub inode_warns: u8,
    /// Number of soft-realtime-block warnings issued.
    pub rtblock_warns: u8,
}

/// An XFS on-disk dquot (64 bytes).
#[derive(Clone, Copy, Default)]
pub struct XfsDquot {
    /// Dquot magic number (0x5144 = "QD").
    pub d_magic: u16,
    /// Dquot version.
    pub d_version: u8,
    /// Dquot flags (type: user/group/project).
    pub d_flags: u8,
    /// Identifier (UID/GID/PROJID).
    pub d_id: u32,
    /// Current 512-byte block usage.
    pub d_bcount: u64,
    /// Current inode count.
    pub d_icount: u64,
    /// Current realtime block usage.
    pub d_rtbcount: u64,
    /// Block hard limit (512-byte units).
    pub d_blk_hardlimit: u64,
    /// Block soft limit (512-byte units).
    pub d_blk_softlimit: u64,
    /// Inode hard limit.
    pub d_ino_hardlimit: u64,
    /// Inode soft limit.
    pub d_ino_softlimit: u64,
    /// Realtime block hard limit.
    pub d_rtb_hardlimit: u64,
    /// Realtime block soft limit.
    pub d_rtb_softlimit: u64,
    /// Block grace period expiry (Unix timestamp).
    pub d_btimer: u32,
    /// Inode grace period expiry.
    pub d_itimer: u32,
    /// Realtime block grace period expiry.
    pub d_rtbtimer: u32,
    /// Warning counts.
    pub d_warnings: QuotaWarnings,
}

/// Magic number for XFS dquot blocks.
pub const XFS_DQUOT_MAGIC: u16 = 0x5144;

impl XfsDquot {
    /// Parses an XFS dquot from a 96-byte slice.
    pub fn from_bytes(b: &[u8]) -> Result<Self> {
        if b.len() < 96 {
            return Err(Error::InvalidArgument);
        }
        let magic = u16::from_be_bytes([b[0], b[1]]);
        if magic != XFS_DQUOT_MAGIC {
            return Err(Error::InvalidArgument);
        }
        Ok(Self {
            d_magic: magic,
            d_version: b[2],
            d_flags: b[3],
            d_id: u32::from_be_bytes([b[4], b[5], b[6], b[7]]),
            d_bcount: u64::from_be_bytes([b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]]),
            d_icount: u64::from_be_bytes([b[16], b[17], b[18], b[19], b[20], b[21], b[22], b[23]]),
            d_rtbcount: u64::from_be_bytes([
                b[24], b[25], b[26], b[27], b[28], b[29], b[30], b[31],
            ]),
            d_blk_hardlimit: u64::from_be_bytes([
                b[32], b[33], b[34], b[35], b[36], b[37], b[38], b[39],
            ]),
            d_blk_softlimit: u64::from_be_bytes([
                b[40], b[41], b[42], b[43], b[44], b[45], b[46], b[47],
            ]),
            d_ino_hardlimit: u64::from_be_bytes([
                b[48], b[49], b[50], b[51], b[52], b[53], b[54], b[55],
            ]),
            d_ino_softlimit: u64::from_be_bytes([
                b[56], b[57], b[58], b[59], b[60], b[61], b[62], b[63],
            ]),
            d_rtb_hardlimit: u64::from_be_bytes([
                b[64], b[65], b[66], b[67], b[68], b[69], b[70], b[71],
            ]),
            d_rtb_softlimit: u64::from_be_bytes([
                b[72], b[73], b[74], b[75], b[76], b[77], b[78], b[79],
            ]),
            d_btimer: u32::from_be_bytes([b[80], b[81], b[82], b[83]]),
            d_itimer: u32::from_be_bytes([b[84], b[85], b[86], b[87]]),
            d_rtbtimer: u32::from_be_bytes([b[88], b[89], b[90], b[91]]),
            d_warnings: QuotaWarnings {
                block_warns: b[92],
                inode_warns: b[93],
                rtblock_warns: b[94],
            },
        })
    }

    /// Returns `true` if the block usage exceeds the hard limit.
    pub const fn over_block_hard_limit(&self) -> bool {
        self.d_blk_hardlimit != 0 && self.d_bcount > self.d_blk_hardlimit
    }

    /// Returns `true` if the block usage exceeds the soft limit.
    pub const fn over_block_soft_limit(&self) -> bool {
        self.d_blk_softlimit != 0 && self.d_bcount > self.d_blk_softlimit
    }

    /// Returns `true` if the inode count exceeds the hard limit.
    pub const fn over_inode_hard_limit(&self) -> bool {
        self.d_ino_hardlimit != 0 && self.d_icount > self.d_ino_hardlimit
    }

    /// Returns `true` if a new file creation should be blocked (hard limit reached).
    pub const fn can_create_file(&self, now: u32) -> bool {
        if self.over_block_hard_limit() || self.over_inode_hard_limit() {
            return false;
        }
        // If soft limit exceeded and grace period expired, also block.
        if self.over_block_soft_limit() && self.d_btimer != 0 && now > self.d_btimer {
            return false;
        }
        true
    }
}
