// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! OCFS2 inode structure and metadata parsing.
//!
//! OCFS2 inodes (called "dinodes" — disk inodes) are stored in a global
//! inode file. Each dinode is 512 bytes and contains all file metadata
//! as well as inline extent information.
//!
//! # Dinode Layout
//!
//! The OCFS2 dinode begins with a signature, followed by mode, uid/gid,
//! size, and timestamps. The extent tree (or inline data) is embedded at
//! the end of the dinode structure.
//!
//! # Inline Data
//!
//! Small files and directories may use inline data stored directly in the
//! dinode's data area when `OCFS2_INLINE_DATA_FL` is set.

use oncrix_lib::{Error, Result};

/// OCFS2 dinode signature bytes.
pub const OCFS2_INODE_SIGNATURE: &[u8; 8] = b"INODE01\0";

/// Size of an OCFS2 dinode on disk.
pub const OCFS2_DINODE_SIZE: usize = 512;

/// OCFS2 inode flags.
pub mod inode_flags {
    /// Inode has inline data.
    pub const OCFS2_INLINE_DATA_FL: u32 = 0x00000001;
    /// Inode is a cluster-allocated file.
    pub const OCFS2_LOCAL_ALLOC_FL: u32 = 0x00000002;
    /// Inode has been opened read-only from this node.
    pub const OCFS2_SYSTEM_FL: u32 = 0x00000004;
    /// Inode uses fast symlink storage.
    pub const OCFS2_FAST_SYMLINK_FL: u32 = 0x00000020;
    /// Inode has extended attributes.
    pub const OCFS2_HAS_XATTR_FL: u32 = 0x00004000;
    /// Inode has inline extended attributes.
    pub const OCFS2_INLINE_XATTR_FL: u32 = 0x00008000;
}

/// An OCFS2 disk inode (dinode).
#[derive(Clone, Copy, Default)]
pub struct OcfsDinode {
    /// Inode generation number.
    pub i_generation: u32,
    /// Inode flags (see [`inode_flags`]).
    pub i_flags: u32,
    /// POSIX file mode bits.
    pub i_mode: u16,
    /// Number of hard links.
    pub i_links_count: u16,
    /// Owner UID.
    pub i_uid: u32,
    /// Owner GID.
    pub i_gid: u32,
    /// File size in bytes.
    pub i_size: u64,
    /// Access time (seconds).
    pub i_atime: u64,
    /// Modification time (seconds).
    pub i_mtime: u64,
    /// Inode change time (seconds).
    pub i_ctime: u64,
    /// Number of 512-byte blocks allocated.
    pub i_blocks: u64,
    /// Inode number.
    pub i_blkno: u64,
    /// Suballocation slot.
    pub i_suballoc_slot: u16,
    /// Suballocation bit within the slot's bitmap.
    pub i_suballoc_bit: u16,
    /// Cluster number of the first inline extent.
    pub i_clusters: u32,
}

impl OcfsDinode {
    /// Parses a dinode from a 512-byte raw block.
    pub fn from_bytes(b: &[u8]) -> Result<Self> {
        if b.len() < OCFS2_DINODE_SIZE {
            return Err(Error::InvalidArgument);
        }
        // Verify signature.
        if &b[..8] != OCFS2_INODE_SIGNATURE {
            return Err(Error::InvalidArgument);
        }
        Ok(Self {
            i_generation: u32::from_le_bytes([b[8], b[9], b[10], b[11]]),
            i_flags: u32::from_le_bytes([b[12], b[13], b[14], b[15]]),
            i_mode: u16::from_le_bytes([b[16], b[17]]),
            i_links_count: u16::from_le_bytes([b[18], b[19]]),
            i_uid: u32::from_le_bytes([b[20], b[21], b[22], b[23]]),
            i_gid: u32::from_le_bytes([b[24], b[25], b[26], b[27]]),
            i_size: u64::from_le_bytes([b[28], b[29], b[30], b[31], b[32], b[33], b[34], b[35]]),
            i_atime: u64::from_le_bytes([b[36], b[37], b[38], b[39], b[40], b[41], b[42], b[43]]),
            i_mtime: u64::from_le_bytes([b[44], b[45], b[46], b[47], b[48], b[49], b[50], b[51]]),
            i_ctime: u64::from_le_bytes([b[52], b[53], b[54], b[55], b[56], b[57], b[58], b[59]]),
            i_blocks: u64::from_le_bytes([b[60], b[61], b[62], b[63], b[64], b[65], b[66], b[67]]),
            i_blkno: u64::from_le_bytes([b[68], b[69], b[70], b[71], b[72], b[73], b[74], b[75]]),
            i_suballoc_slot: u16::from_le_bytes([b[76], b[77]]),
            i_suballoc_bit: u16::from_le_bytes([b[78], b[79]]),
            i_clusters: u32::from_le_bytes([b[80], b[81], b[82], b[83]]),
        })
    }

    /// Returns `true` if this inode uses inline data.
    pub const fn has_inline_data(&self) -> bool {
        self.i_flags & inode_flags::OCFS2_INLINE_DATA_FL != 0
    }

    /// Returns `true` if this is a regular file.
    pub const fn is_regular(&self) -> bool {
        self.i_mode & 0xF000 == 0x8000
    }

    /// Returns `true` if this is a directory.
    pub const fn is_dir(&self) -> bool {
        self.i_mode & 0xF000 == 0x4000
    }

    /// Returns `true` if this is a symbolic link.
    pub const fn is_symlink(&self) -> bool {
        self.i_mode & 0xF000 == 0xA000
    }
}
