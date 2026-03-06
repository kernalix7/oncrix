// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! GFS2 (Global File System 2) on-disk inode structure.
//!
//! GFS2 is Red Hat's cluster filesystem successor to GFS. It uses a
//! resource-group-based allocation system and embeds a small extent tree
//! directly in each inode's disk structure.
//!
//! # Dinode Layout
//!
//! The GFS2 dinode (disk inode) begins with a standard GFS2 metadata header,
//! followed by inode-specific fields and a block pointer region (for small
//! files) or a height/pointer tree (for larger files).
//!
//! # Height-based Indirect Blocks
//!
//! GFS2 uses a variable-height tree of indirect block pointers. Height 0
//! means the file data fits in the inode's direct pointer slots. Height 1+
//! adds layers of indirect blocks.

use oncrix_lib::{Error, Result};

/// GFS2 metadata block type for inodes.
pub const GFS2_METATYPE_DI: u16 = 4;

/// GFS2 metadata header magic.
pub const GFS2_MAGIC: u32 = 0x01161970;

/// GFS2 inode flags.
pub mod di_flags {
    /// Inode is jdata (journaled data mode).
    pub const GFS2_DIF_JDATA: u32 = 0x00000001;
    /// Inode is a directory hash table.
    pub const GFS2_DIF_EXHASH: u32 = 0x00000002;
    /// Inode has extended attributes in the EA space.
    pub const GFS2_DIF_EA_INDIRECT: u32 = 0x00000008;
    /// Inode uses AppendOnly.
    pub const GFS2_DIF_APPENDONLY: u32 = 0x00000010;
    /// Inode is immutable.
    pub const GFS2_DIF_IMMUTABLE: u32 = 0x00000020;
    /// Inode is inhomogeneous (uses stuffed data).
    pub const GFS2_DIF_STUFFED: u32 = 0x00000100;
}

/// GFS2 metadata block header (16 bytes).
#[derive(Clone, Copy, Default)]
pub struct MetaHeader {
    /// Magic number.
    pub mh_magic: u32,
    /// Metadata type.
    pub mh_type: u16,
    /// Format version.
    pub mh_format: u16,
    /// Unused / sequence number.
    pub mh_seq: u64,
}

impl MetaHeader {
    /// Parses from 16 bytes.
    pub fn from_bytes(b: &[u8]) -> Result<Self> {
        if b.len() < 16 {
            return Err(Error::InvalidArgument);
        }
        let magic = u32::from_be_bytes([b[0], b[1], b[2], b[3]]);
        if magic != GFS2_MAGIC {
            return Err(Error::InvalidArgument);
        }
        Ok(Self {
            mh_magic: magic,
            mh_type: u16::from_be_bytes([b[4], b[5]]),
            mh_format: u16::from_be_bytes([b[6], b[7]]),
            mh_seq: u64::from_be_bytes([b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]]),
        })
    }
}

/// GFS2 on-disk inode (dinode).
#[derive(Clone, Copy, Default)]
pub struct Gfs2Dinode {
    /// Metadata header.
    pub header: MetaHeader,
    /// Inode number.
    pub di_num: u64,
    /// POSIX mode bits.
    pub di_mode: u32,
    /// UID.
    pub di_uid: u32,
    /// GID.
    pub di_gid: u32,
    /// Number of hard links.
    pub di_nlink: u32,
    /// File size in bytes.
    pub di_size: u64,
    /// Number of 512-byte blocks allocated.
    pub di_blocks: u64,
    /// Access time (seconds).
    pub di_atime: u64,
    /// Modification time.
    pub di_mtime: u64,
    /// Change time.
    pub di_ctime: u64,
    /// Generation number.
    pub di_generation: u64,
    /// Inode flags (see [`di_flags`]).
    pub di_flags: u32,
    /// Current indirection height.
    pub di_height: u8,
    /// Number of entries in a directory (for directories).
    pub di_entries: u32,
}

impl Gfs2Dinode {
    /// Parses a GFS2 dinode from at least 192 bytes.
    pub fn from_bytes(b: &[u8]) -> Result<Self> {
        if b.len() < 192 {
            return Err(Error::InvalidArgument);
        }
        let header = MetaHeader::from_bytes(&b[0..16])?;
        if header.mh_type != GFS2_METATYPE_DI {
            return Err(Error::InvalidArgument);
        }
        Ok(Self {
            header,
            di_num: u64::from_be_bytes([b[16], b[17], b[18], b[19], b[20], b[21], b[22], b[23]]),
            di_mode: u32::from_be_bytes([b[24], b[25], b[26], b[27]]),
            di_uid: u32::from_be_bytes([b[28], b[29], b[30], b[31]]),
            di_gid: u32::from_be_bytes([b[32], b[33], b[34], b[35]]),
            di_nlink: u32::from_be_bytes([b[36], b[37], b[38], b[39]]),
            di_size: u64::from_be_bytes([b[40], b[41], b[42], b[43], b[44], b[45], b[46], b[47]]),
            di_blocks: u64::from_be_bytes([b[48], b[49], b[50], b[51], b[52], b[53], b[54], b[55]]),
            di_atime: u64::from_be_bytes([b[56], b[57], b[58], b[59], b[60], b[61], b[62], b[63]]),
            di_mtime: u64::from_be_bytes([b[64], b[65], b[66], b[67], b[68], b[69], b[70], b[71]]),
            di_ctime: u64::from_be_bytes([b[72], b[73], b[74], b[75], b[76], b[77], b[78], b[79]]),
            di_generation: u64::from_be_bytes([
                b[80], b[81], b[82], b[83], b[84], b[85], b[86], b[87],
            ]),
            di_flags: u32::from_be_bytes([b[88], b[89], b[90], b[91]]),
            di_height: b[92],
            di_entries: u32::from_be_bytes([b[93], b[94], b[95], b[96]]),
        })
    }

    /// Returns `true` if the inode uses stuffed (inline) data.
    pub const fn is_stuffed(&self) -> bool {
        self.di_flags & di_flags::GFS2_DIF_STUFFED != 0
    }

    /// Returns `true` if this is a directory using hash-based lookup.
    pub const fn uses_exhash(&self) -> bool {
        self.di_flags & di_flags::GFS2_DIF_EXHASH != 0
    }

    /// Returns `true` if the data is journaled.
    pub const fn is_jdata(&self) -> bool {
        self.di_flags & di_flags::GFS2_DIF_JDATA != 0
    }

    /// Returns `true` if this is a regular file.
    pub const fn is_regular(&self) -> bool {
        self.di_mode & 0xF000 == 0x8000
    }

    /// Returns `true` if this is a directory.
    pub const fn is_dir(&self) -> bool {
        self.di_mode & 0xF000 == 0x4000
    }
}
