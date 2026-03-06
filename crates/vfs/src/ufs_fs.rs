// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! UFS (Unix File System) filesystem support.
//!
//! Implements the core data structures and algorithms for UFS1 and UFS2
//! (also known as FFS — Fast File System).  UFS2 is the default filesystem
//! on FreeBSD; UFS1 is compatible with older BSDs and Solaris.

use oncrix_lib::{Error, Result};

/// UFS1 magic number.
pub const UFS1_MAGIC: u32 = 0x011954;
/// UFS2 magic number.
pub const UFS2_MAGIC: u32 = 0x19540119;

/// UFS superblock offset from the start of the partition (bytes).
pub const UFS_SBOFF: u64 = 65536;

/// Size of a UFS cylinder group summary.
pub const UFS_CGSIZE: usize = 4096;

/// Maximum fragment size (log2 = 13 → 8 KiB).
pub const UFS_MAXFRAG: usize = 8192;

/// UFS version tag.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UfsVersion {
    Ufs1,
    Ufs2,
}

/// In-memory UFS superblock.
#[derive(Debug, Clone)]
pub struct UfsSuperblock {
    /// UFS version.
    pub version: UfsVersion,
    /// Total number of inodes.
    pub total_inodes: u64,
    /// Total number of data blocks.
    pub total_blocks: u64,
    /// Number of free blocks.
    pub free_blocks: u64,
    /// Number of free inodes.
    pub free_inodes: u64,
    /// Block size in bytes (power of two, 4 KiB or 8 KiB).
    pub block_size: u32,
    /// Fragment size in bytes (block_size / frags_per_block).
    pub frag_size: u32,
    /// Fragments per block.
    pub frags_per_block: u32,
    /// Cylinder groups count.
    pub cg_count: u32,
    /// Inodes per cylinder group.
    pub inodes_per_cg: u32,
    /// Blocks per cylinder group.
    pub blocks_per_cg: u32,
    /// Rotation delay (legacy; ignored in modern UFS).
    pub rotdelay: u32,
    /// Volume name (UFS2 only, 32 bytes).
    pub volume_name: [u8; 32],
    /// Last mount time.
    pub last_mount_time: i64,
    /// Last written time.
    pub last_write_time: i64,
    /// Mount count since last full fsck.
    pub mount_count: u16,
    /// Maximum mount count before fsck is required.
    pub max_mount_count: u16,
}

impl UfsSuperblock {
    /// Validate magic and construct an in-memory superblock.
    pub fn from_magic(magic: u32, version: u32) -> Result<UfsVersion> {
        match magic {
            UFS1_MAGIC => Ok(UfsVersion::Ufs1),
            UFS2_MAGIC => {
                let _ = version;
                Ok(UfsVersion::Ufs2)
            }
            _ => Err(Error::InvalidArgument),
        }
    }

    /// Create a default UFS2 superblock descriptor.
    pub fn new_ufs2(total_blocks: u64, total_inodes: u64, block_size: u32) -> Self {
        let frag_size = block_size / 8;
        Self {
            version: UfsVersion::Ufs2,
            total_inodes,
            total_blocks,
            free_blocks: total_blocks / 10 * 9,
            free_inodes: total_inodes / 10 * 9,
            block_size,
            frag_size,
            frags_per_block: 8,
            cg_count: 1,
            inodes_per_cg: (total_inodes) as u32,
            blocks_per_cg: (total_blocks) as u32,
            rotdelay: 0,
            volume_name: [0u8; 32],
            last_mount_time: 0,
            last_write_time: 0,
            mount_count: 0,
            max_mount_count: 30,
        }
    }

    /// Whether the filesystem needs a full fsck before mounting.
    pub fn needs_fsck(&self) -> bool {
        self.mount_count >= self.max_mount_count
    }
}

/// UFS inode number type.
pub type UfsIno = u64;

/// UFS inode mode bits.
pub mod mode {
    pub const IFMT: u16 = 0o170000;
    pub const IFDIR: u16 = 0o040000;
    pub const IFCHR: u16 = 0o020000;
    pub const IFBLK: u16 = 0o060000;
    pub const IFREG: u16 = 0o100000;
    pub const IFLNK: u16 = 0o120000;
    pub const IFSOCK: u16 = 0o140000;
    pub const IFIFO: u16 = 0o010000;
    pub const ISUID: u16 = 0o004000;
    pub const ISGID: u16 = 0o002000;
    pub const ISVTX: u16 = 0o001000;
}

/// Number of direct block pointers in a UFS inode.
pub const UFS_NDADDR: usize = 12;
/// Number of indirect block pointers.
pub const UFS_NIADDR: usize = 3;

/// UFS2 on-disk inode.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct Ufs2Inode {
    /// File mode and type.
    pub mode: u16,
    /// Number of hard links.
    pub nlink: u16,
    /// User ID.
    pub uid: u32,
    /// Group ID.
    pub gid: u32,
    /// Block size for this file.
    pub blksize: u32,
    /// File size in bytes.
    pub size: u64,
    /// Number of 512-byte blocks allocated.
    pub blocks: u64,
    /// Access time.
    pub atime: i64,
    pub atime_nsec: i32,
    /// Modified time.
    pub mtime: i64,
    pub mtime_nsec: i32,
    /// Changed time.
    pub ctime: i64,
    pub ctime_nsec: i32,
    /// Birth time (UFS2 only).
    pub birthtime: i64,
    pub birthtime_nsec: i32,
    /// Generation number (NFS).
    pub generation: u32,
    /// Direct block pointers.
    pub db: [i64; UFS_NDADDR],
    /// Indirect block pointers (single, double, triple).
    pub ib: [i64; UFS_NIADDR],
    /// Flags.
    pub flags: u32,
    /// Extended attribute size.
    pub extsize: i64,
    /// Extended attribute block pointers (2 entries).
    pub extb: [i64; 2],
    pub _spare: [i64; 3],
}

impl Ufs2Inode {
    /// File type from mode bits.
    pub fn file_type(&self) -> u16 {
        self.mode & mode::IFMT
    }

    /// Whether this inode is a regular file.
    pub fn is_regular(&self) -> bool {
        self.file_type() == mode::IFREG
    }

    /// Whether this inode is a directory.
    pub fn is_dir(&self) -> bool {
        self.file_type() == mode::IFDIR
    }

    /// Whether this inode is a symbolic link.
    pub fn is_symlink(&self) -> bool {
        self.file_type() == mode::IFLNK
    }
}

/// UFS cylinder group descriptor.
#[derive(Debug, Clone, Copy)]
pub struct UfsCylinderGroup {
    /// CG index.
    pub cg_index: u32,
    /// Free block count in this CG.
    pub free_blocks: u32,
    /// Free inode count in this CG.
    pub free_inodes: u32,
    /// Block number of this CG's inode table.
    pub inode_table_offset: u64,
    /// Whether this CG has been modified since last flush.
    pub dirty: bool,
}

impl UfsCylinderGroup {
    /// Create a new cylinder group descriptor.
    pub fn new(cg_index: u32, free_blocks: u32, free_inodes: u32, inode_table_offset: u64) -> Self {
        Self {
            cg_index,
            free_blocks,
            free_inodes,
            inode_table_offset,
            dirty: false,
        }
    }

    /// Allocate a block from this CG.
    pub fn alloc_block(&mut self) -> Result<()> {
        if self.free_blocks == 0 {
            return Err(Error::OutOfMemory);
        }
        self.free_blocks -= 1;
        self.dirty = true;
        Ok(())
    }

    /// Free a block back to this CG.
    pub fn free_block(&mut self) {
        self.free_blocks += 1;
        self.dirty = true;
    }

    /// Allocate an inode from this CG.
    pub fn alloc_inode(&mut self) -> Result<()> {
        if self.free_inodes == 0 {
            return Err(Error::OutOfMemory);
        }
        self.free_inodes -= 1;
        self.dirty = true;
        Ok(())
    }

    /// Free an inode back to this CG.
    pub fn free_inode(&mut self) {
        self.free_inodes += 1;
        self.dirty = true;
    }
}

/// UFS directory entry.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct UfsDirEntry {
    /// Inode number.
    pub ino: u32,
    /// Length of this directory entry (including name).
    pub reclen: u16,
    /// File type tag.
    pub file_type: u8,
    /// Length of the name.
    pub name_len: u8,
    /// Name bytes (up to 255 + NUL).
    pub name: [u8; 256],
}

impl UfsDirEntry {
    /// Minimum valid record length for a given name length.
    pub fn min_reclen(name_len: u8) -> u16 {
        // 8-byte header + name rounded up to 4-byte boundary.
        let base = 8u16 + name_len as u16;
        (base + 3) & !3
    }

    /// Validate the directory entry fields.
    pub fn validate(&self) -> Result<()> {
        if self.reclen < Self::min_reclen(self.name_len) {
            return Err(Error::InvalidArgument);
        }
        if self.name_len == 0 {
            return Err(Error::InvalidArgument);
        }
        Ok(())
    }

    /// Name as a byte slice.
    pub fn name_bytes(&self) -> &[u8] {
        &self.name[..self.name_len as usize]
    }
}
