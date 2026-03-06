// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Amiga Fast File System (AFFS).
//!
//! AFFS is the native filesystem of AmigaOS, used on floppy disks and hard
//! drives. It employs a block-oriented structure with:
//!
//! - **Boot block** (blocks 0–1): boot code and filesystem type
//! - **Root block** (block N/2): root directory and bitmap pointers
//! - **Bitmap blocks**: allocation bitmap for data blocks
//! - **File header blocks**: inode-like metadata per file/directory
//! - **Data blocks**: raw file data (OFS has a header; FFS is pure data)
//!
//! # Variants
//!
//! | Type         | ID      | Description                              |
//! |--------------|---------|------------------------------------------|
//! | OFS          | 0x444F53 | Original File System (slow but safe)    |
//! | FFS          | 0x444F53 | Fast File System (faster, less overhead)|
//! | OFS+Intl     | 0x444F54 | OFS with international characters       |
//! | FFS+Intl     | 0x444F55 | FFS with international characters       |
//! | OFS+DirCache | 0x444F56 | OFS with directory cache                |
//! | FFS+DirCache | 0x444F57 | FFS with directory cache                |
//!
//! # References
//!
//! - Linux `fs/affs/`
//! - AmigaOS developer docs (Amiga ROM Kernel Reference Manual)

use oncrix_lib::{Error, Result};

/// Maximum filename length in AFFS (30 bytes).
pub const AFFS_NAME_MAX: usize = 30;
/// AFFS root block type identifier.
pub const T_HEADER: u32 = 2;
/// AFFS secondary type for root block.
pub const ST_ROOT: i32 = 1;
/// AFFS secondary type for directory.
pub const ST_DIR: i32 = 2;
/// AFFS secondary type for file.
pub const ST_FILE: i32 = -3;
/// Maximum in-memory file/directory entries.
pub const MAX_AFFS_ENTRIES: usize = 512;
/// Maximum hash chain entries per directory.
pub const HASH_TABLE_SIZE: usize = 72;

/// AFFS filesystem type discriminant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AffsType {
    OFS,
    FFS,
    OFSIntl,
    FFSIntl,
    OFSDirCache,
    FFSDirCache,
}

impl AffsType {
    /// On-disk filesystem type code stored in boot block.
    pub fn disk_type(self) -> u32 {
        match self {
            AffsType::OFS => 0x444F5300,
            AffsType::FFS => 0x444F5301,
            AffsType::OFSIntl => 0x444F5302,
            AffsType::FFSIntl => 0x444F5303,
            AffsType::OFSDirCache => 0x444F5304,
            AffsType::FFSDirCache => 0x444F5305,
        }
    }

    /// True if this is a Fast File System variant.
    pub fn is_ffs(self) -> bool {
        matches!(
            self,
            AffsType::FFS | AffsType::FFSIntl | AffsType::FFSDirCache
        )
    }
}

/// An AFFS filename (inline buffer, NUL-padded).
#[derive(Debug, Clone, Copy)]
pub struct AffsName {
    buf: [u8; AFFS_NAME_MAX],
    len: u8,
}

impl AffsName {
    /// Create from a byte slice.
    pub fn new(name: &[u8]) -> Result<Self> {
        if name.is_empty() || name.len() > AFFS_NAME_MAX {
            return Err(Error::InvalidArgument);
        }
        let mut buf = [0u8; AFFS_NAME_MAX];
        buf[..name.len()].copy_from_slice(name);
        Ok(Self {
            buf,
            len: name.len() as u8,
        })
    }

    /// Byte slice of the name.
    pub fn as_bytes(&self) -> &[u8] {
        &self.buf[..self.len as usize]
    }

    /// Length in bytes.
    pub fn len(&self) -> usize {
        self.len as usize
    }

    /// True if empty.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// AFFS hash function for directory lookup.
    ///
    /// Simple hash: fold chars, mod HASH_TABLE_SIZE.
    pub fn hash(&self) -> usize {
        let mut h: u32 = self.len as u32;
        for &b in &self.buf[..self.len as usize] {
            // Upper-case fold for case-insensitive filesystems.
            let c = if b.is_ascii_lowercase() { b - 0x20 } else { b };
            h = h.wrapping_mul(13).wrapping_add(c as u32);
        }
        (h % HASH_TABLE_SIZE as u32) as usize
    }
}

/// An AFFS inode (corresponds to a file header block on disk).
#[derive(Debug, Clone)]
pub struct AffsInode {
    /// Block number of this header block.
    pub block: u32,
    /// Secondary type (ST_FILE or ST_DIR or ST_ROOT).
    pub sec_type: i32,
    /// Owning UID.
    pub uid: u16,
    /// Owning GID.
    pub gid: u16,
    /// File protection bits.
    pub protect: u32,
    /// File size in bytes.
    pub size: u32,
    /// Modification timestamp (seconds since 1978-01-01 00:00:00 UTC).
    pub mtime: u32,
    /// Comment (up to 79 bytes).
    pub comment: [u8; 80],
    /// Entry name.
    pub name: AffsName,
    /// Hash chain pointer (next entry with same hash in parent dir).
    pub hash_chain: u32,
    /// Parent block number.
    pub parent: u32,
}

impl AffsInode {
    /// Create a new file inode.
    pub fn new_file(block: u32, parent: u32, name: &[u8]) -> Result<Self> {
        Ok(Self {
            block,
            sec_type: ST_FILE,
            uid: 0,
            gid: 0,
            protect: 0,
            size: 0,
            mtime: 0,
            comment: [0u8; 80],
            name: AffsName::new(name)?,
            hash_chain: 0,
            parent,
        })
    }

    /// Create a new directory inode.
    pub fn new_dir(block: u32, parent: u32, name: &[u8]) -> Result<Self> {
        Ok(Self {
            block,
            sec_type: ST_DIR,
            uid: 0,
            gid: 0,
            protect: 0,
            size: 0,
            mtime: 0,
            comment: [0u8; 80],
            name: AffsName::new(name)?,
            hash_chain: 0,
            parent,
        })
    }

    /// True if this is a directory.
    pub fn is_dir(&self) -> bool {
        self.sec_type == ST_DIR || self.sec_type == ST_ROOT
    }

    /// True if this is a regular file.
    pub fn is_file(&self) -> bool {
        self.sec_type == ST_FILE
    }
}

/// In-memory AFFS directory (hash table of entries).
pub struct AffsDir {
    /// Block number of the directory header.
    pub block: u32,
    /// Hash table: each slot holds a block number (0 = empty).
    hash_table: [u32; HASH_TABLE_SIZE],
}

impl AffsDir {
    /// Create a new empty directory.
    pub fn new(block: u32) -> Self {
        Self {
            block,
            hash_table: [0u32; HASH_TABLE_SIZE],
        }
    }

    /// Insert `child_block` into the hash table for `name`.
    ///
    /// This does not handle chain collision (production code would link
    /// via `hash_chain`); for simplicity, returns `AlreadyExists` on collision.
    pub fn insert(&mut self, name: &AffsName, child_block: u32) -> Result<()> {
        let slot = name.hash();
        if self.hash_table[slot] != 0 {
            return Err(Error::AlreadyExists);
        }
        self.hash_table[slot] = child_block;
        Ok(())
    }

    /// Lookup the block number for `name`.
    pub fn lookup(&self, name: &AffsName) -> Option<u32> {
        let slot = name.hash();
        let b = self.hash_table[slot];
        if b == 0 { None } else { Some(b) }
    }

    /// Remove entry for `name`.
    pub fn remove(&mut self, name: &AffsName) -> Result<()> {
        let slot = name.hash();
        if self.hash_table[slot] == 0 {
            return Err(Error::NotFound);
        }
        self.hash_table[slot] = 0;
        Ok(())
    }
}

/// In-memory table of all AFFS inodes for one filesystem.
pub struct AffsInodeTable {
    inodes: [Option<AffsInode>; MAX_AFFS_ENTRIES],
    count: usize,
    next_block: u32,
}

impl AffsInodeTable {
    /// Create an empty inode table starting block allocation at `first_block`.
    pub fn new(first_block: u32) -> Self {
        Self {
            inodes: [const { None }; MAX_AFFS_ENTRIES],
            count: 0,
            next_block: first_block,
        }
    }

    fn alloc_block(&mut self) -> u32 {
        let b = self.next_block;
        self.next_block += 1;
        b
    }

    /// Allocate a new file inode under `parent_block`.
    pub fn alloc_file(&mut self, parent_block: u32, name: &[u8]) -> Result<u32> {
        if self.count >= MAX_AFFS_ENTRIES {
            return Err(Error::OutOfMemory);
        }
        let block = self.alloc_block();
        let inode = AffsInode::new_file(block, parent_block, name)?;
        self.inodes[self.count] = Some(inode);
        self.count += 1;
        Ok(block)
    }

    /// Allocate a new directory inode under `parent_block`.
    pub fn alloc_dir(&mut self, parent_block: u32, name: &[u8]) -> Result<u32> {
        if self.count >= MAX_AFFS_ENTRIES {
            return Err(Error::OutOfMemory);
        }
        let block = self.alloc_block();
        let inode = AffsInode::new_dir(block, parent_block, name)?;
        self.inodes[self.count] = Some(inode);
        self.count += 1;
        Ok(block)
    }

    /// Get inode by block number.
    pub fn get(&self, block: u32) -> Option<&AffsInode> {
        self.inodes[..self.count]
            .iter()
            .filter_map(|i| i.as_ref())
            .find(|i| i.block == block)
    }

    /// Get inode by block number (mutable).
    pub fn get_mut(&mut self, block: u32) -> Option<&mut AffsInode> {
        self.inodes[..self.count]
            .iter_mut()
            .filter_map(|i| i.as_mut())
            .find(|i| i.block == block)
    }

    /// Free an inode (by block number).
    pub fn free(&mut self, block: u32) -> Result<()> {
        let pos = self.inodes[..self.count]
            .iter()
            .position(|i| i.as_ref().map(|i| i.block == block).unwrap_or(false));
        match pos {
            None => Err(Error::NotFound),
            Some(idx) => {
                self.count -= 1;
                self.inodes[idx] = self.inodes[self.count].take();
                Ok(())
            }
        }
    }

    /// Number of allocated inodes.
    pub fn count(&self) -> usize {
        self.count
    }
}

/// AFFS superblock / root block metadata.
#[derive(Debug, Clone, Copy)]
pub struct AffsSuperblock {
    /// Block size in bytes.
    pub block_size: u32,
    /// Total number of blocks on the volume.
    pub total_blocks: u32,
    /// Number of free blocks.
    pub free_blocks: u32,
    /// Root block number (always `total_blocks / 2`).
    pub root_block: u32,
    /// Filesystem type.
    pub fs_type: AffsType,
    /// Volume name.
    pub volume_name: [u8; AFFS_NAME_MAX],
    /// Creation date (seconds since 1978-01-01).
    pub create_date: u32,
}

impl AffsSuperblock {
    /// Create a new superblock for a volume of `total_blocks` blocks.
    pub fn new(total_blocks: u32, block_size: u32, fs_type: AffsType) -> Self {
        Self {
            block_size,
            total_blocks,
            free_blocks: total_blocks.saturating_sub(4),
            root_block: total_blocks / 2,
            fs_type,
            volume_name: [0u8; AFFS_NAME_MAX],
            create_date: 0,
        }
    }

    /// Set volume name (truncated to `AFFS_NAME_MAX`).
    pub fn set_name(&mut self, name: &[u8]) {
        let len = name.len().min(AFFS_NAME_MAX);
        self.volume_name[..len].copy_from_slice(&name[..len]);
    }
}
