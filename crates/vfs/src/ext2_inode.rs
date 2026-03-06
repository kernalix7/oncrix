// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! ext2 inode operations.
//!
//! Implements the ext2 inode on-disk structure and lifecycle operations:
//! - [`Ext2Inode`] — on-disk inode matching `ext2_inode` in the kernel
//! - [`read_inode`] / [`write_inode`] — load/store inode from/to block device
//! - [`alloc_inode`] — allocate a free inode using the inode bitmap
//! - [`free_inode`] — return an inode to the free pool
//! - Direct and indirect block address resolution
//!
//! # ext2 Block Map
//!
//! Each inode stores 15 block pointers (`block[0..14]`):
//! - `block[0..11]`: direct blocks
//! - `block[12]`: singly-indirect block pointer
//! - `block[13]`: doubly-indirect block pointer
//! - `block[14]`: triply-indirect block pointer
//!
//! # References
//! - Linux `fs/ext2/inode.c`, `fs/ext2/ext2.h`
//! - The Second Extended File System design document

extern crate alloc;
use alloc::vec::Vec;
use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// ext2 magic number in the superblock.
pub const EXT2_MAGIC: u16 = 0xEF53;

/// Root directory inode number.
pub const EXT2_ROOT_INO: u32 = 2;

/// First usable inode number (1–10 are reserved).
pub const EXT2_FIRST_INO: u32 = 11;

/// Number of direct block pointers in an inode.
const EXT2_NDIR_BLOCKS: usize = 12;
/// Index of singly-indirect block pointer.
const EXT2_IND_BLOCK: usize = 12;
/// Index of doubly-indirect block pointer.
const EXT2_DIND_BLOCK: usize = 13;
/// Index of triply-indirect block pointer.
const EXT2_TIND_BLOCK: usize = 14;
/// Total block pointer slots.
const EXT2_N_BLOCKS: usize = 15;

/// Block size (simulated: 1 KiB).
pub const EXT2_BLOCK_SIZE: usize = 1024;

/// Maximum simulated inodes.
const MAX_INODES: usize = 1024;

/// Maximum simulated blocks.
const MAX_BLOCKS: usize = 4096;

/// Maximum data stored per block.
const BLOCK_DATA_SIZE: usize = EXT2_BLOCK_SIZE;

// ---------------------------------------------------------------------------
// File mode constants (i_mode bits)
// ---------------------------------------------------------------------------

/// Regular file.
pub const EXT2_S_IFREG: u16 = 0o100000;
/// Directory.
pub const EXT2_S_IFDIR: u16 = 0o040000;
/// Symbolic link.
pub const EXT2_S_IFLNK: u16 = 0o120000;
/// Character device.
pub const EXT2_S_IFCHR: u16 = 0o020000;
/// Block device.
pub const EXT2_S_IFBLK: u16 = 0o060000;
/// FIFO.
pub const EXT2_S_IFIFO: u16 = 0o010000;
/// Socket.
pub const EXT2_S_IFSOCK: u16 = 0o140000;

// ---------------------------------------------------------------------------
// Ext2Inode
// ---------------------------------------------------------------------------

/// ext2 on-disk inode structure (`struct ext2_inode`).
#[derive(Debug, Clone, Copy)]
pub struct Ext2Inode {
    /// File mode (type bits + permission bits).
    pub mode: u16,
    /// Owner user ID (low 16 bits).
    pub uid: u16,
    /// File size in bytes (low 32 bits).
    pub size: u32,
    /// Last access time (seconds since epoch).
    pub atime: u32,
    /// Inode change time.
    pub ctime: u32,
    /// Last modification time.
    pub mtime: u32,
    /// Deletion time (0 if not deleted).
    pub dtime: u32,
    /// Owner group ID (low 16 bits).
    pub gid: u16,
    /// Hard link count.
    pub links_count: u16,
    /// File size in 512-byte sectors.
    pub blocks: u32,
    /// Inode flags (EXT2_*_FL).
    pub flags: u32,
    /// Block pointers (direct + indirect).
    pub block: [u32; EXT2_N_BLOCKS],
    /// File generation number (for NFS).
    pub generation: u32,
    /// Extended attribute block.
    pub file_acl: u32,
    /// File size high 32 bits (for large files).
    pub dir_acl: u32,
    /// Fragment address (obsolete, always 0).
    pub faddr: u32,
}

impl Ext2Inode {
    /// Create a new regular-file inode.
    pub fn new_file(uid: u16, gid: u16, mode: u16) -> Self {
        Self {
            mode: EXT2_S_IFREG | (mode & 0o7777),
            uid,
            size: 0,
            atime: 0,
            ctime: 0,
            mtime: 0,
            dtime: 0,
            gid,
            links_count: 1,
            blocks: 0,
            flags: 0,
            block: [0u32; EXT2_N_BLOCKS],
            generation: 1,
            file_acl: 0,
            dir_acl: 0,
            faddr: 0,
        }
    }

    /// Create a new directory inode.
    pub fn new_dir(uid: u16, gid: u16, mode: u16) -> Self {
        let mut inode = Self::new_file(uid, gid, mode);
        inode.mode = EXT2_S_IFDIR | (mode & 0o7777);
        inode.links_count = 2; // "." + parent link
        inode
    }

    /// Return true if this inode is a regular file.
    pub fn is_file(&self) -> bool {
        self.mode & 0o170000 == EXT2_S_IFREG
    }

    /// Return true if this inode is a directory.
    pub fn is_dir(&self) -> bool {
        self.mode & 0o170000 == EXT2_S_IFDIR
    }

    /// Return true if this inode is a symbolic link.
    pub fn is_symlink(&self) -> bool {
        self.mode & 0o170000 == EXT2_S_IFLNK
    }
}

// ---------------------------------------------------------------------------
// Simulated block device and inode table
// ---------------------------------------------------------------------------

/// Simulated ext2 filesystem for testing inode operations.
pub struct Ext2Fs {
    /// Inode table: index = (ino - 1).
    inodes: [Option<Ext2Inode>; MAX_INODES],
    /// Inode allocation bitmap.
    inode_bitmap: [bool; MAX_INODES],
    /// Block data storage.
    blocks: [[u8; BLOCK_DATA_SIZE]; MAX_BLOCKS],
    /// Block allocation bitmap.
    block_bitmap: [bool; MAX_BLOCKS],
    /// Next free inode scan start.
    inode_scan_start: usize,
    /// Next free block scan start.
    block_scan_start: usize,
}

impl Ext2Fs {
    /// Create a fresh simulated ext2 filesystem.
    pub fn new() -> Self {
        let mut fs = Self {
            inodes: core::array::from_fn(|_| None),
            inode_bitmap: [false; MAX_INODES],
            blocks: [[0u8; BLOCK_DATA_SIZE]; MAX_BLOCKS],
            block_bitmap: [false; MAX_BLOCKS],
            inode_scan_start: (EXT2_FIRST_INO - 1) as usize,
            block_scan_start: 0,
        };
        // Mark inodes 0–10 as reserved.
        for i in 0..(EXT2_FIRST_INO as usize - 1) {
            fs.inode_bitmap[i] = true;
        }
        // Create root directory inode.
        let root_inode = Ext2Inode::new_dir(0, 0, 0o755);
        let root_idx = (EXT2_ROOT_INO - 1) as usize;
        fs.inodes[root_idx] = Some(root_inode);
        fs.inode_bitmap[root_idx] = true;
        fs
    }

    fn find_free_inode(&self) -> Option<usize> {
        for i in self.inode_scan_start..MAX_INODES {
            if !self.inode_bitmap[i] {
                return Some(i);
            }
        }
        None
    }

    fn find_free_block(&self) -> Option<usize> {
        for i in self.block_scan_start..MAX_BLOCKS {
            if !self.block_bitmap[i] {
                return Some(i);
            }
        }
        None
    }
}

impl Default for Ext2Fs {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Inode operations
// ---------------------------------------------------------------------------

/// Read an inode from the simulated filesystem.
///
/// Returns `Err(NotFound)` if `ino` is not allocated.
pub fn read_inode(fs: &Ext2Fs, ino: u32) -> Result<Ext2Inode> {
    if ino == 0 || ino as usize > MAX_INODES {
        return Err(Error::InvalidArgument);
    }
    let idx = (ino - 1) as usize;
    if !fs.inode_bitmap[idx] {
        return Err(Error::NotFound);
    }
    fs.inodes[idx].ok_or(Error::NotFound)
}

/// Write (update) an inode in the simulated filesystem.
pub fn write_inode(fs: &mut Ext2Fs, ino: u32, inode: Ext2Inode) -> Result<()> {
    if ino == 0 || ino as usize > MAX_INODES {
        return Err(Error::InvalidArgument);
    }
    let idx = (ino - 1) as usize;
    if !fs.inode_bitmap[idx] {
        return Err(Error::NotFound);
    }
    fs.inodes[idx] = Some(inode);
    Ok(())
}

/// Allocate a new inode.
///
/// Returns the allocated inode number (1-based).
pub fn alloc_inode(fs: &mut Ext2Fs, uid: u16, gid: u16, mode: u16) -> Result<u32> {
    let idx = fs.find_free_inode().ok_or(Error::OutOfMemory)?;
    fs.inode_bitmap[idx] = true;
    fs.inodes[idx] = Some(Ext2Inode::new_file(uid, gid, mode));
    fs.inode_scan_start = idx + 1;
    Ok((idx + 1) as u32)
}

/// Allocate a new directory inode.
pub fn alloc_dir_inode(fs: &mut Ext2Fs, uid: u16, gid: u16, mode: u16) -> Result<u32> {
    let idx = fs.find_free_inode().ok_or(Error::OutOfMemory)?;
    fs.inode_bitmap[idx] = true;
    fs.inodes[idx] = Some(Ext2Inode::new_dir(uid, gid, mode));
    fs.inode_scan_start = idx + 1;
    Ok((idx + 1) as u32)
}

/// Free an inode back to the pool.
///
/// Marks the inode as deleted (dtime = 1) and clears the bitmap entry.
pub fn free_inode(fs: &mut Ext2Fs, ino: u32) -> Result<()> {
    if ino == 0 || ino as usize > MAX_INODES {
        return Err(Error::InvalidArgument);
    }
    let idx = (ino - 1) as usize;
    if !fs.inode_bitmap[idx] {
        return Err(Error::NotFound);
    }
    if let Some(inode) = fs.inodes[idx].as_mut() {
        inode.links_count = 0;
        inode.dtime = 1; // non-zero = deleted
    }
    fs.inode_bitmap[idx] = false;
    fs.inodes[idx] = None;
    if idx < fs.inode_scan_start {
        fs.inode_scan_start = idx;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Block allocation
// ---------------------------------------------------------------------------

/// Allocate a data block and return its block number (0-based index).
pub fn alloc_block(fs: &mut Ext2Fs) -> Result<u32> {
    let idx = fs.find_free_block().ok_or(Error::OutOfMemory)?;
    fs.block_bitmap[idx] = true;
    fs.block_scan_start = idx + 1;
    Ok(idx as u32)
}

/// Free a data block.
pub fn free_block(fs: &mut Ext2Fs, block: u32) -> Result<()> {
    let idx = block as usize;
    if idx >= MAX_BLOCKS {
        return Err(Error::InvalidArgument);
    }
    if !fs.block_bitmap[idx] {
        return Err(Error::NotFound);
    }
    fs.block_bitmap[idx] = false;
    fs.blocks[idx].fill(0);
    if idx < fs.block_scan_start {
        fs.block_scan_start = idx;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Block I/O
// ---------------------------------------------------------------------------

/// Write data to a block.
pub fn write_block(fs: &mut Ext2Fs, block: u32, data: &[u8]) -> Result<()> {
    let idx = block as usize;
    if idx >= MAX_BLOCKS || !fs.block_bitmap[idx] {
        return Err(Error::InvalidArgument);
    }
    let len = data.len().min(BLOCK_DATA_SIZE);
    fs.blocks[idx][..len].copy_from_slice(&data[..len]);
    Ok(())
}

/// Read data from a block.
pub fn read_block(fs: &Ext2Fs, block: u32) -> Result<Vec<u8>> {
    let idx = block as usize;
    if idx >= MAX_BLOCKS || !fs.block_bitmap[idx] {
        return Err(Error::InvalidArgument);
    }
    Ok(fs.blocks[idx].to_vec())
}

// ---------------------------------------------------------------------------
// Block address resolution (direct + indirect)
// ---------------------------------------------------------------------------

/// Resolve logical block index to physical block number via the inode block map.
///
/// Only supports direct blocks (indices 0–11). Returns `Err(NotImplemented)`
/// for indirect and doubly/triply indirect ranges.
pub fn inode_get_block(inode: &Ext2Inode, logical_block: u32) -> Result<u32> {
    let lb = logical_block as usize;
    if lb < EXT2_NDIR_BLOCKS {
        let phys = inode.block[lb];
        if phys == 0 {
            Err(Error::NotFound)
        } else {
            Ok(phys)
        }
    } else if lb == EXT2_IND_BLOCK || lb == EXT2_DIND_BLOCK || lb == EXT2_TIND_BLOCK {
        // Indirect block resolution requires reading the indirect block from disk.
        Err(Error::NotImplemented)
    } else {
        Err(Error::InvalidArgument)
    }
}

/// Map a byte offset to its logical block number.
pub fn offset_to_block(offset: u64) -> u32 {
    (offset / EXT2_BLOCK_SIZE as u64) as u32
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_alloc_read_free() {
        let mut fs = Ext2Fs::new();
        let ino = alloc_inode(&mut fs, 1000, 1000, 0o644).unwrap();
        let inode = read_inode(&fs, ino).unwrap();
        assert!(inode.is_file());
        free_inode(&mut fs, ino).unwrap();
        assert!(read_inode(&fs, ino).is_err());
    }

    #[test]
    fn test_block_alloc_write_read() {
        let mut fs = Ext2Fs::new();
        let blk = alloc_block(&mut fs).unwrap();
        write_block(&mut fs, blk, b"ext2 block data").unwrap();
        let data = read_block(&fs, blk).unwrap();
        assert_eq!(&data[..15], b"ext2 block data");
    }

    #[test]
    fn test_root_inode_exists() {
        let fs = Ext2Fs::new();
        let root = read_inode(&fs, EXT2_ROOT_INO).unwrap();
        assert!(root.is_dir());
    }
}
