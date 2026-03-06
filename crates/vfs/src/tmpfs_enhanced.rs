// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Enhanced tmpfs — temporary filesystem with size and inode limits.
//!
//! Extends the basic [`Tmpfs`](crate::tmpfs) with configurable resource
//! limits (maximum size, maximum inodes), ownership, permission modes,
//! and huge-page awareness. All data is volatile and backed by in-memory
//! blocks.
//!
//! # Features
//!
//! - Configurable maximum size and inode count (0 = unlimited)
//! - Per-filesystem UID/GID ownership and permission mode
//! - Block-based storage with 4 KiB blocks (1024 blocks = 4 MiB pool)
//! - Inline directory entries (up to 32 per directory)
//! - Stat support via [`TmpfsStat`]
//!
//! Reference: Linux `mm/shmem.c`, POSIX.1-2024 §tmpfs.

use oncrix_lib::{Error, Result};

/// Block size in bytes (4 KiB).
const BLOCK_SIZE: usize = 4096;

/// Maximum number of blocks in the filesystem.
const MAX_BLOCKS: usize = 1024;

/// Maximum number of inodes in the filesystem.
const MAX_INODES: usize = 256;

/// Maximum number of block indices per inode.
const MAX_BLOCKS_PER_INODE: usize = 64;

/// Maximum number of directory entries per directory.
const MAX_DIR_ENTRIES: usize = 32;

/// Maximum filename length in bytes.
const MAX_NAME_LEN: usize = 255;

/// Mount options for the enhanced tmpfs.
#[derive(Debug, Clone, Copy)]
pub struct TmpfsOptions {
    /// Maximum total size in bytes (0 = unlimited).
    pub max_size: u64,
    /// Maximum number of inodes (0 = unlimited).
    pub max_inodes: u64,
    /// Root directory permission mode.
    pub mode: u16,
    /// Owner UID.
    pub uid: u32,
    /// Owner GID.
    pub gid: u32,
    /// Whether to use huge pages for allocation.
    pub huge_pages: bool,
}

impl Default for TmpfsOptions {
    fn default() -> Self {
        Self {
            max_size: 0,
            max_inodes: 0,
            mode: 0o1777,
            uid: 0,
            gid: 0,
            huge_pages: false,
        }
    }
}

/// A single 4 KiB data block.
pub struct TmpfsBlock {
    /// Block data.
    pub data: [u8; BLOCK_SIZE],
    /// Whether this block is currently allocated.
    pub in_use: bool,
}

impl Default for TmpfsBlock {
    fn default() -> Self {
        Self {
            data: [0u8; BLOCK_SIZE],
            in_use: false,
        }
    }
}

impl core::fmt::Debug for TmpfsBlock {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("TmpfsBlock")
            .field("in_use", &self.in_use)
            .finish()
    }
}

/// A directory entry within a tmpfs directory inode.
#[derive(Clone)]
pub struct TmpfsDirEntry {
    /// Entry name bytes.
    pub name: [u8; MAX_NAME_LEN],
    /// Length of the name in bytes.
    pub name_len: u8,
    /// Inode ID this entry points to.
    pub inode_id: u64,
    /// Whether this entry is active.
    pub in_use: bool,
}

impl Default for TmpfsDirEntry {
    fn default() -> Self {
        Self {
            name: [0u8; MAX_NAME_LEN],
            name_len: 0,
            inode_id: 0,
            in_use: false,
        }
    }
}

impl core::fmt::Debug for TmpfsDirEntry {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("TmpfsDirEntry")
            .field("name_len", &self.name_len)
            .field("inode_id", &self.inode_id)
            .field("in_use", &self.in_use)
            .finish()
    }
}

impl TmpfsDirEntry {
    /// Return the entry name as a byte slice.
    pub fn name_bytes(&self) -> &[u8] {
        &self.name[..self.name_len as usize]
    }
}

/// An inode in the enhanced tmpfs.
pub struct TmpfsInode {
    /// Inode identifier.
    pub id: u64,
    /// Permission mode bits.
    pub mode: u16,
    /// Owner UID.
    pub uid: u32,
    /// Owner GID.
    pub gid: u32,
    /// File size in bytes.
    pub size: u64,
    /// Block indices allocated to this inode.
    pub blocks: [u16; MAX_BLOCKS_PER_INODE],
    /// Number of blocks currently in use.
    pub block_count: usize,
    /// Hard link count.
    pub nlinks: u32,
    /// Last access time (seconds since epoch).
    pub atime: u64,
    /// Last modification time (seconds since epoch).
    pub mtime: u64,
    /// Last status change time (seconds since epoch).
    pub ctime: u64,
    /// Whether this inode represents a directory.
    pub is_dir: bool,
    /// Whether this inode slot is active.
    pub in_use: bool,
    /// Directory entries (only meaningful when `is_dir` is true).
    pub dir_entries: [TmpfsDirEntry; MAX_DIR_ENTRIES],
}

impl Default for TmpfsInode {
    fn default() -> Self {
        const DEFAULT_DIR_ENTRY: TmpfsDirEntry = TmpfsDirEntry {
            name: [0u8; MAX_NAME_LEN],
            name_len: 0,
            inode_id: 0,
            in_use: false,
        };
        Self {
            id: 0,
            mode: 0,
            uid: 0,
            gid: 0,
            size: 0,
            blocks: [0u16; MAX_BLOCKS_PER_INODE],
            block_count: 0,
            nlinks: 1,
            atime: 0,
            mtime: 0,
            ctime: 0,
            is_dir: false,
            in_use: false,
            dir_entries: [DEFAULT_DIR_ENTRY; MAX_DIR_ENTRIES],
        }
    }
}

impl core::fmt::Debug for TmpfsInode {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("TmpfsInode")
            .field("id", &self.id)
            .field("mode", &self.mode)
            .field("size", &self.size)
            .field("is_dir", &self.is_dir)
            .field("in_use", &self.in_use)
            .field("block_count", &self.block_count)
            .field("nlinks", &self.nlinks)
            .finish()
    }
}

/// File stat information returned by [`TmpfsFilesystem::stat`].
#[derive(Debug, Clone, Copy, Default)]
pub struct TmpfsStat {
    /// File size in bytes.
    pub size: u64,
    /// Number of blocks allocated.
    pub blocks: u64,
    /// Permission mode bits.
    pub mode: u16,
    /// Owner UID.
    pub uid: u32,
    /// Owner GID.
    pub gid: u32,
    /// Hard link count.
    pub nlinks: u32,
    /// Last access time.
    pub atime: u64,
    /// Last modification time.
    pub mtime: u64,
    /// Last status change time.
    pub ctime: u64,
}

/// Enhanced tmpfs filesystem with configurable resource limits.
///
/// Provides a complete in-memory filesystem with block-based storage,
/// size limits, inode limits, and directory support.
pub struct TmpfsFilesystem {
    /// Mount options.
    options: TmpfsOptions,
    /// Block storage pool.
    blocks: [TmpfsBlock; MAX_BLOCKS],
    /// Inode table.
    inodes: [TmpfsInode; MAX_INODES],
    /// Number of blocks currently in use.
    blocks_used: usize,
    /// Number of inodes currently in use.
    inodes_used: usize,
    /// Total bytes written to files.
    bytes_used: u64,
    /// Root inode ID.
    root_inode: u64,
}

impl core::fmt::Debug for TmpfsFilesystem {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("TmpfsFilesystem")
            .field("blocks_used", &self.blocks_used)
            .field("inodes_used", &self.inodes_used)
            .field("bytes_used", &self.bytes_used)
            .field("root_inode", &self.root_inode)
            .finish()
    }
}

impl Default for TmpfsFilesystem {
    fn default() -> Self {
        Self::new()
    }
}

impl TmpfsFilesystem {
    /// Create a new, unmounted enhanced tmpfs filesystem.
    pub fn new() -> Self {
        const DEFAULT_BLOCK: TmpfsBlock = TmpfsBlock {
            data: [0u8; BLOCK_SIZE],
            in_use: false,
        };
        const DEFAULT_DIR_ENTRY: TmpfsDirEntry = TmpfsDirEntry {
            name: [0u8; MAX_NAME_LEN],
            name_len: 0,
            inode_id: 0,
            in_use: false,
        };
        const DEFAULT_INODE: TmpfsInode = TmpfsInode {
            id: 0,
            mode: 0,
            uid: 0,
            gid: 0,
            size: 0,
            blocks: [0u16; MAX_BLOCKS_PER_INODE],
            block_count: 0,
            nlinks: 1,
            atime: 0,
            mtime: 0,
            ctime: 0,
            is_dir: false,
            in_use: false,
            dir_entries: [DEFAULT_DIR_ENTRY; MAX_DIR_ENTRIES],
        };

        Self {
            options: TmpfsOptions::default(),
            blocks: [DEFAULT_BLOCK; MAX_BLOCKS],
            inodes: [DEFAULT_INODE; MAX_INODES],
            blocks_used: 0,
            inodes_used: 0,
            bytes_used: 0,
            root_inode: 0,
        }
    }

    /// Mount the filesystem with the given options.
    ///
    /// Creates a root directory inode with the permissions, UID, and GID
    /// specified in `options`.
    pub fn mount(&mut self, options: TmpfsOptions) -> Result<()> {
        self.options = options;

        // Allocate root inode (ID 1).
        let root_id = self.alloc_inode()?;
        let root_slot = self.inode_slot(root_id).ok_or(Error::NotFound)?;
        let root = &mut self.inodes[root_slot];
        root.is_dir = true;
        root.mode = self.options.mode;
        root.uid = self.options.uid;
        root.gid = self.options.gid;
        root.nlinks = 2; // "." and parent
        self.root_inode = root_id;

        Ok(())
    }

    /// Return the root inode ID.
    pub fn root_inode_id(&self) -> u64 {
        self.root_inode
    }

    /// Find the slot index for a given inode ID.
    fn inode_slot(&self, id: u64) -> Option<usize> {
        self.inodes
            .iter()
            .position(|ino| ino.in_use && ino.id == id)
    }

    /// Allocate a new inode, returning its ID.
    pub fn alloc_inode(&mut self) -> Result<u64> {
        // Check inode limit.
        if self.options.max_inodes > 0 && self.inodes_used as u64 >= self.options.max_inodes {
            return Err(Error::OutOfMemory);
        }

        let slot = self
            .inodes
            .iter()
            .position(|ino| !ino.in_use)
            .ok_or(Error::OutOfMemory)?;

        // Assign ID = slot + 1 (inode IDs are 1-based).
        let id = (slot as u64) + 1;
        self.inodes[slot] = TmpfsInode::default();
        self.inodes[slot].id = id;
        self.inodes[slot].in_use = true;
        self.inodes_used += 1;

        Ok(id)
    }

    /// Free an inode by ID.
    pub fn free_inode(&mut self, id: u64) {
        if let Some(slot) = self.inode_slot(id) {
            // Free all blocks owned by this inode.
            let block_count = self.inodes[slot].block_count;
            for i in 0..block_count {
                let blk_idx = self.inodes[slot].blocks[i] as usize;
                self.free_block(blk_idx);
            }
            self.inodes[slot].in_use = false;
            self.inodes_used = self.inodes_used.saturating_sub(1);
        }
    }

    /// Allocate a new block, returning its index.
    pub fn alloc_block(&mut self) -> Result<u16> {
        // Check size limit (each block is BLOCK_SIZE bytes).
        if self.options.max_size > 0 {
            let new_bytes = self.bytes_used + BLOCK_SIZE as u64;
            if new_bytes > self.options.max_size {
                return Err(Error::OutOfMemory);
            }
        }

        let idx = self
            .blocks
            .iter()
            .position(|b| !b.in_use)
            .ok_or(Error::OutOfMemory)?;

        self.blocks[idx].in_use = true;
        self.blocks[idx].data.fill(0);
        self.blocks_used += 1;

        Ok(idx as u16)
    }

    /// Free a block by index.
    pub fn free_block(&mut self, idx: usize) {
        if idx < MAX_BLOCKS && self.blocks[idx].in_use {
            self.blocks[idx].in_use = false;
            self.blocks_used = self.blocks_used.saturating_sub(1);
        }
    }

    /// Return the number of bytes of free space available.
    pub fn space_available(&self) -> u64 {
        if self.options.max_size > 0 {
            self.options.max_size.saturating_sub(self.bytes_used)
        } else {
            let total = (MAX_BLOCKS * BLOCK_SIZE) as u64;
            total.saturating_sub(self.bytes_used)
        }
    }

    /// Return the number of inodes still available for allocation.
    pub fn inodes_available(&self) -> u64 {
        if self.options.max_inodes > 0 {
            self.options
                .max_inodes
                .saturating_sub(self.inodes_used as u64)
        } else {
            (MAX_INODES as u64).saturating_sub(self.inodes_used as u64)
        }
    }

    /// Create a regular file in a parent directory.
    ///
    /// Returns the new file's inode ID on success.
    pub fn create_file(&mut self, parent: u64, name: &str, mode: u16) -> Result<u64> {
        let name_bytes = name.as_bytes();
        if name_bytes.is_empty() || name_bytes.len() > MAX_NAME_LEN {
            return Err(Error::InvalidArgument);
        }

        let parent_slot = self.inode_slot(parent).ok_or(Error::NotFound)?;
        if !self.inodes[parent_slot].is_dir {
            return Err(Error::InvalidArgument);
        }

        // Check for duplicate name.
        if self.inodes[parent_slot]
            .dir_entries
            .iter()
            .any(|e| e.in_use && e.name_bytes() == name_bytes)
        {
            return Err(Error::AlreadyExists);
        }

        // Find a free directory entry slot.
        let entry_slot = self.inodes[parent_slot]
            .dir_entries
            .iter()
            .position(|e| !e.in_use)
            .ok_or(Error::OutOfMemory)?;

        // Allocate inode.
        let inode_id = self.alloc_inode()?;
        let inode_slot = self.inode_slot(inode_id).ok_or(Error::NotFound)?;
        self.inodes[inode_slot].mode = mode;
        self.inodes[inode_slot].uid = self.options.uid;
        self.inodes[inode_slot].gid = self.options.gid;
        self.inodes[inode_slot].is_dir = false;

        // Add directory entry.
        let entry = &mut self.inodes[parent_slot].dir_entries[entry_slot];
        entry.name[..name_bytes.len()].copy_from_slice(name_bytes);
        entry.name_len = name_bytes.len() as u8;
        entry.inode_id = inode_id;
        entry.in_use = true;

        Ok(inode_id)
    }

    /// Create a subdirectory in a parent directory.
    ///
    /// Returns the new directory's inode ID on success.
    pub fn create_dir(&mut self, parent: u64, name: &str, mode: u16) -> Result<u64> {
        let name_bytes = name.as_bytes();
        if name_bytes.is_empty() || name_bytes.len() > MAX_NAME_LEN {
            return Err(Error::InvalidArgument);
        }

        let parent_slot = self.inode_slot(parent).ok_or(Error::NotFound)?;
        if !self.inodes[parent_slot].is_dir {
            return Err(Error::InvalidArgument);
        }

        // Check for duplicate name.
        if self.inodes[parent_slot]
            .dir_entries
            .iter()
            .any(|e| e.in_use && e.name_bytes() == name_bytes)
        {
            return Err(Error::AlreadyExists);
        }

        // Find a free directory entry slot.
        let entry_slot = self.inodes[parent_slot]
            .dir_entries
            .iter()
            .position(|e| !e.in_use)
            .ok_or(Error::OutOfMemory)?;

        // Allocate inode.
        let inode_id = self.alloc_inode()?;
        let inode_slot = self.inode_slot(inode_id).ok_or(Error::NotFound)?;
        self.inodes[inode_slot].mode = mode;
        self.inodes[inode_slot].uid = self.options.uid;
        self.inodes[inode_slot].gid = self.options.gid;
        self.inodes[inode_slot].is_dir = true;
        self.inodes[inode_slot].nlinks = 2;

        // Bump parent link count (for "..").
        self.inodes[parent_slot].nlinks += 1;

        // Add directory entry.
        let entry = &mut self.inodes[parent_slot].dir_entries[entry_slot];
        entry.name[..name_bytes.len()].copy_from_slice(name_bytes);
        entry.name_len = name_bytes.len() as u8;
        entry.inode_id = inode_id;
        entry.in_use = true;

        Ok(inode_id)
    }

    /// Write data to a file inode at the given byte offset.
    ///
    /// Returns the number of bytes written. Enforces the filesystem
    /// size limit configured in [`TmpfsOptions::max_size`].
    pub fn write(&mut self, inode_id: u64, offset: u64, data: &[u8]) -> Result<usize> {
        let slot = self.inode_slot(inode_id).ok_or(Error::NotFound)?;
        if self.inodes[slot].is_dir {
            return Err(Error::InvalidArgument);
        }

        if data.is_empty() {
            return Ok(0);
        }

        let offset = offset as usize;
        let end = offset + data.len();
        let max_file_size = MAX_BLOCKS_PER_INODE * BLOCK_SIZE;
        if end > max_file_size {
            return Err(Error::OutOfMemory);
        }

        // Check filesystem size limit.
        if self.options.max_size > 0 {
            let current_size = self.inodes[slot].size as usize;
            let growth = if end > current_size {
                (end - current_size) as u64
            } else {
                0
            };
            if self.bytes_used + growth > self.options.max_size {
                return Err(Error::OutOfMemory);
            }
        }

        let mut bytes_written = 0usize;
        let mut file_pos = offset;

        while bytes_written < data.len() {
            let block_idx_in_file = file_pos / BLOCK_SIZE;
            let block_offset = file_pos % BLOCK_SIZE;
            let chunk = (BLOCK_SIZE - block_offset).min(data.len() - bytes_written);

            if block_idx_in_file >= MAX_BLOCKS_PER_INODE {
                break;
            }

            // Allocate block if needed.
            let block_count = self.inodes[slot].block_count;
            if block_idx_in_file >= block_count {
                // Allocate blocks up to and including this index.
                let needed = block_idx_in_file + 1 - block_count;
                for _ in 0..needed {
                    let blk = self.alloc_block()?;
                    let bc = self.inodes[slot].block_count;
                    self.inodes[slot].blocks[bc] = blk;
                    self.inodes[slot].block_count += 1;
                }
            }

            let pool_idx = self.inodes[slot].blocks[block_idx_in_file] as usize;
            self.blocks[pool_idx].data[block_offset..block_offset + chunk]
                .copy_from_slice(&data[bytes_written..bytes_written + chunk]);

            bytes_written += chunk;
            file_pos += chunk;
        }

        // Update file size and bytes_used.
        let old_size = self.inodes[slot].size;
        let new_size = (end as u64).max(old_size);
        if new_size > old_size {
            self.bytes_used += new_size - old_size;
        }
        self.inodes[slot].size = new_size;

        Ok(bytes_written)
    }

    /// Read data from a file inode at the given byte offset.
    ///
    /// Returns the number of bytes read into `buf`.
    pub fn read(&self, inode_id: u64, offset: u64, buf: &mut [u8]) -> Result<usize> {
        let slot = self.inode_slot(inode_id).ok_or(Error::NotFound)?;
        if self.inodes[slot].is_dir {
            return Err(Error::InvalidArgument);
        }

        let file_size = self.inodes[slot].size as usize;
        let offset = offset as usize;
        if offset >= file_size {
            return Ok(0);
        }

        let available = file_size - offset;
        let to_read = buf.len().min(available);
        let mut bytes_read = 0usize;
        let mut file_pos = offset;

        while bytes_read < to_read {
            let block_idx_in_file = file_pos / BLOCK_SIZE;
            let block_offset = file_pos % BLOCK_SIZE;
            let chunk = (BLOCK_SIZE - block_offset).min(to_read - bytes_read);

            if block_idx_in_file < self.inodes[slot].block_count {
                let pool_idx = self.inodes[slot].blocks[block_idx_in_file] as usize;
                if pool_idx < MAX_BLOCKS && self.blocks[pool_idx].in_use {
                    buf[bytes_read..bytes_read + chunk].copy_from_slice(
                        &self.blocks[pool_idx].data[block_offset..block_offset + chunk],
                    );
                } else {
                    buf[bytes_read..bytes_read + chunk].fill(0);
                }
            } else {
                // Sparse region — return zeros.
                buf[bytes_read..bytes_read + chunk].fill(0);
            }

            bytes_read += chunk;
            file_pos += chunk;
        }

        Ok(bytes_read)
    }

    /// Remove a file from a parent directory by name.
    pub fn unlink(&mut self, parent: u64, name: &str) -> Result<()> {
        let name_bytes = name.as_bytes();
        let parent_slot = self.inode_slot(parent).ok_or(Error::NotFound)?;
        if !self.inodes[parent_slot].is_dir {
            return Err(Error::InvalidArgument);
        }

        // Find the directory entry.
        let (entry_idx, child_id) = self.inodes[parent_slot]
            .dir_entries
            .iter()
            .enumerate()
            .find(|(_, e)| e.in_use && e.name_bytes() == name_bytes)
            .map(|(i, e)| (i, e.inode_id))
            .ok_or(Error::NotFound)?;

        // Verify it is not a directory.
        let child_slot = self.inode_slot(child_id).ok_or(Error::NotFound)?;
        if self.inodes[child_slot].is_dir {
            return Err(Error::PermissionDenied);
        }

        // Decrement nlinks.
        self.inodes[child_slot].nlinks = self.inodes[child_slot].nlinks.saturating_sub(1);

        // If nlinks reaches zero, free the inode and its blocks.
        if self.inodes[child_slot].nlinks == 0 {
            let file_size = self.inodes[child_slot].size;
            self.bytes_used = self.bytes_used.saturating_sub(file_size);
            self.free_inode(child_id);
        }

        // Remove directory entry.
        self.inodes[parent_slot].dir_entries[entry_idx].in_use = false;

        Ok(())
    }

    /// Remove an empty directory from a parent directory by name.
    pub fn rmdir(&mut self, parent: u64, name: &str) -> Result<()> {
        let name_bytes = name.as_bytes();
        let parent_slot = self.inode_slot(parent).ok_or(Error::NotFound)?;
        if !self.inodes[parent_slot].is_dir {
            return Err(Error::InvalidArgument);
        }

        // Find the directory entry.
        let (entry_idx, child_id) = self.inodes[parent_slot]
            .dir_entries
            .iter()
            .enumerate()
            .find(|(_, e)| e.in_use && e.name_bytes() == name_bytes)
            .map(|(i, e)| (i, e.inode_id))
            .ok_or(Error::NotFound)?;

        // Verify it is a directory.
        let child_slot = self.inode_slot(child_id).ok_or(Error::NotFound)?;
        if !self.inodes[child_slot].is_dir {
            return Err(Error::InvalidArgument);
        }

        // Must be empty.
        let has_entries = self.inodes[child_slot].dir_entries.iter().any(|e| e.in_use);
        if has_entries {
            return Err(Error::Busy);
        }

        // Free child inode.
        self.free_inode(child_id);

        // Remove directory entry from parent.
        self.inodes[parent_slot].dir_entries[entry_idx].in_use = false;

        // Decrement parent link count (remove "..").
        self.inodes[parent_slot].nlinks = self.inodes[parent_slot].nlinks.saturating_sub(1);

        Ok(())
    }

    /// Truncate a file to the given size.
    ///
    /// If the new size is smaller, excess blocks are freed and
    /// [`bytes_used`](Self) is updated. If larger, the file is
    /// extended with zero-filled blocks.
    pub fn truncate(&mut self, inode_id: u64, size: u64) -> Result<()> {
        let slot = self.inode_slot(inode_id).ok_or(Error::NotFound)?;
        if self.inodes[slot].is_dir {
            return Err(Error::InvalidArgument);
        }

        let max_file_size = (MAX_BLOCKS_PER_INODE * BLOCK_SIZE) as u64;
        let new_size = size.min(max_file_size);
        let old_size = self.inodes[slot].size;

        if new_size < old_size {
            // Shrink: free blocks beyond new_size.
            let new_block_count = if new_size == 0 {
                0
            } else {
                (new_size as usize).div_ceil(BLOCK_SIZE)
            };
            let old_block_count = self.inodes[slot].block_count;

            for i in new_block_count..old_block_count {
                let blk_idx = self.inodes[slot].blocks[i] as usize;
                self.free_block(blk_idx);
                self.inodes[slot].blocks[i] = 0;
            }
            self.inodes[slot].block_count = new_block_count;

            // Zero partial last block.
            if new_block_count > 0 {
                let last_off = (new_size as usize) % BLOCK_SIZE;
                if last_off > 0 {
                    let blk_idx = self.inodes[slot].blocks[new_block_count - 1] as usize;
                    if blk_idx < MAX_BLOCKS {
                        self.blocks[blk_idx].data[last_off..].fill(0);
                    }
                }
            }

            self.bytes_used = self.bytes_used.saturating_sub(old_size - new_size);
        } else if new_size > old_size {
            // Grow: check size limit.
            let growth = new_size - old_size;
            if self.options.max_size > 0 && self.bytes_used + growth > self.options.max_size {
                return Err(Error::OutOfMemory);
            }

            // Allocate blocks up to new_size.
            let new_block_count = (new_size as usize).div_ceil(BLOCK_SIZE);
            let old_block_count = self.inodes[slot].block_count;

            for _ in old_block_count..new_block_count {
                let blk = self.alloc_block()?;
                let bc = self.inodes[slot].block_count;
                self.inodes[slot].blocks[bc] = blk;
                self.inodes[slot].block_count += 1;
            }

            self.bytes_used += growth;
        }

        self.inodes[slot].size = new_size;
        Ok(())
    }

    /// Return stat information for an inode.
    pub fn stat(&self, inode_id: u64) -> Result<TmpfsStat> {
        let slot = self.inode_slot(inode_id).ok_or(Error::NotFound)?;
        let ino = &self.inodes[slot];
        Ok(TmpfsStat {
            size: ino.size,
            blocks: ino.block_count as u64,
            mode: ino.mode,
            uid: ino.uid,
            gid: ino.gid,
            nlinks: ino.nlinks,
            atime: ino.atime,
            mtime: ino.mtime,
            ctime: ino.ctime,
        })
    }

    /// Return the directory entries for a directory inode.
    pub fn readdir(&self, inode_id: u64) -> Result<&[TmpfsDirEntry]> {
        let slot = self.inode_slot(inode_id).ok_or(Error::NotFound)?;
        if !self.inodes[slot].is_dir {
            return Err(Error::InvalidArgument);
        }
        Ok(&self.inodes[slot].dir_entries)
    }
}
