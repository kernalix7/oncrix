// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! ramfs inode operations.
//!
//! Implements the core inode operations for the in-memory ramfs filesystem:
//!
//! - [`RamfsInode`] — inode with inline data buffer and metadata
//! - `ramfs_create` — create a regular file inode
//! - `ramfs_mkdir` — create a directory inode
//! - `ramfs_lookup` — look up a child entry by name
//! - Read/write/truncate on in-memory data
//!
//! # Design
//!
//! ramfs uses a flat inode table. Directory inodes hold a list of
//! `DirEntry` records (name + inode number). File inodes hold a
//! fixed-size data buffer (up to `RAMFS_MAX_FILE_SIZE` bytes).
//!
//! # Reference
//!
//! Linux `fs/ramfs/inode.c`.

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum number of inodes in the ramfs table.
const MAX_RAMFS_INODES: usize = 512;

/// Maximum file data size (256 KiB).
const RAMFS_MAX_FILE_SIZE: usize = 262144;

/// Maximum directory entries per directory inode.
const MAX_DIR_ENTRIES: usize = 64;

/// Maximum file name length.
const MAX_NAME_LEN: usize = 255;

/// Root inode number.
pub const RAMFS_ROOT_INO: u64 = 1;

// ---------------------------------------------------------------------------
// Directory entry
// ---------------------------------------------------------------------------

/// A directory entry within a ramfs directory inode.
#[derive(Debug, Clone)]
pub struct RamfsDirEntry {
    /// Entry name.
    pub name: [u8; MAX_NAME_LEN],
    /// Valid bytes in `name`.
    pub name_len: usize,
    /// Inode number of the target.
    pub ino: u64,
    /// File type (0=dir, 1=file, 2=symlink).
    pub file_type: u8,
}

impl RamfsDirEntry {
    /// Creates a new directory entry.
    pub fn new(name: &[u8], ino: u64, file_type: u8) -> Result<Self> {
        if name.is_empty() || name.len() > MAX_NAME_LEN {
            return Err(Error::InvalidArgument);
        }
        let mut buf = [0u8; MAX_NAME_LEN];
        buf[..name.len()].copy_from_slice(name);
        Ok(Self {
            name: buf,
            name_len: name.len(),
            ino,
            file_type,
        })
    }

    /// Returns the name as a byte slice.
    pub fn name_bytes(&self) -> &[u8] {
        &self.name[..self.name_len]
    }
}

// ---------------------------------------------------------------------------
// Inode type
// ---------------------------------------------------------------------------

/// Type of a ramfs inode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RamfsInodeType {
    /// Regular file.
    File,
    /// Directory.
    Directory,
    /// Symbolic link.
    Symlink,
}

// ---------------------------------------------------------------------------
// Ramfs inode
// ---------------------------------------------------------------------------

/// An in-memory inode for the ramfs filesystem.
pub struct RamfsInode {
    /// Inode number.
    pub ino: u64,
    /// Inode type.
    pub inode_type: RamfsInodeType,
    /// File permission mode.
    pub mode: u16,
    /// Owner user ID.
    pub uid: u32,
    /// Owner group ID.
    pub gid: u32,
    /// File size in bytes.
    pub size: usize,
    /// Link count.
    pub nlink: u32,
    /// Access time (nanoseconds since epoch).
    pub atime_ns: u64,
    /// Modification time.
    pub mtime_ns: u64,
    /// Change time.
    pub ctime_ns: u64,
    /// File data (for regular files and symlinks).
    pub data: [u8; RAMFS_MAX_FILE_SIZE],
    /// Directory entries (for directory inodes).
    pub dir_entries: [Option<RamfsDirEntry>; MAX_DIR_ENTRIES],
    /// Number of valid directory entries.
    pub dir_count: usize,
    /// Whether this inode is in use.
    pub in_use: bool,
}

impl RamfsInode {
    /// Creates a new empty file inode.
    fn new_file(ino: u64, mode: u16, uid: u32, gid: u32) -> Self {
        Self {
            ino,
            inode_type: RamfsInodeType::File,
            mode,
            uid,
            gid,
            size: 0,
            nlink: 1,
            atime_ns: 0,
            mtime_ns: 0,
            ctime_ns: 0,
            data: [0u8; RAMFS_MAX_FILE_SIZE],
            dir_entries: core::array::from_fn(|_| None),
            dir_count: 0,
            in_use: true,
        }
    }

    /// Creates a new directory inode.
    fn new_dir(ino: u64, mode: u16, uid: u32, gid: u32) -> Self {
        Self {
            inode_type: RamfsInodeType::Directory,
            nlink: 2,
            ..Self::new_file(ino, mode, uid, gid)
        }
    }

    /// Creates a new symlink inode.
    fn new_symlink(ino: u64, uid: u32, gid: u32) -> Self {
        Self {
            inode_type: RamfsInodeType::Symlink,
            ..Self::new_file(ino, 0o777, uid, gid)
        }
    }

    /// Reads file data at the given offset into `buf`.
    /// Returns the number of bytes read.
    pub fn read(&mut self, offset: usize, buf: &mut [u8]) -> Result<usize> {
        if self.inode_type == RamfsInodeType::Directory {
            return Err(Error::InvalidArgument);
        }
        if offset >= self.size {
            return Ok(0);
        }
        let avail = self.size - offset;
        let to_read = buf.len().min(avail);
        buf[..to_read].copy_from_slice(&self.data[offset..offset + to_read]);
        self.atime_ns += 1; // Simplified time update.
        Ok(to_read)
    }

    /// Writes data to the file at the given offset.
    /// Returns the number of bytes written.
    pub fn write(&mut self, offset: usize, data: &[u8]) -> Result<usize> {
        if self.inode_type == RamfsInodeType::Directory {
            return Err(Error::InvalidArgument);
        }
        let end = offset
            .checked_add(data.len())
            .ok_or(Error::InvalidArgument)?;
        if end > RAMFS_MAX_FILE_SIZE {
            return Err(Error::OutOfMemory);
        }
        self.data[offset..end].copy_from_slice(data);
        if end > self.size {
            self.size = end;
        }
        self.mtime_ns += 1;
        self.ctime_ns = self.mtime_ns;
        Ok(data.len())
    }

    /// Truncates the file to the given size.
    pub fn truncate(&mut self, new_size: usize) -> Result<()> {
        if self.inode_type == RamfsInodeType::Directory {
            return Err(Error::InvalidArgument);
        }
        if new_size > RAMFS_MAX_FILE_SIZE {
            return Err(Error::OutOfMemory);
        }
        if new_size < self.size {
            // Zero out the truncated region.
            self.data[new_size..self.size].fill(0);
        }
        self.size = new_size;
        self.mtime_ns += 1;
        self.ctime_ns = self.mtime_ns;
        Ok(())
    }

    /// Adds a directory entry.
    pub fn add_dir_entry(&mut self, name: &[u8], ino: u64, file_type: u8) -> Result<()> {
        if self.inode_type != RamfsInodeType::Directory {
            return Err(Error::InvalidArgument);
        }
        if self.dir_count >= MAX_DIR_ENTRIES {
            return Err(Error::OutOfMemory);
        }
        // Check for duplicate.
        for entry in self.dir_entries[..self.dir_count].iter().flatten() {
            if entry.name_bytes() == name {
                return Err(Error::AlreadyExists);
            }
        }
        for slot in &mut self.dir_entries {
            if slot.is_none() {
                *slot = Some(RamfsDirEntry::new(name, ino, file_type)?);
                self.dir_count += 1;
                self.size += 1; // Simplified size update.
                return Ok(());
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Removes a directory entry by name.
    pub fn remove_dir_entry(&mut self, name: &[u8]) -> Result<u64> {
        for (i, slot) in self.dir_entries[..self.dir_count].iter_mut().enumerate() {
            if slot.as_ref().map(|e| e.name_bytes()) == Some(name) {
                let ino = slot.as_ref().unwrap().ino;
                *slot = None;
                self.dir_count = self.dir_count.saturating_sub(1);
                // Compact.
                for j in i..self.dir_count {
                    self.dir_entries[j] = self.dir_entries[j + 1].take();
                }
                return Ok(ino);
            }
        }
        Err(Error::NotFound)
    }

    /// Looks up a directory entry by name. Returns the inode number.
    pub fn lookup_entry(&self, name: &[u8]) -> Result<u64> {
        if self.inode_type != RamfsInodeType::Directory {
            return Err(Error::InvalidArgument);
        }
        for entry in self.dir_entries[..self.dir_count].iter().flatten() {
            if entry.name_bytes() == name {
                return Ok(entry.ino);
            }
        }
        Err(Error::NotFound)
    }
}

// ---------------------------------------------------------------------------
// Inode table
// ---------------------------------------------------------------------------

/// The ramfs inode table.
pub struct RamfsInodeTable {
    /// Inode storage.
    inodes: [Option<RamfsInode>; MAX_RAMFS_INODES],
    /// Number of allocated inodes.
    count: usize,
    /// Next inode number.
    next_ino: u64,
}

impl RamfsInodeTable {
    /// Creates a new inode table with a root directory.
    pub fn new() -> Self {
        let mut table = Self {
            inodes: core::array::from_fn(|_| None),
            count: 0,
            next_ino: RAMFS_ROOT_INO,
        };
        // Create root inode.
        let root = RamfsInode::new_dir(RAMFS_ROOT_INO, 0o755, 0, 0);
        table.inodes[0] = Some(root);
        table.count = 1;
        table.next_ino = RAMFS_ROOT_INO + 1;
        table
    }

    /// Allocates a new inode number.
    fn alloc_ino(&mut self) -> u64 {
        let ino = self.next_ino;
        self.next_ino += 1;
        ino
    }

    /// Returns a reference to an inode by number.
    pub fn get(&self, ino: u64) -> Option<&RamfsInode> {
        self.inodes
            .iter()
            .flatten()
            .find(|i| i.ino == ino && i.in_use)
    }

    /// Returns a mutable reference to an inode by number.
    pub fn get_mut(&mut self, ino: u64) -> Option<&mut RamfsInode> {
        self.inodes
            .iter_mut()
            .flatten()
            .find(|i| i.ino == ino && i.in_use)
    }

    /// Inserts a new inode.
    fn insert(&mut self, inode: RamfsInode) -> Result<u64> {
        if self.count >= MAX_RAMFS_INODES {
            return Err(Error::OutOfMemory);
        }
        let ino = inode.ino;
        for slot in &mut self.inodes {
            if slot.is_none() {
                *slot = Some(inode);
                self.count += 1;
                return Ok(ino);
            }
        }
        Err(Error::OutOfMemory)
    }
}

impl Default for RamfsInodeTable {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Operations
// ---------------------------------------------------------------------------

/// Creates a regular file in the given directory.
///
/// Returns the new inode number.
pub fn ramfs_create(
    table: &mut RamfsInodeTable,
    dir_ino: u64,
    name: &[u8],
    mode: u16,
    uid: u32,
    gid: u32,
) -> Result<u64> {
    let ino = table.alloc_ino();
    let inode = RamfsInode::new_file(ino, mode, uid, gid);
    table.insert(inode)?;

    // Add entry to parent directory.
    let dir = table.get_mut(dir_ino).ok_or(Error::NotFound)?;
    if dir.inode_type != RamfsInodeType::Directory {
        return Err(Error::InvalidArgument);
    }
    dir.add_dir_entry(name, ino, 1)?;
    Ok(ino)
}

/// Creates a directory in the given parent directory.
///
/// Returns the new inode number.
pub fn ramfs_mkdir(
    table: &mut RamfsInodeTable,
    parent_ino: u64,
    name: &[u8],
    mode: u16,
    uid: u32,
    gid: u32,
) -> Result<u64> {
    let ino = table.alloc_ino();
    let mut inode = RamfsInode::new_dir(ino, mode, uid, gid);
    // Add . and .. entries.
    inode.add_dir_entry(b".", ino, 0)?;
    inode.add_dir_entry(b"..", parent_ino, 0)?;
    table.insert(inode)?;

    let parent = table.get_mut(parent_ino).ok_or(Error::NotFound)?;
    parent.add_dir_entry(name, ino, 0)?;
    parent.nlink += 1;
    Ok(ino)
}

/// Looks up a name in a directory inode.
///
/// Returns the inode number of the matching entry.
pub fn ramfs_lookup(table: &RamfsInodeTable, dir_ino: u64, name: &[u8]) -> Result<u64> {
    let dir = table.get(dir_ino).ok_or(Error::NotFound)?;
    dir.lookup_entry(name)
}

/// Creates a symbolic link.
pub fn ramfs_symlink(
    table: &mut RamfsInodeTable,
    dir_ino: u64,
    name: &[u8],
    target: &[u8],
    uid: u32,
    gid: u32,
) -> Result<u64> {
    let ino = table.alloc_ino();
    let mut inode = RamfsInode::new_symlink(ino, uid, gid);
    inode.write(0, target)?;
    table.insert(inode)?;

    let dir = table.get_mut(dir_ino).ok_or(Error::NotFound)?;
    dir.add_dir_entry(name, ino, 2)?;
    Ok(ino)
}

/// Unlinks a file from a directory.
pub fn ramfs_unlink(table: &mut RamfsInodeTable, dir_ino: u64, name: &[u8]) -> Result<()> {
    let child_ino = {
        let dir = table.get(dir_ino).ok_or(Error::NotFound)?;
        dir.lookup_entry(name)?
    };

    {
        let dir = table.get_mut(dir_ino).ok_or(Error::NotFound)?;
        dir.remove_dir_entry(name)?;
    }

    // Decrement link count.
    if let Some(inode) = table.get_mut(child_ino) {
        inode.nlink = inode.nlink.saturating_sub(1);
        if inode.nlink == 0 {
            inode.in_use = false;
            // Clear data.
            inode.size = 0;
        }
    }
    Ok(())
}
