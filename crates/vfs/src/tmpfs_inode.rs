// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Tmpfs inode implementation.
//!
//! Provides the in-memory inode type for tmpfs, including the file-type union,
//! extended attribute list, page-tracking metadata, and the inode allocation
//! pool with simple reference counting.

use oncrix_lib::{Error, Result};

/// Maximum number of tmpfs inodes.
pub const TMPFS_MAX_INODES: usize = 65536;

/// Tmpfs inode number type.
pub type TmpfsIno = u32;

/// File types stored in tmpfs inodes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TmpfsFileType {
    Regular,
    Directory,
    Symlink,
    Fifo,
    Socket,
    CharDev,
    BlockDev,
}

/// Per-type data stored inside a tmpfs inode.
#[derive(Debug, Clone)]
pub enum TmpfsInodeData {
    /// Regular file: page cache is tracked separately; store byte size.
    Regular { size: u64, pages: u64 },
    /// Directory: child count.
    Directory {
        child_count: u32,
        dot_ino: TmpfsIno,
        dotdot_ino: TmpfsIno,
    },
    /// Symbolic link: target bytes (up to 4095 chars).
    Symlink { target: [u8; 256], target_len: u16 },
    /// Device file: device number.
    Device { dev: u64 },
    /// FIFO / socket: no extra data.
    Pipe,
}

/// A single tmpfs extended attribute entry.
#[derive(Debug, Clone)]
pub struct TmpfsXattr {
    /// Attribute name (NUL-padded, up to 255 bytes).
    pub name: [u8; 256],
    pub name_len: u8,
    /// Value bytes (up to 256 bytes).
    pub value: [u8; 256],
    pub value_len: u16,
}

impl TmpfsXattr {
    /// Name as a byte slice.
    pub fn name_bytes(&self) -> &[u8] {
        &self.name[..self.name_len as usize]
    }

    /// Value as a byte slice.
    pub fn value_bytes(&self) -> &[u8] {
        &self.value[..self.value_len as usize]
    }
}

/// Maximum number of xattrs per tmpfs inode.
pub const TMPFS_MAX_XATTRS: usize = 16;

/// In-memory tmpfs inode.
pub struct TmpfsInode {
    /// Inode number (assigned at allocation).
    pub ino: TmpfsIno,
    /// File type and permissions.
    pub mode: u16,
    /// Owner UID.
    pub uid: u32,
    /// Owner GID.
    pub gid: u32,
    /// Hard link count.
    pub nlink: u32,
    /// Reference count (open fds, dcache pins, …).
    pub ref_count: u32,
    /// Access time (UNIX seconds).
    pub atime: i64,
    /// Modification time.
    pub mtime: i64,
    /// Change time.
    pub ctime: i64,
    /// File-type-specific data.
    pub data: TmpfsInodeData,
    /// Extended attributes.
    pub xattrs: [Option<TmpfsXattr>; TMPFS_MAX_XATTRS],
    pub xattr_count: u8,
    /// Whether this inode is allocated (false = free slot).
    pub allocated: bool,
}

impl TmpfsInode {
    /// Create an allocated regular-file inode.
    pub fn new_regular(ino: TmpfsIno, mode: u16, uid: u32, gid: u32, now: i64) -> Self {
        let mut inode = Self::blank(ino);
        inode.mode = 0o100000 | (mode & 0o7777);
        inode.uid = uid;
        inode.gid = gid;
        inode.atime = now;
        inode.mtime = now;
        inode.ctime = now;
        inode.nlink = 1;
        inode.data = TmpfsInodeData::Regular { size: 0, pages: 0 };
        inode.allocated = true;
        inode
    }

    /// Create an allocated directory inode.
    pub fn new_dir(
        ino: TmpfsIno,
        mode: u16,
        uid: u32,
        gid: u32,
        parent_ino: TmpfsIno,
        now: i64,
    ) -> Self {
        let mut inode = Self::blank(ino);
        inode.mode = 0o040000 | (mode & 0o7777);
        inode.uid = uid;
        inode.gid = gid;
        inode.atime = now;
        inode.mtime = now;
        inode.ctime = now;
        inode.nlink = 2; // "." and parent link
        inode.data = TmpfsInodeData::Directory {
            child_count: 0,
            dot_ino: ino,
            dotdot_ino: parent_ino,
        };
        inode.allocated = true;
        inode
    }

    /// Create an allocated symlink inode.
    pub fn new_symlink(ino: TmpfsIno, uid: u32, gid: u32, target: &[u8], now: i64) -> Result<Self> {
        if target.len() > 255 {
            return Err(Error::InvalidArgument);
        }
        let mut inode = Self::blank(ino);
        inode.mode = 0o120000 | 0o777;
        inode.uid = uid;
        inode.gid = gid;
        inode.atime = now;
        inode.mtime = now;
        inode.ctime = now;
        inode.nlink = 1;
        let mut buf = [0u8; 256];
        buf[..target.len()].copy_from_slice(target);
        inode.data = TmpfsInodeData::Symlink {
            target: buf,
            target_len: target.len() as u16,
        };
        inode.allocated = true;
        Ok(inode)
    }

    fn blank(ino: TmpfsIno) -> Self {
        Self {
            ino,
            mode: 0,
            uid: 0,
            gid: 0,
            nlink: 0,
            ref_count: 0,
            atime: 0,
            mtime: 0,
            ctime: 0,
            data: TmpfsInodeData::Pipe,
            xattrs: [const { None }; TMPFS_MAX_XATTRS],
            xattr_count: 0,
            allocated: false,
        }
    }

    /// Set an extended attribute on this inode.
    pub fn set_xattr(&mut self, name: &[u8], value: &[u8]) -> Result<()> {
        if name.len() > 255 || value.len() > 256 {
            return Err(Error::InvalidArgument);
        }
        // Check for existing entry to update.
        for slot in &mut self.xattrs[..self.xattr_count as usize] {
            if let Some(xa) = slot.as_mut() {
                if xa.name_bytes() == name {
                    xa.value[..value.len()].copy_from_slice(value);
                    xa.value_len = value.len() as u16;
                    return Ok(());
                }
            }
        }
        // Add new entry.
        if self.xattr_count as usize >= TMPFS_MAX_XATTRS {
            return Err(Error::OutOfMemory);
        }
        let mut xa = TmpfsXattr {
            name: [0u8; 256],
            name_len: name.len() as u8,
            value: [0u8; 256],
            value_len: value.len() as u16,
        };
        xa.name[..name.len()].copy_from_slice(name);
        xa.value[..value.len()].copy_from_slice(value);
        self.xattrs[self.xattr_count as usize] = Some(xa);
        self.xattr_count += 1;
        Ok(())
    }

    /// Remove an extended attribute.
    pub fn remove_xattr(&mut self, name: &[u8]) -> Result<()> {
        for i in 0..self.xattr_count as usize {
            if self.xattrs[i]
                .as_ref()
                .map(|xa| xa.name_bytes() == name)
                .unwrap_or(false)
            {
                let end = self.xattr_count as usize;
                self.xattrs[i] = None;
                if i + 1 < end {
                    self.xattrs[i] = self.xattrs[end - 1].take();
                }
                self.xattr_count -= 1;
                return Ok(());
            }
        }
        Err(Error::NotFound)
    }

    /// Increment the reference count.
    pub fn inc_ref(&mut self) {
        self.ref_count += 1;
    }

    /// Decrement the reference count; returns `true` if now zero.
    pub fn dec_ref(&mut self) -> bool {
        if self.ref_count > 0 {
            self.ref_count -= 1;
        }
        self.ref_count == 0
    }
}

/// Tmpfs inode allocator.
pub struct TmpfsInodePool {
    inodes: [Option<TmpfsInode>; TMPFS_MAX_INODES],
    free_count: usize,
    next_hint: usize,
}

impl TmpfsInodePool {
    /// Create an empty pool.
    pub const fn new() -> Self {
        Self {
            inodes: [const { None }; TMPFS_MAX_INODES],
            free_count: TMPFS_MAX_INODES,
            next_hint: 1, // ino 0 is reserved
        }
    }

    /// Allocate the next free inode number.
    pub fn alloc_ino(&mut self) -> Result<TmpfsIno> {
        if self.free_count == 0 {
            return Err(Error::OutOfMemory);
        }
        let start = self.next_hint;
        for i in 0..TMPFS_MAX_INODES {
            let idx = (start + i) % TMPFS_MAX_INODES;
            if idx == 0 {
                continue;
            }
            if self.inodes[idx].is_none() {
                self.next_hint = (idx + 1) % TMPFS_MAX_INODES;
                self.free_count -= 1;
                return Ok(idx as TmpfsIno);
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Store a newly allocated inode.
    pub fn insert(&mut self, inode: TmpfsInode) -> Result<()> {
        let idx = inode.ino as usize;
        if idx == 0 || idx >= TMPFS_MAX_INODES {
            return Err(Error::InvalidArgument);
        }
        if self.inodes[idx].is_some() {
            return Err(Error::AlreadyExists);
        }
        self.inodes[idx] = Some(inode);
        Ok(())
    }

    /// Retrieve an inode by number.
    pub fn get(&self, ino: TmpfsIno) -> Option<&TmpfsInode> {
        let idx = ino as usize;
        if idx >= TMPFS_MAX_INODES {
            None
        } else {
            self.inodes[idx].as_ref()
        }
    }

    /// Retrieve a mutable inode.
    pub fn get_mut(&mut self, ino: TmpfsIno) -> Option<&mut TmpfsInode> {
        let idx = ino as usize;
        if idx >= TMPFS_MAX_INODES {
            None
        } else {
            self.inodes[idx].as_mut()
        }
    }

    /// Free an inode by number.
    pub fn free(&mut self, ino: TmpfsIno) -> Result<()> {
        let idx = ino as usize;
        if idx == 0 || idx >= TMPFS_MAX_INODES {
            return Err(Error::InvalidArgument);
        }
        if self.inodes[idx].is_none() {
            return Err(Error::NotFound);
        }
        self.inodes[idx] = None;
        self.free_count += 1;
        Ok(())
    }

    /// Number of free inode slots.
    pub fn free_count(&self) -> usize {
        self.free_count
    }
}

impl Default for TmpfsInodePool {
    fn default() -> Self {
        Self::new()
    }
}
