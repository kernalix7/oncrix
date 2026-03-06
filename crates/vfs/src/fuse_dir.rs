// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! FUSE directory operations.
//!
//! This module implements the directory-side operations of the FUSE protocol:
//! lookup, mkdir, rmdir, rename, mknod, symlink, link, and readdir/readdirplus.
//!
//! Each operation marshals a FUSE request to userspace and unmarshals the
//! reply. The module maintains a per-directory readdir state to support
//! incremental directory listing.
//!
//! # References
//!
//! - Linux `fs/fuse/dir.c`
//! - `include/uapi/linux/fuse.h`

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum name length for a directory entry.
pub const FUSE_NAME_MAX: usize = 1024;

/// Maximum cached directory entries per directory.
pub const MAX_READDIR_ENTRIES: usize = 256;

/// FUSE op codes for directory operations.
pub const FUSE_LOOKUP: u32 = 1;
pub const FUSE_MKDIR: u32 = 9;
pub const FUSE_UNLINK: u32 = 10;
pub const FUSE_RMDIR: u32 = 11;
pub const FUSE_RENAME: u32 = 12;
pub const FUSE_LINK: u32 = 13;
pub const FUSE_MKNOD: u32 = 8;
pub const FUSE_SYMLINK: u32 = 6;
pub const FUSE_READDIR: u32 = 28;
pub const FUSE_READDIRPLUS: u32 = 44;

/// File type bits for `d_type`.
pub const DT_UNKNOWN: u8 = 0;
pub const DT_DIR: u8 = 4;
pub const DT_REG: u8 = 8;
pub const DT_LNK: u8 = 10;
pub const DT_CHR: u8 = 2;
pub const DT_BLK: u8 = 6;
pub const DT_FIFO: u8 = 1;
pub const DT_SOCK: u8 = 12;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// A single directory entry returned by FUSE readdir.
#[derive(Clone)]
pub struct FuseDirEntry {
    /// Inode number.
    pub ino: u64,
    /// Offset to the next entry (used as cookie for telldir/seekdir).
    pub off: u64,
    /// Name length in bytes.
    pub namelen: u32,
    /// File type (`DT_*`).
    pub dtype: u8,
    /// Entry name (UTF-8 bytes, null-terminated at `namelen`).
    pub name: [u8; FUSE_NAME_MAX],
}

impl FuseDirEntry {
    /// Create a new directory entry.
    pub fn new(ino: u64, off: u64, dtype: u8, name: &[u8]) -> Result<Self> {
        if name.len() > FUSE_NAME_MAX {
            return Err(Error::InvalidArgument);
        }
        let mut entry = Self {
            ino,
            off,
            namelen: name.len() as u32,
            dtype,
            name: [0u8; FUSE_NAME_MAX],
        };
        entry.name[..name.len()].copy_from_slice(name);
        Ok(entry)
    }

    /// Return name as a byte slice.
    pub fn name_bytes(&self) -> &[u8] {
        &self.name[..self.namelen as usize]
    }
}

/// FUSE entry attribute reply (simplified attr set).
#[derive(Debug, Clone, Copy, Default)]
pub struct FuseEntryAttr {
    /// Inode number.
    pub ino: u64,
    /// File size.
    pub size: u64,
    /// File mode bits.
    pub mode: u32,
    /// Number of hard links.
    pub nlink: u32,
    /// UID.
    pub uid: u32,
    /// GID.
    pub gid: u32,
}

/// State for an in-progress FUSE readdir operation.
pub struct FuseReaddirState {
    /// Parent directory inode.
    pub dir_ino: u64,
    /// Current position cookie (offset of next entry to return).
    pub offset: u64,
    /// Cached entries from the last READDIR reply.
    entries: [Option<FuseDirEntry>; MAX_READDIR_ENTRIES],
    /// Number of valid entries in the cache.
    pub entry_count: usize,
    /// Whether all entries have been read.
    pub done: bool,
}

impl FuseReaddirState {
    /// Create a new readdir state for `dir_ino`.
    pub fn new(dir_ino: u64) -> Self {
        Self {
            dir_ino,
            offset: 0,
            entries: core::array::from_fn(|_| None),
            entry_count: 0,
            done: false,
        }
    }

    /// Reset state to re-read from the beginning.
    pub fn rewind(&mut self) {
        self.offset = 0;
        self.entry_count = 0;
        self.done = false;
        for e in self.entries.iter_mut() {
            *e = None;
        }
    }

    /// Append a cached entry. Returns `Err(OutOfMemory)` if cache full.
    pub fn push_entry(&mut self, entry: FuseDirEntry) -> Result<()> {
        if self.entry_count >= MAX_READDIR_ENTRIES {
            return Err(Error::OutOfMemory);
        }
        self.entries[self.entry_count] = Some(entry);
        self.entry_count += 1;
        Ok(())
    }

    /// Return the entry at position `idx` in the cache.
    pub fn get_entry(&self, idx: usize) -> Option<&FuseDirEntry> {
        if idx < self.entry_count {
            self.entries[idx].as_ref()
        } else {
            None
        }
    }
}

/// FUSE directory operation request, forwarded to userspace daemon.
#[derive(Debug, Clone)]
pub struct FuseDirRequest {
    /// Operation code (`FUSE_MKDIR`, `FUSE_RMDIR`, etc.).
    pub opcode: u32,
    /// Parent directory inode.
    pub parent_ino: u64,
    /// Name (null-terminated at `name_len`).
    pub name: [u8; FUSE_NAME_MAX],
    /// Name length.
    pub name_len: usize,
    /// Mode for create operations.
    pub mode: u32,
    /// Rdev for mknod.
    pub rdev: u32,
    /// New parent for rename.
    pub new_parent_ino: u64,
    /// New name for rename/link.
    pub new_name: [u8; FUSE_NAME_MAX],
    /// New name length.
    pub new_name_len: usize,
}

impl FuseDirRequest {
    fn new_simple(opcode: u32, parent_ino: u64, name: &[u8]) -> Result<Self> {
        if name.len() > FUSE_NAME_MAX {
            return Err(Error::InvalidArgument);
        }
        let mut req = Self {
            opcode,
            parent_ino,
            name: [0u8; FUSE_NAME_MAX],
            name_len: name.len(),
            mode: 0,
            rdev: 0,
            new_parent_ino: 0,
            new_name: [0u8; FUSE_NAME_MAX],
            new_name_len: 0,
        };
        req.name[..name.len()].copy_from_slice(name);
        Ok(req)
    }
}

// ---------------------------------------------------------------------------
// Operations
// ---------------------------------------------------------------------------

/// Perform a FUSE LOOKUP request.
///
/// Constructs and returns the request to be dispatched to the FUSE daemon.
/// On success the caller receives a [`FuseDirRequest`] ready for sending.
pub fn fuse_lookup(parent_ino: u64, name: &[u8]) -> Result<FuseDirRequest> {
    FuseDirRequest::new_simple(FUSE_LOOKUP, parent_ino, name)
}

/// Perform a FUSE MKDIR request.
///
/// `mode` is the directory permissions (e.g. `0o755`).
pub fn fuse_mkdir(parent_ino: u64, name: &[u8], mode: u32) -> Result<FuseDirRequest> {
    let mut req = FuseDirRequest::new_simple(FUSE_MKDIR, parent_ino, name)?;
    req.mode = mode;
    Ok(req)
}

/// Perform a FUSE RMDIR request.
pub fn fuse_rmdir(parent_ino: u64, name: &[u8]) -> Result<FuseDirRequest> {
    FuseDirRequest::new_simple(FUSE_RMDIR, parent_ino, name)
}

/// Perform a FUSE UNLINK request (remove a non-directory).
pub fn fuse_unlink(parent_ino: u64, name: &[u8]) -> Result<FuseDirRequest> {
    FuseDirRequest::new_simple(FUSE_UNLINK, parent_ino, name)
}

/// Perform a FUSE RENAME request.
pub fn fuse_rename(
    old_parent: u64,
    old_name: &[u8],
    new_parent: u64,
    new_name: &[u8],
) -> Result<FuseDirRequest> {
    if old_name.len() > FUSE_NAME_MAX || new_name.len() > FUSE_NAME_MAX {
        return Err(Error::InvalidArgument);
    }
    let mut req = FuseDirRequest::new_simple(FUSE_RENAME, old_parent, old_name)?;
    req.new_parent_ino = new_parent;
    req.new_name[..new_name.len()].copy_from_slice(new_name);
    req.new_name_len = new_name.len();
    Ok(req)
}

/// Perform a FUSE MKNOD request.
///
/// `mode` includes type bits and permission bits; `rdev` is the device number.
pub fn fuse_mknod(parent_ino: u64, name: &[u8], mode: u32, rdev: u32) -> Result<FuseDirRequest> {
    let mut req = FuseDirRequest::new_simple(FUSE_MKNOD, parent_ino, name)?;
    req.mode = mode;
    req.rdev = rdev;
    Ok(req)
}

/// Perform a FUSE SYMLINK request.
///
/// `name` is the symlink name; `new_name` holds the link target.
pub fn fuse_symlink(parent_ino: u64, name: &[u8], target: &[u8]) -> Result<FuseDirRequest> {
    if target.len() > FUSE_NAME_MAX {
        return Err(Error::InvalidArgument);
    }
    let mut req = FuseDirRequest::new_simple(FUSE_SYMLINK, parent_ino, name)?;
    req.new_name[..target.len()].copy_from_slice(target);
    req.new_name_len = target.len();
    Ok(req)
}

/// Perform a FUSE LINK (hard link) request.
///
/// `old_ino` is the existing inode; `new_parent` / `new_name` are the new
/// directory entry.
pub fn fuse_link(old_ino: u64, new_parent: u64, new_name: &[u8]) -> Result<FuseDirRequest> {
    if new_name.len() > FUSE_NAME_MAX {
        return Err(Error::InvalidArgument);
    }
    let mut req = FuseDirRequest::new_simple(FUSE_LINK, old_ino, &[])?;
    req.new_parent_ino = new_parent;
    req.new_name[..new_name.len()].copy_from_slice(new_name);
    req.new_name_len = new_name.len();
    Ok(req)
}

/// Prepare a FUSE READDIR request for a directory.
///
/// Returns a request struct. The caller is expected to send this to the
/// FUSE daemon and then call [`readdir_fill`] with the reply entries.
pub fn fuse_readdir(state: &FuseReaddirState) -> FuseDirRequest {
    FuseDirRequest {
        opcode: FUSE_READDIR,
        parent_ino: state.dir_ino,
        name: [0u8; FUSE_NAME_MAX],
        name_len: 0,
        mode: 0,
        rdev: 0,
        new_parent_ino: state.offset,
        new_name: [0u8; FUSE_NAME_MAX],
        new_name_len: 0,
    }
}

/// Prepare a FUSE READDIRPLUS request.
///
/// Like `fuse_readdir` but requests extended attribute data for each entry.
pub fn fuse_readdirplus(state: &FuseReaddirState) -> FuseDirRequest {
    let mut req = fuse_readdir(state);
    req.opcode = FUSE_READDIRPLUS;
    req
}

/// Fill `state` with entries received from the FUSE daemon reply.
///
/// `entries` should be the parsed reply entries. Returns `Err(OutOfMemory)`
/// if more entries than `MAX_READDIR_ENTRIES` are provided.
pub fn readdir_fill(
    state: &mut FuseReaddirState,
    entries: &[(u64, u64, u8, &[u8])], // (ino, off, dtype, name)
    done: bool,
) -> Result<()> {
    state.entry_count = 0;
    for &(ino, off, dtype, name) in entries {
        let entry = FuseDirEntry::new(ino, off, dtype, name)?;
        state.push_entry(entry)?;
        state.offset = off;
    }
    state.done = done;
    Ok(())
}

/// Seek the readdir state to offset `off`.
///
/// Sets the internal offset; next READDIR request will use this cookie.
pub fn readdir_seek(state: &mut FuseReaddirState, off: u64) {
    state.offset = off;
    state.entry_count = 0;
    state.done = false;
}

/// Tell the current readdir position (telldir equivalent).
pub fn readdir_tell(state: &FuseReaddirState) -> u64 {
    state.offset
}
