// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! securityfs node management.
//!
//! Implements the securityfs virtual filesystem used by Linux Security Modules
//! (LSM) to expose state and allow configuration via the filesystem interface.
//! Typical users include SELinux, AppArmor, and IMA.
//!
//! # Components
//!
//! - [`SecurityfsEntry`] — a file or directory node in securityfs
//! - `securityfs_create_file` — create a new file entry
//! - `securityfs_create_dir` — create a new directory entry
//! - Read/write dispatch through registered ops functions
//!
//! # Reference
//!
//! Linux `security/inode.c`, `include/linux/security.h`.

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum number of securityfs entries.
const MAX_SECURITYFS_ENTRIES: usize = 128;

/// Maximum entry name length.
const MAX_NAME_LEN: usize = 64;

/// Maximum path length.
const MAX_PATH_LEN: usize = 256;

/// Maximum read buffer size for ops.
const MAX_READ_SIZE: usize = 4096;

/// Maximum write buffer size for ops.
const MAX_WRITE_SIZE: usize = 4096;

// ---------------------------------------------------------------------------
// Entry type
// ---------------------------------------------------------------------------

/// Type of a securityfs entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryType {
    /// Regular file.
    File,
    /// Directory.
    Directory,
    /// Symbolic link.
    Symlink,
}

// ---------------------------------------------------------------------------
// Entry operations
// ---------------------------------------------------------------------------

/// Per-entry static operations (callback function pointers).
///
/// In this no_std implementation, the callbacks are stored as function
/// pointer values. In a real system, these would be `fn(&SecurityfsEntry, ...)`.
#[derive(Debug, Clone, Copy)]
pub struct EntryOps {
    /// Read handler: returns number of bytes to return.
    pub read_fn: fn(entry: &SecurityfsEntry, buf: &mut [u8], offset: usize) -> Result<usize>,
    /// Write handler: returns number of bytes consumed.
    pub write_fn: fn(entry: &mut SecurityfsEntry, data: &[u8]) -> Result<usize>,
}

// ---------------------------------------------------------------------------
// SecurityfsEntry
// ---------------------------------------------------------------------------

/// A node (file or directory) in the securityfs virtual filesystem.
pub struct SecurityfsEntry {
    /// Entry name.
    pub name: [u8; MAX_NAME_LEN],
    /// Valid bytes in `name`.
    pub name_len: usize,
    /// Full path within securityfs.
    pub path: [u8; MAX_PATH_LEN],
    /// Valid bytes in `path`.
    pub path_len: usize,
    /// Entry type.
    pub entry_type: EntryType,
    /// File permission mode.
    pub mode: u16,
    /// Owner UID.
    pub uid: u32,
    /// Owner GID.
    pub gid: u32,
    /// Inode number (synthetic).
    pub ino: u64,
    /// Operations for this entry.
    pub ops: Option<EntryOps>,
    /// Inline data storage (for simple string/binary state).
    pub data: [u8; MAX_READ_SIZE],
    /// Valid bytes in `data`.
    pub data_len: usize,
    /// Whether this entry is active.
    pub active: bool,
    /// Read count.
    pub read_count: u64,
    /// Write count.
    pub write_count: u64,
    /// LSM owner name (e.g., "selinux", "apparmor").
    pub lsm_name: [u8; MAX_NAME_LEN],
    /// Valid bytes in `lsm_name`.
    pub lsm_name_len: usize,
}

impl SecurityfsEntry {
    /// Creates a new file entry.
    pub fn new_file(name: &[u8], path: &[u8], mode: u16, ino: u64, lsm: &[u8]) -> Result<Self> {
        Self::new(name, path, EntryType::File, mode, ino, lsm)
    }

    /// Creates a new directory entry.
    pub fn new_dir(name: &[u8], path: &[u8], ino: u64, lsm: &[u8]) -> Result<Self> {
        Self::new(name, path, EntryType::Directory, 0o755, ino, lsm)
    }

    fn new(
        name: &[u8],
        path: &[u8],
        entry_type: EntryType,
        mode: u16,
        ino: u64,
        lsm: &[u8],
    ) -> Result<Self> {
        if name.is_empty() || name.len() > MAX_NAME_LEN {
            return Err(Error::InvalidArgument);
        }
        if path.is_empty() || path.len() > MAX_PATH_LEN {
            return Err(Error::InvalidArgument);
        }
        if lsm.len() > MAX_NAME_LEN {
            return Err(Error::InvalidArgument);
        }
        let mut n_buf = [0u8; MAX_NAME_LEN];
        n_buf[..name.len()].copy_from_slice(name);
        let mut p_buf = [0u8; MAX_PATH_LEN];
        p_buf[..path.len()].copy_from_slice(path);
        let mut l_buf = [0u8; MAX_NAME_LEN];
        if !lsm.is_empty() {
            l_buf[..lsm.len()].copy_from_slice(lsm);
        }
        Ok(Self {
            name: n_buf,
            name_len: name.len(),
            path: p_buf,
            path_len: path.len(),
            entry_type,
            mode,
            uid: 0,
            gid: 0,
            ino,
            ops: None,
            data: [0u8; MAX_READ_SIZE],
            data_len: 0,
            active: true,
            read_count: 0,
            write_count: 0,
            lsm_name: l_buf,
            lsm_name_len: lsm.len(),
        })
    }

    /// Returns the entry name as bytes.
    pub fn name_bytes(&self) -> &[u8] {
        &self.name[..self.name_len]
    }

    /// Returns the entry path as bytes.
    pub fn path_bytes(&self) -> &[u8] {
        &self.path[..self.path_len]
    }

    /// Returns the LSM name as bytes.
    pub fn lsm_name_bytes(&self) -> &[u8] {
        &self.lsm_name[..self.lsm_name_len]
    }

    /// Sets the inline data for this entry.
    pub fn set_data(&mut self, data: &[u8]) -> Result<()> {
        if data.len() > MAX_READ_SIZE {
            return Err(Error::InvalidArgument);
        }
        self.data[..data.len()].copy_from_slice(data);
        self.data_len = data.len();
        Ok(())
    }

    /// Returns whether this entry is readable.
    pub fn is_readable(&self) -> bool {
        self.mode & 0o444 != 0
    }

    /// Returns whether this entry is writable.
    pub fn is_writable(&self) -> bool {
        self.mode & 0o222 != 0
    }

    /// Reads from this entry.
    ///
    /// If ops are registered, dispatches to the read_fn. Otherwise reads
    /// from inline data.
    pub fn read(&mut self, buf: &mut [u8], offset: usize) -> Result<usize> {
        if !self.is_readable() {
            return Err(Error::PermissionDenied);
        }
        if !self.active {
            return Err(Error::NotFound);
        }
        self.read_count += 1;
        if let Some(ops) = self.ops {
            // SAFETY: we pass a shared reference; the fn must not mutate.
            let n = (ops.read_fn)(self, buf, offset)?;
            return Ok(n);
        }
        // Default: read from inline data.
        if offset >= self.data_len {
            return Ok(0);
        }
        let avail = self.data_len - offset;
        let to_read = buf.len().min(avail);
        buf[..to_read].copy_from_slice(&self.data[offset..offset + to_read]);
        Ok(to_read)
    }

    /// Writes to this entry.
    ///
    /// If ops are registered, dispatches to the write_fn. Otherwise stores
    /// to inline data.
    pub fn write(&mut self, data: &[u8]) -> Result<usize> {
        if !self.is_writable() {
            return Err(Error::PermissionDenied);
        }
        if !self.active {
            return Err(Error::NotFound);
        }
        self.write_count += 1;
        if let Some(ops) = self.ops {
            return (ops.write_fn)(self, data);
        }
        // Default: store to inline data.
        if data.len() > MAX_READ_SIZE {
            return Err(Error::InvalidArgument);
        }
        self.data[..data.len()].copy_from_slice(data);
        self.data_len = data.len();
        Ok(data.len())
    }
}

// ---------------------------------------------------------------------------
// Securityfs tree
// ---------------------------------------------------------------------------

/// The securityfs virtual filesystem tree.
pub struct SecurityfsTree {
    /// All entries.
    entries: [Option<SecurityfsEntry>; MAX_SECURITYFS_ENTRIES],
    /// Number of active entries.
    count: usize,
    /// Next synthetic inode number.
    next_ino: u64,
}

impl SecurityfsTree {
    /// Creates a new securityfs tree.
    pub fn new() -> Self {
        Self {
            entries: core::array::from_fn(|_| None),
            count: 0,
            next_ino: 1,
        }
    }

    /// Returns the number of entries.
    pub fn count(&self) -> usize {
        self.count
    }

    /// Allocates a new inode number.
    fn alloc_ino(&mut self) -> u64 {
        let ino = self.next_ino;
        self.next_ino += 1;
        ino
    }

    /// Inserts an entry into the tree.
    fn insert(&mut self, entry: SecurityfsEntry) -> Result<()> {
        if self.count >= MAX_SECURITYFS_ENTRIES {
            return Err(Error::OutOfMemory);
        }
        for slot in &mut self.entries {
            if slot
                .as_ref()
                .map(|e| e.path_bytes() == entry.path_bytes() && e.active)
                == Some(true)
            {
                return Err(Error::AlreadyExists);
            }
        }
        for slot in &mut self.entries {
            if slot.is_none() {
                *slot = Some(entry);
                self.count += 1;
                return Ok(());
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Finds an entry by path.
    pub fn find(&self, path: &[u8]) -> Option<&SecurityfsEntry> {
        self.entries
            .iter()
            .flatten()
            .find(|e| e.path_bytes() == path && e.active)
    }

    /// Finds a mutable entry by path.
    pub fn find_mut(&mut self, path: &[u8]) -> Option<&mut SecurityfsEntry> {
        self.entries
            .iter_mut()
            .flatten()
            .find(|e| e.path_bytes() == path && e.active)
    }

    /// Returns an iterator over all active entries.
    pub fn iter(&self) -> impl Iterator<Item = &SecurityfsEntry> {
        self.entries.iter().flatten().filter(|e| e.active)
    }

    /// Returns all entries for a given LSM.
    pub fn entries_for_lsm<'a>(
        &'a self,
        lsm: &'a [u8],
    ) -> impl Iterator<Item = &'a SecurityfsEntry> {
        self.entries
            .iter()
            .flatten()
            .filter(move |e| e.lsm_name_bytes() == lsm && e.active)
    }
}

impl Default for SecurityfsTree {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Operations
// ---------------------------------------------------------------------------

/// Creates a new file node in securityfs.
pub fn securityfs_create_file(
    tree: &mut SecurityfsTree,
    name: &[u8],
    path: &[u8],
    mode: u16,
    lsm: &[u8],
    ops: Option<EntryOps>,
) -> Result<u64> {
    let ino = tree.alloc_ino();
    let mut entry = SecurityfsEntry::new_file(name, path, mode, ino, lsm)?;
    entry.ops = ops;
    tree.insert(entry)?;
    Ok(ino)
}

/// Creates a new directory node in securityfs.
pub fn securityfs_create_dir(
    tree: &mut SecurityfsTree,
    name: &[u8],
    path: &[u8],
    lsm: &[u8],
) -> Result<u64> {
    let ino = tree.alloc_ino();
    let entry = SecurityfsEntry::new_dir(name, path, ino, lsm)?;
    tree.insert(entry)?;
    Ok(ino)
}

/// Removes a securityfs entry by path.
pub fn securityfs_remove(tree: &mut SecurityfsTree, path: &[u8]) -> Result<()> {
    for slot in &mut tree.entries {
        if slot.as_ref().map(|e| e.path_bytes() == path && e.active) == Some(true) {
            if let Some(entry) = slot.as_mut() {
                entry.active = false;
            }
            *slot = None;
            tree.count = tree.count.saturating_sub(1);
            return Ok(());
        }
    }
    Err(Error::NotFound)
}

/// Reads from a securityfs file.
pub fn securityfs_read(
    tree: &mut SecurityfsTree,
    path: &[u8],
    buf: &mut [u8],
    offset: usize,
) -> Result<usize> {
    let entry = tree.find_mut(path).ok_or(Error::NotFound)?;
    if entry.entry_type != EntryType::File {
        return Err(Error::InvalidArgument);
    }
    entry.read(buf, offset)
}

/// Writes to a securityfs file.
pub fn securityfs_write(tree: &mut SecurityfsTree, path: &[u8], data: &[u8]) -> Result<usize> {
    let entry = tree.find_mut(path).ok_or(Error::NotFound)?;
    if entry.entry_type != EntryType::File {
        return Err(Error::InvalidArgument);
    }
    entry.write(data)
}
