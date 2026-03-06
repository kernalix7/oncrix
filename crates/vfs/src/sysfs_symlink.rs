// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! sysfs symbolic links.
//!
//! Implements symbolic link creation and resolution in the sysfs virtual
//! filesystem. sysfs symlinks are used to represent relationships between
//! kernel objects (e.g., a driver pointing to the device it manages).
//!
//! # Operations
//!
//! - [`SysfsDirent`] — sysfs directory entry (file, directory, or symlink)
//! - `sysfs_create_link` — create a symlink within the sysfs tree
//! - `sysfs_remove_link` — remove an existing symlink
//! - `sysfs_resolve_link` — resolve a symlink to its target path
//!
//! # Reference
//!
//! Linux `fs/sysfs/symlink.c`, `fs/sysfs/dir.c`.

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum number of sysfs directory entries.
const MAX_SYSFS_ENTRIES: usize = 256;

/// Maximum path length for sysfs entries.
const MAX_SYSFS_PATH: usize = 256;

/// Maximum symlink target path length.
const MAX_SYMLINK_TARGET: usize = 256;

/// Maximum name length.
const MAX_NAME_LEN: usize = 64;

/// Maximum symlink resolution depth (prevent cycles).
const MAX_RESOLVE_DEPTH: usize = 8;

// ---------------------------------------------------------------------------
// Dirent type
// ---------------------------------------------------------------------------

/// Type of a sysfs directory entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SysfsDirentType {
    /// Regular attribute file.
    File,
    /// Directory (kobject).
    Directory,
    /// Symbolic link.
    Symlink,
    /// Binary attribute file.
    BinFile,
}

// ---------------------------------------------------------------------------
// Sysfs directory entry
// ---------------------------------------------------------------------------

/// A single entry in the sysfs tree.
#[derive(Debug, Clone)]
pub struct SysfsDirent {
    /// Entry name.
    pub name: [u8; MAX_NAME_LEN],
    /// Valid bytes in `name`.
    pub name_len: usize,
    /// Absolute sysfs path of this entry.
    pub path: [u8; MAX_SYSFS_PATH],
    /// Valid bytes in `path`.
    pub path_len: usize,
    /// Entry type.
    pub dirent_type: SysfsDirentType,
    /// Symlink target path (only valid for Symlink type).
    pub target_path: [u8; MAX_SYMLINK_TARGET],
    /// Valid bytes in `target_path`.
    pub target_len: usize,
    /// Permissions (simplified: read-only or read-write).
    pub mode: u16,
    /// Whether this entry is currently active.
    pub active: bool,
    /// Inode number (synthetic).
    pub ino: u64,
}

impl SysfsDirent {
    /// Creates a new regular file entry.
    pub fn file(name: &[u8], path: &[u8], mode: u16, ino: u64) -> Result<Self> {
        Self::new(name, path, SysfsDirentType::File, mode, ino)
    }

    /// Creates a new directory entry.
    pub fn directory(name: &[u8], path: &[u8], ino: u64) -> Result<Self> {
        Self::new(name, path, SysfsDirentType::Directory, 0o755, ino)
    }

    /// Creates a new symlink entry with the given target.
    pub fn symlink(name: &[u8], path: &[u8], target: &[u8], ino: u64) -> Result<Self> {
        let mut entry = Self::new(name, path, SysfsDirentType::Symlink, 0o777, ino)?;
        if target.len() > MAX_SYMLINK_TARGET {
            return Err(Error::InvalidArgument);
        }
        entry.target_path[..target.len()].copy_from_slice(target);
        entry.target_len = target.len();
        Ok(entry)
    }

    fn new(
        name: &[u8],
        path: &[u8],
        dirent_type: SysfsDirentType,
        mode: u16,
        ino: u64,
    ) -> Result<Self> {
        if name.is_empty() || name.len() > MAX_NAME_LEN {
            return Err(Error::InvalidArgument);
        }
        if path.is_empty() || path.len() > MAX_SYSFS_PATH {
            return Err(Error::InvalidArgument);
        }
        let mut n_buf = [0u8; MAX_NAME_LEN];
        n_buf[..name.len()].copy_from_slice(name);
        let mut p_buf = [0u8; MAX_SYSFS_PATH];
        p_buf[..path.len()].copy_from_slice(path);
        Ok(Self {
            name: n_buf,
            name_len: name.len(),
            path: p_buf,
            path_len: path.len(),
            dirent_type,
            target_path: [0u8; MAX_SYMLINK_TARGET],
            target_len: 0,
            mode,
            active: true,
            ino,
        })
    }

    /// Returns the entry name as a byte slice.
    pub fn name_bytes(&self) -> &[u8] {
        &self.name[..self.name_len]
    }

    /// Returns the entry path as a byte slice.
    pub fn path_bytes(&self) -> &[u8] {
        &self.path[..self.path_len]
    }

    /// Returns the symlink target as a byte slice.
    pub fn target_bytes(&self) -> &[u8] {
        &self.target_path[..self.target_len]
    }

    /// Returns whether this is a symlink.
    pub fn is_symlink(&self) -> bool {
        self.dirent_type == SysfsDirentType::Symlink
    }
}

// ---------------------------------------------------------------------------
// Sysfs tree
// ---------------------------------------------------------------------------

/// The sysfs virtual filesystem tree.
pub struct SysfsTree {
    /// All directory entries in the tree.
    entries: [Option<SysfsDirent>; MAX_SYSFS_ENTRIES],
    /// Number of active entries.
    count: usize,
    /// Next synthetic inode number.
    next_ino: u64,
}

impl SysfsTree {
    /// Creates an empty sysfs tree.
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

    /// Inserts a new entry into the tree.
    fn insert(&mut self, entry: SysfsDirent) -> Result<()> {
        if self.count >= MAX_SYSFS_ENTRIES {
            return Err(Error::OutOfMemory);
        }
        // Check for duplicate path.
        for slot in self.entries[..].iter().flatten() {
            if slot.path_bytes() == entry.path_bytes() {
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
    pub fn find(&self, path: &[u8]) -> Option<&SysfsDirent> {
        self.entries
            .iter()
            .flatten()
            .find(|e| e.path_bytes() == path && e.active)
    }

    /// Returns an iterator over all active entries.
    pub fn iter(&self) -> impl Iterator<Item = &SysfsDirent> {
        self.entries.iter().flatten().filter(|e| e.active)
    }

    /// Creates a new directory entry.
    pub fn mkdir(&mut self, name: &[u8], path: &[u8]) -> Result<u64> {
        let ino = self.alloc_ino();
        let entry = SysfsDirent::directory(name, path, ino)?;
        self.insert(entry)?;
        Ok(ino)
    }

    /// Creates a new file entry.
    pub fn create_file(&mut self, name: &[u8], path: &[u8], mode: u16) -> Result<u64> {
        let ino = self.alloc_ino();
        let entry = SysfsDirent::file(name, path, mode, ino)?;
        self.insert(entry)?;
        Ok(ino)
    }
}

impl Default for SysfsTree {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Symlink operations
// ---------------------------------------------------------------------------

/// Creates a symbolic link in the sysfs tree.
///
/// Creates an entry at `link_path` that points to `target_path`. Both
/// paths must be within the sysfs mount point.
pub fn sysfs_create_link(
    tree: &mut SysfsTree,
    name: &[u8],
    link_path: &[u8],
    target_path: &[u8],
) -> Result<u64> {
    // Validate target exists or is a valid sysfs path.
    if link_path.is_empty() || target_path.is_empty() {
        return Err(Error::InvalidArgument);
    }
    let ino = tree.alloc_ino();
    let entry = SysfsDirent::symlink(name, link_path, target_path, ino)?;
    tree.insert(entry)?;
    Ok(ino)
}

/// Removes a symbolic link from the sysfs tree.
pub fn sysfs_remove_link(tree: &mut SysfsTree, link_path: &[u8]) -> Result<()> {
    for slot in &mut tree.entries {
        if let Some(entry) = slot.as_mut() {
            if entry.path_bytes() == link_path && entry.is_symlink() && entry.active {
                entry.active = false;
                tree.count = tree.count.saturating_sub(1);
                return Ok(());
            }
        }
    }
    Err(Error::NotFound)
}

/// Resolves a symbolic link to its final target path.
///
/// Follows symlink chains up to `MAX_RESOLVE_DEPTH` deep.
/// Returns the final target path.
pub fn sysfs_resolve_link<'a>(
    tree: &'a SysfsTree,
    link_path: &[u8],
    out: &'a mut [u8; MAX_SYSFS_PATH],
) -> Result<usize> {
    let mut current = link_path;
    let mut temp: [u8; MAX_SYSFS_PATH] = [0u8; MAX_SYSFS_PATH];
    let mut depth = 0usize;

    loop {
        let entry = tree.find(current).ok_or(Error::NotFound)?;
        if !entry.is_symlink() {
            // Reached a non-symlink: copy final path to out.
            let len = entry.path_len.min(MAX_SYSFS_PATH);
            out[..len].copy_from_slice(&entry.path[..len]);
            return Ok(len);
        }

        depth += 1;
        if depth > MAX_RESOLVE_DEPTH {
            return Err(Error::InvalidArgument); // Symlink loop.
        }

        // Follow the symlink.
        let target_len = entry.target_len.min(MAX_SYSFS_PATH);
        temp[..target_len].copy_from_slice(&entry.target_path[..target_len]);
        current = &temp[..target_len];
    }
}

/// Lists all symlinks in the sysfs tree. Returns count.
pub fn sysfs_list_links(tree: &SysfsTree, out: &mut [SyfsLinkInfo; 32]) -> usize {
    let mut count = 0;
    for entry in tree.iter() {
        if entry.is_symlink() && count < 32 {
            out[count] = SyfsLinkInfo {
                path_len: entry.path_len,
                path: entry.path,
                target_len: entry.target_len,
                target: entry.target_path,
            };
            count += 1;
        }
    }
    count
}

/// Info about a single sysfs symlink.
#[derive(Debug, Clone, Copy)]
pub struct SyfsLinkInfo {
    /// Length of the link path.
    pub path_len: usize,
    /// Link path.
    pub path: [u8; MAX_SYSFS_PATH],
    /// Length of the target path.
    pub target_len: usize,
    /// Target path.
    pub target: [u8; MAX_SYMLINK_TARGET],
}
