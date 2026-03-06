// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `removexattr(2)` / `lremovexattr(2)` / `fremovexattr(2)` syscall handlers.
//!
//! Removes an extended attribute from a filesystem entry.
//!
//! # Key behaviours
//!
//! - The attribute name must be a valid `namespace.key` string.
//! - Returns `ENODATA` (`NotImplemented` here) if the attribute does not exist.
//! - `trusted.*` / `security.*` namespaces require `CAP_SYS_ADMIN`.
//! - `lremovexattr` does not follow symlinks.
//! - `fremovexattr` operates on an open file descriptor.
//!
//! # References
//!
//! - Linux: `fs/xattr.c`, `vfs_removexattr()`
//! - man `removexattr(2)`

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum xattr name length.
pub const XATTR_NAME_MAX: usize = 255;
/// Maximum xattr value size.
pub const XATTR_SIZE_MAX: usize = 65536;
/// Maximum path length.
pub const PATH_MAX: usize = 4096;
/// Maximum xattr entries per file.
pub const MAX_XATTRS_PER_FILE: usize = 16;
/// Maximum files tracked.
pub const MAX_RMXATTR_FILES: usize = 64;

// ---------------------------------------------------------------------------
// XattrNamespace
// ---------------------------------------------------------------------------

/// Extended attribute namespace.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XattrNamespace {
    /// `user.*`.
    User,
    /// `system.*`.
    System,
    /// `trusted.*` — requires `CAP_SYS_ADMIN`.
    Trusted,
    /// `security.*` — requires `CAP_SYS_ADMIN`.
    Security,
}

impl XattrNamespace {
    /// Parse the namespace from an xattr name.
    pub fn from_name(name: &[u8]) -> Option<Self> {
        if name.starts_with(b"user.") {
            Some(Self::User)
        } else if name.starts_with(b"system.") {
            Some(Self::System)
        } else if name.starts_with(b"trusted.") {
            Some(Self::Trusted)
        } else if name.starts_with(b"security.") {
            Some(Self::Security)
        } else {
            None
        }
    }

    /// Return `true` if this namespace requires `CAP_SYS_ADMIN`.
    pub const fn requires_admin(self) -> bool {
        matches!(self, Self::Trusted | Self::Security)
    }
}

// ---------------------------------------------------------------------------
// RmXattrEntry / RmXattrFile / RmXattrTable
// ---------------------------------------------------------------------------

/// One extended attribute record.
pub struct RmXattrEntry {
    pub name: [u8; XATTR_NAME_MAX + 1],
    pub name_len: usize,
    pub value: [u8; XATTR_SIZE_MAX],
    pub value_len: usize,
    pub in_use: bool,
}

impl RmXattrEntry {
    const fn empty() -> Self {
        Self {
            name: [0u8; XATTR_NAME_MAX + 1],
            name_len: 0,
            value: [0u8; XATTR_SIZE_MAX],
            value_len: 0,
            in_use: false,
        }
    }

    /// Name as a byte slice.
    pub fn name_bytes(&self) -> &[u8] {
        &self.name[..self.name_len]
    }
}

/// Per-inode xattr store.
pub struct RmXattrFile {
    pub path_hash: u64,
    pub attrs: [RmXattrEntry; MAX_XATTRS_PER_FILE],
    pub in_use: bool,
}

impl RmXattrFile {
    const fn empty() -> Self {
        Self {
            path_hash: 0,
            attrs: [const { RmXattrEntry::empty() }; MAX_XATTRS_PER_FILE],
            in_use: false,
        }
    }

    /// Find the slot index for a given name (returns the slot index).
    fn find_attr_idx(&self, name: &[u8]) -> Option<usize> {
        self.attrs
            .iter()
            .position(|a| a.in_use && a.name_bytes() == name)
    }

    /// Remove an attribute by name.  Returns `true` if found.
    pub fn remove_attr(&mut self, name: &[u8]) -> bool {
        if let Some(idx) = self.find_attr_idx(name) {
            self.attrs[idx] = RmXattrEntry::empty();
            true
        } else {
            false
        }
    }

    /// Insert a new attribute (for tests).
    pub fn insert_attr(&mut self, name: &[u8], value: &[u8]) -> Result<()> {
        for slot in self.attrs.iter_mut() {
            if !slot.in_use {
                let nlen = name.len();
                let vlen = value.len();
                slot.name[..nlen].copy_from_slice(name);
                slot.name_len = nlen;
                slot.value[..vlen].copy_from_slice(value);
                slot.value_len = vlen;
                slot.in_use = true;
                return Ok(());
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Return the number of attributes.
    pub fn attr_count(&self) -> usize {
        self.attrs.iter().filter(|a| a.in_use).count()
    }
}

/// Global xattr table.
pub struct RmXattrTable {
    files: [RmXattrFile; MAX_RMXATTR_FILES],
    count: usize,
}

impl RmXattrTable {
    /// Create an empty table.
    pub const fn new() -> Self {
        Self {
            files: [const { RmXattrFile::empty() }; MAX_RMXATTR_FILES],
            count: 0,
        }
    }

    /// Ensure a file record exists for `path_hash`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the table is full.
    pub fn ensure_file_mut(&mut self, hash: u64) -> Result<&mut RmXattrFile> {
        let idx = self
            .files
            .iter()
            .position(|f| f.in_use && f.path_hash == hash);
        if let Some(i) = idx {
            return Ok(&mut self.files[i]);
        }
        for (i, slot) in self.files.iter_mut().enumerate() {
            if !slot.in_use {
                slot.path_hash = hash;
                slot.in_use = true;
                self.count += 1;
                return Ok(&mut self.files[i]);
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Find a file record by path hash (mutable).
    pub fn file_for_hash_mut(&mut self, hash: u64) -> Option<&mut RmXattrFile> {
        self.files
            .iter_mut()
            .find(|f| f.in_use && f.path_hash == hash)
    }

    /// Find a file record by path hash (immutable).
    pub fn file_for_hash(&self, hash: u64) -> Option<&RmXattrFile> {
        self.files.iter().find(|f| f.in_use && f.path_hash == hash)
    }

    /// Return the number of files with xattrs.
    pub const fn count(&self) -> usize {
        self.count
    }
}

impl Default for RmXattrTable {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn path_hash(path: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in path {
        h ^= *b as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}

fn validate_name(name: &[u8]) -> Result<XattrNamespace> {
    if name.is_empty() || name.len() > XATTR_NAME_MAX {
        return Err(Error::InvalidArgument);
    }
    XattrNamespace::from_name(name).ok_or(Error::InvalidArgument)
}

// ---------------------------------------------------------------------------
// do_removexattr — handler
// ---------------------------------------------------------------------------

/// Handler for `removexattr(2)`.
///
/// Removes the extended attribute `name` from the file at `path`.
///
/// # Arguments
///
/// * `table`      — global xattr table
/// * `path`       — file path
/// * `name`       — attribute name (`namespace.key`)
/// * `caller_uid` — caller UID for namespace permission check
///
/// # Errors
///
/// * [`Error::InvalidArgument`]  — invalid name or path
/// * [`Error::NotImplemented`]   — attribute does not exist (`ENODATA`)
/// * [`Error::PermissionDenied`] — namespace requires admin, caller is not root
pub fn do_removexattr(
    table: &mut RmXattrTable,
    path: &[u8],
    name: &[u8],
    caller_uid: u32,
) -> Result<()> {
    if path.is_empty() || path.len() >= PATH_MAX {
        return Err(Error::InvalidArgument);
    }
    let ns = validate_name(name)?;
    if ns.requires_admin() && caller_uid != 0 {
        return Err(Error::PermissionDenied);
    }

    let hash = path_hash(path);
    let file = table.file_for_hash_mut(hash).ok_or(Error::NotImplemented)?;

    if !file.remove_attr(name) {
        return Err(Error::NotImplemented); // ENODATA
    }
    Ok(())
}

/// Handler for `lremovexattr(2)` — does not follow symlinks (stub: same).
pub fn do_lremovexattr(
    table: &mut RmXattrTable,
    path: &[u8],
    name: &[u8],
    caller_uid: u32,
) -> Result<()> {
    do_removexattr(table, path, name, caller_uid)
}

/// Handler for `fremovexattr(2)` — operates on open fd by inode stub key.
pub fn do_fremovexattr(
    table: &mut RmXattrTable,
    fd_hash: u64,
    name: &[u8],
    caller_uid: u32,
) -> Result<()> {
    let ns = validate_name(name)?;
    if ns.requires_admin() && caller_uid != 0 {
        return Err(Error::PermissionDenied);
    }
    let file = table
        .file_for_hash_mut(fd_hash)
        .ok_or(Error::NotImplemented)?;
    if !file.remove_attr(name) {
        return Err(Error::NotImplemented);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn setup(t: &mut RmXattrTable, path: &[u8], name: &[u8]) {
        let hash = path_hash(path);
        let file = t.ensure_file_mut(hash).unwrap();
        file.insert_attr(name, b"value").unwrap();
    }

    #[test]
    fn removexattr_removes_attr() {
        let mut t = RmXattrTable::new();
        setup(&mut t, b"/file", b"user.tag");
        do_removexattr(&mut t, b"/file", b"user.tag", 1000).unwrap();
        let file = t.file_for_hash(path_hash(b"/file")).unwrap();
        assert_eq!(file.attr_count(), 0);
    }

    #[test]
    fn removexattr_not_found() {
        let mut t = RmXattrTable::new();
        t.ensure_file_mut(path_hash(b"/file")).unwrap();
        assert_eq!(
            do_removexattr(&mut t, b"/file", b"user.missing", 0),
            Err(Error::NotImplemented)
        );
    }

    #[test]
    fn removexattr_no_file_record() {
        let mut t = RmXattrTable::new();
        assert_eq!(
            do_removexattr(&mut t, b"/no_file", b"user.tag", 0),
            Err(Error::NotImplemented)
        );
    }

    #[test]
    fn removexattr_trusted_requires_admin() {
        let mut t = RmXattrTable::new();
        setup(&mut t, b"/file", b"trusted.key");
        assert_eq!(
            do_removexattr(&mut t, b"/file", b"trusted.key", 1000),
            Err(Error::PermissionDenied)
        );
        do_removexattr(&mut t, b"/file", b"trusted.key", 0).unwrap();
    }

    #[test]
    fn removexattr_invalid_namespace() {
        let mut t = RmXattrTable::new();
        assert_eq!(
            do_removexattr(&mut t, b"/f", b"bad.key", 0),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn removexattr_empty_path_rejected() {
        let mut t = RmXattrTable::new();
        assert_eq!(
            do_removexattr(&mut t, b"", b"user.k", 0),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn fremovexattr_by_hash() {
        let mut t = RmXattrTable::new();
        let hash = path_hash(b"/fd_file");
        let file = t.ensure_file_mut(hash).unwrap();
        file.insert_attr(b"security.ctx", b"ctx").unwrap();
        do_fremovexattr(&mut t, hash, b"security.ctx", 0).unwrap();
        let file = t.file_for_hash(hash).unwrap();
        assert_eq!(file.attr_count(), 0);
    }

    #[test]
    fn lremovexattr_same_as_removexattr() {
        let mut t = RmXattrTable::new();
        setup(&mut t, b"/symlink", b"user.meta");
        do_lremovexattr(&mut t, b"/symlink", b"user.meta", 1000).unwrap();
        let file = t.file_for_hash(path_hash(b"/symlink")).unwrap();
        assert_eq!(file.attr_count(), 0);
    }
}
