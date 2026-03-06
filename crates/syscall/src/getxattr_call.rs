// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `getxattr(2)` / `lgetxattr(2)` / `fgetxattr(2)` syscall handlers.
//!
//! Retrieves the value of an extended attribute associated with a file.
//!
//! # Key behaviours
//!
//! - The attribute name must be in `namespace.key` format
//!   (e.g. `user.comment`, `security.selinux`).
//! - When `size == 0` the syscall returns the required buffer size only.
//! - Returns `ENODATA` if the attribute does not exist.
//! - Attribute namespaces: `user`, `system`, `trusted`, `security`.
//!
//! # POSIX Conformance
//!
//! Extended attributes are a Linux/POSIX extension.  Not in POSIX.1-2024
//! proper but widely standardised.
//!
//! # References
//!
//! - Linux: `fs/xattr.c`, `vfs_getxattr()`
//! - man `getxattr(2)`

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// `AT_FDCWD`.
pub const AT_FDCWD: i32 = -100;
/// Maximum xattr name length (Linux XATTR_NAME_MAX).
pub const XATTR_NAME_MAX: usize = 255;
/// Maximum xattr value size (Linux XATTR_SIZE_MAX = 65536).
pub const XATTR_SIZE_MAX: usize = 65536;
/// Maximum path length.
pub const PATH_MAX: usize = 4096;
/// Maximum xattr entries per file.
pub const MAX_XATTRS_PER_ENTRY: usize = 16;
/// Maximum files tracked.
pub const MAX_XATTR_FILES: usize = 64;

// ---------------------------------------------------------------------------
// XattrNamespace
// ---------------------------------------------------------------------------

/// Extended attribute namespace.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XattrNamespace {
    /// `user.*` — accessible to any process with file permission.
    User,
    /// `system.*` — kernel/system only.
    System,
    /// `trusted.*` — requires `CAP_SYS_ADMIN`.
    Trusted,
    /// `security.*` — LSM (security module) namespace.
    Security,
}

impl XattrNamespace {
    /// Parse the namespace prefix from an xattr name.
    ///
    /// Returns `None` for unknown or malformed names.
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
}

// ---------------------------------------------------------------------------
// XattrEntry — one xattr record
// ---------------------------------------------------------------------------

/// A single extended attribute key-value pair.
pub struct XattrEntry {
    /// Attribute name (namespace.key format).
    pub name: [u8; XATTR_NAME_MAX + 1],
    pub name_len: usize,
    /// Attribute value.
    pub value: [u8; XATTR_SIZE_MAX],
    pub value_len: usize,
    /// Whether this slot is occupied.
    pub in_use: bool,
}

impl XattrEntry {
    const fn empty() -> Self {
        Self {
            name: [0u8; XATTR_NAME_MAX + 1],
            name_len: 0,
            value: [0u8; XATTR_SIZE_MAX],
            value_len: 0,
            in_use: false,
        }
    }

    /// Return the name as a byte slice.
    pub fn name_bytes(&self) -> &[u8] {
        &self.name[..self.name_len]
    }

    /// Return the value as a byte slice.
    pub fn value_bytes(&self) -> &[u8] {
        &self.value[..self.value_len]
    }
}

// ---------------------------------------------------------------------------
// XattrFile — per-inode xattr store
// ---------------------------------------------------------------------------

/// Per-inode extended attribute store.
pub struct XattrFile {
    /// Path hash of the file (dentry stub key).
    pub path_hash: u64,
    /// Xattr entries for this file.
    pub attrs: [XattrEntry; MAX_XATTRS_PER_ENTRY],
    /// Whether this slot is occupied.
    pub in_use: bool,
}

impl XattrFile {
    const fn empty() -> Self {
        Self {
            path_hash: 0,
            attrs: [const { XattrEntry::empty() }; MAX_XATTRS_PER_ENTRY],
            in_use: false,
        }
    }

    /// Find an xattr by name.
    fn find_attr(&self, name: &[u8]) -> Option<&XattrEntry> {
        self.attrs
            .iter()
            .find(|a| a.in_use && a.name_bytes() == name)
    }
}

// ---------------------------------------------------------------------------
// XattrTable — global xattr table
// ---------------------------------------------------------------------------

/// Global extended attribute table.
pub struct XattrTable {
    files: [XattrFile; MAX_XATTR_FILES],
    count: usize,
}

impl XattrTable {
    /// Create an empty table.
    pub const fn new() -> Self {
        Self {
            files: [const { XattrFile::empty() }; MAX_XATTR_FILES],
            count: 0,
        }
    }

    /// Get or create the xattr file record for `path_hash`.
    pub fn file_for_hash_mut(&mut self, hash: u64) -> Option<&mut XattrFile> {
        self.files
            .iter_mut()
            .find(|f| f.in_use && f.path_hash == hash)
    }

    /// Get the xattr file record for `path_hash` (immutable).
    pub fn file_for_hash(&self, hash: u64) -> Option<&XattrFile> {
        self.files.iter().find(|f| f.in_use && f.path_hash == hash)
    }

    /// Ensure a file record exists for `path_hash`, creating one if needed.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the table is full.
    pub fn ensure_file(&mut self, hash: u64) -> Result<&mut XattrFile> {
        // Check if already present.
        let idx = self
            .files
            .iter()
            .position(|f| f.in_use && f.path_hash == hash);
        if let Some(i) = idx {
            return Ok(&mut self.files[i]);
        }
        // Allocate new slot.
        for slot in self.files.iter_mut() {
            if !slot.in_use {
                slot.path_hash = hash;
                slot.in_use = true;
                self.count += 1;
                return Ok(slot);
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Return the number of files with xattrs.
    pub const fn count(&self) -> usize {
        self.count
    }
}

impl Default for XattrTable {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// FNV-1a hash.
fn path_hash(path: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in path {
        h ^= *b as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}

/// Validate an xattr name.
fn validate_xattr_name(name: &[u8]) -> Result<XattrNamespace> {
    if name.is_empty() || name.len() > XATTR_NAME_MAX {
        return Err(Error::InvalidArgument);
    }
    XattrNamespace::from_name(name).ok_or(Error::InvalidArgument)
}

// ---------------------------------------------------------------------------
// do_getxattr — handler
// ---------------------------------------------------------------------------

/// Handler for `getxattr(2)`.
///
/// Retrieves the value of the extended attribute `name` from `path`.
///
/// If `size == 0`, returns the required buffer size (as `Ok(len)`).
/// If `size > 0` but the buffer is too small, returns `InvalidArgument`
/// (ERANGE).
///
/// # Arguments
///
/// * `table`  — global xattr table
/// * `path`   — file path
/// * `name`   — xattr name in `namespace.key` format
/// * `size`   — value buffer size (0 = query size only)
///
/// # Returns
///
/// The value length.  The caller is responsible for providing a
/// buffer of at least that size.
///
/// # Errors
///
/// * [`Error::InvalidArgument`] — empty/overlong path, invalid name, buffer too small
/// * [`Error::NotFound`]        — no xattr record for file (treated as empty)
/// * [`Error::NotImplemented`]  — attribute not found (`ENODATA`)
pub fn do_getxattr(table: &XattrTable, path: &[u8], name: &[u8], size: usize) -> Result<usize> {
    if path.is_empty() || path.len() >= PATH_MAX {
        return Err(Error::InvalidArgument);
    }
    let _ns = validate_xattr_name(name)?;

    let hash = path_hash(path);
    let file = table.file_for_hash(hash).ok_or(Error::NotImplemented)?;
    let attr = file.find_attr(name).ok_or(Error::NotImplemented)?;

    let vlen = attr.value_len;
    if size == 0 {
        return Ok(vlen); // query-size mode
    }
    if size < vlen {
        return Err(Error::InvalidArgument); // ERANGE
    }
    Ok(vlen)
}

/// Handler for `lgetxattr(2)` — does not follow symlinks (stub: same).
pub fn do_lgetxattr(table: &XattrTable, path: &[u8], name: &[u8], size: usize) -> Result<usize> {
    do_getxattr(table, path, name, size)
}

/// Handler for `fgetxattr(2)` — operates on an open fd by inode stub key.
pub fn do_fgetxattr(table: &XattrTable, fd_hash: u64, name: &[u8], size: usize) -> Result<usize> {
    let _ns = validate_xattr_name(name)?;
    let file = table.file_for_hash(fd_hash).ok_or(Error::NotImplemented)?;
    let attr = file.find_attr(name).ok_or(Error::NotImplemented)?;
    let vlen = attr.value_len;
    if size == 0 {
        return Ok(vlen);
    }
    if size < vlen {
        return Err(Error::InvalidArgument);
    }
    Ok(vlen)
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn insert_xattr(t: &mut XattrTable, path: &[u8], name: &[u8], value: &[u8]) {
        let hash = path_hash(path);
        let file = t.ensure_file(hash).unwrap();
        for slot in file.attrs.iter_mut() {
            if !slot.in_use {
                let nlen = name.len();
                let vlen = value.len();
                slot.name[..nlen].copy_from_slice(name);
                slot.name_len = nlen;
                slot.value[..vlen].copy_from_slice(value);
                slot.value_len = vlen;
                slot.in_use = true;
                return;
            }
        }
    }

    #[test]
    fn getxattr_returns_value_len() {
        let mut t = XattrTable::new();
        insert_xattr(&mut t, b"/file", b"user.comment", b"hello");
        let len = do_getxattr(&t, b"/file", b"user.comment", 100).unwrap();
        assert_eq!(len, 5);
    }

    #[test]
    fn getxattr_size_zero_returns_needed() {
        let mut t = XattrTable::new();
        insert_xattr(&mut t, b"/file", b"user.tag", b"value123");
        let len = do_getxattr(&t, b"/file", b"user.tag", 0).unwrap();
        assert_eq!(len, 8);
    }

    #[test]
    fn getxattr_buffer_too_small() {
        let mut t = XattrTable::new();
        insert_xattr(&mut t, b"/file", b"user.k", b"longvalue");
        assert_eq!(
            do_getxattr(&t, b"/file", b"user.k", 3),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn getxattr_no_attr() {
        let mut t = XattrTable::new();
        t.ensure_file(path_hash(b"/file")).unwrap();
        assert_eq!(
            do_getxattr(&t, b"/file", b"user.missing", 0),
            Err(Error::NotImplemented)
        );
    }

    #[test]
    fn getxattr_invalid_namespace() {
        let t = XattrTable::new();
        assert_eq!(
            do_getxattr(&t, b"/file", b"badns.key", 0),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn getxattr_empty_path_rejected() {
        let t = XattrTable::new();
        assert_eq!(
            do_getxattr(&t, b"", b"user.k", 0),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn fgetxattr_by_hash() {
        let mut t = XattrTable::new();
        let hash = path_hash(b"/fd_file");
        let file = t.ensure_file(hash).unwrap();
        let name = b"security.ctx";
        file.attrs[0].name[..name.len()].copy_from_slice(name);
        file.attrs[0].name_len = name.len();
        file.attrs[0].value[0] = 42;
        file.attrs[0].value_len = 1;
        file.attrs[0].in_use = true;
        let len = do_fgetxattr(&t, hash, b"security.ctx", 10).unwrap();
        assert_eq!(len, 1);
    }

    #[test]
    fn namespace_parsing() {
        assert_eq!(
            XattrNamespace::from_name(b"user.foo"),
            Some(XattrNamespace::User)
        );
        assert_eq!(
            XattrNamespace::from_name(b"security.selinux"),
            Some(XattrNamespace::Security)
        );
        assert_eq!(
            XattrNamespace::from_name(b"trusted.overlay"),
            Some(XattrNamespace::Trusted)
        );
        assert_eq!(
            XattrNamespace::from_name(b"system.posix_acl"),
            Some(XattrNamespace::System)
        );
        assert!(XattrNamespace::from_name(b"unknown.key").is_none());
    }
}
