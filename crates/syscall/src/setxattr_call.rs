// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `setxattr(2)` / `lsetxattr(2)` / `fsetxattr(2)` syscall handlers.
//!
//! Sets the value of an extended attribute associated with a file.
//!
//! # Key behaviours
//!
//! - `XATTR_CREATE`: fail if attribute already exists.
//! - `XATTR_REPLACE`: fail if attribute does not exist.
//! - Setting neither `XATTR_CREATE` nor `XATTR_REPLACE` creates or
//!   replaces regardless.
//! - Value size must not exceed `XATTR_SIZE_MAX` (65536 bytes).
//! - Name must be in `namespace.key` format.
//! - `user.*` namespace requires file write permission.
//! - `trusted.*` and `security.*` require `CAP_SYS_ADMIN`.
//!
//! # References
//!
//! - Linux: `fs/xattr.c`, `vfs_setxattr()`
//! - man `setxattr(2)`

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// `XATTR_CREATE` flag: create only (fail if already exists).
pub const XATTR_CREATE: u32 = 1;
/// `XATTR_REPLACE` flag: replace only (fail if does not exist).
pub const XATTR_REPLACE: u32 = 2;
/// Maximum xattr name length.
pub const XATTR_NAME_MAX: usize = 255;
/// Maximum xattr value size.
pub const XATTR_SIZE_MAX: usize = 65536;
/// Maximum path length.
pub const PATH_MAX: usize = 4096;
/// Maximum xattr entries per file.
pub const MAX_XATTRS_PER_FILE: usize = 16;
/// Maximum files in the table.
pub const MAX_SETXATTR_FILES: usize = 64;

// ---------------------------------------------------------------------------
// XattrNamespace (subset, same as getxattr)
// ---------------------------------------------------------------------------

/// Extended attribute namespace.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XattrNamespace {
    /// `user.*` namespace.
    User,
    /// `system.*` namespace.
    System,
    /// `trusted.*` namespace — requires `CAP_SYS_ADMIN`.
    Trusted,
    /// `security.*` namespace — requires `CAP_SYS_ADMIN`.
    Security,
}

impl XattrNamespace {
    /// Parse the namespace prefix from an xattr name.
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
// SetxattrFlags — validated flags
// ---------------------------------------------------------------------------

/// Validated flags for `setxattr`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SetxattrFlags(u32);

impl SetxattrFlags {
    /// Construct from raw flags.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] for unknown flags or for
    /// `XATTR_CREATE | XATTR_REPLACE` used together.
    pub fn from_raw(raw: u32) -> Result<Self> {
        if raw & !(XATTR_CREATE | XATTR_REPLACE) != 0 {
            return Err(Error::InvalidArgument);
        }
        if raw & XATTR_CREATE != 0 && raw & XATTR_REPLACE != 0 {
            return Err(Error::InvalidArgument);
        }
        Ok(Self(raw))
    }

    /// Return `true` if `XATTR_CREATE` is set.
    pub const fn is_create(self) -> bool {
        self.0 & XATTR_CREATE != 0
    }

    /// Return `true` if `XATTR_REPLACE` is set.
    pub const fn is_replace(self) -> bool {
        self.0 & XATTR_REPLACE != 0
    }
}

// ---------------------------------------------------------------------------
// SetXattrEntry / SetXattrFile / SetXattrTable
// ---------------------------------------------------------------------------

/// One extended attribute key-value pair.
pub struct SetXattrEntry {
    pub name: [u8; XATTR_NAME_MAX + 1],
    pub name_len: usize,
    pub value: [u8; XATTR_SIZE_MAX],
    pub value_len: usize,
    pub in_use: bool,
}

impl SetXattrEntry {
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
}

/// Per-inode xattr store.
pub struct SetXattrFile {
    pub path_hash: u64,
    pub attrs: [SetXattrEntry; MAX_XATTRS_PER_FILE],
    pub in_use: bool,
}

impl SetXattrFile {
    const fn empty() -> Self {
        Self {
            path_hash: 0,
            attrs: [const { SetXattrEntry::empty() }; MAX_XATTRS_PER_FILE],
            in_use: false,
        }
    }

    fn find_attr_mut(&mut self, name: &[u8]) -> Option<&mut SetXattrEntry> {
        self.attrs
            .iter_mut()
            .find(|a| a.in_use && a.name_bytes() == name)
    }

    fn find_attr(&self, name: &[u8]) -> Option<&SetXattrEntry> {
        self.attrs
            .iter()
            .find(|a| a.in_use && a.name_bytes() == name)
    }

    fn insert_attr(&mut self, name: &[u8], value: &[u8]) -> Result<()> {
        let nlen = name.len();
        let vlen = value.len();
        for slot in self.attrs.iter_mut() {
            if !slot.in_use {
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
pub struct SetXattrTable {
    files: [SetXattrFile; MAX_SETXATTR_FILES],
    count: usize,
}

impl SetXattrTable {
    /// Create an empty table.
    pub const fn new() -> Self {
        Self {
            files: [const { SetXattrFile::empty() }; MAX_SETXATTR_FILES],
            count: 0,
        }
    }

    /// Ensure a file record exists for `path_hash`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the table is full.
    pub fn ensure_file_mut(&mut self, hash: u64) -> Result<&mut SetXattrFile> {
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

    /// Find a file record by path hash (immutable).
    pub fn file_for_hash(&self, hash: u64) -> Option<&SetXattrFile> {
        self.files.iter().find(|f| f.in_use && f.path_hash == hash)
    }

    /// Return the number of files with xattrs.
    pub const fn count(&self) -> usize {
        self.count
    }
}

impl Default for SetXattrTable {
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
// do_setxattr — handler
// ---------------------------------------------------------------------------

/// Handler for `setxattr(2)`.
///
/// Sets extended attribute `name` to `value` on file at `path`.
///
/// # Arguments
///
/// * `table`       — global xattr table
/// * `path`        — file path
/// * `name`        — attribute name (`namespace.key`)
/// * `value`       — attribute value bytes
/// * `raw_flags`   — `XATTR_CREATE`, `XATTR_REPLACE`, or 0
/// * `caller_uid`  — caller UID (for namespace permission check)
///
/// # Errors
///
/// * [`Error::InvalidArgument`]  — invalid name/flags, value too large
/// * [`Error::AlreadyExists`]    — `XATTR_CREATE` and attribute exists
/// * [`Error::NotImplemented`]   — `XATTR_REPLACE` and attribute missing
/// * [`Error::PermissionDenied`] — namespace requires admin
/// * [`Error::OutOfMemory`]      — table full
pub fn do_setxattr(
    table: &mut SetXattrTable,
    path: &[u8],
    name: &[u8],
    value: &[u8],
    raw_flags: u32,
    caller_uid: u32,
) -> Result<()> {
    if path.is_empty() || path.len() >= PATH_MAX {
        return Err(Error::InvalidArgument);
    }
    if value.len() > XATTR_SIZE_MAX {
        return Err(Error::InvalidArgument);
    }
    let ns = validate_name(name)?;
    let flags = SetxattrFlags::from_raw(raw_flags)?;

    // Namespace permission check.
    if ns.requires_admin() && caller_uid != 0 {
        return Err(Error::PermissionDenied);
    }

    let hash = path_hash(path);
    let file = table.ensure_file_mut(hash)?;

    let exists = file.find_attr(name).is_some();

    if flags.is_create() && exists {
        return Err(Error::AlreadyExists);
    }
    if flags.is_replace() && !exists {
        return Err(Error::NotImplemented); // ENODATA
    }

    if exists {
        // Replace in place.
        let slot = file.find_attr_mut(name).ok_or(Error::NotImplemented)?;
        let vlen = value.len();
        slot.value[..vlen].copy_from_slice(value);
        slot.value_len = vlen;
    } else {
        file.insert_attr(name, value)?;
    }

    Ok(())
}

/// Handler for `lsetxattr(2)` — does not follow symlinks (stub: same).
pub fn do_lsetxattr(
    table: &mut SetXattrTable,
    path: &[u8],
    name: &[u8],
    value: &[u8],
    flags: u32,
    caller_uid: u32,
) -> Result<()> {
    do_setxattr(table, path, name, value, flags, caller_uid)
}

/// Handler for `fsetxattr(2)` — operates on open fd by inode stub key.
pub fn do_fsetxattr(
    table: &mut SetXattrTable,
    fd_hash: u64,
    name: &[u8],
    value: &[u8],
    raw_flags: u32,
    caller_uid: u32,
) -> Result<()> {
    if value.len() > XATTR_SIZE_MAX {
        return Err(Error::InvalidArgument);
    }
    let ns = validate_name(name)?;
    let flags = SetxattrFlags::from_raw(raw_flags)?;
    if ns.requires_admin() && caller_uid != 0 {
        return Err(Error::PermissionDenied);
    }
    let file = table.ensure_file_mut(fd_hash)?;
    let exists = file.find_attr(name).is_some();
    if flags.is_create() && exists {
        return Err(Error::AlreadyExists);
    }
    if flags.is_replace() && !exists {
        return Err(Error::NotImplemented);
    }
    if exists {
        let slot = file.find_attr_mut(name).ok_or(Error::NotImplemented)?;
        let vlen = value.len();
        slot.value[..vlen].copy_from_slice(value);
        slot.value_len = vlen;
    } else {
        file.insert_attr(name, value)?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn setxattr_create() {
        let mut t = SetXattrTable::new();
        do_setxattr(&mut t, b"/file", b"user.tag", b"v1", 0, 1000).unwrap();
        let file = t.file_for_hash(path_hash(b"/file")).unwrap();
        assert_eq!(file.attr_count(), 1);
    }

    #[test]
    fn setxattr_replace_existing() {
        let mut t = SetXattrTable::new();
        do_setxattr(&mut t, b"/file", b"user.tag", b"v1", 0, 1000).unwrap();
        do_setxattr(&mut t, b"/file", b"user.tag", b"v2", 0, 1000).unwrap();
        let file = t.file_for_hash(path_hash(b"/file")).unwrap();
        assert_eq!(file.attr_count(), 1);
    }

    #[test]
    fn setxattr_create_flag_existing_fails() {
        let mut t = SetXattrTable::new();
        do_setxattr(&mut t, b"/file", b"user.tag", b"v1", 0, 1000).unwrap();
        assert_eq!(
            do_setxattr(&mut t, b"/file", b"user.tag", b"v2", XATTR_CREATE, 1000),
            Err(Error::AlreadyExists)
        );
    }

    #[test]
    fn setxattr_replace_flag_missing_fails() {
        let mut t = SetXattrTable::new();
        assert_eq!(
            do_setxattr(&mut t, b"/file", b"user.tag", b"v", XATTR_REPLACE, 1000),
            Err(Error::NotImplemented)
        );
    }

    #[test]
    fn setxattr_trusted_requires_admin() {
        let mut t = SetXattrTable::new();
        assert_eq!(
            do_setxattr(&mut t, b"/file", b"trusted.key", b"v", 0, 1000),
            Err(Error::PermissionDenied)
        );
        do_setxattr(&mut t, b"/file", b"trusted.key", b"v", 0, 0).unwrap();
    }

    #[test]
    fn setxattr_value_too_large() {
        let mut t = SetXattrTable::new();
        let big = [0u8; XATTR_SIZE_MAX + 1];
        assert_eq!(
            do_setxattr(&mut t, b"/file", b"user.k", &big, 0, 1000),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn setxattr_invalid_namespace() {
        let mut t = SetXattrTable::new();
        assert_eq!(
            do_setxattr(&mut t, b"/f", b"badns.k", b"v", 0, 0),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn setxattr_create_replace_exclusive() {
        let mut t = SetXattrTable::new();
        assert_eq!(
            do_setxattr(
                &mut t,
                b"/f",
                b"user.k",
                b"v",
                XATTR_CREATE | XATTR_REPLACE,
                0
            ),
            Err(Error::InvalidArgument)
        );
    }
}
