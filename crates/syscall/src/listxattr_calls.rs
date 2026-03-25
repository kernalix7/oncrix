// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Extended attribute (xattr) syscall family.
//!
//! Implements the kernel-side handlers for POSIX.1-2024 and Linux-compatible
//! extended attribute operations.  Extended attributes are (name, value) pairs
//! associated with filesystem objects (files, directories, symlinks).
//!
//! # Supported syscalls
//!
//! | Function          | Description                                  |
//! |-------------------|----------------------------------------------|
//! | `setxattr`        | Set an xattr on a path                       |
//! | `lsetxattr`       | Set an xattr on a path, no symlink follow    |
//! | `fsetxattr`       | Set an xattr by file descriptor              |
//! | `getxattr`        | Get an xattr value from a path               |
//! | `lgetxattr`       | Get an xattr, no symlink follow              |
//! | `fgetxattr`       | Get an xattr by file descriptor              |
//! | `listxattr`       | List xattr names for a path                  |
//! | `llistxattr`      | List xattr names, no symlink follow          |
//! | `flistxattr`      | List xattr names by file descriptor          |
//! | `removexattr`     | Remove an xattr from a path                  |
//! | `lremovexattr`    | Remove an xattr, no symlink follow           |
//! | `fremovexattr`    | Remove an xattr by file descriptor           |
//!
//! # Namespace conventions
//!
//! xattr names follow a `namespace.name` convention:
//! - `user.*`     — user-defined attributes (most common)
//! - `system.*`   — system attributes (ACLs, capabilities, …)
//! - `security.*` — security labels (SELinux, Smack, …)
//! - `trusted.*`  — trusted attributes (root-only)
//!
//! # Reference
//!
//! - POSIX.1-2024 (susv5): `<sys/xattr.h>` (extension)
//! - Linux: `fs/xattr.c`, `include/uapi/linux/xattr.h`
//! - `man 2 setxattr`

extern crate alloc;
use alloc::{collections::BTreeMap, string::String, vec::Vec};

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Limits
// ---------------------------------------------------------------------------

/// Maximum length of an xattr name (including the namespace prefix).
pub const XATTR_NAME_MAX: usize = 255;

/// Maximum size of a single xattr value.
pub const XATTR_SIZE_MAX: usize = 65536;

/// Maximum total size of all xattr data for one inode.
pub const XATTR_LIST_MAX: usize = 65536;

// ---------------------------------------------------------------------------
// XATTR flag constants (mirrors Linux <linux/xattr.h>)
// ---------------------------------------------------------------------------

/// Create the xattr only if it does not already exist.
pub const XATTR_CREATE: i32 = 1;
/// Replace an xattr only if it already exists.
pub const XATTR_REPLACE: i32 = 2;

// ---------------------------------------------------------------------------
// XattrNamespace
// ---------------------------------------------------------------------------

/// Recognised xattr namespace prefixes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum XattrNamespace {
    /// `user.*` — unprivileged user attributes.
    User,
    /// `system.*` — system attributes (ACLs, capabilities).
    System,
    /// `security.*` — security labels.
    Security,
    /// `trusted.*` — privileged trusted attributes.
    Trusted,
}

impl XattrNamespace {
    /// Parse the namespace from an xattr name string.
    ///
    /// Returns the namespace and the suffix after the `.`, or
    /// `Err(InvalidArgument)` if the prefix is unrecognised.
    pub fn parse(name: &str) -> Result<(Self, &str)> {
        if let Some(suffix) = name.strip_prefix("user.") {
            Ok((Self::User, suffix))
        } else if let Some(suffix) = name.strip_prefix("system.") {
            Ok((Self::System, suffix))
        } else if let Some(suffix) = name.strip_prefix("security.") {
            Ok((Self::Security, suffix))
        } else if let Some(suffix) = name.strip_prefix("trusted.") {
            Ok((Self::Trusted, suffix))
        } else {
            Err(Error::InvalidArgument)
        }
    }
}

// ---------------------------------------------------------------------------
// XattrStore — per-inode attribute storage
// ---------------------------------------------------------------------------

/// In-kernel extended attribute store for a single inode.
///
/// Backed by a `BTreeMap` keyed on full xattr name strings.  A real
/// implementation would store attributes in the filesystem's on-disk format
/// (e.g. ext4 block/inline xattrs) instead.
#[derive(Debug, Default)]
pub struct XattrStore {
    attrs: BTreeMap<String, Vec<u8>>,
}

impl XattrStore {
    /// Create an empty attribute store.
    pub fn new() -> Self {
        Self {
            attrs: BTreeMap::new(),
        }
    }

    /// Validate that a name/value pair fits within kernel limits.
    fn validate(name: &str, value: &[u8]) -> Result<()> {
        if name.is_empty() || name.len() > XATTR_NAME_MAX {
            return Err(Error::InvalidArgument);
        }
        if value.len() > XATTR_SIZE_MAX {
            return Err(Error::InvalidArgument);
        }
        // Verify the namespace prefix is recognised.
        XattrNamespace::parse(name)?;
        Ok(())
    }

    /// Set an extended attribute.
    ///
    /// `flags` controls create/replace semantics:
    /// - `0`              — create or replace.
    /// - `XATTR_CREATE`   — fail if the attribute already exists.
    /// - `XATTR_REPLACE`  — fail if the attribute does not exist.
    pub fn set(&mut self, name: &str, value: &[u8], flags: i32) -> Result<()> {
        Self::validate(name, value)?;

        let exists = self.attrs.contains_key(name);

        if flags & XATTR_CREATE != 0 && exists {
            return Err(Error::AlreadyExists);
        }
        if flags & XATTR_REPLACE != 0 && !exists {
            return Err(Error::NotFound);
        }

        // Check total xattr data budget before inserting.
        let new_value_len = value.len();
        let existing_len = self.attrs.get(name).map_or(0, |v| v.len());
        let total: usize =
            self.attrs.values().map(|v| v.len()).sum::<usize>() - existing_len + new_value_len;
        if total > XATTR_LIST_MAX {
            return Err(Error::OutOfMemory);
        }

        self.attrs.insert(String::from(name), value.to_vec());
        Ok(())
    }

    /// Get the value of an extended attribute.
    ///
    /// If `buf` is empty, returns the size that would be needed.
    /// Otherwise fills `buf` and returns the number of bytes written.
    pub fn get(&self, name: &str, buf: &mut [u8]) -> Result<usize> {
        if name.is_empty() || name.len() > XATTR_NAME_MAX {
            return Err(Error::InvalidArgument);
        }
        let value = self.attrs.get(name).ok_or(Error::NotFound)?;
        if buf.is_empty() {
            // Caller passes size 0 to query the required buffer size.
            return Ok(value.len());
        }
        if buf.len() < value.len() {
            return Err(Error::InvalidArgument);
        }
        buf[..value.len()].copy_from_slice(value);
        Ok(value.len())
    }

    /// List all extended attribute names.
    ///
    /// Writes a NUL-terminated sequence of name strings into `buf`.
    /// If `buf` is empty, returns the total byte count needed.
    pub fn list(&self, buf: &mut [u8]) -> Result<usize> {
        // Calculate required size: sum of (name.len() + 1) for each entry.
        let needed: usize = self.attrs.keys().map(|k| k.len() + 1).sum();
        if buf.is_empty() {
            return Ok(needed);
        }
        if buf.len() < needed {
            return Err(Error::InvalidArgument);
        }
        let mut offset = 0;
        for name in self.attrs.keys() {
            let bytes = name.as_bytes();
            buf[offset..offset + bytes.len()].copy_from_slice(bytes);
            offset += bytes.len();
            buf[offset] = 0; // NUL terminator
            offset += 1;
        }
        Ok(needed)
    }

    /// Remove an extended attribute.
    pub fn remove(&mut self, name: &str) -> Result<()> {
        if name.is_empty() || name.len() > XATTR_NAME_MAX {
            return Err(Error::InvalidArgument);
        }
        // Validate namespace even for removal.
        XattrNamespace::parse(name)?;
        self.attrs.remove(name).map(|_| ()).ok_or(Error::NotFound)
    }

    /// Returns the number of attributes stored.
    pub fn count(&self) -> usize {
        self.attrs.len()
    }
}

// ---------------------------------------------------------------------------
// Path-based xattr handlers
// ---------------------------------------------------------------------------

/// `setxattr` — set an extended attribute on a path.
///
/// `follow_symlinks` controls whether symlinks in `path` are followed
/// (`true` for `setxattr`, `false` for `lsetxattr`).
///
/// In a full implementation, `path` is resolved to an inode whose
/// [`XattrStore`] is updated.  Here the inode store is passed directly
/// as a stub.
pub fn do_setxattr(
    store: &mut XattrStore,
    name: &str,
    value: &[u8],
    flags: i32,
    _follow_symlinks: bool,
) -> Result<()> {
    store.set(name, value, flags)
}

/// `getxattr` — get an extended attribute value from a path.
///
/// Returns the number of bytes written into `buf`, or the required
/// buffer size if `buf` is empty.
pub fn do_getxattr(
    store: &XattrStore,
    name: &str,
    buf: &mut [u8],
    _follow_symlinks: bool,
) -> Result<usize> {
    store.get(name, buf)
}

/// `listxattr` — list all extended attribute names for a path.
///
/// The list is written as consecutive NUL-terminated strings into `buf`.
/// Returns the total number of bytes written (or needed if `buf` is empty).
pub fn do_listxattr(store: &XattrStore, buf: &mut [u8], _follow_symlinks: bool) -> Result<usize> {
    store.list(buf)
}

/// `removexattr` — remove an extended attribute from a path.
pub fn do_removexattr(store: &mut XattrStore, name: &str, _follow_symlinks: bool) -> Result<()> {
    store.remove(name)
}

// ---------------------------------------------------------------------------
// File-descriptor-based xattr handlers
// ---------------------------------------------------------------------------

/// `fsetxattr` — set an extended attribute by file descriptor.
///
/// `fd` must refer to an open file; the resolved inode's [`XattrStore`]
/// is updated.  The store is passed directly in this stub.
pub fn do_fsetxattr(
    fd: i32,
    store: &mut XattrStore,
    name: &str,
    value: &[u8],
    flags: i32,
) -> Result<()> {
    if fd < 0 {
        return Err(Error::InvalidArgument);
    }
    store.set(name, value, flags)
}

/// `fgetxattr` — get an extended attribute value by file descriptor.
pub fn do_fgetxattr(fd: i32, store: &XattrStore, name: &str, buf: &mut [u8]) -> Result<usize> {
    if fd < 0 {
        return Err(Error::InvalidArgument);
    }
    store.get(name, buf)
}

/// `flistxattr` — list all extended attribute names by file descriptor.
pub fn do_flistxattr(fd: i32, store: &XattrStore, buf: &mut [u8]) -> Result<usize> {
    if fd < 0 {
        return Err(Error::InvalidArgument);
    }
    store.list(buf)
}

/// `fremovexattr` — remove an extended attribute by file descriptor.
pub fn do_fremovexattr(fd: i32, store: &mut XattrStore, name: &str) -> Result<()> {
    if fd < 0 {
        return Err(Error::InvalidArgument);
    }
    store.remove(name)
}
