// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! User-namespace extended attribute support (`user.` namespace).
//!
//! Implements the `user.*` xattr namespace which allows arbitrary
//! user-controlled metadata on regular files and directories.
//! The `user.*` namespace is the only xattr namespace accessible
//! without elevated privileges.

use oncrix_lib::{Error, Result};

/// Prefix for the user xattr namespace.
pub const USER_PREFIX: &[u8] = b"user.";

/// Maximum length of a user xattr name (including prefix).
pub const USER_XATTR_NAME_MAX: usize = 255;

/// Maximum size of a user xattr value.
pub const USER_XATTR_VALUE_MAX: usize = 65536;

/// Maximum number of user xattrs per inode.
pub const USER_XATTR_MAX: usize = 32;

/// A single user xattr entry.
#[derive(Clone, Copy)]
pub struct UserXattr {
    /// Full name including `user.` prefix.
    name: [u8; USER_XATTR_NAME_MAX],
    name_len: usize,
    /// Value bytes.
    value: [u8; 256],
    value_len: usize,
}

impl UserXattr {
    /// Create a new empty xattr entry.
    const fn empty() -> Self {
        UserXattr {
            name: [0u8; USER_XATTR_NAME_MAX],
            name_len: 0,
            value: [0u8; 256],
            value_len: 0,
        }
    }

    /// Return the xattr name as a byte slice.
    pub fn name(&self) -> &[u8] {
        &self.name[..self.name_len]
    }

    /// Return the xattr value as a byte slice.
    pub fn value(&self) -> &[u8] {
        &self.value[..self.value_len]
    }
}

/// Per-inode user xattr store.
pub struct UserXattrStore {
    entries: [Option<UserXattr>; USER_XATTR_MAX],
    count: usize,
}

impl UserXattrStore {
    /// Create an empty store.
    pub const fn new() -> Self {
        UserXattrStore {
            entries: [const { None }; USER_XATTR_MAX],
            count: 0,
        }
    }

    /// Set a user xattr.
    ///
    /// `name` must start with `user.` prefix.
    /// `value` must be at most 256 bytes (hardware limit; real FS may vary).
    pub fn set(&mut self, name: &[u8], value: &[u8]) -> Result<()> {
        validate_user_name(name)?;
        if value.len() > 256 {
            return Err(Error::InvalidArgument);
        }
        // Overwrite existing.
        for slot in self.entries.iter_mut().flatten() {
            if slot.name() == name {
                slot.value[..value.len()].copy_from_slice(value);
                slot.value_len = value.len();
                return Ok(());
            }
        }
        // Insert new.
        for slot in &mut self.entries {
            if slot.is_none() {
                let mut entry = UserXattr::empty();
                entry.name[..name.len()].copy_from_slice(name);
                entry.name_len = name.len();
                entry.value[..value.len()].copy_from_slice(value);
                entry.value_len = value.len();
                *slot = Some(entry);
                self.count += 1;
                return Ok(());
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Get a user xattr value.
    pub fn get<'a>(&'a self, name: &[u8], buf: &'a mut [u8]) -> Result<usize> {
        validate_user_name(name)?;
        for entry in self.entries.iter().flatten() {
            if entry.name() == name {
                let val = entry.value();
                if buf.len() < val.len() {
                    return Err(Error::InvalidArgument);
                }
                buf[..val.len()].copy_from_slice(val);
                return Ok(val.len());
            }
        }
        Err(Error::NotFound)
    }

    /// Remove a user xattr.
    pub fn remove(&mut self, name: &[u8]) -> Result<()> {
        validate_user_name(name)?;
        for slot in &mut self.entries {
            if let Some(e) = slot {
                if e.name() == name {
                    *slot = None;
                    self.count = self.count.saturating_sub(1);
                    return Ok(());
                }
            }
        }
        Err(Error::NotFound)
    }

    /// List all xattr names into `buf` as null-terminated strings.
    ///
    /// Returns the total length used.
    pub fn list(&self, buf: &mut [u8]) -> Result<usize> {
        let mut pos = 0;
        for entry in self.entries.iter().flatten() {
            let name = entry.name();
            if pos + name.len() + 1 > buf.len() {
                return Err(Error::InvalidArgument);
            }
            buf[pos..pos + name.len()].copy_from_slice(name);
            pos += name.len();
            buf[pos] = 0;
            pos += 1;
        }
        Ok(pos)
    }

    /// Return count of stored xattrs.
    pub fn count(&self) -> usize {
        self.count
    }
}

impl Default for UserXattrStore {
    fn default() -> Self {
        Self::new()
    }
}

/// Validate that a name starts with the `user.` prefix.
pub fn validate_user_name(name: &[u8]) -> Result<()> {
    if name.len() < USER_PREFIX.len() {
        return Err(Error::InvalidArgument);
    }
    if &name[..USER_PREFIX.len()] != USER_PREFIX {
        return Err(Error::InvalidArgument);
    }
    if name.len() > USER_XATTR_NAME_MAX {
        return Err(Error::InvalidArgument);
    }
    // The suffix after "user." must not be empty.
    if name.len() == USER_PREFIX.len() {
        return Err(Error::InvalidArgument);
    }
    Ok(())
}

/// Strip the `user.` prefix from a name.
///
/// Returns the suffix (e.g., `"comment"` from `"user.comment"`).
pub fn strip_user_prefix(name: &[u8]) -> Result<&[u8]> {
    validate_user_name(name)?;
    Ok(&name[USER_PREFIX.len()..])
}

/// File type restriction for user xattrs.
///
/// Per POSIX, user xattrs are only allowed on regular files and directories.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileType {
    Regular,
    Directory,
    Other,
}

/// Check if user xattrs are permitted on a given file type.
pub fn user_xattr_allowed(ft: FileType) -> Result<()> {
    match ft {
        FileType::Regular | FileType::Directory => Ok(()),
        FileType::Other => Err(Error::PermissionDenied),
    }
}
