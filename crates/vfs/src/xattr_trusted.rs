// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Trusted namespace extended attributes for the ONCRIX VFS.
//!
//! Implements the `trusted.*` xattr namespace, which is accessible only to
//! processes with `CAP_SYS_ADMIN`. Trusted xattrs are used by filesystem
//! implementations and administrative tools to store privileged metadata
//! that must not be visible or writable by unprivileged users.

use oncrix_lib::{Error, Result};

/// Prefix string for trusted xattr names.
pub const XATTR_TRUSTED_PREFIX: &[u8] = b"trusted.";

/// Maximum length of a single trusted xattr value in bytes.
pub const XATTR_TRUSTED_MAX_VALUE: usize = 65536;

/// Maximum length of a trusted xattr name (including prefix).
pub const XATTR_TRUSTED_MAX_NAME: usize = 256;

/// Maximum number of trusted xattrs stored per inode.
pub const XATTR_TRUSTED_MAX_COUNT: usize = 32;

/// A single trusted namespace extended attribute.
#[derive(Debug, Clone, Copy)]
pub struct TrustedXattr {
    /// Full attribute name (e.g., `trusted.overlay.opaque`).
    name: [u8; XATTR_TRUSTED_MAX_NAME],
    /// Length of the name in bytes.
    name_len: usize,
    /// Attribute value buffer.
    value: [u8; 256],
    /// Length of the value in bytes.
    value_len: usize,
    /// Whether this slot is active.
    active: bool,
}

impl TrustedXattr {
    /// Construct an empty (inactive) xattr slot.
    pub const fn new() -> Self {
        Self {
            name: [0u8; XATTR_TRUSTED_MAX_NAME],
            name_len: 0,
            value: [0u8; 256],
            value_len: 0,
            active: false,
        }
    }

    /// Return the attribute name as a byte slice.
    pub fn name(&self) -> &[u8] {
        &self.name[..self.name_len]
    }

    /// Return the attribute value as a byte slice.
    pub fn value(&self) -> &[u8] {
        &self.value[..self.value_len]
    }
}

impl Default for TrustedXattr {
    fn default() -> Self {
        Self::new()
    }
}

/// Per-inode store for trusted namespace xattrs.
pub struct TrustedXattrStore {
    attrs: [TrustedXattr; XATTR_TRUSTED_MAX_COUNT],
    count: usize,
}

impl TrustedXattrStore {
    /// Create an empty store.
    pub const fn new() -> Self {
        Self {
            attrs: [const { TrustedXattr::new() }; XATTR_TRUSTED_MAX_COUNT],
            count: 0,
        }
    }

    /// Set a trusted xattr. Creates a new entry or updates an existing one.
    ///
    /// Returns `PermissionDenied` if the caller does not hold CAP_SYS_ADMIN.
    /// Returns `InvalidArgument` if the name is not in the `trusted.` namespace.
    pub fn set(&mut self, name: &[u8], value: &[u8], has_cap_admin: bool) -> Result<()> {
        if !has_cap_admin {
            return Err(Error::PermissionDenied);
        }
        validate_trusted_name(name)?;
        if value.len() > 256 {
            return Err(Error::InvalidArgument);
        }

        // Update existing attribute.
        for i in 0..self.count {
            if self.attrs[i].active && self.attrs[i].name() == name {
                let vl = value.len();
                self.attrs[i].value[..vl].copy_from_slice(value);
                self.attrs[i].value_len = vl;
                return Ok(());
            }
        }

        // Insert new attribute.
        if self.count >= XATTR_TRUSTED_MAX_COUNT {
            return Err(Error::OutOfMemory);
        }
        let slot = &mut self.attrs[self.count];
        let nl = name.len().min(XATTR_TRUSTED_MAX_NAME);
        slot.name[..nl].copy_from_slice(&name[..nl]);
        slot.name_len = nl;
        let vl = value.len();
        slot.value[..vl].copy_from_slice(value);
        slot.value_len = vl;
        slot.active = true;
        self.count += 1;
        Ok(())
    }

    /// Get the value of a trusted xattr by name.
    ///
    /// Returns `PermissionDenied` if the caller does not hold CAP_SYS_ADMIN.
    pub fn get<'a>(&'a self, name: &[u8], has_cap_admin: bool) -> Result<&'a [u8]> {
        if !has_cap_admin {
            return Err(Error::PermissionDenied);
        }
        validate_trusted_name(name)?;
        for i in 0..self.count {
            if self.attrs[i].active && self.attrs[i].name() == name {
                return Ok(self.attrs[i].value());
            }
        }
        Err(Error::NotFound)
    }

    /// Remove a trusted xattr by name.
    ///
    /// Returns `PermissionDenied` if the caller does not hold CAP_SYS_ADMIN.
    pub fn remove(&mut self, name: &[u8], has_cap_admin: bool) -> Result<()> {
        if !has_cap_admin {
            return Err(Error::PermissionDenied);
        }
        validate_trusted_name(name)?;
        for i in 0..self.count {
            if self.attrs[i].active && self.attrs[i].name() == name {
                self.attrs[i].active = false;
                return Ok(());
            }
        }
        Err(Error::NotFound)
    }

    /// List all active trusted xattr names into `out`, separated by null bytes.
    ///
    /// Returns `PermissionDenied` if the caller does not hold CAP_SYS_ADMIN.
    /// Returns the total number of bytes written.
    pub fn list(&self, out: &mut [u8], has_cap_admin: bool) -> Result<usize> {
        if !has_cap_admin {
            return Err(Error::PermissionDenied);
        }
        let mut pos = 0usize;
        for i in 0..self.count {
            if !self.attrs[i].active {
                continue;
            }
            let nm = self.attrs[i].name();
            let needed = nm.len() + 1; // name + null terminator
            if pos + needed > out.len() {
                return Err(Error::InvalidArgument);
            }
            out[pos..pos + nm.len()].copy_from_slice(nm);
            out[pos + nm.len()] = 0;
            pos += needed;
        }
        Ok(pos)
    }

    /// Return the number of active trusted xattrs.
    pub fn count(&self) -> usize {
        self.attrs[..self.count].iter().filter(|a| a.active).count()
    }
}

impl Default for TrustedXattrStore {
    fn default() -> Self {
        Self::new()
    }
}

/// Validate that `name` starts with the `trusted.` prefix and is not empty.
pub fn validate_trusted_name(name: &[u8]) -> Result<()> {
    if name.len() <= XATTR_TRUSTED_PREFIX.len() {
        return Err(Error::InvalidArgument);
    }
    if !name.starts_with(XATTR_TRUSTED_PREFIX) {
        return Err(Error::InvalidArgument);
    }
    Ok(())
}

/// Strip the `trusted.` prefix from an attribute name.
pub fn strip_prefix(name: &[u8]) -> Result<&[u8]> {
    if name.starts_with(XATTR_TRUSTED_PREFIX) {
        Ok(&name[XATTR_TRUSTED_PREFIX.len()..])
    } else {
        Err(Error::InvalidArgument)
    }
}
