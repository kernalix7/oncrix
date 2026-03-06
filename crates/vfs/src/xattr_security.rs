// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Security namespace extended attributes for the ONCRIX VFS.
//!
//! Implements the `security.*` xattr namespace used by LSM (Linux Security
//! Module) frameworks such as SELinux, Smack, and AppArmor to store security
//! labels and capabilities on filesystem objects.

use oncrix_lib::{Error, Result};

/// Prefix string for security xattr names.
pub const XATTR_SECURITY_PREFIX: &[u8] = b"security.";

/// Maximum length of a security xattr value.
pub const XATTR_SECURITY_MAX_VALUE: usize = 4096;

/// Maximum length of a security xattr name (including prefix).
pub const XATTR_SECURITY_MAX_NAME: usize = 256;

/// Maximum number of security xattrs stored per inode.
pub const XATTR_SECURITY_MAX_COUNT: usize = 16;

/// Known security xattr suffixes used by common LSMs.
pub const SELINUX_LABEL_XATTR: &[u8] = b"security.selinux";
pub const SMACK_LABEL_XATTR: &[u8] = b"security.SMACK64";
pub const APPARMOR_LABEL_XATTR: &[u8] = b"security.apparmor";
pub const IMA_HASH_XATTR: &[u8] = b"security.ima";
pub const CAPS_XATTR: &[u8] = b"security.capability";

/// The LSM framework that is currently active (determines write policy).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ActiveLsm {
    /// No LSM is loaded; security xattrs are freely writable with CAP_SYS_ADMIN.
    #[default]
    None,
    /// SELinux policy enforcement.
    SeLinux,
    /// Smack label enforcement.
    Smack,
    /// AppArmor profile enforcement.
    AppArmor,
}

/// A single security namespace xattr entry.
#[derive(Debug, Clone, Copy)]
pub struct SecurityXattr {
    /// Full attribute name (e.g., `security.selinux`).
    name: [u8; XATTR_SECURITY_MAX_NAME],
    /// Length of the name.
    name_len: usize,
    /// Attribute value (security label or hash).
    value: [u8; 512],
    /// Length of the value.
    value_len: usize,
    /// Whether this slot is occupied.
    active: bool,
}

impl SecurityXattr {
    /// Construct an empty inactive slot.
    pub const fn new() -> Self {
        Self {
            name: [0u8; XATTR_SECURITY_MAX_NAME],
            name_len: 0,
            value: [0u8; 512],
            value_len: 0,
            active: false,
        }
    }

    /// Return the name as a byte slice.
    pub fn name(&self) -> &[u8] {
        &self.name[..self.name_len]
    }

    /// Return the value as a byte slice.
    pub fn value(&self) -> &[u8] {
        &self.value[..self.value_len]
    }
}

impl Default for SecurityXattr {
    fn default() -> Self {
        Self::new()
    }
}

/// Per-inode store for security namespace xattrs.
pub struct SecurityXattrStore {
    attrs: [SecurityXattr; XATTR_SECURITY_MAX_COUNT],
    count: usize,
    /// Active LSM that governs write policy.
    pub lsm: ActiveLsm,
}

impl SecurityXattrStore {
    /// Create an empty store.
    pub const fn new() -> Self {
        Self {
            attrs: [const { SecurityXattr::new() }; XATTR_SECURITY_MAX_COUNT],
            count: 0,
            lsm: ActiveLsm::None,
        }
    }

    /// Set a security xattr value.
    ///
    /// Requires `CAP_SYS_ADMIN` (or LSM-mediated access). Returns
    /// `PermissionDenied` if the caller lacks privileges.
    pub fn set(&mut self, name: &[u8], value: &[u8], has_cap_admin: bool) -> Result<()> {
        if !has_cap_admin {
            return Err(Error::PermissionDenied);
        }
        validate_security_name(name)?;
        if value.len() > 512 {
            return Err(Error::InvalidArgument);
        }

        // Update existing.
        for i in 0..self.count {
            if self.attrs[i].active && self.attrs[i].name() == name {
                let vl = value.len();
                self.attrs[i].value[..vl].copy_from_slice(value);
                self.attrs[i].value_len = vl;
                return Ok(());
            }
        }

        // Insert new.
        if self.count >= XATTR_SECURITY_MAX_COUNT {
            return Err(Error::OutOfMemory);
        }
        let slot = &mut self.attrs[self.count];
        let nl = name.len().min(XATTR_SECURITY_MAX_NAME);
        slot.name[..nl].copy_from_slice(&name[..nl]);
        slot.name_len = nl;
        let vl = value.len();
        slot.value[..vl].copy_from_slice(value);
        slot.value_len = vl;
        slot.active = true;
        self.count += 1;
        Ok(())
    }

    /// Get the value of a security xattr. Readable by any process (labels are public).
    pub fn get(&self, name: &[u8]) -> Result<&[u8]> {
        validate_security_name(name)?;
        for i in 0..self.count {
            if self.attrs[i].active && self.attrs[i].name() == name {
                return Ok(self.attrs[i].value());
            }
        }
        Err(Error::NotFound)
    }

    /// Remove a security xattr.
    ///
    /// Requires `CAP_SYS_ADMIN`.
    pub fn remove(&mut self, name: &[u8], has_cap_admin: bool) -> Result<()> {
        if !has_cap_admin {
            return Err(Error::PermissionDenied);
        }
        validate_security_name(name)?;
        for i in 0..self.count {
            if self.attrs[i].active && self.attrs[i].name() == name {
                self.attrs[i].active = false;
                return Ok(());
            }
        }
        Err(Error::NotFound)
    }

    /// List all active security xattr names into `out` (null-separated).
    pub fn list(&self, out: &mut [u8]) -> Result<usize> {
        let mut pos = 0usize;
        for i in 0..self.count {
            if !self.attrs[i].active {
                continue;
            }
            let nm = self.attrs[i].name();
            let needed = nm.len() + 1;
            if pos + needed > out.len() {
                return Err(Error::InvalidArgument);
            }
            out[pos..pos + nm.len()].copy_from_slice(nm);
            out[pos + nm.len()] = 0;
            pos += needed;
        }
        Ok(pos)
    }

    /// Return the count of active security xattrs.
    pub fn count(&self) -> usize {
        self.attrs[..self.count].iter().filter(|a| a.active).count()
    }
}

impl Default for SecurityXattrStore {
    fn default() -> Self {
        Self::new()
    }
}

/// Validate that `name` starts with the `security.` prefix.
pub fn validate_security_name(name: &[u8]) -> Result<()> {
    if name.len() <= XATTR_SECURITY_PREFIX.len() {
        return Err(Error::InvalidArgument);
    }
    if !name.starts_with(XATTR_SECURITY_PREFIX) {
        return Err(Error::InvalidArgument);
    }
    Ok(())
}

/// Determine which LSM owns a given security xattr name.
pub fn lsm_owner(name: &[u8]) -> ActiveLsm {
    if name == SELINUX_LABEL_XATTR {
        ActiveLsm::SeLinux
    } else if name == SMACK_LABEL_XATTR {
        ActiveLsm::Smack
    } else if name == APPARMOR_LABEL_XATTR {
        ActiveLsm::AppArmor
    } else {
        ActiveLsm::None
    }
}
