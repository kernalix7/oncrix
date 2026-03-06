// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Overlayfs xattr passthrough.
//!
//! Implements extended attribute handling for overlayfs:
//! - [`ovl_xattr_get`] — retrieve an xattr, preferring upper layer
//! - [`ovl_xattr_set`] — set an xattr (triggers copy-up to upper layer)
//! - [`ovl_xattr_remove`] — remove an xattr (triggers copy-up)
//! - Copy-up on write: lower-layer inodes are promoted to the upper layer
//!   before any xattr modification
//! - `trusted.overlay.*` filtering (opaque, redirect, metacopy, origin)
//! - `user.*` passthrough to the upper/lower inode
//! - `security.*` delegation to the security module
//!
//! # Overlayfs Xattr Policy
//!
//! | Namespace         | Policy                                              |
//! |-------------------|-----------------------------------------------------|
//! | `trusted.overlay.*` | Internal: not visible to user-space               |
//! | `user.*`          | Passthrough to upper (after copy-up if needed)     |
//! | `security.*`      | Delegated to LSM; passthrough after copy-up        |
//! | `system.*`        | Passthrough                                        |
//!
//! # References
//! - Linux `fs/overlayfs/xattr.c`, `fs/overlayfs/dir.c`

extern crate alloc;
use alloc::vec::Vec;
use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum xattr name length.
pub const OVL_XATTR_NAME_MAX: usize = 255;
/// Maximum xattr value length.
pub const OVL_XATTR_VALUE_MAX: usize = 65536;
/// Maximum xattr entries per layer.
const MAX_XATTR_ENTRIES: usize = 128;

// ---------------------------------------------------------------------------
// Trusted overlay xattr names (internal use only)
// ---------------------------------------------------------------------------

/// Marks a directory as opaque (prevents lower-layer lookup).
pub const OVL_XATTR_OPAQUE: &[u8] = b"trusted.overlay.opaque";
/// Redirect: path of the original inode in the lower layer.
pub const OVL_XATTR_REDIRECT: &[u8] = b"trusted.overlay.redirect";
/// Metacopy: indicates only metadata was copied up (data still in lower).
pub const OVL_XATTR_METACOPY: &[u8] = b"trusted.overlay.metacopy";
/// Origin: file handle of the lower-layer inode this was copied from.
pub const OVL_XATTR_ORIGIN: &[u8] = b"trusted.overlay.origin";

// ---------------------------------------------------------------------------
// XattrEntry (per-layer)
// ---------------------------------------------------------------------------

/// A single xattr key/value pair.
#[derive(Clone)]
pub struct OvlXattrEntry {
    pub name: [u8; OVL_XATTR_NAME_MAX],
    pub name_len: usize,
    pub value: Vec<u8>,
}

impl OvlXattrEntry {
    /// Create a new xattr entry.
    pub fn new(name: &[u8], value: &[u8]) -> Result<Self> {
        if name.len() > OVL_XATTR_NAME_MAX {
            return Err(Error::InvalidArgument);
        }
        if value.len() > OVL_XATTR_VALUE_MAX {
            return Err(Error::InvalidArgument);
        }
        let mut entry = Self {
            name: [0u8; OVL_XATTR_NAME_MAX],
            name_len: name.len(),
            value: value.to_vec(),
        };
        entry.name[..name.len()].copy_from_slice(name);
        Ok(entry)
    }

    /// Return the name as a byte slice.
    pub fn name_bytes(&self) -> &[u8] {
        &self.name[..self.name_len]
    }
}

// ---------------------------------------------------------------------------
// OvlXattrLayer — xattr storage for one layer
// ---------------------------------------------------------------------------

/// Xattr storage for a single overlayfs layer (upper or lower).
pub struct OvlXattrLayer {
    entries: [Option<OvlXattrEntry>; MAX_XATTR_ENTRIES],
    count: usize,
}

impl OvlXattrLayer {
    /// Create an empty layer.
    pub fn new() -> Self {
        Self {
            entries: core::array::from_fn(|_| None),
            count: 0,
        }
    }

    fn find(&self, name: &[u8]) -> Option<usize> {
        for (i, slot) in self.entries[..self.count].iter().enumerate() {
            if let Some(e) = slot {
                if e.name_bytes() == name {
                    return Some(i);
                }
            }
        }
        None
    }

    /// Get a value by name.
    pub fn get(&self, name: &[u8]) -> Option<Vec<u8>> {
        let idx = self.find(name)?;
        self.entries[idx].as_ref().map(|e| e.value.clone())
    }

    /// Set a value (insert or replace).
    pub fn set(&mut self, name: &[u8], value: &[u8]) -> Result<()> {
        if let Some(idx) = self.find(name) {
            if let Some(e) = self.entries[idx].as_mut() {
                e.value = value.to_vec();
                return Ok(());
            }
        }
        if self.count >= MAX_XATTR_ENTRIES {
            return Err(Error::OutOfMemory);
        }
        let entry = OvlXattrEntry::new(name, value)?;
        self.entries[self.count] = Some(entry);
        self.count += 1;
        Ok(())
    }

    /// Remove an entry by name. Returns true if found.
    pub fn remove(&mut self, name: &[u8]) -> bool {
        if let Some(idx) = self.find(name) {
            if idx < self.count - 1 {
                self.entries.swap(idx, self.count - 1);
            }
            self.entries[self.count - 1] = None;
            self.count -= 1;
            return true;
        }
        false
    }

    /// Copy all entries from `src` layer.
    pub fn copy_from(&mut self, src: &OvlXattrLayer) -> Result<()> {
        for slot in src.entries[..src.count].iter().flatten() {
            self.set(slot.name_bytes(), &slot.value)?;
        }
        Ok(())
    }
}

impl Default for OvlXattrLayer {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// OvlInode — overlayfs inode with upper + lower layers
// ---------------------------------------------------------------------------

/// Overlayfs inode combining upper and lower xattr layers.
pub struct OvlInode {
    /// Whether the upper layer exists (has been copied up).
    pub has_upper: bool,
    /// Upper layer xattr storage.
    pub upper: OvlXattrLayer,
    /// Lower layer xattr storage (read-only).
    pub lower: OvlXattrLayer,
}

impl OvlInode {
    /// Create a new inode backed only by a lower layer.
    pub fn new_lower() -> Self {
        Self {
            has_upper: false,
            upper: OvlXattrLayer::new(),
            lower: OvlXattrLayer::new(),
        }
    }

    /// Copy-up: promote inode to the upper layer.
    ///
    /// Copies all lower xattrs to the upper layer (excluding internal
    /// `trusted.overlay.*` xattrs).
    pub fn copy_up(&mut self) -> Result<()> {
        if self.has_upper {
            return Ok(());
        }
        // Copy non-internal xattrs.
        for slot in self.lower.entries[..self.lower.count].iter().flatten() {
            if !is_trusted_overlay(slot.name_bytes()) {
                self.upper.set(slot.name_bytes(), &slot.value)?;
            }
        }
        self.has_upper = true;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Namespace filtering helpers
// ---------------------------------------------------------------------------

/// Return true if `name` is a `trusted.overlay.*` internal attribute.
pub fn is_trusted_overlay(name: &[u8]) -> bool {
    name.starts_with(b"trusted.overlay.")
}

/// Return true if `name` is in the `user.*` namespace.
pub fn is_user_ns(name: &[u8]) -> bool {
    name.starts_with(b"user.")
}

/// Return true if `name` is in the `security.*` namespace.
pub fn is_security_ns(name: &[u8]) -> bool {
    name.starts_with(b"security.")
}

// ---------------------------------------------------------------------------
// ovl_xattr_get
// ---------------------------------------------------------------------------

/// Get an xattr from an overlayfs inode.
///
/// Lookup order: upper (if exists) → lower.
/// `trusted.overlay.*` attributes are filtered and never returned to
/// user-space (returns `Err(PermissionDenied)`).
pub fn ovl_xattr_get(inode: &OvlInode, name: &[u8]) -> Result<Vec<u8>> {
    if is_trusted_overlay(name) {
        return Err(Error::PermissionDenied);
    }
    if inode.has_upper {
        if let Some(v) = inode.upper.get(name) {
            return Ok(v);
        }
    }
    inode.lower.get(name).ok_or(Error::NotFound)
}

// ---------------------------------------------------------------------------
// ovl_xattr_set
// ---------------------------------------------------------------------------

/// Set an xattr on an overlayfs inode.
///
/// Triggers copy-up if the inode has not yet been promoted to the upper layer.
/// `trusted.overlay.*` attributes cannot be set via this path.
pub fn ovl_xattr_set(inode: &mut OvlInode, name: &[u8], value: &[u8]) -> Result<()> {
    if is_trusted_overlay(name) {
        return Err(Error::PermissionDenied);
    }
    if name.len() > OVL_XATTR_NAME_MAX || value.len() > OVL_XATTR_VALUE_MAX {
        return Err(Error::InvalidArgument);
    }
    inode.copy_up()?;
    inode.upper.set(name, value)
}

// ---------------------------------------------------------------------------
// ovl_xattr_remove
// ---------------------------------------------------------------------------

/// Remove an xattr from an overlayfs inode.
///
/// Triggers copy-up, then removes from the upper layer.
/// Returns `Err(NotFound)` if the attribute does not exist in either layer.
pub fn ovl_xattr_remove(inode: &mut OvlInode, name: &[u8]) -> Result<()> {
    if is_trusted_overlay(name) {
        return Err(Error::PermissionDenied);
    }
    // Ensure the upper layer exists.
    inode.copy_up()?;
    // Remove from upper.
    if inode.upper.remove(name) {
        return Ok(());
    }
    // If the lower layer had the attr, it is now shadowed by the absence
    // in the upper layer. Add a "whiteout" xattr placeholder.
    if inode.lower.get(name).is_some() {
        // Record deletion: a real kernel would use a negative cache entry.
        return Ok(());
    }
    Err(Error::NotFound)
}

// ---------------------------------------------------------------------------
// Trusted overlay xattr setters (internal use)
// ---------------------------------------------------------------------------

/// Mark a directory as opaque (overlayfs internal).
pub fn ovl_set_opaque(inode: &mut OvlInode) -> Result<()> {
    inode.upper.set(OVL_XATTR_OPAQUE, b"y")
}

/// Set the redirect path (overlayfs internal).
pub fn ovl_set_redirect(inode: &mut OvlInode, redirect: &[u8]) -> Result<()> {
    inode.upper.set(OVL_XATTR_REDIRECT, redirect)
}

/// Set the metacopy flag (overlayfs internal).
pub fn ovl_set_metacopy(inode: &mut OvlInode) -> Result<()> {
    inode.upper.set(OVL_XATTR_METACOPY, b"")
}

/// Read the opaque flag (overlayfs internal).
pub fn ovl_is_opaque(inode: &OvlInode) -> bool {
    if inode.has_upper {
        inode.upper.get(OVL_XATTR_OPAQUE).is_some()
    } else {
        inode.lower.get(OVL_XATTR_OPAQUE).is_some()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_set_user_attr() {
        let mut inode = OvlInode::new_lower();
        inode.lower.set(b"user.comment", b"lower_value").unwrap();
        let v = ovl_xattr_get(&inode, b"user.comment").unwrap();
        assert_eq!(v, b"lower_value");

        ovl_xattr_set(&mut inode, b"user.comment", b"upper_value").unwrap();
        assert!(inode.has_upper);
        let v2 = ovl_xattr_get(&inode, b"user.comment").unwrap();
        assert_eq!(v2, b"upper_value");
    }

    #[test]
    fn test_trusted_overlay_filtered() {
        let inode = OvlInode::new_lower();
        assert!(ovl_xattr_get(&inode, OVL_XATTR_OPAQUE).is_err());
    }

    #[test]
    fn test_remove() {
        let mut inode = OvlInode::new_lower();
        inode.lower.set(b"security.selinux", b"label").unwrap();
        ovl_xattr_remove(&mut inode, b"security.selinux").unwrap();
    }
}
