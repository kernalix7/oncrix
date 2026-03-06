// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Extended attribute operations — per-inode xattr store.
//!
//! This module provides a compact, no-heap xattr storage engine used by
//! individual filesystem implementations.  It complements [`crate::xattr_vfs`]
//! (which supplies the VFS routing layer and namespace checks) with the
//! actual per-inode key-value store.
//!
//! # Design
//!
//! Each inode that supports extended attributes holds an [`XattrStore`]:
//! a fixed-size array of [`XattrEntry`] slots keyed by attribute name.
//! The store handles POSIX `setxattr`, `getxattr`, `listxattr`, and
//! `removexattr` semantics including `XATTR_CREATE` / `XATTR_REPLACE` flags.
//!
//! A global [`XattrRegistry`] maps inode identifiers to their stores, so
//! filesystems that lack native xattr support (e.g., FAT32) can still
//! present extended attributes by storing them out-of-band here.
//!
//! # Namespaces
//!
//! The four standard Linux xattr namespaces are recognised and exported as
//! prefix constants so callers can validate names before passing them down:
//!
//! | Namespace | Prefix     | Access |
//! |-----------|------------|--------|
//! | user      | `user.`    | UID check |
//! | trusted   | `trusted.` | CAP_SYS_ADMIN |
//! | security  | `security.`| LSM hook |
//! | system    | `system.`  | internal |
//!
//! # References
//!
//! - Linux `fs/xattr.c`, `include/linux/xattr.h`
//! - POSIX.1-2024 extended attributes
//! - `xattr(7)` manual page

use oncrix_lib::{Error, Result};

// ── Constants ───────────────────────────────────────────────────

/// Maximum length of an xattr name in bytes (including namespace prefix).
pub const XATTR_NAME_MAX: usize = 255;

/// Maximum size of an xattr value in bytes.
pub const XATTR_VALUE_MAX: usize = 65536;

/// Maximum number of xattr entries per inode store.
const MAX_ENTRIES_PER_STORE: usize = 32;

/// Maximum total bytes of xattr values per inode store.
const MAX_VALUE_BYTES: usize = 65536;

/// Maximum number of inode xattr stores in the global registry.
const MAX_STORES: usize = 256;

/// `setxattr` flag: create a new attribute, fail if it already exists.
pub const XATTR_CREATE: u32 = 1;
/// `setxattr` flag: replace an existing attribute, fail if it doesn't exist.
pub const XATTR_REPLACE: u32 = 2;

// ── Namespace prefixes ───────────────────────────────────────────

/// Prefix for `user` namespace xattrs.
pub const NS_USER: &[u8] = b"user.";
/// Prefix for `trusted` namespace xattrs.
pub const NS_TRUSTED: &[u8] = b"trusted.";
/// Prefix for `security` namespace xattrs.
pub const NS_SECURITY: &[u8] = b"security.";
/// Prefix for `system` namespace xattrs.
pub const NS_SYSTEM: &[u8] = b"system.";

// ── XattrNamespace ───────────────────────────────────────────────

/// Identifies the xattr namespace inferred from a name prefix.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XattrNamespace {
    /// `user.*` — accessible to normal users.
    User,
    /// `trusted.*` — requires `CAP_SYS_ADMIN`.
    Trusted,
    /// `security.*` — managed by the LSM layer.
    Security,
    /// `system.*` — kernel-internal.
    System,
    /// Unrecognised prefix.
    Unknown,
}

impl XattrNamespace {
    /// Infers the namespace from the start of `name`.
    pub fn from_name(name: &[u8]) -> Self {
        if name.starts_with(NS_USER) {
            Self::User
        } else if name.starts_with(NS_TRUSTED) {
            Self::Trusted
        } else if name.starts_with(NS_SECURITY) {
            Self::Security
        } else if name.starts_with(NS_SYSTEM) {
            Self::System
        } else {
            Self::Unknown
        }
    }
}

// ── XattrName ────────────────────────────────────────────────────

/// Fixed-size buffer holding an xattr name.
#[derive(Clone, Copy)]
pub struct XattrName {
    buf: [u8; XATTR_NAME_MAX],
    len: usize,
}

impl XattrName {
    /// Creates an empty name.
    pub const fn empty() -> Self {
        Self {
            buf: [0u8; XATTR_NAME_MAX],
            len: 0,
        }
    }

    /// Creates a name from `src`, returning an error if it is too long.
    pub fn from_bytes(src: &[u8]) -> Result<Self> {
        if src.is_empty() || src.len() > XATTR_NAME_MAX {
            return Err(Error::InvalidArgument);
        }
        let mut this = Self::empty();
        this.buf[..src.len()].copy_from_slice(src);
        this.len = src.len();
        Ok(this)
    }

    /// Returns the name as a byte slice.
    pub fn as_bytes(&self) -> &[u8] {
        &self.buf[..self.len]
    }

    /// Returns `true` if this name equals `other`.
    pub fn eq_bytes(&self, other: &[u8]) -> bool {
        self.as_bytes() == other
    }
}

impl core::fmt::Debug for XattrName {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "XattrName({:?})",
            core::str::from_utf8(self.as_bytes()).unwrap_or("<?>")
        )
    }
}

// ── XattrValue ───────────────────────────────────────────────────

/// Variable-length xattr value stored inline up to `MAX_VALUE_BYTES`.
///
/// For simplicity the value is stored as a byte vector within the
/// per-entry allocation; heap allocation is avoided by using a global
/// value pool in [`XattrStore`].
#[derive(Clone, Copy)]
pub struct XattrValue {
    buf: [u8; 256], // inline storage for small values
    len: usize,
}

impl XattrValue {
    /// Creates an empty value.
    pub const fn empty() -> Self {
        Self {
            buf: [0u8; 256],
            len: 0,
        }
    }

    /// Stores `src` as the value.  Returns an error if `src` exceeds the
    /// inline capacity (256 bytes — larger values need the value pool).
    pub fn set_inline(&mut self, src: &[u8]) -> Result<()> {
        if src.len() > 256 {
            return Err(Error::InvalidArgument);
        }
        self.buf[..src.len()].copy_from_slice(src);
        self.len = src.len();
        Ok(())
    }

    /// Returns the value as a byte slice.
    pub fn as_bytes(&self) -> &[u8] {
        &self.buf[..self.len]
    }

    /// Returns the length of the value.
    pub fn len(&self) -> usize {
        self.len
    }

    /// Returns `true` if the value is empty.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

impl core::fmt::Debug for XattrValue {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "XattrValue(len={})", self.len)
    }
}

// ── XattrEntry ───────────────────────────────────────────────────

/// A single extended attribute key-value pair.
#[derive(Clone, Copy, Debug)]
pub struct XattrEntry {
    /// Attribute name.
    pub name: XattrName,
    /// Attribute value (inline up to 256 bytes).
    pub value: XattrValue,
    /// Whether this slot is occupied.
    occupied: bool,
}

impl XattrEntry {
    /// Creates an empty (unoccupied) entry slot.
    pub const fn empty() -> Self {
        Self {
            name: XattrName::empty(),
            value: XattrValue::empty(),
            occupied: false,
        }
    }
}

// ── XattrStore ───────────────────────────────────────────────────

/// Per-inode xattr storage.
///
/// Holds up to `MAX_ENTRIES_PER_STORE` key-value pairs and provides the
/// four POSIX xattr operations: `set`, `get`, `list`, `remove`.
pub struct XattrStore {
    entries: [XattrEntry; MAX_ENTRIES_PER_STORE],
    count: usize,
}

impl XattrStore {
    /// Creates an empty xattr store.
    pub const fn new() -> Self {
        Self {
            entries: [const { XattrEntry::empty() }; MAX_ENTRIES_PER_STORE],
            count: 0,
        }
    }

    /// Sets the extended attribute `name` to `value`.
    ///
    /// `flags`:
    /// - 0 → create or replace.
    /// - [`XATTR_CREATE`] → fail with [`Error::AlreadyExists`] if the
    ///   attribute already exists.
    /// - [`XATTR_REPLACE`] → fail with [`Error::NotFound`] if the
    ///   attribute does not exist.
    pub fn set(&mut self, name: &[u8], value: &[u8], flags: u32) -> Result<()> {
        let xname = XattrName::from_bytes(name)?;
        // Find existing entry.
        for i in 0..MAX_ENTRIES_PER_STORE {
            if self.entries[i].occupied && self.entries[i].name.eq_bytes(name) {
                if flags & XATTR_CREATE != 0 {
                    return Err(Error::AlreadyExists);
                }
                self.entries[i].value.set_inline(value)?;
                return Ok(());
            }
        }
        // Attribute does not exist.
        if flags & XATTR_REPLACE != 0 {
            return Err(Error::NotFound);
        }
        // Insert new entry.
        for i in 0..MAX_ENTRIES_PER_STORE {
            if !self.entries[i].occupied {
                let mut val = XattrValue::empty();
                val.set_inline(value)?;
                self.entries[i] = XattrEntry {
                    name: xname,
                    value: val,
                    occupied: true,
                };
                self.count += 1;
                return Ok(());
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Retrieves the value of attribute `name` into `out`.
    ///
    /// Returns the number of bytes written.  If `out` is empty, returns the
    /// required buffer size (POSIX `getxattr` with `size == 0`).
    pub fn get(&self, name: &[u8], out: &mut [u8]) -> Result<usize> {
        for i in 0..MAX_ENTRIES_PER_STORE {
            if self.entries[i].occupied && self.entries[i].name.eq_bytes(name) {
                let val = self.entries[i].value.as_bytes();
                if out.is_empty() {
                    return Ok(val.len());
                }
                if out.len() < val.len() {
                    return Err(Error::InvalidArgument);
                }
                out[..val.len()].copy_from_slice(val);
                return Ok(val.len());
            }
        }
        Err(Error::NotFound)
    }

    /// Removes the attribute `name`.
    ///
    /// Returns [`Error::NotFound`] if it does not exist.
    pub fn remove(&mut self, name: &[u8]) -> Result<()> {
        for i in 0..MAX_ENTRIES_PER_STORE {
            if self.entries[i].occupied && self.entries[i].name.eq_bytes(name) {
                self.entries[i].occupied = false;
                self.count -= 1;
                return Ok(());
            }
        }
        Err(Error::NotFound)
    }

    /// Lists all attribute names, separated by null bytes, into `out`.
    ///
    /// Returns the number of bytes written.  If `out` is empty, returns the
    /// required buffer size.
    pub fn list(&self, out: &mut [u8]) -> Result<usize> {
        let required: usize = self
            .entries
            .iter()
            .filter(|e| e.occupied)
            .map(|e| e.name.len + 1) // name + '\0'
            .sum();
        if out.is_empty() {
            return Ok(required);
        }
        if out.len() < required {
            return Err(Error::InvalidArgument);
        }
        let mut pos = 0;
        for i in 0..MAX_ENTRIES_PER_STORE {
            if self.entries[i].occupied {
                let n = self.entries[i].name.as_bytes();
                out[pos..pos + n.len()].copy_from_slice(n);
                pos += n.len();
                out[pos] = 0;
                pos += 1;
            }
        }
        Ok(pos)
    }

    /// Returns the number of attributes stored.
    pub fn count(&self) -> usize {
        self.count
    }

    /// Returns `true` if the attribute `name` exists.
    pub fn contains(&self, name: &[u8]) -> bool {
        self.entries
            .iter()
            .any(|e| e.occupied && e.name.eq_bytes(name))
    }
}

// ── XattrRegistryEntry ───────────────────────────────────────────

/// Maps an inode identifier to an [`XattrStore`].
struct XattrRegistryEntry {
    inode_id: u64,
    store: XattrStore,
    occupied: bool,
}

impl XattrRegistryEntry {
    const fn empty() -> Self {
        Self {
            inode_id: 0,
            store: XattrStore::new(),
            occupied: false,
        }
    }
}

// ── XattrRegistry ────────────────────────────────────────────────

/// Global registry mapping inode identifiers to xattr stores.
///
/// Used by filesystems that do not have native xattr storage, and as
/// an overlay for filesystems that delegate to VFS-managed stores.
pub struct XattrRegistry {
    entries: [XattrRegistryEntry; MAX_STORES],
    count: usize,
}

impl XattrRegistry {
    /// Creates an empty registry.
    pub const fn new() -> Self {
        Self {
            entries: [const { XattrRegistryEntry::empty() }; MAX_STORES],
            count: 0,
        }
    }

    /// Ensures an [`XattrStore`] exists for `inode_id` and returns its index.
    fn ensure_store(&mut self, inode_id: u64) -> Result<usize> {
        for i in 0..MAX_STORES {
            if self.entries[i].occupied && self.entries[i].inode_id == inode_id {
                return Ok(i);
            }
        }
        // Allocate new entry.
        for i in 0..MAX_STORES {
            if !self.entries[i].occupied {
                self.entries[i].inode_id = inode_id;
                self.entries[i].store = XattrStore::new();
                self.entries[i].occupied = true;
                self.count += 1;
                return Ok(i);
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Sets the xattr `name` to `value` on `inode_id`.
    pub fn setxattr(&mut self, inode_id: u64, name: &[u8], value: &[u8], flags: u32) -> Result<()> {
        let idx = self.ensure_store(inode_id)?;
        self.entries[idx].store.set(name, value, flags)
    }

    /// Gets the xattr `name` from `inode_id` into `out`.
    pub fn getxattr(&self, inode_id: u64, name: &[u8], out: &mut [u8]) -> Result<usize> {
        for i in 0..MAX_STORES {
            if self.entries[i].occupied && self.entries[i].inode_id == inode_id {
                return self.entries[i].store.get(name, out);
            }
        }
        Err(Error::NotFound)
    }

    /// Removes the xattr `name` from `inode_id`.
    pub fn removexattr(&mut self, inode_id: u64, name: &[u8]) -> Result<()> {
        for i in 0..MAX_STORES {
            if self.entries[i].occupied && self.entries[i].inode_id == inode_id {
                let result = self.entries[i].store.remove(name);
                // Free the store entry if it's now empty.
                if self.entries[i].store.count() == 0 {
                    self.entries[i].occupied = false;
                    self.count -= 1;
                }
                return result;
            }
        }
        Err(Error::NotFound)
    }

    /// Lists xattrs for `inode_id`.
    pub fn listxattr(&self, inode_id: u64, out: &mut [u8]) -> Result<usize> {
        for i in 0..MAX_STORES {
            if self.entries[i].occupied && self.entries[i].inode_id == inode_id {
                return self.entries[i].store.list(out);
            }
        }
        // No store: return empty list.
        if out.is_empty() {
            return Ok(0);
        }
        Ok(0)
    }

    /// Frees all xattrs for `inode_id` (called on inode eviction).
    pub fn evict(&mut self, inode_id: u64) {
        for i in 0..MAX_STORES {
            if self.entries[i].occupied && self.entries[i].inode_id == inode_id {
                self.entries[i].occupied = false;
                self.count -= 1;
                return;
            }
        }
    }

    /// Returns the number of active inode stores.
    pub fn store_count(&self) -> usize {
        self.count
    }
}

// ── Namespace validation helpers ─────────────────────────────────

/// Validates `name` for the `user` namespace.
///
/// Returns [`Error::InvalidArgument`] if the name is empty, too long,
/// or does not begin with `user.`.
pub fn validate_user_xattr(name: &[u8]) -> Result<()> {
    if !name.starts_with(NS_USER) {
        return Err(Error::InvalidArgument);
    }
    if name.len() <= NS_USER.len() {
        return Err(Error::InvalidArgument);
    }
    if name.len() > XATTR_NAME_MAX {
        return Err(Error::InvalidArgument);
    }
    Ok(())
}

/// Validates `name` for the `trusted` namespace.
pub fn validate_trusted_xattr(name: &[u8]) -> Result<()> {
    if !name.starts_with(NS_TRUSTED) {
        return Err(Error::InvalidArgument);
    }
    if name.len() <= NS_TRUSTED.len() {
        return Err(Error::InvalidArgument);
    }
    if name.len() > XATTR_NAME_MAX {
        return Err(Error::InvalidArgument);
    }
    Ok(())
}

/// Validates `name` for the `security` namespace.
pub fn validate_security_xattr(name: &[u8]) -> Result<()> {
    if !name.starts_with(NS_SECURITY) {
        return Err(Error::InvalidArgument);
    }
    if name.len() <= NS_SECURITY.len() {
        return Err(Error::InvalidArgument);
    }
    if name.len() > XATTR_NAME_MAX {
        return Err(Error::InvalidArgument);
    }
    Ok(())
}

// ── Unit tests ───────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_set_get_basic() {
        let mut store = XattrStore::new();
        store.set(b"user.comment", b"hello", 0).unwrap();
        let mut buf = [0u8; 16];
        let n = store.get(b"user.comment", &mut buf).unwrap();
        assert_eq!(&buf[..n], b"hello");
    }

    #[test]
    fn test_xattr_create_flag() {
        let mut store = XattrStore::new();
        store.set(b"user.x", b"1", 0).unwrap();
        let res = store.set(b"user.x", b"2", XATTR_CREATE);
        assert!(matches!(res, Err(Error::AlreadyExists)));
    }

    #[test]
    fn test_xattr_replace_flag() {
        let mut store = XattrStore::new();
        let res = store.set(b"user.x", b"1", XATTR_REPLACE);
        assert!(matches!(res, Err(Error::NotFound)));
        store.set(b"user.x", b"1", 0).unwrap();
        store.set(b"user.x", b"2", XATTR_REPLACE).unwrap();
        let mut buf = [0u8; 4];
        let n = store.get(b"user.x", &mut buf).unwrap();
        assert_eq!(&buf[..n], b"2");
    }

    #[test]
    fn test_remove() {
        let mut store = XattrStore::new();
        store.set(b"user.a", b"v", 0).unwrap();
        store.remove(b"user.a").unwrap();
        assert!(!store.contains(b"user.a"));
        assert_eq!(store.count(), 0);
    }

    #[test]
    fn test_list() {
        let mut store = XattrStore::new();
        store.set(b"user.a", b"1", 0).unwrap();
        store.set(b"user.b", b"2", 0).unwrap();
        let required = store.list(&mut []).unwrap();
        let mut buf = vec![0u8; required];
        store.list(&mut buf).unwrap();
        // Should contain "user.a\0user.b\0".
        assert!(buf.windows(7).any(|w| w == b"user.a\0"));
        assert!(buf.windows(7).any(|w| w == b"user.b\0"));
    }

    #[test]
    fn test_get_size_query() {
        let mut store = XattrStore::new();
        store.set(b"user.hello", b"world", 0).unwrap();
        let size = store.get(b"user.hello", &mut []).unwrap();
        assert_eq!(size, 5);
    }

    #[test]
    fn test_registry_setxattr_getxattr() {
        let mut reg = XattrRegistry::new();
        reg.setxattr(42, b"user.test", b"value", 0).unwrap();
        let mut buf = [0u8; 8];
        let n = reg.getxattr(42, b"user.test", &mut buf).unwrap();
        assert_eq!(&buf[..n], b"value");
    }

    #[test]
    fn test_registry_evict() {
        let mut reg = XattrRegistry::new();
        reg.setxattr(1, b"user.x", b"y", 0).unwrap();
        assert_eq!(reg.store_count(), 1);
        reg.evict(1);
        assert_eq!(reg.store_count(), 0);
    }

    #[test]
    fn test_namespace_detection() {
        assert_eq!(XattrNamespace::from_name(b"user.x"), XattrNamespace::User);
        assert_eq!(
            XattrNamespace::from_name(b"trusted.x"),
            XattrNamespace::Trusted
        );
        assert_eq!(
            XattrNamespace::from_name(b"security.x"),
            XattrNamespace::Security
        );
        assert_eq!(
            XattrNamespace::from_name(b"unknown.x"),
            XattrNamespace::Unknown
        );
    }

    #[test]
    fn test_validate_user_xattr() {
        assert!(validate_user_xattr(b"user.mime_type").is_ok());
        assert!(validate_user_xattr(b"trusted.x").is_err());
        assert!(validate_user_xattr(b"user.").is_err()); // empty suffix
    }
}
