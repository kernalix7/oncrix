// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! tmpfs extended attributes (xattr) support.
//!
//! Implements per-inode extended attribute storage for the tmpfs filesystem.
//! xattrs are stored as a list of name/value pairs attached to each inode.
//!
//! # Operations
//!
//! - [`TmpfsXattr`] — a single name/value xattr pair
//! - `tmpfs_setxattr` — create or update an xattr on an inode
//! - `tmpfs_getxattr` — retrieve an xattr value by name
//! - `tmpfs_listxattr` — enumerate all xattr names on an inode
//! - `tmpfs_removexattr` — delete an xattr from an inode
//!
//! # Reference
//!
//! Linux `mm/shmem.c` (xattr section), `fs/xattr.c`.

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum number of xattrs per inode.
const MAX_XATTRS_PER_INODE: usize = 32;

/// Maximum xattr name length (including namespace prefix).
const MAX_XATTR_NAME: usize = 255;

/// Maximum xattr value size.
const MAX_XATTR_VALUE: usize = 65536;

/// Maximum number of inodes with xattrs.
const MAX_XATTR_INODES: usize = 256;

/// Namespace prefixes.
const NS_USER: &[u8] = b"user.";
const NS_TRUSTED: &[u8] = b"trusted.";
const NS_SECURITY: &[u8] = b"security.";
const NS_SYSTEM: &[u8] = b"system.";

// ---------------------------------------------------------------------------
// xattr flags
// ---------------------------------------------------------------------------

/// Flags for setxattr.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XattrFlags {
    /// Create or replace.
    Set,
    /// Create only — fail if exists.
    Create,
    /// Replace only — fail if not exists.
    Replace,
}

// ---------------------------------------------------------------------------
// Single xattr entry
// ---------------------------------------------------------------------------

/// A single extended attribute name/value pair.
#[derive(Debug, Clone)]
pub struct TmpfsXattr {
    /// Attribute name (e.g., "user.foo").
    pub name: [u8; MAX_XATTR_NAME],
    /// Valid bytes in `name`.
    pub name_len: usize,
    /// Attribute value.
    pub value: [u8; MAX_XATTR_VALUE],
    /// Valid bytes in `value`.
    pub value_len: usize,
}

impl TmpfsXattr {
    /// Creates a new xattr entry.
    pub fn new(name: &[u8], value: &[u8]) -> Result<Self> {
        if name.is_empty() || name.len() > MAX_XATTR_NAME {
            return Err(Error::InvalidArgument);
        }
        if value.len() > MAX_XATTR_VALUE {
            return Err(Error::InvalidArgument);
        }
        let mut n_buf = [0u8; MAX_XATTR_NAME];
        n_buf[..name.len()].copy_from_slice(name);
        let mut v_buf = [0u8; MAX_XATTR_VALUE];
        v_buf[..value.len()].copy_from_slice(value);
        Ok(Self {
            name: n_buf,
            name_len: name.len(),
            value: v_buf,
            value_len: value.len(),
        })
    }

    /// Returns the attribute name as a byte slice.
    pub fn name_bytes(&self) -> &[u8] {
        &self.name[..self.name_len]
    }

    /// Returns the attribute value as a byte slice.
    pub fn value_bytes(&self) -> &[u8] {
        &self.value[..self.value_len]
    }
}

// ---------------------------------------------------------------------------
// Per-inode xattr list
// ---------------------------------------------------------------------------

/// The collection of xattrs attached to a single inode.
pub struct InodeXattrs {
    /// Inode number this xattr set belongs to.
    pub ino: u64,
    /// Xattr entries.
    entries: [Option<TmpfsXattr>; MAX_XATTRS_PER_INODE],
    /// Number of entries.
    count: usize,
}

impl InodeXattrs {
    /// Creates a new empty xattr set for an inode.
    pub const fn new(ino: u64) -> Self {
        Self {
            ino,
            entries: [
                None, None, None, None, None, None, None, None, None, None, None, None, None, None,
                None, None, None, None, None, None, None, None, None, None, None, None, None, None,
                None, None, None, None,
            ],
            count: 0,
        }
    }

    /// Returns the number of xattr entries.
    pub fn count(&self) -> usize {
        self.count
    }

    /// Finds the index of an entry by name.
    fn find_index(&self, name: &[u8]) -> Option<usize> {
        for (i, slot) in self.entries.iter().enumerate() {
            if slot.as_ref().map(|x| x.name_bytes()) == Some(name) {
                return Some(i);
            }
        }
        None
    }

    /// Sets an xattr value with the given flags.
    pub fn set(&mut self, name: &[u8], value: &[u8], flags: XattrFlags) -> Result<()> {
        let existing = self.find_index(name);
        match flags {
            XattrFlags::Create => {
                if existing.is_some() {
                    return Err(Error::AlreadyExists);
                }
            }
            XattrFlags::Replace => {
                if existing.is_none() {
                    return Err(Error::NotFound);
                }
            }
            XattrFlags::Set => {}
        }

        if let Some(idx) = existing {
            // Update existing entry.
            if let Some(entry) = &mut self.entries[idx] {
                if value.len() > MAX_XATTR_VALUE {
                    return Err(Error::InvalidArgument);
                }
                entry.value[..value.len()].copy_from_slice(value);
                entry.value_len = value.len();
                return Ok(());
            }
        }

        // Add new entry.
        if self.count >= MAX_XATTRS_PER_INODE {
            return Err(Error::OutOfMemory);
        }
        let xattr = TmpfsXattr::new(name, value)?;
        for slot in &mut self.entries {
            if slot.is_none() {
                *slot = Some(xattr);
                self.count += 1;
                return Ok(());
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Gets an xattr value by name. Copies into `out`. Returns bytes written.
    pub fn get(&self, name: &[u8], out: &mut [u8]) -> Result<usize> {
        let idx = self.find_index(name).ok_or(Error::NotFound)?;
        let entry = self.entries[idx].as_ref().unwrap();
        let vlen = entry.value_len;
        if out.len() < vlen {
            return Err(Error::InvalidArgument);
        }
        out[..vlen].copy_from_slice(entry.value_bytes());
        Ok(vlen)
    }

    /// Lists all xattr names, separated by NUL bytes. Returns bytes written.
    pub fn list(&self, out: &mut [u8]) -> usize {
        let mut pos = 0;
        for entry in self.entries[..].iter().flatten() {
            let nlen = entry.name_len;
            if pos + nlen + 1 > out.len() {
                break;
            }
            out[pos..pos + nlen].copy_from_slice(entry.name_bytes());
            pos += nlen;
            out[pos] = 0; // NUL separator.
            pos += 1;
        }
        pos
    }

    /// Removes an xattr by name.
    pub fn remove(&mut self, name: &[u8]) -> Result<()> {
        let idx = self.find_index(name).ok_or(Error::NotFound)?;
        self.entries[idx] = None;
        self.count = self.count.saturating_sub(1);
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Global xattr store
// ---------------------------------------------------------------------------

/// Global tmpfs xattr storage keyed by inode number.
pub struct TmpfsXattrStore {
    /// Per-inode xattr sets.
    inode_xattrs: [Option<InodeXattrs>; MAX_XATTR_INODES],
    /// Number of inodes with xattrs.
    count: usize,
}

impl TmpfsXattrStore {
    /// Creates an empty xattr store.
    pub fn new() -> Self {
        Self {
            inode_xattrs: core::array::from_fn(|_| None),
            count: 0,
        }
    }

    /// Returns or creates the xattr set for an inode.
    fn get_or_create(&mut self, ino: u64) -> Result<&mut InodeXattrs> {
        // Check if already exists.
        let exists = self
            .inode_xattrs
            .iter()
            .any(|s| s.as_ref().map(|x| x.ino) == Some(ino));
        if !exists {
            // Create new.
            if self.count >= MAX_XATTR_INODES {
                return Err(Error::OutOfMemory);
            }
            let mut inserted = false;
            for slot in &mut self.inode_xattrs {
                if slot.is_none() {
                    *slot = Some(InodeXattrs::new(ino));
                    self.count += 1;
                    inserted = true;
                    break;
                }
            }
            if !inserted {
                return Err(Error::OutOfMemory);
            }
        }
        // Now find and return mutable reference.
        for slot in &mut self.inode_xattrs {
            if slot.as_ref().map(|x| x.ino) == Some(ino) {
                return Ok(slot.as_mut().unwrap());
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Returns the xattr set for an inode (read-only).
    fn get(&self, ino: u64) -> Option<&InodeXattrs> {
        self.inode_xattrs.iter().flatten().find(|x| x.ino == ino)
    }

    /// Removes the xattr set for an inode entirely.
    pub fn remove_inode(&mut self, ino: u64) {
        for slot in &mut self.inode_xattrs {
            if slot.as_ref().map(|x| x.ino) == Some(ino) {
                *slot = None;
                self.count = self.count.saturating_sub(1);
                return;
            }
        }
    }
}

impl Default for TmpfsXattrStore {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Public operations
// ---------------------------------------------------------------------------

/// Sets an xattr on an inode.
pub fn tmpfs_setxattr(
    store: &mut TmpfsXattrStore,
    ino: u64,
    name: &[u8],
    value: &[u8],
    flags: XattrFlags,
) -> Result<()> {
    validate_xattr_name(name)?;
    let xattrs = store.get_or_create(ino)?;
    xattrs.set(name, value, flags)
}

/// Gets an xattr value from an inode.
pub fn tmpfs_getxattr(
    store: &TmpfsXattrStore,
    ino: u64,
    name: &[u8],
    out: &mut [u8],
) -> Result<usize> {
    validate_xattr_name(name)?;
    let xattrs = store.get(ino).ok_or(Error::NotFound)?;
    xattrs.get(name, out)
}

/// Lists all xattr names on an inode.
pub fn tmpfs_listxattr(store: &TmpfsXattrStore, ino: u64, out: &mut [u8]) -> usize {
    match store.get(ino) {
        Some(xattrs) => xattrs.list(out),
        None => 0,
    }
}

/// Removes an xattr from an inode.
pub fn tmpfs_removexattr(store: &mut TmpfsXattrStore, ino: u64, name: &[u8]) -> Result<()> {
    validate_xattr_name(name)?;
    let xattrs = store
        .inode_xattrs
        .iter_mut()
        .flatten()
        .find(|x| x.ino == ino)
        .ok_or(Error::NotFound)?;
    xattrs.remove(name)
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

/// Validates that an xattr name has a valid namespace prefix.
pub fn validate_xattr_name(name: &[u8]) -> Result<()> {
    if name.is_empty() || name.len() > MAX_XATTR_NAME {
        return Err(Error::InvalidArgument);
    }
    let valid = name.starts_with(NS_USER)
        || name.starts_with(NS_TRUSTED)
        || name.starts_with(NS_SECURITY)
        || name.starts_with(NS_SYSTEM);
    if !valid {
        return Err(Error::InvalidArgument);
    }
    Ok(())
}

/// Returns the namespace of an xattr name.
pub fn xattr_namespace(name: &[u8]) -> Option<&[u8]> {
    if name.starts_with(NS_USER) {
        Some(NS_USER)
    } else if name.starts_with(NS_TRUSTED) {
        Some(NS_TRUSTED)
    } else if name.starts_with(NS_SECURITY) {
        Some(NS_SECURITY)
    } else if name.starts_with(NS_SYSTEM) {
        Some(NS_SYSTEM)
    } else {
        None
    }
}
