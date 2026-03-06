// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! ext4 extended attributes (xattr).
//!
//! Implements the ext4 xattr on-disk layout and access operations:
//! - [`XattrHeader`] — block-xattr header (magic, refcount, h_blocks)
//! - [`XattrEntry`] — individual attribute entry (name_index, value_offs, etc.)
//! - In-inode (ibody) xattr stored in the inode's extra space
//! - Block xattr stored in a dedicated 4 KiB block
//! - [`xattr_get`], [`xattr_set`], [`xattr_remove`] — CRUD operations
//! - Namespace handling: user, system, trusted, security
//!
//! # References
//! - Linux `fs/ext4/xattr.c`, `fs/ext4/xattr.h`
//! - ext4 disk layout wiki — extended attributes section

extern crate alloc;
use alloc::vec::Vec;
use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// ext4 xattr block magic number.
pub const EXT4_XATTR_MAGIC: u32 = 0xEA020000;

/// Maximum xattr name length.
pub const XATTR_NAME_MAX: usize = 255;

/// Maximum xattr value length (64 KiB).
pub const XATTR_VALUE_MAX: usize = 65536;

/// Maximum xattr entries per inode/block.
const MAX_XATTR_ENTRIES: usize = 64;

/// Maximum total xattr value storage (per block, bytes).
const XATTR_BLOCK_VALUE_AREA: usize = 3900;

// ---------------------------------------------------------------------------
// Namespace indices (ext4 EXT4_XATTR_INDEX_*)
// ---------------------------------------------------------------------------

/// user.* namespace.
pub const XATTR_INDEX_USER: u8 = 1;
/// posix_acl_access namespace.
pub const XATTR_INDEX_POSIX_ACL_ACCESS: u8 = 2;
/// posix_acl_default namespace.
pub const XATTR_INDEX_POSIX_ACL_DEFAULT: u8 = 3;
/// trusted.* namespace.
pub const XATTR_INDEX_TRUSTED: u8 = 4;
/// lustre namespace.
pub const XATTR_INDEX_LUSTRE: u8 = 5;
/// security.* namespace.
pub const XATTR_INDEX_SECURITY: u8 = 6;
/// system.* namespace.
pub const XATTR_INDEX_SYSTEM: u8 = 7;
/// richacl namespace.
pub const XATTR_INDEX_RICHACL: u8 = 8;

// ---------------------------------------------------------------------------
// XattrHeader
// ---------------------------------------------------------------------------

/// ext4 extended-attribute block header.
///
/// Appears at the start of a dedicated 4 KiB xattr block.
#[derive(Debug, Clone, Copy)]
pub struct XattrHeader {
    /// Magic number, must be `EXT4_XATTR_MAGIC`.
    pub magic: u32,
    /// Reference count for shared xattr blocks.
    pub refcount: u32,
    /// Number of disk blocks used (always 1 for the basic case).
    pub blocks: u32,
    /// Hash of all entries (used for sharing).
    pub hash: u32,
    /// Checksum (metadata checksum feature).
    pub checksum: u32,
}

impl XattrHeader {
    /// Create a fresh xattr header.
    pub fn new() -> Self {
        Self {
            magic: EXT4_XATTR_MAGIC,
            refcount: 1,
            blocks: 1,
            hash: 0,
            checksum: 0,
        }
    }

    /// Validate magic number.
    pub fn is_valid(&self) -> bool {
        self.magic == EXT4_XATTR_MAGIC
    }
}

impl Default for XattrHeader {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// XattrEntry
// ---------------------------------------------------------------------------

/// ext4 extended-attribute entry descriptor.
///
/// Entries are stored after the header (or after the inode extra space
/// magic). Each entry has a name suffix stored inline (name_len bytes)
/// and the value is stored at the end of the block at `value_offs`.
#[derive(Debug, Clone)]
pub struct XattrEntry {
    /// Namespace index (XATTR_INDEX_*).
    pub name_index: u8,
    /// Length of the name suffix (excluding namespace prefix).
    pub name_len: u8,
    /// Offset of the value within the block's value area.
    pub value_offs: u16,
    /// Inode number of the value block (0 = this block).
    pub value_inum: u32,
    /// Size of the value in bytes.
    pub value_size: u32,
    /// Hash of name + value (used for lookup acceleration).
    pub hash: u32,
    /// Name suffix bytes.
    pub name: [u8; XATTR_NAME_MAX],
    /// Value bytes (stored separately in the value area on disk; here inline).
    pub value: [u8; 256],
}

impl XattrEntry {
    /// Create a new xattr entry.
    ///
    /// Returns `Err(InvalidArgument)` if name or value exceeds limits.
    pub fn new(name_index: u8, name: &[u8], value: &[u8]) -> Result<Self> {
        if name.len() > XATTR_NAME_MAX {
            return Err(Error::InvalidArgument);
        }
        if value.len() > 256 {
            return Err(Error::InvalidArgument);
        }
        let mut entry = Self {
            name_index,
            name_len: name.len() as u8,
            value_offs: 0,
            value_inum: 0,
            value_size: value.len() as u32,
            hash: 0,
            name: [0u8; XATTR_NAME_MAX],
            value: [0u8; 256],
        };
        entry.name[..name.len()].copy_from_slice(name);
        entry.value[..value.len()].copy_from_slice(value);
        Ok(entry)
    }

    /// Return the name as a byte slice.
    pub fn name_bytes(&self) -> &[u8] {
        &self.name[..self.name_len as usize]
    }

    /// Return the value as a byte slice.
    pub fn value_bytes(&self) -> &[u8] {
        &self.value[..self.value_size as usize]
    }
}

// ---------------------------------------------------------------------------
// XattrStore — collection of xattr entries (ibody or block)
// ---------------------------------------------------------------------------

/// Storage for xattr entries within a single inode or block.
pub struct XattrStore {
    /// Block header (used for block-xattr; zero for ibody).
    pub header: XattrHeader,
    entries: [Option<XattrEntry>; MAX_XATTR_ENTRIES],
    count: usize,
    /// Total bytes consumed by values.
    value_bytes_used: usize,
}

impl XattrStore {
    /// Create an empty xattr store.
    pub fn new() -> Self {
        Self {
            header: XattrHeader::new(),
            entries: core::array::from_fn(|_| None),
            count: 0,
            value_bytes_used: 0,
        }
    }

    /// Find entry index by name_index + name.
    fn find(&self, name_index: u8, name: &[u8]) -> Option<usize> {
        for (i, slot) in self.entries[..self.count].iter().enumerate() {
            if let Some(e) = slot {
                if e.name_index == name_index && e.name_bytes() == name {
                    return Some(i);
                }
            }
        }
        None
    }
}

impl Default for XattrStore {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// CRUD operations
// ---------------------------------------------------------------------------

/// Get the value of an extended attribute.
///
/// Returns the value bytes copied into a `Vec<u8>`, or `Err(NotFound)`.
pub fn xattr_get(store: &XattrStore, name_index: u8, name: &[u8]) -> Result<Vec<u8>> {
    let idx = store.find(name_index, name).ok_or(Error::NotFound)?;
    if let Some(e) = &store.entries[idx] {
        Ok(e.value_bytes().to_vec())
    } else {
        Err(Error::NotFound)
    }
}

/// Set (create or replace) an extended attribute.
///
/// Returns `Err(OutOfMemory)` when the store is full.
/// Returns `Err(InvalidArgument)` when name/value exceed limits.
pub fn xattr_set(store: &mut XattrStore, name_index: u8, name: &[u8], value: &[u8]) -> Result<()> {
    if value.len() > XATTR_VALUE_MAX {
        return Err(Error::InvalidArgument);
    }
    // If entry exists, replace value in-place.
    if let Some(idx) = store.find(name_index, name) {
        if let Some(e) = store.entries[idx].as_mut() {
            if value.len() > 256 {
                return Err(Error::InvalidArgument);
            }
            let old_size = e.value_size as usize;
            let new_size = value.len();
            // Update value area accounting.
            store.value_bytes_used = store.value_bytes_used.saturating_sub(old_size) + new_size;
            if store.value_bytes_used > XATTR_BLOCK_VALUE_AREA {
                store.value_bytes_used = store.value_bytes_used.saturating_sub(new_size) + old_size;
                return Err(Error::OutOfMemory);
            }
            e.value[..new_size].copy_from_slice(value);
            e.value_size = new_size as u32;
        }
        return Ok(());
    }
    // New entry.
    if store.count >= MAX_XATTR_ENTRIES {
        return Err(Error::OutOfMemory);
    }
    if store.value_bytes_used + value.len() > XATTR_BLOCK_VALUE_AREA {
        return Err(Error::OutOfMemory);
    }
    let entry = XattrEntry::new(name_index, name, value)?;
    store.value_bytes_used += value.len();
    store.entries[store.count] = Some(entry);
    store.count += 1;
    Ok(())
}

/// Remove an extended attribute.
///
/// Returns `Err(NotFound)` if the attribute does not exist.
pub fn xattr_remove(store: &mut XattrStore, name_index: u8, name: &[u8]) -> Result<()> {
    let idx = store.find(name_index, name).ok_or(Error::NotFound)?;
    if let Some(e) = store.entries[idx].take() {
        store.value_bytes_used = store.value_bytes_used.saturating_sub(e.value_size as usize);
    }
    // Compact the entries array.
    if idx < store.count - 1 {
        store.entries.swap(idx, store.count - 1);
    }
    store.count -= 1;
    Ok(())
}

/// List all extended attribute names as a `Vec` of `(name_index, name_bytes)`.
pub fn xattr_list(store: &XattrStore) -> Vec<(u8, Vec<u8>)> {
    let mut result = Vec::new();
    for slot in &store.entries[..store.count] {
        if let Some(e) = slot {
            result.push((e.name_index, e.name_bytes().to_vec()));
        }
    }
    result
}

// ---------------------------------------------------------------------------
// Namespace helper
// ---------------------------------------------------------------------------

/// Map a namespace prefix string to the ext4 name_index constant.
///
/// Returns `Err(InvalidArgument)` for unknown namespaces.
pub fn namespace_to_index(prefix: &[u8]) -> Result<u8> {
    match prefix {
        b"user" => Ok(XATTR_INDEX_USER),
        b"trusted" => Ok(XATTR_INDEX_TRUSTED),
        b"security" => Ok(XATTR_INDEX_SECURITY),
        b"system" => Ok(XATTR_INDEX_SYSTEM),
        _ => Err(Error::InvalidArgument),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_set_get_remove() {
        let mut store = XattrStore::new();
        xattr_set(&mut store, XATTR_INDEX_USER, b"comment", b"hello").unwrap();
        let v = xattr_get(&store, XATTR_INDEX_USER, b"comment").unwrap();
        assert_eq!(v, b"hello");
        xattr_remove(&mut store, XATTR_INDEX_USER, b"comment").unwrap();
        assert!(xattr_get(&store, XATTR_INDEX_USER, b"comment").is_err());
    }

    #[test]
    fn test_namespace_index() {
        assert_eq!(namespace_to_index(b"user").unwrap(), XATTR_INDEX_USER);
        assert_eq!(
            namespace_to_index(b"security").unwrap(),
            XATTR_INDEX_SECURITY
        );
        assert!(namespace_to_index(b"unknown").is_err());
    }
}
