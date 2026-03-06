// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! POSIX ACL — extended attribute integration for `system.posix_acl_access`
//! and `system.posix_acl_default`.
//!
//! This module bridges the POSIX 1003.1e Access Control List model and the
//! VFS extended-attribute (`xattr`) storage layer.  ACL entries are serialized
//! to/from the binary on-disk format used by Linux (and compatible) kernels, and
//! a small in-memory cache reduces xattr reads on hot inodes.
//!
//! # Binary format
//!
//! ```text
//! ┌──────────────────────────────────────────────────────────┐
//! │ PosixAclXattr                                             │
//! │   version : u32  (must equal POSIX_ACL_XATTR_VERSION)    │
//! │   entries : [PosixAclXattrEntry; N]                       │
//! │     tag   : u16                                           │
//! │     perm  : u16                                           │
//! │     id    : u32  (uid/gid for USER/GROUP tags; 0 otherwise)│
//! └──────────────────────────────────────────────────────────┘
//! ```
//!
//! # References
//!
//! - Linux `fs/posix_acl.c`, `include/linux/posix_acl_xattr.h`
//! - POSIX 1003.1e (withdrawn, but widely implemented)
//! - `man 5 acl`

use oncrix_lib::{Error, Result};

// ── Constants ─────────────────────────────────────────────────────────────────

/// Binary format version embedded in every serialized ACL.
pub const POSIX_ACL_XATTR_VERSION: u32 = 0x0002;

/// Maximum number of ACL entries that can be serialized/deserialized.
pub const MAX_ACL_ENTRIES: usize = 32;

/// Maximum number of cached ACLs in [`PosixAclCache`].
pub const MAX_ACL_CACHE: usize = 256;

/// Byte overhead of the header (version field) in the xattr blob.
const ACL_HEADER_SIZE: usize = 4;

/// Byte size of a single serialized ACL entry.
const ACL_ENTRY_SIZE: usize = 8;

// ── ACL tag constants ─────────────────────────────────────────────────────────

/// ACL entry tags matching the Linux `posix_acl_xattr` wire format.
pub mod acl_tag {
    /// Applies to the file owner.
    pub const USER_OBJ: u16 = 0x0001;
    /// Applies to a named user (uid in the `id` field).
    pub const USER: u16 = 0x0002;
    /// Applies to the owning group.
    pub const GROUP_OBJ: u16 = 0x0004;
    /// Applies to a named group (gid in the `id` field).
    pub const GROUP: u16 = 0x0008;
    /// Masks maximum permissions for GROUP, USER, and MASK entries.
    pub const MASK: u16 = 0x0010;
    /// Applies to all others.
    pub const OTHER: u16 = 0x0020;
}

/// Permission bit constants for ACL entries.
pub mod acl_perm {
    /// Execute permission.
    pub const EXECUTE: u16 = 0x0001;
    /// Write permission.
    pub const WRITE: u16 = 0x0002;
    /// Read permission.
    pub const READ: u16 = 0x0004;
}

// ── PosixAclXattrEntry ────────────────────────────────────────────────────────

/// One entry in the binary xattr representation of a POSIX ACL.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct PosixAclXattrEntry {
    /// Entry tag — one of the [`acl_tag`] constants.
    pub tag: u16,
    /// Permission bits — combination of [`acl_perm`] constants.
    pub perm: u16,
    /// User or group id; `u32::MAX` if not applicable.
    pub id: u32,
}

impl PosixAclXattrEntry {
    /// Construct a new entry.
    pub const fn new(tag: u16, perm: u16, id: u32) -> Self {
        Self { tag, perm, id }
    }

    /// Serialize this entry into `buf` at `offset` (little-endian).
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if there is insufficient space.
    pub fn write_to(&self, buf: &mut [u8], offset: usize) -> Result<()> {
        if offset + ACL_ENTRY_SIZE > buf.len() {
            return Err(Error::InvalidArgument);
        }
        buf[offset..offset + 2].copy_from_slice(&self.tag.to_le_bytes());
        buf[offset + 2..offset + 4].copy_from_slice(&self.perm.to_le_bytes());
        buf[offset + 4..offset + 8].copy_from_slice(&self.id.to_le_bytes());
        Ok(())
    }

    /// Deserialize one entry from `buf` at `offset` (little-endian).
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if there are insufficient bytes.
    pub fn read_from(buf: &[u8], offset: usize) -> Result<Self> {
        if offset + ACL_ENTRY_SIZE > buf.len() {
            return Err(Error::InvalidArgument);
        }
        let tag = u16::from_le_bytes([buf[offset], buf[offset + 1]]);
        let perm = u16::from_le_bytes([buf[offset + 2], buf[offset + 3]]);
        let id = u32::from_le_bytes([
            buf[offset + 4],
            buf[offset + 5],
            buf[offset + 6],
            buf[offset + 7],
        ]);
        Ok(Self { tag, perm, id })
    }
}

// ── PosixAclXattr header ──────────────────────────────────────────────────────

/// Header of the binary xattr blob — only the version word.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct PosixAclXattr {
    /// Must equal [`POSIX_ACL_XATTR_VERSION`].
    pub version: u32,
}

// ── AclXattrName ─────────────────────────────────────────────────────────────

/// Well-known xattr names for POSIX ACLs.
pub struct AclXattrName;

impl AclXattrName {
    /// Xattr name for the access ACL.
    pub const ACCESS: &'static str = "system.posix_acl_access";
    /// Xattr name for the default ACL (directories only).
    pub const DEFAULT: &'static str = "system.posix_acl_default";
}

// ── AclEntries ────────────────────────────────────────────────────────────────

/// An in-memory set of POSIX ACL entries.
#[derive(Debug, Clone, Copy)]
pub struct AclEntries {
    /// The entry array (only `count` entries are valid).
    pub entries: [PosixAclXattrEntry; MAX_ACL_ENTRIES],
    /// Number of valid entries in `entries`.
    pub count: usize,
}

impl Default for AclEntries {
    fn default() -> Self {
        Self {
            entries: [const { PosixAclXattrEntry::new(0, 0, 0) }; MAX_ACL_ENTRIES],
            count: 0,
        }
    }
}

impl AclEntries {
    /// Construct an empty `AclEntries`.
    pub const fn new() -> Self {
        Self {
            entries: [const { PosixAclXattrEntry::new(0, 0, 0) }; MAX_ACL_ENTRIES],
            count: 0,
        }
    }

    /// Add an entry to this set.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] when the set is full.
    pub fn add(&mut self, entry: PosixAclXattrEntry) -> Result<()> {
        if self.count >= MAX_ACL_ENTRIES {
            return Err(Error::OutOfMemory);
        }
        self.entries[self.count] = entry;
        self.count += 1;
        Ok(())
    }

    /// Return a slice of the valid entries.
    pub fn as_slice(&self) -> &[PosixAclXattrEntry] {
        &self.entries[..self.count]
    }

    /// Find the first entry with the given `tag`.
    pub fn find_tag(&self, tag: u16) -> Option<&PosixAclXattrEntry> {
        self.as_slice().iter().find(|e| e.tag == tag)
    }

    /// Return the effective permission bits for `tag`, or 0 if not present.
    pub fn perm_for_tag(&self, tag: u16) -> u16 {
        self.find_tag(tag).map(|e| e.perm).unwrap_or(0)
    }
}

// ── Serialization / deserialization ──────────────────────────────────────────

/// Deserialize a binary xattr blob into an [`AclEntries`] set.
///
/// # Errors
///
/// - [`Error::InvalidArgument`] — blob is too short or version mismatch.
pub fn posix_acl_from_xattr(data: &[u8]) -> Result<AclEntries> {
    if data.len() < ACL_HEADER_SIZE {
        return Err(Error::InvalidArgument);
    }
    let version = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    if version != POSIX_ACL_XATTR_VERSION {
        return Err(Error::InvalidArgument);
    }
    let payload = &data[ACL_HEADER_SIZE..];
    if payload.len() % ACL_ENTRY_SIZE != 0 {
        return Err(Error::InvalidArgument);
    }
    let n = payload.len() / ACL_ENTRY_SIZE;
    if n > MAX_ACL_ENTRIES {
        return Err(Error::InvalidArgument);
    }
    let mut result = AclEntries::new();
    for i in 0..n {
        let entry = PosixAclXattrEntry::read_from(payload, i * ACL_ENTRY_SIZE)?;
        result.add(entry)?;
    }
    Ok(result)
}

/// Serialize an [`AclEntries`] set into a fixed-size xattr blob.
///
/// The blob is written into `out`, which must be at least
/// `ACL_HEADER_SIZE + entries.count * ACL_ENTRY_SIZE` bytes long.
///
/// # Errors
///
/// - [`Error::InvalidArgument`] — `out` is too small.
pub fn posix_acl_to_xattr(entries: &AclEntries, out: &mut [u8]) -> Result<usize> {
    let needed = ACL_HEADER_SIZE + entries.count * ACL_ENTRY_SIZE;
    if out.len() < needed {
        return Err(Error::InvalidArgument);
    }
    out[..4].copy_from_slice(&POSIX_ACL_XATTR_VERSION.to_le_bytes());
    for (i, entry) in entries.as_slice().iter().enumerate() {
        entry.write_to(out, ACL_HEADER_SIZE + i * ACL_ENTRY_SIZE)?;
    }
    Ok(needed)
}

// ── posix_acl_chmod ───────────────────────────────────────────────────────────

/// Update the ACL stored for `inode_id` to reflect a new Unix `mode`.
///
/// Per POSIX semantics, `chmod` sets the owner, group, and other permission
/// bits in the `USER_OBJ`, `GROUP_OBJ` (or `MASK` if a full ACL is present),
/// and `OTHER` entries.
///
/// # Errors
///
/// - [`Error::NotFound`] — no ACL exists for `inode_id`.
pub fn posix_acl_chmod(inode_id: u64, mode: u16, cache: &mut PosixAclCache) -> Result<()> {
    let acl = cache.get_mut(inode_id).ok_or(Error::NotFound)?;

    let owner_perm = ((mode >> 6) & 0x7) as u16;
    let group_perm = ((mode >> 3) & 0x7) as u16;
    let other_perm = (mode & 0x7) as u16;

    // Pre-compute whether a MASK entry exists to avoid a double-borrow inside
    // the mutable loop below.
    let has_mask = acl.as_slice().iter().any(|e| e.tag == acl_tag::MASK);

    for entry in acl.entries[..acl.count].iter_mut() {
        match entry.tag {
            acl_tag::USER_OBJ => entry.perm = owner_perm,
            acl_tag::MASK => entry.perm = group_perm,
            acl_tag::GROUP_OBJ => {
                // Update only if no MASK entry is present (simple ACL).
                if !has_mask {
                    entry.perm = group_perm;
                }
            }
            acl_tag::OTHER => entry.perm = other_perm,
            _ => {}
        }
    }
    Ok(())
}

// ── posix_acl_create ──────────────────────────────────────────────────────────

/// Derive the initial ACL for a newly created inode from its parent's default ACL.
///
/// When a directory has a default ACL, new files and subdirectories inherit
/// it.  This function synthesises the access ACL for `new_inode_id` based on
/// the default ACL of `dir_inode_id` and the creation `mode`.
///
/// # Errors
///
/// - [`Error::NotFound`] — parent has no default ACL (caller should use `mode` only).
/// - [`Error::OutOfMemory`] — cache is full.
pub fn posix_acl_create(
    dir_inode_id: u64,
    new_inode_id: u64,
    mode: u16,
    cache: &mut PosixAclCache,
    stats: &mut PosixAclStats,
) -> Result<AclEntries> {
    // Look up the parent default ACL from the cache.
    let parent_acl = match cache.get(dir_inode_id) {
        Some(a) => *a,
        None => {
            stats.cache_misses += 1;
            return Err(Error::NotFound);
        }
    };
    stats.cache_hits += 1;

    let mut child_acl = AclEntries::new();

    // Copy entries from the parent default ACL, applying the mode mask.
    for entry in parent_acl.as_slice() {
        let mut e = *entry;
        match e.tag {
            acl_tag::USER_OBJ => e.perm = ((mode >> 6) & 0x7) as u16,
            acl_tag::OTHER => e.perm = (mode & 0x7) as u16,
            acl_tag::MASK | acl_tag::GROUP_OBJ => {
                e.perm &= ((mode >> 3) & 0x7) as u16;
            }
            _ => {}
        }
        child_acl.add(e)?;
    }

    // Store the derived ACL in the cache.
    cache.set(new_inode_id, child_acl)?;
    stats.xattr_writes += 1;

    Ok(child_acl)
}

// ── PosixAclCache ─────────────────────────────────────────────────────────────

/// Cached mapping of inode id → ACL entries (up to [`MAX_ACL_CACHE`] entries).
pub struct PosixAclCache {
    /// Inode ids of cached ACLs; 0 means empty slot.
    keys: [u64; MAX_ACL_CACHE],
    /// Cached ACL entry sets.
    values: [AclEntries; MAX_ACL_CACHE],
    /// Count of occupied slots.
    count: usize,
}

impl Default for PosixAclCache {
    fn default() -> Self {
        Self::new()
    }
}

impl PosixAclCache {
    /// Construct an empty cache.
    pub const fn new() -> Self {
        Self {
            keys: [0u64; MAX_ACL_CACHE],
            values: [const { AclEntries::new() }; MAX_ACL_CACHE],
            count: 0,
        }
    }

    /// Look up the ACL for `inode_id`, returning an immutable reference.
    pub fn get(&self, inode_id: u64) -> Option<&AclEntries> {
        let idx = self.find(inode_id)?;
        Some(&self.values[idx])
    }

    /// Look up the ACL for `inode_id`, returning a mutable reference.
    pub fn get_mut(&mut self, inode_id: u64) -> Option<&mut AclEntries> {
        let idx = self.find(inode_id)?;
        Some(&mut self.values[idx])
    }

    /// Insert or replace the ACL for `inode_id`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] when the cache is full and no existing
    /// entry for `inode_id` is found.
    pub fn set(&mut self, inode_id: u64, acl: AclEntries) -> Result<()> {
        if let Some(idx) = self.find(inode_id) {
            self.values[idx] = acl;
            return Ok(());
        }
        if self.count >= MAX_ACL_CACHE {
            // Evict slot 0 (simplistic LRU stub).
            self.keys[0] = inode_id;
            self.values[0] = acl;
            return Ok(());
        }
        self.keys[self.count] = inode_id;
        self.values[self.count] = acl;
        self.count += 1;
        Ok(())
    }

    /// Remove the cached ACL for `inode_id`.
    pub fn invalidate(&mut self, inode_id: u64) {
        if let Some(idx) = self.find(inode_id) {
            // Swap-remove to keep the table compact.
            let last = self.count - 1;
            self.keys[idx] = self.keys[last];
            self.values[idx] = self.values[last];
            self.keys[last] = 0;
            self.values[last] = AclEntries::new();
            self.count -= 1;
        }
    }

    // -- private --

    fn find(&self, inode_id: u64) -> Option<usize> {
        for i in 0..self.count {
            if self.keys[i] == inode_id {
                return Some(i);
            }
        }
        None
    }
}

// ── PosixAclStats ─────────────────────────────────────────────────────────────

/// Cumulative statistics for the POSIX ACL subsystem.
#[derive(Debug, Clone, Copy, Default)]
pub struct PosixAclStats {
    /// ACL cache hits (avoided xattr reads).
    pub cache_hits: u64,
    /// ACL cache misses (required xattr reads).
    pub cache_misses: u64,
    /// Total xattr reads performed to populate the cache.
    pub xattr_reads: u64,
    /// Total xattr writes performed to persist ACL changes.
    pub xattr_writes: u64,
}

impl PosixAclStats {
    /// Construct zeroed stats.
    pub const fn new() -> Self {
        Self {
            cache_hits: 0,
            cache_misses: 0,
            xattr_reads: 0,
            xattr_writes: 0,
        }
    }
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn minimal_acl() -> AclEntries {
        let mut a = AclEntries::new();
        a.add(PosixAclXattrEntry::new(
            acl_tag::USER_OBJ,
            acl_perm::READ | acl_perm::WRITE,
            u32::MAX,
        ))
        .unwrap();
        a.add(PosixAclXattrEntry::new(
            acl_tag::GROUP_OBJ,
            acl_perm::READ,
            u32::MAX,
        ))
        .unwrap();
        a.add(PosixAclXattrEntry::new(acl_tag::OTHER, 0, u32::MAX))
            .unwrap();
        a
    }

    #[test]
    fn xattr_roundtrip() {
        let entries = minimal_acl();
        let mut buf = [0u8; 128];
        let len = posix_acl_to_xattr(&entries, &mut buf).unwrap();
        let decoded = posix_acl_from_xattr(&buf[..len]).unwrap();
        assert_eq!(decoded.count, 3);
        assert_eq!(decoded.entries[0].tag, acl_tag::USER_OBJ);
    }

    #[test]
    fn bad_version_rejected() {
        let mut buf = [0u8; 32];
        buf[0..4].copy_from_slice(&0xDEAD_BEEFu32.to_le_bytes());
        assert!(posix_acl_from_xattr(&buf).is_err());
    }

    #[test]
    fn chmod_updates_cache() {
        let mut cache = PosixAclCache::new();
        cache.set(42, minimal_acl()).unwrap();
        posix_acl_chmod(42, 0o640, &mut cache).unwrap();
        let acl = cache.get(42).unwrap();
        assert_eq!(acl.perm_for_tag(acl_tag::USER_OBJ), 0x6); // rw
        assert_eq!(acl.perm_for_tag(acl_tag::OTHER), 0x0);
    }

    #[test]
    fn cache_invalidate() {
        let mut cache = PosixAclCache::new();
        cache.set(1, minimal_acl()).unwrap();
        assert!(cache.get(1).is_some());
        cache.invalidate(1);
        assert!(cache.get(1).is_none());
    }
}
