// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! NFS directory operations.
//!
//! Implements the NFS client-side directory path:
//! - [`NfsEntry`] — directory entry returned by READDIR/READDIRPLUS
//! - [`nfs_readdir`] — batch-read directory entries with READDIRPLUS attrs
//! - [`nfs_lookup`] — look up a single name within a directory
//! - [`nfs_create`], [`nfs_remove`], [`nfs_rename`] — mutation operations
//! - Directory cache invalidation on server-side change detection
//!
//! # READDIRPLUS
//!
//! READDIRPLUS (NFSv3+) returns file attributes alongside directory entries,
//! populating the dentry cache with fresh attributes and avoiding separate
//! GETATTR calls per entry.
//!
//! # References
//! - Linux `fs/nfs/dir.c`, `fs/nfs/nfs3proc.c`
//! - RFC 1813 (NFSv3), RFC 7530 (NFSv4)

extern crate alloc;
use alloc::string::String;
use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum NFS file name length.
pub const NFS_MAXNAMLEN: usize = 255;

/// Maximum entries returned per READDIR batch.
const MAX_READDIR_ENTRIES: usize = 256;

/// Maximum entries in the directory cache.
const DIR_CACHE_SIZE: usize = 512;

/// NFS file type constants (d_type equivalents).
pub const NFS_DT_UNKNOWN: u8 = 0;
pub const NFS_DT_REG: u8 = 8;
pub const NFS_DT_DIR: u8 = 4;
pub const NFS_DT_LNK: u8 = 10;
pub const NFS_DT_CHR: u8 = 2;
pub const NFS_DT_BLK: u8 = 6;
pub const NFS_DT_FIFO: u8 = 1;
pub const NFS_DT_SOCK: u8 = 12;

// ---------------------------------------------------------------------------
// NfsFattr — file attributes returned by READDIRPLUS
// ---------------------------------------------------------------------------

/// NFS file attributes (subset of fattr3 / fattr4).
#[derive(Debug, Clone, Copy)]
pub struct NfsFattr {
    /// File type and mode.
    pub mode: u32,
    /// Hard link count.
    pub nlink: u32,
    /// Owner UID.
    pub uid: u32,
    /// Owner GID.
    pub gid: u32,
    /// File size in bytes.
    pub size: u64,
    /// File system identifier.
    pub fsid: u64,
    /// File identifier (inode number on server).
    pub fileid: u64,
    /// Attribute cache timeout (seconds).
    pub atime: u64,
    /// Modify time.
    pub mtime: u64,
    /// Change time.
    pub ctime: u64,
}

impl NfsFattr {
    /// Create a default attributes struct.
    pub fn default_file(fileid: u64) -> Self {
        Self {
            mode: 0o100644,
            nlink: 1,
            uid: 0,
            gid: 0,
            size: 0,
            fsid: 1,
            fileid,
            atime: 0,
            mtime: 0,
            ctime: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// NfsEntry
// ---------------------------------------------------------------------------

/// A single NFS directory entry.
///
/// Returned by READDIR (without attributes) or READDIRPLUS (with attributes).
#[derive(Debug, Clone)]
pub struct NfsEntry {
    /// Opaque server-assigned cookie for resuming READDIR.
    pub cookie: u64,
    /// File name.
    pub name: [u8; NFS_MAXNAMLEN],
    /// Length of the name.
    pub name_len: usize,
    /// Server-side inode number (`fileid`).
    pub ino: u64,
    /// File type (NFS_DT_* constant).
    pub d_type: u8,
    /// File attributes (populated by READDIRPLUS; None for plain READDIR).
    pub attrs: Option<NfsFattr>,
}

impl NfsEntry {
    /// Create a new directory entry.
    ///
    /// Returns `Err(InvalidArgument)` if the name exceeds `NFS_MAXNAMLEN`.
    pub fn new(cookie: u64, name: &[u8], ino: u64, d_type: u8) -> Result<Self> {
        if name.len() > NFS_MAXNAMLEN {
            return Err(Error::InvalidArgument);
        }
        let mut entry = Self {
            cookie,
            name: [0u8; NFS_MAXNAMLEN],
            name_len: name.len(),
            ino,
            d_type,
            attrs: None,
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
// NfsDirCache
// ---------------------------------------------------------------------------

/// Client-side directory entry cache for a single directory.
pub struct NfsDirCache {
    /// Server-assigned directory inode number.
    pub dir_ino: u64,
    entries: [Option<NfsEntry>; DIR_CACHE_SIZE],
    count: usize,
    /// Cookie of the last entry seen (for resuming READDIR).
    pub last_cookie: u64,
    /// Cache is still valid (no server change detected).
    pub valid: bool,
}

impl NfsDirCache {
    /// Create an empty directory cache.
    pub fn new(dir_ino: u64) -> Self {
        Self {
            dir_ino,
            entries: core::array::from_fn(|_| None),
            count: 0,
            last_cookie: 0,
            valid: true,
        }
    }

    /// Insert or update an entry in the cache.
    pub fn insert(&mut self, entry: NfsEntry) -> Result<()> {
        // Check for existing entry with same name.
        for slot in self.entries[..self.count].iter_mut().flatten() {
            if slot.name_bytes() == entry.name_bytes() {
                *slot = entry;
                return Ok(());
            }
        }
        if self.count >= DIR_CACHE_SIZE {
            return Err(Error::OutOfMemory);
        }
        self.last_cookie = entry.cookie;
        self.entries[self.count] = Some(entry);
        self.count += 1;
        Ok(())
    }

    /// Look up an entry by name.
    pub fn find(&self, name: &[u8]) -> Option<&NfsEntry> {
        for slot in self.entries[..self.count].iter().flatten() {
            if slot.name_bytes() == name {
                return Some(slot);
            }
        }
        None
    }

    /// Remove a cached entry by name.
    pub fn remove(&mut self, name: &[u8]) -> bool {
        for i in 0..self.count {
            if let Some(e) = &self.entries[i] {
                if e.name_bytes() == name {
                    if i < self.count - 1 {
                        self.entries.swap(i, self.count - 1);
                    }
                    self.entries[self.count - 1] = None;
                    self.count -= 1;
                    return true;
                }
            }
        }
        false
    }

    /// Invalidate the cache (e.g., on server change detection via verifier).
    pub fn invalidate(&mut self) {
        for slot in self.entries[..self.count].iter_mut() {
            *slot = None;
        }
        self.count = 0;
        self.last_cookie = 0;
        self.valid = false;
    }
}

// ---------------------------------------------------------------------------
// nfs_readdir
// ---------------------------------------------------------------------------

/// Simulate a READDIRPLUS response and populate the cache.
///
/// In a real implementation this triggers an RPC. Here we populate the
/// cache with the supplied `server_entries` (as the RPC callback would).
///
/// Returns the number of entries added to `cache`.
pub fn nfs_readdir(cache: &mut NfsDirCache, server_entries: &[NfsEntry]) -> Result<usize> {
    if !cache.valid {
        cache.valid = true;
    }
    let count = server_entries.len().min(MAX_READDIR_ENTRIES);
    let mut added = 0;
    for entry in &server_entries[..count] {
        cache.insert(entry.clone())?;
        added += 1;
    }
    Ok(added)
}

// ---------------------------------------------------------------------------
// nfs_lookup
// ---------------------------------------------------------------------------

/// Look up a name in an NFS directory.
///
/// Returns the cache entry if found, or `Err(NotFound)`.
pub fn nfs_lookup<'a>(cache: &'a NfsDirCache, name: &[u8]) -> Result<&'a NfsEntry> {
    cache.find(name).ok_or(Error::NotFound)
}

// ---------------------------------------------------------------------------
// nfs_create
// ---------------------------------------------------------------------------

/// Create a new entry in the directory cache (simulating a server CREATE/MKDIR).
///
/// In a real client this would issue CREATE/MKDIR RPC first, then populate
/// the cache with the returned `fh` and `fattr`.
pub fn nfs_create(
    cache: &mut NfsDirCache,
    name: &[u8],
    ino: u64,
    d_type: u8,
    attrs: Option<NfsFattr>,
) -> Result<()> {
    if cache.find(name).is_some() {
        return Err(Error::AlreadyExists);
    }
    let cookie = cache.last_cookie + 1;
    let mut entry = NfsEntry::new(cookie, name, ino, d_type)?;
    entry.attrs = attrs;
    cache.insert(entry)
}

// ---------------------------------------------------------------------------
// nfs_remove
// ---------------------------------------------------------------------------

/// Remove an entry from the directory cache (simulating REMOVE/RMDIR RPC).
///
/// Returns `Err(NotFound)` if the name is not cached.
pub fn nfs_remove(cache: &mut NfsDirCache, name: &[u8]) -> Result<()> {
    if cache.remove(name) {
        Ok(())
    } else {
        Err(Error::NotFound)
    }
}

// ---------------------------------------------------------------------------
// nfs_rename
// ---------------------------------------------------------------------------

/// Rename an entry within the directory cache.
///
/// Updates the cached name in-place to simulate an NFS RENAME reply.
/// Returns `Err(NotFound)` if `old_name` is not cached.
/// Returns `Err(AlreadyExists)` if `new_name` is already present.
pub fn nfs_rename(cache: &mut NfsDirCache, old_name: &[u8], new_name: &[u8]) -> Result<()> {
    if new_name.len() > NFS_MAXNAMLEN {
        return Err(Error::InvalidArgument);
    }
    if cache.find(new_name).is_some() {
        return Err(Error::AlreadyExists);
    }
    for slot in cache.entries[..cache.count].iter_mut().flatten() {
        if slot.name_bytes() == old_name {
            slot.name[..new_name.len()].copy_from_slice(new_name);
            if new_name.len() < old_name.len() {
                slot.name[new_name.len()..old_name.len()].fill(0);
            }
            slot.name_len = new_name.len();
            return Ok(());
        }
    }
    Err(Error::NotFound)
}

// ---------------------------------------------------------------------------
// Directory cache invalidation helpers
// ---------------------------------------------------------------------------

/// Build a String representation of a directory listing for debugging.
pub fn dir_listing(cache: &NfsDirCache) -> String {
    let mut s = String::new();
    for slot in cache.entries[..cache.count].iter().flatten() {
        if !s.is_empty() {
            s.push('\n');
        }
        s.push_str(core::str::from_utf8(slot.name_bytes()).unwrap_or("<invalid>"));
    }
    s
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_readdir_and_lookup() {
        let mut cache = NfsDirCache::new(10);
        let entries = vec![
            NfsEntry::new(1, b"foo", 100, NFS_DT_REG).unwrap(),
            NfsEntry::new(2, b"bar", 101, NFS_DT_DIR).unwrap(),
        ];
        let n = nfs_readdir(&mut cache, &entries).unwrap();
        assert_eq!(n, 2);
        let e = nfs_lookup(&cache, b"foo").unwrap();
        assert_eq!(e.ino, 100);
    }

    #[test]
    fn test_create_remove() {
        let mut cache = NfsDirCache::new(10);
        nfs_create(&mut cache, b"newfile", 200, NFS_DT_REG, None).unwrap();
        assert!(nfs_lookup(&cache, b"newfile").is_ok());
        nfs_remove(&mut cache, b"newfile").unwrap();
        assert!(nfs_lookup(&cache, b"newfile").is_err());
    }

    #[test]
    fn test_rename() {
        let mut cache = NfsDirCache::new(10);
        nfs_create(&mut cache, b"old", 300, NFS_DT_REG, None).unwrap();
        nfs_rename(&mut cache, b"old", b"new").unwrap();
        assert!(nfs_lookup(&cache, b"new").is_ok());
        assert!(nfs_lookup(&cache, b"old").is_err());
    }
}
