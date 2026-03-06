// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Btrfs inode operations.
//!
//! Implements Btrfs inode item structures and lifecycle operations:
//! - [`BtrfsInodeItem`] — on-disk inode record stored in the B-tree
//! - Inode cache with lookup-by-ino table
//! - [`btrfs_inode_lookup`], [`btrfs_inode_create`], [`btrfs_inode_unlink`]
//! - Inline data support (small files stored directly in the B-tree leaf)
//!
//! # Btrfs Inode Layout
//!
//! Btrfs stores each inode as a `BTRFS_INODE_ITEM_KEY` item in the
//! filesystem tree. The item data is a fixed-size `BtrfsInodeItem`
//! (160 bytes on disk). File data for very small files (≤ inline threshold)
//! is stored as a `BTRFS_INLINE_EXTENT` immediately following the inode
//! item in the tree leaf.
//!
//! # References
//! - Linux `fs/btrfs/inode.c`, `fs/btrfs/ctree.h`

extern crate alloc;
use alloc::vec::Vec;
use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum inodes in the inode cache.
const MAX_INODES: usize = 512;

/// Inline data threshold: files ≤ this many bytes are stored inline.
pub const BTRFS_INLINE_LIMIT: usize = 2048;

/// Btrfs inode item type key.
pub const BTRFS_INODE_ITEM_KEY: u8 = 1;

/// Btrfs inline extent item type key.
pub const BTRFS_INLINE_EXTENT_KEY: u8 = 18;

// ---------------------------------------------------------------------------
// File type flags (stored in BtrfsInodeItem.mode, top 4 bits)
// ---------------------------------------------------------------------------

/// Regular file.
pub const S_IFREG: u32 = 0o100000;
/// Directory.
pub const S_IFDIR: u32 = 0o040000;
/// Symbolic link.
pub const S_IFLNK: u32 = 0o120000;
/// Character device.
pub const S_IFCHR: u32 = 0o020000;
/// Block device.
pub const S_IFBLK: u32 = 0o060000;
/// FIFO.
pub const S_IFIFO: u32 = 0o010000;
/// Socket.
pub const S_IFSOCK: u32 = 0o140000;

// ---------------------------------------------------------------------------
// BtrfsInodeItem
// ---------------------------------------------------------------------------

/// Btrfs on-disk inode item (`btrfs_inode_item`).
///
/// Stored as a B-tree item with key `(ino, BTRFS_INODE_ITEM_KEY, 0)`.
#[derive(Debug, Clone, Copy)]
pub struct BtrfsInodeItem {
    /// Transaction generation when the inode was created.
    pub generation: u64,
    /// Transaction generation of the last modification.
    pub transid: u64,
    /// File size in bytes.
    pub size: u64,
    /// Number of bytes allocated on disk.
    pub nbytes: u64,
    /// Block group hint.
    pub block_group: u64,
    /// Hard link count.
    pub nlink: u32,
    /// Owner user ID.
    pub uid: u32,
    /// Owner group ID.
    pub gid: u32,
    /// File mode (type + permissions).
    pub mode: u32,
    /// Device number for char/block devices.
    pub rdev: u64,
    /// Btrfs inode flags.
    pub flags: u64,
    /// Sequence number (NFS-compatible change counter).
    pub sequence: u64,
    /// Access time (seconds).
    pub atime_sec: i64,
    /// Access time (nanoseconds).
    pub atime_nsec: u32,
    /// Creation time (seconds).
    pub ctime_sec: i64,
    /// Creation time (nanoseconds).
    pub ctime_nsec: u32,
    /// Modification time (seconds).
    pub mtime_sec: i64,
    /// Modification time (nanoseconds).
    pub mtime_nsec: u32,
    /// Inode change time (seconds).
    pub otime_sec: i64,
    /// Inode change time (nanoseconds).
    pub otime_nsec: u32,
}

impl BtrfsInodeItem {
    /// Create a new inode item for a regular file with default timestamps.
    pub fn new_file(uid: u32, gid: u32, mode: u32) -> Self {
        Self {
            generation: 1,
            transid: 1,
            size: 0,
            nbytes: 0,
            block_group: 0,
            nlink: 1,
            uid,
            gid,
            mode: S_IFREG | (mode & 0o7777),
            rdev: 0,
            flags: 0,
            sequence: 1,
            atime_sec: 0,
            atime_nsec: 0,
            ctime_sec: 0,
            ctime_nsec: 0,
            mtime_sec: 0,
            mtime_nsec: 0,
            otime_sec: 0,
            otime_nsec: 0,
        }
    }

    /// Create a new inode item for a directory.
    pub fn new_dir(uid: u32, gid: u32, mode: u32) -> Self {
        let mut item = Self::new_file(uid, gid, mode);
        item.mode = S_IFDIR | (mode & 0o7777);
        item.nlink = 2; // "." + parent's entry
        item
    }

    /// Return true if this inode represents a regular file.
    pub fn is_file(&self) -> bool {
        self.mode & 0o170000 == S_IFREG
    }

    /// Return true if this inode represents a directory.
    pub fn is_dir(&self) -> bool {
        self.mode & 0o170000 == S_IFDIR
    }
}

// ---------------------------------------------------------------------------
// BtrfsInodeCacheEntry
// ---------------------------------------------------------------------------

/// A cached inode entry: inode number + inode item + optional inline data.
pub struct BtrfsInodeCacheEntry {
    /// Inode number.
    pub ino: u64,
    /// The on-disk inode item.
    pub item: BtrfsInodeItem,
    /// Inline file data (None if the file uses extents or is a directory).
    pub inline_data: Option<Vec<u8>>,
    /// Reference count (open file descriptors + directory references).
    pub refcount: u32,
}

impl BtrfsInodeCacheEntry {
    /// Create a new cache entry for an inode.
    pub fn new(ino: u64, item: BtrfsInodeItem) -> Self {
        Self {
            ino,
            item,
            inline_data: None,
            refcount: 1,
        }
    }
}

// ---------------------------------------------------------------------------
// BtrfsInodeCache
// ---------------------------------------------------------------------------

/// Fixed-capacity inode cache for a Btrfs filesystem tree.
pub struct BtrfsInodeCache {
    entries: [Option<BtrfsInodeCacheEntry>; MAX_INODES],
    count: usize,
    next_ino: u64,
}

impl BtrfsInodeCache {
    /// Create an empty inode cache, pre-allocating inode 1 (tree root).
    pub fn new() -> Self {
        let mut cache = Self {
            entries: core::array::from_fn(|_| None),
            count: 0,
            next_ino: 256, // Btrfs first user inode starts at 256.
        };
        // Reserve inode 256 as the root directory.
        let root_item = BtrfsInodeItem::new_dir(0, 0, 0o755);
        cache
            .insert_entry(BtrfsInodeCacheEntry::new(256, root_item))
            .ok();
        cache
    }

    fn insert_entry(&mut self, entry: BtrfsInodeCacheEntry) -> Result<usize> {
        if self.count >= MAX_INODES {
            return Err(Error::OutOfMemory);
        }
        let idx = self.count;
        self.entries[idx] = Some(entry);
        self.count += 1;
        Ok(idx)
    }

    fn find_idx(&self, ino: u64) -> Option<usize> {
        for (i, slot) in self.entries[..self.count].iter().enumerate() {
            if let Some(e) = slot {
                if e.ino == ino {
                    return Some(i);
                }
            }
        }
        None
    }

    /// Allocate the next available inode number.
    fn alloc_ino(&mut self) -> u64 {
        let ino = self.next_ino;
        self.next_ino += 1;
        ino
    }
}

impl Default for BtrfsInodeCache {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Public inode operations
// ---------------------------------------------------------------------------

/// Look up an inode by number.
///
/// Returns `Err(NotFound)` if the inode is not in cache.
pub fn btrfs_inode_lookup(cache: &BtrfsInodeCache, ino: u64) -> Result<&BtrfsInodeCacheEntry> {
    let idx = cache.find_idx(ino).ok_or(Error::NotFound)?;
    cache.entries[idx].as_ref().ok_or(Error::NotFound)
}

/// Create a new regular-file inode and insert it into the cache.
///
/// Returns the allocated inode number on success.
pub fn btrfs_inode_create(
    cache: &mut BtrfsInodeCache,
    uid: u32,
    gid: u32,
    mode: u32,
) -> Result<u64> {
    let ino = cache.alloc_ino();
    let item = BtrfsInodeItem::new_file(uid, gid, mode);
    let entry = BtrfsInodeCacheEntry::new(ino, item);
    cache.insert_entry(entry)?;
    Ok(ino)
}

/// Create a new directory inode.
///
/// Returns the allocated inode number on success.
pub fn btrfs_dir_create(cache: &mut BtrfsInodeCache, uid: u32, gid: u32, mode: u32) -> Result<u64> {
    let ino = cache.alloc_ino();
    let item = BtrfsInodeItem::new_dir(uid, gid, mode);
    let entry = BtrfsInodeCacheEntry::new(ino, item);
    cache.insert_entry(entry)?;
    Ok(ino)
}

/// Unlink (remove) an inode from the cache.
///
/// Decrements the nlink count; removes when nlink reaches zero.
/// Returns `Err(NotFound)` if `ino` is not cached.
pub fn btrfs_inode_unlink(cache: &mut BtrfsInodeCache, ino: u64) -> Result<()> {
    let idx = cache.find_idx(ino).ok_or(Error::NotFound)?;
    if let Some(entry) = cache.entries[idx].as_mut() {
        if entry.item.nlink == 0 {
            return Err(Error::InvalidArgument);
        }
        entry.item.nlink -= 1;
        if entry.item.nlink == 0 {
            cache.entries[idx] = None;
            // Compact.
            if idx < cache.count - 1 {
                cache.entries.swap(idx, cache.count - 1);
            }
            cache.count -= 1;
        }
    }
    Ok(())
}

/// Write inline data to an inode.
///
/// Only valid for regular files with data ≤ `BTRFS_INLINE_LIMIT`.
/// Returns `Err(InvalidArgument)` when data exceeds the inline limit.
pub fn btrfs_write_inline(cache: &mut BtrfsInodeCache, ino: u64, data: &[u8]) -> Result<()> {
    if data.len() > BTRFS_INLINE_LIMIT {
        return Err(Error::InvalidArgument);
    }
    let idx = cache.find_idx(ino).ok_or(Error::NotFound)?;
    if let Some(entry) = cache.entries[idx].as_mut() {
        if !entry.item.is_file() {
            return Err(Error::InvalidArgument);
        }
        entry.item.size = data.len() as u64;
        entry.item.nbytes = data.len() as u64;
        entry.inline_data = Some(data.to_vec());
    }
    Ok(())
}

/// Read inline data from an inode.
///
/// Returns `Err(NotFound)` if no inline data is present.
pub fn btrfs_read_inline(cache: &BtrfsInodeCache, ino: u64) -> Result<Vec<u8>> {
    let idx = cache.find_idx(ino).ok_or(Error::NotFound)?;
    if let Some(entry) = &cache.entries[idx] {
        if let Some(data) = &entry.inline_data {
            return Ok(data.clone());
        }
    }
    Err(Error::NotFound)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_and_lookup() {
        let mut cache = BtrfsInodeCache::new();
        let ino = btrfs_inode_create(&mut cache, 1000, 1000, 0o644).unwrap();
        let entry = btrfs_inode_lookup(&cache, ino).unwrap();
        assert!(entry.item.is_file());
    }

    #[test]
    fn test_inline_write_read() {
        let mut cache = BtrfsInodeCache::new();
        let ino = btrfs_inode_create(&mut cache, 0, 0, 0o644).unwrap();
        btrfs_write_inline(&mut cache, ino, b"hello btrfs").unwrap();
        let data = btrfs_read_inline(&cache, ino).unwrap();
        assert_eq!(data, b"hello btrfs");
    }

    #[test]
    fn test_unlink() {
        let mut cache = BtrfsInodeCache::new();
        let ino = btrfs_inode_create(&mut cache, 0, 0, 0o644).unwrap();
        btrfs_inode_unlink(&mut cache, ino).unwrap();
        assert!(btrfs_inode_lookup(&cache, ino).is_err());
    }
}
