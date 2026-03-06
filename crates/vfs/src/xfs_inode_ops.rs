// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! XFS inode operations.
//!
//! Implements XFS inode on-disk structures and lifecycle operations:
//! - [`XfsDinode`] — on-disk inode (`xfs_dinode_t`)
//! - [`xfs_iget`] — look up and reference an inode from the cache
//! - [`xfs_iput`] — release an inode reference
//! - [`xfs_ialloc`] — allocate a new inode
//! - [`xfs_ifree`] — free an inode back to the allocation bitmap
//! - Data and attribute fork management (`forkoff`)
//!
//! # XFS Inode Layout
//!
//! Each XFS inode is 512 bytes (by default) and consists of:
//! - A fixed 176-byte header (`xfs_dinode_core`)
//! - A data fork: file data (extents, B-tree root, or inline data)
//! - An optional attribute fork: xattr extents / short-form attrs
//!
//! The `forkoff` field in the core splits the remaining 336 bytes between
//! data fork and attribute fork.
//!
//! # References
//! - Linux `fs/xfs/xfs_inode.c`, `fs/xfs/libxfs/xfs_format.h`

extern crate alloc;
use alloc::vec::Vec;
use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// XFS inode magic.
pub const XFS_DINODE_MAGIC: u16 = 0x494E; // "IN"

/// XFS inode version 3 (supports CRC and project quota).
pub const XFS_DINODE_VERSION3: u8 = 3;

/// Maximum inodes in the inode cache.
const MAX_INODES: usize = 512;

/// Maximum xattr data in the attribute fork (simplified).
const MAX_ATTR_FORK: usize = 256;

/// Maximum inline data in the data fork.
const MAX_INLINE_DATA: usize = 336;

// ---------------------------------------------------------------------------
// Format constants (di_format)
// ---------------------------------------------------------------------------

/// Inode has no data (e.g., empty directory/symlink).
pub const XFS_DINODE_FMT_EXTENTS: u8 = 2;
/// Inode stores data inline in the fork area.
pub const XFS_DINODE_FMT_LOCAL: u8 = 1;
/// Inode stores root of a B-tree in the fork area.
pub const XFS_DINODE_FMT_BTREE: u8 = 3;
/// Inode represents a device node.
pub const XFS_DINODE_FMT_DEV: u8 = 0;

// ---------------------------------------------------------------------------
// File type / mode constants
// ---------------------------------------------------------------------------
/// Regular file mode.
pub const XFS_S_IFREG: u16 = 0o100000;
/// Directory mode.
pub const XFS_S_IFDIR: u16 = 0o040000;
/// Symbolic link mode.
pub const XFS_S_IFLNK: u16 = 0o120000;
/// Character device.
pub const XFS_S_IFCHR: u16 = 0o020000;
/// Block device.
pub const XFS_S_IFBLK: u16 = 0o060000;
/// FIFO.
pub const XFS_S_IFIFO: u16 = 0o010000;
/// Socket.
pub const XFS_S_IFSOCK: u16 = 0o140000;

// ---------------------------------------------------------------------------
// XfsDinode — on-disk inode core
// ---------------------------------------------------------------------------

/// XFS on-disk inode core (`xfs_dinode`).
///
/// This is the fixed-size header portion of an XFS inode.
#[derive(Debug, Clone, Copy)]
pub struct XfsDinode {
    /// Magic number, must be `XFS_DINODE_MAGIC`.
    pub magic: u16,
    /// File mode (type + permissions).
    pub mode: u16,
    /// Inode version (1, 2, or 3).
    pub version: u8,
    /// Data fork format (`XFS_DINODE_FMT_*`).
    pub format: u8,
    /// Owner user ID (low 16 bits).
    pub uid: u32,
    /// Owner group ID (low 16 bits).
    pub gid: u32,
    /// Hard link count.
    pub nlink: u32,
    /// Project ID (low 16 bits, for quota).
    pub projid: u32,
    /// File size in bytes.
    pub size: u64,
    /// Number of filesystem blocks used.
    pub nblocks: u64,
    /// Preferred extent size (hint).
    pub extsize: u32,
    /// Number of extents in the data fork.
    pub nextents: u32,
    /// Byte offset of attribute fork from start of inode literal area.
    /// 0 means no attribute fork.
    pub forkoff: u8,
    /// Attribute fork format.
    pub aformat: u8,
    /// Flags (XFS_DIFLAG_*).
    pub flags: u32,
    /// Access time (seconds since epoch).
    pub atime_sec: i64,
    /// Access time (nanoseconds).
    pub atime_nsec: u32,
    /// Modification time (seconds).
    pub mtime_sec: i64,
    /// Modification time (nanoseconds).
    pub mtime_nsec: u32,
    /// Change (inode) time (seconds).
    pub ctime_sec: i64,
    /// Change time (nanoseconds).
    pub ctime_nsec: u32,
    /// Generation number (v3+).
    pub generation: u32,
    /// Next unlinked pointer (agi_unlinked list).
    pub next_unlinked: u32,
}

impl XfsDinode {
    /// Create a new regular-file inode.
    pub fn new_file(uid: u32, gid: u32, mode: u16, generation: u32) -> Self {
        Self {
            magic: XFS_DINODE_MAGIC,
            mode: XFS_S_IFREG | (mode & 0o7777),
            version: XFS_DINODE_VERSION3,
            format: XFS_DINODE_FMT_EXTENTS,
            uid,
            gid,
            nlink: 1,
            projid: 0,
            size: 0,
            nblocks: 0,
            extsize: 0,
            nextents: 0,
            forkoff: 0,
            aformat: 0,
            flags: 0,
            atime_sec: 0,
            atime_nsec: 0,
            mtime_sec: 0,
            mtime_nsec: 0,
            ctime_sec: 0,
            ctime_nsec: 0,
            generation,
            next_unlinked: u32::MAX,
        }
    }

    /// Create a new directory inode.
    pub fn new_dir(uid: u32, gid: u32, mode: u16, generation: u32) -> Self {
        let mut d = Self::new_file(uid, gid, mode, generation);
        d.mode = XFS_S_IFDIR | (mode & 0o7777);
        d.format = XFS_DINODE_FMT_LOCAL;
        d.nlink = 2;
        d
    }

    /// Return true if this is a regular file.
    pub fn is_file(&self) -> bool {
        self.mode & 0o170000 == XFS_S_IFREG
    }

    /// Return true if this is a directory.
    pub fn is_dir(&self) -> bool {
        self.mode & 0o170000 == XFS_S_IFDIR
    }

    /// Return true if the magic is valid.
    pub fn is_valid(&self) -> bool {
        self.magic == XFS_DINODE_MAGIC
    }
}

// ---------------------------------------------------------------------------
// XfsInodeCacheEntry
// ---------------------------------------------------------------------------

/// Cache entry for an in-memory XFS inode.
pub struct XfsInodeCacheEntry {
    /// Inode number.
    pub ino: u64,
    /// On-disk core.
    pub core: XfsDinode,
    /// Data fork inline/extent data.
    pub data_fork: [u8; MAX_INLINE_DATA],
    /// Bytes of data fork actually used.
    pub data_fork_len: usize,
    /// Attribute fork data (short-form xattrs).
    pub attr_fork: [u8; MAX_ATTR_FORK],
    /// Bytes of attr fork used.
    pub attr_fork_len: usize,
    /// Reference count.
    pub refcount: u32,
}

impl XfsInodeCacheEntry {
    /// Create a new cache entry.
    pub fn new(ino: u64, core: XfsDinode) -> Self {
        Self {
            ino,
            core,
            data_fork: [0u8; MAX_INLINE_DATA],
            data_fork_len: 0,
            attr_fork: [0u8; MAX_ATTR_FORK],
            attr_fork_len: 0,
            refcount: 1,
        }
    }
}

// ---------------------------------------------------------------------------
// XfsInodeCache
// ---------------------------------------------------------------------------

/// Fixed-size XFS inode cache.
pub struct XfsInodeCache {
    entries: [Option<XfsInodeCacheEntry>; MAX_INODES],
    count: usize,
    next_ino: u64,
    next_generation: u32,
}

impl XfsInodeCache {
    /// Create an empty cache.
    pub fn new() -> Self {
        Self {
            entries: core::array::from_fn(|_| None),
            count: 0,
            next_ino: 128, // XFS_INO_RESERVED = 128
            next_generation: 1,
        }
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

    fn alloc_ino(&mut self) -> u64 {
        let ino = self.next_ino;
        self.next_ino += 1;
        ino
    }

    fn alloc_generation(&mut self) -> u32 {
        let g = self.next_generation;
        self.next_generation += 1;
        g
    }
}

impl Default for XfsInodeCache {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Public inode operations
// ---------------------------------------------------------------------------

/// Get (look up and increment refcount) an inode from cache.
///
/// Returns `Err(NotFound)` if not present.
pub fn xfs_iget(cache: &mut XfsInodeCache, ino: u64) -> Result<&XfsInodeCacheEntry> {
    let idx = cache.find_idx(ino).ok_or(Error::NotFound)?;
    if let Some(e) = cache.entries[idx].as_mut() {
        e.refcount += 1;
    }
    cache.entries[idx].as_ref().ok_or(Error::NotFound)
}

/// Put (decrement refcount) an inode.
///
/// If refcount reaches zero the inode may be evicted from cache.
pub fn xfs_iput(cache: &mut XfsInodeCache, ino: u64) -> Result<()> {
    let idx = cache.find_idx(ino).ok_or(Error::NotFound)?;
    if let Some(e) = cache.entries[idx].as_mut() {
        if e.refcount > 0 {
            e.refcount -= 1;
        }
        if e.refcount == 0 && e.core.nlink == 0 {
            // Evict.
            cache.entries[idx] = None;
            if idx < cache.count - 1 {
                cache.entries.swap(idx, cache.count - 1);
            }
            cache.count -= 1;
        }
    }
    Ok(())
}

/// Allocate a new inode (regular file).
///
/// Returns the new inode number.
pub fn xfs_ialloc(cache: &mut XfsInodeCache, uid: u32, gid: u32, mode: u16) -> Result<u64> {
    if cache.count >= MAX_INODES {
        return Err(Error::OutOfMemory);
    }
    let ino = cache.alloc_ino();
    let generation = cache.alloc_generation();
    let core = XfsDinode::new_file(uid, gid, mode, generation);
    let entry = XfsInodeCacheEntry::new(ino, core);
    cache.entries[cache.count] = Some(entry);
    cache.count += 1;
    Ok(ino)
}

/// Allocate a new directory inode.
pub fn xfs_dir_ialloc(cache: &mut XfsInodeCache, uid: u32, gid: u32, mode: u16) -> Result<u64> {
    if cache.count >= MAX_INODES {
        return Err(Error::OutOfMemory);
    }
    let ino = cache.alloc_ino();
    let generation = cache.alloc_generation();
    let core = XfsDinode::new_dir(uid, gid, mode, generation);
    let entry = XfsInodeCacheEntry::new(ino, core);
    cache.entries[cache.count] = Some(entry);
    cache.count += 1;
    Ok(ino)
}

/// Free an inode (unlink + drop).
///
/// Decrements nlink; removes from cache when nlink == 0.
pub fn xfs_ifree(cache: &mut XfsInodeCache, ino: u64) -> Result<()> {
    let idx = cache.find_idx(ino).ok_or(Error::NotFound)?;
    if let Some(e) = cache.entries[idx].as_mut() {
        if e.core.nlink == 0 {
            return Err(Error::InvalidArgument);
        }
        e.core.nlink -= 1;
        if e.core.nlink == 0 {
            cache.entries[idx] = None;
            if idx < cache.count - 1 {
                cache.entries.swap(idx, cache.count - 1);
            }
            cache.count -= 1;
        }
    }
    Ok(())
}

/// Write inline data to the data fork.
pub fn xfs_write_data_fork(cache: &mut XfsInodeCache, ino: u64, data: &[u8]) -> Result<()> {
    if data.len() > MAX_INLINE_DATA {
        return Err(Error::InvalidArgument);
    }
    let idx = cache.find_idx(ino).ok_or(Error::NotFound)?;
    if let Some(e) = cache.entries[idx].as_mut() {
        e.data_fork[..data.len()].copy_from_slice(data);
        e.data_fork_len = data.len();
        e.core.size = data.len() as u64;
        e.core.format = XFS_DINODE_FMT_LOCAL;
    }
    Ok(())
}

/// Read inline data from the data fork.
pub fn xfs_read_data_fork(cache: &XfsInodeCache, ino: u64) -> Result<Vec<u8>> {
    let idx = cache.find_idx(ino).ok_or(Error::NotFound)?;
    if let Some(e) = &cache.entries[idx] {
        return Ok(e.data_fork[..e.data_fork_len].to_vec());
    }
    Err(Error::NotFound)
}

/// Write data to the attribute fork (short-form xattrs).
pub fn xfs_write_attr_fork(cache: &mut XfsInodeCache, ino: u64, data: &[u8]) -> Result<()> {
    if data.len() > MAX_ATTR_FORK {
        return Err(Error::InvalidArgument);
    }
    let idx = cache.find_idx(ino).ok_or(Error::NotFound)?;
    if let Some(e) = cache.entries[idx].as_mut() {
        e.attr_fork[..data.len()].copy_from_slice(data);
        e.attr_fork_len = data.len();
        // Set forkoff to indicate attr fork presence.
        if e.core.forkoff == 0 {
            e.core.forkoff = 1; // simplified
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ialloc_iget_ifree() {
        let mut cache = XfsInodeCache::new();
        let ino = xfs_ialloc(&mut cache, 0, 0, 0o644).unwrap();
        {
            let e = xfs_iget(&mut cache, ino).unwrap();
            assert!(e.core.is_file());
        }
        xfs_ifree(&mut cache, ino).unwrap();
        assert!(cache.find_idx(ino).is_none());
    }

    #[test]
    fn test_data_fork() {
        let mut cache = XfsInodeCache::new();
        let ino = xfs_ialloc(&mut cache, 0, 0, 0o644).unwrap();
        xfs_write_data_fork(&mut cache, ino, b"xfs_data").unwrap();
        let data = xfs_read_data_fork(&cache, ino).unwrap();
        assert_eq!(data, b"xfs_data");
    }
}
