// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! ReiserFS v3 filesystem.
//!
//! ReiserFS was one of the first production journaled filesystems for Linux
//! (merged in 2.4.1, 2001). Its key innovation is a single B+tree (the
//! "S+tree") that stores all filesystem objects — inodes, directories, and
//! file data tails — as typed items keyed by `(object_id, offset, type)`.
//!
//! # Key Concepts
//!
//! - **S+tree**: The main B+tree. All items are addressable by a 128-bit key.
//! - **Leaf node**: Contains actual items (directory entries, stat data, etc.).
//! - **Internal node**: Contains disk block pointers and delimiter keys.
//! - **Direct items**: Small file data stored in the tree ("tail packing").
//! - **Indirect items**: Block array pointers for large files.
//! - **Journal**: Write-ahead log for crash recovery.
//!
//! # References
//!
//! - Linux `fs/reiserfs/`
//! - ReiserFS white paper by Hans Reiser

use oncrix_lib::{Error, Result};

/// ReiserFS superblock magic for v3.6.
pub const REISERFS_MAGIC_V36: u64 = 0x5265497345724673; // "ReIsErFs"
/// ReiserFS superblock magic for v3.5.
pub const REISERFS_MAGIC_V35: u64 = 0x7265497345724673; // "reIsErFs"
/// Maximum filename length.
pub const REISERFS_NAME_MAX: usize = 255;
/// Maximum in-memory items.
pub const MAX_ITEMS: usize = 1024;
/// Maximum in-memory directory entries.
pub const MAX_DIR_ENTRIES: usize = 512;

/// Item type discriminant in the S+tree.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ItemType {
    /// Stat data (inode metadata).
    StatData,
    /// Directory item (list of directory entries).
    Directory,
    /// Direct item (small file data, tail-packed).
    Direct,
    /// Indirect item (array of block pointers).
    Indirect,
    /// Empty item.
    Empty,
}

/// 128-bit S+tree key: `(dirid, objectid, offset_type)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct ReiserKey {
    /// Directory ID (parent object ID).
    pub dir_id: u32,
    /// Object ID (inode number).
    pub object_id: u32,
    /// Byte offset within the object (upper 60 bits) + type (lower 4 bits).
    pub offset_type: u64,
}

impl ReiserKey {
    /// Create a stat data key (offset = 0, type = StatData).
    pub fn stat(dir_id: u32, object_id: u32) -> Self {
        Self {
            dir_id,
            object_id,
            offset_type: 0,
        }
    }

    /// Create a directory key (offset = 0, type = Directory = 0x0200...).
    pub fn dir(dir_id: u32, object_id: u32) -> Self {
        Self {
            dir_id,
            object_id,
            offset_type: 0x0200_0000_0000_0000,
        }
    }

    /// Create a data key at byte `offset`.
    pub fn data(dir_id: u32, object_id: u32, offset: u64) -> Self {
        Self {
            dir_id,
            object_id,
            offset_type: offset,
        }
    }

    /// Extract the byte offset.
    pub fn offset(&self) -> u64 {
        self.offset_type & !0xF
    }

    /// Extract the type nibble.
    pub fn type_nibble(&self) -> u8 {
        (self.offset_type & 0xF) as u8
    }
}

/// Stat data item (corresponds to on-disk stat_data v2 for 3.6).
#[derive(Debug, Clone, Copy, Default)]
pub struct ReiserStatData {
    /// File mode bits.
    pub mode: u16,
    /// Hard link count.
    pub nlink: u32,
    /// File size in bytes.
    pub size: u64,
    /// Owner UID.
    pub uid: u32,
    /// Owner GID.
    pub gid: u32,
    /// Access time (Unix seconds).
    pub atime: u32,
    /// Modification time.
    pub mtime: u32,
    /// Change time.
    pub ctime: u32,
    /// Number of allocated blocks (512-byte units).
    pub blocks: u32,
    /// First direct byte (0 = no tail).
    pub first_direct_byte: u32,
}

/// A directory entry within a ReiserFS directory item.
#[derive(Debug, Clone, Copy)]
pub struct ReiserDirEntry {
    /// Object ID of the entry target.
    pub object_id: u32,
    /// Directory ID of the entry target.
    pub dir_id: u32,
    /// State flags (1 = visible).
    pub state: u16,
    /// Entry name.
    name: [u8; REISERFS_NAME_MAX],
    name_len: u8,
}

impl ReiserDirEntry {
    /// Create a directory entry.
    pub fn new(dir_id: u32, object_id: u32, name: &[u8]) -> Result<Self> {
        if name.is_empty() || name.len() > REISERFS_NAME_MAX {
            return Err(Error::InvalidArgument);
        }
        let mut buf = [0u8; REISERFS_NAME_MAX];
        buf[..name.len()].copy_from_slice(name);
        Ok(Self {
            object_id,
            dir_id,
            state: 1,
            name: buf,
            name_len: name.len() as u8,
        })
    }

    /// Return name bytes.
    pub fn name(&self) -> &[u8] {
        &self.name[..self.name_len as usize]
    }

    /// True if visible (not deleted).
    pub fn is_visible(&self) -> bool {
        self.state & 1 != 0
    }
}

/// An item stored in the S+tree.
#[derive(Debug, Clone)]
pub struct ReiserItem {
    /// Key identifying this item.
    pub key: ReiserKey,
    /// Item type.
    pub item_type: ItemType,
    /// Stat data (valid for `StatData` items).
    pub stat: Option<ReiserStatData>,
    /// Directory entries (valid for `Directory` items).
    pub dir_entries: [Option<ReiserDirEntry>; 32],
    pub dir_count: usize,
    /// Direct data (valid for `Direct` items, up to 4 KB).
    pub direct_data: [u8; 4096],
    pub direct_len: usize,
    /// Indirect block pointers (valid for `Indirect` items).
    pub indirect_blocks: [u32; 128],
    pub indirect_count: usize,
}

impl ReiserItem {
    /// Create a stat data item.
    pub fn new_stat(key: ReiserKey, stat: ReiserStatData) -> Self {
        Self {
            key,
            item_type: ItemType::StatData,
            stat: Some(stat),
            dir_entries: [const { None }; 32],
            dir_count: 0,
            direct_data: [0u8; 4096],
            direct_len: 0,
            indirect_blocks: [0u32; 128],
            indirect_count: 0,
        }
    }

    /// Create a directory item.
    pub fn new_dir(key: ReiserKey) -> Self {
        Self {
            key,
            item_type: ItemType::Directory,
            stat: None,
            dir_entries: [const { None }; 32],
            dir_count: 0,
            direct_data: [0u8; 4096],
            direct_len: 0,
            indirect_blocks: [0u32; 128],
            indirect_count: 0,
        }
    }

    /// Add a directory entry to a Directory item.
    pub fn add_dir_entry(&mut self, entry: ReiserDirEntry) -> Result<()> {
        if self.item_type != ItemType::Directory {
            return Err(Error::InvalidArgument);
        }
        if self.dir_count >= 32 {
            return Err(Error::OutOfMemory);
        }
        // Check for duplicates.
        for i in 0..self.dir_count {
            if let Some(ref e) = self.dir_entries[i] {
                if e.name() == entry.name() {
                    return Err(Error::AlreadyExists);
                }
            }
        }
        self.dir_entries[self.dir_count] = Some(entry);
        self.dir_count += 1;
        Ok(())
    }

    /// Lookup a name in a Directory item.
    pub fn lookup_dir(&self, name: &[u8]) -> Option<(u32, u32)> {
        if self.item_type != ItemType::Directory {
            return None;
        }
        self.dir_entries[..self.dir_count]
            .iter()
            .filter_map(|e| e.as_ref())
            .find(|e| e.name() == name && e.is_visible())
            .map(|e| (e.dir_id, e.object_id))
    }
}

/// In-memory S+tree (simplified flat array for this implementation).
pub struct ReiserSTree {
    items: [Option<ReiserItem>; MAX_ITEMS],
    count: usize,
}

impl ReiserSTree {
    /// Create an empty S+tree.
    pub const fn new() -> Self {
        Self {
            items: [const { None }; MAX_ITEMS],
            count: 0,
        }
    }

    /// Insert an item. Returns `AlreadyExists` if the key is taken.
    pub fn insert(&mut self, item: ReiserItem) -> Result<()> {
        if self.find(&item.key).is_some() {
            return Err(Error::AlreadyExists);
        }
        if self.count >= MAX_ITEMS {
            return Err(Error::OutOfMemory);
        }
        self.items[self.count] = Some(item);
        self.count += 1;
        Ok(())
    }

    /// Find item by key (immutable).
    pub fn find(&self, key: &ReiserKey) -> Option<&ReiserItem> {
        self.items[..self.count]
            .iter()
            .filter_map(|i| i.as_ref())
            .find(|i| &i.key == key)
    }

    /// Find item by key (mutable).
    pub fn find_mut(&mut self, key: &ReiserKey) -> Option<&mut ReiserItem> {
        self.items[..self.count]
            .iter_mut()
            .filter_map(|i| i.as_mut())
            .find(|i| &i.key == key)
    }

    /// Remove item by key.
    pub fn remove(&mut self, key: &ReiserKey) -> Result<()> {
        let pos = self.items[..self.count]
            .iter()
            .position(|i| i.as_ref().map(|i| &i.key == key).unwrap_or(false));
        match pos {
            None => Err(Error::NotFound),
            Some(idx) => {
                self.count -= 1;
                self.items[idx] = self.items[self.count].take();
                Ok(())
            }
        }
    }

    /// Total item count.
    pub fn count(&self) -> usize {
        self.count
    }
}

impl Default for ReiserSTree {
    fn default() -> Self {
        Self::new()
    }
}

/// ReiserFS superblock (in-memory).
#[derive(Debug, Clone, Copy)]
pub struct ReiserSuperblock {
    pub block_count: u32,
    pub free_blocks: u32,
    pub root_block: u32,
    pub journal_block: u32,
    pub journal_size: u32,
    pub block_size: u16,
    pub oid_maxsize: u16,
    pub oid_cursize: u16,
    pub magic: u64,
    pub version: u16,
    pub tree_height: u16,
    pub bmap_nr: u16,
}

impl ReiserSuperblock {
    /// Create a default ReiserFS 3.6 superblock.
    pub fn new(block_count: u32, block_size: u16) -> Self {
        Self {
            block_count,
            free_blocks: block_count.saturating_sub(64),
            root_block: 64,
            journal_block: 18,
            journal_size: 8192,
            block_size,
            oid_maxsize: 1024,
            oid_cursize: 2,
            magic: REISERFS_MAGIC_V36,
            version: 2,
            tree_height: 2,
            bmap_nr: 1,
        }
    }

    /// True if magic matches a known ReiserFS version.
    pub fn is_valid(&self) -> bool {
        self.magic == REISERFS_MAGIC_V36 || self.magic == REISERFS_MAGIC_V35
    }
}

/// Object ID allocator for ReiserFS (object IDs are 32-bit).
pub struct OidAllocator {
    next_oid: u32,
    max_oid: u32,
}

impl OidAllocator {
    /// Create allocator starting at `start` with maximum `max_oid`.
    pub fn new(start: u32, max_oid: u32) -> Self {
        Self {
            next_oid: start,
            max_oid,
        }
    }

    /// Allocate one object ID.
    pub fn alloc(&mut self) -> Result<u32> {
        if self.next_oid >= self.max_oid {
            return Err(Error::OutOfMemory);
        }
        let oid = self.next_oid;
        self.next_oid += 1;
        Ok(oid)
    }

    /// Current next OID (for superblock persistence).
    pub fn next(&self) -> u32 {
        self.next_oid
    }
}
