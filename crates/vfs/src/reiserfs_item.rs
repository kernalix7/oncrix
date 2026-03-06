// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! ReiserFS item layer — item types, keys, and item header parsing.
//!
//! ReiserFS stores all filesystem data in a single balanced tree (the "S+ tree").
//! Every piece of data — directory entries, file extents, stat data, indirect
//! blocks — is an "item" in this tree. Items are identified by a 16-byte key.
//!
//! # Item Types
//!
//! | Type | ID | Description |
//! |------|----|-------------|
//! | Stat data | 0 | Inode metadata (uid, gid, mode, size, timestamps) |
//! | Indirect item | 1 | Array of block pointers for file data |
//! | Direct item | 2 | Inline file data (tail packing) |
//! | Directory item | 3 | Array of directory entries |
//!
//! # Key Format
//!
//! ReiserFS v3.6 keys are 16 bytes: `{dir_id, objectid, offset_and_type}`.
//! The `offset_and_type` field encodes both the item's byte offset within
//! the file and the item type in the high 4 bits.

use oncrix_lib::{Error, Result};

/// Item type codes stored in the high 4 bits of the key's `offset_type` field.
pub mod item_type {
    /// Inode metadata (stat data).
    pub const STAT_DATA: u8 = 0x0;
    /// Indirect item (block pointer array).
    pub const INDIRECT: u8 = 0x1;
    /// Direct item (inline tail data).
    pub const DIRECT: u8 = 0x2;
    /// Directory item (direntry array).
    pub const DIRECTORY: u8 = 0x3;
}

/// A ReiserFS item key (16 bytes, v3.6 format).
#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub struct Key {
    /// Directory ID (parent object ID for directories; object ID for files).
    pub dir_id: u32,
    /// Object ID.
    pub object_id: u32,
    /// Byte offset of the item within the object.
    pub offset: u64,
    /// Item type encoded in the high 4 bits; lower bits are part of `offset` type.
    pub type_code: u8,
}

impl Key {
    /// Parses a v3.6 key from 16 raw bytes.
    pub fn from_bytes(b: &[u8]) -> Result<Self> {
        if b.len() < 16 {
            return Err(Error::InvalidArgument);
        }
        let dir_id = u32::from_le_bytes([b[0], b[1], b[2], b[3]]);
        let object_id = u32::from_le_bytes([b[4], b[5], b[6], b[7]]);
        let raw_offset = u64::from_le_bytes([b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]]);
        // Upper 4 bits of the 64-bit value encode the item type.
        let type_code = ((raw_offset >> 60) & 0x0F) as u8;
        let offset = raw_offset & 0x0FFF_FFFF_FFFF_FFFF;
        Ok(Self {
            dir_id,
            object_id,
            offset,
            type_code,
        })
    }

    /// Serializes this key into 16 bytes.
    pub fn to_bytes(&self, b: &mut [u8; 16]) {
        b[0..4].copy_from_slice(&self.dir_id.to_le_bytes());
        b[4..8].copy_from_slice(&self.object_id.to_le_bytes());
        let raw = self.offset | ((self.type_code as u64) << 60);
        b[8..16].copy_from_slice(&raw.to_le_bytes());
    }

    /// Returns the item type code.
    pub const fn item_type(&self) -> u8 {
        self.type_code
    }

    /// Compares two keys for B-tree ordering.
    pub fn cmp_key(&self, other: &Self) -> core::cmp::Ordering {
        use core::cmp::Ordering;
        match self.dir_id.cmp(&other.dir_id) {
            Ordering::Equal => {}
            o => return o,
        }
        match self.object_id.cmp(&other.object_id) {
            Ordering::Equal => {}
            o => return o,
        }
        // Compare offset + type as encoded u64.
        let s = self.offset | ((self.type_code as u64) << 60);
        let o2 = other.offset | ((other.type_code as u64) << 60);
        s.cmp(&o2)
    }
}

/// Item header stored in an internal B-tree node leaf.
#[derive(Clone, Copy, Default)]
pub struct ItemHeader {
    /// Item key.
    pub key: Key,
    /// Item length in bytes (excludes header).
    pub item_len: u16,
    /// Byte offset of the item body within the leaf block.
    pub item_location: u16,
    /// Item version (1 = old, 2 = new format).
    pub version: u16,
    /// Reserved / item count for directory items.
    pub entry_count: u16,
}

/// Size of an item header on disk (24 bytes).
pub const ITEM_HEADER_SIZE: usize = 24;

impl ItemHeader {
    /// Parses an item header from 24 raw bytes.
    pub fn from_bytes(b: &[u8]) -> Result<Self> {
        if b.len() < ITEM_HEADER_SIZE {
            return Err(Error::InvalidArgument);
        }
        Ok(Self {
            key: Key::from_bytes(&b[0..16])?,
            item_len: u16::from_le_bytes([b[16], b[17]]),
            item_location: u16::from_le_bytes([b[18], b[19]]),
            version: u16::from_le_bytes([b[20], b[21]]),
            entry_count: u16::from_le_bytes([b[22], b[23]]),
        })
    }
}

/// Stat data item (inode metadata) for v3.6 format.
#[derive(Clone, Copy, Default)]
pub struct StatDataV2 {
    /// File mode (POSIX permissions + type bits).
    pub mode: u16,
    /// Number of hard links.
    pub nlink: u16,
    /// User ID of owner.
    pub uid: u32,
    /// File size in bytes.
    pub size: u64,
    /// Last access time (Unix timestamp seconds).
    pub atime: u32,
    /// Last modification time (Unix timestamp seconds).
    pub mtime: u32,
    /// Inode change time (Unix timestamp seconds).
    pub ctime: u32,
    /// Group ID.
    pub gid: u32,
    /// Number of 512-byte blocks allocated.
    pub blocks: u32,
    /// First direct byte offset (for inline data).
    pub first_direct_byte: u32,
}

/// Size of a v3.6 stat data item on disk.
pub const STAT_DATA_V2_SIZE: usize = 44;

impl StatDataV2 {
    /// Parses stat data from raw bytes.
    pub fn from_bytes(b: &[u8]) -> Result<Self> {
        if b.len() < STAT_DATA_V2_SIZE {
            return Err(Error::InvalidArgument);
        }
        Ok(Self {
            mode: u16::from_le_bytes([b[0], b[1]]),
            nlink: u16::from_le_bytes([b[2], b[3]]),
            uid: u32::from_le_bytes([b[4], b[5], b[6], b[7]]),
            size: u64::from_le_bytes([b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]]),
            atime: u32::from_le_bytes([b[16], b[17], b[18], b[19]]),
            mtime: u32::from_le_bytes([b[20], b[21], b[22], b[23]]),
            ctime: u32::from_le_bytes([b[24], b[25], b[26], b[27]]),
            gid: u32::from_le_bytes([b[28], b[29], b[30], b[31]]),
            blocks: u32::from_le_bytes([b[32], b[33], b[34], b[35]]),
            first_direct_byte: u32::from_le_bytes([b[36], b[37], b[38], b[39]]),
        })
    }

    /// Returns `true` if the mode indicates a regular file.
    pub const fn is_regular(&self) -> bool {
        self.mode & 0xF000 == 0x8000
    }

    /// Returns `true` if the mode indicates a directory.
    pub const fn is_dir(&self) -> bool {
        self.mode & 0xF000 == 0x4000
    }
}

/// A directory entry stored within a ReiserFS directory item.
#[derive(Clone, Copy, Default)]
pub struct DirEntry {
    /// Objectid of the entry (combined with dir_id forms the lookup key).
    pub object_id: u32,
    /// Byte offset of the entry name within the directory item body.
    pub name_offset: u16,
    /// State flags (bit 2 = visible, others reserved).
    pub state: u16,
    /// Hash of the entry name.
    pub hash: u32,
}

/// Size of a single directory entry header (8 bytes).
pub const DIR_ENTRY_SIZE: usize = 8;

impl DirEntry {
    /// Parses a directory entry header from 8 raw bytes.
    pub fn from_bytes(b: &[u8]) -> Result<Self> {
        if b.len() < DIR_ENTRY_SIZE {
            return Err(Error::InvalidArgument);
        }
        Ok(Self {
            object_id: u32::from_le_bytes([b[0], b[1], b[2], b[3]]),
            name_offset: u16::from_le_bytes([b[4], b[5]]),
            state: u16::from_le_bytes([b[6], b[7]]),
            hash: 0,
        })
    }

    /// Returns `true` if the visible flag is set.
    pub const fn is_visible(&self) -> bool {
        self.state & 0x0004 != 0
    }
}

/// Iterates over directory entries within a ReiserFS directory item body.
pub struct DirItemIter<'a> {
    data: &'a [u8],
    count: u16,
    pos: u16,
}

impl<'a> DirItemIter<'a> {
    /// Creates a new iterator.
    ///
    /// `count` is the number of entries stored in the `ItemHeader::entry_count`.
    pub const fn new(data: &'a [u8], count: u16) -> Self {
        Self {
            data,
            count,
            pos: 0,
        }
    }

    /// Returns the next `DirEntry`, or `None` when exhausted.
    pub fn next_entry(&mut self) -> Result<Option<DirEntry>> {
        if self.pos >= self.count {
            return Ok(None);
        }
        let off = (self.pos as usize) * DIR_ENTRY_SIZE;
        if off + DIR_ENTRY_SIZE > self.data.len() {
            return Err(Error::InvalidArgument);
        }
        let entry = DirEntry::from_bytes(&self.data[off..])?;
        self.pos += 1;
        Ok(Some(entry))
    }

    /// Reads the null-terminated name for a `DirEntry`.
    ///
    /// The name is stored after all entry headers, at `entry.name_offset`.
    pub fn read_name<'b>(&self, entry: &DirEntry, buf: &'b mut [u8; 256]) -> Result<&'b [u8]> {
        let start = entry.name_offset as usize;
        if start >= self.data.len() {
            return Err(Error::InvalidArgument);
        }
        let remaining = &self.data[start..];
        let len = remaining
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(remaining.len());
        let copy = len.min(255);
        buf[..copy].copy_from_slice(&remaining[..copy]);
        buf[copy] = 0;
        Ok(&buf[..copy])
    }
}
