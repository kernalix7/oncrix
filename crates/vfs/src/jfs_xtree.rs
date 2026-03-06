// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! JFS (Journaled File System) extent tree (xtree) implementation.
//!
//! JFS uses a B+ tree called the "xtree" to map logical file offsets to
//! physical disk block addresses. The tree is embedded in the inode for
//! small files and stored in separate disk blocks for larger files.
//!
//! # Xtree Structure
//!
//! Each xtree node contains:
//! - A header with the entry count and tree height.
//! - An array of `XtEntry` records, each mapping a logical range to a
//!   physical extent.
//!
//! The root node is stored directly in the inode's `di_xtroot` field
//! (128 bytes = header + 8 entries for internal nodes, 18 for leaf nodes).
//!
//! # Extent Flags
//!
//! Extents carry flags indicating whether they are new (not yet written),
//! unwritten (pre-allocated), or regular committed extents.

use oncrix_lib::{Error, Result};

/// Maximum height of the xtree.
pub const XTREE_MAX_HEIGHT: usize = 8;

/// Maximum number of root entries in an inode (leaf).
pub const XTREE_ROOT_LEAF_ENTRIES: usize = 18;

/// Maximum number of root entries in an inode (internal node).
pub const XTREE_ROOT_INTERNAL_ENTRIES: usize = 8;

/// Size of an xtree entry in bytes.
pub const XTENTRY_SIZE: usize = 16;

/// Extent flags in the physical block address field (upper bits).
pub mod extent_flags {
    /// Extent is newly allocated (zeroed pages not yet written).
    pub const NEW: u16 = 0x0001;
    /// Extent is pre-allocated but not written (sparse / unwritten).
    pub const UNWRITTEN: u16 = 0x0002;
    /// Extent was converted from unwritten on first write.
    pub const WRITTEN: u16 = 0x0004;
}

/// JFS xtree node header (8 bytes).
#[derive(Clone, Copy, Default)]
pub struct XtreeHeader {
    /// Magic / flag byte (identifies leaf vs. internal node).
    pub flag: u8,
    /// Next header (for leaf nodes in a linked-list chain; 0 if none).
    pub next_index: u8,
    /// Number of entries in this node.
    pub count: u16,
    /// Maximum number of entries this node can hold.
    pub max_count: u16,
    /// Parent node index (for non-root nodes).
    pub parent: u16,
}

impl XtreeHeader {
    /// Parses an xtree header from 8 bytes.
    pub fn from_bytes(b: &[u8]) -> Result<Self> {
        if b.len() < 8 {
            return Err(Error::InvalidArgument);
        }
        Ok(Self {
            flag: b[0],
            next_index: b[1],
            count: u16::from_le_bytes([b[2], b[3]]),
            max_count: u16::from_le_bytes([b[4], b[5]]),
            parent: u16::from_le_bytes([b[6], b[7]]),
        })
    }

    /// Returns `true` if this is a leaf node (flag bit 0 set).
    pub const fn is_leaf(&self) -> bool {
        self.flag & 0x01 != 0
    }
}

/// An xtree extent entry (16 bytes).
///
/// For leaf nodes, entries map logical file offsets to physical extents.
/// For internal nodes, entries point to child xtree blocks.
#[derive(Clone, Copy, Default)]
pub struct XtEntry {
    /// Logical file offset in units of JFS blocks (4 KiB each).
    pub offset: u32,
    /// Length of the extent in JFS blocks (24-bit, upper 8 bits = flags).
    pub length_and_flags: u32,
    /// Physical address of the first block (48-bit, stored as two u32s).
    pub address_lo: u32,
    /// Upper 16 bits of the physical address.
    pub address_hi: u16,
    /// Reserved.
    pub reserved: u16,
}

impl XtEntry {
    /// Parses an xtree entry from 16 bytes.
    pub fn from_bytes(b: &[u8]) -> Result<Self> {
        if b.len() < XTENTRY_SIZE {
            return Err(Error::InvalidArgument);
        }
        Ok(Self {
            offset: u32::from_le_bytes([b[0], b[1], b[2], b[3]]),
            length_and_flags: u32::from_le_bytes([b[4], b[5], b[6], b[7]]),
            address_lo: u32::from_le_bytes([b[8], b[9], b[10], b[11]]),
            address_hi: u16::from_le_bytes([b[12], b[13]]),
            reserved: u16::from_le_bytes([b[14], b[15]]),
        })
    }

    /// Returns the length of this extent in JFS blocks.
    pub const fn length(&self) -> u32 {
        self.length_and_flags & 0x00FF_FFFF
    }

    /// Returns the extent flags (upper 8 bits of `length_and_flags`).
    pub const fn flags(&self) -> u8 {
        ((self.length_and_flags >> 24) & 0xFF) as u8
    }

    /// Returns the 48-bit physical block address.
    pub const fn physical_block(&self) -> u64 {
        self.address_lo as u64 | ((self.address_hi as u64) << 32)
    }

    /// Returns `true` if this extent is unwritten (pre-allocated).
    pub fn is_unwritten(&self) -> bool {
        (self.flags() as u16) & extent_flags::UNWRITTEN != 0
    }
}

/// An in-memory xtree node holding up to 18 entries.
pub struct XtreeNode {
    /// Node header.
    pub header: XtreeHeader,
    /// Extent entries.
    pub entries: [XtEntry; 18],
}

impl Default for XtreeNode {
    fn default() -> Self {
        Self {
            header: XtreeHeader::default(),
            entries: [XtEntry::default(); 18],
        }
    }
}

impl XtreeNode {
    /// Parses an xtree node from a byte slice.
    ///
    /// The slice must be at least `8 + count * 16` bytes.
    pub fn from_bytes(b: &[u8]) -> Result<Self> {
        let header = XtreeHeader::from_bytes(b)?;
        let count = header.count as usize;
        if count > 18 {
            return Err(Error::InvalidArgument);
        }
        let needed = 8 + count * XTENTRY_SIZE;
        if b.len() < needed {
            return Err(Error::InvalidArgument);
        }
        let mut node = Self::default();
        node.header = header;
        for i in 0..count {
            let off = 8 + i * XTENTRY_SIZE;
            node.entries[i] = XtEntry::from_bytes(&b[off..])?;
        }
        Ok(node)
    }

    /// Performs a binary search for the entry that covers `logical_block`.
    ///
    /// Returns the index of the best matching entry, or `None` if the
    /// logical block is before all entries.
    pub fn search(&self, logical_block: u32) -> Option<usize> {
        let count = self.header.count as usize;
        if count == 0 {
            return None;
        }
        // Linear scan (could be binary search for performance).
        let mut result = None;
        for i in 0..count {
            let e = &self.entries[i];
            if e.offset <= logical_block {
                result = Some(i);
            } else {
                break;
            }
        }
        result
    }

    /// Looks up the physical block address for `logical_block`.
    ///
    /// Returns `(physical_block, offset_within_extent)` on success.
    pub fn lookup(&self, logical_block: u32) -> Result<(u64, u32)> {
        let idx = self.search(logical_block).ok_or(Error::NotFound)?;
        let e = &self.entries[idx];
        let rel = logical_block - e.offset;
        if rel >= e.length() {
            return Err(Error::NotFound);
        }
        Ok((e.physical_block() + rel as u64, rel))
    }
}
