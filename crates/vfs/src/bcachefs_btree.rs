// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! bcachefs B-tree node types and key structures.
//!
//! bcachefs is a modern Linux filesystem that inherits bcache's copy-on-write
//! B-tree implementation. All filesystem metadata is stored in a set of
//! typed B-trees, each indexed by a structured key.
//!
//! # Key Structure
//!
//! bcachefs keys are 16 bytes: `{u64 inode_and_type, u32 snapshot, u32 offset_lo}`.
//! The inode field encodes both the inode number and the B-tree ID in the
//! upper bits.
//!
//! # B-tree IDs
//!
//! Each B-tree stores a specific type of metadata:
//! - `extents`: File data extents.
//! - `inodes`: Inode records.
//! - `dirents`: Directory entries.
//! - `xattrs`: Extended attributes.
//! - `alloc`: Space allocation records.
//! - `quotas`: Quota accounting.
//! - `stripes`: Erasure coding stripe information.

use oncrix_lib::{Error, Result};

/// bcachefs B-tree identifiers.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum BtreeId {
    /// File data extents.
    Extents = 0,
    /// Inode records.
    Inodes = 1,
    /// Directory entries.
    Dirents = 2,
    /// Extended attributes.
    Xattrs = 3,
    /// Space allocation records.
    Alloc = 4,
    /// Quota accounting.
    Quotas = 5,
    /// Stripe information for erasure coding.
    Stripes = 6,
    /// Rebalance work items.
    RebalanceWork = 7,
}

impl BtreeId {
    /// Parses a B-tree ID from its u8 value.
    pub fn from_u8(v: u8) -> Result<Self> {
        match v {
            0 => Ok(Self::Extents),
            1 => Ok(Self::Inodes),
            2 => Ok(Self::Dirents),
            3 => Ok(Self::Xattrs),
            4 => Ok(Self::Alloc),
            5 => Ok(Self::Quotas),
            6 => Ok(Self::Stripes),
            7 => Ok(Self::RebalanceWork),
            _ => Err(Error::InvalidArgument),
        }
    }
}

/// A bcachefs B-tree key (bkey — 16 bytes).
#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub struct BKey {
    /// High 64 bits: inode number + B-tree type in upper bits.
    pub inode_type: u64,
    /// Snapshot ID.
    pub snapshot: u32,
    /// Offset within the inode (sector or entry index).
    pub offset: u32,
}

impl BKey {
    /// Parses a bkey from 16 bytes (little-endian).
    pub fn from_bytes(b: &[u8]) -> Result<Self> {
        if b.len() < 16 {
            return Err(Error::InvalidArgument);
        }
        Ok(Self {
            inode_type: u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]),
            snapshot: u32::from_le_bytes([b[8], b[9], b[10], b[11]]),
            offset: u32::from_le_bytes([b[12], b[13], b[14], b[15]]),
        })
    }

    /// Returns the inode number (lower 48 bits of `inode_type`).
    pub const fn inode(&self) -> u64 {
        self.inode_type & 0x0000_FFFF_FFFF_FFFF
    }

    /// Returns the key type (upper 16 bits of `inode_type`).
    pub const fn key_type(&self) -> u16 {
        ((self.inode_type >> 48) & 0xFFFF) as u16
    }

    /// Compares two keys for B-tree ordering (inode, snapshot desc, offset).
    pub fn btree_cmp(&self, other: &Self) -> core::cmp::Ordering {
        use core::cmp::Ordering;
        match self.inode().cmp(&other.inode()) {
            Ordering::Equal => {}
            o => return o,
        }
        // Snapshot ordering: higher snapshot number compares less (newest first).
        match other.snapshot.cmp(&self.snapshot) {
            Ordering::Equal => {}
            o => return o,
        }
        self.offset.cmp(&other.offset)
    }
}

/// Value header for bcachefs B-tree values.
#[derive(Clone, Copy, Default)]
pub struct BValue {
    /// Type of the value (matches BKey::key_type).
    pub val_type: u8,
    /// Size of the value in u64 units (8-byte units).
    pub u64s: u8,
    /// Format version.
    pub format: u8,
    /// Type-specific flags.
    pub flags: u8,
}

impl BValue {
    /// Parses a value header from 4 bytes.
    pub fn from_bytes(b: &[u8]) -> Result<Self> {
        if b.len() < 4 {
            return Err(Error::InvalidArgument);
        }
        Ok(Self {
            val_type: b[0],
            u64s: b[1],
            format: b[2],
            flags: b[3],
        })
    }

    /// Returns the total value size in bytes (including header).
    pub const fn total_bytes(&self) -> usize {
        (self.u64s as usize) * 8
    }
}

/// An extent pointer within a bcachefs extent value.
#[derive(Clone, Copy, Default)]
pub struct ExtentPointer {
    /// Physical sector on the device.
    pub offset: u64,
    /// Device checksum (CRC32c or xxhash).
    pub checksum: u32,
    /// Device index.
    pub dev: u8,
    /// Cached (in bcache) flag.
    pub cached: bool,
    /// Unwritten (pre-allocated) flag.
    pub unwritten: bool,
}

impl ExtentPointer {
    /// Parses an extent pointer from 16 bytes.
    pub fn from_bytes(b: &[u8]) -> Result<Self> {
        if b.len() < 16 {
            return Err(Error::InvalidArgument);
        }
        let raw_offset = u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]);
        let checksum = u32::from_le_bytes([b[8], b[9], b[10], b[11]]);
        let dev = b[12];
        let flags = b[13];
        Ok(Self {
            offset: raw_offset & 0x0000_FFFF_FFFF_FFFF,
            checksum,
            dev,
            cached: flags & 0x01 != 0,
            unwritten: flags & 0x02 != 0,
        })
    }
}

/// A bcachefs B-tree node on disk.
///
/// This is a simplified representation covering the node header fields
/// needed for traversal. The full node also includes the key/value pairs
/// and padding.
#[derive(Clone, Copy, Default)]
pub struct BtreeNode {
    /// Magic number identifying this as a bcachefs btree node.
    pub magic: u64,
    /// Sequence number for the most recent write.
    pub seq: u64,
    /// Which B-tree this node belongs to.
    pub btree_id: u8,
    /// Level in the B-tree (0 = leaf).
    pub level: u8,
    /// Number of sets of key/value pairs in this node.
    pub nsets: u16,
    /// Minimum key in this node.
    pub min_key: BKey,
    /// Maximum key in this node.
    pub max_key: BKey,
}

/// Expected magic number for bcachefs B-tree nodes.
pub const BTREE_NODE_MAGIC: u64 = 0x9c7d_b1e5_8b8c_3a12;

impl BtreeNode {
    /// Parses a btree node header from raw bytes (first 64 bytes of the node).
    pub fn from_bytes(b: &[u8]) -> Result<Self> {
        if b.len() < 64 {
            return Err(Error::InvalidArgument);
        }
        let magic = u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]);
        if magic != BTREE_NODE_MAGIC {
            return Err(Error::InvalidArgument);
        }
        Ok(Self {
            magic,
            seq: u64::from_le_bytes([b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]]),
            btree_id: b[16],
            level: b[17],
            nsets: u16::from_le_bytes([b[18], b[19]]),
            min_key: BKey::from_bytes(&b[20..36])?,
            max_key: BKey::from_bytes(&b[36..52])?,
        })
    }

    /// Returns `true` if this is a leaf node.
    pub const fn is_leaf(&self) -> bool {
        self.level == 0
    }

    /// Returns `true` if `key` might exist in this node's key range.
    pub fn contains_key(&self, key: &BKey) -> bool {
        key.btree_cmp(&self.min_key) != core::cmp::Ordering::Less
            && key.btree_cmp(&self.max_key) != core::cmp::Ordering::Greater
    }
}
