// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Ext3/Ext4 HTree (hash-tree) directory indexing.
//!
//! HTree directories use a balanced B-tree indexed by the hash of the filename
//! to allow O(log N) directory lookups instead of O(N) linear scan.  This
//! module implements the HTree node structures, hash computation, and the
//! dx_probe lookup algorithm.

use oncrix_lib::{Error, Result};

/// Maximum depth of an HTree (currently 3 in Linux ext4).
pub const HTREE_MAX_DEPTH: usize = 3;

/// Number of dx_entry slots per 4 KiB block (header = 8 bytes, entry = 8 bytes).
pub const DX_ENTRIES_PER_BLOCK: usize = 508;

/// HTree hash algorithms.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum HTreeHashVersion {
    /// Legacy unsigned half-MD4.
    LegacyHalfMd4 = 0,
    /// TEA hash.
    Tea = 1,
    /// Unsigned half-MD4 with dir_index flag.
    UnsignedLegacy = 2,
    /// Unsigned TEA.
    UnsignedTea = 3,
    /// SipHash (ext4 with casefolding).
    SipHash = 4,
}

impl HTreeHashVersion {
    /// Parse from on-disk tag.
    pub fn from_tag(tag: u8) -> Result<Self> {
        match tag {
            0 => Ok(Self::LegacyHalfMd4),
            1 => Ok(Self::Tea),
            2 => Ok(Self::UnsignedLegacy),
            3 => Ok(Self::UnsignedTea),
            4 => Ok(Self::SipHash),
            _ => Err(Error::InvalidArgument),
        }
    }
}

/// A (hash, minor_hash) pair used as the HTree sort key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct DxHash {
    pub hash: u32,
    pub minor_hash: u32,
}

impl DxHash {
    pub fn new(hash: u32, minor_hash: u32) -> Self {
        Self { hash, minor_hash }
    }
}

/// A single entry in an HTree internal or leaf node.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct DxEntry {
    /// Hash value of the name range starting at this entry.
    pub hash: u32,
    /// Block number of the child (internal) or leaf directory block.
    pub block: u32,
}

impl DxEntry {
    pub fn new(hash: u32, block: u32) -> Self {
        Self { hash, block }
    }
}

/// HTree node header (appears before `DxEntry` array).
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct DxHeader {
    /// Reserved (must be 0).
    pub reserved_zero: u32,
    /// Hash version tag.
    pub hash_version: u8,
    /// Length of this header in 32-bit words (always 2).
    pub info_length: u8,
    /// Depth of this node (0 = root).
    pub indirect_levels: u8,
    /// Flags.
    pub unused_flags: u8,
    /// Maximum number of dx_entry slots.
    pub limit: u16,
    /// Number of valid dx_entry slots.
    pub count: u16,
    /// Hash of the first entry (always 0 for the root).
    pub block: u32,
}

impl DxHeader {
    /// Validate a DxHeader read from disk.
    pub fn validate(&self) -> Result<()> {
        if self.reserved_zero != 0 {
            return Err(Error::InvalidArgument);
        }
        if self.indirect_levels as usize >= HTREE_MAX_DEPTH {
            return Err(Error::InvalidArgument);
        }
        if self.count > self.limit {
            return Err(Error::InvalidArgument);
        }
        Ok(())
    }
}

/// In-memory HTree node loaded from one directory block.
pub struct DxNode {
    pub header: DxHeader,
    pub entries: [DxEntry; DX_ENTRIES_PER_BLOCK],
}

impl DxNode {
    /// Create an empty root node.
    pub fn new_root(hash_version: u8) -> Self {
        Self {
            header: DxHeader {
                reserved_zero: 0,
                hash_version,
                info_length: 2,
                indirect_levels: 0,
                unused_flags: 0,
                limit: DX_ENTRIES_PER_BLOCK as u16,
                count: 1,
                block: 0,
            },
            entries: [DxEntry { hash: 0, block: 0 }; DX_ENTRIES_PER_BLOCK],
        }
    }

    /// Binary search for the last entry with `hash <= target`.
    ///
    /// Returns the block number to descend into.
    pub fn lookup(&self, target_hash: u32) -> Result<u32> {
        let count = self.header.count as usize;
        if count == 0 {
            return Err(Error::NotFound);
        }
        // Entries are sorted by hash ascending; the first entry has hash 0
        // and is a catch-all for the leftmost child.
        let mut result_block = self.entries[0].block;
        for entry in &self.entries[1..count] {
            if entry.hash > target_hash {
                break;
            }
            result_block = entry.block;
        }
        Ok(result_block)
    }

    /// Insert a new dx_entry in sorted order.
    pub fn insert(&mut self, entry: DxEntry) -> Result<()> {
        let count = self.header.count as usize;
        if count >= DX_ENTRIES_PER_BLOCK {
            return Err(Error::OutOfMemory);
        }
        let pos = self.entries[..count].partition_point(|e| e.hash <= entry.hash);
        if pos < count {
            self.entries.copy_within(pos..count, pos + 1);
        }
        self.entries[pos] = entry;
        self.header.count += 1;
        Ok(())
    }

    /// Number of valid entries.
    pub fn count(&self) -> usize {
        self.header.count as usize
    }

    /// Whether this node is full.
    pub fn is_full(&self) -> bool {
        self.header.count >= self.header.limit
    }
}

/// Simplified TEA hash (as used in ext2/3/4).
pub fn tea_hash(name: &[u8], seed: u32) -> DxHash {
    let mut a = seed;
    let mut b = seed;
    let mut c: u32 = 0x9e37_79b9;
    let mut d: u32 = 0x9e37_79b9;

    let mut i = 0;
    while i + 4 <= name.len() {
        let word = u32::from_le_bytes([name[i], name[i + 1], name[i + 2], name[i + 3]]);
        a = a.wrapping_add(word);
        b = b.wrapping_add(a);
        c = c.wrapping_add(b);
        d = d.wrapping_add(c);
        i += 4;
    }
    // Handle remaining bytes.
    if i < name.len() {
        let mut word = 0u32;
        for (k, &byte) in name[i..].iter().enumerate() {
            word |= (byte as u32) << (k * 8);
        }
        a = a.wrapping_add(word);
    }
    DxHash::new(a & !1, b)
}

/// Three-level HTree probe: resolve a filename to a leaf directory block.
pub struct DxProbe<'a> {
    nodes: [Option<&'a DxNode>; HTREE_MAX_DEPTH],
    depth: usize,
}

impl<'a> DxProbe<'a> {
    /// Create a probe starting from the root node.
    pub fn new(root: &'a DxNode) -> Self {
        let mut nodes = [None; HTREE_MAX_DEPTH];
        nodes[0] = Some(root);
        Self { nodes, depth: 1 }
    }

    /// Descend one level into a child node.
    pub fn descend(&mut self, child: &'a DxNode) -> Result<()> {
        if self.depth >= HTREE_MAX_DEPTH {
            return Err(Error::InvalidArgument);
        }
        self.nodes[self.depth] = Some(child);
        self.depth += 1;
        Ok(())
    }

    /// Perform lookup at the current deepest level.
    pub fn lookup_at_level(&self, level: usize, hash: u32) -> Result<u32> {
        match self.nodes[level] {
            Some(node) => node.lookup(hash),
            None => Err(Error::NotFound),
        }
    }
}
