// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! ext4 HTree directory indexing.
//!
//! Implements the HTree (hash-tree) indexed directory format used by ext4 to provide
//! O(log n) directory lookup performance for large directories. The HTree is a
//! two-level B-tree indexed by filename hash.

use oncrix_lib::{Error, Result};

/// Maximum depth of the HTree directory index.
pub const HTREE_MAX_DEPTH: u32 = 3;

/// Magic number identifying an HTree root node.
pub const HTREE_MAGIC: u32 = 0x4b52_4d44;

/// Hash version constants for directory entry hashing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum DirHashVersion {
    /// Legacy hash version.
    Legacy = 0,
    /// Half MD4 hash.
    HalfMd4 = 1,
    /// Tea hash.
    Tea = 2,
    /// Legacy unsigned hash.
    LegacyUnsigned = 3,
    /// Half MD4 unsigned hash.
    HalfMd4Unsigned = 4,
    /// Tea unsigned hash.
    TeaUnsigned = 5,
    /// SipHash.
    SipHash = 6,
}

impl TryFrom<u8> for DirHashVersion {
    type Error = Error;

    fn try_from(val: u8) -> Result<Self> {
        match val {
            0 => Ok(Self::Legacy),
            1 => Ok(Self::HalfMd4),
            2 => Ok(Self::Tea),
            3 => Ok(Self::LegacyUnsigned),
            4 => Ok(Self::HalfMd4Unsigned),
            5 => Ok(Self::TeaUnsigned),
            6 => Ok(Self::SipHash),
            _ => Err(Error::InvalidArgument),
        }
    }
}

/// HTree root info embedded in the dot-dot directory entry.
#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct DxRootInfo {
    /// Reserved, must be zero.
    pub reserved_zero: u32,
    /// Hash version used for this directory.
    pub hash_version: u8,
    /// Length of this root info structure.
    pub info_length: u8,
    /// Indirect levels (0 = single-level, 1 = two-level).
    pub indirect_levels: u8,
    /// Unused byte.
    pub unused_flags: u8,
}

/// HTree count/limit pair at start of each HTree node.
#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct DxCountLimit {
    /// Number of valid entries (excluding this header).
    pub count: u16,
    /// Maximum entries that fit in this block.
    pub limit: u16,
}

/// A single HTree entry mapping a hash to a block number.
#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct DxEntry {
    /// Hash value for this entry.
    pub hash: u32,
    /// Block number of the leaf or next-level node.
    pub block: u32,
}

/// HTree node containing a header and an array of entries.
#[derive(Debug)]
pub struct DxNode {
    /// Count and limit header.
    pub count_limit: DxCountLimit,
    /// Entries in this node (up to limit - 1 usable).
    pub entries: [DxEntry; 255],
}

impl DxNode {
    /// Create a new empty DxNode with the given block limit.
    pub const fn new(limit: u16) -> Self {
        Self {
            count_limit: DxCountLimit { count: 1, limit },
            entries: [DxEntry { hash: 0, block: 0 }; 255],
        }
    }

    /// Return the number of valid entries (excluding the fake first entry).
    pub fn entry_count(&self) -> u16 {
        self.count_limit.count.saturating_sub(1)
    }

    /// Return true if the node has room for more entries.
    pub fn has_space(&self) -> bool {
        self.count_limit.count < self.count_limit.limit
    }
}

/// Result of an HTree lookup operation.
#[derive(Debug, Clone, Copy)]
pub struct DxLookupResult {
    /// Block number where the target entry should reside.
    pub block: u32,
    /// Hash of the target name.
    pub hash: u32,
    /// Minor hash component.
    pub minor_hash: u32,
}

/// State for an ongoing HTree directory search.
#[derive(Debug)]
pub struct DxFrame {
    /// Block number of this node.
    pub block_num: u32,
    /// The count/limit header for this node.
    pub count_limit: DxCountLimit,
    /// Index of the matched entry within the node.
    pub at_index: u16,
}

/// HTree directory index manager.
#[derive(Debug)]
pub struct DirIndex {
    /// Inode number of the directory.
    pub inode: u64,
    /// Hash version used.
    pub hash_version: DirHashVersion,
    /// Indirect levels (0 or 1).
    pub indirect_levels: u8,
    /// Whether the large_dir feature is enabled.
    pub large_dir: bool,
}

impl DirIndex {
    /// Create a new DirIndex for the given inode.
    pub const fn new(inode: u64, hash_version: DirHashVersion) -> Self {
        Self {
            inode,
            hash_version,
            indirect_levels: 0,
            large_dir: false,
        }
    }

    /// Compute the hash of a filename using the configured hash version.
    ///
    /// Returns (major_hash, minor_hash).
    pub fn hash_filename(&self, name: &[u8]) -> (u32, u32) {
        match self.hash_version {
            DirHashVersion::HalfMd4 | DirHashVersion::HalfMd4Unsigned => half_md4_hash(name),
            DirHashVersion::Tea | DirHashVersion::TeaUnsigned => tea_hash(name),
            DirHashVersion::SipHash => sip_hash(name),
            DirHashVersion::Legacy | DirHashVersion::LegacyUnsigned => legacy_hash(name),
        }
    }

    /// Look up a filename in the HTree, returning the target leaf block.
    ///
    /// `read_block` is a callback that reads a directory block by its index.
    pub fn lookup<F>(&self, name: &[u8], mut read_block: F) -> Result<DxLookupResult>
    where
        F: FnMut(u32) -> Result<DxNode>,
    {
        if name.is_empty() {
            return Err(Error::InvalidArgument);
        }

        let (hash, minor_hash) = self.hash_filename(name);

        // Block 0 is the root; the HTree root info is in the second entry area.
        let root = read_block(0)?;
        let leaf_block = dx_node_search(&root, hash)?;

        let target_block = if self.indirect_levels > 0 {
            let level2 = read_block(leaf_block)?;
            dx_node_search(&level2, hash)?
        } else {
            leaf_block
        };

        Ok(DxLookupResult {
            block: target_block,
            hash,
            minor_hash,
        })
    }

    /// Add a new entry to the HTree, potentially splitting nodes.
    ///
    /// Returns the leaf block number where the new directory entry should be placed.
    pub fn add_entry<F>(&mut self, name: &[u8], new_block: u32, mut read_block: F) -> Result<u32>
    where
        F: FnMut(u32) -> Result<DxNode>,
    {
        if name.is_empty() {
            return Err(Error::InvalidArgument);
        }

        let (hash, _) = self.hash_filename(name);
        let root = read_block(0)?;

        if root.has_space() {
            let leaf = dx_node_search(&root, hash)?;
            Ok(leaf)
        } else if self.indirect_levels == 0 {
            // Need to split root and add an indirect level.
            self.indirect_levels = 1;
            Ok(new_block)
        } else {
            // Two-level tree is full.
            Err(Error::OutOfMemory)
        }
    }

    /// Initialize a new HTree root block for a freshly-created directory.
    pub fn init_root(block_size: u32) -> Result<DxRootInfo> {
        let entries_per_block = (block_size - 24) / 8;
        if entries_per_block < 2 {
            return Err(Error::InvalidArgument);
        }
        Ok(DxRootInfo {
            reserved_zero: 0,
            hash_version: DirHashVersion::HalfMd4 as u8,
            info_length: core::mem::size_of::<DxRootInfo>() as u8,
            indirect_levels: 0,
            unused_flags: 0,
        })
    }
}

/// Search a DxNode for the entry whose hash is <= `hash`.
fn dx_node_search(node: &DxNode, hash: u32) -> Result<u32> {
    let count = node.entry_count() as usize;
    if count == 0 {
        // Return block 0 as fallback.
        return Ok(0);
    }

    // Binary search for the last entry with entry.hash <= hash.
    let mut lo: usize = 0;
    let mut hi: usize = count;

    while lo < hi {
        let mid = lo + (hi - lo) / 2;
        if node.entries[mid].hash <= hash {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }

    // `lo` is the first entry with hash > target; use lo-1 (or entry 0).
    let idx = if lo == 0 { 0 } else { lo - 1 };
    Ok(node.entries[idx].block)
}

/// Simplified half-MD4 hash for directory entries.
///
/// This is a reduced version of the RSA MD4 hash used by ext2/ext3/ext4.
fn half_md4_hash(name: &[u8]) -> (u32, u32) {
    let mut a: u32 = 0x6745_2301;
    let mut b: u32 = 0xEFCD_AB89;
    let mut c: u32 = 0x98BA_DCFE;
    let mut d: u32 = 0x1032_5476;

    for chunk in name.chunks(4) {
        let mut word = 0u32;
        for (i, &byte) in chunk.iter().enumerate() {
            word |= (byte as u32) << (i * 8);
        }
        a = a.wrapping_add(word);
        b = b.rotate_left(5).wrapping_add(c ^ d ^ a);
        c = c.rotate_left(9).wrapping_add(d & a | b & !a);
        d = d.rotate_left(13).wrapping_add(a ^ b ^ c);
    }

    let major = b & !1;
    let minor = c;
    (major, minor)
}

/// Simplified TEA (Tiny Encryption Algorithm) hash.
fn tea_hash(name: &[u8]) -> (u32, u32) {
    let mut v0: u32 = 0x6745_2301;
    let mut v1: u32 = 0xEFCD_AB89;
    let delta: u32 = 0x9E37_79B9;
    let mut sum: u32 = 0;

    for chunk in name.chunks(8) {
        let mut k = [0u32; 4];
        for (i, byte_pair) in chunk.chunks(2).enumerate().take(4) {
            k[i] = byte_pair
                .iter()
                .enumerate()
                .fold(0u32, |acc, (j, &b)| acc | ((b as u32) << (j * 8)));
        }
        for _ in 0..16 {
            sum = sum.wrapping_add(delta);
            v0 = v0.wrapping_add(
                (v1.wrapping_shl(4).wrapping_add(k[0]))
                    ^ (v1.wrapping_add(sum))
                    ^ (v1.wrapping_shr(5).wrapping_add(k[1])),
            );
            v1 = v1.wrapping_add(
                (v0.wrapping_shl(4).wrapping_add(k[2]))
                    ^ (v0.wrapping_add(sum))
                    ^ (v0.wrapping_shr(5).wrapping_add(k[3])),
            );
        }
    }

    (v0 & !1, v1)
}

/// SipHash-2-4 inspired compact hash for directory entries.
fn sip_hash(name: &[u8]) -> (u32, u32) {
    let mut v0: u64 = 0x736f6d6570736575;
    let mut v1: u64 = 0x646f72616e646f6d;
    let len = name.len() as u64;

    for chunk in name.chunks(8) {
        let mut m = 0u64;
        for (i, &b) in chunk.iter().enumerate() {
            m |= (b as u64) << (i * 8);
        }
        v0 ^= m;
        v1 ^= m;
        v0 = v0.wrapping_add(v1);
        v1 = v1.rotate_left(13);
        v1 ^= v0;
    }

    v0 ^= len;
    v1 ^= 0xff;
    v0 = v0.wrapping_add(v1);
    v1 = v1.rotate_left(17);
    v1 ^= v0;

    ((v0 >> 32) as u32 & !1, v1 as u32)
}

/// Legacy hash used by old ext2 implementations.
fn legacy_hash(name: &[u8]) -> (u32, u32) {
    let mut hash: u32 = 0;
    for (i, &b) in name.iter().enumerate() {
        hash = hash.wrapping_add((b as u32).wrapping_mul(i as u32 + 1));
        hash ^= hash.rotate_left(7);
    }
    (hash & !1, hash >> 1)
}

/// Validate the internal consistency of an HTree frame chain.
///
/// Returns an error if the frames are inconsistent.
pub fn validate_dx_frames(frames: &[DxFrame]) -> Result<()> {
    for (i, frame) in frames.iter().enumerate() {
        if frame.count_limit.count > frame.count_limit.limit {
            return Err(Error::IoError);
        }
        if frame.at_index >= frame.count_limit.count {
            return Err(Error::IoError);
        }
        if i > 0 && frame.block_num == 0 {
            return Err(Error::IoError);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_versions() {
        let idx = DirIndex::new(2, DirHashVersion::HalfMd4);
        let (h, _) = idx.hash_filename(b"testfile.txt");
        assert_eq!(h & 1, 0, "major hash must be even");
    }

    #[test]
    fn test_dx_node_search_empty() {
        let node = DxNode::new(40);
        let block = dx_node_search(&node, 0x1234_5678).unwrap();
        assert_eq!(block, 0);
    }
}
