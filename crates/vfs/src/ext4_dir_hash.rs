// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! ext4 directory hash tree (htree) operations.
//!
//! Implements the Half-MD4 and TEA hash functions used by ext4 for hashed
//! directory index trees.  The htree allows O(log n) directory lookups by
//! mapping filenames to 32-bit hash values and arranging dx_entry records
//! in sorted order within dx_node index blocks.
//!
//! # Architecture
//!
//! ```text
//! Directory inode
//!   └─ dx_root (block 0)
//!        ├─ dx_root_info  (hash version, indirect levels, …)
//!        └─ dx_entry[]    (hash → leaf block number)
//!             └─ dx_node  (interior node at level 1)
//!                  └─ dx_entry[]  (hash → leaf block number)
//!                       └─ linear dir-entry block (actual filenames)
//! ```
//!
//! # Hash Algorithms
//!
//! - [`HashVersion::HalfMd4`]  — truncated MD4 mixing (ext2/3/4 default)
//! - [`HashVersion::Tea`]       — Tiny Encryption Algorithm variant
//! - [`HashVersion::Legacy`]    — unsigned byte-sum (insecure, legacy only)
//!
//! # Structures
//!
//! - [`HashVersion`]     — hash algorithm selector
//! - [`DxEntry`]         — (hash, block) pair inside an index node
//! - [`DxRootInfo`]      — metadata embedded in the first directory block
//! - [`DxRoot`]          — root index node (block 0 of a hashed directory)
//! - [`DxNode`]          — interior index node (level ≥ 1)
//! - [`HtreePath`]       — result of traversing the htree to a leaf block
//! - [`DirHashTree`]     — top-level htree state machine

#![allow(dead_code)]

use oncrix_lib::{Error, Result};

// ── Constants ──────────────────────────────────────────────────────────────

/// Maximum dx_entry slots in a root node (block 0).
const DX_ROOT_MAX_ENTRIES: usize = 508;

/// Maximum dx_entry slots in an interior node.
const DX_NODE_MAX_ENTRIES: usize = 510;

/// Maximum supported indirect levels (0 = root points directly to leaves).
const MAX_HTREE_LEVELS: u8 = 2;

/// Maximum filename length handled by the hash functions.
const MAX_NAME_LEN: usize = 255;

/// Block size assumed for dx_root / dx_node layout (4 KiB).
const BLOCK_SIZE: u32 = 4096;

/// Seed used by the Half-MD4 hash.
const HALF_MD4_SEED: u32 = 0x9e37_79b9;

// ── HashVersion ─────────────────────────────────────────────────────────────

/// Selects which hash function ext4 applies to filenames.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashVersion {
    /// Legacy unsigned-sum hash (insecure; only for very old volumes).
    Legacy = 0,
    /// Half-MD4: the default for most ext3/ext4 volumes.
    HalfMd4 = 1,
    /// TEA (Tiny Encryption Algorithm) variant.
    Tea = 2,
}

impl HashVersion {
    /// Construct from the raw byte stored in `dx_root_info`.
    ///
    /// # Errors
    ///
    /// Returns `InvalidArgument` for unknown values.
    pub fn from_raw(v: u8) -> Result<Self> {
        match v {
            0 => Ok(Self::Legacy),
            1 => Ok(Self::HalfMd4),
            2 => Ok(Self::Tea),
            _ => Err(Error::InvalidArgument),
        }
    }

    /// Raw byte to write into `dx_root_info.hash_version`.
    pub fn as_raw(self) -> u8 {
        self as u8
    }
}

// ── Hash functions ───────────────────────────────────────────────────────────

/// Compute the TEA (Tiny Encryption Algorithm) hash of a filename.
///
/// This is the variant used by ext4 — two 64-bit TEA rounds over 8-byte
/// chunks, producing a final 32-bit value from the high word.
pub fn tea_hash(name: &[u8], seed: u32) -> u32 {
    let mut h0: u32 = seed;
    let mut h1: u32 = seed ^ 0x1234_abcd;

    let mut i = 0usize;
    while i + 4 <= name.len() {
        let w0 = u32::from_le_bytes([name[i], name[i + 1], name[i + 2], name[i + 3]]);
        i += 4;
        let w1 = if i + 4 <= name.len() {
            let v = u32::from_le_bytes([name[i], name[i + 1], name[i + 2], name[i + 3]]);
            i += 4;
            v
        } else {
            0
        };
        // Two Feistel rounds.
        let mut sum: u32 = 0;
        for _ in 0..16u32 {
            sum = sum.wrapping_add(0x9e37_79b9);
            h0 = h0.wrapping_add(
                (h1.wrapping_shl(4).wrapping_add(w0))
                    ^ h1.wrapping_add(sum)
                    ^ (h1.wrapping_shr(5).wrapping_add(w1)),
            );
            h1 = h1.wrapping_add(
                (h0.wrapping_shl(4).wrapping_add(w0))
                    ^ h0.wrapping_add(sum)
                    ^ (h0.wrapping_shr(5).wrapping_add(w1)),
            );
        }
    }
    // Handle remaining bytes.
    if i < name.len() {
        let mut tail = [0u8; 4];
        tail[..name.len() - i].copy_from_slice(&name[i..]);
        let w = u32::from_le_bytes(tail);
        h0 = h0.wrapping_add(w);
        h1 = h1 ^ w;
    }
    h0 ^ h1
}

/// Compute the Half-MD4 hash of a filename.
///
/// Applies the MD4 mixing step across 16-byte chunks, seeded with the
/// directory's `seed` value (from `dx_root_info`).
pub fn half_md4_hash(name: &[u8], seed: u32) -> u32 {
    let (mut a, mut b, mut c, mut d) = (
        seed,
        seed.wrapping_add(HALF_MD4_SEED),
        seed.wrapping_add(0x6ed9_eba1),
        seed.wrapping_add(0x8f1b_bcdc),
    );

    let pad_len = (16 - (name.len() % 16)) % 16;
    let total = name.len() + pad_len;

    let mut offset = 0usize;
    while offset < total {
        let mut chunk = [0u32; 4];
        for (ci, word) in chunk.iter_mut().enumerate() {
            let base = offset + ci * 4;
            let mut bytes = [0u8; 4];
            for (bi, byte) in bytes.iter_mut().enumerate() {
                if base + bi < name.len() {
                    *byte = name[base + bi];
                }
            }
            *word = u32::from_le_bytes(bytes);
        }
        offset += 16;

        // MD4 round 1 mixing (simplified half-MD4 variant).
        let f = |x: u32, y: u32, z: u32| (x & y) | (!x & z);
        a = a
            .wrapping_add(f(b, c, d))
            .wrapping_add(chunk[0])
            .rotate_left(3);
        d = d
            .wrapping_add(f(a, b, c))
            .wrapping_add(chunk[1])
            .rotate_left(7);
        c = c
            .wrapping_add(f(d, a, b))
            .wrapping_add(chunk[2])
            .rotate_left(11);
        b = b
            .wrapping_add(f(c, d, a))
            .wrapping_add(chunk[3])
            .rotate_left(19);
    }
    a ^ b ^ c ^ d
}

/// Legacy hash: sum of bytes cast to u32 (used only for ancient volumes).
pub fn legacy_hash(name: &[u8]) -> u32 {
    name.iter().fold(0u32, |acc, &b| acc.wrapping_add(b as u32))
}

/// Dispatch to the correct hash function based on `version`.
pub fn dir_hash(name: &[u8], version: HashVersion, seed: u32) -> u32 {
    match version {
        HashVersion::Legacy => legacy_hash(name),
        HashVersion::HalfMd4 => half_md4_hash(name, seed),
        HashVersion::Tea => tea_hash(name, seed),
    }
}

// ── DxEntry ─────────────────────────────────────────────────────────────────

/// A single entry in an htree index node.
///
/// Maps a hash value to a filesystem block number.  Entries within a node
/// are stored in ascending hash order, enabling binary search.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DxEntry {
    /// Hash value of the first filename in the subtree rooted here.
    pub hash: u32,
    /// Block number of the child (leaf or interior) block.
    pub block: u32,
}

impl DxEntry {
    /// Create a new entry.
    pub const fn new(hash: u32, block: u32) -> Self {
        Self { hash, block }
    }

    /// Null/unused sentinel entry.
    pub const fn null() -> Self {
        Self { hash: 0, block: 0 }
    }
}

impl Default for DxEntry {
    fn default() -> Self {
        Self::null()
    }
}

// ── DxRootInfo ──────────────────────────────────────────────────────────────

/// Metadata stored in the first 8 bytes after the dot/dotdot entries in
/// block 0 of a hashed directory.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct DxRootInfo {
    /// Reserved (must be zero on disk).
    pub reserved_zero: u32,
    /// Hash algorithm version ([`HashVersion`]).
    pub hash_version: u8,
    /// Length of this info structure (8 bytes).
    pub info_length: u8,
    /// Number of indirect levels (0 = root → leaves directly).
    pub indirect_levels: u8,
    /// Flags (currently unused).
    pub unused_flags: u8,
    /// Hash seed (from superblock `s_hash_seed`).
    pub seed: u32,
}

impl DxRootInfo {
    /// Construct root info for a new htree.
    pub const fn new(version: HashVersion, indirect_levels: u8, seed: u32) -> Self {
        Self {
            reserved_zero: 0,
            hash_version: version as u8,
            info_length: 8,
            indirect_levels,
            unused_flags: 0,
            seed,
        }
    }
}

// ── DxRoot ──────────────────────────────────────────────────────────────────

/// Root index node occupying block 0 of a hashed directory.
///
/// Contains `DxRootInfo` and an array of `DxEntry` values sorted by hash.
/// The first entry (`entries[0]`) has hash 0 and points to the "catch-all"
/// leftmost leaf or interior block.
pub struct DxRoot {
    /// Hash tree metadata.
    pub info: DxRootInfo,
    /// Sorted array of (hash, block) entries.
    pub entries: [DxEntry; DX_ROOT_MAX_ENTRIES],
    /// Number of valid entries (including the guard entry at index 0).
    pub count: usize,
    /// Maximum entries capacity (always ≤ `DX_ROOT_MAX_ENTRIES`).
    pub limit: usize,
}

impl DxRoot {
    /// Create an empty root node.
    pub fn new(info: DxRootInfo) -> Self {
        Self {
            info,
            entries: [DxEntry::null(); DX_ROOT_MAX_ENTRIES],
            count: 1, // entry[0] is the sentinel (hash=0).
            limit: DX_ROOT_MAX_ENTRIES,
        }
    }

    /// Find the entry whose subtree should contain `hash`.
    ///
    /// Returns the index of the last entry whose hash ≤ `hash`.
    pub fn search(&self, hash: u32) -> usize {
        let live = &self.entries[..self.count];
        match live.binary_search_by_key(&hash, |e| e.hash) {
            Ok(pos) => pos,
            Err(pos) => pos.saturating_sub(1),
        }
    }

    /// Insert a new entry in sorted order.
    ///
    /// # Errors
    ///
    /// - `OutOfMemory` if the node is full.
    /// - `AlreadyExists` if an entry with the same hash exists.
    pub fn insert(&mut self, entry: DxEntry) -> Result<()> {
        if self.count >= self.limit {
            return Err(Error::OutOfMemory);
        }
        let live = &self.entries[..self.count];
        match live.binary_search_by_key(&entry.hash, |e| e.hash) {
            Ok(_) => Err(Error::AlreadyExists),
            Err(pos) => {
                self.entries.copy_within(pos..self.count, pos + 1);
                self.entries[pos] = entry;
                self.count += 1;
                Ok(())
            }
        }
    }

    /// Whether the root node is full.
    pub fn is_full(&self) -> bool {
        self.count >= self.limit
    }
}

// ── DxNode ──────────────────────────────────────────────────────────────────

/// An interior index node at htree level ≥ 1.
pub struct DxNode {
    /// Block number of this node on disk.
    pub block: u32,
    /// Sorted (hash, child-block) entries.
    pub entries: [DxEntry; DX_NODE_MAX_ENTRIES],
    /// Number of valid entries.
    pub count: usize,
    /// Capacity limit.
    pub limit: usize,
}

impl DxNode {
    /// Create an empty interior node for the given block.
    pub fn new(block: u32) -> Self {
        Self {
            block,
            entries: [DxEntry::null(); DX_NODE_MAX_ENTRIES],
            count: 1,
            limit: DX_NODE_MAX_ENTRIES,
        }
    }

    /// Find the child entry for `hash`.
    pub fn search(&self, hash: u32) -> usize {
        let live = &self.entries[..self.count];
        match live.binary_search_by_key(&hash, |e| e.hash) {
            Ok(pos) => pos,
            Err(pos) => pos.saturating_sub(1),
        }
    }

    /// Insert an entry in sorted order.
    ///
    /// # Errors
    ///
    /// - `OutOfMemory` if the node is full.
    /// - `AlreadyExists` on hash collision.
    pub fn insert(&mut self, entry: DxEntry) -> Result<()> {
        if self.count >= self.limit {
            return Err(Error::OutOfMemory);
        }
        let live = &self.entries[..self.count];
        match live.binary_search_by_key(&entry.hash, |e| e.hash) {
            Ok(_) => Err(Error::AlreadyExists),
            Err(pos) => {
                self.entries.copy_within(pos..self.count, pos + 1);
                self.entries[pos] = entry;
                self.count += 1;
                Ok(())
            }
        }
    }
}

// ── HtreePath ───────────────────────────────────────────────────────────────

/// Result of traversing the htree for a specific filename hash.
///
/// Carries the block number of the leaf block that should contain the
/// filename, along with the path of (node-block, slot) pairs used to reach
/// it so that insertions can split and propagate upward.
#[derive(Debug, Clone, Copy)]
pub struct HtreePath {
    /// Filesystem block number of the target leaf block.
    pub leaf_block: u32,
    /// Depth of the path (0 = root → leaf, 1 = root → node → leaf).
    pub depth: u8,
    /// Block numbers of the interior nodes on the path (level 0 = root).
    pub node_blocks: [u32; MAX_HTREE_LEVELS as usize],
    /// Slot indices within each node that were followed.
    pub node_slots: [usize; MAX_HTREE_LEVELS as usize],
}

impl HtreePath {
    /// Construct a path result.
    pub const fn new(
        leaf_block: u32,
        depth: u8,
        node_blocks: [u32; MAX_HTREE_LEVELS as usize],
        node_slots: [usize; MAX_HTREE_LEVELS as usize],
    ) -> Self {
        Self {
            leaf_block,
            depth,
            node_blocks,
            node_slots,
        }
    }
}

// ── DirHashTree ─────────────────────────────────────────────────────────────

/// Top-level htree state machine for a single ext4 directory.
///
/// Wraps a [`DxRoot`] and, for two-level trees, a single cached interior
/// node.  In a full kernel implementation each node would be loaded on
/// demand from the block device; here we keep one resident for demonstration.
pub struct DirHashTree {
    /// Root index node.
    pub root: DxRoot,
    /// Hash version and seed used for all lookups in this directory.
    pub version: HashVersion,
    /// Hash seed (copied from `root.info.seed` for convenience).
    pub seed: u32,
    /// Inode number of the owning directory.
    pub dir_ino: u64,
    /// Total leaf blocks allocated for this directory.
    pub leaf_count: u32,
}

impl DirHashTree {
    /// Create a new htree for the directory with inode `dir_ino`.
    ///
    /// # Errors
    ///
    /// - `InvalidArgument` if `version` byte is unrecognised or
    ///   `indirect_levels` exceeds [`MAX_HTREE_LEVELS`].
    pub fn new(dir_ino: u64, version: HashVersion, seed: u32, indirect_levels: u8) -> Result<Self> {
        if indirect_levels > MAX_HTREE_LEVELS {
            return Err(Error::InvalidArgument);
        }
        let info = DxRootInfo::new(version, indirect_levels, seed);
        let mut root = DxRoot::new(info);
        // Block 1 is the first leaf block.
        root.entries[0] = DxEntry::new(0, 1);
        Ok(Self {
            root,
            version,
            seed,
            dir_ino,
            leaf_count: 2, // block 0 = root, block 1 = first leaf.
        })
    }

    /// Hash a filename using this directory's configured algorithm.
    pub fn hash(&self, name: &[u8]) -> u32 {
        dir_hash(name, self.version, self.seed)
    }

    /// Traverse the root (single-level) to locate the leaf block for `name`.
    ///
    /// For zero indirect levels the root entries point directly to leaves.
    ///
    /// # Errors
    ///
    /// - `NotFound` if the root has no entries.
    pub fn lookup_leaf(&self, name: &[u8]) -> Result<HtreePath> {
        if self.root.count == 0 {
            return Err(Error::NotFound);
        }
        let hash = self.hash(name);
        let slot = self.root.search(hash);
        let leaf_block = self.root.entries[slot].block;
        Ok(HtreePath::new(leaf_block, 0, [0u32; 2], [slot, 0]))
    }

    /// Allocate a new leaf block and add a dx_entry into the root.
    ///
    /// Returns the block number of the newly allocated leaf.
    ///
    /// # Errors
    ///
    /// - `OutOfMemory` if the root is full.
    pub fn add_leaf(&mut self, min_hash: u32) -> Result<u32> {
        let new_block = self.leaf_count;
        self.leaf_count += 1;
        self.root.insert(DxEntry::new(min_hash, new_block))?;
        Ok(new_block)
    }

    /// Number of leaf blocks in this directory's htree.
    pub fn leaf_count(&self) -> u32 {
        self.leaf_count
    }

    /// Return the hash version for this directory.
    pub fn hash_version(&self) -> HashVersion {
        self.version
    }
}
