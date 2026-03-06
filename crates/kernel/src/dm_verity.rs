// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! dm-verity block device integrity verification.
//!
//! Provides transparent integrity checking of block devices using a
//! Merkle hash tree (binary tree of SHA-256 hashes). Each data block
//! is verified by walking from its leaf hash up to the root, checking
//! that every hash matches the expected value.
//!
//! # Architecture
//!
//! ```text
//!  VerityRegistry
//!   └── VerityDevice[8]
//!        ├── VeritySuperblock  (magic, version, hash type, root_hash)
//!        ├── VerityHashTree    (Merkle tree of SHA-256 hashes)
//!        └── stats: verified_count, corruption_count
//! ```
//!
//! # Verification flow
//!
//! 1. Compute `SHA-256(data_block)` to get the leaf hash.
//! 2. Walk the Merkle tree from leaf to root, hashing each pair
//!    of siblings and comparing against the stored parent hash.
//! 3. The final root hash must match `superblock.root_hash`.
//!
//! Reference: Linux `drivers/md/dm-verity.c`, `dm-verity-target.c`.

use crate::crypto::Sha256;
use oncrix_lib::{Error, Result};

// ── Constants ─────────────────────────────────────────────────────

/// dm-verity on-disk magic: ASCII `veri` = 0x76657269.
const VERITY_MAGIC: u32 = 0x7665_7269;

/// SHA-256 digest size in bytes.
const DIGEST_SIZE: usize = 32;

/// Default data block size in bytes.
const DATA_BLOCK_SIZE: u32 = 4096;

/// Default hash block size in bytes.
const HASH_BLOCK_SIZE: u32 = 4096;

/// Maximum hash nodes in the Merkle tree.
const MAX_HASH_NODES: usize = 512;

/// Maximum device name length.
const NAME_LEN: usize = 64;

/// Maximum salt length in bytes.
const SALT_LEN: usize = 32;

/// Maximum registered verity devices.
const MAX_DEVICES: usize = 8;

// ── Hash type ─────────────────────────────────────────────────────

/// Supported hash algorithms for verity verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum VerityHashType {
    /// SHA-256 (NIST FIPS 180-4).
    Sha256 = 0,
}

impl VerityHashType {
    /// Create from raw byte value.
    pub const fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::Sha256),
            _ => None,
        }
    }

    /// Digest output size for this hash algorithm.
    pub const fn digest_size(self) -> usize {
        match self {
            Self::Sha256 => DIGEST_SIZE,
        }
    }
}

// ── Superblock ────────────────────────────────────────────────────

/// On-disk verity superblock describing the device layout.
///
/// Stored at the start of the hash partition.
/// All multi-byte fields are native-endian (matching the running
/// kernel) for in-memory use.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct VeritySuperblock {
    /// Magic number: must be [`VERITY_MAGIC`].
    pub magic: u32,
    /// Superblock format version (currently 1).
    pub version: u32,
    /// Hash algorithm identifier.
    pub hash_type: VerityHashType,
    /// Size of each data block in bytes.
    pub data_block_size: u32,
    /// Size of each hash block in bytes.
    pub hash_block_size: u32,
    /// Number of data blocks protected.
    pub data_blocks: u64,
    /// Optional salt prepended to each hash computation.
    pub salt: [u8; SALT_LEN],
    /// Length of salt actually used (0..=SALT_LEN).
    pub salt_len: usize,
    /// Root hash of the Merkle tree.
    pub root_hash: [u8; DIGEST_SIZE],
}

impl VeritySuperblock {
    /// Create a new superblock with the given parameters.
    pub const fn new(
        data_blocks: u64,
        salt: [u8; SALT_LEN],
        salt_len: usize,
        root_hash: [u8; DIGEST_SIZE],
    ) -> Self {
        Self {
            magic: VERITY_MAGIC,
            version: 1,
            hash_type: VerityHashType::Sha256,
            data_block_size: DATA_BLOCK_SIZE,
            hash_block_size: HASH_BLOCK_SIZE,
            data_blocks,
            salt,
            salt_len,
            root_hash,
        }
    }

    /// Validate the superblock fields.
    pub fn validate(&self) -> Result<()> {
        if self.magic != VERITY_MAGIC {
            return Err(Error::InvalidArgument);
        }
        if self.version != 1 {
            return Err(Error::InvalidArgument);
        }
        if self.data_block_size == 0 || self.hash_block_size == 0 {
            return Err(Error::InvalidArgument);
        }
        if self.data_blocks == 0 {
            return Err(Error::InvalidArgument);
        }
        if self.salt_len > SALT_LEN {
            return Err(Error::InvalidArgument);
        }
        Ok(())
    }
}

// ── Hash node ─────────────────────────────────────────────────────

/// A single node in the Merkle hash tree.
#[derive(Debug, Clone, Copy)]
pub struct VerityHashNode {
    /// SHA-256 digest for this node.
    pub hash: [u8; DIGEST_SIZE],
    /// Tree level (0 = leaf, increases toward root).
    pub level: u32,
    /// Index within this level.
    pub index: u64,
}

impl VerityHashNode {
    /// Create a new hash node.
    pub const fn new(hash: [u8; DIGEST_SIZE], level: u32, index: u64) -> Self {
        Self { hash, level, index }
    }

    /// Create a zeroed hash node.
    const fn zeroed() -> Self {
        Self {
            hash: [0u8; DIGEST_SIZE],
            level: 0,
            index: 0,
        }
    }
}

// ── Merkle hash tree ──────────────────────────────────────────────

/// Merkle hash tree for block integrity verification.
///
/// The tree is built bottom-up: leaf hashes are computed from data
/// blocks, then pairs of hashes are combined to produce parent
/// nodes until a single root hash remains.
pub struct VerityHashTree {
    /// Tree nodes stored in a flat array.
    nodes: [VerityHashNode; MAX_HASH_NODES],
    /// Number of nodes currently in the tree.
    node_count: usize,
    /// Number of leaf nodes (= number of data blocks hashed).
    leaf_count: usize,
    /// Total number of tree levels.
    levels: u32,
    /// Salt prepended to each hash input.
    salt: [u8; SALT_LEN],
    /// Length of salt actually used.
    salt_len: usize,
}

impl VerityHashTree {
    /// Create an empty hash tree with the given salt.
    pub const fn new(salt: [u8; SALT_LEN], salt_len: usize) -> Self {
        Self {
            nodes: [VerityHashNode::zeroed(); MAX_HASH_NODES],
            node_count: 0,
            leaf_count: 0,
            levels: 0,
            salt,
            salt_len,
        }
    }

    /// Compute `SHA-256(salt || data)`.
    fn hash_with_salt(&self, data: &[u8]) -> [u8; DIGEST_SIZE] {
        let mut hasher = Sha256::new();
        if self.salt_len > 0 {
            hasher.update(&self.salt[..self.salt_len]);
        }
        hasher.update(data);
        hasher.finalize()
    }

    /// Compute `SHA-256(salt || left || right)`.
    fn hash_pair(&self, left: &[u8; DIGEST_SIZE], right: &[u8; DIGEST_SIZE]) -> [u8; DIGEST_SIZE] {
        let mut hasher = Sha256::new();
        if self.salt_len > 0 {
            hasher.update(&self.salt[..self.salt_len]);
        }
        hasher.update(left);
        hasher.update(right);
        hasher.finalize()
    }

    /// Build the Merkle tree from an array of data block contents.
    ///
    /// Each element of `blocks` is a slice representing one data
    /// block. The function computes leaf hashes, then iteratively
    /// builds parent levels until a single root node remains.
    ///
    /// Returns the root hash on success.
    pub fn build_tree(&mut self, blocks: &[&[u8]]) -> Result<[u8; DIGEST_SIZE]> {
        if blocks.is_empty() {
            return Err(Error::InvalidArgument);
        }

        // Check we have room for all nodes.
        // For N leaves we need at most 2*N - 1 nodes.
        let max_nodes = blocks.len().saturating_mul(2).saturating_sub(1);
        if max_nodes > MAX_HASH_NODES {
            return Err(Error::OutOfMemory);
        }

        self.node_count = 0;
        self.leaf_count = blocks.len();

        // Level 0: compute leaf hashes from data blocks.
        let mut i = 0usize;
        while i < blocks.len() {
            let hash = self.hash_with_salt(blocks[i]);
            self.nodes[self.node_count] = VerityHashNode::new(hash, 0, i as u64);
            self.node_count += 1;
            i += 1;
        }

        // Build internal levels.
        let mut level: u32 = 0;
        let mut level_start = 0usize;
        let mut level_count = self.leaf_count;

        while level_count > 1 {
            let next_level = level + 1;
            let pairs = level_count / 2;
            let odd = level_count % 2;

            let mut p = 0usize;
            while p < pairs {
                let left_idx = level_start + p * 2;
                let right_idx = level_start + p * 2 + 1;
                let left = self.nodes[left_idx].hash;
                let right = self.nodes[right_idx].hash;
                let parent_hash = self.hash_pair(&left, &right);

                if self.node_count >= MAX_HASH_NODES {
                    return Err(Error::OutOfMemory);
                }
                self.nodes[self.node_count] =
                    VerityHashNode::new(parent_hash, next_level, p as u64);
                self.node_count += 1;
                p += 1;
            }

            // If odd number of nodes, promote the last one directly.
            if odd == 1 {
                let last_idx = level_start + level_count - 1;
                let promoted_hash = self.nodes[last_idx].hash;

                if self.node_count >= MAX_HASH_NODES {
                    return Err(Error::OutOfMemory);
                }
                self.nodes[self.node_count] =
                    VerityHashNode::new(promoted_hash, next_level, pairs as u64);
                self.node_count += 1;
            }

            level_start += level_count;
            level_count = pairs + odd;
            level = next_level;
        }

        self.levels = level;
        Ok(self.nodes[self.node_count - 1].hash)
    }

    /// Verify the integrity of a single data block by walking
    /// the Merkle tree from leaf to root.
    ///
    /// Returns `Ok(())` if the block is valid, or
    /// `Error::IoError` if hash verification fails.
    pub fn verify_block(
        &self,
        block_index: usize,
        block_data: &[u8],
        expected_root: &[u8; DIGEST_SIZE],
    ) -> Result<()> {
        if block_index >= self.leaf_count {
            return Err(Error::InvalidArgument);
        }
        if self.node_count == 0 {
            return Err(Error::InvalidArgument);
        }

        // Recompute the leaf hash.
        let leaf_hash = self.hash_with_salt(block_data);

        // Verify the leaf hash matches what we stored.
        if !constant_time_eq(&leaf_hash, &self.nodes[block_index].hash) {
            return Err(Error::IoError);
        }

        // Walk up the tree verifying each parent.
        let mut current_hash = leaf_hash;
        let mut current_index = block_index;
        let mut level_start = 0usize;
        let mut level_count = self.leaf_count;

        while level_count > 1 {
            let is_left = current_index % 2 == 0;
            let sibling_index = if is_left {
                current_index + 1
            } else {
                current_index - 1
            };

            let parent_hash = if is_left && sibling_index < level_count {
                let sibling = &self.nodes[level_start + sibling_index].hash;
                self.hash_pair(&current_hash, sibling)
            } else if !is_left {
                let sibling = &self.nodes[level_start + sibling_index].hash;
                self.hash_pair(sibling, &current_hash)
            } else {
                // Odd node out: promoted directly.
                current_hash
            };

            let pairs = level_count / 2;
            let odd = level_count % 2;

            level_start += level_count;
            level_count = pairs + odd;
            current_index /= 2;
            current_hash = parent_hash;
        }

        // Final root comparison (constant-time).
        if !constant_time_eq(&current_hash, expected_root) {
            return Err(Error::IoError);
        }

        Ok(())
    }

    /// Get the root hash of the tree.
    pub fn root_hash(&self) -> Result<[u8; DIGEST_SIZE]> {
        if self.node_count == 0 {
            return Err(Error::InvalidArgument);
        }
        Ok(self.nodes[self.node_count - 1].hash)
    }

    /// Get the number of tree levels.
    pub fn levels(&self) -> u32 {
        self.levels
    }

    /// Get the total number of nodes.
    pub fn node_count(&self) -> usize {
        self.node_count
    }
}

// ── Constant-time comparison ──────────────────────────────────────

/// Constant-time byte comparison to prevent timing side channels.
fn constant_time_eq(a: &[u8; DIGEST_SIZE], b: &[u8; DIGEST_SIZE]) -> bool {
    let mut diff = 0u8;
    let mut i = 0usize;
    while i < DIGEST_SIZE {
        diff |= a[i] ^ b[i];
        i += 1;
    }
    diff == 0
}

// ── Verity device ─────────────────────────────────────────────────

/// A dm-verity protected block device.
pub struct VerityDevice {
    /// Superblock describing device parameters.
    superblock: VeritySuperblock,
    /// Merkle hash tree for block verification.
    hash_tree: VerityHashTree,
    /// Human-readable device name.
    name: [u8; NAME_LEN],
    /// Length of the name.
    name_len: usize,
    /// Number of blocks successfully verified.
    verified_count: u64,
    /// Number of blocks that failed verification.
    corruption_count: u64,
    /// Whether the device is active.
    active: bool,
}

impl VerityDevice {
    /// Create a new verity device with the given superblock and name.
    pub fn new(superblock: VeritySuperblock, name: &[u8]) -> Result<Self> {
        superblock.validate()?;

        let name_len = if name.len() > NAME_LEN {
            NAME_LEN
        } else {
            name.len()
        };
        let mut name_buf = [0u8; NAME_LEN];
        let mut i = 0usize;
        while i < name_len {
            name_buf[i] = name[i];
            i += 1;
        }

        let salt = superblock.salt;
        let salt_len = superblock.salt_len;

        Ok(Self {
            superblock,
            hash_tree: VerityHashTree::new(salt, salt_len),
            name: name_buf,
            name_len,
            verified_count: 0,
            corruption_count: 0,
            active: false,
        })
    }

    /// Build the hash tree from data blocks and activate the device.
    pub fn build_and_activate(&mut self, blocks: &[&[u8]]) -> Result<()> {
        let root = self.hash_tree.build_tree(blocks)?;

        // The computed root must match the superblock root hash.
        if !constant_time_eq(&root, &self.superblock.root_hash) {
            return Err(Error::IoError);
        }

        self.active = true;
        Ok(())
    }

    /// Verify the integrity of a single data block.
    pub fn verify_block(&mut self, block_index: usize, block_data: &[u8]) -> Result<()> {
        if !self.active {
            return Err(Error::InvalidArgument);
        }

        let result =
            self.hash_tree
                .verify_block(block_index, block_data, &self.superblock.root_hash);

        match result {
            Ok(()) => {
                self.verified_count = self.verified_count.saturating_add(1);
                Ok(())
            }
            Err(e) => {
                self.corruption_count = self.corruption_count.saturating_add(1);
                Err(e)
            }
        }
    }

    /// Get the device name as a byte slice.
    pub fn name(&self) -> &[u8] {
        &self.name[..self.name_len]
    }

    /// Get the number of successfully verified blocks.
    pub fn verified_count(&self) -> u64 {
        self.verified_count
    }

    /// Get the number of corrupted blocks detected.
    pub fn corruption_count(&self) -> u64 {
        self.corruption_count
    }

    /// Check if the device is active.
    pub fn is_active(&self) -> bool {
        self.active
    }

    /// Deactivate the device.
    pub fn deactivate(&mut self) {
        self.active = false;
    }

    /// Get a reference to the superblock.
    pub fn superblock(&self) -> &VeritySuperblock {
        &self.superblock
    }
}

// ── Verity registry ───────────────────────────────────────────────

/// Registry of active dm-verity devices.
pub struct VerityRegistry {
    /// Registered devices.
    devices: [Option<VerityDevice>; MAX_DEVICES],
    /// Number of registered devices.
    count: usize,
}

impl Default for VerityRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl VerityRegistry {
    /// Create an empty verity registry.
    pub const fn new() -> Self {
        const NONE_DEV: Option<VerityDevice> = None;
        Self {
            devices: [NONE_DEV; MAX_DEVICES],
            count: 0,
        }
    }

    /// Register a new verity device.
    ///
    /// Returns the slot index on success.
    pub fn register(&mut self, device: VerityDevice) -> Result<usize> {
        // Check for duplicate names.
        let new_name = device.name();
        for existing in self.devices.iter().flatten() {
            if existing.name() == new_name {
                return Err(Error::AlreadyExists);
            }
        }

        for (i, slot) in self.devices.iter_mut().enumerate() {
            if slot.is_none() {
                *slot = Some(device);
                self.count += 1;
                return Ok(i);
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Unregister a verity device by slot index.
    pub fn unregister(&mut self, slot: usize) -> Result<()> {
        let device = self
            .devices
            .get_mut(slot)
            .and_then(|s| s.as_mut())
            .ok_or(Error::NotFound)?;
        device.deactivate();
        self.devices[slot] = None;
        self.count = self.count.saturating_sub(1);
        Ok(())
    }

    /// Verify a block on a registered device.
    pub fn verify_block(
        &mut self,
        slot: usize,
        block_index: usize,
        block_data: &[u8],
    ) -> Result<()> {
        let device = self
            .devices
            .get_mut(slot)
            .and_then(|s| s.as_mut())
            .ok_or(Error::NotFound)?;
        device.verify_block(block_index, block_data)
    }

    /// Get verification statistics for a device.
    pub fn get_stats(&self, slot: usize) -> Result<(u64, u64)> {
        let device = self
            .devices
            .get(slot)
            .and_then(|s| s.as_ref())
            .ok_or(Error::NotFound)?;
        Ok((device.verified_count(), device.corruption_count()))
    }

    /// Get a reference to a registered device.
    pub fn get(&self, slot: usize) -> Result<&VerityDevice> {
        self.devices
            .get(slot)
            .and_then(|s| s.as_ref())
            .ok_or(Error::NotFound)
    }

    /// Get a mutable reference to a registered device.
    pub fn get_mut(&mut self, slot: usize) -> Result<&mut VerityDevice> {
        self.devices
            .get_mut(slot)
            .and_then(|s| s.as_mut())
            .ok_or(Error::NotFound)
    }

    /// Number of registered devices.
    pub fn count(&self) -> usize {
        self.count
    }
}

impl core::fmt::Debug for VerityRegistry {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("VerityRegistry")
            .field("count", &self.count)
            .field("capacity", &MAX_DEVICES)
            .finish()
    }
}
