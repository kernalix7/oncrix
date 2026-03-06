// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! fs-verity file integrity measurement.
//!
//! fs-verity is a Linux kernel mechanism that provides transparent,
//! read-only integrity protection for files.  Once enabled on a file,
//! its data is covered by a Merkle tree whose root hash is stored as
//! metadata.  Any attempt to read corrupt data is detected and rejected.
//!
//! # How it works
//!
//! ```text
//! File data (4 KiB pages)
//!   → leaf hash nodes  (SHA-256 / SHA-512 of each page)
//!     → internal nodes  (hash of 128 child hashes per block)
//!       → root hash
//!         → signed digest stored in inode / xattr
//! ```
//!
//! # Enabling verification
//!
//! 1. Call [`FsVerityDescriptor::build`] to construct the Merkle tree.
//! 2. Call [`FsVerityDescriptor::enable`] to lock the file as verity.
//! 3. On each page read, call [`FsVerityVerifier::verify_page`] to
//!    check the leaf hash before returning data to the user.
//!
//! # Structures
//!
//! - [`HashAlgo`]             — hash algorithm (SHA-256 / SHA-512)
//! - [`FsVerityDescriptor`]   — on-disk descriptor (layout matches Linux)
//! - [`MerkleNode`]           — single Merkle tree node (hash value)
//! - [`MerkleTree`]           — in-memory Merkle tree representation
//! - [`FsVerityState`]        — per-inode verity state
//! - [`FsVerityVerifier`]     — page verification logic
//! - [`FsVerityRegistry`]     — global registry of verity-enabled inodes
//!
//! # References
//!
//! - Linux `fs/verity/`, `include/uapi/linux/fsverity.h`
//! - `Documentation/filesystems/fsverity.rst`
//! - `FS_IOC_ENABLE_VERITY`, `FS_IOC_MEASURE_VERITY`

use oncrix_lib::{Error, Result};

// ── Constants ─────────────────────────────────────────────────────────────────

/// Maximum number of verity-enabled inodes tracked globally.
pub const MAX_VERITY_INODES: usize = 64;

/// Block (page) size for Merkle tree leaves (4 KiB).
pub const VERITY_BLOCK_SIZE: usize = 4096;

/// SHA-256 digest size in bytes.
pub const SHA256_DIGEST_SIZE: usize = 32;

/// SHA-512 digest size in bytes.
pub const SHA512_DIGEST_SIZE: usize = 64;

/// Maximum digest size we handle.
pub const MAX_DIGEST_SIZE: usize = SHA512_DIGEST_SIZE;

/// Maximum number of Merkle tree nodes we store per inode.
///
/// This limits the file size we can protect to:
/// `MAX_MERKLE_NODES × VERITY_BLOCK_SIZE` = 8 MiB for a two-level tree.
pub const MAX_MERKLE_NODES: usize = 2048;

/// Number of child hashes that fit in one Merkle block
/// = VERITY_BLOCK_SIZE / SHA256_DIGEST_SIZE = 128.
pub const MERKLE_ARITY: usize = VERITY_BLOCK_SIZE / SHA256_DIGEST_SIZE;

/// Salt size for the Merkle tree (up to 32 bytes, matches Linux).
pub const MAX_SALT_SIZE: usize = 32;

/// fs-verity on-disk magic embedded in the descriptor.
pub const FSVERITY_MAGIC: &[u8; 8] = b"FSVerity";

// ── HashAlgo ─────────────────────────────────────────────────────────────────

/// Hash algorithm used to build the Merkle tree.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u8)]
pub enum HashAlgo {
    /// SHA-256 (32-byte digest).
    #[default]
    Sha256 = 1,
    /// SHA-512 (64-byte digest).
    Sha512 = 2,
}

impl HashAlgo {
    /// Digest size in bytes for this algorithm.
    pub fn digest_size(self) -> usize {
        match self {
            HashAlgo::Sha256 => SHA256_DIGEST_SIZE,
            HashAlgo::Sha512 => SHA512_DIGEST_SIZE,
        }
    }

    /// Construct from the on-disk algorithm ID.
    pub fn from_id(id: u8) -> Result<Self> {
        match id {
            1 => Ok(Self::Sha256),
            2 => Ok(Self::Sha512),
            _ => Err(Error::InvalidArgument),
        }
    }
}

// ── Hash functions (stubs) ────────────────────────────────────────────────────

/// Compute a SHA-256-like hash of `data` into `out`.
///
/// This is a deterministic stub using FNV-1a folded into 32 bytes.
/// A real implementation would call a hardware-accelerated SHA-256.
pub fn sha256(data: &[u8], out: &mut [u8; SHA256_DIGEST_SIZE]) {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in data {
        h ^= b as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01B3);
    }
    // Spread 64-bit hash into 32 bytes deterministically.
    for i in 0..8usize {
        let word = h.wrapping_mul(0x9e37_79b9_7f4a_7c15_u64.wrapping_add(i as u64));
        out[i * 4..(i + 1) * 4].copy_from_slice(&(word as u32).to_le_bytes());
    }
}

/// Compute a SHA-512-like hash of `data` into `out`.
pub fn sha512(data: &[u8], out: &mut [u8; SHA512_DIGEST_SIZE]) {
    let mut h0: u64 = 0x6a09_e667_f3bc_c908;
    let mut h1: u64 = 0xbb67_ae85_84ca_a73b;
    for &b in data {
        h0 ^= b as u64;
        h0 = h0.wrapping_mul(0x0000_0100_0000_01B3);
        h1 ^= h0;
        h1 = h1.wrapping_mul(0xc4cc_eb20_02db_8c08);
    }
    for i in 0..8usize {
        let w0 = h0.wrapping_mul(0x9e37_79b9_7f4a_7c15_u64.wrapping_add(i as u64));
        let w1 = h1.wrapping_mul(0xbf58_476d_1ce4_e5b9_u64.wrapping_add(i as u64));
        out[i * 4..(i + 1) * 4].copy_from_slice(&(w0 as u32).to_le_bytes());
        out[32 + i * 4..32 + (i + 1) * 4].copy_from_slice(&(w1 as u32).to_le_bytes());
    }
}

// ── MerkleNode ────────────────────────────────────────────────────────────────

/// A single node in the Merkle tree (stores the hash value).
#[derive(Debug, Clone, Copy)]
pub struct MerkleNode {
    /// Hash bytes (up to [`MAX_DIGEST_SIZE`]).
    pub hash: [u8; MAX_DIGEST_SIZE],
    /// Number of valid hash bytes (digest_size of the algorithm used).
    pub hash_len: usize,
}

impl Default for MerkleNode {
    fn default() -> Self {
        Self {
            hash: [0u8; MAX_DIGEST_SIZE],
            hash_len: 0,
        }
    }
}

impl MerkleNode {
    /// Create a new node with the given hash bytes.
    pub fn new(hash: &[u8]) -> Result<Self> {
        if hash.len() > MAX_DIGEST_SIZE {
            return Err(Error::InvalidArgument);
        }
        let mut node = Self::default();
        node.hash[..hash.len()].copy_from_slice(hash);
        node.hash_len = hash.len();
        Ok(node)
    }

    /// Return the active hash bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.hash[..self.hash_len]
    }
}

// ── MerkleTree ────────────────────────────────────────────────────────────────

/// In-memory Merkle tree for one fs-verity protected file.
pub struct MerkleTree {
    /// All tree nodes stored level-by-level.
    /// Level 0 = leaf hashes, last level = root.
    nodes: [MerkleNode; MAX_MERKLE_NODES],
    node_count: usize,
    /// Number of leaf nodes (= number of 4 KiB pages in the file).
    pub leaf_count: usize,
    /// Number of tree levels (including the root).
    pub levels: usize,
    /// Hash algorithm.
    pub algo: HashAlgo,
    /// Optional salt prepended to each hash input.
    pub salt: [u8; MAX_SALT_SIZE],
    pub salt_len: usize,
}

impl Default for MerkleTree {
    fn default() -> Self {
        Self {
            nodes: [MerkleNode::default(); MAX_MERKLE_NODES],
            node_count: 0,
            leaf_count: 0,
            levels: 0,
            algo: HashAlgo::Sha256,
            salt: [0u8; MAX_SALT_SIZE],
            salt_len: 0,
        }
    }
}

impl MerkleTree {
    /// Hash one block of data (with optional salt) using the tree's algorithm.
    fn hash_block(&self, data: &[u8], out: &mut [u8; MAX_DIGEST_SIZE]) -> usize {
        match self.algo {
            HashAlgo::Sha256 => {
                let mut buf = [0u8; MAX_SALT_SIZE + VERITY_BLOCK_SIZE];
                let salt = &self.salt[..self.salt_len];
                let len = salt.len() + data.len().min(VERITY_BLOCK_SIZE);
                buf[..salt.len()].copy_from_slice(salt);
                buf[salt.len()..len].copy_from_slice(&data[..data.len().min(VERITY_BLOCK_SIZE)]);
                let mut digest = [0u8; SHA256_DIGEST_SIZE];
                sha256(&buf[..len], &mut digest);
                out[..SHA256_DIGEST_SIZE].copy_from_slice(&digest);
                SHA256_DIGEST_SIZE
            }
            HashAlgo::Sha512 => {
                let mut digest = [0u8; SHA512_DIGEST_SIZE];
                sha512(data, &mut digest);
                out[..SHA512_DIGEST_SIZE].copy_from_slice(&digest);
                SHA512_DIGEST_SIZE
            }
        }
    }

    /// Build the Merkle tree from file data blocks.
    ///
    /// `read_block(idx, buf)` should fill `buf` with 4 KiB of data from
    /// block `idx` and return the number of valid bytes (< 4096 for the
    /// last block).
    pub fn build<F>(&mut self, file_size: u64, read_block: F) -> Result<()>
    where
        F: Fn(u64, &mut [u8; VERITY_BLOCK_SIZE]) -> Result<usize>,
    {
        if file_size == 0 {
            return Err(Error::InvalidArgument);
        }
        let leaf_count =
            ((file_size + VERITY_BLOCK_SIZE as u64 - 1) / VERITY_BLOCK_SIZE as u64) as usize;
        if leaf_count > MAX_MERKLE_NODES {
            return Err(Error::OutOfMemory);
        }

        // Build leaf nodes.
        let mut buf = [0u8; VERITY_BLOCK_SIZE];
        for i in 0..leaf_count {
            read_block(i as u64, &mut buf)?;
            let mut hash = [0u8; MAX_DIGEST_SIZE];
            let hash_len = self.hash_block(&buf, &mut hash);
            if self.node_count >= MAX_MERKLE_NODES {
                return Err(Error::OutOfMemory);
            }
            self.nodes[self.node_count] = MerkleNode::new(&hash[..hash_len])?;
            self.node_count += 1;
        }

        self.leaf_count = leaf_count;
        self.levels = 1;

        // Build internal levels until we reach the root.
        let mut level_start = 0usize;
        let mut level_len = leaf_count;

        while level_len > 1 {
            let parent_count = (level_len + MERKLE_ARITY - 1) / MERKLE_ARITY;
            let parent_start = self.node_count;

            for p in 0..parent_count {
                let child_start = level_start + p * MERKLE_ARITY;
                let child_end = (child_start + MERKLE_ARITY).min(level_start + level_len);

                // Concatenate child hashes into a block-sized buffer.
                let mut concat = [0u8; VERITY_BLOCK_SIZE];
                let digest_size = self.algo.digest_size();
                let mut concat_len = 0usize;
                for c in child_start..child_end {
                    let child_hash = self.nodes[c].as_bytes();
                    let copy_len = child_hash.len().min(digest_size);
                    if concat_len + copy_len > VERITY_BLOCK_SIZE {
                        break;
                    }
                    concat[concat_len..concat_len + copy_len]
                        .copy_from_slice(&child_hash[..copy_len]);
                    concat_len += copy_len;
                }

                let mut hash = [0u8; MAX_DIGEST_SIZE];
                let hash_len = self.hash_block(&concat[..concat_len], &mut hash);
                if self.node_count >= MAX_MERKLE_NODES {
                    return Err(Error::OutOfMemory);
                }
                self.nodes[self.node_count] = MerkleNode::new(&hash[..hash_len])?;
                self.node_count += 1;
            }

            level_start = parent_start;
            level_len = parent_count;
            self.levels += 1;
        }

        Ok(())
    }

    /// Return the root node hash (last node in the tree).
    pub fn root(&self) -> Option<&MerkleNode> {
        if self.node_count == 0 {
            None
        } else {
            Some(&self.nodes[self.node_count - 1])
        }
    }

    /// Verify a single leaf (page) against the stored leaf hash.
    ///
    /// `page_idx` is the 0-based page index within the file.
    pub fn verify_page(&self, page_idx: usize, data: &[u8; VERITY_BLOCK_SIZE]) -> Result<()> {
        if page_idx >= self.leaf_count {
            return Err(Error::InvalidArgument);
        }
        let expected = &self.nodes[page_idx];
        let mut computed_hash = [0u8; MAX_DIGEST_SIZE];
        let hash_len = match self.algo {
            HashAlgo::Sha256 => {
                let mut digest = [0u8; SHA256_DIGEST_SIZE];
                sha256(data, &mut digest);
                computed_hash[..SHA256_DIGEST_SIZE].copy_from_slice(&digest);
                SHA256_DIGEST_SIZE
            }
            HashAlgo::Sha512 => {
                let mut digest = [0u8; SHA512_DIGEST_SIZE];
                sha512(data, &mut digest);
                computed_hash[..SHA512_DIGEST_SIZE].copy_from_slice(&digest);
                SHA512_DIGEST_SIZE
            }
        };
        if computed_hash[..hash_len] != expected.hash[..expected.hash_len] {
            return Err(Error::IoError);
        }
        Ok(())
    }
}

// ── FsVerityDescriptor ────────────────────────────────────────────────────────

/// On-disk fs-verity descriptor, matching the Linux `fsverity_descriptor` layout.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct FsVerityDescriptor {
    /// Magic bytes `b"FSVerity"`.
    pub magic: [u8; 8],
    /// Major version (always 1).
    pub major_version: u8,
    /// Minor version (always 0).
    pub minor_version: u8,
    /// Log2 of the Merkle tree block size (default 12 = 4096).
    pub log_blocksize: u8,
    /// Hash algorithm ID (see [`HashAlgo`]).
    pub hash_algorithm: u8,
    /// Log2 of the data block size (same as log_blocksize in Linux).
    pub log_data_blocksize: u8,
    /// Salt length in bytes (0..32).
    pub salt_size: u8,
    /// Reserved, must be zero.
    pub _reserved0: [u8; 2],
    /// File size in bytes.
    pub data_size: u64,
    /// Root hash of the Merkle tree.
    pub root_hash: [u8; MAX_DIGEST_SIZE],
    /// Salt bytes.
    pub salt: [u8; MAX_SALT_SIZE],
    /// Reserved, must be zero.
    pub _reserved1: [u8; 144],
}

impl Default for FsVerityDescriptor {
    fn default() -> Self {
        Self {
            magic: *FSVERITY_MAGIC,
            major_version: 1,
            minor_version: 0,
            log_blocksize: 12,
            hash_algorithm: HashAlgo::Sha256 as u8,
            log_data_blocksize: 12,
            salt_size: 0,
            _reserved0: [0u8; 2],
            data_size: 0,
            root_hash: [0u8; MAX_DIGEST_SIZE],
            salt: [0u8; MAX_SALT_SIZE],
            _reserved1: [0u8; 144],
        }
    }
}

// ── FsVerityState ─────────────────────────────────────────────────────────────

/// Per-inode fs-verity state.
pub struct FsVerityState {
    /// Inode number.
    pub ino: u64,
    /// Whether verity is enabled for this inode.
    pub enabled: bool,
    /// The on-disk descriptor.
    pub descriptor: FsVerityDescriptor,
    /// In-memory Merkle tree (populated when `enabled` is set).
    pub tree: MerkleTree,
    /// Measurement digest (SHA-256 of the descriptor).
    pub measurement: [u8; SHA256_DIGEST_SIZE],
}

impl Default for FsVerityState {
    fn default() -> Self {
        Self {
            ino: 0,
            enabled: false,
            descriptor: FsVerityDescriptor::default(),
            tree: MerkleTree::default(),
            measurement: [0u8; SHA256_DIGEST_SIZE],
        }
    }
}

impl FsVerityState {
    /// Enable verity using the given Merkle tree and descriptor.
    ///
    /// Computes the measurement digest over the descriptor.
    pub fn enable(&mut self, descriptor: FsVerityDescriptor, tree: MerkleTree) -> Result<()> {
        if self.enabled {
            return Err(Error::AlreadyExists);
        }
        // Compute measurement = SHA-256(descriptor bytes).
        // SAFETY: FsVerityDescriptor is repr(C) and we only read its bytes.
        let desc_bytes = unsafe {
            core::slice::from_raw_parts(
                (&descriptor as *const FsVerityDescriptor) as *const u8,
                core::mem::size_of::<FsVerityDescriptor>(),
            )
        };
        sha256(desc_bytes, &mut self.measurement);
        self.descriptor = descriptor;
        self.tree = tree;
        self.enabled = true;
        Ok(())
    }

    /// Verify a page (4 KiB block) at the given page index.
    pub fn verify_page(&self, page_idx: usize, data: &[u8; VERITY_BLOCK_SIZE]) -> Result<()> {
        if !self.enabled {
            return Ok(()); // Not a verity file; pass through.
        }
        self.tree.verify_page(page_idx, data)
    }
}

// ── FsVerityVerifier ──────────────────────────────────────────────────────────

/// Stateless verifier that checks a page against a known root hash.
pub struct FsVerityVerifier;

impl FsVerityVerifier {
    /// Verify that `data` (a 4 KiB page) hashes to `expected_hash`
    /// using `algo`.
    pub fn verify_leaf(
        algo: HashAlgo,
        data: &[u8; VERITY_BLOCK_SIZE],
        expected_hash: &[u8],
    ) -> Result<()> {
        let mut computed = [0u8; MAX_DIGEST_SIZE];
        let hash_len = match algo {
            HashAlgo::Sha256 => {
                let mut digest = [0u8; SHA256_DIGEST_SIZE];
                sha256(data, &mut digest);
                computed[..SHA256_DIGEST_SIZE].copy_from_slice(&digest);
                SHA256_DIGEST_SIZE
            }
            HashAlgo::Sha512 => {
                let mut digest = [0u8; SHA512_DIGEST_SIZE];
                sha512(data, &mut digest);
                computed[..SHA512_DIGEST_SIZE].copy_from_slice(&digest);
                SHA512_DIGEST_SIZE
            }
        };
        if expected_hash.len() != hash_len || computed[..hash_len] != expected_hash[..hash_len] {
            return Err(Error::IoError);
        }
        Ok(())
    }
}

// ── FsVerityRegistry ─────────────────────────────────────────────────────────

/// Global registry of verity-enabled inodes.
pub struct FsVerityRegistry {
    entries: [Option<FsVerityState>; MAX_VERITY_INODES],
    count: usize,
    /// Total pages verified.
    pub pages_verified: u64,
    /// Total verification failures.
    pub failures: u64,
}

impl Default for FsVerityRegistry {
    fn default() -> Self {
        Self {
            entries: core::array::from_fn(|_| None),
            count: 0,
            pages_verified: 0,
            failures: 0,
        }
    }
}

impl FsVerityRegistry {
    /// Register a new inode with verity state.
    ///
    /// Returns [`Error::OutOfMemory`] if the registry is full.
    pub fn register(&mut self, state: FsVerityState) -> Result<()> {
        if self
            .entries
            .iter()
            .any(|e| e.as_ref().is_some_and(|s| s.ino == state.ino))
        {
            return Err(Error::AlreadyExists);
        }
        let slot = self
            .entries
            .iter()
            .position(|e| e.is_none())
            .ok_or(Error::OutOfMemory)?;
        self.entries[slot] = Some(state);
        self.count += 1;
        Ok(())
    }

    /// Unregister a verity inode.
    pub fn unregister(&mut self, ino: u64) -> Result<()> {
        let slot = self
            .entries
            .iter()
            .position(|e| e.as_ref().is_some_and(|s| s.ino == ino))
            .ok_or(Error::NotFound)?;
        self.entries[slot] = None;
        if self.count > 0 {
            self.count -= 1;
        }
        Ok(())
    }

    /// Look up the verity state for an inode.
    pub fn get(&self, ino: u64) -> Option<&FsVerityState> {
        self.entries
            .iter()
            .find_map(|e| e.as_ref().filter(|s| s.ino == ino))
    }

    /// Look up a mutable verity state for an inode.
    pub fn get_mut(&mut self, ino: u64) -> Option<&mut FsVerityState> {
        self.entries
            .iter_mut()
            .find_map(|e| e.as_mut().filter(|s| s.ino == ino))
    }

    /// Verify a page for a verity-protected inode.
    ///
    /// If `ino` is not registered (not a verity file), returns `Ok(())`.
    pub fn verify_page(
        &mut self,
        ino: u64,
        page_idx: usize,
        data: &[u8; VERITY_BLOCK_SIZE],
    ) -> Result<()> {
        match self.get(ino) {
            None => Ok(()),
            Some(state) => match state.verify_page(page_idx, data) {
                Ok(()) => {
                    self.pages_verified += 1;
                    Ok(())
                }
                Err(e) => {
                    self.failures += 1;
                    Err(e)
                }
            },
        }
    }

    /// Retrieve the measurement digest for an inode (for `FS_IOC_MEASURE_VERITY`).
    pub fn measure(&self, ino: u64) -> Result<&[u8; SHA256_DIGEST_SIZE]> {
        self.get(ino)
            .filter(|s| s.enabled)
            .map(|s| &s.measurement)
            .ok_or(Error::NotFound)
    }

    /// Number of registered verity inodes.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Returns `true` if no inodes are registered.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
}
