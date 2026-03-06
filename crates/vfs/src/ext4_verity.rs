// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Ext4 fs-verity integration.
//!
//! fs-verity provides read-only, content-authenticated access to files.
//! A verity file is sealed: its data is covered by a Merkle tree whose root
//! hash is stored in the inode's fs-verity descriptor.  Any read that returns
//! data inconsistent with the tree is rejected.
//!
//! This module implements the ext4-specific on-disk layout for the verity
//! descriptor and the in-memory verification state machine.
//!
//! # On-disk layout (ext4)
//!
//! ```text
//! [file data pages]
//! [Merkle tree pages (appended after EOF, inaccessible to userspace)]
//! [fs-verity descriptor (stored in a separate xattr or inline area)]
//! ```
//!
//! The descriptor records the hash algorithm, block size, root hash, and
//! file size so that the Merkle tree can be reconstructed for verification.
//!
//! # Verification flow
//!
//! 1. On `open(O_RDONLY)`, check `i_flags & EXT4_VERITY_FL`.
//! 2. On each page fault / `read(2)`, look up the corresponding leaf hash.
//! 3. Walk from the leaf up to the root, verifying each hash.
//! 4. Compare the computed root against the stored root hash.
//!
//! # References
//!
//! - Linux `fs/ext4/verity.c`, `fs/verity/`
//! - Documentation: `Documentation/filesystems/fsverity.rst`

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum length of a hash digest (SHA-512 = 64 bytes).
pub const MAX_DIGEST_LEN: usize = 64;

/// Maximum depth of a Merkle tree supported.
pub const MAX_MERKLE_DEPTH: usize = 8;

/// fs-verity version stored in the on-disk descriptor.
pub const FS_VERITY_VERSION: u8 = 1;

/// Block size used for the Merkle tree (must match page size or FS block size).
pub const VERITY_BLOCK_SIZE: u32 = 4096;

/// Maximum number of verity-enabled inodes tracked simultaneously.
pub const MAX_VERITY_INODES: usize = 64;

/// EXT4 inode flag indicating fs-verity is enabled.
pub const EXT4_VERITY_FL: u32 = 0x0010_0000;

// ---------------------------------------------------------------------------
// Hash algorithm identifiers (subset of fs-verity spec)
// ---------------------------------------------------------------------------

/// SHA-256 (32-byte digest).
pub const FS_VERITY_HASH_ALG_SHA256: u8 = 1;
/// SHA-512 (64-byte digest).
pub const FS_VERITY_HASH_ALG_SHA512: u8 = 2;
/// CRC32c (4-byte, for testing only).
pub const FS_VERITY_HASH_ALG_CRC32C: u8 = 255;

// ---------------------------------------------------------------------------
// Structures
// ---------------------------------------------------------------------------

/// On-disk fs-verity descriptor (stored in ext4 xattr or inline area).
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct VerityDescriptor {
    /// fs-verity format version (currently 1).
    pub version: u8,
    /// Hash algorithm identifier (`FS_VERITY_HASH_ALG_*`).
    pub hash_algorithm: u8,
    /// Log2 of the Merkle-tree block size.
    pub log_blocksize: u8,
    /// Length of the salt in bytes (0 = no salt).
    pub salt_size: u8,
    /// Reserved; must be zero.
    pub reserved: u32,
    /// Original file size in bytes (excluding Merkle tree pages).
    pub data_size: u64,
    /// Root hash of the Merkle tree.
    pub root_hash: [u8; MAX_DIGEST_LEN],
    /// Optional per-file salt prepended before each hash.
    pub salt: [u8; 32],
    /// Reserved area for future use.
    pub _pad: [u8; 144],
}

/// In-memory verity state for an open inode.
#[derive(Debug)]
pub struct VerityState {
    /// Inode number this state belongs to.
    pub ino: u64,
    /// Copy of the on-disk descriptor.
    pub desc: VerityDescriptor,
    /// Cached Merkle tree level heights (`level_count` valid entries).
    pub level_count: usize,
    /// Number of hash blocks at each tree level (level 0 = leaves).
    pub level_sizes: [u64; MAX_MERKLE_DEPTH],
    /// Number of `read(2)` calls verified against the tree.
    pub reads_verified: u64,
    /// Number of verification failures detected.
    pub verify_failures: u64,
    /// Whether the state is initialised.
    pub initialised: bool,
}

/// A single Merkle tree node (an array of hashes packed into one block).
#[derive(Clone, Debug)]
pub struct MerkleBlock {
    /// Raw block data (VERITY_BLOCK_SIZE bytes).
    pub data: [u8; 64], // Abbreviated to 64 bytes for simulation
    /// Block index within the Merkle tree.
    pub block_idx: u64,
    /// Tree level this block belongs to (0 = leaf layer).
    pub level: u8,
}

/// Result of verifying a single data page against the Merkle tree.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifyResult {
    /// The page is authentic.
    Ok,
    /// The leaf hash did not match the page data.
    LeafHashMismatch { page_idx: u64 },
    /// An intermediate node hash did not match.
    IntermediateHashMismatch { level: u8, block_idx: u64 },
    /// The root hash does not match the stored descriptor.
    RootHashMismatch,
    /// The Merkle tree is absent or unreadable.
    MerkleUnavailable,
}

// ---------------------------------------------------------------------------
// VerityDescriptor helpers
// ---------------------------------------------------------------------------

impl VerityDescriptor {
    /// Construct a minimal descriptor for SHA-256 with no salt.
    pub const fn sha256(data_size: u64, root_hash: [u8; MAX_DIGEST_LEN]) -> Self {
        Self {
            version: FS_VERITY_VERSION,
            hash_algorithm: FS_VERITY_HASH_ALG_SHA256,
            log_blocksize: 12, // log2(4096)
            salt_size: 0,
            reserved: 0,
            data_size,
            root_hash,
            salt: [0u8; 32],
            _pad: [0u8; 144],
        }
    }

    /// Digest length in bytes for this descriptor's hash algorithm.
    pub fn digest_len(&self) -> Result<usize> {
        match self.hash_algorithm {
            FS_VERITY_HASH_ALG_SHA256 => Ok(32),
            FS_VERITY_HASH_ALG_SHA512 => Ok(64),
            FS_VERITY_HASH_ALG_CRC32C => Ok(4),
            _ => Err(Error::InvalidArgument),
        }
    }

    /// Block size in bytes (2 ^ log_blocksize).
    pub fn block_size(&self) -> u32 {
        1u32 << self.log_blocksize
    }

    /// Number of data blocks covered by this file.
    pub fn data_block_count(&self) -> u64 {
        let bs = self.block_size() as u64;
        self.data_size.saturating_add(bs - 1) / bs
    }
}

// ---------------------------------------------------------------------------
// VerityState implementation
// ---------------------------------------------------------------------------

impl VerityState {
    /// Create a new uninitialised verity state for an inode.
    pub const fn uninit(ino: u64) -> Self {
        Self {
            ino,
            desc: VerityDescriptor {
                version: 0,
                hash_algorithm: 0,
                log_blocksize: 0,
                salt_size: 0,
                reserved: 0,
                data_size: 0,
                root_hash: [0u8; MAX_DIGEST_LEN],
                salt: [0u8; 32],
                _pad: [0u8; 144],
            },
            level_count: 0,
            level_sizes: [0u64; MAX_MERKLE_DEPTH],
            reads_verified: 0,
            verify_failures: 0,
            initialised: false,
        }
    }

    /// Initialise the state from an on-disk descriptor.
    pub fn init(&mut self, desc: VerityDescriptor) -> Result<()> {
        self.desc = desc;
        self.compute_tree_levels()?;
        self.initialised = true;
        Ok(())
    }

    /// Compute the number of Merkle tree levels and the block count at each.
    fn compute_tree_levels(&mut self) -> Result<()> {
        let digest_len = self.desc.digest_len()?;
        let bs = self.desc.block_size() as u64;
        let hashes_per_block = bs / digest_len as u64;
        if hashes_per_block == 0 {
            return Err(Error::InvalidArgument);
        }
        let mut blocks = self.desc.data_block_count();
        let mut level = 0;
        while blocks > 1 {
            if level >= MAX_MERKLE_DEPTH {
                return Err(Error::InvalidArgument);
            }
            self.level_sizes[level] = blocks;
            blocks = blocks.saturating_add(hashes_per_block - 1) / hashes_per_block;
            level += 1;
        }
        // Level `level` holds the root (1 block).
        if level < MAX_MERKLE_DEPTH {
            self.level_sizes[level] = 1;
            self.level_count = level + 1;
        }
        Ok(())
    }

    /// Verify a single data page (identified by `page_idx`) against the Merkle
    /// tree by simulating a bottom-up hash walk.
    ///
    /// In a real implementation this reads actual tree blocks and recomputes
    /// hashes.  Here we simulate the walk and assume correctness unless the
    /// verity state is uninitialised.
    pub fn verify_page(&mut self, page_idx: u64) -> VerifyResult {
        if !self.initialised {
            self.verify_failures += 1;
            return VerifyResult::MerkleUnavailable;
        }
        // Check page is within the file.
        if page_idx >= self.desc.data_block_count() {
            self.verify_failures += 1;
            return VerifyResult::LeafHashMismatch { page_idx };
        }
        self.reads_verified += 1;
        VerifyResult::Ok
    }

    /// Simulate enabling verity on a file: seal it and record the root hash.
    ///
    /// After enabling, the file cannot be modified.
    pub fn enable(&mut self, desc: VerityDescriptor) -> Result<()> {
        if self.initialised {
            return Err(Error::AlreadyExists);
        }
        self.init(desc)
    }

    /// Return the stored root hash from the descriptor.
    pub fn root_hash(&self) -> &[u8; MAX_DIGEST_LEN] {
        &self.desc.root_hash
    }
}

// ---------------------------------------------------------------------------
// Verity inode table
// ---------------------------------------------------------------------------

/// A fixed-size table of verity states for open inodes.
pub struct VerityTable {
    /// Per-inode verity states.
    pub states: [VerityState; MAX_VERITY_INODES],
    /// Number of active entries.
    pub count: usize,
}

impl VerityTable {
    /// Create an empty verity table.
    pub fn new() -> Self {
        Self {
            states: core::array::from_fn(|i| VerityState::uninit(i as u64)),
            count: 0,
        }
    }

    /// Look up or allocate a verity state for `ino`.
    ///
    /// Returns `Err(OutOfMemory)` if the table is full and the inode is new.
    pub fn get_or_create(&mut self, ino: u64) -> Result<&mut VerityState> {
        // Search for an existing entry.
        let pos = self.states[..self.count].iter().position(|s| s.ino == ino);
        if let Some(p) = pos {
            return Ok(&mut self.states[p]);
        }
        if self.count >= MAX_VERITY_INODES {
            return Err(Error::OutOfMemory);
        }
        let slot = self.count;
        self.states[slot] = VerityState::uninit(ino);
        self.count += 1;
        Ok(&mut self.states[slot])
    }

    /// Remove the verity state for `ino` (called on `iput`).
    pub fn remove(&mut self, ino: u64) {
        let pos = self.states[..self.count].iter().position(|s| s.ino == ino);
        if let Some(p) = pos {
            self.states[p..self.count].rotate_left(1);
            self.count -= 1;
        }
    }

    /// Verify a page read for a given inode.
    ///
    /// Returns `Err(IoError)` if the inode is not tracked or verification fails.
    pub fn verify_page(&mut self, ino: u64, page_idx: u64) -> Result<()> {
        let pos = self.states[..self.count].iter().position(|s| s.ino == ino);
        let state = match pos {
            Some(p) => &mut self.states[p],
            None => return Err(Error::NotFound),
        };
        match state.verify_page(page_idx) {
            VerifyResult::Ok => Ok(()),
            _ => Err(Error::IoError),
        }
    }
}

impl Default for VerityTable {
    fn default() -> Self {
        Self::new()
    }
}
