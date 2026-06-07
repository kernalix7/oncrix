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

// ── Hash functions ────────────────────────────────────────────────────────────

// fs-verity is part of the integrity TCB: a leaf/page digest is what stands
// between a tampered page and the user.  It therefore MUST use a real
// cryptographic hash, not a folded FNV stub (which collides trivially).
//
// `oncrix-vfs` cannot depend on `oncrix-kernel` (the kernel crate depends on
// vfs, so that would be a dependency cycle), so the verified SHA-256 is
// implemented here self-contained per FIPS 180-4 — the same algorithm and
// round constants as `crates/kernel/src/crypto.rs`.

/// SHA-256 block size in bytes (512-bit message block).
const SHA256_BLOCK_SIZE: usize = 64;

/// SHA-256 initial hash values (FIPS 180-4 §5.3.3): the first 32 bits of the
/// fractional parts of the square roots of the first eight primes.
const SHA256_H_INIT: [u32; 8] = [
    0x6a09_e667,
    0xbb67_ae85,
    0x3c6e_f372,
    0xa54f_f53a,
    0x510e_527f,
    0x9b05_688c,
    0x1f83_d9ab,
    0x5be0_cd19,
];

/// SHA-256 round constants (FIPS 180-4 §4.2.2): the first 32 bits of the
/// fractional parts of the cube roots of the first 64 primes.
const SHA256_K: [u32; 64] = [
    0x428a_2f98,
    0x7137_4491,
    0xb5c0_fbcf,
    0xe9b5_dba5,
    0x3956_c25b,
    0x59f1_11f1,
    0x923f_82a4,
    0xab1c_5ed5,
    0xd807_aa98,
    0x1283_5b01,
    0x2431_85be,
    0x550c_7dc3,
    0x72be_5d74,
    0x80de_b1fe,
    0x9bdc_06a7,
    0xc19b_f174,
    0xe49b_69c1,
    0xefbe_4786,
    0x0fc1_9dc6,
    0x240c_a1cc,
    0x2de9_2c6f,
    0x4a74_84aa,
    0x5cb0_a9dc,
    0x76f9_88da,
    0x983e_5152,
    0xa831_c66d,
    0xb003_27c8,
    0xbf59_7fc7,
    0xc6e0_0bf3,
    0xd5a7_9147,
    0x06ca_6351,
    0x1429_2967,
    0x27b7_0a85,
    0x2e1b_2138,
    0x4d2c_6dfc,
    0x5338_0d13,
    0x650a_7354,
    0x766a_0abb,
    0x81c2_c92e,
    0x9272_2c85,
    0xa2bf_e8a1,
    0xa81a_664b,
    0xc24b_8b70,
    0xc76c_51a3,
    0xd192_e819,
    0xd699_0624,
    0xf40e_3585,
    0x106a_a070,
    0x19a4_c116,
    0x1e37_6c08,
    0x2748_774c,
    0x34b0_bcb5,
    0x391c_0cb3,
    0x4ed8_aa4a,
    0x5b9c_ca4f,
    0x682e_6ff3,
    0x748f_82ee,
    0x78a5_636f,
    0x84c8_7814,
    0x8cc7_0208,
    0x90be_fffa,
    0xa450_6ceb,
    0xbef9_a3f7,
    0xc671_78f2,
];

/// Process one 64-byte block through the SHA-256 compression function.
fn sha256_compress(h: &mut [u32; 8], block: &[u8; SHA256_BLOCK_SIZE]) {
    let mut w = [0u32; 64];
    let mut t = 0usize;
    while t < 16 {
        let base = t.wrapping_mul(4);
        w[t] = u32::from_be_bytes([
            block[base],
            block[base.wrapping_add(1)],
            block[base.wrapping_add(2)],
            block[base.wrapping_add(3)],
        ]);
        t = t.wrapping_add(1);
    }
    while t < 64 {
        let s0 = w[t.wrapping_sub(15)].rotate_right(7)
            ^ w[t.wrapping_sub(15)].rotate_right(18)
            ^ (w[t.wrapping_sub(15)] >> 3);
        let s1 = w[t.wrapping_sub(2)].rotate_right(17)
            ^ w[t.wrapping_sub(2)].rotate_right(19)
            ^ (w[t.wrapping_sub(2)] >> 10);
        w[t] = w[t.wrapping_sub(16)]
            .wrapping_add(s0)
            .wrapping_add(w[t.wrapping_sub(7)])
            .wrapping_add(s1);
        t = t.wrapping_add(1);
    }

    let mut a = h[0];
    let mut b = h[1];
    let mut c = h[2];
    let mut d = h[3];
    let mut e = h[4];
    let mut f = h[5];
    let mut g = h[6];
    let mut hh = h[7];

    let mut i = 0usize;
    while i < 64 {
        let big_s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
        let ch = (e & f) ^ ((!e) & g);
        let t1 = hh
            .wrapping_add(big_s1)
            .wrapping_add(ch)
            .wrapping_add(SHA256_K[i])
            .wrapping_add(w[i]);
        let big_s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
        let maj = (a & b) ^ (a & c) ^ (b & c);
        let t2 = big_s0.wrapping_add(maj);
        hh = g;
        g = f;
        f = e;
        e = d.wrapping_add(t1);
        d = c;
        c = b;
        b = a;
        a = t1.wrapping_add(t2);
        i = i.wrapping_add(1);
    }

    h[0] = h[0].wrapping_add(a);
    h[1] = h[1].wrapping_add(b);
    h[2] = h[2].wrapping_add(c);
    h[3] = h[3].wrapping_add(d);
    h[4] = h[4].wrapping_add(e);
    h[5] = h[5].wrapping_add(f);
    h[6] = h[6].wrapping_add(g);
    h[7] = h[7].wrapping_add(hh);
}

/// Compute the real SHA-256 (FIPS 180-4) digest of `data` into `out`.
///
/// This is a genuine cryptographic hash: leaf and Merkle-node digests
/// produced here are collision-resistant, so a tampered page cannot be
/// forged to match a stored digest.
pub fn sha256(data: &[u8], out: &mut [u8; SHA256_DIGEST_SIZE]) {
    let mut h = SHA256_H_INIT;
    let total_bits = (data.len() as u64).wrapping_mul(8);

    // Process all complete 64-byte blocks straight from the input.
    let full_blocks = data.len() / SHA256_BLOCK_SIZE;
    let mut block = [0u8; SHA256_BLOCK_SIZE];
    let mut b = 0usize;
    while b < full_blocks {
        let start = b.wrapping_mul(SHA256_BLOCK_SIZE);
        block.copy_from_slice(&data[start..start.wrapping_add(SHA256_BLOCK_SIZE)]);
        sha256_compress(&mut h, &block);
        b = b.wrapping_add(1);
    }

    // Assemble the final (padded) block(s) from the trailing bytes.
    let rem_start = full_blocks.wrapping_mul(SHA256_BLOCK_SIZE);
    let rem = &data[rem_start..];
    let mut last = [0u8; SHA256_BLOCK_SIZE];
    last[..rem.len()].copy_from_slice(rem);
    last[rem.len()] = 0x80;

    if rem.len() >= 56 {
        // Not enough room for the 8-byte length; emit this block and start fresh.
        sha256_compress(&mut h, &last);
        last = [0u8; SHA256_BLOCK_SIZE];
    }

    let len_bytes = total_bits.to_be_bytes();
    last[56..].copy_from_slice(&len_bytes);
    sha256_compress(&mut h, &last);

    let mut w = 0usize;
    while w < 8 {
        let bytes = h[w].to_be_bytes();
        let base = w.wrapping_mul(4);
        out[base] = bytes[0];
        out[base.wrapping_add(1)] = bytes[1];
        out[base.wrapping_add(2)] = bytes[2];
        out[base.wrapping_add(3)] = bytes[3];
        w = w.wrapping_add(1);
    }
}

/// Compare two digests in constant time.
///
/// Returns `true` only if both slices have the same length and identical
/// contents.  Timing is independent of the position of the first differing
/// byte, so it cannot be used as an oracle to forge a digest byte-by-byte.
#[must_use]
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    let mut i = 0usize;
    while i < a.len() {
        diff |= a[i] ^ b[i];
        i = i.wrapping_add(1);
    }
    diff == 0
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
    ///
    /// Returns the digest length on success.  SHA-512 fails closed with
    /// [`Error::NotImplemented`]: no verified SHA-512 is available in this
    /// crate, and silently producing a non-cryptographic digest would let a
    /// tampered page be accepted.
    fn hash_block(&self, data: &[u8], out: &mut [u8; MAX_DIGEST_SIZE]) -> Result<usize> {
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
                Ok(SHA256_DIGEST_SIZE)
            }
            HashAlgo::Sha512 => Err(Error::NotImplemented),
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
            let hash_len = self.hash_block(&buf, &mut hash)?;
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
                let hash_len = self.hash_block(&concat[..concat_len], &mut hash)?;
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
        // Recompute the leaf digest with the tree's salt, exactly as `build`
        // did, so a salted leaf compares against the matching stored digest.
        let mut computed = [0u8; MAX_DIGEST_SIZE];
        let hash_len = self.hash_block(data, &mut computed)?;
        // Constant-time compare: never branch on the position of the first
        // differing byte, so the comparison cannot be used as a forging oracle.
        if constant_time_eq(&computed[..hash_len], &expected.hash[..expected.hash_len]) {
            Ok(())
        } else {
            Err(Error::IoError)
        }
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
            // Fail closed: no verified SHA-512 is available, so a SHA-512
            // verity file can never be accepted on a fabricated digest.
            HashAlgo::Sha512 => return Err(Error::NotImplemented),
        };
        if expected_hash.len() != hash_len
            || !constant_time_eq(&computed[..hash_len], &expected_hash[..hash_len])
        {
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
