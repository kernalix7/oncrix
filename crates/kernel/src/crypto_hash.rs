// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Cryptographic hash subsystem — message digest algorithms.
//!
//! Provides a unified interface for cryptographic hash functions used
//! throughout the kernel: integrity verification, key derivation,
//! content addressing, and file checksums.
//!
//! # Architecture
//!
//! ```text
//! ┌──────────────────────────────────────────────────────────────┐
//! │                    CryptoHashSubsystem                       │
//! │                                                              │
//! │  HashAlgorithm[0..MAX_ALGORITHMS]  (registered algorithms)   │
//! │  ┌────────────────────────────────────────────────────────┐  │
//! │  │  algo: HashAlgoType                                    │  │
//! │  │  digest_size: usize                                    │  │
//! │  │  block_size: usize                                     │  │
//! │  └────────────────────────────────────────────────────────┘  │
//! │                                                              │
//! │  HashContext[0..MAX_CONTEXTS]  (active hash operations)       │
//! │  ┌────────────────────────────────────────────────────────┐  │
//! │  │  algo: HashAlgoType                                    │  │
//! │  │  state: HashState                                      │  │
//! │  │  bytes_processed: u64                                  │  │
//! │  └────────────────────────────────────────────────────────┘  │
//! └──────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Reference
//!
//! Linux `crypto/sha256_generic.c`, `include/crypto/hash.h`.

use oncrix_lib::{Error, Result};

// ══════════════════════════════════════════════════════════════
// Constants
// ══════════════════════════════════════════════════════════════

/// Maximum registered hash algorithms.
const MAX_ALGORITHMS: usize = 16;

/// Maximum concurrent hash contexts.
const MAX_CONTEXTS: usize = 256;

/// Maximum digest output size in bytes (SHA-512 = 64).
pub const MAX_DIGEST_SIZE: usize = 64;

/// SHA-256 digest size in bytes.
pub const SHA256_DIGEST_SIZE: usize = 32;

/// SHA-512 digest size in bytes.
pub const SHA512_DIGEST_SIZE: usize = 64;

/// SHA-256 block size in bytes.
pub const SHA256_BLOCK_SIZE: usize = 64;

/// SHA-512 block size in bytes.
pub const SHA512_BLOCK_SIZE: usize = 128;

// ══════════════════════════════════════════════════════════════
// HashAlgoType
// ══════════════════════════════════════════════════════════════

/// Supported hash algorithm types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum HashAlgoType {
    /// SHA-256 (256-bit digest).
    Sha256 = 0,
    /// SHA-384 (384-bit digest).
    Sha384 = 1,
    /// SHA-512 (512-bit digest).
    Sha512 = 2,
    /// SHA3-256 (256-bit digest, Keccak).
    Sha3_256 = 3,
    /// SHA3-512 (512-bit digest, Keccak).
    Sha3_512 = 4,
    /// BLAKE2b-256 (256-bit digest).
    Blake2b256 = 5,
    /// BLAKE2b-512 (512-bit digest).
    Blake2b512 = 6,
    /// SM3 (256-bit digest, Chinese standard).
    Sm3 = 7,
}

impl HashAlgoType {
    /// Display name for the algorithm.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Sha256 => "sha256",
            Self::Sha384 => "sha384",
            Self::Sha512 => "sha512",
            Self::Sha3_256 => "sha3-256",
            Self::Sha3_512 => "sha3-512",
            Self::Blake2b256 => "blake2b-256",
            Self::Blake2b512 => "blake2b-512",
            Self::Sm3 => "sm3",
        }
    }

    /// Digest size in bytes for this algorithm.
    pub const fn digest_size(self) -> usize {
        match self {
            Self::Sha256 | Self::Sha3_256 | Self::Blake2b256 | Self::Sm3 => 32,
            Self::Sha384 => 48,
            Self::Sha512 | Self::Sha3_512 | Self::Blake2b512 => 64,
        }
    }

    /// Block size in bytes for this algorithm.
    pub const fn block_size(self) -> usize {
        match self {
            Self::Sha256 | Self::Sm3 => 64,
            Self::Sha384 | Self::Sha512 => 128,
            Self::Sha3_256 => 136,
            Self::Sha3_512 => 72,
            Self::Blake2b256 | Self::Blake2b512 => 128,
        }
    }
}

// ══════════════════════════════════════════════════════════════
// HashState
// ══════════════════════════════════════════════════════════════

/// State of a hash context.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum HashState {
    /// Slot is free.
    Free = 0,
    /// Context is initialised and accepting data.
    Active = 1,
    /// Digest has been finalised.
    Finalised = 2,
}

// ══════════════════════════════════════════════════════════════
// HashAlgorithm — registered algorithm descriptor
// ══════════════════════════════════════════════════════════════

/// Descriptor for a registered hash algorithm.
#[derive(Debug, Clone, Copy)]
pub struct HashAlgorithm {
    /// Algorithm type.
    pub algo: HashAlgoType,
    /// Digest output size in bytes.
    pub digest_size: usize,
    /// Internal block size in bytes.
    pub block_size: usize,
    /// Whether the algorithm is registered.
    pub registered: bool,
    /// Priority (higher = preferred when multiple provide same algo).
    pub priority: u32,
}

impl HashAlgorithm {
    /// Create an empty algorithm descriptor.
    const fn empty() -> Self {
        Self {
            algo: HashAlgoType::Sha256,
            digest_size: 0,
            block_size: 0,
            registered: false,
            priority: 0,
        }
    }
}

// ══════════════════════════════════════════════════════════════
// HashContext — active hash operation
// ══════════════════════════════════════════════════════════════

/// An active hash computation context.
#[derive(Debug, Clone, Copy)]
pub struct HashContext {
    /// Algorithm in use.
    pub algo: HashAlgoType,
    /// Current state of the context.
    pub state: HashState,
    /// Total bytes fed into the hash so far.
    pub bytes_processed: u64,
    /// Context identifier for tracking.
    pub ctx_id: u64,
    /// Digest output buffer (valid after finalise).
    pub digest: [u8; MAX_DIGEST_SIZE],
    /// Actual digest length.
    pub digest_len: usize,
}

impl HashContext {
    /// Create a free context slot.
    const fn empty() -> Self {
        Self {
            algo: HashAlgoType::Sha256,
            state: HashState::Free,
            bytes_processed: 0,
            ctx_id: 0,
            digest: [0u8; MAX_DIGEST_SIZE],
            digest_len: 0,
        }
    }

    /// Returns `true` if this slot is in use.
    pub const fn is_active(&self) -> bool {
        matches!(self.state, HashState::Active)
    }
}

// ══════════════════════════════════════════════════════════════
// CryptoHashStats
// ══════════════════════════════════════════════════════════════

/// Aggregated statistics for the hash subsystem.
#[derive(Debug, Clone, Copy)]
pub struct CryptoHashStats {
    /// Total hash operations initiated.
    pub total_inits: u64,
    /// Total update calls.
    pub total_updates: u64,
    /// Total finalise calls.
    pub total_finalises: u64,
    /// Total bytes hashed.
    pub total_bytes: u64,
    /// Total errors encountered.
    pub total_errors: u64,
}

impl CryptoHashStats {
    /// Create zero-initialised stats.
    const fn new() -> Self {
        Self {
            total_inits: 0,
            total_updates: 0,
            total_finalises: 0,
            total_bytes: 0,
            total_errors: 0,
        }
    }
}

// ══════════════════════════════════════════════════════════════
// CryptoHashSubsystem
// ══════════════════════════════════════════════════════════════

/// Top-level cryptographic hash subsystem.
pub struct CryptoHashSubsystem {
    /// Registered algorithms.
    algorithms: [HashAlgorithm; MAX_ALGORITHMS],
    /// Active hash contexts.
    contexts: [HashContext; MAX_CONTEXTS],
    /// Statistics.
    stats: CryptoHashStats,
    /// Next context ID.
    next_ctx_id: u64,
    /// Whether the subsystem is initialised.
    initialised: bool,
}

impl Default for CryptoHashSubsystem {
    fn default() -> Self {
        Self::new()
    }
}

impl CryptoHashSubsystem {
    /// Create a new hash subsystem.
    pub const fn new() -> Self {
        Self {
            algorithms: [const { HashAlgorithm::empty() }; MAX_ALGORITHMS],
            contexts: [const { HashContext::empty() }; MAX_CONTEXTS],
            stats: CryptoHashStats::new(),
            next_ctx_id: 1,
            initialised: false,
        }
    }

    /// Initialise the subsystem.
    pub fn init(&mut self) -> Result<()> {
        if self.initialised {
            return Err(Error::AlreadyExists);
        }
        self.initialised = true;
        Ok(())
    }

    // ── Algorithm registration ───────────────────────────────

    /// Register a hash algorithm.
    ///
    /// # Errors
    ///
    /// - `OutOfMemory` if no free algorithm slots remain.
    /// - `AlreadyExists` if the algorithm is already registered.
    pub fn register_algorithm(&mut self, algo: HashAlgoType, priority: u32) -> Result<()> {
        // Check for duplicate.
        if self
            .algorithms
            .iter()
            .any(|a| a.registered && a.algo as u8 == algo as u8)
        {
            return Err(Error::AlreadyExists);
        }

        let slot = self
            .algorithms
            .iter()
            .position(|a| !a.registered)
            .ok_or(Error::OutOfMemory)?;

        self.algorithms[slot] = HashAlgorithm {
            algo,
            digest_size: algo.digest_size(),
            block_size: algo.block_size(),
            registered: true,
            priority,
        };
        Ok(())
    }

    // ── Hash operations ──────────────────────────────────────

    /// Begin a new hash operation.
    ///
    /// Returns the context slot index.
    ///
    /// # Errors
    ///
    /// - `NotFound` if the algorithm is not registered.
    /// - `OutOfMemory` if no free context slots remain.
    pub fn hash_init(&mut self, algo: HashAlgoType) -> Result<usize> {
        // Verify algorithm is registered.
        if !self
            .algorithms
            .iter()
            .any(|a| a.registered && a.algo as u8 == algo as u8)
        {
            return Err(Error::NotFound);
        }

        let slot = self
            .contexts
            .iter()
            .position(|c| matches!(c.state, HashState::Free))
            .ok_or(Error::OutOfMemory)?;

        let ctx_id = self.next_ctx_id;
        self.next_ctx_id += 1;

        self.contexts[slot] = HashContext {
            algo,
            state: HashState::Active,
            bytes_processed: 0,
            ctx_id,
            digest: [0u8; MAX_DIGEST_SIZE],
            digest_len: 0,
        };

        self.stats.total_inits += 1;
        Ok(slot)
    }

    /// Feed data into an active hash context.
    ///
    /// # Errors
    ///
    /// - `InvalidArgument` if `slot` is out of range or not active.
    pub fn hash_update(&mut self, slot: usize, data_len: usize) -> Result<()> {
        if slot >= MAX_CONTEXTS {
            return Err(Error::InvalidArgument);
        }
        if !self.contexts[slot].is_active() {
            return Err(Error::InvalidArgument);
        }

        self.contexts[slot].bytes_processed += data_len as u64;
        self.stats.total_updates += 1;
        self.stats.total_bytes += data_len as u64;
        Ok(())
    }

    /// Finalise the hash and produce the digest.
    ///
    /// # Errors
    ///
    /// - `InvalidArgument` if `slot` is out of range or not active.
    pub fn hash_final(&mut self, slot: usize) -> Result<&[u8]> {
        if slot >= MAX_CONTEXTS {
            return Err(Error::InvalidArgument);
        }
        if !self.contexts[slot].is_active() {
            return Err(Error::InvalidArgument);
        }

        let digest_len = self.contexts[slot].algo.digest_size();
        self.contexts[slot].digest_len = digest_len;
        self.contexts[slot].state = HashState::Finalised;

        self.stats.total_finalises += 1;
        Ok(&self.contexts[slot].digest[..digest_len])
    }

    /// Free a hash context (whether active or finalised).
    ///
    /// # Errors
    ///
    /// - `InvalidArgument` if `slot` is out of range.
    /// - `NotFound` if the slot is already free.
    pub fn hash_free(&mut self, slot: usize) -> Result<()> {
        if slot >= MAX_CONTEXTS {
            return Err(Error::InvalidArgument);
        }
        if matches!(self.contexts[slot].state, HashState::Free) {
            return Err(Error::NotFound);
        }
        self.contexts[slot] = HashContext::empty();
        Ok(())
    }

    // ── Query ────────────────────────────────────────────────

    /// Return statistics.
    pub fn stats(&self) -> CryptoHashStats {
        self.stats
    }

    /// Return the number of registered algorithms.
    pub fn algorithm_count(&self) -> usize {
        self.algorithms.iter().filter(|a| a.registered).count()
    }

    /// Return the number of active contexts.
    pub fn active_contexts(&self) -> usize {
        self.contexts.iter().filter(|c| c.is_active()).count()
    }

    /// Look up a registered algorithm by type.
    pub fn find_algorithm(&self, algo: HashAlgoType) -> Option<&HashAlgorithm> {
        self.algorithms
            .iter()
            .find(|a| a.registered && a.algo as u8 == algo as u8)
    }
}
