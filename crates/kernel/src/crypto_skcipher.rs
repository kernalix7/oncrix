// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Symmetric key cipher (skcipher) subsystem.
//!
//! Provides a unified interface for symmetric encryption/decryption
//! algorithms used by the kernel: disk encryption, network TLS,
//! credential protection, and secure IPC.
//!
//! # Architecture
//!
//! ```text
//! ┌──────────────────────────────────────────────────────────────┐
//! │                  SkcipherSubsystem                           │
//! │                                                              │
//! │  CipherAlgorithm[0..MAX_ALGORITHMS]                          │
//! │  ┌────────────────────────────────────────────────────────┐  │
//! │  │  algo: CipherAlgoType                                  │  │
//! │  │  key_size: usize                                       │  │
//! │  │  block_size: usize                                     │  │
//! │  │  iv_size: usize                                        │  │
//! │  └────────────────────────────────────────────────────────┘  │
//! │                                                              │
//! │  CipherContext[0..MAX_CONTEXTS]                               │
//! │  ┌────────────────────────────────────────────────────────┐  │
//! │  │  algo: CipherAlgoType                                  │  │
//! │  │  mode: CipherMode                                      │  │
//! │  │  state: CipherState                                    │  │
//! │  │  bytes_processed: u64                                  │  │
//! │  └────────────────────────────────────────────────────────┘  │
//! └──────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Reference
//!
//! Linux `crypto/skcipher.c`, `include/crypto/skcipher.h`.

use oncrix_lib::{Error, Result};

// ══════════════════════════════════════════════════════════════
// Constants
// ══════════════════════════════════════════════════════════════

/// Maximum registered cipher algorithms.
const MAX_ALGORITHMS: usize = 16;

/// Maximum concurrent cipher contexts.
const MAX_CONTEXTS: usize = 128;

/// Maximum key size in bytes (AES-256 = 32).
pub const MAX_KEY_SIZE: usize = 64;

/// Maximum IV/nonce size in bytes.
pub const MAX_IV_SIZE: usize = 16;

/// AES block size in bytes.
pub const AES_BLOCK_SIZE: usize = 16;

// ══════════════════════════════════════════════════════════════
// CipherAlgoType
// ══════════════════════════════════════════════════════════════

/// Supported symmetric cipher algorithm types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CipherAlgoType {
    /// AES-128 (128-bit key).
    Aes128 = 0,
    /// AES-192 (192-bit key).
    Aes192 = 1,
    /// AES-256 (256-bit key).
    Aes256 = 2,
    /// ChaCha20 (256-bit key, stream cipher).
    ChaCha20 = 3,
    /// ChaCha20-Poly1305 (AEAD).
    ChaCha20Poly1305 = 4,
    /// AES-GCM (128-bit key, AEAD).
    AesGcm128 = 5,
    /// AES-GCM (256-bit key, AEAD).
    AesGcm256 = 6,
    /// Camellia-256 (256-bit key).
    Camellia256 = 7,
}

impl CipherAlgoType {
    /// Display name.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Aes128 => "aes-128",
            Self::Aes192 => "aes-192",
            Self::Aes256 => "aes-256",
            Self::ChaCha20 => "chacha20",
            Self::ChaCha20Poly1305 => "chacha20-poly1305",
            Self::AesGcm128 => "aes-gcm-128",
            Self::AesGcm256 => "aes-gcm-256",
            Self::Camellia256 => "camellia-256",
        }
    }

    /// Key size in bytes.
    pub const fn key_size(self) -> usize {
        match self {
            Self::Aes128 | Self::AesGcm128 => 16,
            Self::Aes192 => 24,
            Self::Aes256
            | Self::ChaCha20
            | Self::ChaCha20Poly1305
            | Self::AesGcm256
            | Self::Camellia256 => 32,
        }
    }

    /// Block size in bytes (0 for stream ciphers).
    pub const fn block_size(self) -> usize {
        match self {
            Self::Aes128
            | Self::Aes192
            | Self::Aes256
            | Self::AesGcm128
            | Self::AesGcm256
            | Self::Camellia256 => 16,
            Self::ChaCha20 | Self::ChaCha20Poly1305 => 1,
        }
    }

    /// IV/nonce size in bytes.
    pub const fn iv_size(self) -> usize {
        match self {
            Self::Aes128 | Self::Aes192 | Self::Aes256 | Self::Camellia256 => 16,
            Self::ChaCha20 | Self::ChaCha20Poly1305 => 12,
            Self::AesGcm128 | Self::AesGcm256 => 12,
        }
    }
}

// ══════════════════════════════════════════════════════════════
// CipherMode
// ══════════════════════════════════════════════════════════════

/// Block cipher mode of operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CipherMode {
    /// Electronic Codebook (insecure, for testing only).
    Ecb = 0,
    /// Cipher Block Chaining.
    Cbc = 1,
    /// Counter mode.
    Ctr = 2,
    /// XTS (disk encryption).
    Xts = 3,
    /// Galois/Counter Mode (AEAD).
    Gcm = 4,
}

impl CipherMode {
    /// Display name.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Ecb => "ecb",
            Self::Cbc => "cbc",
            Self::Ctr => "ctr",
            Self::Xts => "xts",
            Self::Gcm => "gcm",
        }
    }
}

// ══════════════════════════════════════════════════════════════
// CipherState
// ══════════════════════════════════════════════════════════════

/// State of a cipher context.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CipherState {
    /// Slot is free.
    Free = 0,
    /// Context allocated, awaiting key setup.
    Allocated = 1,
    /// Key is set, ready for encrypt/decrypt.
    Keyed = 2,
    /// Context in active encrypt/decrypt operation.
    Active = 3,
}

// ══════════════════════════════════════════════════════════════
// CipherAlgorithm — registered algorithm
// ══════════════════════════════════════════════════════════════

/// Descriptor for a registered cipher algorithm.
#[derive(Debug, Clone, Copy)]
pub struct CipherAlgorithm {
    /// Algorithm type.
    pub algo: CipherAlgoType,
    /// Key size in bytes.
    pub key_size: usize,
    /// Block size in bytes.
    pub block_size: usize,
    /// IV size in bytes.
    pub iv_size: usize,
    /// Whether the algorithm is registered.
    pub registered: bool,
    /// Priority for algorithm selection.
    pub priority: u32,
}

impl CipherAlgorithm {
    /// Create an empty descriptor.
    const fn empty() -> Self {
        Self {
            algo: CipherAlgoType::Aes128,
            key_size: 0,
            block_size: 0,
            iv_size: 0,
            registered: false,
            priority: 0,
        }
    }
}

// ══════════════════════════════════════════════════════════════
// CipherContext — active cipher operation
// ══════════════════════════════════════════════════════════════

/// An active cipher context.
#[derive(Debug, Clone, Copy)]
pub struct CipherContext {
    /// Algorithm in use.
    pub algo: CipherAlgoType,
    /// Mode of operation.
    pub mode: CipherMode,
    /// Current state.
    pub state: CipherState,
    /// Context identifier.
    pub ctx_id: u64,
    /// Total bytes encrypted/decrypted.
    pub bytes_processed: u64,
    /// Whether this context is for encryption (true) or decryption.
    pub encrypting: bool,
}

impl CipherContext {
    /// Create a free context.
    const fn empty() -> Self {
        Self {
            algo: CipherAlgoType::Aes128,
            mode: CipherMode::Cbc,
            state: CipherState::Free,
            ctx_id: 0,
            bytes_processed: 0,
            encrypting: true,
        }
    }
}

// ══════════════════════════════════════════════════════════════
// SkcipherStats
// ══════════════════════════════════════════════════════════════

/// Statistics for the skcipher subsystem.
#[derive(Debug, Clone, Copy)]
pub struct SkcipherStats {
    /// Total encrypt operations.
    pub total_encrypts: u64,
    /// Total decrypt operations.
    pub total_decrypts: u64,
    /// Total bytes encrypted.
    pub total_bytes_encrypted: u64,
    /// Total bytes decrypted.
    pub total_bytes_decrypted: u64,
    /// Total errors.
    pub total_errors: u64,
}

impl SkcipherStats {
    const fn new() -> Self {
        Self {
            total_encrypts: 0,
            total_decrypts: 0,
            total_bytes_encrypted: 0,
            total_bytes_decrypted: 0,
            total_errors: 0,
        }
    }
}

// ══════════════════════════════════════════════════════════════
// SkcipherSubsystem
// ══════════════════════════════════════════════════════════════

/// Top-level symmetric cipher subsystem.
pub struct SkcipherSubsystem {
    /// Registered algorithms.
    algorithms: [CipherAlgorithm; MAX_ALGORITHMS],
    /// Active contexts.
    contexts: [CipherContext; MAX_CONTEXTS],
    /// Statistics.
    stats: SkcipherStats,
    /// Next context ID.
    next_ctx_id: u64,
    /// Whether the subsystem is initialised.
    initialised: bool,
}

impl Default for SkcipherSubsystem {
    fn default() -> Self {
        Self::new()
    }
}

impl SkcipherSubsystem {
    /// Create a new cipher subsystem.
    pub const fn new() -> Self {
        Self {
            algorithms: [const { CipherAlgorithm::empty() }; MAX_ALGORITHMS],
            contexts: [const { CipherContext::empty() }; MAX_CONTEXTS],
            stats: SkcipherStats::new(),
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

    /// Register a cipher algorithm.
    pub fn register_algorithm(&mut self, algo: CipherAlgoType, priority: u32) -> Result<()> {
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

        self.algorithms[slot] = CipherAlgorithm {
            algo,
            key_size: algo.key_size(),
            block_size: algo.block_size(),
            iv_size: algo.iv_size(),
            registered: true,
            priority,
        };
        Ok(())
    }

    // ── Context management ───────────────────────────────────

    /// Allocate a new cipher context.
    ///
    /// Returns the context slot index.
    pub fn alloc_context(
        &mut self,
        algo: CipherAlgoType,
        mode: CipherMode,
        encrypting: bool,
    ) -> Result<usize> {
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
            .position(|c| matches!(c.state, CipherState::Free))
            .ok_or(Error::OutOfMemory)?;

        let ctx_id = self.next_ctx_id;
        self.next_ctx_id += 1;

        self.contexts[slot] = CipherContext {
            algo,
            mode,
            state: CipherState::Allocated,
            ctx_id,
            bytes_processed: 0,
            encrypting,
        };
        Ok(slot)
    }

    /// Set the key on a context, making it ready for operations.
    ///
    /// # Errors
    ///
    /// - `InvalidArgument` if `key_len` does not match the algorithm.
    pub fn set_key(&mut self, slot: usize, key_len: usize) -> Result<()> {
        if slot >= MAX_CONTEXTS {
            return Err(Error::InvalidArgument);
        }
        if !matches!(self.contexts[slot].state, CipherState::Allocated) {
            return Err(Error::InvalidArgument);
        }
        let expected = self.contexts[slot].algo.key_size();
        if key_len != expected {
            return Err(Error::InvalidArgument);
        }
        self.contexts[slot].state = CipherState::Keyed;
        Ok(())
    }

    /// Process data (encrypt or decrypt).
    ///
    /// # Errors
    ///
    /// - `InvalidArgument` if `slot` is out of range or context not keyed.
    pub fn process(&mut self, slot: usize, data_len: usize) -> Result<()> {
        if slot >= MAX_CONTEXTS {
            return Err(Error::InvalidArgument);
        }
        if !matches!(
            self.contexts[slot].state,
            CipherState::Keyed | CipherState::Active
        ) {
            return Err(Error::InvalidArgument);
        }

        self.contexts[slot].state = CipherState::Active;
        self.contexts[slot].bytes_processed += data_len as u64;

        if self.contexts[slot].encrypting {
            self.stats.total_encrypts += 1;
            self.stats.total_bytes_encrypted += data_len as u64;
        } else {
            self.stats.total_decrypts += 1;
            self.stats.total_bytes_decrypted += data_len as u64;
        }
        Ok(())
    }

    /// Free a cipher context.
    pub fn free_context(&mut self, slot: usize) -> Result<()> {
        if slot >= MAX_CONTEXTS {
            return Err(Error::InvalidArgument);
        }
        if matches!(self.contexts[slot].state, CipherState::Free) {
            return Err(Error::NotFound);
        }
        self.contexts[slot] = CipherContext::empty();
        Ok(())
    }

    // ── Query ────────────────────────────────────────────────

    /// Return statistics.
    pub fn stats(&self) -> SkcipherStats {
        self.stats
    }

    /// Return the number of registered algorithms.
    pub fn algorithm_count(&self) -> usize {
        self.algorithms.iter().filter(|a| a.registered).count()
    }

    /// Return the number of active contexts.
    pub fn active_contexts(&self) -> usize {
        self.contexts
            .iter()
            .filter(|c| !matches!(c.state, CipherState::Free))
            .count()
    }
}
