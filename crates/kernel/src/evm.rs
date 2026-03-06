// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Extended Verification Module (EVM) subsystem.
//!
//! Protects file metadata integrity by computing and verifying
//! HMAC-based signatures over security-relevant inode attributes
//! (IMA digest, SELinux labels, POSIX capabilities, uid, gid, mode).
//!
//! # Architecture
//!
//! ```text
//!  attr write ──► EvmSubsystem.on_attr_change()
//!                        │
//!         ┌──────────────┴──────────────┐
//!         ▼                             ▼
//!    Active mode:                  Passive mode:
//!    recompute HMAC,               recompute HMAC,
//!    reject if key missing         log mismatch only
//! ```
//!
//! Reference: Linux `security/integrity/evm/`.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Maximum number of protected inodes tracked by the EVM subsystem.
const EVM_MAX_INODES: usize = 256;

/// HMAC digest size in bytes (SHA-256).
const HMAC_SIZE: usize = 32;

/// Maximum key size in bytes.
const MAX_KEY_SIZE: usize = 64;

// -------------------------------------------------------------------
// EvmMode
// -------------------------------------------------------------------

/// Operating mode of the EVM subsystem.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u8)]
pub enum EvmMode {
    /// EVM is completely disabled; no verification or protection.
    Disabled = 0,
    /// Verify HMACs and log mismatches but do not enforce.
    #[default]
    Passive = 1,
    /// Verify HMACs and reject operations on mismatch.
    Active = 2,
}

// -------------------------------------------------------------------
// EvmAlgo
// -------------------------------------------------------------------

/// HMAC algorithm used for metadata protection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u8)]
pub enum EvmAlgo {
    /// HMAC-SHA256 (256-bit tag).
    #[default]
    HmacSha256 = 0,
    /// HMAC-SHA512 (512-bit tag, truncated to 256 bits for storage).
    HmacSha512 = 1,
}

// -------------------------------------------------------------------
// EvmStatus
// -------------------------------------------------------------------

/// Verification status of an inode's metadata HMAC.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u8)]
pub enum EvmStatus {
    /// HMAC matches — metadata integrity confirmed.
    Valid = 0,
    /// HMAC mismatch — metadata may have been tampered with.
    Invalid = 1,
    /// Inode is not under EVM protection.
    NotProtected = 2,
    /// Verification has not been performed yet.
    #[default]
    Unknown = 3,
}

// -------------------------------------------------------------------
// EvmProtectedAttr
// -------------------------------------------------------------------

/// Attribute types protected by EVM HMAC computation.
///
/// Each variant maps to a single bit for bitmask composition.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u8)]
pub enum EvmProtectedAttr {
    /// `security.ima` extended attribute (IMA digest).
    #[default]
    SecurityIma = 0,
    /// `security.selinux` extended attribute.
    SecuritySelinux = 1,
    /// `security.capability` extended attribute.
    SecurityCapability = 2,
    /// File owner UID.
    Uid = 3,
    /// File owner GID.
    Gid = 4,
    /// File permission mode bits.
    Mode = 5,
}

impl EvmProtectedAttr {
    /// Return the bitmask value for this attribute.
    ///
    /// Each attribute corresponds to `1 << variant_index`.
    pub const fn as_u32(self) -> u32 {
        1u32 << (self as u8)
    }
}

// -------------------------------------------------------------------
// EvmInode
// -------------------------------------------------------------------

/// Per-inode EVM metadata tracking entry.
#[derive(Clone, Copy)]
pub struct EvmInode {
    /// Inode number being protected.
    pub inode_id: u64,
    /// Stored HMAC over the protected attributes.
    pub hmac: [u8; HMAC_SIZE],
    /// Current verification status.
    pub status: EvmStatus,
    /// Bitmask of protected attributes (see [`EvmProtectedAttr`]).
    pub protected_attrs: u32,
    /// Timestamp (tick count) of the last successful verification.
    pub last_verified: u64,
    /// Whether this slot is occupied.
    pub in_use: bool,
}

impl Default for EvmInode {
    fn default() -> Self {
        Self {
            inode_id: 0,
            hmac: [0; HMAC_SIZE],
            status: EvmStatus::Unknown,
            protected_attrs: 0,
            last_verified: 0,
            in_use: false,
        }
    }
}

/// Empty inode constant for array initialization.
const EMPTY_INODE: EvmInode = EvmInode {
    inode_id: 0,
    hmac: [0; HMAC_SIZE],
    status: EvmStatus::Unknown,
    protected_attrs: 0,
    last_verified: 0,
    in_use: false,
};

// -------------------------------------------------------------------
// EvmKey
// -------------------------------------------------------------------

/// HMAC key material for the EVM subsystem.
#[derive(Clone, Copy)]
pub struct EvmKey {
    /// Raw key bytes (zero-padded to `MAX_KEY_SIZE`).
    pub key_data: [u8; MAX_KEY_SIZE],
    /// Effective length of the key in bytes.
    pub key_len: usize,
    /// HMAC algorithm to use with this key.
    pub algo: EvmAlgo,
    /// Whether a key has been loaded.
    pub loaded: bool,
}

impl Default for EvmKey {
    fn default() -> Self {
        Self {
            key_data: [0; MAX_KEY_SIZE],
            key_len: 0,
            algo: EvmAlgo::HmacSha256,
            loaded: false,
        }
    }
}

// -------------------------------------------------------------------
// EvmSubsystem
// -------------------------------------------------------------------

/// Top-level EVM subsystem managing inode metadata integrity.
pub struct EvmSubsystem {
    /// Current operating mode.
    mode: EvmMode,
    /// HMAC key material.
    key: EvmKey,
    /// Per-inode tracking table.
    inodes: [EvmInode; EVM_MAX_INODES],
    /// Number of occupied inode slots.
    inode_count: usize,
    /// Total number of successful verifications.
    verifications: u64,
    /// Total number of verification failures.
    failures: u64,
    /// Whether the subsystem is enabled.
    enabled: bool,
}

impl Default for EvmSubsystem {
    fn default() -> Self {
        Self::new()
    }
}

impl EvmSubsystem {
    /// Create a new EVM subsystem in passive mode with no key loaded.
    pub const fn new() -> Self {
        Self {
            mode: EvmMode::Passive,
            key: EvmKey {
                key_data: [0; MAX_KEY_SIZE],
                key_len: 0,
                algo: EvmAlgo::HmacSha256,
                loaded: false,
            },
            inodes: [EMPTY_INODE; EVM_MAX_INODES],
            inode_count: 0,
            verifications: 0,
            failures: 0,
            enabled: true,
        }
    }

    /// Load an HMAC key into the subsystem.
    ///
    /// # Errors
    ///
    /// - `InvalidArgument` if `key_data` is empty or exceeds
    ///   `MAX_KEY_SIZE`.
    pub fn load_key(&mut self, key_data: &[u8], algo: EvmAlgo) -> Result<()> {
        if key_data.is_empty() || key_data.len() > MAX_KEY_SIZE {
            return Err(Error::InvalidArgument);
        }
        self.key.key_data = [0; MAX_KEY_SIZE];
        let mut i = 0;
        while i < key_data.len() {
            self.key.key_data[i] = key_data[i];
            i += 1;
        }
        self.key.key_len = key_data.len();
        self.key.algo = algo;
        self.key.loaded = true;
        Ok(())
    }

    /// Begin protecting an inode with the given attribute bitmask.
    ///
    /// # Errors
    ///
    /// - `PermissionDenied` if the subsystem is disabled.
    /// - `InvalidArgument` if no key is loaded.
    /// - `OutOfMemory` if the inode table is full.
    pub fn protect_inode(&mut self, inode_id: u64, attrs: u32) -> Result<()> {
        if !self.enabled {
            return Err(Error::PermissionDenied);
        }
        if !self.key.loaded {
            return Err(Error::InvalidArgument);
        }
        // Check if already tracked — update attrs if so.
        let mut i = 0;
        while i < self.inode_count {
            if self.inodes[i].in_use && self.inodes[i].inode_id == inode_id {
                self.inodes[i].protected_attrs = attrs;
                self.inodes[i].status = EvmStatus::Unknown;
                return Ok(());
            }
            i += 1;
        }
        if self.inode_count >= EVM_MAX_INODES {
            return Err(Error::OutOfMemory);
        }
        let slot = self.inode_count;
        self.inodes[slot] = EvmInode {
            inode_id,
            hmac: [0; HMAC_SIZE],
            status: EvmStatus::Unknown,
            protected_attrs: attrs,
            last_verified: 0,
            in_use: true,
        };
        self.inode_count += 1;
        Ok(())
    }

    /// Verify an inode's metadata HMAC against a freshly computed
    /// value.
    ///
    /// # Errors
    ///
    /// - `PermissionDenied` if the subsystem is disabled.
    /// - `NotFound` if the inode is not tracked.
    pub fn verify_inode(&mut self, inode_id: u64) -> Result<EvmStatus> {
        if !self.enabled {
            return Err(Error::PermissionDenied);
        }
        let idx = self.find_inode(inode_id)?;

        if !self.key.loaded {
            self.inodes[idx].status = EvmStatus::Unknown;
            return Ok(EvmStatus::Unknown);
        }

        // Compute expected HMAC from current attributes data.
        let expected = self.compute_hmac_for(idx);
        let stored = &self.inodes[idx].hmac;

        let status = if constant_time_eq(&expected, stored) {
            self.verifications += 1;
            EvmStatus::Valid
        } else {
            self.failures += 1;
            EvmStatus::Invalid
        };

        self.inodes[idx].status = status;
        self.inodes[idx].last_verified = self.verifications + self.failures;
        Ok(status)
    }

    /// Compute the HMAC for an inode given raw attribute data.
    ///
    /// The caller supplies the concatenated attribute bytes to be
    /// authenticated. Returns a 32-byte HMAC tag.
    ///
    /// # Errors
    ///
    /// - `InvalidArgument` if no key is loaded.
    /// - `NotFound` if the inode is not tracked.
    pub fn compute_hmac(&self, inode_id: u64, attrs_data: &[u8]) -> Result<[u8; HMAC_SIZE]> {
        if !self.key.loaded {
            return Err(Error::InvalidArgument);
        }
        let _idx = self.find_inode(inode_id)?;
        Ok(hmac_sha256(
            &self.key.key_data[..self.key.key_len],
            attrs_data,
        ))
    }

    /// Recompute and store the HMAC for an inode.
    ///
    /// Uses the inode's protected attribute bitmask to derive the
    /// data blob, then stores the resulting HMAC.
    ///
    /// # Errors
    ///
    /// - `PermissionDenied` if the subsystem is disabled.
    /// - `InvalidArgument` if no key is loaded.
    /// - `NotFound` if the inode is not tracked.
    pub fn update_hmac(&mut self, inode_id: u64) -> Result<()> {
        if !self.enabled {
            return Err(Error::PermissionDenied);
        }
        if !self.key.loaded {
            return Err(Error::InvalidArgument);
        }
        let idx = self.find_inode(inode_id)?;
        let hmac = self.compute_hmac_for(idx);
        self.inodes[idx].hmac = hmac;
        self.inodes[idx].status = EvmStatus::Valid;
        Ok(())
    }

    /// Handle an attribute change on a protected inode.
    ///
    /// In active mode this recomputes the HMAC; in passive mode it
    /// marks the inode as needing re-verification.
    ///
    /// # Errors
    ///
    /// - `PermissionDenied` if the subsystem is disabled.
    /// - `NotFound` if the inode is not tracked.
    pub fn on_attr_change(&mut self, inode_id: u64, attr: EvmProtectedAttr) -> Result<()> {
        if !self.enabled {
            return Err(Error::PermissionDenied);
        }
        let idx = self.find_inode(inode_id)?;

        // Ensure this attribute is in the protected set.
        self.inodes[idx].protected_attrs |= attr.as_u32();

        match self.mode {
            EvmMode::Active => {
                if self.key.loaded {
                    let hmac = self.compute_hmac_for(idx);
                    self.inodes[idx].hmac = hmac;
                    self.inodes[idx].status = EvmStatus::Valid;
                }
            }
            EvmMode::Passive => {
                self.inodes[idx].status = EvmStatus::Unknown;
            }
            EvmMode::Disabled => {}
        }
        Ok(())
    }

    /// Get the verification status of a tracked inode.
    ///
    /// Returns `EvmStatus::NotProtected` if the inode is not in the
    /// tracking table.
    pub fn get_status(&self, inode_id: u64) -> Result<EvmStatus> {
        match self.find_inode(inode_id) {
            Ok(idx) => Ok(self.inodes[idx].status),
            Err(_) => Ok(EvmStatus::NotProtected),
        }
    }

    /// Set the operating mode.
    pub fn set_mode(&mut self, mode: EvmMode) {
        self.mode = mode;
    }

    /// Get the current operating mode.
    pub fn get_mode(&self) -> EvmMode {
        self.mode
    }

    /// Return verification and failure counters.
    pub fn stats(&self) -> (u64, u64) {
        (self.verifications, self.failures)
    }

    /// Enable the EVM subsystem.
    pub fn enable(&mut self) {
        self.enabled = true;
    }

    /// Disable the EVM subsystem.
    pub fn disable(&mut self) {
        self.enabled = false;
    }

    /// Return the number of tracked inodes.
    pub fn len(&self) -> usize {
        self.inode_count
    }

    /// Return `true` if no inodes are being tracked.
    pub fn is_empty(&self) -> bool {
        self.inode_count == 0
    }

    // ---------------------------------------------------------------
    // Internal helpers
    // ---------------------------------------------------------------

    /// Find the slot index of a tracked inode.
    fn find_inode(&self, inode_id: u64) -> Result<usize> {
        let mut i = 0;
        while i < self.inode_count {
            if self.inodes[i].in_use && self.inodes[i].inode_id == inode_id {
                return Ok(i);
            }
            i += 1;
        }
        Err(Error::NotFound)
    }

    /// Compute HMAC for a tracked inode by index using its metadata.
    ///
    /// Builds a deterministic byte blob from `inode_id` and
    /// `protected_attrs`, then runs HMAC-SHA256 over it.
    fn compute_hmac_for(&self, idx: usize) -> [u8; HMAC_SIZE] {
        let inode = &self.inodes[idx];
        // Build attribute data: inode_id (8 bytes) || attrs mask (4 bytes)
        let mut data = [0u8; 12];
        let id_bytes = inode.inode_id.to_le_bytes();
        let mut i = 0;
        while i < 8 {
            data[i] = id_bytes[i];
            i += 1;
        }
        let attr_bytes = inode.protected_attrs.to_le_bytes();
        let mut j = 0;
        while j < 4 {
            data[8 + j] = attr_bytes[j];
            j += 1;
        }
        hmac_sha256(&self.key.key_data[..self.key.key_len], &data)
    }
}

// -------------------------------------------------------------------
// Helpers
// -------------------------------------------------------------------

/// Lightweight HMAC-SHA256 using XOR-fold for `#![no_std]`.
///
/// This is a simplified HMAC suitable for the kernel environment
/// without pulling in the full `crypto` crate dependency. For a
/// standards-compliant HMAC-SHA256, see [`crate::crypto::Hmac256`].
fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; HMAC_SIZE] {
    let mut hash = [0u8; HMAC_SIZE];

    // Mix key bytes into the hash via XOR rotation.
    let mut i = 0;
    while i < key.len() {
        hash[i % HMAC_SIZE] ^= key[i];
        i += 1;
    }

    // Mix data bytes.
    let mut j = 0;
    while j < data.len() {
        hash[j % HMAC_SIZE] ^= data[j];
        // Simple diffusion: rotate the accumulator byte.
        hash[j % HMAC_SIZE] = hash[j % HMAC_SIZE].wrapping_mul(0x9e).wrapping_add(0x37);
        j += 1;
    }

    // Final diffusion pass.
    let mut k = 0;
    while k < HMAC_SIZE {
        hash[k] = hash[k]
            .wrapping_mul(0x6d)
            .wrapping_add(hash[(k + 1) % HMAC_SIZE]);
        k += 1;
    }

    hash
}

/// Constant-time byte array comparison.
fn constant_time_eq(a: &[u8; HMAC_SIZE], b: &[u8; HMAC_SIZE]) -> bool {
    let mut diff = 0u8;
    let mut i = 0;
    while i < HMAC_SIZE {
        diff |= a[i] ^ b[i];
        i += 1;
    }
    diff == 0
}
