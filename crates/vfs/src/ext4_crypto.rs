// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Ext4 file-encryption (fscrypt) integration layer.
//!
//! Ext4 supports per-directory encryption via the kernel fscrypt framework.
//! This module implements the ext4-specific policy structures, encryption
//! context storage (in xattrs), and the key derivation helpers used to
//! activate per-file encryption keys.

use oncrix_lib::{Error, Result};

/// Fscrypt policy version 1 magic.
pub const FSCRYPT_POLICY_V1: u8 = 0;
/// Fscrypt policy version 2 magic.
pub const FSCRYPT_POLICY_V2: u8 = 2;

/// Encryption content modes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum FscryptMode {
    /// AES-256-XTS for file contents.
    Aes256Xts = 1,
    /// AES-256-CTS-CBC for filenames.
    Aes256Cts = 4,
    /// AES-128-CBC for file contents.
    Aes128Cbc = 5,
    /// AES-128-CTS-CBC for filenames.
    Aes128Cts = 6,
    /// Adiantum (ChaCha20 + XChaCha12 + Poly1305) for both.
    Adiantum = 9,
    /// AES-256-HCTR2 for filenames.
    Aes256Hctr2 = 10,
}

impl FscryptMode {
    /// Parse from on-disk u8.
    pub fn from_u8(v: u8) -> Result<Self> {
        match v {
            1 => Ok(Self::Aes256Xts),
            4 => Ok(Self::Aes256Cts),
            5 => Ok(Self::Aes128Cbc),
            6 => Ok(Self::Aes128Cts),
            9 => Ok(Self::Adiantum),
            10 => Ok(Self::Aes256Hctr2),
            _ => Err(Error::InvalidArgument),
        }
    }
}

/// Fscrypt policy flags.
pub mod policy_flags {
    /// IV is derived per-file using a stable per-file nonce.
    pub const IV_INO_LBLK_32: u8 = 0x02;
    /// IV includes the inode number (v2 only).
    pub const IV_INO_LBLK_64: u8 = 0x04;
    /// Direct key derivation (for Adiantum).
    pub const DIRECT_KEY: u8 = 0x01;
}

/// Fscrypt v1 encryption policy (16-byte key descriptor).
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct FscryptPolicyV1 {
    pub version: u8,
    pub contents_encryption_mode: u8,
    pub filenames_encryption_mode: u8,
    pub flags: u8,
    /// Key descriptor (8 bytes, displayed as hex in /proc/keys).
    pub master_key_descriptor: [u8; 8],
}

impl FscryptPolicyV1 {
    /// Validate the policy fields.
    pub fn validate(&self) -> Result<()> {
        if self.version != FSCRYPT_POLICY_V1 {
            return Err(Error::InvalidArgument);
        }
        FscryptMode::from_u8(self.contents_encryption_mode)?;
        FscryptMode::from_u8(self.filenames_encryption_mode)?;
        Ok(())
    }
}

/// Fscrypt v2 encryption policy (16-byte key identifier).
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct FscryptPolicyV2 {
    pub version: u8,
    pub contents_encryption_mode: u8,
    pub filenames_encryption_mode: u8,
    pub flags: u8,
    pub _reserved: [u8; 4],
    /// Key identifier (16 bytes, SHA-512 truncated of the master key).
    pub master_key_identifier: [u8; 16],
}

impl FscryptPolicyV2 {
    /// Validate the policy fields.
    pub fn validate(&self) -> Result<()> {
        if self.version != FSCRYPT_POLICY_V2 {
            return Err(Error::InvalidArgument);
        }
        FscryptMode::from_u8(self.contents_encryption_mode)?;
        FscryptMode::from_u8(self.filenames_encryption_mode)?;
        Ok(())
    }
}

/// Xattr name for storing the fscrypt context.
pub const FSCRYPT_XATTR_NAME: &[u8] = b"encryption.ctx";

/// Encryption context stored as an xattr on each encrypted inode.
///
/// The context includes the policy plus a per-file random nonce.
#[derive(Debug, Clone, Copy)]
pub struct FscryptContext {
    /// Policy version (1 or 2).
    pub version: u8,
    /// Contents mode.
    pub contents_mode: u8,
    /// Filenames mode.
    pub filenames_mode: u8,
    /// Policy flags.
    pub flags: u8,
    /// Per-file 16-byte nonce (generated at inode creation).
    pub nonce: [u8; 16],
}

impl FscryptContext {
    /// Create a new context for a v2 policy.
    pub fn new_v2(policy: &FscryptPolicyV2, nonce: [u8; 16]) -> Result<Self> {
        policy.validate()?;
        Ok(Self {
            version: FSCRYPT_POLICY_V2,
            contents_mode: policy.contents_encryption_mode,
            filenames_mode: policy.filenames_encryption_mode,
            flags: policy.flags,
            nonce,
        })
    }

    /// Encode the context into a byte buffer.
    pub fn encode(&self, buf: &mut [u8]) -> Result<usize> {
        if buf.len() < 20 {
            return Err(Error::InvalidArgument);
        }
        buf[0] = self.version;
        buf[1] = self.contents_mode;
        buf[2] = self.filenames_mode;
        buf[3] = self.flags;
        buf[4..20].copy_from_slice(&self.nonce);
        Ok(20)
    }

    /// Decode from a byte buffer.
    pub fn decode(buf: &[u8]) -> Result<Self> {
        if buf.len() < 20 {
            return Err(Error::InvalidArgument);
        }
        let mut nonce = [0u8; 16];
        nonce.copy_from_slice(&buf[4..20]);
        Ok(Self {
            version: buf[0],
            contents_mode: buf[1],
            filenames_mode: buf[2],
            flags: buf[3],
            nonce,
        })
    }
}

/// Per-file encryption key (derived from the master key + nonce + inode).
///
/// The actual key bytes are kept in a zero-on-drop wrapper; here we model
/// the structure and derivation inputs.
#[derive(Debug, Clone)]
pub struct FscryptFileKey {
    /// Inode number this key is bound to.
    pub ino: u64,
    /// Raw key bytes (AES-256 = 32 bytes).
    key_bytes: [u8; 64],
    pub key_len: u8,
}

impl FscryptFileKey {
    /// Derive a file key from a master key, nonce, and inode number.
    ///
    /// Real implementation uses HKDF-SHA512; this is a stub.
    pub fn derive(master_key: &[u8], nonce: &[u8; 16], ino: u64, key_len: u8) -> Result<Self> {
        if master_key.len() < 16 || key_len as usize > 64 {
            return Err(Error::InvalidArgument);
        }
        let mut key_bytes = [0u8; 64];
        // Stub: XOR master key with nonce as placeholder.
        for (i, b) in key_bytes[..key_len as usize].iter_mut().enumerate() {
            *b = master_key[i % master_key.len()] ^ nonce[i % 16] ^ ((ino >> (i % 8 * 8)) as u8);
        }
        Ok(Self {
            ino,
            key_bytes,
            key_len,
        })
    }

    /// Key bytes slice.
    pub fn key_bytes(&self) -> &[u8] {
        &self.key_bytes[..self.key_len as usize]
    }
}

impl Drop for FscryptFileKey {
    fn drop(&mut self) {
        // Zeroize on drop.
        self.key_bytes = [0u8; 64];
    }
}
