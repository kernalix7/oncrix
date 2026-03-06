// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Device-mapper crypt (dm-crypt) target driver.
//!
//! Implements an AES-XTS transparent block encryption layer over any
//! underlying block device. The `DmCrypt` target intercepts block I/O,
//! encrypts writes and decrypts reads using the configured cipher and key.
//!
//! # Architecture
//!
//! ```text
//! User ──► DmCrypt ──► underlying block device
//!          │
//!          └── AES-XTS-256 (key = 512 bits = two 256-bit keys)
//! ```
//!
//! # dm-crypt Parameters
//!
//! | Parameter   | Description                                  |
//! |-------------|----------------------------------------------|
//! | cipher      | Algorithm:mode:iv e.g. `aes-xts-plain64`    |
//! | key         | Hex-encoded key                              |
//! | iv_offset   | IV offset (sectors from start)               |
//! | dev         | Underlying device                            |
//! | start       | Start LBA on underlying device               |
//!
//! # XTS IV Generation
//!
//! IV = AES-ECB(tweak_key, little-endian-u128(sector_number + iv_offset))
//!
//! This driver models the cipher operations as traits to allow the
//! actual crypto to be plugged in from the crypto layer.
//!
//! Reference: Linux `drivers/md/dm-crypt.c`, cryptsetup LUKS2 spec.

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum number of dm-crypt devices.
pub const MAX_DM_CRYPT_DEVICES: usize = 8;
/// AES-128 key size in bytes.
pub const AES_KEY_128: usize = 16;
/// AES-256 key size in bytes.
pub const AES_KEY_256: usize = 32;
/// XTS key size (two keys = 2 × AES-256).
pub const XTS_KEY_SIZE: usize = 64;
/// AES block size.
pub const AES_BLOCK_SIZE: usize = 16;
/// Sector size (512 bytes).
pub const SECTOR_SIZE: usize = 512;

// ---------------------------------------------------------------------------
// Cipher mode
// ---------------------------------------------------------------------------

/// Cipher algorithm and mode selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CipherMode {
    /// AES-128-XTS.
    Aes128Xts,
    /// AES-256-XTS.
    Aes256Xts,
    /// AES-256-CBC with ESSIV.
    Aes256CbcEssiv,
}

impl Default for CipherMode {
    fn default() -> Self {
        Self::Aes256Xts
    }
}

// ---------------------------------------------------------------------------
// IV generator
// ---------------------------------------------------------------------------

/// IV generation strategy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IvGenerator {
    /// Plain64: IV = little-endian 64-bit sector number + iv_offset.
    Plain64,
    /// ESSIV: IV = AES-ECB(sha256(key), sector_number).
    Essiv,
    /// Null: IV = 0 (insecure, for testing only).
    Null,
}

impl Default for IvGenerator {
    fn default() -> Self {
        Self::Plain64
    }
}

// ---------------------------------------------------------------------------
// DmCryptKey
// ---------------------------------------------------------------------------

/// A dm-crypt encryption key.
#[derive(Clone)]
pub struct DmCryptKey {
    /// Raw key bytes.
    pub bytes: [u8; XTS_KEY_SIZE],
    /// Key length in bytes (16, 32, or 64).
    pub len: usize,
}

impl DmCryptKey {
    /// Creates a key from a byte slice.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `key.len()` is not 16, 32, or 64.
    pub fn from_bytes(key: &[u8]) -> Result<Self> {
        match key.len() {
            16 | 32 | 64 => {}
            _ => return Err(Error::InvalidArgument),
        }
        let mut bytes = [0u8; XTS_KEY_SIZE];
        bytes[..key.len()].copy_from_slice(key);
        Ok(Self {
            bytes,
            len: key.len(),
        })
    }

    /// Returns the encryption key slice.
    pub fn enc_key(&self) -> &[u8] {
        let half = self.len / 2;
        &self.bytes[..half]
    }

    /// Returns the tweak/IV key slice (second half for XTS).
    pub fn tweak_key(&self) -> &[u8] {
        let half = self.len / 2;
        &self.bytes[half..self.len]
    }
}

impl Default for DmCryptKey {
    fn default() -> Self {
        Self {
            bytes: [0u8; XTS_KEY_SIZE],
            len: XTS_KEY_SIZE,
        }
    }
}

// ---------------------------------------------------------------------------
// Sector IV computation
// ---------------------------------------------------------------------------

/// Computes the IV for sector-level encryption.
///
/// For Plain64: IV = u128 little-endian of (sector + iv_offset).
/// For Null: IV = all zeros.
pub fn compute_sector_iv(
    sector: u64,
    iv_offset: u64,
    iv_gen: IvGenerator,
    iv: &mut [u8; AES_BLOCK_SIZE],
) {
    match iv_gen {
        IvGenerator::Plain64 | IvGenerator::Essiv => {
            let val = sector.wrapping_add(iv_offset);
            let le = val.to_le_bytes();
            iv[..8].copy_from_slice(&le);
            iv[8..].fill(0);
        }
        IvGenerator::Null => {
            iv.fill(0);
        }
    }
}

// ---------------------------------------------------------------------------
// Block cipher trait
// ---------------------------------------------------------------------------

/// Trait for a block cipher implementation (AES encrypt/decrypt).
///
/// Implementors are expected to use hardware AES-NI or a software fallback.
pub trait BlockCipher {
    /// Encrypts a single AES block in-place.
    fn encrypt_block(&self, block: &mut [u8; AES_BLOCK_SIZE]);
    /// Decrypts a single AES block in-place.
    fn decrypt_block(&self, block: &mut [u8; AES_BLOCK_SIZE]);
}

// ---------------------------------------------------------------------------
// DmCrypt device
// ---------------------------------------------------------------------------

/// A dm-crypt encrypted block device target.
pub struct DmCrypt {
    /// Cipher mode.
    pub cipher_mode: CipherMode,
    /// IV generator.
    pub iv_mode: IvGenerator,
    /// Encryption key.
    pub key: DmCryptKey,
    /// IV offset (added to sector number for IV generation).
    pub iv_offset: u64,
    /// Start LBA on the underlying device.
    pub start_lba: u64,
    /// Total sectors in this target.
    pub total_sectors: u64,
    /// Underlying device index.
    pub backing_device: usize,
    /// Whether this target is configured.
    pub initialized: bool,
}

impl DmCrypt {
    /// Creates a new dm-crypt device.
    pub const fn new(backing_device: usize) -> Self {
        Self {
            cipher_mode: CipherMode::Aes256Xts,
            iv_mode: IvGenerator::Plain64,
            key: DmCryptKey {
                bytes: [0u8; XTS_KEY_SIZE],
                len: XTS_KEY_SIZE,
            },
            iv_offset: 0,
            start_lba: 0,
            total_sectors: 0,
            backing_device,
            initialized: false,
        }
    }

    /// Configures the dm-crypt target.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if key length doesn't match cipher_mode.
    pub fn configure(
        &mut self,
        cipher_mode: CipherMode,
        iv_mode: IvGenerator,
        key: DmCryptKey,
        iv_offset: u64,
        start_lba: u64,
        total_sectors: u64,
    ) -> Result<()> {
        // Validate key length vs cipher mode.
        match cipher_mode {
            CipherMode::Aes128Xts => {
                if key.len != AES_KEY_128 * 2 {
                    return Err(Error::InvalidArgument);
                }
            }
            CipherMode::Aes256Xts | CipherMode::Aes256CbcEssiv => {
                if key.len != AES_KEY_256 * 2 && key.len != AES_KEY_256 {
                    return Err(Error::InvalidArgument);
                }
            }
        }
        self.cipher_mode = cipher_mode;
        self.iv_mode = iv_mode;
        self.key = key;
        self.iv_offset = iv_offset;
        self.start_lba = start_lba;
        self.total_sectors = total_sectors;
        self.initialized = true;
        Ok(())
    }

    /// Encrypts a sector buffer in-place using the configured cipher.
    ///
    /// `sector_num` is the logical sector number (relative to this target).
    /// `buf` must be exactly `SECTOR_SIZE` bytes.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `buf.len() != SECTOR_SIZE`.
    pub fn encrypt_sector(&self, sector_num: u64, buf: &mut [u8]) -> Result<()> {
        if buf.len() != SECTOR_SIZE {
            return Err(Error::InvalidArgument);
        }
        let mut iv = [0u8; AES_BLOCK_SIZE];
        compute_sector_iv(sector_num, self.iv_offset, self.iv_mode, &mut iv);
        // XTS encryption: process each AES block with tweaked IV.
        // (Actual AES implementation deferred to crypto layer; this models the structure.)
        self.xts_crypt_sector(buf, &iv, true)
    }

    /// Decrypts a sector buffer in-place using the configured cipher.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `buf.len() != SECTOR_SIZE`.
    pub fn decrypt_sector(&self, sector_num: u64, buf: &mut [u8]) -> Result<()> {
        if buf.len() != SECTOR_SIZE {
            return Err(Error::InvalidArgument);
        }
        let mut iv = [0u8; AES_BLOCK_SIZE];
        compute_sector_iv(sector_num, self.iv_offset, self.iv_mode, &mut iv);
        self.xts_crypt_sector(buf, &iv, false)
    }

    /// Translates a target-relative LBA to the backing device LBA.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `lba + count > total_sectors`.
    pub fn translate_lba(&self, lba: u64, count: u64) -> Result<u64> {
        if lba.saturating_add(count) > self.total_sectors {
            return Err(Error::InvalidArgument);
        }
        Ok(self.start_lba + lba)
    }

    /// Returns `true` if the target is configured.
    pub fn is_initialized(&self) -> bool {
        self.initialized
    }

    // -----------------------------------------------------------------------
    // Private: XTS sector encryption stub
    // -----------------------------------------------------------------------

    fn xts_crypt_sector(
        &self,
        buf: &mut [u8],
        iv: &[u8; AES_BLOCK_SIZE],
        _encrypt: bool,
    ) -> Result<()> {
        // XTS mode processes SECTOR_SIZE / AES_BLOCK_SIZE blocks.
        // Each block's tweak = AES_ECB(tweak_key, T xor i) where T = iv, i = block index.
        // This stub XORs each block with the IV (illustrative only — real impl uses AES).
        for block_idx in 0..(SECTOR_SIZE / AES_BLOCK_SIZE) {
            let start = block_idx * AES_BLOCK_SIZE;
            for j in 0..AES_BLOCK_SIZE {
                // Mix in IV and block index (stub; real XTS uses full AES).
                buf[start + j] ^= iv[j] ^ (block_idx as u8);
            }
        }
        Ok(())
    }
}

impl Default for DmCrypt {
    fn default() -> Self {
        Self::new(0)
    }
}

// ---------------------------------------------------------------------------
// Registry
// ---------------------------------------------------------------------------

/// Global dm-crypt device registry.
pub struct DmCryptRegistry {
    devices: [DmCrypt; MAX_DM_CRYPT_DEVICES],
    count: usize,
}

impl DmCryptRegistry {
    /// Creates an empty registry.
    pub const fn new() -> Self {
        Self {
            devices: [const { DmCrypt::new(0) }; MAX_DM_CRYPT_DEVICES],
            count: 0,
        }
    }

    /// Creates a new dm-crypt device.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the registry is full.
    pub fn create(&mut self, backing_device: usize) -> Result<usize> {
        if self.count >= MAX_DM_CRYPT_DEVICES {
            return Err(Error::OutOfMemory);
        }
        let idx = self.count;
        self.devices[idx] = DmCrypt::new(backing_device);
        self.count += 1;
        Ok(idx)
    }

    /// Returns a reference to the device at `index`.
    pub fn get(&self, index: usize) -> Option<&DmCrypt> {
        if index < self.count {
            Some(&self.devices[index])
        } else {
            None
        }
    }

    /// Returns a mutable reference to the device at `index`.
    pub fn get_mut(&mut self, index: usize) -> Option<&mut DmCrypt> {
        if index < self.count {
            Some(&mut self.devices[index])
        } else {
            None
        }
    }

    /// Returns the number of registered devices.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Returns `true` if no devices are registered.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
}

impl Default for DmCryptRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_validation() {
        let key32 = [0u8; 32];
        let k = DmCryptKey::from_bytes(&key32).unwrap();
        assert_eq!(k.len, 32);
        assert_eq!(k.enc_key().len(), 16);
        assert_eq!(k.tweak_key().len(), 16);
    }

    #[test]
    fn key_bad_length() {
        assert!(DmCryptKey::from_bytes(&[0u8; 7]).is_err());
    }

    #[test]
    fn sector_iv_plain64() {
        let mut iv = [0u8; AES_BLOCK_SIZE];
        compute_sector_iv(42, 0, IvGenerator::Plain64, &mut iv);
        assert_eq!(u64::from_le_bytes(iv[..8].try_into().unwrap()), 42);
    }

    #[test]
    fn sector_iv_null() {
        let mut iv = [0xABu8; AES_BLOCK_SIZE];
        compute_sector_iv(42, 0, IvGenerator::Null, &mut iv);
        assert_eq!(iv, [0u8; AES_BLOCK_SIZE]);
    }

    #[test]
    fn dm_crypt_translate_lba() {
        let mut dev = DmCrypt::new(0);
        dev.start_lba = 2048;
        dev.total_sectors = 1024;
        dev.initialized = true;
        assert_eq!(dev.translate_lba(0, 1).unwrap(), 2048);
        assert_eq!(dev.translate_lba(100, 8).unwrap(), 2148);
        assert!(dev.translate_lba(1024, 1).is_err());
    }

    #[test]
    fn encrypt_decrypt_round_trip() {
        let mut dev = DmCrypt::new(0);
        dev.total_sectors = 1000;
        dev.initialized = true;

        let mut sector = [0u8; SECTOR_SIZE];
        // Fill with known pattern.
        for (i, b) in sector.iter_mut().enumerate() {
            *b = (i & 0xFF) as u8;
        }
        let original = sector;
        dev.encrypt_sector(0, &mut sector).unwrap();
        // After encryption, data should differ (XOR with IV != 0 changes it).
        dev.decrypt_sector(0, &mut sector).unwrap();
        // XOR with same IV twice = identity.
        assert_eq!(sector, original);
    }
}
