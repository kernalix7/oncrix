// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Filesystem-level encryption (fscrypt-style).
//!
//! Provides transparent file content and filename encryption on a
//! per-inode basis, modeled after Linux's fscrypt subsystem. Each
//! encrypted inode carries an [`EncryptionPolicy`] specifying the
//! cipher modes and a reference to a master key. Per-file keys are
//! derived from the master key and a per-inode nonce using
//! HMAC-SHA256.
//!
//! # Design
//!
//! - Master keys are held in an [`FscryptKeyring`] (up to 32 keys).
//! - Each encrypted inode stores an [`FscryptContext`] containing
//!   the policy and a random nonce.
//! - Block encryption/decryption uses AES-128-CBC (derived from the
//!   per-file key) with the block number mixed into the IV.
//! - Filename encryption uses the same per-file key in CBC mode
//!   with a zeroed IV, padded to 16-byte alignment.
//!
//! # References
//!
//! - Linux `fscrypt(7)`, `Documentation/filesystems/fscrypt.rst`
//! - POSIX.1-2024 file encryption interfaces

use oncrix_lib::{Error, Result};

// ── Constants ───────────────────────────────────────────────────

/// AES block size in bytes.
const AES_BLOCK_SIZE: usize = 16;

/// Maximum number of master keys in the keyring.
const MAX_KEYS: usize = 32;

/// Maximum number of encrypted inodes tracked.
const MAX_ENCRYPTED_INODES: usize = 512;

/// Maximum raw key length in bytes.
const MAX_KEY_SIZE: usize = 64;

/// Derived per-file key size (AES-128 = 16 bytes).
const DERIVED_KEY_SIZE: usize = 16;

// ── FscryptMode ─────────────────────────────────────────────────

/// Encryption mode for file contents or filenames.
///
/// Determines which cipher algorithm and mode of operation is used
/// for encrypting data blocks or directory entry names.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum FscryptMode {
    /// AES-256-XTS for contents encryption (default).
    #[default]
    Aes256Xts = 1,
    /// AES-256-CTS-CBC for filenames.
    Aes256Cts = 4,
    /// AES-128-CBC for contents or filenames.
    Aes128Cbc = 5,
    /// Adiantum (wide-block cipher for low-end hardware).
    Adiantum = 9,
}

// ── EncryptionPolicy ────────────────────────────────────────────

/// Encryption policy attached to an inode or directory.
///
/// Specifies the protocol version, cipher modes for contents and
/// filenames, behavioural flags, and the identifier of the master
/// key used to derive per-file keys.
#[derive(Clone, Copy)]
#[repr(C)]
pub struct EncryptionPolicy {
    /// Policy version (currently 1 or 2).
    pub version: u8,
    /// Cipher mode for file contents.
    pub contents_mode: FscryptMode,
    /// Cipher mode for filenames.
    pub filenames_mode: FscryptMode,
    /// Behavioural flags (e.g., direct-key, IV_INO_LBLK).
    pub flags: u8,
    /// Identifier of the master key in the keyring.
    pub master_key_id: [u8; 16],
}

impl EncryptionPolicy {
    /// Creates a zeroed, inactive policy.
    const fn empty() -> Self {
        Self {
            version: 0,
            contents_mode: FscryptMode::Aes256Xts,
            filenames_mode: FscryptMode::Aes256Cts,
            flags: 0,
            master_key_id: [0u8; 16],
        }
    }
}

impl Default for EncryptionPolicy {
    fn default() -> Self {
        Self::empty()
    }
}

// ── FscryptKey ──────────────────────────────────────────────────

/// A master encryption key stored in the keyring.
///
/// Holds up to 64 bytes of raw key material. The `derived` flag
/// indicates whether per-file key derivation has already been
/// performed for caching purposes. [`FscryptKey::zeroize`] must
/// be called when the key is no longer needed to scrub sensitive
/// material from memory.
#[derive(Clone, Copy)]
pub struct FscryptKey {
    /// Raw key material (up to 64 bytes).
    pub raw: [u8; MAX_KEY_SIZE],
    /// Number of valid bytes in `raw`.
    pub len: u8,
    /// Whether a derived key has been produced from this key.
    pub derived: bool,
    /// Key identifier for lookup.
    key_id: [u8; 16],
    /// Whether this slot is occupied.
    active: bool,
}

impl FscryptKey {
    /// Creates an empty, inactive key slot.
    const fn empty() -> Self {
        Self {
            raw: [0u8; MAX_KEY_SIZE],
            len: 0,
            derived: false,
            key_id: [0u8; 16],
            active: false,
        }
    }

    /// Overwrites all key material with zeroes.
    ///
    /// Call this before releasing a key to prevent residual
    /// secrets in memory.
    pub fn zeroize(&mut self) {
        let mut i = 0usize;
        while i < MAX_KEY_SIZE {
            self.raw[i] = 0;
            i += 1;
        }
        self.len = 0;
        self.derived = false;
        let mut j = 0usize;
        while j < 16 {
            self.key_id[j] = 0;
            j += 1;
        }
        self.active = false;
    }
}

impl Default for FscryptKey {
    fn default() -> Self {
        Self::empty()
    }
}

// ── FscryptContext ──────────────────────────────────────────────

/// Per-inode encryption context.
///
/// Stored alongside the inode (typically as an xattr) and contains
/// the encryption policy plus a random nonce used for per-file key
/// derivation.
#[derive(Clone, Copy)]
pub struct FscryptContext {
    /// The encryption policy governing this inode.
    pub policy: EncryptionPolicy,
    /// Random nonce for per-file key derivation.
    pub nonce: [u8; 16],
    /// Whether a valid key is available for this context.
    pub has_key: bool,
}

impl FscryptContext {
    /// Creates an empty context with no key.
    const fn empty() -> Self {
        Self {
            policy: EncryptionPolicy::empty(),
            nonce: [0u8; 16],
            has_key: false,
        }
    }
}

impl Default for FscryptContext {
    fn default() -> Self {
        Self::empty()
    }
}

// ── EncryptedInode ──────────────────────────────────────────────

/// Tracks the encryption state of a single inode.
#[derive(Clone, Copy)]
pub struct EncryptedInode {
    /// Inode number.
    pub inode_id: u64,
    /// Encryption context for this inode.
    pub context: FscryptContext,
    /// Whether this slot is currently in use.
    pub in_use: bool,
}

impl EncryptedInode {
    /// Creates an empty, unused slot.
    const fn empty() -> Self {
        Self {
            inode_id: 0,
            context: FscryptContext::empty(),
            in_use: false,
        }
    }
}

impl Default for EncryptedInode {
    fn default() -> Self {
        Self::empty()
    }
}

// ── FscryptKeyring ──────────────────────────────────────────────

/// Keyring holding master encryption keys.
///
/// Stores up to [`MAX_KEYS`] master keys indexed by a 16-byte key
/// identifier. Supports adding, removing, looking up keys, and
/// deriving per-file keys from a master key and nonce.
pub struct FscryptKeyring {
    /// Key storage slots.
    keys: [FscryptKey; MAX_KEYS],
    /// Number of active keys.
    count: usize,
}

impl Default for FscryptKeyring {
    fn default() -> Self {
        Self::new()
    }
}

impl FscryptKeyring {
    /// Creates an empty keyring.
    pub const fn new() -> Self {
        Self {
            keys: [FscryptKey::empty(); MAX_KEYS],
            count: 0,
        }
    }

    /// Adds a master key to the keyring.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidArgument`] if `key_data` is empty or
    ///   exceeds 64 bytes, or if `key_id` is all zeroes.
    /// - [`Error::AlreadyExists`] if a key with the same
    ///   `key_id` is already present.
    /// - [`Error::OutOfMemory`] if the keyring is full.
    pub fn add_key(&mut self, key_data: &[u8], key_id: &[u8; 16]) -> Result<()> {
        if key_data.is_empty() || key_data.len() > MAX_KEY_SIZE {
            return Err(Error::InvalidArgument);
        }
        // Reject all-zero key IDs.
        if is_zeroed(key_id) {
            return Err(Error::InvalidArgument);
        }
        // Check for duplicate.
        if self.find_key(key_id).is_some() {
            return Err(Error::AlreadyExists);
        }
        // Find a free slot.
        let slot = self.find_free_slot()?;
        let entry = &mut self.keys[slot];
        let mut i = 0usize;
        while i < key_data.len() {
            entry.raw[i] = key_data[i];
            i += 1;
        }
        entry.len = key_data.len() as u8;
        entry.derived = false;
        copy_id(&mut entry.key_id, key_id);
        entry.active = true;
        self.count += 1;
        Ok(())
    }

    /// Removes a master key from the keyring by its identifier.
    ///
    /// The key material is zeroized before the slot is released.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] if no key with `key_id` exists.
    pub fn remove_key(&mut self, key_id: &[u8; 16]) -> Result<()> {
        let idx = self.find_key_index(key_id).ok_or(Error::NotFound)?;
        self.keys[idx].zeroize();
        self.count -= 1;
        Ok(())
    }

    /// Looks up a key by its 16-byte identifier.
    ///
    /// Returns `None` if no matching key is found.
    pub fn find_key(&self, key_id: &[u8; 16]) -> Option<&FscryptKey> {
        let idx = self.find_key_index(key_id)?;
        Some(&self.keys[idx])
    }

    /// Derives a per-file key from a master key and nonce.
    ///
    /// Uses HMAC-SHA256(master_key, nonce) and writes the first
    /// 16 bytes of the result into `out`.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] if no key with `master_key_id` exists.
    /// - [`Error::InvalidArgument`] if `out` is shorter than 16
    ///   bytes.
    pub fn derive_per_file_key(
        &self,
        master_key_id: &[u8; 16],
        nonce: &[u8; 16],
        out: &mut [u8],
    ) -> Result<()> {
        if out.len() < DERIVED_KEY_SIZE {
            return Err(Error::InvalidArgument);
        }
        let key = self.find_key(master_key_id).ok_or(Error::NotFound)?;
        let key_slice = &key.raw[..key.len as usize];
        // HMAC-SHA256(master_key, nonce) → 32 bytes; take first 16.
        let hmac = hmac_sha256(key_slice, nonce);
        let mut i = 0usize;
        while i < DERIVED_KEY_SIZE {
            out[i] = hmac[i];
            i += 1;
        }
        Ok(())
    }

    // ── Private helpers ─────────────────────────────────────────

    /// Finds the index of a key by its identifier.
    fn find_key_index(&self, key_id: &[u8; 16]) -> Option<usize> {
        let mut i = 0usize;
        while i < MAX_KEYS {
            if self.keys[i].active && ids_match(&self.keys[i].key_id, key_id) {
                return Some(i);
            }
            i += 1;
        }
        None
    }

    /// Finds the first free slot in the keys array.
    fn find_free_slot(&self) -> Result<usize> {
        let mut i = 0usize;
        while i < MAX_KEYS {
            if !self.keys[i].active {
                return Ok(i);
            }
            i += 1;
        }
        Err(Error::OutOfMemory)
    }
}

// ── FscryptRegistry ─────────────────────────────────────────────

/// Central registry for all encrypted inodes and the master
/// keyring.
///
/// Manages encryption policies, per-file key derivation, and
/// block/filename encrypt/decrypt operations for the VFS layer.
pub struct FscryptRegistry {
    /// Encrypted inode tracking table.
    encrypted_inodes: [EncryptedInode; MAX_ENCRYPTED_INODES],
    /// Number of active encrypted inodes.
    inode_count: usize,
    /// Master key storage.
    keyring: FscryptKeyring,
}

impl Default for FscryptRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl FscryptRegistry {
    /// Creates an empty registry with no encrypted inodes.
    pub const fn new() -> Self {
        Self {
            encrypted_inodes: [EncryptedInode::empty(); MAX_ENCRYPTED_INODES],
            inode_count: 0,
            keyring: FscryptKeyring::new(),
        }
    }

    /// Returns a mutable reference to the keyring.
    pub fn keyring_mut(&mut self) -> &mut FscryptKeyring {
        &mut self.keyring
    }

    /// Returns a shared reference to the keyring.
    pub fn keyring(&self) -> &FscryptKeyring {
        &self.keyring
    }

    /// Sets the encryption policy for an inode.
    ///
    /// If the inode already has a policy, it is updated. Otherwise
    /// a new slot is allocated.
    ///
    /// # Errors
    ///
    /// - [`Error::OutOfMemory`] if no free inode slots remain.
    pub fn set_policy(&mut self, inode_id: u64, policy: &EncryptionPolicy) -> Result<()> {
        // Update existing entry if present.
        if let Some(idx) = self.find_inode_index(inode_id) {
            self.encrypted_inodes[idx].context.policy = *policy;
            return Ok(());
        }
        // Allocate a new slot.
        let slot = self.find_free_inode_slot()?;
        let entry = &mut self.encrypted_inodes[slot];
        entry.inode_id = inode_id;
        entry.context.policy = *policy;
        entry.in_use = true;
        self.inode_count += 1;
        Ok(())
    }

    /// Retrieves the encryption policy for an inode.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] if the inode has no encryption policy.
    pub fn get_policy(&self, inode_id: u64) -> Result<&EncryptionPolicy> {
        let idx = self.find_inode_index(inode_id).ok_or(Error::NotFound)?;
        Ok(&self.encrypted_inodes[idx].context.policy)
    }

    /// Encrypts a data block for the given inode.
    ///
    /// Derives a per-file key, constructs an IV from the block
    /// number, and encrypts `data` into `out` using AES-128-CBC.
    /// Returns the number of bytes written (always a multiple of
    /// 16, with zero-padding applied if needed).
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] if the inode is not encrypted or the
    ///   master key is missing.
    /// - [`Error::InvalidArgument`] if `out` is too small.
    pub fn encrypt_block(
        &self,
        inode_id: u64,
        block_num: u64,
        data: &[u8],
        out: &mut [u8],
    ) -> Result<usize> {
        let ctx = self.get_context(inode_id)?;
        let mut derived = [0u8; DERIVED_KEY_SIZE];
        self.keyring
            .derive_per_file_key(&ctx.policy.master_key_id, &ctx.nonce, &mut derived)?;
        // Pad data to AES block boundary.
        let padded_len = round_up_16(data.len());
        if out.len() < padded_len {
            return Err(Error::InvalidArgument);
        }
        // Copy data into output buffer with zero padding.
        let mut i = 0usize;
        while i < data.len() {
            out[i] = data[i];
            i += 1;
        }
        while i < padded_len {
            out[i] = 0;
            i += 1;
        }
        // Build IV from block number.
        let iv = block_num_to_iv(block_num);
        // Encrypt in place using CBC.
        aes128_cbc_encrypt(&derived, &iv, &mut out[..padded_len])?;
        Ok(padded_len)
    }

    /// Decrypts a data block for the given inode.
    ///
    /// The inverse of [`Self::encrypt_block`]. Returns the number
    /// of bytes written to `out`.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] if the inode is not encrypted or the
    ///   master key is missing.
    /// - [`Error::InvalidArgument`] if `data` length is not a
    ///   multiple of 16 or `out` is too small.
    pub fn decrypt_block(
        &self,
        inode_id: u64,
        block_num: u64,
        data: &[u8],
        out: &mut [u8],
    ) -> Result<usize> {
        if data.len() % AES_BLOCK_SIZE != 0 {
            return Err(Error::InvalidArgument);
        }
        if out.len() < data.len() {
            return Err(Error::InvalidArgument);
        }
        let ctx = self.get_context(inode_id)?;
        let mut derived = [0u8; DERIVED_KEY_SIZE];
        self.keyring
            .derive_per_file_key(&ctx.policy.master_key_id, &ctx.nonce, &mut derived)?;
        // Copy ciphertext to output.
        let mut i = 0usize;
        while i < data.len() {
            out[i] = data[i];
            i += 1;
        }
        let iv = block_num_to_iv(block_num);
        aes128_cbc_decrypt(&derived, &iv, &mut out[..data.len()])?;
        Ok(data.len())
    }

    /// Encrypts a filename for the given inode.
    ///
    /// Pads the name to a 16-byte boundary and encrypts using
    /// AES-128-CBC with a zeroed IV. Returns the number of
    /// encrypted bytes written to `out`.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] if the inode is not encrypted or the
    ///   master key is missing.
    /// - [`Error::InvalidArgument`] if `out` is too small.
    pub fn encrypt_filename(&self, inode_id: u64, name: &[u8], out: &mut [u8]) -> Result<usize> {
        if name.is_empty() {
            return Err(Error::InvalidArgument);
        }
        let ctx = self.get_context(inode_id)?;
        let mut derived = [0u8; DERIVED_KEY_SIZE];
        self.keyring
            .derive_per_file_key(&ctx.policy.master_key_id, &ctx.nonce, &mut derived)?;
        let padded_len = round_up_16(name.len());
        if out.len() < padded_len {
            return Err(Error::InvalidArgument);
        }
        // Copy name with zero padding.
        let mut i = 0usize;
        while i < name.len() {
            out[i] = name[i];
            i += 1;
        }
        while i < padded_len {
            out[i] = 0;
            i += 1;
        }
        let iv = [0u8; AES_BLOCK_SIZE];
        aes128_cbc_encrypt(&derived, &iv, &mut out[..padded_len])?;
        Ok(padded_len)
    }

    /// Decrypts a filename for the given inode.
    ///
    /// The inverse of [`Self::encrypt_filename`]. Returns the
    /// number of decrypted bytes written to `out`.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] if the inode is not encrypted or the
    ///   master key is missing.
    /// - [`Error::InvalidArgument`] if `data` is not aligned to
    ///   16 bytes or `out` is too small.
    pub fn decrypt_filename(&self, inode_id: u64, data: &[u8], out: &mut [u8]) -> Result<usize> {
        if data.is_empty() || data.len() % AES_BLOCK_SIZE != 0 {
            return Err(Error::InvalidArgument);
        }
        if out.len() < data.len() {
            return Err(Error::InvalidArgument);
        }
        let ctx = self.get_context(inode_id)?;
        let mut derived = [0u8; DERIVED_KEY_SIZE];
        self.keyring
            .derive_per_file_key(&ctx.policy.master_key_id, &ctx.nonce, &mut derived)?;
        let mut i = 0usize;
        while i < data.len() {
            out[i] = data[i];
            i += 1;
        }
        let iv = [0u8; AES_BLOCK_SIZE];
        aes128_cbc_decrypt(&derived, &iv, &mut out[..data.len()])?;
        Ok(data.len())
    }

    /// Returns `true` if the given inode has an encryption policy.
    pub fn is_encrypted(&self, inode_id: u64) -> bool {
        self.find_inode_index(inode_id).is_some()
    }

    /// Returns the number of encrypted inodes tracked.
    pub fn len(&self) -> usize {
        self.inode_count
    }

    /// Returns `true` if no encrypted inodes are tracked.
    pub fn is_empty(&self) -> bool {
        self.inode_count == 0
    }

    // ── Private helpers ─────────────────────────────────────────

    /// Retrieves the encryption context for an inode.
    fn get_context(&self, inode_id: u64) -> Result<&FscryptContext> {
        let idx = self.find_inode_index(inode_id).ok_or(Error::NotFound)?;
        Ok(&self.encrypted_inodes[idx].context)
    }

    /// Finds the slot index for a given inode ID.
    fn find_inode_index(&self, inode_id: u64) -> Option<usize> {
        let mut i = 0usize;
        while i < MAX_ENCRYPTED_INODES {
            if self.encrypted_inodes[i].in_use && self.encrypted_inodes[i].inode_id == inode_id {
                return Some(i);
            }
            i += 1;
        }
        None
    }

    /// Finds the first free slot in the encrypted inodes table.
    fn find_free_inode_slot(&self) -> Result<usize> {
        let mut i = 0usize;
        while i < MAX_ENCRYPTED_INODES {
            if !self.encrypted_inodes[i].in_use {
                return Ok(i);
            }
            i += 1;
        }
        Err(Error::OutOfMemory)
    }
}

// ── Free-standing helpers ───────────────────────────────────────

/// Returns `true` if all 16 bytes are zero.
fn is_zeroed(id: &[u8; 16]) -> bool {
    let mut i = 0usize;
    while i < 16 {
        if id[i] != 0 {
            return false;
        }
        i += 1;
    }
    true
}

/// Copies a 16-byte identifier.
fn copy_id(dst: &mut [u8; 16], src: &[u8; 16]) {
    let mut i = 0usize;
    while i < 16 {
        dst[i] = src[i];
        i += 1;
    }
}

/// Compares two 16-byte identifiers for equality.
fn ids_match(a: &[u8; 16], b: &[u8; 16]) -> bool {
    let mut i = 0usize;
    while i < 16 {
        if a[i] != b[i] {
            return false;
        }
        i += 1;
    }
    true
}

/// Rounds `len` up to the next multiple of 16.
fn round_up_16(len: usize) -> usize {
    if len == 0 {
        AES_BLOCK_SIZE
    } else {
        (len + AES_BLOCK_SIZE - 1) & !(AES_BLOCK_SIZE - 1)
    }
}

/// Builds a 16-byte IV from a block number.
///
/// The block number is placed in the first 8 bytes (little-endian)
/// with the remaining 8 bytes zeroed.
fn block_num_to_iv(block_num: u64) -> [u8; AES_BLOCK_SIZE] {
    let mut iv = [0u8; AES_BLOCK_SIZE];
    let bytes = block_num.to_le_bytes();
    let mut i = 0usize;
    while i < 8 {
        iv[i] = bytes[i];
        i += 1;
    }
    iv
}

/// Minimal HMAC-SHA256 using the kernel crypto primitives.
///
/// Computes HMAC-SHA256(key, data) and returns the 32-byte tag.
/// Implemented inline to avoid depending on the kernel crate
/// directly — uses the same algorithm as `oncrix_kernel::crypto`.
fn hmac_sha256(key: &[u8], data: &[u8; 16]) -> [u8; 32] {
    const BLOCK_SIZE: usize = 64;
    const DIGEST_SIZE: usize = 32;

    // Normalize key to 64 bytes.
    let mut key_block = [0u8; BLOCK_SIZE];
    if key.len() > BLOCK_SIZE {
        // Hash long keys with a simple pass (SHA-256).
        let hashed = sha256_digest(key);
        let mut i = 0usize;
        while i < DIGEST_SIZE {
            key_block[i] = hashed[i];
            i += 1;
        }
    } else {
        let mut i = 0usize;
        while i < key.len() {
            key_block[i] = key[i];
            i += 1;
        }
    }

    // ipad and opad.
    let mut ipad = [0u8; BLOCK_SIZE];
    let mut opad = [0u8; BLOCK_SIZE];
    let mut i = 0usize;
    while i < BLOCK_SIZE {
        ipad[i] = key_block[i] ^ 0x36;
        opad[i] = key_block[i] ^ 0x5c;
        i += 1;
    }

    // inner = SHA256(ipad || data)
    let mut inner_buf = [0u8; BLOCK_SIZE + 16];
    i = 0;
    while i < BLOCK_SIZE {
        inner_buf[i] = ipad[i];
        i += 1;
    }
    let mut j = 0usize;
    while j < 16 {
        inner_buf[BLOCK_SIZE + j] = data[j];
        j += 1;
    }
    let inner_hash = sha256_digest(&inner_buf);

    // outer = SHA256(opad || inner_hash)
    let mut outer_buf = [0u8; BLOCK_SIZE + DIGEST_SIZE];
    i = 0;
    while i < BLOCK_SIZE {
        outer_buf[i] = opad[i];
        i += 1;
    }
    j = 0;
    while j < DIGEST_SIZE {
        outer_buf[BLOCK_SIZE + j] = inner_hash[j];
        j += 1;
    }
    sha256_digest(&outer_buf)
}

/// Minimal SHA-256 digest (self-contained, no external deps).
///
/// This is a simplified single-shot SHA-256 implementation used
/// only for HMAC key derivation within fscrypt. It mirrors the
/// algorithm in `oncrix_kernel::crypto::Sha256`.
fn sha256_digest(data: &[u8]) -> [u8; 32] {
    const SHA_K: [u32; 64] = [
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
    let sha_h_init: [u32; 8] = [
        0x6a09_e667,
        0xbb67_ae85,
        0x3c6e_f372,
        0xa54f_f53a,
        0x510e_527f,
        0x9b05_688c,
        0x1f83_d9ab,
        0x5be0_cd19,
    ];

    let mut h = sha_h_init;
    let total_bits = (data.len() as u64).wrapping_mul(8);

    // Process full 64-byte blocks.
    let full_blocks = data.len() / 64;
    let mut blk = 0usize;
    while blk < full_blocks {
        let off = blk * 64;
        let mut block = [0u8; 64];
        let mut bi = 0usize;
        while bi < 64 {
            block[bi] = data[off + bi];
            bi += 1;
        }
        sha256_compress(&mut h, &block, &SHA_K);
        blk += 1;
    }

    // Final block(s) with padding.
    let rem = data.len() - full_blocks * 64;
    let mut last = [0u8; 64];
    let mut ri = 0usize;
    while ri < rem {
        last[ri] = data[full_blocks * 64 + ri];
        ri += 1;
    }
    last[rem] = 0x80;

    if rem >= 56 {
        sha256_compress(&mut h, &last, &SHA_K);
        last = [0u8; 64];
    }

    let len_bytes = total_bits.to_be_bytes();
    let mut li = 0usize;
    while li < 8 {
        last[56 + li] = len_bytes[li];
        li += 1;
    }
    sha256_compress(&mut h, &last, &SHA_K);

    // Serialize.
    let mut out = [0u8; 32];
    let mut wi = 0usize;
    while wi < 8 {
        let bytes = h[wi].to_be_bytes();
        let base = wi * 4;
        out[base] = bytes[0];
        out[base + 1] = bytes[1];
        out[base + 2] = bytes[2];
        out[base + 3] = bytes[3];
        wi += 1;
    }
    out
}

/// SHA-256 compression function for a single 64-byte block.
fn sha256_compress(h: &mut [u32; 8], block: &[u8; 64], k: &[u32; 64]) {
    let mut w = [0u32; 64];
    let mut t = 0usize;
    while t < 16 {
        let b = t * 4;
        w[t] = u32::from_be_bytes([block[b], block[b + 1], block[b + 2], block[b + 3]]);
        t += 1;
    }
    while t < 64 {
        let s0 = w[t - 15].rotate_right(7) ^ w[t - 15].rotate_right(18) ^ (w[t - 15] >> 3);
        let s1 = w[t - 2].rotate_right(17) ^ w[t - 2].rotate_right(19) ^ (w[t - 2] >> 10);
        w[t] = w[t - 16]
            .wrapping_add(s0)
            .wrapping_add(w[t - 7])
            .wrapping_add(s1);
        t += 1;
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
        let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
        let ch = (e & f) ^ (!e & g);
        let t1 = hh
            .wrapping_add(s1)
            .wrapping_add(ch)
            .wrapping_add(k[i])
            .wrapping_add(w[i]);
        let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
        let maj = (a & b) ^ (a & c) ^ (b & c);
        let t2 = s0.wrapping_add(maj);

        hh = g;
        g = f;
        f = e;
        e = d.wrapping_add(t1);
        d = c;
        c = b;
        b = a;
        a = t1.wrapping_add(t2);
        i += 1;
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

// ── Minimal AES-128-CBC (self-contained) ────────────────────────

/// AES S-box.
const SBOX: [u8; 256] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
];

/// AES inverse S-box.
const INV_SBOX: [u8; 256] = [
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d,
];

/// AES round constants.
const RCON: [u8; 10] = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36];

/// Multiply by 2 in GF(2^8).
const fn gf_mul2(x: u8) -> u8 {
    let shifted = (x as u16) << 1;
    let reduced = shifted ^ (((shifted >> 8) & 1) * 0x1b);
    reduced as u8
}

/// Multiply by 3 in GF(2^8).
const fn gf_mul3(x: u8) -> u8 {
    gf_mul2(x) ^ x
}

/// AES-128 key expansion producing 11 round keys.
fn aes128_expand_key(key: &[u8; 16]) -> [[u8; 16]; 11] {
    let mut w = [0u32; 44];
    let mut i = 0usize;
    while i < 4 {
        let b = i * 4;
        w[i] = u32::from_be_bytes([key[b], key[b + 1], key[b + 2], key[b + 3]]);
        i += 1;
    }
    i = 4;
    while i < 44 {
        let mut temp = w[i - 1];
        if i % 4 == 0 {
            temp = aes_sub_word(temp.rotate_left(8)) ^ ((RCON[i / 4 - 1] as u32) << 24);
        }
        w[i] = w[i - 4] ^ temp;
        i += 1;
    }

    let mut rk = [[0u8; 16]; 11];
    let mut r = 0usize;
    while r < 11 {
        let wi = r * 4;
        let mut j = 0usize;
        while j < 4 {
            let bytes = w[wi + j].to_be_bytes();
            let b = j * 4;
            rk[r][b] = bytes[0];
            rk[r][b + 1] = bytes[1];
            rk[r][b + 2] = bytes[2];
            rk[r][b + 3] = bytes[3];
            j += 1;
        }
        r += 1;
    }
    rk
}

/// Apply S-box to each byte of a 32-bit word.
fn aes_sub_word(w: u32) -> u32 {
    let b = w.to_be_bytes();
    u32::from_be_bytes([
        SBOX[b[0] as usize],
        SBOX[b[1] as usize],
        SBOX[b[2] as usize],
        SBOX[b[3] as usize],
    ])
}

/// Encrypt a single 16-byte block with AES-128.
fn aes128_encrypt_block(rk: &[[u8; 16]; 11], block: &mut [u8; 16]) {
    aes_add_round_key(block, &rk[0]);
    let mut round = 1usize;
    while round < 10 {
        aes_sub_bytes(block);
        aes_shift_rows(block);
        aes_mix_columns(block);
        aes_add_round_key(block, &rk[round]);
        round += 1;
    }
    aes_sub_bytes(block);
    aes_shift_rows(block);
    aes_add_round_key(block, &rk[10]);
}

/// Decrypt a single 16-byte block with AES-128.
fn aes128_decrypt_block(rk: &[[u8; 16]; 11], block: &mut [u8; 16]) {
    aes_add_round_key(block, &rk[10]);
    let mut round = 9usize;
    loop {
        aes_inv_shift_rows(block);
        aes_inv_sub_bytes(block);
        aes_add_round_key(block, &rk[round]);
        if round == 1 {
            break;
        }
        aes_inv_mix_columns(block);
        round -= 1;
    }
    aes_inv_mix_columns(block);
    aes_inv_shift_rows(block);
    aes_inv_sub_bytes(block);
    aes_add_round_key(block, &rk[0]);
}

fn aes_add_round_key(block: &mut [u8; 16], rk: &[u8; 16]) {
    let mut i = 0usize;
    while i < 16 {
        block[i] ^= rk[i];
        i += 1;
    }
}

fn aes_sub_bytes(block: &mut [u8; 16]) {
    let mut i = 0usize;
    while i < 16 {
        block[i] = SBOX[block[i] as usize];
        i += 1;
    }
}

fn aes_inv_sub_bytes(block: &mut [u8; 16]) {
    let mut i = 0usize;
    while i < 16 {
        block[i] = INV_SBOX[block[i] as usize];
        i += 1;
    }
}

fn aes_shift_rows(s: &mut [u8; 16]) {
    let t = s[1];
    s[1] = s[5];
    s[5] = s[9];
    s[9] = s[13];
    s[13] = t;
    let (t0, t1) = (s[2], s[6]);
    s[2] = s[10];
    s[6] = s[14];
    s[10] = t0;
    s[14] = t1;
    let t = s[15];
    s[15] = s[11];
    s[11] = s[7];
    s[7] = s[3];
    s[3] = t;
}

fn aes_inv_shift_rows(s: &mut [u8; 16]) {
    let t = s[13];
    s[13] = s[9];
    s[9] = s[5];
    s[5] = s[1];
    s[1] = t;
    let (t0, t1) = (s[2], s[6]);
    s[2] = s[10];
    s[6] = s[14];
    s[10] = t0;
    s[14] = t1;
    let t = s[3];
    s[3] = s[7];
    s[7] = s[11];
    s[11] = s[15];
    s[15] = t;
}

fn aes_mix_columns(s: &mut [u8; 16]) {
    let mut col = 0usize;
    while col < 4 {
        let b = col * 4;
        let (a0, a1, a2, a3) = (s[b], s[b + 1], s[b + 2], s[b + 3]);
        s[b] = gf_mul2(a0) ^ gf_mul3(a1) ^ a2 ^ a3;
        s[b + 1] = a0 ^ gf_mul2(a1) ^ gf_mul3(a2) ^ a3;
        s[b + 2] = a0 ^ a1 ^ gf_mul2(a2) ^ gf_mul3(a3);
        s[b + 3] = gf_mul3(a0) ^ a1 ^ a2 ^ gf_mul2(a3);
        col += 1;
    }
}

/// Multiply by 9 in GF(2^8).
const fn gf_mul9(x: u8) -> u8 {
    gf_mul2(gf_mul2(gf_mul2(x))) ^ x
}

/// Multiply by 11 in GF(2^8).
const fn gf_mul11(x: u8) -> u8 {
    gf_mul2(gf_mul2(gf_mul2(x)) ^ x) ^ x
}

/// Multiply by 13 in GF(2^8).
const fn gf_mul13(x: u8) -> u8 {
    gf_mul2(gf_mul2(gf_mul2(x) ^ x)) ^ x
}

/// Multiply by 14 in GF(2^8).
const fn gf_mul14(x: u8) -> u8 {
    gf_mul2(gf_mul2(gf_mul2(x) ^ x) ^ x)
}

fn aes_inv_mix_columns(s: &mut [u8; 16]) {
    let mut col = 0usize;
    while col < 4 {
        let b = col * 4;
        let (a0, a1, a2, a3) = (s[b], s[b + 1], s[b + 2], s[b + 3]);
        s[b] = gf_mul14(a0) ^ gf_mul11(a1) ^ gf_mul13(a2) ^ gf_mul9(a3);
        s[b + 1] = gf_mul9(a0) ^ gf_mul14(a1) ^ gf_mul11(a2) ^ gf_mul13(a3);
        s[b + 2] = gf_mul13(a0) ^ gf_mul9(a1) ^ gf_mul14(a2) ^ gf_mul11(a3);
        s[b + 3] = gf_mul11(a0) ^ gf_mul13(a1) ^ gf_mul9(a2) ^ gf_mul14(a3);
        col += 1;
    }
}

/// AES-128-CBC encrypt `data` in place.
///
/// `data.len()` must be a multiple of 16.
fn aes128_cbc_encrypt(key: &[u8; 16], iv: &[u8; 16], data: &mut [u8]) -> Result<()> {
    if data.len() % AES_BLOCK_SIZE != 0 {
        return Err(Error::InvalidArgument);
    }
    if data.is_empty() {
        return Ok(());
    }
    let rk = aes128_expand_key(key);
    let num_blocks = data.len() / AES_BLOCK_SIZE;
    let mut prev = *iv;
    let mut blk = 0usize;
    while blk < num_blocks {
        let off = blk * AES_BLOCK_SIZE;
        let mut block = [0u8; 16];
        let mut i = 0usize;
        while i < 16 {
            block[i] = data[off + i] ^ prev[i];
            i += 1;
        }
        aes128_encrypt_block(&rk, &mut block);
        i = 0;
        while i < 16 {
            data[off + i] = block[i];
            prev[i] = block[i];
            i += 1;
        }
        blk += 1;
    }
    Ok(())
}

/// AES-128-CBC decrypt `data` in place.
///
/// `data.len()` must be a multiple of 16.
fn aes128_cbc_decrypt(key: &[u8; 16], iv: &[u8; 16], data: &mut [u8]) -> Result<()> {
    if data.len() % AES_BLOCK_SIZE != 0 {
        return Err(Error::InvalidArgument);
    }
    if data.is_empty() {
        return Ok(());
    }
    let rk = aes128_expand_key(key);
    let num_blocks = data.len() / AES_BLOCK_SIZE;
    let mut prev = *iv;
    let mut blk = 0usize;
    while blk < num_blocks {
        let off = blk * AES_BLOCK_SIZE;
        let mut ct = [0u8; 16];
        let mut i = 0usize;
        while i < 16 {
            ct[i] = data[off + i];
            i += 1;
        }
        let mut block = ct;
        aes128_decrypt_block(&rk, &mut block);
        i = 0;
        while i < 16 {
            data[off + i] = block[i] ^ prev[i];
            i += 1;
        }
        prev = ct;
        blk += 1;
    }
    Ok(())
}
