// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! eCryptfs — stacked cryptographic filesystem.
//!
//! eCryptfs is a POSIX-compliant encrypted filesystem that stacks on top of
//! an existing lower filesystem.  Each file is encrypted independently
//! using a per-file key wrapped in the user's authentication token.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────┐
//! │         VFS / user-space application         │
//! ├─────────────────────────────────────────────┤
//! │  eCryptfs (stacked FS)                       │
//! │  ┌─────────────┐  ┌───────────────────────┐ │
//! │  │ Crypto Core  │  │  Key Management       │ │
//! │  │ (AES-256)    │  │  (session keyring)    │ │
//! │  └─────────────┘  └───────────────────────┘ │
//! ├─────────────────────────────────────────────┤
//! │         Lower filesystem (ext4, etc.)        │
//! └─────────────────────────────────────────────┘
//! ```
//!
//! # Crypto format (per-file)
//!
//! Each encrypted file has an RFC 2440-style header containing:
//! - Marker bytes + version
//! - Cipher code and key size
//! - Encrypted file encryption key (FEK) wrapped by the file encryption
//!   key encryption key (FEKEK)
//!
//! File data is encrypted in extents (4096 bytes by default) using
//! AES-256-CBC with per-extent IVs derived from the extent index.
//!
//! # Reference
//!
//! Linux `fs/ecryptfs/`, eCryptfs design document (Halcrow et al.).

extern crate alloc;

use crate::inode::{FileMode, FileType, Inode, InodeNumber, InodeOps};
use alloc::string::String;
use alloc::vec::Vec;
use oncrix_lib::{Error, Result};

// ── Constants ────────────────────────────────────────────────────────────────

/// eCryptfs magic bytes in the file header.
pub const ECRYPTFS_MAGIC: [u8; 4] = [0x3a, 0x02, 0xec, 0xf5];

/// eCryptfs file header version.
pub const ECRYPTFS_VERSION: u8 = 4;

/// Default extent size (encryption block) in bytes.
const EXTENT_SIZE: usize = 4096;

/// Maximum number of inodes.
const MAX_INODES: usize = 512;

/// Maximum directory entries per directory.
const MAX_DIR_ENTRIES: usize = 128;

/// Maximum file data size in bytes.
const MAX_FILE_DATA: usize = 65536;

/// Maximum filename length.
const MAX_NAME_LEN: usize = 255;

/// Key size in bytes (AES-256).
const KEY_SIZE: usize = 32;

/// IV size in bytes (AES block size).
const IV_SIZE: usize = 16;

/// Maximum number of keys in the session keyring.
const MAX_KEYS: usize = 64;

/// Encrypted filename prefix (for filename encryption mode).
const FNEK_PREFIX: &str = "ECRYPTFS_FNEK_ENCRYPTED.";

/// Maximum header size in bytes.
const MAX_HEADER_SIZE: usize = 8192;

// ── Cipher definitions ───────────────────────────────────────────────────────

/// Supported cipher algorithms.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CipherCode {
    /// AES-128.
    Aes128,
    /// AES-192.
    Aes192,
    /// AES-256 (default).
    Aes256,
    /// Blowfish (legacy).
    Blowfish,
}

impl CipherCode {
    /// Key size in bytes for this cipher.
    pub fn key_size(self) -> usize {
        match self {
            Self::Aes128 => 16,
            Self::Aes192 => 24,
            Self::Aes256 => 32,
            Self::Blowfish => 16,
        }
    }

    /// Numeric code for the header.
    pub fn code(self) -> u8 {
        match self {
            Self::Aes128 => 0x01,
            Self::Aes192 => 0x02,
            Self::Aes256 => 0x03,
            Self::Blowfish => 0x04,
        }
    }

    /// Parse from numeric code.
    pub fn from_code(code: u8) -> Result<Self> {
        match code {
            0x01 => Ok(Self::Aes128),
            0x02 => Ok(Self::Aes192),
            0x03 => Ok(Self::Aes256),
            0x04 => Ok(Self::Blowfish),
            _ => Err(Error::InvalidArgument),
        }
    }
}

// ── RFC 2440-style file header ───────────────────────────────────────────────

/// Per-file cryptographic header stored at the beginning of each
/// encrypted file in the lower filesystem.
#[derive(Debug, Clone)]
pub struct CryptoHeader {
    /// Magic bytes ([`ECRYPTFS_MAGIC`]).
    pub magic: [u8; 4],
    /// Header version.
    pub version: u8,
    /// Cipher algorithm.
    pub cipher: CipherCode,
    /// Encrypted file encryption key (wrapped by FEKEK).
    pub encrypted_fek: [u8; KEY_SIZE],
    /// Signature of the FEKEK used for wrapping (8 bytes).
    pub fekek_signature: [u8; 8],
    /// Flags (filename encryption enabled, etc.).
    pub flags: CryptoFlags,
    /// Number of header pages.
    pub header_pages: u16,
}

/// Crypto header flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CryptoFlags(pub u32);

impl CryptoFlags {
    /// Filename encryption is enabled.
    pub const ENCRYPT_FILENAMES: Self = Self(0x01);
    /// Metadata in xattrs instead of header.
    pub const METADATA_IN_XATTR: Self = Self(0x02);
    /// Passthrough mode (unencrypted files pass through).
    pub const PASSTHROUGH: Self = Self(0x04);

    /// Check if filename encryption is enabled.
    pub fn encrypt_filenames(self) -> bool {
        self.0 & Self::ENCRYPT_FILENAMES.0 != 0
    }
}

impl CryptoHeader {
    /// Create a new header with AES-256 and the given FEKEK signature.
    pub fn new(cipher: CipherCode, fekek_sig: [u8; 8]) -> Self {
        Self {
            magic: ECRYPTFS_MAGIC,
            version: ECRYPTFS_VERSION,
            cipher,
            encrypted_fek: [0u8; KEY_SIZE],
            fekek_signature: fekek_sig,
            flags: CryptoFlags(0),
            header_pages: 1,
        }
    }

    /// Validate the header magic and version.
    pub fn validate(&self) -> Result<()> {
        if self.magic != ECRYPTFS_MAGIC {
            return Err(Error::InvalidArgument);
        }
        if self.version > ECRYPTFS_VERSION {
            return Err(Error::InvalidArgument);
        }
        Ok(())
    }

    /// Serialized header size in bytes.
    pub fn header_size(&self) -> usize {
        usize::from(self.header_pages) * EXTENT_SIZE
    }
}

// ── Key management ───────────────────────────────────────────────────────────

/// An authentication token in the session keyring.
#[derive(Debug, Clone)]
pub struct AuthToken {
    /// 8-byte signature identifying this token.
    pub signature: [u8; 8],
    /// The file encryption key encryption key (FEKEK).
    pub fekek: [u8; KEY_SIZE],
    /// Token type.
    pub token_type: AuthTokenType,
    /// Whether this token is for filename encryption.
    pub for_filename: bool,
}

/// Authentication token type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthTokenType {
    /// Passphrase-derived.
    Passphrase,
    /// Private key (PKI).
    PrivateKey,
}

/// Session keyring holding authentication tokens.
pub struct SessionKeyring {
    /// Tokens indexed by signature.
    tokens: Vec<AuthToken>,
}

impl SessionKeyring {
    /// Create an empty keyring.
    pub fn new() -> Self {
        Self { tokens: Vec::new() }
    }

    /// Add a token. Returns error if the keyring is full.
    pub fn add_token(&mut self, token: AuthToken) -> Result<()> {
        if self.tokens.len() >= MAX_KEYS {
            return Err(Error::OutOfMemory);
        }
        // Replace existing token with same signature.
        if let Some(existing) = self
            .tokens
            .iter_mut()
            .find(|t| t.signature == token.signature)
        {
            *existing = token;
            return Ok(());
        }
        self.tokens.push(token);
        Ok(())
    }

    /// Look up a token by signature.
    pub fn find_token(&self, signature: &[u8; 8]) -> Result<&AuthToken> {
        self.tokens
            .iter()
            .find(|t| &t.signature == signature)
            .ok_or(Error::NotFound)
    }

    /// Remove a token by signature.
    pub fn remove_token(&mut self, signature: &[u8; 8]) -> Result<()> {
        let pos = self
            .tokens
            .iter()
            .position(|t| &t.signature == signature)
            .ok_or(Error::NotFound)?;
        self.tokens.remove(pos);
        Ok(())
    }

    /// Number of tokens in the keyring.
    pub fn token_count(&self) -> usize {
        self.tokens.len()
    }
}

// ── Crypto context (per-file) ────────────────────────────────────────────────

/// Per-file cryptographic context.
///
/// Holds the decrypted file encryption key (FEK) and cipher parameters
/// used for encrypting/decrypting extents.
#[derive(Debug, Clone)]
pub struct CryptoContext {
    /// Cipher algorithm.
    pub cipher: CipherCode,
    /// Decrypted file encryption key.
    pub fek: [u8; KEY_SIZE],
    /// Root IV (derived from inode number or nonce).
    pub root_iv: [u8; IV_SIZE],
    /// Number of extents in the file.
    pub extent_count: u32,
    /// Flags inherited from the header.
    pub flags: CryptoFlags,
}

impl CryptoContext {
    /// Derive the IV for a given extent index.
    ///
    /// IV = root_iv XOR extent_index (simple derivation for modelling).
    pub fn extent_iv(&self, extent_idx: u32) -> [u8; IV_SIZE] {
        let mut iv = self.root_iv;
        let idx_bytes = extent_idx.to_le_bytes();
        for i in 0..4 {
            iv[i] ^= idx_bytes[i];
        }
        iv
    }
}

// ── Extent-based encryption ──────────────────────────────────────────────────

/// Encrypt a single extent using XOR (placeholder for real AES).
///
/// In a production kernel this would use AES-CBC.  We use XOR with the
/// key as a functional placeholder that preserves the encrypt/decrypt
/// symmetry.
fn encrypt_extent(data: &mut [u8], key: &[u8; KEY_SIZE], iv: &[u8; IV_SIZE]) {
    // XOR with repeating key + iv pattern.
    for (i, byte) in data.iter_mut().enumerate() {
        *byte ^= key[i % KEY_SIZE] ^ iv[i % IV_SIZE];
    }
}

/// Decrypt a single extent (symmetric with encrypt for XOR cipher).
fn decrypt_extent(data: &mut [u8], key: &[u8; KEY_SIZE], iv: &[u8; IV_SIZE]) {
    // XOR is self-inverse.
    encrypt_extent(data, key, iv);
}

// ── Filename encryption ──────────────────────────────────────────────────────

/// Encrypt a filename for storage in the lower filesystem.
///
/// Produces a base64-like hex encoding prefixed with [`FNEK_PREFIX`].
pub fn encrypt_filename(name: &str, key: &[u8; KEY_SIZE]) -> String {
    let mut buf = Vec::from(name.as_bytes());
    // Simple XOR encryption of the filename bytes.
    for (i, byte) in buf.iter_mut().enumerate() {
        *byte ^= key[i % KEY_SIZE];
    }
    // Encode as hex string.
    let mut encoded = String::from(FNEK_PREFIX);
    for b in &buf {
        let hi = b >> 4;
        let lo = b & 0x0F;
        encoded.push(hex_char(hi));
        encoded.push(hex_char(lo));
    }
    encoded
}

/// Decrypt a filename from the lower filesystem.
pub fn decrypt_filename(encrypted: &str, key: &[u8; KEY_SIZE]) -> Result<String> {
    let hex_part = encrypted
        .strip_prefix(FNEK_PREFIX)
        .ok_or(Error::InvalidArgument)?;
    if hex_part.len() % 2 != 0 {
        return Err(Error::InvalidArgument);
    }
    let hex_bytes: Vec<u8> = hex_part.as_bytes().to_vec();
    let mut decoded = Vec::with_capacity(hex_bytes.len() / 2);
    let mut i = 0;
    while i < hex_bytes.len() {
        let hi = from_hex_char(hex_bytes[i])?;
        let lo = from_hex_char(hex_bytes[i + 1])?;
        decoded.push((hi << 4) | lo);
        i += 2;
    }
    // XOR decrypt.
    for (j, byte) in decoded.iter_mut().enumerate() {
        *byte ^= key[j % KEY_SIZE];
    }
    String::from_utf8(decoded).map_err(|_| Error::InvalidArgument)
}

/// Convert a nibble to a hex character.
fn hex_char(nibble: u8) -> char {
    match nibble {
        0..=9 => (b'0' + nibble) as char,
        10..=15 => (b'a' + nibble - 10) as char,
        _ => '0',
    }
}

/// Convert a hex character to a nibble.
fn from_hex_char(ch: u8) -> Result<u8> {
    match ch {
        b'0'..=b'9' => Ok(ch - b'0'),
        b'a'..=b'f' => Ok(ch - b'a' + 10),
        b'A'..=b'F' => Ok(ch - b'A' + 10),
        _ => Err(Error::InvalidArgument),
    }
}

// ── eCryptfs inode ───────────────────────────────────────────────────────────

/// eCryptfs inode (stacked layer metadata).
#[derive(Debug, Clone)]
pub struct EcryptfsInode {
    /// Inode number (matches lower inode for simplicity).
    pub ino: u64,
    /// File type.
    pub file_type: FileType,
    /// Permission bits.
    pub mode: u16,
    /// Plaintext file size (lower file is larger due to header + padding).
    pub size: u64,
    /// Hard link count.
    pub nlink: u32,
    /// Owner UID.
    pub uid: u32,
    /// Owner GID.
    pub gid: u32,
    /// Per-file crypto context (None for directories/symlinks).
    pub crypto_ctx: Option<CryptoContext>,
}

impl EcryptfsInode {
    /// Create a new regular file inode with crypto context.
    pub fn new_file(ino: u64, mode: u16, cipher: CipherCode) -> Self {
        let ctx = CryptoContext {
            cipher,
            fek: [0u8; KEY_SIZE],
            root_iv: [0u8; IV_SIZE],
            extent_count: 0,
            flags: CryptoFlags(0),
        };
        Self {
            ino,
            file_type: FileType::Regular,
            mode,
            size: 0,
            nlink: 1,
            uid: 0,
            gid: 0,
            crypto_ctx: Some(ctx),
        }
    }

    /// Create a new directory inode (no crypto context).
    pub fn new_dir(ino: u64, mode: u16) -> Self {
        Self {
            ino,
            file_type: FileType::Directory,
            mode,
            size: 0,
            nlink: 1,
            uid: 0,
            gid: 0,
            crypto_ctx: None,
        }
    }

    /// Convert to a VFS [`Inode`].
    pub fn to_vfs_inode(&self) -> Inode {
        let mut vfs = Inode::new(InodeNumber(self.ino), self.file_type, FileMode(self.mode));
        vfs.size = self.size;
        vfs.nlink = self.nlink;
        vfs.uid = self.uid;
        vfs.gid = self.gid;
        vfs
    }
}

// ── Directory entry ──────────────────────────────────────────────────────────

/// In-memory directory entry.
#[derive(Debug, Clone)]
struct EcryptfsDirEntry {
    /// Target inode number.
    ino: u64,
    /// File type.
    file_type: FileType,
    /// Plaintext name.
    name: String,
}

// ── File data storage ────────────────────────────────────────────────────────

/// In-memory file data (plaintext, encrypted on read-back from lower FS).
struct EcryptfsFileData {
    /// Owning inode number.
    ino: u64,
    /// Plaintext data.
    plaintext: Vec<u8>,
}

// ── Mount options ────────────────────────────────────────────────────────────

/// eCryptfs mount options.
#[derive(Debug, Clone)]
pub struct EcryptfsMountOpts {
    /// Cipher to use for new files.
    pub cipher: CipherCode,
    /// Whether to encrypt filenames.
    pub encrypt_filenames: bool,
    /// Passthrough mode for unencrypted files.
    pub passthrough: bool,
    /// FEKEK signature to use from the keyring.
    pub fekek_sig: [u8; 8],
    /// FNEK signature for filename encryption (if enabled).
    pub fnek_sig: [u8; 8],
}

impl Default for EcryptfsMountOpts {
    fn default() -> Self {
        Self {
            cipher: CipherCode::Aes256,
            encrypt_filenames: false,
            passthrough: false,
            fekek_sig: [0u8; 8],
            fnek_sig: [0u8; 8],
        }
    }
}

// ── Mounted filesystem ───────────────────────────────────────────────────────

/// Mounted eCryptfs filesystem handle.
///
/// Stacks on top of a lower filesystem and provides transparent
/// per-file encryption with key management through a session keyring.
pub struct EcryptfsFs {
    /// Mount options.
    opts: EcryptfsMountOpts,
    /// Session keyring.
    keyring: SessionKeyring,
    /// Inode table.
    inodes: Vec<EcryptfsInode>,
    /// Directory entries (parent_ino, entry).
    dir_entries: Vec<(u64, EcryptfsDirEntry)>,
    /// File data blobs.
    file_data: Vec<EcryptfsFileData>,
    /// Next inode number.
    next_ino: u64,
}

impl EcryptfsFs {
    /// Create a new eCryptfs filesystem with the given mount options.
    pub fn new(opts: EcryptfsMountOpts) -> Result<Self> {
        let root = EcryptfsInode::new_dir(1, 0o755);
        let mut fs = Self {
            opts,
            keyring: SessionKeyring::new(),
            inodes: Vec::new(),
            dir_entries: Vec::new(),
            file_data: Vec::new(),
            next_ino: 2,
        };
        fs.inodes.push(root);
        Ok(fs)
    }

    /// Add an authentication token to the session keyring.
    pub fn add_key(&mut self, token: AuthToken) -> Result<()> {
        self.keyring.add_token(token)
    }

    /// Remove an authentication token from the session keyring.
    pub fn remove_key(&mut self, signature: &[u8; 8]) -> Result<()> {
        self.keyring.remove_token(signature)
    }

    /// Return the session keyring.
    pub fn keyring(&self) -> &SessionKeyring {
        &self.keyring
    }

    /// Return the mount options.
    pub fn mount_opts(&self) -> &EcryptfsMountOpts {
        &self.opts
    }

    /// Encrypt plaintext data using the given crypto context.
    ///
    /// Returns encrypted data with the header prepended.
    pub fn encrypt_file_data(&self, ctx: &CryptoContext, plaintext: &[u8]) -> Result<Vec<u8>> {
        let header = CryptoHeader::new(ctx.cipher, self.opts.fekek_sig);
        let header_size = header.header_size();

        let mut ciphertext = Vec::with_capacity(header_size + plaintext.len());
        // Write a simplified header.
        ciphertext.extend_from_slice(&header.magic);
        ciphertext.push(header.version);
        ciphertext.push(header.cipher.code());
        ciphertext.extend_from_slice(&header.fekek_signature);
        // Pad header to header_size.
        while ciphertext.len() < header_size {
            ciphertext.push(0);
        }

        // Encrypt extent by extent.
        let mut offset = 0;
        let mut extent_idx = 0u32;
        while offset < plaintext.len() {
            let end = (offset + EXTENT_SIZE).min(plaintext.len());
            let mut extent_buf = [0u8; EXTENT_SIZE];
            let chunk_len = end - offset;
            extent_buf[..chunk_len].copy_from_slice(&plaintext[offset..end]);

            let iv = ctx.extent_iv(extent_idx);
            encrypt_extent(&mut extent_buf[..chunk_len], &ctx.fek, &iv);
            ciphertext.extend_from_slice(&extent_buf[..chunk_len]);

            offset = end;
            extent_idx += 1;
        }
        Ok(ciphertext)
    }

    /// Decrypt file data (strip header, decrypt extents).
    pub fn decrypt_file_data(&self, ctx: &CryptoContext, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let header_size = usize::from(1u16) * EXTENT_SIZE; // 1 page header
        if ciphertext.len() < header_size {
            return Err(Error::InvalidArgument);
        }
        // Validate magic.
        if ciphertext.len() >= 4 && ciphertext[..4] != ECRYPTFS_MAGIC {
            return Err(Error::InvalidArgument);
        }

        let encrypted_data = &ciphertext[header_size..];
        let mut plaintext = Vec::with_capacity(encrypted_data.len());

        let mut offset = 0;
        let mut extent_idx = 0u32;
        while offset < encrypted_data.len() {
            let end = (offset + EXTENT_SIZE).min(encrypted_data.len());
            let chunk_len = end - offset;
            let mut extent_buf = [0u8; EXTENT_SIZE];
            extent_buf[..chunk_len].copy_from_slice(&encrypted_data[offset..end]);

            let iv = ctx.extent_iv(extent_idx);
            decrypt_extent(&mut extent_buf[..chunk_len], &ctx.fek, &iv);
            plaintext.extend_from_slice(&extent_buf[..chunk_len]);

            offset = end;
            extent_idx += 1;
        }
        Ok(plaintext)
    }

    // ── Internal helpers ─────────────────────────────────────────────

    /// Find an inode by number.
    fn find_inode(&self, ino: u64) -> Result<&EcryptfsInode> {
        self.inodes
            .iter()
            .find(|i| i.ino == ino)
            .ok_or(Error::NotFound)
    }

    /// Find a mutable inode by number.
    fn find_inode_mut(&mut self, ino: u64) -> Result<&mut EcryptfsInode> {
        self.inodes
            .iter_mut()
            .find(|i| i.ino == ino)
            .ok_or(Error::NotFound)
    }

    /// Allocate a new inode number.
    fn alloc_ino(&mut self) -> Result<u64> {
        if self.inodes.len() >= MAX_INODES {
            return Err(Error::OutOfMemory);
        }
        let ino = self.next_ino;
        self.next_ino += 1;
        Ok(ino)
    }

    /// Find a directory entry by parent inode and name.
    fn find_dir_entry(&self, parent_ino: u64, name: &str) -> Result<&EcryptfsDirEntry> {
        self.dir_entries
            .iter()
            .find(|(p, e)| *p == parent_ino && e.name == name)
            .map(|(_, e)| e)
            .ok_or(Error::NotFound)
    }

    /// Count directory entries for a parent.
    fn dir_entry_count(&self, parent_ino: u64) -> usize {
        self.dir_entries
            .iter()
            .filter(|(p, _)| *p == parent_ino)
            .count()
    }

    /// Get file data.
    fn get_file_data(&self, ino: u64) -> Option<&EcryptfsFileData> {
        self.file_data.iter().find(|f| f.ino == ino)
    }

    /// Get or create file data.
    fn get_or_create_file_data(&mut self, ino: u64) -> &mut EcryptfsFileData {
        if !self.file_data.iter().any(|f| f.ino == ino) {
            self.file_data.push(EcryptfsFileData {
                ino,
                plaintext: Vec::new(),
            });
        }
        self.file_data.iter_mut().find(|f| f.ino == ino).unwrap()
    }

    /// Generate a per-file encryption key from the FEKEK.
    fn generate_fek(&self) -> [u8; KEY_SIZE] {
        // In a real implementation this would be random + wrapped.
        // For modelling, derive from the FEKEK signature.
        let mut fek = [0u8; KEY_SIZE];
        let sig = &self.opts.fekek_sig;
        for i in 0..KEY_SIZE {
            fek[i] = sig[i % 8].wrapping_add(i as u8);
        }
        fek
    }

    /// Derive root IV from inode number.
    fn derive_root_iv(ino: u64) -> [u8; IV_SIZE] {
        let mut iv = [0u8; IV_SIZE];
        let ino_bytes = ino.to_le_bytes();
        iv[..8].copy_from_slice(&ino_bytes);
        iv
    }
}

// ── InodeOps implementation ──────────────────────────────────────────────────

impl InodeOps for EcryptfsFs {
    fn lookup(&self, parent: &Inode, name: &str) -> Result<Inode> {
        let entry = self.find_dir_entry(parent.ino.0, name)?;
        let inode = self.find_inode(entry.ino)?;
        Ok(inode.to_vfs_inode())
    }

    fn create(&mut self, parent: &Inode, name: &str, mode: FileMode) -> Result<Inode> {
        if name.len() > MAX_NAME_LEN || name.is_empty() {
            return Err(Error::InvalidArgument);
        }
        if self.find_dir_entry(parent.ino.0, name).is_ok() {
            return Err(Error::AlreadyExists);
        }
        if self.dir_entry_count(parent.ino.0) >= MAX_DIR_ENTRIES {
            return Err(Error::OutOfMemory);
        }

        let ino = self.alloc_ino()?;
        let mut ecr_inode = EcryptfsInode::new_file(ino, mode.0, self.opts.cipher);

        // Set up crypto context with a generated FEK.
        if let Some(ref mut ctx) = ecr_inode.crypto_ctx {
            ctx.fek = self.generate_fek();
            ctx.root_iv = Self::derive_root_iv(ino);
        }

        self.inodes.push(ecr_inode);
        self.dir_entries.push((
            parent.ino.0,
            EcryptfsDirEntry {
                ino,
                file_type: FileType::Regular,
                name: String::from(name),
            },
        ));

        let created = self.find_inode(ino)?;
        Ok(created.to_vfs_inode())
    }

    fn mkdir(&mut self, parent: &Inode, name: &str, mode: FileMode) -> Result<Inode> {
        if name.len() > MAX_NAME_LEN || name.is_empty() {
            return Err(Error::InvalidArgument);
        }
        if self.find_dir_entry(parent.ino.0, name).is_ok() {
            return Err(Error::AlreadyExists);
        }
        if self.dir_entry_count(parent.ino.0) >= MAX_DIR_ENTRIES {
            return Err(Error::OutOfMemory);
        }

        let ino = self.alloc_ino()?;
        let dir_inode = EcryptfsInode::new_dir(ino, mode.0);
        self.inodes.push(dir_inode);
        self.dir_entries.push((
            parent.ino.0,
            EcryptfsDirEntry {
                ino,
                file_type: FileType::Directory,
                name: String::from(name),
            },
        ));

        let created = self.find_inode(ino)?;
        Ok(created.to_vfs_inode())
    }

    fn unlink(&mut self, parent: &Inode, name: &str) -> Result<()> {
        let entry_ino = self.find_dir_entry(parent.ino.0, name)?.ino;
        let inode = self.find_inode(entry_ino)?;
        if inode.file_type == FileType::Directory {
            return Err(Error::InvalidArgument);
        }

        let pos = self
            .dir_entries
            .iter()
            .position(|(p, e)| *p == parent.ino.0 && e.name == name)
            .ok_or(Error::NotFound)?;
        self.dir_entries.remove(pos);

        let inode_mut = self.find_inode_mut(entry_ino)?;
        inode_mut.nlink = inode_mut.nlink.saturating_sub(1);
        if inode_mut.nlink == 0 {
            self.inodes.retain(|i| i.ino != entry_ino);
            self.file_data.retain(|f| f.ino != entry_ino);
        }
        Ok(())
    }

    fn rmdir(&mut self, parent: &Inode, name: &str) -> Result<()> {
        let entry_ino = self.find_dir_entry(parent.ino.0, name)?.ino;
        let inode = self.find_inode(entry_ino)?;
        if inode.file_type != FileType::Directory {
            return Err(Error::InvalidArgument);
        }
        if self.dir_entry_count(entry_ino) > 0 {
            return Err(Error::Busy);
        }

        let pos = self
            .dir_entries
            .iter()
            .position(|(p, e)| *p == parent.ino.0 && e.name == name)
            .ok_or(Error::NotFound)?;
        self.dir_entries.remove(pos);
        self.inodes.retain(|i| i.ino != entry_ino);
        Ok(())
    }

    fn read(&self, inode: &Inode, offset: u64, buf: &mut [u8]) -> Result<usize> {
        let ecr_inode = self.find_inode(inode.ino.0)?;
        if ecr_inode.file_type != FileType::Regular {
            return Err(Error::InvalidArgument);
        }
        let fd = match self.get_file_data(inode.ino.0) {
            Some(fd) => fd,
            None => return Ok(0),
        };
        let start = offset as usize;
        if start >= fd.plaintext.len() {
            return Ok(0);
        }
        let available = fd.plaintext.len() - start;
        let to_read = buf.len().min(available);
        buf[..to_read].copy_from_slice(&fd.plaintext[start..start + to_read]);
        Ok(to_read)
    }

    fn write(&mut self, inode: &Inode, offset: u64, data: &[u8]) -> Result<usize> {
        let ecr_inode = self.find_inode(inode.ino.0)?;
        if ecr_inode.file_type != FileType::Regular {
            return Err(Error::InvalidArgument);
        }
        let end = offset as usize + data.len();
        if end > MAX_FILE_DATA {
            return Err(Error::OutOfMemory);
        }

        let ino = inode.ino.0;
        let fd = self.get_or_create_file_data(ino);
        if fd.plaintext.len() < end {
            fd.plaintext.resize(end, 0);
        }
        fd.plaintext[offset as usize..end].copy_from_slice(data);

        let new_size = fd.plaintext.len() as u64;
        let inode_mut = self.find_inode_mut(ino)?;
        inode_mut.size = new_size;
        if let Some(ref mut ctx) = inode_mut.crypto_ctx {
            ctx.extent_count = ((new_size as usize + EXTENT_SIZE - 1) / EXTENT_SIZE) as u32;
        }
        Ok(data.len())
    }

    fn truncate(&mut self, inode: &Inode, size: u64) -> Result<()> {
        let ecr_inode = self.find_inode(inode.ino.0)?;
        if ecr_inode.file_type != FileType::Regular {
            return Err(Error::InvalidArgument);
        }
        if size as usize > MAX_FILE_DATA {
            return Err(Error::OutOfMemory);
        }

        let ino = inode.ino.0;
        let fd = self.get_or_create_file_data(ino);
        fd.plaintext.resize(size as usize, 0);

        let inode_mut = self.find_inode_mut(ino)?;
        inode_mut.size = size;
        if let Some(ref mut ctx) = inode_mut.crypto_ctx {
            ctx.extent_count = ((size as usize + EXTENT_SIZE - 1) / EXTENT_SIZE) as u32;
        }
        Ok(())
    }
}
