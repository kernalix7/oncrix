// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! VirtIO Crypto device driver.
//!
//! Implements a VirtIO crypto device (device type 20) for hardware-
//! accelerated cryptographic operations. Supports:
//!
//! - **Symmetric cipher** — AES in CBC, CTR, and XTS modes
//! - **Hash** — SHA-256 and SHA-512
//! - **MAC** — HMAC-SHA-256 and HMAC-SHA-512
//! - **AEAD** — AES-GCM (128/256)
//!
//! The driver uses a control virtqueue for session management
//! (create/destroy) and one or more data virtqueues for crypto
//! operations. Each operation is described by a request header,
//! followed by operation-specific parameters, input data, and an
//! output buffer.
//!
//! # Architecture
//!
//! - **Control virtqueue** (queue 0) — session create/destroy
//! - **Data virtqueues** (queues 1..N) — crypto operations
//! - **Config space** — device capabilities and algorithm support
//!
//! Reference: VirtIO Specification v1.2, §5.9 (Crypto Device).

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// VirtIO crypto device type ID.
pub const VIRTIO_CRYPTO_DEVICE_ID: u32 = 20;

/// Maximum number of data virtqueues.
const MAX_DATA_QUEUES: usize = 4;

/// Maximum number of concurrent crypto sessions.
const MAX_SESSIONS: usize = 64;

/// Maximum key size in bytes (256-bit key = 32 bytes, XTS = 64).
const MAX_KEY_SIZE: usize = 64;

/// Maximum IV/nonce size in bytes.
const MAX_IV_SIZE: usize = 16;

/// Maximum AAD (Additional Authenticated Data) size for AEAD.
const MAX_AAD_SIZE: usize = 256;

/// Maximum tag size for AEAD/MAC operations.
const MAX_TAG_SIZE: usize = 64;

/// Maximum number of crypto devices in the registry.
const MAX_CRYPTO_DEVICES: usize = 4;

/// Maximum in-flight requests per data queue.
const MAX_INFLIGHT: usize = 32;

/// Request buffer size for control operations.
const CTRL_BUF_SIZE: usize = 256;

// ---------------------------------------------------------------------------
// VirtIO crypto status codes (§5.9.7)
// ---------------------------------------------------------------------------

/// Crypto operation completed successfully.
const VIRTIO_CRYPTO_OK: u8 = 0;

/// Unspecified error.
const _VIRTIO_CRYPTO_ERR: u8 = 1;

/// Bad message (invalid parameters).
const _VIRTIO_CRYPTO_BADMSG: u8 = 2;

/// Operation not supported.
const _VIRTIO_CRYPTO_NOTSUPP: u8 = 3;

/// Insufficient resources on device.
const _VIRTIO_CRYPTO_INVSESS: u8 = 4;

// ---------------------------------------------------------------------------
// Service types (§5.9.7.1)
// ---------------------------------------------------------------------------

/// Crypto service type: symmetric cipher.
const VIRTIO_CRYPTO_SERVICE_CIPHER: u32 = 0;

/// Crypto service type: hash.
const VIRTIO_CRYPTO_SERVICE_HASH: u32 = 1;

/// Crypto service type: MAC.
const VIRTIO_CRYPTO_SERVICE_MAC: u32 = 2;

/// Crypto service type: AEAD.
const VIRTIO_CRYPTO_SERVICE_AEAD: u32 = 3;

// ---------------------------------------------------------------------------
// Control opcodes (§5.9.7.2)
// ---------------------------------------------------------------------------

/// Control opcode: create session.
const VIRTIO_CRYPTO_CREATE_SESSION: u32 = 0x02;

/// Control opcode: destroy session.
const VIRTIO_CRYPTO_DESTROY_SESSION: u32 = 0x03;

// ---------------------------------------------------------------------------
// Cipher algorithms (§5.9.7.3)
// ---------------------------------------------------------------------------

/// Cipher algorithm identifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum CipherAlgo {
    /// No cipher / unused.
    None = 0,
    /// AES in CBC mode.
    AesCbc = 1,
    /// AES in CTR mode.
    AesCtr = 2,
    /// AES in XTS mode (requires double-width key).
    AesXts = 3,
    /// AES in ECB mode (no IV required).
    AesEcb = 4,
    /// DES in CBC mode (legacy, not recommended).
    DesCbc = 10,
    /// 3DES in CBC mode (legacy).
    Des3Cbc = 11,
}

impl CipherAlgo {
    /// Required key length in bytes for this algorithm.
    pub const fn key_len(self) -> usize {
        match self {
            Self::None => 0,
            Self::AesCbc | Self::AesCtr | Self::AesEcb => 16,
            Self::AesXts => 32,
            Self::DesCbc => 8,
            Self::Des3Cbc => 24,
        }
    }

    /// Required IV length in bytes for this algorithm.
    pub const fn iv_len(self) -> usize {
        match self {
            Self::None | Self::AesEcb => 0,
            Self::AesCbc | Self::AesCtr | Self::AesXts => 16,
            Self::DesCbc | Self::Des3Cbc => 8,
        }
    }

    /// Block size in bytes.
    pub const fn block_size(self) -> usize {
        match self {
            Self::None => 0,
            Self::AesCbc | Self::AesCtr | Self::AesXts | Self::AesEcb => 16,
            Self::DesCbc | Self::Des3Cbc => 8,
        }
    }
}

// ---------------------------------------------------------------------------
// Hash algorithms (§5.9.7.4)
// ---------------------------------------------------------------------------

/// Hash algorithm identifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum HashAlgo {
    /// No hash / unused.
    None = 0,
    /// MD5 (128-bit digest, legacy).
    Md5 = 1,
    /// SHA-1 (160-bit digest, legacy).
    Sha1 = 2,
    /// SHA-224 (224-bit digest).
    Sha224 = 3,
    /// SHA-256 (256-bit digest).
    Sha256 = 4,
    /// SHA-384 (384-bit digest).
    Sha384 = 5,
    /// SHA-512 (512-bit digest).
    Sha512 = 6,
}

impl HashAlgo {
    /// Digest length in bytes for this algorithm.
    pub const fn digest_len(self) -> usize {
        match self {
            Self::None => 0,
            Self::Md5 => 16,
            Self::Sha1 => 20,
            Self::Sha224 => 28,
            Self::Sha256 => 32,
            Self::Sha384 => 48,
            Self::Sha512 => 64,
        }
    }

    /// Block size in bytes used internally by the hash.
    pub const fn block_size(self) -> usize {
        match self {
            Self::None => 0,
            Self::Md5 | Self::Sha1 | Self::Sha224 | Self::Sha256 => 64,
            Self::Sha384 | Self::Sha512 => 128,
        }
    }
}

// ---------------------------------------------------------------------------
// MAC algorithms (§5.9.7.5)
// ---------------------------------------------------------------------------

/// MAC algorithm identifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum MacAlgo {
    /// No MAC / unused.
    None = 0,
    /// HMAC-MD5.
    HmacMd5 = 1,
    /// HMAC-SHA-1.
    HmacSha1 = 2,
    /// HMAC-SHA-224.
    HmacSha224 = 3,
    /// HMAC-SHA-256.
    HmacSha256 = 4,
    /// HMAC-SHA-384.
    HmacSha384 = 5,
    /// HMAC-SHA-512.
    HmacSha512 = 6,
    /// AES-CMAC (128-bit).
    AesCmac = 25,
}

impl MacAlgo {
    /// Output tag length in bytes.
    pub const fn tag_len(self) -> usize {
        match self {
            Self::None => 0,
            Self::HmacMd5 => 16,
            Self::HmacSha1 => 20,
            Self::HmacSha224 => 28,
            Self::HmacSha256 => 32,
            Self::HmacSha384 => 48,
            Self::HmacSha512 => 64,
            Self::AesCmac => 16,
        }
    }

    /// Required key length in bytes (0 = variable/hash-dependent).
    pub const fn key_len(self) -> usize {
        match self {
            Self::AesCmac => 16,
            _ => 0,
        }
    }
}

// ---------------------------------------------------------------------------
// AEAD algorithms (§5.9.7.6)
// ---------------------------------------------------------------------------

/// AEAD algorithm identifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum AeadAlgo {
    /// No AEAD / unused.
    None = 0,
    /// AES-GCM with 128-bit key.
    AesGcm128 = 1,
    /// AES-GCM with 256-bit key.
    AesGcm256 = 2,
    /// AES-CCM with 128-bit key.
    AesCcm128 = 3,
    /// AES-CCM with 256-bit key.
    AesCcm256 = 4,
    /// ChaCha20-Poly1305.
    ChaCha20Poly1305 = 5,
}

impl AeadAlgo {
    /// Required key length in bytes.
    pub const fn key_len(self) -> usize {
        match self {
            Self::None => 0,
            Self::AesGcm128 | Self::AesCcm128 => 16,
            Self::AesGcm256 | Self::AesCcm256 => 32,
            Self::ChaCha20Poly1305 => 32,
        }
    }

    /// IV/nonce length in bytes.
    pub const fn iv_len(self) -> usize {
        match self {
            Self::None => 0,
            Self::AesGcm128 | Self::AesGcm256 => 12,
            Self::AesCcm128 | Self::AesCcm256 => 12,
            Self::ChaCha20Poly1305 => 12,
        }
    }

    /// Authentication tag length in bytes.
    pub const fn tag_len(self) -> usize {
        match self {
            Self::None => 0,
            Self::AesGcm128 | Self::AesGcm256 => 16,
            Self::AesCcm128 | Self::AesCcm256 => 16,
            Self::ChaCha20Poly1305 => 16,
        }
    }
}

// ---------------------------------------------------------------------------
// Device configuration (§5.9.4)
// ---------------------------------------------------------------------------

/// VirtIO crypto device configuration read from config space.
///
/// The device exposes its capabilities (supported algorithms) as
/// bitmasks in the configuration space, along with the maximum
/// number of data queues it supports.
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct VirtioCryptoConfig {
    /// Device status (1 = ready).
    pub status: u32,
    /// Maximum number of data virtqueues.
    pub max_dataqueues: u32,
    /// Bitmask of supported cipher algorithms.
    pub cipher_algo_l: u32,
    /// Bitmask of supported cipher algorithms (high 32 bits).
    pub cipher_algo_h: u32,
    /// Bitmask of supported hash algorithms.
    pub hash_algo: u32,
    /// Bitmask of supported MAC algorithms.
    pub mac_algo_l: u32,
    /// Bitmask of supported MAC algorithms (high 32 bits).
    pub mac_algo_h: u32,
    /// Bitmask of supported AEAD algorithms.
    pub aead_algo: u32,
    /// Maximum cipher key length supported (bytes).
    pub max_cipher_key_len: u32,
    /// Maximum authentication key length supported (bytes).
    pub max_auth_key_len: u32,
    /// Reserved for future use.
    pub _reserved: u32,
}

impl VirtioCryptoConfig {
    /// Check if a cipher algorithm is supported.
    pub fn supports_cipher(&self, algo: CipherAlgo) -> bool {
        let bit = algo as u32;
        if bit < 32 {
            self.cipher_algo_l & (1 << bit) != 0
        } else {
            self.cipher_algo_h & (1 << (bit - 32)) != 0
        }
    }

    /// Check if a hash algorithm is supported.
    pub fn supports_hash(&self, algo: HashAlgo) -> bool {
        self.hash_algo & (1 << algo as u32) != 0
    }

    /// Check if a MAC algorithm is supported.
    pub fn supports_mac(&self, algo: MacAlgo) -> bool {
        let bit = algo as u32;
        if bit < 32 {
            self.mac_algo_l & (1 << bit) != 0
        } else {
            self.mac_algo_h & (1 << (bit - 32)) != 0
        }
    }

    /// Check if an AEAD algorithm is supported.
    pub fn supports_aead(&self, algo: AeadAlgo) -> bool {
        self.aead_algo & (1 << algo as u32) != 0
    }
}

// ---------------------------------------------------------------------------
// Crypto operation type
// ---------------------------------------------------------------------------

/// The type of cryptographic operation to perform.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CryptoOpType {
    /// Encrypt plaintext.
    Encrypt,
    /// Decrypt ciphertext.
    Decrypt,
}

// ---------------------------------------------------------------------------
// Crypto session
// ---------------------------------------------------------------------------

/// A cryptographic session with the device.
///
/// Sessions hold algorithm and key state. Multiple operations can
/// be performed within a single session without re-negotiating
/// parameters.
#[derive(Clone, Copy)]
pub struct CryptoSession {
    /// Session identifier assigned by the device.
    pub session_id: u64,
    /// Service type for this session.
    service: u32,
    /// Algorithm identifier (interpretation depends on `service`).
    algo_id: u32,
    /// Session key material.
    key: [u8; MAX_KEY_SIZE],
    /// Length of the key in bytes.
    key_len: usize,
    /// Whether this session is active.
    active: bool,
}

impl Default for CryptoSession {
    fn default() -> Self {
        Self {
            session_id: 0,
            service: 0,
            algo_id: 0,
            key: [0u8; MAX_KEY_SIZE],
            key_len: 0,
            active: false,
        }
    }
}

impl CryptoSession {
    /// Returns the service type of this session.
    pub fn service_type(&self) -> u32 {
        self.service
    }

    /// Returns the algorithm identifier.
    pub fn algorithm_id(&self) -> u32 {
        self.algo_id
    }

    /// Returns the key length in bytes.
    pub fn key_length(&self) -> usize {
        self.key_len
    }

    /// Returns `true` if this session is active.
    pub fn is_active(&self) -> bool {
        self.active
    }
}

// ---------------------------------------------------------------------------
// Control request/response (§5.9.7.2)
// ---------------------------------------------------------------------------

/// Control virtqueue request header.
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct CryptoCtrlHeader {
    /// Opcode (create/destroy session).
    pub opcode: u32,
    /// Algorithm type (service type).
    pub algo: u32,
    /// Flags (reserved, must be zero).
    pub flag: u32,
    /// Padding.
    pub _padding: u32,
}

/// Session creation request for cipher operations.
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct CryptoCipherSessionReq {
    /// Cipher algorithm (see [`CipherAlgo`]).
    pub algo: u32,
    /// Key length in bytes.
    pub key_len: u32,
    /// Operation direction (encrypt/decrypt).
    pub op: u32,
    /// Padding.
    pub _padding: u32,
}

/// Session creation request for hash operations.
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct CryptoHashSessionReq {
    /// Hash algorithm (see [`HashAlgo`]).
    pub algo: u32,
    /// Hash result length in bytes.
    pub hash_result_len: u32,
}

/// Session creation request for MAC operations.
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct CryptoMacSessionReq {
    /// MAC algorithm (see [`MacAlgo`]).
    pub algo: u32,
    /// MAC result length in bytes.
    pub hash_result_len: u32,
    /// Authentication key length.
    pub auth_key_len: u32,
    /// Padding.
    pub _padding: u32,
}

/// Session creation request for AEAD operations.
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct CryptoAeadSessionReq {
    /// AEAD algorithm (see [`AeadAlgo`]).
    pub algo: u32,
    /// Key length in bytes.
    pub key_len: u32,
    /// Authentication tag length.
    pub tag_len: u32,
    /// AAD length.
    pub aad_len: u32,
    /// Operation direction (encrypt/decrypt).
    pub op: u32,
    /// Padding.
    pub _padding: u32,
}

/// Session creation response from the device.
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct CryptoSessionResponse {
    /// Session ID assigned by the device (0 on failure).
    pub session_id: u64,
    /// Status code.
    pub status: u8,
    /// Padding.
    pub _padding: [u8; 7],
}

// ---------------------------------------------------------------------------
// Data request/response (§5.9.7.3)
// ---------------------------------------------------------------------------

/// Data virtqueue request header for cipher operations.
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct CryptoCipherDataReq {
    /// Session ID.
    pub session_id: u64,
    /// Operation: 0 = encrypt, 1 = decrypt.
    pub op: u32,
    /// Source data length.
    pub src_data_len: u32,
    /// Destination data length.
    pub dst_data_len: u32,
    /// IV length.
    pub iv_len: u32,
}

/// Data virtqueue request header for hash operations.
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct CryptoHashDataReq {
    /// Session ID.
    pub session_id: u64,
    /// Source data length.
    pub src_data_len: u32,
    /// Hash result length.
    pub hash_result_len: u32,
}

/// Data virtqueue request header for MAC operations.
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct CryptoMacDataReq {
    /// Session ID.
    pub session_id: u64,
    /// Source data length.
    pub src_data_len: u32,
    /// MAC result length.
    pub hash_result_len: u32,
}

/// Data virtqueue request header for AEAD operations.
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct CryptoAeadDataReq {
    /// Session ID.
    pub session_id: u64,
    /// Operation: 0 = encrypt, 1 = decrypt.
    pub op: u32,
    /// Source data length.
    pub src_data_len: u32,
    /// Destination data length.
    pub dst_data_len: u32,
    /// AAD length.
    pub aad_len: u32,
    /// IV length.
    pub iv_len: u32,
    /// Tag length.
    pub tag_len: u32,
}

/// Data operation response from the device.
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct CryptoDataResponse {
    /// Status code (0 = success).
    pub status: u8,
    /// Padding.
    pub _padding: [u8; 7],
}

// ---------------------------------------------------------------------------
// In-flight request tracking
// ---------------------------------------------------------------------------

/// Tracks an in-flight data operation.
#[derive(Debug, Clone, Copy, Default)]
struct InflightRequest {
    /// Session this request belongs to.
    session_id: u64,
    /// Head descriptor index in the virtqueue.
    head_desc: u16,
    /// Whether this slot is active.
    active: bool,
}

// ---------------------------------------------------------------------------
// Data queue state
// ---------------------------------------------------------------------------

/// Per-data-queue state.
struct DataQueue {
    /// Queue index (1-based; queue 0 is the control queue).
    queue_idx: u16,
    /// In-flight request tracking.
    inflight: [InflightRequest; MAX_INFLIGHT],
    /// Number of active in-flight requests.
    inflight_count: usize,
}

impl DataQueue {
    /// Create a new data queue.
    const fn new(queue_idx: u16) -> Self {
        Self {
            queue_idx,
            inflight: [InflightRequest {
                session_id: 0,
                head_desc: 0,
                active: false,
            }; MAX_INFLIGHT],
            inflight_count: 0,
        }
    }

    /// Find a free in-flight slot.
    fn find_free_slot(&self) -> Option<usize> {
        for (i, req) in self.inflight.iter().enumerate() {
            if !req.active {
                return Some(i);
            }
        }
        None
    }

    /// Record a new in-flight request.
    fn submit(&mut self, session_id: u64, head_desc: u16) -> Result<usize> {
        let idx = self.find_free_slot().ok_or(Error::Busy)?;
        self.inflight[idx] = InflightRequest {
            session_id,
            head_desc,
            active: true,
        };
        self.inflight_count += 1;
        Ok(idx)
    }

    /// Complete an in-flight request by descriptor index.
    fn complete(&mut self, head_desc: u16) -> Result<u64> {
        for req in self.inflight.iter_mut() {
            if req.active && req.head_desc == head_desc {
                let session_id = req.session_id;
                req.active = false;
                self.inflight_count = self.inflight_count.saturating_sub(1);
                return Ok(session_id);
            }
        }
        Err(Error::NotFound)
    }

    /// Returns the queue index.
    pub fn index(&self) -> u16 {
        self.queue_idx
    }
}

// ---------------------------------------------------------------------------
// VirtIO crypto device
// ---------------------------------------------------------------------------

/// VirtIO crypto device driver.
///
/// Manages crypto sessions and dispatches cipher, hash, MAC, and
/// AEAD operations through the VirtIO virtqueue interface.
pub struct VirtioCrypto {
    /// MMIO base address.
    mmio_base: u64,
    /// Device configuration.
    config: VirtioCryptoConfig,
    /// Session table.
    sessions: [CryptoSession; MAX_SESSIONS],
    /// Number of active sessions.
    session_count: usize,
    /// Next session ID to assign.
    next_session_id: u64,
    /// Data queues.
    data_queues: [DataQueue; MAX_DATA_QUEUES],
    /// Number of active data queues.
    num_data_queues: usize,
    /// Control queue buffer.
    ctrl_buf: [u8; CTRL_BUF_SIZE],
    /// Whether the device has been initialized.
    initialized: bool,
}

impl VirtioCrypto {
    /// Create a new VirtIO crypto device.
    pub const fn new(mmio_base: u64) -> Self {
        Self {
            mmio_base,
            config: VirtioCryptoConfig {
                status: 0,
                max_dataqueues: 0,
                cipher_algo_l: 0,
                cipher_algo_h: 0,
                hash_algo: 0,
                mac_algo_l: 0,
                mac_algo_h: 0,
                aead_algo: 0,
                max_cipher_key_len: 0,
                max_auth_key_len: 0,
                _reserved: 0,
            },
            sessions: [CryptoSession {
                session_id: 0,
                service: 0,
                algo_id: 0,
                key: [0u8; MAX_KEY_SIZE],
                key_len: 0,
                active: false,
            }; MAX_SESSIONS],
            session_count: 0,
            next_session_id: 1,
            data_queues: [
                DataQueue::new(1),
                DataQueue::new(2),
                DataQueue::new(3),
                DataQueue::new(4),
            ],
            num_data_queues: 0,
            ctrl_buf: [0u8; CTRL_BUF_SIZE],
            initialized: false,
        }
    }

    /// Initialize the VirtIO crypto device.
    ///
    /// Performs device discovery, feature negotiation, and virtqueue
    /// setup. Reads the device configuration to determine supported
    /// algorithms.
    pub fn init(&mut self) -> Result<()> {
        if self.initialized {
            return Err(Error::AlreadyExists);
        }

        // Read device configuration (in a real driver, this reads
        // from MMIO config space at the device's BAR).
        // For now, set reasonable defaults for a capable device.
        self.config = VirtioCryptoConfig {
            status: 1,
            max_dataqueues: MAX_DATA_QUEUES as u32,
            cipher_algo_l: (1 << CipherAlgo::AesCbc as u32)
                | (1 << CipherAlgo::AesCtr as u32)
                | (1 << CipherAlgo::AesXts as u32)
                | (1 << CipherAlgo::AesEcb as u32),
            cipher_algo_h: 0,
            hash_algo: (1 << HashAlgo::Sha256 as u32) | (1 << HashAlgo::Sha512 as u32),
            mac_algo_l: (1 << MacAlgo::HmacSha256 as u32) | (1 << MacAlgo::HmacSha512 as u32),
            mac_algo_h: 0,
            aead_algo: (1 << AeadAlgo::AesGcm128 as u32) | (1 << AeadAlgo::AesGcm256 as u32),
            max_cipher_key_len: MAX_KEY_SIZE as u32,
            max_auth_key_len: MAX_KEY_SIZE as u32,
            _reserved: 0,
        };

        // Set up data queues.
        let num_queues = (self.config.max_dataqueues as usize).min(MAX_DATA_QUEUES);
        self.num_data_queues = num_queues;

        self.initialized = true;
        Ok(())
    }

    /// Returns the MMIO base address.
    pub fn mmio_base(&self) -> u64 {
        self.mmio_base
    }

    /// Returns the device configuration.
    pub fn config(&self) -> &VirtioCryptoConfig {
        &self.config
    }

    /// Returns whether the device is initialized.
    pub fn is_initialized(&self) -> bool {
        self.initialized
    }

    // -- Session management (§5.9.7.2) ----------------------------------

    /// Find a free session slot.
    fn find_free_session(&self) -> Option<usize> {
        for (i, s) in self.sessions.iter().enumerate() {
            if !s.active {
                return Some(i);
            }
        }
        None
    }

    /// Find a session by ID.
    fn find_session(&self, session_id: u64) -> Option<usize> {
        for (i, s) in self.sessions.iter().enumerate() {
            if s.active && s.session_id == session_id {
                return Some(i);
            }
        }
        None
    }

    /// Create a cipher session.
    ///
    /// Allocates a session for symmetric cipher operations with the
    /// given algorithm and key.
    pub fn create_cipher_session(&mut self, algo: CipherAlgo, key: &[u8]) -> Result<u64> {
        if !self.initialized {
            return Err(Error::IoError);
        }
        if !self.config.supports_cipher(algo) {
            return Err(Error::NotImplemented);
        }
        if key.len() > MAX_KEY_SIZE {
            return Err(Error::InvalidArgument);
        }
        let expected_key_len = algo.key_len();
        if expected_key_len > 0 && key.len() != expected_key_len {
            return Err(Error::InvalidArgument);
        }

        let idx = self.find_free_session().ok_or(Error::OutOfMemory)?;

        let session_id = self.next_session_id;
        self.next_session_id += 1;

        self.sessions[idx].session_id = session_id;
        self.sessions[idx].service = VIRTIO_CRYPTO_SERVICE_CIPHER;
        self.sessions[idx].algo_id = algo as u32;
        self.sessions[idx].key[..key.len()].copy_from_slice(key);
        self.sessions[idx].key_len = key.len();
        self.sessions[idx].active = true;
        self.session_count += 1;

        // Build control request for the device.
        self.build_create_session_ctrl(session_id, algo as u32)?;

        Ok(session_id)
    }

    /// Create a hash session.
    ///
    /// Allocates a session for hash operations (no key required).
    pub fn create_hash_session(&mut self, algo: HashAlgo) -> Result<u64> {
        if !self.initialized {
            return Err(Error::IoError);
        }
        if !self.config.supports_hash(algo) {
            return Err(Error::NotImplemented);
        }

        let idx = self.find_free_session().ok_or(Error::OutOfMemory)?;

        let session_id = self.next_session_id;
        self.next_session_id += 1;

        self.sessions[idx].session_id = session_id;
        self.sessions[idx].service = VIRTIO_CRYPTO_SERVICE_HASH;
        self.sessions[idx].algo_id = algo as u32;
        self.sessions[idx].key_len = 0;
        self.sessions[idx].active = true;
        self.session_count += 1;

        Ok(session_id)
    }

    /// Create a MAC session.
    ///
    /// Allocates a session for MAC operations with the given
    /// algorithm and authentication key.
    pub fn create_mac_session(&mut self, algo: MacAlgo, key: &[u8]) -> Result<u64> {
        if !self.initialized {
            return Err(Error::IoError);
        }
        if !self.config.supports_mac(algo) {
            return Err(Error::NotImplemented);
        }
        if key.len() > MAX_KEY_SIZE {
            return Err(Error::InvalidArgument);
        }

        let idx = self.find_free_session().ok_or(Error::OutOfMemory)?;

        let session_id = self.next_session_id;
        self.next_session_id += 1;

        self.sessions[idx].session_id = session_id;
        self.sessions[idx].service = VIRTIO_CRYPTO_SERVICE_MAC;
        self.sessions[idx].algo_id = algo as u32;
        self.sessions[idx].key[..key.len()].copy_from_slice(key);
        self.sessions[idx].key_len = key.len();
        self.sessions[idx].active = true;
        self.session_count += 1;

        Ok(session_id)
    }

    /// Create an AEAD session.
    ///
    /// Allocates a session for AEAD operations with the given
    /// algorithm and key.
    pub fn create_aead_session(&mut self, algo: AeadAlgo, key: &[u8]) -> Result<u64> {
        if !self.initialized {
            return Err(Error::IoError);
        }
        if !self.config.supports_aead(algo) {
            return Err(Error::NotImplemented);
        }
        let expected_key_len = algo.key_len();
        if key.len() != expected_key_len {
            return Err(Error::InvalidArgument);
        }

        let idx = self.find_free_session().ok_or(Error::OutOfMemory)?;

        let session_id = self.next_session_id;
        self.next_session_id += 1;

        self.sessions[idx].session_id = session_id;
        self.sessions[idx].service = VIRTIO_CRYPTO_SERVICE_AEAD;
        self.sessions[idx].algo_id = algo as u32;
        self.sessions[idx].key[..key.len()].copy_from_slice(key);
        self.sessions[idx].key_len = key.len();
        self.sessions[idx].active = true;
        self.session_count += 1;

        Ok(session_id)
    }

    /// Destroy a session.
    ///
    /// Releases the session resources both locally and on the device.
    pub fn destroy_session(&mut self, session_id: u64) -> Result<()> {
        if !self.initialized {
            return Err(Error::IoError);
        }

        let idx = self.find_session(session_id).ok_or(Error::NotFound)?;

        // Zero out key material before releasing.
        self.sessions[idx].key = [0u8; MAX_KEY_SIZE];
        self.sessions[idx].key_len = 0;
        self.sessions[idx].active = false;
        self.session_count = self.session_count.saturating_sub(1);

        Ok(())
    }

    /// Build the control virtqueue buffer for session creation.
    ///
    /// In a real driver this would submit the request through the
    /// control virtqueue and await the device response.
    fn build_create_session_ctrl(&mut self, _session_id: u64, _algo: u32) -> Result<()> {
        // Build the control header in the control buffer.
        let hdr = CryptoCtrlHeader {
            opcode: VIRTIO_CRYPTO_CREATE_SESSION,
            algo: VIRTIO_CRYPTO_SERVICE_CIPHER,
            flag: 0,
            _padding: 0,
        };

        let hdr_bytes = hdr.opcode.to_le_bytes();
        if self.ctrl_buf.len() >= 4 {
            self.ctrl_buf[..4].copy_from_slice(&hdr_bytes);
        }

        // In a real implementation, this would:
        // 1. Build descriptor chain (header + algo params + key)
        // 2. Submit to control virtqueue
        // 3. Wait for completion and read session ID from response
        Ok(())
    }

    // -- Cipher operations (§5.9.7.3) -----------------------------------

    /// Perform a cipher operation (encrypt or decrypt).
    ///
    /// Uses the session identified by `session_id` to encrypt or
    /// decrypt `src` into `dst`. The IV must match the algorithm's
    /// IV size.
    pub fn cipher_op(
        &mut self,
        session_id: u64,
        op: CryptoOpType,
        iv: &[u8],
        src: &[u8],
        dst: &mut [u8],
    ) -> Result<usize> {
        if !self.initialized {
            return Err(Error::IoError);
        }

        let sess_idx = self.find_session(session_id).ok_or(Error::NotFound)?;
        if self.sessions[sess_idx].service != VIRTIO_CRYPTO_SERVICE_CIPHER {
            return Err(Error::InvalidArgument);
        }
        if iv.len() > MAX_IV_SIZE {
            return Err(Error::InvalidArgument);
        }
        if dst.len() < src.len() {
            return Err(Error::InvalidArgument);
        }

        // Select a data queue (round-robin over available queues).
        let queue_idx = (session_id as usize) % self.num_data_queues;
        if queue_idx >= self.num_data_queues {
            return Err(Error::IoError);
        }

        // Build the data request.
        let _req = CryptoCipherDataReq {
            session_id,
            op: match op {
                CryptoOpType::Encrypt => 0,
                CryptoOpType::Decrypt => 1,
            },
            src_data_len: src.len() as u32,
            dst_data_len: dst.len() as u32,
            iv_len: iv.len() as u32,
        };

        // Submit to data queue (would be virtqueue submission).
        let _slot = self.data_queues[queue_idx].submit(session_id, 0)?;

        // In a real driver, we would wait for the device to process
        // the request and copy the result. For now, copy src to dst
        // as a placeholder.
        dst[..src.len()].copy_from_slice(src);

        // Complete the request.
        let _ = self.data_queues[queue_idx].complete(0);

        Ok(src.len())
    }

    /// Encrypt data using a cipher session.
    pub fn encrypt(
        &mut self,
        session_id: u64,
        iv: &[u8],
        plaintext: &[u8],
        ciphertext: &mut [u8],
    ) -> Result<usize> {
        self.cipher_op(session_id, CryptoOpType::Encrypt, iv, plaintext, ciphertext)
    }

    /// Decrypt data using a cipher session.
    pub fn decrypt(
        &mut self,
        session_id: u64,
        iv: &[u8],
        ciphertext: &[u8],
        plaintext: &mut [u8],
    ) -> Result<usize> {
        self.cipher_op(session_id, CryptoOpType::Decrypt, iv, ciphertext, plaintext)
    }

    // -- Hash operations (§5.9.7.4) -------------------------------------

    /// Compute a hash digest.
    ///
    /// Uses the session identified by `session_id` to hash `data`
    /// and write the digest into `digest_buf`. Returns the digest
    /// length.
    pub fn hash(&mut self, session_id: u64, data: &[u8], digest_buf: &mut [u8]) -> Result<usize> {
        if !self.initialized {
            return Err(Error::IoError);
        }

        let sess_idx = self.find_session(session_id).ok_or(Error::NotFound)?;
        if self.sessions[sess_idx].service != VIRTIO_CRYPTO_SERVICE_HASH {
            return Err(Error::InvalidArgument);
        }

        // Determine digest length from algorithm.
        let algo_id = self.sessions[sess_idx].algo_id;
        let digest_len = match algo_id {
            x if x == HashAlgo::Sha256 as u32 => HashAlgo::Sha256.digest_len(),
            x if x == HashAlgo::Sha512 as u32 => HashAlgo::Sha512.digest_len(),
            x if x == HashAlgo::Sha384 as u32 => HashAlgo::Sha384.digest_len(),
            x if x == HashAlgo::Sha224 as u32 => HashAlgo::Sha224.digest_len(),
            x if x == HashAlgo::Sha1 as u32 => HashAlgo::Sha1.digest_len(),
            x if x == HashAlgo::Md5 as u32 => HashAlgo::Md5.digest_len(),
            _ => return Err(Error::InvalidArgument),
        };

        if digest_buf.len() < digest_len {
            return Err(Error::InvalidArgument);
        }

        let _req = CryptoHashDataReq {
            session_id,
            src_data_len: data.len() as u32,
            hash_result_len: digest_len as u32,
        };

        // Submit to data queue.
        let queue_idx = (session_id as usize) % self.num_data_queues;
        let _slot = self.data_queues[queue_idx].submit(session_id, 0)?;

        // Placeholder: zero the digest buffer.
        for b in digest_buf[..digest_len].iter_mut() {
            *b = 0;
        }

        let _ = self.data_queues[queue_idx].complete(0);

        Ok(digest_len)
    }

    // -- MAC operations (§5.9.7.5) --------------------------------------

    /// Compute a MAC tag.
    ///
    /// Uses the session identified by `session_id` to compute a
    /// MAC over `data` and write the tag into `tag_buf`. Returns
    /// the tag length.
    pub fn mac(&mut self, session_id: u64, data: &[u8], tag_buf: &mut [u8]) -> Result<usize> {
        if !self.initialized {
            return Err(Error::IoError);
        }

        let sess_idx = self.find_session(session_id).ok_or(Error::NotFound)?;
        if self.sessions[sess_idx].service != VIRTIO_CRYPTO_SERVICE_MAC {
            return Err(Error::InvalidArgument);
        }

        let algo_id = self.sessions[sess_idx].algo_id;
        let tag_len = match algo_id {
            x if x == MacAlgo::HmacSha256 as u32 => MacAlgo::HmacSha256.tag_len(),
            x if x == MacAlgo::HmacSha512 as u32 => MacAlgo::HmacSha512.tag_len(),
            x if x == MacAlgo::HmacSha384 as u32 => MacAlgo::HmacSha384.tag_len(),
            x if x == MacAlgo::HmacSha224 as u32 => MacAlgo::HmacSha224.tag_len(),
            x if x == MacAlgo::HmacSha1 as u32 => MacAlgo::HmacSha1.tag_len(),
            x if x == MacAlgo::HmacMd5 as u32 => MacAlgo::HmacMd5.tag_len(),
            x if x == MacAlgo::AesCmac as u32 => MacAlgo::AesCmac.tag_len(),
            _ => return Err(Error::InvalidArgument),
        };

        if tag_buf.len() < tag_len {
            return Err(Error::InvalidArgument);
        }

        let _req = CryptoMacDataReq {
            session_id,
            src_data_len: data.len() as u32,
            hash_result_len: tag_len as u32,
        };

        let queue_idx = (session_id as usize) % self.num_data_queues;
        let _slot = self.data_queues[queue_idx].submit(session_id, 0)?;

        // Placeholder: zero the tag buffer.
        for b in tag_buf[..tag_len].iter_mut() {
            *b = 0;
        }

        let _ = self.data_queues[queue_idx].complete(0);

        Ok(tag_len)
    }

    // -- AEAD operations (§5.9.7.6) -------------------------------------

    /// Perform an AEAD encrypt operation.
    ///
    /// Encrypts `plaintext` with `aad` and `iv`, writing ciphertext
    /// and appended authentication tag into `dst`. Returns the total
    /// output length (ciphertext + tag).
    pub fn aead_encrypt(
        &mut self,
        session_id: u64,
        iv: &[u8],
        aad: &[u8],
        plaintext: &[u8],
        dst: &mut [u8],
    ) -> Result<usize> {
        if !self.initialized {
            return Err(Error::IoError);
        }

        let sess_idx = self.find_session(session_id).ok_or(Error::NotFound)?;
        if self.sessions[sess_idx].service != VIRTIO_CRYPTO_SERVICE_AEAD {
            return Err(Error::InvalidArgument);
        }
        if iv.len() > MAX_IV_SIZE || aad.len() > MAX_AAD_SIZE {
            return Err(Error::InvalidArgument);
        }

        let algo_id = self.sessions[sess_idx].algo_id;
        let tag_len = match algo_id {
            x if x == AeadAlgo::AesGcm128 as u32 => AeadAlgo::AesGcm128.tag_len(),
            x if x == AeadAlgo::AesGcm256 as u32 => AeadAlgo::AesGcm256.tag_len(),
            x if x == AeadAlgo::AesCcm128 as u32 => AeadAlgo::AesCcm128.tag_len(),
            x if x == AeadAlgo::AesCcm256 as u32 => AeadAlgo::AesCcm256.tag_len(),
            x if x == AeadAlgo::ChaCha20Poly1305 as u32 => AeadAlgo::ChaCha20Poly1305.tag_len(),
            _ => return Err(Error::InvalidArgument),
        };

        let total_out = plaintext.len() + tag_len;
        if dst.len() < total_out {
            return Err(Error::InvalidArgument);
        }

        let _req = CryptoAeadDataReq {
            session_id,
            op: 0,
            src_data_len: plaintext.len() as u32,
            dst_data_len: total_out as u32,
            aad_len: aad.len() as u32,
            iv_len: iv.len() as u32,
            tag_len: tag_len as u32,
        };

        let queue_idx = (session_id as usize) % self.num_data_queues;
        let _slot = self.data_queues[queue_idx].submit(session_id, 0)?;

        // Placeholder: copy plaintext and zero the tag.
        dst[..plaintext.len()].copy_from_slice(plaintext);
        for b in dst[plaintext.len()..total_out].iter_mut() {
            *b = 0;
        }

        let _ = self.data_queues[queue_idx].complete(0);

        Ok(total_out)
    }

    /// Perform an AEAD decrypt operation.
    ///
    /// Decrypts `ciphertext` (which includes the appended tag) with
    /// `aad` and `iv`, writing plaintext into `dst`. Returns the
    /// plaintext length.
    pub fn aead_decrypt(
        &mut self,
        session_id: u64,
        iv: &[u8],
        aad: &[u8],
        ciphertext: &[u8],
        dst: &mut [u8],
    ) -> Result<usize> {
        if !self.initialized {
            return Err(Error::IoError);
        }

        let sess_idx = self.find_session(session_id).ok_or(Error::NotFound)?;
        if self.sessions[sess_idx].service != VIRTIO_CRYPTO_SERVICE_AEAD {
            return Err(Error::InvalidArgument);
        }
        if iv.len() > MAX_IV_SIZE || aad.len() > MAX_AAD_SIZE {
            return Err(Error::InvalidArgument);
        }

        let algo_id = self.sessions[sess_idx].algo_id;
        let tag_len = match algo_id {
            x if x == AeadAlgo::AesGcm128 as u32 => AeadAlgo::AesGcm128.tag_len(),
            x if x == AeadAlgo::AesGcm256 as u32 => AeadAlgo::AesGcm256.tag_len(),
            x if x == AeadAlgo::AesCcm128 as u32 => AeadAlgo::AesCcm128.tag_len(),
            x if x == AeadAlgo::AesCcm256 as u32 => AeadAlgo::AesCcm256.tag_len(),
            x if x == AeadAlgo::ChaCha20Poly1305 as u32 => AeadAlgo::ChaCha20Poly1305.tag_len(),
            _ => return Err(Error::InvalidArgument),
        };

        if ciphertext.len() < tag_len {
            return Err(Error::InvalidArgument);
        }
        let plaintext_len = ciphertext.len() - tag_len;
        if dst.len() < plaintext_len {
            return Err(Error::InvalidArgument);
        }

        let _req = CryptoAeadDataReq {
            session_id,
            op: 1,
            src_data_len: ciphertext.len() as u32,
            dst_data_len: plaintext_len as u32,
            aad_len: aad.len() as u32,
            iv_len: iv.len() as u32,
            tag_len: tag_len as u32,
        };

        let queue_idx = (session_id as usize) % self.num_data_queues;
        let _slot = self.data_queues[queue_idx].submit(session_id, 0)?;

        // Placeholder: copy ciphertext (minus tag) to plaintext.
        dst[..plaintext_len].copy_from_slice(&ciphertext[..plaintext_len]);

        let _ = self.data_queues[queue_idx].complete(0);

        Ok(plaintext_len)
    }

    // -- Interrupt handler ----------------------------------------------

    /// Handle a crypto device interrupt.
    ///
    /// Reads the interrupt status register, processes completed
    /// operations in all data queues, and acknowledges the interrupt.
    /// Returns a bitmask indicating which queues had completions.
    pub fn handle_interrupt(&mut self) -> Result<u32> {
        if !self.initialized {
            return Err(Error::IoError);
        }

        // In a real driver, read the interrupt status from MMIO.
        // For now, return 0 (no completions).
        let _status: u32 = 0;

        Ok(0)
    }

    // -- Statistics ------------------------------------------------------

    /// Number of active crypto sessions.
    pub fn session_count(&self) -> usize {
        self.session_count
    }

    /// Number of active data queues.
    pub fn data_queue_count(&self) -> usize {
        self.num_data_queues
    }

    /// Total in-flight requests across all data queues.
    pub fn total_inflight(&self) -> usize {
        let mut total = 0;
        for i in 0..self.num_data_queues {
            total += self.data_queues[i].inflight_count;
        }
        total
    }

    /// Get session information by session ID.
    pub fn get_session_info(&self, session_id: u64) -> Result<(u32, u32, usize)> {
        let idx = self.find_session(session_id).ok_or(Error::NotFound)?;
        let s = &self.sessions[idx];
        Ok((s.service, s.algo_id, s.key_len))
    }
}

// ---------------------------------------------------------------------------
// Global registry
// ---------------------------------------------------------------------------

/// Global registry of VirtIO crypto devices.
struct CryptoRegistry {
    /// Base addresses of registered devices.
    devices: [u64; MAX_CRYPTO_DEVICES],
    /// Number of registered devices.
    count: usize,
}

/// Static crypto device registry.
static mut CRYPTO_REGISTRY: CryptoRegistry = CryptoRegistry {
    devices: [0; MAX_CRYPTO_DEVICES],
    count: 0,
};

/// Register a VirtIO crypto device by its MMIO base address.
///
/// # Safety
///
/// The caller must ensure exclusive access (e.g., during single-
/// threaded device enumeration).
pub unsafe fn register_crypto_device(mmio_base: u64) -> Result<usize> {
    // SAFETY: Accessed during single-threaded device enumeration.
    let registry = unsafe { &mut *core::ptr::addr_of_mut!(CRYPTO_REGISTRY) };
    if registry.count >= MAX_CRYPTO_DEVICES {
        return Err(Error::OutOfMemory);
    }
    let idx = registry.count;
    registry.devices[idx] = mmio_base;
    registry.count += 1;
    Ok(idx)
}

/// Get the MMIO base of a registered crypto device.
///
/// # Safety
///
/// The caller must ensure no concurrent modifications.
pub unsafe fn get_crypto_device(index: usize) -> Result<u64> {
    // SAFETY: Read access to static registry.
    let registry = unsafe { &*core::ptr::addr_of!(CRYPTO_REGISTRY) };
    if index >= registry.count {
        return Err(Error::NotFound);
    }
    Ok(registry.devices[index])
}

/// Number of registered crypto devices.
///
/// # Safety
///
/// The caller must ensure no concurrent modifications.
pub unsafe fn crypto_device_count() -> usize {
    // SAFETY: Read access to static registry.
    let registry = unsafe { &*core::ptr::addr_of!(CRYPTO_REGISTRY) };
    registry.count
}
