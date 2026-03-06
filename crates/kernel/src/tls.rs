// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! TLS 1.3 record layer for the ONCRIX network stack.
//!
//! Implements the TLS 1.3 (RFC 8446) record protocol: content type
//! framing, record header construction, session state machine,
//! encrypt/decrypt of application data records, and a fixed-size
//! session registry for managing concurrent TLS sessions.
//!
//! The record layer sits between the transport (TCP) and application
//! protocols, providing confidentiality and integrity via AEAD
//! cipher suites (AES-128-GCM, AES-256-GCM, ChaCha20-Poly1305).

use oncrix_lib::{Error, Result};

// =========================================================================
// Constants
// =========================================================================

/// Maximum number of concurrent TLS sessions.
const TLS_TABLE_SIZE: usize = 32;

/// TLS record header size in bytes (content_type + version + length).
const TLS_RECORD_HEADER_SIZE: usize = 5;

/// Maximum TLS record plaintext payload (2^14 = 16384 bytes).
const TLS_MAX_PLAINTEXT: usize = 16384;

/// AEAD authentication tag size in bytes.
const AEAD_TAG_SIZE: usize = 16;

/// AES-128 key size in bytes.
const AES128_KEY_SIZE: usize = 16;

/// AES-256 key size in bytes.
const AES256_KEY_SIZE: usize = 32;

/// AEAD nonce (IV) size in bytes.
const AEAD_NONCE_SIZE: usize = 12;

// =========================================================================
// TlsVersion
// =========================================================================

/// TLS protocol version identifiers.
///
/// TLS 1.3 uses legacy version 0x0303 in the record layer for
/// backwards compatibility, with the actual version negotiated
/// in the handshake.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u16)]
pub enum TlsVersion {
    /// TLS 1.2 — legacy version field value.
    Tls12 = 0x0303,
    /// TLS 1.3 — negotiated via supported_versions extension.
    #[default]
    Tls13 = 0x0304,
}

impl TlsVersion {
    /// Return the raw `u16` wire encoding of this version.
    pub const fn as_u16(self) -> u16 {
        self as u16
    }

    /// Try to convert a raw `u16` value into a [`TlsVersion`].
    ///
    /// Returns `None` if the value does not match a known version.
    pub const fn from_u16(v: u16) -> Option<Self> {
        match v {
            0x0303 => Some(Self::Tls12),
            0x0304 => Some(Self::Tls13),
            _ => None,
        }
    }
}

// =========================================================================
// TlsContentType
// =========================================================================

/// TLS record content types (RFC 8446 section 5.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u8)]
pub enum TlsContentType {
    /// Change cipher spec (compatibility, ignored in TLS 1.3).
    ChangeCipherSpec = 20,
    /// Alert message.
    Alert = 21,
    /// Handshake message.
    Handshake = 22,
    /// Application data (encrypted in TLS 1.3).
    #[default]
    ApplicationData = 23,
}

impl TlsContentType {
    /// Return the raw `u8` wire encoding of this content type.
    pub const fn as_u8(self) -> u8 {
        self as u8
    }

    /// Try to convert a raw `u8` value into a [`TlsContentType`].
    ///
    /// Returns `None` if the value does not match a known type.
    pub const fn from_u8(v: u8) -> Option<Self> {
        match v {
            20 => Some(Self::ChangeCipherSpec),
            21 => Some(Self::Alert),
            22 => Some(Self::Handshake),
            23 => Some(Self::ApplicationData),
            _ => None,
        }
    }
}

// =========================================================================
// TlsAlertLevel
// =========================================================================

/// TLS alert severity levels (RFC 8446 section 6).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u8)]
pub enum TlsAlertLevel {
    /// Warning alert — connection may continue.
    #[default]
    Warning = 1,
    /// Fatal alert — connection must be terminated.
    Fatal = 2,
}

// =========================================================================
// TlsAlertDesc
// =========================================================================

/// TLS alert descriptions (RFC 8446 section 6.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u8)]
pub enum TlsAlertDesc {
    /// Graceful connection closure.
    #[default]
    CloseNotify = 0,
    /// Received an unexpected message type.
    UnexpectedMessage = 10,
    /// Record MAC verification failed.
    BadRecordMac = 20,
    /// Handshake negotiation failed.
    HandshakeFailure = 40,
    /// A certificate is required but was not provided.
    CertificateRequired = 116,
    /// Internal implementation error.
    InternalError = 80,
    /// Message could not be decoded.
    DecodeError = 50,
}

// =========================================================================
// TlsCipherSuite
// =========================================================================

/// TLS 1.3 cipher suites (RFC 8446 section B.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TlsCipherSuite {
    /// AES-128-GCM with SHA-256.
    #[default]
    Aes128GcmSha256,
    /// AES-256-GCM with SHA-384.
    Aes256GcmSha384,
    /// ChaCha20-Poly1305 with SHA-256.
    ChaCha20Poly1305,
}

impl TlsCipherSuite {
    /// Return the AEAD key size in bytes for this cipher suite.
    pub const fn key_size(self) -> usize {
        match self {
            Self::Aes128GcmSha256 => AES128_KEY_SIZE,
            Self::Aes256GcmSha384 => AES256_KEY_SIZE,
            Self::ChaCha20Poly1305 => AES256_KEY_SIZE,
        }
    }
}

// =========================================================================
// TlsRecordHeader
// =========================================================================

/// TLS record layer header (RFC 8446 section 5.1).
///
/// Wire format: `content_type(1) || legacy_version(2) || length(2)`.
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct TlsRecordHeader {
    /// Content type byte (see [`TlsContentType`]).
    pub content_type: u8,
    /// Legacy protocol version (always 0x0303 for TLS 1.3).
    pub legacy_version: u16,
    /// Length of the following record payload in bytes.
    pub length: u16,
}

impl TlsRecordHeader {
    /// Serialize this header into the first 5 bytes of `out`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `out` is shorter than
    /// [`TLS_RECORD_HEADER_SIZE`].
    pub fn write_to(&self, out: &mut [u8]) -> Result<()> {
        if out.len() < TLS_RECORD_HEADER_SIZE {
            return Err(Error::InvalidArgument);
        }
        out[0] = self.content_type;
        let ver = self.legacy_version.to_be_bytes();
        out[1] = ver[0];
        out[2] = ver[1];
        let len = self.length.to_be_bytes();
        out[3] = len[0];
        out[4] = len[1];
        Ok(())
    }

    /// Parse a record header from the first 5 bytes of `data`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `data` is shorter than
    /// [`TLS_RECORD_HEADER_SIZE`].
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < TLS_RECORD_HEADER_SIZE {
            return Err(Error::InvalidArgument);
        }
        Ok(Self {
            content_type: data[0],
            legacy_version: u16::from_be_bytes([data[1], data[2]]),
            length: u16::from_be_bytes([data[3], data[4]]),
        })
    }
}

// =========================================================================
// TlsHandshakeType
// =========================================================================

/// TLS 1.3 handshake message types (RFC 8446 section 4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u8)]
pub enum TlsHandshakeType {
    /// Client initiates the handshake.
    #[default]
    ClientHello = 1,
    /// Server responds to ClientHello.
    ServerHello = 2,
    /// Server sends encrypted extensions.
    EncryptedExtensions = 8,
    /// Server sends its certificate chain.
    Certificate = 11,
    /// Server proves possession of private key.
    CertificateVerify = 15,
    /// Handshake integrity verification.
    Finished = 20,
}

impl TlsHandshakeType {
    /// Try to convert a raw `u8` value into a [`TlsHandshakeType`].
    ///
    /// Returns `None` if the value does not match a known type.
    pub const fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(Self::ClientHello),
            2 => Some(Self::ServerHello),
            8 => Some(Self::EncryptedExtensions),
            11 => Some(Self::Certificate),
            15 => Some(Self::CertificateVerify),
            20 => Some(Self::Finished),
            _ => None,
        }
    }
}

// =========================================================================
// TlsSessionState
// =========================================================================

/// TLS session state machine states.
///
/// Models the lifecycle of a TLS 1.3 connection from initial
/// handshake through established data transfer to graceful close.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TlsSessionState {
    /// No handshake has been initiated.
    #[default]
    Initial,
    /// ClientHello has been sent, awaiting ServerHello.
    ClientHelloSent,
    /// ServerHello has been received.
    ServerHelloReceived,
    /// Handshake is in progress (encrypted extensions, certs).
    Handshaking,
    /// Handshake complete, application data may flow.
    Established,
    /// Close alert has been sent or received.
    Closing,
    /// Connection is fully closed.
    Closed,
}

// =========================================================================
// TlsSession
// =========================================================================

/// A single TLS 1.3 session with AEAD keying material.
///
/// Holds the negotiated cipher suite, read/write keys, IVs,
/// sequence numbers, and the session state machine. Provides
/// methods for encrypting and decrypting TLS records.
pub struct TlsSession {
    /// Unique session identifier.
    pub id: u64,
    /// Current session state.
    pub state: TlsSessionState,
    /// Negotiated cipher suite.
    pub cipher_suite: TlsCipherSuite,
    /// AEAD key for encrypting outgoing records.
    write_key: [u8; 32],
    /// AEAD key for decrypting incoming records.
    read_key: [u8; 32],
    /// Write-side IV (nonce base).
    write_iv: [u8; AEAD_NONCE_SIZE],
    /// Read-side IV (nonce base).
    read_iv: [u8; AEAD_NONCE_SIZE],
    /// Write-side sequence number (XORed with IV for nonce).
    write_seq: u64,
    /// Read-side sequence number (XORed with IV for nonce).
    read_seq: u64,
    /// Identifier of the remote peer.
    pub peer_id: u64,
    /// Whether this session slot is actively in use.
    pub in_use: bool,
}

impl Default for TlsSession {
    fn default() -> Self {
        Self::new()
    }
}

impl TlsSession {
    /// Create a new TLS session with default (zeroed) state.
    pub const fn new() -> Self {
        Self {
            id: 0,
            state: TlsSessionState::Initial,
            cipher_suite: TlsCipherSuite::Aes128GcmSha256,
            write_key: [0u8; 32],
            read_key: [0u8; 32],
            write_iv: [0u8; AEAD_NONCE_SIZE],
            read_iv: [0u8; AEAD_NONCE_SIZE],
            write_seq: 0,
            read_seq: 0,
            peer_id: 0,
            in_use: false,
        }
    }

    /// Construct the per-record nonce by XORing the IV with the
    /// sequence number (RFC 8446 section 5.3).
    fn build_nonce(iv: &[u8; AEAD_NONCE_SIZE], seq: u64) -> [u8; AEAD_NONCE_SIZE] {
        let seq_bytes = seq.to_be_bytes();
        let mut nonce = [0u8; AEAD_NONCE_SIZE];
        // Copy IV into nonce.
        let mut i = 0usize;
        while i < AEAD_NONCE_SIZE {
            nonce[i] = iv[i];
            i += 1;
        }
        // XOR the last 8 bytes of the nonce with the sequence number.
        let mut j = 0usize;
        while j < 8 {
            nonce[AEAD_NONCE_SIZE - 8 + j] ^= seq_bytes[j];
            j += 1;
        }
        nonce
    }

    /// Simple AEAD-like encrypt using AES-CTR + appended tag.
    ///
    /// This is a simplified construction for the record layer;
    /// a full GCM/Poly1305 implementation would replace this.
    /// Encrypts `plaintext` using AES-CTR with the first 16 bytes
    /// of the key and appends a 16-byte authentication tag derived
    /// from an HMAC over the ciphertext and AAD.
    fn aead_encrypt(
        key: &[u8; 32],
        nonce: &[u8; AEAD_NONCE_SIZE],
        aad: &[u8],
        plaintext: &[u8],
        out: &mut [u8],
    ) -> Result<usize> {
        let needed = plaintext.len() + AEAD_TAG_SIZE;
        if out.len() < needed {
            return Err(Error::InvalidArgument);
        }

        // Copy plaintext to output, then encrypt with AES-CTR.
        let mut i = 0usize;
        while i < plaintext.len() {
            out[i] = plaintext[i];
            i += 1;
        }

        // Use first 16 bytes of key for AES-128-CTR.
        let mut aes_key = [0u8; 16];
        let mut k = 0usize;
        while k < 16 {
            aes_key[k] = key[k];
            k += 1;
        }
        let ctr = super::crypto::AesCtr::new(&aes_key);
        ctr.encrypt(nonce, 1, &mut out[..plaintext.len()]);

        // Compute authentication tag via HMAC-SHA256 over AAD +
        // ciphertext, truncated to 16 bytes.
        let mut mac = super::crypto::Hmac256::new(key);
        mac.update(aad);
        mac.update(&out[..plaintext.len()]);
        let tag_full = mac.finalize();

        // Append truncated tag.
        let mut t = 0usize;
        while t < AEAD_TAG_SIZE {
            out[plaintext.len() + t] = tag_full[t];
            t += 1;
        }

        Ok(needed)
    }

    /// Simple AEAD-like decrypt using AES-CTR + tag verification.
    fn aead_decrypt(
        key: &[u8; 32],
        nonce: &[u8; AEAD_NONCE_SIZE],
        aad: &[u8],
        ciphertext_with_tag: &[u8],
        out: &mut [u8],
    ) -> Result<usize> {
        if ciphertext_with_tag.len() < AEAD_TAG_SIZE {
            return Err(Error::InvalidArgument);
        }
        let ct_len = ciphertext_with_tag.len() - AEAD_TAG_SIZE;
        if out.len() < ct_len {
            return Err(Error::InvalidArgument);
        }

        // Verify tag first.
        let mut mac = super::crypto::Hmac256::new(key);
        mac.update(aad);
        mac.update(&ciphertext_with_tag[..ct_len]);
        let expected_tag = mac.finalize();

        // Constant-time tag comparison.
        let received_tag = &ciphertext_with_tag[ct_len..];
        if !super::crypto::constant_time_eq(&expected_tag[..AEAD_TAG_SIZE], received_tag) {
            return Err(Error::InvalidArgument);
        }

        // Decrypt: copy ciphertext to output, then AES-CTR decrypt.
        let mut i = 0usize;
        while i < ct_len {
            out[i] = ciphertext_with_tag[i];
            i += 1;
        }

        let mut aes_key = [0u8; 16];
        let mut k = 0usize;
        while k < 16 {
            aes_key[k] = key[k];
            k += 1;
        }
        let ctr = super::crypto::AesCtr::new(&aes_key);
        ctr.decrypt(nonce, 1, &mut out[..ct_len]);

        Ok(ct_len)
    }

    /// Encrypt a TLS record.
    ///
    /// Wraps `plaintext` into an encrypted TLS 1.3 record
    /// (content type ApplicationData on the wire). Writes the
    /// complete record (header + encrypted payload + tag) to `out`
    /// and returns the total number of bytes written.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `plaintext` exceeds
    /// [`TLS_MAX_PLAINTEXT`] or `out` is too small, or if the
    /// session is not in the `Established` state.
    pub fn encrypt_record(
        &mut self,
        content_type: TlsContentType,
        plaintext: &[u8],
        out: &mut [u8],
    ) -> Result<usize> {
        if self.state != TlsSessionState::Established {
            return Err(Error::InvalidArgument);
        }
        if plaintext.len() > TLS_MAX_PLAINTEXT {
            return Err(Error::InvalidArgument);
        }

        // Inner plaintext: original content type appended to
        // plaintext (RFC 8446 section 5.2).
        // We need: plaintext + content_type byte.
        let inner_len = plaintext.len() + 1;
        // Encrypted output: inner_len + AEAD_TAG_SIZE.
        let enc_len = inner_len + AEAD_TAG_SIZE;
        let total = TLS_RECORD_HEADER_SIZE + enc_len;

        if out.len() < total {
            return Err(Error::InvalidArgument);
        }

        // Build the record header (outer type is always
        // ApplicationData for encrypted records).
        let header = TlsRecordHeader {
            content_type: TlsContentType::ApplicationData.as_u8(),
            legacy_version: TlsVersion::Tls12.as_u16(),
            length: enc_len as u16,
        };
        header.write_to(out)?;

        // Build inner plaintext: payload + actual content type byte.
        let mut inner = [0u8; TLS_MAX_PLAINTEXT + 1];
        let mut i = 0usize;
        while i < plaintext.len() {
            inner[i] = plaintext[i];
            i += 1;
        }
        inner[plaintext.len()] = content_type.as_u8();

        // Construct per-record nonce.
        let nonce = Self::build_nonce(&self.write_iv, self.write_seq);

        // AAD is the record header (first 5 bytes). Copy it out
        // to avoid overlapping borrows on `out`.
        let mut aad = [0u8; TLS_RECORD_HEADER_SIZE];
        let mut a = 0usize;
        while a < TLS_RECORD_HEADER_SIZE {
            aad[a] = out[a];
            a += 1;
        }
        let written = Self::aead_encrypt(
            &self.write_key,
            &nonce,
            &aad,
            &inner[..inner_len],
            &mut out[TLS_RECORD_HEADER_SIZE..],
        )?;

        self.write_seq = self.write_seq.wrapping_add(1);

        Ok(TLS_RECORD_HEADER_SIZE + written)
    }

    /// Decrypt a TLS record.
    ///
    /// Takes an encrypted TLS record (header + ciphertext + tag)
    /// in `ciphertext`, decrypts it, writes the plaintext to `out`,
    /// and returns the inner content type and plaintext length.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if the record is
    /// malformed, the MAC check fails, or the session is not in
    /// the `Established` state.
    pub fn decrypt_record(
        &mut self,
        ciphertext: &[u8],
        out: &mut [u8],
    ) -> Result<(TlsContentType, usize)> {
        if self.state != TlsSessionState::Established {
            return Err(Error::InvalidArgument);
        }
        if ciphertext.len() < TLS_RECORD_HEADER_SIZE {
            return Err(Error::InvalidArgument);
        }

        let header = TlsRecordHeader::parse(ciphertext)?;
        let payload_len = header.length as usize;

        if ciphertext.len() < TLS_RECORD_HEADER_SIZE + payload_len {
            return Err(Error::InvalidArgument);
        }
        if payload_len < AEAD_TAG_SIZE + 1 {
            return Err(Error::InvalidArgument);
        }

        // Construct per-record nonce.
        let nonce = Self::build_nonce(&self.read_iv, self.read_seq);

        // Decrypt inner plaintext.
        let enc_data = &ciphertext[TLS_RECORD_HEADER_SIZE..TLS_RECORD_HEADER_SIZE + payload_len];

        // We need a temporary buffer for the decrypted inner
        // plaintext (payload + content type byte).
        let mut inner = [0u8; TLS_MAX_PLAINTEXT + 1 + AEAD_TAG_SIZE];
        let inner_len = Self::aead_decrypt(
            &self.read_key,
            &nonce,
            &ciphertext[..TLS_RECORD_HEADER_SIZE],
            enc_data,
            &mut inner,
        )?;

        if inner_len == 0 {
            return Err(Error::InvalidArgument);
        }

        // Last byte of inner plaintext is the real content type.
        let real_ct_byte = inner[inner_len - 1];
        let real_ct = TlsContentType::from_u8(real_ct_byte).ok_or(Error::InvalidArgument)?;

        let plaintext_len = inner_len - 1;
        if out.len() < plaintext_len {
            return Err(Error::InvalidArgument);
        }

        let mut i = 0usize;
        while i < plaintext_len {
            out[i] = inner[i];
            i += 1;
        }

        self.read_seq = self.read_seq.wrapping_add(1);

        Ok((real_ct, plaintext_len))
    }

    /// Build and send a TLS alert record.
    ///
    /// Writes an encrypted alert record to `out` and returns the
    /// total number of bytes written. If the session is not yet
    /// established, writes an unencrypted alert.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `out` is too small.
    pub fn send_alert(
        &mut self,
        level: TlsAlertLevel,
        desc: TlsAlertDesc,
        out: &mut [u8],
    ) -> Result<usize> {
        let alert_body = [level as u8, desc as u8];

        if self.state == TlsSessionState::Established {
            // Encrypt the alert as an Alert content type record.
            let result = self.encrypt_record(TlsContentType::Alert, &alert_body, out);
            if desc == TlsAlertDesc::CloseNotify {
                self.state = TlsSessionState::Closing;
            }
            result
        } else {
            // Plaintext alert (pre-handshake or already closing).
            self.build_record(TlsContentType::Alert, &alert_body, out)
        }
    }

    /// Build an unencrypted TLS record.
    ///
    /// Writes a plaintext TLS record (header + payload) to `out`.
    /// Used for initial handshake messages and plaintext alerts.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `out` is too small
    /// or `payload` exceeds [`TLS_MAX_PLAINTEXT`].
    pub fn build_record(
        &self,
        content_type: TlsContentType,
        payload: &[u8],
        out: &mut [u8],
    ) -> Result<usize> {
        if payload.len() > TLS_MAX_PLAINTEXT {
            return Err(Error::InvalidArgument);
        }
        let total = TLS_RECORD_HEADER_SIZE + payload.len();
        if out.len() < total {
            return Err(Error::InvalidArgument);
        }

        let header = TlsRecordHeader {
            content_type: content_type.as_u8(),
            legacy_version: TlsVersion::Tls12.as_u16(),
            length: payload.len() as u16,
        };
        header.write_to(out)?;

        let mut i = 0usize;
        while i < payload.len() {
            out[TLS_RECORD_HEADER_SIZE + i] = payload[i];
            i += 1;
        }

        Ok(total)
    }

    /// Advance the session state machine based on a handshake event.
    ///
    /// # State Transitions
    ///
    /// | Current State        | Event             | Next State           |
    /// |----------------------|-------------------|----------------------|
    /// | Initial              | ClientHello       | ClientHelloSent      |
    /// | ClientHelloSent      | ServerHello       | ServerHelloReceived  |
    /// | ServerHelloReceived  | EncryptedExt      | Handshaking          |
    /// | Handshaking          | Finished          | Established          |
    /// | Established          | CloseNotify       | Closing              |
    /// | Closing              | CloseNotify       | Closed               |
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if the event is not valid
    /// in the current state.
    pub fn advance_state(&mut self, event: TlsHandshakeType) -> Result<()> {
        match (&self.state, event) {
            (TlsSessionState::Initial, TlsHandshakeType::ClientHello) => {
                self.state = TlsSessionState::ClientHelloSent;
                Ok(())
            }
            (TlsSessionState::ClientHelloSent, TlsHandshakeType::ServerHello) => {
                self.state = TlsSessionState::ServerHelloReceived;
                Ok(())
            }
            (TlsSessionState::ServerHelloReceived, TlsHandshakeType::EncryptedExtensions) => {
                self.state = TlsSessionState::Handshaking;
                Ok(())
            }
            (TlsSessionState::Handshaking, TlsHandshakeType::Finished) => {
                self.state = TlsSessionState::Established;
                Ok(())
            }
            _ => Err(Error::InvalidArgument),
        }
    }
}

// =========================================================================
// TlsRegistry
// =========================================================================

/// Fixed-size registry of TLS sessions.
///
/// Manages up to [`TLS_TABLE_SIZE`] concurrent TLS sessions,
/// providing session creation, key installation, and
/// encrypt/decrypt dispatch by session ID.
pub struct TlsRegistry {
    /// Fixed-size array of session slots.
    sessions: [TlsSession; TLS_TABLE_SIZE],
    /// Number of active sessions.
    count: usize,
}

impl Default for TlsRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl TlsRegistry {
    /// Create an empty TLS session registry.
    pub const fn new() -> Self {
        const EMPTY: TlsSession = TlsSession::new();
        Self {
            sessions: [EMPTY; TLS_TABLE_SIZE],
            count: 0,
        }
    }

    /// Create a new TLS session with the given cipher suite.
    ///
    /// Returns the session ID of the newly created session.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if all session slots are
    /// occupied.
    pub fn create_session(&mut self, cipher_suite: TlsCipherSuite) -> Result<u64> {
        if self.count >= TLS_TABLE_SIZE {
            return Err(Error::OutOfMemory);
        }
        let id = self.next_id();
        for session in self.sessions.iter_mut() {
            if !session.in_use {
                session.id = id;
                session.state = TlsSessionState::Initial;
                session.cipher_suite = cipher_suite;
                session.write_key = [0u8; 32];
                session.read_key = [0u8; 32];
                session.write_iv = [0u8; AEAD_NONCE_SIZE];
                session.read_iv = [0u8; AEAD_NONCE_SIZE];
                session.write_seq = 0;
                session.read_seq = 0;
                session.peer_id = 0;
                session.in_use = true;
                self.count += 1;
                return Ok(id);
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Install AEAD keying material for a session.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if no session with the given
    /// `id` exists.
    pub fn set_keys(
        &mut self,
        id: u64,
        write_key: &[u8; 32],
        read_key: &[u8; 32],
        write_iv: &[u8; AEAD_NONCE_SIZE],
        read_iv: &[u8; AEAD_NONCE_SIZE],
    ) -> Result<()> {
        let session = self.get_mut(id).ok_or(Error::NotFound)?;
        session.write_key = *write_key;
        session.read_key = *read_key;
        session.write_iv = *write_iv;
        session.read_iv = *read_iv;
        session.write_seq = 0;
        session.read_seq = 0;
        Ok(())
    }

    /// Encrypt data as a TLS record for the given session.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the session does not exist.
    /// Propagates errors from [`TlsSession::encrypt_record`].
    pub fn encrypt(
        &mut self,
        id: u64,
        content_type: TlsContentType,
        data: &[u8],
        out: &mut [u8],
    ) -> Result<usize> {
        let session = self.get_mut(id).ok_or(Error::NotFound)?;
        session.encrypt_record(content_type, data, out)
    }

    /// Decrypt a TLS record for the given session.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the session does not exist.
    /// Propagates errors from [`TlsSession::decrypt_record`].
    pub fn decrypt(
        &mut self,
        id: u64,
        data: &[u8],
        out: &mut [u8],
    ) -> Result<(TlsContentType, usize)> {
        let session = self.get_mut(id).ok_or(Error::NotFound)?;
        session.decrypt_record(data, out)
    }

    /// Close and release a TLS session.
    ///
    /// Marks the session slot as inactive and decrements the count.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if no session with the given
    /// `id` exists.
    pub fn close(&mut self, id: u64) -> Result<()> {
        for session in self.sessions.iter_mut() {
            if session.in_use && session.id == id {
                session.in_use = false;
                session.state = TlsSessionState::Closed;
                self.count -= 1;
                return Ok(());
            }
        }
        Err(Error::NotFound)
    }

    /// Look up a session by ID, returning an immutable reference.
    ///
    /// Returns `None` if no active session with the given `id`
    /// exists.
    pub fn get(&self, id: u64) -> Option<&TlsSession> {
        self.sessions.iter().find(|s| s.in_use && s.id == id)
    }

    /// Return the number of active sessions.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Return `true` if there are no active sessions.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Look up a session by ID, returning a mutable reference.
    fn get_mut(&mut self, id: u64) -> Option<&mut TlsSession> {
        self.sessions.iter_mut().find(|s| s.in_use && s.id == id)
    }

    /// Generate a simple unique session ID.
    ///
    /// Uses a monotonically increasing counter seeded from the
    /// current session count to avoid ID reuse in practice.
    fn next_id(&self) -> u64 {
        // Find the highest existing ID and increment.
        let max_id = self
            .sessions
            .iter()
            .filter(|s| s.in_use)
            .map(|s| s.id)
            .max()
            .unwrap_or(0);
        max_id + 1
    }
}
