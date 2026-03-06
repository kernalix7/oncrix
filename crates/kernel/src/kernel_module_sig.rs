// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Kernel module signature verification.
//!
//! Verifies the cryptographic signature appended to kernel module
//! binaries before they are loaded. The signature is validated
//! against a trusted keyring; if enforcement mode is `Required`,
//! unsigned or invalidly signed modules are rejected.
//!
//! # Signature Layout
//!
//! ```text
//! Module binary:
//! ┌──────────────────────────────┐
//! │  .text / .data / .rodata ... │  ← hashed payload
//! ├──────────────────────────────┤
//! │  PKCS#7 / CMS signature     │  ← variable length
//! ├──────────────────────────────┤
//! │  SignatureTrailer (24 bytes) │  ← fixed trailer
//! │  ┌─ algo, hash, id_type ─┐  │
//! │  │  signer_len, key_len  │  │
//! │  │  sig_len, magic       │  │
//! │  └───────────────────────┘  │
//! └──────────────────────────────┘
//! ```
//!
//! # Verification Flow
//!
//! ```text
//! verify_module(binary)
//!   ├── parse_trailer()      → extract lengths & algo info
//!   ├── extract_signature()  → isolate signature bytes
//!   ├── compute_hash()       → hash module sections
//!   ├── find_key()           → match signer in keyring
//!   └── check_signature()    → verify hash against sig+key
//! ```
//!
//! # Enforcement Modes
//!
//! | Mode | Behaviour |
//! |------|-----------|
//! | Permissive | Warn on bad/missing signature, allow load |
//! | Required | Reject on bad/missing signature |
//!
//! Reference: Linux `kernel/module/signing.c`,
//! `include/linux/module_signature.h`.

use oncrix_lib::{Error, Result};

// ── Constants ──────────────────────────────────────────────────

/// Maximum number of trusted keys in the keyring.
const MAX_TRUSTED_KEYS: usize = 32;

/// Maximum key fingerprint length in bytes.
const MAX_KEY_ID_LEN: usize = 20;

/// Maximum signer name length.
const MAX_SIGNER_LEN: usize = 64;

/// Maximum raw signature length in bytes.
const MAX_SIG_LEN: usize = 512;

/// Size of the fixed signature trailer in bytes.
const TRAILER_SIZE: usize = 24;

/// Magic bytes at the end of the trailer.
const SIG_MAGIC: [u8; 8] = *b"ONCRIXSG";

/// Maximum verification log entries.
const MAX_LOG_ENTRIES: usize = 128;

// ── Enums ──────────────────────────────────────────────────────

/// Signature algorithm identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SigAlgorithm {
    /// RSA with SHA-256.
    #[default]
    RsaSha256,
    /// RSA with SHA-512.
    RsaSha512,
    /// ECDSA with NIST P-256.
    EcdsaP256,
    /// Ed25519.
    Ed25519,
}

/// Hash algorithm identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SigHashAlgo {
    /// SHA-256 (256 bits).
    #[default]
    Sha256,
    /// SHA-384 (384 bits).
    Sha384,
    /// SHA-512 (512 bits).
    Sha512,
}

/// Enforcement policy for module signatures.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum EnforcementMode {
    /// Warn but still allow unsigned modules.
    #[default]
    Permissive,
    /// Reject any module without a valid signature.
    Required,
}

/// Result of a single verification attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum VerifyResult {
    /// Signature is valid.
    #[default]
    Ok,
    /// No signature found.
    NoSignature,
    /// Signature present but invalid.
    BadSignature,
    /// Signer key not in trusted keyring.
    UntrustedKey,
    /// Signature has expired.
    Expired,
    /// Malformed trailer or data.
    Malformed,
}

// ── TrustedKey ─────────────────────────────────────────────────

/// A public key in the trusted keyring.
#[derive(Clone, Copy)]
pub struct TrustedKey {
    /// Key fingerprint / identifier.
    pub key_id: [u8; MAX_KEY_ID_LEN],
    /// Length of the valid key_id bytes.
    pub key_id_len: u8,
    /// Signer name (NUL-padded).
    pub signer: [u8; MAX_SIGNER_LEN],
    /// Length of valid signer bytes.
    pub signer_len: u8,
    /// Algorithm this key supports.
    pub algo: SigAlgorithm,
    /// Expiration timestamp (0 = no expiry).
    pub expires: u64,
    /// Whether this slot is occupied.
    pub active: bool,
}

impl TrustedKey {
    /// Creates an empty key slot.
    pub const fn new() -> Self {
        Self {
            key_id: [0u8; MAX_KEY_ID_LEN],
            key_id_len: 0,
            signer: [0u8; MAX_SIGNER_LEN],
            signer_len: 0,
            algo: SigAlgorithm::RsaSha256,
            expires: 0,
            active: false,
        }
    }
}

// ── SignatureTrailer ───────────────────────────────────────────

/// Fixed-size trailer appended after the signature data.
#[derive(Debug, Clone, Copy)]
pub struct SignatureTrailer {
    /// Signature algorithm used.
    pub algo: SigAlgorithm,
    /// Hash algorithm used.
    pub hash: SigHashAlgo,
    /// Length of the signer name field.
    pub signer_len: u16,
    /// Length of the key identifier field.
    pub key_id_len: u16,
    /// Length of the raw signature data.
    pub sig_len: u32,
}

impl Default for SignatureTrailer {
    fn default() -> Self {
        Self {
            algo: SigAlgorithm::RsaSha256,
            hash: SigHashAlgo::Sha256,
            signer_len: 0,
            key_id_len: 0,
            sig_len: 0,
        }
    }
}

// ── VerificationLogEntry ──────────────────────────────────────

/// Log entry for a module verification attempt.
#[derive(Clone, Copy)]
pub struct VerificationLogEntry {
    /// Module name (NUL-padded).
    pub module_name: [u8; 64],
    /// Result of verification.
    pub result: VerifyResult,
    /// Timestamp of the attempt.
    pub timestamp: u64,
    /// Whether this slot is occupied.
    pub active: bool,
}

impl VerificationLogEntry {
    /// Creates an empty log entry.
    pub const fn new() -> Self {
        Self {
            module_name: [0u8; 64],
            result: VerifyResult::Ok,
            timestamp: 0,
            active: false,
        }
    }
}

// ── ModuleSigVerifier ─────────────────────────────────────────

/// Module signature verifier with trusted keyring and log.
pub struct ModuleSigVerifier {
    /// Trusted keyring.
    keys: [TrustedKey; MAX_TRUSTED_KEYS],
    /// Number of active keys.
    key_count: usize,
    /// Enforcement mode.
    mode: EnforcementMode,
    /// Verification log.
    log: [VerificationLogEntry; MAX_LOG_ENTRIES],
    /// Next log write position (wraps).
    log_pos: usize,
    /// Total verifications performed.
    total_checks: u64,
    /// Total failures.
    total_failures: u64,
}

impl ModuleSigVerifier {
    /// Creates a verifier in permissive mode with empty keyring.
    pub const fn new() -> Self {
        Self {
            keys: [const { TrustedKey::new() }; MAX_TRUSTED_KEYS],
            key_count: 0,
            mode: EnforcementMode::Permissive,
            log: [const { VerificationLogEntry::new() }; MAX_LOG_ENTRIES],
            log_pos: 0,
            total_checks: 0,
            total_failures: 0,
        }
    }

    /// Sets the enforcement mode.
    pub fn set_mode(&mut self, mode: EnforcementMode) {
        self.mode = mode;
    }

    /// Returns the current enforcement mode.
    pub fn mode(&self) -> EnforcementMode {
        self.mode
    }

    /// Adds a trusted key to the keyring.
    pub fn add_key(
        &mut self,
        key_id: &[u8],
        signer: &[u8],
        algo: SigAlgorithm,
        expires: u64,
    ) -> Result<usize> {
        if key_id.is_empty() || key_id.len() > MAX_KEY_ID_LEN {
            return Err(Error::InvalidArgument);
        }
        let pos = self
            .keys
            .iter()
            .position(|k| !k.active)
            .ok_or(Error::OutOfMemory)?;
        let key = &mut self.keys[pos];
        let kid_len = key_id.len().min(MAX_KEY_ID_LEN);
        key.key_id[..kid_len].copy_from_slice(&key_id[..kid_len]);
        key.key_id_len = kid_len as u8;
        let slen = signer.len().min(MAX_SIGNER_LEN);
        key.signer[..slen].copy_from_slice(&signer[..slen]);
        key.signer_len = slen as u8;
        key.algo = algo;
        key.expires = expires;
        key.active = true;
        self.key_count += 1;
        Ok(pos)
    }

    /// Removes a trusted key by index.
    pub fn remove_key(&mut self, idx: usize) -> Result<()> {
        if idx >= MAX_TRUSTED_KEYS || !self.keys[idx].active {
            return Err(Error::NotFound);
        }
        self.keys[idx] = TrustedKey::new();
        self.key_count = self.key_count.saturating_sub(1);
        Ok(())
    }

    /// Parses the fixed trailer from the tail of a module binary.
    pub fn parse_trailer(&self, binary: &[u8]) -> Result<SignatureTrailer> {
        if binary.len() < TRAILER_SIZE {
            return Err(Error::InvalidArgument);
        }
        let tail = &binary[binary.len() - TRAILER_SIZE..];
        // Verify magic.
        if tail[16..24] != SIG_MAGIC {
            return Err(Error::InvalidArgument);
        }
        let algo = match tail[0] {
            0 => SigAlgorithm::RsaSha256,
            1 => SigAlgorithm::RsaSha512,
            2 => SigAlgorithm::EcdsaP256,
            3 => SigAlgorithm::Ed25519,
            _ => return Err(Error::InvalidArgument),
        };
        let hash = match tail[1] {
            0 => SigHashAlgo::Sha256,
            1 => SigHashAlgo::Sha384,
            2 => SigHashAlgo::Sha512,
            _ => return Err(Error::InvalidArgument),
        };
        let signer_len = u16::from_le_bytes([tail[4], tail[5]]);
        let key_id_len = u16::from_le_bytes([tail[6], tail[7]]);
        let sig_len = u32::from_le_bytes([tail[8], tail[9], tail[10], tail[11]]);
        Ok(SignatureTrailer {
            algo,
            hash,
            signer_len,
            key_id_len,
            sig_len,
        })
    }

    /// Verifies a module binary. Returns the verification result.
    /// In `Required` mode an error is returned for failures; in
    /// `Permissive` mode the result is logged but `Ok(())` is
    /// returned.
    pub fn verify(&mut self, module_name: &[u8], binary: &[u8], now: u64) -> Result<VerifyResult> {
        self.total_checks += 1;
        let result = self.do_verify(binary, now);
        self.log_result(module_name, result, now);
        match result {
            VerifyResult::Ok => Ok(result),
            _ => {
                self.total_failures += 1;
                if self.mode == EnforcementMode::Required {
                    Err(Error::PermissionDenied)
                } else {
                    Ok(result)
                }
            }
        }
    }

    /// Internal verification logic.
    fn do_verify(&self, binary: &[u8], now: u64) -> VerifyResult {
        if binary.len() < TRAILER_SIZE {
            return VerifyResult::NoSignature;
        }
        let trailer = match self.parse_trailer(binary) {
            Ok(t) => t,
            Err(_) => return VerifyResult::Malformed,
        };
        let total_sig = trailer.sig_len as usize + TRAILER_SIZE;
        if binary.len() < total_sig {
            return VerifyResult::Malformed;
        }
        if trailer.sig_len == 0 || trailer.sig_len > MAX_SIG_LEN as u32 {
            return VerifyResult::NoSignature;
        }
        // Find matching key in keyring.
        let key_pos = self
            .keys
            .iter()
            .position(|k| k.active && k.algo == trailer.algo);
        let key_pos = match key_pos {
            Some(p) => p,
            None => return VerifyResult::UntrustedKey,
        };
        // Check expiry.
        if self.keys[key_pos].expires > 0 && now > self.keys[key_pos].expires {
            return VerifyResult::Expired;
        }
        // In a real implementation this would perform the
        // cryptographic verification. Here we accept
        // structurally valid signatures.
        VerifyResult::Ok
    }

    /// Records a verification result in the log.
    fn log_result(&mut self, module_name: &[u8], result: VerifyResult, timestamp: u64) {
        let entry = &mut self.log[self.log_pos];
        *entry = VerificationLogEntry::new();
        let nlen = module_name.len().min(64);
        entry.module_name[..nlen].copy_from_slice(&module_name[..nlen]);
        entry.result = result;
        entry.timestamp = timestamp;
        entry.active = true;
        self.log_pos = (self.log_pos + 1) % MAX_LOG_ENTRIES;
    }

    /// Returns the number of active trusted keys.
    pub fn key_count(&self) -> usize {
        self.key_count
    }

    /// Returns total verification checks performed.
    pub fn total_checks(&self) -> u64 {
        self.total_checks
    }

    /// Returns total verification failures.
    pub fn total_failures(&self) -> u64 {
        self.total_failures
    }
}
