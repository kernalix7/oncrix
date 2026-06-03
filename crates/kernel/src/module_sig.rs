// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Module signature verification.
//!
//! Verifies cryptographic signatures on kernel modules before they
//! are loaded. Supports multiple signature formats and key sources.
//! When signature enforcement is enabled, unsigned or incorrectly
//! signed modules are rejected.
//!
//! # Security Status
//!
//! [`ModuleSigVerifier::verify`] takes the full module payload,
//! computes its real SHA-256 digest (FIPS 180-4, [`crate::crypto::Sha256`])
//! so the verified input is cryptographically bound, and selects the
//! signing key by a constant-time `key_id` match. The asymmetric
//! signature primitive (RSA-PKCS#1 / ECDSA-P256 / Ed25519) is **not
//! yet implemented** in-tree, so the public-key check over the digest
//! cannot be performed. Until it exists, verification **fails closed**:
//! a structurally valid, key-matched module yields
//! [`VerificationResult::Unverified`], which is rejected when
//! enforcement is enabled. The verifier **never** returns
//! [`VerificationResult::Valid`] on structural validity alone.
//! Implementing the asymmetric verifier is the remaining work.

use crate::crypto::{Sha256, constant_time_eq};
use oncrix_lib::{Error, Result};

// ── Constants ────────────────────────────────────────────────────────

/// Maximum number of trusted keys.
const MAX_TRUSTED_KEYS: usize = 32;

/// Maximum signature data length.
const MAX_SIGNATURE_LEN: usize = 512;

/// Maximum number of verification records.
const MAX_VERIFICATION_LOG: usize = 128;

/// Signature magic suffix appended to modules.
const MODULE_SIG_MAGIC: [u8; 8] = *b"ONCRIXSG";

/// Placeholder digest used in log entries when the declared hash
/// algorithm is unsupported and no real payload digest can be
/// computed. All-zero is never a valid SHA-256 of a signed payload.
const fn digest_unavailable() -> [u8; 32] {
    [0u8; 32]
}

// ── Types ────────────────────────────────────────────────────────────

/// Signature algorithm used.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureAlgorithm {
    /// RSA with SHA-256.
    RsaSha256,
    /// RSA with SHA-512.
    RsaSha512,
    /// ECDSA with P-256 curve.
    EcdsaP256,
    /// Ed25519.
    Ed25519,
}

impl Default for SignatureAlgorithm {
    fn default() -> Self {
        Self::RsaSha256
    }
}

/// Hash algorithm for signature computation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashAlgorithm {
    /// SHA-256.
    Sha256,
    /// SHA-384.
    Sha384,
    /// SHA-512.
    Sha512,
}

impl Default for HashAlgorithm {
    fn default() -> Self {
        Self::Sha256
    }
}

/// Result of a signature verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerificationResult {
    /// Signature is valid.
    Valid,
    /// Signature is invalid (bad signature data).
    Invalid,
    /// Module is unsigned.
    Unsigned,
    /// Key not found in trusted keyring.
    UnknownKey,
    /// Signature format is unsupported.
    UnsupportedFormat,
    /// Structurally valid and digest bound, but the asymmetric
    /// signature could not be verified because no in-tree public-key
    /// verifier exists yet. Treated as a failure (fail closed).
    Unverified,
}

/// Represents a trusted signing key.
#[derive(Debug, Clone)]
pub struct TrustedKey {
    /// Key identifier (fingerprint).
    key_id: [u8; 32],
    /// Algorithm this key uses.
    algorithm: SignatureAlgorithm,
    /// Whether this key is currently valid.
    valid: bool,
    /// Expiration timestamp (0 = no expiration).
    expires_at: u64,
    /// Number of successful verifications with this key.
    verification_count: u64,
}

impl TrustedKey {
    /// Creates a new trusted key.
    pub const fn new(key_id: [u8; 32], algorithm: SignatureAlgorithm) -> Self {
        Self {
            key_id,
            algorithm,
            valid: true,
            expires_at: 0,
            verification_count: 0,
        }
    }

    /// Returns whether the key is valid.
    pub const fn is_valid(&self) -> bool {
        self.valid
    }

    /// Returns the signature algorithm.
    pub const fn algorithm(&self) -> SignatureAlgorithm {
        self.algorithm
    }
}

/// Parsed module signature header.
#[derive(Debug, Clone)]
pub struct ModuleSignature {
    /// Signature algorithm.
    algorithm: SignatureAlgorithm,
    /// Hash algorithm used.
    hash: HashAlgorithm,
    /// Key identifier.
    key_id: [u8; 32],
    /// Signature data.
    sig_data: [u8; MAX_SIGNATURE_LEN],
    /// Length of valid signature data.
    sig_len: usize,
    /// Offset within the module file.
    offset: u64,
}

impl ModuleSignature {
    /// Creates a new module signature.
    pub const fn new(algorithm: SignatureAlgorithm, hash: HashAlgorithm) -> Self {
        Self {
            algorithm,
            hash,
            key_id: [0u8; 32],
            sig_data: [0u8; MAX_SIGNATURE_LEN],
            sig_len: 0,
            offset: 0,
        }
    }

    /// Returns the signature algorithm.
    pub const fn algorithm(&self) -> SignatureAlgorithm {
        self.algorithm
    }

    /// Returns the hash algorithm.
    pub const fn hash(&self) -> HashAlgorithm {
        self.hash
    }
}

/// Verification log entry.
#[derive(Debug, Clone)]
pub struct VerificationLogEntry {
    /// SHA-256 digest of the verified module payload.
    module_digest: [u8; 32],
    /// Verification result.
    result: VerificationResult,
    /// Algorithm used.
    algorithm: SignatureAlgorithm,
    /// Timestamp in nanoseconds.
    timestamp_ns: u64,
}

impl VerificationLogEntry {
    /// Creates a new log entry bound to the module payload digest.
    pub const fn new(
        module_digest: [u8; 32],
        result: VerificationResult,
        algorithm: SignatureAlgorithm,
    ) -> Self {
        Self {
            module_digest,
            result,
            algorithm,
            timestamp_ns: 0,
        }
    }
}

/// Module signature verification statistics.
#[derive(Debug, Clone)]
pub struct ModuleSigStats {
    /// Total verification attempts.
    pub total_verifications: u64,
    /// Successful verifications.
    pub valid_count: u64,
    /// Invalid signature count.
    pub invalid_count: u64,
    /// Unsigned module count.
    pub unsigned_count: u64,
    /// Unknown key count.
    pub unknown_key_count: u64,
}

impl Default for ModuleSigStats {
    fn default() -> Self {
        Self::new()
    }
}

impl ModuleSigStats {
    /// Creates zeroed statistics.
    pub const fn new() -> Self {
        Self {
            total_verifications: 0,
            valid_count: 0,
            invalid_count: 0,
            unsigned_count: 0,
            unknown_key_count: 0,
        }
    }
}

/// Central module signature verifier.
#[derive(Debug)]
pub struct ModuleSigVerifier {
    /// Trusted signing keys.
    keys: [Option<TrustedKey>; MAX_TRUSTED_KEYS],
    /// Number of trusted keys.
    key_count: usize,
    /// Verification log.
    log: [Option<VerificationLogEntry>; MAX_VERIFICATION_LOG],
    /// Log write position.
    log_pos: usize,
    /// Whether enforcement is enabled.
    enforce: bool,
    /// Statistics.
    stats: ModuleSigStats,
}

impl Default for ModuleSigVerifier {
    fn default() -> Self {
        Self::new()
    }
}

impl ModuleSigVerifier {
    /// Creates a new module signature verifier.
    pub const fn new() -> Self {
        Self {
            keys: [const { None }; MAX_TRUSTED_KEYS],
            key_count: 0,
            log: [const { None }; MAX_VERIFICATION_LOG],
            log_pos: 0,
            enforce: false,
            stats: ModuleSigStats::new(),
        }
    }

    /// Adds a trusted signing key.
    pub fn add_trusted_key(
        &mut self,
        key_id: [u8; 32],
        algorithm: SignatureAlgorithm,
    ) -> Result<()> {
        if self.key_count >= MAX_TRUSTED_KEYS {
            return Err(Error::OutOfMemory);
        }
        let key = TrustedKey::new(key_id, algorithm);
        if let Some(slot) = self.keys.iter_mut().find(|s| s.is_none()) {
            *slot = Some(key);
            self.key_count += 1;
            Ok(())
        } else {
            Err(Error::OutOfMemory)
        }
    }

    /// Verifies a module signature against the trusted keyring.
    ///
    /// `payload` is the full module image that the signature is
    /// expected to cover. Its SHA-256 digest is computed (FIPS 180-4)
    /// so the verified input is cryptographically bound, the signing
    /// key is selected by a constant-time `key_id` match, and the
    /// asymmetric signature check is attempted.
    ///
    /// Because no in-tree public-key verifier exists yet, a
    /// structurally valid, key-matched module yields
    /// [`VerificationResult::Unverified`] (fail closed) — never
    /// [`VerificationResult::Valid`]. When enforcement is enabled,
    /// any non-`Valid` result returns [`Error::PermissionDenied`].
    pub fn verify(
        &mut self,
        payload: &[u8],
        signature: &ModuleSignature,
    ) -> Result<VerificationResult> {
        self.stats.total_verifications += 1;
        // Compute the real payload digest. Only SHA-256 is available
        // in-tree; reject any module that declares a hash whose
        // primitive is not implemented rather than downgrading.
        let digest = match signature.hash {
            HashAlgorithm::Sha256 => {
                let mut h = Sha256::new();
                h.update(payload);
                h.finalize()
            }
            HashAlgorithm::Sha384 | HashAlgorithm::Sha512 => {
                self.stats.invalid_count += 1;
                let result = VerificationResult::UnsupportedFormat;
                self.log_verification(digest_unavailable(), result, signature.algorithm);
                if self.enforce {
                    return Err(Error::PermissionDenied);
                }
                return Ok(result);
            }
        };
        if signature.sig_len == 0 {
            self.stats.unsigned_count += 1;
            let result = VerificationResult::Unsigned;
            self.log_verification(digest, result, signature.algorithm);
            if self.enforce {
                return Err(Error::PermissionDenied);
            }
            return Ok(result);
        }
        // Select the signing key by a constant-time key_id match
        // (both identifiers are fixed 32-byte fingerprints), scanning
        // all slots so timing does not depend on the match position.
        let mut found = false;
        for k in self.keys.iter().flatten() {
            if k.valid && constant_time_eq(&k.key_id, &signature.key_id) {
                found = true;
            }
        }
        let result = if !found {
            self.stats.unknown_key_count += 1;
            VerificationResult::UnknownKey
        } else {
            // The asymmetric signature primitive over `digest` is not
            // yet implemented in-tree. The payload is bound and the
            // signer is identified, but we cannot assert the signature
            // is valid, so we must not accept. Fail closed.
            // TODO(security): verify `signature.sig_data[..sig_len]`
            // over `digest` with the matched public key and return
            // `Valid` only on cryptographic success.
            self.stats.invalid_count += 1;
            VerificationResult::Unverified
        };
        self.log_verification(digest, result, signature.algorithm);
        if self.enforce && result != VerificationResult::Valid {
            return Err(Error::PermissionDenied);
        }
        Ok(result)
    }

    /// Logs a verification event bound to the payload digest.
    fn log_verification(
        &mut self,
        module_digest: [u8; 32],
        result: VerificationResult,
        algorithm: SignatureAlgorithm,
    ) {
        let entry = VerificationLogEntry::new(module_digest, result, algorithm);
        self.log[self.log_pos] = Some(entry);
        self.log_pos = (self.log_pos + 1) % MAX_VERIFICATION_LOG;
    }

    /// Enables or disables signature enforcement.
    pub fn set_enforce(&mut self, enforce: bool) {
        self.enforce = enforce;
    }

    /// Returns whether enforcement is enabled.
    pub const fn is_enforcing(&self) -> bool {
        self.enforce
    }

    /// Returns verification statistics.
    pub fn stats(&self) -> &ModuleSigStats {
        &self.stats
    }

    /// Returns the number of trusted keys.
    pub const fn key_count(&self) -> usize {
        self.key_count
    }
}
