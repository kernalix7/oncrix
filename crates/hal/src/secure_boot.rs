// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Secure boot chain-of-trust verification infrastructure.
//!
//! Provides the HAL-level primitives for verifying the boot chain
//! before executing each stage:
//!
//! - [`SecureBootConfig`] — active secure boot policy (from eFuse/firmware)
//! - [`ImageHeader`] — authenticated image header format
//! - [`SignatureScheme`] — supported signature algorithms
//! - [`ChainOfTrust`] — trust anchor and certificate chain management
//! - [`SecureBoot`] — top-level boot verifier
//!
//! # Verification Flow
//!
//! 1. Read secure boot policy from eFuse (`crates/hal/src/efuse_hw.rs`)
//! 2. Load the trust anchor (public key hash) from a read-only region
//! 3. Verify each boot stage image against the anchor or a certificate chain
//! 4. Measure the image into the TPM PCR (if present)
//! 5. Transfer control only on successful verification
//!
//! Reference: UEFI Specification 2.10 §32; TCG Platform Reset Attack
//! Mitigation Specification.

use oncrix_lib::{Error, Result};

/// Length of a SHA-256 digest in bytes.
pub const SHA256_LEN: usize = 32;
/// Length of a SHA-384 digest in bytes.
pub const SHA384_LEN: usize = 48;
/// Length of a SHA-512 digest in bytes.
pub const SHA512_LEN: usize = 64;
/// Maximum image digest size (SHA-512).
pub const MAX_DIGEST_LEN: usize = SHA512_LEN;
/// Maximum public key size (RSA-4096 / EC P-521).
pub const MAX_KEY_LEN: usize = 512;
/// Maximum signature size.
pub const MAX_SIG_LEN: usize = 512;
/// Maximum number of certificates in a chain.
pub const MAX_CERT_CHAIN_DEPTH: usize = 4;
/// Maximum boot images tracked in the chain of trust.
pub const MAX_BOOT_IMAGES: usize = 8;

// ── Signature Scheme ───────────────────────────────────────────────────────

/// Supported signature/hash schemes.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SignatureScheme {
    /// RSA-2048 with SHA-256 (PKCS#1 v1.5).
    Rsa2048Sha256,
    /// RSA-4096 with SHA-384 (PKCS#1 v1.5).
    Rsa4096Sha384,
    /// ECDSA P-256 with SHA-256.
    EcdsaP256Sha256,
    /// ECDSA P-384 with SHA-384.
    EcdsaP384Sha384,
    /// Ed25519.
    Ed25519,
}

impl SignatureScheme {
    /// Digest length in bytes for this scheme.
    pub fn digest_len(self) -> usize {
        match self {
            Self::Rsa2048Sha256 | Self::EcdsaP256Sha256 => SHA256_LEN,
            Self::Rsa4096Sha384 | Self::EcdsaP384Sha384 => SHA384_LEN,
            Self::Ed25519 => SHA512_LEN,
        }
    }
}

// ── Image Header ───────────────────────────────────────────────────────────

/// Magic number identifying a signed boot image.
pub const IMAGE_MAGIC: u32 = 0x4F4E5258; // "ONRX"

/// Authenticated boot image header.
#[repr(C)]
pub struct ImageHeader {
    /// Magic: must equal `IMAGE_MAGIC`.
    pub magic: u32,
    /// Header version.
    pub version: u16,
    /// Signature scheme.
    pub scheme: u16,
    /// Image load address.
    pub load_addr: u64,
    /// Image entry point.
    pub entry_addr: u64,
    /// Image size in bytes (excluding header and signature).
    pub image_size: u32,
    /// Flags (bit 0 = rollback protection, bit 1 = anti-rollback index valid).
    pub flags: u32,
    /// Anti-rollback version counter.
    pub rollback_version: u32,
    /// Reserved for future use.
    pub _reserved: [u8; 4],
    /// Digest of the image payload.
    pub digest: [u8; MAX_DIGEST_LEN],
    /// Signature over the header fields and digest.
    pub signature: [u8; MAX_SIG_LEN],
}

impl ImageHeader {
    /// Validate magic number and basic header sanity.
    pub fn validate_magic(&self) -> Result<()> {
        if self.magic != IMAGE_MAGIC {
            return Err(Error::InvalidArgument);
        }
        if self.image_size == 0 {
            return Err(Error::InvalidArgument);
        }
        Ok(())
    }

    /// Return the scheme as a typed enum.
    pub fn signature_scheme(&self) -> Result<SignatureScheme> {
        match self.scheme {
            0 => Ok(SignatureScheme::Rsa2048Sha256),
            1 => Ok(SignatureScheme::Rsa4096Sha384),
            2 => Ok(SignatureScheme::EcdsaP256Sha256),
            3 => Ok(SignatureScheme::EcdsaP384Sha384),
            4 => Ok(SignatureScheme::Ed25519),
            _ => Err(Error::InvalidArgument),
        }
    }
}

// ── Trust Anchor ───────────────────────────────────────────────────────────

/// A trust anchor: the hash of the root public key stored in eFuse.
#[derive(Clone, Copy)]
pub struct TrustAnchor {
    /// Hash of the root public key.
    pub key_hash: [u8; SHA256_LEN],
    /// Scheme this anchor is for.
    pub scheme: SignatureScheme,
    /// Rollback version floor — images below this are rejected.
    pub min_rollback_version: u32,
}

impl TrustAnchor {
    /// Create a trust anchor from a raw key hash.
    pub fn new(key_hash: [u8; SHA256_LEN], scheme: SignatureScheme) -> Self {
        Self {
            key_hash,
            scheme,
            min_rollback_version: 0,
        }
    }

    /// Set the minimum anti-rollback version.
    pub fn with_min_rollback(mut self, version: u32) -> Self {
        self.min_rollback_version = version;
        self
    }
}

// ── Secure Boot Configuration ──────────────────────────────────────────────

/// Active secure boot policy.
#[derive(Clone, Copy)]
pub struct SecureBootConfig {
    /// True if secure boot verification is enforced.
    pub enabled: bool,
    /// True if JTAG debug is disabled.
    pub jtag_disabled: bool,
    /// True if the rollback counter must be checked.
    pub rollback_protection: bool,
    /// Supported signature schemes bitmask (bit N = SignatureScheme ordinal N).
    pub allowed_schemes: u8,
}

impl SecureBootConfig {
    /// Permissive configuration (all verification disabled — development only).
    pub const PERMISSIVE: Self = Self {
        enabled: false,
        jtag_disabled: false,
        rollback_protection: false,
        allowed_schemes: 0xFF,
    };

    /// Production configuration.
    pub const PRODUCTION: Self = Self {
        enabled: true,
        jtag_disabled: true,
        rollback_protection: true,
        allowed_schemes: 0b0000_1110, // RSA-4096, ECDSA P-256, ECDSA P-384
    };

    /// Check if a given scheme is allowed.
    pub fn is_scheme_allowed(&self, scheme: SignatureScheme) -> bool {
        let bit = match scheme {
            SignatureScheme::Rsa2048Sha256 => 0,
            SignatureScheme::Rsa4096Sha384 => 1,
            SignatureScheme::EcdsaP256Sha256 => 2,
            SignatureScheme::EcdsaP384Sha384 => 3,
            SignatureScheme::Ed25519 => 4,
        };
        self.allowed_schemes & (1 << bit) != 0
    }
}

// ── Verification Record ────────────────────────────────────────────────────

/// Result of a single image verification step.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum VerifyResult {
    /// Image passed all verification checks.
    Valid,
    /// Magic number mismatch.
    InvalidMagic,
    /// Signature scheme not allowed by policy.
    SchemeNotAllowed,
    /// Rollback version below floor.
    RollbackViolation,
    /// Signature verification failed (cryptographic failure).
    SignatureInvalid,
    /// Digest mismatch.
    DigestMismatch,
    /// Measurement into TPM failed (non-fatal for boot).
    MeasurementFailed,
}

// ── Chain of Trust ─────────────────────────────────────────────────────────

/// Measurement record for a single verified image.
#[derive(Clone, Copy)]
pub struct Measurement {
    /// Image load address.
    pub load_addr: u64,
    /// Image digest.
    pub digest: [u8; SHA256_LEN],
    /// Verification result.
    pub result: VerifyResult,
}

/// Chain-of-trust verifier and measurement log.
pub struct ChainOfTrust {
    config: SecureBootConfig,
    anchor: Option<TrustAnchor>,
    measurements: [Option<Measurement>; MAX_BOOT_IMAGES],
    measurement_count: usize,
}

impl ChainOfTrust {
    /// Create a new chain of trust.
    pub fn new(config: SecureBootConfig) -> Self {
        Self {
            config,
            anchor: None,
            measurements: [const { None }; MAX_BOOT_IMAGES],
            measurement_count: 0,
        }
    }

    /// Set the trust anchor from eFuse-provisioned data.
    pub fn set_anchor(&mut self, anchor: TrustAnchor) {
        self.anchor = Some(anchor);
    }

    /// Verify an image header against policy and the trust anchor.
    ///
    /// This function validates the header format and policy; the actual
    /// cryptographic signature verification is delegated to the platform
    /// crypto engine (see `crates/hal/src/crypto_engine.rs`).
    pub fn verify_header(&mut self, header: &ImageHeader) -> VerifyResult {
        if header.validate_magic().is_err() {
            return VerifyResult::InvalidMagic;
        }
        let scheme = match header.signature_scheme() {
            Ok(s) => s,
            Err(_) => return VerifyResult::SignatureInvalid,
        };
        if self.config.enabled && !self.config.is_scheme_allowed(scheme) {
            return VerifyResult::SchemeNotAllowed;
        }
        if self.config.rollback_protection {
            if let Some(anchor) = &self.anchor {
                if header.rollback_version < anchor.min_rollback_version {
                    return VerifyResult::RollbackViolation;
                }
            }
        }
        VerifyResult::Valid
    }

    /// Record a measurement for a verified image.
    pub fn record_measurement(
        &mut self,
        load_addr: u64,
        digest: [u8; SHA256_LEN],
        result: VerifyResult,
    ) -> Result<()> {
        if self.measurement_count >= MAX_BOOT_IMAGES {
            return Err(Error::OutOfMemory);
        }
        self.measurements[self.measurement_count] = Some(Measurement {
            load_addr,
            digest,
            result,
        });
        self.measurement_count += 1;
        Ok(())
    }

    /// Return the measurement log as a slice.
    pub fn measurements(&self) -> &[Option<Measurement>] {
        &self.measurements[..self.measurement_count]
    }

    /// Return the active config.
    pub fn config(&self) -> &SecureBootConfig {
        &self.config
    }

    /// Return true if all recorded measurements passed verification.
    pub fn all_valid(&self) -> bool {
        self.measurements[..self.measurement_count]
            .iter()
            .flatten()
            .all(|m| m.result == VerifyResult::Valid)
    }
}

// ── Secure Boot Top-Level ──────────────────────────────────────────────────

/// Top-level secure boot controller.
pub struct SecureBoot {
    chain: ChainOfTrust,
}

impl SecureBoot {
    /// Initialize secure boot with the given policy.
    pub fn new(config: SecureBootConfig) -> Self {
        Self {
            chain: ChainOfTrust::new(config),
        }
    }

    /// Install the trust anchor.
    pub fn install_anchor(&mut self, anchor: TrustAnchor) {
        self.chain.set_anchor(anchor);
    }

    /// Verify a boot stage and record its measurement.
    pub fn verify_stage(
        &mut self,
        header: &ImageHeader,
        digest: [u8; SHA256_LEN],
    ) -> Result<VerifyResult> {
        let result = self.chain.verify_header(header);
        self.chain
            .record_measurement(header.load_addr, digest, result)?;
        Ok(result)
    }

    /// Returns true if the system is operating under enforcement.
    pub fn is_enforcing(&self) -> bool {
        self.chain.config().enabled
    }

    /// Return a reference to the chain of trust.
    pub fn chain(&self) -> &ChainOfTrust {
        &self.chain
    }
}
