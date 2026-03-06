// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Integrity measurement and verification subsystem.
//!
//! Provides file integrity measurement, verification, and policy
//! enforcement for the ONCRIX kernel. This subsystem maintains an
//! append-only measurement list that records cryptographic digests
//! of files, enabling tamper detection and remote attestation.
//!
//! # Architecture
//!
//! ```text
//!  file open ──► IntegrityPolicy ──► Action
//!                                       │
//!                 ┌─────────────────────┘
//!                 ▼
//!             Enforce ──► verify + deny on mismatch
//!             Log ──────► verify + log-only
//!             Fix ──────► verify + auto-update reference
//!             Off ──────► skip all checks
//! ```
//!
//! # Measurement List
//!
//! The [`MeasurementList`] is an append-only log of
//! [`MeasurementEntry`] records. Each entry stores a file's
//! path hash (for lookup), its SHA-256 digest, a PCR index
//! for TPM extend operations, and a template name.
//!
//! # Appraisal Rules
//!
//! [`AppraisalRule`]s associate path patterns with required
//! signature status, enabling per-file verification policies.
//!
//! Reference: Linux `security/integrity/`.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// SHA-256 digest size in bytes.
const DIGEST_SIZE: usize = 32;

/// Maximum number of entries in the measurement list.
const MAX_MEASUREMENTS: usize = 1024;

/// Maximum number of appraisal rules.
const MAX_APPRAISAL_RULES: usize = 64;

/// Maximum template name length in bytes.
const TEMPLATE_NAME_LEN: usize = 16;

/// Maximum path pattern length in an appraisal rule.
const PATH_PATTERN_LEN: usize = 64;

// -------------------------------------------------------------------
// IntegrityHash
// -------------------------------------------------------------------

/// A SHA-256 integrity digest (32 bytes).
///
/// Wrapper around a fixed-size byte array providing constant-time
/// comparison to prevent timing side-channels.
#[derive(Clone, Copy)]
pub struct IntegrityHash {
    /// Raw digest bytes.
    digest: [u8; DIGEST_SIZE],
}

impl IntegrityHash {
    /// Create an integrity hash from a 32-byte digest.
    pub const fn new(digest: [u8; DIGEST_SIZE]) -> Self {
        Self { digest }
    }

    /// Create a zeroed hash (for uninitialized entries).
    pub const fn zero() -> Self {
        Self {
            digest: [0u8; DIGEST_SIZE],
        }
    }

    /// Return the raw digest bytes.
    pub fn as_bytes(&self) -> &[u8; DIGEST_SIZE] {
        &self.digest
    }

    /// Constant-time comparison with another hash.
    ///
    /// Returns `true` if both digests are identical, using
    /// constant-time comparison to prevent timing attacks.
    pub fn constant_eq(&self, other: &Self) -> bool {
        let mut diff = 0u8;
        let mut i = 0;
        while i < DIGEST_SIZE {
            diff |= self.digest[i] ^ other.digest[i];
            i += 1;
        }
        diff == 0
    }
}

impl PartialEq for IntegrityHash {
    fn eq(&self, other: &Self) -> bool {
        self.constant_eq(other)
    }
}

impl Eq for IntegrityHash {}

impl core::fmt::Debug for IntegrityHash {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "IntegrityHash(")?;
        for b in &self.digest[..4] {
            write!(f, "{b:02x}")?;
        }
        write!(f, "...)")
    }
}

// -------------------------------------------------------------------
// IntegrityPolicy
// -------------------------------------------------------------------

/// Global integrity policy mode controlling enforcement behavior.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum IntegrityPolicy {
    /// Verify digests and deny access on mismatch.
    #[default]
    Enforce,
    /// Verify digests and log mismatches but allow access.
    Log,
    /// Verify digests and auto-update reference on mismatch.
    Fix,
    /// Skip all integrity checks.
    Off,
}

// -------------------------------------------------------------------
// VerifyResult
// -------------------------------------------------------------------

/// Result of a file integrity verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifyResult {
    /// The measured digest matches the expected digest.
    Valid,
    /// The measured digest does not match the expected digest.
    Invalid,
    /// No measurement exists for the given file.
    NotMeasured,
    /// The integrity policy was violated (enforcement action).
    PolicyViolation,
}

// -------------------------------------------------------------------
// MeasurementEntry
// -------------------------------------------------------------------

/// A single entry in the integrity measurement list.
///
/// Each entry records a file's path hash (used for lookup), its
/// SHA-256 digest, the PCR index for TPM extend, and a template
/// name describing the measurement format.
#[derive(Clone, Copy)]
pub struct MeasurementEntry {
    /// Hash of the file path (for efficient lookup).
    pub path_hash: u64,
    /// SHA-256 digest of the file content.
    pub digest: IntegrityHash,
    /// TPM Platform Configuration Register index.
    pub pcr_index: u8,
    /// Template name (e.g., "ima-ng", "ima-sig").
    template_name: [u8; TEMPLATE_NAME_LEN],
    /// Valid length of the template name.
    template_len: u8,
    /// Whether this entry is in use.
    pub in_use: bool,
}

impl MeasurementEntry {
    /// Create an empty, unused entry.
    const fn empty() -> Self {
        Self {
            path_hash: 0,
            digest: IntegrityHash::zero(),
            pcr_index: 0,
            template_name: [0u8; TEMPLATE_NAME_LEN],
            template_len: 0,
            in_use: false,
        }
    }

    /// Return the template name as a byte slice.
    pub fn template_name(&self) -> &[u8] {
        &self.template_name[..self.template_len as usize]
    }
}

impl core::fmt::Debug for MeasurementEntry {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("MeasurementEntry")
            .field("path_hash", &self.path_hash)
            .field("digest", &self.digest)
            .field("pcr_index", &self.pcr_index)
            .field("in_use", &self.in_use)
            .finish()
    }
}

// -------------------------------------------------------------------
// SignatureStatus
// -------------------------------------------------------------------

/// Signature verification status for appraisal rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SignatureStatus {
    /// No signature required.
    #[default]
    NotRequired,
    /// A valid signature is required.
    Required,
    /// The file must have a valid signature from a trusted key.
    RequiredTrusted,
}

// -------------------------------------------------------------------
// AppraisalRule
// -------------------------------------------------------------------

/// An appraisal rule that specifies integrity requirements for
/// files matching a path pattern.
#[derive(Debug, Clone, Copy)]
pub struct AppraisalRule {
    /// Path pattern for matching (prefix-based).
    pattern: [u8; PATH_PATTERN_LEN],
    /// Valid length of the path pattern.
    pattern_len: u8,
    /// Required signature status for matching files.
    pub required_sig: SignatureStatus,
    /// Whether this rule slot is active.
    pub active: bool,
}

impl AppraisalRule {
    /// Create an empty, inactive rule.
    const fn empty() -> Self {
        Self {
            pattern: [0u8; PATH_PATTERN_LEN],
            pattern_len: 0,
            required_sig: SignatureStatus::NotRequired,
            active: false,
        }
    }

    /// Create a new appraisal rule.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `pattern` exceeds
    /// [`PATH_PATTERN_LEN`].
    pub fn new(pattern: &[u8], required_sig: SignatureStatus) -> Result<Self> {
        if pattern.len() > PATH_PATTERN_LEN {
            return Err(Error::InvalidArgument);
        }
        let mut rule = Self::empty();
        rule.pattern[..pattern.len()].copy_from_slice(pattern);
        rule.pattern_len = pattern.len() as u8;
        rule.required_sig = required_sig;
        rule.active = true;
        Ok(rule)
    }

    /// Return the path pattern as a byte slice.
    pub fn pattern(&self) -> &[u8] {
        &self.pattern[..self.pattern_len as usize]
    }
}

// -------------------------------------------------------------------
// MeasurementList
// -------------------------------------------------------------------

/// Append-only measurement list recording integrity digests.
///
/// Stores up to [`MAX_MEASUREMENTS`] entries. Once full, new
/// measurements are rejected to preserve the integrity chain.
/// The list is designed to be append-only — entries are never
/// modified or removed (except in Fix policy mode).
pub struct MeasurementList {
    /// Measurement entries.
    entries: [MeasurementEntry; MAX_MEASUREMENTS],
    /// Number of valid entries.
    count: usize,
    /// Global integrity policy.
    policy: IntegrityPolicy,
    /// Appraisal rules.
    appraisal_rules: [AppraisalRule; MAX_APPRAISAL_RULES],
    /// Number of active appraisal rules.
    appraisal_count: usize,
    /// Number of integrity violations detected.
    violations: u64,
}

impl Default for MeasurementList {
    fn default() -> Self {
        Self::new()
    }
}

impl MeasurementList {
    /// Create an empty measurement list with Enforce policy.
    pub const fn new() -> Self {
        Self {
            entries: [MeasurementEntry::empty(); MAX_MEASUREMENTS],
            count: 0,
            policy: IntegrityPolicy::Enforce,
            appraisal_rules: [AppraisalRule::empty(); MAX_APPRAISAL_RULES],
            appraisal_count: 0,
            violations: 0,
        }
    }

    /// Get the current integrity policy.
    pub fn policy(&self) -> IntegrityPolicy {
        self.policy
    }

    /// Set the global integrity policy.
    pub fn set_policy(&mut self, policy: IntegrityPolicy) {
        self.policy = policy;
    }

    /// Return the number of measurements recorded.
    pub fn measurement_count(&self) -> usize {
        self.count
    }

    /// Return the number of integrity violations detected.
    pub fn violation_count(&self) -> u64 {
        self.violations
    }

    /// Record a file measurement.
    ///
    /// Appends an entry to the measurement list with the given
    /// path hash, SHA-256 digest, PCR index, and template name.
    ///
    /// # Arguments
    ///
    /// - `path_hash`: hash of the file path (for lookup)
    /// - `digest`: SHA-256 digest of file content
    /// - `pcr_index`: TPM PCR index
    /// - `template_name`: measurement template (e.g., b"ima-ng")
    ///
    /// # Errors
    ///
    /// - [`Error::PermissionDenied`] if the policy is Off
    /// - [`Error::OutOfMemory`] if the measurement list is full
    pub fn measure_file(
        &mut self,
        path_hash: u64,
        digest: &[u8; DIGEST_SIZE],
        pcr_index: u8,
        template_name: &[u8],
    ) -> Result<()> {
        if self.policy == IntegrityPolicy::Off {
            return Err(Error::PermissionDenied);
        }
        if self.count >= MAX_MEASUREMENTS {
            return Err(Error::OutOfMemory);
        }

        let mut entry = MeasurementEntry::empty();
        entry.path_hash = path_hash;
        entry.digest = IntegrityHash::new(*digest);
        entry.pcr_index = pcr_index;
        entry.in_use = true;

        let name_len = template_name.len().min(TEMPLATE_NAME_LEN);
        entry.template_name[..name_len].copy_from_slice(&template_name[..name_len]);
        entry.template_len = name_len as u8;

        self.entries[self.count] = entry;
        self.count += 1;
        Ok(())
    }

    /// Verify a file's integrity against its stored measurement.
    ///
    /// Looks up the most recent measurement for `path_hash` and
    /// compares its digest against `expected`. The behavior on
    /// mismatch depends on the current policy:
    ///
    /// - **Enforce**: returns [`VerifyResult::PolicyViolation`]
    /// - **Log**: returns [`VerifyResult::Invalid`] (log only)
    /// - **Fix**: updates the stored digest and returns
    ///   [`VerifyResult::Valid`]
    /// - **Off**: returns [`VerifyResult::Valid`] without checking
    pub fn verify_file(&mut self, path_hash: u64, expected: &[u8; DIGEST_SIZE]) -> VerifyResult {
        if self.policy == IntegrityPolicy::Off {
            return VerifyResult::Valid;
        }

        let expected_hash = IntegrityHash::new(*expected);

        // Find the most recent measurement for this path_hash
        // (scanning from the end for the latest entry).
        let mut found_idx: Option<usize> = None;
        let mut i = self.count;
        while i > 0 {
            i -= 1;
            if self.entries[i].in_use && self.entries[i].path_hash == path_hash {
                found_idx = Some(i);
                break;
            }
        }

        let idx = match found_idx {
            Some(i) => i,
            None => return VerifyResult::NotMeasured,
        };

        if self.entries[idx].digest == expected_hash {
            return VerifyResult::Valid;
        }

        // Mismatch detected.
        self.violations += 1;

        match self.policy {
            IntegrityPolicy::Enforce => VerifyResult::PolicyViolation,
            IntegrityPolicy::Log => VerifyResult::Invalid,
            IntegrityPolicy::Fix => {
                // Auto-update the reference digest.
                self.entries[idx].digest = expected_hash;
                VerifyResult::Valid
            }
            IntegrityPolicy::Off => VerifyResult::Valid,
        }
    }

    /// Look up a measurement entry by path hash.
    ///
    /// Returns the most recent measurement for the given path hash,
    /// or `None` if no measurement exists.
    pub fn find_measurement(&self, path_hash: u64) -> Option<&MeasurementEntry> {
        let mut i = self.count;
        while i > 0 {
            i -= 1;
            if self.entries[i].in_use && self.entries[i].path_hash == path_hash {
                return Some(&self.entries[i]);
            }
        }
        None
    }

    /// Get a measurement entry by index.
    pub fn get_measurement(&self, idx: usize) -> Option<&MeasurementEntry> {
        if idx < self.count && self.entries[idx].in_use {
            Some(&self.entries[idx])
        } else {
            None
        }
    }

    /// Add an appraisal rule.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the appraisal rule table
    /// is full.
    pub fn add_appraisal_rule(&mut self, rule: AppraisalRule) -> Result<()> {
        if self.appraisal_count >= MAX_APPRAISAL_RULES {
            return Err(Error::OutOfMemory);
        }
        self.appraisal_rules[self.appraisal_count] = rule;
        self.appraisal_count += 1;
        Ok(())
    }

    /// Remove an appraisal rule by index.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if the index is out of
    /// range.
    pub fn remove_appraisal_rule(&mut self, idx: usize) -> Result<()> {
        if idx >= self.appraisal_count {
            return Err(Error::InvalidArgument);
        }
        let mut i = idx;
        while i + 1 < self.appraisal_count {
            self.appraisal_rules[i] = self.appraisal_rules[i + 1];
            i += 1;
        }
        self.appraisal_rules[self.appraisal_count - 1] = AppraisalRule::empty();
        self.appraisal_count -= 1;
        Ok(())
    }

    /// Look up the required signature status for a file path.
    ///
    /// Scans the appraisal rules for the first matching path
    /// pattern (prefix-based match). Returns
    /// [`SignatureStatus::NotRequired`] if no rule matches.
    pub fn required_signature(&self, path: &[u8]) -> SignatureStatus {
        let mut i = 0;
        while i < self.appraisal_count {
            let rule = &self.appraisal_rules[i];
            if rule.active {
                let plen = rule.pattern_len as usize;
                if path.len() >= plen && path[..plen] == rule.pattern[..plen] {
                    return rule.required_sig;
                }
            }
            i += 1;
        }
        SignatureStatus::NotRequired
    }

    /// Return the number of active appraisal rules.
    pub fn appraisal_rule_count(&self) -> usize {
        self.appraisal_count
    }
}

impl core::fmt::Debug for MeasurementList {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("MeasurementList")
            .field("measurements", &self.count)
            .field("policy", &self.policy)
            .field("appraisal_rules", &self.appraisal_count)
            .field("violations", &self.violations)
            .finish()
    }
}
