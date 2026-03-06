// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Integrity Measurement Architecture (IMA) subsystem.
//!
//! Provides file integrity measurement, appraisal, and audit
//! capabilities for the ONCRIX kernel. Measurements are stored
//! in a tamper-evident log that can be extended into a TPM PCR
//! for remote attestation.
//!
//! # Architecture
//!
//! ```text
//!  file open ──► ImaPolicy.evaluate() ──► ImaAction
//!                                            │
//!                  ┌─────────────────────────┘
//!                  ▼
//!              Measure ──► ImaLog (append measurement)
//!              Appraise ─► compare digest against reference
//!              Audit ────► log event via audit subsystem
//!              Hash ─────► compute file hash only
//! ```
//!
//! Reference: Linux `security/integrity/ima/`.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Maximum number of measurements stored in the IMA log.
const IMA_LOG_SIZE: usize = 512;

/// Maximum number of policy rules.
const IMA_MAX_RULES: usize = 64;

/// Maximum filename length in a measurement entry.
const IMA_FILENAME_LEN: usize = 256;

/// SHA-256 digest size in bytes.
const DIGEST_SIZE: usize = 32;

/// Maximum formatted ASCII log line length.
const MAX_ASCII_LINE: usize = 128;

// -------------------------------------------------------------------
// ImaAction
// -------------------------------------------------------------------

/// Action to take when a file matches an IMA policy rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u8)]
pub enum ImaAction {
    /// Extend the measurement log with the file's digest.
    #[default]
    Measure = 0,
    /// Verify the file's digest against a reference value.
    Appraise = 1,
    /// Log the file access event for auditing.
    Audit = 2,
    /// Compute the file hash without recording it.
    Hash = 3,
    /// Explicitly skip measurement.
    DontMeasure = 4,
    /// Explicitly skip appraisal.
    DontAppraise = 5,
    /// Explicitly skip audit logging.
    DontAudit = 6,
    /// Explicitly skip hashing.
    DontHash = 7,
}

// -------------------------------------------------------------------
// ImaHashAlgo
// -------------------------------------------------------------------

/// Hash algorithm used for IMA digest computation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u8)]
pub enum ImaHashAlgo {
    /// SHA-256 (256-bit digest).
    #[default]
    Sha256 = 0,
    /// SHA-384 (384-bit digest).
    Sha384 = 1,
    /// SHA-512 (512-bit digest).
    Sha512 = 2,
}

// -------------------------------------------------------------------
// ImaObjType
// -------------------------------------------------------------------

/// Object type classifications for IMA policy matching.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u8)]
pub enum ImaObjType {
    /// Regular file.
    #[default]
    File = 0,
    /// Executable being loaded via exec.
    Exec = 1,
    /// Memory-mapped executable region.
    MmapExec = 2,
    /// Kernel module being loaded.
    Module = 3,
    /// Firmware blob being loaded.
    Firmware = 4,
    /// IMA policy file itself.
    Policy = 5,
    /// Kexec kernel image.
    Kexec = 6,
}

// -------------------------------------------------------------------
// ImaPolicyCondition
// -------------------------------------------------------------------

/// Conditions that can be matched in an IMA policy rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImaPolicyCondition {
    /// Match by user ID.
    Uid(u32),
    /// Match by group ID.
    Gid(u32),
    /// Match by file owner UID.
    Fowner(u32),
    /// Match by filesystem UUID.
    FsUuid([u8; 16]),
    /// Match by filesystem magic number.
    FsMagic(u32),
    /// Match by object type.
    Obj(ImaObjType),
}

// -------------------------------------------------------------------
// ImaMeasurement
// -------------------------------------------------------------------

/// A single IMA measurement log entry.
///
/// Records the PCR index, file digest, filename, and a template
/// hash combining all fields for TPM extend operations.
#[derive(Clone, Copy)]
pub struct ImaMeasurement {
    /// PCR (Platform Configuration Register) index.
    pub pcr: u8,
    /// SHA-256 digest of the measured file content.
    pub digest: [u8; DIGEST_SIZE],
    /// Filename bytes (null-padded).
    pub filename: [u8; IMA_FILENAME_LEN],
    /// Valid length of `filename`.
    pub filename_len: usize,
    /// Template hash combining PCR, digest, and filename.
    pub template_hash: [u8; DIGEST_SIZE],
    /// Whether this measurement slot is in use.
    pub in_use: bool,
}

impl Default for ImaMeasurement {
    fn default() -> Self {
        Self {
            pcr: 0,
            digest: [0; DIGEST_SIZE],
            filename: [0; IMA_FILENAME_LEN],
            filename_len: 0,
            template_hash: [0; DIGEST_SIZE],
            in_use: false,
        }
    }
}

/// Empty measurement constant for array initialization.
const EMPTY_MEASUREMENT: ImaMeasurement = ImaMeasurement {
    pcr: 0,
    digest: [0; DIGEST_SIZE],
    filename: [0; IMA_FILENAME_LEN],
    filename_len: 0,
    template_hash: [0; DIGEST_SIZE],
    in_use: false,
};

// -------------------------------------------------------------------
// ImaPolicyRule
// -------------------------------------------------------------------

/// A single IMA policy rule controlling measurement behavior.
///
/// Rules are evaluated in order; the first matching rule determines
/// the action taken for a given file access.
#[derive(Debug, Clone, Copy, Default)]
pub struct ImaPolicyRule {
    /// Action to perform when this rule matches.
    pub action: ImaAction,
    /// Object type this rule applies to.
    pub obj_type: ImaObjType,
    /// Bitmask of active condition fields.
    pub condition_mask: u32,
    /// UID to match (when condition_mask bit 0 is set).
    pub uid: u32,
    /// File owner UID to match (when condition_mask bit 1 is set).
    pub fowner: u32,
    /// Whether this rule is active.
    pub active: bool,
}

/// Condition mask bit for UID matching.
const COND_UID: u32 = 1 << 0;

/// Condition mask bit for file owner matching.
const COND_FOWNER: u32 = 1 << 1;

/// Empty policy rule constant for array initialization.
const EMPTY_RULE: ImaPolicyRule = ImaPolicyRule {
    action: ImaAction::Measure,
    obj_type: ImaObjType::File,
    condition_mask: 0,
    uid: 0,
    fowner: 0,
    active: false,
};

// -------------------------------------------------------------------
// ImaLog
// -------------------------------------------------------------------

/// Measurement log storing IMA entries in a fixed-size array.
///
/// Entries are appended sequentially. Once full, new measurements
/// are rejected to preserve the integrity chain.
pub struct ImaLog {
    /// Measurement storage.
    measurements: [ImaMeasurement; IMA_LOG_SIZE],
    /// Number of valid measurements.
    count: usize,
    /// Cumulative policy violation count.
    violations: u64,
}

impl Default for ImaLog {
    fn default() -> Self {
        Self::new()
    }
}

impl ImaLog {
    /// Create an empty IMA measurement log.
    pub const fn new() -> Self {
        Self {
            measurements: [EMPTY_MEASUREMENT; IMA_LOG_SIZE],
            count: 0,
            violations: 0,
        }
    }
}

// -------------------------------------------------------------------
// ImaPolicy
// -------------------------------------------------------------------

/// IMA policy engine holding an ordered set of rules.
///
/// Rules are evaluated sequentially; the first matching rule's
/// action is returned. If no rule matches, the default action
/// is [`ImaAction::Measure`].
pub struct ImaPolicy {
    /// Policy rules.
    rules: [ImaPolicyRule; IMA_MAX_RULES],
    /// Number of active rules.
    rule_count: usize,
}

impl Default for ImaPolicy {
    fn default() -> Self {
        Self::new()
    }
}

impl ImaPolicy {
    /// Create an empty IMA policy.
    pub const fn new() -> Self {
        Self {
            rules: [EMPTY_RULE; IMA_MAX_RULES],
            rule_count: 0,
        }
    }

    /// Add a new rule to the policy.
    ///
    /// Returns `Err(OutOfMemory)` if the rule table is full.
    pub fn add_rule(&mut self, rule: ImaPolicyRule) -> Result<()> {
        if self.rule_count >= IMA_MAX_RULES {
            return Err(Error::OutOfMemory);
        }
        self.rules[self.rule_count] = rule;
        self.rules[self.rule_count].active = true;
        self.rule_count += 1;
        Ok(())
    }

    /// Remove a rule by index.
    ///
    /// Returns `Err(InvalidArgument)` if the index is out of range.
    pub fn remove_rule(&mut self, idx: usize) -> Result<()> {
        if idx >= self.rule_count {
            return Err(Error::InvalidArgument);
        }
        // Shift remaining rules down.
        let mut i = idx;
        while i + 1 < self.rule_count {
            self.rules[i] = self.rules[i + 1];
            i += 1;
        }
        self.rule_count -= 1;
        self.rules[self.rule_count] = EMPTY_RULE;
        Ok(())
    }

    /// Evaluate the policy for a given object type, UID, and file
    /// owner.
    ///
    /// Returns the action from the first matching active rule, or
    /// [`ImaAction::Measure`] if no rule matches.
    pub fn evaluate(&self, obj_type: ImaObjType, uid: u32, fowner: u32) -> ImaAction {
        let mut i = 0;
        while i < self.rule_count {
            let rule = &self.rules[i];
            if rule.active && Self::rule_matches(rule, obj_type, uid, fowner) {
                return rule.action;
            }
            i += 1;
        }
        ImaAction::Measure
    }

    /// Check whether a single rule matches the given parameters.
    fn rule_matches(rule: &ImaPolicyRule, obj_type: ImaObjType, uid: u32, fowner: u32) -> bool {
        if rule.obj_type as u8 != obj_type as u8 {
            return false;
        }
        if rule.condition_mask & COND_UID != 0 && rule.uid != uid {
            return false;
        }
        if rule.condition_mask & COND_FOWNER != 0 && rule.fowner != fowner {
            return false;
        }
        true
    }
}

// -------------------------------------------------------------------
// ImaSubsystem
// -------------------------------------------------------------------

/// Top-level IMA subsystem combining the measurement log, policy
/// engine, and configuration state.
pub struct ImaSubsystem {
    /// Measurement log.
    log: ImaLog,
    /// Policy engine.
    policy: ImaPolicy,
    /// Hash algorithm in use.
    hash_algo: ImaHashAlgo,
    /// Whether the IMA subsystem is enabled.
    enabled: bool,
}

impl Default for ImaSubsystem {
    fn default() -> Self {
        Self::new()
    }
}

impl ImaSubsystem {
    /// Create a new IMA subsystem with default settings.
    ///
    /// The subsystem starts enabled with SHA-256 hashing and an
    /// empty policy (default action: Measure).
    pub const fn new() -> Self {
        Self {
            log: ImaLog::new(),
            policy: ImaPolicy::new(),
            hash_algo: ImaHashAlgo::Sha256,
            enabled: true,
        }
    }

    /// Get the currently configured hash algorithm.
    pub fn hash_algo(&self) -> ImaHashAlgo {
        self.hash_algo
    }

    /// Get a reference to the policy engine.
    pub fn policy(&self) -> &ImaPolicy {
        &self.policy
    }

    /// Get a mutable reference to the policy engine.
    pub fn policy_mut(&mut self) -> &mut ImaPolicy {
        &mut self.policy
    }

    /// Record a file measurement in the IMA log.
    ///
    /// # Arguments
    ///
    /// - `filename`: file path bytes
    /// - `digest`: SHA-256 digest of the file content
    /// - `pcr`: TPM PCR index to extend
    ///
    /// # Errors
    ///
    /// - `PermissionDenied` if the subsystem is disabled
    /// - `OutOfMemory` if the measurement log is full
    pub fn measure_file(
        &mut self,
        filename: &[u8],
        digest: &[u8; DIGEST_SIZE],
        pcr: u8,
    ) -> Result<()> {
        if !self.enabled {
            return Err(Error::PermissionDenied);
        }
        if self.log.count >= IMA_LOG_SIZE {
            return Err(Error::OutOfMemory);
        }

        let mut entry = EMPTY_MEASUREMENT;
        entry.pcr = pcr;
        entry.digest = *digest;

        let name_len = filename.len().min(IMA_FILENAME_LEN);
        entry.filename[..name_len].copy_from_slice(&filename[..name_len]);
        entry.filename_len = name_len;

        // Compute template hash: simple XOR-fold of PCR, digest,
        // and filename prefix for a lightweight binding.
        entry.template_hash = compute_template_hash(pcr, digest, filename);
        entry.in_use = true;

        self.log.measurements[self.log.count] = entry;
        self.log.count += 1;
        Ok(())
    }

    /// Appraise a file by comparing its actual digest against an
    /// expected reference digest.
    ///
    /// Returns `Ok(true)` if the digests match, `Ok(false)` if they
    /// differ (a violation is recorded), or an error if the
    /// subsystem is disabled.
    pub fn appraise_file(
        &mut self,
        _filename: &[u8],
        expected_digest: &[u8; DIGEST_SIZE],
        actual_digest: &[u8; DIGEST_SIZE],
    ) -> Result<bool> {
        if !self.enabled {
            return Err(Error::PermissionDenied);
        }
        if constant_time_eq(expected_digest, actual_digest) {
            Ok(true)
        } else {
            self.log.violations += 1;
            Ok(false)
        }
    }

    /// Evaluate the policy for a file and perform the resulting
    /// action (measure, appraise, or skip).
    ///
    /// Returns the action that was taken.
    pub fn check_and_measure(
        &mut self,
        filename: &[u8],
        obj_type: ImaObjType,
        uid: u32,
        fowner: u32,
        digest: &[u8; DIGEST_SIZE],
    ) -> Result<ImaAction> {
        if !self.enabled {
            return Err(Error::PermissionDenied);
        }
        let action = self.policy.evaluate(obj_type, uid, fowner);
        match action {
            ImaAction::Measure => {
                self.measure_file(filename, digest, 10)?;
            }
            ImaAction::Appraise | ImaAction::Audit | ImaAction::Hash => {
                // For appraise/audit/hash the caller must handle
                // the specific action; we only record the decision.
            }
            ImaAction::DontMeasure
            | ImaAction::DontAppraise
            | ImaAction::DontAudit
            | ImaAction::DontHash => {
                // Explicitly skipped by policy.
            }
        }
        Ok(action)
    }

    /// Get a reference to a measurement by index.
    pub fn get_measurement(&self, idx: usize) -> Option<&ImaMeasurement> {
        if idx < self.log.count {
            Some(&self.log.measurements[idx])
        } else {
            None
        }
    }

    /// Format a measurement entry as an ASCII log line.
    ///
    /// Output format: `pcr=<NN> digest=<hex16>... fn=<name>`
    ///
    /// Returns the formatted bytes and their length, or
    /// `Err(InvalidArgument)` if the index is out of range.
    pub fn get_ascii_log(&self, idx: usize) -> Result<([u8; MAX_ASCII_LINE], usize)> {
        if idx >= self.log.count {
            return Err(Error::InvalidArgument);
        }
        let m = &self.log.measurements[idx];
        let mut buf = [0u8; MAX_ASCII_LINE];
        let mut pos = 0usize;

        // "pcr="
        pos = write_bytes(b"pcr=", &mut buf, pos);
        pos = write_u8_decimal(m.pcr, &mut buf, pos);

        // " digest="
        pos = write_bytes(b" digest=", &mut buf, pos);
        // Write first 8 bytes of digest as hex (16 hex chars).
        let hex_bytes = 8.min(DIGEST_SIZE);
        let mut i = 0;
        while i < hex_bytes && pos + 1 < MAX_ASCII_LINE {
            let hi = m.digest[i] >> 4;
            let lo = m.digest[i] & 0x0f;
            buf[pos] = hex_nibble(hi);
            pos += 1;
            buf[pos] = hex_nibble(lo);
            pos += 1;
            i += 1;
        }

        // " fn="
        pos = write_bytes(b" fn=", &mut buf, pos);
        let name_len = m.filename_len.min(MAX_ASCII_LINE.saturating_sub(pos));
        buf[pos..pos + name_len].copy_from_slice(&m.filename[..name_len]);
        pos += name_len;

        Ok((buf, pos))
    }

    /// Return the total number of integrity violations detected.
    pub fn violation_count(&self) -> u64 {
        self.log.violations
    }

    /// Enable the IMA subsystem.
    pub fn enable(&mut self) {
        self.enabled = true;
    }

    /// Disable the IMA subsystem.
    pub fn disable(&mut self) {
        self.enabled = false;
    }

    /// Return the number of measurements currently in the log.
    pub fn measurement_count(&self) -> usize {
        self.log.count
    }
}

// -------------------------------------------------------------------
// Helpers
// -------------------------------------------------------------------

/// Compute a template hash from PCR index, digest, and filename.
///
/// Uses a simple XOR-fold scheme suitable for `#![no_std]`
/// environments without pulling in the full SHA-256 implementation.
fn compute_template_hash(
    pcr: u8,
    digest: &[u8; DIGEST_SIZE],
    filename: &[u8],
) -> [u8; DIGEST_SIZE] {
    let mut hash = [0u8; DIGEST_SIZE];

    // Fold the digest into the template hash.
    let mut i = 0;
    while i < DIGEST_SIZE {
        hash[i] = digest[i];
        i += 1;
    }

    // Mix in PCR index.
    hash[0] ^= pcr;

    // Mix in filename bytes via XOR rotation.
    let name_len = filename.len().min(IMA_FILENAME_LEN);
    let mut j = 0;
    while j < name_len {
        hash[j % DIGEST_SIZE] ^= filename[j];
        j += 1;
    }

    hash
}

/// Constant-time byte slice comparison.
fn constant_time_eq(a: &[u8; DIGEST_SIZE], b: &[u8; DIGEST_SIZE]) -> bool {
    let mut diff = 0u8;
    let mut i = 0;
    while i < DIGEST_SIZE {
        diff |= a[i] ^ b[i];
        i += 1;
    }
    diff == 0
}

/// Convert a nibble (0..15) to its ASCII hex character.
const fn hex_nibble(n: u8) -> u8 {
    if n < 10 { b'0' + n } else { b'a' + (n - 10) }
}

/// Copy `src` bytes into `buf` starting at `pos`, capped at buffer
/// length. Returns the new position.
fn write_bytes(src: &[u8], buf: &mut [u8; MAX_ASCII_LINE], pos: usize) -> usize {
    let avail = MAX_ASCII_LINE.saturating_sub(pos);
    let len = src.len().min(avail);
    buf[pos..pos + len].copy_from_slice(&src[..len]);
    pos + len
}

/// Write a `u8` as decimal ASCII into `buf` starting at `pos`.
/// Returns the new position.
fn write_u8_decimal(val: u8, buf: &mut [u8; MAX_ASCII_LINE], pos: usize) -> usize {
    if val == 0 {
        if pos < MAX_ASCII_LINE {
            buf[pos] = b'0';
            return pos + 1;
        }
        return pos;
    }
    let mut digits = [0u8; 3];
    let mut n = val;
    let mut count = 0usize;
    while n > 0 {
        digits[count] = b'0' + n % 10;
        n /= 10;
        count += 1;
    }
    let mut p = pos;
    let mut i = count;
    while i > 0 && p < MAX_ASCII_LINE {
        i -= 1;
        buf[p] = digits[i];
        p += 1;
    }
    p
}
