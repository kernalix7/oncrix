// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Secure boot chain verification subsystem.
//!
//! Provides a chain-of-trust mechanism for validating each stage of
//! the boot process, from firmware through bootloader, kernel,
//! modules, and into user space. Measurements are recorded as
//! SHA-256 hashes and verified against a signature database of
//! trusted keys and forbidden hashes.
//!
//! # Architecture
//!
//! ```text
//!  SecureBootSubsystem
//!   ├── SignatureDb
//!   │    ├── trusted_keys: [TrustedKey; 16]
//!   │    └── forbidden_hashes: [ForbiddenHash; 32]
//!   ├── BootChain
//!   │    └── measurements: [BootMeasurement; 32]
//!   └── SecureBootState
//!        ├── enabled / enforcement
//!        └── violation_log: [BootViolation; 64]
//! ```
//!
//! Reference: UEFI Specification (Secure Boot), TCG Platform
//! Firmware Profile.

use oncrix_lib::{Error, Result};

// ── Constants ─────────────────────────────────────────────────────

/// SHA-256 digest size in bytes.
const DIGEST_SIZE: usize = 32;

/// Maximum number of measurements in the boot chain.
const MAX_MEASUREMENTS: usize = 32;

/// Maximum number of trusted keys in the signature database.
const MAX_TRUSTED_KEYS: usize = 16;

/// Maximum number of forbidden hashes in the signature database.
const MAX_FORBIDDEN_HASHES: usize = 32;

/// Maximum number of violation log entries.
const MAX_VIOLATIONS: usize = 64;

/// Maximum length of a boot stage description.
const DESC_LEN: usize = 64;

/// Maximum length of a key name or identifier.
const KEY_NAME_LEN: usize = 32;

// ── BootStage ─────────────────────────────────────────────────────

/// Stages of the boot process in chain-of-trust order.
///
/// Each stage must be measured and verified before the next stage
/// is allowed to execute.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
#[repr(u8)]
pub enum BootStage {
    /// Platform firmware (UEFI/BIOS ROM).
    #[default]
    Firmware = 0,
    /// Bootloader (GRUB, systemd-boot, etc.).
    Bootloader = 1,
    /// Kernel image.
    Kernel = 2,
    /// Kernel modules and initrd/initramfs.
    Modules = 3,
    /// User-space init process and early services.
    UserSpace = 4,
}

impl BootStage {
    /// Short label for formatted output.
    pub const fn label(self) -> &'static str {
        match self {
            Self::Firmware => "FIRMWARE",
            Self::Bootloader => "BOOTLOADER",
            Self::Kernel => "KERNEL",
            Self::Modules => "MODULES",
            Self::UserSpace => "USERSPACE",
        }
    }
}

// ── EnforcementMode ───────────────────────────────────────────────

/// Enforcement mode for the secure boot subsystem.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum EnforcementMode {
    /// Full enforcement: violations block boot.
    #[default]
    Full,
    /// Audit only: violations are logged but boot continues.
    Audit,
}

// ── BootMeasurement ───────────────────────────────────────────────

/// A single measurement in the boot chain.
///
/// Records the boot stage, its SHA-256 hash, and a human-readable
/// description of the measured component.
#[derive(Clone, Copy)]
pub struct BootMeasurement {
    /// Boot stage this measurement belongs to.
    pub stage: BootStage,
    /// SHA-256 hash of the measured component.
    pub hash: [u8; DIGEST_SIZE],
    /// Human-readable description of the component.
    pub description: [u8; DESC_LEN],
    /// Valid length of the description.
    pub desc_len: usize,
    /// Whether this measurement slot is in use.
    pub in_use: bool,
}

impl BootMeasurement {
    /// Create an empty, unused measurement.
    const fn empty() -> Self {
        Self {
            stage: BootStage::Firmware,
            hash: [0u8; DIGEST_SIZE],
            description: [0u8; DESC_LEN],
            desc_len: 0,
            in_use: false,
        }
    }

    /// Create a new measurement.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `description` exceeds
    /// [`DESC_LEN`] bytes.
    pub fn new(stage: BootStage, hash: [u8; DIGEST_SIZE], description: &[u8]) -> Result<Self> {
        if description.len() > DESC_LEN {
            return Err(Error::InvalidArgument);
        }
        let mut m = Self::empty();
        m.stage = stage;
        m.hash = hash;
        m.description[..description.len()].copy_from_slice(description);
        m.desc_len = description.len();
        m.in_use = true;
        Ok(m)
    }

    /// Return the description as a byte slice.
    pub fn desc_bytes(&self) -> &[u8] {
        &self.description[..self.desc_len]
    }
}

// ── BootChain ─────────────────────────────────────────────────────

/// Ordered sequence of boot measurements forming the chain of trust.
///
/// Measurements are appended sequentially as each boot stage is
/// verified. The chain can be replayed to validate that all stages
/// were measured in the correct order.
pub struct BootChain {
    /// Ordered measurement slots.
    measurements: [BootMeasurement; MAX_MEASUREMENTS],
    /// Number of recorded measurements.
    count: usize,
}

impl Default for BootChain {
    fn default() -> Self {
        Self::new()
    }
}

impl BootChain {
    /// Create an empty boot chain.
    pub const fn new() -> Self {
        Self {
            measurements: [BootMeasurement::empty(); MAX_MEASUREMENTS],
            count: 0,
        }
    }

    /// Extend the chain with a new measurement.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the chain is full.
    /// Returns [`Error::InvalidArgument`] if the stage is earlier
    /// than the last recorded stage (out-of-order measurement).
    pub fn extend_measurement(&mut self, measurement: BootMeasurement) -> Result<()> {
        if self.count >= MAX_MEASUREMENTS {
            return Err(Error::OutOfMemory);
        }
        // Enforce ordered stages: new measurement must not precede
        // the last one in the boot sequence.
        if self.count > 0 {
            let last_stage = self.measurements[self.count - 1].stage;
            if (measurement.stage as u8) < (last_stage as u8) {
                return Err(Error::InvalidArgument);
            }
        }
        self.measurements[self.count] = measurement;
        self.count = self.count.saturating_add(1);
        Ok(())
    }

    /// Verify the integrity of the chain.
    ///
    /// Checks that all measurements are in order and that no
    /// measurement slot is uninitialized between valid entries.
    /// Returns `true` if the chain is valid.
    pub fn verify_chain(&self) -> bool {
        if self.count == 0 {
            return true;
        }
        let mut i = 0;
        while i < self.count {
            if !self.measurements[i].in_use {
                return false;
            }
            if i > 0 {
                let prev = self.measurements[i - 1].stage as u8;
                let curr = self.measurements[i].stage as u8;
                if curr < prev {
                    return false;
                }
            }
            i = i.saturating_add(1);
        }
        true
    }

    /// Get a measurement by index.
    pub fn get(&self, index: usize) -> Option<&BootMeasurement> {
        if index < self.count {
            Some(&self.measurements[index])
        } else {
            None
        }
    }

    /// Return the number of recorded measurements.
    pub fn count(&self) -> usize {
        self.count
    }

    /// Check if the chain is empty.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Clear all measurements.
    pub fn clear(&mut self) {
        self.measurements = [BootMeasurement::empty(); MAX_MEASUREMENTS];
        self.count = 0;
    }
}

// ── TrustedKey ────────────────────────────────────────────────────

/// A trusted signing key in the signature database.
///
/// In a full implementation this would hold the public key material
/// (e.g., RSA-2048 or ECDSA P-256). Currently stores a key hash
/// as a stand-in for the full key.
#[derive(Clone, Copy)]
pub struct TrustedKey {
    /// Key identifier / name.
    pub name: [u8; KEY_NAME_LEN],
    /// Valid length of the name.
    pub name_len: usize,
    /// SHA-256 hash of the public key.
    pub key_hash: [u8; DIGEST_SIZE],
    /// Whether this key slot is in use.
    pub active: bool,
}

impl TrustedKey {
    /// Create an empty, inactive key entry.
    const fn empty() -> Self {
        Self {
            name: [0u8; KEY_NAME_LEN],
            name_len: 0,
            key_hash: [0u8; DIGEST_SIZE],
            active: false,
        }
    }
}

// ── ForbiddenHash ─────────────────────────────────────────────────

/// A forbidden image hash in the signature database (dbx).
///
/// Images whose SHA-256 hash matches a forbidden entry are
/// rejected during verification, even if signed by a trusted key.
#[derive(Clone, Copy)]
pub struct ForbiddenHash {
    /// SHA-256 hash of the forbidden image.
    pub hash: [u8; DIGEST_SIZE],
    /// Whether this slot is in use.
    pub active: bool,
}

impl ForbiddenHash {
    /// Create an empty, inactive forbidden hash entry.
    const fn empty() -> Self {
        Self {
            hash: [0u8; DIGEST_SIZE],
            active: false,
        }
    }
}

// ── SignatureDb ────────────────────────────────────────────────────

/// Signature database containing trusted keys (db) and forbidden
/// hashes (dbx) for secure boot image verification.
pub struct SignatureDb {
    /// Trusted signing keys (db).
    trusted_keys: [TrustedKey; MAX_TRUSTED_KEYS],
    /// Number of active trusted keys.
    trusted_count: usize,
    /// Forbidden image hashes (dbx).
    forbidden_hashes: [ForbiddenHash; MAX_FORBIDDEN_HASHES],
    /// Number of active forbidden hashes.
    forbidden_count: usize,
}

impl Default for SignatureDb {
    fn default() -> Self {
        Self::new()
    }
}

impl SignatureDb {
    /// Create an empty signature database.
    pub const fn new() -> Self {
        Self {
            trusted_keys: [TrustedKey::empty(); MAX_TRUSTED_KEYS],
            trusted_count: 0,
            forbidden_hashes: [ForbiddenHash::empty(); MAX_FORBIDDEN_HASHES],
            forbidden_count: 0,
        }
    }

    /// Add a trusted key to the database.
    ///
    /// # Errors
    ///
    /// - [`Error::OutOfMemory`] if the trusted key table is full.
    /// - [`Error::InvalidArgument`] if `name` is empty or too long.
    pub fn add_trusted_key(&mut self, name: &[u8], key_hash: [u8; DIGEST_SIZE]) -> Result<()> {
        if name.is_empty() || name.len() > KEY_NAME_LEN {
            return Err(Error::InvalidArgument);
        }
        if self.trusted_count >= MAX_TRUSTED_KEYS {
            return Err(Error::OutOfMemory);
        }
        let slot = self.find_free_key_slot().ok_or(Error::OutOfMemory)?;
        self.trusted_keys[slot].name[..name.len()].copy_from_slice(name);
        self.trusted_keys[slot].name_len = name.len();
        self.trusted_keys[slot].key_hash = key_hash;
        self.trusted_keys[slot].active = true;
        self.trusted_count = self.trusted_count.saturating_add(1);
        Ok(())
    }

    /// Remove a trusted key by name.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if no key with the given name
    /// exists.
    pub fn remove_trusted_key(&mut self, name: &[u8]) -> Result<()> {
        let mut i = 0;
        while i < MAX_TRUSTED_KEYS {
            let key = &self.trusted_keys[i];
            if key.active && key.name_len == name.len() && key.name[..key.name_len] == *name {
                self.trusted_keys[i].active = false;
                self.trusted_count = self.trusted_count.saturating_sub(1);
                return Ok(());
            }
            i = i.saturating_add(1);
        }
        Err(Error::NotFound)
    }

    /// Add a forbidden hash to the database (dbx).
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the forbidden hash table
    /// is full.
    pub fn add_forbidden_hash(&mut self, hash: [u8; DIGEST_SIZE]) -> Result<()> {
        if self.forbidden_count >= MAX_FORBIDDEN_HASHES {
            return Err(Error::OutOfMemory);
        }
        let slot = self.find_free_forbidden_slot().ok_or(Error::OutOfMemory)?;
        self.forbidden_hashes[slot].hash = hash;
        self.forbidden_hashes[slot].active = true;
        self.forbidden_count = self.forbidden_count.saturating_add(1);
        Ok(())
    }

    /// Remove a forbidden hash from the database.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the hash is not in the
    /// forbidden list.
    pub fn remove_forbidden_hash(&mut self, hash: &[u8; DIGEST_SIZE]) -> Result<()> {
        let mut i = 0;
        while i < MAX_FORBIDDEN_HASHES {
            if self.forbidden_hashes[i].active
                && constant_time_eq(&self.forbidden_hashes[i].hash, hash)
            {
                self.forbidden_hashes[i].active = false;
                self.forbidden_count = self.forbidden_count.saturating_sub(1);
                return Ok(());
            }
            i = i.saturating_add(1);
        }
        Err(Error::NotFound)
    }

    /// Check whether an image hash is in the forbidden list.
    ///
    /// Uses constant-time comparison for each entry.
    pub fn is_forbidden(&self, hash: &[u8; DIGEST_SIZE]) -> bool {
        let mut i = 0;
        while i < MAX_FORBIDDEN_HASHES {
            if self.forbidden_hashes[i].active
                && constant_time_eq(&self.forbidden_hashes[i].hash, hash)
            {
                return true;
            }
            i = i.saturating_add(1);
        }
        false
    }

    /// Check whether an image hash matches any trusted key's hash.
    ///
    /// In a full implementation this would verify a cryptographic
    /// signature using the key material. Currently checks if the
    /// image hash matches any trusted key hash (simplified model).
    pub fn is_trusted(&self, image_hash: &[u8; DIGEST_SIZE]) -> bool {
        let mut i = 0;
        while i < MAX_TRUSTED_KEYS {
            if self.trusted_keys[i].active
                && constant_time_eq(&self.trusted_keys[i].key_hash, image_hash)
            {
                return true;
            }
            i = i.saturating_add(1);
        }
        false
    }

    /// Return the number of trusted keys.
    pub fn trusted_key_count(&self) -> usize {
        self.trusted_count
    }

    /// Return the number of forbidden hashes.
    pub fn forbidden_hash_count(&self) -> usize {
        self.forbidden_count
    }

    // ── Internal helpers ──────────────────────────────────────────

    /// Find the first inactive trusted key slot.
    fn find_free_key_slot(&self) -> Option<usize> {
        let mut i = 0;
        while i < MAX_TRUSTED_KEYS {
            if !self.trusted_keys[i].active {
                return Some(i);
            }
            i = i.saturating_add(1);
        }
        None
    }

    /// Find the first inactive forbidden hash slot.
    fn find_free_forbidden_slot(&self) -> Option<usize> {
        let mut i = 0;
        while i < MAX_FORBIDDEN_HASHES {
            if !self.forbidden_hashes[i].active {
                return Some(i);
            }
            i = i.saturating_add(1);
        }
        None
    }
}

// ── BootViolation ─────────────────────────────────────────────────

/// A recorded secure boot violation event.
#[derive(Clone, Copy)]
pub struct BootViolation {
    /// Boot stage where the violation occurred.
    pub stage: BootStage,
    /// SHA-256 hash of the offending image.
    pub image_hash: [u8; DIGEST_SIZE],
    /// Description of the violation.
    pub description: [u8; DESC_LEN],
    /// Valid length of the description.
    pub desc_len: usize,
    /// Whether the violation was in the forbidden list.
    pub is_forbidden: bool,
    /// Whether the violation was due to missing trust (not signed).
    pub untrusted: bool,
    /// Whether this violation slot is in use.
    pub in_use: bool,
}

impl BootViolation {
    /// Create an empty, unused violation entry.
    const fn empty() -> Self {
        Self {
            stage: BootStage::Firmware,
            image_hash: [0u8; DIGEST_SIZE],
            description: [0u8; DESC_LEN],
            desc_len: 0,
            is_forbidden: false,
            untrusted: false,
            in_use: false,
        }
    }
}

// ── SecureBootState ───────────────────────────────────────────────

/// Runtime state of the secure boot subsystem.
///
/// Tracks whether secure boot is enabled, the enforcement mode,
/// and a log of detected violations.
pub struct SecureBootState {
    /// Whether secure boot is enabled.
    pub enabled: bool,
    /// Current enforcement mode.
    pub enforcement: EnforcementMode,
    /// Ring buffer of violation events.
    violation_log: [BootViolation; MAX_VIOLATIONS],
    /// Number of violations recorded (may wrap).
    violation_count: usize,
}

impl Default for SecureBootState {
    fn default() -> Self {
        Self::new()
    }
}

impl SecureBootState {
    /// Create a new secure boot state (disabled by default).
    pub const fn new() -> Self {
        Self {
            enabled: false,
            enforcement: EnforcementMode::Full,
            violation_log: [BootViolation::empty(); MAX_VIOLATIONS],
            violation_count: 0,
        }
    }

    /// Record a violation in the log.
    fn record_violation(&mut self, violation: BootViolation) {
        let idx = self.violation_count % MAX_VIOLATIONS;
        self.violation_log[idx] = violation;
        self.violation_count = self.violation_count.saturating_add(1);
    }

    /// Get a violation entry by index.
    ///
    /// Returns `None` if the index is out of bounds or unused.
    pub fn get_violation(&self, index: usize) -> Option<&BootViolation> {
        if index < MAX_VIOLATIONS {
            let entry = &self.violation_log[index];
            if entry.in_use { Some(entry) } else { None }
        } else {
            None
        }
    }

    /// Return the total number of violations recorded.
    pub fn violation_count(&self) -> usize {
        self.violation_count
    }
}

// ── SecureBootSubsystem ───────────────────────────────────────────

/// Top-level secure boot subsystem combining the signature database,
/// boot chain, and runtime state.
///
/// Provides image verification against the signature database,
/// boot stage measurement, and chain-of-trust validation.
pub struct SecureBootSubsystem {
    /// Signature database (trusted keys + forbidden hashes).
    signature_db: SignatureDb,
    /// Boot measurement chain.
    boot_chain: BootChain,
    /// Runtime state and violation log.
    state: SecureBootState,
}

impl Default for SecureBootSubsystem {
    fn default() -> Self {
        Self::new()
    }
}

impl SecureBootSubsystem {
    /// Create a new secure boot subsystem (disabled).
    pub const fn new() -> Self {
        Self {
            signature_db: SignatureDb::new(),
            boot_chain: BootChain::new(),
            state: SecureBootState::new(),
        }
    }

    /// Enable the secure boot subsystem.
    pub fn enable(&mut self, mode: EnforcementMode) {
        self.state.enabled = true;
        self.state.enforcement = mode;
    }

    /// Disable the secure boot subsystem.
    pub fn disable(&mut self) {
        self.state.enabled = false;
    }

    /// Check whether secure boot is enabled.
    pub fn is_enabled(&self) -> bool {
        self.state.enabled
    }

    /// Get the current enforcement mode.
    pub fn enforcement_mode(&self) -> EnforcementMode {
        self.state.enforcement
    }

    /// Get a mutable reference to the signature database.
    pub fn signature_db_mut(&mut self) -> &mut SignatureDb {
        &mut self.signature_db
    }

    /// Get a reference to the signature database.
    pub fn signature_db(&self) -> &SignatureDb {
        &self.signature_db
    }

    /// Get a reference to the boot chain.
    pub fn boot_chain(&self) -> &BootChain {
        &self.boot_chain
    }

    /// Get a reference to the secure boot state.
    pub fn get_state(&self) -> &SecureBootState {
        &self.state
    }

    /// Verify an image against the signature database.
    ///
    /// Checks the image hash is not in the forbidden list and is
    /// signed by a trusted key. In Full enforcement mode, a
    /// verification failure returns [`Error::PermissionDenied`].
    /// In Audit mode, failures are logged but `Ok(false)` is
    /// returned.
    ///
    /// # Arguments
    ///
    /// - `stage`: the boot stage this image belongs to
    /// - `image_hash`: SHA-256 hash of the image
    /// - `description`: human-readable name of the image
    ///
    /// # Returns
    ///
    /// `Ok(true)` if the image is verified, `Ok(false)` in audit
    /// mode on failure, or `Err(PermissionDenied)` in full
    /// enforcement mode on failure.
    pub fn verify_image(
        &mut self,
        stage: BootStage,
        image_hash: &[u8; DIGEST_SIZE],
        description: &[u8],
    ) -> Result<bool> {
        if !self.state.enabled {
            return Ok(true);
        }

        // Check the forbidden hash list first (deny takes priority).
        if self.signature_db.is_forbidden(image_hash) {
            let violation = make_violation(stage, image_hash, description, true, false);
            self.state.record_violation(violation);

            return match self.state.enforcement {
                EnforcementMode::Full => Err(Error::PermissionDenied),
                EnforcementMode::Audit => Ok(false),
            };
        }

        // Check against trusted keys.
        if !self.signature_db.is_trusted(image_hash) {
            let violation = make_violation(stage, image_hash, description, false, true);
            self.state.record_violation(violation);

            return match self.state.enforcement {
                EnforcementMode::Full => Err(Error::PermissionDenied),
                EnforcementMode::Audit => Ok(false),
            };
        }

        Ok(true)
    }

    /// Measure a boot stage by recording it in the boot chain.
    ///
    /// The measurement is appended to the chain. No verification
    /// is performed; use [`Self::verify_image`] first to validate
    /// the image.
    ///
    /// # Errors
    ///
    /// - [`Error::OutOfMemory`] if the boot chain is full.
    /// - [`Error::InvalidArgument`] if the description is too long
    ///   or the stage is out of order.
    pub fn measure_boot_stage(
        &mut self,
        stage: BootStage,
        hash: [u8; DIGEST_SIZE],
        description: &[u8],
    ) -> Result<()> {
        let measurement = BootMeasurement::new(stage, hash, description)?;
        self.boot_chain.extend_measurement(measurement)
    }

    /// Verify the integrity of the entire boot chain.
    ///
    /// Returns `true` if all measurements are in order and the
    /// chain is consistent.
    pub fn verify_boot_chain(&self) -> bool {
        self.boot_chain.verify_chain()
    }

    /// Return the number of violations recorded.
    pub fn violation_count(&self) -> usize {
        self.state.violation_count()
    }

    /// Return the number of measurements in the boot chain.
    pub fn measurement_count(&self) -> usize {
        self.boot_chain.count()
    }
}

// ── Helpers ───────────────────────────────────────────────────────

/// Constant-time byte comparison for security-sensitive hash checks.
fn constant_time_eq(a: &[u8; DIGEST_SIZE], b: &[u8; DIGEST_SIZE]) -> bool {
    let mut diff = 0u8;
    let mut i = 0;
    while i < DIGEST_SIZE {
        diff |= a[i] ^ b[i];
        i = i.saturating_add(1);
    }
    diff == 0
}

/// Build a boot violation record.
fn make_violation(
    stage: BootStage,
    image_hash: &[u8; DIGEST_SIZE],
    description: &[u8],
    is_forbidden: bool,
    untrusted: bool,
) -> BootViolation {
    let mut v = BootViolation::empty();
    v.stage = stage;
    v.image_hash = *image_hash;
    let desc_len = description.len().min(DESC_LEN);
    v.description[..desc_len].copy_from_slice(&description[..desc_len]);
    v.desc_len = desc_len;
    v.is_forbidden = is_forbidden;
    v.untrusted = untrusted;
    v.in_use = true;
    v
}
