// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! LoadPin Linux Security Module — trusted filesystem enforcement for
//! kernel module and firmware loading.
//!
//! LoadPin ensures that all kernel modules, firmware blobs, and other
//! security-sensitive payloads originate from the **same** filesystem
//! (identified by device ID) that provided the first such payload.
//! This prevents an attacker who gains write access to a secondary
//! filesystem from injecting malicious modules or firmware.
//!
//! # Policy Model
//!
//! 1. On the first `kernel_load_data` or `kernel_read_file` call,
//!    LoadPin records the device ID of the source filesystem as the
//!    **trusted root**.
//! 2. All subsequent loads must originate from a filesystem with the
//!    same device ID. Any load from a different device is denied.
//! 3. Optionally, an explicit trusted device ID can be set before
//!    the first load, pinning the root manually.
//! 4. A set of **exempt content types** can be configured to bypass
//!    the device check (e.g., allowing firmware from tmpfs during
//!    early boot).
//!
//! # Content Types
//!
//! LoadPin classifies loaded content into types matching the Linux
//! kernel's `kernel_load_data_id` and `kernel_read_file_id` enums:
//!
//! - Kernel modules (`*.ko`)
//! - Firmware blobs
//! - kexec images
//! - Security policy files
//! - x.509 certificates
//!
//! # Architecture
//!
//! ```text
//!  LoadPinSubsystem
//!   ├── trusted_dev: Option<DeviceId>
//!   ├── pinned: bool
//!   ├── exemptions: ContentTypeMask
//!   ├── audit_log: [LoadPinAuditEntry; MAX_AUDIT_ENTRIES]
//!   └── stats: LoadPinStats
//! ```
//!
//! Reference: Linux `security/loadpin/loadpin.c`.

use oncrix_lib::{Error, Result};

// ── Constants ─────────────────────────────────────────────────────

/// Maximum number of audit log entries.
const MAX_AUDIT_ENTRIES: usize = 256;

/// Maximum length of a path stored in audit entries.
const PATH_LEN: usize = 128;

// ── DeviceId ─────────────────────────────────────────────────────

/// A filesystem device identifier.
///
/// Combines a major and minor number, mirroring the Linux `dev_t`
/// representation. Used to identify the trusted root filesystem.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct DeviceId {
    /// Major device number.
    pub major: u32,
    /// Minor device number.
    pub minor: u32,
}

impl DeviceId {
    /// Create a new device ID.
    pub const fn new(major: u32, minor: u32) -> Self {
        Self { major, minor }
    }

    /// Return the combined `dev_t`-style value.
    pub const fn raw(&self) -> u64 {
        ((self.major as u64) << 20) | (self.minor as u64)
    }
}

// ── ContentType ──────────────────────────────────────────────────

/// Classification of loaded content, matching the Linux kernel's
/// `kernel_load_data_id` / `kernel_read_file_id` values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContentType {
    /// Kernel module (`.ko` file).
    KernelModule = 0,
    /// Firmware blob.
    Firmware = 1,
    /// kexec image for live kernel replacement.
    KexecImage = 2,
    /// kexec initramfs.
    KexecInitramfs = 3,
    /// Security policy (SELinux, AppArmor, etc.).
    SecurityPolicy = 4,
    /// X.509 certificate for key ring.
    X509Certificate = 5,
}

impl ContentType {
    /// Return the bit position for this content type in a
    /// [`ContentTypeMask`].
    const fn bit(self) -> u32 {
        1 << (self as u32)
    }

    /// Create a content type from its integer value.
    pub const fn from_u32(val: u32) -> Option<Self> {
        match val {
            0 => Some(Self::KernelModule),
            1 => Some(Self::Firmware),
            2 => Some(Self::KexecImage),
            3 => Some(Self::KexecInitramfs),
            4 => Some(Self::SecurityPolicy),
            5 => Some(Self::X509Certificate),
            _ => None,
        }
    }
}

// ── ContentTypeMask ──────────────────────────────────────────────

/// A bitmask of [`ContentType`] values indicating which types are
/// exempt from the LoadPin device check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ContentTypeMask {
    /// Raw bitmask.
    bits: u32,
}

impl ContentTypeMask {
    /// Create an empty mask (no exemptions).
    pub const fn empty() -> Self {
        Self { bits: 0 }
    }

    /// Create a mask from a raw bitmask.
    pub const fn from_raw(bits: u32) -> Self {
        Self { bits }
    }

    /// Add an exemption for a content type.
    pub fn exempt(&mut self, ct: ContentType) {
        self.bits |= ct.bit();
    }

    /// Remove an exemption for a content type.
    pub fn unexempt(&mut self, ct: ContentType) {
        self.bits &= !ct.bit();
    }

    /// Check whether a content type is exempt.
    pub const fn is_exempt(&self, ct: ContentType) -> bool {
        (self.bits & ct.bit()) != 0
    }

    /// Check whether no types are exempt.
    pub const fn is_empty(&self) -> bool {
        self.bits == 0
    }

    /// Return the raw bitmask.
    pub const fn raw(&self) -> u32 {
        self.bits
    }
}

// ── LoadPinMode ──────────────────────────────────────────────────

/// Operating mode for the LoadPin subsystem.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum LoadPinMode {
    /// Enforcing: deny loads from non-trusted devices.
    #[default]
    Enforcing,
    /// Permissive: log violations but allow all loads.
    Permissive,
    /// Disabled: no checks are performed.
    Disabled,
}

// ── LoadPinAuditAction ───────────────────────────────────────────

/// Actions recorded in the LoadPin audit log.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum LoadPinAuditAction {
    /// A load was allowed (device matched or type exempt).
    #[default]
    LoadAllowed,
    /// A load was denied (device mismatch, not exempt).
    LoadDenied,
    /// The trusted root device was pinned (first load).
    DevicePinned,
    /// The trusted root device was explicitly set.
    DeviceSet,
    /// A content type exemption was added.
    ExemptionAdded,
    /// A content type exemption was removed.
    ExemptionRemoved,
}

// ── LoadPinAuditEntry ────────────────────────────────────────────

/// A single entry in the LoadPin audit log.
#[derive(Debug, Clone, Copy)]
pub struct LoadPinAuditEntry {
    /// The content type of the load.
    pub content_type: ContentType,
    /// Device ID of the source filesystem.
    pub source_dev: DeviceId,
    /// Path of the loaded file (truncated to [`PATH_LEN`]).
    pub path: [u8; PATH_LEN],
    /// Valid length of the path.
    pub path_len: usize,
    /// The action that was audited.
    pub action: LoadPinAuditAction,
    /// Timestamp (kernel ticks) of the event.
    pub timestamp: u64,
    /// Whether this audit slot is in use.
    pub in_use: bool,
}

impl LoadPinAuditEntry {
    /// Create an empty, unused audit entry.
    const fn empty() -> Self {
        Self {
            content_type: ContentType::KernelModule,
            source_dev: DeviceId { major: 0, minor: 0 },
            path: [0u8; PATH_LEN],
            path_len: 0,
            action: LoadPinAuditAction::LoadAllowed,
            timestamp: 0,
            in_use: false,
        }
    }
}

// ── LoadPinStats ─────────────────────────────────────────────────

/// Cumulative statistics for the LoadPin subsystem.
#[derive(Debug, Clone, Copy, Default)]
pub struct LoadPinStats {
    /// Number of loads allowed.
    pub allowed: u64,
    /// Number of loads denied.
    pub denied: u64,
    /// Number of loads allowed due to type exemption.
    pub exempt_allowed: u64,
    /// Number of loads allowed in permissive mode despite mismatch.
    pub permissive_allowed: u64,
}

// ── LoadRequest ──────────────────────────────────────────────────

/// A request to load a kernel module, firmware, or other content.
///
/// Passed by the caller to [`LoadPinSubsystem::check_load`] with
/// information about the source filesystem and content type.
#[derive(Debug, Clone, Copy)]
pub struct LoadRequest<'a> {
    /// The type of content being loaded.
    pub content_type: ContentType,
    /// Device ID of the filesystem the content resides on.
    pub source_dev: DeviceId,
    /// Path to the file being loaded (for audit).
    pub path: &'a [u8],
}

// ── LoadPinSubsystem ─────────────────────────────────────────────

/// The LoadPin LSM subsystem controlling module and firmware
/// loading.
///
/// Ensures all security-sensitive payloads originate from the same
/// trusted filesystem, preventing injection from untrusted media.
pub struct LoadPinSubsystem {
    /// Device ID of the trusted root filesystem, if pinned.
    trusted_dev: Option<DeviceId>,
    /// Whether the trusted device has been pinned.
    pinned: bool,
    /// Content types exempt from the device check.
    exemptions: ContentTypeMask,
    /// Operating mode.
    mode: LoadPinMode,
    /// Ring buffer of audit entries.
    audit_log: [LoadPinAuditEntry; MAX_AUDIT_ENTRIES],
    /// Total number of audit entries recorded (may wrap).
    audit_count: usize,
    /// Cumulative statistics.
    stats: LoadPinStats,
    /// Whether the subsystem is enabled.
    enabled: bool,
}

impl Default for LoadPinSubsystem {
    fn default() -> Self {
        Self::new()
    }
}

impl LoadPinSubsystem {
    /// Create a new LoadPin subsystem with no trusted root.
    pub const fn new() -> Self {
        Self {
            trusted_dev: None,
            pinned: false,
            exemptions: ContentTypeMask::empty(),
            mode: LoadPinMode::Enforcing,
            audit_log: [LoadPinAuditEntry::empty(); MAX_AUDIT_ENTRIES],
            audit_count: 0,
            stats: LoadPinStats {
                allowed: 0,
                denied: 0,
                exempt_allowed: 0,
                permissive_allowed: 0,
            },
            enabled: true,
        }
    }

    // ── Trusted device management ────────────────────────────────

    /// Explicitly set the trusted root device.
    ///
    /// This can only be called before the first load pins the
    /// device automatically. Once pinned, the trusted device
    /// cannot be changed.
    ///
    /// # Errors
    ///
    /// Returns [`Error::PermissionDenied`] if the device is already
    /// pinned.
    pub fn set_trusted_device(&mut self, dev: DeviceId, timestamp: u64) -> Result<()> {
        if self.pinned {
            return Err(Error::PermissionDenied);
        }
        self.trusted_dev = Some(dev);
        self.pinned = true;
        self.record_audit_simple(
            ContentType::KernelModule,
            dev,
            &[],
            LoadPinAuditAction::DeviceSet,
            timestamp,
        );
        Ok(())
    }

    /// Return the trusted device, if pinned.
    pub const fn trusted_device(&self) -> Option<&DeviceId> {
        self.trusted_dev.as_ref()
    }

    /// Return whether the trusted device has been pinned.
    pub const fn is_pinned(&self) -> bool {
        self.pinned
    }

    // ── Exemption management ─────────────────────────────────────

    /// Add a content type exemption.
    ///
    /// Exempt content types bypass the device check entirely. This
    /// is useful for firmware loaded from tmpfs during early boot.
    pub fn add_exemption(&mut self, ct: ContentType, timestamp: u64) {
        self.exemptions.exempt(ct);
        self.record_audit_simple(
            ct,
            DeviceId::new(0, 0),
            &[],
            LoadPinAuditAction::ExemptionAdded,
            timestamp,
        );
    }

    /// Remove a content type exemption.
    pub fn remove_exemption(&mut self, ct: ContentType, timestamp: u64) {
        self.exemptions.unexempt(ct);
        self.record_audit_simple(
            ct,
            DeviceId::new(0, 0),
            &[],
            LoadPinAuditAction::ExemptionRemoved,
            timestamp,
        );
    }

    /// Check whether a content type is exempt from the device check.
    pub const fn is_exempt(&self, ct: ContentType) -> bool {
        self.exemptions.is_exempt(ct)
    }

    /// Return the exemption mask.
    pub const fn exemptions(&self) -> &ContentTypeMask {
        &self.exemptions
    }

    // ── Mode management ──────────────────────────────────────────

    /// Return the current operating mode.
    pub const fn mode(&self) -> LoadPinMode {
        self.mode
    }

    /// Set the operating mode.
    pub fn set_mode(&mut self, mode: LoadPinMode) {
        self.mode = mode;
    }

    // ── Load check (main LSM hook) ───────────────────────────────

    /// Check whether a load request is permitted.
    ///
    /// This is the main LSM hook for `kernel_load_data` and
    /// `kernel_read_file`. The decision logic:
    ///
    /// 1. If disabled or the subsystem is off, allow.
    /// 2. If the content type is exempt, allow.
    /// 3. If no device is pinned yet, pin the source device and
    ///    allow.
    /// 4. If the source device matches the trusted device, allow.
    /// 5. Otherwise, deny (enforcing) or log (permissive).
    ///
    /// # Errors
    ///
    /// Returns [`Error::PermissionDenied`] if the load is denied in
    /// enforcing mode.
    pub fn check_load(&mut self, request: &LoadRequest<'_>, timestamp: u64) -> Result<()> {
        if !self.enabled || self.mode == LoadPinMode::Disabled {
            return Ok(());
        }

        // Exempt content types bypass the check.
        if self.exemptions.is_exempt(request.content_type) {
            self.stats.exempt_allowed = self.stats.exempt_allowed.saturating_add(1);
            self.stats.allowed = self.stats.allowed.saturating_add(1);
            self.record_audit_simple(
                request.content_type,
                request.source_dev,
                request.path,
                LoadPinAuditAction::LoadAllowed,
                timestamp,
            );
            return Ok(());
        }

        // Pin on first load.
        if !self.pinned {
            self.trusted_dev = Some(request.source_dev);
            self.pinned = true;
            self.record_audit_simple(
                request.content_type,
                request.source_dev,
                request.path,
                LoadPinAuditAction::DevicePinned,
                timestamp,
            );
            self.stats.allowed = self.stats.allowed.saturating_add(1);
            return Ok(());
        }

        // Check device match.
        let trusted = match self.trusted_dev {
            Some(dev) => dev,
            None => {
                // Should not happen if pinned is true, but fail
                // closed.
                self.stats.denied = self.stats.denied.saturating_add(1);
                return Err(Error::PermissionDenied);
            }
        };

        if request.source_dev == trusted {
            self.stats.allowed = self.stats.allowed.saturating_add(1);
            self.record_audit_simple(
                request.content_type,
                request.source_dev,
                request.path,
                LoadPinAuditAction::LoadAllowed,
                timestamp,
            );
            Ok(())
        } else {
            // Device mismatch.
            self.record_audit_simple(
                request.content_type,
                request.source_dev,
                request.path,
                LoadPinAuditAction::LoadDenied,
                timestamp,
            );
            match self.mode {
                LoadPinMode::Enforcing => {
                    self.stats.denied = self.stats.denied.saturating_add(1);
                    Err(Error::PermissionDenied)
                }
                LoadPinMode::Permissive => {
                    self.stats.permissive_allowed = self.stats.permissive_allowed.saturating_add(1);
                    self.stats.allowed = self.stats.allowed.saturating_add(1);
                    Ok(())
                }
                LoadPinMode::Disabled => Ok(()),
            }
        }
    }

    // ── Query ────────────────────────────────────────────────────

    /// Return whether the subsystem is enabled.
    pub const fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Enable the subsystem.
    pub fn enable(&mut self) {
        self.enabled = true;
    }

    /// Disable the subsystem.
    pub fn disable(&mut self) {
        self.enabled = false;
    }

    /// Return a reference to the cumulative statistics.
    pub const fn stats(&self) -> &LoadPinStats {
        &self.stats
    }

    /// Return the total number of audit entries recorded.
    pub const fn audit_count(&self) -> usize {
        self.audit_count
    }

    /// Return a reference to the audit entry at `index`.
    ///
    /// Returns `None` if the index is out of bounds or the entry is
    /// not in use.
    pub fn get_audit_entry(&self, index: usize) -> Option<&LoadPinAuditEntry> {
        self.audit_log.get(index).filter(|e| e.in_use)
    }

    // ── Internal helpers ─────────────────────────────────────────

    /// Record an audit entry in the ring buffer.
    fn record_audit_simple(
        &mut self,
        content_type: ContentType,
        source_dev: DeviceId,
        path: &[u8],
        action: LoadPinAuditAction,
        timestamp: u64,
    ) {
        let idx = self.audit_count % MAX_AUDIT_ENTRIES;
        let mut entry = LoadPinAuditEntry::empty();
        entry.content_type = content_type;
        entry.source_dev = source_dev;
        let copy_len = path.len().min(PATH_LEN);
        entry.path[..copy_len].copy_from_slice(&path[..copy_len]);
        entry.path_len = copy_len;
        entry.action = action;
        entry.timestamp = timestamp;
        entry.in_use = true;
        self.audit_log[idx] = entry;
        self.audit_count = self.audit_count.saturating_add(1);
    }
}
