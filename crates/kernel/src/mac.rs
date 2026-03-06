// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! SELinux-style Mandatory Access Control (MAC) framework.
//!
//! Provides a label-based access control mechanism where every subject
//! (process) and object (file, socket, IPC endpoint) carries a
//! **security context** of the form `user:role:type:level`. Access
//! decisions are determined by a loaded policy that maps
//! `(source_type, target_type, object_class)` triples to allowed
//! permission vectors.
//!
//! Operating modes:
//! - **Enforcing**: denials are enforced and audited.
//! - **Permissive**: denials are logged but not enforced.
//! - **Disabled**: MAC checks are bypassed entirely.
//!
//! Reference: Linux `security/selinux/`, SELinux policy language.

use oncrix_lib::{Error, Result};

// ── Constants ─────────────────────────────────────────────────────

/// Maximum number of rules in a single MAC policy.
pub const MAX_MAC_RULES: usize = 128;

/// Maximum number of audit log entries.
pub const MAX_AUDIT_ENTRIES: usize = 256;

// ── MacMode ───────────────────────────────────────────────────────

/// Operating mode for the MAC subsystem.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum MacMode {
    /// Policy is enforced — denials block access and are audited.
    #[default]
    Enforcing,
    /// Policy violations are logged but access is still granted.
    Permissive,
    /// MAC is completely disabled — all checks return allowed.
    Disabled,
}

// ── MacPermission ─────────────────────────────────────────────────

/// Individual permission types for MAC access decisions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum MacPermission {
    /// Read access.
    #[default]
    Read,
    /// Write access.
    Write,
    /// Execute access.
    Execute,
    /// Create a new object.
    Create,
    /// Delete an existing object.
    Delete,
    /// Change the security label of an object.
    Relabel,
    /// Transition to a different security domain.
    Transition,
    /// Send a signal to a process.
    Signal,
    /// Bind a socket to an address.
    Bind,
    /// Initiate a network connection.
    Connect,
}

impl MacPermission {
    /// Return the bit position for this permission in an [`AccessVector`].
    const fn bit(self) -> u32 {
        1 << (self as u32)
    }
}

// ── AccessVector ──────────────────────────────────────────────────

/// A bitfield of [`MacPermission`] values.
///
/// Each bit corresponds to one permission variant, allowing compact
/// representation of multiple allowed operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct AccessVector {
    /// Raw permission bitmask.
    pub permissions: u32,
}

impl AccessVector {
    /// Create an empty access vector (no permissions).
    pub const fn empty() -> Self {
        Self { permissions: 0 }
    }

    /// Create an access vector from a raw bitmask.
    pub const fn from_raw(bits: u32) -> Self {
        Self { permissions: bits }
    }

    /// Add a permission to this vector.
    pub fn grant(&mut self, perm: MacPermission) {
        self.permissions |= perm.bit();
    }

    /// Remove a permission from this vector.
    pub fn revoke(&mut self, perm: MacPermission) {
        self.permissions &= !perm.bit();
    }

    /// Check whether a specific permission is present.
    pub const fn contains(&self, perm_bit: u32) -> bool {
        (self.permissions & perm_bit) == perm_bit
    }

    /// Check whether this vector has no permissions.
    pub const fn is_empty(&self) -> bool {
        self.permissions == 0
    }
}

// ── SecurityContext ───────────────────────────────────────────────

/// A security label attached to every subject and object.
///
/// Follows the SELinux convention: `user:role:type:level`.
/// Fields are stored as fixed-size byte arrays to avoid heap allocation.
#[derive(Debug, Clone, Copy, Default)]
pub struct SecurityContext {
    /// SELinux user identity.
    pub user: [u8; 32],
    /// Length of the user string.
    pub user_len: usize,
    /// SELinux role.
    pub role: [u8; 32],
    /// Length of the role string.
    pub role_len: usize,
    /// SELinux type (domain for subjects, type for objects).
    pub type_field: [u8; 32],
    /// Length of the type string.
    pub type_len: usize,
    /// MLS/MCS security level.
    pub level: [u8; 16],
    /// Length of the level string.
    pub level_len: usize,
}

impl SecurityContext {
    /// Create a new security context from string slices.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if any field exceeds the
    /// fixed buffer size.
    pub fn new(user: &[u8], role: &[u8], type_field: &[u8], level: &[u8]) -> Result<Self> {
        if user.len() > 32 || role.len() > 32 || type_field.len() > 32 || level.len() > 16 {
            return Err(Error::InvalidArgument);
        }
        let mut ctx = Self::default();
        ctx.user[..user.len()].copy_from_slice(user);
        ctx.user_len = user.len();
        ctx.role[..role.len()].copy_from_slice(role);
        ctx.role_len = role.len();
        ctx.type_field[..type_field.len()].copy_from_slice(type_field);
        ctx.type_len = type_field.len();
        ctx.level[..level.len()].copy_from_slice(level);
        ctx.level_len = level.len();
        Ok(ctx)
    }

    /// Return the type field as a byte slice.
    pub fn type_bytes(&self) -> &[u8] {
        &self.type_field[..self.type_len]
    }
}

// ── MacRule ───────────────────────────────────────────────────────

/// A single MAC policy rule.
///
/// Maps a `(source_type, target_type, object_class)` triple to an
/// [`AccessVector`] of allowed permissions.
#[derive(Debug, Clone, Copy)]
pub struct MacRule {
    /// Type label of the source (subject).
    pub source_type: [u8; 32],
    /// Length of the source type string.
    pub source_len: usize,
    /// Type label of the target (object).
    pub target_type: [u8; 32],
    /// Length of the target type string.
    pub target_len: usize,
    /// Object class (e.g., `file`, `process`, `socket`).
    pub obj_class: [u8; 16],
    /// Length of the object class string.
    pub class_len: usize,
    /// Allowed permissions for this triple.
    pub allowed: AccessVector,
    /// Whether to generate an audit record on access.
    pub audit: bool,
    /// Whether this rule slot is active.
    pub active: bool,
}

impl MacRule {
    /// Create an empty, inactive rule.
    const fn empty() -> Self {
        Self {
            source_type: [0u8; 32],
            source_len: 0,
            target_type: [0u8; 32],
            target_len: 0,
            obj_class: [0u8; 16],
            class_len: 0,
            allowed: AccessVector::empty(),
            audit: false,
            active: false,
        }
    }

    /// Check whether this rule matches the given triple.
    fn matches(&self, source: &[u8], target: &[u8], class: &[u8]) -> bool {
        self.active
            && self.source_len == source.len()
            && self.target_len == target.len()
            && self.class_len == class.len()
            && self.source_type[..self.source_len] == *source
            && self.target_type[..self.target_len] == *target
            && self.obj_class[..self.class_len] == *class
    }
}

// ── MacPolicy ─────────────────────────────────────────────────────

/// A loaded MAC policy containing rules and operational mode.
pub struct MacPolicy {
    /// Fixed-size array of policy rules.
    rules: [MacRule; MAX_MAC_RULES],
    /// Number of active rules.
    rule_count: usize,
    /// Current enforcement mode.
    pub mode: MacMode,
    /// Policy version number.
    pub version: u32,
}

impl Default for MacPolicy {
    fn default() -> Self {
        Self::new()
    }
}

impl MacPolicy {
    /// Create an empty policy in enforcing mode.
    pub const fn new() -> Self {
        const EMPTY: MacRule = MacRule::empty();
        Self {
            rules: [EMPTY; MAX_MAC_RULES],
            rule_count: 0,
            mode: MacMode::Enforcing,
            version: 0,
        }
    }

    /// Add a rule to the policy.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the policy already contains
    /// [`MAX_MAC_RULES`] rules.
    pub fn add_rule(&mut self, rule: MacRule) -> Result<()> {
        if self.rule_count >= MAX_MAC_RULES {
            return Err(Error::OutOfMemory);
        }
        self.rules[self.rule_count] = rule;
        self.rules[self.rule_count].active = true;
        self.rule_count = self.rule_count.saturating_add(1);
        Ok(())
    }

    /// Remove the rule at `index` by marking it inactive.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `index` is out of bounds
    /// or the slot is already inactive.
    pub fn remove_rule(&mut self, index: usize) -> Result<()> {
        if index >= self.rule_count {
            return Err(Error::InvalidArgument);
        }
        let rule = &mut self.rules[index];
        if !rule.active {
            return Err(Error::InvalidArgument);
        }
        rule.active = false;
        Ok(())
    }

    /// Check whether `perm` is allowed for the given triple.
    ///
    /// Iterates active rules looking for a match. Returns `Ok(true)` if
    /// a matching rule grants the permission, `Ok(false)` otherwise.
    pub fn check_access(
        &self,
        source: &[u8],
        target: &[u8],
        class: &[u8],
        perm: MacPermission,
    ) -> Result<bool> {
        let perm_bit = perm.bit();
        let mut i = 0;
        while i < self.rule_count {
            let rule = &self.rules[i];
            if rule.matches(source, target, class) && rule.allowed.contains(perm_bit) {
                return Ok(true);
            }
            i = i.saturating_add(1);
        }
        Ok(false)
    }

    /// Replace all rules with a new set.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if the slice exceeds
    /// [`MAX_MAC_RULES`].
    pub fn load_policy(&mut self, rules: &[MacRule]) -> Result<()> {
        if rules.len() > MAX_MAC_RULES {
            return Err(Error::InvalidArgument);
        }
        // Clear existing rules.
        const EMPTY: MacRule = MacRule::empty();
        self.rules = [EMPTY; MAX_MAC_RULES];
        let mut i = 0;
        while i < rules.len() {
            self.rules[i] = rules[i];
            self.rules[i].active = true;
            i = i.saturating_add(1);
        }
        self.rule_count = rules.len();
        self.version = self.version.saturating_add(1);
        Ok(())
    }

    /// Return the number of active rules.
    pub fn len(&self) -> usize {
        self.rule_count
    }

    /// Return whether the policy has no rules.
    pub fn is_empty(&self) -> bool {
        self.rule_count == 0
    }
}

// ── MacAuditEntry ─────────────────────────────────────────────────

/// A single entry in the MAC audit log.
#[derive(Debug, Clone, Copy, Default)]
pub struct MacAuditEntry {
    /// Security context of the subject.
    pub source_ctx: SecurityContext,
    /// Security context of the object.
    pub target_ctx: SecurityContext,
    /// The permission that was requested.
    pub permission: MacPermission,
    /// Whether the access was denied.
    pub denied: bool,
    /// Timestamp (kernel ticks or TSC) of the event.
    pub timestamp: u64,
    /// Whether this audit slot is in use.
    pub in_use: bool,
}

impl MacAuditEntry {
    /// Create an empty, unused audit entry.
    const fn empty() -> Self {
        Self {
            source_ctx: SecurityContext {
                user: [0u8; 32],
                user_len: 0,
                role: [0u8; 32],
                role_len: 0,
                type_field: [0u8; 32],
                type_len: 0,
                level: [0u8; 16],
                level_len: 0,
            },
            target_ctx: SecurityContext {
                user: [0u8; 32],
                user_len: 0,
                role: [0u8; 32],
                role_len: 0,
                type_field: [0u8; 32],
                type_len: 0,
                level: [0u8; 16],
                level_len: 0,
            },
            permission: MacPermission::Read,
            denied: false,
            timestamp: 0,
            in_use: false,
        }
    }
}

// ── MacSubsystem ──────────────────────────────────────────────────

/// The top-level MAC subsystem combining policy, audit, and control.
pub struct MacSubsystem {
    /// The loaded MAC policy.
    policy: MacPolicy,
    /// Ring buffer of audit entries.
    audit_log: [MacAuditEntry; MAX_AUDIT_ENTRIES],
    /// Number of audit entries recorded (may wrap).
    audit_count: usize,
    /// Whether the MAC subsystem is enabled.
    enabled: bool,
}

impl Default for MacSubsystem {
    fn default() -> Self {
        Self::new()
    }
}

impl MacSubsystem {
    /// Create a new MAC subsystem with an empty policy in enforcing mode.
    pub const fn new() -> Self {
        const EMPTY_AUDIT: MacAuditEntry = MacAuditEntry::empty();
        const EMPTY_RULE: MacRule = MacRule::empty();
        Self {
            policy: MacPolicy {
                rules: [EMPTY_RULE; MAX_MAC_RULES],
                rule_count: 0,
                mode: MacMode::Enforcing,
                version: 0,
            },
            audit_log: [EMPTY_AUDIT; MAX_AUDIT_ENTRIES],
            audit_count: 0,
            enabled: true,
        }
    }

    /// Check whether `perm` is allowed for the given source/target/class.
    ///
    /// In **Enforcing** mode, a denial returns `Ok(false)`.
    /// In **Permissive** mode, denials are logged but `Ok(true)` is
    /// returned. In **Disabled** mode, `Ok(true)` is always returned
    /// without logging.
    ///
    /// An audit entry is recorded for every decision when the
    /// subsystem is enabled and not disabled.
    pub fn check_permission(
        &mut self,
        source: &SecurityContext,
        target: &SecurityContext,
        class: &[u8],
        perm: MacPermission,
    ) -> Result<bool> {
        if !self.enabled || self.policy.mode == MacMode::Disabled {
            return Ok(true);
        }

        let allowed =
            self.policy
                .check_access(source.type_bytes(), target.type_bytes(), class, perm)?;

        let denied = !allowed;

        // Record audit entry.
        self.record_audit(*source, *target, perm, denied, 0);

        match self.policy.mode {
            MacMode::Enforcing => Ok(allowed),
            MacMode::Permissive => Ok(true),
            MacMode::Disabled => Ok(true),
        }
    }

    /// Set the enforcement mode.
    pub fn set_mode(&mut self, mode: MacMode) {
        self.policy.mode = mode;
    }

    /// Get the current enforcement mode.
    pub fn get_mode(&self) -> MacMode {
        self.policy.mode
    }

    /// Return a default security context for a given PID.
    ///
    /// In a full implementation this would look up the process table.
    /// Currently returns a placeholder context labelled with the PID.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if the context cannot be
    /// constructed.
    pub fn get_context_for_pid(&self, pid: u64) -> Result<SecurityContext> {
        // Encode the PID into the user field as a simple decimal string.
        let mut buf = [0u8; 32];
        let len = format_u64(pid, &mut buf);
        SecurityContext::new(&buf[..len], b"object_r", b"default_t", b"s0")
    }

    /// Perform a domain transition: produce a new context with a
    /// different type field while preserving user, role, and level.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `new_type` exceeds the
    /// type field buffer size.
    pub fn transition(
        &self,
        old_ctx: &SecurityContext,
        new_type: &[u8],
    ) -> Result<SecurityContext> {
        if new_type.len() > 32 {
            return Err(Error::InvalidArgument);
        }
        let mut ctx = *old_ctx;
        ctx.type_field = [0u8; 32];
        ctx.type_field[..new_type.len()].copy_from_slice(new_type);
        ctx.type_len = new_type.len();
        Ok(ctx)
    }

    /// Return the total number of audit entries recorded.
    pub fn audit_count(&self) -> usize {
        self.audit_count
    }

    /// Return a reference to the audit entry at `index`.
    ///
    /// Returns `None` if the index is out of bounds or the entry is
    /// not in use.
    pub fn get_audit_entry(&self, index: usize) -> Option<&MacAuditEntry> {
        self.audit_log.get(index).filter(|e| e.in_use)
    }

    /// Enable the MAC subsystem.
    pub fn enable(&mut self) {
        self.enabled = true;
    }

    /// Disable the MAC subsystem.
    pub fn disable(&mut self) {
        self.enabled = false;
    }

    /// Return the number of active policy rules.
    pub fn len(&self) -> usize {
        self.policy.len()
    }

    /// Return whether the policy has no rules.
    pub fn is_empty(&self) -> bool {
        self.policy.is_empty()
    }

    /// Return a mutable reference to the underlying policy.
    pub fn policy_mut(&mut self) -> &mut MacPolicy {
        &mut self.policy
    }

    /// Return a reference to the underlying policy.
    pub fn policy(&self) -> &MacPolicy {
        &self.policy
    }

    // ── Internal helpers ──────────────────────────────────────────

    /// Record an audit entry in the ring buffer.
    fn record_audit(
        &mut self,
        source: SecurityContext,
        target: SecurityContext,
        perm: MacPermission,
        denied: bool,
        timestamp: u64,
    ) {
        let idx = self.audit_count % MAX_AUDIT_ENTRIES;
        self.audit_log[idx] = MacAuditEntry {
            source_ctx: source,
            target_ctx: target,
            permission: perm,
            denied,
            timestamp,
            in_use: true,
        };
        self.audit_count = self.audit_count.saturating_add(1);
    }
}

// ── Helper: format u64 into decimal bytes ─────────────────────────

/// Format a `u64` as a decimal string into `buf`, returning the
/// number of bytes written.
fn format_u64(mut val: u64, buf: &mut [u8; 32]) -> usize {
    if val == 0 {
        buf[0] = b'0';
        return 1;
    }
    let mut tmp = [0u8; 20]; // max digits for u64
    let mut pos = 0usize;
    while val > 0 {
        tmp[pos] = b'0' + (val % 10) as u8;
        val /= 10;
        pos = pos.saturating_add(1);
    }
    // Reverse into buf.
    let mut i = 0;
    while i < pos {
        buf[i] = tmp[pos - 1 - i];
        i = i.saturating_add(1);
    }
    pos
}
