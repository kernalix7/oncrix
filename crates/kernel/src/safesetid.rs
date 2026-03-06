// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! SafeSetID Linux Security Module — UID/GID transition allowlisting.
//!
//! SafeSetID restricts which UID and GID transitions are permitted
//! when a process calls `setuid(2)`, `setgid(2)`, `setreuid(2)`,
//! `setregid(2)`, or similar credential-changing system calls. By
//! default, a process with `CAP_SETUID` or `CAP_SETGID` can switch
//! to **any** UID or GID. SafeSetID constrains this to an explicit
//! allowlist of `(from_id, to_id)` transitions.
//!
//! # Policy Model
//!
//! The policy is a set of `(source, target)` ID transition rules.
//! A UID or GID transition is permitted only if:
//!
//! 1. The policy is not enforcing (disabled), OR
//! 2. There is no rule for the source ID (unmanaged — pass through
//!    to normal capability checks), OR
//! 3. An explicit `(source, target)` rule exists.
//!
//! When the source ID appears in at least one rule but the
//! `(source, target)` pair does not exist, the transition is
//! **denied** — even if the process holds `CAP_SETUID`/`CAP_SETGID`.
//!
//! This prevents a compromised daemon running as a specific service
//! UID from escalating to root or other sensitive UIDs.
//!
//! # Architecture
//!
//! ```text
//!  SafeSetIdSubsystem
//!   ├── uid_policy: IdTransitionPolicy
//!   ├── gid_policy: IdTransitionPolicy
//!   ├── audit_log: [SafeSetIdAuditEntry; MAX_AUDIT_ENTRIES]
//!   └── stats: SafeSetIdStats
//! ```
//!
//! Reference: Linux `security/safesetid/`.

use oncrix_lib::{Error, Result};

// ── Constants ─────────────────────────────────────────────────────

/// Maximum number of transition rules per policy (UID or GID).
const MAX_RULES: usize = 128;

/// Maximum number of audit log entries.
const MAX_AUDIT_ENTRIES: usize = 256;

// ── PolicyMode ───────────────────────────────────────────────────

/// Operating mode for the SafeSetID subsystem.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PolicyMode {
    /// Enforcing: deny transitions not in the allowlist.
    #[default]
    Enforcing,
    /// Permissive: log violations but allow all transitions.
    Permissive,
    /// Disabled: no checks are performed.
    Disabled,
}

// ── IdType ───────────────────────────────────────────────────────

/// The type of identifier being transitioned.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum IdType {
    /// User ID transition.
    #[default]
    Uid,
    /// Group ID transition.
    Gid,
}

// ── IdTransitionRule ─────────────────────────────────────────────

/// A single `(source_id, target_id)` transition rule.
///
/// When a process running as `source_id` attempts to transition to
/// `target_id`, this rule explicitly permits the transition.
#[derive(Debug, Clone, Copy)]
pub struct IdTransitionRule {
    /// The current UID/GID of the process.
    pub source_id: u32,
    /// The target UID/GID the process wants to transition to.
    pub target_id: u32,
    /// Whether this rule slot is active.
    pub active: bool,
}

impl IdTransitionRule {
    /// Create an empty, inactive rule.
    const fn empty() -> Self {
        Self {
            source_id: 0,
            target_id: 0,
            active: false,
        }
    }
}

// ── IdTransitionPolicy ───────────────────────────────────────────

/// A set of `(source, target)` ID transition rules.
///
/// Manages the allowlist for either UID or GID transitions.
pub struct IdTransitionPolicy {
    /// Fixed-size array of transition rules.
    rules: [IdTransitionRule; MAX_RULES],
    /// Number of active rules.
    rule_count: usize,
    /// The type of ID this policy manages.
    id_type: IdType,
}

impl IdTransitionPolicy {
    /// Create an empty policy for the given ID type.
    const fn new(id_type: IdType) -> Self {
        Self {
            rules: [IdTransitionRule::empty(); MAX_RULES],
            rule_count: 0,
            id_type,
        }
    }

    /// Add a transition rule `(source, target)`.
    ///
    /// Duplicate rules are silently ignored.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the rule table is full.
    fn add_rule(&mut self, source_id: u32, target_id: u32) -> Result<()> {
        // Check for duplicate.
        if self.has_rule(source_id, target_id) {
            return Ok(());
        }
        if self.rule_count >= MAX_RULES {
            return Err(Error::OutOfMemory);
        }
        // Find a free slot.
        let mut i = 0;
        while i < MAX_RULES {
            if !self.rules[i].active {
                self.rules[i] = IdTransitionRule {
                    source_id,
                    target_id,
                    active: true,
                };
                self.rule_count = self.rule_count.saturating_add(1);
                return Ok(());
            }
            i = i.saturating_add(1);
        }
        Err(Error::OutOfMemory)
    }

    /// Remove a transition rule.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the rule does not exist.
    fn remove_rule(&mut self, source_id: u32, target_id: u32) -> Result<()> {
        let mut i = 0;
        while i < MAX_RULES {
            if self.rules[i].active
                && self.rules[i].source_id == source_id
                && self.rules[i].target_id == target_id
            {
                self.rules[i].active = false;
                self.rule_count = self.rule_count.saturating_sub(1);
                return Ok(());
            }
            i = i.saturating_add(1);
        }
        Err(Error::NotFound)
    }

    /// Check whether a specific `(source, target)` rule exists.
    fn has_rule(&self, source_id: u32, target_id: u32) -> bool {
        let mut i = 0;
        while i < MAX_RULES {
            if self.rules[i].active
                && self.rules[i].source_id == source_id
                && self.rules[i].target_id == target_id
            {
                return true;
            }
            i = i.saturating_add(1);
        }
        false
    }

    /// Check whether the source ID appears in any active rule.
    ///
    /// If the source is not managed by this policy, the transition
    /// should fall through to normal capability checks.
    fn is_managed(&self, source_id: u32) -> bool {
        let mut i = 0;
        while i < MAX_RULES {
            if self.rules[i].active && self.rules[i].source_id == source_id {
                return true;
            }
            i = i.saturating_add(1);
        }
        false
    }

    /// Check whether a transition from `source_id` to `target_id`
    /// is permitted.
    ///
    /// Returns:
    /// - `Ok(true)` if the transition is explicitly allowed.
    /// - `Ok(false)` if the source is managed but the transition is
    ///   not in the allowlist (deny).
    /// - `Err(())` (as `Ok(true)`) if the source is not managed
    ///   (pass-through to normal checks).
    fn check_transition(&self, source_id: u32, target_id: u32) -> TransitionResult {
        // Identity transition is always allowed.
        if source_id == target_id {
            return TransitionResult::Allowed;
        }
        // If the source is not in the policy, pass through.
        if !self.is_managed(source_id) {
            return TransitionResult::Unmanaged;
        }
        // Source is managed — check for an explicit allow rule.
        if self.has_rule(source_id, target_id) {
            TransitionResult::Allowed
        } else {
            TransitionResult::Denied
        }
    }

    /// Remove all rules and reset the policy.
    fn clear(&mut self) {
        let mut i = 0;
        while i < MAX_RULES {
            self.rules[i].active = false;
            i = i.saturating_add(1);
        }
        self.rule_count = 0;
    }

    /// Return the number of active rules.
    const fn len(&self) -> usize {
        self.rule_count
    }

    /// Return whether the policy has no rules.
    const fn is_empty(&self) -> bool {
        self.rule_count == 0
    }

    /// Return the ID type this policy manages.
    const fn id_type(&self) -> IdType {
        self.id_type
    }
}

// ── TransitionResult ─────────────────────────────────────────────

/// Internal result of a single policy check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TransitionResult {
    /// The transition is explicitly allowed.
    Allowed,
    /// The source is managed and the transition is denied.
    Denied,
    /// The source is not managed — defer to normal checks.
    Unmanaged,
}

// ── SafeSetIdAuditAction ─────────────────────────────────────────

/// Actions recorded in the SafeSetID audit log.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SafeSetIdAuditAction {
    /// A UID/GID transition was allowed.
    #[default]
    TransitionAllowed,
    /// A UID/GID transition was denied.
    TransitionDenied,
    /// A new transition rule was added.
    RuleAdded,
    /// A transition rule was removed.
    RuleRemoved,
    /// The policy mode was changed.
    ModeChanged,
}

// ── SafeSetIdAuditEntry ──────────────────────────────────────────

/// A single entry in the SafeSetID audit log.
#[derive(Debug, Clone, Copy)]
pub struct SafeSetIdAuditEntry {
    /// PID of the process performing the transition.
    pub pid: u64,
    /// Source UID/GID.
    pub source_id: u32,
    /// Target UID/GID.
    pub target_id: u32,
    /// Whether this is a UID or GID transition.
    pub id_type: IdType,
    /// The action that was audited.
    pub action: SafeSetIdAuditAction,
    /// Timestamp (kernel ticks) of the event.
    pub timestamp: u64,
    /// Whether this audit slot is in use.
    pub in_use: bool,
}

impl SafeSetIdAuditEntry {
    /// Create an empty, unused audit entry.
    const fn empty() -> Self {
        Self {
            pid: 0,
            source_id: 0,
            target_id: 0,
            id_type: IdType::Uid,
            action: SafeSetIdAuditAction::TransitionAllowed,
            timestamp: 0,
            in_use: false,
        }
    }
}

// ── SafeSetIdStats ───────────────────────────────────────────────

/// Cumulative statistics for the SafeSetID subsystem.
#[derive(Debug, Clone, Copy, Default)]
pub struct SafeSetIdStats {
    /// Number of UID transitions allowed.
    pub uid_allowed: u64,
    /// Number of UID transitions denied.
    pub uid_denied: u64,
    /// Number of GID transitions allowed.
    pub gid_allowed: u64,
    /// Number of GID transitions denied.
    pub gid_denied: u64,
    /// Number of transitions that were unmanaged (pass-through).
    pub unmanaged: u64,
}

// ── SafeSetIdSubsystem ───────────────────────────────────────────

/// The SafeSetID LSM subsystem controlling UID/GID transitions.
///
/// Manages separate allowlist policies for UID and GID transitions,
/// audit logging, and statistics.
pub struct SafeSetIdSubsystem {
    /// UID transition policy.
    uid_policy: IdTransitionPolicy,
    /// GID transition policy.
    gid_policy: IdTransitionPolicy,
    /// Operating mode.
    mode: PolicyMode,
    /// Ring buffer of audit entries.
    audit_log: [SafeSetIdAuditEntry; MAX_AUDIT_ENTRIES],
    /// Total number of audit entries recorded (may wrap).
    audit_count: usize,
    /// Cumulative statistics.
    stats: SafeSetIdStats,
    /// Whether the subsystem is enabled.
    enabled: bool,
}

impl Default for SafeSetIdSubsystem {
    fn default() -> Self {
        Self::new()
    }
}

impl SafeSetIdSubsystem {
    /// Create a new SafeSetID subsystem with empty policies.
    pub const fn new() -> Self {
        Self {
            uid_policy: IdTransitionPolicy::new(IdType::Uid),
            gid_policy: IdTransitionPolicy::new(IdType::Gid),
            mode: PolicyMode::Enforcing,
            audit_log: [SafeSetIdAuditEntry::empty(); MAX_AUDIT_ENTRIES],
            audit_count: 0,
            stats: SafeSetIdStats {
                uid_allowed: 0,
                uid_denied: 0,
                gid_allowed: 0,
                gid_denied: 0,
                unmanaged: 0,
            },
            enabled: true,
        }
    }

    // ── Mode management ──────────────────────────────────────────

    /// Return the current policy mode.
    pub const fn mode(&self) -> PolicyMode {
        self.mode
    }

    /// Set the policy mode.
    pub fn set_mode(&mut self, mode: PolicyMode, timestamp: u64) {
        self.mode = mode;
        self.record_audit(
            0,
            0,
            0,
            IdType::Uid,
            SafeSetIdAuditAction::ModeChanged,
            timestamp,
        );
    }

    // ── UID policy management ────────────────────────────────────

    /// Add a UID transition rule allowing `source_uid` to transition
    /// to `target_uid`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the UID rule table is full.
    pub fn add_uid_rule(&mut self, source_uid: u32, target_uid: u32, timestamp: u64) -> Result<()> {
        self.uid_policy.add_rule(source_uid, target_uid)?;
        self.record_audit(
            0,
            source_uid,
            target_uid,
            IdType::Uid,
            SafeSetIdAuditAction::RuleAdded,
            timestamp,
        );
        Ok(())
    }

    /// Remove a UID transition rule.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the rule does not exist.
    pub fn remove_uid_rule(
        &mut self,
        source_uid: u32,
        target_uid: u32,
        timestamp: u64,
    ) -> Result<()> {
        self.uid_policy.remove_rule(source_uid, target_uid)?;
        self.record_audit(
            0,
            source_uid,
            target_uid,
            IdType::Uid,
            SafeSetIdAuditAction::RuleRemoved,
            timestamp,
        );
        Ok(())
    }

    /// Clear all UID transition rules.
    pub fn clear_uid_policy(&mut self) {
        self.uid_policy.clear();
    }

    /// Return the number of active UID transition rules.
    pub const fn uid_rule_count(&self) -> usize {
        self.uid_policy.len()
    }

    // ── GID policy management ────────────────────────────────────

    /// Add a GID transition rule allowing `source_gid` to transition
    /// to `target_gid`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the GID rule table is full.
    pub fn add_gid_rule(&mut self, source_gid: u32, target_gid: u32, timestamp: u64) -> Result<()> {
        self.gid_policy.add_rule(source_gid, target_gid)?;
        self.record_audit(
            0,
            source_gid,
            target_gid,
            IdType::Gid,
            SafeSetIdAuditAction::RuleAdded,
            timestamp,
        );
        Ok(())
    }

    /// Remove a GID transition rule.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the rule does not exist.
    pub fn remove_gid_rule(
        &mut self,
        source_gid: u32,
        target_gid: u32,
        timestamp: u64,
    ) -> Result<()> {
        self.gid_policy.remove_rule(source_gid, target_gid)?;
        self.record_audit(
            0,
            source_gid,
            target_gid,
            IdType::Gid,
            SafeSetIdAuditAction::RuleRemoved,
            timestamp,
        );
        Ok(())
    }

    /// Clear all GID transition rules.
    pub fn clear_gid_policy(&mut self) {
        self.gid_policy.clear();
    }

    /// Return the number of active GID transition rules.
    pub const fn gid_rule_count(&self) -> usize {
        self.gid_policy.len()
    }

    // ── Transition checks (LSM hooks) ────────────────────────────

    /// Check whether a UID transition is permitted.
    ///
    /// This is the main LSM hook for `task_fix_setuid`. The result
    /// depends on the current mode and the UID allowlist.
    ///
    /// # Errors
    ///
    /// Returns [`Error::PermissionDenied`] if the transition is
    /// denied in enforcing mode.
    pub fn check_uid_transition(
        &mut self,
        pid: u64,
        current_uid: u32,
        target_uid: u32,
        timestamp: u64,
    ) -> Result<()> {
        self.check_transition(pid, current_uid, target_uid, IdType::Uid, timestamp)
    }

    /// Check whether a GID transition is permitted.
    ///
    /// This is the main LSM hook for `task_fix_setgid`. The result
    /// depends on the current mode and the GID allowlist.
    ///
    /// # Errors
    ///
    /// Returns [`Error::PermissionDenied`] if the transition is
    /// denied in enforcing mode.
    pub fn check_gid_transition(
        &mut self,
        pid: u64,
        current_gid: u32,
        target_gid: u32,
        timestamp: u64,
    ) -> Result<()> {
        self.check_transition(pid, current_gid, target_gid, IdType::Gid, timestamp)
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
    pub const fn stats(&self) -> &SafeSetIdStats {
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
    pub fn get_audit_entry(&self, index: usize) -> Option<&SafeSetIdAuditEntry> {
        self.audit_log.get(index).filter(|e| e.in_use)
    }

    /// Check whether a specific UID transition rule exists.
    pub fn has_uid_rule(&self, source_uid: u32, target_uid: u32) -> bool {
        self.uid_policy.has_rule(source_uid, target_uid)
    }

    /// Check whether a specific GID transition rule exists.
    pub fn has_gid_rule(&self, source_gid: u32, target_gid: u32) -> bool {
        self.gid_policy.has_rule(source_gid, target_gid)
    }

    // ── Internal helpers ─────────────────────────────────────────

    /// Unified transition check for both UID and GID.
    fn check_transition(
        &mut self,
        pid: u64,
        current_id: u32,
        target_id: u32,
        id_type: IdType,
        timestamp: u64,
    ) -> Result<()> {
        if !self.enabled || self.mode == PolicyMode::Disabled {
            return Ok(());
        }

        let policy = match id_type {
            IdType::Uid => &self.uid_policy,
            IdType::Gid => &self.gid_policy,
        };

        let result = policy.check_transition(current_id, target_id);

        match result {
            TransitionResult::Allowed => {
                self.increment_allowed(id_type);
                self.record_audit(
                    pid,
                    current_id,
                    target_id,
                    id_type,
                    SafeSetIdAuditAction::TransitionAllowed,
                    timestamp,
                );
                Ok(())
            }
            TransitionResult::Unmanaged => {
                self.stats.unmanaged = self.stats.unmanaged.saturating_add(1);
                Ok(())
            }
            TransitionResult::Denied => {
                self.increment_denied(id_type);
                self.record_audit(
                    pid,
                    current_id,
                    target_id,
                    id_type,
                    SafeSetIdAuditAction::TransitionDenied,
                    timestamp,
                );
                match self.mode {
                    PolicyMode::Enforcing => Err(Error::PermissionDenied),
                    PolicyMode::Permissive | PolicyMode::Disabled => Ok(()),
                }
            }
        }
    }

    /// Increment the allowed counter for the given ID type.
    fn increment_allowed(&mut self, id_type: IdType) {
        match id_type {
            IdType::Uid => {
                self.stats.uid_allowed = self.stats.uid_allowed.saturating_add(1);
            }
            IdType::Gid => {
                self.stats.gid_allowed = self.stats.gid_allowed.saturating_add(1);
            }
        }
    }

    /// Increment the denied counter for the given ID type.
    fn increment_denied(&mut self, id_type: IdType) {
        match id_type {
            IdType::Uid => {
                self.stats.uid_denied = self.stats.uid_denied.saturating_add(1);
            }
            IdType::Gid => {
                self.stats.gid_denied = self.stats.gid_denied.saturating_add(1);
            }
        }
    }

    /// Record an audit entry in the ring buffer.
    fn record_audit(
        &mut self,
        pid: u64,
        source_id: u32,
        target_id: u32,
        id_type: IdType,
        action: SafeSetIdAuditAction,
        timestamp: u64,
    ) {
        let idx = self.audit_count % MAX_AUDIT_ENTRIES;
        self.audit_log[idx] = SafeSetIdAuditEntry {
            pid,
            source_id,
            target_id,
            id_type,
            action,
            timestamp,
            in_use: true,
        };
        self.audit_count = self.audit_count.saturating_add(1);
    }
}
