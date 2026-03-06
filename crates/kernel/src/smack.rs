// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Simplified Mandatory Access Control Kernel (SMACK).
//!
//! SMACK is a label-based mandatory access control (MAC) system.
//! Every subject (process) and object (file, IPC endpoint, etc.)
//! carries a [`SmackLabel`] — a short, fixed-size security label.
//! Access decisions are made by looking up a (subject, object)
//! pair in a [`SmackRuleSet`] and checking the requested
//! [`AccessType`] against the stored access mask.
//!
//! # Well-Known Labels
//!
//! | Label | Meaning |
//! |-------|---------|
//! | `_` (FLOOR) | Readable by all subjects |
//! | `^` (HAT) | Read-accessible to all subjects |
//! | `*` (STAR) | Has access to everything |
//! | `@` (WEB) | Internet-facing, minimal trust |
//!
//! # Default Policy
//!
//! If no explicit rule matches a (subject, object) pair, access
//! is **denied** (fail-closed). Special labels override this:
//! - A subject with the STAR label is granted all access.
//! - An object with the FLOOR label is readable by all subjects.
//!
//! # Label Inheritance
//!
//! On `fork()`, the child inherits the parent's SMACK label.
//! On `exec()`, the label may change if a transition rule is
//! defined; otherwise it is preserved.
//!
//! Reference: Linux `security/smack/`.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Maximum byte length of a SMACK label (matching Linux SMACK).
const SMACK_LABEL_LEN: usize = 23;

/// Maximum number of rules in a rule set.
const MAX_RULES: usize = 256;

/// Maximum number of label transition rules.
const MAX_TRANSITIONS: usize = 64;

/// Maximum number of per-PID label assignments.
const MAX_PID_LABELS: usize = 256;

// -------------------------------------------------------------------
// SmackLabel
// -------------------------------------------------------------------

/// A fixed-size SMACK security label (up to 23 bytes).
///
/// Labels are compared byte-for-byte. Two labels are equal if
/// and only if their content bytes and lengths match.
#[derive(Clone, Copy)]
pub struct SmackLabel {
    /// Label content (null-padded).
    bytes: [u8; SMACK_LABEL_LEN],
    /// Valid length of the label (0..=[`SMACK_LABEL_LEN`]).
    len: u8,
}

impl SmackLabel {
    /// The FLOOR label (`_`): readable by all subjects.
    pub const FLOOR: Self = Self::from_byte(b'_');

    /// The HAT label (`^`): read-accessible to all subjects.
    pub const HAT: Self = Self::from_byte(b'^');

    /// The STAR label (`*`): has access to everything.
    pub const STAR: Self = Self::from_byte(b'*');

    /// The WEB label (`@`): internet-facing, minimal trust.
    pub const WEB: Self = Self::from_byte(b'@');

    /// Create a label from a single ASCII byte (for well-known labels).
    const fn from_byte(b: u8) -> Self {
        let mut bytes = [0u8; SMACK_LABEL_LEN];
        bytes[0] = b;
        Self { bytes, len: 1 }
    }

    /// Create a label from a byte slice.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `name` is empty or
    /// exceeds [`SMACK_LABEL_LEN`] bytes.
    pub fn new(name: &[u8]) -> Result<Self> {
        if name.is_empty() || name.len() > SMACK_LABEL_LEN {
            return Err(Error::InvalidArgument);
        }
        let mut label = Self {
            bytes: [0u8; SMACK_LABEL_LEN],
            len: 0,
        };
        label.bytes[..name.len()].copy_from_slice(name);
        label.len = name.len() as u8;
        Ok(label)
    }

    /// Return the label content as a byte slice.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len as usize]
    }

    /// Return the length of the label in bytes.
    pub fn len(&self) -> usize {
        self.len as usize
    }

    /// Check if the label is empty.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Check if this is the STAR label.
    pub fn is_star(&self) -> bool {
        self.len == 1 && self.bytes[0] == b'*'
    }

    /// Check if this is the FLOOR label.
    pub fn is_floor(&self) -> bool {
        self.len == 1 && self.bytes[0] == b'_'
    }

    /// Check if this is the HAT label.
    pub fn is_hat(&self) -> bool {
        self.len == 1 && self.bytes[0] == b'^'
    }

    /// Constant-time label comparison.
    ///
    /// Returns `true` if both labels have the same length and
    /// identical content bytes, using constant-time comparison
    /// to prevent timing side-channels on label values.
    fn constant_eq(&self, other: &Self) -> bool {
        if self.len != other.len {
            return false;
        }
        let mut diff = 0u8;
        let mut i = 0;
        while i < SMACK_LABEL_LEN {
            diff |= self.bytes[i] ^ other.bytes[i];
            i += 1;
        }
        diff == 0
    }
}

impl PartialEq for SmackLabel {
    fn eq(&self, other: &Self) -> bool {
        self.constant_eq(other)
    }
}

impl Eq for SmackLabel {}

impl core::fmt::Debug for SmackLabel {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SmackLabel")
            .field("len", &self.len)
            .finish()
    }
}

// -------------------------------------------------------------------
// AccessType
// -------------------------------------------------------------------

/// Permission bits for SMACK access control decisions.
///
/// These are combined as a bitmask in each rule to specify which
/// operations are permitted on the object.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(transparent)]
pub struct AccessType(u8);

impl AccessType {
    /// No access.
    pub const NONE: Self = Self(0);
    /// Read permission.
    pub const READ: Self = Self(1 << 0);
    /// Write permission.
    pub const WRITE: Self = Self(1 << 1);
    /// Execute permission.
    pub const EXECUTE: Self = Self(1 << 2);
    /// Append permission.
    pub const APPEND: Self = Self(1 << 3);
    /// Transmute permission (change label on write).
    pub const TRANSMUTE: Self = Self(1 << 4);
    /// All permissions.
    pub const ALL: Self = Self(0x1F);

    /// Create from raw bits.
    pub const fn from_raw(bits: u8) -> Self {
        Self(bits)
    }

    /// Get the raw bitmask.
    pub const fn bits(self) -> u8 {
        self.0
    }

    /// Check if `self` contains all of `required`.
    pub const fn contains(self, required: Self) -> bool {
        (self.0 & required.0) == required.0
    }

    /// Check if no permissions are set.
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }
}

// -------------------------------------------------------------------
// AccessDecision
// -------------------------------------------------------------------

/// Result of a SMACK access check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessDecision {
    /// Access is allowed.
    Allow,
    /// Access is denied.
    Deny,
    /// Access is allowed but should be audited.
    Audit,
}

// -------------------------------------------------------------------
// SmackRule
// -------------------------------------------------------------------

/// A single SMACK access control rule.
///
/// Associates a (subject label, object label) pair with a set
/// of permitted access types and an optional audit flag.
#[derive(Debug, Clone, Copy)]
pub struct SmackRule {
    /// Subject (process) label.
    pub subject: SmackLabel,
    /// Object (resource) label.
    pub object: SmackLabel,
    /// Permitted access mask.
    pub access_mask: AccessType,
    /// Whether matching accesses should be audited.
    pub audit: bool,
    /// Whether this rule slot is active.
    pub active: bool,
}

impl SmackRule {
    /// Create an empty, inactive rule.
    const fn empty() -> Self {
        Self {
            subject: SmackLabel {
                bytes: [0u8; SMACK_LABEL_LEN],
                len: 0,
            },
            object: SmackLabel {
                bytes: [0u8; SMACK_LABEL_LEN],
                len: 0,
            },
            access_mask: AccessType::NONE,
            audit: false,
            active: false,
        }
    }

    /// Create a new rule.
    pub fn new(
        subject: SmackLabel,
        object: SmackLabel,
        access_mask: AccessType,
        audit: bool,
    ) -> Self {
        Self {
            subject,
            object,
            access_mask,
            audit,
            active: true,
        }
    }
}

// -------------------------------------------------------------------
// SmackTransition
// -------------------------------------------------------------------

/// A SMACK label transition rule for exec.
///
/// When a process with `subject_label` executes a binary labeled
/// `object_label`, its label changes to `new_label`.
#[derive(Debug, Clone, Copy)]
pub struct SmackTransition {
    /// Current process label.
    pub subject_label: SmackLabel,
    /// Binary label that triggers the transition.
    pub object_label: SmackLabel,
    /// Label to assign after exec.
    pub new_label: SmackLabel,
    /// Whether this slot is active.
    pub active: bool,
}

impl SmackTransition {
    /// Create an empty, inactive transition.
    const fn empty() -> Self {
        let empty_label = SmackLabel {
            bytes: [0u8; SMACK_LABEL_LEN],
            len: 0,
        };
        Self {
            subject_label: empty_label,
            object_label: empty_label,
            new_label: empty_label,
            active: false,
        }
    }
}

// -------------------------------------------------------------------
// PidLabel
// -------------------------------------------------------------------

/// Maps a PID to its SMACK label.
#[derive(Debug, Clone, Copy)]
struct PidLabel {
    /// Process ID.
    pid: u64,
    /// SMACK label assigned to this process.
    label: SmackLabel,
    /// Whether this slot is in use.
    active: bool,
}

impl PidLabel {
    /// Create an empty, inactive entry.
    const fn empty() -> Self {
        Self {
            pid: 0,
            label: SmackLabel {
                bytes: [0u8; SMACK_LABEL_LEN],
                len: 0,
            },
            active: false,
        }
    }
}

// -------------------------------------------------------------------
// SmackRuleSet
// -------------------------------------------------------------------

/// SMACK rule table holding up to [`MAX_RULES`] access rules.
///
/// Rules are searched linearly for a matching (subject, object)
/// pair. If no rule matches, the default policy is **deny**.
///
/// Special label semantics are applied before rule lookup:
/// - STAR subject: access to everything (Allow).
/// - FLOOR object with READ request: always allowed.
/// - HAT object with READ request: always allowed.
/// - Subject equals object: always allowed.
pub struct SmackRuleSet {
    /// Access control rules.
    rules: [SmackRule; MAX_RULES],
    /// Number of active rules.
    rule_count: usize,
    /// Label transition rules for exec.
    transitions: [SmackTransition; MAX_TRANSITIONS],
    /// Number of active transitions.
    transition_count: usize,
    /// PID-to-label mappings.
    pid_labels: [PidLabel; MAX_PID_LABELS],
    /// Number of active PID label assignments.
    pid_label_count: usize,
}

impl Default for SmackRuleSet {
    fn default() -> Self {
        Self::new()
    }
}

impl SmackRuleSet {
    /// Create an empty rule set with no rules, transitions, or
    /// PID assignments.
    pub const fn new() -> Self {
        Self {
            rules: [SmackRule::empty(); MAX_RULES],
            rule_count: 0,
            transitions: [SmackTransition::empty(); MAX_TRANSITIONS],
            transition_count: 0,
            pid_labels: [PidLabel::empty(); MAX_PID_LABELS],
            pid_label_count: 0,
        }
    }

    /// Add an access control rule to the rule set.
    ///
    /// If a rule for the same (subject, object) pair already exists,
    /// it is updated with the new access mask and audit flag.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the rule table is full
    /// and no existing rule matches.
    pub fn add_rule(&mut self, rule: SmackRule) -> Result<()> {
        // Check for existing rule with same subject/object.
        let mut i = 0;
        while i < self.rule_count {
            if self.rules[i].active
                && self.rules[i].subject == rule.subject
                && self.rules[i].object == rule.object
            {
                self.rules[i].access_mask = rule.access_mask;
                self.rules[i].audit = rule.audit;
                return Ok(());
            }
            i += 1;
        }
        if self.rule_count >= MAX_RULES {
            return Err(Error::OutOfMemory);
        }
        self.rules[self.rule_count] = rule;
        self.rule_count += 1;
        Ok(())
    }

    /// Remove a rule by (subject, object) pair.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if no matching rule exists.
    pub fn remove_rule(&mut self, subject: &SmackLabel, object: &SmackLabel) -> Result<()> {
        let mut i = 0;
        while i < self.rule_count {
            if self.rules[i].active
                && self.rules[i].subject == *subject
                && self.rules[i].object == *object
            {
                // Shift remaining rules down.
                let mut j = i;
                while j + 1 < self.rule_count {
                    self.rules[j] = self.rules[j + 1];
                    j += 1;
                }
                self.rules[self.rule_count - 1] = SmackRule::empty();
                self.rule_count -= 1;
                return Ok(());
            }
            i += 1;
        }
        Err(Error::NotFound)
    }

    /// Check access for a (subject, object) pair against the
    /// requested access type.
    ///
    /// Applies special label rules first, then searches the rule
    /// table. Returns [`AccessDecision::Deny`] if no rule matches.
    pub fn check_access(
        &self,
        subject: &SmackLabel,
        object: &SmackLabel,
        access: AccessType,
    ) -> AccessDecision {
        // STAR subject has access to everything.
        if subject.is_star() {
            return AccessDecision::Allow;
        }

        // Same label: always allowed (self-access).
        if *subject == *object {
            return AccessDecision::Allow;
        }

        // FLOOR/HAT object with READ-only request: allowed.
        if (object.is_floor() || object.is_hat()) && access.contains(AccessType::READ) {
            // Only allow if the request is purely read.
            let read_only = AccessType::from_raw(access.bits() & !AccessType::READ.bits());
            if read_only.is_empty() {
                return AccessDecision::Allow;
            }
        }

        // Search rule table.
        let mut i = 0;
        while i < self.rule_count {
            let rule = &self.rules[i];
            if rule.active && rule.subject == *subject && rule.object == *object {
                if rule.access_mask.contains(access) {
                    return if rule.audit {
                        AccessDecision::Audit
                    } else {
                        AccessDecision::Allow
                    };
                }
                // Rule found but access bits not sufficient.
                return AccessDecision::Deny;
            }
            i += 1;
        }

        // Default deny.
        AccessDecision::Deny
    }

    /// Add a label transition rule for exec.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the transition table is full.
    pub fn add_transition(
        &mut self,
        subject_label: SmackLabel,
        object_label: SmackLabel,
        new_label: SmackLabel,
    ) -> Result<()> {
        if self.transition_count >= MAX_TRANSITIONS {
            return Err(Error::OutOfMemory);
        }
        self.transitions[self.transition_count] = SmackTransition {
            subject_label,
            object_label,
            new_label,
            active: true,
        };
        self.transition_count += 1;
        Ok(())
    }

    /// Look up a transition for a (subject, binary) label pair.
    ///
    /// Returns the new label if a transition is defined.
    pub fn find_transition(&self, subject: &SmackLabel, object: &SmackLabel) -> Option<SmackLabel> {
        let mut i = 0;
        while i < self.transition_count {
            let t = &self.transitions[i];
            if t.active && t.subject_label == *subject && t.object_label == *object {
                return Some(t.new_label);
            }
            i += 1;
        }
        None
    }

    /// Assign a SMACK label to a PID.
    ///
    /// If the PID already has an assignment, it is updated.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the PID label table is
    /// full and the PID does not have an existing entry.
    pub fn assign_label(&mut self, pid: u64, label: SmackLabel) -> Result<()> {
        // Update existing assignment.
        let mut i = 0;
        while i < MAX_PID_LABELS {
            if self.pid_labels[i].active && self.pid_labels[i].pid == pid {
                self.pid_labels[i].label = label;
                return Ok(());
            }
            i += 1;
        }
        // Find a free slot.
        let mut j = 0;
        while j < MAX_PID_LABELS {
            if !self.pid_labels[j].active {
                self.pid_labels[j] = PidLabel {
                    pid,
                    label,
                    active: true,
                };
                self.pid_label_count += 1;
                return Ok(());
            }
            j += 1;
        }
        Err(Error::OutOfMemory)
    }

    /// Remove a PID's label assignment.
    pub fn unassign_label(&mut self, pid: u64) {
        let mut i = 0;
        while i < MAX_PID_LABELS {
            if self.pid_labels[i].active && self.pid_labels[i].pid == pid {
                self.pid_labels[i].active = false;
                self.pid_label_count = self.pid_label_count.saturating_sub(1);
                return;
            }
            i += 1;
        }
    }

    /// Look up the SMACK label for a PID.
    pub fn get_label(&self, pid: u64) -> Option<&SmackLabel> {
        let mut i = 0;
        while i < MAX_PID_LABELS {
            if self.pid_labels[i].active && self.pid_labels[i].pid == pid {
                return Some(&self.pid_labels[i].label);
            }
            i += 1;
        }
        None
    }

    /// Handle label inheritance on `fork()`.
    ///
    /// The child process inherits the parent's SMACK label.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] if the parent PID has no label.
    /// - [`Error::OutOfMemory`] if the PID label table is full.
    pub fn inherit_on_fork(&mut self, parent_pid: u64, child_pid: u64) -> Result<()> {
        let parent_label = *self.get_label(parent_pid).ok_or(Error::NotFound)?;
        self.assign_label(child_pid, parent_label)
    }

    /// Handle label transition on `exec()`.
    ///
    /// If a transition rule matches the process's current label
    /// and the binary's label, the process label is updated.
    /// Otherwise the label is preserved.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] if the PID has no label.
    pub fn handle_exec(&mut self, pid: u64, binary_label: &SmackLabel) -> Result<()> {
        let current = *self.get_label(pid).ok_or(Error::NotFound)?;
        if let Some(new_label) = self.find_transition(&current, binary_label) {
            self.assign_label(pid, new_label)?;
        }
        Ok(())
    }

    /// Return the number of active rules.
    pub fn rule_count(&self) -> usize {
        self.rule_count
    }

    /// Return the number of active PID label assignments.
    pub fn pid_label_count(&self) -> usize {
        self.pid_label_count
    }

    /// Return the number of active transition rules.
    pub fn transition_count(&self) -> usize {
        self.transition_count
    }
}

impl core::fmt::Debug for SmackRuleSet {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SmackRuleSet")
            .field("rules", &self.rule_count)
            .field("transitions", &self.transition_count)
            .field("pid_labels", &self.pid_label_count)
            .finish()
    }
}
