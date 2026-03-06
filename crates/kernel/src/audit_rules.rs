// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Audit rules engine for fine-grained event filtering.
//!
//! Provides a configurable rule-based system for controlling which
//! events are recorded by the kernel audit subsystem. Rules match on
//! fields such as UID, GID, PID, syscall number, architecture, and
//! exit code, using comparison operators including bitwise tests.
//!
//! Rules are organised into four rule sets corresponding to different
//! evaluation points:
//!
//! - **Entry**: evaluated at syscall entry.
//! - **Exit**: evaluated at syscall exit.
//! - **Task**: evaluated at task creation.
//! - **Exclude**: rules for excluding events from the log.
//!
//! Each rule specifies an action (`Always`, `Never`, or `Log`) and up
//! to [`MAX_FIELD_MATCHES`] field conditions. A rule matches when all
//! of its field conditions are satisfied. An optional syscall bitmask
//! restricts matching to specific syscall numbers.
//!
//! # Architecture
//!
//! ```text
//!  AuditRuleRegistry
//!   ├── entry:   AuditRuleSet  ← syscall entry rules
//!   ├── exit:    AuditRuleSet  ← syscall exit rules
//!   ├── task:    AuditRuleSet  ← task creation rules
//!   ├── exclude: AuditRuleSet  ← event exclusion rules
//!   └── enabled: bool
//! ```
//!
//! Reference: Linux `kernel/auditfilter.c`, `include/uapi/linux/audit.h`.

use oncrix_lib::{Error, Result};

// ── Constants ─────────────────────────────────────────────────────

/// Maximum number of field match conditions per rule.
const MAX_FIELD_MATCHES: usize = 8;

/// Maximum number of rules in a single rule set.
const MAX_RULES: usize = 128;

/// Maximum length of a string value in a field match (bytes).
const STRING_VALUE_LEN: usize = 128;

/// Number of bits in the syscall bitmask (covers 512 syscalls).
const SYSCALL_MASK_BITS: usize = 512;

/// Number of `u64` words needed for the syscall bitmask.
const SYSCALL_MASK_WORDS: usize = SYSCALL_MASK_BITS / 64;

// ── AuditField ────────────────────────────────────────────────────

/// Fields that can be matched in an audit rule condition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditField {
    /// User ID of the process.
    Uid,
    /// Group ID of the process.
    Gid,
    /// Process ID.
    Pid,
    /// System call number.
    SyscallNr,
    /// Architecture identifier.
    Arch,
    /// Audit message type.
    Msgtype,
    /// File path (compared as a string).
    Path,
    /// Whether the syscall succeeded.
    Success,
    /// Exit code of the syscall.
    Exit,
}

// ── AuditOperator ─────────────────────────────────────────────────

/// Comparison operators for audit field matching.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditOperator {
    /// Field equals the specified value.
    Equal,
    /// Field does not equal the specified value.
    NotEqual,
    /// Field is strictly less than the specified value.
    LessThan,
    /// Field is strictly greater than the specified value.
    GreaterThan,
    /// Field bitwise-AND with value is non-zero.
    BitMask,
    /// Field bitwise-AND with value equals the value (all bits set).
    BitTest,
}

// ── AuditFieldMatch ───────────────────────────────────────────────

/// A single field match condition within an audit rule.
///
/// For numeric fields ([`AuditField::Uid`], [`AuditField::Gid`], etc.)
/// the `value` field is used. For string fields
/// ([`AuditField::Path`]) the `string_value` buffer is used.
#[derive(Debug, Clone, Copy)]
pub struct AuditFieldMatch {
    /// Which field to compare.
    pub field: AuditField,
    /// Comparison operator.
    pub operator: AuditOperator,
    /// Numeric comparison value.
    pub value: u64,
    /// String comparison value (fixed-size buffer).
    string_value: [u8; STRING_VALUE_LEN],
    /// Valid length of `string_value`.
    string_len: u8,
    /// Whether this match slot is active.
    active: bool,
}

impl AuditFieldMatch {
    /// Create an empty, inactive field match.
    const fn empty() -> Self {
        Self {
            field: AuditField::Uid,
            operator: AuditOperator::Equal,
            value: 0,
            string_value: [0u8; STRING_VALUE_LEN],
            string_len: 0,
            active: false,
        }
    }

    /// Create a numeric field match.
    pub const fn numeric(field: AuditField, operator: AuditOperator, value: u64) -> Self {
        Self {
            field,
            operator,
            value,
            string_value: [0u8; STRING_VALUE_LEN],
            string_len: 0,
            active: true,
        }
    }

    /// Create a string field match.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `string_val` exceeds
    /// [`STRING_VALUE_LEN`] bytes.
    pub fn string(field: AuditField, operator: AuditOperator, string_val: &[u8]) -> Result<Self> {
        if string_val.len() > STRING_VALUE_LEN {
            return Err(Error::InvalidArgument);
        }
        let mut m = Self::empty();
        m.field = field;
        m.operator = operator;
        m.string_value[..string_val.len()].copy_from_slice(string_val);
        m.string_len = string_val.len() as u8;
        m.active = true;
        Ok(m)
    }

    /// Return the string value as a byte slice.
    pub fn string_value(&self) -> &[u8] {
        &self.string_value[..self.string_len as usize]
    }

    /// Evaluate this field match against an audit context.
    fn evaluate(&self, ctx: &AuditContext) -> bool {
        if !self.active {
            return true;
        }

        match self.field {
            AuditField::Path => self.compare_string(ctx.path()),
            _ => {
                let field_val = match self.field {
                    AuditField::Uid => ctx.uid,
                    AuditField::Gid => ctx.gid,
                    AuditField::Pid => ctx.pid,
                    AuditField::SyscallNr => ctx.syscall_nr,
                    AuditField::Arch => ctx.arch,
                    AuditField::Msgtype => 0,
                    AuditField::Path => unreachable!(),
                    AuditField::Success => {
                        if ctx.success {
                            1
                        } else {
                            0
                        }
                    }
                    AuditField::Exit => ctx.exit_code,
                };
                self.compare_numeric(field_val)
            }
        }
    }

    /// Compare a numeric field value using this match's operator.
    fn compare_numeric(&self, field_val: u64) -> bool {
        match self.operator {
            AuditOperator::Equal => field_val == self.value,
            AuditOperator::NotEqual => field_val != self.value,
            AuditOperator::LessThan => field_val < self.value,
            AuditOperator::GreaterThan => field_val > self.value,
            AuditOperator::BitMask => field_val & self.value != 0,
            AuditOperator::BitTest => field_val & self.value == self.value,
        }
    }

    /// Compare a string field value using this match's operator.
    fn compare_string(&self, field_val: &[u8]) -> bool {
        let pattern = self.string_value();
        match self.operator {
            AuditOperator::Equal => field_val == pattern,
            AuditOperator::NotEqual => field_val != pattern,
            // String comparisons for ordered/bitwise operators are
            // not meaningful; treat as not matching.
            _ => false,
        }
    }
}

// ── AuditAction ───────────────────────────────────────────────────

/// Action to take when an audit rule matches.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AuditAction {
    /// Always record the event.
    #[default]
    Always,
    /// Never record the event.
    Never,
    /// Record the event conditionally (based on further criteria).
    Log,
}

// ── Syscall bitmask ───────────────────────────────────────────────

/// A bitmask covering 512 syscall numbers.
///
/// If a syscall mask is present on a rule, the rule only applies to
/// syscalls whose bit is set.
#[derive(Debug, Clone, Copy)]
struct SyscallMask {
    /// Bitmask words (bit N set means syscall N is included).
    words: [u64; SYSCALL_MASK_WORDS],
    /// Whether this mask is active (if false, all syscalls match).
    active: bool,
}

impl SyscallMask {
    /// Create an inactive mask (matches all syscalls).
    const fn inactive() -> Self {
        Self {
            words: [0u64; SYSCALL_MASK_WORDS],
            active: false,
        }
    }

    /// Set the bit for a specific syscall number.
    ///
    /// Returns `false` if `nr` is out of range.
    pub fn set(&mut self, nr: u32) -> bool {
        let idx = nr as usize;
        if idx >= SYSCALL_MASK_BITS {
            return false;
        }
        self.words[idx / 64] |= 1u64 << (idx % 64);
        self.active = true;
        true
    }

    /// Check whether a syscall number is included in the mask.
    fn contains(&self, nr: u64) -> bool {
        if !self.active {
            return true;
        }
        let idx = nr as usize;
        if idx >= SYSCALL_MASK_BITS {
            return false;
        }
        self.words[idx / 64] & (1u64 << (idx % 64)) != 0
    }
}

// ── AuditRule ─────────────────────────────────────────────────────

/// A single audit rule combining an action, field conditions, and
/// an optional syscall bitmask.
///
/// A rule matches when:
/// 1. The syscall number is included in the syscall mask (if active).
/// 2. All active field match conditions are satisfied.
#[derive(Debug, Clone, Copy)]
pub struct AuditRule {
    /// Action to take when this rule matches.
    pub action: AuditAction,
    /// Field match conditions (up to [`MAX_FIELD_MATCHES`]).
    field_matches: [AuditFieldMatch; MAX_FIELD_MATCHES],
    /// Number of active field matches.
    match_count: usize,
    /// Optional syscall bitmask filter.
    syscall_mask: SyscallMask,
    /// Whether this rule slot is active.
    active: bool,
}

impl AuditRule {
    /// Create an empty, inactive rule.
    const fn empty() -> Self {
        Self {
            action: AuditAction::Always,
            field_matches: [AuditFieldMatch::empty(); MAX_FIELD_MATCHES],
            match_count: 0,
            syscall_mask: SyscallMask::inactive(),
            active: false,
        }
    }

    /// Create a new rule with the given action.
    pub const fn new(action: AuditAction) -> Self {
        Self {
            action,
            field_matches: [AuditFieldMatch::empty(); MAX_FIELD_MATCHES],
            match_count: 0,
            syscall_mask: SyscallMask::inactive(),
            active: true,
        }
    }

    /// Add a field match condition to this rule.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the rule already has
    /// [`MAX_FIELD_MATCHES`] conditions.
    pub fn add_field_match(&mut self, field_match: AuditFieldMatch) -> Result<()> {
        if self.match_count >= MAX_FIELD_MATCHES {
            return Err(Error::OutOfMemory);
        }
        self.field_matches[self.match_count] = field_match;
        self.match_count = self.match_count.saturating_add(1);
        Ok(())
    }

    /// Set the syscall bitmask to match all syscalls.
    pub fn set_syscall_mask_all(&mut self) {
        self.syscall_mask.words = [u64::MAX; SYSCALL_MASK_WORDS];
        self.syscall_mask.active = true;
    }

    /// Set a single syscall in the bitmask.
    ///
    /// Activates the mask if it is not already active.
    pub fn add_syscall(&mut self, nr: u32) -> bool {
        self.syscall_mask.set(nr)
    }

    /// Evaluate this rule against an audit context.
    ///
    /// Returns `true` if all conditions match.
    fn evaluate(&self, ctx: &AuditContext) -> bool {
        if !self.active {
            return false;
        }
        // Check syscall mask first.
        if !self.syscall_mask.contains(ctx.syscall_nr) {
            return false;
        }
        // All field conditions must match.
        let mut i = 0;
        while i < self.match_count {
            if !self.field_matches[i].evaluate(ctx) {
                return false;
            }
            i = i.saturating_add(1);
        }
        true
    }
}

// ── AuditRuleSet ──────────────────────────────────────────────────

/// A set of audit rules evaluated as an ordered list.
///
/// Rules are evaluated in order; the first matching rule's action
/// determines the outcome. If no rule matches, the default action
/// is [`AuditAction::Always`] (record the event).
pub struct AuditRuleSet {
    /// Rule storage.
    rules: [AuditRule; MAX_RULES],
    /// Number of active rules.
    rule_count: usize,
}

impl Default for AuditRuleSet {
    fn default() -> Self {
        Self::new()
    }
}

impl AuditRuleSet {
    /// Create an empty rule set.
    pub const fn new() -> Self {
        Self {
            rules: [AuditRule::empty(); MAX_RULES],
            rule_count: 0,
        }
    }

    /// Add a rule to this set.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the set already has
    /// [`MAX_RULES`] rules.
    pub fn add_rule(&mut self, rule: AuditRule) -> Result<usize> {
        if self.rule_count >= MAX_RULES {
            return Err(Error::OutOfMemory);
        }
        let idx = self.rule_count;
        self.rules[idx] = rule;
        self.rule_count = self.rule_count.saturating_add(1);
        Ok(idx)
    }

    /// Remove the rule at `index` by marking it inactive.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `index` is out of bounds
    /// or the rule is already inactive.
    pub fn remove_rule(&mut self, index: usize) -> Result<()> {
        if index >= self.rule_count {
            return Err(Error::InvalidArgument);
        }
        if !self.rules[index].active {
            return Err(Error::InvalidArgument);
        }
        self.rules[index].active = false;
        Ok(())
    }

    /// Evaluate all rules against an audit context.
    ///
    /// Returns the action of the first matching rule, or
    /// [`AuditAction::Always`] if no rule matches (default: record).
    pub fn evaluate(&self, ctx: &AuditContext) -> AuditAction {
        let mut i = 0;
        while i < self.rule_count {
            let rule = &self.rules[i];
            if rule.evaluate(ctx) {
                return rule.action;
            }
            i = i.saturating_add(1);
        }
        AuditAction::Always
    }

    /// Return the number of rules in this set.
    pub fn len(&self) -> usize {
        self.rule_count
    }

    /// Return whether this set has no rules.
    pub fn is_empty(&self) -> bool {
        self.rule_count == 0
    }
}

// ── AuditContext ──────────────────────────────────────────────────

/// Context information for evaluating audit rules.
///
/// Populated by the kernel at each audit evaluation point with
/// relevant process and syscall information.
#[derive(Debug, Clone, Copy)]
pub struct AuditContext {
    /// User ID of the process.
    pub uid: u64,
    /// Group ID of the process.
    pub gid: u64,
    /// Process ID.
    pub pid: u64,
    /// System call number being evaluated.
    pub syscall_nr: u64,
    /// Architecture identifier.
    pub arch: u64,
    /// Whether the syscall succeeded.
    pub success: bool,
    /// Exit code (or return value) of the syscall.
    pub exit_code: u64,
    /// File path relevant to the event (fixed-size buffer).
    path: [u8; STRING_VALUE_LEN],
    /// Valid length of `path`.
    path_len: u8,
}

impl AuditContext {
    /// Create a new audit context.
    pub const fn new(
        uid: u64,
        gid: u64,
        pid: u64,
        syscall_nr: u64,
        arch: u64,
        success: bool,
        exit_code: u64,
    ) -> Self {
        Self {
            uid,
            gid,
            pid,
            syscall_nr,
            arch,
            success,
            exit_code,
            path: [0u8; STRING_VALUE_LEN],
            path_len: 0,
        }
    }

    /// Set the path for this context.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `path` exceeds
    /// [`STRING_VALUE_LEN`] bytes.
    pub fn set_path(&mut self, path: &[u8]) -> Result<()> {
        if path.len() > STRING_VALUE_LEN {
            return Err(Error::InvalidArgument);
        }
        self.path[..path.len()].copy_from_slice(path);
        self.path_len = path.len() as u8;
        Ok(())
    }

    /// Return the path as a byte slice.
    pub fn path(&self) -> &[u8] {
        &self.path[..self.path_len as usize]
    }
}

// ── AuditRuleRegistry ─────────────────────────────────────────────

/// Top-level audit rule registry managing four rule sets.
///
/// Provides centralised control over audit rule evaluation, loading,
/// and lifecycle management.
pub struct AuditRuleRegistry {
    /// Rules evaluated at syscall entry.
    entry: AuditRuleSet,
    /// Rules evaluated at syscall exit.
    exit: AuditRuleSet,
    /// Rules evaluated at task creation.
    task: AuditRuleSet,
    /// Rules for excluding events from the audit log.
    exclude: AuditRuleSet,
    /// Whether the rule engine is enabled.
    enabled: bool,
}

impl Default for AuditRuleRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Identifies one of the four rule sets in the registry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleSetType {
    /// Syscall entry rules.
    Entry,
    /// Syscall exit rules.
    Exit,
    /// Task creation rules.
    Task,
    /// Event exclusion rules.
    Exclude,
}

impl AuditRuleRegistry {
    /// Create a new, enabled registry with empty rule sets.
    pub const fn new() -> Self {
        Self {
            entry: AuditRuleSet::new(),
            exit: AuditRuleSet::new(),
            task: AuditRuleSet::new(),
            exclude: AuditRuleSet::new(),
            enabled: true,
        }
    }

    /// Enable the audit rule engine.
    pub fn enable(&mut self) {
        self.enabled = true;
    }

    /// Disable the audit rule engine.
    pub fn disable(&mut self) {
        self.enabled = false;
    }

    /// Return whether the engine is enabled.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Return a reference to a rule set by type.
    pub fn get_rule_set(&self, set_type: RuleSetType) -> &AuditRuleSet {
        match set_type {
            RuleSetType::Entry => &self.entry,
            RuleSetType::Exit => &self.exit,
            RuleSetType::Task => &self.task,
            RuleSetType::Exclude => &self.exclude,
        }
    }

    /// Return a mutable reference to a rule set by type.
    pub fn get_rule_set_mut(&mut self, set_type: RuleSetType) -> &mut AuditRuleSet {
        match set_type {
            RuleSetType::Entry => &mut self.entry,
            RuleSetType::Exit => &mut self.exit,
            RuleSetType::Task => &mut self.task,
            RuleSetType::Exclude => &mut self.exclude,
        }
    }

    /// Load a rule into the specified rule set.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the rule set is full.
    pub fn load(&mut self, set_type: RuleSetType, rule: AuditRule) -> Result<usize> {
        self.get_rule_set_mut(set_type).add_rule(rule)
    }

    /// Remove a rule from the specified rule set.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if the index is invalid.
    pub fn unload(&mut self, set_type: RuleSetType, index: usize) -> Result<()> {
        self.get_rule_set_mut(set_type).remove_rule(index)
    }

    /// Evaluate all four rule sets against an audit context.
    ///
    /// Returns the most restrictive action across the entry, exit,
    /// and task rule sets. If the exclude rule set matches with
    /// [`AuditAction::Never`], the event is suppressed regardless
    /// of other results.
    ///
    /// If the engine is disabled, always returns
    /// [`AuditAction::Always`].
    pub fn evaluate_all(&self, ctx: &AuditContext) -> AuditAction {
        if !self.enabled {
            return AuditAction::Always;
        }

        // Check exclusion rules first.
        let exclude_action = self.exclude.evaluate(ctx);
        if exclude_action == AuditAction::Never {
            return AuditAction::Never;
        }

        // Evaluate the three main rule sets and pick the most
        // restrictive action. Priority: Never > Log > Always.
        let entry_action = self.entry.evaluate(ctx);
        let exit_action = self.exit.evaluate(ctx);
        let task_action = self.task.evaluate(ctx);

        // Find the most restrictive.
        most_restrictive(most_restrictive(entry_action, exit_action), task_action)
    }
}

/// Return the more restrictive of two audit actions.
///
/// Priority ordering: `Never` > `Log` > `Always`.
fn most_restrictive(a: AuditAction, b: AuditAction) -> AuditAction {
    let pri_a = action_priority(a);
    let pri_b = action_priority(b);
    if pri_a <= pri_b { a } else { b }
}

/// Return a numeric priority for an action (lower = more restrictive).
const fn action_priority(action: AuditAction) -> u8 {
    match action {
        AuditAction::Never => 0,
        AuditAction::Log => 1,
        AuditAction::Always => 2,
    }
}
