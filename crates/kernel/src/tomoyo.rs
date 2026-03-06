// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! TOMOYO-style pathname-based Mandatory Access Control (MAC).
//!
//! TOMOYO confines programs using **domain-based** access control where
//! each domain has a set of file path rules specifying allowed
//! operations. Domains are organised hierarchically and processes
//! transition between domains on `exec` via configurable transitions.
//!
//! Operating modes (per domain):
//!
//! - **Disabled**: no restrictions enforced and no logging.
//! - **Learning**: violations are automatically added as allow rules.
//! - **Permissive**: violations are logged but access is permitted.
//! - **Enforcing**: violations are denied and logged.
//!
//! Key design properties:
//! - Path-based rules (no inode dependency).
//! - Domains form a tree rooted at `<kernel>`.
//! - Exec triggers domain transitions via a transition table.
//! - Learning mode enables policy discovery before enforcement.
//!
//! # Architecture
//!
//! ```text
//!  TomoyoRegistry
//!   ├── policy: TomoyoPolicy
//!   │    ├── domains: [TomoyoDomain; 256]
//!   │    │    ├── name: [u8; 128]
//!   │    │    ├── rules: [TomoyoFileRule; 64]
//!   │    │    └── mode: TomoyoMode
//!   │    └── transitions: [DomainTransition; 128]
//!   └── pid_map: [PidDomainEntry; 256]
//! ```
//!
//! Reference: Linux `security/tomoyo/`, TOMOYO Linux project.

use oncrix_lib::{Error, Result};

// ── Constants ─────────────────────────────────────────────────────

/// Maximum path pattern length in bytes.
const PATH_PATTERN_LEN: usize = 128;

/// Maximum domain name length in bytes.
const DOMAIN_NAME_LEN: usize = 128;

/// Maximum file rules per domain.
const MAX_RULES_PER_DOMAIN: usize = 64;

/// Maximum domains in a policy.
const MAX_DOMAINS: usize = 256;

/// Maximum domain transitions in a policy.
const MAX_TRANSITIONS: usize = 128;

/// Maximum tracked PIDs for domain assignment.
const MAX_PIDS: usize = 256;

// ── TomoyoMode ────────────────────────────────────────────────────

/// Operating mode for a TOMOYO domain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TomoyoMode {
    /// MAC checks are completely bypassed.
    #[default]
    Disabled,
    /// Violations auto-generate allow rules (policy discovery).
    Learning,
    /// Violations are logged but access is still granted.
    Permissive,
    /// Violations are denied and logged.
    Enforcing,
}

// ── TomoyoPermission ──────────────────────────────────────────────

/// File operation permission bits (bitmask).
///
/// Multiple permissions can be combined with bitwise OR.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(transparent)]
pub struct TomoyoPermission(u16);

impl TomoyoPermission {
    /// No permissions.
    pub const NONE: Self = Self(0);
    /// Read file contents.
    pub const READ: Self = Self(1 << 0);
    /// Write file contents.
    pub const WRITE: Self = Self(1 << 1);
    /// Execute a file.
    pub const EXECUTE: Self = Self(1 << 2);
    /// Create a file.
    pub const CREATE: Self = Self(1 << 3);
    /// Unlink (delete) a file.
    pub const UNLINK: Self = Self(1 << 4);
    /// Create a directory.
    pub const MKDIR: Self = Self(1 << 5);
    /// Remove a directory.
    pub const RMDIR: Self = Self(1 << 6);
    /// Rename a file or directory.
    pub const RENAME: Self = Self(1 << 7);

    /// Create from a raw bitmask value.
    pub const fn from_raw(bits: u16) -> Self {
        Self(bits)
    }

    /// Return the raw bitmask value.
    pub const fn bits(self) -> u16 {
        self.0
    }

    /// Check whether `self` contains all bits in `required`.
    pub const fn contains(self, required: TomoyoPermission) -> bool {
        (self.0 & required.0) == required.0
    }

    /// Check whether any permission bit is set.
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }
}

// ── TomoyoFileRule ────────────────────────────────────────────────

/// A single file access rule within a TOMOYO domain.
///
/// Pairs a path pattern with a permission bitmask and an allow/deny
/// flag. Rules are evaluated in order; the first matching rule wins.
#[derive(Debug, Clone, Copy)]
pub struct TomoyoFileRule {
    /// Path pattern to match (fixed-size buffer).
    path_pattern: [u8; PATH_PATTERN_LEN],
    /// Valid length of `path_pattern`.
    path_len: u8,
    /// Bitmask of operations covered by this rule.
    permissions: TomoyoPermission,
    /// Whether this rule allows (`true`) or denies (`false`) access.
    allow: bool,
    /// Whether this rule slot is active.
    active: bool,
}

impl TomoyoFileRule {
    /// Create an empty, inactive rule.
    const fn empty() -> Self {
        Self {
            path_pattern: [0u8; PATH_PATTERN_LEN],
            path_len: 0,
            permissions: TomoyoPermission::NONE,
            allow: false,
            active: false,
        }
    }

    /// Create a new file rule.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `path` exceeds
    /// [`PATH_PATTERN_LEN`] bytes.
    pub fn new(path: &[u8], permissions: TomoyoPermission, allow: bool) -> Result<Self> {
        if path.len() > PATH_PATTERN_LEN {
            return Err(Error::InvalidArgument);
        }
        let mut rule = Self::empty();
        rule.path_pattern[..path.len()].copy_from_slice(path);
        rule.path_len = path.len() as u8;
        rule.permissions = permissions;
        rule.allow = allow;
        rule.active = true;
        Ok(rule)
    }

    /// Return the path pattern as a byte slice.
    pub fn path(&self) -> &[u8] {
        &self.path_pattern[..self.path_len as usize]
    }

    /// Check whether this rule matches a given path and permission.
    ///
    /// A rule matches if it is active, the path matches the pattern,
    /// and the requested permission bits are a subset of the rule's
    /// permission bitmask.
    fn matches(&self, path: &[u8], perm: TomoyoPermission) -> bool {
        if !self.active {
            return false;
        }
        if !self.permissions.contains(perm) {
            return false;
        }
        let pattern = self.path();
        // Simple prefix match: the rule's path pattern must be a
        // prefix of the requested path (or an exact match).
        if path.len() < pattern.len() {
            return false;
        }
        path[..pattern.len()] == *pattern
    }
}

// ── TomoyoDomain ──────────────────────────────────────────────────

/// A TOMOYO security domain.
///
/// Each domain has a unique name, a set of file access rules, an
/// operating mode, and an optional parent domain index for hierarchy.
#[derive(Debug, Clone)]
pub struct TomoyoDomain {
    /// Domain name (fixed-size buffer).
    name: [u8; DOMAIN_NAME_LEN],
    /// Valid length of `name`.
    name_len: u8,
    /// File access rules.
    rules: [TomoyoFileRule; MAX_RULES_PER_DOMAIN],
    /// Number of active rules.
    rule_count: usize,
    /// Operating mode for this domain.
    mode: TomoyoMode,
    /// Index of the parent domain in the policy's domain array,
    /// or `None` for the root domain.
    parent: Option<usize>,
    /// Whether this domain slot is active.
    active: bool,
}

impl TomoyoDomain {
    /// Create an empty, inactive domain.
    const fn empty() -> Self {
        Self {
            name: [0u8; DOMAIN_NAME_LEN],
            name_len: 0,
            rules: [TomoyoFileRule::empty(); MAX_RULES_PER_DOMAIN],
            rule_count: 0,
            mode: TomoyoMode::Disabled,
            parent: None,
            active: false,
        }
    }

    /// Return the domain name as a byte slice.
    pub fn name(&self) -> &[u8] {
        &self.name[..self.name_len as usize]
    }

    /// Return the current operating mode.
    pub fn mode(&self) -> TomoyoMode {
        self.mode
    }

    /// Set the operating mode.
    pub fn set_mode(&mut self, mode: TomoyoMode) {
        self.mode = mode;
    }

    /// Return the number of active rules.
    pub fn rule_count(&self) -> usize {
        self.rule_count
    }

    /// Return the parent domain index.
    pub fn parent(&self) -> Option<usize> {
        self.parent
    }

    /// Add a file rule to this domain.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the domain already has
    /// [`MAX_RULES_PER_DOMAIN`] rules.
    pub fn add_rule(&mut self, rule: TomoyoFileRule) -> Result<()> {
        if self.rule_count >= MAX_RULES_PER_DOMAIN {
            return Err(Error::OutOfMemory);
        }
        self.rules[self.rule_count] = rule;
        self.rule_count = self.rule_count.saturating_add(1);
        Ok(())
    }

    /// Check whether `perm` on `path` is allowed by this domain's rules.
    ///
    /// Scans rules in order. The first matching rule determines the
    /// outcome. If no rule matches, access is denied (default deny).
    fn check_access(&self, path: &[u8], perm: TomoyoPermission) -> bool {
        let mut i = 0;
        while i < self.rule_count {
            let rule = &self.rules[i];
            if rule.matches(path, perm) {
                return rule.allow;
            }
            i = i.saturating_add(1);
        }
        // Default deny: no matching rule means access is not allowed.
        false
    }
}

// ── DomainTransition ──────────────────────────────────────────────

/// A domain transition rule triggered by exec.
///
/// When a process in `from_domain` executes a binary matching
/// `trigger_path`, it transitions to `to_domain`.
#[derive(Debug, Clone, Copy)]
pub struct DomainTransition {
    /// Index of the source domain.
    pub from_domain: usize,
    /// Path that triggers the transition (fixed-size buffer).
    trigger_path: [u8; PATH_PATTERN_LEN],
    /// Valid length of `trigger_path`.
    trigger_len: u8,
    /// Index of the destination domain.
    pub to_domain: usize,
    /// Whether this transition slot is active.
    active: bool,
}

impl DomainTransition {
    /// Create an empty, inactive transition.
    const fn empty() -> Self {
        Self {
            from_domain: 0,
            trigger_path: [0u8; PATH_PATTERN_LEN],
            trigger_len: 0,
            to_domain: 0,
            active: false,
        }
    }

    /// Create a new domain transition.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `trigger` exceeds
    /// [`PATH_PATTERN_LEN`] bytes.
    pub fn new(from_domain: usize, trigger: &[u8], to_domain: usize) -> Result<Self> {
        if trigger.len() > PATH_PATTERN_LEN {
            return Err(Error::InvalidArgument);
        }
        let mut t = Self::empty();
        t.from_domain = from_domain;
        t.trigger_path[..trigger.len()].copy_from_slice(trigger);
        t.trigger_len = trigger.len() as u8;
        t.to_domain = to_domain;
        t.active = true;
        Ok(t)
    }

    /// Return the trigger path as a byte slice.
    pub fn trigger(&self) -> &[u8] {
        &self.trigger_path[..self.trigger_len as usize]
    }
}

// ── TomoyoPolicy ──────────────────────────────────────────────────

/// The complete TOMOYO policy: domains and transitions.
pub struct TomoyoPolicy {
    /// Domain table.
    domains: [TomoyoDomain; MAX_DOMAINS],
    /// Number of active domains.
    domain_count: usize,
    /// Domain transition rules.
    transitions: [DomainTransition; MAX_TRANSITIONS],
    /// Number of active transitions.
    transition_count: usize,
}

impl Default for TomoyoPolicy {
    fn default() -> Self {
        Self::new()
    }
}

impl TomoyoPolicy {
    /// Create an empty policy with no domains or transitions.
    pub fn new() -> Self {
        // We cannot use `[TomoyoDomain::empty(); MAX_DOMAINS]` because
        // `TomoyoDomain` contains an array of `TomoyoFileRule` that is
        // `Clone` but the const initializer works fine for the inner type.
        // We use a loop-based init.
        let mut policy = Self {
            domains: [const { TomoyoDomain::empty() }; MAX_DOMAINS],
            domain_count: 0,
            transitions: [DomainTransition::empty(); MAX_TRANSITIONS],
            transition_count: 0,
        };
        // Suppress unused-mut if the compiler is smart enough.
        let _ = &mut policy;
        policy
    }

    /// Add a new domain to the policy.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the domain table is full.
    /// Returns [`Error::InvalidArgument`] if `name` exceeds
    /// [`DOMAIN_NAME_LEN`] bytes.
    pub fn add_domain(
        &mut self,
        name: &[u8],
        mode: TomoyoMode,
        parent: Option<usize>,
    ) -> Result<usize> {
        if name.len() > DOMAIN_NAME_LEN {
            return Err(Error::InvalidArgument);
        }
        if self.domain_count >= MAX_DOMAINS {
            return Err(Error::OutOfMemory);
        }
        // Validate parent index if provided.
        if let Some(p) = parent {
            if p >= self.domain_count || !self.domains[p].active {
                return Err(Error::InvalidArgument);
            }
        }
        let idx = self.domain_count;
        let domain = &mut self.domains[idx];
        domain.name[..name.len()].copy_from_slice(name);
        domain.name_len = name.len() as u8;
        domain.mode = mode;
        domain.parent = parent;
        domain.active = true;
        domain.rule_count = 0;
        self.domain_count = self.domain_count.saturating_add(1);
        Ok(idx)
    }

    /// Add a domain transition rule.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the transition table is full.
    pub fn add_transition(&mut self, transition: DomainTransition) -> Result<()> {
        if self.transition_count >= MAX_TRANSITIONS {
            return Err(Error::OutOfMemory);
        }
        self.transitions[self.transition_count] = transition;
        self.transition_count = self.transition_count.saturating_add(1);
        Ok(())
    }

    /// Check file access within a specific domain.
    ///
    /// Returns the access decision based on the domain's mode:
    /// - **Disabled**: always allowed, no logging.
    /// - **Learning**: always allowed, auto-adds a rule for the access.
    /// - **Permissive**: always allowed (caller should log).
    /// - **Enforcing**: allowed only if a matching allow rule exists.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `domain_idx` is out of
    /// range or the domain is inactive.
    /// Returns [`Error::PermissionDenied`] in enforcing mode when no
    /// matching allow rule exists.
    pub fn check_file_access(
        &mut self,
        domain_idx: usize,
        path: &[u8],
        perm: TomoyoPermission,
    ) -> Result<()> {
        if domain_idx >= self.domain_count {
            return Err(Error::InvalidArgument);
        }
        let domain = &self.domains[domain_idx];
        if !domain.active {
            return Err(Error::InvalidArgument);
        }

        match domain.mode {
            TomoyoMode::Disabled => Ok(()),
            TomoyoMode::Learning => {
                if !domain.check_access(path, perm) {
                    self.learn(domain_idx, path, perm)?;
                }
                Ok(())
            }
            TomoyoMode::Permissive => {
                // Access is allowed regardless; caller may log the
                // denial for policy development.
                Ok(())
            }
            TomoyoMode::Enforcing => {
                if domain.check_access(path, perm) {
                    Ok(())
                } else {
                    Err(Error::PermissionDenied)
                }
            }
        }
    }

    /// Handle an exec transition.
    ///
    /// Searches the transition table for a rule matching the current
    /// domain and the exec path. Returns the new domain index if a
    /// transition is found, or `None` if no transition matches.
    pub fn handle_exec_transition(&self, current_domain: usize, exec_path: &[u8]) -> Option<usize> {
        let mut i = 0;
        while i < self.transition_count {
            let t = &self.transitions[i];
            if t.active
                && t.from_domain == current_domain
                && exec_path.len() >= t.trigger_len as usize
                && exec_path[..t.trigger_len as usize] == t.trigger_path[..t.trigger_len as usize]
            {
                // Validate the destination domain.
                if t.to_domain < self.domain_count && self.domains[t.to_domain].active {
                    return Some(t.to_domain);
                }
            }
            i = i.saturating_add(1);
        }
        None
    }

    /// Auto-add an allow rule to a domain (learning mode).
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the domain's rule table is
    /// full, or [`Error::InvalidArgument`] if the path is too long.
    fn learn(&mut self, domain_idx: usize, path: &[u8], perm: TomoyoPermission) -> Result<()> {
        let rule = TomoyoFileRule::new(path, perm, true)?;
        self.domains[domain_idx].add_rule(rule)
    }

    /// Return the number of active domains.
    pub fn domain_count(&self) -> usize {
        self.domain_count
    }

    /// Return the number of active transitions.
    pub fn transition_count(&self) -> usize {
        self.transition_count
    }

    /// Return a reference to a domain by index.
    pub fn get_domain(&self, idx: usize) -> Option<&TomoyoDomain> {
        if idx < self.domain_count {
            let d = &self.domains[idx];
            if d.active {
                return Some(d);
            }
        }
        None
    }

    /// Return a mutable reference to a domain by index.
    pub fn get_domain_mut(&mut self, idx: usize) -> Option<&mut TomoyoDomain> {
        if idx < self.domain_count {
            let d = &mut self.domains[idx];
            if d.active {
                return Some(d);
            }
        }
        None
    }
}

// ── PID-to-domain mapping ─────────────────────────────────────────

/// Maps a PID to a domain index.
#[derive(Debug, Clone, Copy)]
struct PidDomainEntry {
    /// Process ID.
    pid: u64,
    /// Index into the policy's domain table.
    domain_idx: usize,
    /// Whether this slot is active.
    active: bool,
}

impl PidDomainEntry {
    /// Create an empty, inactive entry.
    const fn empty() -> Self {
        Self {
            pid: 0,
            domain_idx: 0,
            active: false,
        }
    }
}

// ── TomoyoRegistry ────────────────────────────────────────────────

/// Top-level TOMOYO subsystem registry.
///
/// Manages the policy, PID-to-domain assignments, and subsystem
/// enable/disable state.
pub struct TomoyoRegistry {
    /// The loaded TOMOYO policy.
    policy: TomoyoPolicy,
    /// PID-to-domain mapping table.
    pid_map: [PidDomainEntry; MAX_PIDS],
    /// Whether the TOMOYO subsystem is enabled.
    enabled: bool,
}

impl Default for TomoyoRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl TomoyoRegistry {
    /// Create a new, disabled registry with an empty policy.
    pub fn new() -> Self {
        Self {
            policy: TomoyoPolicy::new(),
            pid_map: [PidDomainEntry::empty(); MAX_PIDS],
            enabled: false,
        }
    }

    /// Enable the TOMOYO subsystem.
    pub fn enable(&mut self) {
        self.enabled = true;
    }

    /// Disable the TOMOYO subsystem.
    pub fn disable(&mut self) {
        self.enabled = false;
    }

    /// Return whether the subsystem is enabled.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Return a reference to the policy.
    pub fn get_policy(&self) -> &TomoyoPolicy {
        &self.policy
    }

    /// Return a mutable reference to the policy.
    pub fn get_policy_mut(&mut self) -> &mut TomoyoPolicy {
        &mut self.policy
    }

    /// Look up the domain index assigned to a PID.
    pub fn get_domain_for_pid(&self, pid: u64) -> Option<usize> {
        let mut i = 0;
        while i < MAX_PIDS {
            let entry = &self.pid_map[i];
            if entry.active && entry.pid == pid {
                return Some(entry.domain_idx);
            }
            i = i.saturating_add(1);
        }
        None
    }

    /// Assign a PID to a domain.
    ///
    /// If the PID already has an assignment it is updated.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `domain_idx` is out of
    /// range or the domain is inactive.
    /// Returns [`Error::OutOfMemory`] if the PID map is full.
    pub fn set_domain(&mut self, pid: u64, domain_idx: usize) -> Result<()> {
        // Validate the domain index.
        if self.policy.get_domain(domain_idx).is_none() {
            return Err(Error::InvalidArgument);
        }

        // Try to update an existing entry for this PID.
        let mut i = 0;
        while i < MAX_PIDS {
            let entry = &mut self.pid_map[i];
            if entry.active && entry.pid == pid {
                entry.domain_idx = domain_idx;
                return Ok(());
            }
            i = i.saturating_add(1);
        }

        // Find a free slot.
        let mut j = 0;
        while j < MAX_PIDS {
            let entry = &mut self.pid_map[j];
            if !entry.active {
                entry.pid = pid;
                entry.domain_idx = domain_idx;
                entry.active = true;
                return Ok(());
            }
            j = j.saturating_add(1);
        }

        Err(Error::OutOfMemory)
    }

    /// Remove the domain assignment for a PID.
    ///
    /// Intended for process teardown cleanup.
    pub fn remove_pid(&mut self, pid: u64) {
        let mut i = 0;
        while i < MAX_PIDS {
            let entry = &mut self.pid_map[i];
            if entry.active && entry.pid == pid {
                entry.active = false;
                return;
            }
            i = i.saturating_add(1);
        }
    }

    /// Check file access for a PID.
    ///
    /// If the subsystem is disabled or the PID has no domain
    /// assignment, access is permitted. Otherwise, the check is
    /// delegated to the domain's rules via the policy.
    ///
    /// # Errors
    ///
    /// Returns [`Error::PermissionDenied`] if the domain is in
    /// enforcing mode and no allow rule matches.
    pub fn check_file_access(
        &mut self,
        pid: u64,
        path: &[u8],
        perm: TomoyoPermission,
    ) -> Result<()> {
        if !self.enabled {
            return Ok(());
        }
        let domain_idx = match self.get_domain_for_pid(pid) {
            Some(idx) => idx,
            None => return Ok(()),
        };
        self.policy.check_file_access(domain_idx, path, perm)
    }

    /// Handle an exec event for a PID.
    ///
    /// Checks the transition table and updates the PID's domain
    /// assignment if a matching transition exists. Returns the new
    /// domain index, or `None` if no transition was triggered.
    ///
    /// # Errors
    ///
    /// Returns an error if updating the PID's domain assignment fails.
    pub fn handle_exec(&mut self, pid: u64, exec_path: &[u8]) -> Result<Option<usize>> {
        if !self.enabled {
            return Ok(None);
        }
        let current = match self.get_domain_for_pid(pid) {
            Some(idx) => idx,
            None => return Ok(None),
        };
        if let Some(new_domain) = self.policy.handle_exec_transition(current, exec_path) {
            self.set_domain(pid, new_domain)?;
            Ok(Some(new_domain))
        } else {
            Ok(None)
        }
    }
}
