// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! AppArmor-style profile-based Mandatory Access Control (MAC).
//!
//! AppArmor confines programs by associating each process with a
//! security profile that specifies allowed file, network, and
//! capability operations. Profiles can operate in multiple modes:
//!
//! - **Enforce**: violations are denied and logged.
//! - **Complain**: violations are logged but permitted.
//! - **Kill**: violations immediately terminate the process.
//! - **Unconfined**: no restrictions are applied.
//!
//! Profiles support path-based file access rules, network socket
//! rules, capability rules, and domain transitions triggered by
//! exec-like operations on specific paths.
//!
//! # Architecture
//!
//! ```text
//!  AppArmorRegistry
//!   ├── profiles: [AppArmorProfile; 64]
//!   │    ├── mode: ProfileMode
//!   │    ├── file_rules:  [FileRule; 32]
//!   │    ├── net_rules:   [NetRule; 16]
//!   │    ├── cap_rules:   [CapRule; 16]
//!   │    └── transitions: [ProfileTransition; 8]
//!   └── AppArmorState (per-PID profile assignment)
//!        └── assignments: [PidAssignment; 256]
//! ```
//!
//! Reference: Linux `security/apparmor/`, AppArmor profile language.

use oncrix_lib::{Error, Result};

// ── Constants ─────────────────────────────────────────────────────

/// Maximum number of file access rules per profile.
const MAX_FILE_RULES: usize = 32;

/// Maximum number of network access rules per profile.
const MAX_NET_RULES: usize = 16;

/// Maximum number of capability rules per profile.
const MAX_CAP_RULES: usize = 16;

/// Maximum number of domain transitions per profile.
const MAX_TRANSITIONS: usize = 8;

/// Maximum number of registered profiles.
const MAX_PROFILES: usize = 64;

/// Maximum number of tracked PID-to-profile assignments.
const MAX_PIDS: usize = 256;

/// Maximum length of a profile name.
const PROFILE_NAME_LEN: usize = 64;

/// Maximum length of a path pattern in a file rule.
const PATH_PATTERN_LEN: usize = 64;

/// Maximum number of compiled binary match entries.
const MAX_MATCH_ENTRIES: usize = 64;

/// Maximum number of stacked profiles per PID.
const MAX_PROFILE_STACK: usize = 4;

/// Maximum number of audit log entries.
const MAX_AUDIT_LOG: usize = 128;

/// Maximum audit description length.
const AUDIT_DESC_LEN: usize = 64;

// ── ProfileMode ───────────────────────────────────────────────────

/// Operating mode for an AppArmor profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ProfileMode {
    /// Enforce: deny and log violations.
    #[default]
    Enforce,
    /// Complain: log violations but allow access.
    Complain,
    /// Kill: terminate the process on any violation.
    Kill,
    /// Unconfined: no restrictions applied.
    Unconfined,
}

// ── FilePermission ────────────────────────────────────────────────

/// Permission bits for file access rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(transparent)]
pub struct FilePermission(u8);

impl FilePermission {
    /// No permissions.
    pub const NONE: Self = Self(0);
    /// Read permission.
    pub const READ: Self = Self(1 << 0);
    /// Write permission.
    pub const WRITE: Self = Self(1 << 1);
    /// Execute permission.
    pub const EXEC: Self = Self(1 << 2);
    /// Append permission.
    pub const APPEND: Self = Self(1 << 3);
    /// Link/rename permission.
    pub const LINK: Self = Self(1 << 4);
    /// Lock permission.
    pub const LOCK: Self = Self(1 << 5);

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

// ── FileRule ──────────────────────────────────────────────────────

/// A file access rule within an AppArmor profile.
///
/// Associates a path pattern with a set of permitted file
/// operations. Path matching uses a simple prefix comparison.
#[derive(Debug, Clone, Copy)]
pub struct FileRule {
    /// Path pattern to match (prefix-based matching).
    pub path: [u8; PATH_PATTERN_LEN],
    /// Valid length of the path pattern.
    pub path_len: usize,
    /// Permitted file operations.
    pub permissions: FilePermission,
    /// Whether this rule slot is active.
    pub active: bool,
}

impl FileRule {
    /// Create an empty, inactive file rule.
    const fn empty() -> Self {
        Self {
            path: [0u8; PATH_PATTERN_LEN],
            path_len: 0,
            permissions: FilePermission::NONE,
            active: false,
        }
    }

    /// Create a new file rule from a path and permissions.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `path` exceeds the
    /// maximum path pattern length.
    pub fn new(path: &[u8], permissions: FilePermission) -> Result<Self> {
        if path.len() > PATH_PATTERN_LEN {
            return Err(Error::InvalidArgument);
        }
        let mut rule = Self::empty();
        rule.path[..path.len()].copy_from_slice(path);
        rule.path_len = path.len();
        rule.permissions = permissions;
        rule.active = true;
        Ok(rule)
    }

    /// Check whether `request_path` matches this rule's pattern.
    ///
    /// Supports glob-style matching:
    /// - `*` matches any sequence of non-`/` characters within a
    ///   single path component.
    /// - `**` matches any sequence of characters including `/`
    ///   (recursive glob).
    /// - Trailing `/` matches any path under that directory.
    /// - Otherwise, exact match or prefix match.
    fn matches_path(&self, request_path: &[u8]) -> bool {
        if !self.active {
            return false;
        }
        let pattern = &self.path[..self.path_len];
        aa_glob_match(pattern, request_path)
    }
}

// ── AddressFamily ─────────────────────────────────────────────────

/// Network address family for network rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AddressFamily {
    /// IPv4 (AF_INET).
    #[default]
    Inet,
    /// IPv6 (AF_INET6).
    Inet6,
    /// UNIX domain sockets (AF_UNIX).
    Unix,
    /// Netlink (AF_NETLINK).
    Netlink,
    /// Any address family (wildcard).
    Any,
}

// ── SocketType ────────────────────────────────────────────────────

/// Socket type for network rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SocketType {
    /// Stream socket (SOCK_STREAM).
    #[default]
    Stream,
    /// Datagram socket (SOCK_DGRAM).
    Dgram,
    /// Raw socket (SOCK_RAW).
    Raw,
    /// Any socket type (wildcard).
    Any,
}

// ── NetPermission ─────────────────────────────────────────────────

/// Permission bits for network access rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(transparent)]
pub struct NetPermission(u8);

impl NetPermission {
    /// No permissions.
    pub const NONE: Self = Self(0);
    /// Create a socket.
    pub const CREATE: Self = Self(1 << 0);
    /// Bind a socket to an address.
    pub const BIND: Self = Self(1 << 1);
    /// Listen for incoming connections.
    pub const LISTEN: Self = Self(1 << 2);
    /// Connect to a remote address.
    pub const CONNECT: Self = Self(1 << 3);
    /// Send data on a socket.
    pub const SEND: Self = Self(1 << 4);
    /// Receive data from a socket.
    pub const RECV: Self = Self(1 << 5);

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
}

// ── NetRule ───────────────────────────────────────────────────────

/// A network access rule within an AppArmor profile.
///
/// Specifies which socket operations are permitted for a given
/// address family and socket type combination.
#[derive(Debug, Clone, Copy)]
pub struct NetRule {
    /// Address family this rule applies to.
    pub domain: AddressFamily,
    /// Socket type this rule applies to.
    pub sock_type: SocketType,
    /// Permitted network operations.
    pub permission: NetPermission,
    /// Whether this rule slot is active.
    pub active: bool,
}

impl NetRule {
    /// Create an empty, inactive network rule.
    const fn empty() -> Self {
        Self {
            domain: AddressFamily::Inet,
            sock_type: SocketType::Stream,
            permission: NetPermission::NONE,
            active: false,
        }
    }

    /// Check whether this rule matches a given domain/type pair.
    fn matches(&self, domain: AddressFamily, sock_type: SocketType) -> bool {
        if !self.active {
            return false;
        }
        let domain_match = self.domain == domain
            || self.domain == AddressFamily::Any
            || domain == AddressFamily::Any;
        let type_match = self.sock_type == sock_type
            || self.sock_type == SocketType::Any
            || sock_type == SocketType::Any;
        domain_match && type_match
    }
}

// ── CapRule ───────────────────────────────────────────────────────

/// A capability rule within an AppArmor profile.
///
/// Controls whether a specific Linux-style capability is permitted
/// for processes running under this profile.
#[derive(Debug, Clone, Copy)]
pub struct CapRule {
    /// Capability identifier (e.g. CAP_NET_ADMIN = 12).
    pub cap_id: u32,
    /// Whether this capability is allowed.
    pub allowed: bool,
    /// Whether this rule slot is active.
    pub active: bool,
}

impl CapRule {
    /// Create an empty, inactive capability rule.
    const fn empty() -> Self {
        Self {
            cap_id: 0,
            allowed: false,
            active: false,
        }
    }
}

// ── ProfileTransition ─────────────────────────────────────────────

/// A domain transition rule that triggers when a specific path
/// is executed, switching the process to a different profile.
#[derive(Debug, Clone, Copy)]
pub struct ProfileTransition {
    /// Path that triggers the transition (prefix match).
    pub trigger_path: [u8; PATH_PATTERN_LEN],
    /// Valid length of the trigger path.
    pub trigger_len: usize,
    /// Name of the target profile to transition into.
    pub target_profile: [u8; PROFILE_NAME_LEN],
    /// Valid length of the target profile name.
    pub target_len: usize,
    /// Whether this transition slot is active.
    pub active: bool,
}

impl ProfileTransition {
    /// Create an empty, inactive transition.
    const fn empty() -> Self {
        Self {
            trigger_path: [0u8; PATH_PATTERN_LEN],
            trigger_len: 0,
            target_profile: [0u8; PROFILE_NAME_LEN],
            target_len: 0,
            active: false,
        }
    }

    /// Create a new profile transition.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `trigger` or `target`
    /// exceeds the maximum buffer size.
    pub fn new(trigger: &[u8], target: &[u8]) -> Result<Self> {
        if trigger.len() > PATH_PATTERN_LEN || target.len() > PROFILE_NAME_LEN {
            return Err(Error::InvalidArgument);
        }
        let mut t = Self::empty();
        t.trigger_path[..trigger.len()].copy_from_slice(trigger);
        t.trigger_len = trigger.len();
        t.target_profile[..target.len()].copy_from_slice(target);
        t.target_len = target.len();
        t.active = true;
        Ok(t)
    }

    /// Check whether an exec path matches this transition trigger.
    fn matches_path(&self, exec_path: &[u8]) -> bool {
        if !self.active || exec_path.len() < self.trigger_len {
            return false;
        }
        exec_path[..self.trigger_len] == self.trigger_path[..self.trigger_len]
    }
}

// ── AppArmorProfile ───────────────────────────────────────────────

/// An AppArmor security profile defining access rules for a
/// confined process.
///
/// Each profile contains file, network, and capability rules along
/// with domain transition specifications. The profile mode
/// determines enforcement behavior.
pub struct AppArmorProfile {
    /// Profile name.
    pub name: [u8; PROFILE_NAME_LEN],
    /// Valid length of the profile name.
    pub name_len: usize,
    /// Operating mode (enforce, complain, kill, unconfined).
    pub mode: ProfileMode,
    /// File access rules.
    file_rules: [FileRule; MAX_FILE_RULES],
    /// Number of active file rules.
    file_rule_count: usize,
    /// Network access rules.
    net_rules: [NetRule; MAX_NET_RULES],
    /// Number of active network rules.
    net_rule_count: usize,
    /// Capability rules.
    cap_rules: [CapRule; MAX_CAP_RULES],
    /// Number of active capability rules.
    cap_rule_count: usize,
    /// Domain transition rules.
    transitions: [ProfileTransition; MAX_TRANSITIONS],
    /// Number of active transitions.
    transition_count: usize,
    /// Index of the parent profile, or `None` for top-level profiles.
    pub parent_idx: Option<usize>,
    /// Compiled binary match table for fast rule evaluation.
    match_table: CompiledMatchTable,
    /// Whether this profile slot is active in the registry.
    pub active: bool,
}

impl AppArmorProfile {
    /// Create an empty, inactive profile.
    const fn empty() -> Self {
        Self {
            name: [0u8; PROFILE_NAME_LEN],
            name_len: 0,
            mode: ProfileMode::Enforce,
            file_rules: [FileRule::empty(); MAX_FILE_RULES],
            file_rule_count: 0,
            net_rules: [NetRule::empty(); MAX_NET_RULES],
            net_rule_count: 0,
            cap_rules: [CapRule::empty(); MAX_CAP_RULES],
            cap_rule_count: 0,
            transitions: [ProfileTransition::empty(); MAX_TRANSITIONS],
            transition_count: 0,
            parent_idx: None,
            match_table: CompiledMatchTable::empty(),
            active: false,
        }
    }

    /// Return the profile name as a byte slice.
    pub fn name_bytes(&self) -> &[u8] {
        &self.name[..self.name_len]
    }

    /// Add a file access rule to this profile.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the file rule table is full.
    pub fn add_file_rule(&mut self, rule: FileRule) -> Result<()> {
        if self.file_rule_count >= MAX_FILE_RULES {
            return Err(Error::OutOfMemory);
        }
        self.file_rules[self.file_rule_count] = rule;
        self.file_rule_count = self.file_rule_count.saturating_add(1);
        Ok(())
    }

    /// Add a network access rule to this profile.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the network rule table is full.
    pub fn add_net_rule(&mut self, rule: NetRule) -> Result<()> {
        if self.net_rule_count >= MAX_NET_RULES {
            return Err(Error::OutOfMemory);
        }
        self.net_rules[self.net_rule_count] = rule;
        self.net_rule_count = self.net_rule_count.saturating_add(1);
        Ok(())
    }

    /// Add a capability rule to this profile.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the capability rule table is full.
    pub fn add_cap_rule(&mut self, rule: CapRule) -> Result<()> {
        if self.cap_rule_count >= MAX_CAP_RULES {
            return Err(Error::OutOfMemory);
        }
        self.cap_rules[self.cap_rule_count] = rule;
        self.cap_rule_count = self.cap_rule_count.saturating_add(1);
        Ok(())
    }

    /// Add a domain transition rule to this profile.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the transition table is full.
    pub fn add_transition(&mut self, transition: ProfileTransition) -> Result<()> {
        if self.transition_count >= MAX_TRANSITIONS {
            return Err(Error::OutOfMemory);
        }
        self.transitions[self.transition_count] = transition;
        self.transition_count = self.transition_count.saturating_add(1);
        Ok(())
    }

    /// Check whether a file access is permitted by this profile.
    ///
    /// Searches for a matching file rule whose permissions include
    /// all of `requested`. Returns `true` if found.
    fn check_file_access(&self, path: &[u8], requested: FilePermission) -> bool {
        let mut i = 0;
        while i < self.file_rule_count {
            let rule = &self.file_rules[i];
            if rule.matches_path(path) && rule.permissions.contains(requested) {
                return true;
            }
            i = i.saturating_add(1);
        }
        false
    }

    /// Check whether a network operation is permitted by this profile.
    ///
    /// Searches for a matching network rule whose permissions include
    /// all of `requested`. Returns `true` if found.
    fn check_net_access(
        &self,
        domain: AddressFamily,
        sock_type: SocketType,
        requested: NetPermission,
    ) -> bool {
        let mut i = 0;
        while i < self.net_rule_count {
            let rule = &self.net_rules[i];
            if rule.matches(domain, sock_type) && rule.permission.contains(requested) {
                return true;
            }
            i = i.saturating_add(1);
        }
        false
    }

    /// Check whether a capability is allowed by this profile.
    ///
    /// Returns `true` if a matching capability rule explicitly
    /// permits `cap_id`.
    fn check_cap_access(&self, cap_id: u32) -> bool {
        let mut i = 0;
        while i < self.cap_rule_count {
            let rule = &self.cap_rules[i];
            if rule.active && rule.cap_id == cap_id && rule.allowed {
                return true;
            }
            i = i.saturating_add(1);
        }
        false
    }

    /// Look up a domain transition for the given exec path.
    ///
    /// Returns the target profile name bytes if a matching
    /// transition is found.
    fn find_transition(&self, exec_path: &[u8]) -> Option<&[u8]> {
        let mut i = 0;
        while i < self.transition_count {
            let t = &self.transitions[i];
            if t.matches_path(exec_path) {
                return Some(&t.target_profile[..t.target_len]);
            }
            i = i.saturating_add(1);
        }
        None
    }

    /// Return the number of active file rules.
    pub fn file_rule_count(&self) -> usize {
        self.file_rule_count
    }

    /// Return the number of active capability rules.
    pub fn cap_rule_count(&self) -> usize {
        self.cap_rule_count
    }

    /// Return the number of active network rules.
    pub fn net_rule_count(&self) -> usize {
        self.net_rule_count
    }

    /// Return the parent profile index.
    pub fn parent(&self) -> Option<usize> {
        self.parent_idx
    }

    /// Return a reference to the compiled match table.
    pub fn match_table(&self) -> &CompiledMatchTable {
        &self.match_table
    }

    /// Compile all file rules into the binary match table.
    ///
    /// This pre-processes file rules into a flat lookup structure
    /// for faster runtime evaluation. Call after adding all rules.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if too many rules to compile.
    pub fn compile(&mut self) -> Result<()> {
        self.match_table = CompiledMatchTable::empty();
        let mut idx = 0;
        while idx < self.file_rule_count {
            let rule = &self.file_rules[idx];
            if rule.active {
                if self.match_table.count >= MAX_MATCH_ENTRIES {
                    return Err(Error::OutOfMemory);
                }
                let entry = &mut self.match_table.entries[self.match_table.count];
                entry.path = rule.path;
                entry.path_len = rule.path_len;
                entry.permissions = rule.permissions;
                entry.active = true;
                self.match_table.count = self.match_table.count.saturating_add(1);
            }
            idx = idx.saturating_add(1);
        }
        self.match_table.compiled = true;
        Ok(())
    }

    /// Check file access using the compiled match table.
    ///
    /// Falls back to the regular rule scan if the table has not
    /// been compiled.
    fn check_file_access_compiled(&self, path: &[u8], requested: FilePermission) -> bool {
        if !self.match_table.compiled {
            return self.check_file_access(path, requested);
        }
        let mut i = 0;
        while i < self.match_table.count {
            let entry = &self.match_table.entries[i];
            if entry.active {
                let pattern = &entry.path[..entry.path_len];
                if aa_glob_match(pattern, path) && entry.permissions.contains(requested) {
                    return true;
                }
            }
            i = i.saturating_add(1);
        }
        false
    }
}

// ── PidAssignment ─────────────────────────────────────────────────

/// Maps a PID to one or more profile indices (stacked profiles).
///
/// Profile stacking allows a process to be confined by multiple
/// profiles simultaneously. Access is allowed only if ALL stacked
/// profiles grant the requested operation (intersection semantics).
#[derive(Debug, Clone, Copy)]
struct PidAssignment {
    /// Process ID.
    pid: u64,
    /// Profile indices (stacked).
    profile_stack: [usize; MAX_PROFILE_STACK],
    /// Number of stacked profiles.
    stack_depth: usize,
    /// Whether this assignment slot is in use.
    active: bool,
}

impl PidAssignment {
    /// Create an empty, inactive assignment.
    const fn empty() -> Self {
        Self {
            pid: 0,
            profile_stack: [0; MAX_PROFILE_STACK],
            stack_depth: 0,
            active: false,
        }
    }
}

// ── AppArmorState ─────────────────────────────────────────────────

/// Per-PID profile assignment table.
///
/// Tracks which AppArmor profile each process is confined under.
/// Supports up to [`MAX_PIDS`] simultaneous assignments.
pub struct AppArmorState {
    /// PID-to-profile mappings.
    assignments: [PidAssignment; MAX_PIDS],
    /// Number of active assignments.
    count: usize,
}

impl Default for AppArmorState {
    fn default() -> Self {
        Self::new()
    }
}

impl AppArmorState {
    /// Create an empty assignment table.
    pub const fn new() -> Self {
        Self {
            assignments: [PidAssignment::empty(); MAX_PIDS],
            count: 0,
        }
    }

    /// Assign a profile to a PID (replaces any existing assignment).
    ///
    /// If the PID already has an assignment, its profile stack is
    /// replaced with the single provided profile.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the table is full and the
    /// PID does not have an existing entry.
    fn assign(&mut self, pid: u64, profile_idx: usize) -> Result<()> {
        // Update existing assignment if present.
        let mut i = 0;
        while i < MAX_PIDS {
            if self.assignments[i].active && self.assignments[i].pid == pid {
                self.assignments[i].profile_stack[0] = profile_idx;
                self.assignments[i].stack_depth = 1;
                return Ok(());
            }
            i = i.saturating_add(1);
        }
        // Find a free slot.
        let mut j = 0;
        while j < MAX_PIDS {
            if !self.assignments[j].active {
                let entry = &mut self.assignments[j];
                entry.pid = pid;
                entry.profile_stack = [0; MAX_PROFILE_STACK];
                entry.profile_stack[0] = profile_idx;
                entry.stack_depth = 1;
                entry.active = true;
                self.count = self.count.saturating_add(1);
                return Ok(());
            }
            j = j.saturating_add(1);
        }
        Err(Error::OutOfMemory)
    }

    /// Push an additional profile onto a PID's stack.
    ///
    /// Profile stacking causes all stacked profiles to be evaluated
    /// with intersection semantics (all must allow).
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the PID has no assignment.
    /// Returns [`Error::OutOfMemory`] if the stack is full.
    fn stack_profile(&mut self, pid: u64, profile_idx: usize) -> Result<()> {
        let mut i = 0;
        while i < MAX_PIDS {
            if self.assignments[i].active && self.assignments[i].pid == pid {
                let entry = &mut self.assignments[i];
                if entry.stack_depth >= MAX_PROFILE_STACK {
                    return Err(Error::OutOfMemory);
                }
                entry.profile_stack[entry.stack_depth] = profile_idx;
                entry.stack_depth = entry.stack_depth.saturating_add(1);
                return Ok(());
            }
            i = i.saturating_add(1);
        }
        Err(Error::NotFound)
    }

    /// Remove a PID's profile assignment.
    fn unassign(&mut self, pid: u64) {
        let mut i = 0;
        while i < MAX_PIDS {
            if self.assignments[i].active && self.assignments[i].pid == pid {
                self.assignments[i].active = false;
                self.count = self.count.saturating_sub(1);
                return;
            }
            i = i.saturating_add(1);
        }
    }

    /// Look up the primary profile index for a PID.
    fn lookup(&self, pid: u64) -> Option<usize> {
        let mut i = 0;
        while i < MAX_PIDS {
            if self.assignments[i].active && self.assignments[i].pid == pid {
                if self.assignments[i].stack_depth > 0 {
                    return Some(self.assignments[i].profile_stack[0]);
                }
                return None;
            }
            i = i.saturating_add(1);
        }
        None
    }

    /// Look up the full profile stack for a PID.
    ///
    /// Returns the stack slice and depth, or `None` if unassigned.
    fn lookup_stack(&self, pid: u64) -> Option<(&[usize; MAX_PROFILE_STACK], usize)> {
        let mut i = 0;
        while i < MAX_PIDS {
            if self.assignments[i].active && self.assignments[i].pid == pid {
                return Some((
                    &self.assignments[i].profile_stack,
                    self.assignments[i].stack_depth,
                ));
            }
            i = i.saturating_add(1);
        }
        None
    }

    /// Return the number of active assignments.
    pub fn count(&self) -> usize {
        self.count
    }
}

// ── AppArmorRegistry ──────────────────────────────────────────────

/// Global AppArmor profile registry and access control engine.
///
/// Manages profile loading/unloading, PID-to-profile assignment,
/// profile stacking, hierarchy, and access checks for file,
/// network, and capability operations.
pub struct AppArmorRegistry {
    /// Registered profiles.
    profiles: [AppArmorProfile; MAX_PROFILES],
    /// Number of active profiles.
    profile_count: usize,
    /// PID-to-profile assignment state.
    state: AppArmorState,
    /// Audit log for denied operations and mode changes.
    audit_log: AppArmorAuditLog,
}

impl Default for AppArmorRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl AppArmorRegistry {
    /// Create an empty registry with no profiles.
    pub const fn new() -> Self {
        const EMPTY: AppArmorProfile = AppArmorProfile::empty();
        Self {
            profiles: [EMPTY; MAX_PROFILES],
            profile_count: 0,
            state: AppArmorState::new(),
            audit_log: AppArmorAuditLog::new(),
        }
    }

    /// Load a new profile into the registry.
    ///
    /// The profile is assigned a slot and marked active. Its name
    /// must be unique within the registry.
    ///
    /// # Errors
    ///
    /// - [`Error::OutOfMemory`] if the registry is full.
    /// - [`Error::InvalidArgument`] if `name` is empty or exceeds
    ///   [`PROFILE_NAME_LEN`].
    /// - [`Error::AlreadyExists`] if a profile with the same name
    ///   is already loaded.
    pub fn load_profile(&mut self, name: &[u8], mode: ProfileMode) -> Result<usize> {
        self.load_profile_with_parent(name, mode, None)
    }

    /// Load a profile with an optional parent (child profile).
    ///
    /// Child profiles inherit the parent's restrictions: access is
    /// allowed only if both the child and its parent permit it.
    ///
    /// # Errors
    ///
    /// Same as [`Self::load_profile`], plus
    /// [`Error::InvalidArgument`] if the parent index is invalid.
    pub fn load_profile_with_parent(
        &mut self,
        name: &[u8],
        mode: ProfileMode,
        parent: Option<usize>,
    ) -> Result<usize> {
        if name.is_empty() || name.len() > PROFILE_NAME_LEN {
            return Err(Error::InvalidArgument);
        }
        // Validate parent if provided.
        if let Some(p) = parent {
            if p >= MAX_PROFILES || !self.profiles[p].active {
                return Err(Error::InvalidArgument);
            }
        }
        // Check for duplicate name.
        if self.find_profile_idx(name).is_some() {
            return Err(Error::AlreadyExists);
        }
        if self.profile_count >= MAX_PROFILES {
            return Err(Error::OutOfMemory);
        }
        // Find first inactive slot.
        let slot = self.find_free_slot().ok_or(Error::OutOfMemory)?;

        self.profiles[slot] = AppArmorProfile::empty();
        self.profiles[slot].name[..name.len()].copy_from_slice(name);
        self.profiles[slot].name_len = name.len();
        self.profiles[slot].mode = mode;
        self.profiles[slot].parent_idx = parent;
        self.profiles[slot].active = true;
        self.profile_count = self.profile_count.saturating_add(1);
        Ok(slot)
    }

    /// Unload a profile by name.
    ///
    /// All PID assignments referencing this profile are removed.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if no profile with the given
    /// name exists.
    pub fn unload_profile(&mut self, name: &[u8]) -> Result<()> {
        let idx = self.find_profile_idx(name).ok_or(Error::NotFound)?;
        self.profiles[idx].active = false;
        self.profile_count = self.profile_count.saturating_sub(1);

        // Remove all PID assignments that reference this profile
        // in any position of their stack.
        let mut i = 0;
        while i < MAX_PIDS {
            if self.state.assignments[i].active {
                let entry = &self.state.assignments[i];
                let mut found = false;
                let mut j = 0;
                while j < entry.stack_depth {
                    if entry.profile_stack[j] == idx {
                        found = true;
                    }
                    j = j.saturating_add(1);
                }
                if found {
                    self.state.assignments[i].active = false;
                    self.state.count = self.state.count.saturating_sub(1);
                }
            }
            i = i.saturating_add(1);
        }
        Ok(())
    }

    /// Change the operating mode of a profile.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if no profile with the given
    /// name exists.
    pub fn set_mode(&mut self, name: &[u8], mode: ProfileMode) -> Result<()> {
        let idx = self.find_profile_idx(name).ok_or(Error::NotFound)?;
        self.profiles[idx].mode = mode;
        Ok(())
    }

    /// Assign a PID to a named profile.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] if the profile name is not registered.
    /// - [`Error::OutOfMemory`] if the assignment table is full.
    pub fn assign_profile(&mut self, pid: u64, name: &[u8]) -> Result<()> {
        let idx = self.find_profile_idx(name).ok_or(Error::NotFound)?;
        self.state.assign(pid, idx)
    }

    /// Remove a PID's profile assignment (process cleanup).
    pub fn unassign_pid(&mut self, pid: u64) {
        self.state.unassign(pid);
    }

    /// Check file access for a process.
    ///
    /// Evaluates all stacked profiles with intersection semantics:
    /// access is allowed only if every profile in the stack permits
    /// it. Parent profiles are also checked recursively.
    ///
    /// Returns `Ok(())` if access is permitted. In Enforce mode,
    /// returns [`Error::PermissionDenied`] on denial. In Complain
    /// mode, always returns `Ok(())` (denial is logged). In Kill
    /// mode, returns [`Error::PermissionDenied`] on denial (caller
    /// must terminate the process). Unconfined profiles allow access.
    ///
    /// If the PID has no profile assignment, access is allowed
    /// (unconfined by default).
    pub fn check_file(&mut self, pid: u64, path: &[u8], requested: FilePermission) -> Result<()> {
        let (stack, depth) = match self.state.lookup_stack(pid) {
            Some(s) => s,
            None => return Ok(()),
        };
        // Copy stack to avoid borrow issues.
        let mut local_stack = [0usize; MAX_PROFILE_STACK];
        let local_depth = depth;
        local_stack[..local_depth].copy_from_slice(&stack[..local_depth]);

        let mut idx = 0;
        while idx < local_depth {
            let profile_idx = local_stack[idx];
            let result = self.check_file_single_with_parents(profile_idx, path, requested);
            if let Err(e) = result {
                self.audit_log
                    .record(pid, profile_idx, AaAuditKind::FileDenied, path);
                return Err(e);
            }
            idx = idx.saturating_add(1);
        }
        Ok(())
    }

    /// Check network access for a process.
    ///
    /// Same stacked intersection semantics as [`Self::check_file`].
    pub fn check_net(
        &mut self,
        pid: u64,
        domain: AddressFamily,
        sock_type: SocketType,
        requested: NetPermission,
    ) -> Result<()> {
        let (stack, depth) = match self.state.lookup_stack(pid) {
            Some(s) => s,
            None => return Ok(()),
        };
        let mut local_stack = [0usize; MAX_PROFILE_STACK];
        let local_depth = depth;
        local_stack[..local_depth].copy_from_slice(&stack[..local_depth]);

        let mut idx = 0;
        while idx < local_depth {
            let profile_idx = local_stack[idx];
            if let Err(e) = self.check_net_single(profile_idx, domain, sock_type, requested) {
                self.audit_log
                    .record(pid, profile_idx, AaAuditKind::NetDenied, b"net");
                return Err(e);
            }
            idx = idx.saturating_add(1);
        }
        Ok(())
    }

    /// Check capability access for a process.
    ///
    /// Same stacked intersection semantics as [`Self::check_file`].
    pub fn check_cap(&mut self, pid: u64, cap_id: u32) -> Result<()> {
        let (stack, depth) = match self.state.lookup_stack(pid) {
            Some(s) => s,
            None => return Ok(()),
        };
        let mut local_stack = [0usize; MAX_PROFILE_STACK];
        let local_depth = depth;
        local_stack[..local_depth].copy_from_slice(&stack[..local_depth]);

        let mut idx = 0;
        while idx < local_depth {
            let profile_idx = local_stack[idx];
            if let Err(e) = self.check_cap_single(profile_idx, cap_id) {
                self.audit_log
                    .record(pid, profile_idx, AaAuditKind::CapDenied, b"cap");
                return Err(e);
            }
            idx = idx.saturating_add(1);
        }
        Ok(())
    }

    /// Look up a domain transition for an exec path.
    ///
    /// If the PID's current profile has a transition rule matching
    /// `exec_path`, the process is reassigned to the target profile.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] if no transition matches or the target
    ///   profile does not exist.
    pub fn handle_exec_transition(&mut self, pid: u64, exec_path: &[u8]) -> Result<()> {
        let profile_idx = match self.state.lookup(pid) {
            Some(idx) => idx,
            None => return Ok(()), // No profile = no transition
        };

        // Find a matching transition in the current profile.
        let target_name = {
            let profile = &self.profiles[profile_idx];
            if !profile.active {
                return Ok(());
            }
            match profile.find_transition(exec_path) {
                Some(name) => {
                    // Copy the target name to avoid borrowing issues.
                    let mut buf = [0u8; PROFILE_NAME_LEN];
                    let len = name.len().min(PROFILE_NAME_LEN);
                    buf[..len].copy_from_slice(&name[..len]);
                    (buf, len)
                }
                None => return Ok(()),
            }
        };

        // Find the target profile and reassign.
        let target_idx = self
            .find_profile_idx(&target_name.0[..target_name.1])
            .ok_or(Error::NotFound)?;
        self.state.assign(pid, target_idx)
    }

    /// Get a mutable reference to a profile by name.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if no profile with the given
    /// name exists.
    pub fn get_profile_mut(&mut self, name: &[u8]) -> Result<&mut AppArmorProfile> {
        let idx = self.find_profile_idx(name).ok_or(Error::NotFound)?;
        Ok(&mut self.profiles[idx])
    }

    /// Stack an additional profile onto a PID's confinement.
    ///
    /// The process will be checked against all stacked profiles
    /// with intersection semantics (all must allow).
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] if the profile name or PID is not found.
    /// - [`Error::OutOfMemory`] if the profile stack is full.
    pub fn stack_profile(&mut self, pid: u64, name: &[u8]) -> Result<()> {
        let idx = self.find_profile_idx(name).ok_or(Error::NotFound)?;
        self.state.stack_profile(pid, idx)
    }

    /// Get the current label (active profile names) for a PID.
    ///
    /// The label is formatted as `profile1//&profile2` for stacked
    /// profiles. Returns the label bytes and length.
    pub fn get_label(&self, pid: u64) -> Option<([u8; PROFILE_NAME_LEN], usize)> {
        let (stack, depth) = self.state.lookup_stack(pid)?;
        if depth == 0 {
            return None;
        }
        let mut buf = [0u8; PROFILE_NAME_LEN];
        let mut pos = 0usize;
        let mut idx = 0;
        while idx < depth {
            let profile_idx = stack[idx];
            let profile = &self.profiles[profile_idx];
            if !profile.active {
                idx = idx.saturating_add(1);
                continue;
            }
            if pos > 0 && pos + 3 < PROFILE_NAME_LEN {
                buf[pos] = b'/';
                buf[pos + 1] = b'/';
                buf[pos + 2] = b'&';
                pos += 3;
            }
            let name_len = profile.name_len.min(PROFILE_NAME_LEN.saturating_sub(pos));
            buf[pos..pos + name_len].copy_from_slice(&profile.name[..name_len]);
            pos += name_len;
            idx = idx.saturating_add(1);
        }
        Some((buf, pos))
    }

    /// Compile a profile's rules into its binary match table.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the profile is not found, or
    /// [`Error::OutOfMemory`] if there are too many rules.
    pub fn compile_profile(&mut self, name: &[u8]) -> Result<()> {
        let idx = self.find_profile_idx(name).ok_or(Error::NotFound)?;
        self.profiles[idx].compile()
    }

    /// Return the number of loaded profiles.
    pub fn profile_count(&self) -> usize {
        self.profile_count
    }

    /// Return the number of active PID assignments.
    pub fn assignment_count(&self) -> usize {
        self.state.count()
    }

    /// Return a reference to the audit log.
    pub fn audit_log(&self) -> &AppArmorAuditLog {
        &self.audit_log
    }

    /// Get a profile by index (read-only).
    pub fn get_profile(&self, idx: usize) -> Option<&AppArmorProfile> {
        if idx < MAX_PROFILES && self.profiles[idx].active {
            Some(&self.profiles[idx])
        } else {
            None
        }
    }

    // ── Internal helpers ──────────────────────────────────────────

    /// Check file access for a single profile, walking up the
    /// parent hierarchy.
    fn check_file_single_with_parents(
        &self,
        profile_idx: usize,
        path: &[u8],
        requested: FilePermission,
    ) -> Result<()> {
        let mut cur = profile_idx;
        loop {
            let profile = &self.profiles[cur];
            if !profile.active {
                return Err(Error::PermissionDenied);
            }
            match profile.mode {
                ProfileMode::Unconfined => {}
                ProfileMode::Complain => {}
                ProfileMode::Enforce | ProfileMode::Kill => {
                    let allowed = profile.check_file_access_compiled(path, requested);
                    if !allowed {
                        return Err(Error::PermissionDenied);
                    }
                }
            }
            match profile.parent_idx {
                Some(parent) => cur = parent,
                None => break,
            }
        }
        Ok(())
    }

    /// Check network access for a single profile.
    fn check_net_single(
        &self,
        profile_idx: usize,
        domain: AddressFamily,
        sock_type: SocketType,
        requested: NetPermission,
    ) -> Result<()> {
        let profile = &self.profiles[profile_idx];
        if !profile.active {
            return Err(Error::PermissionDenied);
        }
        match profile.mode {
            ProfileMode::Unconfined | ProfileMode::Complain => Ok(()),
            ProfileMode::Enforce | ProfileMode::Kill => {
                if profile.check_net_access(domain, sock_type, requested) {
                    Ok(())
                } else {
                    Err(Error::PermissionDenied)
                }
            }
        }
    }

    /// Check capability access for a single profile.
    fn check_cap_single(&self, profile_idx: usize, cap_id: u32) -> Result<()> {
        let profile = &self.profiles[profile_idx];
        if !profile.active {
            return Err(Error::PermissionDenied);
        }
        match profile.mode {
            ProfileMode::Unconfined | ProfileMode::Complain => Ok(()),
            ProfileMode::Enforce | ProfileMode::Kill => {
                if profile.check_cap_access(cap_id) {
                    Ok(())
                } else {
                    Err(Error::PermissionDenied)
                }
            }
        }
    }

    /// Find the index of a profile by name.
    fn find_profile_idx(&self, name: &[u8]) -> Option<usize> {
        let mut i = 0;
        while i < MAX_PROFILES {
            let p = &self.profiles[i];
            if p.active && p.name_len == name.len() && p.name[..p.name_len] == *name {
                return Some(i);
            }
            i = i.saturating_add(1);
        }
        None
    }

    /// Find the first inactive profile slot.
    fn find_free_slot(&self) -> Option<usize> {
        let mut i = 0;
        while i < MAX_PROFILES {
            if !self.profiles[i].active {
                return Some(i);
            }
            i = i.saturating_add(1);
        }
        None
    }

    /// Get a reference to the profile assigned to a PID.
    #[allow(dead_code)]
    fn get_profile_for_pid(&self, pid: u64) -> Option<&AppArmorProfile> {
        let idx = self.state.lookup(pid)?;
        let profile = &self.profiles[idx];
        if profile.active { Some(profile) } else { None }
    }
}

// ── CompiledMatchTable ───────────────────────────────────────────

/// A single compiled match entry for fast file rule evaluation.
#[derive(Debug, Clone, Copy)]
pub struct CompiledMatchEntry {
    /// Path pattern (copied from file rule).
    pub path: [u8; PATH_PATTERN_LEN],
    /// Valid length of the path pattern.
    pub path_len: usize,
    /// Permitted file operations.
    pub permissions: FilePermission,
    /// Whether this entry is active.
    pub active: bool,
}

impl CompiledMatchEntry {
    /// Create an empty, inactive entry.
    const fn empty() -> Self {
        Self {
            path: [0u8; PATH_PATTERN_LEN],
            path_len: 0,
            permissions: FilePermission::NONE,
            active: false,
        }
    }
}

/// Compiled binary match table for a profile.
///
/// Pre-processes file rules into a flat array for faster
/// evaluation at access-check time. Rules are compiled once
/// via [`AppArmorProfile::compile`] and evaluated on every
/// file access check.
pub struct CompiledMatchTable {
    /// Match entries.
    entries: [CompiledMatchEntry; MAX_MATCH_ENTRIES],
    /// Number of active entries.
    count: usize,
    /// Whether the table has been compiled.
    compiled: bool,
}

impl CompiledMatchTable {
    /// Create an empty, uncompiled match table.
    const fn empty() -> Self {
        Self {
            entries: [CompiledMatchEntry::empty(); MAX_MATCH_ENTRIES],
            count: 0,
            compiled: false,
        }
    }

    /// Return whether the table has been compiled.
    pub fn is_compiled(&self) -> bool {
        self.compiled
    }

    /// Return the number of compiled entries.
    pub fn entry_count(&self) -> usize {
        self.count
    }
}

// ── AppArmor Audit Log ──────────────────────────────────────────

/// Kind of AppArmor audit event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AaAuditKind {
    /// File access denied.
    FileDenied,
    /// Network access denied.
    NetDenied,
    /// Capability denied.
    CapDenied,
    /// Profile transition.
    Transition,
    /// Profile mode change.
    ModeChange,
}

/// A single AppArmor audit log entry.
#[derive(Debug, Clone, Copy)]
pub struct AaAuditEntry {
    /// Process ID.
    pub pid: u64,
    /// Profile index.
    pub profile_idx: usize,
    /// Kind of event.
    pub kind: AaAuditKind,
    /// Description (path, cap name, etc.).
    pub desc: [u8; AUDIT_DESC_LEN],
    /// Valid length of description.
    pub desc_len: usize,
    /// Whether this slot is in use.
    pub in_use: bool,
}

impl AaAuditEntry {
    /// Create an empty, inactive entry.
    const fn empty() -> Self {
        Self {
            pid: 0,
            profile_idx: 0,
            kind: AaAuditKind::FileDenied,
            desc: [0u8; AUDIT_DESC_LEN],
            desc_len: 0,
            in_use: false,
        }
    }
}

/// Ring-buffer audit log for AppArmor events.
pub struct AppArmorAuditLog {
    /// Audit entries.
    entries: [AaAuditEntry; MAX_AUDIT_LOG],
    /// Total events recorded (may exceed capacity).
    total: usize,
}

impl Default for AppArmorAuditLog {
    fn default() -> Self {
        Self::new()
    }
}

impl AppArmorAuditLog {
    /// Create an empty audit log.
    pub const fn new() -> Self {
        Self {
            entries: [AaAuditEntry::empty(); MAX_AUDIT_LOG],
            total: 0,
        }
    }

    /// Record an audit event.
    pub fn record(&mut self, pid: u64, profile_idx: usize, kind: AaAuditKind, desc: &[u8]) {
        let idx = self.total % MAX_AUDIT_LOG;
        let entry = &mut self.entries[idx];
        entry.pid = pid;
        entry.profile_idx = profile_idx;
        entry.kind = kind;
        let copy_len = desc.len().min(AUDIT_DESC_LEN);
        entry.desc = [0u8; AUDIT_DESC_LEN];
        entry.desc[..copy_len].copy_from_slice(&desc[..copy_len]);
        entry.desc_len = copy_len;
        entry.in_use = true;
        self.total = self.total.saturating_add(1);
    }

    /// Return total events recorded.
    pub fn total_events(&self) -> usize {
        self.total
    }

    /// Return the number of available entries.
    pub fn available_entries(&self) -> usize {
        self.total.min(MAX_AUDIT_LOG)
    }

    /// Retrieve an entry by ring-buffer index.
    pub fn get_entry(&self, idx: usize) -> Option<&AaAuditEntry> {
        if idx >= self.available_entries() {
            return None;
        }
        let start = self.total.saturating_sub(MAX_AUDIT_LOG);
        let real_idx = (start + idx) % MAX_AUDIT_LOG;
        let entry = &self.entries[real_idx];
        if entry.in_use { Some(entry) } else { None }
    }
}

// ── Glob pattern matching ────────────────────────────────────────

/// Match a path against a glob-style pattern.
///
/// Supports `*` (single component), `**` (recursive), and trailing
/// `/` (directory prefix). Iterative algorithm, no allocation.
fn aa_glob_match(pattern: &[u8], path: &[u8]) -> bool {
    // Trailing '/' means directory prefix match.
    if !pattern.is_empty()
        && pattern[pattern.len() - 1] == b'/'
        && path.len() >= pattern.len()
        && path[..pattern.len()] == *pattern
    {
        return true;
    }

    let mut pi = 0usize;
    let mut si = 0usize;
    let mut star_pi: Option<usize> = None;
    let mut star_si = 0usize;

    while si < path.len() {
        // Check for `**`.
        if pi + 1 < pattern.len() && pattern[pi] == b'*' && pattern[pi + 1] == b'*' {
            pi += 2;
            if pi < pattern.len() && pattern[pi] == b'/' {
                pi += 1;
            }
            if pi >= pattern.len() {
                return true;
            }
            while si < path.len() {
                if aa_glob_match(&pattern[pi..], &path[si..]) {
                    return true;
                }
                si += 1;
            }
            return aa_glob_match(&pattern[pi..], &path[si..]);
        }

        if pi < pattern.len() && pattern[pi] == b'*' {
            star_pi = Some(pi);
            star_si = si;
            pi += 1;
            continue;
        }

        if pi < pattern.len() && pattern[pi] == path[si] {
            pi += 1;
            si += 1;
            continue;
        }

        if let Some(sp) = star_pi {
            pi = sp + 1;
            star_si += 1;
            if path[star_si - 1] == b'/' {
                return false;
            }
            si = star_si;
            continue;
        }

        return false;
    }

    while pi < pattern.len() && pattern[pi] == b'*' {
        pi += 1;
    }

    pi >= pattern.len()
}
