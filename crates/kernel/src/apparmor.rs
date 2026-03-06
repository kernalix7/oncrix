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
    /// Uses prefix-based matching: the rule matches if the
    /// request path starts with the rule's path pattern.
    fn matches_path(&self, request_path: &[u8]) -> bool {
        if !self.active || request_path.len() < self.path_len {
            return false;
        }
        request_path[..self.path_len] == self.path[..self.path_len]
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
}

// ── PidAssignment ─────────────────────────────────────────────────

/// Maps a PID to a profile index in the registry.
#[derive(Debug, Clone, Copy)]
struct PidAssignment {
    /// Process ID.
    pid: u64,
    /// Index into the registry's profile array.
    profile_idx: usize,
    /// Whether this assignment slot is in use.
    active: bool,
}

impl PidAssignment {
    /// Create an empty, inactive assignment.
    const fn empty() -> Self {
        Self {
            pid: 0,
            profile_idx: 0,
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

    /// Assign a profile to a PID.
    ///
    /// If the PID already has an assignment, it is updated.
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
                self.assignments[i].profile_idx = profile_idx;
                return Ok(());
            }
            i = i.saturating_add(1);
        }
        // Find a free slot.
        let mut j = 0;
        while j < MAX_PIDS {
            if !self.assignments[j].active {
                self.assignments[j] = PidAssignment {
                    pid,
                    profile_idx,
                    active: true,
                };
                self.count = self.count.saturating_add(1);
                return Ok(());
            }
            j = j.saturating_add(1);
        }
        Err(Error::OutOfMemory)
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

    /// Look up the profile index for a PID.
    fn lookup(&self, pid: u64) -> Option<usize> {
        let mut i = 0;
        while i < MAX_PIDS {
            if self.assignments[i].active && self.assignments[i].pid == pid {
                return Some(self.assignments[i].profile_idx);
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
/// and access checks for file, network, and capability operations.
pub struct AppArmorRegistry {
    /// Registered profiles.
    profiles: [AppArmorProfile; MAX_PROFILES],
    /// Number of active profiles.
    profile_count: usize,
    /// PID-to-profile assignment state.
    state: AppArmorState,
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
        if name.is_empty() || name.len() > PROFILE_NAME_LEN {
            return Err(Error::InvalidArgument);
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

        // Remove all PID assignments pointing to this profile.
        let mut i = 0;
        while i < MAX_PIDS {
            if self.state.assignments[i].active && self.state.assignments[i].profile_idx == idx {
                self.state.assignments[i].active = false;
                self.state.count = self.state.count.saturating_sub(1);
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
    /// Returns `Ok(())` if access is permitted. In Enforce mode,
    /// returns [`Error::PermissionDenied`] on denial. In Complain
    /// mode, always returns `Ok(())`. In Kill mode, returns
    /// [`Error::PermissionDenied`] on denial (caller must terminate
    /// the process). Unconfined profiles always allow access.
    ///
    /// If the PID has no profile assignment, access is allowed
    /// (unconfined by default).
    pub fn check_file(&self, pid: u64, path: &[u8], requested: FilePermission) -> Result<()> {
        let profile = match self.get_profile_for_pid(pid) {
            Some(p) => p,
            None => return Ok(()), // No profile = unconfined
        };

        match profile.mode {
            ProfileMode::Unconfined => Ok(()),
            ProfileMode::Complain => Ok(()), // Log only, always allow
            ProfileMode::Enforce | ProfileMode::Kill => {
                if profile.check_file_access(path, requested) {
                    Ok(())
                } else {
                    Err(Error::PermissionDenied)
                }
            }
        }
    }

    /// Check network access for a process.
    ///
    /// Same enforcement semantics as [`Self::check_file`].
    pub fn check_net(
        &self,
        pid: u64,
        domain: AddressFamily,
        sock_type: SocketType,
        requested: NetPermission,
    ) -> Result<()> {
        let profile = match self.get_profile_for_pid(pid) {
            Some(p) => p,
            None => return Ok(()),
        };

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

    /// Check capability access for a process.
    ///
    /// Same enforcement semantics as [`Self::check_file`].
    pub fn check_cap(&self, pid: u64, cap_id: u32) -> Result<()> {
        let profile = match self.get_profile_for_pid(pid) {
            Some(p) => p,
            None => return Ok(()),
        };

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

    /// Return the number of loaded profiles.
    pub fn profile_count(&self) -> usize {
        self.profile_count
    }

    /// Return the number of active PID assignments.
    pub fn assignment_count(&self) -> usize {
        self.state.count()
    }

    // ── Internal helpers ──────────────────────────────────────────

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
    fn get_profile_for_pid(&self, pid: u64) -> Option<&AppArmorProfile> {
        let idx = self.state.lookup(pid)?;
        let profile = &self.profiles[idx];
        if profile.active { Some(profile) } else { None }
    }
}
