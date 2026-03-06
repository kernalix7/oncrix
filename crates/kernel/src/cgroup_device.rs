// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Cgroup v2 device controller for device access control.
//!
//! Implements the `devices` controller from Linux cgroups v2 with:
//! - Device type (char/block) and major/minor number matching
//! - Per-cgroup allow/deny rule lists
//! - Permission checking for read, write, and mknod operations
//! - Hierarchical permission inheritance from parent cgroups
//! - Default-deny policy (no access unless explicitly allowed)
//! - Wildcard matching for major/minor numbers
//!
//! # Types
//!
//! - [`DeviceType`] — character, block, or all device types
//! - [`DeviceAccess`] — read, write, mknod permission flags
//! - [`DeviceRule`] — a single allow/deny rule
//! - [`DeviceCgroupController`] — a single device cgroup instance
//! - [`DeviceCgroupRegistry`] — system-wide registry of device cgroups
//!
//! # Security Model
//!
//! The device cgroup implements a default-deny policy. Unless a rule
//! explicitly allows access, all device operations are rejected. Rules
//! are evaluated in order; the first matching rule determines the
//! outcome. Child cgroups cannot grant permissions not held by their
//! parent (hierarchical constraint).

use oncrix_lib::{Error, Result};

// ── Constants ──────────────────────────────────────────────────────

/// Maximum number of device cgroup controllers in the system.
const MAX_DEVICE_CGROUPS: usize = 64;

/// Maximum number of rules per device cgroup controller.
const MAX_RULES_PER_CGROUP: usize = 64;

/// Maximum number of PIDs per device cgroup controller.
const MAX_PIDS: usize = 32;

/// Maximum name length in bytes.
const MAX_NAME_LEN: usize = 64;

/// Wildcard value for major or minor device number.
const DEVICE_WILDCARD: u32 = u32::MAX;

// ── DeviceType ─────────────────────────────────────────────────────

/// Type of device a rule applies to.
///
/// Matches the Linux device model: character devices (terminals,
/// serial ports), block devices (disks), or all device types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceType {
    /// Character device (c).
    Char,
    /// Block device (b).
    Block,
    /// Matches both character and block devices (a).
    All,
}

impl Default for DeviceType {
    fn default() -> Self {
        Self::All
    }
}

// ── DeviceAccess ───────────────────────────────────────────────────

/// Permission flags for device access.
///
/// Each flag corresponds to a device operation: read, write, or
/// mknod (create device node). Multiple flags may be combined.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeviceAccess {
    /// Allow read operations on the device.
    pub read: bool,
    /// Allow write operations on the device.
    pub write: bool,
    /// Allow mknod (device node creation) operations.
    pub mknod: bool,
}

impl DeviceAccess {
    /// No access permissions.
    pub const NONE: Self = Self {
        read: false,
        write: false,
        mknod: false,
    };

    /// Full access permissions (read + write + mknod).
    pub const ALL: Self = Self {
        read: true,
        write: true,
        mknod: true,
    };

    /// Read-only access.
    pub const READ_ONLY: Self = Self {
        read: true,
        write: false,
        mknod: false,
    };

    /// Write-only access.
    pub const WRITE_ONLY: Self = Self {
        read: false,
        write: true,
        mknod: false,
    };

    /// Read-write access (no mknod).
    pub const READ_WRITE: Self = Self {
        read: true,
        write: true,
        mknod: false,
    };

    /// Returns `true` if no permissions are set.
    pub fn is_empty(&self) -> bool {
        !self.read && !self.write && !self.mknod
    }

    /// Returns `true` if the requested access is a subset of this
    /// access mask.
    pub fn contains(&self, requested: &DeviceAccess) -> bool {
        (!requested.read || self.read)
            && (!requested.write || self.write)
            && (!requested.mknod || self.mknod)
    }

    /// Returns the intersection of two access masks.
    pub fn intersect(&self, other: &DeviceAccess) -> DeviceAccess {
        DeviceAccess {
            read: self.read && other.read,
            write: self.write && other.write,
            mknod: self.mknod && other.mknod,
        }
    }
}

impl Default for DeviceAccess {
    fn default() -> Self {
        Self::NONE
    }
}

// ── RuleAction ─────────────────────────────────────────────────────

/// Whether a rule allows or denies access.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleAction {
    /// Permit the matched device access.
    Allow,
    /// Deny the matched device access.
    Deny,
}

impl Default for RuleAction {
    fn default() -> Self {
        Self::Deny
    }
}

// ── DeviceRule ──────────────────────────────────────────────────────

/// A single device access control rule.
///
/// Rules specify a device type, major/minor numbers (or wildcards),
/// the permission flags to match, and whether to allow or deny.
/// A major or minor value of [`DEVICE_WILDCARD`] matches any number.
#[derive(Debug, Clone, Copy)]
pub struct DeviceRule {
    /// Device type this rule applies to.
    pub dev_type: DeviceType,
    /// Major device number (`DEVICE_WILDCARD` = any).
    pub major: u32,
    /// Minor device number (`DEVICE_WILDCARD` = any).
    pub minor: u32,
    /// Permission flags for this rule.
    pub access: DeviceAccess,
    /// Whether this rule allows or denies access.
    pub action: RuleAction,
    /// Whether this rule slot is active.
    pub active: bool,
}

impl DeviceRule {
    /// Creates an inactive (empty) rule slot.
    const fn empty() -> Self {
        Self {
            dev_type: DeviceType::All,
            major: DEVICE_WILDCARD,
            minor: DEVICE_WILDCARD,
            access: DeviceAccess::NONE,
            action: RuleAction::Deny,
            active: false,
        }
    }

    /// Checks whether this rule matches the given device parameters.
    ///
    /// A rule matches if:
    /// - The device type matches (or the rule type is `All`)
    /// - The major number matches (or the rule major is wildcard)
    /// - The minor number matches (or the rule minor is wildcard)
    /// - The requested access is covered by the rule's access mask
    pub fn matches(
        &self,
        dev_type: DeviceType,
        major: u32,
        minor: u32,
        requested: &DeviceAccess,
    ) -> bool {
        if !self.active {
            return false;
        }

        // Check device type.
        let type_match = self.dev_type == DeviceType::All || self.dev_type == dev_type;
        if !type_match {
            return false;
        }

        // Check major number (wildcard matches all).
        if self.major != DEVICE_WILDCARD && self.major != major {
            return false;
        }

        // Check minor number (wildcard matches all).
        if self.minor != DEVICE_WILDCARD && self.minor != minor {
            return false;
        }

        // Check that the rule covers the requested access.
        self.access.contains(requested)
    }
}

// ── DeviceCgroupStats ──────────────────────────────────────────────

/// Statistics for a device cgroup controller.
#[derive(Debug, Clone, Copy, Default)]
pub struct DeviceCgroupStats {
    /// Total number of access checks performed.
    pub checks_total: u64,
    /// Number of accesses that were allowed.
    pub checks_allowed: u64,
    /// Number of accesses that were denied.
    pub checks_denied: u64,
    /// Number of active allow rules.
    pub allow_rules: u32,
    /// Number of active deny rules.
    pub deny_rules: u32,
}

// ── DeviceCgroupController ─────────────────────────────────────────

/// A single device cgroup controller instance.
///
/// Manages device access rules and permission checking for a set
/// of attached PIDs. Implements a default-deny policy: access is
/// denied unless an explicit allow rule matches. Rules are evaluated
/// in order; the first matching rule determines the verdict.
#[derive(Debug, Clone, Copy)]
pub struct DeviceCgroupController {
    /// Unique identifier for this controller.
    pub id: u64,
    /// Controller name (UTF-8 bytes, null-padded).
    pub name: [u8; MAX_NAME_LEN],
    /// Name length in bytes.
    name_len: usize,
    /// Device access rules (evaluated in order).
    rules: [DeviceRule; MAX_RULES_PER_CGROUP],
    /// Number of active rules.
    rule_count: usize,
    /// Attached process IDs.
    pids: [u64; MAX_PIDS],
    /// Number of attached PIDs.
    pid_count: usize,
    /// Access check statistics.
    stats: DeviceCgroupStats,
    /// Parent cgroup ID for hierarchical inheritance (0 = root).
    parent_id: u64,
    /// Whether this controller is enabled.
    pub enabled: bool,
    /// Whether this slot is actively in use.
    pub in_use: bool,
    /// Default policy when no rule matches.
    default_action: RuleAction,
}

impl DeviceCgroupController {
    /// Creates an empty (inactive) controller slot.
    const fn empty() -> Self {
        Self {
            id: 0,
            name: [0u8; MAX_NAME_LEN],
            name_len: 0,
            rules: [DeviceRule::empty(); MAX_RULES_PER_CGROUP],
            rule_count: 0,
            pids: [0u64; MAX_PIDS],
            pid_count: 0,
            stats: DeviceCgroupStats {
                checks_total: 0,
                checks_allowed: 0,
                checks_denied: 0,
                allow_rules: 0,
                deny_rules: 0,
            },
            parent_id: 0,
            enabled: false,
            in_use: false,
            default_action: RuleAction::Deny,
        }
    }

    /// Adds a device access rule to this controller.
    ///
    /// Rules are appended to the end of the rule list and evaluated
    /// in order during access checks.
    ///
    /// # Errors
    ///
    /// - `Error::InvalidArgument` — access mask is empty.
    /// - `Error::OutOfMemory` — rule list is full.
    pub fn add_rule(
        &mut self,
        dev_type: DeviceType,
        major: u32,
        minor: u32,
        access: DeviceAccess,
        action: RuleAction,
    ) -> Result<usize> {
        if access.is_empty() {
            return Err(Error::InvalidArgument);
        }
        if self.rule_count >= MAX_RULES_PER_CGROUP {
            return Err(Error::OutOfMemory);
        }

        let idx = self.rule_count;
        self.rules[idx] = DeviceRule {
            dev_type,
            major,
            minor,
            access,
            action,
            active: true,
        };
        self.rule_count += 1;

        // Update stats counters.
        match action {
            RuleAction::Allow => {
                self.stats.allow_rules = self.stats.allow_rules.saturating_add(1);
            }
            RuleAction::Deny => {
                self.stats.deny_rules = self.stats.deny_rules.saturating_add(1);
            }
        }

        Ok(idx)
    }

    /// Removes the rule at the given index.
    ///
    /// The remaining rules are shifted down to maintain order.
    ///
    /// # Errors
    ///
    /// Returns `Error::InvalidArgument` if the index is out of range.
    pub fn remove_rule(&mut self, index: usize) -> Result<()> {
        if index >= self.rule_count {
            return Err(Error::InvalidArgument);
        }

        // Update stats counters before removal.
        let rule = &self.rules[index];
        match rule.action {
            RuleAction::Allow => {
                self.stats.allow_rules = self.stats.allow_rules.saturating_sub(1);
            }
            RuleAction::Deny => {
                self.stats.deny_rules = self.stats.deny_rules.saturating_sub(1);
            }
        }

        // Shift remaining rules down to preserve evaluation order.
        let mut i = index;
        while i + 1 < self.rule_count {
            self.rules[i] = self.rules[i + 1];
            i += 1;
        }
        self.rules[self.rule_count.saturating_sub(1)] = DeviceRule::empty();
        self.rule_count = self.rule_count.saturating_sub(1);

        Ok(())
    }

    /// Removes all rules from this controller.
    pub fn clear_rules(&mut self) {
        for i in 0..self.rule_count {
            self.rules[i] = DeviceRule::empty();
        }
        self.rule_count = 0;
        self.stats.allow_rules = 0;
        self.stats.deny_rules = 0;
    }

    /// Checks whether the given device access is permitted.
    ///
    /// Evaluates rules in order. The first matching rule determines
    /// the verdict. If no rule matches, the default-deny policy
    /// applies (returns `false`).
    pub fn check_access(
        &mut self,
        dev_type: DeviceType,
        major: u32,
        minor: u32,
        requested: &DeviceAccess,
    ) -> bool {
        self.stats.checks_total = self.stats.checks_total.saturating_add(1);

        if !self.enabled {
            // Disabled controller allows all access.
            self.stats.checks_allowed = self.stats.checks_allowed.saturating_add(1);
            return true;
        }

        for i in 0..self.rule_count {
            let rule = &self.rules[i];
            if rule.matches(dev_type, major, minor, requested) {
                match rule.action {
                    RuleAction::Allow => {
                        self.stats.checks_allowed = self.stats.checks_allowed.saturating_add(1);
                        return true;
                    }
                    RuleAction::Deny => {
                        self.stats.checks_denied = self.stats.checks_denied.saturating_add(1);
                        return false;
                    }
                }
            }
        }

        // No rule matched — apply default policy.
        match self.default_action {
            RuleAction::Allow => {
                self.stats.checks_allowed = self.stats.checks_allowed.saturating_add(1);
                true
            }
            RuleAction::Deny => {
                self.stats.checks_denied = self.stats.checks_denied.saturating_add(1);
                false
            }
        }
    }

    /// Checks whether the given device access is permitted for a
    /// specific PID.
    ///
    /// Returns `Error::PermissionDenied` if the PID is attached to
    /// this controller and the access check fails.
    ///
    /// Returns `Ok(())` if the PID is not in this cgroup (not our
    /// responsibility) or if access is allowed.
    pub fn check_pid_access(
        &mut self,
        pid: u64,
        dev_type: DeviceType,
        major: u32,
        minor: u32,
        requested: &DeviceAccess,
    ) -> Result<()> {
        if !self.has_pid(pid) {
            return Ok(());
        }

        if self.check_access(dev_type, major, minor, requested) {
            Ok(())
        } else {
            Err(Error::PermissionDenied)
        }
    }

    /// Sets the parent cgroup ID for hierarchical inheritance.
    pub fn set_parent(&mut self, parent_id: u64) {
        self.parent_id = parent_id;
    }

    /// Returns the parent cgroup ID.
    pub fn parent_id(&self) -> u64 {
        self.parent_id
    }

    /// Sets the default action when no rule matches.
    pub fn set_default_action(&mut self, action: RuleAction) {
        self.default_action = action;
    }

    /// Returns the current default action.
    pub fn default_action(&self) -> RuleAction {
        self.default_action
    }

    /// Adds a PID to this controller.
    ///
    /// # Errors
    ///
    /// - `Error::AlreadyExists` — PID is already attached.
    /// - `Error::OutOfMemory` — PID list is full.
    pub fn add_pid(&mut self, pid: u64) -> Result<()> {
        if self.pids[..self.pid_count].contains(&pid) {
            return Err(Error::AlreadyExists);
        }
        if self.pid_count >= MAX_PIDS {
            return Err(Error::OutOfMemory);
        }
        self.pids[self.pid_count] = pid;
        self.pid_count += 1;
        Ok(())
    }

    /// Removes a PID from this controller.
    ///
    /// # Errors
    ///
    /// Returns `Error::NotFound` if the PID is not attached.
    pub fn remove_pid(&mut self, pid: u64) -> Result<()> {
        let pos = self.pids[..self.pid_count]
            .iter()
            .position(|&p| p == pid)
            .ok_or(Error::NotFound)?;

        self.pid_count -= 1;
        if pos < self.pid_count {
            self.pids[pos] = self.pids[self.pid_count];
        }
        self.pids[self.pid_count] = 0;
        Ok(())
    }

    /// Returns whether a PID is attached to this controller.
    pub fn has_pid(&self, pid: u64) -> bool {
        self.pids[..self.pid_count].contains(&pid)
    }

    /// Returns the number of attached PIDs.
    pub fn pid_count(&self) -> usize {
        self.pid_count
    }

    /// Returns the number of active rules.
    pub fn rule_count(&self) -> usize {
        self.rule_count
    }

    /// Returns a reference to the rule at the given index.
    ///
    /// Returns `None` if the index is out of range.
    pub fn get_rule(&self, index: usize) -> Option<&DeviceRule> {
        if index < self.rule_count {
            Some(&self.rules[index])
        } else {
            None
        }
    }

    /// Returns a reference to the access check statistics.
    pub fn get_stats(&self) -> &DeviceCgroupStats {
        &self.stats
    }

    /// Resets access check counters to zero.
    pub fn reset_stats(&mut self) {
        self.stats.checks_total = 0;
        self.stats.checks_allowed = 0;
        self.stats.checks_denied = 0;
    }
}

// ── DeviceCgroupRegistry ───────────────────────────────────────────

/// System-wide registry of device cgroup controllers.
///
/// Manages up to [`MAX_DEVICE_CGROUPS`] controllers in a fixed-size
/// array. Each controller is identified by a unique `u64` ID
/// assigned at creation time. Supports hierarchical permission
/// inheritance between parent and child cgroups.
pub struct DeviceCgroupRegistry {
    /// Fixed-size array of controller slots.
    controllers: [DeviceCgroupController; MAX_DEVICE_CGROUPS],
    /// Next controller ID to assign.
    next_id: u64,
    /// Number of active controllers.
    count: usize,
}

impl Default for DeviceCgroupRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl DeviceCgroupRegistry {
    /// Creates a new, empty registry.
    pub const fn new() -> Self {
        const EMPTY: DeviceCgroupController = DeviceCgroupController::empty();
        Self {
            controllers: [EMPTY; MAX_DEVICE_CGROUPS],
            next_id: 1,
            count: 0,
        }
    }

    /// Returns the number of active controllers.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Returns `true` if no controllers are registered.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Creates a new device cgroup controller with the given name.
    ///
    /// Returns the new controller's unique ID.
    ///
    /// # Errors
    ///
    /// - `Error::InvalidArgument` — name is empty or too long.
    /// - `Error::OutOfMemory` — no free slots available.
    pub fn create(&mut self, name: &[u8]) -> Result<u64> {
        if name.is_empty() || name.len() > MAX_NAME_LEN {
            return Err(Error::InvalidArgument);
        }
        if self.count >= MAX_DEVICE_CGROUPS {
            return Err(Error::OutOfMemory);
        }

        let slot = self
            .controllers
            .iter()
            .position(|c| !c.in_use)
            .ok_or(Error::OutOfMemory)?;

        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);

        let ctrl = &mut self.controllers[slot];
        *ctrl = DeviceCgroupController::empty();
        ctrl.id = id;
        ctrl.in_use = true;
        ctrl.enabled = true;
        ctrl.name_len = name.len();
        ctrl.name[..name.len()].copy_from_slice(name);

        self.count += 1;
        Ok(id)
    }

    /// Creates a child device cgroup with the given parent.
    ///
    /// The child inherits all rules from the parent at creation
    /// time. The child cannot later add rules that exceed the
    /// parent's permissions.
    ///
    /// # Errors
    ///
    /// - `Error::InvalidArgument` — name is empty or too long.
    /// - `Error::NotFound` — parent ID does not exist.
    /// - `Error::OutOfMemory` — no free slots or rule overflow.
    pub fn create_child(&mut self, name: &[u8], parent_id: u64) -> Result<u64> {
        // Validate parent exists and collect its rules.
        let parent_idx = self.index_of(parent_id)?;
        let parent_rule_count = self.controllers[parent_idx].rule_count;

        // Snapshot parent rules (Copy type, so we can copy them).
        let mut parent_rules = [DeviceRule::empty(); MAX_RULES_PER_CGROUP];
        for i in 0..parent_rule_count {
            parent_rules[i] = self.controllers[parent_idx].rules[i];
        }
        let parent_default = self.controllers[parent_idx].default_action;

        // Create the child.
        let child_id = self.create(name)?;
        let child_idx = self.index_of(child_id)?;
        let child = &mut self.controllers[child_idx];
        child.parent_id = parent_id;
        child.default_action = parent_default;

        // Copy parent rules to child.
        for i in 0..parent_rule_count {
            child.rules[i] = parent_rules[i];
        }
        child.rule_count = parent_rule_count;

        // Recalculate stats.
        let mut allow_count = 0u32;
        let mut deny_count = 0u32;
        for i in 0..parent_rule_count {
            match child.rules[i].action {
                RuleAction::Allow => allow_count += 1,
                RuleAction::Deny => deny_count += 1,
            }
        }
        child.stats.allow_rules = allow_count;
        child.stats.deny_rules = deny_count;

        Ok(child_id)
    }

    /// Destroys a device cgroup controller by ID.
    ///
    /// # Errors
    ///
    /// - `Error::NotFound` — controller does not exist.
    /// - `Error::Busy` — controller still has attached PIDs or
    ///   child cgroups.
    pub fn destroy(&mut self, id: u64) -> Result<()> {
        let idx = self.index_of(id)?;

        if self.controllers[idx].pid_count > 0 {
            return Err(Error::Busy);
        }

        // Check for child cgroups.
        let has_children = self
            .controllers
            .iter()
            .any(|c| c.in_use && c.parent_id == id);
        if has_children {
            return Err(Error::Busy);
        }

        self.controllers[idx].in_use = false;
        self.controllers[idx].enabled = false;
        self.count = self.count.saturating_sub(1);
        Ok(())
    }

    /// Returns an immutable reference to a controller by ID.
    pub fn get(&self, id: u64) -> Option<&DeviceCgroupController> {
        self.controllers.iter().find(|c| c.in_use && c.id == id)
    }

    /// Returns a mutable reference to a controller by ID.
    pub fn get_mut(&mut self, id: u64) -> Option<&mut DeviceCgroupController> {
        self.controllers.iter_mut().find(|c| c.in_use && c.id == id)
    }

    /// Adds a device access rule to a controller.
    ///
    /// If the controller has a parent, the rule is validated against
    /// the parent's rules to enforce hierarchical constraints: a
    /// child cannot allow access that the parent denies.
    ///
    /// # Errors
    ///
    /// - `Error::NotFound` — controller does not exist.
    /// - `Error::PermissionDenied` — rule exceeds parent permissions.
    /// - `Error::InvalidArgument` — empty access mask.
    /// - `Error::OutOfMemory` — rule list is full.
    pub fn add_rule(
        &mut self,
        id: u64,
        dev_type: DeviceType,
        major: u32,
        minor: u32,
        access: DeviceAccess,
        action: RuleAction,
    ) -> Result<usize> {
        let idx = self.index_of(id)?;
        let parent_id = self.controllers[idx].parent_id;

        // Hierarchical check: allow rules must be permitted by
        // the parent.
        if action == RuleAction::Allow && parent_id != 0 {
            if let Some(parent) = self.get_parent_index(parent_id) {
                let parent_ctrl = &self.controllers[parent];
                if !self.parent_permits(parent_ctrl, dev_type, major, minor, &access) {
                    return Err(Error::PermissionDenied);
                }
            }
        }

        self.controllers[idx].add_rule(dev_type, major, minor, access, action)
    }

    /// Checks device access for a PID across all active controllers.
    ///
    /// Iterates all cgroups that contain the given PID. If any
    /// cgroup denies access, the check fails.
    ///
    /// # Errors
    ///
    /// Returns `Error::PermissionDenied` if any containing cgroup
    /// denies the requested access.
    pub fn check_access(
        &mut self,
        pid: u64,
        dev_type: DeviceType,
        major: u32,
        minor: u32,
        requested: &DeviceAccess,
    ) -> Result<()> {
        for i in 0..MAX_DEVICE_CGROUPS {
            let ctrl = &self.controllers[i];
            if !ctrl.in_use || !ctrl.enabled {
                continue;
            }
            if !ctrl.pids[..ctrl.pid_count].contains(&pid) {
                continue;
            }

            // We need mutable access for stats tracking.
            // Re-borrow mutably for the specific controller.
            let ctrl = &mut self.controllers[i];
            if !ctrl.check_access(dev_type, major, minor, requested) {
                return Err(Error::PermissionDenied);
            }
        }
        Ok(())
    }

    /// Attaches a PID to a controller.
    ///
    /// # Errors
    ///
    /// - `Error::NotFound` — controller does not exist.
    /// - `Error::AlreadyExists` — PID is already attached.
    /// - `Error::OutOfMemory` — PID list is full.
    pub fn add_pid(&mut self, id: u64, pid: u64) -> Result<()> {
        let idx = self.index_of(id)?;
        self.controllers[idx].add_pid(pid)
    }

    /// Detaches a PID from a controller.
    ///
    /// # Errors
    ///
    /// - `Error::NotFound` — controller does not exist or PID is
    ///   not attached.
    pub fn remove_pid(&mut self, id: u64, pid: u64) -> Result<()> {
        let idx = self.index_of(id)?;
        self.controllers[idx].remove_pid(pid)
    }

    // ── Internal helpers ───────────────────────────────────────────

    /// Returns the index of an active controller by ID.
    fn index_of(&self, id: u64) -> Result<usize> {
        self.controllers
            .iter()
            .position(|c| c.in_use && c.id == id)
            .ok_or(Error::NotFound)
    }

    /// Returns the index of a parent controller, if it exists.
    fn get_parent_index(&self, parent_id: u64) -> Option<usize> {
        self.controllers
            .iter()
            .position(|c| c.in_use && c.id == parent_id)
    }

    /// Checks whether the parent controller permits the given
    /// device access.
    ///
    /// Walks the parent's rules to determine if a matching allow
    /// rule exists. Used to enforce hierarchical constraints.
    fn parent_permits(
        &self,
        parent: &DeviceCgroupController,
        dev_type: DeviceType,
        major: u32,
        minor: u32,
        access: &DeviceAccess,
    ) -> bool {
        for i in 0..parent.rule_count {
            let rule = &parent.rules[i];
            if rule.matches(dev_type, major, minor, access) {
                return rule.action == RuleAction::Allow;
            }
        }

        // No matching rule — fall back to parent's default.
        parent.default_action == RuleAction::Allow
    }
}
