// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Landlock — unprivileged security sandboxing.
//!
//! Landlock enables any process to restrict its own access rights
//! without requiring elevated privileges. This is conceptually
//! similar to Linux's `landlock(7)` subsystem: a process creates a
//! ruleset describing which filesystem objects and network ports it
//! needs, then enforces that ruleset on itself. After enforcement
//! only the explicitly allowed accesses are permitted.
//!
//! Key concepts:
//! - **Ruleset**: declares handled access rights and a set of rules.
//! - **Rule**: pairs a resource (inode or network port) with an
//!   allowed access bitmask.
//! - **Enforcement**: once a ruleset is enforced on a process any
//!   access that falls under the handled rights but is not
//!   explicitly allowed is denied.
//!
//! Reference: Linux `security/landlock/`, `include/uapi/linux/landlock.h`.

use oncrix_lib::{Error, Result};

// ── Limits ──────────────────────────────────────────────────────

/// Maximum number of rulesets tracked by the global registry.
pub const MAX_RULESETS: usize = 32;

/// Maximum number of rules within a single ruleset.
pub const MAX_RULES_PER_SET: usize = 64;

// ── Filesystem access flags ────────────────────────────────────

/// Execute a file.
pub const LANDLOCK_ACCESS_FS_EXECUTE: u64 = 1 << 0;

/// Read a regular file.
pub const LANDLOCK_ACCESS_FS_READ_FILE: u64 = 1 << 1;

/// Read a directory (list entries).
pub const LANDLOCK_ACCESS_FS_READ_DIR: u64 = 1 << 2;

/// Write to a regular file.
pub const LANDLOCK_ACCESS_FS_WRITE_FILE: u64 = 1 << 3;

/// Remove a directory.
pub const LANDLOCK_ACCESS_FS_REMOVE_DIR: u64 = 1 << 4;

/// Remove (unlink) a regular file.
pub const LANDLOCK_ACCESS_FS_REMOVE_FILE: u64 = 1 << 5;

/// Create a character device node.
pub const LANDLOCK_ACCESS_FS_MAKE_CHAR: u64 = 1 << 6;

/// Create a directory.
pub const LANDLOCK_ACCESS_FS_MAKE_DIR: u64 = 1 << 7;

/// Create a regular file.
pub const LANDLOCK_ACCESS_FS_MAKE_REG: u64 = 1 << 8;

/// Create a UNIX domain socket node.
pub const LANDLOCK_ACCESS_FS_MAKE_SOCK: u64 = 1 << 9;

/// Create a named pipe (FIFO).
pub const LANDLOCK_ACCESS_FS_MAKE_FIFO: u64 = 1 << 10;

/// Create a block device node.
pub const LANDLOCK_ACCESS_FS_MAKE_BLOCK: u64 = 1 << 11;

/// Create a symbolic link.
pub const LANDLOCK_ACCESS_FS_MAKE_SYM: u64 = 1 << 12;

/// Link or rename a file across directories.
pub const LANDLOCK_ACCESS_FS_REFER: u64 = 1 << 13;

/// Truncate a file.
pub const LANDLOCK_ACCESS_FS_TRUNCATE: u64 = 1 << 14;

// ── Rule type ──────────────────────────────────────────────────

/// The kind of resource a [`LandlockRule`] applies to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum LandlockRuleType {
    /// Filesystem path-beneath rule (matched by inode).
    #[default]
    PathBeneath,
    /// Network port rule.
    NetPort,
}

// ── Rule ───────────────────────────────────────────────────────

/// A single Landlock access rule.
///
/// Each rule pairs a resource identifier (inode or port) with a
/// bitmask of allowed accesses from the filesystem or network
/// access flag constants.
#[derive(Debug, Clone, Copy)]
pub struct LandlockRule {
    /// Type of resource this rule covers.
    pub rule_type: LandlockRuleType,
    /// Bitmask of allowed access rights.
    pub allowed_access: u64,
    /// Inode number (only meaningful for [`LandlockRuleType::PathBeneath`]).
    pub inode: u64,
    /// Port number (only meaningful for [`LandlockRuleType::NetPort`]).
    pub port: u16,
    /// Whether this rule slot is active.
    pub active: bool,
}

impl LandlockRule {
    /// Create an empty, inactive rule.
    const fn empty() -> Self {
        Self {
            rule_type: LandlockRuleType::PathBeneath,
            allowed_access: 0,
            inode: 0,
            port: 0,
            active: false,
        }
    }
}

// ── Ruleset ────────────────────────────────────────────────────

/// A Landlock ruleset.
///
/// Groups a set of rules together with declarations of which
/// filesystem and network access classes are handled. Any handled
/// access that is not covered by a matching rule will be denied
/// once the ruleset is enforced.
pub struct LandlockRuleset {
    /// Unique identifier assigned by the registry.
    pub id: u32,
    /// Bitmask of handled filesystem access rights.
    pub handled_access_fs: u64,
    /// Bitmask of handled network access rights.
    pub handled_access_net: u64,
    /// Fixed-size array of rules.
    rules: [LandlockRule; MAX_RULES_PER_SET],
    /// Number of active rules.
    rule_count: usize,
    /// Whether this ruleset has been enforced.
    enforced: bool,
    /// PID of the process that owns this ruleset.
    pub owner_pid: u64,
    /// Whether this slot in the registry is occupied.
    pub active: bool,
}

impl LandlockRuleset {
    /// Create an empty, inactive ruleset.
    const fn empty() -> Self {
        Self {
            id: 0,
            handled_access_fs: 0,
            handled_access_net: 0,
            rules: [LandlockRule::empty(); MAX_RULES_PER_SET],
            rule_count: 0,
            enforced: false,
            owner_pid: 0,
            active: false,
        }
    }

    /// Add a rule to this ruleset.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the ruleset already
    /// contains [`MAX_RULES_PER_SET`] rules.
    pub fn add_rule(&mut self, rule: LandlockRule) -> Result<()> {
        if self.rule_count >= MAX_RULES_PER_SET {
            return Err(Error::OutOfMemory);
        }
        self.rules[self.rule_count] = rule;
        self.rules[self.rule_count].active = true;
        self.rule_count = self.rule_count.saturating_add(1);
        Ok(())
    }

    /// Remove the rule at `index`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `index` is out of
    /// bounds or the slot is already inactive.
    pub fn remove_rule(&mut self, index: usize) -> Result<()> {
        if index >= self.rule_count || !self.rules[index].active {
            return Err(Error::InvalidArgument);
        }
        self.rules[index].active = false;
        Ok(())
    }

    /// Check whether `access` to `inode` is allowed by this ruleset.
    ///
    /// Only access bits that fall within [`Self::handled_access_fs`]
    /// are checked. If the handled bits of the requested access are
    /// not fully covered by at least one matching rule the call
    /// returns [`Error::PermissionDenied`].
    pub fn check_fs_access(&self, inode: u64, access: u64) -> Result<()> {
        let relevant = access & self.handled_access_fs;
        if relevant == 0 {
            return Ok(());
        }

        let mut allowed: u64 = 0;
        let mut i = 0;
        while i < self.rule_count {
            let rule = &self.rules[i];
            if rule.active && rule.rule_type == LandlockRuleType::PathBeneath && rule.inode == inode
            {
                allowed |= rule.allowed_access;
            }
            i = i.saturating_add(1);
        }

        if relevant & allowed == relevant {
            Ok(())
        } else {
            Err(Error::PermissionDenied)
        }
    }

    /// Check whether `access` to `port` is allowed by this ruleset.
    ///
    /// Analogous to [`Self::check_fs_access`] but for network port
    /// rules.
    pub fn check_net_access(&self, port: u16, access: u64) -> Result<()> {
        let relevant = access & self.handled_access_net;
        if relevant == 0 {
            return Ok(());
        }

        let mut allowed: u64 = 0;
        let mut i = 0;
        while i < self.rule_count {
            let rule = &self.rules[i];
            if rule.active && rule.rule_type == LandlockRuleType::NetPort && rule.port == port {
                allowed |= rule.allowed_access;
            }
            i = i.saturating_add(1);
        }

        if relevant & allowed == relevant {
            Ok(())
        } else {
            Err(Error::PermissionDenied)
        }
    }

    /// Return the number of active rules.
    pub fn rule_count(&self) -> usize {
        self.rule_count
    }

    /// Return whether the ruleset has been enforced.
    pub fn is_enforced(&self) -> bool {
        self.enforced
    }
}

// ── Registry ───────────────────────────────────────────────────

/// Global registry of Landlock rulesets.
///
/// Manages creation, lookup, enforcement, and destruction of
/// rulesets. Each process may own multiple rulesets; enforcement
/// is per-ruleset.
pub struct LandlockRegistry {
    /// Fixed-size array of rulesets.
    rulesets: [LandlockRuleset; MAX_RULESETS],
    /// Next id to assign.
    next_id: u32,
    /// Number of active rulesets.
    count: usize,
}

impl Default for LandlockRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl LandlockRegistry {
    /// Create a new, empty registry.
    pub const fn new() -> Self {
        // `const fn` requires explicit array initialisation.
        const EMPTY: LandlockRuleset = LandlockRuleset::empty();
        Self {
            rulesets: [EMPTY; MAX_RULESETS],
            next_id: 1,
            count: 0,
        }
    }

    /// Create a new ruleset for `pid`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the registry is full.
    pub fn create_ruleset(&mut self, handled_fs: u64, handled_net: u64, pid: u64) -> Result<u32> {
        if self.count >= MAX_RULESETS {
            return Err(Error::OutOfMemory);
        }

        // Find the first inactive slot.
        let slot = self
            .rulesets
            .iter()
            .position(|r| !r.active)
            .ok_or(Error::OutOfMemory)?;

        let id = self.next_id;
        self.rulesets[slot] = LandlockRuleset {
            id,
            handled_access_fs: handled_fs,
            handled_access_net: handled_net,
            rules: [LandlockRule::empty(); MAX_RULES_PER_SET],
            rule_count: 0,
            enforced: false,
            owner_pid: pid,
            active: true,
        };
        self.next_id = self.next_id.saturating_add(1);
        self.count = self.count.saturating_add(1);
        Ok(id)
    }

    /// Add a rule to the ruleset identified by `ruleset_id`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if no active ruleset with the
    /// given id exists, or propagates errors from
    /// [`LandlockRuleset::add_rule`].
    pub fn add_rule(&mut self, ruleset_id: u32, rule: LandlockRule) -> Result<()> {
        let rs = self
            .rulesets
            .iter_mut()
            .find(|r| r.active && r.id == ruleset_id)
            .ok_or(Error::NotFound)?;
        rs.add_rule(rule)
    }

    /// Enforce the ruleset identified by `ruleset_id`.
    ///
    /// After this call, the owning process's accesses are checked
    /// against this ruleset's rules.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if no active ruleset with the
    /// given id exists. Returns [`Error::AlreadyExists`] if the
    /// ruleset is already enforced.
    pub fn restrict_self(&mut self, ruleset_id: u32) -> Result<()> {
        let rs = self
            .rulesets
            .iter_mut()
            .find(|r| r.active && r.id == ruleset_id)
            .ok_or(Error::NotFound)?;
        if rs.enforced {
            return Err(Error::AlreadyExists);
        }
        rs.enforced = true;
        Ok(())
    }

    /// Check filesystem access for `pid`.
    ///
    /// Iterates over all enforced rulesets owned by `pid`. If any
    /// ruleset denies the access the call fails with
    /// [`Error::PermissionDenied`].
    pub fn check_access(&self, pid: u64, inode: u64, access: u64) -> Result<()> {
        let mut i = 0;
        while i < MAX_RULESETS {
            let rs = &self.rulesets[i];
            if rs.active && rs.enforced && rs.owner_pid == pid {
                rs.check_fs_access(inode, access)?;
            }
            i = i.saturating_add(1);
        }
        Ok(())
    }

    /// Destroy the ruleset identified by `id`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if no active ruleset with the
    /// given id exists.
    pub fn destroy_ruleset(&mut self, id: u32) -> Result<()> {
        let rs = self
            .rulesets
            .iter_mut()
            .find(|r| r.active && r.id == id)
            .ok_or(Error::NotFound)?;
        rs.active = false;
        rs.enforced = false;
        self.count = self.count.saturating_sub(1);
        Ok(())
    }

    /// Remove all rulesets owned by `pid`.
    ///
    /// This is intended for process teardown cleanup.
    pub fn cleanup_pid(&mut self, pid: u64) {
        let mut i = 0;
        while i < MAX_RULESETS {
            if self.rulesets[i].active && self.rulesets[i].owner_pid == pid {
                self.rulesets[i].active = false;
                self.rulesets[i].enforced = false;
                self.count = self.count.saturating_sub(1);
            }
            i = i.saturating_add(1);
        }
    }

    /// Return the number of active rulesets.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Return whether the registry contains no active rulesets.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
}
