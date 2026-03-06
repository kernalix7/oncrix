// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Landlock LSM core — unprivileged, stackable security module.
//!
//! Landlock enables unprivileged processes to restrict their own access
//! rights using a rule-based sandbox.  Unlike other LSMs, Landlock does
//! not require root privileges to activate.
//!
//! # Architecture
//!
//! ```text
//! ┌──────────────────────────────────────────────────────────────┐
//! │                    LandlockSubsystem                         │
//! │                                                              │
//! │  Ruleset[0..MAX_RULESETS]                                    │
//! │  ┌────────────────────────────────────────────────────────┐  │
//! │  │  id: u64                                               │  │
//! │  │  handled_access_fs: u64                                │  │
//! │  │  handled_access_net: u64                               │  │
//! │  │  rules: [Rule; MAX_RULES_PER_SET]                      │  │
//! │  │  rule_count: usize                                     │  │
//! │  │  state: RulesetState                                   │  │
//! │  └────────────────────────────────────────────────────────┘  │
//! │                                                              │
//! │  Domain[0..MAX_DOMAINS]  (enforcement contexts)              │
//! │  ┌────────────────────────────────────────────────────────┐  │
//! │  │  pid: u64                                              │  │
//! │  │  ruleset_id: u64                                       │  │
//! │  │  enforced: bool                                        │  │
//! │  └────────────────────────────────────────────────────────┘  │
//! └──────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Reference
//!
//! Linux `security/landlock/`, `include/uapi/linux/landlock.h`.

use oncrix_lib::{Error, Result};

// ══════════════════════════════════════════════════════════════
// Constants
// ══════════════════════════════════════════════════════════════

/// Maximum number of rulesets.
const MAX_RULESETS: usize = 256;

/// Maximum rules per ruleset.
const MAX_RULES_PER_SET: usize = 64;

/// Maximum active enforcement domains.
const MAX_DOMAINS: usize = 1024;

// ── Access right bit flags (filesystem) ──────────────────────

/// Execute a file.
pub const ACCESS_FS_EXECUTE: u64 = 1 << 0;
/// Open a file for writing.
pub const ACCESS_FS_WRITE_FILE: u64 = 1 << 1;
/// Open a file for reading.
pub const ACCESS_FS_READ_FILE: u64 = 1 << 2;
/// Open a directory for reading.
pub const ACCESS_FS_READ_DIR: u64 = 1 << 3;
/// Remove a directory.
pub const ACCESS_FS_REMOVE_DIR: u64 = 1 << 4;
/// Remove a file.
pub const ACCESS_FS_REMOVE_FILE: u64 = 1 << 5;
/// Create a regular file.
pub const ACCESS_FS_MAKE_REG: u64 = 1 << 6;
/// Create a directory.
pub const ACCESS_FS_MAKE_DIR: u64 = 1 << 7;

// ── Access right bit flags (network) ─────────────────────────

/// Bind to a TCP port.
pub const ACCESS_NET_BIND_TCP: u64 = 1 << 0;
/// Connect to a TCP port.
pub const ACCESS_NET_CONNECT_TCP: u64 = 1 << 1;

// ══════════════════════════════════════════════════════════════
// RuleType
// ══════════════════════════════════════════════════════════════

/// Type of Landlock rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum RuleType {
    /// Filesystem path-based rule.
    PathBeneath = 0,
    /// Network port-based rule.
    NetPort = 1,
}

// ══════════════════════════════════════════════════════════════
// RulesetState
// ══════════════════════════════════════════════════════════════

/// State of a Landlock ruleset.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum RulesetState {
    /// Slot is empty.
    Empty = 0,
    /// Ruleset is being built (accepting new rules).
    Building = 1,
    /// Ruleset is enforced (immutable).
    Enforced = 2,
}

// ══════════════════════════════════════════════════════════════
// Rule
// ══════════════════════════════════════════════════════════════

/// A single Landlock access rule.
#[derive(Debug, Clone, Copy)]
pub struct Rule {
    /// Rule type (path or network).
    pub rule_type: RuleType,
    /// Allowed access bitmask for this rule.
    pub allowed_access: u64,
    /// Object identifier (inode for paths, port for network).
    pub object_id: u64,
    /// Whether the rule is active.
    pub active: bool,
}

impl Rule {
    /// Create an empty rule.
    const fn empty() -> Self {
        Self {
            rule_type: RuleType::PathBeneath,
            allowed_access: 0,
            object_id: 0,
            active: false,
        }
    }
}

// ══════════════════════════════════════════════════════════════
// Ruleset
// ══════════════════════════════════════════════════════════════

/// A Landlock ruleset: a collection of access rules.
#[derive(Debug, Clone, Copy)]
pub struct Ruleset {
    /// Unique ruleset identifier.
    pub id: u64,
    /// Bitmask of filesystem access rights handled by this ruleset.
    pub handled_access_fs: u64,
    /// Bitmask of network access rights handled by this ruleset.
    pub handled_access_net: u64,
    /// Rules within this ruleset.
    pub rules: [Rule; MAX_RULES_PER_SET],
    /// Number of active rules.
    pub rule_count: usize,
    /// Current state.
    pub state: RulesetState,
}

impl Ruleset {
    /// Create an empty ruleset slot.
    const fn empty() -> Self {
        Self {
            id: 0,
            handled_access_fs: 0,
            handled_access_net: 0,
            rules: [const { Rule::empty() }; MAX_RULES_PER_SET],
            rule_count: 0,
            state: RulesetState::Empty,
        }
    }

    /// Returns `true` if the slot is occupied.
    pub const fn is_active(&self) -> bool {
        !matches!(self.state, RulesetState::Empty)
    }
}

// ══════════════════════════════════════════════════════════════
// Domain — enforcement context
// ══════════════════════════════════════════════════════════════

/// An enforcement domain binding a process to a ruleset.
#[derive(Debug, Clone, Copy)]
pub struct Domain {
    /// PID of the sandboxed process.
    pub pid: u64,
    /// Ruleset ID applied to this process.
    pub ruleset_id: u64,
    /// Whether enforcement is active.
    pub enforced: bool,
}

impl Domain {
    /// Create an empty domain slot.
    const fn empty() -> Self {
        Self {
            pid: 0,
            ruleset_id: 0,
            enforced: false,
        }
    }
}

// ══════════════════════════════════════════════════════════════
// LandlockStats
// ══════════════════════════════════════════════════════════════

/// Aggregated Landlock statistics.
#[derive(Debug, Clone, Copy)]
pub struct LandlockStats {
    /// Total rulesets created.
    pub total_rulesets_created: u64,
    /// Total rules added.
    pub total_rules_added: u64,
    /// Total domains enforced.
    pub total_domains_enforced: u64,
    /// Total access checks performed.
    pub total_access_checks: u64,
    /// Total access denials.
    pub total_denials: u64,
}

impl LandlockStats {
    /// Create zero-initialised stats.
    const fn new() -> Self {
        Self {
            total_rulesets_created: 0,
            total_rules_added: 0,
            total_domains_enforced: 0,
            total_access_checks: 0,
            total_denials: 0,
        }
    }
}

// ══════════════════════════════════════════════════════════════
// LandlockSubsystem
// ══════════════════════════════════════════════════════════════

/// Top-level Landlock security subsystem.
pub struct LandlockSubsystem {
    /// Ruleset table.
    rulesets: [Ruleset; MAX_RULESETS],
    /// Enforcement domains.
    domains: [Domain; MAX_DOMAINS],
    /// Statistics.
    stats: LandlockStats,
    /// Next ruleset ID to allocate.
    next_id: u64,
    /// Whether the subsystem is initialised.
    initialised: bool,
}

impl Default for LandlockSubsystem {
    fn default() -> Self {
        Self::new()
    }
}

impl LandlockSubsystem {
    /// Create a new, uninitialised Landlock subsystem.
    pub const fn new() -> Self {
        Self {
            rulesets: [const { Ruleset::empty() }; MAX_RULESETS],
            domains: [const { Domain::empty() }; MAX_DOMAINS],
            stats: LandlockStats::new(),
            next_id: 1,
            initialised: false,
        }
    }

    /// Initialise the subsystem.
    pub fn init(&mut self) -> Result<()> {
        if self.initialised {
            return Err(Error::AlreadyExists);
        }
        self.initialised = true;
        Ok(())
    }

    // ── Ruleset management ───────────────────────────────────

    /// Create a new ruleset with the given handled access flags.
    ///
    /// Returns the ruleset ID.
    ///
    /// # Errors
    ///
    /// - `OutOfMemory` if no free ruleset slots remain.
    pub fn create_ruleset(
        &mut self,
        handled_access_fs: u64,
        handled_access_net: u64,
    ) -> Result<u64> {
        let slot = self.find_free_ruleset()?;
        let id = self.next_id;
        self.next_id += 1;

        self.rulesets[slot].id = id;
        self.rulesets[slot].handled_access_fs = handled_access_fs;
        self.rulesets[slot].handled_access_net = handled_access_net;
        self.rulesets[slot].state = RulesetState::Building;
        self.rulesets[slot].rule_count = 0;

        self.stats.total_rulesets_created += 1;
        Ok(id)
    }

    /// Add a rule to a ruleset.
    ///
    /// # Errors
    ///
    /// - `NotFound` if the ruleset does not exist.
    /// - `InvalidArgument` if the ruleset is already enforced.
    /// - `OutOfMemory` if the ruleset is full.
    pub fn add_rule(
        &mut self,
        ruleset_id: u64,
        rule_type: RuleType,
        allowed_access: u64,
        object_id: u64,
    ) -> Result<()> {
        let slot = self.find_ruleset(ruleset_id)?;

        if matches!(self.rulesets[slot].state, RulesetState::Enforced) {
            return Err(Error::InvalidArgument);
        }

        let rule_idx = self.rulesets[slot].rule_count;
        if rule_idx >= MAX_RULES_PER_SET {
            return Err(Error::OutOfMemory);
        }

        self.rulesets[slot].rules[rule_idx] = Rule {
            rule_type,
            allowed_access,
            object_id,
            active: true,
        };
        self.rulesets[slot].rule_count += 1;
        self.stats.total_rules_added += 1;
        Ok(())
    }

    // ── Enforcement ──────────────────────────────────────────

    /// Enforce a ruleset on a process (restrict_self equivalent).
    ///
    /// # Errors
    ///
    /// - `NotFound` if the ruleset does not exist.
    /// - `OutOfMemory` if no domain slots remain.
    pub fn enforce(&mut self, ruleset_id: u64, pid: u64) -> Result<()> {
        let rs_slot = self.find_ruleset(ruleset_id)?;
        self.rulesets[rs_slot].state = RulesetState::Enforced;

        let dom_slot = self.find_free_domain()?;
        self.domains[dom_slot].pid = pid;
        self.domains[dom_slot].ruleset_id = ruleset_id;
        self.domains[dom_slot].enforced = true;

        self.stats.total_domains_enforced += 1;
        Ok(())
    }

    /// Check if a filesystem access is allowed for a process.
    ///
    /// Returns `Ok(true)` if allowed, `Ok(false)` if denied.
    pub fn check_fs_access(&mut self, pid: u64, access: u64, object_id: u64) -> Result<bool> {
        self.stats.total_access_checks += 1;

        let dom = match self.find_domain(pid) {
            Some(idx) => idx,
            None => return Ok(true), // Not sandboxed.
        };

        let ruleset_id = self.domains[dom].ruleset_id;
        let rs_slot = self.find_ruleset(ruleset_id)?;
        let ruleset = &self.rulesets[rs_slot];

        // If this access type is not handled, allow it.
        if (ruleset.handled_access_fs & access) == 0 {
            return Ok(true);
        }

        // Check rules for a matching allow.
        for i in 0..ruleset.rule_count {
            let rule = &ruleset.rules[i];
            if rule.active
                && matches!(rule.rule_type, RuleType::PathBeneath)
                && rule.object_id == object_id
                && (rule.allowed_access & access) == access
            {
                return Ok(true);
            }
        }

        self.stats.total_denials += 1;
        Ok(false)
    }

    // ── Query ────────────────────────────────────────────────

    /// Return statistics.
    pub fn stats(&self) -> LandlockStats {
        self.stats
    }

    /// Return the number of active rulesets.
    pub fn active_rulesets(&self) -> usize {
        self.rulesets.iter().filter(|r| r.is_active()).count()
    }

    /// Return the number of enforced domains.
    pub fn enforced_domains(&self) -> usize {
        self.domains.iter().filter(|d| d.enforced).count()
    }

    // ── Internal helpers ─────────────────────────────────────

    fn find_free_ruleset(&self) -> Result<usize> {
        self.rulesets
            .iter()
            .position(|r| matches!(r.state, RulesetState::Empty))
            .ok_or(Error::OutOfMemory)
    }

    fn find_ruleset(&self, id: u64) -> Result<usize> {
        self.rulesets
            .iter()
            .position(|r| r.is_active() && r.id == id)
            .ok_or(Error::NotFound)
    }

    fn find_free_domain(&self) -> Result<usize> {
        self.domains
            .iter()
            .position(|d| !d.enforced)
            .ok_or(Error::OutOfMemory)
    }

    fn find_domain(&self, pid: u64) -> Option<usize> {
        self.domains.iter().position(|d| d.enforced && d.pid == pid)
    }
}
