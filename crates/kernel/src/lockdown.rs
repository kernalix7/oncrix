// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Kernel lockdown subsystem.
//!
//! Restricts access to kernel features that could be used to modify
//! the running kernel or extract confidential information. Lockdown
//! enforces a monotonically increasing restriction level:
//!
//! - **None**: All operations permitted (development mode).
//! - **Integrity**: Operations that could modify the running kernel
//!   are blocked (e.g., module loading, `/dev/mem`, kexec).
//! - **Confidentiality**: In addition to integrity protections,
//!   operations that could leak kernel data are blocked
//!   (e.g., `/proc/kcore`, BPF read, perf events).
//!
//! Once the lockdown level is raised, it cannot be lowered without
//! a reboot.
//!
//! # Architecture
//!
//! ```text
//!  LockdownRegistry
//!   └── LockdownState
//!        ├── current level: None | Integrity | Confidentiality
//!        ├── rules[32]: (operation → minimum blocking level)
//!        └── violation_log[64]: ring buffer of denied operations
//! ```
//!
//! Reference: Linux `security/lockdown/lockdown.c`,
//! `include/linux/security.h`.

use oncrix_lib::{Error, Result};

// ── Constants ─────────────────────────────────────────────────────

/// Maximum number of lockdown rules.
const MAX_RULES: usize = 32;

/// Maximum violation log entries (ring buffer).
const MAX_VIOLATIONS: usize = 64;

/// Maximum length of a violation description.
const VIOLATION_DESC_LEN: usize = 64;

// ── Lockdown level ────────────────────────────────────────────────

/// Kernel lockdown restriction level.
///
/// Levels are ordered: `None < Integrity < Confidentiality`.
/// A higher level implies all restrictions of lower levels.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum LockdownLevel {
    /// No restrictions. Full kernel access permitted.
    None = 0,
    /// Integrity protection: prevent kernel code modification.
    Integrity = 1,
    /// Confidentiality protection: also prevent data extraction.
    Confidentiality = 2,
}

impl LockdownLevel {
    /// Create from raw integer value.
    pub const fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::None),
            1 => Some(Self::Integrity),
            2 => Some(Self::Confidentiality),
            _ => Option::None,
        }
    }

    /// Returns `true` if `self` is at least as restrictive as `other`.
    pub const fn at_least(self, other: LockdownLevel) -> bool {
        (self as u8) >= (other as u8)
    }
}

impl core::fmt::Display for LockdownLevel {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::None => write!(f, "none"),
            Self::Integrity => write!(f, "integrity"),
            Self::Confidentiality => write!(f, "confidentiality"),
        }
    }
}

// ── Lockdown operation ────────────────────────────────────────────

/// Kernel operations that can be restricted by lockdown.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum LockdownOperation {
    /// Loading kernel modules from user space.
    ModuleLoading = 0,
    /// Direct access to physical memory (`/dev/mem`).
    DevMem = 1,
    /// Loading a new kernel via kexec.
    Kexec = 2,
    /// Hibernation (writes kernel memory to disk).
    Hibernation = 3,
    /// Direct PCI configuration space access.
    PciAccess = 4,
    /// Direct I/O port access (x86 `in`/`out`).
    IoPortAccess = 5,
    /// Model-specific register access (x86 `rdmsr`/`wrmsr`).
    MsrAccess = 6,
    /// ACPI table override from user space.
    AcpiTables = 7,
    /// Debugfs access.
    Debugfs = 8,
    /// BPF read of kernel memory.
    BpfRead = 9,
    /// Performance monitoring events.
    PerfEvents = 10,
    /// Trace filesystem access.
    Tracefs = 11,
    /// Access to `/proc/kcore` (kernel memory image).
    KcoreAccess = 12,
}

impl LockdownOperation {
    /// Create from raw integer value.
    pub const fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::ModuleLoading),
            1 => Some(Self::DevMem),
            2 => Some(Self::Kexec),
            3 => Some(Self::Hibernation),
            4 => Some(Self::PciAccess),
            5 => Some(Self::IoPortAccess),
            6 => Some(Self::MsrAccess),
            7 => Some(Self::AcpiTables),
            8 => Some(Self::Debugfs),
            9 => Some(Self::BpfRead),
            10 => Some(Self::PerfEvents),
            11 => Some(Self::Tracefs),
            12 => Some(Self::KcoreAccess),
            _ => Option::None,
        }
    }
}

impl core::fmt::Display for LockdownOperation {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::ModuleLoading => write!(f, "module_loading"),
            Self::DevMem => write!(f, "dev_mem"),
            Self::Kexec => write!(f, "kexec"),
            Self::Hibernation => write!(f, "hibernation"),
            Self::PciAccess => write!(f, "pci_access"),
            Self::IoPortAccess => write!(f, "ioport_access"),
            Self::MsrAccess => write!(f, "msr_access"),
            Self::AcpiTables => write!(f, "acpi_tables"),
            Self::Debugfs => write!(f, "debugfs"),
            Self::BpfRead => write!(f, "bpf_read"),
            Self::PerfEvents => write!(f, "perf_events"),
            Self::Tracefs => write!(f, "tracefs"),
            Self::KcoreAccess => write!(f, "kcore_access"),
        }
    }
}

// ── Lockdown rule ─────────────────────────────────────────────────

/// A rule mapping an operation to the minimum lockdown level
/// at which it becomes blocked.
#[derive(Debug, Clone, Copy)]
pub struct LockdownRule {
    /// The operation this rule applies to.
    pub operation: LockdownOperation,
    /// Minimum lockdown level that blocks this operation.
    ///
    /// If the current lockdown level is `>= min_level`, the
    /// operation is denied.
    pub min_level: LockdownLevel,
}

impl LockdownRule {
    /// Create a new lockdown rule.
    pub const fn new(operation: LockdownOperation, min_level: LockdownLevel) -> Self {
        Self {
            operation,
            min_level,
        }
    }
}

// ── Violation log entry ───────────────────────────────────────────

/// Record of a denied lockdown operation.
#[derive(Debug, Clone, Copy)]
pub struct LockdownViolation {
    /// The operation that was denied.
    pub operation: LockdownOperation,
    /// The lockdown level that caused denial.
    pub level: LockdownLevel,
    /// Timestamp (kernel ticks) when the violation occurred.
    pub timestamp: u64,
    /// Process ID that attempted the operation.
    pub pid: u32,
    /// Short description of the violation context.
    pub description: [u8; VIOLATION_DESC_LEN],
    /// Length of the description.
    pub desc_len: usize,
}

impl LockdownViolation {
    /// Create a zeroed violation entry.
    const fn zeroed() -> Self {
        Self {
            operation: LockdownOperation::ModuleLoading,
            level: LockdownLevel::None,
            timestamp: 0,
            pid: 0,
            description: [0u8; VIOLATION_DESC_LEN],
            desc_len: 0,
        }
    }

    /// Create a new violation record.
    pub fn new(
        operation: LockdownOperation,
        level: LockdownLevel,
        timestamp: u64,
        pid: u32,
        desc: &[u8],
    ) -> Self {
        let desc_len = if desc.len() > VIOLATION_DESC_LEN {
            VIOLATION_DESC_LEN
        } else {
            desc.len()
        };
        let mut description = [0u8; VIOLATION_DESC_LEN];
        let mut i = 0usize;
        while i < desc_len {
            description[i] = desc[i];
            i += 1;
        }
        Self {
            operation,
            level,
            timestamp,
            pid,
            description,
            desc_len,
        }
    }
}

// ── Lockdown state ────────────────────────────────────────────────

/// Internal lockdown state tracking current level, rules, and
/// violation history.
pub struct LockdownState {
    /// Current lockdown level (can only increase).
    level: LockdownLevel,
    /// Configured rules.
    rules: [Option<LockdownRule>; MAX_RULES],
    /// Number of active rules.
    rule_count: usize,
    /// Violation log (ring buffer).
    violations: [LockdownViolation; MAX_VIOLATIONS],
    /// Total number of violations recorded.
    violation_count: u64,
    /// Write position in the ring buffer.
    violation_head: usize,
}

impl LockdownState {
    /// Create a new lockdown state at level `None` with default rules.
    pub fn new() -> Self {
        const NONE_RULE: Option<LockdownRule> = Option::None;
        let mut state = Self {
            level: LockdownLevel::None,
            rules: [NONE_RULE; MAX_RULES],
            rule_count: 0,
            violations: [LockdownViolation::zeroed(); MAX_VIOLATIONS],
            violation_count: 0,
            violation_head: 0,
        };
        // Install default rules matching Linux lockdown semantics.
        state.install_default_rules();
        state
    }

    /// Install the default lockdown rules.
    ///
    /// Integrity-level blocks: module loading, /dev/mem, kexec,
    /// hibernation, PCI, I/O port, MSR, ACPI tables.
    /// Confidentiality-level blocks: debugfs, BPF read, perf,
    /// tracefs, /proc/kcore.
    fn install_default_rules(&mut self) {
        let defaults = [
            LockdownRule::new(LockdownOperation::ModuleLoading, LockdownLevel::Integrity),
            LockdownRule::new(LockdownOperation::DevMem, LockdownLevel::Integrity),
            LockdownRule::new(LockdownOperation::Kexec, LockdownLevel::Integrity),
            LockdownRule::new(LockdownOperation::Hibernation, LockdownLevel::Integrity),
            LockdownRule::new(LockdownOperation::PciAccess, LockdownLevel::Integrity),
            LockdownRule::new(LockdownOperation::IoPortAccess, LockdownLevel::Integrity),
            LockdownRule::new(LockdownOperation::MsrAccess, LockdownLevel::Integrity),
            LockdownRule::new(LockdownOperation::AcpiTables, LockdownLevel::Integrity),
            LockdownRule::new(LockdownOperation::Debugfs, LockdownLevel::Confidentiality),
            LockdownRule::new(LockdownOperation::BpfRead, LockdownLevel::Confidentiality),
            LockdownRule::new(
                LockdownOperation::PerfEvents,
                LockdownLevel::Confidentiality,
            ),
            LockdownRule::new(LockdownOperation::Tracefs, LockdownLevel::Confidentiality),
            LockdownRule::new(
                LockdownOperation::KcoreAccess,
                LockdownLevel::Confidentiality,
            ),
        ];

        let mut i = 0usize;
        while i < defaults.len() {
            if i < MAX_RULES {
                self.rules[i] = Some(defaults[i]);
                self.rule_count += 1;
            }
            i += 1;
        }
    }

    /// Record a violation in the ring buffer.
    fn record_violation(&mut self, violation: LockdownViolation) {
        self.violations[self.violation_head] = violation;
        self.violation_head = (self.violation_head + 1) % MAX_VIOLATIONS;
        self.violation_count = self.violation_count.saturating_add(1);
    }
}

impl Default for LockdownState {
    fn default() -> Self {
        Self::new()
    }
}

// ── check_lockdown (standalone) ───────────────────────────────────

/// Check whether an operation is permitted under the current
/// lockdown state.
///
/// Returns `Ok(())` if the operation is allowed, or
/// `Error::PermissionDenied` if blocked.
///
/// This is the hot-path function called by subsystems before
/// performing privileged operations.
pub fn check_lockdown(
    state: &mut LockdownState,
    operation: LockdownOperation,
    timestamp: u64,
    pid: u32,
) -> Result<()> {
    // No restrictions at level None.
    if matches!(state.level, LockdownLevel::None) {
        return Ok(());
    }

    // Check each rule.
    let mut i = 0usize;
    while i < state.rule_count {
        if let Some(rule) = &state.rules[i] {
            if rule.operation as u8 == operation as u8 && state.level.at_least(rule.min_level) {
                // Operation is blocked. Record violation.
                let violation = LockdownViolation::new(
                    operation,
                    state.level,
                    timestamp,
                    pid,
                    b"lockdown policy denied",
                );
                state.record_violation(violation);
                return Err(Error::PermissionDenied);
            }
        }
        i += 1;
    }

    Ok(())
}

// ── Lockdown registry ─────────────────────────────────────────────

/// Kernel lockdown policy registry.
///
/// Provides the top-level API for setting the lockdown level,
/// checking operations, and inspecting violation history.
pub struct LockdownRegistry {
    /// Internal state.
    state: LockdownState,
}

impl Default for LockdownRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl LockdownRegistry {
    /// Create a new lockdown registry at level `None`.
    pub fn new() -> Self {
        Self {
            state: LockdownState::new(),
        }
    }

    /// Set the lockdown level.
    ///
    /// The level can only be raised, never lowered. Attempting to
    /// lower the level returns `Error::PermissionDenied`.
    pub fn set_level(&mut self, level: LockdownLevel) -> Result<()> {
        if (level as u8) < (self.state.level as u8) {
            return Err(Error::PermissionDenied);
        }
        self.state.level = level;
        Ok(())
    }

    /// Check if an operation is permitted at the current level.
    ///
    /// Returns `Ok(())` if allowed, `Error::PermissionDenied` if
    /// blocked. Violations are logged automatically.
    pub fn check(&mut self, operation: LockdownOperation, timestamp: u64, pid: u32) -> Result<()> {
        check_lockdown(&mut self.state, operation, timestamp, pid)
    }

    /// Get the current lockdown level.
    pub fn get_state(&self) -> LockdownLevel {
        self.state.level
    }

    /// Get the total number of recorded violations.
    pub fn violation_count(&self) -> u64 {
        self.state.violation_count
    }

    /// Get the violation log entries.
    ///
    /// Returns a slice of the ring buffer (may contain stale
    /// entries if the buffer has wrapped).
    pub fn get_violations(&self) -> &[LockdownViolation] {
        let used = if self.state.violation_count >= MAX_VIOLATIONS as u64 {
            MAX_VIOLATIONS
        } else {
            self.state.violation_count as usize
        };
        &self.state.violations[..used]
    }

    /// Add a custom lockdown rule.
    ///
    /// If a rule for the same operation already exists, it is
    /// updated with the new minimum level.
    pub fn add_rule(&mut self, rule: LockdownRule) -> Result<()> {
        // Check for existing rule for this operation.
        let mut i = 0usize;
        while i < self.state.rule_count {
            if let Some(existing) = &mut self.state.rules[i] {
                if existing.operation as u8 == rule.operation as u8 {
                    existing.min_level = rule.min_level;
                    return Ok(());
                }
            }
            i += 1;
        }

        // Add new rule.
        if self.state.rule_count >= MAX_RULES {
            return Err(Error::OutOfMemory);
        }
        self.state.rules[self.state.rule_count] = Some(rule);
        self.state.rule_count += 1;
        Ok(())
    }

    /// Get the number of active rules.
    pub fn rule_count(&self) -> usize {
        self.state.rule_count
    }
}

impl core::fmt::Debug for LockdownRegistry {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("LockdownRegistry")
            .field("level", &self.state.level)
            .field("rules", &self.state.rule_count)
            .field("violations", &self.state.violation_count)
            .finish()
    }
}
