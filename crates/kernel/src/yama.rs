// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Yama Linux Security Module — ptrace scope restriction.
//!
//! Yama hardens the kernel against ptrace-based attacks by restricting
//! which processes may attach to others. It defines four scope levels
//! of increasing restriction:
//!
//! - **Normal** (0): Classic ptrace permissions — a process can trace
//!   any other process running under the same UID, as long as it has
//!   the proper capabilities.
//! - **RestrictedChild** (1): A process can only trace its direct
//!   descendants (children) unless an explicit exception is granted
//!   via `prctl(PR_SET_PTRACER, ...)`.
//! - **AdminOnly** (2): Only processes with `CAP_SYS_PTRACE` may
//!   trace any process.
//! - **NoAttach** (3): No process may ptrace another, regardless of
//!   credentials. This level cannot be lowered once set.
//!
//! Additionally, per-process exception lists allow a tracer PID to be
//! explicitly granted permission to attach, bypassing the
//! `RestrictedChild` scope check.
//!
//! # Architecture
//!
//! ```text
//!  YamaSubsystem
//!   ├── scope: PtraceScope
//!   ├── exceptions: [YamaException; MAX_EXCEPTIONS]
//!   ├── audit_log: [YamaAuditEntry; MAX_AUDIT_ENTRIES]
//!   └── stats: YamaStats
//! ```
//!
//! Reference: Linux `security/yama/yama_lsm.c`.

use oncrix_lib::{Error, Result};

// ── Constants ─────────────────────────────────────────────────────

/// Maximum number of per-process ptrace exceptions.
const MAX_EXCEPTIONS: usize = 128;

/// Maximum number of audit log entries.
const MAX_AUDIT_ENTRIES: usize = 256;

/// Sentinel value meaning "allow any process to trace me".
pub const YAMA_PTRACER_ANY: u64 = u64::MAX;

/// Capability ID for `CAP_SYS_PTRACE` (matches Linux value 19).
const CAP_SYS_PTRACE: u32 = 19;

// ── PtraceScope ──────────────────────────────────────────────────

/// Ptrace scope level controlling which processes may attach to
/// others.
///
/// Scope levels are ordered by increasing restriction. Once the
/// scope is set to [`PtraceScope::NoAttach`], it cannot be lowered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
pub enum PtraceScope {
    /// Classic ptrace: same-UID processes may trace each other.
    Normal = 0,
    /// Only direct descendants may be traced (unless excepted).
    #[default]
    RestrictedChild = 1,
    /// Only `CAP_SYS_PTRACE` holders may trace.
    AdminOnly = 2,
    /// No ptrace attachment is allowed at all.
    NoAttach = 3,
}

impl PtraceScope {
    /// Create a scope from its integer value.
    ///
    /// Returns `None` if the value does not correspond to a valid
    /// scope level.
    pub const fn from_u32(val: u32) -> Option<Self> {
        match val {
            0 => Some(Self::Normal),
            1 => Some(Self::RestrictedChild),
            2 => Some(Self::AdminOnly),
            3 => Some(Self::NoAttach),
            _ => None,
        }
    }

    /// Return the integer value of this scope level.
    pub const fn as_u32(self) -> u32 {
        self as u32
    }
}

// ── YamaException ────────────────────────────────────────────────

/// A per-process exception allowing a specific tracer to attach.
///
/// When the scope is [`PtraceScope::RestrictedChild`], a tracee
/// process can grant a specific tracer PID (or any tracer via
/// [`YAMA_PTRACER_ANY`]) the right to attach. This models the
/// Linux `prctl(PR_SET_PTRACER, tracer_pid)` mechanism.
#[derive(Debug, Clone, Copy)]
struct YamaException {
    /// PID of the process granting the exception (tracee).
    tracee_pid: u64,
    /// PID of the process allowed to trace, or
    /// [`YAMA_PTRACER_ANY`] for any tracer.
    tracer_pid: u64,
    /// Whether this exception slot is active.
    active: bool,
}

impl YamaException {
    /// Create an empty, inactive exception.
    const fn empty() -> Self {
        Self {
            tracee_pid: 0,
            tracer_pid: 0,
            active: false,
        }
    }
}

// ── YamaAuditAction ──────────────────────────────────────────────

/// Actions that can be recorded in the Yama audit log.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum YamaAuditAction {
    /// A ptrace attach was allowed.
    #[default]
    PtraceAllowed,
    /// A ptrace attach was denied.
    PtraceDenied,
    /// An exception was granted (PR_SET_PTRACER).
    ExceptionGranted,
    /// An exception was revoked.
    ExceptionRevoked,
    /// The ptrace scope level was changed.
    ScopeChanged,
}

// ── YamaAuditEntry ───────────────────────────────────────────────

/// A single entry in the Yama audit log.
#[derive(Debug, Clone, Copy)]
pub struct YamaAuditEntry {
    /// PID of the process requesting the action.
    pub tracer_pid: u64,
    /// PID of the target process.
    pub tracee_pid: u64,
    /// The action that was audited.
    pub action: YamaAuditAction,
    /// The ptrace scope at the time of the event.
    pub scope: PtraceScope,
    /// Timestamp (kernel ticks) of the event.
    pub timestamp: u64,
    /// Whether this audit slot is in use.
    pub in_use: bool,
}

impl YamaAuditEntry {
    /// Create an empty, unused audit entry.
    const fn empty() -> Self {
        Self {
            tracer_pid: 0,
            tracee_pid: 0,
            action: YamaAuditAction::PtraceAllowed,
            scope: PtraceScope::Normal,
            timestamp: 0,
            in_use: false,
        }
    }
}

// ── YamaStats ────────────────────────────────────────────────────

/// Cumulative statistics for the Yama subsystem.
#[derive(Debug, Clone, Copy, Default)]
pub struct YamaStats {
    /// Number of ptrace attach requests that were allowed.
    pub allowed: u64,
    /// Number of ptrace attach requests that were denied.
    pub denied: u64,
    /// Total number of exceptions currently active.
    pub active_exceptions: u64,
    /// Total number of scope changes performed.
    pub scope_changes: u64,
}

// ── ProcessRelation ──────────────────────────────────────────────

/// Descriptor passed by the caller to describe the relationship
/// between a tracer and a tracee for scope evaluation.
#[derive(Debug, Clone, Copy)]
pub struct ProcessRelation {
    /// PID of the process requesting ptrace (tracer).
    pub tracer_pid: u64,
    /// PID of the target process (tracee).
    pub tracee_pid: u64,
    /// UID of the tracer process.
    pub tracer_uid: u32,
    /// UID of the tracee process.
    pub tracee_uid: u32,
    /// Whether the tracee is a direct descendant of the tracer.
    pub is_descendant: bool,
    /// Capability bitmask of the tracer process (bit N = cap N).
    pub tracer_caps: u64,
}

impl ProcessRelation {
    /// Check whether the tracer holds `CAP_SYS_PTRACE`.
    pub const fn has_cap_sys_ptrace(&self) -> bool {
        (self.tracer_caps >> CAP_SYS_PTRACE) & 1 == 1
    }
}

// ── YamaSubsystem ────────────────────────────────────────────────

/// The Yama LSM subsystem controlling ptrace restrictions.
///
/// Manages the global ptrace scope, per-process exception lists,
/// audit logging, and statistics.
pub struct YamaSubsystem {
    /// Current ptrace scope level.
    scope: PtraceScope,
    /// Per-process ptrace exceptions.
    exceptions: [YamaException; MAX_EXCEPTIONS],
    /// Number of active exceptions.
    exception_count: usize,
    /// Ring buffer of audit entries.
    audit_log: [YamaAuditEntry; MAX_AUDIT_ENTRIES],
    /// Total number of audit entries recorded (may wrap).
    audit_count: usize,
    /// Cumulative statistics.
    stats: YamaStats,
    /// Whether the subsystem is enabled.
    enabled: bool,
}

impl Default for YamaSubsystem {
    fn default() -> Self {
        Self::new()
    }
}

impl YamaSubsystem {
    /// Create a new Yama subsystem with default settings.
    ///
    /// The default scope is [`PtraceScope::RestrictedChild`] and the
    /// subsystem is enabled.
    pub const fn new() -> Self {
        Self {
            scope: PtraceScope::RestrictedChild,
            exceptions: [YamaException::empty(); MAX_EXCEPTIONS],
            exception_count: 0,
            audit_log: [YamaAuditEntry::empty(); MAX_AUDIT_ENTRIES],
            audit_count: 0,
            stats: YamaStats {
                allowed: 0,
                denied: 0,
                active_exceptions: 0,
                scope_changes: 0,
            },
            enabled: true,
        }
    }

    // ── Scope management ─────────────────────────────────────────

    /// Return the current ptrace scope.
    pub const fn scope(&self) -> PtraceScope {
        self.scope
    }

    /// Set the ptrace scope level.
    ///
    /// # Rules
    ///
    /// - Once [`PtraceScope::NoAttach`] is active, the scope cannot
    ///   be lowered (the kernel treats scope 3 as a one-way lock).
    /// - The new scope must be a valid [`PtraceScope`] variant.
    ///
    /// # Errors
    ///
    /// - [`Error::PermissionDenied`] if the current scope is
    ///   `NoAttach` and `new_scope` attempts to lower it.
    /// - [`Error::InvalidArgument`] if `scope_val` is not a valid
    ///   scope level.
    pub fn set_scope(&mut self, scope_val: u32) -> Result<()> {
        let new_scope = PtraceScope::from_u32(scope_val).ok_or(Error::InvalidArgument)?;

        // NoAttach is a one-way lock.
        if self.scope == PtraceScope::NoAttach && new_scope < self.scope {
            return Err(Error::PermissionDenied);
        }

        let old_scope = self.scope;
        self.scope = new_scope;
        self.stats.scope_changes = self.stats.scope_changes.saturating_add(1);

        self.record_audit(0, 0, YamaAuditAction::ScopeChanged, old_scope, 0);
        Ok(())
    }

    // ── Ptrace access check ──────────────────────────────────────

    /// Check whether a ptrace attach is permitted.
    ///
    /// This is the main LSM hook for `ptrace_access_check`. The
    /// decision depends on the current scope level:
    ///
    /// - **Normal**: tracer and tracee must share the same UID, or
    ///   the tracer must hold `CAP_SYS_PTRACE`.
    /// - **RestrictedChild**: the tracee must be a descendant of the
    ///   tracer, or an explicit exception must exist, or the tracer
    ///   holds `CAP_SYS_PTRACE`.
    /// - **AdminOnly**: the tracer must hold `CAP_SYS_PTRACE`.
    /// - **NoAttach**: always denied, even with `CAP_SYS_PTRACE`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::PermissionDenied`] if the attach is not
    /// permitted.
    pub fn check_ptrace_access(
        &mut self,
        relation: &ProcessRelation,
        timestamp: u64,
    ) -> Result<()> {
        if !self.enabled {
            return Ok(());
        }

        let allowed = match self.scope {
            PtraceScope::Normal => {
                relation.tracer_uid == relation.tracee_uid || relation.has_cap_sys_ptrace()
            }
            PtraceScope::RestrictedChild => {
                relation.is_descendant
                    || self.has_exception(relation.tracee_pid, relation.tracer_pid)
                    || relation.has_cap_sys_ptrace()
            }
            PtraceScope::AdminOnly => relation.has_cap_sys_ptrace(),
            PtraceScope::NoAttach => false,
        };

        if allowed {
            self.stats.allowed = self.stats.allowed.saturating_add(1);
            self.record_audit(
                relation.tracer_pid,
                relation.tracee_pid,
                YamaAuditAction::PtraceAllowed,
                self.scope,
                timestamp,
            );
            Ok(())
        } else {
            self.stats.denied = self.stats.denied.saturating_add(1);
            self.record_audit(
                relation.tracer_pid,
                relation.tracee_pid,
                YamaAuditAction::PtraceDenied,
                self.scope,
                timestamp,
            );
            Err(Error::PermissionDenied)
        }
    }

    // ── Exception management (PR_SET_PTRACER) ────────────────────

    /// Grant a ptrace exception: allow `tracer_pid` to attach to
    /// `tracee_pid`.
    ///
    /// Pass [`YAMA_PTRACER_ANY`] as `tracer_pid` to allow any
    /// process to trace the tracee.
    ///
    /// If an exception already exists for this tracee, the tracer
    /// PID is updated.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidArgument`] if `tracee_pid` is zero.
    /// - [`Error::OutOfMemory`] if the exception table is full.
    pub fn set_ptracer(&mut self, tracee_pid: u64, tracer_pid: u64, timestamp: u64) -> Result<()> {
        if tracee_pid == 0 {
            return Err(Error::InvalidArgument);
        }

        // Update existing exception for this tracee.
        let mut i = 0;
        while i < MAX_EXCEPTIONS {
            if self.exceptions[i].active && self.exceptions[i].tracee_pid == tracee_pid {
                self.exceptions[i].tracer_pid = tracer_pid;
                self.record_audit(
                    tracer_pid,
                    tracee_pid,
                    YamaAuditAction::ExceptionGranted,
                    self.scope,
                    timestamp,
                );
                return Ok(());
            }
            i = i.saturating_add(1);
        }

        // Find a free slot.
        let mut j = 0;
        while j < MAX_EXCEPTIONS {
            if !self.exceptions[j].active {
                self.exceptions[j] = YamaException {
                    tracee_pid,
                    tracer_pid,
                    active: true,
                };
                self.exception_count = self.exception_count.saturating_add(1);
                self.stats.active_exceptions = self.stats.active_exceptions.saturating_add(1);
                self.record_audit(
                    tracer_pid,
                    tracee_pid,
                    YamaAuditAction::ExceptionGranted,
                    self.scope,
                    timestamp,
                );
                return Ok(());
            }
            j = j.saturating_add(1);
        }

        Err(Error::OutOfMemory)
    }

    /// Revoke a ptrace exception for a tracee process.
    ///
    /// Typically called when the tracee exits or explicitly revokes
    /// its ptracer setting.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if no exception exists for the
    /// given tracee.
    pub fn clear_ptracer(&mut self, tracee_pid: u64, timestamp: u64) -> Result<()> {
        let mut i = 0;
        while i < MAX_EXCEPTIONS {
            if self.exceptions[i].active && self.exceptions[i].tracee_pid == tracee_pid {
                let tracer = self.exceptions[i].tracer_pid;
                self.exceptions[i].active = false;
                self.exception_count = self.exception_count.saturating_sub(1);
                self.stats.active_exceptions = self.stats.active_exceptions.saturating_sub(1);
                self.record_audit(
                    tracer,
                    tracee_pid,
                    YamaAuditAction::ExceptionRevoked,
                    self.scope,
                    timestamp,
                );
                return Ok(());
            }
            i = i.saturating_add(1);
        }
        Err(Error::NotFound)
    }

    /// Remove all exceptions where the given PID appears as either
    /// tracer or tracee.
    ///
    /// Called during process exit cleanup.
    pub fn cleanup_pid(&mut self, pid: u64) {
        let mut i = 0;
        while i < MAX_EXCEPTIONS {
            if self.exceptions[i].active
                && (self.exceptions[i].tracee_pid == pid || self.exceptions[i].tracer_pid == pid)
            {
                self.exceptions[i].active = false;
                self.exception_count = self.exception_count.saturating_sub(1);
                self.stats.active_exceptions = self.stats.active_exceptions.saturating_sub(1);
            }
            i = i.saturating_add(1);
        }
    }

    // ── Query ────────────────────────────────────────────────────

    /// Check whether an exception exists allowing `tracer_pid` to
    /// trace `tracee_pid`.
    fn has_exception(&self, tracee_pid: u64, tracer_pid: u64) -> bool {
        let mut i = 0;
        while i < MAX_EXCEPTIONS {
            if self.exceptions[i].active
                && self.exceptions[i].tracee_pid == tracee_pid
                && (self.exceptions[i].tracer_pid == tracer_pid
                    || self.exceptions[i].tracer_pid == YAMA_PTRACER_ANY)
            {
                return true;
            }
            i = i.saturating_add(1);
        }
        false
    }

    /// Return the number of active exceptions.
    pub const fn exception_count(&self) -> usize {
        self.exception_count
    }

    /// Return a reference to the cumulative statistics.
    pub const fn stats(&self) -> &YamaStats {
        &self.stats
    }

    /// Return whether the subsystem is enabled.
    pub const fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Enable the Yama subsystem.
    pub fn enable(&mut self) {
        self.enabled = true;
    }

    /// Disable the Yama subsystem.
    ///
    /// When disabled, all ptrace access checks return `Ok(())`.
    pub fn disable(&mut self) {
        self.enabled = false;
    }

    // ── Audit log ────────────────────────────────────────────────

    /// Return the total number of audit entries recorded.
    pub const fn audit_count(&self) -> usize {
        self.audit_count
    }

    /// Return a reference to the audit entry at `index`.
    ///
    /// Returns `None` if the index is out of bounds or the entry is
    /// not in use.
    pub fn get_audit_entry(&self, index: usize) -> Option<&YamaAuditEntry> {
        self.audit_log.get(index).filter(|e| e.in_use)
    }

    // ── Internal helpers ─────────────────────────────────────────

    /// Record an audit entry in the ring buffer.
    fn record_audit(
        &mut self,
        tracer: u64,
        tracee: u64,
        action: YamaAuditAction,
        scope: PtraceScope,
        timestamp: u64,
    ) {
        let idx = self.audit_count % MAX_AUDIT_ENTRIES;
        self.audit_log[idx] = YamaAuditEntry {
            tracer_pid: tracer,
            tracee_pid: tracee,
            action,
            scope,
            timestamp,
            in_use: true,
        };
        self.audit_count = self.audit_count.saturating_add(1);
    }
}
