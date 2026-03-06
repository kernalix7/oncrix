// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `vhangup(2)` syscall handler — simulate a hangup on the current terminal.
//!
//! `vhangup` simulates a hangup on the controlling terminal.  This causes
//! processes that have the terminal open to receive a `SIGHUP` and the
//! terminal to be closed.  Only processes with `CAP_SYS_TTY_CONFIG` may
//! call this syscall.
//!
//! # Syscall signature
//!
//! ```text
//! int vhangup(void);
//! ```
//!
//! # POSIX / Linux compliance
//!
//! This is a Linux-specific extension (not in POSIX).  Requires
//! `CAP_SYS_TTY_CONFIG` capability.
//!
//! # References
//!
//! - Linux: `drivers/tty/tty_io.c`
//! - `vhangup(2)` man page

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Capability constants
// ---------------------------------------------------------------------------

/// Capability index for `CAP_SYS_TTY_CONFIG`.
pub const CAP_SYS_TTY_CONFIG: u32 = 26;

// ---------------------------------------------------------------------------
// Data structures
// ---------------------------------------------------------------------------

/// Context for a `vhangup` call, capturing caller credentials.
#[derive(Debug, Clone, Copy)]
pub struct VhangupContext {
    /// Effective user ID of the caller.
    pub euid: u32,
    /// Capability bitmask (simplified).
    pub capabilities: u64,
}

impl VhangupContext {
    /// Create a new context.
    pub const fn new(euid: u32, capabilities: u64) -> Self {
        Self { euid, capabilities }
    }

    /// Return whether the caller has `CAP_SYS_TTY_CONFIG`.
    pub fn has_tty_config_cap(&self) -> bool {
        self.capabilities & (1u64 << CAP_SYS_TTY_CONFIG) != 0
    }
}

impl Default for VhangupContext {
    fn default() -> Self {
        Self::new(0, 0)
    }
}

/// Result of a vhangup operation.
#[derive(Debug, Clone, Copy, Default)]
pub struct VhangupResult {
    /// Number of processes that received SIGHUP.
    pub processes_signaled: u32,
}

impl VhangupResult {
    /// Create a new result.
    pub const fn new(processes_signaled: u32) -> Self {
        Self { processes_signaled }
    }
}

/// The state of a controlling terminal at the time of a vhangup call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TtyHangupState {
    /// Terminal was active with a foreground process group.
    HadForeground,
    /// Terminal had no active foreground process group.
    NoForeground,
    /// No controlling terminal was found for the process.
    NoControllingTty,
}

impl Default for TtyHangupState {
    fn default() -> Self {
        Self::NoControllingTty
    }
}

/// Outcome of a completed vhangup operation.
#[derive(Debug, Clone, Copy, Default)]
pub struct VhangupOutcome {
    /// State of the TTY before the hangup was applied.
    pub pre_state: TtyHangupState,
    /// Number of open file descriptors that were closed.
    pub fds_closed: u32,
    /// Number of processes notified via SIGHUP.
    pub procs_signaled: u32,
}

impl VhangupOutcome {
    /// Create a new outcome record.
    pub const fn new(pre_state: TtyHangupState, fds_closed: u32, procs_signaled: u32) -> Self {
        Self {
            pre_state,
            fds_closed,
            procs_signaled,
        }
    }
}

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

/// Handle the `vhangup(2)` syscall.
///
/// Simulates a hangup on the controlling terminal.  Requires
/// `CAP_SYS_TTY_CONFIG`.
///
/// # Errors
///
/// - [`Error::PermissionDenied`] — caller lacks `CAP_SYS_TTY_CONFIG`.
/// - [`Error::NotImplemented`] — TTY subsystem not yet wired.
pub fn sys_vhangup(ctx: &VhangupContext) -> Result<i64> {
    if !ctx.has_tty_config_cap() {
        return Err(Error::PermissionDenied);
    }
    do_vhangup()
}

fn do_vhangup() -> Result<i64> {
    // TODO: Locate the controlling terminal of the calling process, revoke
    // all open file descriptors for it, and deliver SIGHUP to the foreground
    // process group.
    Err(Error::NotImplemented)
}

/// Entry point called from the syscall dispatcher.
///
/// The dispatcher is responsible for building a `VhangupContext` from the
/// current task's credentials before calling this function.
pub fn do_vhangup_syscall(euid: u32, caps: u64) -> Result<i64> {
    let ctx = VhangupContext::new(euid, caps);
    sys_vhangup(&ctx)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_capability_rejected() {
        let ctx = VhangupContext::new(0, 0);
        assert_eq!(sys_vhangup(&ctx).unwrap_err(), Error::PermissionDenied);
    }

    #[test]
    fn root_without_cap_rejected() {
        // Even uid=0 must have the capability bit set.
        let ctx = VhangupContext::new(0, 0);
        assert_eq!(sys_vhangup(&ctx).unwrap_err(), Error::PermissionDenied);
    }

    #[test]
    fn with_capability_passes_permission_check() {
        let caps = 1u64 << CAP_SYS_TTY_CONFIG;
        let ctx = VhangupContext::new(1000, caps);
        assert!(ctx.has_tty_config_cap());
        // Will fail with NotImplemented, not PermissionDenied.
        assert_eq!(sys_vhangup(&ctx).unwrap_err(), Error::NotImplemented);
    }

    #[test]
    fn context_default_no_caps() {
        let ctx = VhangupContext::default();
        assert!(!ctx.has_tty_config_cap());
    }

    #[test]
    fn result_default() {
        let r = VhangupResult::default();
        assert_eq!(r.processes_signaled, 0);
    }

    #[test]
    fn result_new() {
        let r = VhangupResult::new(3);
        assert_eq!(r.processes_signaled, 3);
    }
}
