// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Extended wait operations: `waitid(2)` extended dispatch and helper types.
//!
//! Provides supplementary types and logic for `waitid`, including ID type
//! validation, `siginfo_t`-based result construction, and process-state
//! reporting helpers used by both `wait4` and `waitid`.
//!
//! # References
//!
//! - POSIX.1-2024: `waitid()`
//! - Linux: `kernel/exit.c` `do_wait()`

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// ID type constants (POSIX `idtype_t`)
// ---------------------------------------------------------------------------

/// Wait for any child process.
pub const P_ALL: u32 = 0;
/// Wait for the child with a specific PID.
pub const P_PID: u32 = 1;
/// Wait for any child in a specific process group.
pub const P_PGID: u32 = 2;
/// Wait for any child in the same process group as the caller.
pub const P_PIDFD: u32 = 3;

/// Maximum recognised `idtype` value.
const IDTYPE_MAX: u32 = P_PIDFD;

// ---------------------------------------------------------------------------
// WaitOptions — decoded waitid options
// ---------------------------------------------------------------------------

/// POSIX `WEXITED` — report children that terminated.
pub const WEXITED: u32 = 4;
/// POSIX `WSTOPPED` — report children stopped by a signal.
pub const WSTOPPED: u32 = 2;
/// POSIX `WCONTINUED` — report children continued via SIGCONT.
pub const WCONTINUED: u32 = 8;
/// Linux `WNOHANG` — return immediately if no child is ready.
pub const WNOHANG: u32 = 1;
/// Linux `WNOWAIT` — do not reap; leave the child waitable.
pub const WNOWAIT: u32 = 0x0100_0000;

/// Mask of all recognised `waitid` options.
const WAITID_OPTIONS_KNOWN: u32 = WEXITED | WSTOPPED | WCONTINUED | WNOHANG | WNOWAIT;

/// Minimum required option bits (must report at least one state).
const WAITID_OPTIONS_REQUIRED: u32 = WEXITED | WSTOPPED | WCONTINUED;

// ---------------------------------------------------------------------------
// WaitidIdSpec — validated id specification
// ---------------------------------------------------------------------------

/// Validated `(idtype, id)` pair for `waitid`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WaitidIdSpec {
    /// Any child.
    AnyChild,
    /// Child with specific PID.
    Pid(u64),
    /// Any child in specific PGID.
    Pgid(u64),
    /// Child referenced by pidfd.
    Pidfd(i32),
}

impl WaitidIdSpec {
    /// Parse and validate a raw `(idtype, id)` pair.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidArgument`] for unrecognised `idtype` or invalid `id`.
    pub fn from_raw(idtype: u32, id: u64) -> Result<Self> {
        match idtype {
            P_ALL => Ok(Self::AnyChild),
            P_PID => {
                if id == 0 || id > 4_194_304 {
                    return Err(Error::InvalidArgument);
                }
                Ok(Self::Pid(id))
            }
            P_PGID => {
                if id == 0 || id > 4_194_304 {
                    return Err(Error::InvalidArgument);
                }
                Ok(Self::Pgid(id))
            }
            P_PIDFD => {
                if id > i32::MAX as u64 {
                    return Err(Error::InvalidArgument);
                }
                Ok(Self::Pidfd(id as i32))
            }
            t if t > IDTYPE_MAX => Err(Error::InvalidArgument),
            _ => Err(Error::InvalidArgument),
        }
    }
}

// ---------------------------------------------------------------------------
// WaitidOptions — validated options set
// ---------------------------------------------------------------------------

/// Validated options set for `waitid`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WaitidOptions {
    /// Report terminated children.
    pub exited: bool,
    /// Report stopped children.
    pub stopped: bool,
    /// Report continued children.
    pub continued: bool,
    /// Return immediately if no child matches.
    pub no_hang: bool,
    /// Do not reap.
    pub no_wait: bool,
}

impl WaitidOptions {
    /// Parse and validate raw options integer.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidArgument`] for unrecognised bits or missing required bits.
    pub fn from_raw(raw: u32) -> Result<Self> {
        if raw & !WAITID_OPTIONS_KNOWN != 0 {
            return Err(Error::InvalidArgument);
        }
        if raw & WAITID_OPTIONS_REQUIRED == 0 {
            return Err(Error::InvalidArgument);
        }
        Ok(Self {
            exited: raw & WEXITED != 0,
            stopped: raw & WSTOPPED != 0,
            continued: raw & WCONTINUED != 0,
            no_hang: raw & WNOHANG != 0,
            no_wait: raw & WNOWAIT != 0,
        })
    }
}

// ---------------------------------------------------------------------------
// SiginfoResult — simplified siginfo for waitid
// ---------------------------------------------------------------------------

/// Simplified `siginfo_t` result for `waitid`.
///
/// The kernel fills this structure for the parent when a child changes state.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SiginfoResult {
    /// Signal number (always `SIGCHLD`).
    pub si_signo: u32,
    /// Signal code (one of `CLD_*`).
    pub si_code: i32,
    /// PID of the child.
    pub si_pid: u64,
    /// UID of the child.
    pub si_uid: u32,
    /// Child exit status or signal number.
    pub si_status: i32,
}

/// Child exited normally.
pub const CLD_EXITED: i32 = 1;
/// Child was killed by a signal.
pub const CLD_KILLED: i32 = 2;
/// Child was stopped by a signal.
pub const CLD_STOPPED: i32 = 5;
/// Child was continued.
pub const CLD_CONTINUED: i32 = 6;
/// Signal number for child status change.
pub const SIGCHLD: u32 = 17;

impl SiginfoResult {
    /// Construct a `CLD_EXITED` result.
    pub const fn exited(pid: u64, uid: u32, exit_code: i32) -> Self {
        Self {
            si_signo: SIGCHLD,
            si_code: CLD_EXITED,
            si_pid: pid,
            si_uid: uid,
            si_status: exit_code,
        }
    }

    /// Construct a `CLD_KILLED` result.
    pub const fn killed(pid: u64, uid: u32, signal: i32) -> Self {
        Self {
            si_signo: SIGCHLD,
            si_code: CLD_KILLED,
            si_pid: pid,
            si_uid: uid,
            si_status: signal,
        }
    }

    /// Construct a `CLD_STOPPED` result.
    pub const fn stopped(pid: u64, uid: u32, signal: i32) -> Self {
        Self {
            si_signo: SIGCHLD,
            si_code: CLD_STOPPED,
            si_pid: pid,
            si_uid: uid,
            si_status: signal,
        }
    }

    /// Construct a `CLD_CONTINUED` result.
    pub const fn continued(pid: u64, uid: u32) -> Self {
        Self {
            si_signo: SIGCHLD,
            si_code: CLD_CONTINUED,
            si_pid: pid,
            si_uid: uid,
            si_status: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// Validation entry point
// ---------------------------------------------------------------------------

/// Validate all `waitid` arguments.
///
/// # Errors
///
/// See [`WaitidIdSpec::from_raw`] and [`WaitidOptions::from_raw`].
pub fn validate_waitid_args(
    idtype: u32,
    id: u64,
    options: u32,
) -> Result<(WaitidIdSpec, WaitidOptions)> {
    let spec = WaitidIdSpec::from_raw(idtype, id)?;
    let opts = WaitidOptions::from_raw(options)?;
    Ok((spec, opts))
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn p_all_any_id() {
        let (spec, _) = validate_waitid_args(P_ALL, 0, WEXITED).unwrap();
        assert_eq!(spec, WaitidIdSpec::AnyChild);
    }

    #[test]
    fn p_pid_valid() {
        let (spec, _) = validate_waitid_args(P_PID, 42, WEXITED).unwrap();
        assert_eq!(spec, WaitidIdSpec::Pid(42));
    }

    #[test]
    fn p_pid_zero_rejected() {
        assert_eq!(
            validate_waitid_args(P_PID, 0, WEXITED),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn unknown_idtype_rejected() {
        assert_eq!(
            validate_waitid_args(99, 1, WEXITED),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn no_state_bits_rejected() {
        assert_eq!(
            validate_waitid_args(P_ALL, 0, WNOHANG),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn unknown_option_bits_rejected() {
        assert_eq!(
            validate_waitid_args(P_ALL, 0, 0xFF00),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn siginfo_exited() {
        let s = SiginfoResult::exited(42, 1000, 0);
        assert_eq!(s.si_code, CLD_EXITED);
        assert_eq!(s.si_pid, 42);
        assert_eq!(s.si_status, 0);
    }

    #[test]
    fn siginfo_killed() {
        let s = SiginfoResult::killed(7, 0, 9);
        assert_eq!(s.si_code, CLD_KILLED);
        assert_eq!(s.si_status, 9);
    }
}
