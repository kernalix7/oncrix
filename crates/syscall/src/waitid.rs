// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Extended `waitid(2)` syscall handler.
//!
//! Implements the POSIX.1-2024 `waitid` interface with Linux extensions
//! including `P_PIDFD` support. Provides typed enums for `idtype_t`,
//! wait flags, and CLD signal codes, plus a structured result type
//! that includes resource-usage fields.
//!
//! Reference: POSIX.1-2024 `waitid()`, Linux `waitid(2)`.

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// IdType — POSIX idtype_t (repr(u32) for ABI compatibility)
// ---------------------------------------------------------------------------

/// Identifier type for `waitid`, selecting which children to wait for.
///
/// Corresponds to POSIX `idtype_t`. Values match the Linux ABI.
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdType {
    /// Wait for any child process (`id` is ignored).
    PAll = 0,
    /// Wait for the child whose PID equals `id`.
    PPid = 1,
    /// Wait for any child whose process group ID equals `id`.
    PPgid = 2,
    /// Wait for the child identified by the pidfd `id` (Linux extension).
    PPidfd = 3,
}

impl IdType {
    /// Convert a raw `u32` value to a typed [`IdType`].
    ///
    /// Returns `Err(Error::InvalidArgument)` for unrecognised values.
    pub fn from_u32(val: u32) -> Result<Self> {
        match val {
            0 => Ok(Self::PAll),
            1 => Ok(Self::PPid),
            2 => Ok(Self::PPgid),
            3 => Ok(Self::PPidfd),
            _ => Err(Error::InvalidArgument),
        }
    }
}

// ---------------------------------------------------------------------------
// WaitidFlags — bitmask (u32)
// ---------------------------------------------------------------------------

/// Wait for processes that have exited.
pub const WEXITED: u32 = 0x0000_0004;

/// Wait for processes that have been stopped by a signal.
pub const WSTOPPED: u32 = 0x0000_0002;

/// Wait for processes that have continued from a stop.
pub const WCONTINUED: u32 = 0x0000_0008;

/// Do not block if no matching status is available.
pub const WNOHANG: u32 = 0x0000_0001;

/// Leave the child in a waitable state (do not consume the event).
pub const WNOWAIT: u32 = 0x0100_0000;

/// Mask of all valid waitid flag bits.
const WAITID_FLAGS_ALL: u32 = WEXITED | WSTOPPED | WCONTINUED | WNOHANG | WNOWAIT;

/// Mask of flags that select a child state change category.
const WAITID_STATE_FLAGS: u32 = WEXITED | WSTOPPED | WCONTINUED;

/// Validate a raw waitid flags value.
///
/// Returns `Err(Error::InvalidArgument)` if unknown bits are set or
/// none of `WEXITED`, `WSTOPPED`, `WCONTINUED` are specified (per POSIX:
/// "Applications shall specify at least one of the flags").
pub fn waitid_flags_valid(flags: u32) -> Result<()> {
    if flags & !WAITID_FLAGS_ALL != 0 {
        return Err(Error::InvalidArgument);
    }
    if flags & WAITID_STATE_FLAGS == 0 {
        return Err(Error::InvalidArgument);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// CLD codes — si_code values for SIGCHLD
// ---------------------------------------------------------------------------

/// SIGCHLD signal number (x86_64 / generic Linux).
pub const SIGCHLD: i32 = 17;

/// Child has exited normally.
pub const CLD_EXITED: i32 = 1;
/// Child was killed by a signal.
pub const CLD_KILLED: i32 = 2;
/// Child was killed by a signal and produced a core dump.
pub const CLD_DUMPED: i32 = 3;
/// Child was stopped by a signal (delivery of a stopping signal).
pub const CLD_TRAPPED: i32 = 4;
/// Child has stopped (job control stop).
pub const CLD_STOPPED: i32 = 5;
/// Stopped child has continued.
pub const CLD_CONTINUED: i32 = 6;

/// Encode a CLD code from a raw wait status.
///
/// Maps exit/signal/stop/continue conditions to the corresponding
/// `CLD_*` constant. Returns `CLD_EXITED` for a clean exit,
/// `CLD_KILLED` for signal termination (no core), `CLD_DUMPED` when
/// a core was generated, `CLD_STOPPED` for job-control stops, and
/// `CLD_CONTINUED` for continue events.
///
/// The `core_dumped` flag indicates whether a core dump was produced
/// during signal termination.
pub const fn encode_cld_code(
    exited: bool,
    signaled: bool,
    stopped: bool,
    continued: bool,
    core_dumped: bool,
) -> i32 {
    if exited {
        return CLD_EXITED;
    }
    if signaled {
        return if core_dumped { CLD_DUMPED } else { CLD_KILLED };
    }
    if stopped {
        return CLD_STOPPED;
    }
    if continued {
        return CLD_CONTINUED;
    }
    // Default to exited if no condition matched (should not happen in
    // well-formed usage).
    CLD_EXITED
}

// ---------------------------------------------------------------------------
// SiginfoChild — repr(C) siginfo subset for waitid
// ---------------------------------------------------------------------------

/// Abbreviated `siginfo_t` tailored for `waitid` child-status reporting.
///
/// Layout is `repr(C)` for direct copy to user space. Fields follow
/// POSIX.1-2024 requirements for `si_signo`, `si_pid`, `si_uid`,
/// `si_status`, and `si_code` when the signal is `SIGCHLD`.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct SiginfoChild {
    /// PID of the child process.
    pub si_pid: u32,
    /// Real UID of the child process.
    pub si_uid: u32,
    /// Signal number — always [`SIGCHLD`] for waitid results.
    pub si_signo: i32,
    /// Exit status or signal number that caused the state change.
    pub si_status: i32,
    /// Signal code indicating the reason for the state change
    /// (one of the `CLD_*` constants).
    pub si_code: i32,
}

// ---------------------------------------------------------------------------
// WaitidResult
// ---------------------------------------------------------------------------

/// Result of a successful `waitid` call.
///
/// Contains the child's signal information and basic resource-usage
/// accounting fields (user CPU time and system CPU time in
/// microseconds).
#[derive(Debug, Clone, Copy, Default)]
pub struct WaitidResult {
    /// Whether a matching child was found. When `WNOHANG` is set and
    /// no child has changed state, this is `false` and `siginfo`
    /// contains zeroed fields per POSIX.
    pub found: bool,
    /// Signal information for the child.
    pub siginfo: SiginfoChild,
    /// User CPU time consumed by the child (microseconds).
    pub utime: u64,
    /// System CPU time consumed by the child (microseconds).
    pub stime: u64,
}

// ---------------------------------------------------------------------------
// do_waitid — main dispatcher
// ---------------------------------------------------------------------------

/// `waitid` — wait for a child process to change state (POSIX.1-2024).
///
/// Selects children based on `idtype` and `id`:
/// - [`IdType::PAll`] — any child (`id` is ignored).
/// - [`IdType::PPid`] — the child whose PID equals `id`.
/// - [`IdType::PPgid`] — any child in process group `id`.
/// - [`IdType::PPidfd`] — the child identified by pidfd `id`.
///
/// `flags` is a bitmask of [`WEXITED`], [`WSTOPPED`], [`WCONTINUED`],
/// [`WNOHANG`], and [`WNOWAIT`]. At least one of the first three must
/// be specified.
///
/// Returns a [`WaitidResult`] on success. When `WNOHANG` is set and no
/// matching child has changed state, the result has `found == false`
/// and `siginfo` fields zeroed (per POSIX: si_signo and si_pid set to
/// zero).
///
/// # Errors
///
/// - [`Error::InvalidArgument`] — invalid flags or invalid idtype/id
///   combination.
/// - [`Error::NotFound`] — no existing unwaited-for child processes
///   (maps to `ECHILD`).
pub fn do_waitid(idtype: IdType, id: u64, flags: u32) -> Result<WaitidResult> {
    // Validate flags.
    waitid_flags_valid(flags)?;

    // Validate id when targeting a specific process or group.
    match idtype {
        IdType::PPid | IdType::PPgid | IdType::PPidfd => {
            if id == 0 {
                return Err(Error::InvalidArgument);
            }
        }
        IdType::PAll => { /* id is ignored */ }
    }

    // WNOHANG: return immediately with an empty result if no child
    // has changed state.
    if flags & WNOHANG != 0 {
        // Per POSIX: si_signo and si_pid are set to zero.
        return Ok(WaitidResult::default());
    }

    // Stub: a real kernel would walk the child list, match by
    // idtype/id, and block until a child changes state. We return a
    // placeholder child that exited with code 0.
    let _ = id;
    Ok(WaitidResult {
        found: true,
        siginfo: SiginfoChild {
            si_pid: 2,
            si_uid: 0,
            si_signo: SIGCHLD,
            si_status: 0,
            si_code: CLD_EXITED,
        },
        utime: 0,
        stime: 0,
    })
}
