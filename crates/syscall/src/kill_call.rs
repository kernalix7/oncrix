// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `kill(2)`, `tkill(2)`, and `tgkill(2)` signal delivery syscall handlers.
//!
//! Send a signal to a process, thread, or process group.
//!
//! # POSIX Conformance
//!
//! Follows POSIX.1-2024 `kill()` specification.  Key behaviours:
//! - `pid > 0`   — send signal to the specific process.
//! - `pid == 0`  — send to every process in the caller's process group.
//! - `pid == -1` — send to every process for which the caller has permission
//!   (except PID 1).
//! - `pid < -1`  — send to every process in the process group `|pid|`.
//! - `sig == 0`  — permission check only; no signal is sent.
//! - Permission: caller must have the same UID/EUID as the target, or
//!   possess `CAP_KILL`.
//! - `ESRCH` if no matching process exists.
//! - `EPERM` if permission is denied for all targets.
//! - Signal numbers must be in `[1, 64]` or 0 for the null signal.
//!
//! # tkill / tgkill
//!
//! Linux extensions:
//! - `tkill(tid, sig)` — send to specific thread (deprecated).
//! - `tgkill(tgid, tid, sig)` — send to a thread in a specific thread group.
//!
//! # References
//!
//! - POSIX.1-2024: `kill()`
//! - Linux man pages: `kill(2)`, `tkill(2)`, `tgkill(2)`

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Signal range
// ---------------------------------------------------------------------------

/// Minimum valid signal number.
pub const SIGMIN: i32 = 1;
/// Maximum valid signal number (POSIX requires at least 31; Linux has 64).
pub const SIGMAX: i32 = 64;

// ---------------------------------------------------------------------------
// Signal numbers (subset)
// ---------------------------------------------------------------------------

/// Hangup.
pub const SIGHUP: i32 = 1;
/// Interrupt.
pub const SIGINT: i32 = 2;
/// Quit.
pub const SIGQUIT: i32 = 3;
/// Kill (un-catchable).
pub const SIGKILL: i32 = 9;
/// Termination.
pub const SIGTERM: i32 = 15;

// ---------------------------------------------------------------------------
// Process credential snapshot (for permission checks)
// ---------------------------------------------------------------------------

/// Credential snapshot used for signal permission checks.
#[derive(Debug, Clone, Copy)]
pub struct SignalCred {
    /// Process UID.
    pub uid: u32,
    /// Process effective UID.
    pub euid: u32,
    /// Saved-set UID.
    pub suid: u32,
}

/// Whether the caller has `CAP_KILL`.
pub type HasCapKill = bool;

// ---------------------------------------------------------------------------
// Target process descriptor
// ---------------------------------------------------------------------------

/// Minimal process record for kill permission checks.
#[derive(Debug, Clone, Copy)]
pub struct KillTarget {
    /// PID of the target process.
    pub pid: i32,
    /// Thread group ID (for `tgkill`).
    pub tgid: i32,
    /// Thread ID.
    pub tid: i32,
    /// Process group ID.
    pub pgid: i32,
    /// Target credentials.
    pub cred: SignalCred,
}

// ---------------------------------------------------------------------------
// Kill target selector
// ---------------------------------------------------------------------------

/// Decoded `pid` argument for `kill(2)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KillTarget_ {
    /// Send to the specific PID.
    Pid(i32),
    /// Send to every process in the caller's process group.
    CallerGroup,
    /// Send to every accessible process except PID 1.
    Broadcast,
    /// Send to every process in process group `pgid`.
    Group(i32),
}

/// Parse the `pid` argument into a [`KillTarget_`].
pub fn parse_kill_pid(pid: i32) -> KillTarget_ {
    match pid {
        p if p > 0 => KillTarget_::Pid(p),
        0 => KillTarget_::CallerGroup,
        -1 => KillTarget_::Broadcast,
        p => KillTarget_::Group(-p),
    }
}

// ---------------------------------------------------------------------------
// Permission check
// ---------------------------------------------------------------------------

/// Returns `true` if `caller` has permission to send a signal to `target`.
///
/// Permission rules (POSIX.1-2024):
/// 1. Caller has `CAP_KILL`.
/// 2. Caller's real or effective UID matches the target's real or saved-set UID.
pub fn signal_permission(caller: &SignalCred, target: &SignalCred, cap_kill: HasCapKill) -> bool {
    if cap_kill {
        return true;
    }
    // Caller real UID or EUID must match target real UID or saved-set UID.
    (caller.uid == target.uid || caller.uid == target.suid)
        || (caller.euid == target.uid || caller.euid == target.suid)
}

// ---------------------------------------------------------------------------
// Kill outcome
// ---------------------------------------------------------------------------

/// Result of a `kill` / `tkill` / `tgkill` call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KillResult {
    /// Number of processes to which the signal was (or would be) delivered.
    pub targets_hit: usize,
    /// Whether the signal was only a permission check (sig == 0).
    pub null_signal: bool,
}

// ---------------------------------------------------------------------------
// Core handler — kill
// ---------------------------------------------------------------------------

/// Handler for `kill(2)`.
///
/// Validates `sig` and iterates `targets` to find matching processes, applying
/// permission checks.  In a real kernel this would also queue the signal.
///
/// # Arguments
///
/// * `caller_pid`  — PID of the calling process.
/// * `caller_pgid` — PGID of the calling process.
/// * `caller_cred` — Credentials of the calling process.
/// * `cap_kill`    — Whether the caller has `CAP_KILL`.
/// * `targets`     — Table of all processes.
/// * `pid`         — Target selector.
/// * `sig`         — Signal number (0 for null check).
///
/// # Errors
///
/// | `Error`      | Condition                                         |
/// |--------------|---------------------------------------------------|
/// | `InvalidArg` | `sig` out of range `[0, 64]`                      |
/// | `NotFound`   | No matching process found (`ESRCH`)               |
/// | `AccessDenied`| Permission denied for all matching processes     |
pub fn do_kill(
    caller_pid: i32,
    caller_pgid: i32,
    caller_cred: &SignalCred,
    cap_kill: HasCapKill,
    targets: &[KillTarget],
    pid: i32,
    sig: i32,
) -> Result<KillResult> {
    // Validate signal number.
    if !(0..=SIGMAX).contains(&sig) {
        return Err(Error::InvalidArgument);
    }

    let selector = parse_kill_pid(pid);
    let null_signal = sig == 0;

    let mut found = 0usize;
    let mut permitted = 0usize;

    for t in targets {
        let matches = match selector {
            KillTarget_::Pid(p) => t.pid == p,
            KillTarget_::CallerGroup => t.pgid == caller_pgid,
            KillTarget_::Broadcast => t.pid != 1 && t.pid != caller_pid,
            KillTarget_::Group(g) => t.pgid == g,
        };

        if matches {
            found += 1;
            if signal_permission(caller_cred, &t.cred, cap_kill) {
                permitted += 1;
            }
        }
    }

    if found == 0 {
        return Err(Error::NotFound);
    }
    if permitted == 0 {
        return Err(Error::PermissionDenied);
    }

    Ok(KillResult {
        targets_hit: permitted,
        null_signal,
    })
}

// ---------------------------------------------------------------------------
// Core handler — tgkill
// ---------------------------------------------------------------------------

/// Handler for `tgkill(2)`.
///
/// Sends `sig` to thread `tid` in thread group `tgid`.
///
/// # Errors
///
/// | `Error`      | Condition                                         |
/// |--------------|---------------------------------------------------|
/// | `InvalidArg` | `sig` out of range or `tgid`/`tid` ≤ 0           |
/// | `NotFound`   | No thread with matching `tgid` + `tid` (`ESRCH`)  |
/// | `AccessDenied`| Permission denied                                |
pub fn do_tgkill(
    caller_cred: &SignalCred,
    cap_kill: HasCapKill,
    targets: &[KillTarget],
    tgid: i32,
    tid: i32,
    sig: i32,
) -> Result<KillResult> {
    if !(0..=SIGMAX).contains(&sig) {
        return Err(Error::InvalidArgument);
    }
    if tgid <= 0 || tid <= 0 {
        return Err(Error::InvalidArgument);
    }

    let target = targets
        .iter()
        .find(|t| t.tgid == tgid && t.tid == tid)
        .ok_or(Error::NotFound)?;

    if !signal_permission(caller_cred, &target.cred, cap_kill) {
        return Err(Error::PermissionDenied);
    }

    Ok(KillResult {
        targets_hit: 1,
        null_signal: sig == 0,
    })
}

/// Handler for `tkill(2)` (deprecated; equivalent to `tgkill` with tgid = tid).
///
/// Sends `sig` to thread `tid` regardless of thread group.
pub fn do_tkill(
    caller_cred: &SignalCred,
    cap_kill: HasCapKill,
    targets: &[KillTarget],
    tid: i32,
    sig: i32,
) -> Result<KillResult> {
    if !(0..=SIGMAX).contains(&sig) {
        return Err(Error::InvalidArgument);
    }
    if tid <= 0 {
        return Err(Error::InvalidArgument);
    }

    let target = targets
        .iter()
        .find(|t| t.tid == tid)
        .ok_or(Error::NotFound)?;

    if !signal_permission(caller_cred, &target.cred, cap_kill) {
        return Err(Error::PermissionDenied);
    }

    Ok(KillResult {
        targets_hit: 1,
        null_signal: sig == 0,
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn cred(uid: u32) -> SignalCred {
        SignalCred {
            uid,
            euid: uid,
            suid: uid,
        }
    }

    fn target(pid: i32, pgid: i32, uid: u32) -> KillTarget {
        KillTarget {
            pid,
            tgid: pid,
            tid: pid,
            pgid,
            cred: cred(uid),
        }
    }

    #[test]
    fn kill_specific_ok() {
        let caller_cred = cred(1000);
        let targets = [target(100, 50, 1000), target(200, 50, 1001)];
        let res = do_kill(1, 1, &caller_cred, false, &targets, 100, SIGTERM).unwrap();
        assert_eq!(res.targets_hit, 1);
    }

    #[test]
    fn kill_group() {
        let caller_cred = cred(1000);
        let targets = [
            target(100, 50, 1000),
            target(101, 50, 1000),
            target(200, 60, 1000),
        ];
        let res = do_kill(99, 50, &caller_cred, false, &targets, 0, SIGTERM).unwrap();
        assert_eq!(res.targets_hit, 2);
    }

    #[test]
    fn kill_no_permission() {
        let caller_cred = cred(1000);
        let targets = [target(100, 50, 2000)];
        assert_eq!(
            do_kill(1, 1, &caller_cred, false, &targets, 100, SIGKILL),
            Err(Error::PermissionDenied)
        );
    }

    #[test]
    fn kill_cap_kill_overrides() {
        let caller_cred = cred(0);
        let targets = [target(100, 50, 9999)];
        let res = do_kill(1, 1, &caller_cred, true, &targets, 100, SIGKILL).unwrap();
        assert_eq!(res.targets_hit, 1);
    }

    #[test]
    fn kill_invalid_signal() {
        let caller_cred = cred(0);
        assert_eq!(
            do_kill(1, 1, &caller_cred, true, &[], 0, 65),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn kill_not_found() {
        let caller_cred = cred(0);
        assert_eq!(
            do_kill(1, 1, &caller_cred, true, &[], 999, SIGTERM),
            Err(Error::NotFound)
        );
    }

    #[test]
    fn tgkill_ok() {
        let caller_cred = cred(1000);
        let targets = [KillTarget {
            pid: 10,
            tgid: 10,
            tid: 11,
            pgid: 5,
            cred: cred(1000),
        }];
        let res = do_tgkill(&caller_cred, false, &targets, 10, 11, SIGTERM).unwrap();
        assert_eq!(res.targets_hit, 1);
    }
}
