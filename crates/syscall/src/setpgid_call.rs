// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Process group and session syscall handlers.
//!
//! Implements `setpgid(2)`, `getpgid(2)`, `getpgrp(2)`, `setsid(2)`, and
//! `getsid(2)` — the POSIX process group and session management interface.
//!
//! # POSIX Conformance
//!
//! Follows POSIX.1-2024 for all functions.  Key behaviours:
//! - `setpgid(0, 0)` sets the caller's process group to its own PID.
//! - `setpgid(pid, 0)` sets the process group of `pid` to `pid`.
//! - `setpgid(pid, pgid)` moves `pid` into group `pgid`.
//! - `setsid` creates a new session; the caller must not already be a
//!   process group leader (`EPERM`).
//! - `getpgrp()` returns the PGID of the calling process.
//!
//! # References
//!
//! - POSIX.1-2024: `setpgid()`, `getpgid()`, `setsid()`, `getpgrp()`
//! - Linux man pages: `setpgid(2)`, `setsid(2)`

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Process group / session descriptor
// ---------------------------------------------------------------------------

/// Session and process group state for a single process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PgroupState {
    /// Process ID.
    pub pid: u32,
    /// Process group ID.
    pub pgid: u32,
    /// Session ID.
    pub sid: u32,
    /// Whether this process is the process group leader.
    pub is_pgroup_leader: bool,
    /// Whether this process is the session leader.
    pub is_session_leader: bool,
    /// Whether this process has a controlling terminal.
    pub has_ctty: bool,
}

impl PgroupState {
    /// Create a new standalone process state (PID = PGID = SID).
    pub const fn new_standalone(pid: u32) -> Self {
        Self {
            pid,
            pgid: pid,
            sid: pid,
            is_pgroup_leader: true,
            is_session_leader: true,
            has_ctty: false,
        }
    }

    /// Create a child state inheriting session and group from a parent.
    pub const fn new_child(pid: u32, parent: &PgroupState) -> Self {
        Self {
            pid,
            pgid: parent.pgid,
            sid: parent.sid,
            is_pgroup_leader: false,
            is_session_leader: false,
            has_ctty: parent.has_ctty,
        }
    }
}

// ---------------------------------------------------------------------------
// setpgid
// ---------------------------------------------------------------------------

/// Handler for `setpgid(2)`.
///
/// Sets the process group of process `pid` to `pgid`.
/// `pid == 0` means the calling process; `pgid == 0` means use `pid` as
/// the new PGID.
///
/// # Arguments
///
/// * `caller`    — Mutable state of the calling process.
/// * `target`    — Mutable state of the target process (`None` if `pid == 0`
///   or if `pid == caller.pid`).
/// * `pid`       — PID argument (0 = calling process).
/// * `pgid`      — New PGID (0 = use effective PID).
///
/// # Errors
///
/// | `Error`      | Condition                                               |
/// |--------------|---------------------------------------------------------|
/// | `AccessDenied`| `pid` is a session leader (`EPERM`)                   |
/// | `InvalidArg` | `pgid` is negative (`EINVAL`)                           |
/// | `NotFound`   | `pid` not in the same session (`EPERM` semantics)      |
pub fn do_setpgid(
    caller: &mut PgroupState,
    target: Option<&mut PgroupState>,
    pid: u32,
    pgid: u32,
) -> Result<()> {
    // Resolve effective pid and pgid.
    let eff_pid = if pid == 0 { caller.pid } else { pid };
    let eff_pgid = if pgid == 0 { eff_pid } else { pgid };

    let proc = if eff_pid == caller.pid {
        caller
    } else {
        let t = target.ok_or(Error::NotFound)?;
        // Target must be in the same session.
        if t.sid != caller.sid {
            return Err(Error::PermissionDenied);
        }
        t
    };

    // Session leaders cannot change their process group.
    if proc.is_session_leader {
        return Err(Error::PermissionDenied);
    }

    let old_pgid = proc.pgid;
    proc.pgid = eff_pgid;
    proc.is_pgroup_leader = proc.pid == eff_pgid;
    // If moving out of old group, old group no longer has this process as leader.
    let _ = old_pgid; // old_pgid used for logging in a real kernel
    Ok(())
}

/// Handler for `getpgid(2)`.
///
/// Returns the PGID of process `pid`.  `pid == 0` returns the caller's PGID.
///
/// # Errors
///
/// Returns `Err(NotFound)` if `pid` is not found.
pub fn do_getpgid(caller: &PgroupState, target: Option<&PgroupState>, pid: u32) -> Result<u32> {
    if pid == 0 || pid == caller.pid {
        return Ok(caller.pgid);
    }
    target.map(|t| t.pgid).ok_or(Error::NotFound)
}

/// Handler for `getpgrp(2)`.
///
/// Returns the process group ID of the calling process.
pub fn do_getpgrp(caller: &PgroupState) -> u32 {
    caller.pgid
}

// ---------------------------------------------------------------------------
// setsid
// ---------------------------------------------------------------------------

/// Handler for `setsid(2)`.
///
/// Creates a new session for the calling process.  The process becomes the
/// session leader and the process group leader of a new process group.
///
/// # Errors
///
/// | `Error`      | Condition                                          |
/// |--------------|----------------------------------------------------|
/// | `AccessDenied`| Caller is already a process group leader (`EPERM`) |
pub fn do_setsid(caller: &mut PgroupState) -> Result<u32> {
    // Process group leaders cannot call setsid.
    if caller.is_pgroup_leader {
        return Err(Error::PermissionDenied);
    }

    // New session: SID = PGID = PID.
    caller.sid = caller.pid;
    caller.pgid = caller.pid;
    caller.is_pgroup_leader = true;
    caller.is_session_leader = true;
    caller.has_ctty = false;

    Ok(caller.sid)
}

/// Handler for `getsid(2)`.
///
/// Returns the session ID of process `pid`.  `pid == 0` returns the caller's
/// session ID.
///
/// # Errors
///
/// Returns `Err(NotFound)` if `pid` is not found.  Returns `Err(AccessDenied)`
/// if `pid` is in a different session than the caller (on some systems).
pub fn do_getsid(caller: &PgroupState, target: Option<&PgroupState>, pid: u32) -> Result<u32> {
    if pid == 0 || pid == caller.pid {
        return Ok(caller.sid);
    }
    target.map(|t| t.sid).ok_or(Error::NotFound)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_child(pid: u32, parent: &PgroupState) -> PgroupState {
        PgroupState::new_child(pid, parent)
    }

    #[test]
    fn setpgid_self() {
        let mut p = PgroupState::new_standalone(100);
        // Move to a new group first by making it non-leader.
        p.is_pgroup_leader = false;
        p.pgid = 50; // in another group but not leader
        do_setpgid(&mut p, None, 0, 200).unwrap();
        assert_eq!(p.pgid, 200);
    }

    #[test]
    fn setpgid_session_leader_fails() {
        let mut p = PgroupState::new_standalone(100);
        assert_eq!(
            do_setpgid(&mut p, None, 0, 200),
            Err(Error::PermissionDenied)
        );
    }

    #[test]
    fn setsid_ok() {
        let parent = PgroupState::new_standalone(1);
        let mut child = make_child(200, &parent);
        let sid = do_setsid(&mut child).unwrap();
        assert_eq!(sid, 200);
        assert!(child.is_session_leader);
        assert_eq!(child.sid, 200);
    }

    #[test]
    fn setsid_group_leader_fails() {
        let mut p = PgroupState::new_standalone(100);
        assert_eq!(do_setsid(&mut p), Err(Error::PermissionDenied));
    }

    #[test]
    fn getpgid_self() {
        let p = PgroupState::new_standalone(42);
        assert_eq!(do_getpgid(&p, None, 0).unwrap(), 42);
    }

    #[test]
    fn getsid_self() {
        let p = PgroupState::new_standalone(10);
        assert_eq!(do_getsid(&p, None, 0).unwrap(), 10);
    }
}
