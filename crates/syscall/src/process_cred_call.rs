// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Process credential syscalls: `getuid`, `geteuid`, `getgid`, `getegid`,
//! `getpid`, `getppid`, `gettid`, `getpgrp`, `getsid`.
//!
//! Provides the read-side of process identity syscalls in a unified,
//! testable module.  The write-side (`setuid`, `setgid`, etc.) is handled
//! by `cred_calls.rs`.
//!
//! # POSIX reference
//!
//! POSIX.1-2024 §getpid, §getuid, §getgid, §getsid, §getpgrp.
//!
//! # References
//!
//! - Linux: `kernel/sys.c`
//! - `getpid(2)`, `getuid(2)`, `getgid(2)`, `getsid(2)` man pages

use oncrix_lib::Result;

// ---------------------------------------------------------------------------
// ProcessCredentials — per-process identity record
// ---------------------------------------------------------------------------

/// Process identity record.
#[derive(Debug, Clone, Copy)]
pub struct ProcessCredentials {
    /// Process ID.
    pub pid: u64,
    /// Parent process ID.
    pub ppid: u64,
    /// Thread ID.
    pub tid: u64,
    /// Process group ID.
    pub pgid: u64,
    /// Session ID.
    pub sid: u64,
    /// Real user ID.
    pub uid: u32,
    /// Effective user ID.
    pub euid: u32,
    /// Saved set-user-ID.
    pub suid: u32,
    /// Real group ID.
    pub gid: u32,
    /// Effective group ID.
    pub egid: u32,
    /// Saved set-group-ID.
    pub sgid: u32,
}

impl ProcessCredentials {
    /// Create a root process credential set.
    pub const fn root(pid: u64, ppid: u64) -> Self {
        Self {
            pid,
            ppid,
            tid: pid,
            pgid: pid,
            sid: pid,
            uid: 0,
            euid: 0,
            suid: 0,
            gid: 0,
            egid: 0,
            sgid: 0,
        }
    }

    /// Create a non-root process.
    pub const fn user(pid: u64, ppid: u64, uid: u32, gid: u32) -> Self {
        Self {
            pid,
            ppid,
            tid: pid,
            pgid: pid,
            sid: ppid, // inherit parent's session
            uid,
            euid: uid,
            suid: uid,
            gid,
            egid: gid,
            sgid: gid,
        }
    }
}

// ---------------------------------------------------------------------------
// sys_getpid
// ---------------------------------------------------------------------------

/// Handler for `getpid(2)`.
pub fn sys_getpid(cred: &ProcessCredentials) -> Result<u64> {
    Ok(cred.pid)
}

// ---------------------------------------------------------------------------
// sys_getppid
// ---------------------------------------------------------------------------

/// Handler for `getppid(2)`.
pub fn sys_getppid(cred: &ProcessCredentials) -> Result<u64> {
    Ok(cred.ppid)
}

// ---------------------------------------------------------------------------
// sys_gettid
// ---------------------------------------------------------------------------

/// Handler for `gettid(2)`.
pub fn sys_gettid(cred: &ProcessCredentials) -> Result<u64> {
    Ok(cred.tid)
}

// ---------------------------------------------------------------------------
// sys_getuid
// ---------------------------------------------------------------------------

/// Handler for `getuid(2)`.
pub fn sys_getuid(cred: &ProcessCredentials) -> Result<u32> {
    Ok(cred.uid)
}

// ---------------------------------------------------------------------------
// sys_geteuid
// ---------------------------------------------------------------------------

/// Handler for `geteuid(2)`.
pub fn sys_geteuid(cred: &ProcessCredentials) -> Result<u32> {
    Ok(cred.euid)
}

// ---------------------------------------------------------------------------
// sys_getgid
// ---------------------------------------------------------------------------

/// Handler for `getgid(2)`.
pub fn sys_getgid(cred: &ProcessCredentials) -> Result<u32> {
    Ok(cred.gid)
}

// ---------------------------------------------------------------------------
// sys_getegid
// ---------------------------------------------------------------------------

/// Handler for `getegid(2)`.
pub fn sys_getegid(cred: &ProcessCredentials) -> Result<u32> {
    Ok(cred.egid)
}

// ---------------------------------------------------------------------------
// sys_getpgrp
// ---------------------------------------------------------------------------

/// Handler for `getpgrp(2)`.
///
/// Returns the process group ID of the calling process.
pub fn sys_getpgrp(cred: &ProcessCredentials) -> Result<u64> {
    Ok(cred.pgid)
}

// ---------------------------------------------------------------------------
// sys_getsid
// ---------------------------------------------------------------------------

/// Handler for `getsid(2)`.
///
/// Returns the session ID of process `pid`.
/// When `pid == 0`, returns the session of the calling process.
///
/// # Arguments
///
/// * `cred`   — Credentials of the calling process.
/// * `pid`    — Target PID (0 = self).
/// * `target` — Optional credentials of the target process (required when `pid != 0`).
pub fn sys_getsid(
    cred: &ProcessCredentials,
    pid: u64,
    target: Option<&ProcessCredentials>,
) -> Result<u64> {
    use oncrix_lib::Error;
    if pid == 0 || pid == cred.pid {
        return Ok(cred.sid);
    }
    target.map(|t| t.sid).ok_or(Error::NotFound)
}

// ---------------------------------------------------------------------------
// sys_getpgid
// ---------------------------------------------------------------------------

/// Handler for `getpgid(2)`.
///
/// Returns the process group ID of process `pid` (0 = self).
pub fn sys_getpgid(
    cred: &ProcessCredentials,
    pid: u64,
    target: Option<&ProcessCredentials>,
) -> Result<u64> {
    use oncrix_lib::Error;
    if pid == 0 || pid == cred.pid {
        return Ok(cred.pgid);
    }
    target.map(|t| t.pgid).ok_or(Error::NotFound)
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_cred() -> ProcessCredentials {
        ProcessCredentials::user(100, 1, 1000, 1000)
    }

    #[test]
    fn getpid() {
        let c = make_cred();
        assert_eq!(sys_getpid(&c).unwrap(), 100);
    }

    #[test]
    fn getppid() {
        let c = make_cred();
        assert_eq!(sys_getppid(&c).unwrap(), 1);
    }

    #[test]
    fn getuid_euid() {
        let c = make_cred();
        assert_eq!(sys_getuid(&c).unwrap(), 1000);
        assert_eq!(sys_geteuid(&c).unwrap(), 1000);
    }

    #[test]
    fn root_cred() {
        let c = ProcessCredentials::root(1, 0);
        assert_eq!(sys_getuid(&c).unwrap(), 0);
        assert_eq!(sys_getegid(&c).unwrap(), 0);
    }

    #[test]
    fn getsid_self() {
        let c = make_cred();
        assert_eq!(sys_getsid(&c, 0, None).unwrap(), c.sid);
    }

    #[test]
    fn getsid_other() {
        let caller = make_cred();
        let target = ProcessCredentials::root(200, 100);
        assert_eq!(sys_getsid(&caller, 200, Some(&target)).unwrap(), target.sid);
    }

    #[test]
    fn getsid_other_not_found() {
        use oncrix_lib::Error;
        let caller = make_cred();
        assert_eq!(sys_getsid(&caller, 999, None), Err(Error::NotFound));
    }

    #[test]
    fn getpgid_self() {
        let c = make_cred();
        assert_eq!(sys_getpgid(&c, 0, None).unwrap(), c.pgid);
    }
}
