// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `getuid(2)`, `geteuid(2)`, `getgid(2)`, `getegid(2)`,
//! `getresuid(2)`, and `getresgid(2)` syscall handlers.
//!
//! Return credential information for the calling process.
//!
//! # POSIX Conformance
//!
//! Follows POSIX.1-2024 specification.  All functions always succeed.
//! Key behaviours:
//! - `getuid` returns the real user ID.
//! - `geteuid` returns the effective user ID.
//! - `getgid` returns the real group ID.
//! - `getegid` returns the effective group ID.
//! - `getresuid` returns (ruid, euid, suid) — Linux extension.
//! - `getresgid` returns (rgid, egid, sgid) — Linux extension.
//!
//! # References
//!
//! - POSIX.1-2024: `getuid()`, `geteuid()`, `getgid()`, `getegid()`
//! - Linux man pages: `getresuid(2)`

// ---------------------------------------------------------------------------
// Credentials
// ---------------------------------------------------------------------------

/// Process credential set (uid/gid triplets).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Credentials {
    /// Real user ID.
    pub uid: u32,
    /// Effective user ID.
    pub euid: u32,
    /// Saved-set user ID.
    pub suid: u32,
    /// Filesystem user ID.
    pub fsuid: u32,
    /// Real group ID.
    pub gid: u32,
    /// Effective group ID.
    pub egid: u32,
    /// Saved-set group ID.
    pub sgid: u32,
    /// Filesystem group ID.
    pub fsgid: u32,
}

impl Credentials {
    /// Construct root credentials.
    pub const fn root() -> Self {
        Self {
            uid: 0,
            euid: 0,
            suid: 0,
            fsuid: 0,
            gid: 0,
            egid: 0,
            sgid: 0,
            fsgid: 0,
        }
    }

    /// Construct unprivileged credentials.
    pub const fn user(uid: u32, gid: u32) -> Self {
        Self {
            uid,
            euid: uid,
            suid: uid,
            fsuid: uid,
            gid,
            egid: gid,
            sgid: gid,
            fsgid: gid,
        }
    }
}

// ---------------------------------------------------------------------------
// Core handlers
// ---------------------------------------------------------------------------

/// Handler for `getuid(2)`.
pub fn do_getuid(cred: &Credentials) -> u32 {
    cred.uid
}

/// Handler for `geteuid(2)`.
pub fn do_geteuid(cred: &Credentials) -> u32 {
    cred.euid
}

/// Handler for `getgid(2)`.
pub fn do_getgid(cred: &Credentials) -> u32 {
    cred.gid
}

/// Handler for `getegid(2)`.
pub fn do_getegid(cred: &Credentials) -> u32 {
    cred.egid
}

/// Handler for `getresuid(2)`.
///
/// Returns `(ruid, euid, suid)`.
pub fn do_getresuid(cred: &Credentials) -> (u32, u32, u32) {
    (cred.uid, cred.euid, cred.suid)
}

/// Handler for `getresgid(2)`.
///
/// Returns `(rgid, egid, sgid)`.
pub fn do_getresgid(cred: &Credentials) -> (u32, u32, u32) {
    (cred.gid, cred.egid, cred.sgid)
}

/// Handler for `getfsuid(2)` — filesystem UID (Linux extension).
pub fn do_getfsuid(cred: &Credentials) -> u32 {
    cred.fsuid
}

/// Handler for `getfsgid(2)` — filesystem GID (Linux extension).
pub fn do_getfsgid(cred: &Credentials) -> u32 {
    cred.fsgid
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn cred() -> Credentials {
        Credentials::user(1000, 1000)
    }

    #[test]
    fn getuid() {
        assert_eq!(do_getuid(&cred()), 1000);
    }

    #[test]
    fn geteuid() {
        assert_eq!(do_geteuid(&cred()), 1000);
    }

    #[test]
    fn getgid() {
        assert_eq!(do_getgid(&cred()), 1000);
    }

    #[test]
    fn getegid() {
        assert_eq!(do_getegid(&cred()), 1000);
    }

    #[test]
    fn getresuid() {
        let (r, e, s) = do_getresuid(&cred());
        assert_eq!(r, 1000);
        assert_eq!(e, 1000);
        assert_eq!(s, 1000);
    }

    #[test]
    fn getresgid() {
        let (r, e, s) = do_getresgid(&cred());
        assert_eq!((r, e, s), (1000, 1000, 1000));
    }

    #[test]
    fn root_credentials() {
        let c = Credentials::root();
        assert_eq!(do_getuid(&c), 0);
        assert_eq!(do_geteuid(&c), 0);
    }
}
