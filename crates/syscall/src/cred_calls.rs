// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Process credential syscall handlers.
//!
//! Implements the POSIX.1-2024 and Linux credential management syscalls that
//! allow processes to query and change their user and group identities.
//!
//! # Operations
//!
//! | Syscall         | Handler                | Purpose                              |
//! |-----------------|------------------------|--------------------------------------|
//! | `getuid`        | [`do_getuid`]          | Get real UID                         |
//! | `geteuid`       | [`do_geteuid`]         | Get effective UID                    |
//! | `getgid`        | [`do_getgid`]          | Get real GID                         |
//! | `getegid`       | [`do_getegid`]         | Get effective GID                    |
//! | `setuid`        | [`do_setuid`]          | Set UID (POSIX semantics)            |
//! | `setgid`        | [`do_setgid`]          | Set GID (POSIX semantics)            |
//! | `setreuid`      | [`do_setreuid`]        | Set real and effective UID           |
//! | `setregid`      | [`do_setregid`]        | Set real and effective GID           |
//! | `setresuid`     | [`do_setresuid`]       | Set real, effective, saved UID       |
//! | `setresgid`     | [`do_setresgid`]       | Set real, effective, saved GID       |
//! | `getresuid`     | [`do_getresuid`]       | Get real, effective, saved UID       |
//! | `getresgid`     | [`do_getresgid`]       | Get real, effective, saved GID       |
//! | `getgroups`     | [`do_getgroups`]       | Get supplementary group list         |
//! | `setgroups`     | [`do_setgroups`]       | Set supplementary group list         |
//!
//! # References
//!
//! - POSIX.1-2024: `setuid()`, `setgid()`, `getgroups()`, `setgroups()`
//! - Linux: `kernel/sys.c`, `include/linux/cred.h`

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Sentinel meaning "do not change this field" in `setreuid`/`setregid`.
pub const NOOP_ID: u32 = u32::MAX;

/// Maximum number of supplementary groups per process.
pub const NGROUPS_MAX: usize = 32;

// ---------------------------------------------------------------------------
// Credentials structure
// ---------------------------------------------------------------------------

/// Full set of credentials for a process.
///
/// Mirrors `struct cred` from the Linux kernel, carrying real, effective, and
/// saved-set user/group IDs plus the supplementary group list.
#[derive(Debug, Clone)]
pub struct Credentials {
    /// Real user ID.
    pub uid: u32,
    /// Effective user ID — used for most permission checks.
    pub euid: u32,
    /// Saved-set user ID — allows dropping and re-acquiring privileges.
    pub suid: u32,
    /// Filesystem user ID (Linux extension; mirrors euid unless changed).
    pub fsuid: u32,
    /// Real group ID.
    pub gid: u32,
    /// Effective group ID.
    pub egid: u32,
    /// Saved-set group ID.
    pub sgid: u32,
    /// Filesystem group ID (mirrors egid unless changed).
    pub fsgid: u32,
    /// Supplementary groups.
    pub groups: [u32; NGROUPS_MAX],
    /// Number of valid entries in `groups`.
    pub ngroups: usize,
}

impl Credentials {
    /// Create credentials for a root process (all IDs = 0, no supplementary groups).
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
            groups: [0u32; NGROUPS_MAX],
            ngroups: 0,
        }
    }

    /// Create credentials for a non-privileged user.
    pub const fn new_user(uid: u32, gid: u32) -> Self {
        Self {
            uid,
            euid: uid,
            suid: uid,
            fsuid: uid,
            gid,
            egid: gid,
            sgid: gid,
            fsgid: gid,
            groups: [0u32; NGROUPS_MAX],
            ngroups: 0,
        }
    }

    /// Return `true` if the effective UID is 0 (root / superuser).
    pub const fn is_privileged(&self) -> bool {
        self.euid == 0
    }

    /// Check whether `gid` is in the supplementary group list.
    pub fn in_group(&self, gid: u32) -> bool {
        self.groups[..self.ngroups].iter().any(|&g| g == gid)
    }
}

impl Default for Credentials {
    fn default() -> Self {
        Self::new_user(1000, 1000)
    }
}

// ---------------------------------------------------------------------------
// Simple getters
// ---------------------------------------------------------------------------

/// Handler for `getuid(2)` — returns the real UID of the calling process.
pub fn do_getuid(cred: &Credentials) -> u32 {
    cred.uid
}

/// Handler for `geteuid(2)` — returns the effective UID of the calling process.
pub fn do_geteuid(cred: &Credentials) -> u32 {
    cred.euid
}

/// Handler for `getgid(2)` — returns the real GID of the calling process.
pub fn do_getgid(cred: &Credentials) -> u32 {
    cred.gid
}

/// Handler for `getegid(2)` — returns the effective GID of the calling process.
pub fn do_getegid(cred: &Credentials) -> u32 {
    cred.egid
}

/// Handler for `getresuid(2)`.
///
/// Writes the real, effective, and saved-set UIDs into the supplied output
/// variables.
///
/// # Returns
///
/// `(ruid, euid, suid)` on success.
///
/// # Linux conformance
///
/// All three values are always returned; no permission checks are required.
pub fn do_getresuid(cred: &Credentials) -> (u32, u32, u32) {
    (cred.uid, cred.euid, cred.suid)
}

/// Handler for `getresgid(2)`.
///
/// Returns the real, effective, and saved-set GIDs.
///
/// # Returns
///
/// `(rgid, egid, sgid)` on success.
pub fn do_getresgid(cred: &Credentials) -> (u32, u32, u32) {
    (cred.gid, cred.egid, cred.sgid)
}

/// Handler for `getgroups(2)`.
///
/// Fills `buf` with up to `buf.len()` supplementary group IDs and returns the
/// total number of supplementary groups.
///
/// # Errors
///
/// Returns [`Error::InvalidArgument`] if `buf` is smaller than the actual
/// supplementary group count (and non-empty).
///
/// # POSIX conformance
///
/// Calling with an empty `buf` is a valid way to query the group count without
/// copying.
pub fn do_getgroups(cred: &Credentials, buf: &mut [u32]) -> Result<usize> {
    if buf.is_empty() {
        // Query-only: return count.
        return Ok(cred.ngroups);
    }
    if buf.len() < cred.ngroups {
        return Err(Error::InvalidArgument);
    }
    buf[..cred.ngroups].copy_from_slice(&cred.groups[..cred.ngroups]);
    Ok(cred.ngroups)
}

// ---------------------------------------------------------------------------
// do_setuid
// ---------------------------------------------------------------------------

/// Handler for `setuid(2)`.
///
/// POSIX semantics:
/// - If the caller is privileged (`euid == 0`), sets `uid`, `euid`, and `suid`
///   to `new_uid`.
/// - Otherwise, sets `euid` to `new_uid` only if `new_uid == uid` or
///   `new_uid == suid`.
///
/// # Errors
///
/// * [`Error::PermissionDenied`] — Unprivileged caller trying to set an
///   arbitrary UID.
///
/// # POSIX conformance
///
/// `setuid()` — POSIX.1-2024 §2.2.
pub fn do_setuid(cred: &mut Credentials, new_uid: u32) -> Result<()> {
    if cred.is_privileged() {
        cred.uid = new_uid;
        cred.euid = new_uid;
        cred.suid = new_uid;
        cred.fsuid = new_uid;
        return Ok(());
    }
    // Unprivileged: only allow switching to real or saved-set UID.
    if new_uid == cred.uid || new_uid == cred.suid {
        cred.euid = new_uid;
        cred.fsuid = new_uid;
        return Ok(());
    }
    Err(Error::PermissionDenied)
}

// ---------------------------------------------------------------------------
// do_setgid
// ---------------------------------------------------------------------------

/// Handler for `setgid(2)`.
///
/// POSIX semantics mirror those of [`do_setuid`] but for the GID dimension.
///
/// # Errors
///
/// * [`Error::PermissionDenied`] — Unprivileged caller.
pub fn do_setgid(cred: &mut Credentials, new_gid: u32) -> Result<()> {
    if cred.is_privileged() {
        cred.gid = new_gid;
        cred.egid = new_gid;
        cred.sgid = new_gid;
        cred.fsgid = new_gid;
        return Ok(());
    }
    if new_gid == cred.gid || new_gid == cred.sgid {
        cred.egid = new_gid;
        cred.fsgid = new_gid;
        return Ok(());
    }
    Err(Error::PermissionDenied)
}

// ---------------------------------------------------------------------------
// do_setreuid
// ---------------------------------------------------------------------------

/// Handler for `setreuid(2)`.
///
/// Sets the real and/or effective UID.  [`NOOP_ID`] (`u32::MAX`) means "leave
/// unchanged".
///
/// Rules (Linux / POSIX):
/// - Privileged processes may set either to any value.
/// - Unprivileged processes may swap real and effective UID, or set the
///   effective UID to the saved-set UID.
/// - The saved-set UID is updated when the effective UID changes and the new
///   euid does not equal the old ruid.
///
/// # Errors
///
/// * [`Error::PermissionDenied`] — Forbidden combination for unprivileged caller.
pub fn do_setreuid(cred: &mut Credentials, ruid: u32, euid: u32) -> Result<()> {
    let old_uid = cred.uid;
    let old_euid = cred.euid;
    let old_suid = cred.suid;

    if cred.is_privileged() {
        if ruid != NOOP_ID {
            cred.uid = ruid;
        }
        if euid != NOOP_ID {
            cred.euid = euid;
            cred.fsuid = euid;
        }
    } else {
        // ruid must be NOOP, current uid, or current euid.
        if ruid != NOOP_ID && ruid != old_uid && ruid != old_euid {
            return Err(Error::PermissionDenied);
        }
        // euid must be NOOP, current uid, current euid, or saved-set uid.
        if euid != NOOP_ID && euid != old_uid && euid != old_euid && euid != old_suid {
            return Err(Error::PermissionDenied);
        }
        if ruid != NOOP_ID {
            cred.uid = ruid;
        }
        if euid != NOOP_ID {
            cred.euid = euid;
            cred.fsuid = euid;
        }
    }

    // Update saved-set UID: if ruid was set, or euid != new uid, update suid.
    let new_euid = cred.euid;
    let new_uid = cred.uid;
    if ruid != NOOP_ID || (euid != NOOP_ID && new_euid != new_uid) {
        cred.suid = new_euid;
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// do_setregid
// ---------------------------------------------------------------------------

/// Handler for `setregid(2)`.
///
/// Sets the real and/or effective GID.  [`NOOP_ID`] means "leave unchanged".
///
/// # Errors
///
/// * [`Error::PermissionDenied`] — Forbidden combination for unprivileged caller.
pub fn do_setregid(cred: &mut Credentials, rgid: u32, egid: u32) -> Result<()> {
    let old_gid = cred.gid;
    let old_egid = cred.egid;
    let old_sgid = cred.sgid;

    if cred.is_privileged() {
        if rgid != NOOP_ID {
            cred.gid = rgid;
        }
        if egid != NOOP_ID {
            cred.egid = egid;
            cred.fsgid = egid;
        }
    } else {
        if rgid != NOOP_ID && rgid != old_gid && rgid != old_egid {
            return Err(Error::PermissionDenied);
        }
        if egid != NOOP_ID && egid != old_gid && egid != old_egid && egid != old_sgid {
            return Err(Error::PermissionDenied);
        }
        if rgid != NOOP_ID {
            cred.gid = rgid;
        }
        if egid != NOOP_ID {
            cred.egid = egid;
            cred.fsgid = egid;
        }
    }

    // Update saved-set GID analogously to saved-set UID.
    let new_egid = cred.egid;
    let new_gid = cred.gid;
    if rgid != NOOP_ID || (egid != NOOP_ID && new_egid != new_gid) {
        cred.sgid = new_egid;
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// do_setresuid / do_setresgid
// ---------------------------------------------------------------------------

/// Handler for `setresuid(2)`.
///
/// Explicitly sets real, effective, and saved-set UID.  [`NOOP_ID`] means
/// "leave unchanged".
///
/// Privileged processes may set each field to any value.  Unprivileged
/// processes may only use IDs already present in the current `{uid,euid,suid}`
/// set.
///
/// # Errors
///
/// * [`Error::PermissionDenied`] — Unprivileged caller uses an ID outside the
///   current set.
pub fn do_setresuid(cred: &mut Credentials, ruid: u32, euid: u32, suid: u32) -> Result<()> {
    if !cred.is_privileged() {
        let allowed = [cred.uid, cred.euid, cred.suid];
        if ruid != NOOP_ID && !allowed.contains(&ruid) {
            return Err(Error::PermissionDenied);
        }
        if euid != NOOP_ID && !allowed.contains(&euid) {
            return Err(Error::PermissionDenied);
        }
        if suid != NOOP_ID && !allowed.contains(&suid) {
            return Err(Error::PermissionDenied);
        }
    }
    if ruid != NOOP_ID {
        cred.uid = ruid;
    }
    if euid != NOOP_ID {
        cred.euid = euid;
        cred.fsuid = euid;
    }
    if suid != NOOP_ID {
        cred.suid = suid;
    }
    Ok(())
}

/// Handler for `setresgid(2)`.
///
/// Explicitly sets real, effective, and saved-set GID.  [`NOOP_ID`] means
/// "leave unchanged".
///
/// # Errors
///
/// * [`Error::PermissionDenied`] — Unprivileged caller uses a GID outside
///   the current set.
pub fn do_setresgid(cred: &mut Credentials, rgid: u32, egid: u32, sgid: u32) -> Result<()> {
    if !cred.is_privileged() {
        let allowed = [cred.gid, cred.egid, cred.sgid];
        if rgid != NOOP_ID && !allowed.contains(&rgid) {
            return Err(Error::PermissionDenied);
        }
        if egid != NOOP_ID && !allowed.contains(&egid) {
            return Err(Error::PermissionDenied);
        }
        if sgid != NOOP_ID && !allowed.contains(&sgid) {
            return Err(Error::PermissionDenied);
        }
    }
    if rgid != NOOP_ID {
        cred.gid = rgid;
    }
    if egid != NOOP_ID {
        cred.egid = egid;
        cred.fsgid = egid;
    }
    if sgid != NOOP_ID {
        cred.sgid = sgid;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// do_setgroups
// ---------------------------------------------------------------------------

/// Handler for `setgroups(2)`.
///
/// Replaces the supplementary group list with `groups[..count]`.
///
/// # Arguments
///
/// * `cred`   — Credential set to update.
/// * `groups` — New supplementary group IDs.
///
/// # Errors
///
/// * [`Error::PermissionDenied`] — Caller is not privileged.
/// * [`Error::InvalidArgument`]  — `groups.len() > NGROUPS_MAX`.
///
/// # POSIX conformance
///
/// Requires `CAP_SETGID` or root privilege.  Here simplified to `euid == 0`.
pub fn do_setgroups(cred: &mut Credentials, groups: &[u32]) -> Result<()> {
    if !cred.is_privileged() {
        return Err(Error::PermissionDenied);
    }
    if groups.len() > NGROUPS_MAX {
        return Err(Error::InvalidArgument);
    }
    cred.ngroups = groups.len();
    cred.groups[..groups.len()].copy_from_slice(groups);
    Ok(())
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // --- getters ---

    #[test]
    fn getuid_returns_real_uid() {
        let cred = Credentials::new_user(500, 500);
        assert_eq!(do_getuid(&cred), 500);
    }

    #[test]
    fn geteuid_matches_euid() {
        let cred = Credentials::new_user(500, 500);
        assert_eq!(do_geteuid(&cred), 500);
    }

    #[test]
    fn getresuid_all_three() {
        let cred = Credentials::new_user(500, 500);
        assert_eq!(do_getresuid(&cred), (500, 500, 500));
    }

    #[test]
    fn getresgid_all_three() {
        let cred = Credentials::new_user(500, 600);
        assert_eq!(do_getresgid(&cred), (600, 600, 600));
    }

    // --- getgroups ---

    #[test]
    fn getgroups_empty_buf_returns_count() {
        let mut cred = Credentials::root();
        do_setgroups(&mut cred, &[1000, 2000]).unwrap();
        let count = do_getgroups(&cred, &mut []).unwrap();
        assert_eq!(count, 2);
    }

    #[test]
    fn getgroups_fills_buffer() {
        let mut cred = Credentials::root();
        do_setgroups(&mut cred, &[10, 20, 30]).unwrap();
        let mut buf = [0u32; 8];
        let n = do_getgroups(&cred, &mut buf).unwrap();
        assert_eq!(n, 3);
        assert_eq!(&buf[..3], &[10, 20, 30]);
    }

    #[test]
    fn getgroups_buffer_too_small_fails() {
        let mut cred = Credentials::root();
        do_setgroups(&mut cred, &[1, 2, 3, 4]).unwrap();
        let mut buf = [0u32; 2];
        assert_eq!(do_getgroups(&cred, &mut buf), Err(Error::InvalidArgument));
    }

    // --- setgroups ---

    #[test]
    fn setgroups_requires_root() {
        let mut cred = Credentials::new_user(500, 500);
        assert_eq!(
            do_setgroups(&mut cred, &[1000]),
            Err(Error::PermissionDenied)
        );
    }

    #[test]
    fn setgroups_too_many_fails() {
        let mut cred = Credentials::root();
        let groups: [u32; NGROUPS_MAX + 1] = [0u32; NGROUPS_MAX + 1];
        assert_eq!(
            do_setgroups(&mut cred, &groups),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn setgroups_root_succeeds() {
        let mut cred = Credentials::root();
        do_setgroups(&mut cred, &[100, 200]).unwrap();
        assert_eq!(cred.ngroups, 2);
        assert!(cred.in_group(100));
        assert!(cred.in_group(200));
        assert!(!cred.in_group(300));
    }

    // --- setuid ---

    #[test]
    fn setuid_root_sets_all_three() {
        let mut cred = Credentials::root();
        do_setuid(&mut cred, 500).unwrap();
        assert_eq!((cred.uid, cred.euid, cred.suid), (500, 500, 500));
    }

    #[test]
    fn setuid_unprivileged_own_uid() {
        let mut cred = Credentials::new_user(500, 500);
        do_setuid(&mut cred, 500).unwrap();
        assert_eq!(cred.euid, 500);
    }

    #[test]
    fn setuid_unprivileged_arbitrary_denied() {
        let mut cred = Credentials::new_user(500, 500);
        assert_eq!(do_setuid(&mut cred, 999), Err(Error::PermissionDenied));
    }

    #[test]
    fn setuid_to_suid_allowed() {
        // Simulate dropping privileges then re-acquiring via suid.
        let mut cred = Credentials {
            uid: 500,
            euid: 0,
            suid: 500,
            fsuid: 0,
            ..Credentials::new_user(500, 500)
        };
        // unprivileged (euid != 0 after setuid drops it)
        cred.euid = 100;
        cred.fsuid = 100;
        // can return to suid=500
        do_setuid(&mut cred, 500).unwrap();
        assert_eq!(cred.euid, 500);
    }

    // --- setgid ---

    #[test]
    fn setgid_root_sets_all_three() {
        let mut cred = Credentials::root();
        do_setgid(&mut cred, 500).unwrap();
        assert_eq!((cred.gid, cred.egid, cred.sgid), (500, 500, 500));
    }

    #[test]
    fn setgid_unprivileged_arbitrary_denied() {
        let mut cred = Credentials::new_user(500, 500);
        assert_eq!(do_setgid(&mut cred, 999), Err(Error::PermissionDenied));
    }

    // --- setreuid ---

    #[test]
    fn setreuid_root_arbitrary() {
        let mut cred = Credentials::root();
        do_setreuid(&mut cred, 100, 200).unwrap();
        assert_eq!(cred.uid, 100);
        assert_eq!(cred.euid, 200);
    }

    #[test]
    fn setreuid_noop_unchanged() {
        let mut cred = Credentials::new_user(500, 500);
        do_setreuid(&mut cred, NOOP_ID, NOOP_ID).unwrap();
        assert_eq!((cred.uid, cred.euid), (500, 500));
    }

    #[test]
    fn setreuid_unpriv_swap_uid_euid() {
        let mut cred = Credentials::new_user(500, 500);
        cred.euid = 600;
        cred.suid = 600;
        // Can swap: set ruid=600 (current euid), euid=500 (current uid)
        do_setreuid(&mut cred, 600, 500).unwrap();
        assert_eq!(cred.uid, 600);
        assert_eq!(cred.euid, 500);
    }

    // --- setresuid ---

    #[test]
    fn setresuid_unprivileged_own_ids() {
        let mut cred = Credentials::new_user(500, 500);
        do_setresuid(&mut cred, 500, 500, 500).unwrap();
    }

    #[test]
    fn setresuid_unprivileged_foreign_denied() {
        let mut cred = Credentials::new_user(500, 500);
        assert_eq!(
            do_setresuid(&mut cred, 500, 500, 999),
            Err(Error::PermissionDenied)
        );
    }

    #[test]
    fn setresuid_root_arbitrary() {
        let mut cred = Credentials::root();
        do_setresuid(&mut cred, 1, 2, 3).unwrap();
        assert_eq!((cred.uid, cred.euid, cred.suid), (1, 2, 3));
    }

    // --- setresgid ---

    #[test]
    fn setresgid_root_arbitrary() {
        let mut cred = Credentials::root();
        do_setresgid(&mut cred, 10, 20, 30).unwrap();
        assert_eq!((cred.gid, cred.egid, cred.sgid), (10, 20, 30));
    }

    #[test]
    fn setresgid_unprivileged_foreign_denied() {
        let mut cred = Credentials::new_user(500, 500);
        assert_eq!(
            do_setresgid(&mut cred, 500, 500, 999),
            Err(Error::PermissionDenied)
        );
    }

    // --- is_privileged ---

    #[test]
    fn root_is_privileged() {
        assert!(Credentials::root().is_privileged());
    }

    #[test]
    fn non_root_not_privileged() {
        assert!(!Credentials::new_user(500, 500).is_privileged());
    }
}
