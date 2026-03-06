// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `setuid(2)`, `seteuid(2)`, `setgid(2)`, `setegid(2)`,
//! `setreuid(2)`, `setregid(2)`, `setresuid(2)`, and `setresgid(2)`
//! syscall handlers.
//!
//! Set credential information for the calling process.
//!
//! # POSIX Conformance
//!
//! Follows POSIX.1-2024 `setuid()` etc.  Key behaviours:
//! - If the caller has `CAP_SETUID`, `setuid` sets all three (real, effective,
//!   saved) UIDs to `uid`.
//! - Without `CAP_SETUID`, `setuid` sets only the effective UID to `uid`
//!   (which must equal the real or saved UID).
//! - `-1` in `setresuid`/`setresgid` means "leave unchanged".
//!
//! # References
//!
//! - POSIX.1-2024: `setuid()`, `setgid()`
//! - Linux man pages: `setuid(2)`, `setresuid(2)`

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Credentials
// ---------------------------------------------------------------------------

/// Process credential set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Credentials {
    /// Real user ID.
    pub uid: u32,
    /// Effective user ID.
    pub euid: u32,
    /// Saved-set user ID.
    pub suid: u32,
    /// Real group ID.
    pub gid: u32,
    /// Effective group ID.
    pub egid: u32,
    /// Saved-set group ID.
    pub sgid: u32,
}

impl Credentials {
    /// Construct unprivileged credentials.
    pub const fn user(uid: u32, gid: u32) -> Self {
        Self {
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
// Helpers
// ---------------------------------------------------------------------------

/// Sentinel meaning "do not change" in setresuid/setresgid.
pub const UNCHANGED: u32 = u32::MAX;

// ---------------------------------------------------------------------------
// Core handlers
// ---------------------------------------------------------------------------

/// Handler for `setuid(2)`.
///
/// With `CAP_SETUID`: sets uid, euid, suid to `uid`.
/// Without: sets euid to `uid` if `uid == real_uid || uid == suid`.
///
/// # Errors
///
/// | `Error`           | Condition                                        |
/// |-------------------|--------------------------------------------------|
/// | `PermissionDenied`| No cap and `uid` not in {ruid, suid}             |
pub fn do_setuid(cred: &mut Credentials, uid: u32, cap_setuid: bool) -> Result<()> {
    if cap_setuid {
        cred.uid = uid;
        cred.euid = uid;
        cred.suid = uid;
    } else {
        if uid != cred.uid && uid != cred.suid {
            return Err(Error::PermissionDenied);
        }
        cred.euid = uid;
    }
    Ok(())
}

/// Handler for `seteuid(2)`.
///
/// Sets effective UID.  With cap: any value; without: must be ruid or suid.
///
/// # Errors
///
/// | `Error`           | Condition                          |
/// |-------------------|------------------------------------|
/// | `PermissionDenied`| Not in {ruid, suid} without cap    |
pub fn do_seteuid(cred: &mut Credentials, euid: u32, cap_setuid: bool) -> Result<()> {
    if !cap_setuid && euid != cred.uid && euid != cred.suid {
        return Err(Error::PermissionDenied);
    }
    cred.euid = euid;
    Ok(())
}

/// Handler for `setgid(2)`.
///
/// With `CAP_SETGID`: sets gid, egid, sgid.
/// Without: sets egid if `gid` is rgid or sgid.
pub fn do_setgid(cred: &mut Credentials, gid: u32, cap_setgid: bool) -> Result<()> {
    if cap_setgid {
        cred.gid = gid;
        cred.egid = gid;
        cred.sgid = gid;
    } else {
        if gid != cred.gid && gid != cred.sgid {
            return Err(Error::PermissionDenied);
        }
        cred.egid = gid;
    }
    Ok(())
}

/// Handler for `setegid(2)`.
pub fn do_setegid(cred: &mut Credentials, egid: u32, cap_setgid: bool) -> Result<()> {
    if !cap_setgid && egid != cred.gid && egid != cred.sgid {
        return Err(Error::PermissionDenied);
    }
    cred.egid = egid;
    Ok(())
}

/// Handler for `setreuid(2)`.
///
/// Sets real and/or effective UID.  `-1` (as u32::MAX) means unchanged.
pub fn do_setreuid(cred: &mut Credentials, ruid: u32, euid: u32, cap_setuid: bool) -> Result<()> {
    // Validate.
    if !cap_setuid {
        if ruid != UNCHANGED && ruid != cred.uid && ruid != cred.euid {
            return Err(Error::PermissionDenied);
        }
        if euid != UNCHANGED && euid != cred.uid && euid != cred.euid && euid != cred.suid {
            return Err(Error::PermissionDenied);
        }
    }
    let new_ruid = if ruid == UNCHANGED { cred.uid } else { ruid };
    let new_euid = if euid == UNCHANGED { cred.euid } else { euid };
    // If ruid changed or new_euid != old ruid, update suid.
    let new_suid = if ruid != UNCHANGED || new_euid != cred.uid {
        new_euid
    } else {
        cred.suid
    };
    cred.uid = new_ruid;
    cred.euid = new_euid;
    cred.suid = new_suid;
    Ok(())
}

/// Handler for `setresuid(2)`.
///
/// Sets real, effective, and saved UIDs.  `UNCHANGED` means leave as-is.
pub fn do_setresuid(
    cred: &mut Credentials,
    ruid: u32,
    euid: u32,
    suid: u32,
    cap_setuid: bool,
) -> Result<()> {
    if !cap_setuid {
        let valid = |v: u32| v == UNCHANGED || v == cred.uid || v == cred.euid || v == cred.suid;
        if !valid(ruid) || !valid(euid) || !valid(suid) {
            return Err(Error::PermissionDenied);
        }
    }
    if ruid != UNCHANGED {
        cred.uid = ruid;
    }
    if euid != UNCHANGED {
        cred.euid = euid;
    }
    if suid != UNCHANGED {
        cred.suid = suid;
    }
    Ok(())
}

/// Handler for `setresgid(2)`.
pub fn do_setresgid(
    cred: &mut Credentials,
    rgid: u32,
    egid: u32,
    sgid: u32,
    cap_setgid: bool,
) -> Result<()> {
    if !cap_setgid {
        let valid = |v: u32| v == UNCHANGED || v == cred.gid || v == cred.egid || v == cred.sgid;
        if !valid(rgid) || !valid(egid) || !valid(sgid) {
            return Err(Error::PermissionDenied);
        }
    }
    if rgid != UNCHANGED {
        cred.gid = rgid;
    }
    if egid != UNCHANGED {
        cred.egid = egid;
    }
    if sgid != UNCHANGED {
        cred.sgid = sgid;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn user_cred() -> Credentials {
        Credentials::user(1000, 1000)
    }

    #[test]
    fn setuid_privileged() {
        let mut c = user_cred();
        do_setuid(&mut c, 0, true).unwrap();
        assert_eq!(c.uid, 0);
        assert_eq!(c.euid, 0);
        assert_eq!(c.suid, 0);
    }

    #[test]
    fn setuid_unprivileged_ok() {
        let mut c = user_cred();
        c.suid = 2000;
        do_setuid(&mut c, 2000, false).unwrap();
        assert_eq!(c.euid, 2000);
    }

    #[test]
    fn setuid_unprivileged_fail() {
        let mut c = user_cred();
        assert_eq!(do_setuid(&mut c, 9999, false), Err(Error::PermissionDenied));
    }

    #[test]
    fn setresuid_partial() {
        let mut c = user_cred();
        do_setresuid(&mut c, UNCHANGED, 1000, UNCHANGED, true).unwrap();
        assert_eq!(c.euid, 1000);
    }

    #[test]
    fn setresgid_ok() {
        let mut c = user_cred();
        do_setresgid(&mut c, 2000, 2000, 2000, true).unwrap();
        assert_eq!(c.gid, 2000);
        assert_eq!(c.egid, 2000);
    }
}
