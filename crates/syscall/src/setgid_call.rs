// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `setgid` syscall implementation.
//!
//! Sets the effective group ID of the calling process. If the process
//! has appropriate privileges, also sets the real and saved-set-GID.
//!
//! POSIX Reference: susv5 functions/setgid.html
//! POSIX.1-2024 — EPERM if unprivileged and gid is not one of the
//! real, effective, or saved-set-GID.

use oncrix_lib::{Error, Result};

/// Group ID type matching POSIX `gid_t`.
pub type Gid = u32;

/// Sentinel for an invalid GID.
pub const GID_INVALID: Gid = u32::MAX;

/// Group credential set for a process.
#[derive(Debug, Clone, Copy, Default)]
pub struct GroupCred {
    /// Real GID.
    pub rgid: Gid,
    /// Effective GID.
    pub egid: Gid,
    /// Saved set-GID.
    pub sgid: Gid,
    /// Filesystem GID.
    pub fsgid: Gid,
}

impl GroupCred {
    /// Create a credential set with all GIDs set to `gid`.
    pub const fn new(gid: Gid) -> Self {
        Self {
            rgid: gid,
            egid: gid,
            sgid: gid,
            fsgid: gid,
        }
    }

    /// Check if `gid` is one of the real, effective, or saved-set GID.
    pub fn contains(&self, gid: Gid) -> bool {
        self.rgid == gid || self.egid == gid || self.sgid == gid
    }
}

/// Arguments for the `setgid` syscall.
#[derive(Debug, Clone, Copy)]
pub struct SetgidArgs {
    /// The new GID to set.
    pub gid: Gid,
}

/// Validate `setgid` arguments.
pub fn validate_setgid_args(args: &SetgidArgs) -> Result<()> {
    if args.gid == GID_INVALID {
        return Err(Error::InvalidArgument);
    }
    Ok(())
}

/// Apply `setgid` semantics for a privileged process (CAP_SETGID).
///
/// Sets rgid, egid, sgid, and fsgid all to `gid`.
pub fn apply_setgid_privileged(cred: &mut GroupCred, gid: Gid) {
    cred.rgid = gid;
    cred.egid = gid;
    cred.sgid = gid;
    cred.fsgid = gid;
}

/// Apply `setgid` semantics for an unprivileged process.
///
/// Only allowed if `gid` is one of rgid, egid, or sgid. Sets only egid
/// and fsgid.
///
/// Returns `Err(PermissionDenied)` if `gid` is not in the credential set.
pub fn apply_setgid_unprivileged(cred: &mut GroupCred, gid: Gid) -> Result<()> {
    if !cred.contains(gid) {
        return Err(Error::PermissionDenied);
    }
    cred.egid = gid;
    cred.fsgid = gid;
    Ok(())
}

/// Handle the `setgid` syscall.
///
/// With CAP_SETGID: sets rgid, egid, sgid, fsgid to `gid`.
/// Without privilege: sets egid and fsgid if `gid` is among the
/// existing real/effective/saved-set GIDs.
///
/// Returns 0 on success, or an error.
pub fn sys_setgid(args: &SetgidArgs) -> Result<i64> {
    validate_setgid_args(args)?;
    // Stub: real implementation would:
    // 1. Check current->cred for CAP_SETGID.
    // 2. If privileged: apply_setgid_privileged.
    // 3. Else: apply_setgid_unprivileged.
    // 4. Commit new credentials.
    // 5. Return 0.
    Err(Error::NotImplemented)
}

/// Check if the calling process has CAP_SETGID.
pub fn has_cap_setgid() -> bool {
    // Stub: real check queries effective capability set.
    false
}
