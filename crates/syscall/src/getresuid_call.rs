// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `getresuid` and `getresgid` syscall implementations.
//!
//! Returns the real, effective, and saved-set user (or group) IDs of the
//! calling process. These are Linux extensions not in strict POSIX but
//! present in most UNIX systems.
//!
//! POSIX Reference: getuid/getgid covered by susv5; getresuid is Linux-specific.

use oncrix_lib::{Error, Result};

/// User ID type matching POSIX `uid_t`.
pub type Uid = u32;
/// Group ID type matching POSIX `gid_t`.
pub type Gid = u32;

/// Triple of real, effective, and saved-set UIDs.
#[derive(Debug, Clone, Copy, Default)]
pub struct ResUid {
    /// Real UID.
    pub ruid: Uid,
    /// Effective UID.
    pub euid: Uid,
    /// Saved set-UID.
    pub suid: Uid,
}

impl ResUid {
    /// Create a ResUid with all three IDs equal.
    pub const fn uniform(uid: Uid) -> Self {
        Self {
            ruid: uid,
            euid: uid,
            suid: uid,
        }
    }

    /// Check if `uid` matches any of the three values.
    pub fn contains(&self, uid: Uid) -> bool {
        self.ruid == uid || self.euid == uid || self.suid == uid
    }
}

/// Triple of real, effective, and saved-set GIDs.
#[derive(Debug, Clone, Copy, Default)]
pub struct ResGid {
    /// Real GID.
    pub rgid: Gid,
    /// Effective GID.
    pub egid: Gid,
    /// Saved set-GID.
    pub sgid: Gid,
}

impl ResGid {
    /// Create a ResGid with all three IDs equal.
    pub const fn uniform(gid: Gid) -> Self {
        Self {
            rgid: gid,
            egid: gid,
            sgid: gid,
        }
    }

    /// Check if `gid` matches any of the three values.
    pub fn contains(&self, gid: Gid) -> bool {
        self.rgid == gid || self.egid == gid || self.sgid == gid
    }
}

/// Arguments for `getresuid`.
#[derive(Debug)]
pub struct GetresuidArgs {
    /// Pointer to user-space `uid_t` to receive the real UID.
    pub ruid_ptr: usize,
    /// Pointer to user-space `uid_t` to receive the effective UID.
    pub euid_ptr: usize,
    /// Pointer to user-space `uid_t` to receive the saved set-UID.
    pub suid_ptr: usize,
}

/// Arguments for `getresgid`.
#[derive(Debug)]
pub struct GetresgidArgs {
    /// Pointer to user-space `gid_t` to receive the real GID.
    pub rgid_ptr: usize,
    /// Pointer to user-space `gid_t` to receive the effective GID.
    pub egid_ptr: usize,
    /// Pointer to user-space `gid_t` to receive the saved set-GID.
    pub sgid_ptr: usize,
}

/// Validate getresuid / getresgid output pointer arguments.
pub fn validate_res_id_args(rptr: usize, eptr: usize, sptr: usize) -> Result<()> {
    if rptr == 0 || eptr == 0 || sptr == 0 {
        return Err(Error::InvalidArgument);
    }
    Ok(())
}

/// Handle the `getresuid` syscall.
///
/// Writes the real, effective, and saved-set UIDs to the three user-space
/// pointers. Per Linux semantics this always succeeds if the pointers are valid.
///
/// Returns 0 on success, or an error.
pub fn sys_getresuid(args: &GetresuidArgs) -> Result<i64> {
    validate_res_id_args(args.ruid_ptr, args.euid_ptr, args.suid_ptr)?;
    // Stub: real implementation reads current->cred and copy_to_user each value.
    Err(Error::NotImplemented)
}

/// Handle the `getresgid` syscall.
///
/// Writes the real, effective, and saved-set GIDs to the three user-space
/// pointers.
///
/// Returns 0 on success, or an error.
pub fn sys_getresgid(args: &GetresgidArgs) -> Result<i64> {
    validate_res_id_args(args.rgid_ptr, args.egid_ptr, args.sgid_ptr)?;
    // Stub: real implementation reads current->cred and copy_to_user each value.
    Err(Error::NotImplemented)
}

/// Check whether any of the three UIDs is the effective UID of the process.
pub fn any_is_euid(ids: &ResUid, euid: Uid) -> bool {
    ids.euid == euid
}

/// Check whether any of the three GIDs is the effective GID of the process.
pub fn any_is_egid(ids: &ResGid, egid: Gid) -> bool {
    ids.egid == egid
}
