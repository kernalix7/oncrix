// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `getegid` syscall implementation.
//!
//! Returns the effective group ID of the calling process.
//!
//! POSIX Reference: susv5 functions/getegid.html
//! POSIX.1-2024 — always succeeds, no errors defined.

use oncrix_lib::{Error, Result};

/// Group ID type matching the POSIX `gid_t`.
pub type Gid = u32;

/// Sentinel value for an uninitialized or invalid GID.
pub const GID_INVALID: Gid = u32::MAX;

/// Group ID credentials stored in the process credential set.
#[derive(Debug, Clone, Copy, Default)]
pub struct GroupCred {
    /// Real GID.
    pub rgid: Gid,
    /// Effective GID.
    pub egid: Gid,
    /// Saved set-GID.
    pub sgid: Gid,
    /// Filesystem GID (Linux extension).
    pub fsgid: Gid,
}

impl GroupCred {
    /// Create a group credential set with all GIDs equal to `gid`.
    pub const fn new(gid: Gid) -> Self {
        Self {
            rgid: gid,
            egid: gid,
            sgid: gid,
            fsgid: gid,
        }
    }

    /// Return the effective GID.
    pub fn effective(&self) -> Gid {
        self.egid
    }

    /// Return the real GID.
    pub fn real(&self) -> Gid {
        self.rgid
    }

    /// Check whether the process runs with an elevated effective GID.
    pub fn is_elevated(&self) -> bool {
        self.egid != self.rgid
    }
}

/// Handle the `getegid` syscall.
///
/// Returns the effective group ID of the calling process. Per POSIX,
/// this call always succeeds.
///
/// Returns the effective GID as a non-negative integer.
pub fn sys_getegid() -> Result<i64> {
    // Stub: real implementation reads current->cred->egid.
    Ok(0)
}

/// Handle the `getgid` syscall.
///
/// Returns the real group ID of the calling process. Per POSIX, this
/// call always succeeds.
///
/// Returns the real GID as a non-negative integer.
pub fn sys_getgid() -> Result<i64> {
    // Stub: real implementation reads current->cred->gid.
    Ok(0)
}

/// Validate that a GID is within the valid range for this system.
///
/// GIDs from 0 to GID_MAX (65534 on Linux) are valid. GID_INVALID is not.
pub fn validate_gid(gid: Gid) -> Result<()> {
    if gid == GID_INVALID {
        return Err(Error::InvalidArgument);
    }
    Ok(())
}

/// Check if the given GID matches the process's effective GID.
pub fn is_effective_gid(cred: &GroupCred, gid: Gid) -> bool {
    cred.egid == gid
}

/// Check if the given GID is any of the process's GIDs (real, effective, saved).
pub fn is_process_gid(cred: &GroupCred, gid: Gid) -> bool {
    cred.rgid == gid || cred.egid == gid || cred.sgid == gid
}
