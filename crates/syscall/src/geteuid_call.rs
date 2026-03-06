// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `geteuid` syscall implementation.
//!
//! Returns the effective user ID of the calling process.
//!
//! POSIX Reference: susv5 functions/geteuid.html
//! POSIX.1-2024 — always succeeds, no errors defined.

use oncrix_lib::{Error, Result};

/// User ID type matching the POSIX `uid_t`.
pub type Uid = u32;

/// Sentinel value for an invalid or unset UID.
pub const UID_INVALID: Uid = u32::MAX;

/// Root user ID.
pub const ROOT_UID: Uid = 0;

/// User ID credentials stored in the process credential set.
#[derive(Debug, Clone, Copy, Default)]
pub struct UserCred {
    /// Real UID.
    pub ruid: Uid,
    /// Effective UID.
    pub euid: Uid,
    /// Saved set-UID.
    pub suid: Uid,
    /// Filesystem UID (Linux extension).
    pub fsuid: Uid,
}

impl UserCred {
    /// Create a credential set with all UIDs equal to `uid`.
    pub const fn new(uid: Uid) -> Self {
        Self {
            ruid: uid,
            euid: uid,
            suid: uid,
            fsuid: uid,
        }
    }

    /// Return the effective UID.
    pub fn effective(&self) -> Uid {
        self.euid
    }

    /// Return the real UID.
    pub fn real(&self) -> Uid {
        self.ruid
    }

    /// Return true if the process runs as root (euid == 0).
    pub fn is_root(&self) -> bool {
        self.euid == ROOT_UID
    }

    /// Return true if the effective UID differs from the real UID.
    pub fn is_setuid(&self) -> bool {
        self.euid != self.ruid
    }
}

/// Handle the `geteuid` syscall.
///
/// Returns the effective user ID. Per POSIX, this always succeeds.
///
/// Returns the effective UID as a non-negative integer.
pub fn sys_geteuid() -> Result<i64> {
    // Stub: real implementation reads current->cred->euid.
    Ok(0)
}

/// Handle the `getuid` syscall.
///
/// Returns the real user ID. Per POSIX, this always succeeds.
///
/// Returns the real UID as a non-negative integer.
pub fn sys_getuid() -> Result<i64> {
    // Stub: real implementation reads current->cred->uid.
    Ok(0)
}

/// Validate that a UID is within the valid system range.
pub fn validate_uid(uid: Uid) -> Result<()> {
    if uid == UID_INVALID {
        return Err(Error::InvalidArgument);
    }
    Ok(())
}

/// Check if the calling process has root privileges (effective UID == 0).
pub fn is_root_cred(cred: &UserCred) -> bool {
    cred.euid == ROOT_UID
}

/// Check whether a UID matches any of the process's UID slots.
pub fn is_process_uid(cred: &UserCred, uid: Uid) -> bool {
    cred.ruid == uid || cred.euid == uid || cred.suid == uid
}
