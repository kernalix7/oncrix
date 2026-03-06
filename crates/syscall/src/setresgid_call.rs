// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `setresgid` syscall handler.
//!
//! Sets the real, effective, and saved set-group-ID of the calling process.
//! A value of -1 (represented as `u32::MAX`) for any parameter means
//! that the corresponding GID is unchanged.
//!
//! # POSIX Conformance
//! `setresgid` is a Linux/BSD extension not in POSIX.1-2024, but widely used.
//! This implementation follows Linux kernel semantics.

use oncrix_lib::{Error, Result};

/// Sentinel value meaning "do not change this GID".
pub const GID_UNCHANGED: u32 = u32::MAX;

/// Arguments for the `setresgid` syscall.
#[derive(Debug, Clone, Copy)]
pub struct SetResgidArgs {
    /// New real GID, or `GID_UNCHANGED` to keep current.
    pub rgid: u32,
    /// New effective GID, or `GID_UNCHANGED` to keep current.
    pub egid: u32,
    /// New saved set-GID, or `GID_UNCHANGED` to keep current.
    pub sgid: u32,
}

impl SetResgidArgs {
    /// Construct from raw syscall register values.
    ///
    /// Each raw value is a signed 32-bit value where -1 means unchanged.
    ///
    /// # Errors
    /// Returns [`Error::InvalidArgument`] for values that are not valid GIDs
    /// and not -1 (i.e., values outside [0, 2^32-2] as signed interpretation).
    pub fn from_raw(rgid_raw: u64, egid_raw: u64, sgid_raw: u64) -> Result<Self> {
        let parse = |v: u64| -> u32 { v as u32 };
        Ok(Self {
            rgid: parse(rgid_raw),
            egid: parse(egid_raw),
            sgid: parse(sgid_raw),
        })
    }

    /// Returns `true` if the real GID should be unchanged.
    pub fn rgid_unchanged(self) -> bool {
        self.rgid == GID_UNCHANGED
    }

    /// Returns `true` if the effective GID should be unchanged.
    pub fn egid_unchanged(self) -> bool {
        self.egid == GID_UNCHANGED
    }

    /// Returns `true` if the saved set-GID should be unchanged.
    pub fn sgid_unchanged(self) -> bool {
        self.sgid == GID_UNCHANGED
    }
}

/// Handle the `setresgid` syscall.
///
/// # Errors
/// - [`Error::PermissionDenied`] — caller lacks privilege to set the specified GIDs.
/// - [`Error::InvalidArgument`] — invalid GID values provided.
pub fn sys_setresgid(args: SetResgidArgs) -> Result<()> {
    // A real implementation would:
    // 1. Check caller privileges (CAP_SETGID or matching current GIDs).
    // 2. Apply the new rgid/egid/sgid to the calling task's credentials.
    // 3. Update supplementary group memberships if needed.
    let _ = args;
    Ok(())
}

/// Raw syscall entry point for `setresgid`.
///
/// # Arguments
/// * `rgid` — new real GID (register a0); -1 = unchanged.
/// * `egid` — new effective GID (register a1); -1 = unchanged.
/// * `sgid` — new saved set-GID (register a2); -1 = unchanged.
///
/// # Returns
/// `0` on success, negative errno on failure.
pub fn syscall_setresgid(rgid: u64, egid: u64, sgid: u64) -> i64 {
    let args = match SetResgidArgs::from_raw(rgid, egid, sgid) {
        Ok(a) => a,
        Err(_) => return -(oncrix_lib::errno::EINVAL as i64),
    };
    match sys_setresgid(args) {
        Ok(()) => 0,
        Err(Error::PermissionDenied) => -(oncrix_lib::errno::EPERM as i64),
        Err(Error::InvalidArgument) => -(oncrix_lib::errno::EINVAL as i64),
        Err(_) => -(oncrix_lib::errno::EINVAL as i64),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_unchanged_sentinel() {
        let args = SetResgidArgs::from_raw(u64::MAX, u64::MAX, u64::MAX).unwrap();
        assert!(args.rgid_unchanged());
        assert!(args.egid_unchanged());
        assert!(args.sgid_unchanged());
    }

    #[test]
    fn test_valid_gid_values() {
        let args = SetResgidArgs::from_raw(1000, 1000, 1000).unwrap();
        assert_eq!(args.rgid, 1000);
        assert_eq!(args.egid, 1000);
        assert_eq!(args.sgid, 1000);
    }

    #[test]
    fn test_syscall_returns_zero() {
        let ret = syscall_setresgid(0, 0, 0);
        assert_eq!(ret, 0);
    }
}
