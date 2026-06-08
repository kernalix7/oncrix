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
        // SECURITY: validate each raw register BEFORE narrowing u64 -> u32.
        // A bare `v as u32` silently truncates an out-of-range argument down
        // into a valid (often 0 == root group) GID, which would bypass the
        // intended EINVAL and could grant an unintended group. Accept only the
        // -1 / GID_UNCHANGED sentinel (u64::MAX) or a value that fits in u32;
        // reject everything else as InvalidArgument (fail closed).
        let parse = |v: u64| -> Result<u32> {
            if v == u64::MAX {
                // -1 sign-extended: the "unchanged" sentinel.
                Ok(GID_UNCHANGED)
            } else if v <= u32::MAX as u64 {
                Ok(v as u32)
            } else {
                Err(Error::InvalidArgument)
            }
        };
        Ok(Self {
            rgid: parse(rgid_raw)?,
            egid: parse(egid_raw)?,
            sgid: parse(sgid_raw)?,
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
    // SECURITY: fail closed. This is an authorization-bearing syscall: a real
    // implementation MUST, for each of rgid/egid/sgid that is not
    // GID_UNCHANGED, require CAP_SETGID or that the new GID already be one of
    // the caller's {real, effective, saved} GIDs (else PermissionDenied), and
    // only then commit. Until the credential set and capability check are
    // wired in, returning Ok(()) here would promise success without enforcing
    // that gate — a privilege-escalation contract once a real mutation lands.
    // Return NotImplemented to match the fail-closed siblings sys_setgid /
    // sys_setgroups (and sys_setresgid in setresuid_call.rs). Never leave an
    // always-Ok authorization stub.
    // SECURITY INVARIANT: when this gate is implemented, the dispatcher must
    // pass the caller credentials + effective capability set so the
    // CAP_SETGID / {real,eff,saved}-membership check can be enforced before
    // any credential mutation.
    let _ = args;
    Err(Error::NotImplemented)
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
    fn test_handler_fails_closed() {
        // SECURITY: an authorization-bearing syscall must not report success
        // without enforcing its gate. The handler fails closed until the
        // CAP_SETGID / {real,eff,saved}-membership check is wired in.
        assert_eq!(
            sys_setresgid(SetResgidArgs::from_raw(0, 0, 0).unwrap()).unwrap_err(),
            Error::NotImplemented
        );
    }

    #[test]
    fn test_syscall_entry_does_not_succeed() {
        // The raw entry maps NotImplemented to a negative errno, never 0.
        let ret = syscall_setresgid(0, 0, 0);
        assert!(ret < 0);
    }

    #[test]
    fn test_out_of_range_raw_rejected() {
        // SECURITY: a value above u32::MAX (but not the -1 sentinel) must be
        // rejected, not silently truncated into a valid GID.
        let too_big = (u32::MAX as u64) + 1;
        assert_eq!(
            SetResgidArgs::from_raw(too_big, 0, 0).unwrap_err(),
            Error::InvalidArgument
        );
        assert_eq!(
            SetResgidArgs::from_raw(0, too_big, 0).unwrap_err(),
            Error::InvalidArgument
        );
        assert_eq!(
            SetResgidArgs::from_raw(0, 0, too_big).unwrap_err(),
            Error::InvalidArgument
        );
        // The -1 / GID_UNCHANGED sentinel must still be accepted.
        assert!(
            SetResgidArgs::from_raw(u64::MAX, 0, 0)
                .unwrap()
                .rgid_unchanged()
        );
    }
}
