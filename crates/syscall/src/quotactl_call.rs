// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `quotactl(2)` syscall dispatch layer.
//!
//! This module is the thin syscall entry point for `quotactl(2)`.  It
//! validates the `cmd` encoding and argument pointers, then delegates to the
//! per-command handlers in [`crate::quotactl`].
//!
//! # Syscall signature
//!
//! ```text
//! int quotactl(int cmd, const char *special, int id, caddr_t addr);
//! ```
//!
//! The `cmd` argument encodes both the quota type and the command in a
//! single integer using the `QCMD(cmd, type)` macro:
//!
//! ```text
//! cmd = (base_cmd << 8) | quota_type
//! ```
//!
//! # POSIX / Linux notes
//!
//! `quotactl` is a Linux extension.  The implementation follows the Linux
//! ABI documented in `quotactl(2)`.
//!
//! # References
//!
//! - Linux: `fs/quota/quota.c`
//! - `include/uapi/linux/quota.h`
//! - `quotactl(2)` man page

use oncrix_lib::{Error, Result};

// Re-export the constants from the detailed module.
pub use crate::quotactl::{
    GRPQUOTA, PRJQUOTA, Q_GETFMT, Q_GETINFO, Q_GETQUOTA, Q_QUOTAOFF, Q_QUOTAON, Q_SETINFO,
    Q_SETQUOTA, Q_SYNC, USRQUOTA,
};

// ---------------------------------------------------------------------------
// QCMD encoding / decoding
// ---------------------------------------------------------------------------

/// Encode a quota command and quota type into a single `cmd` integer.
///
/// `QCMD(cmd, type)` = `(cmd << 8) | (type & 0xff)`.
pub const fn qcmd(cmd: i32, quota_type: i32) -> i32 {
    (cmd << 8) | (quota_type & 0xFF)
}

/// Extract the base command from an encoded `cmd` value.
pub const fn qcmd_base(cmd: i32) -> i32 {
    (cmd >> 8) & 0xFF
}

/// Extract the quota type from an encoded `cmd` value.
pub const fn qcmd_type(cmd: i32) -> i32 {
    cmd & 0xFF
}

// ---------------------------------------------------------------------------
// Command validity
// ---------------------------------------------------------------------------

/// Returns `true` if `base` is a recognised quota base command.
pub fn is_valid_cmd(base: i32) -> bool {
    matches!(
        base,
        Q_QUOTAON
            | Q_QUOTAOFF
            | Q_GETFMT
            | Q_GETINFO
            | Q_SETINFO
            | Q_GETQUOTA
            | Q_SETQUOTA
            | Q_SYNC
    )
}

/// Returns `true` if `quota_type` is a recognised quota type.
pub fn is_valid_quota_type(quota_type: i32) -> bool {
    matches!(quota_type, USRQUOTA | GRPQUOTA | PRJQUOTA)
}

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

/// Handle the `quotactl(2)` syscall.
///
/// `cmd` encodes the base command and quota type as `(base << 8) | type`.
/// `special_ptr` is a pointer to a null-terminated filesystem device path.
/// `id` is the UID/GID/project-ID for per-ID commands; ignored for others.
/// `addr_ptr` is a pointer to the command-specific data structure.
///
/// Returns 0 on success.
///
/// # Errors
///
/// - [`Error::InvalidArgument`] — unknown command, invalid quota type,
///   `special_ptr` is null for filesystem commands, or `addr_ptr` is null
///   when required.
/// - [`Error::PermissionDenied`] — caller lacks `CAP_SYS_ADMIN`.
/// - [`Error::NotFound`] — the specified filesystem is not quota-enabled or
///   the requested ID has no quota entry.
/// - [`Error::NotImplemented`] — command is valid but not yet implemented.
pub fn sys_quotactl(cmd: i32, special_ptr: u64, id: u32, addr_ptr: u64) -> Result<i64> {
    let base = qcmd_base(cmd);
    let quota_type = qcmd_type(cmd);

    if !is_valid_cmd(base) {
        return Err(Error::InvalidArgument);
    }

    // Q_SYNC is filesystem-global and can operate with a null special pointer
    // (means "sync all mounted filesystems").  All other commands require it.
    if base != Q_SYNC && special_ptr == 0 {
        return Err(Error::InvalidArgument);
    }

    // Validate quota type for commands that are type-specific.
    if base != Q_SYNC && !is_valid_quota_type(quota_type) {
        return Err(Error::InvalidArgument);
    }

    // Commands that require addr_ptr.
    let addr_required = matches!(
        base,
        Q_QUOTAON | Q_GETQUOTA | Q_SETQUOTA | Q_GETINFO | Q_SETINFO | Q_GETFMT
    );
    if addr_required && addr_ptr == 0 {
        return Err(Error::InvalidArgument);
    }

    // TODO: resolve the device path from special_ptr, look up the QuotaState,
    // and call crate::quotactl::do_quotactl with the appropriate arguments.
    let _ = (base, quota_type, special_ptr, id, addr_ptr);
    Err(Error::NotImplemented)
}

/// Entry point called from the syscall dispatcher.
pub fn do_quotactl_call(cmd: i32, special_ptr: u64, id: u32, addr_ptr: u64) -> Result<i64> {
    sys_quotactl(cmd, special_ptr, id, addr_ptr)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn qcmd_encode_decode() {
        let encoded = qcmd(Q_QUOTAON, USRQUOTA);
        assert_eq!(qcmd_base(encoded), Q_QUOTAON);
        assert_eq!(qcmd_type(encoded), USRQUOTA);
    }

    #[test]
    fn unknown_cmd_rejected() {
        let cmd = qcmd(0xFF, USRQUOTA);
        assert_eq!(
            sys_quotactl(cmd, 0x1000, 0, 0x1000).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn null_special_for_non_sync_rejected() {
        let cmd = qcmd(Q_QUOTAON, USRQUOTA);
        assert_eq!(
            sys_quotactl(cmd, 0, 0, 0x1000).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn invalid_quota_type_rejected() {
        let cmd = qcmd(Q_QUOTAON, 99);
        assert_eq!(
            sys_quotactl(cmd, 0x1000, 0, 0x1000).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn quotaon_null_addr_rejected() {
        let cmd = qcmd(Q_QUOTAON, USRQUOTA);
        assert_eq!(
            sys_quotactl(cmd, 0x1000, 0, 0).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn sync_null_special_ok() {
        // Q_SYNC with null special means "sync all" — should not be rejected
        // at validation; it will reach the stub and return NotImplemented.
        let cmd = qcmd(Q_SYNC, USRQUOTA);
        let r = sys_quotactl(cmd, 0, 0, 0);
        assert_ne!(r.unwrap_err(), Error::InvalidArgument);
    }

    #[test]
    fn is_valid_cmd_check() {
        assert!(is_valid_cmd(Q_QUOTAON));
        assert!(is_valid_cmd(Q_SYNC));
        assert!(!is_valid_cmd(0xFF));
    }

    #[test]
    fn is_valid_quota_type_check() {
        assert!(is_valid_quota_type(USRQUOTA));
        assert!(is_valid_quota_type(GRPQUOTA));
        assert!(is_valid_quota_type(PRJQUOTA));
        assert!(!is_valid_quota_type(99));
    }
}
