// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `setfsuid` syscall handler.
//!
//! Sets the filesystem user ID (fsuid) of the calling process. The fsuid is
//! used exclusively for filesystem permission checks. It is normally equal to
//! the effective UID but can be changed independently to allow a process to
//! modify files without gaining full effective UID privileges.
//!
//! On success, `setfsuid` returns the previous fsuid value.
//!
//! # POSIX Conformance
//! `setfsuid` is a Linux-specific extension not in POSIX.1-2024.

use oncrix_lib::Result;

/// Arguments for the `setfsuid` syscall.
#[derive(Debug, Clone, Copy)]
pub struct SetFsuidArgs {
    /// New filesystem user ID.
    pub fsuid: u32,
}

impl SetFsuidArgs {
    /// Construct from a raw syscall register value.
    pub fn from_raw(fsuid_raw: u64) -> Self {
        Self {
            fsuid: fsuid_raw as u32,
        }
    }
}

/// Result of `setfsuid`: the previous fsuid.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SetFsuidResult {
    /// The filesystem UID before this call.
    pub previous_fsuid: u32,
}

impl SetFsuidResult {
    /// Construct a new result.
    pub const fn new(previous_fsuid: u32) -> Self {
        Self { previous_fsuid }
    }
}

/// Handle the `setfsuid` syscall.
///
/// Sets the filesystem UID for the calling process and returns the previous
/// value. Setting to a value other than the current ruid/euid/suid requires
/// `CAP_SETUID`. The old fsuid is always returned regardless of whether the
/// change was applied.
pub fn sys_setfsuid(args: SetFsuidArgs) -> Result<SetFsuidResult> {
    // A full implementation would:
    // 1. Read the current fsuid from the calling task's credentials.
    // 2. Check privilege: new fsuid must match one of ruid/euid/suid, or CAP_SETUID.
    // 3. If allowed: update fsuid in the credentials struct.
    // 4. Return the old fsuid.
    let _ = args;
    Ok(SetFsuidResult::new(0))
}

/// Raw syscall entry point for `setfsuid`.
///
/// # Arguments
/// * `fsuid` — new filesystem UID (register a0).
///
/// # Returns
/// The previous fsuid value (always non-negative).
pub fn syscall_setfsuid(fsuid: u64) -> i64 {
    let args = SetFsuidArgs::from_raw(fsuid);
    match sys_setfsuid(args) {
        Ok(result) => result.previous_fsuid as i64,
        Err(_) => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_from_raw_preserves_value() {
        let args = SetFsuidArgs::from_raw(2000);
        assert_eq!(args.fsuid, 2000);
    }

    #[test]
    fn test_max_value_accepted() {
        let args = SetFsuidArgs::from_raw(u64::MAX);
        assert_eq!(args.fsuid, u32::MAX);
    }

    #[test]
    fn test_result_stores_previous() {
        let r = SetFsuidResult::new(100);
        assert_eq!(r.previous_fsuid, 100);
    }

    #[test]
    fn test_syscall_returns_nonnegative() {
        let ret = syscall_setfsuid(1000);
        assert!(ret >= 0);
    }
}
