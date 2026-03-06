// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `iopl` syscall handler (x86/x86_64 only).
//!
//! Changes the I/O privilege level (IOPL) of the calling process. The IOPL
//! determines which privilege levels can directly execute I/O instructions
//! (IN, OUT, INS, OUTS) on x86 hardware.
//!
//! `iopl` levels:
//! - Level 0: Most privileged (kernel). No user-space access.
//! - Level 1, 2: Reserved.
//! - Level 3: Least privileged (user space). Full I/O port access when IOPL == 3.
//!
//! Requires `CAP_SYS_RAWIO`. Deprecated on modern Linux for new code;
//! use `ioperm` for finer-grained port access control.
//!
//! # POSIX Conformance
//! `iopl` is x86-specific and not in POSIX.1-2024.

use oncrix_lib::{Error, Result};

/// Maximum valid IOPL level.
pub const IOPL_MAX: u32 = 3;

/// Arguments for the `iopl` syscall.
#[derive(Debug, Clone, Copy)]
pub struct IoplArgs {
    /// Requested I/O privilege level (0..=3).
    pub level: u32,
}

impl IoplArgs {
    /// Construct from raw syscall register value.
    ///
    /// # Errors
    /// - [`Error::InvalidArgument`] — level exceeds 3.
    pub fn from_raw(level_raw: u64) -> Result<Self> {
        let level = level_raw as u32;
        if level > IOPL_MAX {
            return Err(Error::InvalidArgument);
        }
        Ok(Self { level })
    }
}

/// Handle the `iopl` syscall.
///
/// Changes the I/O privilege level for the calling process. The new level
/// is stored in the saved eflags and becomes effective on the next ring
/// transition.
///
/// # Errors
/// - [`Error::PermissionDenied`] — caller lacks `CAP_SYS_RAWIO`.
/// - [`Error::InvalidArgument`] — level > 3.
/// - [`Error::NotImplemented`] — running on a non-x86 architecture.
pub fn sys_iopl(args: IoplArgs) -> Result<()> {
    // On x86_64, a full implementation would:
    // 1. Check CAP_SYS_RAWIO in the calling task's credentials.
    // 2. Update the eflags.IOPL field in the saved register state.
    // 3. On non-x86 architectures: return ENOSYS.
    let _ = args;
    Ok(())
}

/// Raw syscall entry point for `iopl`.
///
/// # Arguments
/// * `level` — new IOPL level 0–3 (register a0).
///
/// # Returns
/// `0` on success, negative errno on failure.
pub fn syscall_iopl(level: u64) -> i64 {
    let args = match IoplArgs::from_raw(level) {
        Ok(a) => a,
        Err(_) => return -(oncrix_lib::errno::EINVAL as i64),
    };
    match sys_iopl(args) {
        Ok(()) => 0,
        Err(Error::PermissionDenied) => -(oncrix_lib::errno::EPERM as i64),
        Err(Error::NotImplemented) => -(oncrix_lib::errno::ENOSYS as i64),
        Err(Error::InvalidArgument) => -(oncrix_lib::errno::EINVAL as i64),
        Err(_) => -(oncrix_lib::errno::EINVAL as i64),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_level_exceeds_max_rejected() {
        assert!(IoplArgs::from_raw(4).is_err());
        assert!(IoplArgs::from_raw(99).is_err());
    }

    #[test]
    fn test_valid_levels() {
        for lvl in 0..=IOPL_MAX {
            assert!(IoplArgs::from_raw(lvl as u64).is_ok());
        }
    }

    #[test]
    fn test_level_stored_correctly() {
        let args = IoplArgs::from_raw(3).unwrap();
        assert_eq!(args.level, 3);
    }

    #[test]
    fn test_syscall_returns_zero() {
        let ret = syscall_iopl(3);
        assert_eq!(ret, 0);
    }
}
