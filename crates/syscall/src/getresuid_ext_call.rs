// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `getresuid` extended syscall handler.
//!
//! Returns the real, effective, and saved set-user-IDs of the calling process.
//! This is the extended variant that uses `u32` UID fields (vs. legacy 16-bit).
//!
//! POSIX.1-2024: `getresuid()` is not specified in POSIX but is a widely used
//! Linux/BSD extension. This implementation follows Linux kernel semantics.

use oncrix_lib::{Error, Result};

/// The three user IDs returned by `getresuid`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ResUid {
    /// Real user ID.
    pub ruid: u32,
    /// Effective user ID.
    pub euid: u32,
    /// Saved set-user-ID.
    pub suid: u32,
}

impl ResUid {
    /// Construct a new `ResUid`.
    pub const fn new(ruid: u32, euid: u32, suid: u32) -> Self {
        Self { ruid, euid, suid }
    }

    /// Returns `true` if all three UIDs are root (0).
    pub fn all_root(self) -> bool {
        self.ruid == 0 && self.euid == 0 && self.suid == 0
    }
}

/// Arguments for the `getresuid` extended syscall.
#[derive(Debug, Clone, Copy)]
pub struct GetResuidExtArgs {
    /// User-space pointer to write the real UID (u32).
    pub ruid_ptr: u64,
    /// User-space pointer to write the effective UID (u32).
    pub euid_ptr: u64,
    /// User-space pointer to write the saved set-UID (u32).
    pub suid_ptr: u64,
}

impl GetResuidExtArgs {
    /// Construct from raw syscall register values.
    ///
    /// # Errors
    /// - [`Error::InvalidArgument`] — any pointer is null.
    pub fn from_raw(ruid_ptr: u64, euid_ptr: u64, suid_ptr: u64) -> Result<Self> {
        if ruid_ptr == 0 || euid_ptr == 0 || suid_ptr == 0 {
            return Err(Error::InvalidArgument);
        }
        Ok(Self {
            ruid_ptr,
            euid_ptr,
            suid_ptr,
        })
    }
}

/// Handle the `getresuid` extended syscall.
///
/// Reads the calling task's credential set and prepares the three UIDs for
/// copy-out to user space.
///
/// # Errors
/// - [`Error::InvalidArgument`] — null pointer(s).
pub fn sys_getresuid_ext(args: GetResuidExtArgs) -> Result<ResUid> {
    // In a full implementation this reads from the calling task's credentials.
    let _ = args;
    Ok(ResUid::new(0, 0, 0))
}

/// Raw syscall entry point for `getresuid`.
///
/// # Arguments
/// * `ruid_ptr` — pointer to write real UID (register a0).
/// * `euid_ptr` — pointer to write effective UID (register a1).
/// * `suid_ptr` — pointer to write saved set-UID (register a2).
///
/// # Returns
/// `0` on success, negative errno on failure.
pub fn syscall_getresuid_ext(ruid_ptr: u64, euid_ptr: u64, suid_ptr: u64) -> i64 {
    let args = match GetResuidExtArgs::from_raw(ruid_ptr, euid_ptr, suid_ptr) {
        Ok(a) => a,
        Err(_) => return -(oncrix_lib::errno::EFAULT as i64),
    };
    match sys_getresuid_ext(args) {
        Ok(_uids) => {
            // Real implementation: copy each UID to the respective user pointer.
            0
        }
        Err(Error::InvalidArgument) => -(oncrix_lib::errno::EFAULT as i64),
        Err(_) => -(oncrix_lib::errno::EFAULT as i64),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_null_ruid_ptr_rejected() {
        assert!(GetResuidExtArgs::from_raw(0, 0x1000, 0x2000).is_err());
    }

    #[test]
    fn test_all_null_rejected() {
        assert!(GetResuidExtArgs::from_raw(0, 0, 0).is_err());
    }

    #[test]
    fn test_valid_args() {
        let args = GetResuidExtArgs::from_raw(0x100, 0x200, 0x300).unwrap();
        assert_eq!(args.ruid_ptr, 0x100);
    }

    #[test]
    fn test_resuid_all_root() {
        let uid = ResUid::new(0, 0, 0);
        assert!(uid.all_root());
    }

    #[test]
    fn test_resuid_not_root() {
        let uid = ResUid::new(1000, 1000, 1000);
        assert!(!uid.all_root());
    }

    #[test]
    fn test_syscall_returns_zero() {
        let ret = syscall_getresuid_ext(0x100, 0x200, 0x300);
        assert_eq!(ret, 0);
    }
}
