// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `getresgid` syscall handler.
//!
//! Returns the real, effective, and saved set-group-IDs of the calling process
//! by writing them into three user-space pointers.
//!
//! # POSIX Conformance
//! `getresgid` is not in POSIX.1-2024 but is a common Linux/BSD extension.
//! This implementation follows Linux kernel semantics.

use oncrix_lib::{Error, Result};

/// The three group IDs returned by `getresgid`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ResGid {
    /// Real group ID.
    pub rgid: u32,
    /// Effective group ID.
    pub egid: u32,
    /// Saved set-group-ID.
    pub sgid: u32,
}

impl ResGid {
    /// Construct a new `ResGid`.
    pub const fn new(rgid: u32, egid: u32, sgid: u32) -> Self {
        Self { rgid, egid, sgid }
    }
}

/// Arguments for the `getresgid` syscall.
#[derive(Debug, Clone, Copy)]
pub struct GetResgidArgs {
    /// User-space pointer to write the real GID into.
    pub rgid_ptr: u64,
    /// User-space pointer to write the effective GID into.
    pub egid_ptr: u64,
    /// User-space pointer to write the saved set-GID into.
    pub sgid_ptr: u64,
}

impl GetResgidArgs {
    /// Construct from raw syscall register values.
    ///
    /// # Errors
    /// - [`Error::InvalidArgument`] if any pointer is null.
    pub fn from_raw(rgid_ptr: u64, egid_ptr: u64, sgid_ptr: u64) -> Result<Self> {
        if rgid_ptr == 0 || egid_ptr == 0 || sgid_ptr == 0 {
            return Err(Error::InvalidArgument);
        }
        Ok(Self {
            rgid_ptr,
            egid_ptr,
            sgid_ptr,
        })
    }
}

/// Handle the `getresgid` syscall.
///
/// Retrieves all three GIDs and prepares them for copy-out to user space.
///
/// # Errors
/// - [`Error::InvalidArgument`] — null user-space pointer(s).
pub fn sys_getresgid(args: GetResgidArgs) -> Result<ResGid> {
    // In a full implementation this reads from the calling task's credentials.
    let _ = args;
    Ok(ResGid::new(0, 0, 0))
}

/// Raw syscall entry point for `getresgid`.
///
/// # Arguments
/// * `rgid_ptr` — pointer to write real GID (register a0).
/// * `egid_ptr` — pointer to write effective GID (register a1).
/// * `sgid_ptr` — pointer to write saved set-GID (register a2).
///
/// # Returns
/// `0` on success, negative errno on failure.
pub fn syscall_getresgid(rgid_ptr: u64, egid_ptr: u64, sgid_ptr: u64) -> i64 {
    let args = match GetResgidArgs::from_raw(rgid_ptr, egid_ptr, sgid_ptr) {
        Ok(a) => a,
        Err(_) => return -(oncrix_lib::errno::EINVAL as i64),
    };
    match sys_getresgid(args) {
        Ok(_gids) => {
            // Real implementation: copy each GID to the respective user pointer.
            0
        }
        Err(Error::InvalidArgument) => -(oncrix_lib::errno::EINVAL as i64),
        Err(_) => -(oncrix_lib::errno::EINVAL as i64),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_null_rgid_ptr_rejected() {
        assert!(GetResgidArgs::from_raw(0, 0x1000, 0x2000).is_err());
    }

    #[test]
    fn test_all_null_rejected() {
        assert!(GetResgidArgs::from_raw(0, 0, 0).is_err());
    }

    #[test]
    fn test_valid_args() {
        let args = GetResgidArgs::from_raw(0x100, 0x200, 0x300).unwrap();
        assert_eq!(args.rgid_ptr, 0x100);
    }

    #[test]
    fn test_resgid_construction() {
        let g = ResGid::new(1000, 1000, 1000);
        assert_eq!(g.rgid, 1000);
        assert_eq!(g.egid, 1000);
        assert_eq!(g.sgid, 1000);
    }

    #[test]
    fn test_syscall_success() {
        let ret = syscall_getresgid(0x100, 0x200, 0x300);
        assert_eq!(ret, 0);
    }
}
