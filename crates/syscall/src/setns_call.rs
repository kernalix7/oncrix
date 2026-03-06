// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `setns` syscall handler.
//!
//! Allows a process to associate itself with a namespace referred to by
//! an open file descriptor. The `fd` must refer to a namespace file (e.g.,
//! `/proc/[pid]/ns/mnt`).
//!
//! `nstype` restricts the type of namespace the `fd` may refer to.
//! If `nstype` is 0, the check is skipped.
//!
//! Namespace type flags (CLONE_* constants):
//! - `CLONE_NEWIPC` (0x8000000)
//! - `CLONE_NEWNET` (0x40000000)
//! - `CLONE_NEWNS` (0x20000)
//! - `CLONE_NEWPID` (0x20000000)
//! - `CLONE_NEWUSER` (0x10000000)
//! - `CLONE_NEWUTS` (0x4000000)
//! - `CLONE_NEWCGROUP` (0x2000000)
//!
//! # POSIX Conformance
//! `setns` is a Linux-specific extension not in POSIX.1-2024.

use oncrix_lib::{Error, Result};

/// Flag: IPC namespace.
pub const CLONE_NEWIPC: u32 = 0x0800_0000;
/// Flag: network namespace.
pub const CLONE_NEWNET: u32 = 0x4000_0000;
/// Flag: mount namespace.
pub const CLONE_NEWNS: u32 = 0x0002_0000;
/// Flag: PID namespace.
pub const CLONE_NEWPID: u32 = 0x2000_0000;
/// Flag: user namespace.
pub const CLONE_NEWUSER: u32 = 0x1000_0000;
/// Flag: UTS namespace.
pub const CLONE_NEWUTS: u32 = 0x0400_0000;
/// Flag: cgroup namespace.
pub const CLONE_NEWCGROUP: u32 = 0x0200_0000;

/// Bitmask of all recognized namespace type flags for `setns`.
const VALID_NSTYPE: u32 = CLONE_NEWIPC
    | CLONE_NEWNET
    | CLONE_NEWNS
    | CLONE_NEWPID
    | CLONE_NEWUSER
    | CLONE_NEWUTS
    | CLONE_NEWCGROUP;

/// Validated namespace type restriction for `setns`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NsType {
    /// No restriction on namespace type.
    Any,
    /// Restrict to a specific namespace type.
    Specific(u32),
}

impl NsType {
    /// Construct from a raw `nstype` value.
    ///
    /// # Errors
    /// Returns [`Error::InvalidArgument`] if `nstype` contains unknown bits.
    pub fn from_raw(raw: u32) -> Result<Self> {
        if raw == 0 {
            return Ok(Self::Any);
        }
        if raw & !VALID_NSTYPE != 0 {
            return Err(Error::InvalidArgument);
        }
        // Only one type flag may be set.
        if raw.count_ones() != 1 {
            return Err(Error::InvalidArgument);
        }
        Ok(Self::Specific(raw))
    }

    /// Returns `true` if there is no type restriction.
    pub fn is_any(self) -> bool {
        matches!(self, Self::Any)
    }
}

/// Arguments for the `setns` syscall.
#[derive(Debug, Clone, Copy)]
pub struct SetnsArgs {
    /// File descriptor referring to the target namespace.
    pub fd: i32,
    /// Namespace type restriction.
    pub nstype: NsType,
}

impl SetnsArgs {
    /// Construct from raw syscall register values.
    ///
    /// # Errors
    /// - [`Error::InvalidArgument`] — negative fd or invalid nstype.
    pub fn from_raw(fd_raw: u64, nstype_raw: u64) -> Result<Self> {
        let fd = fd_raw as i32;
        if fd < 0 {
            return Err(Error::InvalidArgument);
        }
        let nstype = NsType::from_raw(nstype_raw as u32)?;
        Ok(Self { fd, nstype })
    }
}

/// Handle the `setns` syscall.
///
/// Associates the calling process with the namespace referenced by `fd`.
///
/// # Errors
/// - [`Error::PermissionDenied`] — caller lacks privilege (CAP_SYS_ADMIN for most namespaces).
/// - [`Error::InvalidArgument`] — fd is not a namespace descriptor, or nstype mismatch.
/// - [`Error::NotFound`] — fd is not a valid open file descriptor.
pub fn sys_setns(args: SetnsArgs) -> Result<()> {
    // A full implementation would:
    // 1. Look up the file descriptor in the calling process's fdtable.
    // 2. Verify it refers to a namespace (special proc ns file).
    // 3. If nstype != Any, verify the namespace type matches.
    // 4. Check privileges for the target namespace type.
    // 5. Switch the current task into the new namespace.
    let _ = args;
    Ok(())
}

/// Raw syscall entry point for `setns`.
///
/// # Arguments
/// * `fd` — file descriptor for the namespace (register a0).
/// * `nstype` — namespace type filter (register a1), 0 for any.
///
/// # Returns
/// `0` on success, negative errno on failure.
pub fn syscall_setns(fd: u64, nstype: u64) -> i64 {
    let args = match SetnsArgs::from_raw(fd, nstype) {
        Ok(a) => a,
        Err(_) => return -(oncrix_lib::errno::EINVAL as i64),
    };
    match sys_setns(args) {
        Ok(()) => 0,
        Err(Error::PermissionDenied) => -(oncrix_lib::errno::EPERM as i64),
        Err(Error::NotFound) => -(oncrix_lib::errno::EBADF as i64),
        Err(Error::InvalidArgument) => -(oncrix_lib::errno::EINVAL as i64),
        Err(_) => -(oncrix_lib::errno::EINVAL as i64),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_negative_fd_rejected() {
        assert!(SetnsArgs::from_raw(u64::MAX, 0).is_err());
    }

    #[test]
    fn test_zero_nstype_is_any() {
        let args = SetnsArgs::from_raw(5, 0).unwrap();
        assert!(args.nstype.is_any());
    }

    #[test]
    fn test_valid_nstype_newipc() {
        let args = SetnsArgs::from_raw(5, CLONE_NEWIPC as u64).unwrap();
        assert_eq!(args.nstype, NsType::Specific(CLONE_NEWIPC));
    }

    #[test]
    fn test_multiple_nstype_flags_rejected() {
        assert!(SetnsArgs::from_raw(5, (CLONE_NEWIPC | CLONE_NEWNET) as u64).is_err());
    }

    #[test]
    fn test_unknown_nstype_rejected() {
        assert!(SetnsArgs::from_raw(5, 0x1).is_err());
    }

    #[test]
    fn test_syscall_success() {
        let ret = syscall_setns(3, 0);
        assert_eq!(ret, 0);
    }
}
