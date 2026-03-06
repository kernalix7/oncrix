// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `unshare` syscall handler.
//!
//! Disassociates parts of the calling process's execution context that are
//! currently being shared with other processes. This allows creating new
//! namespaces without spawning a new process (unlike `clone`).
//!
//! Common `unshare` flags (CLONE_* constants):
//! - `CLONE_FILES` (0x400) — Unshare the file descriptor table.
//! - `CLONE_FS` (0x200) — Unshare filesystem information (root, cwd, umask).
//! - `CLONE_NEWIPC` (0x8000000) — Create a new IPC namespace.
//! - `CLONE_NEWNET` (0x40000000) — Create a new network namespace.
//! - `CLONE_NEWNS` (0x20000) — Create a new mount namespace.
//! - `CLONE_NEWPID` (0x20000000) — Create a new PID namespace.
//! - `CLONE_NEWUSER` (0x10000000) — Create a new user namespace.
//! - `CLONE_NEWUTS` (0x4000000) — Create a new UTS namespace.
//! - `CLONE_SYSVSEM` (0x40000) — Unshare System V semaphore undo values.
//!
//! # POSIX Conformance
//! `unshare` is a Linux-specific extension not in POSIX.1-2024.

use oncrix_lib::{Error, Result};

/// Flag: unshare the file descriptor table.
pub const CLONE_FILES: u64 = 0x400;
/// Flag: unshare filesystem attributes.
pub const CLONE_FS: u64 = 0x200;
/// Flag: create a new IPC namespace.
pub const CLONE_NEWIPC: u64 = 0x0800_0000;
/// Flag: create a new network namespace.
pub const CLONE_NEWNET: u64 = 0x4000_0000;
/// Flag: create a new mount namespace.
pub const CLONE_NEWNS: u64 = 0x0002_0000;
/// Flag: create a new PID namespace.
pub const CLONE_NEWPID: u64 = 0x2000_0000;
/// Flag: create a new user namespace.
pub const CLONE_NEWUSER: u64 = 0x1000_0000;
/// Flag: create a new UTS namespace.
pub const CLONE_NEWUTS: u64 = 0x0400_0000;
/// Flag: unshare System V semaphore undo values.
pub const CLONE_SYSVSEM: u64 = 0x0004_0000;

/// Bitmask of all recognized `unshare` flags.
const VALID_FLAGS: u64 = CLONE_FILES
    | CLONE_FS
    | CLONE_NEWIPC
    | CLONE_NEWNET
    | CLONE_NEWNS
    | CLONE_NEWPID
    | CLONE_NEWUSER
    | CLONE_NEWUTS
    | CLONE_SYSVSEM;

/// Validated `unshare` flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct UnshareFlags(u64);

impl UnshareFlags {
    /// Construct from raw flags.
    ///
    /// # Errors
    /// - [`Error::InvalidArgument`] if unknown flags are set or no flags provided.
    pub fn from_raw(raw: u64) -> Result<Self> {
        if raw & !VALID_FLAGS != 0 {
            return Err(Error::InvalidArgument);
        }
        if raw == 0 {
            return Err(Error::InvalidArgument);
        }
        Ok(Self(raw))
    }

    /// Returns the raw flags value.
    pub fn raw(self) -> u64 {
        self.0
    }

    /// Returns `true` if any new namespace flag is set.
    pub fn creates_namespace(self) -> bool {
        self.0
            & (CLONE_NEWIPC
                | CLONE_NEWNET
                | CLONE_NEWNS
                | CLONE_NEWPID
                | CLONE_NEWUSER
                | CLONE_NEWUTS)
            != 0
    }

    /// Returns `true` if a new user namespace is requested.
    pub fn new_user_ns(self) -> bool {
        self.0 & CLONE_NEWUSER != 0
    }
}

/// Handle the `unshare` syscall.
///
/// # Errors
/// - [`Error::PermissionDenied`] — creating namespaces requires privilege (except user NS).
/// - [`Error::InvalidArgument`] — unknown or zero flags.
/// - [`Error::OutOfMemory`] — insufficient memory to create new structures.
pub fn sys_unshare(flags: UnshareFlags) -> Result<()> {
    // A full implementation would:
    // 1. Check CAP_SYS_ADMIN for most namespace types.
    // 2. CLONE_NEWUSER may be created without privilege but implies others later.
    // 3. Allocate new namespace structures and attach to current task.
    // 4. For CLONE_FILES: duplicate the current fdtable.
    // 5. For CLONE_FS: duplicate the fs_struct.
    let _ = flags;
    Ok(())
}

/// Raw syscall entry point for `unshare`.
///
/// # Arguments
/// * `flags` — unshare flags (register a0).
///
/// # Returns
/// `0` on success, negative errno on failure.
pub fn syscall_unshare(flags: u64) -> i64 {
    let f = match UnshareFlags::from_raw(flags) {
        Ok(f) => f,
        Err(_) => return -(oncrix_lib::errno::EINVAL as i64),
    };
    match sys_unshare(f) {
        Ok(()) => 0,
        Err(Error::PermissionDenied) => -(oncrix_lib::errno::EPERM as i64),
        Err(Error::OutOfMemory) => -(oncrix_lib::errno::ENOMEM as i64),
        Err(Error::InvalidArgument) => -(oncrix_lib::errno::EINVAL as i64),
        Err(_) => -(oncrix_lib::errno::EINVAL as i64),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zero_flags_rejected() {
        assert!(UnshareFlags::from_raw(0).is_err());
    }

    #[test]
    fn test_unknown_flag_rejected() {
        assert!(UnshareFlags::from_raw(0x1).is_err());
    }

    #[test]
    fn test_newns_flag_valid() {
        let f = UnshareFlags::from_raw(CLONE_NEWNS).unwrap();
        assert!(f.creates_namespace());
        assert!(!f.new_user_ns());
    }

    #[test]
    fn test_newuser_flag_valid() {
        let f = UnshareFlags::from_raw(CLONE_NEWUSER).unwrap();
        assert!(f.creates_namespace());
        assert!(f.new_user_ns());
    }

    #[test]
    fn test_files_flag_no_namespace() {
        let f = UnshareFlags::from_raw(CLONE_FILES).unwrap();
        assert!(!f.creates_namespace());
    }

    #[test]
    fn test_multiple_flags_combined() {
        let f = UnshareFlags::from_raw(CLONE_NEWNET | CLONE_NEWIPC).unwrap();
        assert!(f.creates_namespace());
    }

    #[test]
    fn test_syscall_success() {
        let ret = syscall_unshare(CLONE_FILES);
        assert_eq!(ret, 0);
    }
}
