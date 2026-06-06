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
use oncrix_process::namespace::CapSet;

/// `CAP_SYS_ADMIN` capability index (Linux value; mirrors
/// `oncrix_kernel::capability::CAP_SYS_ADMIN` and
/// `oncrix_process::namespace`). Joining a namespace via `setns` requires
/// this capability for every namespace type.
const CAP_SYS_ADMIN: u32 = 21;

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
/// `caller_caps` is the *effective* capability set of the authenticated
/// caller, threaded down by the syscall dispatcher.
///
/// # Errors
/// - [`Error::PermissionDenied`] — caller lacks `CAP_SYS_ADMIN` (required for
///   every namespace type).
/// - [`Error::NotImplemented`] — the namespace-switch backend is not yet
///   wired up; a privileged caller receives this rather than a false success.
//
// SECURITY: this handler fails closed. It MUST NOT return `Ok(())` while the
// transition is unimplemented — doing so would let a caller believe it had
// entered the target namespace when it had not (privilege/isolation
// confusion). Two gates apply:
//   1. CAP_SYS_ADMIN is required up front; without it the request is denied
//      regardless of `fd`/`nstype` (no information leak about the target).
//      The dispatcher MUST thread the real caller's effective `CapSet`;
//      `CapSet::EMPTY` (fail-closed default) denies every call.
//   2. Even with the capability, the fd→namespace lookup and the
//      `oncrix_kernel::nsproxy::NsProxyTable::setns` transition (which itself
//      now demands the caller's `CapSet`) are not reachable from this stub, so
//      we return `NotImplemented` rather than fabricate success.
pub fn sys_setns(args: SetnsArgs, caller_caps: CapSet) -> Result<()> {
    let _ = args;
    // Gate 1: joining any namespace requires CAP_SYS_ADMIN. Fail closed.
    if !caller_caps.has(CAP_SYS_ADMIN) {
        return Err(Error::PermissionDenied);
    }
    // Gate 2: a full implementation would
    //   1. look up `fd` in the calling process's fdtable,
    //   2. verify it refers to a namespace (special proc ns file),
    //   3. if `nstype != Any`, verify the namespace type matches,
    //   4. re-check privileges against the target user namespace, and
    //   5. switch the current task into the new namespace via nsproxy.
    // None of that backend is reachable here yet, so deny rather than lie.
    Err(Error::NotImplemented)
}

/// Raw syscall entry point for `setns`.
///
/// # Arguments
/// * `fd` — file descriptor for the namespace (register a0).
/// * `nstype` — namespace type filter (register a1), 0 for any.
/// * `caller_caps` — effective capability set of the authenticated caller,
///   threaded by the dispatcher. Use [`CapSet::EMPTY`] only when no real
///   credentials are available (fail-closed: every call is then denied).
///
/// # Returns
/// `0` on success, negative errno on failure. Currently never returns `0`:
/// the transition backend is unimplemented, so callers get `-EPERM`
/// (missing `CAP_SYS_ADMIN`) or `-ENOSYS`.
pub fn syscall_setns(fd: u64, nstype: u64, caller_caps: CapSet) -> i64 {
    let args = match SetnsArgs::from_raw(fd, nstype) {
        Ok(a) => a,
        Err(_) => return -(oncrix_lib::errno::EINVAL as i64),
    };
    match sys_setns(args, caller_caps) {
        Ok(()) => 0,
        Err(Error::PermissionDenied) => -(oncrix_lib::errno::EPERM as i64),
        Err(Error::NotImplemented) => -(oncrix_lib::errno::ENOSYS as i64),
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

    /// Capability set holding `CAP_SYS_ADMIN`.
    fn admin_caps() -> CapSet {
        let mut bits = [0u64; 2];
        bits[(CAP_SYS_ADMIN / 64) as usize] |= 1u64 << (CAP_SYS_ADMIN % 64);
        CapSet::from_bits(bits)
    }

    #[test]
    fn test_setns_denied_without_cap_sys_admin() {
        // Fail closed: unprivileged caller is denied, never a false success.
        assert_eq!(
            sys_setns(SetnsArgs::from_raw(3, 0).unwrap(), CapSet::EMPTY),
            Err(Error::PermissionDenied)
        );
        assert_eq!(
            syscall_setns(3, 0, CapSet::EMPTY),
            -(oncrix_lib::errno::EPERM as i64)
        );
    }

    #[test]
    fn test_setns_not_implemented_with_cap() {
        // Privileged caller must NOT receive a fabricated success while the
        // namespace-switch backend is unimplemented.
        assert_eq!(
            sys_setns(SetnsArgs::from_raw(3, 0).unwrap(), admin_caps()),
            Err(Error::NotImplemented)
        );
        assert_eq!(
            syscall_setns(3, 0, admin_caps()),
            -(oncrix_lib::errno::ENOSYS as i64)
        );
    }

    #[test]
    fn test_setns_never_returns_success() {
        // Regression guard: the stub must never report 0 (success).
        assert_ne!(syscall_setns(3, 0, admin_caps()), 0);
        assert_ne!(syscall_setns(3, 0, CapSet::EMPTY), 0);
    }
}
