// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Extended `getrlimit` / `prlimit64` syscall handler.
//!
//! Provides process resource limit retrieval with 64-bit limits and
//! the ability to target other processes (unlike the basic `getrlimit`
//! which only queries the calling process).
//!
//! POSIX.1-2024: `getrlimit()` is specified; `prlimit64` is a Linux extension
//! for 64-bit limits and cross-process operations.
//!
//! # Resource Limit Types
//! Common `RLIMIT_*` constants used in this module:
//! - `RLIMIT_CPU` (0) — CPU time limit in seconds.
//! - `RLIMIT_FSIZE` (1) — Maximum file size in bytes.
//! - `RLIMIT_DATA` (2) — Maximum data segment size.
//! - `RLIMIT_STACK` (3) — Maximum stack size.
//! - `RLIMIT_CORE` (4) — Maximum core dump file size.
//! - `RLIMIT_NOFILE` (7) — Maximum number of open file descriptors.
//! - `RLIMIT_AS` (9) — Maximum address space size.
//! - `RLIMIT_NPROC` (6) — Maximum number of processes.

use oncrix_lib::{Error, Result};

/// Unlimited resource limit value.
pub const RLIM_INFINITY: u64 = u64::MAX;

/// Number of recognized resource limit types.
pub const RLIM_NLIMITS: u32 = 16;

/// A pair of resource limits (soft and hard).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(C)]
pub struct Rlimit64 {
    /// Soft limit: the current enforced limit.
    pub rlim_cur: u64,
    /// Hard limit: the ceiling for the soft limit.
    pub rlim_max: u64,
}

impl Rlimit64 {
    /// Construct a new `Rlimit64`.
    pub const fn new(rlim_cur: u64, rlim_max: u64) -> Self {
        Self { rlim_cur, rlim_max }
    }

    /// Construct an unlimited limit pair.
    pub const fn unlimited() -> Self {
        Self::new(RLIM_INFINITY, RLIM_INFINITY)
    }

    /// Returns `true` if the soft limit exceeds the hard limit (invalid).
    pub fn is_inconsistent(self) -> bool {
        self.rlim_cur > self.rlim_max
    }
}

/// Arguments for the extended `getrlimit` / `prlimit64` syscall.
#[derive(Debug, Clone, Copy)]
pub struct GetRlimitExtArgs {
    /// Target PID (0 = calling process).
    pub pid: u32,
    /// Resource type identifier.
    pub resource: u32,
    /// User-space pointer for the new limit to set (NULL = query only).
    pub new_limit_ptr: u64,
    /// User-space pointer to write the old (current) limit.
    pub old_limit_ptr: u64,
}

impl GetRlimitExtArgs {
    /// Construct from raw syscall register values.
    ///
    /// # Errors
    /// - [`Error::InvalidArgument`] — negative pid, unknown resource, or both pointers null.
    pub fn from_raw(pid_raw: u64, resource_raw: u64, new_ptr: u64, old_ptr: u64) -> Result<Self> {
        let pid_signed = pid_raw as i64;
        if pid_signed < 0 {
            return Err(Error::InvalidArgument);
        }
        let resource = resource_raw as u32;
        if resource >= RLIM_NLIMITS {
            return Err(Error::InvalidArgument);
        }
        if new_ptr == 0 && old_ptr == 0 {
            return Err(Error::InvalidArgument);
        }
        Ok(Self {
            pid: pid_raw as u32,
            resource,
            new_limit_ptr: new_ptr,
            old_limit_ptr: old_ptr,
        })
    }

    /// Returns `true` if this is a set operation (new limit provided).
    pub fn is_set(self) -> bool {
        self.new_limit_ptr != 0
    }

    /// Returns `true` if this is a get operation (old limit requested).
    pub fn is_get(self) -> bool {
        self.old_limit_ptr != 0
    }
}

/// Result of the get operation.
#[derive(Debug, Clone, Copy)]
pub struct GetRlimitExtResult {
    /// The current limit for the resource (if queried).
    pub old_limit: Option<Rlimit64>,
}

impl GetRlimitExtResult {
    /// Construct a result with an old limit.
    pub const fn with_old(old: Rlimit64) -> Self {
        Self {
            old_limit: Some(old),
        }
    }

    /// Construct a set-only result (no old limit returned).
    pub const fn set_only() -> Self {
        Self { old_limit: None }
    }
}

/// Handle the extended `getrlimit` / `prlimit64` syscall.
///
/// # Errors
/// - [`Error::NotFound`] — target process does not exist.
/// - [`Error::PermissionDenied`] — caller lacks privilege.
/// - [`Error::InvalidArgument`] — invalid args.
pub fn sys_getrlimit_ext(args: GetRlimitExtArgs) -> Result<GetRlimitExtResult> {
    // A full implementation would:
    // 1. Look up the target process (args.pid).
    // 2. If is_get: copy the current rlimit to old_limit_ptr.
    // 3. If is_set: validate new_limit (cur <= max), apply with privilege check.
    let _ = args;
    if args.is_get() {
        Ok(GetRlimitExtResult::with_old(Rlimit64::unlimited()))
    } else {
        Ok(GetRlimitExtResult::set_only())
    }
}

/// Raw syscall entry point for `prlimit64`.
///
/// # Arguments
/// * `pid` — target PID (register a0), 0 for calling process.
/// * `resource` — resource type (register a1).
/// * `new_ptr` — pointer to new limit (register a2), or 0 to query.
/// * `old_ptr` — pointer to write old limit (register a3), or 0 to discard.
///
/// # Returns
/// `0` on success, negative errno on failure.
pub fn syscall_prlimit64(pid: u64, resource: u64, new_ptr: u64, old_ptr: u64) -> i64 {
    let args = match GetRlimitExtArgs::from_raw(pid, resource, new_ptr, old_ptr) {
        Ok(a) => a,
        Err(_) => return -(oncrix_lib::errno::EINVAL as i64),
    };
    match sys_getrlimit_ext(args) {
        Ok(_) => 0,
        Err(Error::NotFound) => -(oncrix_lib::errno::ESRCH as i64),
        Err(Error::PermissionDenied) => -(oncrix_lib::errno::EPERM as i64),
        Err(Error::InvalidArgument) => -(oncrix_lib::errno::EINVAL as i64),
        Err(_) => -(oncrix_lib::errno::EINVAL as i64),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_both_null_ptrs_rejected() {
        assert!(GetRlimitExtArgs::from_raw(0, 7, 0, 0).is_err());
    }

    #[test]
    fn test_resource_out_of_range_rejected() {
        assert!(GetRlimitExtArgs::from_raw(0, RLIM_NLIMITS as u64, 0, 0x1000).is_err());
    }

    #[test]
    fn test_negative_pid_rejected() {
        assert!(GetRlimitExtArgs::from_raw(u64::MAX, 7, 0, 0x1000).is_err());
    }

    #[test]
    fn test_get_only_query() {
        let args = GetRlimitExtArgs::from_raw(0, 7, 0, 0x1000).unwrap();
        assert!(!args.is_set());
        assert!(args.is_get());
    }

    #[test]
    fn test_set_and_get() {
        let args = GetRlimitExtArgs::from_raw(0, 7, 0x1000, 0x2000).unwrap();
        assert!(args.is_set());
        assert!(args.is_get());
    }

    #[test]
    fn test_rlimit64_inconsistency_check() {
        let bad = Rlimit64::new(100, 50);
        assert!(bad.is_inconsistent());
        let ok = Rlimit64::new(50, 100);
        assert!(!ok.is_inconsistent());
    }

    #[test]
    fn test_prlimit64_success() {
        let ret = syscall_prlimit64(0, 7, 0, 0x1000);
        assert_eq!(ret, 0);
    }
}
