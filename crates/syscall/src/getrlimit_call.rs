// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `getrlimit(2)` / `setrlimit(2)` / `prlimit64(2)` dispatch layer.
//!
//! This module is the thin syscall entry point that validates raw arguments
//! and delegates to the full implementation in [`crate::rlimit_calls`].
//!
//! # Syscall signatures
//!
//! ```text
//! int getrlimit(int resource, struct rlimit *rlim);
//! int setrlimit(int resource, const struct rlimit *rlim);
//! int prlimit64(pid_t pid, int resource,
//!               const struct rlimit64 *new_limit,
//!               struct rlimit64 *old_limit);
//! ```
//!
//! # POSIX Reference
//!
//! - POSIX.1-2024: `getrlimit()`, `setrlimit()` in `<sys/resource.h>`
//! - Linux extension: `prlimit64(2)` adds per-PID targeting and 64-bit limits
//!
//! # References
//!
//! - Linux: `kernel/sys.c` (`do_prlimit`)
//! - `include/uapi/linux/resource.h`
//! - `getrlimit(2)`, `setrlimit(2)`, `prlimit(2)` man pages

use oncrix_lib::{Error, Result};

// Re-export resource ID constants from rlimit_calls so callers can use
// either import path.
pub use crate::rlimit_calls::{
    RLIMIT_AS, RLIMIT_CORE, RLIMIT_CPU, RLIMIT_DATA, RLIMIT_FSIZE, RLIMIT_LOCKS, RLIMIT_MEMLOCK,
    RLIMIT_MSGQUEUE, RLIMIT_NOFILE, RLIMIT_NPROC, RLIMIT_RSS, RLIMIT_RTPRIO, RLIMIT_RTTIME,
    RLIMIT_SIGPENDING, RLIMIT_STACK,
};

// Re-export the core types and the total count.
pub use crate::rlimit_calls::{RLIM_INFINITY, RLIM_NLIMITS, RLimit};

/// Alias for the total number of recognised resource IDs.
pub const RLIMIT_NLIMITS: usize = RLIM_NLIMITS;

// ---------------------------------------------------------------------------
// Validation helpers
// ---------------------------------------------------------------------------

/// Returns `true` if `resource` is a valid resource ID.
pub fn is_valid_resource(resource: usize) -> bool {
    resource < RLIMIT_NLIMITS
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// Handle `getrlimit(2)`.
///
/// Copies the soft and hard limits for `resource` of the calling process
/// into the `rlimit` structure pointed to by `rlim_ptr`.
///
/// # Errors
///
/// - [`Error::InvalidArgument`] — `resource` is out of range or `rlim_ptr` is null.
pub fn sys_getrlimit(resource: usize, rlim_ptr: u64) -> Result<i64> {
    if !is_valid_resource(resource) {
        return Err(Error::InvalidArgument);
    }
    if rlim_ptr == 0 {
        return Err(Error::InvalidArgument);
    }
    // TODO: Look up the calling process's RLimitSet and write the RLimit to
    // user-space via copy_to_user.
    Err(Error::NotImplemented)
}

/// Handle `setrlimit(2)`.
///
/// Updates the soft and/or hard limits for `resource` of the calling process
/// from the `rlimit` structure pointed to by `rlim_ptr`.
///
/// # Errors
///
/// - [`Error::InvalidArgument`] — `resource` is out of range, `rlim_ptr` is
///   null, or the new soft limit exceeds the new hard limit.
/// - [`Error::PermissionDenied`] — attempt to raise the hard limit without
///   `CAP_SYS_RESOURCE`.
pub fn sys_setrlimit(resource: usize, rlim_ptr: u64) -> Result<i64> {
    if !is_valid_resource(resource) {
        return Err(Error::InvalidArgument);
    }
    if rlim_ptr == 0 {
        return Err(Error::InvalidArgument);
    }
    // SAFETY: Caller validates pointer.
    let new_limit = unsafe { *(rlim_ptr as *const RLimit) };
    if new_limit.soft > new_limit.hard {
        return Err(Error::InvalidArgument);
    }
    // TODO: Apply the new limit to the calling process's RLimitSet.
    Err(Error::NotImplemented)
}

/// Handle `prlimit64(2)`.
///
/// Gets and/or sets the resource limits of the process identified by `pid`
/// (0 means the calling process).  Either `new_rlim_ptr` or `old_rlim_ptr`
/// (or both) may be null to skip the set or get operation respectively.
///
/// # Errors
///
/// - [`Error::InvalidArgument`] — `resource` is out of range or both
///   `new_rlim_ptr` and `old_rlim_ptr` are null.
/// - [`Error::NotFound`] — `pid` does not refer to an existing process.
/// - [`Error::PermissionDenied`] — insufficient privilege for the target PID
///   or for raising the hard limit.
pub fn sys_prlimit64(
    pid: u32,
    resource: usize,
    new_rlim_ptr: u64,
    old_rlim_ptr: u64,
) -> Result<i64> {
    if !is_valid_resource(resource) {
        return Err(Error::InvalidArgument);
    }
    // At least one of new/old must be provided.
    if new_rlim_ptr == 0 && old_rlim_ptr == 0 {
        return Err(Error::InvalidArgument);
    }
    if new_rlim_ptr != 0 {
        // SAFETY: Caller validates pointer.
        let new_limit = unsafe { *(new_rlim_ptr as *const RLimit) };
        if new_limit.soft > new_limit.hard {
            return Err(Error::InvalidArgument);
        }
    }
    let _ = pid;
    // TODO: Look up the target process, apply the new limit (if provided),
    // and write the old limit to old_rlim_ptr (if provided).
    Err(Error::NotImplemented)
}

/// Entry point for `getrlimit` from the syscall dispatcher.
pub fn do_getrlimit_call(resource: usize, rlim_ptr: u64) -> Result<i64> {
    sys_getrlimit(resource, rlim_ptr)
}

/// Entry point for `setrlimit` from the syscall dispatcher.
pub fn do_setrlimit_call(resource: usize, rlim_ptr: u64) -> Result<i64> {
    sys_setrlimit(resource, rlim_ptr)
}

/// Entry point for `prlimit64` from the syscall dispatcher.
pub fn do_prlimit64_call(
    pid: u32,
    resource: usize,
    new_rlim_ptr: u64,
    old_rlim_ptr: u64,
) -> Result<i64> {
    sys_prlimit64(pid, resource, new_rlim_ptr, old_rlim_ptr)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn getrlimit_invalid_resource() {
        assert_eq!(
            sys_getrlimit(RLIMIT_NLIMITS, 0x1000).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn getrlimit_null_ptr() {
        assert_eq!(
            sys_getrlimit(RLIMIT_NOFILE, 0).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn setrlimit_invalid_resource() {
        assert_eq!(
            sys_setrlimit(RLIMIT_NLIMITS + 5, 0x1000).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn setrlimit_null_ptr() {
        assert_eq!(
            sys_setrlimit(RLIMIT_CPU, 0).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn prlimit64_invalid_resource() {
        assert_eq!(
            sys_prlimit64(0, RLIMIT_NLIMITS, 0, 0x1000).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn prlimit64_both_ptrs_null() {
        assert_eq!(
            sys_prlimit64(0, RLIMIT_CPU, 0, 0).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn is_valid_resource_check() {
        assert!(is_valid_resource(RLIMIT_NOFILE));
        assert!(!is_valid_resource(RLIMIT_NLIMITS));
        assert!(!is_valid_resource(999));
    }
}
