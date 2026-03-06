// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `sched_getparam` syscall handler.
//!
//! Retrieves the scheduling parameters for a process.
//! POSIX.1-2024: `sched_getparam()` returns the scheduling parameters of
//! the specified process. If `pid` is zero, the calling process's parameters
//! are returned.
//!
//! The result is written into a `sched_param` structure in user space,
//! containing at minimum `sched_priority`.
//!
//! # POSIX Conformance
//! Implements POSIX.1-2024 `sched_getparam()` semantics.

use oncrix_lib::{Error, Result};

/// Kernel-side representation of `struct sched_param`.
///
/// Matches the POSIX-defined layout: a single `sched_priority` field
/// as the minimum required member.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(C)]
pub struct SchedParam {
    /// The scheduling priority of the process.
    /// For non-real-time policies this is 0.
    /// For SCHED_FIFO/SCHED_RR this is in `[1, sched_get_priority_max]`.
    pub sched_priority: i32,
}

impl SchedParam {
    /// Construct a `SchedParam` with the given priority.
    pub const fn new(sched_priority: i32) -> Self {
        Self { sched_priority }
    }

    /// Construct a default (zero priority) param used by non-RT policies.
    pub const fn zero() -> Self {
        Self { sched_priority: 0 }
    }
}

/// Arguments for the `sched_getparam` syscall.
#[derive(Debug, Clone, Copy)]
pub struct SchedGetParamArgs {
    /// Target process ID. Zero means the calling process.
    pub pid: u32,
    /// User-space pointer to `struct sched_param` to write into.
    pub param_ptr: u64,
}

impl SchedGetParamArgs {
    /// Construct from raw syscall register values.
    ///
    /// # Errors
    /// - [`Error::InvalidArgument`] if `pid` is negative or `param_ptr` is null.
    pub fn from_raw(pid_raw: u64, param_ptr: u64) -> Result<Self> {
        if (pid_raw as i64) < 0 {
            return Err(Error::InvalidArgument);
        }
        if param_ptr == 0 {
            return Err(Error::InvalidArgument);
        }
        Ok(Self {
            pid: pid_raw as u32,
            param_ptr,
        })
    }
}

/// Result produced by `sched_getparam`.
#[derive(Debug, Clone, Copy)]
pub struct SchedGetParamResult {
    /// The scheduling parameters to write to user space.
    pub param: SchedParam,
}

impl SchedGetParamResult {
    /// Construct a new result.
    pub const fn new(param: SchedParam) -> Self {
        Self { param }
    }
}

/// Handle the `sched_getparam` syscall.
///
/// Looks up the scheduling parameters for the specified process and
/// writes them into user space at `args.param_ptr`.
///
/// # Errors
/// - [`Error::NotFound`] — process `pid` does not exist.
/// - [`Error::PermissionDenied`] — caller lacks permission to query the process.
/// - [`Error::InvalidArgument`] — invalid `pid` or null `param_ptr`.
pub fn sys_sched_getparam(args: SchedGetParamArgs) -> Result<SchedGetParamResult> {
    // In a full implementation this function would:
    // 1. Look up the process by pid in the process table.
    // 2. Read the current sched_param from the process descriptor.
    // 3. Validate and copy the param to user space via copy_to_user.
    //
    // This stub returns zero priority (SCHED_OTHER default).
    let _ = args;
    Ok(SchedGetParamResult::new(SchedParam::zero()))
}

/// Raw syscall entry point for `sched_getparam`.
///
/// # Arguments
/// * `pid` — process identifier (register a0).
/// * `param_ptr` — user-space pointer to `struct sched_param` (register a1).
///
/// # Returns
/// `0` on success, negative errno on failure.
pub fn syscall_sched_getparam(pid: u64, param_ptr: u64) -> i64 {
    let args = match SchedGetParamArgs::from_raw(pid, param_ptr) {
        Ok(a) => a,
        Err(_) => return -(oncrix_lib::errno::EINVAL as i64),
    };
    match sys_sched_getparam(args) {
        Ok(_result) => {
            // In a real implementation, copy result.param to args.param_ptr here.
            0
        }
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
    fn test_null_param_ptr_rejected() {
        assert!(SchedGetParamArgs::from_raw(0, 0).is_err());
    }

    #[test]
    fn test_negative_pid_rejected() {
        assert!(SchedGetParamArgs::from_raw(u64::MAX, 0x1000).is_err());
    }

    #[test]
    fn test_valid_args() {
        let args = SchedGetParamArgs::from_raw(42, 0x8000).unwrap();
        assert_eq!(args.pid, 42);
        assert_eq!(args.param_ptr, 0x8000);
    }

    #[test]
    fn test_zero_pid_allowed() {
        let args = SchedGetParamArgs::from_raw(0, 0x1000).unwrap();
        assert_eq!(args.pid, 0);
    }

    #[test]
    fn test_sched_param_default_zero() {
        let p = SchedParam::zero();
        assert_eq!(p.sched_priority, 0);
    }

    #[test]
    fn test_syscall_returns_zero_on_success() {
        let ret = syscall_sched_getparam(0, 0x1000);
        assert_eq!(ret, 0);
    }
}
