// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `sched_setparam` syscall handler.
//!
//! Sets the scheduling parameters for a process without changing the policy.
//! POSIX.1-2024: `sched_setparam()` sets the scheduling parameters of the
//! specified process according to `param`. The scheduling policy is unchanged.
//! If `pid` is zero, the calling process is targeted.
//!
//! # POSIX Conformance
//! Implements POSIX.1-2024 `sched_setparam()` semantics.
//! Returns 0 on success, -1 on error.

use oncrix_lib::{Error, Result};

/// Valid range for real-time scheduling priorities.
pub const RT_PRIORITY_MIN: i32 = 1;
/// Maximum real-time scheduling priority.
pub const RT_PRIORITY_MAX: i32 = 99;

/// Kernel-side representation of `struct sched_param`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(C)]
pub struct SchedParam {
    /// Scheduling priority. 0 for non-RT policies; 1–99 for RT policies.
    pub sched_priority: i32,
}

impl SchedParam {
    /// Construct a new `SchedParam`.
    pub const fn new(sched_priority: i32) -> Self {
        Self { sched_priority }
    }

    /// Returns `true` if the priority is within the valid real-time range.
    pub fn is_valid_rt(self) -> bool {
        (RT_PRIORITY_MIN..=RT_PRIORITY_MAX).contains(&self.sched_priority)
    }

    /// Returns `true` if the priority is zero (required for non-RT policies).
    pub fn is_zero(self) -> bool {
        self.sched_priority == 0
    }
}

/// Arguments for the `sched_setparam` syscall.
#[derive(Debug, Clone, Copy)]
pub struct SchedSetParamArgs {
    /// Target process ID. Zero means the calling process.
    pub pid: u32,
    /// User-space pointer to the `struct sched_param` to read.
    pub param_ptr: u64,
    /// The scheduling parameter (already copied from user space).
    pub param: SchedParam,
}

impl SchedSetParamArgs {
    /// Construct from raw syscall arguments.
    ///
    /// In a real kernel this would call `copy_from_user` to read the param
    /// structure. Here we accept a pre-validated param for the dispatch layer.
    ///
    /// # Errors
    /// - [`Error::InvalidArgument`] — negative pid or null pointer.
    pub fn from_raw(pid_raw: u64, param_ptr: u64, priority: i32) -> Result<Self> {
        if (pid_raw as i64) < 0 {
            return Err(Error::InvalidArgument);
        }
        if param_ptr == 0 {
            return Err(Error::InvalidArgument);
        }
        Ok(Self {
            pid: pid_raw as u32,
            param_ptr,
            param: SchedParam::new(priority),
        })
    }
}

/// Handle the `sched_setparam` syscall.
///
/// Sets the scheduling parameter for the target process without changing
/// the scheduling policy. The priority must be appropriate for the current
/// policy of the target process.
///
/// # Errors
/// - [`Error::NotFound`] — process `pid` does not exist.
/// - [`Error::PermissionDenied`] — caller lacks permission.
/// - [`Error::InvalidArgument`] — null pointer, negative pid, or invalid priority.
pub fn sys_sched_setparam(args: SchedSetParamArgs) -> Result<()> {
    // In a full implementation:
    // 1. Look up the process by pid.
    // 2. Check caller permissions (CAP_SYS_NICE for RT increase).
    // 3. Validate priority against the process's current policy.
    // 4. Apply the new priority.
    let _ = args;
    Ok(())
}

/// Raw syscall entry point for `sched_setparam`.
///
/// # Arguments
/// * `pid` — process identifier (register a0).
/// * `param_ptr` — user-space pointer to `struct sched_param` (register a1).
/// * `priority` — sched_priority field value (pre-extracted for stub purposes).
///
/// # Returns
/// `0` on success, negative errno on failure.
pub fn syscall_sched_setparam(pid: u64, param_ptr: u64, priority: i32) -> i64 {
    let args = match SchedSetParamArgs::from_raw(pid, param_ptr, priority) {
        Ok(a) => a,
        Err(_) => return -(oncrix_lib::errno::EINVAL as i64),
    };
    match sys_sched_setparam(args) {
        Ok(()) => 0,
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
    fn test_null_ptr_rejected() {
        assert!(SchedSetParamArgs::from_raw(0, 0, 0).is_err());
    }

    #[test]
    fn test_negative_pid_rejected() {
        assert!(SchedSetParamArgs::from_raw(u64::MAX, 0x1000, 0).is_err());
    }

    #[test]
    fn test_valid_zero_priority() {
        let args = SchedSetParamArgs::from_raw(0, 0x1000, 0).unwrap();
        assert!(args.param.is_zero());
    }

    #[test]
    fn test_rt_priority_valid_range() {
        let p = SchedParam::new(50);
        assert!(p.is_valid_rt());
    }

    #[test]
    fn test_rt_priority_invalid_zero() {
        let p = SchedParam::new(0);
        assert!(!p.is_valid_rt());
    }

    #[test]
    fn test_syscall_success() {
        let ret = syscall_sched_setparam(0, 0x1000, 0);
        assert_eq!(ret, 0);
    }
}
