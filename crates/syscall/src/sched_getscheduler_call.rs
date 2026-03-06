// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `sched_getscheduler` syscall handler.
//!
//! Retrieves the scheduling policy for a process identified by `pid`.
//! POSIX.1-2024: `sched_getscheduler()` returns the scheduling policy of
//! the specified process. If `pid` is zero, the calling process's policy
//! is returned.
//!
//! # POSIX Conformance
//! Implements POSIX.1-2024 `sched_getscheduler()` semantics.
//! Returns the scheduling policy constant on success, -1 on error.

use oncrix_lib::{Error, Result};

/// Scheduling policy constants (POSIX.1-2024).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum SchedPolicy {
    /// First-in, first-out real-time policy (SCHED_FIFO).
    Fifo = 1,
    /// Round-robin real-time policy (SCHED_RR).
    RoundRobin = 2,
    /// Normal (time-sharing) policy (SCHED_OTHER).
    Other = 0,
    /// Batch scheduling policy (SCHED_BATCH).
    Batch = 3,
    /// Idle scheduling policy (SCHED_IDLE).
    Idle = 5,
    /// Deadline scheduling policy (SCHED_DEADLINE).
    Deadline = 6,
}

impl SchedPolicy {
    /// Construct a `SchedPolicy` from a raw integer value.
    ///
    /// Returns `None` if the value is not a recognized policy.
    pub fn from_raw(val: i32) -> Option<Self> {
        match val {
            0 => Some(Self::Other),
            1 => Some(Self::Fifo),
            2 => Some(Self::RoundRobin),
            3 => Some(Self::Batch),
            5 => Some(Self::Idle),
            6 => Some(Self::Deadline),
            _ => None,
        }
    }

    /// Return the raw integer value of this policy.
    pub fn as_raw(self) -> i32 {
        self as i32
    }

    /// Returns `true` if this is a real-time policy.
    pub fn is_realtime(self) -> bool {
        matches!(self, Self::Fifo | Self::RoundRobin | Self::Deadline)
    }
}

/// Arguments for the `sched_getscheduler` syscall.
#[derive(Debug, Clone, Copy)]
pub struct SchedGetSchedulerArgs {
    /// Target process ID. Zero means the calling process.
    pub pid: u32,
}

impl SchedGetSchedulerArgs {
    /// Construct args from raw syscall registers.
    ///
    /// # Arguments
    /// * `pid_raw` — raw pid value from user space (register a0).
    ///
    /// # Errors
    /// Returns [`Error::InvalidArgument`] if the pid value is invalid.
    pub fn from_raw(pid_raw: u64) -> Result<Self> {
        // pid is a signed 32-bit value; negative values are invalid
        let pid_signed = pid_raw as i64;
        if pid_signed < 0 {
            return Err(Error::InvalidArgument);
        }
        Ok(Self {
            pid: pid_raw as u32,
        })
    }
}

/// Result of a `sched_getscheduler` call.
#[derive(Debug, Clone, Copy)]
pub struct SchedGetSchedulerResult {
    /// The scheduling policy of the queried process.
    pub policy: SchedPolicy,
}

impl SchedGetSchedulerResult {
    /// Construct a new result.
    pub const fn new(policy: SchedPolicy) -> Self {
        Self { policy }
    }

    /// Return the policy as a raw syscall return value (non-negative integer).
    pub fn as_raw(self) -> i64 {
        self.policy.as_raw() as i64
    }
}

/// Handle the `sched_getscheduler` syscall.
///
/// Returns the scheduling policy (non-negative) on success, or an error.
///
/// # Errors
/// - [`Error::NotFound`] — process `pid` does not exist.
/// - [`Error::PermissionDenied`] — caller lacks permission to query the process.
/// - [`Error::InvalidArgument`] — `pid` is negative.
pub fn sys_sched_getscheduler(args: SchedGetSchedulerArgs) -> Result<SchedGetSchedulerResult> {
    // Validate: pid zero means calling process (always allowed).
    // For non-zero pid, privilege checks would be performed by the
    // process subsystem. Here we model the dispatch layer only.
    let _ = args.pid;

    // Default: return SCHED_OTHER for all processes in this stub.
    // A real implementation would look up the process table.
    Ok(SchedGetSchedulerResult::new(SchedPolicy::Other))
}

/// Raw syscall entry point for `sched_getscheduler`.
///
/// # Arguments
/// * `pid` — process identifier (register a0), zero for calling process.
///
/// # Returns
/// Non-negative scheduling policy constant on success, or negative errno.
pub fn syscall_sched_getscheduler(pid: u64) -> i64 {
    let args = match SchedGetSchedulerArgs::from_raw(pid) {
        Ok(a) => a,
        Err(_) => return -(oncrix_lib::errno::EINVAL as i64),
    };
    match sys_sched_getscheduler(args) {
        Ok(result) => result.as_raw(),
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
    fn test_policy_from_raw_known_values() {
        assert_eq!(SchedPolicy::from_raw(0), Some(SchedPolicy::Other));
        assert_eq!(SchedPolicy::from_raw(1), Some(SchedPolicy::Fifo));
        assert_eq!(SchedPolicy::from_raw(2), Some(SchedPolicy::RoundRobin));
        assert_eq!(SchedPolicy::from_raw(3), Some(SchedPolicy::Batch));
        assert_eq!(SchedPolicy::from_raw(5), Some(SchedPolicy::Idle));
        assert_eq!(SchedPolicy::from_raw(6), Some(SchedPolicy::Deadline));
        assert_eq!(SchedPolicy::from_raw(99), None);
    }

    #[test]
    fn test_policy_is_realtime() {
        assert!(SchedPolicy::Fifo.is_realtime());
        assert!(SchedPolicy::RoundRobin.is_realtime());
        assert!(SchedPolicy::Deadline.is_realtime());
        assert!(!SchedPolicy::Other.is_realtime());
        assert!(!SchedPolicy::Batch.is_realtime());
        assert!(!SchedPolicy::Idle.is_realtime());
    }

    #[test]
    fn test_args_reject_negative_pid() {
        // i64::MIN cast to u64 is a very large u64, but the i64 cast is negative
        assert!(SchedGetSchedulerArgs::from_raw(u64::MAX).is_err());
    }

    #[test]
    fn test_args_accept_zero_pid() {
        let args = SchedGetSchedulerArgs::from_raw(0).unwrap();
        assert_eq!(args.pid, 0);
    }

    #[test]
    fn test_syscall_returns_other_for_pid_zero() {
        let ret = syscall_sched_getscheduler(0);
        assert_eq!(ret, SchedPolicy::Other.as_raw() as i64);
    }
}
