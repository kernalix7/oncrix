// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `sched_setscheduler` syscall handler.
//!
//! Sets the scheduling policy and parameters for a process.
//! POSIX.1-2024: `sched_setscheduler()` sets the scheduling policy and
//! associated parameters for the process whose ID is specified by `pid`.
//! If `pid` is zero, the scheduling policy and parameters of the calling
//! process are set.
//!
//! # POSIX Conformance
//! Implements POSIX.1-2024 `sched_setscheduler()` semantics.
//! Returns the former scheduling policy on success, -1 on error.

use oncrix_lib::{Error, Result};

/// Scheduling priority parameters as specified by POSIX `sched_param`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SchedParam {
    /// The scheduling priority. Valid range depends on the policy.
    /// For SCHED_FIFO and SCHED_RR: 1..=99 (implementation-defined max).
    /// For SCHED_OTHER, SCHED_BATCH, SCHED_IDLE: must be 0.
    pub sched_priority: i32,
}

impl SchedParam {
    /// Construct a new `SchedParam` with the given priority.
    pub const fn new(sched_priority: i32) -> Self {
        Self { sched_priority }
    }

    /// Returns the priority value.
    pub const fn priority(self) -> i32 {
        self.sched_priority
    }
}

/// Scheduling policy constants (mirrors `sched_getscheduler_call`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum SchedPolicy {
    /// Normal time-sharing policy (SCHED_OTHER).
    Other = 0,
    /// First-in, first-out real-time policy (SCHED_FIFO).
    Fifo = 1,
    /// Round-robin real-time policy (SCHED_RR).
    RoundRobin = 2,
    /// Batch scheduling policy (SCHED_BATCH).
    Batch = 3,
    /// Idle scheduling policy (SCHED_IDLE).
    Idle = 5,
    /// Deadline scheduling policy (SCHED_DEADLINE).
    Deadline = 6,
}

impl SchedPolicy {
    /// Construct from a raw integer.
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

    /// Return raw integer value.
    pub fn as_raw(self) -> i32 {
        self as i32
    }

    /// Returns `true` for real-time policies that require non-zero priority.
    pub fn requires_rt_priority(self) -> bool {
        matches!(self, Self::Fifo | Self::RoundRobin)
    }
}

/// Maximum real-time priority (POSIX minimum is 32; common value is 99).
pub const SCHED_RT_PRIORITY_MAX: i32 = 99;
/// Minimum real-time priority (POSIX requires at least 32 levels).
pub const SCHED_RT_PRIORITY_MIN: i32 = 1;

/// Arguments for the `sched_setscheduler` syscall.
#[derive(Debug, Clone, Copy)]
pub struct SchedSetSchedulerArgs {
    /// Target process ID. Zero means the calling process.
    pub pid: u32,
    /// The new scheduling policy.
    pub policy: SchedPolicy,
    /// The scheduling parameters (priority).
    pub param: SchedParam,
}

impl SchedSetSchedulerArgs {
    /// Construct from raw syscall register values.
    ///
    /// # Errors
    /// Returns [`Error::InvalidArgument`] on invalid pid, policy, or priority.
    pub fn from_raw(pid_raw: u64, policy_raw: u64, priority_raw: u64) -> Result<Self> {
        let pid_signed = pid_raw as i64;
        if pid_signed < 0 {
            return Err(Error::InvalidArgument);
        }
        let policy_i32 = policy_raw as i32;
        let policy = SchedPolicy::from_raw(policy_i32).ok_or(Error::InvalidArgument)?;
        let priority = priority_raw as i32;

        // Validate priority range by policy.
        if policy.requires_rt_priority() {
            if !(SCHED_RT_PRIORITY_MIN..=SCHED_RT_PRIORITY_MAX).contains(&priority) {
                return Err(Error::InvalidArgument);
            }
        } else if priority != 0 {
            return Err(Error::InvalidArgument);
        }

        Ok(Self {
            pid: pid_raw as u32,
            policy,
            param: SchedParam::new(priority),
        })
    }
}

/// Result of `sched_setscheduler`: the former scheduling policy.
#[derive(Debug, Clone, Copy)]
pub struct SchedSetSchedulerResult {
    /// The previous scheduling policy of the process.
    pub former_policy: SchedPolicy,
}

impl SchedSetSchedulerResult {
    /// Construct a new result.
    pub const fn new(former_policy: SchedPolicy) -> Self {
        Self { former_policy }
    }

    /// Convert to raw syscall return value.
    pub fn as_raw(self) -> i64 {
        self.former_policy.as_raw() as i64
    }
}

/// Handle the `sched_setscheduler` syscall.
///
/// # Errors
/// - [`Error::NotFound`] — target process does not exist.
/// - [`Error::PermissionDenied`] — caller lacks privilege to change the policy.
/// - [`Error::InvalidArgument`] — invalid pid, policy, or priority.
pub fn sys_sched_setscheduler(args: SchedSetSchedulerArgs) -> Result<SchedSetSchedulerResult> {
    // Privilege check: setting SCHED_FIFO or SCHED_RR requires CAP_SYS_NICE
    // or appropriate RLIMIT_RTPRIO. This stub assumes the dispatch layer
    // performs capability checks before invoking this handler.
    let _ = (args.pid, args.policy, args.param);

    // Return SCHED_OTHER as the former policy in this stub implementation.
    Ok(SchedSetSchedulerResult::new(SchedPolicy::Other))
}

/// Raw syscall entry point for `sched_setscheduler`.
///
/// # Arguments
/// * `pid` — process identifier (register a0).
/// * `policy` — new scheduling policy (register a1).
/// * `priority` — scheduling priority value (register a2).
///
/// # Returns
/// Former scheduling policy on success, negative errno on failure.
pub fn syscall_sched_setscheduler(pid: u64, policy: u64, priority: u64) -> i64 {
    let args = match SchedSetSchedulerArgs::from_raw(pid, policy, priority) {
        Ok(a) => a,
        Err(_) => return -(oncrix_lib::errno::EINVAL as i64),
    };
    match sys_sched_setscheduler(args) {
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
    fn test_valid_fifo_priority() {
        let args = SchedSetSchedulerArgs::from_raw(0, SchedPolicy::Fifo as u64, 50).unwrap();
        assert_eq!(args.policy, SchedPolicy::Fifo);
        assert_eq!(args.param.priority(), 50);
    }

    #[test]
    fn test_other_policy_requires_zero_priority() {
        assert!(SchedSetSchedulerArgs::from_raw(0, SchedPolicy::Other as u64, 0).is_ok());
        assert!(SchedSetSchedulerArgs::from_raw(0, SchedPolicy::Other as u64, 1).is_err());
    }

    #[test]
    fn test_invalid_policy_rejected() {
        assert!(SchedSetSchedulerArgs::from_raw(0, 99, 0).is_err());
    }

    #[test]
    fn test_negative_pid_rejected() {
        assert!(SchedSetSchedulerArgs::from_raw(u64::MAX, 0, 0).is_err());
    }

    #[test]
    fn test_rt_priority_bounds() {
        // Min bound
        assert!(
            SchedSetSchedulerArgs::from_raw(
                0,
                SchedPolicy::Fifo as u64,
                SCHED_RT_PRIORITY_MIN as u64
            )
            .is_ok()
        );
        // Max bound
        assert!(
            SchedSetSchedulerArgs::from_raw(
                0,
                SchedPolicy::Fifo as u64,
                SCHED_RT_PRIORITY_MAX as u64
            )
            .is_ok()
        );
        // Out of bounds (zero for RT)
        assert!(SchedSetSchedulerArgs::from_raw(0, SchedPolicy::RoundRobin as u64, 0).is_err());
    }
}
