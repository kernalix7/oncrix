// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `sched_get_priority_max` and `sched_get_priority_min` syscall handlers.
//!
//! Returns the maximum or minimum priority value for the given scheduling policy.
//! POSIX.1-2024: `sched_get_priority_max()` and `sched_get_priority_min()` return
//! the maximum and minimum priority values supported for the given `policy`.
//!
//! # Priority Ranges (ONCRIX)
//! - `SCHED_FIFO`, `SCHED_RR`: min = 1, max = 99
//! - `SCHED_OTHER`, `SCHED_BATCH`, `SCHED_IDLE`: min = max = 0
//! - `SCHED_DEADLINE`: min = max = 0 (uses separate deadline parameters)
//!
//! # POSIX Conformance
//! Implements POSIX.1-2024 `sched_get_priority_max()` / `sched_get_priority_min()`.

use oncrix_lib::{Error, Result};

/// Scheduling policy identifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum SchedPolicy {
    /// Normal time-sharing (SCHED_OTHER).
    Other = 0,
    /// FIFO real-time (SCHED_FIFO).
    Fifo = 1,
    /// Round-robin real-time (SCHED_RR).
    RoundRobin = 2,
    /// Batch (SCHED_BATCH).
    Batch = 3,
    /// Idle (SCHED_IDLE).
    Idle = 5,
    /// Deadline (SCHED_DEADLINE).
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

    /// Returns the maximum scheduling priority for this policy.
    pub fn priority_max(self) -> i32 {
        match self {
            Self::Fifo | Self::RoundRobin => 99,
            _ => 0,
        }
    }

    /// Returns the minimum scheduling priority for this policy.
    pub fn priority_min(self) -> i32 {
        match self {
            Self::Fifo | Self::RoundRobin => 1,
            _ => 0,
        }
    }
}

/// Handle `sched_get_priority_max`.
///
/// # Errors
/// - [`Error::InvalidArgument`] — the policy value is not recognized.
pub fn sys_sched_get_priority_max(policy_raw: i32) -> Result<i32> {
    let policy = SchedPolicy::from_raw(policy_raw).ok_or(Error::InvalidArgument)?;
    Ok(policy.priority_max())
}

/// Handle `sched_get_priority_min`.
///
/// # Errors
/// - [`Error::InvalidArgument`] — the policy value is not recognized.
pub fn sys_sched_get_priority_min(policy_raw: i32) -> Result<i32> {
    let policy = SchedPolicy::from_raw(policy_raw).ok_or(Error::InvalidArgument)?;
    Ok(policy.priority_min())
}

/// Raw syscall entry point for `sched_get_priority_max`.
///
/// # Arguments
/// * `policy` — scheduling policy integer (register a0).
///
/// # Returns
/// Maximum priority value on success, -1 (EINVAL) on failure.
pub fn syscall_sched_get_priority_max(policy: u64) -> i64 {
    match sys_sched_get_priority_max(policy as i32) {
        Ok(max) => max as i64,
        Err(Error::InvalidArgument) => -(oncrix_lib::errno::EINVAL as i64),
        Err(_) => -(oncrix_lib::errno::EINVAL as i64),
    }
}

/// Raw syscall entry point for `sched_get_priority_min`.
///
/// # Arguments
/// * `policy` — scheduling policy integer (register a0).
///
/// # Returns
/// Minimum priority value on success, -1 (EINVAL) on failure.
pub fn syscall_sched_get_priority_min(policy: u64) -> i64 {
    match sys_sched_get_priority_min(policy as i32) {
        Ok(min) => min as i64,
        Err(Error::InvalidArgument) => -(oncrix_lib::errno::EINVAL as i64),
        Err(_) => -(oncrix_lib::errno::EINVAL as i64),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fifo_max_is_99() {
        assert_eq!(sys_sched_get_priority_max(1).unwrap(), 99);
    }

    #[test]
    fn test_fifo_min_is_1() {
        assert_eq!(sys_sched_get_priority_min(1).unwrap(), 1);
    }

    #[test]
    fn test_rr_max_is_99() {
        assert_eq!(sys_sched_get_priority_max(2).unwrap(), 99);
    }

    #[test]
    fn test_other_max_is_0() {
        assert_eq!(sys_sched_get_priority_max(0).unwrap(), 0);
    }

    #[test]
    fn test_other_min_is_0() {
        assert_eq!(sys_sched_get_priority_min(0).unwrap(), 0);
    }

    #[test]
    fn test_invalid_policy_rejected() {
        assert!(sys_sched_get_priority_max(99).is_err());
        assert!(sys_sched_get_priority_min(99).is_err());
    }

    #[test]
    fn test_idle_both_zero() {
        assert_eq!(sys_sched_get_priority_max(5).unwrap(), 0);
        assert_eq!(sys_sched_get_priority_min(5).unwrap(), 0);
    }
}
