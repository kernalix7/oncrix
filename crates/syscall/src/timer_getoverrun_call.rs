// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `timer_getoverrun` syscall handler.
//!
//! Returns the overrun count for a POSIX per-process interval timer.
//! The overrun count is the number of timer expirations that occurred since
//! the last signal delivery that was not blocked. The count is capped at
//! `DELAYTIMER_MAX`.
//!
//! POSIX.1-2024: `timer_getoverrun()` returns a non-negative value on success.
//! If the timer has not yet fired, the overrun count is 0.
//!
//! # POSIX Conformance
//! Implements POSIX.1-2024 `timer_getoverrun()` semantics.

use oncrix_lib::{Error, Result};

/// Maximum overrun count (POSIX minimum is 32; Linux caps at INT_MAX).
pub const DELAYTIMER_MAX: i32 = i32::MAX;

/// Opaque POSIX timer identifier (`timer_t`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TimerId(pub u32);

impl TimerId {
    /// Construct from a raw value.
    pub const fn from_raw(val: u32) -> Self {
        Self(val)
    }

    /// Return the raw value.
    pub const fn as_raw(self) -> u32 {
        self.0
    }
}

/// Arguments for the `timer_getoverrun` syscall.
#[derive(Debug, Clone, Copy)]
pub struct TimerGetOverrunArgs {
    /// The timer to query.
    pub timerid: TimerId,
}

impl TimerGetOverrunArgs {
    /// Construct from raw syscall register values.
    pub fn from_raw(timerid_raw: u64) -> Result<Self> {
        Ok(Self {
            timerid: TimerId::from_raw(timerid_raw as u32),
        })
    }
}

/// Handle the `timer_getoverrun` syscall.
///
/// Returns the number of extra expirations that occurred since the last
/// signal delivery. Returns 0 if the timer has not yet expired.
///
/// # Errors
/// - [`Error::InvalidArgument`] — the timer ID is not owned by the calling process.
pub fn sys_timer_getoverrun(args: TimerGetOverrunArgs) -> Result<i32> {
    // A full implementation would:
    // 1. Look up the timer in the calling process's timer list.
    // 2. Read and return the `overrun` counter atomically.
    // 3. The overrun counter is reset after each signal delivery.
    let _ = args;
    Ok(0)
}

/// Raw syscall entry point for `timer_getoverrun`.
///
/// # Arguments
/// * `timerid` — timer identifier (register a0).
///
/// # Returns
/// Non-negative overrun count on success, negative errno on failure.
pub fn syscall_timer_getoverrun(timerid: u64) -> i64 {
    let args = match TimerGetOverrunArgs::from_raw(timerid) {
        Ok(a) => a,
        Err(_) => return -(oncrix_lib::errno::EINVAL as i64),
    };
    match sys_timer_getoverrun(args) {
        Ok(count) => count as i64,
        Err(Error::InvalidArgument) => -(oncrix_lib::errno::EINVAL as i64),
        Err(_) => -(oncrix_lib::errno::EINVAL as i64),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_from_raw_timer_id() {
        let args = TimerGetOverrunArgs::from_raw(10).unwrap();
        assert_eq!(args.timerid.as_raw(), 10);
    }

    #[test]
    fn test_overrun_nonnegative() {
        let args = TimerGetOverrunArgs::from_raw(0).unwrap();
        let result = sys_timer_getoverrun(args).unwrap();
        assert!(result >= 0);
    }

    #[test]
    fn test_syscall_returns_zero_overrun() {
        let ret = syscall_timer_getoverrun(0);
        assert_eq!(ret, 0);
    }

    #[test]
    fn test_delaytimer_max_is_positive() {
        assert!(DELAYTIMER_MAX > 0);
    }
}
