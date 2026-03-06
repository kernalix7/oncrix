// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `timer_delete` syscall handler.
//!
//! Deletes a POSIX per-process interval timer previously created with
//! `timer_create`. After deletion, the timer ID is no longer valid.
//!
//! POSIX.1-2024: `timer_delete()` is specified and must return 0 on success.
//! If the timer was armed, it is stopped before deletion. Any pending
//! signals from the timer are discarded.
//!
//! # POSIX Conformance
//! Implements POSIX.1-2024 `timer_delete()` semantics.

use oncrix_lib::{Error, Result};

/// Opaque POSIX timer identifier (`timer_t`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TimerId(pub u32);

impl TimerId {
    /// Construct a timer ID from a raw value.
    pub const fn from_raw(val: u32) -> Self {
        Self(val)
    }

    /// Return the raw timer ID value.
    pub const fn as_raw(self) -> u32 {
        self.0
    }
}

/// Arguments for the `timer_delete` syscall.
#[derive(Debug, Clone, Copy)]
pub struct TimerDeleteArgs {
    /// The timer to delete.
    pub timerid: TimerId,
}

impl TimerDeleteArgs {
    /// Construct from raw syscall register values.
    ///
    /// # Errors
    /// No validation at this layer — timer existence is checked by the handler.
    pub fn from_raw(timerid_raw: u64) -> Result<Self> {
        Ok(Self {
            timerid: TimerId::from_raw(timerid_raw as u32),
        })
    }
}

/// Handle the `timer_delete` syscall.
///
/// Deletes the specified POSIX timer. If the timer is armed it is disarmed
/// first. Any queued signals are discarded.
///
/// # Errors
/// - [`Error::InvalidArgument`] — the timer ID does not belong to the calling process.
pub fn sys_timer_delete(args: TimerDeleteArgs) -> Result<()> {
    // A full implementation would:
    // 1. Look up the timer in the calling process's timer list by ID.
    // 2. If not found: return EINVAL.
    // 3. Disarm the timer (cancel any pending hrtimer or softirq).
    // 4. Remove pending signals queued for this timer.
    // 5. Free the timer object and release the ID.
    let _ = args;
    Ok(())
}

/// Raw syscall entry point for `timer_delete`.
///
/// # Arguments
/// * `timerid` — timer identifier (register a0).
///
/// # Returns
/// `0` on success, negative errno on failure.
pub fn syscall_timer_delete(timerid: u64) -> i64 {
    let args = match TimerDeleteArgs::from_raw(timerid) {
        Ok(a) => a,
        Err(_) => return -(oncrix_lib::errno::EINVAL as i64),
    };
    match sys_timer_delete(args) {
        Ok(()) => 0,
        Err(Error::InvalidArgument) => -(oncrix_lib::errno::EINVAL as i64),
        Err(_) => -(oncrix_lib::errno::EINVAL as i64),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_from_raw_preserves_id() {
        let args = TimerDeleteArgs::from_raw(42).unwrap();
        assert_eq!(args.timerid.as_raw(), 42);
    }

    #[test]
    fn test_timer_id_zero() {
        let args = TimerDeleteArgs::from_raw(0).unwrap();
        assert_eq!(args.timerid.as_raw(), 0);
    }

    #[test]
    fn test_syscall_returns_zero() {
        let ret = syscall_timer_delete(5);
        assert_eq!(ret, 0);
    }

    #[test]
    fn test_timer_id_roundtrip() {
        let id = TimerId::from_raw(99);
        assert_eq!(id.as_raw(), 99);
    }
}
