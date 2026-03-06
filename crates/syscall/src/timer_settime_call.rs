// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `timer_settime(2)` and `timer_gettime(2)` syscall dispatch layer.
//!
//! Arms/disarms or queries a POSIX per-process timer created by `timer_create(2)`.
//!
//! # Syscall signatures
//!
//! ```text
//! int timer_settime(timer_t timerid, int flags,
//!                   const struct itimerspec *new_value,
//!                   struct itimerspec *old_value);
//!
//! int timer_gettime(timer_t timerid, struct itimerspec *curr_value);
//! ```
//!
//! # POSIX reference
//!
//! - POSIX.1-2024: `timer_settime()` in `<time.h>`
//! - `.TheOpenGroup/susv5-html/functions/timer_settime.html`
//!
//! # References
//!
//! - Linux: `kernel/time/posix-timers.c`

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Flag: interpret `new_value` as an absolute time (not relative).
pub const TIMER_ABSTIME: i32 = 1;

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// Handle `timer_settime(2)`.
///
/// `timerid` is a timer ID returned by `timer_create(2)`.  `new_value_ptr`
/// is a user-space pointer to `struct itimerspec`; must be non-null.
/// `old_value_ptr` receives the previous timer setting; may be null.
///
/// # Errors
///
/// - [`Error::InvalidArgument`] — null `new_value_ptr` or unknown `flags` bits.
/// - [`Error::NotFound`] — `timerid` is invalid.
/// - [`Error::NotImplemented`] — stub.
pub fn sys_timer_settime(
    timerid: i32,
    flags: i32,
    new_value_ptr: u64,
    old_value_ptr: u64,
) -> Result<i64> {
    if new_value_ptr == 0 {
        return Err(Error::InvalidArgument);
    }
    if flags & !TIMER_ABSTIME != 0 {
        return Err(Error::InvalidArgument);
    }
    let _ = (timerid, flags, new_value_ptr, old_value_ptr);
    Err(Error::NotImplemented)
}

/// Handle `timer_gettime(2)`.
///
/// Retrieves the time until the timer `timerid` next fires and the reload
/// interval, writing them into `curr_value_ptr`.
///
/// # Errors
///
/// - [`Error::InvalidArgument`] — null `curr_value_ptr`.
/// - [`Error::NotFound`] — `timerid` is invalid.
/// - [`Error::NotImplemented`] — stub.
pub fn sys_timer_gettime(timerid: i32, curr_value_ptr: u64) -> Result<i64> {
    if curr_value_ptr == 0 {
        return Err(Error::InvalidArgument);
    }
    let _ = (timerid, curr_value_ptr);
    Err(Error::NotImplemented)
}

/// Entry point for `timer_settime` from the syscall dispatcher.
pub fn do_timer_settime_call(
    timerid: i32,
    flags: i32,
    new_value_ptr: u64,
    old_value_ptr: u64,
) -> Result<i64> {
    sys_timer_settime(timerid, flags, new_value_ptr, old_value_ptr)
}

/// Entry point for `timer_gettime` from the syscall dispatcher.
pub fn do_timer_gettime_call(timerid: i32, curr_value_ptr: u64) -> Result<i64> {
    sys_timer_gettime(timerid, curr_value_ptr)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn settime_null_new_value_rejected() {
        assert_eq!(
            sys_timer_settime(0, 0, 0, 0).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn settime_unknown_flags_rejected() {
        assert_eq!(
            sys_timer_settime(0, 0xFF, 0x1000, 0).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn settime_relative_reaches_stub() {
        let r = sys_timer_settime(1, 0, 0x1000, 0x2000);
        assert_eq!(r.unwrap_err(), Error::NotImplemented);
    }

    #[test]
    fn settime_abstime_reaches_stub() {
        let r = sys_timer_settime(1, TIMER_ABSTIME, 0x1000, 0);
        assert_eq!(r.unwrap_err(), Error::NotImplemented);
    }

    #[test]
    fn gettime_null_ptr_rejected() {
        assert_eq!(sys_timer_gettime(1, 0).unwrap_err(), Error::InvalidArgument);
    }

    #[test]
    fn gettime_valid_reaches_stub() {
        let r = sys_timer_gettime(1, 0x1000);
        assert_eq!(r.unwrap_err(), Error::NotImplemented);
    }
}
