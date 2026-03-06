// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `timer_gettime(2)` / `timer_settime(2)` / `timer_delete(2)` dispatch layer.
//!
//! POSIX per-process timers created with `timer_create(2)`.
//!
//! # Syscall signatures
//!
//! ```text
//! int timer_gettime(timer_t timerid, struct itimerspec *curr_value);
//! int timer_settime(timer_t timerid, int flags,
//!                   const struct itimerspec *new_value,
//!                   struct itimerspec *old_value);
//! int timer_delete(timer_t timerid);
//! ```
//!
//! # POSIX reference
//!
//! - POSIX.1-2024: `timer_gettime()`, `timer_settime()`, `timer_delete()`
//!   in `<time.h>`
//! - `.TheOpenGroup/susv5-html/functions/timer_gettime.html`
//!
//! # References
//!
//! - Linux: `kernel/time/posix-timers.c`
//! - `timer_gettime(2)`, `timer_settime(2)`, `timer_delete(2)` man pages

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Interpret `it_value` as an absolute time when set.
pub const TIMER_ABSTIME: i32 = 1;

/// Maximum timer ID value (kernel uses a 32-bit slot index).
const TIMER_ID_MAX: u32 = 0x0FFF_FFFF;

// ---------------------------------------------------------------------------
// Validation helpers
// ---------------------------------------------------------------------------

/// Returns `true` if `timerid` is in the plausible range.
pub fn is_valid_timerid(timerid: u32) -> bool {
    timerid <= TIMER_ID_MAX
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// Handle `timer_gettime(2)`.
///
/// Writes the current timer value and interval into `curr_value_ptr`.
///
/// # Errors
///
/// - [`Error::InvalidArgument`] — null `curr_value_ptr` or invalid `timerid`.
/// - [`Error::NotFound`] — `timerid` does not refer to an existing timer.
/// - [`Error::NotImplemented`] — stub.
pub fn sys_timer_gettime(timerid: u32, curr_value_ptr: u64) -> Result<i64> {
    if !is_valid_timerid(timerid) {
        return Err(Error::InvalidArgument);
    }
    if curr_value_ptr == 0 {
        return Err(Error::InvalidArgument);
    }
    let _ = (timerid, curr_value_ptr);
    Err(Error::NotImplemented)
}

/// Handle `timer_settime(2)`.
///
/// Sets the timer.  `old_value_ptr` may be null if the caller does not need
/// the previous setting.
///
/// # Errors
///
/// - [`Error::InvalidArgument`] — null `new_value_ptr`, unknown `flags`, or
///   invalid `timerid`.
/// - [`Error::NotFound`] — `timerid` does not refer to an existing timer.
/// - [`Error::NotImplemented`] — stub.
pub fn sys_timer_settime(
    timerid: u32,
    flags: i32,
    new_value_ptr: u64,
    old_value_ptr: u64,
) -> Result<i64> {
    if !is_valid_timerid(timerid) {
        return Err(Error::InvalidArgument);
    }
    if flags & !TIMER_ABSTIME != 0 {
        return Err(Error::InvalidArgument);
    }
    if new_value_ptr == 0 {
        return Err(Error::InvalidArgument);
    }
    let _ = (timerid, flags, new_value_ptr, old_value_ptr);
    Err(Error::NotImplemented)
}

/// Handle `timer_delete(2)`.
///
/// # Errors
///
/// - [`Error::InvalidArgument`] — invalid `timerid`.
/// - [`Error::NotFound`] — `timerid` does not refer to an existing timer.
/// - [`Error::NotImplemented`] — stub.
pub fn sys_timer_delete(timerid: u32) -> Result<i64> {
    if !is_valid_timerid(timerid) {
        return Err(Error::InvalidArgument);
    }
    let _ = timerid;
    Err(Error::NotImplemented)
}

/// Entry point for `timer_gettime` from the syscall dispatcher.
pub fn do_timer_gettime_call(timerid: u32, curr_value_ptr: u64) -> Result<i64> {
    sys_timer_gettime(timerid, curr_value_ptr)
}

/// Entry point for `timer_settime` from the syscall dispatcher.
pub fn do_timer_settime_call(
    timerid: u32,
    flags: i32,
    new_value_ptr: u64,
    old_value_ptr: u64,
) -> Result<i64> {
    sys_timer_settime(timerid, flags, new_value_ptr, old_value_ptr)
}

/// Entry point for `timer_delete` from the syscall dispatcher.
pub fn do_timer_delete_call(timerid: u32) -> Result<i64> {
    sys_timer_delete(timerid)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timer_gettime_null_ptr_rejected() {
        assert_eq!(sys_timer_gettime(0, 0).unwrap_err(), Error::InvalidArgument);
    }

    #[test]
    fn timer_settime_null_new_value_rejected() {
        assert_eq!(
            sys_timer_settime(0, 0, 0, 0x1000).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn timer_settime_unknown_flags_rejected() {
        assert_eq!(
            sys_timer_settime(0, 0xFF, 0x1000, 0).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn timer_settime_abstime_ok() {
        let r = sys_timer_settime(0, TIMER_ABSTIME, 0x1000, 0);
        assert_eq!(r.unwrap_err(), Error::NotImplemented);
    }

    #[test]
    fn timer_delete_reaches_stub() {
        let r = sys_timer_delete(0);
        assert_eq!(r.unwrap_err(), Error::NotImplemented);
    }
}
