// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `getitimer(2)` / `setitimer(2)` syscall dispatch layer.
//!
//! Gets or sets the value of one of the three per-process interval timers.
//! Interval timers send a signal to the process when they expire and, if
//! the interval is non-zero, restart automatically.
//!
//! # Syscall signatures
//!
//! ```text
//! int getitimer(int which, struct itimerval *curr_value);
//! int setitimer(int which, const struct itimerval *new_value,
//!               struct itimerval *old_value);
//! ```
//!
//! # Timer types
//!
//! | Constant        | Value | Signal    | Description |
//! |-----------------|-------|-----------|-------------|
//! | `ITIMER_REAL`   | 0     | `SIGALRM` | Wall-clock time |
//! | `ITIMER_VIRTUAL`| 1     | `SIGVTALRM` | Process CPU time |
//! | `ITIMER_PROF`   | 2     | `SIGPROF` | Process + system CPU time |
//!
//! # POSIX reference
//!
//! - POSIX.1-2024: `getitimer()`, `setitimer()` in `<sys/time.h>`
//!
//! # References
//!
//! - Linux: `kernel/time/itimer.c`
//! - `getitimer(2)` man page

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Real-time (wall-clock) interval timer; delivers `SIGALRM`.
pub const ITIMER_REAL: i32 = 0;
/// Virtual (process CPU time) interval timer; delivers `SIGVTALRM`.
pub const ITIMER_VIRTUAL: i32 = 1;
/// Profiling (process + kernel CPU time) interval timer; delivers `SIGPROF`.
pub const ITIMER_PROF: i32 = 2;

// ---------------------------------------------------------------------------
// Validation helpers
// ---------------------------------------------------------------------------

/// Returns `true` if `which` is a valid interval timer type.
pub fn is_valid_which(which: i32) -> bool {
    matches!(which, ITIMER_REAL | ITIMER_VIRTUAL | ITIMER_PROF)
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// Handle `getitimer(2)`.
///
/// # Errors
///
/// - [`Error::InvalidArgument`] — unknown `which` or null `curr_value_ptr`.
/// - [`Error::NotImplemented`] — stub.
pub fn sys_getitimer(which: i32, curr_value_ptr: u64) -> Result<i64> {
    if !is_valid_which(which) {
        return Err(Error::InvalidArgument);
    }
    if curr_value_ptr == 0 {
        return Err(Error::InvalidArgument);
    }
    let _ = (which, curr_value_ptr);
    Err(Error::NotImplemented)
}

/// Handle `setitimer(2)`.
///
/// `old_value_ptr` may be null when the caller does not need the previous
/// setting.  `new_value_ptr` must be non-null.
///
/// # Errors
///
/// - [`Error::InvalidArgument`] — unknown `which` or null `new_value_ptr`.
/// - [`Error::NotImplemented`] — stub.
pub fn sys_setitimer(which: i32, new_value_ptr: u64, old_value_ptr: u64) -> Result<i64> {
    if !is_valid_which(which) {
        return Err(Error::InvalidArgument);
    }
    if new_value_ptr == 0 {
        return Err(Error::InvalidArgument);
    }
    let _ = (which, new_value_ptr, old_value_ptr);
    Err(Error::NotImplemented)
}

/// Entry point for `getitimer` from the syscall dispatcher.
pub fn do_getitimer_call(which: i32, curr_value_ptr: u64) -> Result<i64> {
    sys_getitimer(which, curr_value_ptr)
}

/// Entry point for `setitimer` from the syscall dispatcher.
pub fn do_setitimer_call(which: i32, new_value_ptr: u64, old_value_ptr: u64) -> Result<i64> {
    sys_setitimer(which, new_value_ptr, old_value_ptr)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_which_rejected() {
        assert_eq!(
            sys_getitimer(99, 0x1000).unwrap_err(),
            Error::InvalidArgument
        );
        assert_eq!(
            sys_setitimer(99, 0x1000, 0).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn null_curr_value_rejected() {
        assert_eq!(
            sys_getitimer(ITIMER_REAL, 0).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn null_new_value_rejected() {
        assert_eq!(
            sys_setitimer(ITIMER_REAL, 0, 0x1000).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn getitimer_reaches_stub() {
        let r = sys_getitimer(ITIMER_REAL, 0x1000);
        assert_eq!(r.unwrap_err(), Error::NotImplemented);
    }

    #[test]
    fn setitimer_null_old_ok() {
        let r = sys_setitimer(ITIMER_VIRTUAL, 0x1000, 0);
        assert_eq!(r.unwrap_err(), Error::NotImplemented);
    }
}
