// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `clock_getres(2)` syscall dispatch layer.
//!
//! Returns the resolution (precision) of the specified clock.  The
//! resolution is the smallest non-zero delta that the clock can represent.
//!
//! # Syscall signature
//!
//! ```text
//! int clock_getres(clockid_t clockid, struct timespec *res);
//! ```
//!
//! `res` may be null — in that case the call only validates `clockid`.
//!
//! # POSIX reference
//!
//! - POSIX.1-2024: `clock_getres()` in `<time.h>`
//! - `.TheOpenGroup/susv5-html/functions/clock_getres.html`
//!
//! # References
//!
//! - Linux: `kernel/time/posix-timers.c` (`sys_clock_getres`)
//! - `clock_getres(2)` man page

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Clock IDs (subset of commonly used)
// ---------------------------------------------------------------------------

/// System-wide real-time clock.
pub const CLOCK_REALTIME: u32 = 0;
/// Monotonic clock (cannot be set).
pub const CLOCK_MONOTONIC: u32 = 1;
/// CPU-time clock for the calling process.
pub const CLOCK_PROCESS_CPUTIME_ID: u32 = 2;
/// CPU-time clock for the calling thread.
pub const CLOCK_THREAD_CPUTIME_ID: u32 = 3;
/// Monotonic clock including suspend time.
pub const CLOCK_BOOTTIME: u32 = 7;
/// Real-time clock that wakes from suspend.
pub const CLOCK_REALTIME_ALARM: u32 = 8;
/// Boottime clock that wakes from suspend.
pub const CLOCK_BOOTTIME_ALARM: u32 = 9;
/// TAI (International Atomic Time) clock.
pub const CLOCK_TAI: u32 = 11;

// ---------------------------------------------------------------------------
// Validation helpers
// ---------------------------------------------------------------------------

/// Returns `true` if `clockid` is a supported clock identifier.
pub fn is_valid_clock(clockid: u32) -> bool {
    matches!(
        clockid,
        CLOCK_REALTIME
            | CLOCK_MONOTONIC
            | CLOCK_PROCESS_CPUTIME_ID
            | CLOCK_THREAD_CPUTIME_ID
            | CLOCK_BOOTTIME
            | CLOCK_REALTIME_ALARM
            | CLOCK_BOOTTIME_ALARM
            | CLOCK_TAI
    )
}

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

/// Handle `clock_getres(2)`.
///
/// # Errors
///
/// - [`Error::InvalidArgument`] — `clockid` is not a supported clock.
/// - [`Error::NotImplemented`] — stub.
pub fn sys_clock_getres(clockid: u32, res_ptr: u64) -> Result<i64> {
    if !is_valid_clock(clockid) {
        return Err(Error::InvalidArgument);
    }
    // res_ptr may be null (caller only wants to validate clockid).
    let _ = (clockid, res_ptr);
    Err(Error::NotImplemented)
}

/// Entry point called from the syscall dispatcher.
pub fn do_clock_getres_call(clockid: u32, res_ptr: u64) -> Result<i64> {
    sys_clock_getres(clockid, res_ptr)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_clock_rejected() {
        assert_eq!(
            sys_clock_getres(99, 0x1000).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn null_res_ok() {
        // Null res_ptr is allowed — caller just validates clockid.
        let r = sys_clock_getres(CLOCK_REALTIME, 0);
        assert_eq!(r.unwrap_err(), Error::NotImplemented);
    }

    #[test]
    fn all_known_clocks_valid() {
        for &id in &[
            CLOCK_REALTIME,
            CLOCK_MONOTONIC,
            CLOCK_PROCESS_CPUTIME_ID,
            CLOCK_THREAD_CPUTIME_ID,
            CLOCK_BOOTTIME,
            CLOCK_TAI,
        ] {
            assert!(is_valid_clock(id), "clock {id} should be valid");
        }
    }
}
