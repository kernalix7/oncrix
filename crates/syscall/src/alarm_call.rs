// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `alarm(2)` syscall dispatch layer.
//!
//! Arranges for a `SIGALRM` signal to be delivered to the calling process
//! after `seconds` real-time seconds have elapsed.  If `seconds` is 0 any
//! existing alarm is cancelled.  Only one alarm can be scheduled at a time;
//! a new call supersedes any previous alarm.
//!
//! # Syscall signature
//!
//! ```text
//! unsigned int alarm(unsigned int seconds);
//! ```
//!
//! Returns the number of seconds remaining until any previously scheduled
//! alarm would have been delivered, or 0 if there was no previous alarm.
//!
//! # POSIX reference
//!
//! - POSIX.1-2024: `alarm()` in `<unistd.h>`
//! - `.TheOpenGroup/susv5-html/functions/alarm.html`
//!
//! # References
//!
//! - Linux: `kernel/time/itimer.c` (`sys_alarm`)
//! - `alarm(2)` man page

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

/// Handle `alarm(2)`.
///
/// Any non-negative `seconds` value is valid; 0 cancels the alarm.
/// Returns the remaining time of the previous alarm (or 0).
///
/// # Errors
///
/// - [`Error::NotImplemented`] — stub; timer infrastructure not yet wired.
pub fn sys_alarm(seconds: u32) -> Result<i64> {
    let _ = seconds;
    Err(Error::NotImplemented)
}

/// Entry point called from the syscall dispatcher.
pub fn do_alarm_call(seconds: u32) -> Result<i64> {
    sys_alarm(seconds)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alarm_zero_cancels() {
        let r = sys_alarm(0);
        assert_eq!(r.unwrap_err(), Error::NotImplemented);
    }

    #[test]
    fn alarm_nonzero_schedules() {
        let r = sys_alarm(5);
        assert_eq!(r.unwrap_err(), Error::NotImplemented);
    }
}
