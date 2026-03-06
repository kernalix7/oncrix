// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `adjtimex(2)` and `clock_adjtime(2)` syscall dispatch layer.
//!
//! Tunes kernel clock parameters (NTP-style frequency and offset adjustments).
//!
//! # Syscall signatures
//!
//! ```text
//! int adjtimex(struct timex *buf);
//! int clock_adjtime(clockid_t clk_id, struct timex *buf);
//! ```
//!
//! # References
//!
//! - Linux: `kernel/time/ntp.c` (`sys_adjtimex`, `sys_clock_adjtime`)
//! - `adjtimex(2)` man page

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Mode flag: time offset (ADJ_OFFSET / MOD_OFFSET).
pub const ADJ_OFFSET: u32 = 0x0001;
/// Mode flag: frequency (ADJ_FREQUENCY / MOD_FREQUENCY).
pub const ADJ_FREQUENCY: u32 = 0x0002;
/// Mode flag: maximum time error (ADJ_MAXERROR).
pub const ADJ_MAXERROR: u32 = 0x0004;
/// Mode flag: estimated time error (ADJ_ESTERROR).
pub const ADJ_ESTERROR: u32 = 0x0008;
/// Mode flag: clock status (ADJ_STATUS).
pub const ADJ_STATUS: u32 = 0x0010;
/// Mode flag: PLL time constant (ADJ_TIMECONST).
pub const ADJ_TIMECONST: u32 = 0x0020;
/// Mode flag: set TAI offset (ADJ_TAI).
pub const ADJ_TAI: u32 = 0x0080;
/// Mode flag: set tick value (ADJ_TICK).
pub const ADJ_TICK: u32 = 0x4000;

/// Clock ID: REALTIME.
pub const CLOCK_REALTIME: i32 = 0;
/// Clock ID: TAI.
pub const CLOCK_TAI: i32 = 11;

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// Handle `adjtimex(2)`.
///
/// `buf_ptr` is a user-space pointer to `struct timex`.  The kernel reads
/// the `modes` field and applies the requested adjustments, then fills the
/// remaining fields with the current clock state.
///
/// Returns the clock state (TIME_OK, TIME_INS, TIME_DEL, TIME_OOP, TIME_WAIT,
/// TIME_ERROR), encoded as an i64.
///
/// # Errors
///
/// - [`Error::InvalidArgument`] — null `buf_ptr`.
/// - [`Error::PermissionDenied`] — adjustment requires `CAP_SYS_TIME`.
/// - [`Error::NotImplemented`] — stub.
pub fn sys_adjtimex(buf_ptr: u64) -> Result<i64> {
    if buf_ptr == 0 {
        return Err(Error::InvalidArgument);
    }
    let _ = buf_ptr;
    Err(Error::NotImplemented)
}

/// Handle `clock_adjtime(2)`.
///
/// Like `adjtimex` but targets a specific clock.  Currently only
/// `CLOCK_REALTIME` and `CLOCK_TAI` are adjustable.
///
/// # Errors
///
/// - [`Error::InvalidArgument`] — null `buf_ptr` or unsupported `clk_id`.
/// - [`Error::PermissionDenied`] — requires `CAP_SYS_TIME`.
/// - [`Error::NotImplemented`] — stub.
pub fn sys_clock_adjtime(clk_id: i32, buf_ptr: u64) -> Result<i64> {
    if buf_ptr == 0 {
        return Err(Error::InvalidArgument);
    }
    if clk_id != CLOCK_REALTIME && clk_id != CLOCK_TAI {
        return Err(Error::InvalidArgument);
    }
    let _ = (clk_id, buf_ptr);
    Err(Error::NotImplemented)
}

/// Entry point for `adjtimex` from the syscall dispatcher.
pub fn do_adjtimex_call(buf_ptr: u64) -> Result<i64> {
    sys_adjtimex(buf_ptr)
}

/// Entry point for `clock_adjtime` from the syscall dispatcher.
pub fn do_clock_adjtime_call(clk_id: i32, buf_ptr: u64) -> Result<i64> {
    sys_clock_adjtime(clk_id, buf_ptr)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adjtimex_null_buf_rejected() {
        assert_eq!(sys_adjtimex(0).unwrap_err(), Error::InvalidArgument);
    }

    #[test]
    fn adjtimex_valid_reaches_stub() {
        let r = sys_adjtimex(0x1000);
        assert_eq!(r.unwrap_err(), Error::NotImplemented);
    }

    #[test]
    fn clock_adjtime_null_buf_rejected() {
        assert_eq!(
            sys_clock_adjtime(CLOCK_REALTIME, 0).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn clock_adjtime_unsupported_clock_rejected() {
        assert_eq!(
            sys_clock_adjtime(99, 0x1000).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn clock_adjtime_tai_reaches_stub() {
        let r = sys_clock_adjtime(CLOCK_TAI, 0x1000);
        assert_eq!(r.unwrap_err(), Error::NotImplemented);
    }
}
