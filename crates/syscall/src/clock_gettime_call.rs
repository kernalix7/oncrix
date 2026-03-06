// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `clock_gettime(2)` and `clock_settime(2)` syscall handlers.
//!
//! Retrieve or set the value of a POSIX clock.
//!
//! # POSIX Conformance
//!
//! Follows POSIX.1-2024 `clock_gettime()` / `clock_settime()`.  Key behaviours:
//! - `EINVAL` for unknown clock IDs.
//! - `EPERM` for `clock_settime` on clocks the caller cannot set.
//! - `CLOCK_REALTIME` is settable; monotonic clocks are not.
//! - Nanosecond field must be in `[0, 999_999_999]` for `settime`.
//!
//! # References
//!
//! - POSIX.1-2024: `clock_gettime()`, `clock_settime()`
//! - Linux man pages: `clock_gettime(2)`

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Clock IDs
// ---------------------------------------------------------------------------

/// Real-time clock (wall clock).
pub const CLOCK_REALTIME: i32 = 0;
/// Monotonic clock (cannot go backwards).
pub const CLOCK_MONOTONIC: i32 = 1;
/// Per-process CPU-time clock.
pub const CLOCK_PROCESS_CPUTIME_ID: i32 = 2;
/// Per-thread CPU-time clock.
pub const CLOCK_THREAD_CPUTIME_ID: i32 = 3;
/// Monotonic raw (not affected by NTP).
pub const CLOCK_MONOTONIC_RAW: i32 = 4;
/// Boot-time clock (includes suspend).
pub const CLOCK_BOOTTIME: i32 = 7;
/// Realtime alarm clock.
pub const CLOCK_REALTIME_ALARM: i32 = 8;
/// Boottime alarm clock.
pub const CLOCK_BOOTTIME_ALARM: i32 = 9;

/// Nanoseconds per second.
pub const NANOS_PER_SEC: i64 = 1_000_000_000;

// ---------------------------------------------------------------------------
// Timespec
// ---------------------------------------------------------------------------

/// POSIX `struct timespec`.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Timespec {
    /// Whole seconds.
    pub tv_sec: i64,
    /// Nanoseconds (0–999_999_999).
    pub tv_nsec: i64,
}

impl Timespec {
    /// Construct a new `Timespec`.
    pub const fn new(tv_sec: i64, tv_nsec: i64) -> Self {
        Self { tv_sec, tv_nsec }
    }

    /// Returns `true` if `tv_nsec` is in `[0, 999_999_999]`.
    pub fn is_valid(&self) -> bool {
        self.tv_nsec >= 0 && self.tv_nsec < NANOS_PER_SEC
    }
}

// ---------------------------------------------------------------------------
// Clock source
// ---------------------------------------------------------------------------

/// Kernel-side clock values provided to the handlers.
#[derive(Debug, Clone, Copy)]
pub struct ClockValues {
    /// Current CLOCK_REALTIME value.
    pub realtime: Timespec,
    /// Current CLOCK_MONOTONIC value.
    pub monotonic: Timespec,
    /// Current CLOCK_MONOTONIC_RAW value.
    pub monotonic_raw: Timespec,
    /// Current CLOCK_BOOTTIME value.
    pub boottime: Timespec,
    /// Per-process CPU time.
    pub process_cputime: Timespec,
    /// Per-thread CPU time.
    pub thread_cputime: Timespec,
}

// ---------------------------------------------------------------------------
// Core handlers
// ---------------------------------------------------------------------------

/// Handler for `clock_gettime(2)`.
///
/// Returns the current time for `clk_id` from `clocks`.
///
/// # Errors
///
/// | `Error`         | Condition              |
/// |-----------------|------------------------|
/// | `InvalidArgument` | Unknown clock ID     |
pub fn do_clock_gettime(clocks: &ClockValues, clk_id: i32) -> Result<Timespec> {
    match clk_id {
        CLOCK_REALTIME | CLOCK_REALTIME_ALARM => Ok(clocks.realtime),
        CLOCK_MONOTONIC => Ok(clocks.monotonic),
        CLOCK_MONOTONIC_RAW => Ok(clocks.monotonic_raw),
        CLOCK_BOOTTIME | CLOCK_BOOTTIME_ALARM => Ok(clocks.boottime),
        CLOCK_PROCESS_CPUTIME_ID => Ok(clocks.process_cputime),
        CLOCK_THREAD_CPUTIME_ID => Ok(clocks.thread_cputime),
        _ => Err(Error::InvalidArgument),
    }
}

/// Handler for `clock_settime(2)`.
///
/// Only `CLOCK_REALTIME` can be set; all other clocks return `EPERM`.
///
/// # Errors
///
/// | `Error`           | Condition                            |
/// |-------------------|--------------------------------------|
/// | `InvalidArgument` | Unknown clock ID or invalid timespec |
/// | `PermissionDenied`| Clock is not settable (`EPERM`)      |
pub fn do_clock_settime(
    clocks: &mut ClockValues,
    clk_id: i32,
    value: Timespec,
    privileged: bool,
) -> Result<()> {
    if !value.is_valid() {
        return Err(Error::InvalidArgument);
    }
    match clk_id {
        CLOCK_REALTIME => {
            if !privileged {
                return Err(Error::PermissionDenied);
            }
            clocks.realtime = value;
            Ok(())
        }
        CLOCK_MONOTONIC
        | CLOCK_MONOTONIC_RAW
        | CLOCK_BOOTTIME
        | CLOCK_PROCESS_CPUTIME_ID
        | CLOCK_THREAD_CPUTIME_ID => Err(Error::PermissionDenied),
        _ => Err(Error::InvalidArgument),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn clocks() -> ClockValues {
        let t = Timespec::new(1_700_000_000, 0);
        ClockValues {
            realtime: t,
            monotonic: Timespec::new(3600, 0),
            monotonic_raw: Timespec::new(3600, 100),
            boottime: Timespec::new(3601, 0),
            process_cputime: Timespec::new(0, 500_000_000),
            thread_cputime: Timespec::new(0, 100_000_000),
        }
    }

    #[test]
    fn gettime_realtime() {
        let c = clocks();
        let t = do_clock_gettime(&c, CLOCK_REALTIME).unwrap();
        assert_eq!(t.tv_sec, 1_700_000_000);
    }

    #[test]
    fn gettime_monotonic() {
        let c = clocks();
        let t = do_clock_gettime(&c, CLOCK_MONOTONIC).unwrap();
        assert_eq!(t.tv_sec, 3600);
    }

    #[test]
    fn gettime_invalid() {
        let c = clocks();
        assert_eq!(do_clock_gettime(&c, 999), Err(Error::InvalidArgument));
    }

    #[test]
    fn settime_realtime_privileged() {
        let mut c = clocks();
        let new = Timespec::new(2_000_000_000, 0);
        do_clock_settime(&mut c, CLOCK_REALTIME, new, true).unwrap();
        assert_eq!(c.realtime.tv_sec, 2_000_000_000);
    }

    #[test]
    fn settime_realtime_unprivileged_fails() {
        let mut c = clocks();
        assert_eq!(
            do_clock_settime(&mut c, CLOCK_REALTIME, Timespec::new(0, 0), false),
            Err(Error::PermissionDenied)
        );
    }

    #[test]
    fn settime_monotonic_fails() {
        let mut c = clocks();
        assert_eq!(
            do_clock_settime(&mut c, CLOCK_MONOTONIC, Timespec::new(0, 0), true),
            Err(Error::PermissionDenied)
        );
    }
}
