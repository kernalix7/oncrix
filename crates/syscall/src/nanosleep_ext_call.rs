// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Extended nanosleep / clock_nanosleep dispatch.
//!
//! Provides validation, remainder computation, and sleep-state management
//! shared by `nanosleep(2)` and `clock_nanosleep(2)`.
//!
//! # Syscall signatures
//!
//! ```text
//! int nanosleep(const struct timespec *req, struct timespec *rem);
//! int clock_nanosleep(clockid_t clockid, int flags,
//!                     const struct timespec *request,
//!                     struct timespec *remain);
//! ```
//!
//! # POSIX reference
//!
//! POSIX.1-2024 §nanosleep, §clock_nanosleep — `<time.h>`.
//!
//! # References
//!
//! - Linux: `kernel/time/hrtimer.c`, `kernel/time/posix-timers.c`
//! - `nanosleep(2)`, `clock_nanosleep(2)` man pages

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Clock IDs
// ---------------------------------------------------------------------------

/// Realtime system-wide clock.
pub const CLOCK_REALTIME: u32 = 0;
/// Monotonic clock (cannot be set).
pub const CLOCK_MONOTONIC: u32 = 1;
/// Process CPU clock.
pub const CLOCK_PROCESS_CPUTIME_ID: u32 = 2;
/// Thread CPU clock.
pub const CLOCK_THREAD_CPUTIME_ID: u32 = 3;
/// Monotonic raw (not subject to NTP).
pub const CLOCK_MONOTONIC_RAW: u32 = 4;
/// Boottime clock (includes suspend).
pub const CLOCK_BOOTTIME: u32 = 7;
/// Realtime alarm clock.
pub const CLOCK_REALTIME_ALARM: u32 = 8;
/// Boottime alarm clock.
pub const CLOCK_BOOTTIME_ALARM: u32 = 9;

/// Maximum recognised clock ID.
const CLOCKID_MAX: u32 = 11;

// ---------------------------------------------------------------------------
// Flags for clock_nanosleep
// ---------------------------------------------------------------------------

/// Use an absolute time specification (vs. relative).
pub const TIMER_ABSTIME: i32 = 1;

/// Mask of recognised flags.
const CLOCK_NANOSLEEP_FLAGS: i32 = TIMER_ABSTIME;

// ---------------------------------------------------------------------------
// Timespec — nanosecond-resolution time
// ---------------------------------------------------------------------------

/// POSIX `struct timespec`.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Timespec {
    /// Seconds component.
    pub tv_sec: i64,
    /// Nanoseconds component (0..999_999_999).
    pub tv_nsec: i64,
}

impl Timespec {
    /// Validate that the timespec is well-formed.
    ///
    /// Rejects negative seconds or nanoseconds, or nanoseconds >= 1_000_000_000.
    pub fn validate(&self) -> Result<()> {
        if self.tv_sec < 0 {
            return Err(Error::InvalidArgument);
        }
        if self.tv_nsec < 0 || self.tv_nsec >= 1_000_000_000 {
            return Err(Error::InvalidArgument);
        }
        Ok(())
    }

    /// Convert to total nanoseconds (saturates at u64::MAX).
    pub const fn to_ns(&self) -> u64 {
        (self.tv_sec as u64)
            .saturating_mul(1_000_000_000)
            .saturating_add(self.tv_nsec as u64)
    }

    /// Construct from nanoseconds.
    pub const fn from_ns(ns: u64) -> Self {
        Self {
            tv_sec: (ns / 1_000_000_000) as i64,
            tv_nsec: (ns % 1_000_000_000) as i64,
        }
    }

    /// Return `true` if this is a zero duration.
    pub const fn is_zero(&self) -> bool {
        self.tv_sec == 0 && self.tv_nsec == 0
    }

    /// Compute the remaining time: `self - elapsed` (clamped to 0).
    pub fn remaining(&self, elapsed_ns: u64) -> Self {
        let total = self.to_ns();
        if elapsed_ns >= total {
            Self::default()
        } else {
            Self::from_ns(total - elapsed_ns)
        }
    }
}

// ---------------------------------------------------------------------------
// SleepRequest — parsed sleep descriptor
// ---------------------------------------------------------------------------

/// Parsed and validated sleep request.
#[derive(Debug, Clone, Copy)]
pub struct SleepRequest {
    /// Clock used for the sleep.
    pub clockid: u32,
    /// Whether the time is absolute.
    pub absolute: bool,
    /// Requested sleep time.
    pub request: Timespec,
}

// ---------------------------------------------------------------------------
// SleepState — in-progress sleep tracking
// ---------------------------------------------------------------------------

/// State of a thread currently sleeping in `nanosleep` or `clock_nanosleep`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SleepState {
    /// Currently sleeping; `remaining_ns` until expiry.
    Sleeping { remaining_ns: u64 },
    /// Sleep completed normally.
    Expired,
    /// Sleep was interrupted by a signal.
    Interrupted { remaining_ns: u64 },
}

// ---------------------------------------------------------------------------
// Validation helpers
// ---------------------------------------------------------------------------

/// Validate a clock ID for `clock_nanosleep`.
///
/// Process and thread CPU clocks are not supported for `clock_nanosleep`.
fn validate_clockid(clockid: u32) -> Result<()> {
    if clockid > CLOCKID_MAX {
        return Err(Error::InvalidArgument);
    }
    // Process/thread CPU clocks are disallowed for nanosleep.
    if clockid == CLOCK_PROCESS_CPUTIME_ID || clockid == CLOCK_THREAD_CPUTIME_ID {
        return Err(Error::InvalidArgument);
    }
    Ok(())
}

/// Validate `clock_nanosleep` flags.
fn validate_flags(flags: i32) -> Result<()> {
    if flags & !CLOCK_NANOSLEEP_FLAGS != 0 {
        return Err(Error::InvalidArgument);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// sys_nanosleep — entry point
// ---------------------------------------------------------------------------

/// Handler for `nanosleep(2)`.
///
/// Validates the request timespec.  Returns the duration to sleep in
/// nanoseconds.  If interrupted, the caller must provide the remaining
/// duration via [`compute_remainder`].
///
/// # Errors
///
/// [`Error::InvalidArgument`] for invalid timespec.
pub fn sys_nanosleep(request: &Timespec) -> Result<u64> {
    request.validate()?;
    Ok(request.to_ns())
}

// ---------------------------------------------------------------------------
// sys_clock_nanosleep — entry point
// ---------------------------------------------------------------------------

/// Handler for `clock_nanosleep(2)`.
///
/// Returns a [`SleepRequest`] describing the validated sleep parameters.
///
/// # Arguments
///
/// * `clockid`  — Clock to use.
/// * `flags`    — `0` (relative) or `TIMER_ABSTIME` (absolute).
/// * `request`  — Requested sleep time.
///
/// # Errors
///
/// * [`Error::InvalidArgument`] — invalid clockid, flags, or timespec.
pub fn sys_clock_nanosleep(clockid: u32, flags: i32, request: &Timespec) -> Result<SleepRequest> {
    validate_clockid(clockid)?;
    validate_flags(flags)?;
    request.validate()?;
    Ok(SleepRequest {
        clockid,
        absolute: flags & TIMER_ABSTIME != 0,
        request: *request,
    })
}

// ---------------------------------------------------------------------------
// compute_remainder — remaining sleep after interruption
// ---------------------------------------------------------------------------

/// Compute the remaining sleep after `elapsed_ns` nanoseconds have passed.
///
/// Used to fill `*rem` in `nanosleep` when interrupted by a signal.
pub fn compute_remainder(request: &Timespec, elapsed_ns: u64) -> Timespec {
    request.remaining(elapsed_ns)
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nanosleep_valid() {
        let req = Timespec {
            tv_sec: 1,
            tv_nsec: 500_000_000,
        };
        let ns = sys_nanosleep(&req).unwrap();
        assert_eq!(ns, 1_500_000_000);
    }

    #[test]
    fn nanosleep_zero() {
        let req = Timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        let ns = sys_nanosleep(&req).unwrap();
        assert_eq!(ns, 0);
    }

    #[test]
    fn nanosleep_negative_sec() {
        let req = Timespec {
            tv_sec: -1,
            tv_nsec: 0,
        };
        assert_eq!(sys_nanosleep(&req), Err(Error::InvalidArgument));
    }

    #[test]
    fn nanosleep_nsec_too_large() {
        let req = Timespec {
            tv_sec: 0,
            tv_nsec: 1_000_000_000,
        };
        assert_eq!(sys_nanosleep(&req), Err(Error::InvalidArgument));
    }

    #[test]
    fn clock_nanosleep_monotonic() {
        let req = Timespec {
            tv_sec: 0,
            tv_nsec: 100_000,
        };
        let sr = sys_clock_nanosleep(CLOCK_MONOTONIC, 0, &req).unwrap();
        assert_eq!(sr.clockid, CLOCK_MONOTONIC);
        assert!(!sr.absolute);
    }

    #[test]
    fn clock_nanosleep_abstime() {
        let req = Timespec {
            tv_sec: 1000,
            tv_nsec: 0,
        };
        let sr = sys_clock_nanosleep(CLOCK_REALTIME, TIMER_ABSTIME, &req).unwrap();
        assert!(sr.absolute);
    }

    #[test]
    fn clock_nanosleep_cpu_clock_rejected() {
        let req = Timespec {
            tv_sec: 0,
            tv_nsec: 1,
        };
        assert_eq!(
            sys_clock_nanosleep(CLOCK_PROCESS_CPUTIME_ID, 0, &req),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn clock_nanosleep_unknown_flag() {
        let req = Timespec {
            tv_sec: 0,
            tv_nsec: 1,
        };
        assert_eq!(
            sys_clock_nanosleep(CLOCK_MONOTONIC, 0xFF, &req),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn compute_remainder_partial() {
        let req = Timespec {
            tv_sec: 1,
            tv_nsec: 0,
        };
        let rem = compute_remainder(&req, 400_000_000);
        assert_eq!(rem.to_ns(), 600_000_000);
    }

    #[test]
    fn compute_remainder_expired() {
        let req = Timespec {
            tv_sec: 0,
            tv_nsec: 100,
        };
        let rem = compute_remainder(&req, 200);
        assert!(rem.is_zero());
    }
}
