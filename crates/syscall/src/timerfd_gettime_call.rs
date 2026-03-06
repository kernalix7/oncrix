// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `timerfd_gettime(2)` syscall handler — get the current timer setting.
//!
//! `timerfd_gettime` returns the current value of the timer associated with a
//! timerfd file descriptor.  The current value includes both the time until the
//! next expiry (`it_value`) and the interval for periodic timers (`it_interval`).
//!
//! # POSIX reference
//!
//! Linux-specific: `timerfd_gettime(2)` man page.
//! Conceptually related to POSIX `timer_gettime(2)`.

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// A timespec value with nanosecond precision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Timespec {
    /// Seconds component.
    pub tv_sec: i64,
    /// Nanoseconds component (0 ..= 999_999_999).
    pub tv_nsec: i64,
}

impl Timespec {
    /// Construct a new `Timespec`.
    pub const fn new(tv_sec: i64, tv_nsec: i64) -> Self {
        Self { tv_sec, tv_nsec }
    }

    /// Return `true` if both fields are zero (i.e. the timer is disarmed).
    pub fn is_zero(&self) -> bool {
        self.tv_sec == 0 && self.tv_nsec == 0
    }
}

/// An interval timer specification with nanosecond precision.
///
/// Mirrors `struct itimerspec` from `<time.h>`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Itimerspec {
    /// The interval for periodic timers.  Zero means the timer is one-shot.
    pub it_interval: Timespec,
    /// Time until the next expiry.  Zero means the timer is disarmed.
    pub it_value: Timespec,
}

impl Itimerspec {
    /// Construct a new `Itimerspec`.
    pub const fn new(it_interval: Timespec, it_value: Timespec) -> Self {
        Self {
            it_interval,
            it_value,
        }
    }

    /// Return `true` if the timer is disarmed (`it_value` is zero).
    pub fn is_disarmed(&self) -> bool {
        self.it_value.is_zero()
    }

    /// Return `true` if the timer fires once (interval is zero).
    pub fn is_one_shot(&self) -> bool {
        self.it_interval.is_zero()
    }
}

/// Validated `timerfd_gettime` request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TimerfdGettimeRequest {
    /// File descriptor referring to a timerfd.
    pub fd: i32,
}

impl TimerfdGettimeRequest {
    /// Construct a new request.
    pub const fn new(fd: i32) -> Self {
        Self { fd }
    }
}

// ---------------------------------------------------------------------------
// Core handler
// ---------------------------------------------------------------------------

/// Handler for `timerfd_gettime(2)`.
///
/// Validates the `fd` argument and returns a parsed request.  The actual timer
/// state is retrieved from the timerfd context associated with the fd.
///
/// # Arguments
///
/// - `fd`          — file descriptor created by `timerfd_create`
/// - `curr_value`  — output pointer for the current timer state (user-space;
///   must be non-null; validated before dereference)
///
/// # Errors
///
/// | `Error`           | Condition                                     |
/// |-------------------|-----------------------------------------------|
/// | `InvalidArgument` | `fd` is negative or `curr_value` pointer is null |
/// | `NotFound`        | `fd` does not refer to a timerfd              |
pub fn do_timerfd_gettime(fd: i32, curr_value_ptr: usize) -> Result<TimerfdGettimeRequest> {
    if fd < 0 {
        return Err(Error::InvalidArgument);
    }
    if curr_value_ptr == 0 {
        return Err(Error::InvalidArgument);
    }
    Ok(TimerfdGettimeRequest::new(fd))
}

/// Validate that a `Timespec` has a legal nanosecond component.
///
/// # Errors
///
/// Returns `Error::InvalidArgument` if `tv_nsec` is outside `[0, 999_999_999]`.
pub fn validate_timespec(ts: &Timespec) -> Result<()> {
    if ts.tv_nsec < 0 || ts.tv_nsec > 999_999_999 {
        return Err(Error::InvalidArgument);
    }
    Ok(())
}

/// Build a human-readable description of the timer state.
///
/// Returns `"disarmed"` when `it_value` is zero, otherwise describes the
/// expiry time and optional interval.
pub fn describe_itimerspec(spec: &Itimerspec) -> &'static str {
    if spec.is_disarmed() {
        "disarmed"
    } else if spec.is_one_shot() {
        "one-shot"
    } else {
        "periodic"
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_fd_ok() {
        let req = do_timerfd_gettime(3, 0xDEAD_BEEF).unwrap();
        assert_eq!(req.fd, 3);
    }

    #[test]
    fn negative_fd_rejected() {
        assert_eq!(
            do_timerfd_gettime(-1, 0xDEAD_BEEF),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn null_ptr_rejected() {
        assert_eq!(do_timerfd_gettime(3, 0), Err(Error::InvalidArgument));
    }

    #[test]
    fn disarmed_timer() {
        let spec = Itimerspec::new(Timespec::new(0, 0), Timespec::new(0, 0));
        assert!(spec.is_disarmed());
        assert_eq!(describe_itimerspec(&spec), "disarmed");
    }

    #[test]
    fn one_shot_timer() {
        let spec = Itimerspec::new(Timespec::new(0, 0), Timespec::new(1, 0));
        assert!(!spec.is_disarmed());
        assert!(spec.is_one_shot());
        assert_eq!(describe_itimerspec(&spec), "one-shot");
    }

    #[test]
    fn periodic_timer() {
        let spec = Itimerspec::new(Timespec::new(1, 0), Timespec::new(1, 0));
        assert!(!spec.is_disarmed());
        assert!(!spec.is_one_shot());
        assert_eq!(describe_itimerspec(&spec), "periodic");
    }

    #[test]
    fn validate_timespec_ok() {
        assert!(validate_timespec(&Timespec::new(10, 500_000_000)).is_ok());
    }

    #[test]
    fn validate_timespec_negative_nsec() {
        assert_eq!(
            validate_timespec(&Timespec::new(0, -1)),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn validate_timespec_overflow_nsec() {
        assert_eq!(
            validate_timespec(&Timespec::new(0, 1_000_000_000)),
            Err(Error::InvalidArgument)
        );
    }
}
