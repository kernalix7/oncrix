// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `setitimer` and `getitimer` syscall implementations.
//!
//! `setitimer` arms a per-process interval timer that delivers a signal
//! when it expires. `getitimer` returns the remaining time.
//!
//! POSIX Reference: susv5 functions/setitimer.html
//! POSIX.1-2024 — both calls are mandatory.

use oncrix_lib::{Error, Result};

/// ITIMER_REAL: decrements in real (wall-clock) time; sends SIGALRM.
pub const ITIMER_REAL: i32 = 0;
/// ITIMER_VIRTUAL: decrements in user-mode CPU time; sends SIGVTALRM.
pub const ITIMER_VIRTUAL: i32 = 1;
/// ITIMER_PROF: decrements in user+kernel CPU time; sends SIGPROF.
pub const ITIMER_PROF: i32 = 2;

/// Timeval for use in interval timer structures (seconds + microseconds).
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct Timeval {
    /// Seconds component.
    pub tv_sec: i64,
    /// Microseconds component (0..999_999).
    pub tv_usec: i64,
}

impl Timeval {
    /// Create a zero Timeval.
    pub const fn zero() -> Self {
        Self {
            tv_sec: 0,
            tv_usec: 0,
        }
    }

    /// Create a Timeval from milliseconds.
    pub const fn from_millis(ms: u64) -> Self {
        Self {
            tv_sec: (ms / 1000) as i64,
            tv_usec: ((ms % 1000) * 1000) as i64,
        }
    }

    /// Check that microseconds are within valid range.
    pub fn is_valid(&self) -> bool {
        self.tv_usec >= 0 && self.tv_usec < 1_000_000 && self.tv_sec >= 0
    }

    /// Check if this timeval is zero (timer disarmed).
    pub fn is_zero(&self) -> bool {
        self.tv_sec == 0 && self.tv_usec == 0
    }

    /// Convert to microseconds (saturating on overflow).
    pub fn to_micros(&self) -> u64 {
        (self.tv_sec as u64)
            .saturating_mul(1_000_000)
            .saturating_add(self.tv_usec as u64)
    }
}

/// Interval timer value structure (mirrors `struct itimerval`).
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct ItimerVal {
    /// Reload interval (0 = one-shot timer).
    pub it_interval: Timeval,
    /// Time until next expiry (0 = disarmed).
    pub it_value: Timeval,
}

impl ItimerVal {
    /// Create a disarmed timer.
    pub const fn disarmed() -> Self {
        Self {
            it_interval: Timeval::zero(),
            it_value: Timeval::zero(),
        }
    }

    /// Create a one-shot timer expiring in `value`.
    pub const fn one_shot(value: Timeval) -> Self {
        Self {
            it_interval: Timeval::zero(),
            it_value: value,
        }
    }

    /// Create a periodic timer with given interval and initial value.
    pub const fn periodic(interval: Timeval, value: Timeval) -> Self {
        Self {
            it_interval: interval,
            it_value: value,
        }
    }

    /// Check if the timer is disarmed (it_value is zero).
    pub fn is_disarmed(&self) -> bool {
        self.it_value.is_zero()
    }

    /// Check if both Timeval fields are valid.
    pub fn is_valid(&self) -> bool {
        self.it_interval.is_valid() && self.it_value.is_valid()
    }
}

/// Arguments for the `setitimer` syscall.
#[derive(Debug)]
pub struct SetitimerArgs {
    /// Timer type (ITIMER_REAL, ITIMER_VIRTUAL, or ITIMER_PROF).
    pub which: i32,
    /// Pointer to the new timer value in user space.
    pub new_value_ptr: usize,
    /// Pointer to receive the old timer value in user space (may be 0).
    pub old_value_ptr: usize,
}

/// Arguments for the `getitimer` syscall.
#[derive(Debug)]
pub struct GetitimerArgs {
    /// Timer type (ITIMER_REAL, ITIMER_VIRTUAL, or ITIMER_PROF).
    pub which: i32,
    /// Pointer to receive the current timer value in user space.
    pub curr_value_ptr: usize,
}

/// Validate the `which` field for interval timer syscalls.
pub fn validate_itimer_which(which: i32) -> Result<()> {
    if !matches!(which, ITIMER_REAL | ITIMER_VIRTUAL | ITIMER_PROF) {
        return Err(Error::InvalidArgument);
    }
    Ok(())
}

/// Validate `setitimer` arguments.
pub fn validate_setitimer_args(args: &SetitimerArgs) -> Result<()> {
    validate_itimer_which(args.which)?;
    if args.new_value_ptr == 0 {
        return Err(Error::InvalidArgument);
    }
    Ok(())
}

/// Handle the `setitimer` syscall.
///
/// Sets the interval timer `which` to the value at `new_value_ptr`.
/// If `old_value_ptr` is non-null, writes the previous timer value there.
/// Setting `it_value` to zero disarms the timer.
///
/// Returns 0 on success, or an error.
pub fn sys_setitimer(args: &SetitimerArgs) -> Result<i64> {
    validate_setitimer_args(args)?;
    // Stub: real implementation would:
    // 1. copy_from_user the new ItimerVal; validate fields.
    // 2. Read and store the old timer state.
    // 3. Arm or disarm the hrtimer for the requested type.
    // 4. If old_value_ptr != 0: copy_to_user the old ItimerVal.
    // 5. Return 0.
    Err(Error::NotImplemented)
}

/// Handle the `getitimer` syscall.
///
/// Writes the current state of the timer `which` to `curr_value_ptr`.
/// The returned `it_value` shows the remaining time until expiry.
///
/// Returns 0 on success, or an error.
pub fn sys_getitimer(args: &GetitimerArgs) -> Result<i64> {
    validate_itimer_which(args.which)?;
    if args.curr_value_ptr == 0 {
        return Err(Error::InvalidArgument);
    }
    // Stub: real implementation reads the current hrtimer state and
    // copies the ItimerVal to user space.
    Err(Error::NotImplemented)
}

/// Map an itimer type to the signal it delivers on expiry.
pub fn itimer_signal(which: i32) -> Option<u32> {
    match which {
        ITIMER_REAL => Some(14),    // SIGALRM
        ITIMER_VIRTUAL => Some(26), // SIGVTALRM
        ITIMER_PROF => Some(27),    // SIGPROF
        _ => None,
    }
}
