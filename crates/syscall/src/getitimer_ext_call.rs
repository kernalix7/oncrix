// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Extended `getitimer` syscall handler.
//!
//! Returns the current value of an interval timer. This module covers all
//! three POSIX interval timers:
//! - `ITIMER_REAL` (0) — decrements in real time; delivers `SIGALRM`.
//! - `ITIMER_VIRTUAL` (1) — decrements when the process is executing; delivers `SIGVTALRM`.
//! - `ITIMER_PROF` (2) — decrements when the process or kernel is executing; delivers `SIGPROF`.
//!
//! POSIX.1-2024: `getitimer()` is marked obsolescent in favor of `timer_gettime()`.
//! This implementation follows Linux semantics.

use oncrix_lib::{Error, Result};

/// `ITIMER_REAL` — real-time interval timer.
pub const ITIMER_REAL: u32 = 0;
/// `ITIMER_VIRTUAL` — virtual (user-time) interval timer.
pub const ITIMER_VIRTUAL: u32 = 1;
/// `ITIMER_PROF` — profiling interval timer.
pub const ITIMER_PROF: u32 = 2;

/// Kernel-side `struct timeval` (seconds + microseconds).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(C)]
pub struct TimeVal {
    /// Seconds.
    pub tv_sec: i64,
    /// Microseconds (0..999_999).
    pub tv_usec: i64,
}

impl TimeVal {
    /// Construct a new `TimeVal`.
    pub const fn new(tv_sec: i64, tv_usec: i64) -> Self {
        Self { tv_sec, tv_usec }
    }

    /// Returns `true` if both fields are zero (timer not set).
    pub fn is_zero(self) -> bool {
        self.tv_sec == 0 && self.tv_usec == 0
    }
}

/// Kernel-side `struct itimerval`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(C)]
pub struct ItimerVal {
    /// Interval to reload after expiration; 0 = one-shot.
    pub it_interval: TimeVal,
    /// Time remaining until the next expiration.
    pub it_value: TimeVal,
}

impl ItimerVal {
    /// Construct a new `ItimerVal`.
    pub const fn new(it_interval: TimeVal, it_value: TimeVal) -> Self {
        Self {
            it_interval,
            it_value,
        }
    }

    /// Returns `true` if the timer is disarmed (`it_value` is zero).
    pub fn is_disarmed(self) -> bool {
        self.it_value.is_zero()
    }
}

/// Arguments for the extended `getitimer` syscall.
#[derive(Debug, Clone, Copy)]
pub struct GetitimerExtArgs {
    /// Timer type: `ITIMER_REAL`, `ITIMER_VIRTUAL`, or `ITIMER_PROF`.
    pub which: u32,
    /// User-space pointer to write `struct itimerval`.
    pub curr_value_ptr: u64,
}

impl GetitimerExtArgs {
    /// Construct from raw syscall register values.
    ///
    /// # Errors
    /// - [`Error::InvalidArgument`] — unknown timer type or null pointer.
    pub fn from_raw(which_raw: u64, curr_value_ptr: u64) -> Result<Self> {
        let which = which_raw as u32;
        if which > ITIMER_PROF {
            return Err(Error::InvalidArgument);
        }
        if curr_value_ptr == 0 {
            return Err(Error::InvalidArgument);
        }
        Ok(Self {
            which,
            curr_value_ptr,
        })
    }
}

/// Handle the extended `getitimer` syscall.
///
/// Returns the current state of the specified interval timer.
///
/// # Errors
/// - [`Error::InvalidArgument`] — unknown timer type or null pointer.
pub fn sys_getitimer_ext(args: GetitimerExtArgs) -> Result<ItimerVal> {
    // A full implementation would:
    // 1. Select the appropriate itimer (real/virtual/prof) from the task struct.
    // 2. Read the remaining time (`it_value`) and the reload interval.
    // 3. Copy the itimerval to user space via copy_to_user.
    let _ = args;
    Ok(ItimerVal::default())
}

/// Raw syscall entry point for extended `getitimer`.
///
/// # Arguments
/// * `which` — timer type (register a0): 0=REAL, 1=VIRTUAL, 2=PROF.
/// * `curr_value_ptr` — pointer to `struct itimerval` output (register a1).
///
/// # Returns
/// `0` on success, negative errno on failure.
pub fn syscall_getitimer_ext(which: u64, curr_value_ptr: u64) -> i64 {
    let args = match GetitimerExtArgs::from_raw(which, curr_value_ptr) {
        Ok(a) => a,
        Err(_) => return -(oncrix_lib::errno::EINVAL as i64),
    };
    match sys_getitimer_ext(args) {
        Ok(_val) => {
            // Real implementation: copy val to curr_value_ptr.
            0
        }
        Err(Error::InvalidArgument) => -(oncrix_lib::errno::EINVAL as i64),
        Err(_) => -(oncrix_lib::errno::EINVAL as i64),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_unknown_which_rejected() {
        assert!(GetitimerExtArgs::from_raw(3, 0x1000).is_err());
    }

    #[test]
    fn test_null_ptr_rejected() {
        assert!(GetitimerExtArgs::from_raw(ITIMER_REAL as u64, 0).is_err());
    }

    #[test]
    fn test_valid_real_timer() {
        let args = GetitimerExtArgs::from_raw(ITIMER_REAL as u64, 0x1000).unwrap();
        assert_eq!(args.which, ITIMER_REAL);
    }

    #[test]
    fn test_itimer_disarmed_check() {
        let iv = ItimerVal::default();
        assert!(iv.is_disarmed());
    }

    #[test]
    fn test_syscall_success() {
        let ret = syscall_getitimer_ext(ITIMER_REAL as u64, 0x1000);
        assert_eq!(ret, 0);
    }
}
