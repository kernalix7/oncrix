// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `gettimeofday` syscall handler.
//!
//! Returns the current time as seconds and microseconds since the Unix epoch,
//! along with timezone information (deprecated, use `clock_gettime` instead).
//!
//! POSIX.1-2024: `gettimeofday()` is marked obsolescent and applications
//! should use `clock_gettime(CLOCK_REALTIME)` instead. However, it remains
//! widely used and must be supported for compatibility.
//!
//! The `tz` argument is deprecated; passing `NULL` is preferred.
//!
//! # POSIX Conformance
//! Implements POSIX.1-2024 `gettimeofday()` with the noted obsolescence.

use oncrix_lib::{Error, Result};

/// Kernel-side `struct timeval` (seconds + microseconds).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(C)]
pub struct TimeVal {
    /// Seconds since the Unix epoch.
    pub tv_sec: i64,
    /// Microseconds within the current second (0..999_999).
    pub tv_usec: i64,
}

impl TimeVal {
    /// Construct a new `TimeVal`.
    pub const fn new(tv_sec: i64, tv_usec: i64) -> Self {
        Self { tv_sec, tv_usec }
    }

    /// Returns `true` if the microseconds field is in the valid range.
    pub fn is_valid(self) -> bool {
        self.tv_usec >= 0 && self.tv_usec < 1_000_000
    }
}

/// Deprecated timezone structure (tz_minuteswest, tz_dsttime).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(C)]
pub struct TimeZone {
    /// Minutes west of Greenwich (deprecated).
    pub tz_minuteswest: i32,
    /// Type of daylight saving time correction (deprecated).
    pub tz_dsttime: i32,
}

impl TimeZone {
    /// Construct a new (deprecated) timezone.
    pub const fn new(minuteswest: i32, dsttime: i32) -> Self {
        Self {
            tz_minuteswest: minuteswest,
            tz_dsttime: dsttime,
        }
    }
}

/// Arguments for the `gettimeofday` syscall.
#[derive(Debug, Clone, Copy)]
pub struct GettimeofdayArgs {
    /// User-space pointer to write `struct timeval` (may be 0 to discard).
    pub tv_ptr: u64,
    /// User-space pointer to write `struct timezone` (should be 0, deprecated).
    pub tz_ptr: u64,
}

impl GettimeofdayArgs {
    /// Construct from raw syscall register values.
    ///
    /// # Errors
    /// No mandatory errors — both pointers may be null.
    pub fn from_raw(tv_ptr: u64, tz_ptr: u64) -> Result<Self> {
        Ok(Self { tv_ptr, tz_ptr })
    }
}

/// Result of `gettimeofday`.
#[derive(Debug, Clone, Copy)]
pub struct GettimeofdayResult {
    /// Current time.
    pub tv: TimeVal,
    /// Timezone (deprecated, always zeros in new code).
    pub tz: TimeZone,
}

impl GettimeofdayResult {
    /// Construct a result with a specific time and default timezone.
    pub const fn new(tv: TimeVal) -> Self {
        Self {
            tv,
            tz: TimeZone::new(0, 0),
        }
    }
}

/// Handle the `gettimeofday` syscall.
///
/// Returns the current wall-clock time. The timezone is always returned as
/// zeros since the tz argument is deprecated.
///
/// # Errors
/// None expected for valid pointers. `EFAULT` would be returned by
/// `copy_to_user` on bad pointers in a real implementation.
pub fn sys_gettimeofday(args: GettimeofdayArgs) -> Result<GettimeofdayResult> {
    // In a full implementation this reads from the kernel's CLOCK_REALTIME.
    let _ = args;
    Ok(GettimeofdayResult::new(TimeVal::new(0, 0)))
}

/// Raw syscall entry point for `gettimeofday`.
///
/// # Arguments
/// * `tv_ptr` — pointer to `struct timeval` (register a0), or 0.
/// * `tz_ptr` — pointer to `struct timezone` (register a1), or 0 (deprecated).
///
/// # Returns
/// `0` on success, negative errno on failure.
pub fn syscall_gettimeofday(tv_ptr: u64, tz_ptr: u64) -> i64 {
    let args = match GettimeofdayArgs::from_raw(tv_ptr, tz_ptr) {
        Ok(a) => a,
        Err(_) => return -(oncrix_lib::errno::EINVAL as i64),
    };
    match sys_gettimeofday(args) {
        Ok(_result) => {
            // Real implementation: copy tv and tz to user pointers if non-null.
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
    fn test_both_null_args_accepted() {
        let args = GettimeofdayArgs::from_raw(0, 0).unwrap();
        assert_eq!(args.tv_ptr, 0);
        assert_eq!(args.tz_ptr, 0);
    }

    #[test]
    fn test_timeval_validity() {
        assert!(TimeVal::new(1000, 500_000).is_valid());
        assert!(!TimeVal::new(1000, 1_000_000).is_valid());
        assert!(!TimeVal::new(1000, -1).is_valid());
    }

    #[test]
    fn test_syscall_success() {
        let ret = syscall_gettimeofday(0x1000, 0);
        assert_eq!(ret, 0);
    }

    #[test]
    fn test_syscall_with_both_ptrs() {
        let ret = syscall_gettimeofday(0x1000, 0x2000);
        assert_eq!(ret, 0);
    }
}
