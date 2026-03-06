// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `settimeofday(2)` and `gettimeofday(2)` syscall dispatch layer.
//!
//! Get or set the wall-clock time with microsecond resolution.
//!
//! # Syscall signatures
//!
//! ```text
//! int gettimeofday(struct timeval *tv, struct timezone *tz);
//! int settimeofday(const struct timeval *tv, const struct timezone *tz);
//! ```
//!
//! Note: `gettimeofday` is superseded by `clock_gettime(CLOCK_REALTIME)` in
//! POSIX.1-2024 but remains for backwards compatibility.
//!
//! # POSIX reference
//!
//! - POSIX.1-2024: `gettimeofday()` in `<sys/time.h>`
//!
//! # References
//!
//! - Linux: `kernel/time.c` (`sys_settimeofday`, `sys_gettimeofday`)
//! - `settimeofday(2)` man page

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Microseconds per second.
pub const USEC_PER_SEC: i64 = 1_000_000;

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// Handle `gettimeofday(2)`.
///
/// `tv_ptr` is a user-space pointer to `struct timeval`; may be null if the
/// caller only wants timezone info.  `tz_ptr` is a user-space pointer to
/// `struct timezone`; may be null.
///
/// # Errors
///
/// - [`Error::InvalidArgument`] — both `tv_ptr` and `tz_ptr` are null.
/// - [`Error::NotImplemented`] — stub.
pub fn sys_gettimeofday(tv_ptr: u64, tz_ptr: u64) -> Result<i64> {
    if tv_ptr == 0 && tz_ptr == 0 {
        return Err(Error::InvalidArgument);
    }
    let _ = (tv_ptr, tz_ptr);
    Err(Error::NotImplemented)
}

/// Handle `settimeofday(2)`.
///
/// Both `tv_ptr` and `tz_ptr` may be null independently; passing both null
/// is rejected.  Requires `CAP_SYS_TIME`.
///
/// The `tv` fields must be normalised: `0 <= tv_usec < 1_000_000`.
///
/// # Errors
///
/// - [`Error::InvalidArgument`] — both pointers null.
/// - [`Error::PermissionDenied`] — lacks `CAP_SYS_TIME`.
/// - [`Error::NotImplemented`] — stub.
pub fn sys_settimeofday(tv_ptr: u64, tz_ptr: u64) -> Result<i64> {
    if tv_ptr == 0 && tz_ptr == 0 {
        return Err(Error::InvalidArgument);
    }
    let _ = (tv_ptr, tz_ptr);
    Err(Error::NotImplemented)
}

/// Entry point for `gettimeofday` from the syscall dispatcher.
pub fn do_gettimeofday_call(tv_ptr: u64, tz_ptr: u64) -> Result<i64> {
    sys_gettimeofday(tv_ptr, tz_ptr)
}

/// Entry point for `settimeofday` from the syscall dispatcher.
pub fn do_settimeofday_call(tv_ptr: u64, tz_ptr: u64) -> Result<i64> {
    sys_settimeofday(tv_ptr, tz_ptr)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gettimeofday_both_null_rejected() {
        assert_eq!(sys_gettimeofday(0, 0).unwrap_err(), Error::InvalidArgument);
    }

    #[test]
    fn gettimeofday_tv_only_reaches_stub() {
        let r = sys_gettimeofday(0x1000, 0);
        assert_eq!(r.unwrap_err(), Error::NotImplemented);
    }

    #[test]
    fn gettimeofday_tz_only_reaches_stub() {
        let r = sys_gettimeofday(0, 0x2000);
        assert_eq!(r.unwrap_err(), Error::NotImplemented);
    }

    #[test]
    fn settimeofday_both_null_rejected() {
        assert_eq!(sys_settimeofday(0, 0).unwrap_err(), Error::InvalidArgument);
    }

    #[test]
    fn settimeofday_valid_reaches_stub() {
        let r = sys_settimeofday(0x1000, 0x2000);
        assert_eq!(r.unwrap_err(), Error::NotImplemented);
    }
}
