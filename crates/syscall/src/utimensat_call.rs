// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `utimensat(2)` syscall dispatch layer.
//!
//! Updates the access and modification timestamps of a file with
//! nanosecond precision.  Either or both timestamps may be set to the
//! current time by passing `UTIME_NOW`, or left unchanged via `UTIME_OMIT`.
//!
//! # Syscall signature
//!
//! ```text
//! int utimensat(int dirfd, const char *pathname,
//!               const struct timespec times[2], int flags);
//! ```
//!
//! `times[0]` is the access time (atime); `times[1]` is the modification
//! time (mtime).  If `times` is null both are set to the current time.
//!
//! # POSIX reference
//!
//! - POSIX.1-2024: `utimensat()` in `<sys/stat.h>`
//! - `.TheOpenGroup/susv5-html/functions/utimensat.html`
//!
//! # References
//!
//! - Linux: `fs/utimes.c` (`do_utimensat`)
//! - `utimensat(2)` man page

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Use the current working directory as the base for relative paths.
pub const AT_FDCWD: i32 = -100;

/// Do not follow trailing symbolic links.
pub const AT_SYMLINK_NOFOLLOW: i32 = 0x100;

/// All valid flag bits.
const FLAGS_VALID: i32 = AT_SYMLINK_NOFOLLOW;

/// Set this timestamp to the current time.
pub const UTIME_NOW: i64 = 1_073_741_823; // (1<<30) - 1
/// Leave this timestamp unchanged.
pub const UTIME_OMIT: i64 = 1_073_741_822; // (1<<30) - 2

/// Maximum valid file descriptor number.
const FD_MAX: i32 = 1_048_576;

// ---------------------------------------------------------------------------
// Timespec (kernel representation)
// ---------------------------------------------------------------------------

/// A POSIX `struct timespec` as passed from user space.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct Timespec {
    /// Seconds since the epoch.
    pub tv_sec: i64,
    /// Nanoseconds [0, 999_999_999] or a `UTIME_*` sentinel.
    pub tv_nsec: i64,
}

impl Timespec {
    /// Returns `true` if the nsec field holds a valid nanosecond count or
    /// one of the two `UTIME_*` sentinels.
    pub fn is_valid(&self) -> bool {
        self.tv_nsec == UTIME_NOW
            || self.tv_nsec == UTIME_OMIT
            || (0..1_000_000_000).contains(&self.tv_nsec)
    }
}

// ---------------------------------------------------------------------------
// Validation helpers
// ---------------------------------------------------------------------------

/// Returns `true` if `dirfd` is `AT_FDCWD` or a plausible open fd number.
pub fn is_valid_dirfd(dirfd: i32) -> bool {
    dirfd == AT_FDCWD || (0..=FD_MAX).contains(&dirfd)
}

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

/// Handle `utimensat(2)`.
///
/// `times_ptr` points to an array of two `Timespec` structures.  When
/// `times_ptr` is null both timestamps are set to the current time.
///
/// # Errors
///
/// - [`Error::InvalidArgument`] — unknown flags, invalid dirfd, or a
///   `timespec` with an out-of-range `tv_nsec`.
/// - [`Error::NotFound`] — the path does not exist.
/// - [`Error::PermissionDenied`] — caller lacks the required privilege.
/// - [`Error::NotImplemented`] — stub.
pub fn sys_utimensat(dirfd: i32, pathname_ptr: u64, times_ptr: u64, flags: i32) -> Result<i64> {
    if !is_valid_dirfd(dirfd) {
        return Err(Error::InvalidArgument);
    }
    if flags & !FLAGS_VALID != 0 {
        return Err(Error::InvalidArgument);
    }
    // Validate both timespecs when provided.
    if times_ptr != 0 {
        // SAFETY: caller is responsible for a valid pointer; this is a stub
        // that only inspects the values for argument validation.
        let ts = unsafe { core::slice::from_raw_parts(times_ptr as *const Timespec, 2) };
        if !ts[0].is_valid() || !ts[1].is_valid() {
            return Err(Error::InvalidArgument);
        }
    }
    let _ = (dirfd, pathname_ptr, times_ptr, flags);
    Err(Error::NotImplemented)
}

/// Entry point called from the syscall dispatcher.
pub fn do_utimensat_call(dirfd: i32, pathname_ptr: u64, times_ptr: u64, flags: i32) -> Result<i64> {
    sys_utimensat(dirfd, pathname_ptr, times_ptr, flags)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_flags_rejected() {
        assert_eq!(
            sys_utimensat(AT_FDCWD, 0x1000, 0, 0x8000).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn null_times_means_now() {
        // Null times_ptr is valid — means set both to current time.
        let r = sys_utimensat(AT_FDCWD, 0x1000, 0, 0);
        assert_eq!(r.unwrap_err(), Error::NotImplemented);
    }

    #[test]
    fn invalid_dirfd_rejected() {
        assert_eq!(
            sys_utimensat(-500, 0x1000, 0, 0).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn timespec_validation() {
        let ts = Timespec {
            tv_sec: 0,
            tv_nsec: 1_000_000_000,
        };
        assert!(!ts.is_valid());
        let ts_now = Timespec {
            tv_sec: 0,
            tv_nsec: UTIME_NOW,
        };
        assert!(ts_now.is_valid());
        let ts_omit = Timespec {
            tv_sec: 0,
            tv_nsec: UTIME_OMIT,
        };
        assert!(ts_omit.is_valid());
    }
}
