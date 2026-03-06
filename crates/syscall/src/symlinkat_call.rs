// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `symlinkat(2)` syscall dispatch layer.
//!
//! Creates a symbolic link named `linkpath` (relative to `newdirfd`) that
//! contains the string `target`.  The target string is stored verbatim and
//! is not resolved at creation time.
//!
//! # Syscall signature
//!
//! ```text
//! int symlinkat(const char *target, int newdirfd, const char *linkpath);
//! ```
//!
//! # POSIX reference
//!
//! - POSIX.1-2024: `symlinkat()` in `<unistd.h>`
//! - `.TheOpenGroup/susv5-html/functions/symlinkat.html`
//!
//! # References
//!
//! - Linux: `fs/namei.c` (`do_symlinkat`)
//! - `symlinkat(2)` man page

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Use the current working directory as the base for relative `linkpath`.
pub const AT_FDCWD: i32 = -100;

/// Maximum valid file descriptor number.
const FD_MAX: i32 = 1_048_576;

/// Maximum supported target length (PATH_MAX).
pub const SYMLINK_MAX_LEN: usize = 4096;

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

/// Handle `symlinkat(2)`.
///
/// Both `target_ptr` and `linkpath_ptr` must be non-null.
///
/// # Errors
///
/// - [`Error::InvalidArgument`] — null pointer arguments or invalid `newdirfd`.
/// - [`Error::NotFound`] — a component of `linkpath` does not exist.
/// - [`Error::AlreadyExists`] — `linkpath` already exists.
/// - [`Error::PermissionDenied`] — write permission denied on the parent
///   directory of `linkpath`.
/// - [`Error::NotImplemented`] — stub.
pub fn sys_symlinkat(target_ptr: u64, newdirfd: i32, linkpath_ptr: u64) -> Result<i64> {
    if !is_valid_dirfd(newdirfd) {
        return Err(Error::InvalidArgument);
    }
    if target_ptr == 0 {
        return Err(Error::InvalidArgument);
    }
    if linkpath_ptr == 0 {
        return Err(Error::InvalidArgument);
    }
    let _ = (target_ptr, newdirfd, linkpath_ptr);
    Err(Error::NotImplemented)
}

/// Entry point called from the syscall dispatcher.
pub fn do_symlinkat_call(target_ptr: u64, newdirfd: i32, linkpath_ptr: u64) -> Result<i64> {
    sys_symlinkat(target_ptr, newdirfd, linkpath_ptr)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn null_target_rejected() {
        assert_eq!(
            sys_symlinkat(0, AT_FDCWD, 0x1000).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn null_linkpath_rejected() {
        assert_eq!(
            sys_symlinkat(0x1000, AT_FDCWD, 0).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn invalid_dirfd_rejected() {
        assert_eq!(
            sys_symlinkat(0x1000, -500, 0x2000).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn valid_call_reaches_stub() {
        let r = sys_symlinkat(0x1000, AT_FDCWD, 0x2000);
        assert_eq!(r.unwrap_err(), Error::NotImplemented);
    }

    #[test]
    fn explicit_dirfd_valid() {
        let r = sys_symlinkat(0x1000, 5, 0x2000);
        assert_eq!(r.unwrap_err(), Error::NotImplemented);
    }
}
