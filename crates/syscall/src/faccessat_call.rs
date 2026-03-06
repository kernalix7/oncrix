// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `faccessat(2)` syscall dispatch layer.
//!
//! Checks whether the calling process can access the file at `pathname`
//! relative to the open directory `dirfd`.  Equivalent to calling
//! `access(2)` with `AT_FDCWD` when `dirfd` is `AT_FDCWD`.
//!
//! # Syscall signature
//!
//! ```text
//! int faccessat(int dirfd, const char *pathname, int mode, int flags);
//! ```
//!
//! # Mode bits (POSIX `<unistd.h>`)
//!
//! | Constant | Value | Meaning |
//! |----------|-------|---------|
//! | `F_OK`   | 0     | File exists |
//! | `X_OK`   | 1     | Execute permission |
//! | `W_OK`   | 2     | Write permission |
//! | `R_OK`   | 4     | Read permission |
//!
//! # POSIX reference
//!
//! - POSIX.1-2024: `faccessat()` in `<unistd.h>`
//! - `.TheOpenGroup/susv5-html/functions/faccessat.html`
//!
//! # References
//!
//! - Linux: `fs/open.c` (`do_faccessat`)
//! - `faccessat(2)` man page

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Use the current working directory as the base for relative paths.
pub const AT_FDCWD: i32 = -100;

/// Test for file existence.
pub const F_OK: i32 = 0;
/// Test for read permission.
pub const R_OK: i32 = 4;
/// Test for write permission.
pub const W_OK: i32 = 2;
/// Test for execute/search permission.
pub const X_OK: i32 = 1;

/// All valid `mode` bits.
const MODE_VALID: i32 = R_OK | W_OK | X_OK;

/// Do not follow symbolic links.
pub const AT_SYMLINK_NOFOLLOW: i32 = 0x100;
/// Use effective UID/GID for the permission check.
pub const AT_EACCESS: i32 = 0x200;
/// Operate on `dirfd` itself when `pathname` is empty.
pub const AT_EMPTY_PATH: i32 = 0x1000;

/// All valid flag bits for `faccessat`.
const FLAGS_VALID: i32 = AT_SYMLINK_NOFOLLOW | AT_EACCESS | AT_EMPTY_PATH;

/// Maximum valid file descriptor number.
const FD_MAX: i32 = 1_048_576;

// ---------------------------------------------------------------------------
// Validation helpers
// ---------------------------------------------------------------------------

/// Returns `true` if `dirfd` is `AT_FDCWD` or a plausible open fd number.
pub fn is_valid_dirfd(dirfd: i32) -> bool {
    dirfd == AT_FDCWD || (0..=FD_MAX).contains(&dirfd)
}

/// Returns `true` if `mode` contains only recognised bits.
pub fn is_valid_mode(mode: i32) -> bool {
    mode == F_OK || (mode & !MODE_VALID == 0 && mode != 0)
}

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

/// Handle `faccessat(2)`.
///
/// Validates `dirfd`, `pathname_ptr`, `mode`, and `flags`, then performs
/// the access check against the target path.
///
/// # Errors
///
/// - [`Error::InvalidArgument`] — `mode` has invalid bits, `flags` has
///   unknown bits, `pathname_ptr` is null without `AT_EMPTY_PATH`, or
///   `dirfd` is out of range.
/// - [`Error::NotFound`] — path does not exist.
/// - [`Error::PermissionDenied`] — access denied.
/// - [`Error::NotImplemented`] — stub; full VFS path walk not yet wired.
pub fn sys_faccessat(dirfd: i32, pathname_ptr: u64, mode: i32, flags: i32) -> Result<i64> {
    if !is_valid_dirfd(dirfd) {
        return Err(Error::InvalidArgument);
    }
    if flags & !FLAGS_VALID != 0 {
        return Err(Error::InvalidArgument);
    }
    // pathname_ptr may be null only with AT_EMPTY_PATH
    if pathname_ptr == 0 && (flags & AT_EMPTY_PATH == 0) {
        return Err(Error::InvalidArgument);
    }
    if !is_valid_mode(mode) {
        return Err(Error::InvalidArgument);
    }
    let _ = (dirfd, pathname_ptr, mode, flags);
    Err(Error::NotImplemented)
}

/// Entry point called from the syscall dispatcher.
pub fn do_faccessat_call(dirfd: i32, pathname_ptr: u64, mode: i32, flags: i32) -> Result<i64> {
    sys_faccessat(dirfd, pathname_ptr, mode, flags)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_mode_bits_rejected() {
        assert_eq!(
            sys_faccessat(AT_FDCWD, 0x1000, 0xFF, 0).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn unknown_flags_rejected() {
        assert_eq!(
            sys_faccessat(AT_FDCWD, 0x1000, R_OK, 0x8000).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn null_path_without_empty_path_rejected() {
        assert_eq!(
            sys_faccessat(AT_FDCWD, 0, R_OK, 0).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn null_path_with_empty_path_ok() {
        let r = sys_faccessat(AT_FDCWD, 0, F_OK, AT_EMPTY_PATH);
        assert_eq!(r.unwrap_err(), Error::NotImplemented);
    }

    #[test]
    fn valid_call_reaches_stub() {
        let r = sys_faccessat(AT_FDCWD, 0x2000, R_OK | W_OK, 0);
        assert_eq!(r.unwrap_err(), Error::NotImplemented);
    }

    #[test]
    fn is_valid_dirfd_checks() {
        assert!(is_valid_dirfd(AT_FDCWD));
        assert!(is_valid_dirfd(3));
        assert!(!is_valid_dirfd(-200));
    }
}
