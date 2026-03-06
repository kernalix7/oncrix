// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `mkdirat(2)` syscall dispatch layer.
//!
//! Creates a directory named by `pathname` relative to the open directory
//! `dirfd`.  When `dirfd` is `AT_FDCWD` the call is equivalent to
//! `mkdir(2)`.
//!
//! # Syscall signature
//!
//! ```text
//! int mkdirat(int dirfd, const char *pathname, mode_t mode);
//! ```
//!
//! # POSIX reference
//!
//! - POSIX.1-2024: `mkdirat()` in `<sys/stat.h>`
//! - `.TheOpenGroup/susv5-html/functions/mkdirat.html`
//!
//! # References
//!
//! - Linux: `fs/namei.c` (`do_mkdirat`)
//! - `mkdirat(2)` man page

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Use the current working directory as the base for relative paths.
pub const AT_FDCWD: i32 = -100;

/// Mask covering the 12 permission/suid/sgid/sticky bits.
const MODE_MASK: u32 = 0o7777;

/// Maximum valid file descriptor number.
const FD_MAX: i32 = 1_048_576;

// ---------------------------------------------------------------------------
// Validation helpers
// ---------------------------------------------------------------------------

/// Returns `true` if `dirfd` is `AT_FDCWD` or a plausible open fd number.
pub fn is_valid_dirfd(dirfd: i32) -> bool {
    dirfd == AT_FDCWD || (0..=FD_MAX).contains(&dirfd)
}

/// Returns `true` if `mode` contains only the 12 file-mode bits.
pub fn is_valid_mode(mode: u32) -> bool {
    mode & !MODE_MASK == 0
}

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

/// Handle `mkdirat(2)`.
///
/// The final mode applied to the new directory is `mode & ~umask`.  The
/// umask application is performed during VFS path resolution and is not
/// replicated here.
///
/// # Errors
///
/// - [`Error::InvalidArgument`] — null `pathname_ptr`, invalid `dirfd`,
///   or `mode` has bits outside the 12 file-mode bits.
/// - [`Error::AlreadyExists`] — a file at that path already exists.
/// - [`Error::NotFound`] — a component of the path does not exist.
/// - [`Error::PermissionDenied`] — write permission denied on the parent.
/// - [`Error::NotImplemented`] — stub.
pub fn sys_mkdirat(dirfd: i32, pathname_ptr: u64, mode: u32) -> Result<i64> {
    if !is_valid_dirfd(dirfd) {
        return Err(Error::InvalidArgument);
    }
    if pathname_ptr == 0 {
        return Err(Error::InvalidArgument);
    }
    if !is_valid_mode(mode) {
        return Err(Error::InvalidArgument);
    }
    let _ = (dirfd, pathname_ptr, mode);
    Err(Error::NotImplemented)
}

/// Entry point called from the syscall dispatcher.
pub fn do_mkdirat_call(dirfd: i32, pathname_ptr: u64, mode: u32) -> Result<i64> {
    sys_mkdirat(dirfd, pathname_ptr, mode)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn null_pathname_rejected() {
        assert_eq!(
            sys_mkdirat(AT_FDCWD, 0, 0o755).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn invalid_mode_bits_rejected() {
        assert_eq!(
            sys_mkdirat(AT_FDCWD, 0x1000, 0o100_000).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn invalid_dirfd_rejected() {
        assert_eq!(
            sys_mkdirat(-200, 0x1000, 0o755).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn valid_call_reaches_stub() {
        let r = sys_mkdirat(AT_FDCWD, 0x1000, 0o755);
        assert_eq!(r.unwrap_err(), Error::NotImplemented);
    }
}
