// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `unlinkat(2)` syscall dispatch layer.
//!
//! Removes the directory entry (link) named by `pathname` relative to the
//! open directory `dirfd`.  When `AT_REMOVEDIR` is set in `flags` the call
//! is equivalent to `rmdir(2)`; otherwise it is equivalent to `unlink(2)`.
//!
//! # Syscall signature
//!
//! ```text
//! int unlinkat(int dirfd, const char *pathname, int flags);
//! ```
//!
//! # POSIX reference
//!
//! - POSIX.1-2024: `unlinkat()` in `<unistd.h>`
//! - `.TheOpenGroup/susv5-html/functions/unlinkat.html`
//!
//! # References
//!
//! - Linux: `fs/namei.c` (`do_unlinkat`, `do_rmdir`)
//! - `unlinkat(2)` man page

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Use the current working directory as the base for relative paths.
pub const AT_FDCWD: i32 = -100;

/// Remove the path as a directory rather than a file.
pub const AT_REMOVEDIR: i32 = 0x200;

/// All valid flag bits.
const FLAGS_VALID: i32 = AT_REMOVEDIR;

/// Maximum valid file descriptor number.
const FD_MAX: i32 = 1_048_576;

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

/// Handle `unlinkat(2)`.
///
/// # Errors
///
/// - [`Error::InvalidArgument`] — unknown flags, null `pathname_ptr`, or
///   `dirfd` is out of range.
/// - [`Error::NotFound`] — the path does not exist.
/// - [`Error::PermissionDenied`] — write permission denied on the parent
///   directory, or the sticky bit is set and the caller does not own the file.
/// - [`Error::Busy`] — the path is in use (e.g., a mount point).
/// - [`Error::NotImplemented`] — stub.
pub fn sys_unlinkat(dirfd: i32, pathname_ptr: u64, flags: i32) -> Result<i64> {
    if !is_valid_dirfd(dirfd) {
        return Err(Error::InvalidArgument);
    }
    if flags & !FLAGS_VALID != 0 {
        return Err(Error::InvalidArgument);
    }
    if pathname_ptr == 0 {
        return Err(Error::InvalidArgument);
    }
    let _ = (dirfd, pathname_ptr, flags);
    Err(Error::NotImplemented)
}

/// Entry point called from the syscall dispatcher.
pub fn do_unlinkat_call(dirfd: i32, pathname_ptr: u64, flags: i32) -> Result<i64> {
    sys_unlinkat(dirfd, pathname_ptr, flags)
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
            sys_unlinkat(AT_FDCWD, 0, 0).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn unknown_flags_rejected() {
        assert_eq!(
            sys_unlinkat(AT_FDCWD, 0x1000, 0x8000).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn invalid_dirfd_rejected() {
        assert_eq!(
            sys_unlinkat(-500, 0x1000, 0).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn unlink_reaches_stub() {
        let r = sys_unlinkat(AT_FDCWD, 0x1000, 0);
        assert_eq!(r.unwrap_err(), Error::NotImplemented);
    }

    #[test]
    fn rmdir_flag_reaches_stub() {
        let r = sys_unlinkat(AT_FDCWD, 0x1000, AT_REMOVEDIR);
        assert_eq!(r.unwrap_err(), Error::NotImplemented);
    }
}
