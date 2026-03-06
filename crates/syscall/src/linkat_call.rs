// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `linkat(2)` syscall dispatch layer.
//!
//! Creates a new hard link for an existing file.  `oldpath` is looked up
//! relative to `olddirfd` and the new link `newpath` is created relative to
//! `newdirfd`.
//!
//! # Syscall signature
//!
//! ```text
//! int linkat(int olddirfd, const char *oldpath,
//!            int newdirfd, const char *newpath,
//!            int flags);
//! ```
//!
//! # Flags
//!
//! | Constant             | Value  | Description |
//! |----------------------|--------|-------------|
//! | `AT_SYMLINK_FOLLOW`  | 0x400  | Follow symlinks when resolving `oldpath` |
//! | `AT_EMPTY_PATH`      | 0x1000 | Use `olddirfd` itself when `oldpath` is empty |
//!
//! # POSIX reference
//!
//! - POSIX.1-2024: `linkat()` in `<unistd.h>`
//! - `.TheOpenGroup/susv5-html/functions/linkat.html`
//!
//! # References
//!
//! - Linux: `fs/namei.c` (`do_linkat`)
//! - `linkat(2)` man page

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Use the current working directory as the base for relative paths.
pub const AT_FDCWD: i32 = -100;

/// Follow symbolic links when resolving `oldpath`.
pub const AT_SYMLINK_FOLLOW: i32 = 0x400;

/// Use `olddirfd` itself when `oldpath` is an empty string.
pub const AT_EMPTY_PATH: i32 = 0x1000;

/// All valid flag bits.
const FLAGS_VALID: i32 = AT_SYMLINK_FOLLOW | AT_EMPTY_PATH;

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

/// Handle `linkat(2)`.
///
/// # Errors
///
/// - [`Error::InvalidArgument`] — unknown flags, null `newpath_ptr`, null
///   `oldpath_ptr` without `AT_EMPTY_PATH`, or an invalid dirfd.
/// - [`Error::NotFound`] — `oldpath` does not exist.
/// - [`Error::AlreadyExists`] — `newpath` already exists.
/// - [`Error::PermissionDenied`] — write permission denied on the target
///   directory, or the filesystem does not support hard links.
/// - [`Error::NotImplemented`] — stub.
pub fn sys_linkat(
    olddirfd: i32,
    oldpath_ptr: u64,
    newdirfd: i32,
    newpath_ptr: u64,
    flags: i32,
) -> Result<i64> {
    if !is_valid_dirfd(olddirfd) || !is_valid_dirfd(newdirfd) {
        return Err(Error::InvalidArgument);
    }
    if flags & !FLAGS_VALID != 0 {
        return Err(Error::InvalidArgument);
    }
    if oldpath_ptr == 0 && (flags & AT_EMPTY_PATH == 0) {
        return Err(Error::InvalidArgument);
    }
    if newpath_ptr == 0 {
        return Err(Error::InvalidArgument);
    }
    let _ = (olddirfd, oldpath_ptr, newdirfd, newpath_ptr, flags);
    Err(Error::NotImplemented)
}

/// Entry point called from the syscall dispatcher.
pub fn do_linkat_call(
    olddirfd: i32,
    oldpath_ptr: u64,
    newdirfd: i32,
    newpath_ptr: u64,
    flags: i32,
) -> Result<i64> {
    sys_linkat(olddirfd, oldpath_ptr, newdirfd, newpath_ptr, flags)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn null_newpath_rejected() {
        assert_eq!(
            sys_linkat(AT_FDCWD, 0x1000, AT_FDCWD, 0, 0).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn null_oldpath_without_empty_path_rejected() {
        assert_eq!(
            sys_linkat(AT_FDCWD, 0, AT_FDCWD, 0x2000, 0).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn null_oldpath_with_empty_path_ok() {
        let r = sys_linkat(3, 0, AT_FDCWD, 0x2000, AT_EMPTY_PATH);
        assert_eq!(r.unwrap_err(), Error::NotImplemented);
    }

    #[test]
    fn unknown_flags_rejected() {
        assert_eq!(
            sys_linkat(AT_FDCWD, 0x1000, AT_FDCWD, 0x2000, 0x8000).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn valid_call_reaches_stub() {
        let r = sys_linkat(AT_FDCWD, 0x1000, AT_FDCWD, 0x2000, 0);
        assert_eq!(r.unwrap_err(), Error::NotImplemented);
    }
}
