// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `ftruncate(2)` / `truncate(2)` dispatch layer.
//!
//! `ftruncate` sets the size of the file referred to by `fd` to `length`
//! bytes.  `truncate` does the same via a pathname.  If the file was
//! previously longer, the extra data is discarded.  If shorter, the file
//! is extended with null bytes up to `length`.
//!
//! # Syscall signatures
//!
//! ```text
//! int ftruncate(int fd, off_t length);
//! int truncate(const char *path, off_t length);
//! ```
//!
//! # POSIX reference
//!
//! - POSIX.1-2024: `ftruncate()` in `<unistd.h>`
//! - `.TheOpenGroup/susv5-html/functions/ftruncate.html`
//!
//! # References
//!
//! - Linux: `fs/open.c` (`do_sys_ftruncate`)
//! - `ftruncate(2)` man page

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum valid file descriptor number.
const FD_MAX: i32 = 1_048_576;

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// Handle `ftruncate(2)`.
///
/// # Errors
///
/// - [`Error::InvalidArgument`] — `fd` out of range or `length` is negative.
/// - [`Error::NotFound`] — `fd` is not open.
/// - [`Error::PermissionDenied`] — file is not open for writing.
/// - [`Error::NotImplemented`] — stub.
pub fn sys_ftruncate(fd: i32, length: i64) -> Result<i64> {
    if fd < 0 || fd > FD_MAX {
        return Err(Error::InvalidArgument);
    }
    if length < 0 {
        return Err(Error::InvalidArgument);
    }
    let _ = (fd, length);
    Err(Error::NotImplemented)
}

/// Handle `truncate(2)`.
///
/// # Errors
///
/// - [`Error::InvalidArgument`] — null `path_ptr` or negative `length`.
/// - [`Error::NotFound`] — path does not exist.
/// - [`Error::PermissionDenied`] — insufficient privilege.
/// - [`Error::NotImplemented`] — stub.
pub fn sys_truncate(path_ptr: u64, length: i64) -> Result<i64> {
    if path_ptr == 0 {
        return Err(Error::InvalidArgument);
    }
    if length < 0 {
        return Err(Error::InvalidArgument);
    }
    let _ = (path_ptr, length);
    Err(Error::NotImplemented)
}

/// Entry point for `ftruncate` from the syscall dispatcher.
pub fn do_ftruncate_call(fd: i32, length: i64) -> Result<i64> {
    sys_ftruncate(fd, length)
}

/// Entry point for `truncate` from the syscall dispatcher.
pub fn do_truncate_call(path_ptr: u64, length: i64) -> Result<i64> {
    sys_truncate(path_ptr, length)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn negative_fd_rejected() {
        assert_eq!(sys_ftruncate(-1, 1024).unwrap_err(), Error::InvalidArgument);
    }

    #[test]
    fn negative_length_ftruncate_rejected() {
        assert_eq!(sys_ftruncate(3, -1).unwrap_err(), Error::InvalidArgument);
    }

    #[test]
    fn zero_length_ok() {
        let r = sys_ftruncate(3, 0);
        assert_eq!(r.unwrap_err(), Error::NotImplemented);
    }

    #[test]
    fn truncate_null_path_rejected() {
        assert_eq!(sys_truncate(0, 1024).unwrap_err(), Error::InvalidArgument);
    }

    #[test]
    fn truncate_negative_length_rejected() {
        assert_eq!(
            sys_truncate(0x1000, -1).unwrap_err(),
            Error::InvalidArgument
        );
    }
}
