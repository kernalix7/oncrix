// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `readlinkat(2)` syscall dispatch layer.
//!
//! Reads the value of the symbolic link named by `pathname` (relative to
//! `dirfd`) into the caller-supplied buffer `buf_ptr` of length `bufsiz`.
//! The result is *not* NUL-terminated; on success the return value is the
//! number of bytes placed in the buffer.
//!
//! # Syscall signature
//!
//! ```text
//! ssize_t readlinkat(int dirfd, const char *restrict pathname,
//!                    char *restrict buf, size_t bufsiz);
//! ```
//!
//! # POSIX reference
//!
//! - POSIX.1-2024: `readlinkat()` in `<unistd.h>`
//! - `.TheOpenGroup/susv5-html/functions/readlinkat.html`
//!
//! # References
//!
//! - Linux: `fs/stat.c` (`do_readlinkat`)
//! - `readlinkat(2)` man page

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Use the current working directory as the base for relative paths.
pub const AT_FDCWD: i32 = -100;

/// Operate on `dirfd` itself when `pathname` is empty.
pub const AT_EMPTY_PATH: i32 = 0x1000;

/// Maximum buffer size that will be accepted (sanity cap).
pub const READLINK_MAX_BUF: usize = 65536;

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

/// Handle `readlinkat(2)`.
///
/// Returns the number of bytes written to `buf_ptr` on success (without a
/// NUL terminator).  Returns [`Error::InvalidArgument`] immediately when
/// `bufsiz` is zero.
///
/// # Errors
///
/// - [`Error::InvalidArgument`] — `buf_ptr` is null, `bufsiz` is zero,
///   `pathname_ptr` is null without `AT_EMPTY_PATH`, or `dirfd` is invalid.
/// - [`Error::NotFound`] — path does not exist.
/// - [`Error::IoError`] — the named path is not a symbolic link.
/// - [`Error::NotImplemented`] — stub.
pub fn sys_readlinkat(
    dirfd: i32,
    pathname_ptr: u64,
    buf_ptr: u64,
    bufsiz: usize,
    flags: i32,
) -> Result<i64> {
    if !is_valid_dirfd(dirfd) {
        return Err(Error::InvalidArgument);
    }
    if pathname_ptr == 0 && (flags & AT_EMPTY_PATH == 0) {
        return Err(Error::InvalidArgument);
    }
    if buf_ptr == 0 {
        return Err(Error::InvalidArgument);
    }
    if bufsiz == 0 {
        return Err(Error::InvalidArgument);
    }
    let _ = (dirfd, pathname_ptr, buf_ptr, bufsiz, flags);
    Err(Error::NotImplemented)
}

/// Entry point called from the syscall dispatcher (no `flags` in the Linux ABI
/// for `readlinkat` itself; `flags` is reserved and must be zero on kernel
/// entry — kept here for future extension via `readlinkat2`).
pub fn do_readlinkat_call(
    dirfd: i32,
    pathname_ptr: u64,
    buf_ptr: u64,
    bufsiz: usize,
) -> Result<i64> {
    sys_readlinkat(dirfd, pathname_ptr, buf_ptr, bufsiz, 0)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn null_buf_rejected() {
        assert_eq!(
            sys_readlinkat(AT_FDCWD, 0x1000, 0, 256, 0).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn zero_bufsiz_rejected() {
        assert_eq!(
            sys_readlinkat(AT_FDCWD, 0x1000, 0x2000, 0, 0).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn null_pathname_without_empty_path_rejected() {
        assert_eq!(
            sys_readlinkat(AT_FDCWD, 0, 0x2000, 256, 0).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn null_pathname_with_empty_path_ok() {
        let r = sys_readlinkat(3, 0, 0x2000, 256, AT_EMPTY_PATH);
        assert_eq!(r.unwrap_err(), Error::NotImplemented);
    }

    #[test]
    fn valid_call_reaches_stub() {
        let r = sys_readlinkat(AT_FDCWD, 0x1000, 0x2000, 256, 0);
        assert_eq!(r.unwrap_err(), Error::NotImplemented);
    }

    #[test]
    fn invalid_dirfd_rejected() {
        assert_eq!(
            sys_readlinkat(-500, 0x1000, 0x2000, 256, 0).unwrap_err(),
            Error::InvalidArgument
        );
    }
}
