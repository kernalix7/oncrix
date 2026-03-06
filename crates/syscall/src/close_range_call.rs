// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `close_range(2)` syscall dispatch layer.
//!
//! Closes all file descriptors in the inclusive range `[first, last]`.
//! Optionally, with `CLOSE_RANGE_UNSHARE`, the file descriptor table is
//! first unshared (useful after `clone` with `CLONE_FILES`).  With
//! `CLOSE_RANGE_CLOEXEC` the descriptors are flagged close-on-exec instead
//! of being closed immediately.
//!
//! # Syscall signature
//!
//! ```text
//! int close_range(unsigned int first, unsigned int last,
//!                 unsigned int flags);
//! ```
//!
//! # Flags
//!
//! | Constant                | Value | Description |
//! |-------------------------|-------|-------------|
//! | `CLOSE_RANGE_UNSHARE`   | 2     | Unshare fd table before closing |
//! | `CLOSE_RANGE_CLOEXEC`   | 4     | Set close-on-exec instead of closing |
//!
//! # References
//!
//! - Linux: `fs/file.c` (`__close_range`)
//! - `close_range(2)` man page

use oncrix_lib::{Error, Result};

// Re-export constants from the detailed module.
pub use crate::close_range::{CLOSE_RANGE_CLOEXEC, CLOSE_RANGE_UNSHARE};

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

/// Handle `close_range(2)`.
///
/// `first` must be <= `last`.  Both are file descriptor numbers; `last` may
/// be `u32::MAX` to indicate "all fds from `first` onwards".
///
/// # Errors
///
/// - [`Error::InvalidArgument`] — unknown flags or `first > last`.
/// - [`Error::NotImplemented`] — stub.
pub fn sys_close_range(first: u32, last: u32, flags: u32) -> Result<i64> {
    let valid_flags = CLOSE_RANGE_UNSHARE | CLOSE_RANGE_CLOEXEC;
    if flags & !valid_flags != 0 {
        return Err(Error::InvalidArgument);
    }
    if first > last {
        return Err(Error::InvalidArgument);
    }
    let _ = (first, last, flags);
    Err(Error::NotImplemented)
}

/// Entry point called from the syscall dispatcher.
pub fn do_close_range_call(first: u32, last: u32, flags: u32) -> Result<i64> {
    sys_close_range(first, last, flags)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_greater_than_last_rejected() {
        assert_eq!(
            sys_close_range(10, 5, 0).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn unknown_flags_rejected() {
        assert_eq!(
            sys_close_range(3, 10, 0x80).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn valid_range_reaches_stub() {
        let r = sys_close_range(3, 100, 0);
        assert_eq!(r.unwrap_err(), Error::NotImplemented);
    }

    #[test]
    fn max_last_ok() {
        let r = sys_close_range(3, u32::MAX, CLOSE_RANGE_CLOEXEC);
        assert_eq!(r.unwrap_err(), Error::NotImplemented);
    }

    #[test]
    fn equal_first_last_ok() {
        let r = sys_close_range(5, 5, 0);
        assert_eq!(r.unwrap_err(), Error::NotImplemented);
    }
}
