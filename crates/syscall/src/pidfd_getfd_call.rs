// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `pidfd_getfd(2)` syscall dispatch layer.
//!
//! Duplicates a file descriptor from the process referred to by `pidfd`
//! into the calling process.  The target file descriptor `targetfd` is
//! looked up in the open-file table of the process identified by `pidfd`.
//!
//! # Syscall signature
//!
//! ```text
//! int pidfd_getfd(int pidfd, int targetfd, unsigned int flags);
//! ```
//!
//! `flags` is currently reserved and must be zero.
//!
//! # References
//!
//! - Linux: `kernel/pid.c` (`sys_pidfd_getfd`)
//! - `pidfd_getfd(2)` man page

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum valid file descriptor number.
const FD_MAX: i32 = 1_048_576;

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

/// Handle `pidfd_getfd(2)`.
///
/// # Errors
///
/// - [`Error::InvalidArgument`] — `pidfd` or `targetfd` out of range, or
///   non-zero `flags`.
/// - [`Error::NotFound`] — `pidfd` does not refer to a live process, or
///   `targetfd` is not open in the target process.
/// - [`Error::PermissionDenied`] — caller does not have `ptrace` access to
///   the target process (`PTRACE_MODE_ATTACH_REALCREDS`).
/// - [`Error::NotImplemented`] — stub.
pub fn sys_pidfd_getfd(pidfd: i32, targetfd: i32, flags: u32) -> Result<i64> {
    if pidfd < 0 || pidfd > FD_MAX {
        return Err(Error::InvalidArgument);
    }
    if targetfd < 0 || targetfd > FD_MAX {
        return Err(Error::InvalidArgument);
    }
    if flags != 0 {
        return Err(Error::InvalidArgument);
    }
    let _ = (pidfd, targetfd, flags);
    Err(Error::NotImplemented)
}

/// Entry point called from the syscall dispatcher.
pub fn do_pidfd_getfd_call(pidfd: i32, targetfd: i32, flags: u32) -> Result<i64> {
    sys_pidfd_getfd(pidfd, targetfd, flags)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn negative_pidfd_rejected() {
        assert_eq!(
            sys_pidfd_getfd(-1, 3, 0).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn negative_targetfd_rejected() {
        assert_eq!(
            sys_pidfd_getfd(3, -1, 0).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn nonzero_flags_rejected() {
        assert_eq!(
            sys_pidfd_getfd(3, 4, 1).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn valid_call_reaches_stub() {
        let r = sys_pidfd_getfd(3, 4, 0);
        assert_eq!(r.unwrap_err(), Error::NotImplemented);
    }
}
