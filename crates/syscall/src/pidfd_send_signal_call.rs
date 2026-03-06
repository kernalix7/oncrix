// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `pidfd_send_signal(2)` syscall dispatch layer.
//!
//! Sends a signal to the process referred to by a pidfd.  Because the
//! pidfd refers to a specific process (not a PID that may be recycled),
//! this is race-free unlike `kill(2)`.
//!
//! # Syscall signature
//!
//! ```text
//! int pidfd_send_signal(int pidfd, int sig,
//!                       siginfo_t *info, unsigned int flags);
//! ```
//!
//! `sig` 0 is valid and can be used to check process existence without
//! delivering a signal.  `info` may be null; when non-null it must be a
//! valid `siginfo_t` with `si_code` set to `SI_QUEUE` or `SI_USER`.
//! `flags` is currently reserved and must be zero.
//!
//! # References
//!
//! - Linux: `kernel/signal.c` (`sys_pidfd_send_signal`)
//! - `pidfd_send_signal(2)` man page

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum signal number (POSIX minimum is 31; Linux goes to 64).
pub const SIGMAX: i32 = 64;

/// Maximum valid file descriptor number.
const FD_MAX: i32 = 1_048_576;

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

/// Handle `pidfd_send_signal(2)`.
///
/// # Errors
///
/// - [`Error::InvalidArgument`] — `sig` out of range `[0, SIGMAX]`, non-zero
///   `flags`, or `pidfd` out of range.
/// - [`Error::NotFound`] — `pidfd` does not refer to a live process.
/// - [`Error::PermissionDenied`] — caller lacks permission to signal the
///   target process.
/// - [`Error::NotImplemented`] — stub.
pub fn sys_pidfd_send_signal(pidfd: i32, sig: i32, info_ptr: u64, flags: u32) -> Result<i64> {
    if pidfd < 0 || pidfd > FD_MAX {
        return Err(Error::InvalidArgument);
    }
    if sig < 0 || sig > SIGMAX {
        return Err(Error::InvalidArgument);
    }
    if flags != 0 {
        return Err(Error::InvalidArgument);
    }
    let _ = (pidfd, sig, info_ptr, flags);
    Err(Error::NotImplemented)
}

/// Entry point called from the syscall dispatcher.
pub fn do_pidfd_send_signal_call(pidfd: i32, sig: i32, info_ptr: u64, flags: u32) -> Result<i64> {
    sys_pidfd_send_signal(pidfd, sig, info_ptr, flags)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn negative_sig_rejected() {
        assert_eq!(
            sys_pidfd_send_signal(3, -1, 0, 0).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn sig_too_large_rejected() {
        assert_eq!(
            sys_pidfd_send_signal(3, SIGMAX + 1, 0, 0).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn nonzero_flags_rejected() {
        assert_eq!(
            sys_pidfd_send_signal(3, 9, 0, 1).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn sig_zero_check() {
        // sig=0 is valid (existence check).
        let r = sys_pidfd_send_signal(3, 0, 0, 0);
        assert_eq!(r.unwrap_err(), Error::NotImplemented);
    }

    #[test]
    fn valid_signal_reaches_stub() {
        let r = sys_pidfd_send_signal(3, 9, 0, 0);
        assert_eq!(r.unwrap_err(), Error::NotImplemented);
    }
}
