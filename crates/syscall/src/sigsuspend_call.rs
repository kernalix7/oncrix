// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `sigsuspend(2)` / `rt_sigsuspend(2)` syscall dispatch layer.
//!
//! Temporarily replaces the calling thread's signal mask with `mask` and
//! suspends execution until a signal is delivered that invokes a signal
//! handler or terminates the thread.  On return, the previous signal mask
//! is restored.
//!
//! The call always returns -1 with errno `EINTR` when a signal handler
//! returns (POSIX requirement).
//!
//! # Syscall signature
//!
//! ```text
//! int sigsuspend(const sigset_t *mask);
//! int rt_sigsuspend(const sigset_t *unewset, size_t sigsetsize);
//! ```
//!
//! # POSIX reference
//!
//! - POSIX.1-2024: `sigsuspend()` in `<signal.h>`
//! - `.TheOpenGroup/susv5-html/functions/sigsuspend.html`
//!
//! # References
//!
//! - Linux: `kernel/signal.c` (`sys_rt_sigsuspend`)
//! - `sigsuspend(2)` man page

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Expected size of `sigset_t` in bytes.
pub const SIGSET_SIZE: usize = 8;

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

/// Handle `rt_sigsuspend(2)`.
///
/// This call is expected to return `EINTR` when a signal is received.
/// The stub returns `NotImplemented` since the scheduler is not yet wired.
///
/// # Errors
///
/// - [`Error::InvalidArgument`] — null `mask_ptr` or `sigsetsize` mismatch.
/// - [`Error::Interrupted`] — a signal was received (normal return path).
/// - [`Error::NotImplemented`] — stub.
pub fn sys_rt_sigsuspend(mask_ptr: u64, sigsetsize: usize) -> Result<i64> {
    if mask_ptr == 0 {
        return Err(Error::InvalidArgument);
    }
    if sigsetsize != SIGSET_SIZE {
        return Err(Error::InvalidArgument);
    }
    let _ = (mask_ptr, sigsetsize);
    Err(Error::NotImplemented)
}

/// Entry point called from the syscall dispatcher.
pub fn do_sigsuspend_call(mask_ptr: u64, sigsetsize: usize) -> Result<i64> {
    sys_rt_sigsuspend(mask_ptr, sigsetsize)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn null_mask_rejected() {
        assert_eq!(
            sys_rt_sigsuspend(0, SIGSET_SIZE).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn wrong_size_rejected() {
        assert_eq!(
            sys_rt_sigsuspend(0x1000, 4).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn valid_call_reaches_stub() {
        let r = sys_rt_sigsuspend(0x1000, SIGSET_SIZE);
        assert_eq!(r.unwrap_err(), Error::NotImplemented);
    }
}
