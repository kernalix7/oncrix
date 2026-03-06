// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `sigpending(2)` / `rt_sigpending(2)` syscall dispatch layer.
//!
//! Returns the set of pending signals — signals that have been raised but
//! are currently blocked.  The result is written to a caller-supplied
//! `sigset_t`.
//!
//! # Syscall signature
//!
//! ```text
//! int sigpending(sigset_t *set);
//! int rt_sigpending(sigset_t *set, size_t sigsetsize);
//! ```
//!
//! # POSIX reference
//!
//! - POSIX.1-2024: `sigpending()` in `<signal.h>`
//! - `.TheOpenGroup/susv5-html/functions/sigpending.html`
//!
//! # References
//!
//! - Linux: `kernel/signal.c` (`sys_rt_sigpending`)
//! - `sigpending(2)` man page

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Expected size of `sigset_t` in bytes.
pub const SIGSET_SIZE: usize = 8;

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

/// Handle `rt_sigpending(2)`.
///
/// # Errors
///
/// - [`Error::InvalidArgument`] — null `set_ptr` or `sigsetsize` mismatch.
/// - [`Error::NotImplemented`] — stub.
pub fn sys_rt_sigpending(set_ptr: u64, sigsetsize: usize) -> Result<i64> {
    if set_ptr == 0 {
        return Err(Error::InvalidArgument);
    }
    if sigsetsize != SIGSET_SIZE {
        return Err(Error::InvalidArgument);
    }
    let _ = (set_ptr, sigsetsize);
    Err(Error::NotImplemented)
}

/// Entry point called from the syscall dispatcher.
pub fn do_sigpending_call(set_ptr: u64, sigsetsize: usize) -> Result<i64> {
    sys_rt_sigpending(set_ptr, sigsetsize)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn null_set_rejected() {
        assert_eq!(
            sys_rt_sigpending(0, SIGSET_SIZE).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn wrong_size_rejected() {
        assert_eq!(
            sys_rt_sigpending(0x1000, 16).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn valid_call_reaches_stub() {
        let r = sys_rt_sigpending(0x1000, SIGSET_SIZE);
        assert_eq!(r.unwrap_err(), Error::NotImplemented);
    }
}
