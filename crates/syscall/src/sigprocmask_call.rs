// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `sigprocmask(2)` / `rt_sigprocmask(2)` syscall dispatch layer.
//!
//! Examines and changes the calling thread's signal mask.  The signal mask
//! is the set of signals whose delivery is currently blocked.
//!
//! # Syscall signature
//!
//! ```text
//! int sigprocmask(int how, const sigset_t *set, sigset_t *oldset);
//! int rt_sigprocmask(int how, const sigset_t *set, sigset_t *oldset,
//!                    size_t sigsetsize);
//! ```
//!
//! # `how` values
//!
//! | Constant    | Value | Description |
//! |-------------|-------|-------------|
//! | `SIG_BLOCK`   | 0   | Add `set` to the mask |
//! | `SIG_UNBLOCK` | 1   | Remove `set` from the mask |
//! | `SIG_SETMASK` | 2   | Replace the mask with `set` |
//!
//! # POSIX reference
//!
//! - POSIX.1-2024: `sigprocmask()` in `<signal.h>`
//! - `.TheOpenGroup/susv5-html/functions/sigprocmask.html`
//!
//! # References
//!
//! - Linux: `kernel/signal.c` (`sys_rt_sigprocmask`)
//! - `sigprocmask(2)` man page

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Add `set` to the current signal mask.
pub const SIG_BLOCK: i32 = 0;
/// Remove `set` from the current signal mask.
pub const SIG_UNBLOCK: i32 = 1;
/// Replace the current signal mask with `set`.
pub const SIG_SETMASK: i32 = 2;

/// Expected size of `sigset_t` in bytes (64 signals / 8 bits).
pub const SIGSET_SIZE: usize = 8;

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

/// Handle `rt_sigprocmask(2)`.
///
/// Either `set_ptr` or `oldset_ptr` (or both) must be non-null.
/// `sigsetsize` must equal `SIGSET_SIZE`.
///
/// # Errors
///
/// - [`Error::InvalidArgument`] — unknown `how`, `sigsetsize` mismatch, or
///   both `set_ptr` and `oldset_ptr` are null.
/// - [`Error::NotImplemented`] — stub.
pub fn sys_rt_sigprocmask(
    how: i32,
    set_ptr: u64,
    oldset_ptr: u64,
    sigsetsize: usize,
) -> Result<i64> {
    if sigsetsize != SIGSET_SIZE {
        return Err(Error::InvalidArgument);
    }
    if set_ptr == 0 && oldset_ptr == 0 {
        return Err(Error::InvalidArgument);
    }
    if set_ptr != 0 && !matches!(how, SIG_BLOCK | SIG_UNBLOCK | SIG_SETMASK) {
        return Err(Error::InvalidArgument);
    }
    let _ = (how, set_ptr, oldset_ptr, sigsetsize);
    Err(Error::NotImplemented)
}

/// Entry point called from the syscall dispatcher.
pub fn do_sigprocmask_call(
    how: i32,
    set_ptr: u64,
    oldset_ptr: u64,
    sigsetsize: usize,
) -> Result<i64> {
    sys_rt_sigprocmask(how, set_ptr, oldset_ptr, sigsetsize)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wrong_sigsetsize_rejected() {
        assert_eq!(
            sys_rt_sigprocmask(SIG_BLOCK, 0x1000, 0, 16).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn both_null_rejected() {
        assert_eq!(
            sys_rt_sigprocmask(SIG_BLOCK, 0, 0, SIGSET_SIZE).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn unknown_how_with_set_rejected() {
        assert_eq!(
            sys_rt_sigprocmask(99, 0x1000, 0, SIGSET_SIZE).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn get_only_null_set_ok() {
        // set_ptr=0 means get only; how is irrelevant.
        let r = sys_rt_sigprocmask(SIG_BLOCK, 0, 0x2000, SIGSET_SIZE);
        assert_eq!(r.unwrap_err(), Error::NotImplemented);
    }

    #[test]
    fn block_with_set_ok() {
        let r = sys_rt_sigprocmask(SIG_BLOCK, 0x1000, 0x2000, SIGSET_SIZE);
        assert_eq!(r.unwrap_err(), Error::NotImplemented);
    }
}
