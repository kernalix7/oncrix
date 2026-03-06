// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `gettid(2)` syscall dispatch layer.
//!
//! Returns the caller's thread ID (TID).  In a single-threaded process the
//! TID equals the PID returned by `getpid(2)`.  Each thread in a
//! multi-threaded process has a unique TID.
//!
//! # Syscall signature
//!
//! ```text
//! pid_t gettid(void);
//! ```
//!
//! Takes no arguments and always succeeds.
//!
//! # References
//!
//! - Linux: `kernel/sys.c` (`sys_gettid`)
//! - `gettid(2)` man page

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

/// Handle `gettid(2)`.
///
/// Returns the calling thread's TID as a non-negative `i64`.
///
/// # Errors
///
/// - [`Error::NotImplemented`] — stub; thread context not yet wired.
pub fn sys_gettid() -> Result<i64> {
    Err(Error::NotImplemented)
}

/// Entry point called from the syscall dispatcher.
pub fn do_gettid_call() -> Result<i64> {
    sys_gettid()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gettid_reaches_stub() {
        assert_eq!(sys_gettid().unwrap_err(), Error::NotImplemented);
    }
}
