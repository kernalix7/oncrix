// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `getsid(2)` syscall dispatch layer.
//!
//! Returns the session ID of the process with the given PID.  When `pid`
//! is 0 the session ID of the calling process is returned.
//!
//! # Syscall signature
//!
//! ```text
//! pid_t getsid(pid_t pid);
//! ```
//!
//! # POSIX reference
//!
//! - POSIX.1-2024: `getsid()` in `<unistd.h>`
//! - `.TheOpenGroup/susv5-html/functions/getsid.html`
//!
//! # References
//!
//! - Linux: `kernel/sys.c` (`sys_getsid`)
//! - `getsid(2)` man page

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

/// Handle `getsid(2)`.
///
/// When `pid` is 0 returns the session ID of the calling process.
///
/// # Errors
///
/// - [`Error::NotFound`] — no process with `pid` exists.
/// - [`Error::PermissionDenied`] — the target process is in a different
///   session (Linux restriction).
/// - [`Error::NotImplemented`] — stub.
pub fn sys_getsid(pid: u32) -> Result<i64> {
    let _ = pid;
    Err(Error::NotImplemented)
}

/// Entry point called from the syscall dispatcher.
pub fn do_getsid_call(pid: u32) -> Result<i64> {
    sys_getsid(pid)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn getsid_self_reaches_stub() {
        assert_eq!(sys_getsid(0).unwrap_err(), Error::NotImplemented);
    }

    #[test]
    fn getsid_pid_reaches_stub() {
        assert_eq!(sys_getsid(1234).unwrap_err(), Error::NotImplemented);
    }
}
