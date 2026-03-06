// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `setsid(2)` syscall dispatch layer.
//!
//! Creates a new session and sets the process group ID of the calling
//! process to its PID.  The calling process becomes the session leader
//! of the new session, which has no controlling terminal.
//!
//! `setsid(2)` fails with `EPERM` if the calling process is already a
//! process group leader (i.e. its PID equals its PGID).
//!
//! # Syscall signature
//!
//! ```text
//! pid_t setsid(void);
//! ```
//!
//! Returns the new session ID on success.
//!
//! # POSIX reference
//!
//! - POSIX.1-2024: `setsid()` in `<unistd.h>`
//! - `.TheOpenGroup/susv5-html/functions/setsid.html`
//!
//! # References
//!
//! - Linux: `kernel/sys.c` (`sys_setsid`)
//! - `setsid(2)` man page

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

/// Handle `setsid(2)`.
///
/// # Errors
///
/// - [`Error::PermissionDenied`] — the calling process is already a process
///   group leader.
/// - [`Error::NotImplemented`] — stub.
pub fn sys_setsid() -> Result<i64> {
    Err(Error::NotImplemented)
}

/// Entry point called from the syscall dispatcher.
pub fn do_setsid_call() -> Result<i64> {
    sys_setsid()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn setsid_reaches_stub() {
        assert_eq!(sys_setsid().unwrap_err(), Error::NotImplemented);
    }
}
