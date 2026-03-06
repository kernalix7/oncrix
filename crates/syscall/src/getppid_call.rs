// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `getppid(2)` syscall dispatch layer.
//!
//! Returns the process ID of the parent of the calling process.  If the
//! parent has already exited, the calling process has been reparented to
//! `init` (PID 1) or the nearest subreaper, whose PID is returned.
//!
//! # Syscall signature
//!
//! ```text
//! pid_t getppid(void);
//! ```
//!
//! Takes no arguments and always succeeds.
//!
//! # POSIX reference
//!
//! - POSIX.1-2024: `getppid()` in `<unistd.h>`
//! - `.TheOpenGroup/susv5-html/functions/getppid.html`
//!
//! # References
//!
//! - Linux: `kernel/sys.c` (`sys_getppid`)
//! - `getppid(2)` man page

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

/// Handle `getppid(2)`.
///
/// # Errors
///
/// - [`Error::NotImplemented`] — stub; process table not yet wired.
pub fn sys_getppid() -> Result<i64> {
    Err(Error::NotImplemented)
}

/// Entry point called from the syscall dispatcher.
pub fn do_getppid_call() -> Result<i64> {
    sys_getppid()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn getppid_reaches_stub() {
        assert_eq!(sys_getppid().unwrap_err(), Error::NotImplemented);
    }
}
