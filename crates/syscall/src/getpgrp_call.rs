// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `getpgrp(2)` / `getpgid(2)` syscall dispatch layer.
//!
//! `getpgrp()` returns the process group ID of the calling process.
//! `getpgid(pid)` returns the process group ID of the process with the
//! given PID; when `pid` is 0 it is equivalent to `getpgrp()`.
//!
//! # Syscall signatures
//!
//! ```text
//! pid_t getpgrp(void);
//! pid_t getpgid(pid_t pid);
//! ```
//!
//! # POSIX reference
//!
//! - POSIX.1-2024: `getpgid()`, `getpgrp()` in `<unistd.h>`
//! - `.TheOpenGroup/susv5-html/functions/getpgid.html`
//!
//! # References
//!
//! - Linux: `kernel/sys.c` (`sys_getpgid`)
//! - `getpgid(2)` man page

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

/// Handle `getpgid(2)`.
///
/// When `pid` is 0 the caller's own PGID is returned.
///
/// # Errors
///
/// - [`Error::NotFound`] — no process with the given `pid` exists.
/// - [`Error::NotImplemented`] — stub.
pub fn sys_getpgid(pid: u32) -> Result<i64> {
    let _ = pid;
    Err(Error::NotImplemented)
}

/// Handle `getpgrp(2)` — equivalent to `getpgid(0)`.
pub fn sys_getpgrp() -> Result<i64> {
    sys_getpgid(0)
}

/// Entry point for `getpgid` from the syscall dispatcher.
pub fn do_getpgid_call(pid: u32) -> Result<i64> {
    sys_getpgid(pid)
}

/// Entry point for `getpgrp` from the syscall dispatcher.
pub fn do_getpgrp_call() -> Result<i64> {
    sys_getpgrp()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn getpgrp_reaches_stub() {
        assert_eq!(sys_getpgrp().unwrap_err(), Error::NotImplemented);
    }

    #[test]
    fn getpgid_zero_reaches_stub() {
        assert_eq!(sys_getpgid(0).unwrap_err(), Error::NotImplemented);
    }

    #[test]
    fn getpgid_pid_reaches_stub() {
        assert_eq!(sys_getpgid(1234).unwrap_err(), Error::NotImplemented);
    }
}
