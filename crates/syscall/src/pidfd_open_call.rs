// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `pidfd_open(2)` syscall dispatch layer.
//!
//! Creates a file descriptor that refers to a process identified by its PID.
//! The returned pidfd can be used with `poll(2)`, `waitid(2)` (with
//! `P_PIDFD`), `pidfd_send_signal(2)`, and `pidfd_getfd(2)`.
//!
//! # Syscall signature
//!
//! ```text
//! int pidfd_open(pid_t pid, unsigned int flags);
//! ```
//!
//! Currently the only defined flag is `PIDFD_NONBLOCK` (value 2048).
//!
//! # References
//!
//! - Linux: `kernel/pid.c` (`sys_pidfd_open`)
//! - `pidfd_open(2)` man page

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Set `O_NONBLOCK` on the returned file descriptor.
pub const PIDFD_NONBLOCK: u32 = 2048;

/// All valid flag bits.
const FLAGS_VALID: u32 = PIDFD_NONBLOCK;

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

/// Handle `pidfd_open(2)`.
///
/// `pid` must be a positive integer (PID 0 is not a valid target).
///
/// # Errors
///
/// - [`Error::InvalidArgument`] — `pid` is zero or negative, or unknown flags.
/// - [`Error::NotFound`] — no process with `pid` exists.
/// - [`Error::NotImplemented`] — stub.
pub fn sys_pidfd_open(pid: u32, flags: u32) -> Result<i64> {
    if pid == 0 {
        return Err(Error::InvalidArgument);
    }
    if flags & !FLAGS_VALID != 0 {
        return Err(Error::InvalidArgument);
    }
    let _ = (pid, flags);
    Err(Error::NotImplemented)
}

/// Entry point called from the syscall dispatcher.
pub fn do_pidfd_open_call(pid: u32, flags: u32) -> Result<i64> {
    sys_pidfd_open(pid, flags)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pid_zero_rejected() {
        assert_eq!(sys_pidfd_open(0, 0).unwrap_err(), Error::InvalidArgument);
    }

    #[test]
    fn unknown_flags_rejected() {
        assert_eq!(sys_pidfd_open(1, 0x01).unwrap_err(), Error::InvalidArgument);
    }

    #[test]
    fn valid_call_reaches_stub() {
        let r = sys_pidfd_open(1234, 0);
        assert_eq!(r.unwrap_err(), Error::NotImplemented);
    }

    #[test]
    fn nonblock_flag_ok() {
        let r = sys_pidfd_open(1234, PIDFD_NONBLOCK);
        assert_eq!(r.unwrap_err(), Error::NotImplemented);
    }
}
