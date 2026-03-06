// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `pipe(2)` and `pipe2(2)` syscall dispatch layer.
//!
//! Creates a pipe — a unidirectional data channel.
//!
//! # Syscall signatures
//!
//! ```text
//! int pipe(int pipefd[2]);
//! int pipe2(int pipefd[2], int flags);
//! ```
//!
//! `pipe2` extends `pipe` with flags controlling `O_CLOEXEC`, `O_NONBLOCK`,
//! and `O_DIRECT` (packet mode).
//!
//! # POSIX reference
//!
//! - POSIX.1-2024: `pipe()` in `<unistd.h>`
//! - `.TheOpenGroup/susv5-html/functions/pipe.html`
//!
//! # References
//!
//! - Linux: `fs/pipe.c` (`sys_pipe2`)

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Close-on-exec on both ends.
pub const O_CLOEXEC: i32 = 0o2000000;
/// Non-blocking I/O on both ends.
pub const O_NONBLOCK: i32 = 0o4000;
/// Packet (direct) mode pipe.
pub const O_DIRECT: i32 = 0o40000;

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// Handle `pipe(2)`.
///
/// `pipefd_ptr` is a user-space pointer to an `int[2]` array that receives
/// the read (index 0) and write (index 1) file descriptors.
///
/// # Errors
///
/// - [`Error::InvalidArgument`] — null `pipefd_ptr`.
/// - [`Error::NotImplemented`] — stub.
pub fn sys_pipe(pipefd_ptr: u64) -> Result<i64> {
    if pipefd_ptr == 0 {
        return Err(Error::InvalidArgument);
    }
    let _ = pipefd_ptr;
    Err(Error::NotImplemented)
}

/// Handle `pipe2(2)`.
///
/// Like `pipe` with optional `O_CLOEXEC`, `O_NONBLOCK`, and/or `O_DIRECT`
/// flags applied atomically to both file descriptors.
///
/// # Errors
///
/// - [`Error::InvalidArgument`] — null `pipefd_ptr` or unknown flag bits.
/// - [`Error::NotImplemented`] — stub.
pub fn sys_pipe2(pipefd_ptr: u64, flags: i32) -> Result<i64> {
    if pipefd_ptr == 0 {
        return Err(Error::InvalidArgument);
    }
    if flags & !(O_CLOEXEC | O_NONBLOCK | O_DIRECT) != 0 {
        return Err(Error::InvalidArgument);
    }
    let _ = (pipefd_ptr, flags);
    Err(Error::NotImplemented)
}

/// Entry point for `pipe` from the syscall dispatcher.
pub fn do_pipe_call(pipefd_ptr: u64) -> Result<i64> {
    sys_pipe(pipefd_ptr)
}

/// Entry point for `pipe2` from the syscall dispatcher.
pub fn do_pipe2_call(pipefd_ptr: u64, flags: i32) -> Result<i64> {
    sys_pipe2(pipefd_ptr, flags)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pipe_null_ptr_rejected() {
        assert_eq!(sys_pipe(0).unwrap_err(), Error::InvalidArgument);
    }

    #[test]
    fn pipe_valid_reaches_stub() {
        let r = sys_pipe(0x1000);
        assert_eq!(r.unwrap_err(), Error::NotImplemented);
    }

    #[test]
    fn pipe2_null_ptr_rejected() {
        assert_eq!(sys_pipe2(0, O_CLOEXEC).unwrap_err(), Error::InvalidArgument);
    }

    #[test]
    fn pipe2_unknown_flags_rejected() {
        assert_eq!(
            sys_pipe2(0x1000, 0x0002).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn pipe2_cloexec_nonblock_reaches_stub() {
        let r = sys_pipe2(0x1000, O_CLOEXEC | O_NONBLOCK);
        assert_eq!(r.unwrap_err(), Error::NotImplemented);
    }

    #[test]
    fn pipe2_direct_mode_reaches_stub() {
        let r = sys_pipe2(0x1000, O_DIRECT);
        assert_eq!(r.unwrap_err(), Error::NotImplemented);
    }
}
