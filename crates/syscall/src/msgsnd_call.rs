// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `msgsnd(2)` syscall dispatch layer.
//!
//! Sends a message to a System V message queue.
//!
//! # Syscall signature
//!
//! ```text
//! int msgsnd(int msqid, const void *msgp, size_t msgsz, int msgflg);
//! ```
//!
//! `msgp` points to a caller-defined structure whose first member is a `long`
//! message type (> 0), followed by up to `msgsz` bytes of data.
//!
//! # POSIX reference
//!
//! - POSIX.1-2024: `msgsnd()` in `<sys/msg.h>`
//! - `.TheOpenGroup/susv5-html/functions/msgsnd.html`
//!
//! # References
//!
//! - Linux: `ipc/msg.c` (`sys_msgsnd`)
//! - `msgsnd(2)` man page

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum message data size per POSIX/Linux default.
pub const MSGMAX: usize = 8192;

/// Do not block; return `EAGAIN` if the queue is full.
pub const IPC_NOWAIT: i32 = 0x0800;

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

/// Handle `msgsnd(2)`.
///
/// Enqueues a message onto queue `msqid`.  `msgp_ptr` is a user-space pointer
/// to a `msgbuf`-compatible structure; `msgsz` is the data length (not counting
/// the 8-byte mtype field); `msgflg` controls blocking behaviour.
///
/// # Errors
///
/// - [`Error::InvalidArgument`] — `msqid < 0`, null `msgp_ptr`, or
///   `msgsz > MSGMAX`.
/// - [`Error::WouldBlock`] — queue full and `IPC_NOWAIT` set.
/// - [`Error::NotImplemented`] — stub.
pub fn sys_msgsnd(msqid: i32, msgp_ptr: u64, msgsz: usize, msgflg: i32) -> Result<i64> {
    if msqid < 0 {
        return Err(Error::InvalidArgument);
    }
    if msgp_ptr == 0 {
        return Err(Error::InvalidArgument);
    }
    if msgsz > MSGMAX {
        return Err(Error::InvalidArgument);
    }
    let _ = (msqid, msgp_ptr, msgsz, msgflg);
    Err(Error::NotImplemented)
}

/// Entry point called from the syscall dispatcher.
pub fn do_msgsnd_call(msqid: i32, msgp_ptr: u64, msgsz: usize, msgflg: i32) -> Result<i64> {
    sys_msgsnd(msqid, msgp_ptr, msgsz, msgflg)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn negative_msqid_rejected() {
        assert_eq!(
            sys_msgsnd(-1, 0x1000, 64, 0).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn null_msgp_rejected() {
        assert_eq!(sys_msgsnd(0, 0, 64, 0).unwrap_err(), Error::InvalidArgument);
    }

    #[test]
    fn oversized_msg_rejected() {
        assert_eq!(
            sys_msgsnd(0, 0x1000, MSGMAX + 1, 0).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn valid_call_reaches_stub() {
        let r = sys_msgsnd(0, 0x1000, 64, 0);
        assert_eq!(r.unwrap_err(), Error::NotImplemented);
    }

    #[test]
    fn zero_length_msg_valid() {
        let r = sys_msgsnd(1, 0x2000, 0, IPC_NOWAIT);
        assert_eq!(r.unwrap_err(), Error::NotImplemented);
    }
}
