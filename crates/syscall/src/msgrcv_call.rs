// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `msgrcv(2)` syscall dispatch layer.
//!
//! Receives a message from a System V message queue.
//!
//! # Syscall signature
//!
//! ```text
//! ssize_t msgrcv(int msqid, void *msgp, size_t msgsz,
//!                long msgtyp, int msgflg);
//! ```
//!
//! `msgtyp` selects the message to receive:
//! - 0: first message in the queue
//! - > 0: first message of that type
//! - < 0: first message with type <= |msgtyp|
//!
//! # POSIX reference
//!
//! - POSIX.1-2024: `msgrcv()` in `<sys/msg.h>`
//! - `.TheOpenGroup/susv5-html/functions/msgrcv.html`
//!
//! # References
//!
//! - Linux: `ipc/msg.c` (`sys_msgrcv`)
//! - `msgrcv(2)` man page

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum message data size.
pub const MSGMAX: usize = 8192;

/// Do not block; return immediately if no matching message.
pub const IPC_NOWAIT: i32 = 0x0800;
/// Remove message even if its data is larger than `msgsz`.
pub const MSG_NOERROR: i32 = 0x1000;
/// Receive messages in type order (Linux extension).
pub const MSG_EXCEPT: i32 = 0x2000;
/// Copy message without removing from queue (Linux 3.8+).
pub const MSG_COPY: i32 = 0x4000;

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

/// Returns `true` if `msgflg` contains only known flag bits.
pub fn flags_valid(msgflg: i32) -> bool {
    let known = IPC_NOWAIT | MSG_NOERROR | MSG_EXCEPT | MSG_COPY;
    msgflg & !known == 0
}

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

/// Handle `msgrcv(2)`.
///
/// Dequeues the first message matching `msgtyp` from queue `msqid` and copies
/// up to `msgsz` bytes of its data payload into the caller's buffer at
/// `msgp_ptr`.
///
/// # Errors
///
/// - [`Error::InvalidArgument`] — `msqid < 0`, null `msgp_ptr`, `msgsz > MSGMAX`,
///   or unknown flag bits.
/// - [`Error::WouldBlock`] — no matching message and `IPC_NOWAIT` set.
/// - [`Error::NotFound`] — queue does not exist.
/// - [`Error::NotImplemented`] — stub.
pub fn sys_msgrcv(
    msqid: i32,
    msgp_ptr: u64,
    msgsz: usize,
    msgtyp: i64,
    msgflg: i32,
) -> Result<i64> {
    if msqid < 0 {
        return Err(Error::InvalidArgument);
    }
    if msgp_ptr == 0 {
        return Err(Error::InvalidArgument);
    }
    if msgsz > MSGMAX {
        return Err(Error::InvalidArgument);
    }
    if !flags_valid(msgflg) {
        return Err(Error::InvalidArgument);
    }
    let _ = (msqid, msgp_ptr, msgsz, msgtyp, msgflg);
    Err(Error::NotImplemented)
}

/// Entry point called from the syscall dispatcher.
pub fn do_msgrcv_call(
    msqid: i32,
    msgp_ptr: u64,
    msgsz: usize,
    msgtyp: i64,
    msgflg: i32,
) -> Result<i64> {
    sys_msgrcv(msqid, msgp_ptr, msgsz, msgtyp, msgflg)
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
            sys_msgrcv(-1, 0x1000, 64, 0, 0).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn null_msgp_rejected() {
        assert_eq!(
            sys_msgrcv(0, 0, 64, 0, 0).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn oversized_msgsz_rejected() {
        assert_eq!(
            sys_msgrcv(0, 0x1000, MSGMAX + 1, 0, 0).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn unknown_flags_rejected() {
        assert_eq!(
            sys_msgrcv(0, 0x1000, 64, 0, 0xFF00).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn valid_call_reaches_stub() {
        let r = sys_msgrcv(0, 0x1000, 128, 0, 0);
        assert_eq!(r.unwrap_err(), Error::NotImplemented);
    }

    #[test]
    fn negative_msgtyp_valid() {
        let r = sys_msgrcv(1, 0x2000, 64, -5, MSG_NOERROR);
        assert_eq!(r.unwrap_err(), Error::NotImplemented);
    }
}
