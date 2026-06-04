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
use oncrix_mm::address_space::{USER_SPACE_END, USER_SPACE_START};

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

/// Size of the `mtype` field that precedes the message data in a `msgbuf`.
///
/// POSIX `struct msgbuf` begins with `long mtype` (8 bytes on 64-bit).
const MTYPE_SIZE: usize = 8;

/// Validate that `ptr` and the given `total` byte length form a
/// well-formed user-space range: non-null, no wrap-around, and
/// entirely within the canonical user lower-half window.
///
/// Returns [`Error::InvalidArgument`] (→ `EFAULT`) on any violation.
fn validate_user_msgbuf(ptr: u64, total: usize) -> Result<()> {
    // NULL pointer is always invalid.
    if ptr == 0 {
        return Err(Error::InvalidArgument);
    }
    // Must start within the canonical user window.
    if ptr < USER_SPACE_START {
        return Err(Error::InvalidArgument);
    }
    // Checked end — guards against wrap-around with attacker-supplied size.
    let end = ptr
        .checked_add(total as u64)
        .ok_or(Error::InvalidArgument)?;
    // End must not exceed the top of user space.
    if end > USER_SPACE_END.saturating_add(1) {
        return Err(Error::InvalidArgument);
    }
    Ok(())
}

/// Handle `msgsnd(2)`.
///
/// Enqueues a message onto queue `msqid`.  `msgp_ptr` is a user-space pointer
/// to a `msgbuf`-compatible structure; `msgsz` is the data length (not counting
/// the 8-byte `mtype` field); `msgflg` controls blocking behaviour.
///
/// # Errors
///
/// - [`Error::InvalidArgument`] — `msqid < 0`, null or out-of-range
///   `msgp_ptr`, `msgsz` that overflows when added to the `mtype` header
///   size, or `msgsz > MSGMAX`.
/// - [`Error::WouldBlock`] — queue full and `IPC_NOWAIT` set.
/// - [`Error::NotImplemented`] — stub.
pub fn sys_msgsnd(msqid: i32, msgp_ptr: u64, msgsz: usize, msgflg: i32) -> Result<i64> {
    if msqid < 0 {
        return Err(Error::InvalidArgument);
    }
    if msgsz > MSGMAX {
        return Err(Error::InvalidArgument);
    }
    // Total buffer size = 8-byte mtype header + msgsz data bytes.
    // Use checked_add so an attacker cannot craft msgsz = usize::MAX - 7
    // to bypass the size check.
    let total = MTYPE_SIZE
        .checked_add(msgsz)
        .ok_or(Error::InvalidArgument)?;
    // Validate the entire user buffer before any future deref.
    validate_user_msgbuf(msgp_ptr, total)?;
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
        // Use a valid user-space address (above USER_SPACE_START = 0x40_0000).
        let r = sys_msgsnd(0, 0x0000_0000_0080_0000, 64, 0);
        assert_eq!(r.unwrap_err(), Error::NotImplemented);
    }

    #[test]
    fn zero_length_msg_valid() {
        // Use a valid user-space address (above USER_SPACE_START = 0x40_0000).
        let r = sys_msgsnd(1, 0x0000_0000_0080_0000, 0, IPC_NOWAIT);
        assert_eq!(r.unwrap_err(), Error::NotImplemented);
    }

    #[test]
    fn kernel_addr_rejected() {
        // Addresses in the kernel higher half must be rejected.
        assert_eq!(
            sys_msgsnd(0, 0xFFFF_8000_0000_0000, 64, 0).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn below_user_start_rejected() {
        // Addresses below USER_SPACE_START (0x40_0000) must be rejected.
        assert_eq!(
            sys_msgsnd(0, 0x1000, 64, 0).unwrap_err(),
            Error::InvalidArgument
        );
    }
}
