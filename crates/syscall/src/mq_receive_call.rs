// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `mq_receive(2)` and `mq_timedreceive(2)` syscall dispatch layer.
//!
//! Receives a message from a POSIX message queue.
//!
//! # Syscall signatures
//!
//! ```text
//! ssize_t mq_receive(mqd_t mqdes, char *msg_ptr,
//!                    size_t msg_len, unsigned int *msg_prio);
//!
//! ssize_t mq_timedreceive(mqd_t mqdes, char *msg_ptr,
//!                          size_t msg_len, unsigned int *msg_prio,
//!                          const struct timespec *abs_timeout);
//! ```
//!
//! # POSIX reference
//!
//! - POSIX.1-2024: `mq_receive()` in `<mqueue.h>`
//! - `.TheOpenGroup/susv5-html/functions/mq_receive.html`
//!
//! # References
//!
//! - Linux: `ipc/mqueue.c` (`sys_mq_timedreceive`)

use oncrix_lib::{Error, Result};

// Re-export the max message size constant.
pub use crate::mq_send_call::MQ_MSGSIZE_MAX;

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// Handle `mq_receive(2)`.
///
/// Receives the highest-priority message from the queue `mqdes` into the
/// buffer at `msg_ptr` (at least `msg_len` bytes).  If `msg_prio_ptr` is
/// non-null, the message priority is written there.
///
/// Returns the number of bytes in the received message on success.
///
/// # Errors
///
/// - [`Error::InvalidArgument`] — `mqdes < 0`, null `msg_ptr`, or
///   `msg_len > MQ_MSGSIZE_MAX`.
/// - [`Error::WouldBlock`] — queue is empty and descriptor is non-blocking.
/// - [`Error::NotImplemented`] — stub.
pub fn sys_mq_receive(mqdes: i32, msg_ptr: u64, msg_len: usize, msg_prio_ptr: u64) -> Result<i64> {
    if mqdes < 0 {
        return Err(Error::InvalidArgument);
    }
    if msg_ptr == 0 {
        return Err(Error::InvalidArgument);
    }
    if msg_len > MQ_MSGSIZE_MAX {
        return Err(Error::InvalidArgument);
    }
    let _ = (mqdes, msg_ptr, msg_len, msg_prio_ptr);
    Err(Error::NotImplemented)
}

/// Handle `mq_timedreceive(2)`.
///
/// Like `mq_receive` but blocks until the absolute timeout `abs_timeout_ptr`
/// (a `struct timespec` in user space) if the queue is empty.
///
/// # Errors
///
/// - Same as `sys_mq_receive` plus:
/// - [`Error::InvalidArgument`] — null `abs_timeout_ptr`.
/// - [`Error::NotImplemented`] — stub.
pub fn sys_mq_timedreceive(
    mqdes: i32,
    msg_ptr: u64,
    msg_len: usize,
    msg_prio_ptr: u64,
    abs_timeout_ptr: u64,
) -> Result<i64> {
    if mqdes < 0 {
        return Err(Error::InvalidArgument);
    }
    if msg_ptr == 0 {
        return Err(Error::InvalidArgument);
    }
    if msg_len > MQ_MSGSIZE_MAX {
        return Err(Error::InvalidArgument);
    }
    if abs_timeout_ptr == 0 {
        return Err(Error::InvalidArgument);
    }
    let _ = (mqdes, msg_ptr, msg_len, msg_prio_ptr, abs_timeout_ptr);
    Err(Error::NotImplemented)
}

/// Entry point for `mq_receive` from the syscall dispatcher.
pub fn do_mq_receive_call(
    mqdes: i32,
    msg_ptr: u64,
    msg_len: usize,
    msg_prio_ptr: u64,
) -> Result<i64> {
    sys_mq_receive(mqdes, msg_ptr, msg_len, msg_prio_ptr)
}

/// Entry point for `mq_timedreceive` from the syscall dispatcher.
pub fn do_mq_timedreceive_call(
    mqdes: i32,
    msg_ptr: u64,
    msg_len: usize,
    msg_prio_ptr: u64,
    abs_timeout_ptr: u64,
) -> Result<i64> {
    sys_mq_timedreceive(mqdes, msg_ptr, msg_len, msg_prio_ptr, abs_timeout_ptr)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn negative_mqdes_rejected() {
        assert_eq!(
            sys_mq_receive(-1, 0x1000, 64, 0).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn null_msg_ptr_rejected() {
        assert_eq!(
            sys_mq_receive(3, 0, 64, 0).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn oversized_msg_len_rejected() {
        assert_eq!(
            sys_mq_receive(3, 0x1000, MQ_MSGSIZE_MAX + 1, 0).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn valid_receive_reaches_stub() {
        let r = sys_mq_receive(3, 0x1000, 64, 0x2000);
        assert_eq!(r.unwrap_err(), Error::NotImplemented);
    }

    #[test]
    fn timedreceive_null_timeout_rejected() {
        assert_eq!(
            sys_mq_timedreceive(3, 0x1000, 64, 0, 0).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn valid_timedreceive_reaches_stub() {
        let r = sys_mq_timedreceive(3, 0x1000, 64, 0x2000, 0x3000);
        assert_eq!(r.unwrap_err(), Error::NotImplemented);
    }
}
