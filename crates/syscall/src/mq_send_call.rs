// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `mq_send(2)` and `mq_timedsend(2)` syscall dispatch layer.
//!
//! Sends a message to a POSIX message queue.
//!
//! # Syscall signatures
//!
//! ```text
//! int mq_send(mqd_t mqdes, const char *msg_ptr,
//!             size_t msg_len, unsigned int msg_prio);
//!
//! int mq_timedsend(mqd_t mqdes, const char *msg_ptr,
//!                  size_t msg_len, unsigned int msg_prio,
//!                  const struct timespec *abs_timeout);
//! ```
//!
//! # POSIX reference
//!
//! - POSIX.1-2024: `mq_send()` in `<mqueue.h>`
//! - `.TheOpenGroup/susv5-html/functions/mq_send.html`
//!
//! # References
//!
//! - Linux: `ipc/mqueue.c` (`sys_mq_timedsend`)

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum message priority (POSIX requires at least MQ_PRIO_MAX = 32768).
pub const MQ_PRIO_MAX: u32 = 32768;

/// Maximum message size per send.
pub const MQ_MSGSIZE_MAX: usize = 16 * 1024 * 1024; // 16 MiB

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// Handle `mq_send(2)`.
///
/// `mqdes` is a message queue descriptor.  `msg_ptr` is a user-space pointer
/// to the message data.  `msg_prio` must be < `MQ_PRIO_MAX`.
///
/// # Errors
///
/// - [`Error::InvalidArgument`] — `mqdes < 0`, null `msg_ptr`, `msg_len` too large,
///   or `msg_prio >= MQ_PRIO_MAX`.
/// - [`Error::WouldBlock`] — queue is full and descriptor is non-blocking.
/// - [`Error::NotImplemented`] — stub.
pub fn sys_mq_send(mqdes: i32, msg_ptr: u64, msg_len: usize, msg_prio: u32) -> Result<i64> {
    if mqdes < 0 {
        return Err(Error::InvalidArgument);
    }
    if msg_ptr == 0 {
        return Err(Error::InvalidArgument);
    }
    if msg_len > MQ_MSGSIZE_MAX {
        return Err(Error::InvalidArgument);
    }
    if msg_prio >= MQ_PRIO_MAX {
        return Err(Error::InvalidArgument);
    }
    let _ = (mqdes, msg_ptr, msg_len, msg_prio);
    Err(Error::NotImplemented)
}

/// Handle `mq_timedsend(2)`.
///
/// Like `mq_send` but blocks until the absolute timeout `abs_timeout_ptr`
/// (a `struct timespec` in user space) if the queue is full.
///
/// # Errors
///
/// - Same as `sys_mq_send` plus:
/// - [`Error::InvalidArgument`] — null `abs_timeout_ptr`.
/// - [`Error::NotImplemented`] — stub.
pub fn sys_mq_timedsend(
    mqdes: i32,
    msg_ptr: u64,
    msg_len: usize,
    msg_prio: u32,
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
    if msg_prio >= MQ_PRIO_MAX {
        return Err(Error::InvalidArgument);
    }
    if abs_timeout_ptr == 0 {
        return Err(Error::InvalidArgument);
    }
    let _ = (mqdes, msg_ptr, msg_len, msg_prio, abs_timeout_ptr);
    Err(Error::NotImplemented)
}

/// Entry point for `mq_send` from the syscall dispatcher.
pub fn do_mq_send_call(mqdes: i32, msg_ptr: u64, msg_len: usize, msg_prio: u32) -> Result<i64> {
    sys_mq_send(mqdes, msg_ptr, msg_len, msg_prio)
}

/// Entry point for `mq_timedsend` from the syscall dispatcher.
pub fn do_mq_timedsend_call(
    mqdes: i32,
    msg_ptr: u64,
    msg_len: usize,
    msg_prio: u32,
    abs_timeout_ptr: u64,
) -> Result<i64> {
    sys_mq_timedsend(mqdes, msg_ptr, msg_len, msg_prio, abs_timeout_ptr)
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
            sys_mq_send(-1, 0x1000, 64, 0).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn null_msg_ptr_rejected() {
        assert_eq!(
            sys_mq_send(3, 0, 64, 0).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn prio_at_limit_rejected() {
        assert_eq!(
            sys_mq_send(3, 0x1000, 64, MQ_PRIO_MAX).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn valid_send_reaches_stub() {
        let r = sys_mq_send(3, 0x1000, 64, 0);
        assert_eq!(r.unwrap_err(), Error::NotImplemented);
    }

    #[test]
    fn timedsend_null_timeout_rejected() {
        assert_eq!(
            sys_mq_timedsend(3, 0x1000, 64, 0, 0).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn valid_timedsend_reaches_stub() {
        let r = sys_mq_timedsend(3, 0x1000, 64, 5, 0x2000);
        assert_eq!(r.unwrap_err(), Error::NotImplemented);
    }
}
