// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `mq_notify(2)` syscall dispatch layer.
//!
//! Registers or unregisters for notification when a message becomes available
//! in a POSIX message queue.
//!
//! # Syscall signature
//!
//! ```text
//! int mq_notify(mqd_t mqdes, const struct sigevent *sevp);
//! ```
//!
//! Passing a null `sevp` deregisters any existing notification.
//!
//! # POSIX reference
//!
//! - POSIX.1-2024: `mq_notify()` in `<mqueue.h>`
//! - `.TheOpenGroup/susv5-html/functions/mq_notify.html`
//!
//! # References
//!
//! - Linux: `ipc/mqueue.c` (`sys_mq_notify`)

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// `sigev_notify` value: no notification.
pub const SIGEV_NONE: i32 = 1;
/// `sigev_notify` value: send a signal.
pub const SIGEV_SIGNAL: i32 = 0;
/// `sigev_notify` value: deliver via a new thread.
pub const SIGEV_THREAD: i32 = 2;

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

/// Handle `mq_notify(2)`.
///
/// `mqdes` is a message queue descriptor.  `sevp_ptr` is a user-space pointer
/// to `struct sigevent`; if null, any existing notification registration is
/// removed.
///
/// # Errors
///
/// - [`Error::InvalidArgument`] — `mqdes < 0`.
/// - [`Error::Busy`] — another process is already registered for notification.
/// - [`Error::NotImplemented`] — stub.
pub fn sys_mq_notify(mqdes: i32, sevp_ptr: u64) -> Result<i64> {
    if mqdes < 0 {
        return Err(Error::InvalidArgument);
    }
    // sevp_ptr == 0 is valid (deregisters notification).
    let _ = (mqdes, sevp_ptr);
    Err(Error::NotImplemented)
}

/// Entry point called from the syscall dispatcher.
pub fn do_mq_notify_call(mqdes: i32, sevp_ptr: u64) -> Result<i64> {
    sys_mq_notify(mqdes, sevp_ptr)
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
            sys_mq_notify(-1, 0x1000).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn null_sevp_deregisters() {
        // null sevp is valid — deregisters notification.
        let r = sys_mq_notify(3, 0);
        assert_eq!(r.unwrap_err(), Error::NotImplemented);
    }

    #[test]
    fn valid_notify_reaches_stub() {
        let r = sys_mq_notify(3, 0x1000);
        assert_eq!(r.unwrap_err(), Error::NotImplemented);
    }
}
