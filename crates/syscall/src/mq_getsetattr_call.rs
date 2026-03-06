// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `mq_getattr(2)` / `mq_setattr(2)` syscall dispatch layer.
//!
//! Gets or sets the attributes of a POSIX message queue.
//!
//! # Syscall signature (Linux kernel ABI)
//!
//! ```text
//! int mq_getsetattr(mqd_t mqdes,
//!                   const struct mq_attr *newattr,
//!                   struct mq_attr *oldattr);
//! ```
//!
//! The `mq_getattr` and `mq_setattr` library wrappers both call this single
//! kernel entry point.
//!
//! # POSIX reference
//!
//! - POSIX.1-2024: `mq_getattr()` / `mq_setattr()` in `<mqueue.h>`
//!
//! # References
//!
//! - Linux: `ipc/mqueue.c` (`sys_mq_getsetattr`)

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// `mq_attr.mq_flags`: non-blocking queue flag.
pub const O_NONBLOCK: i64 = 0o4000;

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

/// Handle `mq_getsetattr(2)`.
///
/// `mqdes` is a message queue descriptor.  `newattr_ptr` (if non-null) sets
/// the queue attributes (only `mq_flags` is modifiable, specifically the
/// `O_NONBLOCK` bit).  `oldattr_ptr` (if non-null) receives the previous
/// attributes.
///
/// # Errors
///
/// - [`Error::InvalidArgument`] — `mqdes < 0` or both pointers null.
/// - [`Error::NotImplemented`] — stub.
pub fn sys_mq_getsetattr(mqdes: i32, newattr_ptr: u64, oldattr_ptr: u64) -> Result<i64> {
    if mqdes < 0 {
        return Err(Error::InvalidArgument);
    }
    if newattr_ptr == 0 && oldattr_ptr == 0 {
        return Err(Error::InvalidArgument);
    }
    let _ = (mqdes, newattr_ptr, oldattr_ptr);
    Err(Error::NotImplemented)
}

/// Entry point called from the syscall dispatcher.
pub fn do_mq_getsetattr_call(mqdes: i32, newattr_ptr: u64, oldattr_ptr: u64) -> Result<i64> {
    sys_mq_getsetattr(mqdes, newattr_ptr, oldattr_ptr)
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
            sys_mq_getsetattr(-1, 0x1000, 0x2000).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn both_null_ptrs_rejected() {
        assert_eq!(
            sys_mq_getsetattr(3, 0, 0).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn getattr_only_reaches_stub() {
        let r = sys_mq_getsetattr(3, 0, 0x2000);
        assert_eq!(r.unwrap_err(), Error::NotImplemented);
    }

    #[test]
    fn setattr_and_get_reaches_stub() {
        let r = sys_mq_getsetattr(3, 0x1000, 0x2000);
        assert_eq!(r.unwrap_err(), Error::NotImplemented);
    }
}
