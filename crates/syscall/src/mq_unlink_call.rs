// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `mq_unlink(2)` syscall dispatch layer.
//!
//! Removes a POSIX message queue.
//!
//! # Syscall signature
//!
//! ```text
//! int mq_unlink(const char *name);
//! ```
//!
//! # POSIX reference
//!
//! - POSIX.1-2024: `mq_unlink()` in `<mqueue.h>`
//! - `.TheOpenGroup/susv5-html/functions/mq_unlink.html`
//!
//! # References
//!
//! - Linux: `ipc/mqueue.c` (`sys_mq_unlink`)

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

/// Handle `mq_unlink(2)`.
///
/// Removes the message queue named `name`.  The queue is destroyed once all
/// open descriptors referencing it are closed.
///
/// # Errors
///
/// - [`Error::InvalidArgument`] — null `name_ptr`.
/// - [`Error::NotFound`] — queue does not exist.
/// - [`Error::PermissionDenied`] — insufficient privilege.
/// - [`Error::NotImplemented`] — stub.
pub fn sys_mq_unlink(name_ptr: u64) -> Result<i64> {
    if name_ptr == 0 {
        return Err(Error::InvalidArgument);
    }
    let _ = name_ptr;
    Err(Error::NotImplemented)
}

/// Entry point called from the syscall dispatcher.
pub fn do_mq_unlink_call(name_ptr: u64) -> Result<i64> {
    sys_mq_unlink(name_ptr)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn null_name_rejected() {
        assert_eq!(sys_mq_unlink(0).unwrap_err(), Error::InvalidArgument);
    }

    #[test]
    fn valid_name_reaches_stub() {
        let r = sys_mq_unlink(0x1000);
        assert_eq!(r.unwrap_err(), Error::NotImplemented);
    }
}
