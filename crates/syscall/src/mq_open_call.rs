// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `mq_open(2)` syscall dispatch layer.
//!
//! Opens a POSIX message queue, creating it if necessary.
//!
//! # Syscall signature
//!
//! ```text
//! mqd_t mq_open(const char *name, int oflag, ...);
//! // with O_CREAT:
//! mqd_t mq_open(const char *name, int oflag, mode_t mode,
//!               struct mq_attr *attr);
//! ```
//!
//! # POSIX reference
//!
//! - POSIX.1-2024: `mq_open()` in `<mqueue.h>`
//! - `.TheOpenGroup/susv5-html/functions/mq_open.html`
//!
//! # References
//!
//! - Linux: `ipc/mqueue.c` (`sys_mq_open`)

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum message queue name length (including leading '/' and NUL).
pub const MQ_NAME_MAX: usize = 255;

/// Maximum number of messages in a queue.
pub const MQ_MAXMSG_DEFAULT: i64 = 10;

/// Maximum message size in bytes.
pub const MQ_MSGSIZE_DEFAULT: i64 = 8192;

/// Open for reading only.
pub const O_RDONLY: i32 = 0;
/// Open for writing only.
pub const O_WRONLY: i32 = 1;
/// Open for reading and writing.
pub const O_RDWR: i32 = 2;
/// Create queue if it does not exist.
pub const O_CREAT: i32 = 0o100;
/// Exclusive create (fail if exists).
pub const O_EXCL: i32 = 0o200;
/// Non-blocking operations.
pub const O_NONBLOCK: i32 = 0o4000;
/// Close-on-exec.
pub const O_CLOEXEC: i32 = 0o2000000;

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

/// Handle `mq_open(2)`.
///
/// `name_ptr` is a user-space pointer to a NUL-terminated queue name (must
/// begin with '/').  `attr_ptr` is required when `O_CREAT` is set; it may be
/// null to use system defaults.
///
/// Returns a message queue descriptor (non-negative integer) on success.
///
/// # Errors
///
/// - [`Error::InvalidArgument`] — null `name_ptr` or invalid `oflag`.
/// - [`Error::AlreadyExists`] — queue exists and both `O_CREAT` and `O_EXCL` set.
/// - [`Error::NotFound`] — queue does not exist and `O_CREAT` not set.
/// - [`Error::NotImplemented`] — stub.
pub fn sys_mq_open(name_ptr: u64, oflag: i32, mode: u32, attr_ptr: u64) -> Result<i64> {
    if name_ptr == 0 {
        return Err(Error::InvalidArgument);
    }
    // Access mode must be O_RDONLY, O_WRONLY, or O_RDWR.
    let access = oflag & 0o3;
    if access > O_RDWR {
        return Err(Error::InvalidArgument);
    }
    let _ = (name_ptr, oflag, mode, attr_ptr);
    Err(Error::NotImplemented)
}

/// Entry point called from the syscall dispatcher.
pub fn do_mq_open_call(name_ptr: u64, oflag: i32, mode: u32, attr_ptr: u64) -> Result<i64> {
    sys_mq_open(name_ptr, oflag, mode, attr_ptr)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn null_name_rejected() {
        assert_eq!(
            sys_mq_open(0, O_RDONLY, 0, 0).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn invalid_access_mode_rejected() {
        // Access mode 3 is not valid (only 0, 1, 2).
        assert_eq!(
            sys_mq_open(0x1000, 0o3, 0o644, 0).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn rdonly_open_reaches_stub() {
        let r = sys_mq_open(0x1000, O_RDONLY, 0, 0);
        assert_eq!(r.unwrap_err(), Error::NotImplemented);
    }

    #[test]
    fn creat_with_attr_reaches_stub() {
        let r = sys_mq_open(0x1000, O_RDWR | O_CREAT, 0o644, 0x2000);
        assert_eq!(r.unwrap_err(), Error::NotImplemented);
    }
}
