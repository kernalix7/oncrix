// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `fsync(2)` syscall dispatch layer.
//!
//! Transfers ("flushes") all modified in-core data of the file referred to
//! by `fd` to the disk device, including updated file metadata such as
//! modification timestamps and ownership.  The call blocks until the
//! transfer is complete.
//!
//! # Syscall signature
//!
//! ```text
//! int fsync(int fd);
//! ```
//!
//! # POSIX reference
//!
//! - POSIX.1-2024: `fsync()` in `<unistd.h>`
//! - `.TheOpenGroup/susv5-html/functions/fsync.html`
//!
//! # References
//!
//! - Linux: `fs/sync.c` (`sys_fsync`)
//! - `fsync(2)` man page

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum valid file descriptor number.
const FD_MAX: i32 = 1_048_576;

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

/// Handle `fsync(2)`.
///
/// # Errors
///
/// - [`Error::InvalidArgument`] — `fd` is out of valid range.
/// - [`Error::NotFound`] — `fd` is not open.
/// - [`Error::IoError`] — an I/O error occurred while flushing.
/// - [`Error::NotImplemented`] — stub.
pub fn sys_fsync(fd: i32) -> Result<i64> {
    if fd < 0 || fd > FD_MAX {
        return Err(Error::InvalidArgument);
    }
    let _ = fd;
    Err(Error::NotImplemented)
}

/// Entry point called from the syscall dispatcher.
pub fn do_fsync_call(fd: i32) -> Result<i64> {
    sys_fsync(fd)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn negative_fd_rejected() {
        assert_eq!(sys_fsync(-1).unwrap_err(), Error::InvalidArgument);
    }

    #[test]
    fn valid_fd_reaches_stub() {
        let r = sys_fsync(3);
        assert_eq!(r.unwrap_err(), Error::NotImplemented);
    }
}
