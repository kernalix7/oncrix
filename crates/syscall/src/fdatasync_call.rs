// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `fdatasync(2)` syscall dispatch layer.
//!
//! Flushes the data of the file referred to by `fd` to the storage device,
//! but — unlike `fsync(2)` — does not necessarily flush updated metadata
//! (e.g. modification time) unless that metadata is needed for a subsequent
//! data retrieval.  This can be faster than `fsync` when only data
//! durability is required.
//!
//! # Syscall signature
//!
//! ```text
//! int fdatasync(int fd);
//! ```
//!
//! # POSIX reference
//!
//! - POSIX.1-2024: `fdatasync()` in `<unistd.h>`
//! - `.TheOpenGroup/susv5-html/functions/fdatasync.html`
//!
//! # References
//!
//! - Linux: `fs/sync.c` (`sys_fdatasync`)
//! - `fdatasync(2)` man page

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum valid file descriptor number.
const FD_MAX: i32 = 1_048_576;

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

/// Handle `fdatasync(2)`.
///
/// # Errors
///
/// - [`Error::InvalidArgument`] — `fd` is out of valid range.
/// - [`Error::NotFound`] — `fd` is not open.
/// - [`Error::IoError`] — an I/O error occurred while flushing.
/// - [`Error::NotImplemented`] — stub.
pub fn sys_fdatasync(fd: i32) -> Result<i64> {
    if fd < 0 || fd > FD_MAX {
        return Err(Error::InvalidArgument);
    }
    let _ = fd;
    Err(Error::NotImplemented)
}

/// Entry point called from the syscall dispatcher.
pub fn do_fdatasync_call(fd: i32) -> Result<i64> {
    sys_fdatasync(fd)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn negative_fd_rejected() {
        assert_eq!(sys_fdatasync(-1).unwrap_err(), Error::InvalidArgument);
    }

    #[test]
    fn valid_fd_reaches_stub() {
        let r = sys_fdatasync(3);
        assert_eq!(r.unwrap_err(), Error::NotImplemented);
    }
}
