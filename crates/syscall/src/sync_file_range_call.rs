// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `sync_file_range(2)` syscall dispatch layer.
//!
//! Initiates or waits for writeback of a byte range within a file without
//! flushing the file's metadata.  This is a Linux-specific interface that
//! provides finer-grained control than `fsync(2)` or `fdatasync(2)`.
//!
//! # Syscall signature
//!
//! ```text
//! int sync_file_range(int fd, off64_t offset, off64_t nbytes,
//!                     unsigned int flags);
//! ```
//!
//! # Flags
//!
//! | Constant                        | Value | Description |
//! |---------------------------------|-------|-------------|
//! | `SYNC_FILE_RANGE_WAIT_BEFORE`   | 1     | Wait for writeback already in flight |
//! | `SYNC_FILE_RANGE_WRITE`         | 2     | Initiate writeback of dirty pages |
//! | `SYNC_FILE_RANGE_WAIT_AFTER`    | 4     | Wait for writeback initiated above |
//!
//! # References
//!
//! - Linux: `fs/sync.c` (`ksys_sync_file_range`)
//! - `sync_file_range(2)` man page

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Wait for I/O already in progress before starting.
pub const SYNC_FILE_RANGE_WAIT_BEFORE: u32 = 1;
/// Initiate writeback for the range.
pub const SYNC_FILE_RANGE_WRITE: u32 = 2;
/// Wait for I/O to complete after initiating writeback.
pub const SYNC_FILE_RANGE_WAIT_AFTER: u32 = 4;

/// All valid flag bits.
const FLAGS_VALID: u32 =
    SYNC_FILE_RANGE_WAIT_BEFORE | SYNC_FILE_RANGE_WRITE | SYNC_FILE_RANGE_WAIT_AFTER;

/// Maximum valid file descriptor number.
const FD_MAX: i32 = 1_048_576;

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

/// Handle `sync_file_range(2)`.
///
/// `offset` must be non-negative.  `nbytes` of 0 means "to end of file".
///
/// # Errors
///
/// - [`Error::InvalidArgument`] — unknown flags, negative `offset`, or `fd`
///   out of range.
/// - [`Error::NotFound`] — `fd` is not open.
/// - [`Error::IoError`] — writeback failed.
/// - [`Error::NotImplemented`] — stub.
pub fn sys_sync_file_range(fd: i32, offset: i64, nbytes: i64, flags: u32) -> Result<i64> {
    if fd < 0 || fd > FD_MAX {
        return Err(Error::InvalidArgument);
    }
    if flags & !FLAGS_VALID != 0 {
        return Err(Error::InvalidArgument);
    }
    if offset < 0 {
        return Err(Error::InvalidArgument);
    }
    if nbytes < 0 {
        return Err(Error::InvalidArgument);
    }
    let _ = (fd, offset, nbytes, flags);
    Err(Error::NotImplemented)
}

/// Entry point called from the syscall dispatcher.
pub fn do_sync_file_range_call(fd: i32, offset: i64, nbytes: i64, flags: u32) -> Result<i64> {
    sys_sync_file_range(fd, offset, nbytes, flags)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_flags_rejected() {
        assert_eq!(
            sys_sync_file_range(3, 0, 0, 0x80).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn negative_offset_rejected() {
        assert_eq!(
            sys_sync_file_range(3, -1, 0, SYNC_FILE_RANGE_WRITE).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn negative_fd_rejected() {
        assert_eq!(
            sys_sync_file_range(-1, 0, 0, SYNC_FILE_RANGE_WRITE).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn zero_nbytes_means_eof() {
        let r = sys_sync_file_range(3, 0, 0, SYNC_FILE_RANGE_WRITE);
        assert_eq!(r.unwrap_err(), Error::NotImplemented);
    }

    #[test]
    fn all_flags_valid() {
        let r = sys_sync_file_range(
            3,
            4096,
            8192,
            SYNC_FILE_RANGE_WAIT_BEFORE | SYNC_FILE_RANGE_WRITE | SYNC_FILE_RANGE_WAIT_AFTER,
        );
        assert_eq!(r.unwrap_err(), Error::NotImplemented);
    }
}
