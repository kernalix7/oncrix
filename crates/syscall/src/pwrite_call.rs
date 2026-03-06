// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `pread64(2)` / `pwrite64(2)` syscall dispatch layer.
//!
//! `pread64` reads `count` bytes from file descriptor `fd` at file offset
//! `offset` into the buffer at `buf_ptr`, without modifying the file's
//! current position.  `pwrite64` is the write counterpart.
//!
//! # Syscall signatures
//!
//! ```text
//! ssize_t pread64(int fd, void *buf, size_t count, off_t offset);
//! ssize_t pwrite64(int fd, const void *buf, size_t count, off_t offset);
//! ```
//!
//! # POSIX reference
//!
//! - POSIX.1-2024: `pread()`, `pwrite()` in `<unistd.h>`
//! - `.TheOpenGroup/susv5-html/functions/pread.html`
//!
//! # References
//!
//! - Linux: `fs/read_write.c` (`ksys_pread64`, `ksys_pwrite64`)
//! - `pread(2)` man page

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum valid file descriptor number.
const FD_MAX: i32 = 1_048_576;

/// Maximum sane transfer size (2 GiB).
const MAX_RW_COUNT: usize = 0x7FFF_F000;

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// Handle `pread64(2)`.
///
/// # Errors
///
/// - [`Error::InvalidArgument`] — `fd` out of range, null `buf_ptr`, zero
///   `count`, `count` exceeds `MAX_RW_COUNT`, or negative `offset`.
/// - [`Error::NotFound`] — `fd` is not open.
/// - [`Error::NotImplemented`] — stub.
pub fn sys_pread64(fd: i32, buf_ptr: u64, count: usize, offset: i64) -> Result<i64> {
    if fd < 0 || fd > FD_MAX {
        return Err(Error::InvalidArgument);
    }
    if buf_ptr == 0 {
        return Err(Error::InvalidArgument);
    }
    if count == 0 {
        return Ok(0); // zero-byte read returns 0 immediately
    }
    if count > MAX_RW_COUNT {
        return Err(Error::InvalidArgument);
    }
    if offset < 0 {
        return Err(Error::InvalidArgument);
    }
    let _ = (fd, buf_ptr, count, offset);
    Err(Error::NotImplemented)
}

/// Handle `pwrite64(2)`.
///
/// # Errors
///
/// - [`Error::InvalidArgument`] — `fd` out of range, null `buf_ptr`, `count`
///   exceeds `MAX_RW_COUNT`, or negative `offset`.
/// - [`Error::NotFound`] — `fd` is not open.
/// - [`Error::NotImplemented`] — stub.
pub fn sys_pwrite64(fd: i32, buf_ptr: u64, count: usize, offset: i64) -> Result<i64> {
    if fd < 0 || fd > FD_MAX {
        return Err(Error::InvalidArgument);
    }
    if buf_ptr == 0 {
        return Err(Error::InvalidArgument);
    }
    if count == 0 {
        return Ok(0); // zero-byte write returns 0 immediately
    }
    if count > MAX_RW_COUNT {
        return Err(Error::InvalidArgument);
    }
    if offset < 0 {
        return Err(Error::InvalidArgument);
    }
    let _ = (fd, buf_ptr, count, offset);
    Err(Error::NotImplemented)
}

/// Entry point for `pread64` from the syscall dispatcher.
pub fn do_pread64_call(fd: i32, buf_ptr: u64, count: usize, offset: i64) -> Result<i64> {
    sys_pread64(fd, buf_ptr, count, offset)
}

/// Entry point for `pwrite64` from the syscall dispatcher.
pub fn do_pwrite64_call(fd: i32, buf_ptr: u64, count: usize, offset: i64) -> Result<i64> {
    sys_pwrite64(fd, buf_ptr, count, offset)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn negative_fd_rejected() {
        assert_eq!(
            sys_pread64(-1, 0x1000, 128, 0).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn null_buf_rejected() {
        assert_eq!(
            sys_pread64(3, 0, 128, 0).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn negative_offset_rejected() {
        assert_eq!(
            sys_pread64(3, 0x1000, 128, -1).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn zero_count_returns_zero() {
        assert_eq!(sys_pread64(3, 0x1000, 0, 0).unwrap(), 0);
        assert_eq!(sys_pwrite64(3, 0x1000, 0, 0).unwrap(), 0);
    }

    #[test]
    fn valid_pread_reaches_stub() {
        let r = sys_pread64(3, 0x1000, 512, 4096);
        assert_eq!(r.unwrap_err(), Error::NotImplemented);
    }

    #[test]
    fn valid_pwrite_reaches_stub() {
        let r = sys_pwrite64(3, 0x1000, 512, 4096);
        assert_eq!(r.unwrap_err(), Error::NotImplemented);
    }
}
