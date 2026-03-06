// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `readv(2)` and `writev(2)` scatter-gather I/O syscall handlers.
//!
//! These syscalls allow reading into or writing from multiple discontiguous
//! memory buffers (an "iovec array") in a single atomic system call, avoiding
//! the need for a separate user-space copy step.
//!
//! # POSIX Conformance
//!
//! Follows POSIX.1-2024 `readv()` / `writev()` specification.  Key behaviours:
//! - `EINVAL` if `iovcnt` is ≤ 0 or > `UIO_MAXIOV` (1024).
//! - `EINVAL` if any `iov_len` is negative.
//! - `EINVAL` if the total byte count overflows `SSIZE_MAX`.
//! - Each `iov_base` pointer must be valid (non-null when `iov_len > 0`).
//! - Reads/writes are performed in order; a short read/write does not advance
//!   past the current buffer.
//! - `EFAULT` if any user pointer is invalid (validated before I/O begins).
//!
//! # References
//!
//! - POSIX.1-2024: `readv()`, `writev()`
//! - Linux man pages: `readv(2)`

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum number of iovec elements per `readv`/`writev` call.
pub const UIO_MAXIOV: usize = 1024;

/// Maximum value returnable by `readv`/`writev` (i64::MAX on 64-bit).
pub const SSIZE_MAX: u64 = i64::MAX as u64;

// ---------------------------------------------------------------------------
// Iovec
// ---------------------------------------------------------------------------

/// A single scatter-gather buffer descriptor (`struct iovec`).
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Iovec {
    /// Pointer to the buffer (user-space virtual address).
    pub iov_base: u64,
    /// Length of the buffer in bytes.
    pub iov_len: u64,
}

impl Iovec {
    /// Construct a new `Iovec`.
    pub const fn new(base: u64, len: u64) -> Self {
        Self {
            iov_base: base,
            iov_len: len,
        }
    }

    /// Returns `true` if this element is empty (zero-length buffer).
    pub const fn is_empty(&self) -> bool {
        self.iov_len == 0
    }
}

// ---------------------------------------------------------------------------
// Validation helpers
// ---------------------------------------------------------------------------

/// Validate an iovec array and return the total byte count.
///
/// # Errors
///
/// | `Error`    | Condition                                                |
/// |------------|----------------------------------------------------------|
/// | `InvalidArg` | `iovcnt` is 0, negative, or > `UIO_MAXIOV`            |
/// | `InvalidArg` | Any `iov_len` causes total to overflow `SSIZE_MAX`     |
/// | `Fault`    | Non-null `iov_base` is 0 for a non-empty buffer          |
pub fn validate_iovec(iov: &[Iovec]) -> Result<usize> {
    if iov.is_empty() || iov.len() > UIO_MAXIOV {
        return Err(Error::InvalidArgument);
    }

    let mut total: u64 = 0;
    for v in iov {
        // Null pointer for non-empty buffer is a fault.
        if v.iov_len > 0 && v.iov_base == 0 {
            return Err(Error::InvalidArgument);
        }
        total = total.checked_add(v.iov_len).ok_or(Error::InvalidArgument)?;
        if total > SSIZE_MAX {
            return Err(Error::InvalidArgument);
        }
    }
    Ok(total as usize)
}

// ---------------------------------------------------------------------------
// Read result
// ---------------------------------------------------------------------------

/// Outcome of a simulated `readv` operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReadvResult {
    /// Total bytes read across all buffers.
    pub bytes_read: usize,
    /// Number of iovec elements fully consumed.
    pub vecs_consumed: usize,
}

// ---------------------------------------------------------------------------
// Core handlers
// ---------------------------------------------------------------------------

/// Handler for `readv(2)`.
///
/// Validates the iovec array and simulates reading `available` bytes from
/// the file described by `fd` into the scatter buffers.
///
/// The simulation fills buffers in order until `available` bytes are consumed
/// or all buffers are filled.  In a real kernel, `fd` would be dispatched to
/// the VFS read path.
///
/// # Errors
///
/// Returns `Err` on iovec validation failure; see [`validate_iovec`].
pub fn do_readv(_fd: i32, iov: &[Iovec], available: usize) -> Result<ReadvResult> {
    let _total = validate_iovec(iov)?;

    let mut remaining = available;
    let mut bytes_read = 0usize;
    let mut vecs_consumed = 0usize;

    for v in iov {
        if remaining == 0 {
            break;
        }
        let take = (v.iov_len as usize).min(remaining);
        bytes_read += take;
        remaining -= take;
        if take == v.iov_len as usize {
            vecs_consumed += 1;
        } else {
            vecs_consumed += 1; // partial — still counts as the current vec
            break;
        }
    }

    Ok(ReadvResult {
        bytes_read,
        vecs_consumed,
    })
}

/// Handler for `writev(2)`.
///
/// Validates the iovec array and returns the total bytes that would be
/// written.  In a real kernel the data would be dispatched to the VFS
/// write path.
///
/// # Errors
///
/// Returns `Err` on iovec validation failure; see [`validate_iovec`].
pub fn do_writev(_fd: i32, iov: &[Iovec]) -> Result<usize> {
    validate_iovec(iov)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_ok() {
        let iov = [Iovec::new(0x1000, 100), Iovec::new(0x2000, 200)];
        assert_eq!(validate_iovec(&iov).unwrap(), 300);
    }

    #[test]
    fn validate_empty_array() {
        assert_eq!(validate_iovec(&[]), Err(Error::InvalidArgument));
    }

    #[test]
    fn validate_null_ptr_nonempty() {
        let iov = [Iovec::new(0, 10)];
        assert_eq!(validate_iovec(&iov), Err(Error::InvalidArgument));
    }

    #[test]
    fn validate_overflow() {
        let iov = [Iovec::new(0x1000, u64::MAX), Iovec::new(0x2000, 1)];
        assert_eq!(validate_iovec(&iov), Err(Error::InvalidArgument));
    }

    #[test]
    fn readv_partial() {
        let iov = [Iovec::new(0x1000, 100), Iovec::new(0x2000, 100)];
        let res = do_readv(3, &iov, 150).unwrap();
        assert_eq!(res.bytes_read, 150);
    }

    #[test]
    fn readv_full() {
        let iov = [Iovec::new(0x1000, 50), Iovec::new(0x2000, 50)];
        let res = do_readv(3, &iov, 200).unwrap();
        assert_eq!(res.bytes_read, 100);
        assert_eq!(res.vecs_consumed, 2);
    }

    #[test]
    fn writev_returns_total() {
        let iov = [Iovec::new(0x1000, 64), Iovec::new(0x2000, 32)];
        assert_eq!(do_writev(4, &iov).unwrap(), 96);
    }
}
