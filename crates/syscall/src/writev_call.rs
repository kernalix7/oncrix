// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `writev` / `pwritev` syscall handlers.
//!
//! Implements scatter/gather write operations per POSIX.1-2024.
//! `writev` gathers data from multiple buffers (an iovec array) and
//! writes it atomically to a file descriptor, as if written in order.
//! `pwritev` adds a file offset parameter for positioned writes.
//!
//! # References
//!
//! - POSIX.1-2024: `writev()`
//! - Linux man pages: `writev(2)`, `pwritev(2)`

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum number of iovec entries per writev call (matches Linux UIO_MAXIOV).
pub const UIO_MAXIOV: usize = 1024;

/// Maximum total bytes allowed in a single writev call (2 GiB - 1).
const WRITEV_MAX_BYTES: usize = 0x7FFF_FFFF;

// ---------------------------------------------------------------------------
// IoVec — scatter/gather buffer descriptor
// ---------------------------------------------------------------------------

/// POSIX `struct iovec` — a single buffer in a scatter/gather operation.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct IoVec {
    /// User-space pointer to the buffer (represented as a raw address).
    pub iov_base: u64,
    /// Length of the buffer in bytes.
    pub iov_len: usize,
}

impl IoVec {
    /// Construct a new `IoVec`.
    pub const fn new(iov_base: u64, iov_len: usize) -> Self {
        Self { iov_base, iov_len }
    }

    /// Return `true` if this entry has zero length (may be skipped).
    pub const fn is_empty(&self) -> bool {
        self.iov_len == 0
    }
}

// ---------------------------------------------------------------------------
// WritevArgs — bundled arguments
// ---------------------------------------------------------------------------

/// Arguments for `writev` / `pwritev`.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct WritevArgs {
    /// File descriptor to write to.
    pub fd: i32,
    /// Number of `IoVec` entries.
    pub iov_count: usize,
    /// Optional file offset for `pwritev` (None for `writev`).
    pub offset: Option<u64>,
}

impl WritevArgs {
    /// Validate the `writev` arguments.
    ///
    /// Returns `Err(InvalidArgument)` when:
    /// - `fd` is negative.
    /// - `iov_count` exceeds `UIO_MAXIOV`.
    pub fn validate(&self) -> Result<()> {
        if self.fd < 0 {
            return Err(Error::InvalidArgument);
        }
        if self.iov_count > UIO_MAXIOV {
            return Err(Error::InvalidArgument);
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Total-length computation
// ---------------------------------------------------------------------------

/// Compute the total byte count for an iovec array.
///
/// Returns `Err(InvalidArgument)` on overflow or if the sum exceeds
/// `WRITEV_MAX_BYTES`.
pub fn iov_total_len(iov: &[IoVec]) -> Result<usize> {
    let mut total: usize = 0;
    for v in iov {
        total = total.checked_add(v.iov_len).ok_or(Error::InvalidArgument)?;
        if total > WRITEV_MAX_BYTES {
            return Err(Error::InvalidArgument);
        }
    }
    Ok(total)
}

// ---------------------------------------------------------------------------
// WriteTarget — simulated write destination
// ---------------------------------------------------------------------------

/// Simulated write destination for testing.
///
/// A production implementation writes to the underlying file object.
#[derive(Debug)]
pub struct WriteTarget {
    /// Bytes written so far (accumulated count).
    bytes_written: usize,
    /// Maximum bytes the target can accept.
    capacity: usize,
}

impl WriteTarget {
    /// Create a `WriteTarget` with the given remaining capacity.
    pub fn new(capacity: usize) -> Self {
        Self {
            bytes_written: 0,
            capacity,
        }
    }

    /// Record a write of `len` bytes. Returns the bytes actually accepted.
    pub fn write(&mut self, len: usize) -> usize {
        let accepted = len.min(self.capacity);
        self.bytes_written += accepted;
        self.capacity -= accepted;
        accepted
    }

    /// Return the total bytes written so far.
    pub fn total_written(&self) -> usize {
        self.bytes_written
    }
}

// ---------------------------------------------------------------------------
// Validation helpers
// ---------------------------------------------------------------------------

/// Validate that the file descriptor is non-negative.
fn validate_fd(fd: i32) -> Result<()> {
    if fd < 0 {
        return Err(Error::InvalidArgument);
    }
    Ok(())
}

/// Validate the iovec array: count, per-entry length, and total.
fn validate_iov(iov: &[IoVec]) -> Result<usize> {
    if iov.len() > UIO_MAXIOV {
        return Err(Error::InvalidArgument);
    }
    iov_total_len(iov)
}

// ---------------------------------------------------------------------------
// Public syscall handlers
// ---------------------------------------------------------------------------

/// `writev` — gather-write to a file descriptor.
///
/// Writes the data from all buffers in `iov` to `fd` in order, as if
/// each buffer were written in sequence, but atomically (no interleaving
/// with other writers).
///
/// Returns the total number of bytes written.
///
/// # Errors
///
/// | `Error`           | Condition                                      |
/// |-------------------|------------------------------------------------|
/// | `InvalidArgument` | `fd < 0`, `iov_count > UIO_MAXIOV`, or overflow |
///
/// Reference: POSIX.1-2024 §writev.
pub fn do_writev(fd: i32, iov: &[IoVec], target: Option<&mut WriteTarget>) -> Result<usize> {
    validate_fd(fd)?;
    let total = validate_iov(iov)?;

    match target {
        None => {
            // Stub: no write target provided.
            let _ = total;
            Err(Error::NotImplemented)
        }
        Some(tgt) => {
            let mut written = 0usize;
            for entry in iov {
                if entry.is_empty() {
                    continue;
                }
                let accepted = tgt.write(entry.iov_len);
                written += accepted;
                if accepted < entry.iov_len {
                    // Target is full; partial write.
                    break;
                }
            }
            Ok(written)
        }
    }
}

/// `pwritev` — gather-write to a file descriptor at a specified offset.
///
/// Like `writev` but writes starting at `offset` bytes from the beginning
/// of the file. The file's current position is not changed.
///
/// Returns the total number of bytes written.
///
/// # Errors
///
/// | `Error`           | Condition                                      |
/// |-------------------|------------------------------------------------|
/// | `InvalidArgument` | Same as `writev`, or `offset` overflow         |
///
/// Reference: Linux pwritev(2).
pub fn do_pwritev(
    fd: i32,
    iov: &[IoVec],
    offset: u64,
    target: Option<&mut WriteTarget>,
) -> Result<usize> {
    validate_fd(fd)?;
    let total = validate_iov(iov)?;

    // offset must be representable as a signed 64-bit value.
    if offset > i64::MAX as u64 {
        return Err(Error::InvalidArgument);
    }

    let _ = total;

    match target {
        None => Err(Error::NotImplemented),
        Some(tgt) => {
            let mut written = 0usize;
            for entry in iov {
                if entry.is_empty() {
                    continue;
                }
                let accepted = tgt.write(entry.iov_len);
                written += accepted;
                if accepted < entry.iov_len {
                    break;
                }
            }
            let _ = offset;
            Ok(written)
        }
    }
}

/// Validate `writev` arguments without performing the write.
pub fn validate_writev_args(fd: i32, iov: &[IoVec]) -> Result<usize> {
    validate_fd(fd)?;
    validate_iov(iov)
}
