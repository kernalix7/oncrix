// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `vmsplice` syscall implementation.
//!
//! `vmsplice` splices user-space pages into a pipe, allowing zero-copy
//! data transfer from user virtual memory into the kernel pipe buffer.
//! Combined with `splice`, this enables zero-copy pipelines from
//! user buffers through pipes to file descriptors.
//!
//! Linux-specific: not in POSIX. Related to `splice` and `tee`.

use oncrix_lib::{Error, Result};

/// Maximum iovec entries per vmsplice call.
pub const VMSPLICE_MAX_IOVECS: usize = 16;

/// Maximum bytes transferred per vmsplice call (16 MiB).
pub const VMSPLICE_MAX_BYTES: usize = 16 * 1024 * 1024;

/// vmsplice flags controlling transfer behavior.
pub struct VmspliceFlags;

impl VmspliceFlags {
    /// Move pages instead of copying (hint; may fall back to copy).
    pub const SPLICE_F_MOVE: u32 = 0x01;
    /// Non-blocking operation.
    pub const SPLICE_F_NONBLOCK: u32 = 0x02;
    /// Expect more data (pipeline hint).
    pub const SPLICE_F_MORE: u32 = 0x04;
    /// Gift the pages to the kernel (relinquish ownership).
    pub const SPLICE_F_GIFT: u32 = 0x08;
}

/// User-space I/O vector — mirrors `struct iovec` from `<sys/uio.h>`.
///
/// Each entry describes one contiguous user-space buffer segment.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct IoVec {
    /// Base address of the user-space buffer.
    pub iov_base: usize,
    /// Length of the buffer in bytes.
    pub iov_len: usize,
}

impl IoVec {
    /// Create a new IoVec for the given user buffer.
    pub const fn new(base: usize, len: usize) -> Self {
        Self {
            iov_base: base,
            iov_len: len,
        }
    }

    /// Check if this iovec is valid (non-null base, non-zero length).
    pub fn is_valid(&self) -> bool {
        self.iov_base != 0 && self.iov_len > 0
    }
}

/// Arguments for the `vmsplice` syscall.
#[derive(Debug)]
pub struct VmspliceArgs {
    /// Write end of a pipe file descriptor.
    pub fd: i32,
    /// Pointer to array of user iovec structures.
    pub iov_ptr: usize,
    /// Number of iovec entries.
    pub nr_segs: usize,
    /// Splice flags (VmspliceFlags constants).
    pub flags: u32,
}

/// Result of a validated vmsplice request.
pub struct VmspliceRequest {
    /// Write-end pipe fd.
    pub fd: i32,
    /// Number of iovec segments.
    pub nr_segs: usize,
    /// Parsed flags.
    pub flags: u32,
    /// Whether the gift flag is set (kernel takes ownership of pages).
    pub gift: bool,
    /// Whether non-blocking mode is requested.
    pub nonblock: bool,
}

/// Validate vmsplice arguments.
///
/// Checks fd is non-negative, iov_ptr is non-null, nr_segs is within
/// bounds, and only known flags are set.
pub fn validate_vmsplice_args(args: &VmspliceArgs) -> Result<VmspliceRequest> {
    if args.fd < 0 {
        return Err(Error::InvalidArgument);
    }
    if args.iov_ptr == 0 {
        return Err(Error::InvalidArgument);
    }
    if args.nr_segs == 0 || args.nr_segs > VMSPLICE_MAX_IOVECS {
        return Err(Error::InvalidArgument);
    }

    let known = VmspliceFlags::SPLICE_F_MOVE
        | VmspliceFlags::SPLICE_F_NONBLOCK
        | VmspliceFlags::SPLICE_F_MORE
        | VmspliceFlags::SPLICE_F_GIFT;
    if args.flags & !known != 0 {
        return Err(Error::InvalidArgument);
    }

    let gift = (args.flags & VmspliceFlags::SPLICE_F_GIFT) != 0;
    let nonblock = (args.flags & VmspliceFlags::SPLICE_F_NONBLOCK) != 0;

    Ok(VmspliceRequest {
        fd: args.fd,
        nr_segs: args.nr_segs,
        flags: args.flags,
        gift,
        nonblock,
    })
}

/// Validate a single IoVec segment against the per-call byte limit.
///
/// Returns the new accumulated total or an error on overflow / limit exceeded.
pub fn validate_iovec(iov: &IoVec, accumulated: usize) -> Result<usize> {
    if !iov.is_valid() {
        return Err(Error::InvalidArgument);
    }
    let total = accumulated
        .checked_add(iov.iov_len)
        .ok_or(Error::InvalidArgument)?;
    if total > VMSPLICE_MAX_BYTES {
        return Err(Error::InvalidArgument);
    }
    Ok(total)
}

/// Handle the `vmsplice` syscall.
///
/// Reads `nr_segs` iovec structures from user space and transfers the
/// described pages into the write end of `fd` (which must be a pipe).
///
/// With `SPLICE_F_GIFT`, the pages are gifted to the kernel; the caller
/// must not access them afterward.
///
/// Returns the number of bytes transferred, or an error.
pub fn sys_vmsplice(args: &VmspliceArgs) -> Result<i64> {
    let req = validate_vmsplice_args(args)?;
    // Stub: real implementation would:
    // 1. Verify fd refers to the write end of a pipe.
    // 2. copy_from_user the iovec array (nr_segs * sizeof(IoVec) bytes).
    // 3. Validate each IoVec and accumulate total_bytes.
    // 4. If SPLICE_F_GIFT: pin user pages and gift to pipe buffer.
    //    Else: copy user data into pipe page cache.
    // 5. Return total bytes written.
    let _ = req;
    Err(Error::NotImplemented)
}

/// Check whether a file descriptor is the write end of a pipe.
///
/// Returns `Err(InvalidArgument)` if it is the read end or not a pipe,
/// `Err(NotFound)` if the fd is not open.
pub fn check_pipe_write_end(fd: i32) -> Result<()> {
    if fd < 0 {
        return Err(Error::InvalidArgument);
    }
    // Stub: real check queries file table.
    Err(Error::NotImplemented)
}

/// Compute the total byte count from a slice of IoVecs, returning None on overflow.
pub fn iovec_total(iovecs: &[IoVec]) -> Option<usize> {
    iovecs
        .iter()
        .try_fold(0usize, |acc, iov| acc.checked_add(iov.iov_len))
}
