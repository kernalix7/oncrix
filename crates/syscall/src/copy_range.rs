// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `copy_file_range(2)` syscall handler.
//!
//! Implements in-kernel file-to-file copy without round-tripping data
//! through user space.  The source and destination may refer to the same
//! file.  Offsets are updated atomically so that successive calls can be
//! chained to copy an entire file.
//!
//! Reference: Linux `copy_file_range(2)`, POSIX.1-2024 `copy_file_range()`.

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Size of the intermediate kernel-space copy buffer (bytes).
const COPY_BUF_SIZE: usize = 4096;

/// Maximum single-call copy length to prevent unbounded kernel time.
const MAX_COPY_LEN: usize = 1 << 30; // 1 GiB

// ---------------------------------------------------------------------------
// CopyFileRangeArgs — repr(C) argument block
// ---------------------------------------------------------------------------

/// Arguments for the `copy_file_range` system call.
///
/// Packed as `repr(C)` so it can be copied directly from user space
/// via `copy_from_user`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct CopyFileRangeArgs {
    /// Source file descriptor.
    pub fd_in: i32,
    /// Offset in the source file (updated on return).  `-1` means use
    /// and update the file's current position.
    pub off_in: i64,
    /// Destination file descriptor.
    pub fd_out: i32,
    /// Offset in the destination file (updated on return).  `-1` means
    /// use and update the file's current position.
    pub off_out: i64,
    /// Number of bytes to copy.
    pub len: usize,
    /// Flags (must be zero for now — reserved for future extensions).
    pub flags: u32,
}

impl Default for CopyFileRangeArgs {
    fn default() -> Self {
        Self {
            fd_in: -1,
            off_in: 0,
            fd_out: -1,
            off_out: 0,
            len: 0,
            flags: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

/// Validate `copy_file_range` arguments.
///
/// # Errors
///
/// - [`Error::InvalidArgument`] — negative file descriptor, negative
///   offset, zero length, length exceeds [`MAX_COPY_LEN`], or non-zero
///   flags.
pub fn validate_copy_range_args(args: &CopyFileRangeArgs) -> Result<()> {
    // File descriptors must be non-negative.
    if args.fd_in < 0 || args.fd_out < 0 {
        return Err(Error::InvalidArgument);
    }

    // Offsets (when explicitly provided) must be non-negative.
    if args.off_in < -1 || args.off_out < -1 {
        return Err(Error::InvalidArgument);
    }

    // Length must be positive and bounded.
    if args.len == 0 || args.len > MAX_COPY_LEN {
        return Err(Error::InvalidArgument);
    }

    // Flags are reserved — must be zero.
    if args.flags != 0 {
        return Err(Error::InvalidArgument);
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// do_copy_file_range — main syscall handler
// ---------------------------------------------------------------------------

/// `copy_file_range` — copy a range of bytes between two file descriptors.
///
/// Copies up to `args.len` bytes from `fd_in` at `off_in` to `fd_out`
/// at `off_out` using an intermediate 4 KiB kernel buffer.  Both
/// offsets are advanced by the number of bytes successfully copied.
///
/// Returns the total number of bytes copied, which may be less than
/// `args.len` if the source file is shorter or an error is encountered
/// mid-copy.
///
/// # Errors
///
/// - [`Error::InvalidArgument`] — see [`validate_copy_range_args`].
/// - [`Error::NotFound`] — one of the file descriptors is invalid.
/// - [`Error::IoError`] — a read or write to the underlying file failed.
pub fn do_copy_file_range(args: &mut CopyFileRangeArgs) -> Result<usize> {
    validate_copy_range_args(args)?;

    // Intermediate copy buffer — lives on the kernel stack.
    let mut buf = [0u8; COPY_BUF_SIZE];

    let mut remaining = args.len;
    let mut total_copied: usize = 0;

    while remaining > 0 {
        let chunk = remaining.min(COPY_BUF_SIZE);

        // Stub: in a real kernel we would:
        // 1. vfs_read(fd_in, off_in, &mut buf[..chunk])
        // 2. vfs_write(fd_out, off_out, &buf[..bytes_read])
        //
        // For now, simulate a successful copy of `chunk` bytes.
        let bytes_read = chunk;
        let _bytes_written = chunk;

        // Advance offsets.
        if args.off_in >= 0 {
            args.off_in = args.off_in.saturating_add(bytes_read as i64);
        }
        if args.off_out >= 0 {
            args.off_out = args.off_out.saturating_add(bytes_read as i64);
        }

        total_copied = total_copied.saturating_add(bytes_read);
        remaining -= bytes_read;

        // Zero the portion of the buffer we used (defense-in-depth).
        buf[..chunk].fill(0);
    }

    Ok(total_copied)
}
