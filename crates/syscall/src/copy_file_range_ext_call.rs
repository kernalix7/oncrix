// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Extended `copy_file_range` syscall with additional policy flags.
//!
//! This module provides an extended interface layered on top of the base
//! `copy_file_range` syscall, adding flags for copy-on-write hints,
//! cross-filesystem fallbacks, and bandwidth throttling.
//!
//! POSIX Reference: copy_file_range is Linux-specific. The base call is
//! in `copy_file_range_call.rs`. This module handles policy extensions.

use oncrix_lib::{Error, Result};

/// Maximum bytes per single copy_file_range_ext call (1 GiB).
pub const COPY_FILE_RANGE_EXT_MAX: u64 = 1 << 30;

/// Flags for the extended copy_file_range interface.
pub struct CopyFileRangeExtFlags;

impl CopyFileRangeExtFlags {
    /// Hint that the underlying filesystem should use CoW reflinks.
    pub const COPY_FR_REFLINK: u32 = 0x0001;
    /// Fall back to read+write if the filesystem cannot do server-side copy.
    pub const COPY_FR_FALLBACK: u32 = 0x0002;
    /// Fail with EXDEV instead of falling back for cross-filesystem copies.
    pub const COPY_FR_NO_XDEV: u32 = 0x0004;
    /// Synchronize data before returning (equivalent to fdatasync on dst).
    pub const COPY_FR_SYNC: u32 = 0x0008;
}

/// Describes a byte range in a file.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct FileRange {
    /// Offset within the file in bytes.
    pub offset: u64,
    /// Length of the range in bytes.
    pub length: u64,
}

impl FileRange {
    /// Create a new file range.
    pub const fn new(offset: u64, length: u64) -> Self {
        Self { offset, length }
    }

    /// Check that the range does not overflow file offset arithmetic.
    pub fn is_valid(&self) -> bool {
        self.length > 0 && self.offset.checked_add(self.length).is_some()
    }

    /// Compute end offset (exclusive), returning None on overflow.
    pub fn end(&self) -> Option<u64> {
        self.offset.checked_add(self.length)
    }
}

/// Arguments for the extended `copy_file_range` syscall.
#[derive(Debug)]
pub struct CopyFileRangeExtArgs {
    /// Source file descriptor (must be open for reading).
    pub fd_in: i32,
    /// Pointer to source offset (updated on success); 0 = use current pos.
    pub off_in_ptr: usize,
    /// Destination file descriptor (must be open for writing).
    pub fd_out: i32,
    /// Pointer to destination offset (updated on success); 0 = use current pos.
    pub off_out_ptr: usize,
    /// Number of bytes to copy.
    pub len: u64,
    /// Extension flags (CopyFileRangeExtFlags).
    pub flags: u32,
}

/// Validated copy_file_range_ext request.
pub struct CopyFileRangeExtRequest {
    /// Source fd.
    pub fd_in: i32,
    /// Source offset pointer (0 if use file position).
    pub off_in_ptr: usize,
    /// Destination fd.
    pub fd_out: i32,
    /// Destination offset pointer (0 if use file position).
    pub off_out_ptr: usize,
    /// Bytes to copy.
    pub len: u64,
    /// Parsed extension flags.
    pub flags: u32,
    /// Whether CoW reflink is requested.
    pub reflink: bool,
    /// Whether read+write fallback is allowed.
    pub fallback: bool,
    /// Whether cross-device copies are prohibited.
    pub no_xdev: bool,
    /// Whether to sync data after copy.
    pub sync: bool,
}

/// Validate extended copy_file_range arguments.
///
/// Returns a structured request or an appropriate errno.
pub fn validate_copy_file_range_ext_args(
    args: &CopyFileRangeExtArgs,
) -> Result<CopyFileRangeExtRequest> {
    if args.fd_in < 0 || args.fd_out < 0 {
        return Err(Error::InvalidArgument);
    }
    if args.fd_in == args.fd_out {
        // Overlapping source/destination on the same fd is not allowed.
        return Err(Error::InvalidArgument);
    }
    if args.len == 0 {
        return Err(Error::InvalidArgument);
    }
    if args.len > COPY_FILE_RANGE_EXT_MAX {
        return Err(Error::InvalidArgument);
    }

    // Validate flag combinations.
    let known = CopyFileRangeExtFlags::COPY_FR_REFLINK
        | CopyFileRangeExtFlags::COPY_FR_FALLBACK
        | CopyFileRangeExtFlags::COPY_FR_NO_XDEV
        | CopyFileRangeExtFlags::COPY_FR_SYNC;
    if args.flags & !known != 0 {
        return Err(Error::InvalidArgument);
    }

    // FALLBACK and NO_XDEV are mutually exclusive.
    let fallback = (args.flags & CopyFileRangeExtFlags::COPY_FR_FALLBACK) != 0;
    let no_xdev = (args.flags & CopyFileRangeExtFlags::COPY_FR_NO_XDEV) != 0;
    if fallback && no_xdev {
        return Err(Error::InvalidArgument);
    }

    Ok(CopyFileRangeExtRequest {
        fd_in: args.fd_in,
        off_in_ptr: args.off_in_ptr,
        fd_out: args.fd_out,
        off_out_ptr: args.off_out_ptr,
        len: args.len,
        flags: args.flags,
        reflink: (args.flags & CopyFileRangeExtFlags::COPY_FR_REFLINK) != 0,
        fallback,
        no_xdev,
        sync: (args.flags & CopyFileRangeExtFlags::COPY_FR_SYNC) != 0,
    })
}

/// Handle the extended `copy_file_range` syscall.
///
/// Copies `len` bytes from `fd_in` to `fd_out`, optionally at explicit
/// offsets. The extended flags allow the caller to request CoW reflinks
/// (if supported by the filesystem), allow or prohibit cross-device
/// fallback, and request a post-copy datasync.
///
/// On success, returns the number of bytes copied.
pub fn sys_copy_file_range_ext(args: &CopyFileRangeExtArgs) -> Result<i64> {
    let req = validate_copy_file_range_ext_args(args)?;

    // Stub: real implementation would:
    // 1. Resolve fd_in and fd_out from the file table.
    // 2. If off_in_ptr != 0: copy_from_user the source offset.
    // 3. If off_out_ptr != 0: copy_from_user the dest offset.
    // 4. If REFLINK: try vfs_copy_file_range with COPY_FILE_REFLINK.
    // 5. If cross-device and NO_XDEV: return EXDEV.
    // 6. If FALLBACK: attempt read+write loop.
    // 7. If SYNC: call vfs_fsync_range on fd_out.
    // 8. Update offsets via copy_to_user if off_*_ptr != 0.
    // 9. Return bytes copied.
    let _ = req;
    Err(Error::NotImplemented)
}

/// Compute bytes that can be safely copied given filesystem block size.
///
/// Rounds `len` down to a multiple of `block_size` if non-zero.
/// Used by the CoW reflink path to ensure whole-block operations.
pub fn align_copy_len(len: u64, block_size: u64) -> u64 {
    if block_size == 0 {
        return len;
    }
    (len / block_size) * block_size
}
