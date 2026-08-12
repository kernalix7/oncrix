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

/// Inclusive upper bound of the canonical user-space lower half (x86_64).
///
/// Mirrors `oncrix_mm::address_space::USER_SPACE_END`.  Any pointer supplied
/// by the caller for `off_in_ptr` / `off_out_ptr` must satisfy
/// `ptr <= USER_PTR_MAX`.
const USER_PTR_MAX: u64 = 0x0000_7FFF_FFFF_FFFF;

/// Minimum alignment (in bytes) required for `off_in_ptr` / `off_out_ptr`.
///
/// Both pointers reference a `u64` offset, so they must be 8-byte aligned.
const OFFSET_PTR_ALIGN: usize = core::mem::align_of::<u64>();

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
#[derive(Debug)]
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

/// Validate that a user-supplied offset pointer is safe to dereference.
///
/// A value of `0` means "use current file position" and is explicitly
/// permitted.  Any non-zero value must be:
///
/// - Within the canonical user-space lower half (`<= USER_PTR_MAX`).
/// - Aligned to `OFFSET_PTR_ALIGN` bytes (the pointer targets a `u64`).
///
/// # Errors
///
/// Returns `InvalidArgument` if the pointer is a non-zero kernel-half or
/// non-canonical address, or if it is insufficiently aligned.
fn validate_offset_ptr(ptr: usize) -> Result<()> {
    if ptr == 0 {
        // Zero is the sentinel meaning "use current file position".
        return Ok(());
    }
    if ptr as u64 > USER_PTR_MAX {
        return Err(Error::InvalidArgument);
    }
    if ptr % OFFSET_PTR_ALIGN != 0 {
        return Err(Error::InvalidArgument);
    }
    Ok(())
}

/// Validate extended copy_file_range arguments.
///
/// Returns a structured request or an appropriate errno.
///
/// # Security
///
/// `off_in_ptr` and `off_out_ptr` are user-supplied virtual addresses that
/// the kernel will dereference (via `copy_from_user` / `copy_to_user`).
/// Each non-zero pointer is validated to be within the canonical user-space
/// lower half and properly aligned before the call proceeds.  A kernel-half
/// address would cause a ring-0 fault and halt the kernel.
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

    // Validate offset pointers before any kernel dereference.
    validate_offset_ptr(args.off_in_ptr)?;
    validate_offset_ptr(args.off_out_ptr)?;

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

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_args() -> CopyFileRangeExtArgs {
        CopyFileRangeExtArgs {
            fd_in: 3,
            off_in_ptr: 0,
            fd_out: 4,
            off_out_ptr: 0,
            len: 4096,
            flags: 0,
        }
    }

    #[test]
    fn valid_args_accepted() {
        assert!(validate_copy_file_range_ext_args(&valid_args()).is_ok());
    }

    #[test]
    fn negative_fd_rejected() {
        let mut args = valid_args();
        args.fd_in = -1;
        assert_eq!(
            validate_copy_file_range_ext_args(&args).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn same_fd_rejected() {
        let mut args = valid_args();
        args.fd_out = args.fd_in;
        assert_eq!(
            validate_copy_file_range_ext_args(&args).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn zero_len_rejected() {
        let mut args = valid_args();
        args.len = 0;
        assert_eq!(
            validate_copy_file_range_ext_args(&args).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn kernel_half_off_in_ptr_rejected() {
        // off_in_ptr pointing into kernel-half is a ring-0 dereference hazard.
        let mut args = valid_args();
        args.off_in_ptr = 0xFFFF_8000_0000_0000_usize;
        assert_eq!(
            validate_copy_file_range_ext_args(&args).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn kernel_half_off_out_ptr_rejected() {
        let mut args = valid_args();
        args.off_out_ptr = 0xFFFF_8000_0000_0008_usize;
        assert_eq!(
            validate_copy_file_range_ext_args(&args).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn unaligned_off_in_ptr_rejected() {
        let mut args = valid_args();
        // Must be 8-byte aligned (points to u64).
        args.off_in_ptr = 0x1001;
        assert_eq!(
            validate_copy_file_range_ext_args(&args).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn unaligned_off_out_ptr_rejected() {
        let mut args = valid_args();
        args.off_out_ptr = 0x1003;
        assert_eq!(
            validate_copy_file_range_ext_args(&args).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn aligned_user_ptr_accepted() {
        // A properly aligned, user-space pointer is valid.
        let mut args = valid_args();
        args.off_in_ptr = 0x1000; // page-aligned, well within user space
        args.off_out_ptr = 0x2000;
        assert!(validate_copy_file_range_ext_args(&args).is_ok());
    }

    #[test]
    fn zero_ptrs_accepted() {
        // Zero == "use file position", always permitted.
        let args = valid_args();
        assert_eq!(args.off_in_ptr, 0);
        assert_eq!(args.off_out_ptr, 0);
        assert!(validate_copy_file_range_ext_args(&args).is_ok());
    }

    #[test]
    fn fallback_and_no_xdev_mutually_exclusive() {
        let mut args = valid_args();
        args.flags =
            CopyFileRangeExtFlags::COPY_FR_FALLBACK | CopyFileRangeExtFlags::COPY_FR_NO_XDEV;
        assert_eq!(
            validate_copy_file_range_ext_args(&args).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn align_copy_len_rounds_down() {
        assert_eq!(align_copy_len(4100, 4096), 4096);
        assert_eq!(align_copy_len(8192, 4096), 8192);
        assert_eq!(align_copy_len(1, 512), 0);
    }

    #[test]
    fn align_copy_len_zero_block_size() {
        assert_eq!(align_copy_len(1234, 0), 1234);
    }
}
