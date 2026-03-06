// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `statx(2)` syscall dispatch layer.
//!
//! Retrieves extended file metadata for the file named by `pathname`
//! relative to `dirfd`.  The caller supplies a bitmask of requested
//! fields; the kernel fills only the fields it can satisfy.
//!
//! # Syscall signature
//!
//! ```text
//! int statx(int dirfd, const char *restrict pathname, int flags,
//!           unsigned int mask, struct statx *restrict statxbuf);
//! ```
//!
//! # POSIX / Linux notes
//!
//! `statx` is a Linux extension.  It supersedes `stat(2)` / `lstat(2)` /
//! `fstat(2)` by adding birth-time, mount ID, and direct-I/O alignment.
//!
//! # References
//!
//! - Linux: `fs/stat.c` (`do_statx`)
//! - `statx(2)` man page
//! - `include/uapi/linux/stat.h`

use oncrix_lib::{Error, Result};

// Re-export the full implementation types from the existing statx module.
pub use crate::statx::{StatxMask, StatxTimestamp};

// ---------------------------------------------------------------------------
// AT_* flag constants
// ---------------------------------------------------------------------------

/// Use the current working directory as the base for relative paths.
pub const AT_FDCWD: i32 = -100;

/// Do not follow trailing symbolic links.
pub const AT_SYMLINK_NOFOLLOW: i32 = 0x100;

/// Operate on `dirfd` itself when `pathname` is empty.
pub const AT_EMPTY_PATH: i32 = 0x1000;

/// Do not automount the final path component.
pub const AT_NO_AUTOMOUNT: i32 = 0x800;

/// Request only fields that can be returned without querying the filesystem.
pub const AT_STATX_SYNC_AS_STAT: i32 = 0x0000;
/// Force synchronisation with the filesystem before returning.
pub const AT_STATX_FORCE_SYNC: i32 = 0x2000;
/// Do not synchronise — return cached data only.
pub const AT_STATX_DONT_SYNC: i32 = 0x4000;

/// All valid flag bits.
const FLAGS_VALID: i32 = AT_SYMLINK_NOFOLLOW
    | AT_EMPTY_PATH
    | AT_NO_AUTOMOUNT
    | AT_STATX_FORCE_SYNC
    | AT_STATX_DONT_SYNC;

/// Maximum valid file descriptor number.
const FD_MAX: i32 = 1_048_576;

// ---------------------------------------------------------------------------
// Validation helpers
// ---------------------------------------------------------------------------

/// Returns `true` if `dirfd` is `AT_FDCWD` or a plausible open fd number.
pub fn is_valid_dirfd(dirfd: i32) -> bool {
    dirfd == AT_FDCWD || (0..=FD_MAX).contains(&dirfd)
}

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

/// Handle `statx(2)`.
///
/// # Errors
///
/// - [`Error::InvalidArgument`] — unknown flags, null `statxbuf_ptr`,
///   null `pathname_ptr` without `AT_EMPTY_PATH`, or invalid `dirfd`.
/// - [`Error::NotFound`] — path does not exist.
/// - [`Error::NotImplemented`] — stub.
pub fn sys_statx(
    dirfd: i32,
    pathname_ptr: u64,
    flags: i32,
    mask: u32,
    statxbuf_ptr: u64,
) -> Result<i64> {
    if !is_valid_dirfd(dirfd) {
        return Err(Error::InvalidArgument);
    }
    if flags & !FLAGS_VALID != 0 {
        return Err(Error::InvalidArgument);
    }
    if pathname_ptr == 0 && (flags & AT_EMPTY_PATH == 0) {
        return Err(Error::InvalidArgument);
    }
    if statxbuf_ptr == 0 {
        return Err(Error::InvalidArgument);
    }
    let _ = (dirfd, pathname_ptr, flags, mask, statxbuf_ptr);
    Err(Error::NotImplemented)
}

/// Entry point called from the syscall dispatcher.
pub fn do_statx_call(
    dirfd: i32,
    pathname_ptr: u64,
    flags: i32,
    mask: u32,
    statxbuf_ptr: u64,
) -> Result<i64> {
    sys_statx(dirfd, pathname_ptr, flags, mask, statxbuf_ptr)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn null_statxbuf_rejected() {
        assert_eq!(
            sys_statx(AT_FDCWD, 0x1000, 0, 0xFFFF, 0).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn null_path_without_empty_path_rejected() {
        assert_eq!(
            sys_statx(AT_FDCWD, 0, 0, 0xFFFF, 0x2000).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn null_path_with_empty_path_ok() {
        let r = sys_statx(3, 0, AT_EMPTY_PATH, 0xFFFF, 0x2000);
        assert_eq!(r.unwrap_err(), Error::NotImplemented);
    }

    #[test]
    fn unknown_flags_rejected() {
        assert_eq!(
            sys_statx(AT_FDCWD, 0x1000, 0x8000, 0, 0x2000).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn valid_call_reaches_stub() {
        let r = sys_statx(AT_FDCWD, 0x1000, 0, 0x7FF, 0x2000);
        assert_eq!(r.unwrap_err(), Error::NotImplemented);
    }
}
