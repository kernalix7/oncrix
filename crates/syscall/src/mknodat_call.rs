// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `mknodat(2)` syscall dispatch layer.
//!
//! Creates a filesystem node (regular file, device file, named pipe, or
//! socket) named by `pathname` relative to the open directory `dirfd`.
//!
//! # Syscall signature
//!
//! ```text
//! int mknodat(int dirfd, const char *pathname, mode_t mode, dev_t dev);
//! ```
//!
//! The `dev` argument is used only when `mode` specifies a character or
//! block device (`S_IFCHR` or `S_IFBLK`); it encodes major and minor
//! device numbers.
//!
//! # File type bits (`mode & S_IFMT`)
//!
//! | Constant  | Value  | Description |
//! |-----------|--------|-------------|
//! | `S_IFREG` | 0o100000 | Regular file |
//! | `S_IFCHR` | 0o020000 | Character device |
//! | `S_IFBLK` | 0o060000 | Block device |
//! | `S_IFIFO` | 0o010000 | Named pipe (FIFO) |
//! | `S_IFSOCK`| 0o140000 | Unix-domain socket |
//!
//! # POSIX reference
//!
//! - POSIX.1-2024: `mknodat()` in `<sys/stat.h>`
//! - `.TheOpenGroup/susv5-html/functions/mknodat.html`
//!
//! # References
//!
//! - Linux: `fs/namei.c` (`do_mknodat`)
//! - `mknodat(2)` man page

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Use the current working directory as the base for relative paths.
pub const AT_FDCWD: i32 = -100;

/// File type mask.
pub const S_IFMT: u32 = 0o170000;
/// Regular file.
pub const S_IFREG: u32 = 0o100000;
/// Character device.
pub const S_IFCHR: u32 = 0o020000;
/// Block device.
pub const S_IFBLK: u32 = 0o060000;
/// Named pipe (FIFO).
pub const S_IFIFO: u32 = 0o010000;
/// Unix-domain socket.
pub const S_IFSOCK: u32 = 0o140000;

/// Mask of all 12 permission + special bits.
const PERM_MASK: u32 = 0o7777;

/// Maximum valid file descriptor number.
const FD_MAX: i32 = 1_048_576;

// ---------------------------------------------------------------------------
// Validation helpers
// ---------------------------------------------------------------------------

/// Returns `true` if `dirfd` is `AT_FDCWD` or a plausible open fd number.
pub fn is_valid_dirfd(dirfd: i32) -> bool {
    dirfd == AT_FDCWD || (0..=FD_MAX).contains(&dirfd)
}

/// Returns `true` if the file-type bits of `mode` are one of the allowed types.
pub fn is_valid_filetype(mode: u32) -> bool {
    matches!(
        mode & S_IFMT,
        S_IFREG | S_IFCHR | S_IFBLK | S_IFIFO | S_IFSOCK
    )
}

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

/// Handle `mknodat(2)`.
///
/// # Errors
///
/// - [`Error::InvalidArgument`] — null `pathname_ptr`, invalid `dirfd`,
///   or unrecognised file-type bits in `mode`.
/// - [`Error::PermissionDenied`] — creating device nodes requires
///   `CAP_MKNOD`.
/// - [`Error::AlreadyExists`] — a node at that path already exists.
/// - [`Error::NotFound`] — a component of the path does not exist.
/// - [`Error::NotImplemented`] — stub.
pub fn sys_mknodat(dirfd: i32, pathname_ptr: u64, mode: u32, dev: u64) -> Result<i64> {
    if !is_valid_dirfd(dirfd) {
        return Err(Error::InvalidArgument);
    }
    if pathname_ptr == 0 {
        return Err(Error::InvalidArgument);
    }
    if !is_valid_filetype(mode) {
        return Err(Error::InvalidArgument);
    }
    // Permission bits must fit within the 12-bit mask.
    if mode & !S_IFMT & !PERM_MASK != 0 {
        return Err(Error::InvalidArgument);
    }
    let _ = (dirfd, pathname_ptr, mode, dev);
    Err(Error::NotImplemented)
}

/// Entry point called from the syscall dispatcher.
pub fn do_mknodat_call(dirfd: i32, pathname_ptr: u64, mode: u32, dev: u64) -> Result<i64> {
    sys_mknodat(dirfd, pathname_ptr, mode, dev)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn null_pathname_rejected() {
        assert_eq!(
            sys_mknodat(AT_FDCWD, 0, S_IFREG | 0o644, 0).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn invalid_filetype_rejected() {
        // S_IFDIR (0o040000) is not a valid mknodat type.
        assert_eq!(
            sys_mknodat(AT_FDCWD, 0x1000, 0o040000 | 0o755, 0).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn regular_file_valid() {
        let r = sys_mknodat(AT_FDCWD, 0x1000, S_IFREG | 0o644, 0);
        assert_eq!(r.unwrap_err(), Error::NotImplemented);
    }

    #[test]
    fn char_device_valid() {
        let r = sys_mknodat(AT_FDCWD, 0x1000, S_IFCHR | 0o600, 0x0501);
        assert_eq!(r.unwrap_err(), Error::NotImplemented);
    }

    #[test]
    fn fifo_valid() {
        let r = sys_mknodat(AT_FDCWD, 0x1000, S_IFIFO | 0o666, 0);
        assert_eq!(r.unwrap_err(), Error::NotImplemented);
    }
}
