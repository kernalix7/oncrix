// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `fchmodat(2)` syscall dispatch layer.
//!
//! Changes the file permission bits of the file named by `pathname`
//! relative to the open directory `dirfd`.
//!
//! # Syscall signature
//!
//! ```text
//! int fchmodat(int dirfd, const char *pathname, mode_t mode, int flags);
//! ```
//!
//! # Mode bits
//!
//! Only the lower 12 bits of `mode` are meaningful:
//! - Bits 0..8:  `rwxrwxrwx` permission bits.
//! - Bits 9..11: setuid, setgid, sticky.
//!
//! # POSIX reference
//!
//! - POSIX.1-2024: `fchmodat()` in `<sys/stat.h>`
//! - `.TheOpenGroup/susv5-html/functions/fchmodat.html`
//!
//! # References
//!
//! - Linux: `fs/attr.c`, `fs/open.c`
//! - `fchmodat(2)` man page

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Use the current working directory as the base for relative paths.
pub const AT_FDCWD: i32 = -100;

/// Do not follow trailing symbolic links.
pub const AT_SYMLINK_NOFOLLOW: i32 = 0x100;

/// Operate on `dirfd` itself when `pathname` is empty.
pub const AT_EMPTY_PATH: i32 = 0x1000;

/// All valid flag bits.
const FLAGS_VALID: i32 = AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH;

/// Mask covering all 12 mode bits (permission + suid/sgid/sticky).
const MODE_MASK: u32 = 0o7777;

/// Maximum valid file descriptor number.
const FD_MAX: i32 = 1_048_576;

// ---------------------------------------------------------------------------
// Validation helpers
// ---------------------------------------------------------------------------

/// Returns `true` if `dirfd` is `AT_FDCWD` or a plausible open fd number.
pub fn is_valid_dirfd(dirfd: i32) -> bool {
    dirfd == AT_FDCWD || (0..=FD_MAX).contains(&dirfd)
}

/// Returns `true` if `mode` contains only the 12 file-mode bits.
pub fn is_valid_mode(mode: u32) -> bool {
    mode & !MODE_MASK == 0
}

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

/// Handle `fchmodat(2)`.
///
/// # Errors
///
/// - [`Error::InvalidArgument`] — unknown flags, mode bits out of range,
///   null pathname without `AT_EMPTY_PATH`, or `dirfd` is out of range.
/// - [`Error::NotFound`] — path does not exist.
/// - [`Error::PermissionDenied`] — caller is not the file owner and lacks
///   `CAP_FOWNER`.
/// - [`Error::NotImplemented`] — stub.
pub fn sys_fchmodat(dirfd: i32, pathname_ptr: u64, mode: u32, flags: i32) -> Result<i64> {
    if !is_valid_dirfd(dirfd) {
        return Err(Error::InvalidArgument);
    }
    if flags & !FLAGS_VALID != 0 {
        return Err(Error::InvalidArgument);
    }
    if pathname_ptr == 0 && (flags & AT_EMPTY_PATH == 0) {
        return Err(Error::InvalidArgument);
    }
    if !is_valid_mode(mode) {
        return Err(Error::InvalidArgument);
    }
    let _ = (dirfd, pathname_ptr, mode, flags);
    Err(Error::NotImplemented)
}

/// Entry point called from the syscall dispatcher.
pub fn do_fchmodat_call(dirfd: i32, pathname_ptr: u64, mode: u32, flags: i32) -> Result<i64> {
    sys_fchmodat(dirfd, pathname_ptr, mode, flags)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_flags_rejected() {
        assert_eq!(
            sys_fchmodat(AT_FDCWD, 0x1000, 0o644, 0x4000).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn null_path_without_empty_path_rejected() {
        assert_eq!(
            sys_fchmodat(AT_FDCWD, 0, 0o644, 0).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn invalid_mode_bits_rejected() {
        // Bit 13 is outside the 12-bit mask.
        assert_eq!(
            sys_fchmodat(AT_FDCWD, 0x1000, 0o100_000, 0).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn valid_call_reaches_stub() {
        let r = sys_fchmodat(AT_FDCWD, 0x1000, 0o755, 0);
        assert_eq!(r.unwrap_err(), Error::NotImplemented);
    }

    #[test]
    fn empty_path_with_flag_ok() {
        let r = sys_fchmodat(3, 0, 0o644, AT_EMPTY_PATH);
        assert_eq!(r.unwrap_err(), Error::NotImplemented);
    }
}
