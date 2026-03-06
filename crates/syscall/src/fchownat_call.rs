// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `fchownat(2)` syscall dispatch layer.
//!
//! Changes the owner and group of a file specified by `pathname` relative
//! to the open directory `dirfd`.  Passing `-1` for `uid` or `gid` leaves
//! the respective field unchanged (POSIX.1-2024 semantics).
//!
//! # Syscall signature
//!
//! ```text
//! int fchownat(int dirfd, const char *pathname,
//!              uid_t owner, gid_t group, int flags);
//! ```
//!
//! # POSIX reference
//!
//! - POSIX.1-2024: `fchownat()` in `<unistd.h>`
//! - `.TheOpenGroup/susv5-html/functions/fchownat.html`
//!
//! # References
//!
//! - Linux: `fs/attr.c` (`chown_common`)
//! - `fchownat(2)` man page

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

/// Sentinel meaning "do not change this credential field".
pub const UNCHANGED: u32 = u32::MAX;

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

/// Handle `fchownat(2)`.
///
/// `uid` and `gid` may each be `UNCHANGED` (`u32::MAX` / `-1` in the C ABI)
/// to leave the corresponding field unmodified.
///
/// # Errors
///
/// - [`Error::InvalidArgument`] — unknown flags, null pathname without
///   `AT_EMPTY_PATH`, or `dirfd` is out of range.
/// - [`Error::NotFound`] — path does not exist.
/// - [`Error::PermissionDenied`] — caller lacks the required privilege.
/// - [`Error::NotImplemented`] — stub.
pub fn sys_fchownat(dirfd: i32, pathname_ptr: u64, uid: u32, gid: u32, flags: i32) -> Result<i64> {
    if !is_valid_dirfd(dirfd) {
        return Err(Error::InvalidArgument);
    }
    if flags & !FLAGS_VALID != 0 {
        return Err(Error::InvalidArgument);
    }
    if pathname_ptr == 0 && (flags & AT_EMPTY_PATH == 0) {
        return Err(Error::InvalidArgument);
    }
    let _ = (dirfd, pathname_ptr, uid, gid, flags);
    Err(Error::NotImplemented)
}

/// Entry point called from the syscall dispatcher.
pub fn do_fchownat_call(
    dirfd: i32,
    pathname_ptr: u64,
    uid: u32,
    gid: u32,
    flags: i32,
) -> Result<i64> {
    sys_fchownat(dirfd, pathname_ptr, uid, gid, flags)
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
            sys_fchownat(AT_FDCWD, 0x1000, 1000, 1000, 0x8000).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn null_path_without_empty_path_rejected() {
        assert_eq!(
            sys_fchownat(AT_FDCWD, 0, 1000, 1000, 0).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn unchanged_uid_and_gid_ok() {
        // Both UNCHANGED — no-op change is valid to request.
        let r = sys_fchownat(AT_FDCWD, 0x1000, UNCHANGED, UNCHANGED, 0);
        assert_eq!(r.unwrap_err(), Error::NotImplemented);
    }

    #[test]
    fn empty_path_with_flag_ok() {
        let r = sys_fchownat(3, 0, 1000, 1000, AT_EMPTY_PATH);
        assert_eq!(r.unwrap_err(), Error::NotImplemented);
    }

    #[test]
    fn symlink_nofollow_valid() {
        let r = sys_fchownat(AT_FDCWD, 0x2000, 0, 0, AT_SYMLINK_NOFOLLOW);
        assert_eq!(r.unwrap_err(), Error::NotImplemented);
    }
}
