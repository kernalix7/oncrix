// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `renameat2(2)` syscall dispatch layer.
//!
//! Renames (or exchanges / whiteouts) a filesystem path.  `renameat2`
//! extends `renameat(1)` by adding a `flags` argument that controls
//! atomicity and special rename modes.
//!
//! # Syscall signature
//!
//! ```text
//! int renameat2(int olddirfd, const char *oldpath,
//!               int newdirfd, const char *newpath,
//!               unsigned int flags);
//! ```
//!
//! # Flags
//!
//! | Constant              | Value | Description |
//! |-----------------------|-------|-------------|
//! | `RENAME_NOREPLACE`    | 1     | Fail if `newpath` already exists |
//! | `RENAME_EXCHANGE`     | 2     | Atomically swap old and new |
//! | `RENAME_WHITEOUT`     | 4     | Leave a whiteout at `oldpath` |
//!
//! `RENAME_NOREPLACE` and `RENAME_EXCHANGE` are mutually exclusive.
//!
//! # POSIX reference
//!
//! - POSIX.1-2024: `rename()` in `<stdio.h>`
//! - Linux extension: `renameat2(2)` man page
//!
//! # References
//!
//! - Linux: `fs/namei.c` (`do_renameat2`)
//! - `renameat2(2)` man page

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Use the current working directory as the base for relative paths.
pub const AT_FDCWD: i32 = -100;

/// Do not replace `newpath` if it already exists.
pub const RENAME_NOREPLACE: u32 = 1;
/// Atomically exchange `oldpath` and `newpath`.
pub const RENAME_EXCHANGE: u32 = 2;
/// Create a whiteout at `oldpath` after renaming.
pub const RENAME_WHITEOUT: u32 = 4;

/// All valid flag bits.
const FLAGS_VALID: u32 = RENAME_NOREPLACE | RENAME_EXCHANGE | RENAME_WHITEOUT;

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

/// Handle `renameat2(2)`.
///
/// # Errors
///
/// - [`Error::InvalidArgument`] — unknown flags, `RENAME_NOREPLACE` and
///   `RENAME_EXCHANGE` both set, null path pointers, or invalid dirfds.
/// - [`Error::NotFound`] — `oldpath` does not exist.
/// - [`Error::AlreadyExists`] — `newpath` exists and `RENAME_NOREPLACE` is set.
/// - [`Error::PermissionDenied`] — write permission denied on a parent directory.
/// - [`Error::NotImplemented`] — stub.
pub fn sys_renameat2(
    olddirfd: i32,
    oldpath_ptr: u64,
    newdirfd: i32,
    newpath_ptr: u64,
    flags: u32,
) -> Result<i64> {
    if !is_valid_dirfd(olddirfd) || !is_valid_dirfd(newdirfd) {
        return Err(Error::InvalidArgument);
    }
    if flags & !FLAGS_VALID != 0 {
        return Err(Error::InvalidArgument);
    }
    // RENAME_NOREPLACE and RENAME_EXCHANGE are mutually exclusive.
    if flags & RENAME_NOREPLACE != 0 && flags & RENAME_EXCHANGE != 0 {
        return Err(Error::InvalidArgument);
    }
    if oldpath_ptr == 0 || newpath_ptr == 0 {
        return Err(Error::InvalidArgument);
    }
    let _ = (olddirfd, oldpath_ptr, newdirfd, newpath_ptr, flags);
    Err(Error::NotImplemented)
}

/// Entry point called from the syscall dispatcher.
pub fn do_renameat2_call(
    olddirfd: i32,
    oldpath_ptr: u64,
    newdirfd: i32,
    newpath_ptr: u64,
    flags: u32,
) -> Result<i64> {
    sys_renameat2(olddirfd, oldpath_ptr, newdirfd, newpath_ptr, flags)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn null_oldpath_rejected() {
        assert_eq!(
            sys_renameat2(AT_FDCWD, 0, AT_FDCWD, 0x1000, 0).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn null_newpath_rejected() {
        assert_eq!(
            sys_renameat2(AT_FDCWD, 0x1000, AT_FDCWD, 0, 0).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn unknown_flags_rejected() {
        assert_eq!(
            sys_renameat2(AT_FDCWD, 0x1000, AT_FDCWD, 0x2000, 0x80).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn noreplace_and_exchange_mutually_exclusive() {
        assert_eq!(
            sys_renameat2(
                AT_FDCWD,
                0x1000,
                AT_FDCWD,
                0x2000,
                RENAME_NOREPLACE | RENAME_EXCHANGE
            )
            .unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn plain_rename_reaches_stub() {
        let r = sys_renameat2(AT_FDCWD, 0x1000, AT_FDCWD, 0x2000, 0);
        assert_eq!(r.unwrap_err(), Error::NotImplemented);
    }

    #[test]
    fn exchange_flag_reaches_stub() {
        let r = sys_renameat2(AT_FDCWD, 0x1000, AT_FDCWD, 0x2000, RENAME_EXCHANGE);
        assert_eq!(r.unwrap_err(), Error::NotImplemented);
    }
}
