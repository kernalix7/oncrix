// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `dup3(2)` syscall dispatch layer.
//!
//! Like `dup2(2)` but also allows the caller to force `O_CLOEXEC` on the new
//! descriptor.  If `oldfd == newfd` with `dup3`, it fails with `EINVAL`
//! (unlike `dup2` which succeeds in that case).
//!
//! # Syscall signature
//!
//! ```text
//! int dup3(int oldfd, int newfd, int flags);
//! ```
//!
//! The only defined flag is `O_CLOEXEC`.
//!
//! # References
//!
//! - Linux: `fs/file.c` (`sys_dup3`)
//! - `dup3(2)` man page

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum valid file descriptor number.
const FD_MAX: i32 = 1_048_576;

/// Close-on-exec flag for the new descriptor.
pub const O_CLOEXEC: i32 = 0o2000000;

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

/// Handle `dup3(2)`.
///
/// Duplicates `oldfd` to `newfd` with optional `O_CLOEXEC`.  `oldfd` must
/// not equal `newfd`.
///
/// # Errors
///
/// - [`Error::InvalidArgument`] — `oldfd == newfd`, either fd < 0 or > `FD_MAX`,
///   or `flags` contains bits other than `O_CLOEXEC`.
/// - [`Error::NotFound`] — `oldfd` is not open.
/// - [`Error::NotImplemented`] — stub.
pub fn sys_dup3(oldfd: i32, newfd: i32, flags: i32) -> Result<i64> {
    if oldfd < 0 || oldfd > FD_MAX {
        return Err(Error::InvalidArgument);
    }
    if newfd < 0 || newfd > FD_MAX {
        return Err(Error::InvalidArgument);
    }
    if oldfd == newfd {
        return Err(Error::InvalidArgument);
    }
    if flags & !O_CLOEXEC != 0 {
        return Err(Error::InvalidArgument);
    }
    let _ = (oldfd, newfd, flags);
    Err(Error::NotImplemented)
}

/// Entry point called from the syscall dispatcher.
pub fn do_dup3_call(oldfd: i32, newfd: i32, flags: i32) -> Result<i64> {
    sys_dup3(oldfd, newfd, flags)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_fds_rejected() {
        assert_eq!(sys_dup3(3, 3, 0).unwrap_err(), Error::InvalidArgument);
    }

    #[test]
    fn unknown_flags_rejected() {
        assert_eq!(sys_dup3(3, 5, 0x0002).unwrap_err(), Error::InvalidArgument);
    }

    #[test]
    fn negative_oldfd_rejected() {
        assert_eq!(sys_dup3(-1, 5, 0).unwrap_err(), Error::InvalidArgument);
    }

    #[test]
    fn valid_without_cloexec_reaches_stub() {
        let r = sys_dup3(3, 5, 0);
        assert_eq!(r.unwrap_err(), Error::NotImplemented);
    }

    #[test]
    fn valid_with_cloexec_reaches_stub() {
        let r = sys_dup3(3, 5, O_CLOEXEC);
        assert_eq!(r.unwrap_err(), Error::NotImplemented);
    }
}
