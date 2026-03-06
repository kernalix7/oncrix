// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `dup2(2)` syscall dispatch layer.
//!
//! Duplicates a file descriptor to a specific target descriptor number,
//! closing the target first if it is already open.
//!
//! # Syscall signature
//!
//! ```text
//! int dup2(int oldfd, int newfd);
//! ```
//!
//! # POSIX reference
//!
//! - POSIX.1-2024: `dup2()` in `<unistd.h>`
//! - `.TheOpenGroup/susv5-html/functions/dup2.html`
//!
//! # References
//!
//! - Linux: `fs/file.c` (`sys_dup2`)

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum valid file descriptor number.
const FD_MAX: i32 = 1_048_576;

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

/// Handle `dup2(2)`.
///
/// Duplicates `oldfd` to `newfd`.  If `oldfd == newfd` and `oldfd` is open,
/// returns `newfd` immediately without closing.
///
/// # Errors
///
/// - [`Error::InvalidArgument`] — `oldfd < 0`, `newfd < 0`, or either fd
///   exceeds `FD_MAX`.
/// - [`Error::NotFound`] — `oldfd` is not open.
/// - [`Error::NotImplemented`] — stub.
pub fn sys_dup2(oldfd: i32, newfd: i32) -> Result<i64> {
    if oldfd < 0 || oldfd > FD_MAX {
        return Err(Error::InvalidArgument);
    }
    if newfd < 0 || newfd > FD_MAX {
        return Err(Error::InvalidArgument);
    }
    let _ = (oldfd, newfd);
    Err(Error::NotImplemented)
}

/// Entry point called from the syscall dispatcher.
pub fn do_dup2_call(oldfd: i32, newfd: i32) -> Result<i64> {
    sys_dup2(oldfd, newfd)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn negative_oldfd_rejected() {
        assert_eq!(sys_dup2(-1, 3).unwrap_err(), Error::InvalidArgument);
    }

    #[test]
    fn negative_newfd_rejected() {
        assert_eq!(sys_dup2(3, -1).unwrap_err(), Error::InvalidArgument);
    }

    #[test]
    fn fd_exceeds_max_rejected() {
        assert_eq!(sys_dup2(3, FD_MAX + 1).unwrap_err(), Error::InvalidArgument);
    }

    #[test]
    fn valid_dup2_reaches_stub() {
        let r = sys_dup2(3, 5);
        assert_eq!(r.unwrap_err(), Error::NotImplemented);
    }

    #[test]
    fn same_fd_reaches_stub() {
        let r = sys_dup2(3, 3);
        assert_eq!(r.unwrap_err(), Error::NotImplemented);
    }
}
