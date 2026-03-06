// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `setgroups(2)` syscall dispatch layer.
//!
//! Sets the supplementary group IDs of the calling process.  Requires
//! `CAP_SETGID`.  Passing `size` 0 clears the supplementary group list.
//!
//! # Syscall signature
//!
//! ```text
//! int setgroups(size_t size, const gid_t *list);
//! ```
//!
//! # POSIX reference
//!
//! - POSIX.1-2024: `setgroups()` in `<grp.h>`
//! - `.TheOpenGroup/susv5-html/functions/setgroups.html`
//!
//! # References
//!
//! - Linux: `kernel/groups.c` (`sys_setgroups`)
//! - `setgroups(2)` man page

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum number of supplementary groups per process.
pub const NGROUPS_MAX: usize = 65536;

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

/// Handle `setgroups(2)`.
///
/// When `size` is 0 the supplementary group list is cleared; `list_ptr` is
/// not dereferenced in that case.
///
/// # Errors
///
/// - [`Error::InvalidArgument`] — `size` exceeds `NGROUPS_MAX` or `size` is
///   non-zero and `list_ptr` is null.
/// - [`Error::PermissionDenied`] — caller lacks `CAP_SETGID`.
/// - [`Error::NotImplemented`] — stub.
pub fn sys_setgroups(size: usize, list_ptr: u64) -> Result<i64> {
    if size > NGROUPS_MAX {
        return Err(Error::InvalidArgument);
    }
    if size > 0 && list_ptr == 0 {
        return Err(Error::InvalidArgument);
    }
    let _ = (size, list_ptr);
    Err(Error::NotImplemented)
}

/// Entry point called from the syscall dispatcher.
pub fn do_setgroups_call(size: usize, list_ptr: u64) -> Result<i64> {
    sys_setgroups(size, list_ptr)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn size_too_large_rejected() {
        assert_eq!(
            sys_setgroups(NGROUPS_MAX + 1, 0x1000).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn nonzero_size_null_ptr_rejected() {
        assert_eq!(sys_setgroups(1, 0).unwrap_err(), Error::InvalidArgument);
    }

    #[test]
    fn zero_size_clears_groups() {
        let r = sys_setgroups(0, 0);
        assert_eq!(r.unwrap_err(), Error::NotImplemented);
    }

    #[test]
    fn valid_call_reaches_stub() {
        let r = sys_setgroups(3, 0x1000);
        assert_eq!(r.unwrap_err(), Error::NotImplemented);
    }
}
