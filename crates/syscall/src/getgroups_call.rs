// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `getgroups(2)` syscall dispatch layer.
//!
//! Copies the supplementary group IDs of the calling process into a
//! caller-supplied array.  If `size` is 0 the call returns the number of
//! supplementary groups without writing to `list_ptr`.
//!
//! # Syscall signature
//!
//! ```text
//! int getgroups(int size, gid_t list[]);
//! ```
//!
//! Returns the number of supplementary group IDs.
//!
//! # POSIX reference
//!
//! - POSIX.1-2024: `getgroups()` in `<unistd.h>`
//! - `.TheOpenGroup/susv5-html/functions/getgroups.html`
//!
//! # References
//!
//! - Linux: `kernel/groups.c` (`sys_getgroups`)
//! - `getgroups(2)` man page

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum number of supplementary groups per process (NGROUPS_MAX).
pub const NGROUPS_MAX: usize = 65536;

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

/// Handle `getgroups(2)`.
///
/// When `size` is 0 the call returns the current number of supplementary
/// groups without touching `list_ptr` (which may be null).  When `size` is
/// non-zero and `list_ptr` is null the call returns `EINVAL`.
///
/// # Errors
///
/// - [`Error::InvalidArgument`] — `size` is negative or `size` is non-zero
///   but `list_ptr` is null, or `size` exceeds `NGROUPS_MAX`.
/// - [`Error::NotImplemented`] — stub.
pub fn sys_getgroups(size: i32, list_ptr: u64) -> Result<i64> {
    if size < 0 {
        return Err(Error::InvalidArgument);
    }
    if size as usize > NGROUPS_MAX {
        return Err(Error::InvalidArgument);
    }
    if size > 0 && list_ptr == 0 {
        return Err(Error::InvalidArgument);
    }
    let _ = (size, list_ptr);
    Err(Error::NotImplemented)
}

/// Entry point called from the syscall dispatcher.
pub fn do_getgroups_call(size: i32, list_ptr: u64) -> Result<i64> {
    sys_getgroups(size, list_ptr)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn negative_size_rejected() {
        assert_eq!(sys_getgroups(-1, 0).unwrap_err(), Error::InvalidArgument);
    }

    #[test]
    fn nonzero_size_null_ptr_rejected() {
        assert_eq!(sys_getgroups(10, 0).unwrap_err(), Error::InvalidArgument);
    }

    #[test]
    fn zero_size_null_ptr_ok() {
        // size=0 with null ptr is valid — returns group count.
        let r = sys_getgroups(0, 0);
        assert_eq!(r.unwrap_err(), Error::NotImplemented);
    }

    #[test]
    fn size_too_large_rejected() {
        assert_eq!(
            sys_getgroups(NGROUPS_MAX as i32 + 1, 0x1000).unwrap_err(),
            Error::InvalidArgument
        );
    }
}
