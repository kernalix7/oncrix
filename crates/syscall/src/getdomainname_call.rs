// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `getdomainname(2)` and `setdomainname(2)` syscall dispatch layer.
//!
//! Get or set the NIS (YP) domain name of the host.
//!
//! # Syscall signatures
//!
//! ```text
//! int getdomainname(char *name, size_t len);
//! int setdomainname(const char *name, size_t len);
//! ```
//!
//! # References
//!
//! - Linux: `kernel/sys.c` (`sys_getdomainname`, `sys_setdomainname`)
//! - `getdomainname(2)` man page

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum domain name length (including NUL terminator).
pub const HOST_NAME_MAX: usize = 64;

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// Handle `getdomainname(2)`.
///
/// `name_ptr` is a user-space pointer to a buffer of at least `len` bytes.
///
/// # Errors
///
/// - [`Error::InvalidArgument`] — null `name_ptr` or `len == 0`.
/// - [`Error::NotImplemented`] — stub.
pub fn sys_getdomainname(name_ptr: u64, len: usize) -> Result<i64> {
    if name_ptr == 0 {
        return Err(Error::InvalidArgument);
    }
    if len == 0 {
        return Err(Error::InvalidArgument);
    }
    let _ = (name_ptr, len);
    Err(Error::NotImplemented)
}

/// Handle `setdomainname(2)`.
///
/// `name_ptr` is a user-space pointer to the new domain name (not necessarily
/// NUL-terminated); `len` is the byte count (not counting NUL, max
/// `HOST_NAME_MAX - 1`).
///
/// # Errors
///
/// - [`Error::InvalidArgument`] — null `name_ptr` or `len >= HOST_NAME_MAX`.
/// - [`Error::PermissionDenied`] — requires `CAP_SYS_ADMIN`.
/// - [`Error::NotImplemented`] — stub.
pub fn sys_setdomainname(name_ptr: u64, len: usize) -> Result<i64> {
    if name_ptr == 0 {
        return Err(Error::InvalidArgument);
    }
    if len >= HOST_NAME_MAX {
        return Err(Error::InvalidArgument);
    }
    let _ = (name_ptr, len);
    Err(Error::NotImplemented)
}

/// Entry point for `getdomainname` from the syscall dispatcher.
pub fn do_getdomainname_call(name_ptr: u64, len: usize) -> Result<i64> {
    sys_getdomainname(name_ptr, len)
}

/// Entry point for `setdomainname` from the syscall dispatcher.
pub fn do_setdomainname_call(name_ptr: u64, len: usize) -> Result<i64> {
    sys_setdomainname(name_ptr, len)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn getdomainname_null_ptr_rejected() {
        assert_eq!(
            sys_getdomainname(0, 64).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn getdomainname_zero_len_rejected() {
        assert_eq!(
            sys_getdomainname(0x1000, 0).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn getdomainname_valid_reaches_stub() {
        let r = sys_getdomainname(0x1000, 64);
        assert_eq!(r.unwrap_err(), Error::NotImplemented);
    }

    #[test]
    fn setdomainname_null_ptr_rejected() {
        assert_eq!(sys_setdomainname(0, 8).unwrap_err(), Error::InvalidArgument);
    }

    #[test]
    fn setdomainname_too_long_rejected() {
        assert_eq!(
            sys_setdomainname(0x1000, HOST_NAME_MAX).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn setdomainname_valid_reaches_stub() {
        let r = sys_setdomainname(0x1000, 10);
        assert_eq!(r.unwrap_err(), Error::NotImplemented);
    }
}
