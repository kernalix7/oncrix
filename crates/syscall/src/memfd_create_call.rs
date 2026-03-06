// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `memfd_create(2)` syscall dispatch layer.
//!
//! Creates an anonymous file that lives in memory.  The file descriptor
//! returned behaves like a regular file descriptor but has no path in the
//! filesystem.  It supports file sealing via `fcntl(F_ADD_SEALS)`.
//!
//! # Syscall signature
//!
//! ```text
//! int memfd_create(const char *name, unsigned int flags);
//! ```
//!
//! `name` is used for display purposes only (appears under `/proc/<pid>/fd/`)
//! and does not have to be unique.
//!
//! # Flags
//!
//! | Constant          | Value | Description |
//! |-------------------|-------|-------------|
//! | `MFD_CLOEXEC`     | 0x01  | Set `FD_CLOEXEC` on the new fd |
//! | `MFD_ALLOW_SEALING` | 0x02 | Enable `F_ADD_SEALS` operations |
//! | `MFD_HUGETLB`     | 0x04  | Back with huge pages |
//!
//! # References
//!
//! - Linux: `mm/memfd.c` (`memfd_create`)
//! - `memfd_create(2)` man page

use oncrix_lib::{Error, Result};

// Re-export flag constants from the existing memfd module.
pub use crate::memfd::{MFD_ALLOW_SEALING, MFD_CLOEXEC, MFD_HUGETLB};

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

/// Handle `memfd_create(2)`.
///
/// `name_ptr` must be non-null and point to a NUL-terminated string.
///
/// # Errors
///
/// - [`Error::InvalidArgument`] — unknown flags or null `name_ptr`.
/// - [`Error::OutOfMemory`] — insufficient resources to create the fd.
/// - [`Error::NotImplemented`] — stub.
pub fn sys_memfd_create(name_ptr: u64, flags: u32) -> Result<i64> {
    if name_ptr == 0 {
        return Err(Error::InvalidArgument);
    }
    let valid_flags = MFD_CLOEXEC | MFD_ALLOW_SEALING | MFD_HUGETLB;
    if flags & !valid_flags != 0 {
        return Err(Error::InvalidArgument);
    }
    let _ = (name_ptr, flags);
    Err(Error::NotImplemented)
}

/// Entry point called from the syscall dispatcher.
pub fn do_memfd_create_call(name_ptr: u64, flags: u32) -> Result<i64> {
    sys_memfd_create(name_ptr, flags)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn null_name_rejected() {
        assert_eq!(sys_memfd_create(0, 0).unwrap_err(), Error::InvalidArgument);
    }

    #[test]
    fn unknown_flags_rejected() {
        assert_eq!(
            sys_memfd_create(0x1000, 0x80).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn valid_call_reaches_stub() {
        let r = sys_memfd_create(0x1000, MFD_CLOEXEC | MFD_ALLOW_SEALING);
        assert_eq!(r.unwrap_err(), Error::NotImplemented);
    }

    #[test]
    fn no_flags_valid() {
        let r = sys_memfd_create(0x1000, 0);
        assert_eq!(r.unwrap_err(), Error::NotImplemented);
    }
}
