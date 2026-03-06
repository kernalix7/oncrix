// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `userfaultfd(2)` syscall dispatch layer.
//!
//! Creates a file descriptor for user-space page-fault handling.  The returned
//! fd is used with `ioctl(2)` to register virtual memory ranges and wait for
//! page-fault events.
//!
//! # Syscall signature
//!
//! ```text
//! int userfaultfd(int flags);
//! ```
//!
//! # References
//!
//! - Linux: `fs/userfaultfd.c` (`sys_userfaultfd`)
//! - `userfaultfd(2)` man page

use oncrix_lib::{Error, Result};

// Re-export flag types from the base module.
pub use crate::userfaultfd_calls::{UFFD_API, UffdFeatures, UffdFlags};

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

/// Handle `userfaultfd(2)`.
///
/// Creates a userfaultfd object.  `flags` may contain `O_NONBLOCK`,
/// `O_CLOEXEC`, and (Linux 5.11+) `UFFD_USER_MODE_ONLY`.
///
/// Returns a file descriptor on success.
///
/// # Errors
///
/// - [`Error::InvalidArgument`] — unknown flag bits.
/// - [`Error::PermissionDenied`] — requires `CAP_SYS_PTRACE` (unless
///   `UFFD_USER_MODE_ONLY` is set).
/// - [`Error::NotImplemented`] — stub.
pub fn sys_userfaultfd(flags: u32) -> Result<i64> {
    // Validate flags via the typed wrapper.
    UffdFlags::from_raw(flags).map_err(|_| Error::InvalidArgument)?;
    let _ = flags;
    Err(Error::NotImplemented)
}

/// Entry point called from the syscall dispatcher.
pub fn do_userfaultfd_call(flags: u32) -> Result<i64> {
    sys_userfaultfd(flags)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_flags_rejected() {
        // Bit 0x10 is not a recognised userfaultfd flag.
        assert_eq!(sys_userfaultfd(0x10).unwrap_err(), Error::InvalidArgument);
    }

    #[test]
    fn zero_flags_reaches_stub() {
        let r = sys_userfaultfd(0);
        assert_eq!(r.unwrap_err(), Error::NotImplemented);
    }

    #[test]
    fn cloexec_nonblock_reaches_stub() {
        let r = sys_userfaultfd(UffdFlags::O_CLOEXEC | UffdFlags::O_NONBLOCK);
        assert_eq!(r.unwrap_err(), Error::NotImplemented);
    }

    #[test]
    fn user_mode_only_reaches_stub() {
        let r = sys_userfaultfd(UffdFlags::UFFD_USER_MODE_ONLY);
        assert_eq!(r.unwrap_err(), Error::NotImplemented);
    }
}
