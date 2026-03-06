// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `process_madvise(2)` syscall dispatch layer.
//!
//! Advises the kernel about a set of virtual-memory ranges belonging to
//! *another* process (identified by `pidfd`).  The advice semantics are
//! the same as `madvise(2)` applied to those ranges.
//!
//! # Syscall signature
//!
//! ```text
//! ssize_t process_madvise(int pidfd, const struct iovec *iovec,
//!                         size_t vlen, int advice, unsigned int flags);
//! ```
//!
//! `flags` is currently unused and must be zero.
//!
//! # Advice values (shared with `madvise`)
//!
//! | Constant        | Value | Description |
//! |-----------------|-------|-------------|
//! | `MADV_DONTNEED` | 4     | Release pages (re-faulted on next access) |
//! | `MADV_FREE`     | 8     | Pages may be reused under memory pressure |
//! | `MADV_COLD`     | 20    | Deprioritise pages for reclaim |
//! | `MADV_PAGEOUT`  | 21    | Eagerly reclaim pages |
//!
//! # References
//!
//! - Linux: `mm/madvise.c` (`process_madvise`)
//! - `process_madvise(2)` man page

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum number of `iovec` entries accepted in a single call.
pub const PROCESS_MADVISE_MAX_VEC: usize = 512;

/// Release the given pages; they will be zeroed on next access.
pub const MADV_DONTNEED: i32 = 4;
/// Pages may be reused without zeroing when under memory pressure.
pub const MADV_FREE: i32 = 8;
/// Make pages cold (low priority for reclaim).
pub const MADV_COLD: i32 = 20;
/// Proactively reclaim pages.
pub const MADV_PAGEOUT: i32 = 21;

/// Maximum valid file descriptor number.
const FD_MAX: i32 = 1_048_576;

// ---------------------------------------------------------------------------
// Validation helpers
// ---------------------------------------------------------------------------

/// Returns `true` if `advice` is one of the process_madvise-supported values.
pub fn is_valid_advice(advice: i32) -> bool {
    matches!(advice, MADV_DONTNEED | MADV_FREE | MADV_COLD | MADV_PAGEOUT)
}

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

/// Handle `process_madvise(2)`.
///
/// # Errors
///
/// - [`Error::InvalidArgument`] — unknown advice, non-zero `flags`, null
///   `iovec_ptr` with non-zero `vlen`, or `vlen` exceeds the maximum.
/// - [`Error::NotFound`] — `pidfd` does not refer to a live process.
/// - [`Error::PermissionDenied`] — insufficient privilege to advise the
///   target process.
/// - [`Error::NotImplemented`] — stub.
pub fn sys_process_madvise(
    pidfd: i32,
    iovec_ptr: u64,
    vlen: usize,
    advice: i32,
    flags: u32,
) -> Result<i64> {
    if pidfd < 0 || pidfd > FD_MAX {
        return Err(Error::InvalidArgument);
    }
    if flags != 0 {
        return Err(Error::InvalidArgument);
    }
    if vlen > PROCESS_MADVISE_MAX_VEC {
        return Err(Error::InvalidArgument);
    }
    if vlen > 0 && iovec_ptr == 0 {
        return Err(Error::InvalidArgument);
    }
    if !is_valid_advice(advice) {
        return Err(Error::InvalidArgument);
    }
    let _ = (pidfd, iovec_ptr, vlen, advice, flags);
    Err(Error::NotImplemented)
}

/// Entry point called from the syscall dispatcher.
pub fn do_process_madvise_call(
    pidfd: i32,
    iovec_ptr: u64,
    vlen: usize,
    advice: i32,
    flags: u32,
) -> Result<i64> {
    sys_process_madvise(pidfd, iovec_ptr, vlen, advice, flags)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nonzero_flags_rejected() {
        assert_eq!(
            sys_process_madvise(3, 0x1000, 1, MADV_COLD, 1).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn unknown_advice_rejected() {
        assert_eq!(
            sys_process_madvise(3, 0x1000, 1, 99, 0).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn null_iovec_with_nonzero_vlen_rejected() {
        assert_eq!(
            sys_process_madvise(3, 0, 1, MADV_DONTNEED, 0).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn zero_vlen_with_null_iovec_ok() {
        let r = sys_process_madvise(3, 0, 0, MADV_COLD, 0);
        assert_eq!(r.unwrap_err(), Error::NotImplemented);
    }

    #[test]
    fn valid_call_reaches_stub() {
        let r = sys_process_madvise(3, 0x1000, 4, MADV_PAGEOUT, 0);
        assert_eq!(r.unwrap_err(), Error::NotImplemented);
    }
}
