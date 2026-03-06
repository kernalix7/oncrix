// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `set_tid_address(2)` syscall dispatch layer.
//!
//! Sets the clear-child-tid address for the calling thread.  When the
//! thread exits the kernel writes 0 to `tidptr` and wakes any futex waiters
//! at that address.  This is used by the C library (glibc/musl) during
//! `pthread_create` / thread exit to implement `CLONE_CHILD_CLEARTID`.
//!
//! # Syscall signature
//!
//! ```text
//! pid_t set_tid_address(int *tidptr);
//! ```
//!
//! Returns the caller's thread ID (TID).  `tidptr` may be null to clear the
//! previously registered address.
//!
//! # POSIX / Linux notes
//!
//! This is a Linux-specific interface used internally by threading libraries.
//! It is not part of POSIX.
//!
//! # References
//!
//! - Linux: `kernel/fork.c` (`sys_set_tid_address`)
//! - `set_tid_address(2)` man page

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

/// Handle `set_tid_address(2)`.
///
/// Sets the calling thread's clear-child-tid pointer to `tidptr` (which may
/// be null to disable the feature).  Returns the caller's TID.
///
/// # Errors
///
/// - [`Error::NotImplemented`] — stub; TID lookup is not yet wired.
pub fn sys_set_tid_address(tidptr: u64) -> Result<i64> {
    // Any pointer value (including null) is accepted.
    let _ = tidptr;
    Err(Error::NotImplemented)
}

/// Entry point called from the syscall dispatcher.
pub fn do_set_tid_address_call(tidptr: u64) -> Result<i64> {
    sys_set_tid_address(tidptr)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn null_tidptr_ok() {
        // Null is a valid value — it clears the address.
        let r = sys_set_tid_address(0);
        assert_eq!(r.unwrap_err(), Error::NotImplemented);
    }

    #[test]
    fn nonzero_tidptr_ok() {
        let r = sys_set_tid_address(0xDEAD_BEEF_u64);
        assert_eq!(r.unwrap_err(), Error::NotImplemented);
    }
}
