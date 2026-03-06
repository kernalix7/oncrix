// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `memfd_secret(2)` syscall dispatch layer.
//!
//! Creates a file descriptor for a new "secretmem" region — memory that is
//! inaccessible to the kernel itself (hardware-enforced on supporting CPUs)
//! and excluded from core dumps and `/proc/<pid>/mem`.
//!
//! # Syscall signature
//!
//! ```text
//! int memfd_secret(unsigned int flags);
//! ```
//!
//! Currently the only defined flag is `FD_CLOEXEC` (value 1).
//!
//! # References
//!
//! - Linux: `mm/secretmem.c` (`sys_memfd_secret`)
//! - `memfd_secret(2)` man page

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Set `FD_CLOEXEC` on the returned file descriptor.
pub const FD_CLOEXEC: u32 = 1;

/// All valid flag bits.
const FLAGS_VALID: u32 = FD_CLOEXEC;

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

/// Handle `memfd_secret(2)`.
///
/// # Errors
///
/// - [`Error::InvalidArgument`] — unknown flags.
/// - [`Error::NotImplemented`] — secretmem is not yet wired to the MM layer;
///   also returned when the CPU does not support the feature.
pub fn sys_memfd_secret(flags: u32) -> Result<i64> {
    if flags & !FLAGS_VALID != 0 {
        return Err(Error::InvalidArgument);
    }
    let _ = flags;
    Err(Error::NotImplemented)
}

/// Entry point called from the syscall dispatcher.
pub fn do_memfd_secret_call(flags: u32) -> Result<i64> {
    sys_memfd_secret(flags)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_flags_rejected() {
        assert_eq!(sys_memfd_secret(0x80).unwrap_err(), Error::InvalidArgument);
    }

    #[test]
    fn no_flags_reaches_stub() {
        let r = sys_memfd_secret(0);
        assert_eq!(r.unwrap_err(), Error::NotImplemented);
    }

    #[test]
    fn cloexec_flag_reaches_stub() {
        let r = sys_memfd_secret(FD_CLOEXEC);
        assert_eq!(r.unwrap_err(), Error::NotImplemented);
    }
}
