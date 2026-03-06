// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `ioperm(2)` and `iopl(2)` syscall dispatch layer.
//!
//! Control access to I/O ports on x86/x86_64.
//!
//! # Syscall signatures
//!
//! ```text
//! int ioperm(unsigned long from, unsigned long num, int turn_on);
//! int iopl(int level);
//! ```
//!
//! `ioperm` grants or revokes access to `num` I/O ports starting at `from`.
//! `iopl` sets the I/O privilege level of the calling thread (0–3).
//!
//! # Architecture note
//!
//! These syscalls are x86/x86_64-specific.  On other architectures they
//! return `ENOSYS`.
//!
//! # References
//!
//! - Linux: `arch/x86/kernel/ioport.c`
//! - `ioperm(2)`, `iopl(2)` man pages

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Highest I/O port address accessible via `ioperm` (exclusive).
pub const IO_BITMAP_BITS: u64 = 65536;

/// Maximum I/O privilege level for `iopl`.
pub const IOPL_MAX: i32 = 3;

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// Handle `ioperm(2)`.
///
/// Grants (`turn_on != 0`) or revokes (`turn_on == 0`) access to the ports
/// `[from, from+num)`.  The range must not overflow `IO_BITMAP_BITS`.
///
/// # Errors
///
/// - [`Error::InvalidArgument`] — `num == 0` or the range exceeds
///   `IO_BITMAP_BITS`.
/// - [`Error::PermissionDenied`] — requires `CAP_SYS_RAWIO`.
/// - [`Error::NotImplemented`] — stub.
pub fn sys_ioperm(from: u64, num: u64, turn_on: i32) -> Result<i64> {
    if num == 0 {
        return Err(Error::InvalidArgument);
    }
    if from.saturating_add(num) > IO_BITMAP_BITS {
        return Err(Error::InvalidArgument);
    }
    let _ = (from, num, turn_on);
    Err(Error::NotImplemented)
}

/// Handle `iopl(2)`.
///
/// Sets the I/O privilege level of the calling thread to `level`.  A `level`
/// of 0 removes all port access; 3 grants full port access.
///
/// # Errors
///
/// - [`Error::InvalidArgument`] — `level > IOPL_MAX`.
/// - [`Error::PermissionDenied`] — requires `CAP_SYS_RAWIO` to raise level.
/// - [`Error::NotImplemented`] — stub.
pub fn sys_iopl(level: i32) -> Result<i64> {
    if level < 0 || level > IOPL_MAX {
        return Err(Error::InvalidArgument);
    }
    let _ = level;
    Err(Error::NotImplemented)
}

/// Entry point for `ioperm` from the syscall dispatcher.
pub fn do_ioperm_call(from: u64, num: u64, turn_on: i32) -> Result<i64> {
    sys_ioperm(from, num, turn_on)
}

/// Entry point for `iopl` from the syscall dispatcher.
pub fn do_iopl_call(level: i32) -> Result<i64> {
    sys_iopl(level)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ioperm_zero_num_rejected() {
        assert_eq!(sys_ioperm(0, 0, 1).unwrap_err(), Error::InvalidArgument);
    }

    #[test]
    fn ioperm_out_of_range_rejected() {
        // from=65535, num=2 → 65537 > 65536.
        assert_eq!(sys_ioperm(65535, 2, 1).unwrap_err(), Error::InvalidArgument);
    }

    #[test]
    fn ioperm_valid_reaches_stub() {
        let r = sys_ioperm(0x300, 8, 1);
        assert_eq!(r.unwrap_err(), Error::NotImplemented);
    }

    #[test]
    fn iopl_invalid_level_rejected() {
        assert_eq!(sys_iopl(4).unwrap_err(), Error::InvalidArgument);
    }

    #[test]
    fn iopl_negative_level_rejected() {
        assert_eq!(sys_iopl(-1).unwrap_err(), Error::InvalidArgument);
    }

    #[test]
    fn iopl_valid_level_reaches_stub() {
        let r = sys_iopl(3);
        assert_eq!(r.unwrap_err(), Error::NotImplemented);
    }
}
