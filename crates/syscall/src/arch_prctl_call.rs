// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `arch_prctl(2)` syscall dispatch layer.
//!
//! Sets or gets architecture-specific thread state.  On x86_64 this is
//! primarily used to set the `FS` and `GS` segment base registers, which
//! threading libraries use for thread-local storage (TLS).
//!
//! # Syscall signature
//!
//! ```text
//! int arch_prctl(int code, unsigned long addr);
//! ```
//!
//! # Supported codes (x86_64)
//!
//! | Constant            | Value  | Description |
//! |---------------------|--------|-------------|
//! | `ARCH_SET_GS`       | 0x1001 | Set the `GS` base address |
//! | `ARCH_SET_FS`       | 0x1002 | Set the `FS` base address |
//! | `ARCH_GET_FS`       | 0x1003 | Get the `FS` base address |
//! | `ARCH_GET_GS`       | 0x1004 | Get the `GS` base address |
//! | `ARCH_GET_CPUID`    | 0x1011 | Get the CPUID enable state |
//! | `ARCH_SET_CPUID`    | 0x1012 | Enable/disable CPUID |
//!
//! # References
//!
//! - Linux: `arch/x86/kernel/process_64.c` (`do_arch_prctl_64`)
//! - `arch_prctl(2)` man page

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Set the `GS` base register.
pub const ARCH_SET_GS: i32 = 0x1001;
/// Set the `FS` base register (used for TLS by glibc/musl).
pub const ARCH_SET_FS: i32 = 0x1002;
/// Get the current `FS` base register value.
pub const ARCH_GET_FS: i32 = 0x1003;
/// Get the current `GS` base register value.
pub const ARCH_GET_GS: i32 = 0x1004;
/// Get the CPUID enable/disable state.
pub const ARCH_GET_CPUID: i32 = 0x1011;
/// Enable or disable CPUID instruction for the thread.
pub const ARCH_SET_CPUID: i32 = 0x1012;

// ---------------------------------------------------------------------------
// Validation helpers
// ---------------------------------------------------------------------------

/// Returns `true` if `code` is a recognised `arch_prctl` code.
pub fn is_valid_code(code: i32) -> bool {
    matches!(
        code,
        ARCH_SET_GS | ARCH_SET_FS | ARCH_GET_FS | ARCH_GET_GS | ARCH_GET_CPUID | ARCH_SET_CPUID
    )
}

/// Returns `true` if `code` is a get operation (writes to `addr`).
pub fn is_get_code(code: i32) -> bool {
    matches!(code, ARCH_GET_FS | ARCH_GET_GS | ARCH_GET_CPUID)
}

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

/// Handle `arch_prctl(2)`.
///
/// For get operations `addr` must be a non-null pointer (the value is
/// written there).  For set operations `addr` is the value to set.
///
/// # Errors
///
/// - [`Error::InvalidArgument`] — unknown `code` or null `addr` for get ops.
/// - [`Error::NotImplemented`] — stub; CPU state not yet wired.
pub fn sys_arch_prctl(code: i32, addr: u64) -> Result<i64> {
    if !is_valid_code(code) {
        return Err(Error::InvalidArgument);
    }
    if is_get_code(code) && addr == 0 {
        return Err(Error::InvalidArgument);
    }
    let _ = (code, addr);
    Err(Error::NotImplemented)
}

/// Entry point called from the syscall dispatcher.
pub fn do_arch_prctl_call(code: i32, addr: u64) -> Result<i64> {
    sys_arch_prctl(code, addr)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_code_rejected() {
        assert_eq!(
            sys_arch_prctl(0x9999, 0).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn get_fs_null_addr_rejected() {
        assert_eq!(
            sys_arch_prctl(ARCH_GET_FS, 0).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn set_fs_zero_addr_ok() {
        // Setting FS to address 0 is valid.
        let r = sys_arch_prctl(ARCH_SET_FS, 0);
        assert_eq!(r.unwrap_err(), Error::NotImplemented);
    }

    #[test]
    fn get_fs_nonzero_reaches_stub() {
        let r = sys_arch_prctl(ARCH_GET_FS, 0x1000);
        assert_eq!(r.unwrap_err(), Error::NotImplemented);
    }
}
