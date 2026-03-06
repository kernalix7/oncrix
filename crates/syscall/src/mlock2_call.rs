// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `mlock2(2)` / `munlock(2)` / `mlockall(2)` / `munlockall(2)` dispatch layer.
//!
//! `mlock2` locks pages in the range `[addr, addr+len)` into RAM.  Unlike
//! `mlock(2)`, it accepts a `flags` argument to request that pages be
//! populated before being locked (`MLOCK_ONFAULT` defers faulting).
//!
//! # Syscall signatures
//!
//! ```text
//! int mlock2(const void *addr, size_t len, unsigned int flags);
//! int munlock(const void *addr, size_t len);
//! int mlockall(int flags);
//! int munlockall(void);
//! ```
//!
//! # References
//!
//! - Linux: `mm/mlock.c` (`sys_mlock2`)
//! - `mlock(2)` man page

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Lock pages only when they are faulted in (do not pre-fault).
pub const MLOCK_ONFAULT: u32 = 0x01;

/// All valid `mlock2` flag bits.
const MLOCK2_FLAGS_VALID: u32 = MLOCK_ONFAULT;

/// Lock all current and future pages.
pub const MCL_CURRENT: i32 = 1;
/// Lock all future mappings.
pub const MCL_FUTURE: i32 = 2;
/// Combined with MCL_*: use MLOCK_ONFAULT semantics.
pub const MCL_ONFAULT: i32 = 4;

/// All valid `mlockall` flag bits.
const MLOCKALL_FLAGS_VALID: i32 = MCL_CURRENT | MCL_FUTURE | MCL_ONFAULT;

/// System page size for alignment checks.
const PAGE_SIZE: u64 = 4096;

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// Handle `mlock2(2)`.
///
/// # Errors
///
/// - [`Error::InvalidArgument`] — `addr` is not page-aligned, `len` is 0,
///   or unknown flags.
/// - [`Error::PermissionDenied`] — caller lacks `CAP_IPC_LOCK` and would
///   exceed the `RLIMIT_MEMLOCK` limit.
/// - [`Error::NotImplemented`] — stub.
pub fn sys_mlock2(addr: u64, len: usize, flags: u32) -> Result<i64> {
    if addr % PAGE_SIZE != 0 {
        return Err(Error::InvalidArgument);
    }
    if len == 0 {
        return Err(Error::InvalidArgument);
    }
    if flags & !MLOCK2_FLAGS_VALID != 0 {
        return Err(Error::InvalidArgument);
    }
    let _ = (addr, len, flags);
    Err(Error::NotImplemented)
}

/// Handle `munlock(2)`.
///
/// # Errors
///
/// - [`Error::InvalidArgument`] — `addr` is not page-aligned or `len` is 0.
/// - [`Error::NotImplemented`] — stub.
pub fn sys_munlock(addr: u64, len: usize) -> Result<i64> {
    if addr % PAGE_SIZE != 0 {
        return Err(Error::InvalidArgument);
    }
    if len == 0 {
        return Err(Error::InvalidArgument);
    }
    let _ = (addr, len);
    Err(Error::NotImplemented)
}

/// Handle `mlockall(2)`.
///
/// # Errors
///
/// - [`Error::InvalidArgument`] — unknown flags.
/// - [`Error::NotImplemented`] — stub.
pub fn sys_mlockall(flags: i32) -> Result<i64> {
    if flags & !MLOCKALL_FLAGS_VALID != 0 {
        return Err(Error::InvalidArgument);
    }
    let _ = flags;
    Err(Error::NotImplemented)
}

/// Handle `munlockall(2)`.
pub fn sys_munlockall() -> Result<i64> {
    Err(Error::NotImplemented)
}

/// Entry point for `mlock2` from the syscall dispatcher.
pub fn do_mlock2_call(addr: u64, len: usize, flags: u32) -> Result<i64> {
    sys_mlock2(addr, len, flags)
}

/// Entry point for `munlock` from the syscall dispatcher.
pub fn do_munlock_call(addr: u64, len: usize) -> Result<i64> {
    sys_munlock(addr, len)
}

/// Entry point for `mlockall` from the syscall dispatcher.
pub fn do_mlockall_call(flags: i32) -> Result<i64> {
    sys_mlockall(flags)
}

/// Entry point for `munlockall` from the syscall dispatcher.
pub fn do_munlockall_call() -> Result<i64> {
    sys_munlockall()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unaligned_addr_rejected() {
        assert_eq!(
            sys_mlock2(0x1001, 4096, 0).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn zero_len_rejected() {
        assert_eq!(
            sys_mlock2(0x1000, 0, 0).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn unknown_mlock2_flags_rejected() {
        assert_eq!(
            sys_mlock2(0x1000, 4096, 0x80).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn onfault_flag_ok() {
        let r = sys_mlock2(0x1000, 4096, MLOCK_ONFAULT);
        assert_eq!(r.unwrap_err(), Error::NotImplemented);
    }

    #[test]
    fn mlockall_unknown_flags_rejected() {
        assert_eq!(sys_mlockall(0xFF).unwrap_err(), Error::InvalidArgument);
    }

    #[test]
    fn munlockall_ok() {
        let r = sys_munlockall();
        assert_eq!(r.unwrap_err(), Error::NotImplemented);
    }
}
