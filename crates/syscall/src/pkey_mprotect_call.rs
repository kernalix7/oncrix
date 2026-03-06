// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `pkey_mprotect(2)` syscall dispatch layer.
//!
//! Changes the memory protection of a virtual address range and associates it
//! with a memory protection key (pkey).
//!
//! # Syscall signature
//!
//! ```text
//! int pkey_mprotect(void *addr, size_t len, int prot, int pkey);
//! ```
//!
//! # References
//!
//! - Linux: `mm/mprotect.c` (`sys_pkey_mprotect`)
//! - `pkey_mprotect(2)` man page

use oncrix_lib::{Error, Result};

// Re-export the protection key limit from the pkey module.
pub use crate::pkey::PKEY_MAX;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Page size used for alignment checks (x86_64).
const PAGE_SIZE: u64 = 4096;

/// PROT_NONE — page is not accessible.
pub const PROT_NONE: i32 = 0x0;
/// PROT_READ — page may be read.
pub const PROT_READ: i32 = 0x1;
/// PROT_WRITE — page may be written.
pub const PROT_WRITE: i32 = 0x2;
/// PROT_EXEC — page may be executed.
pub const PROT_EXEC: i32 = 0x4;

/// PROT_GROWSDOWN — applied to a growsdown mapping.
pub const PROT_GROWSDOWN: i32 = 0x0100_0000_u32 as i32;
/// PROT_GROWSUP — applied to a growsup mapping.
pub const PROT_GROWSUP: i32 = 0x0200_0000_u32 as i32;

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

/// Returns `true` if `prot` contains only recognised protection bits.
pub fn prot_valid(prot: i32) -> bool {
    let known = PROT_NONE | PROT_READ | PROT_WRITE | PROT_EXEC | PROT_GROWSDOWN | PROT_GROWSUP;
    prot & !known == 0
}

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

/// Handle `pkey_mprotect(2)`.
///
/// Changes the access protection of the range `[addr, addr+len)` to `prot`
/// and associates the protection key `pkey` with the range.
///
/// `pkey` must be -1 (remove key association) or a valid pkey in `[0, PKEY_MAX)`.
///
/// # Errors
///
/// - [`Error::InvalidArgument`] — `addr` not page-aligned, `len == 0`, unknown
///   `prot` bits, or `pkey` out of range.
/// - [`Error::NotFound`] — specified range not mapped.
/// - [`Error::PermissionDenied`] — PKEY not owned by caller.
/// - [`Error::NotImplemented`] — stub.
pub fn sys_pkey_mprotect(addr: u64, len: usize, prot: i32, pkey: i32) -> Result<i64> {
    if addr % PAGE_SIZE != 0 {
        return Err(Error::InvalidArgument);
    }
    if len == 0 {
        return Err(Error::InvalidArgument);
    }
    if !prot_valid(prot) {
        return Err(Error::InvalidArgument);
    }
    // pkey == -1 means remove the key association; otherwise must be in range.
    if pkey != -1 && (pkey < 0 || pkey as usize >= PKEY_MAX) {
        return Err(Error::InvalidArgument);
    }
    let _ = (addr, len, prot, pkey);
    Err(Error::NotImplemented)
}

/// Entry point called from the syscall dispatcher.
pub fn do_pkey_mprotect_call(addr: u64, len: usize, prot: i32, pkey: i32) -> Result<i64> {
    sys_pkey_mprotect(addr, len, prot, pkey)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn misaligned_addr_rejected() {
        assert_eq!(
            sys_pkey_mprotect(0x1001, 4096, PROT_READ, 0).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn zero_len_rejected() {
        assert_eq!(
            sys_pkey_mprotect(0x1000, 0, PROT_READ, 0).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn unknown_prot_rejected() {
        assert_eq!(
            sys_pkey_mprotect(0x1000, 4096, 0x0080, 0).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn pkey_out_of_range_rejected() {
        assert_eq!(
            sys_pkey_mprotect(0x1000, 4096, PROT_READ, PKEY_MAX as i32).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn pkey_minus_one_removes_association() {
        // pkey = -1 is valid (removes association).
        let r = sys_pkey_mprotect(0x1000, 4096, PROT_READ | PROT_WRITE, -1);
        assert_eq!(r.unwrap_err(), Error::NotImplemented);
    }

    #[test]
    fn valid_call_reaches_stub() {
        let r = sys_pkey_mprotect(0x2000, 8192, PROT_READ, 0);
        assert_eq!(r.unwrap_err(), Error::NotImplemented);
    }
}
