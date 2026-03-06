// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `mbind(2)` syscall dispatch layer.
//!
//! Sets the NUMA memory policy for a virtual memory range.
//!
//! # Syscall signature
//!
//! ```text
//! int mbind(void *addr, unsigned long len, int mode,
//!           const unsigned long *nodemask, unsigned long maxnode,
//!           unsigned int flags);
//! ```
//!
//! # References
//!
//! - Linux: `mm/mempolicy.c` (`sys_mbind`)
//! - `mbind(2)` man page

use oncrix_lib::{Error, Result};

// Re-export shared constants.
pub use crate::set_mempolicy_call::{
    MAX_NUMNODES, MPOL_BIND, MPOL_DEFAULT, MPOL_INTERLEAVE, MPOL_LOCAL, MPOL_PREFERRED,
    is_valid_mode,
};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Page size for alignment checks.
const PAGE_SIZE: u64 = 4096;

/// Move pages currently allocated on other nodes (flags).
pub const MPOL_MF_STRICT: u32 = 1 << 0;
/// Move pages rather than copying.
pub const MPOL_MF_MOVE: u32 = 1 << 1;
/// Move all pages in the range (including those shared with other processes).
pub const MPOL_MF_MOVE_ALL: u32 = 1 << 2;

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

/// Handle `mbind(2)`.
///
/// Applies the memory policy `mode` to the virtual address range
/// `[addr, addr+len)`.  `nodemask_ptr` is a user-space pointer to the node
/// bitmap; `maxnode` is the number of valid bits.
///
/// # Errors
///
/// - [`Error::InvalidArgument`] — `addr` not page-aligned, `len == 0`,
///   unknown mode, `maxnode > MAX_NUMNODES`, or unknown `flags` bits.
/// - [`Error::NotImplemented`] — stub.
pub fn sys_mbind(
    addr: u64,
    len: u64,
    mode: i32,
    nodemask_ptr: u64,
    maxnode: u64,
    flags: u32,
) -> Result<i64> {
    if addr % PAGE_SIZE != 0 {
        return Err(Error::InvalidArgument);
    }
    if len == 0 {
        return Err(Error::InvalidArgument);
    }
    if !is_valid_mode(mode) {
        return Err(Error::InvalidArgument);
    }
    if maxnode > MAX_NUMNODES {
        return Err(Error::InvalidArgument);
    }
    let known_flags = MPOL_MF_STRICT | MPOL_MF_MOVE | MPOL_MF_MOVE_ALL;
    if flags & !known_flags != 0 {
        return Err(Error::InvalidArgument);
    }
    let _ = (addr, len, mode, nodemask_ptr, maxnode, flags);
    Err(Error::NotImplemented)
}

/// Entry point called from the syscall dispatcher.
pub fn do_mbind_call(
    addr: u64,
    len: u64,
    mode: i32,
    nodemask_ptr: u64,
    maxnode: u64,
    flags: u32,
) -> Result<i64> {
    sys_mbind(addr, len, mode, nodemask_ptr, maxnode, flags)
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
            sys_mbind(0x1001, 4096, MPOL_DEFAULT, 0, 0, 0).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn zero_len_rejected() {
        assert_eq!(
            sys_mbind(0x1000, 0, MPOL_DEFAULT, 0, 0, 0).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn unknown_mode_rejected() {
        assert_eq!(
            sys_mbind(0x1000, 4096, 99, 0, 0, 0).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn excessive_maxnode_rejected() {
        assert_eq!(
            sys_mbind(0x1000, 4096, MPOL_BIND, 0x2000, MAX_NUMNODES + 1, 0).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn unknown_flags_rejected() {
        assert_eq!(
            sys_mbind(0x1000, 4096, MPOL_DEFAULT, 0, 0, 0xFF).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn valid_mbind_reaches_stub() {
        let r = sys_mbind(0x1000, 4096, MPOL_INTERLEAVE, 0x2000, 8, MPOL_MF_MOVE);
        assert_eq!(r.unwrap_err(), Error::NotImplemented);
    }
}
