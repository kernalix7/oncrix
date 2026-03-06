// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `get_mempolicy(2)` syscall dispatch layer.
//!
//! Retrieves the NUMA memory policy for the calling thread or a given
//! virtual address.
//!
//! # Syscall signature
//!
//! ```text
//! int get_mempolicy(int *mode, unsigned long *nodemask,
//!                  unsigned long maxnode, void *addr,
//!                  unsigned long flags);
//! ```
//!
//! # References
//!
//! - Linux: `mm/mempolicy.c` (`sys_get_mempolicy`)
//! - `get_mempolicy(2)` man page

use oncrix_lib::{Error, Result};

// Re-use node limit from the set_mempolicy module.
pub use crate::set_mempolicy_call::MAX_NUMNODES;

// ---------------------------------------------------------------------------
// Query flags
// ---------------------------------------------------------------------------

/// Return the policy for the virtual address `addr`.
pub const MPOL_F_ADDR: u64 = 1 << 1;
/// Return the next node to be used for interleaving.
pub const MPOL_F_NODE: u64 = 1 << 0;
/// Return per-VMA policy, not per-thread (Linux 4.5+).
pub const MPOL_F_MEMS_ALLOWED: u64 = 1 << 2;

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

/// Handle `get_mempolicy(2)`.
///
/// Writes the effective memory policy mode into `mode_ptr` (if non-null) and
/// up to `maxnode` bits of the nodemask into `nodemask_ptr` (if non-null).
///
/// `addr` is used only when `MPOL_F_ADDR` is set in `flags`.
///
/// # Errors
///
/// - [`Error::InvalidArgument`] — `maxnode > MAX_NUMNODES` or unknown flag bits.
/// - [`Error::NotImplemented`] — stub.
pub fn sys_get_mempolicy(
    mode_ptr: u64,
    nodemask_ptr: u64,
    maxnode: u64,
    addr: u64,
    flags: u64,
) -> Result<i64> {
    if maxnode > MAX_NUMNODES {
        return Err(Error::InvalidArgument);
    }
    let known_flags = MPOL_F_ADDR | MPOL_F_NODE | MPOL_F_MEMS_ALLOWED;
    if flags & !known_flags != 0 {
        return Err(Error::InvalidArgument);
    }
    // MPOL_F_ADDR requires an actual addr.
    if flags & MPOL_F_ADDR != 0 && addr == 0 {
        return Err(Error::InvalidArgument);
    }
    let _ = (mode_ptr, nodemask_ptr, maxnode, addr, flags);
    Err(Error::NotImplemented)
}

/// Entry point called from the syscall dispatcher.
pub fn do_get_mempolicy_call(
    mode_ptr: u64,
    nodemask_ptr: u64,
    maxnode: u64,
    addr: u64,
    flags: u64,
) -> Result<i64> {
    sys_get_mempolicy(mode_ptr, nodemask_ptr, maxnode, addr, flags)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn excessive_maxnode_rejected() {
        assert_eq!(
            sys_get_mempolicy(0, 0, MAX_NUMNODES + 1, 0, 0).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn unknown_flags_rejected() {
        assert_eq!(
            sys_get_mempolicy(0x1000, 0x2000, 8, 0, 0xFF00).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn f_addr_with_null_addr_rejected() {
        assert_eq!(
            sys_get_mempolicy(0x1000, 0x2000, 8, 0, MPOL_F_ADDR).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn basic_query_reaches_stub() {
        let r = sys_get_mempolicy(0x1000, 0x2000, 8, 0, 0);
        assert_eq!(r.unwrap_err(), Error::NotImplemented);
    }
}
