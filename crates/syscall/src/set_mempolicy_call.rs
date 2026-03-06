// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `set_mempolicy(2)` syscall dispatch layer.
//!
//! Sets the NUMA memory policy for the calling thread's address space or for
//! a specified range.
//!
//! # Syscall signature
//!
//! ```text
//! int set_mempolicy(int mode, const unsigned long *nodemask,
//!                  unsigned long maxnode);
//! ```
//!
//! # Policy modes
//!
//! | Constant | Value | Description |
//! |----------|-------|-------------|
//! | `MPOL_DEFAULT` | 0 | Default NUMA policy |
//! | `MPOL_PREFERRED` | 1 | Prefer a set of nodes |
//! | `MPOL_BIND` | 2 | Allocate only from listed nodes |
//! | `MPOL_INTERLEAVE` | 3 | Interleave across nodes |
//! | `MPOL_LOCAL` | 4 | Prefer local node (Linux 3.8+) |
//!
//! # References
//!
//! - Linux: `mm/mempolicy.c` (`sys_set_mempolicy`)
//! - `set_mempolicy(2)` man page

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Policy mode constants
// ---------------------------------------------------------------------------

/// Default NUMA policy (inherit from parent).
pub const MPOL_DEFAULT: i32 = 0;
/// Preferred node set.
pub const MPOL_PREFERRED: i32 = 1;
/// Bind allocations to the listed nodes.
pub const MPOL_BIND: i32 = 2;
/// Interleave allocations across the listed nodes.
pub const MPOL_INTERLEAVE: i32 = 3;
/// Prefer the local NUMA node.
pub const MPOL_LOCAL: i32 = 4;

/// Mode flag: apply relative node IDs.
pub const MPOL_F_RELATIVE_NODES: i32 = 1 << 14;
/// Mode flag: apply static node IDs.
pub const MPOL_F_STATIC_NODES: i32 = 1 << 15;
/// Mode flag: set policy on the NUMA node (not address space).
pub const MPOL_F_NUMA_BALANCING: i32 = 1 << 13;

/// Maximum NUMA node count (kernel internal limit).
pub const MAX_NUMNODES: u64 = 64;

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

/// Returns the base mode (without flag bits).
pub fn mpol_base(mode: i32) -> i32 {
    mode & 0x0FFF
}

/// Returns `true` if `mode` (base) is a recognised policy.
pub fn is_valid_mode(mode: i32) -> bool {
    matches!(
        mpol_base(mode),
        MPOL_DEFAULT | MPOL_PREFERRED | MPOL_BIND | MPOL_INTERLEAVE | MPOL_LOCAL
    )
}

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

/// Handle `set_mempolicy(2)`.
///
/// `nodemask_ptr` is a user-space pointer to an unsigned long nodemask bitmap.
/// When `mode` is `MPOL_DEFAULT`, `nodemask_ptr` and `maxnode` are ignored.
///
/// # Errors
///
/// - [`Error::InvalidArgument`] — unrecognised mode, `maxnode > MAX_NUMNODES`,
///   or non-null nodemask with incompatible mode.
/// - [`Error::NotImplemented`] — stub.
pub fn sys_set_mempolicy(mode: i32, nodemask_ptr: u64, maxnode: u64) -> Result<i64> {
    if !is_valid_mode(mode) {
        return Err(Error::InvalidArgument);
    }
    if maxnode > MAX_NUMNODES {
        return Err(Error::InvalidArgument);
    }
    let _ = (mode, nodemask_ptr, maxnode);
    Err(Error::NotImplemented)
}

/// Entry point called from the syscall dispatcher.
pub fn do_set_mempolicy_call(mode: i32, nodemask_ptr: u64, maxnode: u64) -> Result<i64> {
    sys_set_mempolicy(mode, nodemask_ptr, maxnode)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_mode_rejected() {
        assert_eq!(
            sys_set_mempolicy(99, 0, 0).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn excessive_maxnode_rejected() {
        assert_eq!(
            sys_set_mempolicy(MPOL_BIND, 0x1000, MAX_NUMNODES + 1).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn default_policy_reaches_stub() {
        let r = sys_set_mempolicy(MPOL_DEFAULT, 0, 0);
        assert_eq!(r.unwrap_err(), Error::NotImplemented);
    }

    #[test]
    fn interleave_with_nodemask_reaches_stub() {
        let r = sys_set_mempolicy(MPOL_INTERLEAVE, 0x1000, 8);
        assert_eq!(r.unwrap_err(), Error::NotImplemented);
    }
}
