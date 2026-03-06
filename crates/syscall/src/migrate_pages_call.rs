// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `migrate_pages(2)` syscall dispatch layer.
//!
//! Moves all pages in `pid`'s address space that reside on nodes in
//! `old_nodes` to nodes in `new_nodes`.
//!
//! # Syscall signature
//!
//! ```text
//! long migrate_pages(pid_t pid, unsigned long maxnode,
//!                   const unsigned long *old_nodes,
//!                   const unsigned long *new_nodes);
//! ```
//!
//! # References
//!
//! - Linux: `mm/migrate.c` (`sys_migrate_pages`)
//! - `migrate_pages(2)` man page

use oncrix_lib::{Error, Result};

// Re-export node limit.
pub use crate::set_mempolicy_call::MAX_NUMNODES;

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

/// Handle `migrate_pages(2)`.
///
/// Migrates pages belonging to process `pid` from the nodes specified in the
/// `old_nodes` bitmap to those in `new_nodes`.  Both bitmaps must be non-null
/// when `maxnode > 0`.
///
/// A `pid` of 0 refers to the calling process.
///
/// # Errors
///
/// - [`Error::InvalidArgument`] — `maxnode > MAX_NUMNODES`, or `maxnode > 0`
///   with a null node pointer.
/// - [`Error::NotFound`] — `pid` does not exist.
/// - [`Error::PermissionDenied`] — no permission to migrate `pid`'s pages.
/// - [`Error::NotImplemented`] — stub.
pub fn sys_migrate_pages(
    pid: i32,
    maxnode: u64,
    old_nodes_ptr: u64,
    new_nodes_ptr: u64,
) -> Result<i64> {
    if maxnode > MAX_NUMNODES {
        return Err(Error::InvalidArgument);
    }
    if maxnode > 0 && (old_nodes_ptr == 0 || new_nodes_ptr == 0) {
        return Err(Error::InvalidArgument);
    }
    let _ = (pid, maxnode, old_nodes_ptr, new_nodes_ptr);
    Err(Error::NotImplemented)
}

/// Entry point called from the syscall dispatcher.
pub fn do_migrate_pages_call(
    pid: i32,
    maxnode: u64,
    old_nodes_ptr: u64,
    new_nodes_ptr: u64,
) -> Result<i64> {
    sys_migrate_pages(pid, maxnode, old_nodes_ptr, new_nodes_ptr)
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
            sys_migrate_pages(0, MAX_NUMNODES + 1, 0x1000, 0x2000).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn null_old_nodes_with_maxnode_rejected() {
        assert_eq!(
            sys_migrate_pages(0, 8, 0, 0x2000).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn null_new_nodes_with_maxnode_rejected() {
        assert_eq!(
            sys_migrate_pages(0, 8, 0x1000, 0).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn zero_maxnode_null_ptrs_valid() {
        // maxnode=0 means migrate all pages; node pointers are ignored.
        let r = sys_migrate_pages(0, 0, 0, 0);
        assert_eq!(r.unwrap_err(), Error::NotImplemented);
    }

    #[test]
    fn valid_call_reaches_stub() {
        let r = sys_migrate_pages(1, 4, 0x1000, 0x2000);
        assert_eq!(r.unwrap_err(), Error::NotImplemented);
    }
}
