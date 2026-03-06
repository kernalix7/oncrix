// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `move_pages(2)` syscall dispatch layer.
//!
//! Moves individual pages of a process to specified NUMA nodes, or queries
//! which node each page currently resides on.
//!
//! # Syscall signature
//!
//! ```text
//! long move_pages(pid_t pid, unsigned long count,
//!                 void **pages, const int *nodes,
//!                 int *status, int flags);
//! ```
//!
//! # References
//!
//! - Linux: `mm/migrate.c` (`sys_move_pages`)
//! - `move_pages(2)` man page

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum number of pages per `move_pages` call (Linux internal).
pub const MOVE_PAGES_MAX_COUNT: u64 = 1024 * 1024; // 1 M pages

/// Flag: move all pages of other threads in the thread group too.
pub const MPOL_MF_MOVE: i32 = 1 << 1;
/// Flag: move pages shared with other processes (requires `CAP_SYS_NICE`).
pub const MPOL_MF_MOVE_ALL: i32 = 1 << 2;

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

/// Handle `move_pages(2)`.
///
/// `pages_ptr` is a user-space array of `count` virtual addresses.
/// `nodes_ptr` is a user-space array of `count` target NUMA node numbers;
/// may be null to query current placement without moving.
/// `status_ptr` is a user-space array of `count` `int` slots for per-page
/// results; must be non-null.
///
/// A `pid` of 0 refers to the calling process.
///
/// # Errors
///
/// - [`Error::InvalidArgument`] — `count == 0`, `count > MOVE_PAGES_MAX_COUNT`,
///   null `pages_ptr`, null `status_ptr`, or unknown flag bits.
/// - [`Error::NotImplemented`] — stub.
pub fn sys_move_pages(
    pid: i32,
    count: u64,
    pages_ptr: u64,
    nodes_ptr: u64,
    status_ptr: u64,
    flags: i32,
) -> Result<i64> {
    if count == 0 || count > MOVE_PAGES_MAX_COUNT {
        return Err(Error::InvalidArgument);
    }
    if pages_ptr == 0 {
        return Err(Error::InvalidArgument);
    }
    if status_ptr == 0 {
        return Err(Error::InvalidArgument);
    }
    let known_flags = MPOL_MF_MOVE | MPOL_MF_MOVE_ALL;
    if flags & !known_flags != 0 {
        return Err(Error::InvalidArgument);
    }
    let _ = (pid, count, pages_ptr, nodes_ptr, status_ptr, flags);
    Err(Error::NotImplemented)
}

/// Entry point called from the syscall dispatcher.
pub fn do_move_pages_call(
    pid: i32,
    count: u64,
    pages_ptr: u64,
    nodes_ptr: u64,
    status_ptr: u64,
    flags: i32,
) -> Result<i64> {
    sys_move_pages(pid, count, pages_ptr, nodes_ptr, status_ptr, flags)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_count_rejected() {
        assert_eq!(
            sys_move_pages(0, 0, 0x1000, 0, 0x2000, 0).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn excessive_count_rejected() {
        assert_eq!(
            sys_move_pages(0, MOVE_PAGES_MAX_COUNT + 1, 0x1000, 0, 0x2000, 0).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn null_pages_ptr_rejected() {
        assert_eq!(
            sys_move_pages(0, 4, 0, 0x1000, 0x2000, 0).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn null_status_ptr_rejected() {
        assert_eq!(
            sys_move_pages(0, 4, 0x1000, 0x2000, 0, 0).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn unknown_flags_rejected() {
        assert_eq!(
            sys_move_pages(0, 4, 0x1000, 0x2000, 0x3000, 0xFF).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn query_only_null_nodes_valid() {
        // nodes_ptr == 0 means query placement only.
        let r = sys_move_pages(0, 4, 0x1000, 0, 0x2000, 0);
        assert_eq!(r.unwrap_err(), Error::NotImplemented);
    }
}
