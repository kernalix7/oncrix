// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `set_robust_list(2)` syscall handler — register a futex robust list.
//!
//! `set_robust_list` installs a pointer to a `struct robust_list_head` in the
//! calling thread's task struct.  When the thread dies, the kernel walks this
//! list and unlocks any futexes that were held by it, preventing other threads
//! from deadlocking on orphaned locks.
//!
//! This module provides the standalone handler for `set_robust_list`.  The
//! `get_robust_list` counterpart and shared types live in
//! [`get_robust_list_call`](super::get_robust_list_call).
//!
//! # Syscall signature
//!
//! ```text
//! long set_robust_list(struct robust_list_head *head, size_t len);
//! ```
//!
//! # POSIX Compliance
//!
//! This is a Linux-specific extension enabling POSIX robust mutex semantics
//! defined in POSIX.1-2008.
//!
//! # References
//!
//! - Linux: `kernel/futex/robust_list.c`
//! - `set_robust_list(2)` man page

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Expected size of `struct robust_list_head` on 64-bit platforms.
pub const ROBUST_LIST_HEAD_SIZE: usize = 24;

/// Maximum number of robust mutex entries the kernel will process on exit.
pub const ROBUST_LIST_LIMIT: usize = 2048;

// ---------------------------------------------------------------------------
// Data structures
// ---------------------------------------------------------------------------

/// Layout of `struct robust_list_head` (userspace ABI).
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct RobustListHead {
    /// Pointer to the first entry in the list.
    pub list: u64,
    /// Offset within the lock structure of the futex word.
    pub futex_offset: i64,
    /// Pointer to the lock that was being acquired or released.
    pub list_op_pending: u64,
}

impl RobustListHead {
    /// Create a new empty robust list header.
    pub const fn new() -> Self {
        Self {
            list: 0,
            futex_offset: 0,
            list_op_pending: 0,
        }
    }

    /// Return whether the list is empty (head points to itself, encoded as 0).
    pub fn is_empty(&self) -> bool {
        self.list == 0
    }
}

/// Validated request to install a robust list.
#[derive(Debug, Clone, Copy)]
pub struct SetRobustListRequest {
    /// User-space pointer to the robust list head structure.
    pub head: u64,
    /// Length of the structure; must equal `ROBUST_LIST_HEAD_SIZE`.
    pub len: usize,
}

impl SetRobustListRequest {
    /// Create a new request.
    pub const fn new(head: u64, len: usize) -> Self {
        Self { head, len }
    }

    /// Validate the request.
    pub fn validate(&self) -> Result<()> {
        if self.head == 0 {
            return Err(Error::InvalidArgument);
        }
        if self.len != ROBUST_LIST_HEAD_SIZE {
            return Err(Error::InvalidArgument);
        }
        Ok(())
    }
}

impl Default for SetRobustListRequest {
    fn default() -> Self {
        Self::new(0, 0)
    }
}

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

/// Handle the `set_robust_list(2)` syscall.
///
/// Installs the robust list pointer for the calling thread.
///
/// # Errors
///
/// - [`Error::InvalidArgument`] — null `head` or `len` != `ROBUST_LIST_HEAD_SIZE`.
/// - [`Error::NotImplemented`] — robust list subsystem not yet wired.
pub fn sys_set_robust_list(head: u64, len: usize) -> Result<i64> {
    let req = SetRobustListRequest::new(head, len);
    req.validate()?;
    do_set_robust_list(&req)
}

fn do_set_robust_list(req: &SetRobustListRequest) -> Result<i64> {
    let _ = req;
    // TODO: Install the head pointer into current->robust_list.  Also
    // verify that the pointer is in user space and not a kernel address.
    Err(Error::NotImplemented)
}

/// Entry point called from the syscall dispatcher.
pub fn do_set_robust_list_syscall(head: u64, len: usize) -> Result<i64> {
    sys_set_robust_list(head, len)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn null_head_rejected() {
        assert_eq!(
            sys_set_robust_list(0, ROBUST_LIST_HEAD_SIZE).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn wrong_len_rejected() {
        assert_eq!(
            sys_set_robust_list(0x1000, 16).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn too_large_len_rejected() {
        assert_eq!(
            sys_set_robust_list(0x1000, 48).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn valid_request_reaches_subsystem() {
        assert_eq!(
            sys_set_robust_list(0x1000, ROBUST_LIST_HEAD_SIZE).unwrap_err(),
            Error::NotImplemented
        );
    }

    #[test]
    fn robust_list_head_empty() {
        let h = RobustListHead::new();
        assert!(h.is_empty());
    }

    #[test]
    fn robust_list_head_non_empty() {
        let h = RobustListHead {
            list: 0x1000,
            futex_offset: -8,
            list_op_pending: 0,
        };
        assert!(!h.is_empty());
    }

    #[test]
    fn request_default_invalid() {
        let req = SetRobustListRequest::default();
        assert!(req.validate().is_err());
    }
}
