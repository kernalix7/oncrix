// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `get_robust_list(2)` / `set_robust_list(2)` — futex robust list management.
//!
//! These syscalls allow a thread to register a list of futexes that the kernel
//! should automatically unlock if the thread exits without releasing them.
//! This prevents other threads from deadlocking on unrecoverable futexes.
//!
//! # Syscall signatures
//!
//! ```text
//! long get_robust_list(int pid, struct robust_list_head **head_ptr,
//!                      size_t *len_ptr);
//! long set_robust_list(struct robust_list_head *head, size_t len);
//! ```
//!
//! # POSIX Compliance
//!
//! The robust list is a Linux extension to POSIX robust mutexes defined in
//! POSIX.1-2008.  It enables POSIX robust mutex behaviour in user space.
//!
//! # References
//!
//! - Linux: `kernel/futex/robust_list.c`
//! - `get_robust_list(2)`, `set_robust_list(2)` man pages

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Expected length of `struct robust_list_head` on 64-bit platforms.
pub const ROBUST_LIST_HEAD_SIZE: usize = 24;

// ---------------------------------------------------------------------------
// Data structures
// ---------------------------------------------------------------------------

/// Minimal representation of the robust list header.
///
/// The full structure is defined in `<linux/futex.h>`.  We use only the
/// pointer-sized fields needed for validation.
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct RobustListHead {
    /// Pointer to the first futex in the robust list (NULL = empty).
    pub list_ptr: u64,
    /// Offset of the futex lock field within the enclosing structure.
    pub futex_offset: i64,
    /// Pointer to a thread-private futex used during list processing.
    pub list_op_pending: u64,
}

impl RobustListHead {
    /// Create a new empty robust list header.
    pub const fn new() -> Self {
        Self {
            list_ptr: 0,
            futex_offset: 0,
            list_op_pending: 0,
        }
    }
}

/// Parameters for `get_robust_list`.
#[derive(Debug, Clone, Copy)]
pub struct GetRobustListRequest {
    /// Target thread PID (0 = calling thread).
    pub pid: i32,
    /// User-space pointer-to-pointer where head address is written.
    pub head_ptr: u64,
    /// User-space pointer where the list length is written.
    pub len_ptr: u64,
}

impl GetRobustListRequest {
    /// Create a new request.
    pub const fn new(pid: i32, head_ptr: u64, len_ptr: u64) -> Self {
        Self {
            pid,
            head_ptr,
            len_ptr,
        }
    }

    /// Validate the request fields.
    pub fn validate(&self) -> Result<()> {
        if self.pid < 0 {
            return Err(Error::InvalidArgument);
        }
        if self.head_ptr == 0 || self.len_ptr == 0 {
            return Err(Error::InvalidArgument);
        }
        Ok(())
    }
}

impl Default for GetRobustListRequest {
    fn default() -> Self {
        Self::new(0, 0, 0)
    }
}

/// Parameters for `set_robust_list`.
#[derive(Debug, Clone, Copy)]
pub struct SetRobustListRequest {
    /// User-space pointer to the robust list head structure.
    pub head: u64,
    /// Length of the head structure (must match `ROBUST_LIST_HEAD_SIZE`).
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
// Handlers
// ---------------------------------------------------------------------------

/// Handle `get_robust_list(2)`.
///
/// # Errors
///
/// - [`Error::InvalidArgument`] — negative pid or null output pointers.
/// - [`Error::NotFound`] — pid does not match any thread.
/// - [`Error::NotImplemented`] — futex robust list not yet wired.
pub fn sys_get_robust_list(pid: i32, head_ptr: u64, len_ptr: u64) -> Result<i64> {
    let req = GetRobustListRequest::new(pid, head_ptr, len_ptr);
    req.validate()?;
    do_get_robust_list(&req)
}

fn do_get_robust_list(req: &GetRobustListRequest) -> Result<i64> {
    let _ = req;
    // TODO: Look up the target thread, read its robust_list pointer, and
    // write it (and the list length) to the user-space output pointers.
    Err(Error::NotImplemented)
}

/// Handle `set_robust_list(2)`.
///
/// # Errors
///
/// - [`Error::InvalidArgument`] — null head or wrong length.
/// - [`Error::NotImplemented`] — futex robust list not yet wired.
pub fn sys_set_robust_list(head: u64, len: usize) -> Result<i64> {
    let req = SetRobustListRequest::new(head, len);
    req.validate()?;
    do_set_robust_list(&req)
}

fn do_set_robust_list(req: &SetRobustListRequest) -> Result<i64> {
    let _ = req;
    // TODO: Install the robust list head pointer into the current thread's
    // task_struct.
    Err(Error::NotImplemented)
}

/// Entry point for `get_robust_list` from the syscall dispatcher.
pub fn do_get_robust_list_syscall(pid: i32, head_ptr: u64, len_ptr: u64) -> Result<i64> {
    sys_get_robust_list(pid, head_ptr, len_ptr)
}

/// Entry point for `set_robust_list` from the syscall dispatcher.
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
    fn get_negative_pid_rejected() {
        assert_eq!(
            sys_get_robust_list(-1, 1, 1).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn get_null_head_ptr_rejected() {
        assert_eq!(
            sys_get_robust_list(0, 0, 1).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn get_null_len_ptr_rejected() {
        assert_eq!(
            sys_get_robust_list(0, 1, 0).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn set_null_head_rejected() {
        assert_eq!(
            sys_set_robust_list(0, ROBUST_LIST_HEAD_SIZE).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn set_wrong_len_rejected() {
        assert_eq!(
            sys_set_robust_list(1, 8).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn set_valid_reaches_subsystem() {
        assert_eq!(
            sys_set_robust_list(0x1000, ROBUST_LIST_HEAD_SIZE).unwrap_err(),
            Error::NotImplemented
        );
    }

    #[test]
    fn robust_list_head_default() {
        let h = RobustListHead::default();
        assert_eq!(h.list_ptr, 0);
    }
}
