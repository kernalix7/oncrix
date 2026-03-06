// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `clone3(2)` syscall dispatch layer.
//!
//! An extended version of `clone(2)` that passes all parameters via a
//! `struct clone_args` rather than packed register arguments.  This allows
//! new fields to be added without breaking the ABI.
//!
//! # Syscall signature
//!
//! ```text
//! long clone3(struct clone_args *cl_args, size_t size);
//! ```
//!
//! # `clone_args` (subset of fields)
//!
//! | Field        | Type   | Description |
//! |--------------|--------|-------------|
//! | `flags`      | u64    | Clone flags (e.g. `CLONE_THREAD`, `CLONE_VM`) |
//! | `pidfd`      | u64    | Pointer to store the pidfd (if `CLONE_PIDFD`) |
//! | `child_tid`  | u64    | Pointer for `CLONE_CHILD_SETTID` |
//! | `parent_tid` | u64    | Pointer for `CLONE_PARENT_SETTID` |
//! | `exit_signal`| u64    | Signal to parent on child exit (0 = none) |
//! | `stack`      | u64    | Child stack base |
//! | `stack_size` | u64    | Child stack size |
//! | `tls`        | u64    | TLS descriptor |
//! | `set_tid`    | u64    | Pointer to `pid_t[]` for PID namespace setup |
//! | `set_tid_size`| u64   | Number of entries in `set_tid` |
//! | `cgroup`     | u64    | Cgroup fd for the new task |
//!
//! # References
//!
//! - Linux: `kernel/fork.c` (`sys_clone3`)
//! - `clone3(2)` man page
//! - `include/uapi/linux/sched.h`

use oncrix_lib::{Error, Result};

// Re-export clone flag constants from the detailed module.
pub use crate::clone3::{
    CLONE_CHILD_CLEARTID, CLONE_CHILD_SETTID, CLONE_FILES, CLONE_FS, CLONE_NEWCGROUP, CLONE_NEWIPC,
    CLONE_NEWNET, CLONE_NEWNS, CLONE_NEWPID, CLONE_NEWUSER, CLONE_NEWUTS, CLONE_PARENT,
    CLONE_PARENT_SETTID, CLONE_PIDFD, CLONE_SETTLS, CLONE_SIGHAND, CLONE_SYSVSEM, CLONE_THREAD,
    CLONE_VFORK, CLONE_VM,
};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Minimum `size` for `struct clone_args` (ABI v0 — 64 bytes).
pub const CLONE_ARGS_SIZE_VER0: usize = 64;
/// Extended size including `set_tid` / `set_tid_size` (ABI v1 — 80 bytes).
pub const CLONE_ARGS_SIZE_VER1: usize = 80;
/// Extended size including `cgroup` (ABI v2 — 88 bytes).
pub const CLONE_ARGS_SIZE_VER2: usize = 88;

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

/// Handle `clone3(2)`.
///
/// # Errors
///
/// - [`Error::InvalidArgument`] — null `cl_args`, `size` below the minimum,
///   or `size` is not a multiple of 8 (alignment requirement).
/// - [`Error::OutOfMemory`] — insufficient resources to create the child.
/// - [`Error::NotImplemented`] — stub.
pub fn sys_clone3(cl_args_ptr: u64, size: usize) -> Result<i64> {
    if cl_args_ptr == 0 {
        return Err(Error::InvalidArgument);
    }
    if size < CLONE_ARGS_SIZE_VER0 {
        return Err(Error::InvalidArgument);
    }
    // struct clone_args must be naturally aligned (8 bytes).
    if size % 8 != 0 {
        return Err(Error::InvalidArgument);
    }
    let _ = (cl_args_ptr, size);
    Err(Error::NotImplemented)
}

/// Entry point called from the syscall dispatcher.
pub fn do_clone3_call(cl_args_ptr: u64, size: usize) -> Result<i64> {
    sys_clone3(cl_args_ptr, size)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn null_args_rejected() {
        assert_eq!(
            sys_clone3(0, CLONE_ARGS_SIZE_VER0).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn size_too_small_rejected() {
        assert_eq!(
            sys_clone3(0x1000, CLONE_ARGS_SIZE_VER0 - 8).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn unaligned_size_rejected() {
        assert_eq!(
            sys_clone3(0x1000, CLONE_ARGS_SIZE_VER0 + 3).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn minimum_size_ok() {
        let r = sys_clone3(0x1000, CLONE_ARGS_SIZE_VER0);
        assert_eq!(r.unwrap_err(), Error::NotImplemented);
    }

    #[test]
    fn extended_size_ok() {
        let r = sys_clone3(0x1000, CLONE_ARGS_SIZE_VER2);
        assert_eq!(r.unwrap_err(), Error::NotImplemented);
    }
}
