// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `seccomp(2)` syscall handler — dispatch layer.
//!
//! This module provides the `seccomp(2)` syscall entry point.  It validates
//! the operation, flags, and attribute pointer, then delegates to the
//! detailed filter/mode logic in [`crate::seccomp_calls`].
//!
//! # Syscall signature
//!
//! ```text
//! int seccomp(unsigned int operation, unsigned int flags, void *args);
//! ```
//!
//! # Operations
//!
//! | Operation                   | Value | Description                              |
//! |-----------------------------|-------|------------------------------------------|
//! | `SECCOMP_SET_MODE_STRICT`   | 0     | Allow only `read`, `write`, `_exit`, `sigreturn` |
//! | `SECCOMP_SET_MODE_FILTER`   | 1     | Install a BPF syscall filter             |
//! | `SECCOMP_GET_ACTION_AVAIL`  | 2     | Query if an action value is supported    |
//! | `SECCOMP_GET_NOTIF_SIZES`   | 3     | Get sizes of user-notification structs   |
//!
//! # POSIX Notes
//!
//! `seccomp` is a Linux extension and not part of POSIX.  The implementation
//! follows the Linux ABI documented in `seccomp(2)`.
//!
//! # References
//!
//! - Linux: `kernel/seccomp.c`
//! - `include/uapi/linux/seccomp.h`
//! - `seccomp(2)` man page

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Operation constants
// ---------------------------------------------------------------------------

/// Restrict to `{read, write, _exit, sigreturn}` only.
pub const SECCOMP_SET_MODE_STRICT: u32 = 0;
/// Install a BPF syscall filter program.
pub const SECCOMP_SET_MODE_FILTER: u32 = 1;
/// Query if a specific seccomp action is available.
pub const SECCOMP_GET_ACTION_AVAIL: u32 = 2;
/// Get sizes of user-notification structures.
pub const SECCOMP_GET_NOTIF_SIZES: u32 = 3;

// ---------------------------------------------------------------------------
// Flag constants
// ---------------------------------------------------------------------------

/// Allowed flag for `SECCOMP_SET_MODE_FILTER`.
pub const SECCOMP_FILTER_FLAG_TSYNC: u32 = 1 << 0;
/// Log filter actions to the audit subsystem.
pub const SECCOMP_FILTER_FLAG_LOG: u32 = 1 << 1;
/// Speculative-store bypass safe mode.
pub const SECCOMP_FILTER_FLAG_SPEC_ALLOW: u32 = 1 << 2;
/// Create a user-notification fd pair for this filter.
pub const SECCOMP_FILTER_FLAG_NEW_LISTENER: u32 = 1 << 3;
/// Tsyncs for all threads, even if they have existing filters.
pub const SECCOMP_FILTER_FLAG_TSYNC_ESRCH: u32 = 1 << 4;
/// Wait-killable on user notification.
pub const SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV: u32 = 1 << 5;

/// All valid filter flags.
const SECCOMP_FILTER_FLAGS_MASK: u32 = SECCOMP_FILTER_FLAG_TSYNC
    | SECCOMP_FILTER_FLAG_LOG
    | SECCOMP_FILTER_FLAG_SPEC_ALLOW
    | SECCOMP_FILTER_FLAG_NEW_LISTENER
    | SECCOMP_FILTER_FLAG_TSYNC_ESRCH
    | SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV;

// ---------------------------------------------------------------------------
// Return action constants
// ---------------------------------------------------------------------------

/// Kill the entire process.
pub const SECCOMP_RET_KILL_PROCESS: u32 = 0x8000_0000;
/// Kill only the offending thread.
pub const SECCOMP_RET_KILL_THREAD: u32 = 0x0000_0000;
/// Deliver `SIGSYS` to the thread.
pub const SECCOMP_RET_TRAP: u32 = 0x0003_0000;
/// Return a custom errno to the caller.
pub const SECCOMP_RET_ERRNO: u32 = 0x0005_0000;
/// Notify a user-space supervisor.
pub const SECCOMP_RET_USER_NOTIF: u32 = 0x7fc0_0000;
/// Notify a ptrace tracer.
pub const SECCOMP_RET_TRACE: u32 = 0x7ff0_0000;
/// Allow and log.
pub const SECCOMP_RET_LOG: u32 = 0x7ffc_0000;
/// Allow unconditionally.
pub const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;

/// Mask for the data portion of `SECCOMP_RET_ERRNO` and `SECCOMP_RET_TRAP`.
pub const SECCOMP_RET_DATA: u32 = 0x0000_FFFF;
/// Mask for the action class bits.
pub const SECCOMP_RET_ACTION_FULL: u32 = 0xFFFF_0000;

// ---------------------------------------------------------------------------
// sock_fprog — BPF program descriptor for SECCOMP_SET_MODE_FILTER
// ---------------------------------------------------------------------------

/// A classic BPF instruction.
///
/// Matches `struct sock_filter` from `<linux/filter.h>`.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct SockFilter {
    /// Opcode.
    pub code: u16,
    /// Jump-true offset.
    pub jt: u8,
    /// Jump-false offset.
    pub jf: u8,
    /// Generic multi-purpose field.
    pub k: u32,
}

/// A BPF filter program.
///
/// Matches `struct sock_fprog` from `<linux/filter.h>`.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct SockFprog {
    /// Number of instructions in the program.
    pub len: u16,
    /// Padding.
    pub pad: [u8; 6],
    /// Pointer to the instruction array.
    pub filter: u64,
}

// ---------------------------------------------------------------------------
// seccomp_notif_sizes — result of SECCOMP_GET_NOTIF_SIZES
// ---------------------------------------------------------------------------

/// Sizes of the user-notification structures.
///
/// Matches `struct seccomp_notif_sizes` from `<linux/seccomp.h>`.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct SeccompNotifSizes {
    /// Size of `struct seccomp_notif`.
    pub seccomp_notif: u16,
    /// Size of `struct seccomp_notif_resp`.
    pub seccomp_notif_resp: u16,
    /// Size of `struct seccomp_data`.
    pub seccomp_data: u16,
}

/// Current sizes (must match the Linux UAPI values).
const NOTIF_SIZES: SeccompNotifSizes = SeccompNotifSizes {
    seccomp_notif: 80,
    seccomp_notif_resp: 24,
    seccomp_data: 64,
};

// ---------------------------------------------------------------------------
// Filter mode state
// ---------------------------------------------------------------------------

/// The seccomp mode of a thread.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SeccompMode {
    /// No seccomp restrictions.
    Disabled,
    /// Strict mode: only `{read, write, _exit, sigreturn}` allowed.
    Strict,
    /// Filter mode: BPF program applied to each syscall.
    Filter,
}

impl SeccompMode {
    /// Numeric value compatible with `PR_GET_SECCOMP`.
    pub const fn as_u64(self) -> u64 {
        match self {
            Self::Disabled => 0,
            Self::Strict => 1,
            Self::Filter => 2,
        }
    }
}

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

/// Handle the `seccomp(2)` syscall.
///
/// Validates the `operation`, `flags`, and `args` pointer, then executes
/// the requested seccomp operation.
///
/// Returns 0 on success (or an fd for `SECCOMP_FILTER_FLAG_NEW_LISTENER`).
///
/// # Errors
///
/// - [`Error::InvalidArgument`] — unknown operation, invalid flags, null
///   pointer when required, or reserved fields non-zero.
/// - [`Error::PermissionDenied`] — `no_new_privs` is not set and caller
///   lacks `CAP_SYS_ADMIN` (required for `SECCOMP_SET_MODE_FILTER`).
/// - [`Error::NotImplemented`] — operation is valid but not yet implemented.
pub fn sys_seccomp(operation: u32, flags: u32, args: u64) -> Result<i64> {
    match operation {
        SECCOMP_SET_MODE_STRICT => {
            if flags != 0 {
                return Err(Error::InvalidArgument);
            }
            if args != 0 {
                return Err(Error::InvalidArgument);
            }
            do_set_mode_strict()
        }
        SECCOMP_SET_MODE_FILTER => {
            if flags & !SECCOMP_FILTER_FLAGS_MASK != 0 {
                return Err(Error::InvalidArgument);
            }
            if args == 0 {
                return Err(Error::InvalidArgument);
            }
            // TSYNC and NEW_LISTENER are mutually exclusive.
            if flags & SECCOMP_FILTER_FLAG_TSYNC != 0
                && flags & SECCOMP_FILTER_FLAG_NEW_LISTENER != 0
            {
                return Err(Error::InvalidArgument);
            }
            do_set_mode_filter(flags, args)
        }
        SECCOMP_GET_ACTION_AVAIL => {
            if flags != 0 {
                return Err(Error::InvalidArgument);
            }
            if args == 0 {
                return Err(Error::InvalidArgument);
            }
            // SAFETY: Caller validates user-space pointer.
            let action = unsafe { *(args as *const u32) };
            do_get_action_avail(action)
        }
        SECCOMP_GET_NOTIF_SIZES => {
            if flags != 0 {
                return Err(Error::InvalidArgument);
            }
            if args == 0 {
                return Err(Error::InvalidArgument);
            }
            do_get_notif_sizes(args)
        }
        _ => Err(Error::InvalidArgument),
    }
}

fn do_set_mode_strict() -> Result<i64> {
    // TODO: set the calling thread's seccomp mode to SECCOMP_MODE_STRICT.
    // This is a one-way operation; once set it cannot be reversed.
    Err(Error::NotImplemented)
}

fn do_set_mode_filter(flags: u32, fprog_ptr: u64) -> Result<i64> {
    // SAFETY: fprog_ptr validated non-zero by caller.
    let fprog = unsafe { *(fprog_ptr as *const SockFprog) };
    if fprog.len == 0 {
        return Err(Error::InvalidArgument);
    }
    // TODO:
    // 1. Check no_new_privs or CAP_SYS_ADMIN.
    // 2. copy_from_user the BPF instructions.
    // 3. Run the BPF verifier.
    // 4. Install the filter into the thread's filter list.
    // 5. If TSYNC, apply to all threads in the thread group.
    // 6. If NEW_LISTENER, create notification fd and return it.
    let _ = flags;
    Err(Error::NotImplemented)
}

fn do_get_action_avail(action: u32) -> Result<i64> {
    let supported = [
        SECCOMP_RET_KILL_PROCESS,
        SECCOMP_RET_KILL_THREAD,
        SECCOMP_RET_TRAP,
        SECCOMP_RET_ERRNO,
        SECCOMP_RET_USER_NOTIF,
        SECCOMP_RET_TRACE,
        SECCOMP_RET_LOG,
        SECCOMP_RET_ALLOW,
    ];
    let action_class = action & SECCOMP_RET_ACTION_FULL;
    if supported.contains(&action_class) {
        Ok(0)
    } else {
        Err(Error::NotFound)
    }
}

fn do_get_notif_sizes(out_ptr: u64) -> Result<i64> {
    // SAFETY: Caller validates user-space pointer.
    unsafe {
        *(out_ptr as *mut SeccompNotifSizes) = NOTIF_SIZES;
    }
    Ok(0)
}

/// Entry point called from the syscall dispatcher.
pub fn do_seccomp(operation: u32, flags: u32, args: u64) -> Result<i64> {
    sys_seccomp(operation, flags, args)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strict_nonzero_flags_rejected() {
        assert_eq!(
            sys_seccomp(SECCOMP_SET_MODE_STRICT, 1, 0).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn strict_nonzero_args_rejected() {
        assert_eq!(
            sys_seccomp(SECCOMP_SET_MODE_STRICT, 0, 1).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn filter_null_args_rejected() {
        assert_eq!(
            sys_seccomp(SECCOMP_SET_MODE_FILTER, 0, 0).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn filter_invalid_flags_rejected() {
        assert_eq!(
            sys_seccomp(SECCOMP_SET_MODE_FILTER, 0xFFFF, 0x1000).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn filter_tsync_newlistener_conflict() {
        let flags = SECCOMP_FILTER_FLAG_TSYNC | SECCOMP_FILTER_FLAG_NEW_LISTENER;
        assert_eq!(
            sys_seccomp(SECCOMP_SET_MODE_FILTER, flags, 0x1000).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn get_action_avail_known_action() {
        assert_eq!(
            sys_seccomp(
                SECCOMP_GET_ACTION_AVAIL,
                0,
                &SECCOMP_RET_ALLOW as *const u32 as u64
            ),
            Ok(0)
        );
    }

    #[test]
    fn get_action_avail_unknown_action() {
        let bad_action: u32 = 0x1234_0000;
        assert_eq!(
            sys_seccomp(
                SECCOMP_GET_ACTION_AVAIL,
                0,
                &bad_action as *const u32 as u64
            )
            .unwrap_err(),
            Error::NotFound
        );
    }

    #[test]
    fn get_notif_sizes() {
        let mut sizes = SeccompNotifSizes::default();
        let r = sys_seccomp(
            SECCOMP_GET_NOTIF_SIZES,
            0,
            &mut sizes as *mut SeccompNotifSizes as u64,
        );
        assert_eq!(r, Ok(0));
        assert_eq!(sizes.seccomp_notif, NOTIF_SIZES.seccomp_notif);
    }

    #[test]
    fn unknown_operation_rejected() {
        assert_eq!(sys_seccomp(99, 0, 0).unwrap_err(), Error::InvalidArgument);
    }

    #[test]
    fn seccomp_mode_values() {
        assert_eq!(SeccompMode::Disabled.as_u64(), 0);
        assert_eq!(SeccompMode::Strict.as_u64(), 1);
        assert_eq!(SeccompMode::Filter.as_u64(), 2);
    }
}
