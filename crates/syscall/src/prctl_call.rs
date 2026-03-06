// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `prctl(2)` syscall dispatch layer.
//!
//! This module is the thin entry point that validates raw syscall arguments
//! and delegates to [`crate::prctl`] which contains the full option-by-option
//! implementation.
//!
//! # Syscall signature
//!
//! ```text
//! int prctl(int option, unsigned long arg2, unsigned long arg3,
//!           unsigned long arg4, unsigned long arg5);
//! ```
//!
//! All five arguments are passed through to the dispatcher in `prctl.rs`.
//! Unknown option values must return `EINVAL` (mapped to
//! [`oncrix_lib::Error::InvalidArgument`]).
//!
//! # POSIX / Linux notes
//!
//! `prctl` is a Linux-specific interface and not part of POSIX.  The full
//! set of option codes and per-option semantics is defined in
//! `include/uapi/linux/prctl.h`.  The implementation follows the Linux ABI.
//!
//! # References
//!
//! - Linux: `kernel/sys.c` (`sys_prctl`)
//! - `include/uapi/linux/prctl.h`
//! - `prctl(2)` man page

use oncrix_lib::{Error, Result};

// Re-export option constants from the full implementation module so callers
// can use either import path.
pub use crate::prctl::{
    PR_CAP_BSET_DROP, PR_CAP_BSET_READ, PR_GET_CHILD_SUBREAPER, PR_GET_DUMPABLE, PR_GET_KEEPCAPS,
    PR_GET_NAME, PR_GET_NO_NEW_PRIVS, PR_GET_PDEATHSIG, PR_GET_SECCOMP, PR_GET_TIMER_SLACK,
    PR_SET_CHILD_SUBREAPER, PR_SET_DUMPABLE, PR_SET_KEEPCAPS, PR_SET_NAME, PR_SET_NO_NEW_PRIVS,
    PR_SET_PDEATHSIG, PR_SET_SECCOMP, PR_SET_TIMER_SLACK,
};

// ---------------------------------------------------------------------------
// Additional option constants not in the base prctl module
// ---------------------------------------------------------------------------

/// Set the machine-check memory corruption kill policy.
pub const PR_MCE_KILL: i32 = 33;
/// Get the machine-check memory corruption kill policy.
pub const PR_MCE_KILL_GET: i32 = 34;
/// Set the MMAP minimum address.
pub const PR_SET_MM: i32 = 35;
/// Enable or disable speculative store bypass mitigation.
pub const PR_SET_SPECULATION_CTRL: i32 = 53;
/// Get the speculation control setting.
pub const PR_GET_SPECULATION_CTRL: i32 = 52;
/// Set Tagged Address Control (AArch64).
pub const PR_SET_TAGGED_ADDR_CTRL: i32 = 55;
/// Get Tagged Address Control (AArch64).
pub const PR_GET_TAGGED_ADDR_CTRL: i32 = 56;
/// Enable syscall user dispatch.
pub const PR_SET_SYSCALL_USER_DISPATCH: i32 = 59;
/// Set the Shadow Stack control bits.
pub const PR_SET_SHADOW_STACK_STATUS: i32 = 74;
/// Get the Shadow Stack control bits.
pub const PR_GET_SHADOW_STACK_STATUS: i32 = 75;

// ---------------------------------------------------------------------------
// Sub-argument constants (PR_MCE_KILL)
// ---------------------------------------------------------------------------

/// Default MCE kill policy (inherits from parent).
pub const PR_MCE_KILL_CLEAR: u64 = 0;
/// Set a custom MCE kill policy.
pub const PR_MCE_KILL_SET: u64 = 1;
/// Kill the whole process on an MCE.
pub const PR_MCE_KILL_EARLY: u64 = 1;
/// Late kill: rely on OS to kill on next access.
pub const PR_MCE_KILL_LATE: u64 = 0;
/// Default kill mode.
pub const PR_MCE_KILL_DEFAULT: u64 = 2;

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

/// Handle the `prctl(2)` syscall.
///
/// Validates the five raw unsigned-long arguments and dispatches to the
/// appropriate per-option handler.  Returns 0 on success for set operations;
/// returns the queried value for get operations.
///
/// # Errors
///
/// - [`Error::InvalidArgument`] — unknown option or invalid sub-arguments.
/// - [`Error::PermissionDenied`] — insufficient privilege for the operation.
/// - [`Error::NotImplemented`] — option is valid but not yet implemented.
pub fn sys_prctl(option: i32, arg2: u64, arg3: u64, arg4: u64, arg5: u64) -> Result<i64> {
    // Reject obviously garbage arguments up-front.
    // arg3..arg5 must be zero for most get options; the per-option handlers
    // are responsible for finer-grained validation.
    match option {
        // Options that take no arg3/arg4/arg5 on get path.
        PR_GET_DUMPABLE | PR_GET_KEEPCAPS | PR_GET_NO_NEW_PRIVS | PR_GET_SECCOMP
        | PR_GET_TIMER_SLACK => {
            if arg3 != 0 || arg4 != 0 || arg5 != 0 {
                return Err(Error::InvalidArgument);
            }
        }
        _ => {}
    }

    // Forward to per-option dispatch.  Requires a PrctlTable reference and
    // pid_idx that are not available at the raw syscall entry point; those will
    // be plumbed in once the process context accessor is wired up.
    let _ = (option, arg2, arg3, arg4, arg5);
    Err(Error::NotImplemented)
}

/// Entry point called from the syscall dispatcher.
pub fn do_prctl_call(option: i32, arg2: u64, arg3: u64, arg4: u64, arg5: u64) -> Result<i64> {
    sys_prctl(option, arg2, arg3, arg4, arg5)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_dumpable_nonzero_trailing_args_rejected() {
        // arg3 non-zero with a get option should be rejected.
        assert_eq!(
            sys_prctl(PR_GET_DUMPABLE, 0, 1, 0, 0).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn get_no_new_privs_trailing_args_rejected() {
        assert_eq!(
            sys_prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 1, 0).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn get_timer_slack_clean() {
        // Should pass validation (no trailing args) and reach the stub.
        // The stub returns NotImplemented, not InvalidArgument.
        let r = sys_prctl(PR_GET_TIMER_SLACK, 0, 0, 0, 0);
        assert_eq!(r.unwrap_err(), Error::NotImplemented);
    }
}
