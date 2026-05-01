// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! SYS_RT_SIGACTION and SYS_RT_SIGRETURN syscall bodies.
//!
//! POSIX.1-2024 `sigaction(3p)` semantics — installs a per-process
//! disposition for a signal so subsequent deliveries either ignore it,
//! take the kernel default, or invoke a user-mode handler. The handler
//! address and `sa_flags` are recorded on the per-process
//! [`SignalState`] for use by [`crate::signal_dispatch`].
//!
//! # Reference
//!
//! `.priv-storage/.TheOpenGroup/susv5-html/functions/sigaction.html`.

use oncrix_process::signal::{Signal, SignalAction, SignalState};

/// Kernel mirror of the POSIX `struct sigaction`.
///
/// Field order matches the userspace `oncrix_ulibc::Sigaction` exactly
/// — the kernel reads it byte-by-byte from user space via volatile
/// loads, so any change here must be mirrored in the libc wrapper.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct KernelSigaction {
    /// Handler address; `0` = `SIG_DFL`, `1` = `SIG_IGN`, anything
    /// else is treated as a user-mode handler entry point.
    pub sa_handler: u64,
    /// `SA_*` flags (see [`oncrix_process::signal`]).
    pub sa_flags: u64,
    /// Trampoline address — currently ignored; the kernel always uses
    /// its own in-process trampoline at `SIGRETURN_TRAMPOLINE_VA`.
    pub sa_restorer: u64,
    /// Blocked-signal mask while the handler runs. Currently stored
    /// but not yet consulted on delivery (mask manipulation is a
    /// later batch).
    pub sa_mask: u64,
}

/// Conventional `SIG_DFL` sentinel.
const SIG_DFL: u64 = 0;
/// Conventional `SIG_IGN` sentinel.
const SIG_IGN: u64 = 1;

/// User-canonical address ceiling. Anything at or above this is a
/// kernel-half address (or non-canonical) and rejected as `EFAULT`.
const USER_VA_CEILING: u64 = 0x0000_8000_0000_0000;

/// Kernel handler for `SYS_RT_SIGACTION` (Linux number 13).
///
/// `sig` is the signal number; `act` and `oldact` are user pointers.
/// If `oldact` is non-null, the previous disposition is copied into it
/// before `act` (if non-null) replaces it. Returns 0 on success or a
/// negative errno.
///
/// # Safety
///
/// Must be called from the SYSCALL dispatch path on the single CPU.
/// `act` / `oldact` are user pointers and validated below.
pub unsafe fn sys_rt_sigaction(sig: u64, act: u64, oldact: u64) -> i64 {
    // POSIX: sig must be a valid signal number, and SIGKILL/SIGSTOP
    // cannot have their disposition altered.
    if sig == 0 || sig as u8 > Signal::MAX {
        return -22; // EINVAL
    }
    let sig = Signal(sig as u8);
    if sig == Signal::SIGKILL || sig == Signal::SIGSTOP {
        return -22; // EINVAL
    }

    // Validate user pointers — non-null pointers must be in the user
    // canonical half. `act` and `oldact` may both be null.
    if act != 0 && (act >= USER_VA_CEILING) {
        return -14; // EFAULT
    }
    if oldact != 0 && (oldact >= USER_VA_CEILING) {
        return -14; // EFAULT
    }

    let pid = match crate::current::current_pid() {
        Some(p) => p,
        None => return -3, // ESRCH — no current thread
    };

    // SAFETY: single-CPU SYSCALL context — exclusive access to the
    // process table for the duration of this borrow.
    let signals: &mut SignalState = unsafe {
        let table = crate::fork_dispatch::process_table_mut();
        match table.get_mut(pid) {
            Some(e) => &mut e.signals,
            None => return -3, // ESRCH
        }
    };

    // Save the old disposition before overwriting.
    if oldact != 0 {
        let old_action = signals.get_action(sig);
        let old_handler = match old_action {
            SignalAction::Default => SIG_DFL,
            SignalAction::Ignore => SIG_IGN,
            SignalAction::Handler(rip) => rip,
        };
        let old = KernelSigaction {
            sa_handler: old_handler,
            sa_flags: signals.get_flags(sig),
            sa_restorer: 0,
            sa_mask: 0,
        };
        // SAFETY: oldact is a non-null user-canonical pointer.
        unsafe {
            (oldact as *mut KernelSigaction).write_volatile(old);
        }
    }

    if act != 0 {
        // SAFETY: act is a non-null user-canonical pointer.
        let new = unsafe { (act as *const KernelSigaction).read_volatile() };
        let new_action = match new.sa_handler {
            SIG_DFL => SignalAction::Default,
            SIG_IGN => SignalAction::Ignore,
            rip => {
                if rip >= USER_VA_CEILING {
                    return -14; // EFAULT — non-canonical handler
                }
                SignalAction::Handler(rip)
            }
        };
        if signals
            .set_action_with_flags(sig, new_action, new.sa_flags)
            .is_err()
        {
            return -22; // EINVAL
        }
    }

    0
}
