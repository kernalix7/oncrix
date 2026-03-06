// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `ptrace(2)` syscall dispatch layer.
//!
//! This module provides the `ptrace(2)` syscall entry point, validates the
//! raw arguments, and dispatches to the full implementation in
//! [`crate::ptrace_calls`].
//!
//! # Syscall signature
//!
//! ```text
//! long ptrace(enum __ptrace_request request, pid_t pid,
//!             void *addr, void *data);
//! ```
//!
//! # Request classification
//!
//! Requests are partitioned into three categories:
//!
//! | Category | Examples | `addr` / `data` usage |
//! |----------|----------|------------------------|
//! | Attach/detach | `PTRACE_ATTACH`, `PTRACE_DETACH` | `data` = signal |
//! | Memory peek/poke | `PTRACE_PEEKTEXT`, `PTRACE_POKETEXT` | `addr` = virtual address |
//! | Register access | `PTRACE_GETREGS`, `PTRACE_SETREGS` | `data` = struct pointer |
//! | Control | `PTRACE_CONT`, `PTRACE_SINGLESTEP` | `data` = signal |
//! | Options | `PTRACE_SETOPTIONS` | `data` = bitmask |
//!
//! # POSIX Notes
//!
//! POSIX.1-2008 and later mark `ptrace` as a legacy interface without
//! specifying full semantics.  The implementation follows the Linux ABI
//! documented in `ptrace(2)`.
//!
//! # References
//!
//! - Linux: `kernel/ptrace.c`
//! - `include/uapi/linux/ptrace.h`
//! - `ptrace(2)` man page

use oncrix_lib::{Error, Result};

// Re-export request codes and option flags from the full ptrace module.
pub use crate::ptrace_calls::{
    PTRACE_O_EXITKILL, PTRACE_O_TRACECLONE, PTRACE_O_TRACEEXEC, PTRACE_O_TRACEEXIT,
    PTRACE_O_TRACEFORK, PTRACE_O_TRACESECCOMP, PTRACE_O_TRACESYSGOOD, PTRACE_O_TRACEVFORK,
    PtraceRequest,
};

/// Combined mask of all valid PTRACE_O_* flags.
const PTRACE_O_MASK: u32 = PTRACE_O_EXITKILL
    | PTRACE_O_TRACECLONE
    | PTRACE_O_TRACEEXEC
    | PTRACE_O_TRACEEXIT
    | PTRACE_O_TRACEFORK
    | PTRACE_O_TRACESECCOMP
    | PTRACE_O_TRACESYSGOOD
    | PTRACE_O_TRACEVFORK;

// ---------------------------------------------------------------------------
// Additional request codes not yet in ptrace_calls
// ---------------------------------------------------------------------------

/// Continue the tracee, delivering `data` as a signal (0 = none).
pub const PTRACE_CONT: u64 = 7;
/// Kill the tracee.
pub const PTRACE_KILL: u64 = 8;
/// Single-step the tracee, delivering `data` as a signal.
pub const PTRACE_SINGLESTEP: u64 = 9;
/// Get the tracee's general-purpose registers.
pub const PTRACE_GETREGS: u64 = 12;
/// Set the tracee's general-purpose registers.
pub const PTRACE_SETREGS: u64 = 13;
/// Get the tracee's floating-point registers.
pub const PTRACE_GETFPREGS: u64 = 14;
/// Set the tracee's floating-point registers.
pub const PTRACE_SETFPREGS: u64 = 15;
/// Read a word from tracee memory.
pub const PTRACE_PEEKTEXT: u64 = 1;
/// Read a word from tracee data segment.
pub const PTRACE_PEEKDATA: u64 = 2;
/// Read a word from tracee user-struct.
pub const PTRACE_PEEKUSER: u64 = 3;
/// Write a word to tracee memory.
pub const PTRACE_POKETEXT: u64 = 4;
/// Write a word to tracee data segment.
pub const PTRACE_POKEDATA: u64 = 5;
/// Write a word to tracee user-struct.
pub const PTRACE_POKEUSER: u64 = 6;
/// Detach from a tracee, optionally delivering a signal.
pub const PTRACE_DETACH: u64 = 17;
/// Get signal information from the tracee's pending signal.
pub const PTRACE_GETSIGINFO: u64 = 0x4202;
/// Set signal information on the tracee's pending signal.
pub const PTRACE_SETSIGINFO: u64 = 0x4203;
/// Set ptrace options.
pub const PTRACE_SETOPTIONS: u64 = 0x4200;
/// Retrieve an event message.
pub const PTRACE_GETEVENTMSG: u64 = 0x4201;
/// Get register set by type.
pub const PTRACE_GETREGSET: u64 = 0x4204;
/// Set register set by type.
pub const PTRACE_SETREGSET: u64 = 0x4205;
/// Attach, waiting for stop.
pub const PTRACE_SEIZE: u64 = 0x4206;
/// Query the tracee's state.
pub const PTRACE_INTERRUPT: u64 = 0x4207;
/// Listen for events without resuming.
pub const PTRACE_LISTEN: u64 = 0x4208;
/// Get signal mask of the tracee.
pub const PTRACE_GETSIGMASK: u64 = 0x420a;
/// Set signal mask of the tracee.
pub const PTRACE_SETSIGMASK: u64 = 0x420b;
/// Get syscall info from the tracee.
pub const PTRACE_GET_SYSCALL_INFO: u64 = 0x420e;
/// Get RSEQ configuration of tracee.
pub const PTRACE_GET_RSEQ_CONFIGURATION: u64 = 0x420f;
/// Seccomp user-notification fd operations.
pub const PTRACE_SET_SYSCALL_USER_DISPATCH_CONFIG: u64 = 0x4210;
/// Get the exception-level of the tracee (AArch64).
pub const PTRACE_PEEKMTETAGS: u64 = 0x4213;
/// Set the exception-level tags of the tracee (AArch64).
pub const PTRACE_POKEMTETAGS: u64 = 0x4214;

// ---------------------------------------------------------------------------
// Validation helpers
// ---------------------------------------------------------------------------

/// Returns `true` if `request` is a known ptrace request code.
fn is_known_request(request: u64) -> bool {
    matches!(
        request,
        PTRACE_PEEKTEXT
            | PTRACE_PEEKDATA
            | PTRACE_PEEKUSER
            | PTRACE_POKETEXT
            | PTRACE_POKEDATA
            | PTRACE_POKEUSER
            | PTRACE_CONT
            | PTRACE_KILL
            | PTRACE_SINGLESTEP
            | PTRACE_GETREGS
            | PTRACE_SETREGS
            | PTRACE_GETFPREGS
            | PTRACE_SETFPREGS
            | PTRACE_DETACH
            | PTRACE_GETSIGINFO
            | PTRACE_SETSIGINFO
            | PTRACE_SETOPTIONS
            | PTRACE_GETEVENTMSG
            | PTRACE_GETREGSET
            | PTRACE_SETREGSET
            | PTRACE_SEIZE
            | PTRACE_INTERRUPT
            | PTRACE_LISTEN
            | PTRACE_GETSIGMASK
            | PTRACE_SETSIGMASK
            | PTRACE_GET_SYSCALL_INFO
            | PTRACE_GET_RSEQ_CONFIGURATION
            | PTRACE_PEEKMTETAGS
            | PTRACE_POKEMTETAGS
            // PTRACE_TRACEME is 0; validated separately.
            | 0
    )
}

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

/// Handle the `ptrace(2)` syscall.
///
/// `request` is the ptrace request code.  `pid` is the target PID (ignored
/// for `PTRACE_TRACEME`).  `addr` and `data` are request-specific.
///
/// Returns 0 on success for most requests.  `PTRACE_PEEKTEXT` and related
/// peek requests return the peeked value directly.
///
/// # Errors
///
/// - [`Error::InvalidArgument`] — unknown request code, `pid` is 0 or
///   negative for requests that require a target, `data` is zero when a
///   non-null pointer is required.
/// - [`Error::NotFound`] — the target process does not exist or is not
///   currently being traced by this process.
/// - [`Error::PermissionDenied`] — insufficient privilege to trace the
///   target, or the target has `PR_SET_DUMPABLE` cleared.
/// - [`Error::Busy`] — target is not in a stopped state.
/// - [`Error::NotImplemented`] — request is valid but not yet implemented.
pub fn sys_ptrace(request: u64, pid: u32, addr: u64, data: u64) -> Result<i64> {
    // PTRACE_TRACEME (0) uses pid = 0, addr = 0, data = 0.
    if request == 0 {
        return do_traceme();
    }

    if !is_known_request(request) {
        return Err(Error::InvalidArgument);
    }

    // All other requests require a positive PID.
    if pid == 0 {
        return Err(Error::InvalidArgument);
    }

    dispatch_request(request, pid, addr, data)
}

fn do_traceme() -> Result<i64> {
    // TODO: Mark the calling process as traceable by its parent.
    // POSIX: PTRACE_TRACEME sets the calling process's PT_TRACED flag.
    Err(Error::NotImplemented)
}

fn dispatch_request(request: u64, pid: u32, addr: u64, data: u64) -> Result<i64> {
    match request {
        PTRACE_PEEKTEXT | PTRACE_PEEKDATA => do_peek(pid, addr),
        PTRACE_PEEKUSER => do_peek_user(pid, addr),
        PTRACE_POKETEXT | PTRACE_POKEDATA => do_poke(pid, addr, data),
        PTRACE_POKEUSER => do_poke_user(pid, addr, data),
        PTRACE_CONT => do_cont(pid, data as u32),
        PTRACE_KILL => do_kill_tracee(pid),
        PTRACE_SINGLESTEP => do_singlestep(pid, data as u32),
        PTRACE_GETREGS => do_getregs(pid, data),
        PTRACE_SETREGS => do_setregs(pid, data),
        PTRACE_GETFPREGS => do_getfpregs(pid, data),
        PTRACE_SETFPREGS => do_setfpregs(pid, data),
        PTRACE_DETACH => do_detach(pid, data as u32),
        PTRACE_SETOPTIONS => do_setoptions(pid, data as u32),
        PTRACE_GETEVENTMSG => do_geteventmsg(pid, data),
        PTRACE_GETSIGINFO => do_getsiginfo(pid, data),
        PTRACE_SETSIGINFO => do_setsiginfo(pid, data),
        PTRACE_GETREGSET => do_getregset(pid, addr as u32, data),
        PTRACE_SETREGSET => do_setregset(pid, addr as u32, data),
        PTRACE_SEIZE => do_seize(pid, data as u32),
        PTRACE_INTERRUPT => do_interrupt(pid),
        PTRACE_LISTEN => do_listen(pid),
        PTRACE_GETSIGMASK => do_getsigmask(pid, addr, data),
        PTRACE_SETSIGMASK => do_setsigmask(pid, addr, data),
        PTRACE_GET_SYSCALL_INFO => do_get_syscall_info(pid, addr, data),
        _ => Err(Error::NotImplemented),
    }
}

// ---------------------------------------------------------------------------
// Per-request stubs
// ---------------------------------------------------------------------------

fn do_peek(_pid: u32, _addr: u64) -> Result<i64> {
    Err(Error::NotImplemented)
}
fn do_peek_user(_pid: u32, _addr: u64) -> Result<i64> {
    Err(Error::NotImplemented)
}
fn do_poke(_pid: u32, _addr: u64, _data: u64) -> Result<i64> {
    Err(Error::NotImplemented)
}
fn do_poke_user(_pid: u32, _addr: u64, _data: u64) -> Result<i64> {
    Err(Error::NotImplemented)
}
fn do_cont(_pid: u32, signal: u32) -> Result<i64> {
    // Signal must fit in u8.
    if signal > 255 {
        return Err(Error::InvalidArgument);
    }
    Err(Error::NotImplemented)
}
fn do_kill_tracee(_pid: u32) -> Result<i64> {
    Err(Error::NotImplemented)
}
fn do_singlestep(_pid: u32, signal: u32) -> Result<i64> {
    if signal > 255 {
        return Err(Error::InvalidArgument);
    }
    Err(Error::NotImplemented)
}
fn do_getregs(_pid: u32, data: u64) -> Result<i64> {
    if data == 0 {
        return Err(Error::InvalidArgument);
    }
    Err(Error::NotImplemented)
}
fn do_setregs(_pid: u32, data: u64) -> Result<i64> {
    if data == 0 {
        return Err(Error::InvalidArgument);
    }
    Err(Error::NotImplemented)
}
fn do_getfpregs(_pid: u32, data: u64) -> Result<i64> {
    if data == 0 {
        return Err(Error::InvalidArgument);
    }
    Err(Error::NotImplemented)
}
fn do_setfpregs(_pid: u32, data: u64) -> Result<i64> {
    if data == 0 {
        return Err(Error::InvalidArgument);
    }
    Err(Error::NotImplemented)
}
fn do_detach(_pid: u32, signal: u32) -> Result<i64> {
    if signal > 255 {
        return Err(Error::InvalidArgument);
    }
    Err(Error::NotImplemented)
}
fn do_setoptions(_pid: u32, opts: u32) -> Result<i64> {
    if opts & !PTRACE_O_MASK != 0 {
        return Err(Error::InvalidArgument);
    }
    Err(Error::NotImplemented)
}
fn do_geteventmsg(_pid: u32, data: u64) -> Result<i64> {
    if data == 0 {
        return Err(Error::InvalidArgument);
    }
    Err(Error::NotImplemented)
}
fn do_getsiginfo(_pid: u32, data: u64) -> Result<i64> {
    if data == 0 {
        return Err(Error::InvalidArgument);
    }
    Err(Error::NotImplemented)
}
fn do_setsiginfo(_pid: u32, data: u64) -> Result<i64> {
    if data == 0 {
        return Err(Error::InvalidArgument);
    }
    Err(Error::NotImplemented)
}
fn do_getregset(_pid: u32, _nt: u32, data: u64) -> Result<i64> {
    if data == 0 {
        return Err(Error::InvalidArgument);
    }
    Err(Error::NotImplemented)
}
fn do_setregset(_pid: u32, _nt: u32, data: u64) -> Result<i64> {
    if data == 0 {
        return Err(Error::InvalidArgument);
    }
    Err(Error::NotImplemented)
}
fn do_seize(_pid: u32, opts: u32) -> Result<i64> {
    if opts & !PTRACE_O_MASK != 0 {
        return Err(Error::InvalidArgument);
    }
    Err(Error::NotImplemented)
}
fn do_interrupt(_pid: u32) -> Result<i64> {
    Err(Error::NotImplemented)
}
fn do_listen(_pid: u32) -> Result<i64> {
    Err(Error::NotImplemented)
}
fn do_getsigmask(_pid: u32, sigsetsize: u64, data: u64) -> Result<i64> {
    if sigsetsize != 8 || data == 0 {
        return Err(Error::InvalidArgument);
    }
    Err(Error::NotImplemented)
}
fn do_setsigmask(_pid: u32, sigsetsize: u64, data: u64) -> Result<i64> {
    if sigsetsize != 8 || data == 0 {
        return Err(Error::InvalidArgument);
    }
    Err(Error::NotImplemented)
}
fn do_get_syscall_info(_pid: u32, _size: u64, data: u64) -> Result<i64> {
    if data == 0 {
        return Err(Error::InvalidArgument);
    }
    Err(Error::NotImplemented)
}

/// Entry point called from the syscall dispatcher.
pub fn do_ptrace(request: u64, pid: u32, addr: u64, data: u64) -> Result<i64> {
    sys_ptrace(request, pid, addr, data)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn traceme_pid_zero_ok() {
        // PTRACE_TRACEME should not reject zero pid.
        // It returns NotImplemented (not InvalidArgument) since it reaches the stub.
        assert_ne!(sys_ptrace(0, 0, 0, 0).unwrap_err(), Error::InvalidArgument);
    }

    #[test]
    fn unknown_request_rejected() {
        assert_eq!(
            sys_ptrace(0x9999, 1, 0, 0).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn non_traceme_zero_pid_rejected() {
        assert_eq!(
            sys_ptrace(PTRACE_CONT, 0, 0, 0).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn cont_large_signal_rejected() {
        assert_eq!(
            sys_ptrace(PTRACE_CONT, 1, 0, 999).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn setoptions_invalid_bits_rejected() {
        assert_eq!(
            sys_ptrace(PTRACE_SETOPTIONS, 1, 0, 0xDEAD_DEAD).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn getregs_null_data_rejected() {
        assert_eq!(
            sys_ptrace(PTRACE_GETREGS, 1, 0, 0).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn getsigmask_wrong_sigsetsize_rejected() {
        let mut mask: u64 = 0;
        assert_eq!(
            sys_ptrace(PTRACE_GETSIGMASK, 1, 4, &mut mask as *mut u64 as u64).unwrap_err(),
            Error::InvalidArgument
        );
    }
}
