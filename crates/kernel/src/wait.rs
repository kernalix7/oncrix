// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `wait4` implementation — wait for child process state changes.
//!
//! Implements the POSIX `wait4(pid, wstatus, options, rusage)` semantics:
//!
//! - `pid > 0`: wait for the specific child
//! - `pid == -1`: wait for any child
//! - `pid == 0`: wait for any child in the same process group (not yet supported)
//! - `pid < -1`: wait for any child in process group `-pid` (not yet supported)
//!
//! The `wstatus` value encodes exit information per POSIX:
//! - Normal exit: `(exit_code & 0xFF) << 8`
//! - Signal death: `signal_number & 0x7F`
//!
//! Reference: POSIX.1-2024 §wait, Linux `kernel/exit.c`.

use oncrix_lib::{Error, Result};
use oncrix_process::pid::Pid;
use oncrix_process::table::{ExitStatus, ProcessTable};

/// Options for wait4 (matches POSIX values).
pub mod options {
    /// Return immediately if no child has exited.
    pub const WNOHANG: u64 = 1;
    /// Also report stopped (not just terminated) children.
    #[allow(dead_code)]
    pub const WUNTRACED: u64 = 2;
}

/// Encode an `ExitStatus` into the POSIX `wstatus` format.
///
/// POSIX wstatus encoding:
/// - Normal exit: bits 15:8 = exit code, bits 7:0 = 0
/// - Signal death: bits 7:0 = signal number (no core dump bit for now)
pub fn encode_wstatus(status: &ExitStatus) -> i32 {
    if status.was_signaled() {
        // Signal number is stored as 128 + sig, extract sig.
        let sig = status.raw() - 128;
        sig & 0x7F
    } else {
        // Normal exit: code in bits 15:8.
        (status.raw() & 0xFF) << 8
    }
}

/// Result of a successful wait4 call.
#[derive(Debug)]
pub struct WaitResult {
    /// PID of the child that changed state.
    pub pid: Pid,
    /// Encoded wstatus value (POSIX format).
    pub wstatus: i32,
}

/// Perform the wait4 operation on the process table.
///
/// `caller` is the PID of the calling process (the parent).
/// `target_pid` is the raw pid argument from the syscall:
///   - positive: wait for that specific child
///   - -1: wait for any child
///
/// `opts` is the options bitmask (WNOHANG, etc.).
///
/// On success, returns `WaitResult` with the reaped child's PID and
/// encoded wstatus. On WNOHANG with no zombie, returns `WouldBlock`.
///
/// The zombie entry is removed from the table (reaped).
pub fn do_wait4(
    table: &mut ProcessTable,
    caller: Pid,
    target_pid: i64,
    opts: u64,
) -> Result<WaitResult> {
    let wnohang = opts & options::WNOHANG != 0;

    if target_pid > 0 {
        // Wait for a specific child.
        wait_for_pid(table, caller, Pid::new(target_pid as u64), wnohang)
    } else if target_pid == -1 {
        // Wait for any child.
        wait_for_any(table, caller, wnohang)
    } else {
        // pid == 0 or pid < -1: process group waits not yet supported.
        Err(Error::NotImplemented)
    }
}

/// Wait for a specific child by PID.
fn wait_for_pid(
    table: &mut ProcessTable,
    caller: Pid,
    child_pid: Pid,
    wnohang: bool,
) -> Result<WaitResult> {
    // Verify the target is actually our child.
    let entry = table.get(child_pid).ok_or(Error::NotFound)?;
    if entry.parent != caller {
        // ECHILD — not our child.
        return Err(Error::NotFound);
    }

    if entry.is_zombie() {
        // Child has exited — reap it.
        let status = entry.exit_status.unwrap();
        let wstatus = encode_wstatus(&status);
        table.remove(child_pid);
        Ok(WaitResult {
            pid: child_pid,
            wstatus,
        })
    } else if wnohang {
        Err(Error::WouldBlock)
    } else {
        // Blocking wait: the caller should be put to sleep and
        // re-checked when the child exits. For now, return WouldBlock
        // since we don't yet have a sleep/wakeup mechanism.
        Err(Error::WouldBlock)
    }
}

/// Wait for any zombie child.
fn wait_for_any(table: &mut ProcessTable, caller: Pid, wnohang: bool) -> Result<WaitResult> {
    // Check if we have any children at all.
    let has_children = table.iter().any(|e| e.parent == caller);
    if !has_children {
        // ECHILD — no children.
        return Err(Error::NotFound);
    }

    // Look for a zombie child to reap.
    let zombie_pid = table
        .zombie_children(caller)
        .next()
        .map(|e| (e.pid(), e.exit_status.unwrap()));

    if let Some((pid, status)) = zombie_pid {
        let wstatus = encode_wstatus(&status);
        table.remove(pid);
        Ok(WaitResult { pid, wstatus })
    } else if wnohang {
        // No zombie yet, but WNOHANG — return 0 (no child changed state).
        // We signal this as WouldBlock; the syscall handler translates
        // this to returning 0 (not an error).
        Err(Error::WouldBlock)
    } else {
        // Blocking wait: not yet implemented.
        Err(Error::WouldBlock)
    }
}

/// POSIX wstatus macros — helper functions for decoding wstatus.
/// These mirror the C macros WIFEXITED, WEXITSTATUS, etc.
pub mod wstatus {
    /// True if the child terminated normally (exit, not signal).
    pub const fn wifexited(status: i32) -> bool {
        (status & 0x7F) == 0
    }

    /// Return the exit code (only valid if `wifexited` is true).
    pub const fn wexitstatus(status: i32) -> i32 {
        (status >> 8) & 0xFF
    }

    /// True if the child was killed by a signal.
    pub const fn wifsignaled(status: i32) -> bool {
        (status & 0x7F) != 0
    }

    /// Return the signal number (only valid if `wifsignaled` is true).
    pub const fn wtermsig(status: i32) -> i32 {
        status & 0x7F
    }
}
