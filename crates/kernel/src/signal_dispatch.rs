// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! POSIX signal delivery on the SYSCALL/SYSRET return path.
//!
//! Pending signals are recorded on the per-process [`SignalState`] by
//! handlers such as [`crate::fork_dispatch::sys_kill`] and
//! [`crate::fork_dispatch::sys_exit`] (the latter raises `SIGCHLD` on
//! the parent). Those handlers only set bits — actual delivery is
//! deferred until the SYSCALL epilogue calls
//! [`deliver_pending_signals`], which iterates the pending bitmap and
//! applies the kernel-default action for each signal.
//!
//! # Phase 19 scope — kernel-default actions only
//!
//! Custom user-mode signal handlers installed via `sigaction(2)` are
//! out of scope for this phase: setting up a user-stack signal frame
//! and a `sigreturn` trampoline is deferred to a later batch (the
//! infrastructure for that lives in [`crate::signal_deliver`]). For
//! now, every pending signal takes one of three POSIX-default paths:
//!
//! * **Terminate** — for SIGHUP, SIGINT, SIGQUIT, SIGABRT, SIGBUS,
//!   SIGKILL, SIGSEGV, SIGTERM. The current process exits with status
//!   `128 + sig` (POSIX `wait(3p)` "terminated by signal" convention).
//! * **Ignore** — for SIGCHLD, SIGCONT, SIGURG, SIGWINCH, SIGIO. The
//!   pending bit is cleared and execution continues.
//! * **Default-ignore** — any other signal whose default action would
//!   require user-handler support is treated as ignored for now (bit
//!   cleared, execution continues).
//!
//! # POSIX references
//!
//! POSIX.1-2024 `signal(3p)`, `sigaction(3p)` — see
//! `.priv-storage/.TheOpenGroup/susv5-html/functions/sigaction.html`
//! "Signal Concepts" → default action table.

use oncrix_process::signal::Signal;

/// Iterate the current process's pending signal bitmap and apply the
/// kernel-default action for each set bit.
///
/// Called from the SYSCALL epilogue (see
/// [`crate::arch::x86_64::syscall_entry::syscall_dispatch_wrapper`])
/// after the syscall result has been computed but before the wrapper
/// returns to the assembly stub that performs SYSRET. This is the
/// canonical "check for signals on return-to-user" point.
///
/// Terminating signals call [`crate::fork_dispatch::sys_exit`] with
/// status `128 + sig` and never return; pending bits are cleared
/// before any such call so the entry remains consistent if the
/// process is reaped via `wait4`.
///
/// # Safety
///
/// Must be called from the SYSCALL dispatch path on the single CPU,
/// with interrupts effectively disabled (FMASK has cleared `IF` and
/// no enabling has happened in this Rust frame). This is the only
/// context in which the global `PROCESS_TABLE` may be mutated without
/// further synchronization.
pub unsafe fn deliver_pending_signals() {
    // No current thread (very early boot, before the scheduler has
    // any task) → nothing to deliver.
    let pid = match crate::current::current_pid() {
        Some(p) => p,
        None => return,
    };

    // Snapshot the pending bitmap and clear delivered bits in one
    // pass. We must drop the &mut borrow before calling sys_exit
    // (which itself walks the table to raise SIGCHLD on the parent).
    //
    // SAFETY: single-CPU SYSCALL context; exclusive access to the
    // process table for the duration of this borrow. The borrow is
    // dropped before any call to `sys_exit` below.
    let pending_bits: u32 = unsafe {
        let table = crate::fork_dispatch::process_table_mut();
        let entry = match table.get_mut(pid) {
            Some(e) => e,
            None => return,
        };
        let raw = pending_raw(&entry.signals.pending);
        if raw == 0 {
            return;
        }
        // Clear all currently pending bits. Any handler that wants
        // to short-circuit re-checks the bitmap on the next syscall.
        for bit in 0..Signal::MAX {
            if raw & (1u32 << bit) != 0 {
                entry.signals.pending.clear(Signal(bit + 1));
            }
        }
        raw
    };

    // Walk the snapshot and apply each signal's default action.
    // Terminate-class signals are processed first via sys_exit and
    // therefore short-circuit the loop (sys_exit does not return).
    for bit in 0..Signal::MAX {
        if pending_bits & (1u32 << bit) == 0 {
            continue;
        }
        let sig = Signal(bit + 1);
        match default_action(sig) {
            DefaultAction::Terminate => {
                // POSIX `wait(3p)` encodes "terminated by signal N"
                // as exit status 128 + N.
                let code = 128u64 + sig.0 as u64;
                // SAFETY: SYSCALL context — see fn-level safety doc.
                // sys_exit transitions the current thread to Exited
                // and does not return.
                unsafe { crate::fork_dispatch::sys_exit(code) };
                // Defensive: should be unreachable.
                return;
            }
            DefaultAction::Ignore => {
                // Bit was already cleared above; nothing more to do.
            }
        }
    }
}

/// Kernel-default action for a signal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DefaultAction {
    /// Terminate the process with status `128 + sig`.
    Terminate,
    /// Ignore the signal (clear pending bit, continue execution).
    Ignore,
}

/// POSIX.1-2024 default-action lookup, restricted to what the kernel
/// can apply without user-mode handler support.
///
/// Signals whose POSIX default is "stop" or "core dump" are treated
/// as `Terminate` for now (the process exits with `128 + sig`); a
/// later batch will distinguish these once job-control and core dump
/// support land.
const fn default_action(sig: Signal) -> DefaultAction {
    match sig {
        // Terminate by default (POSIX "T" or "A" disposition).
        Signal::SIGHUP
        | Signal::SIGINT
        | Signal::SIGQUIT
        | Signal::SIGABRT
        | Signal::SIGBUS
        | Signal::SIGKILL
        | Signal::SIGSEGV
        | Signal::SIGTERM => DefaultAction::Terminate,

        // Ignore by default (POSIX "I" disposition).
        // SIGURG (23), SIGWINCH (28), SIGIO (29) are not yet defined
        // as named constants on `Signal`, so match by raw number.
        Signal::SIGCHLD | Signal::SIGCONT => DefaultAction::Ignore,
        Signal(23) | Signal(28) | Signal(29) => DefaultAction::Ignore,

        // Anything else — including signals whose POSIX default is
        // "core" (SIGILL, SIGFPE, etc.) or "stop" (SIGSTOP, SIGTSTP) —
        // is treated as ignore for now. Custom handler delivery and
        // job control are deferred to later phases.
        _ => DefaultAction::Ignore,
    }
}

/// Read the raw bitmap out of a [`PendingSignals`].
///
/// `oncrix_process::signal::PendingSignals` is `#[repr(transparent)]`
/// over a `u32` but does not expose the inner value publicly. Reading
/// the bitmap as a single word lets us snapshot all pending signals
/// without iterating every signal number twice.
fn pending_raw(pending: &oncrix_process::signal::PendingSignals) -> u32 {
    let mut raw: u32 = 0;
    for bit in 0..Signal::MAX {
        if pending.is_pending(Signal(bit + 1)) {
            raw |= 1u32 << bit;
        }
    }
    raw
}
