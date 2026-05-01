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
//! either runs the kernel-default action or — when the process has
//! installed a user-mode handler via `sigaction(2)` — pushes a
//! [`UserSignalFrame`] onto the user stack and redirects SYSRET into
//! the handler.
//!
//! # User-handler delivery
//!
//! When a pending signal's [`SignalAction`] is `Handler(rip)`, the
//! delivery path:
//!
//! 1. Reads the saved user RIP/RSP/RFLAGS from the SYSCALL entry stub.
//! 2. Decrements the saved RSP by `sizeof(UserSignalFrame) + 8` bytes
//!    (8 bytes of pretcode + frame).
//! 3. Writes a [`UserSignalFrame`] containing the saved register state
//!    and the magic word `b"ONCRSIGF"` so [`do_sigreturn`] can
//!    authenticate the frame on return.
//! 4. Pushes the trampoline VA (`SIGRETURN_TRAMPOLINE_VA`) at the new
//!    top-of-stack as the "pretcode" — the handler returns into it,
//!    which issues `SYS_RT_SIGRETURN` and restores the frame.
//! 5. Updates `SYSCALL_SAVED_USER_{RIP,RSP,RFLAGS}` and overwrites
//!    `args.arg0` with the signal number so the SYSCALL epilogue
//!    restores RDI = signum (System V handler ABI).
//!
//! [`do_sigreturn`] reverses the process: validates the magic, restores
//! the saved register state on the SYSCALL exit atomics so SYSRET
//! resumes the interrupted user instruction.
//!
//! # Default actions
//!
//! Signals without a user-installed handler take one of three POSIX
//! default paths:
//!
//! * **Terminate** — `SIGHUP`, `SIGINT`, `SIGQUIT`, `SIGABRT`, `SIGBUS`,
//!   `SIGKILL`, `SIGSEGV`, `SIGTERM`. The current process exits with
//!   status `128 + sig`.
//! * **Ignore** — `SIGCHLD`, `SIGCONT`, `SIGURG`, `SIGWINCH`, `SIGIO`.
//!   The pending bit is cleared; execution continues.
//! * **Default-ignore** — anything else (including signals whose POSIX
//!   default would be "stop" or "core") is treated as ignore for now.
//!
//! # POSIX references
//!
//! POSIX.1-2024 `signal(3p)`, `sigaction(3p)` — see
//! `.priv-storage/.TheOpenGroup/susv5-html/functions/sigaction.html`.

use oncrix_lib::{Error, Result};
use oncrix_process::signal::{Signal, SignalAction};
use oncrix_syscall::dispatch::SyscallArgs;

use crate::arch::x86_64::init_embed::SIGRETURN_TRAMPOLINE_VA;
use crate::arch::x86_64::syscall_entry::{
    SYSCALL_SAVED_USER_RFLAGS, SYSCALL_SAVED_USER_RIP, SYSCALL_SAVED_USER_RSP,
};

/// Magic word identifying a kernel-pushed signal frame.
///
/// Eight bytes — `"ONCRSIGF"` — written little-endian as a `u64`.
/// `do_sigreturn` checks this before restoring the saved registers so a
/// userspace fake `rt_sigreturn` cannot trivially redirect SYSRET to an
/// arbitrary RIP.
pub const SIGFRAME_MAGIC: u64 = u64::from_le_bytes(*b"ONCRSIGF");

/// Layout of the signal-delivery frame written on the user stack.
///
/// `repr(C)` so the userspace trampoline (which only sees the address)
/// can compute fixed offsets. Field order is fixed and load-bearing.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct UserSignalFrame {
    /// Authentication tag — `SIGFRAME_MAGIC`.
    pub magic: u64,
    /// Signal number that was delivered.
    pub signum: u32,
    /// Padding — keep `saved_rip` 8-byte aligned.
    pub _pad: u32,
    /// Saved user RIP at the moment the signal was delivered.
    pub saved_rip: u64,
    /// Saved user RSP at the moment the signal was delivered.
    pub saved_rsp: u64,
    /// Saved user RFLAGS at the moment the signal was delivered.
    pub saved_rflags: u64,
}

const FRAME_SIZE: usize = core::mem::size_of::<UserSignalFrame>();

/// Iterate the current process's pending signal bitmap and deliver any
/// signals whose action is `Handler(rip)` via a user-stack frame, or
/// apply the kernel-default action for the rest.
///
/// `args` is the live `SyscallArgs` on the kernel stack — when a
/// handler is delivered, `args.arg0` is overwritten with the signum so
/// the SYSCALL epilogue's `pop rdi` plants RDI = signum (System V
/// signal-handler ABI).
///
/// Called from the SYSCALL epilogue (see
/// [`crate::arch::x86_64::syscall_entry::syscall_dispatch_wrapper`])
/// after the syscall result has been computed but before the wrapper
/// returns to the assembly stub that performs SYSRET.
///
/// # Safety
///
/// Must be called from the SYSCALL dispatch path on the single CPU,
/// with interrupts effectively disabled (FMASK has cleared `IF` and
/// no enabling has happened in this Rust frame). `args` must point at
/// the live SyscallArgs slot on the kernel stack so a write to
/// `args.arg0` is observed by the SYSRET epilogue's `pop rdi`.
pub unsafe fn deliver_pending_signals(args: *mut SyscallArgs) {
    use core::sync::atomic::Ordering;

    let pid = match crate::current::current_pid() {
        Some(p) => p,
        None => return,
    };

    // Snapshot pending signals and capture each one's action so we can
    // drop the table borrow before user-mode delivery side-effects.
    //
    // SAFETY: single-CPU SYSCALL context.
    let snapshot = unsafe {
        let table = crate::fork_dispatch::process_table_mut();
        let entry = match table.get_mut(pid) {
            Some(e) => e,
            None => return,
        };
        let mut snap: [(Signal, SignalAction); Signal::MAX as usize] =
            [(Signal(0), SignalAction::Default); Signal::MAX as usize];
        let mut count = 0usize;
        for bit in 0..Signal::MAX {
            let sig = Signal(bit + 1);
            if entry.signals.pending.is_pending(sig) && !entry.signals.mask.is_blocked(sig) {
                snap[count] = (sig, entry.signals.get_action(sig));
                entry.signals.pending.clear(sig);
                count += 1;
            }
        }
        if count == 0 {
            return;
        }
        (snap, count)
    };
    let (snap, count) = snapshot;

    for entry in snap.iter().take(count) {
        let (sig, action) = *entry;
        match action {
            SignalAction::Handler(handler_rip) => {
                // The exception-path caller (#PF) passes a null `args`
                // because no SyscallArgs frame exists in fault context.
                // Without it we cannot plant `RDI = signum` for the
                // handler, so fall back to the default action.
                if args.is_null() {
                    apply_default_action(sig);
                    continue;
                }
                // SAFETY: same single-CPU context; the saved-user atomics and
                // user backing region are the only resources mutated.
                if unsafe { deliver_user_handler(sig, handler_rip, args) }.is_err() {
                    // Handler delivery failed (couldn't write the user
                    // frame). Fall back to the default action so we
                    // still make progress on the bit.
                    apply_default_action(sig);
                }
                // Only one handler-style signal per syscall epilogue —
                // additional pending bits stay queued (already cleared
                // here, so they are effectively dropped under the
                // current Phase 19 semantics; a later batch will
                // restore queueing once a real per-process pending list
                // exists).
                return;
            }
            SignalAction::Ignore => {
                // Already cleared from pending above.
            }
            SignalAction::Default => {
                apply_default_action(sig);
            }
        }
    }

    // Silence "potentially unused" warnings for the saved-RFLAGS atomic
    // when this function compiles without exercising every branch.
    let _ = SYSCALL_SAVED_USER_RFLAGS.load(Ordering::Relaxed);
}

/// Build a user-stack signal frame, plant the trampoline pretcode, and
/// redirect the SYSCALL epilogue to invoke the handler.
///
/// # Safety
///
/// Must be called from the SYSCALL dispatch path on the single CPU.
/// `args` must be the live `SyscallArgs` pointer so writing `arg0`
/// survives the dispatcher return into the SYSRET epilogue.
unsafe fn deliver_user_handler(
    sig: Signal,
    handler_rip: u64,
    args: *mut SyscallArgs,
) -> Result<()> {
    use core::sync::atomic::Ordering;

    // Snapshot the current user-mode context.
    let saved_rip = SYSCALL_SAVED_USER_RIP.load(Ordering::Relaxed);
    let saved_rsp = SYSCALL_SAVED_USER_RSP.load(Ordering::Relaxed);
    let saved_rflags = SYSCALL_SAVED_USER_RFLAGS.load(Ordering::Relaxed);

    // Reject obviously-bogus user RSP — must be a non-null user-VA.
    if saved_rsp == 0 || saved_rsp >= 0x0000_8000_0000_0000 {
        return Err(Error::InvalidArgument);
    }

    // New stack layout (high → low addresses):
    //
    //   [old_rsp]                 ← top before delivery
    //   ...
    //   [old_rsp - FRAME_SIZE]    UserSignalFrame
    //   [old_rsp - FRAME_SIZE-8]  pretcode (= SIGRETURN_TRAMPOLINE_VA)  ← new RSP
    //
    // The trampoline at `SIGRETURN_TRAMPOLINE_VA` does
    // `lea -0x8(%rsp), %rdi` — i.e. the frame address is `rsp + 8`,
    // which equals `old_rsp - FRAME_SIZE` exactly.
    let frame_va = saved_rsp
        .checked_sub(FRAME_SIZE as u64)
        .ok_or(Error::InvalidArgument)?;
    let pretcode_va = frame_va.checked_sub(8).ok_or(Error::InvalidArgument)?;

    // Both writes target the user's mapped backing region. Single-CPU
    // SYSCALL context means the calling process's UAS is still live in
    // CR3, so user-VA stores hit the right physical frames.
    //
    // SAFETY: caller upholds the SYSCALL context invariant; user-VA
    // writes are aligned and within the per-process backing region
    // (the stack page lives at 0x5FF000 and the frame fits comfortably).
    unsafe {
        let frame_ptr = frame_va as *mut UserSignalFrame;
        frame_ptr.write_volatile(UserSignalFrame {
            magic: SIGFRAME_MAGIC,
            signum: sig.0 as u32,
            _pad: 0,
            saved_rip,
            saved_rsp,
            saved_rflags,
        });
        let pretcode_ptr = pretcode_va as *mut u64;
        pretcode_ptr.write_volatile(SIGRETURN_TRAMPOLINE_VA);
    }

    // Redirect the SYSCALL epilogue to the handler.
    SYSCALL_SAVED_USER_RIP.store(handler_rip, Ordering::Relaxed);
    SYSCALL_SAVED_USER_RSP.store(pretcode_va, Ordering::Relaxed);
    // RFLAGS is sanitised by the SYSRET epilogue regardless; keep the
    // saved value so a later sigreturn restores the same bits.

    // Plant RDI = signum so the System V handler signature
    // `void handler(int signum)` works. The SYSRET epilogue does
    // `pop rdi` from the stacked SyscallArgs immediately before
    // sysretq, so writing `args.arg0` here is observed by the user.
    //
    // SAFETY: caller guarantees `args` is the live SyscallArgs pointer.
    unsafe {
        (*args).arg0 = sig.0 as u64;
    }

    Ok(())
}

/// Restore the saved user context from a kernel-pushed signal frame.
///
/// Reads the [`UserSignalFrame`] at `frame_va`, validates its magic,
/// and writes the saved RIP/RSP/RFLAGS back into the SYSCALL exit
/// atomics so SYSRET resumes the interrupted instruction.
///
/// Returns 0 on success, `-EINVAL` when the magic is wrong or the
/// pointer is bogus.
///
/// # Safety
///
/// Must be called from the SYSCALL dispatch path. `frame_va` is taken
/// from user space and is treated with the same trust level as any
/// other user pointer — the magic check is the load-bearing defence.
pub unsafe fn do_sigreturn(frame_va: u64) -> i64 {
    use core::sync::atomic::Ordering;

    if frame_va == 0 || frame_va >= 0x0000_8000_0000_0000 {
        return -22; // EINVAL
    }
    if frame_va & 0x7 != 0 {
        return -22; // EINVAL — frame must be 8-byte aligned
    }

    // SAFETY: frame_va is a user-VA in the calling process's mapped
    // backing region; volatile read avoids any compiler reordering with
    // the subsequent store-to-atomics.
    let frame: UserSignalFrame = unsafe { (frame_va as *const UserSignalFrame).read_volatile() };

    if frame.magic != SIGFRAME_MAGIC {
        return -22; // EINVAL
    }

    // Restore the saved user context. The SYSCALL epilogue will
    // sysret/iretq into `saved_rip` with `RSP = saved_rsp` and a
    // sanitised RFLAGS derived from `saved_rflags`.
    SYSCALL_SAVED_USER_RIP.store(frame.saved_rip, Ordering::Relaxed);
    SYSCALL_SAVED_USER_RSP.store(frame.saved_rsp, Ordering::Relaxed);
    SYSCALL_SAVED_USER_RFLAGS.store(frame.saved_rflags, Ordering::Relaxed);

    // Returning 0 is fine — the value lands in RAX but the SYSRET
    // epilogue's RIP/RSP overwrite from the atomics takes precedence;
    // user code observes the return value of whatever syscall the
    // handler interrupted (we do not currently restore RAX from the
    // frame because the System V handler convention does not preserve
    // it across the call).
    0
}

/// Apply the kernel-default action for a signal that has no installed
/// user handler.
fn apply_default_action(sig: Signal) {
    match default_action(sig) {
        DefaultAction::Terminate => {
            let code = 128u64 + sig.0 as u64;
            // SAFETY: SYSCALL dispatch context — sys_exit transitions
            // the current thread to Exited and does not return.
            unsafe { crate::fork_dispatch::sys_exit(code) };
        }
        DefaultAction::Ignore => {
            // Pending bit was already cleared by the snapshot pass.
        }
    }
}

/// Kernel-default action for a signal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DefaultAction {
    Terminate,
    Ignore,
}

/// POSIX.1-2024 default-action lookup, restricted to what the kernel
/// can apply without job-control or core-dump support.
const fn default_action(sig: Signal) -> DefaultAction {
    match sig {
        Signal::SIGHUP
        | Signal::SIGINT
        | Signal::SIGQUIT
        | Signal::SIGABRT
        | Signal::SIGBUS
        | Signal::SIGKILL
        | Signal::SIGSEGV
        | Signal::SIGTERM => DefaultAction::Terminate,
        Signal::SIGCHLD | Signal::SIGCONT => DefaultAction::Ignore,
        Signal(23) | Signal(28) | Signal(29) => DefaultAction::Ignore,
        _ => DefaultAction::Ignore,
    }
}
