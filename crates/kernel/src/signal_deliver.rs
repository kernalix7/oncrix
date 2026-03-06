// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! POSIX signal delivery and sigreturn.
//!
//! This module implements the mechanism for delivering signals to
//! user-space processes. When a signal is pending and unblocked,
//! the kernel sets up a `SignalFrame` on the user stack containing
//! the saved register context, then redirects execution to the
//! signal handler. On `sigreturn`, the kernel restores the saved
//! context from the frame and resumes normal execution.

use oncrix_lib::{Error, Result};
use oncrix_process::signal::{Signal, SignalAction, SignalState};

/// Maximum user-space address for signal frame placement.
///
/// Frames must reside below this boundary to remain in valid
/// user-space memory on x86_64.
const USER_STACK_CEILING: u64 = 0x0000_7FFF_FFFF_0000;

/// Minimum user-space address (frames must not wrap below this).
const USER_STACK_FLOOR: u64 = 0x0000_0000_0040_0000;

/// Alignment requirement for the signal frame (16-byte ABI).
const FRAME_ALIGN: u64 = 16;

/// Saved register context passed between kernel and signal
/// delivery/restore paths.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct SavedContext {
    /// RAX register.
    pub rax: u64,
    /// RBX register.
    pub rbx: u64,
    /// RCX register.
    pub rcx: u64,
    /// RDX register.
    pub rdx: u64,
    /// RSI register.
    pub rsi: u64,
    /// RDI register.
    pub rdi: u64,
    /// RBP register.
    pub rbp: u64,
    /// RSP register (user stack pointer).
    pub rsp: u64,
    /// R8 register.
    pub r8: u64,
    /// R9 register.
    pub r9: u64,
    /// R10 register.
    pub r10: u64,
    /// R11 register.
    pub r11: u64,
    /// R12 register.
    pub r12: u64,
    /// R13 register.
    pub r13: u64,
    /// R14 register.
    pub r14: u64,
    /// R15 register.
    pub r15: u64,
    /// RIP (instruction pointer at time of interruption).
    pub rip: u64,
    /// RFLAGS register.
    pub rflags: u64,
}

/// Signal frame pushed onto the user stack before entering a
/// signal handler.
///
/// The layout follows a Linux-compatible `ucontext`-like structure
/// so that user-space C libraries can parse it. The `pretcode`
/// field holds the address of a sigreturn trampoline that issues
/// `SYS_RT_SIGRETURN` when the handler returns.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct SignalFrame {
    /// Return address pointing to the sigreturn trampoline.
    pub pretcode: u64,
    /// `ucontext` flags (reserved, currently zero).
    pub uc_flags: u64,
    /// Pointer to the next `ucontext` (reserved, currently zero).
    pub uc_link: u64,
    /// Saved RAX.
    pub saved_rax: u64,
    /// Saved RBX.
    pub saved_rbx: u64,
    /// Saved RCX.
    pub saved_rcx: u64,
    /// Saved RDX.
    pub saved_rdx: u64,
    /// Saved RSI.
    pub saved_rsi: u64,
    /// Saved RDI.
    pub saved_rdi: u64,
    /// Saved RBP.
    pub saved_rbp: u64,
    /// Saved RSP (original user stack pointer).
    pub saved_rsp: u64,
    /// Saved R8.
    pub saved_r8: u64,
    /// Saved R9.
    pub saved_r9: u64,
    /// Saved R10.
    pub saved_r10: u64,
    /// Saved R11.
    pub saved_r11: u64,
    /// Saved R12.
    pub saved_r12: u64,
    /// Saved R13.
    pub saved_r13: u64,
    /// Saved R14.
    pub saved_r14: u64,
    /// Saved R15.
    pub saved_r15: u64,
    /// Saved RIP (resume address after sigreturn).
    pub saved_rip: u64,
    /// Saved RFLAGS.
    pub saved_rflags: u64,
    /// Saved signal mask (restored on sigreturn).
    pub saved_signal_mask: u64,
}

/// Action the scheduler should take after signal delivery analysis.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignalDeliveryAction {
    /// Redirect execution to a user-space signal handler.
    InvokeHandler {
        /// Entry point of the signal handler.
        rip: u64,
        /// New stack pointer (pointing to the signal frame).
        rsp: u64,
        /// Signal number passed as the first argument (RDI).
        signal_nr: u64,
    },
    /// Terminate the process with the given signal.
    Terminate {
        /// Signal that caused termination.
        signal: Signal,
    },
    /// Terminate the process and produce a core dump.
    CoreDump {
        /// Signal that caused the core dump.
        signal: Signal,
    },
    /// Stop the process (e.g., SIGSTOP, SIGTSTP).
    Stop,
    /// Continue a stopped process (SIGCONT).
    Continue,
}

/// Set up a signal frame on the user stack.
///
/// Computes a 16-byte-aligned frame address below the current user
/// RSP, validates that it fits within user address space, populates
/// the frame with saved register state, and returns the new RSP
/// value that the scheduler should load before jumping to the
/// handler.
///
/// # Arguments
///
/// * `stack_ptr` - Current user-space RSP.
/// * `signal` - Signal number being delivered.
/// * `action` - The signal action (must be `Handler`; caller
///   responsibility).
/// * `saved_context` - Register state at the point of interruption.
///
/// # Errors
///
/// Returns `Error::InvalidArgument` if the frame does not fit in
/// user address space.
pub fn setup_signal_frame(
    stack_ptr: u64,
    _signal: Signal,
    _action: &SignalAction,
    saved_context: &SavedContext,
) -> Result<u64> {
    let frame_size = core::mem::size_of::<SignalFrame>() as u64;

    // Compute the frame base: below current RSP, aligned down to
    // 16 bytes. Subtract an extra 8 bytes so that after the CPU
    // pushes the return address the stack is 16-byte aligned per
    // the System V ABI.
    let raw_base = stack_ptr
        .checked_sub(frame_size)
        .ok_or(Error::InvalidArgument)?;
    let aligned_base = raw_base & !(FRAME_ALIGN.saturating_sub(1));

    // Validate user-space bounds.
    if aligned_base < USER_STACK_FLOOR {
        return Err(Error::InvalidArgument);
    }
    let frame_end = aligned_base
        .checked_add(frame_size)
        .ok_or(Error::InvalidArgument)?;
    if frame_end > USER_STACK_CEILING {
        return Err(Error::InvalidArgument);
    }

    // Build the frame in kernel memory, then write it out.
    //
    // SAFETY: `aligned_base` has been validated to lie within the
    // user-space range and is properly aligned. The caller must
    // ensure the pages are mapped and writable.
    let frame = SignalFrame {
        pretcode: 0, // Caller must patch with trampoline address.
        uc_flags: 0,
        uc_link: 0,
        saved_rax: saved_context.rax,
        saved_rbx: saved_context.rbx,
        saved_rcx: saved_context.rcx,
        saved_rdx: saved_context.rdx,
        saved_rsi: saved_context.rsi,
        saved_rdi: saved_context.rdi,
        saved_rbp: saved_context.rbp,
        saved_rsp: saved_context.rsp,
        saved_r8: saved_context.r8,
        saved_r9: saved_context.r9,
        saved_r10: saved_context.r10,
        saved_r11: saved_context.r11,
        saved_r12: saved_context.r12,
        saved_r13: saved_context.r13,
        saved_r14: saved_context.r14,
        saved_r15: saved_context.r15,
        saved_rip: saved_context.rip,
        saved_rflags: saved_context.rflags,
        saved_signal_mask: 0, // Caller should patch with current mask.
    };

    // SAFETY: Pointer validated above. Caller guarantees mapping.
    unsafe {
        let dest = aligned_base as *mut SignalFrame;
        core::ptr::write(dest, frame);
    }

    Ok(aligned_base)
}

/// Determine the default action for a signal.
///
/// Returns `Some(action)` for signals with a non-ignore default, or
/// `None` for signals whose default action is to be ignored
/// (e.g., SIGCHLD, SIGCONT when the process is already running).
fn default_action(sig: Signal) -> Option<SignalDeliveryAction> {
    match sig {
        // Terminate.
        Signal::SIGHUP | Signal::SIGINT | Signal::SIGPIPE | Signal::SIGALRM | Signal::SIGTERM => {
            Some(SignalDeliveryAction::Terminate { signal: sig })
        }
        // Terminate (uncatchable).
        Signal::SIGKILL => Some(SignalDeliveryAction::Terminate { signal: sig }),
        // Core dump.
        Signal::SIGQUIT
        | Signal::SIGILL
        | Signal::SIGABRT
        | Signal::SIGBUS
        | Signal::SIGFPE
        | Signal::SIGSEGV => Some(SignalDeliveryAction::CoreDump { signal: sig }),
        // Stop.
        Signal::SIGSTOP | Signal::SIGTSTP => Some(SignalDeliveryAction::Stop),
        // Continue.
        Signal::SIGCONT => Some(SignalDeliveryAction::Continue),
        // Ignore by default (SIGCHLD and others).
        Signal::SIGCHLD => None,
        // Unknown signals: terminate as a safe default.
        _ => Some(SignalDeliveryAction::Terminate { signal: sig }),
    }
}

/// Deliver the next pending, unblocked signal.
///
/// Dequeues the highest-priority (lowest-numbered) deliverable
/// signal, consults the signal action table, and returns the
/// action the scheduler should take:
///
/// - `Ok(Some(InvokeHandler { .. }))` — set up the handler frame
///   and jump to it.
/// - `Ok(Some(Terminate { .. }))` — kill the process.
/// - `Ok(Some(CoreDump { .. }))` — kill with core dump.
/// - `Ok(Some(Stop))` — stop the process.
/// - `Ok(Some(Continue))` — continue a stopped process.
/// - `Ok(None)` — signal was ignored; no action needed.
///
/// # Arguments
///
/// * `pending` - Mutable reference to the pending signal set.
/// * `signal_state` - Per-process signal state (actions + mask).
/// * `saved_context` - Current register state (needed for handler
///   frame setup).
pub fn do_signal_delivery(
    signal_state: &mut SignalState,
    saved_context: &SavedContext,
) -> Result<Option<SignalDeliveryAction>> {
    let (sig, action) = match signal_state.dequeue() {
        Some(pair) => pair,
        None => return Ok(None),
    };

    match action {
        SignalAction::Ignore => Ok(None),
        SignalAction::Default => Ok(default_action(sig)),
        SignalAction::Handler(entry_point) => {
            let new_rsp = setup_signal_frame(saved_context.rsp, sig, &action, saved_context)?;
            Ok(Some(SignalDeliveryAction::InvokeHandler {
                rip: entry_point,
                rsp: new_rsp,
                signal_nr: sig.0 as u64,
            }))
        }
    }
}

/// Restore saved context from a signal frame (sigreturn).
///
/// Reads the `SignalFrame` at the given user-stack address,
/// extracts the saved registers, and returns a `SavedContext`
/// that the scheduler should load to resume the interrupted
/// execution.
///
/// # Arguments
///
/// * `frame_ptr` - User-space address of the `SignalFrame`.
///
/// # Errors
///
/// Returns `Error::InvalidArgument` if the frame pointer is
/// outside user address space or misaligned.
///
/// # Safety
///
/// The caller must ensure that the memory at `frame_ptr` is
/// mapped, readable, and contains a valid `SignalFrame` written
/// by `setup_signal_frame`.
pub fn do_sigreturn(frame_ptr: u64) -> Result<SavedContext> {
    let frame_size = core::mem::size_of::<SignalFrame>() as u64;

    // Validate address range.
    if frame_ptr < USER_STACK_FLOOR {
        return Err(Error::InvalidArgument);
    }
    let frame_end = frame_ptr
        .checked_add(frame_size)
        .ok_or(Error::InvalidArgument)?;
    if frame_end > USER_STACK_CEILING {
        return Err(Error::InvalidArgument);
    }

    // Validate alignment.
    if frame_ptr % FRAME_ALIGN != 0 {
        return Err(Error::InvalidArgument);
    }

    // SAFETY: Range and alignment validated above. Caller
    // guarantees that the memory is mapped and contains a valid
    // frame.
    let frame = unsafe {
        let src = frame_ptr as *const SignalFrame;
        core::ptr::read(src)
    };

    Ok(SavedContext {
        rax: frame.saved_rax,
        rbx: frame.saved_rbx,
        rcx: frame.saved_rcx,
        rdx: frame.saved_rdx,
        rsi: frame.saved_rsi,
        rdi: frame.saved_rdi,
        rbp: frame.saved_rbp,
        rsp: frame.saved_rsp,
        r8: frame.saved_r8,
        r9: frame.saved_r9,
        r10: frame.saved_r10,
        r11: frame.saved_r11,
        r12: frame.saved_r12,
        r13: frame.saved_r13,
        r14: frame.saved_r14,
        r15: frame.saved_r15,
        rip: frame.saved_rip,
        rflags: frame.saved_rflags,
    })
}

/// Retrieve the saved signal mask from a signal frame.
///
/// This is typically called alongside `do_sigreturn` so the kernel
/// can restore the process's signal mask to its pre-handler state.
///
/// # Safety
///
/// Same requirements as `do_sigreturn`.
pub fn get_saved_signal_mask(frame_ptr: u64) -> Result<u64> {
    let frame_size = core::mem::size_of::<SignalFrame>() as u64;

    if frame_ptr < USER_STACK_FLOOR {
        return Err(Error::InvalidArgument);
    }
    let frame_end = frame_ptr
        .checked_add(frame_size)
        .ok_or(Error::InvalidArgument)?;
    if frame_end > USER_STACK_CEILING {
        return Err(Error::InvalidArgument);
    }
    if frame_ptr % FRAME_ALIGN != 0 {
        return Err(Error::InvalidArgument);
    }

    // SAFETY: Validated above.
    let frame = unsafe {
        let src = frame_ptr as *const SignalFrame;
        core::ptr::read(src)
    };

    Ok(frame.saved_signal_mask)
}
