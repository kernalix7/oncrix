// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! x86_64 low-level context switch.
//!
//! The CPU register block is defined once in
//! [`oncrix_process::context::CpuContext`] — this module only provides
//! the assembly primitive that swaps callee-saved registers and the
//! kernel stack pointer between two [`CpuContext`] instances.

pub use oncrix_process::context::CpuContext;

/// Perform a context switch from `old` to `new`.
///
/// Saves callee-saved registers into `old`'s kernel stack, stores the
/// current `RSP` at `old.rsp` (offset 48), loads `new.rsp`, pops
/// callee-saved registers, and returns into the new thread.
///
/// Both structs share the same memory layout: `rsp` is at byte offset
/// 48 in `oncrix_process::context::CpuContext` so the inline assembly
/// can access it directly by field offset.
///
/// # Safety
///
/// - `old` and `new` must point to valid `CpuContext` structs.
/// - `new.rsp` must reference a kernel stack whose top-of-stack word is
///   a valid return target (either the previous caller of
///   `switch_context` or a fork-trampoline seed).
/// - Must be called with interrupts disabled.
#[unsafe(naked)]
pub unsafe extern "C" fn switch_context(_old: *mut CpuContext, _new: *const CpuContext) {
    // SAFETY: Naked function — no prologue runs before the asm. The
    // callee-saved set is pushed on the *current* (old) kernel stack,
    // the stack pointer is stored into old.rsp (offset 48), the new
    // stack pointer is loaded, registers are popped, and `ret`
    // transfers control to the new thread. All clobbers are covered
    // by the System V ABI callee-saved save/restore sequence below.
    core::arch::naked_asm!(
        "push rbx",
        "push rbp",
        "push r12",
        "push r13",
        "push r14",
        "push r15",
        "mov [rdi + 48], rsp",
        "mov rsp, [rsi + 48]",
        "pop r15",
        "pop r14",
        "pop r13",
        "pop r12",
        "pop rbp",
        "pop rbx",
        "ret",
    );
}
