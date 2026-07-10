// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! AArch64 low-level context switch.
//!
//! The CPU register block is defined once in
//! [`oncrix_process::context::CpuContext`] — this module only provides
//! the assembly primitive that swaps callee-saved registers and the
//! kernel stack pointer between two [`CpuContext`] instances.

pub use oncrix_process::context::CpuContext;

/// Perform a context switch from `old` to `new`.
///
/// Saves the AAPCS64 callee-saved GPRs (`x19`–`x28`), the frame pointer
/// (`x29`) and link register (`x30`) onto `old`'s kernel stack, stores the
/// resulting `SP` at `old.sp` (byte offset 0 of the non-x86
/// [`CpuContext`]), loads `new.sp`, restores the callee-saved set from the
/// new stack, and `ret`s into the new thread. Caller-saved registers are
/// the caller's responsibility per the procedure call standard, exactly as
/// on the x86_64 path.
///
/// # Safety
///
/// - `old` and `new` must point to valid [`CpuContext`] structs.
/// - `new.sp` must reference a kernel stack whose saved frame was produced
///   by a previous `switch_context` (or a fork-trampoline seed).
/// - Must be called with interrupts (DAIF) masked.
#[unsafe(naked)]
pub unsafe extern "C" fn switch_context(_old: *mut CpuContext, _new: *const CpuContext) {
    // SAFETY: Naked function — no prologue runs before the asm. The
    // callee-saved set is stored on the current (old) kernel stack via a
    // pre-indexed `stp`, the adjusted SP is written to `old.sp` (x0,
    // offset 0), the new SP is loaded from `new.sp` (x1, offset 0), the
    // registers are reloaded from the new stack, and `ret` branches to the
    // restored `x30`. x0/x1 hold the two pointer arguments per AAPCS64.
    core::arch::naked_asm!(
        // Reserve a 96-byte frame (12 x 8) and save x29/x30.
        "stp x29, x30, [sp, #-96]!",
        "stp x27, x28, [sp, #16]",
        "stp x25, x26, [sp, #32]",
        "stp x23, x24, [sp, #48]",
        "stp x21, x22, [sp, #64]",
        "stp x19, x20, [sp, #80]",
        // old.sp = current SP  (CpuContext.sp is at byte offset 0).
        "mov x9, sp",
        "str x9, [x0]",
        // SP = new.sp
        "ldr x9, [x1]",
        "mov sp, x9",
        // Restore the callee-saved set from the new stack.
        "ldp x19, x20, [sp, #80]",
        "ldp x21, x22, [sp, #64]",
        "ldp x23, x24, [sp, #48]",
        "ldp x25, x26, [sp, #32]",
        "ldp x27, x28, [sp, #16]",
        "ldp x29, x30, [sp], #96",
        "ret",
    );
}
