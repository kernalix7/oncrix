// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! RISC-V 64-bit low-level context switch.
//!
//! The CPU register block is defined once in
//! [`oncrix_process::context::CpuContext`] — this module only provides
//! the assembly primitive that swaps callee-saved registers and the
//! kernel stack pointer between two [`CpuContext`] instances.

pub use oncrix_process::context::CpuContext;

/// Perform a context switch from `old` to `new`.
///
/// Saves the callee-saved integer registers (`ra`, `s0`–`s11`) onto
/// `old`'s kernel stack, stores the resulting `sp` at `old.sp` (byte
/// offset 0 of the non-x86 [`CpuContext`]), loads `new.sp`, restores the
/// callee-saved set from the new stack, and `ret`s into the new thread.
/// Caller-saved (temporary/argument) registers are the caller's
/// responsibility per the RISC-V calling convention, exactly as on the
/// x86_64 path.
///
/// # Safety
///
/// - `old` and `new` must point to valid [`CpuContext`] structs.
/// - `new.sp` must reference a kernel stack whose saved frame was produced
///   by a previous `switch_context` (or a fork-trampoline seed).
/// - Must be called with supervisor interrupts (`sstatus.SIE`) masked.
#[unsafe(naked)]
pub unsafe extern "C" fn switch_context(_old: *mut CpuContext, _new: *const CpuContext) {
    // SAFETY: Naked function — no prologue runs before the asm. The
    // callee-saved set is stored on the current (old) kernel stack, the
    // adjusted sp is written to `old.sp` (a0, offset 0), the new sp is
    // loaded from `new.sp` (a1, offset 0), the registers are reloaded from
    // the new stack, and `ret` (jalr x0, ra) branches to the restored
    // `ra`. a0/a1 hold the two pointer arguments per the RISC-V ABI.
    core::arch::naked_asm!(
        // Reserve a 112-byte frame (13 x 8, 16-byte aligned) and save
        // ra + s0-s11.
        "addi sp, sp, -112",
        "sd ra, 0(sp)",
        "sd s0, 8(sp)",
        "sd s1, 16(sp)",
        "sd s2, 24(sp)",
        "sd s3, 32(sp)",
        "sd s4, 40(sp)",
        "sd s5, 48(sp)",
        "sd s6, 56(sp)",
        "sd s7, 64(sp)",
        "sd s8, 72(sp)",
        "sd s9, 80(sp)",
        "sd s10, 88(sp)",
        "sd s11, 96(sp)",
        // old.sp = current sp  (CpuContext.sp is at byte offset 0).
        "sd sp, 0(a0)",
        // sp = new.sp
        "ld sp, 0(a1)",
        // Restore the callee-saved set from the new stack.
        "ld ra, 0(sp)",
        "ld s0, 8(sp)",
        "ld s1, 16(sp)",
        "ld s2, 24(sp)",
        "ld s3, 32(sp)",
        "ld s4, 40(sp)",
        "ld s5, 48(sp)",
        "ld s6, 56(sp)",
        "ld s7, 64(sp)",
        "ld s8, 72(sp)",
        "ld s9, 80(sp)",
        "ld s10, 88(sp)",
        "ld s11, 96(sp)",
        "addi sp, sp, 112",
        "ret",
    );
}
