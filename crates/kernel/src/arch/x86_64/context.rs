// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! x86_64 context switching.
//!
//! Saves and restores callee-saved registers (System V AMD64 ABI)
//! plus the stack pointer. This is a cooperative-style context switch
//! invoked by the scheduler; the hardware interrupt handler pushes
//! the interrupt frame separately.

/// CPU context saved across a context switch.
///
/// Only callee-saved registers need to be explicitly saved. The
/// compiler handles caller-saved registers, and the stack pointer
/// captures the rest of the execution context.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct CpuContext {
    /// RBX (callee-saved).
    pub rbx: u64,
    /// RBP (frame pointer, callee-saved).
    pub rbp: u64,
    /// R12 (callee-saved).
    pub r12: u64,
    /// R13 (callee-saved).
    pub r13: u64,
    /// R14 (callee-saved).
    pub r14: u64,
    /// R15 (callee-saved).
    pub r15: u64,
    /// RSP (stack pointer — stored separately during switch).
    pub rsp: u64,
    /// RIP (instruction pointer — return address on the stack).
    pub rip: u64,
}

impl CpuContext {
    /// Create a zeroed context.
    pub const fn empty() -> Self {
        Self {
            rbx: 0,
            rbp: 0,
            r12: 0,
            r13: 0,
            r14: 0,
            r15: 0,
            rsp: 0,
            rip: 0,
        }
    }

    /// Create a context for a new thread.
    ///
    /// `entry` is the function pointer to start executing.
    /// `stack_top` is the top of the thread's kernel stack.
    pub const fn new(entry: u64, stack_top: u64) -> Self {
        Self {
            rbx: 0,
            rbp: 0,
            r12: 0,
            r13: 0,
            r14: 0,
            r15: 0,
            rsp: stack_top,
            rip: entry,
        }
    }
}

/// Perform a context switch from `old` to `new`.
///
/// Saves callee-saved registers into `old`, then restores them from
/// `new` and jumps to the new context's return address.
///
/// # Safety
///
/// - Both `old` and `new` must point to valid `CpuContext` structs.
/// - `new` must contain a valid stack pointer and instruction pointer.
/// - Must be called with interrupts disabled.
pub unsafe fn switch_context(old: *mut CpuContext, new: *const CpuContext) {
    // SAFETY: Inline assembly performs a standard context switch.
    // The callee-saved registers are pushed onto the old stack,
    // the stack pointer is saved, then restored from the new context,
    // and callee-saved registers are popped.
    unsafe {
        core::arch::asm!(
            // Save callee-saved registers of current context.
            "push rbx",
            "push rbp",
            "push r12",
            "push r13",
            "push r14",
            "push r15",
            // Save current stack pointer into old context.
            "mov [rdi + 48], rsp",  // old.rsp = current rsp
            // Load new stack pointer from new context.
            "mov rsp, [rsi + 48]",  // rsp = new.rsp
            // Restore callee-saved registers of new context.
            "pop r15",
            "pop r14",
            "pop r13",
            "pop r12",
            "pop rbp",
            "pop rbx",
            // Return (pops return address from new stack).
            "ret",
            in("rdi") old,
            in("rsi") new,
            options(noreturn),
        );
    }
}
