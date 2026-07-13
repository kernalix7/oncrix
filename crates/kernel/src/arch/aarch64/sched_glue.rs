// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! AArch64 scheduler plumbing (context-switch driver).
//!
//! Kernel-thread cooperative scheduling for the aarch64 bring-up port.
//! Unlike the x86_64 [`sched_glue`](crate::arch::x86_64::sched_glue),
//! this path deliberately does **no** userspace/TSS/CR3/syscall-mirror
//! work: aarch64 kernel threads all run at EL1 on the identity-mapped
//! address space installed by the boot stub (`TTBR0_EL1` is already
//! programmed), so a switch is just the callee-saved register swap
//! performed by [`switch_context`](super::context::switch_context).
//!
//! Per-process address spaces and the ring 0 → EL0 transition needed for
//! *user* threads are still unimplemented; those hooks live in
//! [`crate::arch::aarch64::init`] as no-ops.

use oncrix_process::context::Cr3Frame;
use oncrix_process::scheduler::RoundRobinScheduler;

/// Attempt one round-robin, kernel-thread-only cooperative switch.
///
/// Asks the scheduler for the next runnable thread via
/// [`RoundRobinScheduler::prepare_switch`]; if one exists, saves the
/// outgoing thread's callee-saved state and restores the incoming
/// thread's via [`switch_context`](super::context::switch_context).
///
/// Returns `true` if a switch actually happened, `false` if no other
/// ready thread was available (or the scheduler handed back a null
/// context pointer).
///
/// # Safety
///
/// * Must be called with interrupts (`DAIF`) masked.
/// * `sched` must be the live kernel scheduler whose threads own the
///   kernel stacks referenced by the saved contexts.
/// * The outgoing thread must be reachable again via its own
///   [`CpuContext`](oncrix_process::context::CpuContext) once the switch
///   completes.
pub unsafe fn sched_yield_once(sched: &mut RoundRobinScheduler) -> bool {
    let Some(t) = sched.prepare_switch() else {
        return false;
    };
    if t.prev_ctx.is_null() || t.next_ctx.is_null() {
        return false;
    }
    // Kernel threads share the identity-mapped address space (TTBR0_EL1
    // is already installed), so there is no CR3/TSS or per-process
    // page-table work to do around the switch — just swap register state.
    //
    // SAFETY: `prev_ctx`/`next_ctx` are non-null `CpuContext` pointers
    // owned by threads in `sched` (checked above); interrupts are masked
    // per this function's contract; `switch_context` upholds the AAPCS64
    // saved-frame invariant documented on it.
    unsafe {
        super::context::switch_context(t.prev_ctx, t.next_ctx);
    }
    true
}

/// Read the active address-space root (`TTBR0_EL1`).
///
/// The aarch64 analogue of reading `CR3`. Consumed by the
/// architecture-neutral fork dispatch; the aarch64 kernel-thread
/// scheduler does not otherwise need it (kernel threads keep the boot
/// `TTBR0_EL1`).
///
/// # Safety
///
/// Safe to call from any ring-0 (EL1) context; `mrs <reg>, ttbr0_el1`
/// is a privileged but side-effect-free system-register read.
pub unsafe fn read_cr3() -> Cr3Frame {
    let ttbr0: u64;
    // SAFETY: Reading `TTBR0_EL1` is privileged but has no side effects;
    // the ring-0 caller is legitimate by construction (kernel-only
    // module). No memory operand, no stack use.
    unsafe {
        core::arch::asm!("mrs {0}, ttbr0_el1", out(reg) ttbr0, options(nomem, nostack));
    }
    Cr3Frame::new(ttbr0)
}
