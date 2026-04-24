// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Architecture-specific scheduler plumbing.
//!
//! Wraps the generic [`RoundRobinScheduler`](oncrix_process::scheduler::RoundRobinScheduler)
//! with the x86_64 steps required on every context switch:
//!
//! 1. Install the incoming thread's 16 KiB kernel stack into
//!    `TSS.RSP0` so the next ring 3 → 0 trap lands on the right
//!    per-thread stack.
//! 2. Load the incoming thread's `CR3` when it changes, flushing
//!    the TLB and activating the thread's user address space.
//! 3. Perform the low-level context switch (save callee-saved
//!    state + swap RSP + ret into the new thread's pending work).
//!
//! The switch routine itself is implemented in
//! [`context::switch_context`](super::context::switch_context);
//! this module is the minimal driver that computes the arguments
//! and honours steps 1–2 around the call.

use super::clone::load_cr3;
use super::context::switch_context;
use super::init::switch_tss_rsp0;
use oncrix_process::context::{CpuContext, Cr3Frame};
use oncrix_process::scheduler::{RoundRobinScheduler, SwitchTargets};

/// Attempt one round-robin preemption.
///
/// If another runnable thread exists, swap it with the current one
/// by:
///
/// 1. Calling [`RoundRobinScheduler::prepare_switch`] to compute
///    the raw `prev`/`next` context pointers and the new kernel
///    stack top.
/// 2. Updating `TSS.RSP0` with the incoming stack.
/// 3. Reloading `CR3` if the incoming thread has a different
///    address space.
/// 4. Invoking the arch switch, which does not return on this side
///    until the outgoing thread is next resumed.
///
/// Returns `true` if a switch actually happened, `false` if no
/// other ready thread was available.
///
/// # Safety
///
/// * Must be called with interrupts disabled.
/// * `sched` must be the live kernel scheduler (the one whose
///   threads' kernel stacks are the authority for `TSS.RSP0`).
/// * The outgoing thread must be reachable again via its own
///   `CpuContext::rsp` once the switch completes.
pub unsafe fn sched_yield_once(sched: &mut RoundRobinScheduler) -> bool {
    let Some(targets) = sched.prepare_switch() else {
        return false;
    };
    let SwitchTargets {
        prev_ctx,
        next_ctx,
        next_kstack_top,
        next_tid: _,
    } = targets;

    if prev_ctx.is_null() || next_ctx.is_null() {
        return false;
    }

    // Step 1: update the trap stack BEFORE anything can trap.
    // SAFETY: Called with interrupts disabled per function contract.
    unsafe { switch_tss_rsp0(next_kstack_top) };

    // Step 2: if the incoming thread has an address space (user
    // thread), install it. Kernel threads leave `cr3 == NONE` so
    // we keep the current CR3 across them.
    //
    // SAFETY: We only dereference `next_ctx` which is a `*const`
    // obtained from `prepare_switch` above; it remains valid for
    // the duration of this call because no other code can mutate
    // the scheduler while interrupts are off on the single CPU.
    let incoming_cr3 = unsafe { (*next_ctx).cr3 };
    if !incoming_cr3.is_none() {
        // SAFETY: caller contract guarantees the Cr3Frame points
        // to a valid page table that keeps the kernel higher-half
        // mapped. See `load_cr3` docs.
        unsafe { load_cr3(incoming_cr3) };
    }

    // Step 3: perform the callee-saved register swap.
    // SAFETY: Both pointers are valid CpuContext instances owned
    // by threads in the scheduler, as documented on
    // `switch_context`.
    unsafe {
        switch_context(prev_ctx, next_ctx);
    }

    true
}

/// Install the given thread's context onto the CPU without a
/// counterpart save.
///
/// Used to jump-start the very first user thread after boot: there
/// is no "previous" thread whose state needs preserving. The call
/// does not return — execution resumes inside `ctx`.
///
/// # Safety
///
/// * Interrupts must be disabled.
/// * `ctx` must describe a fully-initialized thread (valid `rsp`
///   pointing at a seeded kernel stack, valid `cr3`, etc.).
/// * `kernel_stack_top` must be the top of that thread's private
///   kernel stack (or `0` to leave the global stack installed).
pub unsafe fn jump_into_thread(ctx: &CpuContext, kernel_stack_top: u64) -> ! {
    // SAFETY: caller contract: interrupts off.
    unsafe { switch_tss_rsp0(kernel_stack_top) };

    if !ctx.cr3.is_none() {
        // SAFETY: see `sched_yield_once`.
        unsafe { load_cr3(ctx.cr3) };
    }

    // We construct a throwaway dummy CpuContext on our current
    // stack to satisfy `switch_context`'s "save prev" contract;
    // its contents are never read back.
    let mut dummy = CpuContext::empty();
    // SAFETY: `dummy` lives for the duration of the call; `ctx`
    // is the caller's reference. Both pointers are valid. The
    // switch does not return on this thread, so `dummy` being
    // clobbered is fine.
    unsafe {
        switch_context(&mut dummy as *mut _, ctx as *const _);
    }
    // `switch_context` is declared `noreturn`; this loop satisfies
    // the `!` return type for the compiler without emitting code.
    #[allow(clippy::empty_loop)]
    loop {}
}

/// Cr3Frame for the current CPU's active address space.
///
/// Reads the `CR3` register. Mostly used for sanity checks in
/// debug paths; routine scheduling should trust the per-thread
/// `CpuContext::cr3` instead.
///
/// # Safety
///
/// Safe to call from any ring-0 context; `mov <reg>, cr3` is
/// privileged but has no side effects.
pub unsafe fn read_cr3() -> Cr3Frame {
    let phys: u64;
    // SAFETY: Reading CR3 is a privileged but idempotent
    // operation; the ring-0 caller is legitimate by construction
    // (kernel-only module).
    unsafe {
        core::arch::asm!(
            "mov {0}, cr3",
            out(reg) phys,
            options(nomem, nostack, preserves_flags),
        );
    }
    Cr3Frame::new(phys)
}
