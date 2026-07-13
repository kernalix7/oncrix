// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! AArch64 kernel thread creation and management.
//!
//! Mirror of [`crate::arch::x86_64::kthread`] for the aarch64 port.
//! Provides the ability to spawn kernel threads with their own stacks
//! and CPU contexts. Kernel threads run at EL1 (Ring 0) and are used
//! for background tasks (idle loop, init, housekeeping).
//!
//! The distinguishing aarch64 detail is the **seeded switch frame**:
//! [`spawn_kthread`] writes a 96-byte frame at the top of the new
//! thread's stack laid out exactly the way
//! [`switch_context`](super::context::switch_context) pops it, so the
//! very first switch *into* the thread restores zeroed callee-saved
//! registers and `ret`s straight to the entry point.

use super::context::CpuContext;
use oncrix_process::pid::{Pid, Tid, alloc_tid};
use oncrix_process::thread::{Priority, Thread};

/// Kernel thread stack size (16 KiB per thread).
///
/// Matches the x86_64 port: 8 KiB is too small for threads that nest
/// function calls, 16 KiB matches the Linux kernel default.
const KTHREAD_STACK_SIZE: usize = 16384;

/// Maximum number of kernel threads.
const MAX_KTHREADS: usize = 32;

/// Size of the seeded [`switch_context`](super::context::switch_context)
/// restore frame, in bytes (12 × 8 = the `x19`–`x30` callee-saved set
/// plus the frame pointer). A multiple of 16, so subtracting it from a
/// 16-aligned stack top keeps `SP` 16-aligned as AArch64 requires.
const SWITCH_FRAME_SIZE: u64 = 96;

/// 16-byte aligned stack buffer.
///
/// The AAPCS64 procedure call standard requires `SP` to be 16-byte
/// aligned at a public interface. Wrapping the stack array ensures the
/// base address (and therefore every 16-aligned offset) is compliant.
#[repr(C, align(16))]
#[derive(Clone, Copy)]
struct AlignedStack([u8; KTHREAD_STACK_SIZE]);

impl AlignedStack {
    const fn zero() -> Self {
        Self([0; KTHREAD_STACK_SIZE])
    }
}

/// Static pool of kernel thread stacks.
///
/// Each thread gets a dedicated 16 KiB, 16-byte-aligned stack. Placed
/// in BSS so it does not bloat the kernel image.
static mut KTHREAD_STACKS: [AlignedStack; MAX_KTHREADS] = [AlignedStack::zero(); MAX_KTHREADS];

/// CPU contexts for kernel threads (parallel array with stacks).
static mut KTHREAD_CONTEXTS: [CpuContext; MAX_KTHREADS] =
    [const { CpuContext::empty() }; MAX_KTHREADS];

/// Allocation bitmap: true = slot in use.
static mut KTHREAD_USED: [bool; MAX_KTHREADS] = [false; MAX_KTHREADS];

/// Execute a closure with interrupts disabled, restoring the previous
/// `DAIF` interrupt-mask state on return.
///
/// AArch64 analogue of the x86_64 `pushfq`/`cli`/`sti` helper: the
/// current `DAIF` field is captured with `mrs`, all four masks
/// (`D`, `A`, `I`, `F`) are asserted with `msr daifset`, and the saved
/// state is written back verbatim with `msr daif` — so a caller that
/// was already masked stays masked.
///
/// # Safety
///
/// The closure must not enable interrupts itself.
#[inline]
unsafe fn with_interrupts_disabled<F, R>(f: F) -> R
where
    F: FnOnce() -> R,
{
    let daif: u64;
    // SAFETY: Critical-section entry — read the current DAIF mask into
    // `daif`, then mask all interrupts. `mrs`/`msr daifset` have no
    // memory operands and do not touch the stack.
    unsafe {
        core::arch::asm!(
            "mrs {0}, daif",
            "msr daifset, #0b1111",
            out(reg) daif,
            options(nomem, nostack),
        );
    }
    let result = f();
    // SAFETY: Restore the exact DAIF state captured above. `msr daif`
    // writes only the interrupt-mask PSTATE field.
    unsafe {
        core::arch::asm!("msr daif, {0}", in(reg) daif, options(nomem, nostack));
    }
    result
}

/// Kernel thread descriptor returned after spawning.
#[derive(Debug, Clone, Copy)]
pub struct KernelThread {
    /// Thread ID.
    pub tid: Tid,
    /// Slot index in the static pool.
    pub slot: usize,
}

/// Spawn a new kernel thread.
///
/// `entry` is the function the thread will execute. It must be
/// `extern "C" fn() -> !` (never returns).
///
/// A 96-byte [`switch_context`](super::context::switch_context) restore
/// frame is seeded at the top of the thread's stack so that the first
/// switch *into* the thread pops zeroed callee-saved registers and
/// `ret`s to `entry`. The parallel [`CpuContext`] in the static pool is
/// initialised to point `SP` at that frame; callers copy it into the
/// scheduler-owned [`Thread`] via [`kthread_context`].
///
/// Returns a [`KernelThread`] descriptor and a [`Thread`] for the
/// scheduler.
///
/// # Safety
///
/// `entry` must point to a valid kernel function that never returns.
pub unsafe fn spawn_kthread(
    entry: extern "C" fn() -> !,
    priority: Priority,
) -> oncrix_lib::Result<(KernelThread, Thread)> {
    // All access to the static arrays is wrapped in a critical section
    // (DAIF-masked) to prevent races with interrupt handlers that might
    // also inspect thread state.

    // Find a free slot.
    // SAFETY: Interrupts are disabled for the duration of the search,
    // preventing concurrent modification of the pool bitmap.
    let slot = unsafe {
        with_interrupts_disabled(|| {
            let used_ptr = &raw mut KTHREAD_USED;
            let mut found = None;
            for (i, used) in (*used_ptr).iter_mut().enumerate() {
                if !*used {
                    *used = true;
                    found = Some(i);
                    break;
                }
            }
            found
        })
    }
    .ok_or(oncrix_lib::Error::OutOfMemory)?;

    // Compute the stack top. AArch64 stacks grow downward; the buffer is
    // 16-byte aligned via `AlignedStack` and `KTHREAD_STACK_SIZE` is a
    // multiple of 16, so `stack_top` is 16-aligned.
    // SAFETY: Interrupts disabled; raw pointer to our own pool.
    let stack_top = unsafe {
        with_interrupts_disabled(|| {
            let stacks_ptr = &raw const KTHREAD_STACKS;
            let base = (*stacks_ptr)[slot].0.as_ptr();
            base as u64 + KTHREAD_STACK_SIZE as u64
        })
    };

    // Seed the switch-context restore frame and the parallel CpuContext.
    //
    // `switch_context` restores the new thread with:
    //   ldp x19, x20, [sp, #80]
    //   ldp x21, x22, [sp, #64]
    //   ldp x23, x24, [sp, #48]
    //   ldp x25, x26, [sp, #32]
    //   ldp x27, x28, [sp, #16]
    //   ldp x29, x30, [sp], #96   ; x29 <- [sp+0], x30 <- [sp+8], sp += 96
    //   ret                        ; branch to x30
    //
    // So the only slot that matters is byte offset +8 (x30 = the address
    // `ret` jumps to). Every other slot is a callee-saved GPR / frame
    // pointer we simply zero.
    //
    // SAFETY: Interrupts disabled; `frame_base .. frame_base + 96` lies
    // inside this slot's 16 KiB stack buffer, and we write our own
    // context array.
    let frame_base = stack_top - SWITCH_FRAME_SIZE;
    unsafe {
        with_interrupts_disabled(|| {
            // Zero all twelve 8-byte slots of the frame.
            for i in 0..12u64 {
                let slot_ptr = (frame_base + i * 8) as *mut u64;
                *slot_ptr = 0;
            }
            // x30 (link register / return address) lives at offset +8.
            let x30_ptr = (frame_base + 8) as *mut u64;
            *x30_ptr = entry as *const () as u64;

            let ctx_ptr = &raw mut KTHREAD_CONTEXTS;
            let ctx = &mut (*ctx_ptr)[slot];
            *ctx = CpuContext::empty();
            // CpuContext.sp is byte offset 0 — the value switch_context
            // loads into SP before popping the seeded frame.
            ctx.sp = frame_base;
            ctx.pc = entry as *const () as u64;
        });
    }

    let tid = alloc_tid();
    let thread = Thread::new(tid, Pid::KERNEL, priority);

    let kt = KernelThread { tid, slot };

    Ok((kt, thread))
}

/// Get a pointer to a kernel thread's CPU context.
///
/// Callers copy the pointed-to [`CpuContext`] into the scheduler-owned
/// [`Thread`] (via [`Thread::set_cpu_context`]) so the scheduler's
/// context-switch datapath reads the seeded `SP`/`PC`.
///
/// # Safety
///
/// The slot must be a valid, in-use kernel thread slot.
pub unsafe fn kthread_context(slot: usize) -> *mut CpuContext {
    // SAFETY: Interrupts disabled to prevent concurrent modification.
    // The caller guarantees `slot` is valid.
    unsafe {
        with_interrupts_disabled(|| {
            let ctx_ptr = &raw mut KTHREAD_CONTEXTS;
            &raw mut (*ctx_ptr)[slot]
        })
    }
}

/// Free a kernel thread slot.
///
/// # Safety
///
/// The thread must no longer be scheduled or running.
pub unsafe fn free_kthread(slot: usize) {
    if slot < MAX_KTHREADS {
        // SAFETY: Interrupts disabled to prevent concurrent access;
        // `slot` is bounds-checked above.
        unsafe {
            with_interrupts_disabled(|| {
                let used_ptr = &raw mut KTHREAD_USED;
                (*used_ptr)[slot] = false;
            });
        }
    }
}
