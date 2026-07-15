// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! RISC-V 64-bit kernel thread creation and management.
//!
//! Mirror of [`crate::arch::aarch64::kthread`] for the riscv64 port.
//! Provides the ability to spawn kernel threads with their own stacks
//! and CPU contexts. Kernel threads run in supervisor mode (S-mode, the
//! RISC-V analogue of Ring 0) and are used for background tasks (idle
//! loop, init, housekeeping).
//!
//! The distinguishing riscv64 detail is the **seeded switch frame**:
//! [`spawn_kthread`] writes a 112-byte frame at the top of the new
//! thread's stack laid out exactly the way
//! [`switch_context`](super::context::switch_context) pops it, so the
//! very first switch *into* the thread restores zeroed callee-saved
//! registers and `ret`s straight to the entry point.

use super::context::CpuContext;
use oncrix_process::pid::{Pid, Tid, alloc_tid};
use oncrix_process::thread::{Priority, Thread};

/// Kernel thread stack size (16 KiB per thread).
///
/// Matches the x86_64 and aarch64 ports: 8 KiB is too small for threads
/// that nest function calls, 16 KiB matches the Linux kernel default.
const KTHREAD_STACK_SIZE: usize = 16384;

/// Maximum number of kernel threads.
const MAX_KTHREADS: usize = 32;

/// Size of the seeded [`switch_context`](super::context::switch_context)
/// restore frame, in bytes (13 × 8 = the `ra` + `s0`–`s11` callee-saved
/// set, rounded up to 112 for 16-byte alignment). A multiple of 16, so
/// subtracting it from a 16-aligned stack top keeps `sp` 16-aligned as
/// the RISC-V calling convention requires.
const SWITCH_FRAME_SIZE: u64 = 112;

/// Number of 8-byte slots spanned by the seeded frame (112 / 8 = 14:
/// `ra` + `s0`–`s11` = 13 live slots plus one alignment-padding slot).
const SWITCH_FRAME_SLOTS: u64 = SWITCH_FRAME_SIZE / 8;

/// 16-byte aligned stack buffer.
///
/// The RISC-V calling convention requires `sp` to be 16-byte aligned at a
/// procedure-call boundary. Wrapping the stack array ensures the base
/// address (and therefore every 16-aligned offset) is compliant.
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
/// Each thread gets a dedicated 16 KiB, 16-byte-aligned stack. Placed in
/// BSS so it does not bloat the kernel image.
static mut KTHREAD_STACKS: [AlignedStack; MAX_KTHREADS] = [AlignedStack::zero(); MAX_KTHREADS];

/// CPU contexts for kernel threads (parallel array with stacks).
static mut KTHREAD_CONTEXTS: [CpuContext; MAX_KTHREADS] =
    [const { CpuContext::empty() }; MAX_KTHREADS];

/// Allocation bitmap: true = slot in use.
static mut KTHREAD_USED: [bool; MAX_KTHREADS] = [false; MAX_KTHREADS];

/// Execute a closure with supervisor interrupts disabled, restoring the
/// previous `sstatus.SIE` interrupt-enable state on return.
///
/// RISC-V analogue of the aarch64 `DAIF` mask/restore helper: the current
/// `sstatus` is read while `SIE` (bit 1) is cleared in one atomic
/// `csrrci`, and on exit `SIE` is re-set only if it was set on entry — so
/// a caller that was already masked stays masked.
///
/// # Safety
///
/// The closure must not enable interrupts itself.
#[inline]
unsafe fn with_interrupts_disabled<F, R>(f: F) -> R
where
    F: FnOnce() -> R,
{
    /// `sstatus.SIE` — the global supervisor interrupt-enable bit.
    const SSTATUS_SIE: usize = 1 << 1;

    let prev: usize;
    // SAFETY: Critical-section entry — read the current `sstatus` into
    // `prev` and clear `SIE` (immediate `0b10`) atomically. No `nomem`:
    // toggling the global interrupt-enable is cli/sti-class and must act
    // as a compiler barrier so the closure's memory ops are not reordered
    // out of the critical section. `csrrci` has no memory/stack operand.
    unsafe {
        core::arch::asm!("csrrci {0}, sstatus, 0b10", out(reg) prev, options(nostack));
    }
    let result = f();
    // Re-set `SIE` only if it was set on entry (`restore` is `SIE` or 0).
    let restore = prev & SSTATUS_SIE;
    // SAFETY: Restore the captured interrupt-enable state. No `nomem` — the
    // enable is cli/sti-class and must fence the closure's memory ops. A
    // `csrs` of 0 sets no bits, so a previously-masked caller stays masked.
    unsafe {
        core::arch::asm!("csrs sstatus, {0}", in(reg) restore, options(nostack));
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
/// A 112-byte [`switch_context`](super::context::switch_context) restore
/// frame is seeded at the top of the thread's stack so that the first
/// switch *into* the thread pops zeroed callee-saved registers and `ret`s
/// to `entry`. The parallel [`CpuContext`] in the static pool is
/// initialised to point `sp` at that frame; callers copy it into the
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
    // (SIE-masked) to prevent races with trap handlers that might also
    // inspect thread state.

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

    // Compute the stack top. RISC-V stacks grow downward; the buffer is
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
    //   ld  sp, 0(a1)      ; sp <- new.sp = frame_base
    //   ld  ra, 0(sp)      ; ra  <- [frame_base + 0]   (return address)
    //   ld  s0, 8(sp)      ; s0  <- [frame_base + 8]
    //   ...
    //   ld  s11, 96(sp)    ; s11 <- [frame_base + 96]
    //   addi sp, sp, 112   ; sp = frame_base + 112 = stack_top
    //   ret                ; jump to ra
    //
    // So the only slot that matters is byte offset +0 (`ra` = the address
    // `ret` jumps to). Every other slot is a callee-saved GPR / alignment
    // pad we simply zero.
    //
    // SAFETY: Interrupts disabled; `frame_base .. frame_base + 112` lies
    // inside this slot's 16 KiB stack buffer, and we write our own context
    // array.
    let frame_base = stack_top - SWITCH_FRAME_SIZE;
    unsafe {
        with_interrupts_disabled(|| {
            // Zero all fourteen 8-byte slots of the frame.
            for i in 0..SWITCH_FRAME_SLOTS {
                let slot_ptr = (frame_base + i * 8) as *mut u64;
                *slot_ptr = 0;
            }
            // `ra` (return address) lives at offset +0 — `switch_context`
            // does `ld ra, 0(sp)` first.
            let ra_ptr = frame_base as *mut u64;
            *ra_ptr = entry as *const () as u64;

            let ctx_ptr = &raw mut KTHREAD_CONTEXTS;
            let ctx = &mut (*ctx_ptr)[slot];
            *ctx = CpuContext::empty();
            // CpuContext.sp is byte offset 0 — the value switch_context
            // loads into `sp` before popping the seeded frame.
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
/// context-switch datapath reads the seeded `sp`/`pc`.
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
