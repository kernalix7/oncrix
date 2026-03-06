// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Kernel thread creation and management.
//!
//! Provides the ability to spawn kernel threads with their own stacks
//! and CPU contexts. Kernel threads run at Ring 0 and are used for
//! background tasks (idle loop, init, housekeeping).

use super::context::CpuContext;
use oncrix_hal::arch::x86_64::uart::{COM1, Uart16550};
use oncrix_hal::serial::SerialPort;
use oncrix_process::pid::{Pid, Tid, alloc_tid};
use oncrix_process::thread::{Priority, Thread};

/// Kernel thread stack size (8 KiB per thread).
const KTHREAD_STACK_SIZE: usize = 8192;

/// Maximum number of kernel threads.
const MAX_KTHREADS: usize = 32;

/// Static pool of kernel thread stacks.
///
/// Each thread gets a dedicated 8 KiB stack from this pool.
/// In BSS, so doesn't bloat the kernel image.
static mut KTHREAD_STACKS: [[u8; KTHREAD_STACK_SIZE]; MAX_KTHREADS] =
    [[0; KTHREAD_STACK_SIZE]; MAX_KTHREADS];

/// CPU contexts for kernel threads (parallel array with stacks).
static mut KTHREAD_CONTEXTS: [CpuContext; MAX_KTHREADS] =
    [const { CpuContext::empty() }; MAX_KTHREADS];

/// Allocation bitmap: true = slot in use.
static mut KTHREAD_USED: [bool; MAX_KTHREADS] = [false; MAX_KTHREADS];

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
/// Returns a `KernelThread` descriptor and a `Thread` for the
/// scheduler.
///
/// # Safety
///
/// `entry` must point to a valid kernel function that never returns.
pub unsafe fn spawn_kthread(
    entry: extern "C" fn() -> !,
    priority: Priority,
) -> oncrix_lib::Result<(KernelThread, Thread)> {
    // Find a free slot.
    // SAFETY: Single-threaded boot context or called with interrupts
    // disabled during runtime.
    let slot = unsafe {
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
    }
    .ok_or(oncrix_lib::Error::OutOfMemory)?;

    // Compute stack top (stacks grow downward on x86_64).
    // SAFETY: Raw pointer to static array.
    let stack_top = unsafe {
        let stacks_ptr = &raw const KTHREAD_STACKS;
        let base = (*stacks_ptr)[slot].as_ptr();
        base as u64 + KTHREAD_STACK_SIZE as u64
    };

    // Initialize the CPU context.
    //
    // The context switch code expects callee-saved registers pushed
    // on the stack with a return address at the top. We set up the
    // stack so that when the context is "restored", it pops zeroed
    // registers and then `ret` jumps to `entry`.
    //
    // Stack layout (growing down):
    //   [stack_top - 8]  = entry (return address for `ret`)
    //   [stack_top - 16] = 0 (r15)
    //   [stack_top - 24] = 0 (r14)
    //   [stack_top - 32] = 0 (r13)
    //   [stack_top - 40] = 0 (r12)
    //   [stack_top - 48] = 0 (rbp)
    //   [stack_top - 56] = 0 (rbx)
    //   RSP points here ^
    // SAFETY: Writing to our own stack buffer.
    unsafe {
        let ret_addr_ptr = (stack_top - 8) as *mut u64;
        *ret_addr_ptr = entry as *const () as u64;

        // Zero out the 6 callee-saved register slots.
        for i in 1..7 {
            let slot_ptr = (stack_top - 8 - i * 8) as *mut u64;
            *slot_ptr = 0;
        }

        let ctx_ptr = &raw mut KTHREAD_CONTEXTS;
        (*ctx_ptr)[slot] = CpuContext::new(
            entry as *const () as u64,
            stack_top - 56, // RSP after 7 pushes (ret + 6 regs)
        );
    }

    let tid = alloc_tid();
    let thread = Thread::new(tid, Pid::KERNEL, priority);

    let kt = KernelThread { tid, slot };

    Ok((kt, thread))
}

/// Get a pointer to a kernel thread's CPU context.
///
/// # Safety
///
/// The slot must be a valid, in-use kernel thread slot.
pub unsafe fn kthread_context(slot: usize) -> *mut CpuContext {
    unsafe {
        let ctx_ptr = &raw mut KTHREAD_CONTEXTS;
        &raw mut (*ctx_ptr)[slot]
    }
}

/// Free a kernel thread slot.
///
/// # Safety
///
/// The thread must no longer be scheduled or running.
pub unsafe fn free_kthread(slot: usize) {
    if slot < MAX_KTHREADS {
        unsafe {
            let used_ptr = &raw mut KTHREAD_USED;
            (*used_ptr)[slot] = false;
        }
    }
}

/// Idle thread entry point — halts until the next interrupt.
pub extern "C" fn idle_thread_entry() -> ! {
    loop {
        // SAFETY: `hlt` halts until an interrupt wakes us.
        unsafe {
            core::arch::asm!("hlt", options(nomem, nostack));
        }
    }
}

/// Init thread entry point — placeholder for the first user-space
/// process launcher.
pub extern "C" fn init_thread_entry() -> ! {
    let mut serial = Uart16550::new(COM1);
    let _ = serial.write_str("[ONCRIX] Init thread running\n");

    // In a full kernel, this would load and execute /sbin/init.
    // For now, just loop.
    loop {
        unsafe {
            core::arch::asm!("hlt", options(nomem, nostack));
        }
    }
}
