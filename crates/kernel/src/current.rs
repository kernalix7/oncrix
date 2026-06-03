// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! "Current task" accessors for the rest of the kernel.
//!
//! The syscall-api and various subsystems need a uniform way to
//! reach the currently running thread / process without taking a
//! dependency on the arch-specific scheduler instance. This module
//! is the thin bridge: it consults the global [`SCHEDULER`]
//! populated during boot.
//!
//! [`SCHEDULER`]: crate::arch::x86_64::init::SCHEDULER
//!
//! # Single-CPU caveat
//!
//! These helpers assume a single CPU: they read/write the global
//! scheduler through a `static mut` raw pointer. Adding SMP will
//! require per-CPU storage (`swapgs` / GSBASE) and a per-CPU
//! `current_thread` pointer; that upgrade is deferred.

use crate::arch::x86_64::clone::{ForkSnapshot, arch_clone_thread};
use crate::arch::x86_64::init::{SCHEDULER, switch_tss_rsp0};
use crate::arch::x86_64::sched_glue::sched_yield_once;
use oncrix_lib::{Error, Result};
use oncrix_process::pid::{Pid, Tid};
use oncrix_process::thread::Thread;

/// Return a shared reference to the currently running thread.
///
/// Returns `None` when no thread is scheduled (e.g. very early
/// boot, before `init_scheduler` has added the idle thread).
///
/// # Safety
///
/// The returned borrow must not outlive the scheduler mutation
/// that picks a different thread. In practice all callers consume
/// it inside a single syscall or interrupt handler with interrupts
/// disabled, which upholds that invariant.
pub fn current_thread() -> Option<&'static Thread> {
    // SAFETY: SCHEDULER lives for the kernel's lifetime. Single-
    // CPU + interrupts-off context prevents aliased mutations.
    unsafe {
        #[allow(static_mut_refs)]
        let sched = &SCHEDULER;
        sched.current()
    }
}

/// Return a mutable reference to the currently running thread.
///
/// # Safety
///
/// Caller must ensure no other code concurrently accesses the
/// scheduler (interrupts off on the single CPU is sufficient).
/// The borrow must be dropped before any scheduler mutation that
/// could evict the current thread.
pub unsafe fn current_thread_mut() -> Option<&'static mut Thread> {
    // SAFETY: Exclusive access guaranteed by the caller (single-
    // CPU + interrupts off). We erase the scheduler borrow by
    // going through a raw mut pointer.
    unsafe {
        #[allow(static_mut_refs)]
        let sched = &mut SCHEDULER;
        sched.current_mut()
    }
}

/// Return the TID of the currently running thread, if any.
pub fn current_tid() -> Option<Tid> {
    current_thread().map(|t| t.tid())
}

/// Return the PID of the process that owns the currently running
/// thread, if any.
pub fn current_pid() -> Option<Pid> {
    current_thread().map(|t| t.pid())
}

/// Yield the CPU to the next runnable thread.
///
/// Wraps [`sched_yield_once`] so callers in other crates (syscall
/// handlers, IPC waiters) don't need to reach into arch-specific
/// modules. Returns `true` if a switch happened.
///
/// # Safety
///
/// Must be called with interrupts disabled. Caller must hold no
/// scheduler borrow.
pub unsafe fn yield_now() -> bool {
    // SAFETY: caller contract: interrupts off; no scheduler borrow.
    unsafe {
        #[allow(static_mut_refs)]
        let sched = &mut SCHEDULER;
        sched_yield_once(sched)
    }
}

/// Register a freshly-built thread with the scheduler.
///
/// Handed a `Thread` produced by `arch_clone_thread` or similar
/// factory; the thread must already be in the `Ready` state with
/// a live kernel stack.
///
/// # Safety
///
/// Single-CPU / interrupts-off requirement as with the other
/// accessors.
pub unsafe fn spawn_thread(thread: Thread) -> Result<Tid> {
    let tid = thread.tid();
    // SAFETY: see module-level note.
    unsafe {
        #[allow(static_mut_refs)]
        let sched = &mut SCHEDULER;
        sched.add(thread)?;
    }
    Ok(tid)
}

/// Install the currently running thread's kernel stack into
/// `TSS.RSP0`.
///
/// Used after clone-style transitions or whenever code outside
/// the scheduler needs to guarantee that the trap stack matches
/// the active thread (e.g. after the first jump to ring 3).
///
/// # Safety
///
/// Must be called with interrupts disabled.
pub unsafe fn sync_tss_rsp0_with_current() {
    let top = current_thread().map(|t| t.kernel_stack_top()).unwrap_or(0);
    // SAFETY: caller contract: interrupts off.
    unsafe { switch_tss_rsp0(top) };
}

// ── Fork bridge for syscall-api ────────────────────────────────

/// Build a child thread from a fork [`ForkSnapshot`] and register
/// it with the scheduler.
///
/// This is the entry point other crates (`oncrix_syscall::clone_call`
/// in particular) call to complete a `fork()`: the mm-subsystem
/// delivers a fresh `Cr3Frame` via `UserAddressSpace::clone_for_fork`,
/// the caller packages it along with the parent's user register
/// snapshot into a [`ForkSnapshot`], and we do the rest — allocate
/// the child's kernel stack, seed the `iretq` frame, hand the child
/// to the scheduler, and return the child TID.
///
/// # Errors
///
/// * `NotFound` — no current thread to clone from.
/// * `InvalidArgument` — `snapshot.child_cr3 == Cr3Frame::NONE`.
/// * `OutOfMemory` — kernel heap exhausted.
///
/// # Safety
///
/// Must be called with interrupts disabled on a single CPU.
pub unsafe fn fork_current(snapshot: ForkSnapshot) -> Result<Tid> {
    let parent = current_thread().ok_or(Error::NotFound)?;
    let child = arch_clone_thread(parent, &snapshot)?;

    // `arch_clone_thread` has already bumped the fd-backend refcounts of every
    // inherited handle. If `spawn_thread` fails (e.g. the scheduler table is
    // full → `OutOfMemory`), `child` is moved into `add` and dropped without
    // any `Drop` impl rebalancing those out-of-band counts. Snapshot the
    // inherited backends now so the error path can release each bump.
    let mut inherited = [None; oncrix_process::fd_table::MAX_FDS];
    let mut n_inherited = 0usize;
    for (_fd, handle) in child.fd_table.iter() {
        inherited[n_inherited] = Some(handle.backend);
        n_inherited += 1;
    }

    // SAFETY: module-level invariants.
    match unsafe { spawn_thread(child) } {
        Ok(tid) => Ok(tid),
        Err(e) => {
            // Undo each inherited backend bump before propagating the error;
            // `child` is already gone, so we use the pre-snapshotted list.
            for backend in inherited.iter().take(n_inherited).flatten() {
                // SAFETY: single-CPU SYSCALL context; backends came from the
                // child table whose refcounts `arch_clone_thread` bumped.
                unsafe { crate::fd_table::undo_backend_refcount_bump(*backend) };
            }
            Err(e)
        }
    }
}
