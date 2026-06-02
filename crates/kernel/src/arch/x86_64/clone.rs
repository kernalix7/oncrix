// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! x86_64 implementation of the architecture-specific half of
//! [`fork(2)`](https://pubs.opengroup.org/onlinepubs/9699919799/functions/fork.html).
//!
//! This module builds a child thread whose kernel stack is
//! pre-seeded with an `iretq` frame, so that the first time the
//! scheduler dispatches into it the CPU lands in ring 3 at
//! *exactly* the same instruction the parent was about to execute
//! after its own `SYSCALL`, but with `RAX = 0` (the fork return
//! value in the child).
//!
//! # Stack layout produced
//!
//! The child's 16 KiB kernel stack is laid out (high → low) as:
//!
//! ```text
//!   [top-0x08]  SS     = USER_DATA | 3  = 0x1B
//!   [top-0x10]  RSP    = child_user_rsp
//!   [top-0x18]  RFLAGS = parent's RFLAGS (IF=1, reserved bit 1=1)
//!   [top-0x20]  CS     = USER_CODE | 3  = 0x23
//!   [top-0x28]  RIP    = child_rip (user return address)
//!   [top-0x30]  ret    = address of fork_trampoline (return target
//!                        of the context-switch `ret`)
//!   [top-0x38]  rbx    = 0  (consumed by the final `pop rbx`)
//!   [top-0x40]  rbp    = 0
//!   [top-0x48]  r12    = 0
//!   [top-0x50]  r13    = 0
//!   [top-0x58]  r14    = 0
//!   [top-0x60]  r15    = 0  (consumed by the first `pop r15`)
//! ```
//!
//! The [`CpuContext`] `rsp` field is set to `top-0x60`. The scheduler's
//! `switch_context` does `pop r15/r14/r13/r12/rbp/rbx; ret`, which
//! consumes the 6 zero words and then lands on `fork_trampoline`.
//! The trampoline zeroes `RAX` and issues `iretq` against the
//! remaining 40 bytes — delivering control to ring 3.

use oncrix_hal::arch::x86_64::gdt::selector;
use oncrix_lib::{Error, Result};
use oncrix_process::context::{CpuContext, Cr3Frame};
use oncrix_process::pid::{Pid, alloc_tid};
use oncrix_process::thread::{Priority, Thread};

/// RFLAGS bit 1 (always 1).
const RFLAGS_RESERVED: u64 = 1 << 1;
/// RFLAGS.IF — interrupts enabled when the child resumes in ring 3.
const RFLAGS_IF: u64 = 1 << 9;

/// User `SS` selector (USER_DATA, RPL=3).
const USER_SS: u64 = selector::USER_DATA as u64;
/// User `CS` selector (USER_CODE, RPL=3).
const USER_CS: u64 = selector::USER_CODE as u64;

/// Size of the `iretq` frame pushed onto the child stack: 5×u64.
const IRETQ_FRAME_BYTES: usize = 5 * 8;
/// Offset (from stack top) of the `fork_trampoline` return address —
/// this sits directly above the 6 callee-saved register slots.
const TRAMPOLINE_OFFSET: usize = IRETQ_FRAME_BYTES + 8;
/// Total bytes pre-seeded on the child stack: iretq frame (40 B) +
/// trampoline return address (8 B) + 6 callee-saved register slots
/// (48 B) that `switch_context` pops before `ret`.
const SEED_BYTES: usize = TRAMPOLINE_OFFSET + 6 * 8;

/// Trampoline executed the first time a freshly-forked child is
/// dispatched.
///
/// The scheduler's context-switch routine returns here (because the
/// bottom-most pre-seeded word on the child stack is the address of
/// this function). The trampoline zeroes `RAX` — so that `fork()`
/// returns 0 in the child — and issues `iretq` to descend into ring 3
/// using the five user-mode words sitting on the stack just above it.
///
/// # Safety
///
/// Must be the target of a `ret` whose stack has been pre-seeded by
/// [`arch_clone_thread`]. Any other entry will deliver `iretq` with
/// undefined kernel data as the user frame — a privilege escalation.
#[unsafe(no_mangle)]
#[unsafe(naked)]
pub extern "C" fn fork_trampoline() {
    // SAFETY: Entered via `ret` from the scheduler context-switch
    // with the stack laid out as documented above. `iretq` pops
    // RIP/CS/RFLAGS/RSP/SS and transitions to ring 3. RAX is
    // cleared so the child observes `fork()` returning 0. All
    // other GP registers are zeroed to prevent leaking kernel
    // state (stack addresses, register spills) to user space.
    core::arch::naked_asm!(
        "xor rax, rax",
        "xor rbx, rbx",
        "xor rcx, rcx",
        "xor rdx, rdx",
        "xor rsi, rsi",
        "xor rdi, rdi",
        "xor rbp, rbp",
        "xor r8, r8",
        "xor r9, r9",
        "xor r10, r10",
        "xor r11, r11",
        "xor r12, r12",
        "xor r13, r13",
        "xor r14, r14",
        "xor r15, r15",
        "iretq",
    );
}

/// Parent context snapshot used to build the child.
///
/// Captured by the syscall entry path after it saves the user
/// register set. The kernel creates a `ForkSnapshot` from those
/// saved values, then hands it plus the child's new address space
/// to [`arch_clone_thread`].
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct ForkSnapshot {
    /// Parent's user-mode RIP (the instruction after the `SYSCALL`).
    pub user_rip: u64,
    /// Parent's user-mode RSP.
    pub user_rsp: u64,
    /// Parent's user-mode RFLAGS.
    pub user_rflags: u64,
    /// Child's priority (inherit from parent).
    pub priority: Priority,
    /// Child's address-space root (from `UserAddressSpace::clone_for_fork`).
    pub child_cr3: Cr3Frame,
    /// Child's PID (pre-allocated by the caller).
    pub child_pid: Pid,
}

impl ForkSnapshot {
    /// Sanitize RFLAGS for ring 3: force `IF=1` and reserved bit 1,
    /// clear all privileged bits (IOPL, NT, TF, AC, VM, RF).
    pub const fn sanitized_rflags(&self) -> u64 {
        const SAFE_MASK: u64 = 0x003C_7FD7;
        (self.user_rflags & SAFE_MASK) | RFLAGS_RESERVED | RFLAGS_IF
    }
}

/// Build the child thread for a fork-like clone.
///
/// Allocates a fresh 16 KiB kernel stack, seeds it with an `iretq`
/// frame plus the [`fork_trampoline`] return address, fills in a
/// [`CpuContext`] whose `rsp` points to the top-most seeded word
/// and whose `cr3` is the child's address space, and returns the
/// fully-initialized [`Thread`] ready to hand to the scheduler.
///
/// The child's first register state when it reaches ring 3 will be:
/// * `RIP = snapshot.user_rip`
/// * `RSP = snapshot.user_rsp`
/// * `RAX = 0` (fork return value)
/// * `CS  = USER_CODE | 3`, `SS = USER_DATA | 3`
/// * `RFLAGS` sanitized to `IF=1` with all privileged bits cleared.
///
/// # Errors
///
/// * `OutOfMemory` — kernel heap exhausted while allocating the stack.
/// * `InvalidArgument` — the child CR3 is `NONE` (no address space)
///   or the seeding arithmetic overflowed.
pub fn arch_clone_thread(parent: &Thread, snapshot: &ForkSnapshot) -> Result<Thread> {
    if snapshot.child_cr3.is_none() {
        return Err(Error::InvalidArgument);
    }

    let child_tid = alloc_tid();
    let mut child = Thread::new(child_tid, snapshot.child_pid, snapshot.priority);
    child.ensure_kernel_stack()?;
    child.set_address_space(snapshot.child_cr3);

    // POSIX.1-2024: the child inherits the parent's cwd across fork(2).
    child.set_cwd(parent.cwd());

    // POSIX.1-2024 fork(3p): "the child inherits copies of the parent's
    // set of open file descriptors". Deep-copy the fd table; bump pipe
    // refcounts for each inherited Pipe fd so close semantics remain correct.
    child.fd_table = oncrix_process::fd_table::KernelFdTable::new();
    for (fd_idx, handle) in parent.fd_table.iter() {
        // Bump pipe refcounts so close on either thread decrements correctly.
        if let oncrix_process::fd_table::FileBackend::Pipe {
            ring_id,
            is_write_end,
        } = handle.backend
        {
            // SAFETY: single-CPU SYSCALL context; sole accessor of pipe table.
            unsafe {
                if is_write_end {
                    crate::pipe::pipe_dup_write(ring_id);
                } else {
                    crate::pipe::pipe_dup_read(ring_id);
                }
            }
        }
        // Bump both ring refcounts for a socketpair end so close on either
        // thread decrements correctly.
        if let oncrix_process::fd_table::FileBackend::SocketPair {
            read_ring,
            write_ring,
        } = handle.backend
        {
            // SAFETY: single-CPU SYSCALL context; sole accessor of pipe table.
            unsafe {
                crate::pipe::pipe_dup_read(read_ring);
                crate::pipe::pipe_dup_write(write_ring);
            }
        }
        // Bump eventfd refcount so close on either thread decrements correctly.
        if let oncrix_process::fd_table::FileBackend::EventFd { id } = handle.backend {
            // SAFETY: single-CPU SYSCALL context; sole accessor of eventfd table.
            unsafe { crate::fd_table::eventfd_dup(id) }
        }
        // Bump epoll refcount so close on either thread decrements correctly.
        if let oncrix_process::fd_table::FileBackend::EpollInstance { id } = handle.backend {
            // SAFETY: single-CPU SYSCALL context; sole accessor of epoll table.
            unsafe { crate::fd_table::epoll_dup(id) }
        }
        // Bump timerfd refcount so close on either thread decrements correctly.
        if let oncrix_process::fd_table::FileBackend::TimerFd { id } = handle.backend {
            // SAFETY: single-CPU SYSCALL context; sole accessor of timerfd table.
            unsafe { crate::fd_table::timerfd_dup(id) }
        }
        // Bump signalfd refcount so close on either thread decrements correctly.
        if let oncrix_process::fd_table::FileBackend::SignalFd { id } = handle.backend {
            // SAFETY: single-CPU SYSCALL context; sole accessor of signalfd table.
            unsafe { crate::fd_table::signalfd_dup(id) }
        }
        // Bump socket refcount so close on either thread decrements correctly.
        if let oncrix_process::fd_table::FileBackend::Socket { handle_id } = handle.backend {
            // SAFETY: single-CPU SYSCALL context; sole accessor of socket table.
            unsafe { crate::socket::socket_dup(handle_id) }
        }
        // Console, RamfsFile, DevFile, ProcFile: trivial copy, no refcount.
        let _ = child.fd_table.install_at(fd_idx, *handle);
    }

    let rflags = snapshot.sanitized_rflags();
    let user_rip = snapshot.user_rip;
    let user_rsp = snapshot.user_rsp;

    let ctx_rsp = {
        let stack = child.kernel_stack_mut().ok_or(Error::InvalidArgument)?;

        // Seed the iretq frame (high → low).
        let _ss = stack.write_u64_from_top(0x08, USER_SS)?;
        let _rsp = stack.write_u64_from_top(0x10, user_rsp)?;
        let _rfl = stack.write_u64_from_top(0x18, rflags)?;
        let _cs = stack.write_u64_from_top(0x20, USER_CS)?;
        let _rip = stack.write_u64_from_top(0x28, user_rip)?;

        // Seed the trampoline return address at top-0x30: this is what
        // the final `ret` inside `switch_context` pops into RIP.
        let _tr =
            stack.write_u64_from_top(TRAMPOLINE_OFFSET, fork_trampoline as *const () as u64)?;

        // Seed 6 zero slots for the callee-saved register pops that
        // `switch_context` does before `ret`. The lowest word's
        // address (top-0x60) is what the context-switch loads into
        // RSP when resuming this thread.
        let _rbx = stack.write_u64_from_top(TRAMPOLINE_OFFSET + 0x08, 0)?;
        let _rbp = stack.write_u64_from_top(TRAMPOLINE_OFFSET + 0x10, 0)?;
        let _r12 = stack.write_u64_from_top(TRAMPOLINE_OFFSET + 0x18, 0)?;
        let _r13 = stack.write_u64_from_top(TRAMPOLINE_OFFSET + 0x20, 0)?;
        let _r14 = stack.write_u64_from_top(TRAMPOLINE_OFFSET + 0x28, 0)?;
        stack.write_u64_from_top(SEED_BYTES, 0)?
    };

    let mut ctx = CpuContext::new_kernel(fork_trampoline as *const () as u64, ctx_rsp);
    ctx.cr3 = snapshot.child_cr3;
    ctx.rflags = rflags;
    child.set_cpu_context(ctx);

    Ok(child)
}

/// Return an untyped pointer to the fork trampoline.
///
/// Exposed so that syscall-api code can construct a `CpuContext`
/// pointing at the trampoline without taking a direct dependency
/// on the assembly stub.
pub fn fork_trampoline_addr() -> u64 {
    fork_trampoline as *const () as u64
}

/// Apply the child's address-space root to the active CPU.
///
/// Wraps the `mov cr3, <phys>` instruction with a safe interface
/// so callers don't have to write inline asm. Writing CR3 triggers
/// a TLB flush on x86_64, making this the standard switch-address-
/// space primitive.
///
/// # Safety
///
/// `cr3` must point at a valid top-level page table that maps at
/// least the kernel higher-half (otherwise the CPU will page-fault
/// on the very next instruction). Caller must be running in ring 0.
pub unsafe fn load_cr3(cr3: Cr3Frame) {
    let phys = cr3.as_u64();
    // SAFETY: caller contract above — `phys` is a physical page
    // table base for a valid address space and the kernel mapping
    // is preserved. `mov cr3` is privileged and has no operand
    // alias hazards beyond what the caller guarantees.
    unsafe {
        core::arch::asm!(
            "mov cr3, {0}",
            in(reg) phys,
            options(nostack, preserves_flags),
        );
    }
}
