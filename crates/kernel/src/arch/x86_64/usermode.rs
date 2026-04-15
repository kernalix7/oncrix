// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! x86_64 transition from Ring 0 (kernel) to Ring 3 (user space).
//!
//! Uses `iretq` to switch privilege levels. The CPU pops SS, RSP,
//! RFLAGS, CS, and RIP from the stack, transitioning to the target
//! code with the specified segment selectors and stack.

use oncrix_hal::arch::x86_64::gdt::selector;
use oncrix_hal::arch::x86_64::uart::{COM1, Uart16550};
use oncrix_hal::serial::SerialPort;

/// RFLAGS.IF (enable interrupts in user space).
const RFLAGS_IF: u64 = 1 << 9;
/// RFLAGS bit 1 is always set.
const RFLAGS_RESERVED: u64 = 1 << 1;

/// Page-aligned user-space stack wrapper.
///
/// This is a **single-use, test-only** stack for early Ring 3
/// transition testing. A real multi-process kernel must
/// dynamically allocate per-process user stacks in user-space
/// virtual memory.
#[repr(C, align(4096))]
struct UserStack([u8; 65536]);

/// User-space stack (64 KiB, page-aligned).
///
/// This static is safe (non-mut) because we only hand the
/// address to user-space via iretq; the kernel itself never
/// writes through it after boot.
static USER_STACK: UserStack = UserStack([0; 65536]);

/// Jump to user space.
///
/// Constructs an `iretq` frame on the kernel stack and returns to
/// the given entry point at Ring 3.
///
/// # Safety
///
/// - `entry` must point to valid, executable user-space code.
/// - The user-space stack must be properly mapped and accessible.
/// - GDT must have valid user code/data segments at the expected
///   selector indices.
pub unsafe fn jump_to_usermode(entry: u64) {
    let mut serial = Uart16550::new(COM1);
    let _ = serial.write_str("[ONCRIX] Transitioning to Ring 3...\n");

    let base = &raw const USER_STACK;
    let user_stack_top = base as u64 + 65536;

    let user_cs = selector::USER_CODE as u64;
    let user_ss = selector::USER_DATA as u64;
    let user_rflags = RFLAGS_IF | RFLAGS_RESERVED;

    // SAFETY: Build an iretq frame and execute it. This drops
    // from Ring 0 to Ring 3. Before iretq, all general-purpose
    // registers are zeroed to prevent leaking kernel data
    // (stack addresses, heap pointers, etc.) to user space.
    // The CPU will:
    // 1. Pop RIP (entry point)
    // 2. Pop CS (user code segment, RPL=3)
    // 3. Pop RFLAGS (interrupts enabled)
    // 4. Pop RSP (user stack)
    // 5. Pop SS (user data segment, RPL=3)
    unsafe {
        core::arch::asm!(
            // Build the iretq frame first (uses reg operands).
            "push {ss}",      // SS
            "push {rsp_val}", // RSP (user stack top)
            "push {rflags}",  // RFLAGS
            "push {cs}",      // CS
            "push {rip}",     // RIP (entry point)
            // Clear all GP registers to prevent kernel data
            // leaks to user space.
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
            ss = in(reg) user_ss,
            rsp_val = in(reg) user_stack_top,
            rflags = in(reg) user_rflags,
            cs = in(reg) user_cs,
            rip = in(reg) entry,
            options(noreturn),
        );
    }
}

/// A minimal test function that can be run in user space.
///
/// In a real kernel, user-space code would be loaded from an ELF
/// binary. This test function demonstrates the Ring 3 transition
/// by executing a SYSCALL back to the kernel.
///
/// # Safety
///
/// This function is designed to execute at Ring 3. It must only
/// use user-space-accessible instructions.
#[unsafe(no_mangle)]
pub extern "C" fn usermode_test_entry() -> ! {
    // Execute a syscall: sys_getpid (number 39).
    // SYSCALL convention: RAX = syscall number.
    // SAFETY: `syscall` is a user-space instruction that traps
    // into the kernel. We are at Ring 3 and the kernel's
    // SYSCALL handler has been configured.
    unsafe {
        core::arch::asm!(
            "mov rax, 39", // SYS_GETPID
            "syscall",
            options(nomem, nostack),
        );
    }

    // Execute sys_exit(0).
    // SAFETY: `syscall` traps into the kernel; this call does
    // not return — the kernel will terminate this process.
    unsafe {
        core::arch::asm!(
            "mov rax, 60",  // SYS_EXIT
            "xor rdi, rdi", // status = 0
            "syscall",
            options(noreturn),
        );
    }
}
