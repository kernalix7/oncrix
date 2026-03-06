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

/// User-space stack (64 KiB, page-aligned).
///
/// In a full kernel, this would be dynamically allocated per-process
/// in user-space virtual memory. For early testing, we use a static
/// buffer in BSS.
static mut USER_STACK: [u8; 65536] = [0; 65536];

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

    let base = &raw const USER_STACK as *const u8;
    let user_stack_top = base as u64 + 65536;

    let user_cs = selector::USER_CODE as u64;
    let user_ss = selector::USER_DATA as u64;
    let user_rflags = RFLAGS_IF | RFLAGS_RESERVED;

    // SAFETY: Build an iretq frame and execute it. This drops
    // from Ring 0 to Ring 3. The CPU will:
    // 1. Pop RIP (entry point)
    // 2. Pop CS (user code segment, RPL=3)
    // 3. Pop RFLAGS (interrupts enabled)
    // 4. Pop RSP (user stack)
    // 5. Pop SS (user data segment, RPL=3)
    unsafe {
        core::arch::asm!(
            "push {ss}",      // SS
            "push {rsp}",     // RSP (user stack top)
            "push {rflags}",  // RFLAGS
            "push {cs}",      // CS
            "push {rip}",     // RIP (entry point)
            "iretq",
            ss = in(reg) user_ss,
            rsp = in(reg) user_stack_top,
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
    unsafe {
        core::arch::asm!(
            "mov rax, 39", // SYS_GETPID
            "syscall",
            options(nomem, nostack),
        );
    }

    // Execute sys_exit(0).
    unsafe {
        core::arch::asm!(
            "mov rax, 60",  // SYS_EXIT
            "xor rdi, rdi", // status = 0
            "syscall",
            options(noreturn),
        );
    }
}
