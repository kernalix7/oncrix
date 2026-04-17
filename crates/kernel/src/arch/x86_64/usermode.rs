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

/// Minimal userspace test entry point executed at Ring 3.
///
/// Calls `SYS_WRITE` (1) to emit "hello from ring3\n" on stdout,
/// then calls `SYS_EXIT` (60) with status 0.  This is a self-contained
/// inline-asm function: the message bytes are pushed onto the user stack
/// so no external data mapping is required.
///
/// # Safety
///
/// This function executes at Ring 3 and uses only user-space instructions.
/// The buffer is local to the user stack, so no pointer validation beyond
/// the user/kernel boundary is needed.
#[unsafe(no_mangle)]
pub extern "C" fn usermode_test_entry() -> ! {
    // "hello from ring3\n" = 18 bytes
    // Push the string onto the stack as 64-bit little-endian words, then
    // call write(1, rsp, 18).
    //
    // Bytes: h=0x68 e=0x65 l=0x6C l=0x6C o=0x6F ' '=0x20 f=0x66 r=0x72
    //        o=0x6F m=0x6D ' '=0x20 r=0x72 i=0x69 n=0x6E g=0x67
    //        3=0x33 \n=0x0A (+ 6 padding bytes = 0)
    //
    // Word 0 (lowest addr): "hello fr" = 0x72_66_20_6F_6C_6C_65_68
    // Word 1               : "om ring3" = 0x33_67_6E_69_72_20_6D_6F
    // Word 2 (2 bytes used): "\n\0\0\0\0\0\0\0" = 0x00_00_00_00_00_00_00_0A
    //
    // SAFETY: All instructions are valid at Ring 3. The syscall instruction
    // traps into the kernel SYSCALL entry stub. The buffer address (RSP
    // after pushes) is on the current user stack which is kernel-mapped BSS
    // in this early-boot phase. SYS_EXIT does not return.
    unsafe {
        core::arch::asm!(
            // Build the message on the stack (24 bytes, 3 × 8).
            // "hello fr" little-endian: h=68 e=65 l=6C l=6C o=6F ' '=20 f=66 r=72
            // "om ring3" little-endian: o=6F m=6D ' '=20 r=72 i=69 n=6E g=67 3=33
            // "\n"      little-endian: 0x0A + 7 zero padding bytes
            "sub rsp, 24",
            "mov rax, 0x7266206F6C6C6568", // "hello fr"
            "mov [rsp], rax",
            "mov rax, 0x33676E6972206D6F", // "om ring3"
            "mov [rsp+8], rax",
            "mov rax, 0x000000000000000A", // "\n" + padding
            "mov [rsp+16], rax",
            // write(1, rsp, 18)
            "mov rax, 1",   // SYS_WRITE
            "mov rdi, 1",   // fd = stdout
            "mov rsi, rsp", // buf = &message
            "mov rdx, 18",  // count = 18
            "syscall",
            // Clean up stack frame.
            "add rsp, 24",
            // exit(0)
            "mov rax, 60",  // SYS_EXIT
            "xor rdi, rdi", // status = 0
            "syscall",
            options(noreturn),
        );
    }
}
