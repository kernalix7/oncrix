// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! x86_64 SYSCALL/SYSRET fast system call entry point.
//!
//! Configures the Model Specific Registers (MSRs) required for the
//! SYSCALL instruction, and provides the assembly entry/exit stub
//! that saves/restores user-space registers and dispatches to the
//! Rust syscall handler.
//!
//! # MSR Configuration
//!
//! - `IA32_STAR` (0xC000_0081): segment selectors for SYSCALL/SYSRET
//! - `IA32_LSTAR` (0xC000_0082): RIP for SYSCALL entry
//! - `IA32_FMASK` (0xC000_0084): RFLAGS mask (clear IF on entry)
//! - `IA32_EFER` (0xC000_0080): enable SCE (SYSCALL Enable) bit

use oncrix_hal::arch::x86_64::uart::{COM1, Uart16550};
use oncrix_hal::serial::SerialPort;

/// IA32_EFER MSR address.
const MSR_EFER: u32 = 0xC000_0080;
/// IA32_STAR MSR address.
const MSR_STAR: u32 = 0xC000_0081;
/// IA32_LSTAR MSR address.
const MSR_LSTAR: u32 = 0xC000_0082;
/// IA32_FMASK MSR address.
const MSR_FMASK: u32 = 0xC000_0084;

/// EFER.SCE (System Call Enable) bit.
const EFER_SCE: u64 = 1 << 0;

/// RFLAGS.IF (Interrupt Flag) bit — masked on SYSCALL entry.
const RFLAGS_IF: u64 = 1 << 9;

/// Read a Model Specific Register.
///
/// # Safety
///
/// Caller must ensure the MSR address is valid and accessible.
unsafe fn rdmsr(msr: u32) -> u64 {
    let lo: u32;
    let hi: u32;
    unsafe {
        core::arch::asm!(
            "rdmsr",
            in("ecx") msr,
            out("eax") lo,
            out("edx") hi,
            options(nomem, nostack, preserves_flags),
        );
    }
    (hi as u64) << 32 | lo as u64
}

/// Write a Model Specific Register.
///
/// # Safety
///
/// Caller must ensure the MSR address and value are valid.
unsafe fn wrmsr(msr: u32, value: u64) {
    let lo = value as u32;
    let hi = (value >> 32) as u32;
    unsafe {
        core::arch::asm!(
            "wrmsr",
            in("ecx") msr,
            in("eax") lo,
            in("edx") hi,
            options(nomem, nostack, preserves_flags),
        );
    }
}

/// Initialize the SYSCALL/SYSRET mechanism.
///
/// After this call, user-space code can execute `SYSCALL` to enter
/// the kernel via `syscall_entry`.
///
/// # Safety
///
/// Must be called after GDT initialization. The GDT segment layout
/// must match the expected order (kernel code at index 1, user
/// code/data at indices 3-4).
pub unsafe fn init_syscall() {
    let mut serial = Uart16550::new(COM1);

    unsafe {
        // Enable SYSCALL/SYSRET in EFER.
        let efer = rdmsr(MSR_EFER);
        wrmsr(MSR_EFER, efer | EFER_SCE);

        // STAR: bits 47:32 = kernel CS (0x08), bits 63:48 = user CS base.
        //
        // On SYSRET, the CPU loads:
        //   CS = STAR[63:48] + 16 (for 64-bit mode)
        //   SS = STAR[63:48] + 8
        //
        // With user_data at GDT index 3 (selector 0x18 without RPL)
        // and user_code at GDT index 4 (selector 0x20 without RPL):
        //   STAR[63:48] = 0x18 → CS = 0x18+16 = 0x28? No.
        //
        // Actually for SYSRET in 64-bit mode:
        //   CS = STAR[63:48] + 16, SS = STAR[63:48] + 8
        // We need CS=0x20|3=0x23, SS=0x18|3=0x1B
        //   So STAR[63:48] should be 0x10 (then CS=0x10+16=0x20, SS=0x10+8=0x18)
        //   CPU adds RPL=3 automatically for SYSRET.
        //
        // On SYSCALL:
        //   CS = STAR[47:32], SS = STAR[47:32] + 8
        //   We need CS=0x08 (kernel code), SS=0x10 (kernel data)
        //   So STAR[47:32] = 0x08
        let star = (0x0010_u64 << 48) | (0x0008_u64 << 32);
        wrmsr(MSR_STAR, star);

        // LSTAR: entry point for SYSCALL.
        wrmsr(MSR_LSTAR, syscall_entry as *const () as u64);

        // FMASK: clear IF on SYSCALL entry (disable interrupts).
        wrmsr(MSR_FMASK, RFLAGS_IF);
    }

    let _ = serial.write_str("[ONCRIX] SYSCALL/SYSRET initialized\n");
}

/// Syscall entry point (called by the CPU on SYSCALL instruction).
///
/// On entry:
/// - RCX = user RIP (return address)
/// - R11 = user RFLAGS
/// - RAX = syscall number
/// - RDI, RSI, RDX, R10, R8, R9 = arguments
/// - Interrupts are disabled (FMASK clears IF)
///
/// We swap GS to access per-CPU data, save user state, build a
/// `SyscallArgs` struct, call the dispatcher, and return via SYSRET.
///
/// # Kernel Stack Switch
///
/// A production syscall entry MUST switch from the user stack to a
/// per-CPU kernel stack (stored at `gs:KERNEL_STACK_OFFSET`) before
/// pushing any data. Until per-CPU data is implemented, this entry
/// point is only safe for kernel-initiated test calls where RSP
/// already points to a kernel stack.
#[unsafe(no_mangle)]
pub extern "C" fn syscall_entry() {
    // SAFETY: This is the SYSCALL entry stub. We swap GS base for
    // per-CPU data, save all user registers, call the Rust dispatcher,
    // then restore and SYSRET.
    unsafe {
        core::arch::asm!(
            // Swap GS base: user GS ↔ kernel GS (MSR_KERNEL_GS_BASE).
            "swapgs",
            // --- Kernel stack switch would go here ---
            // In production: mov rsp, gs:[KERNEL_STACK_OFFSET]
            // For now, we rely on RSP already being a kernel stack.
            //
            // Save user RCX (RIP) and R11 (RFLAGS) on the kernel stack.
            "push rcx",       // user RIP
            "push r11",       // user RFLAGS
            // Save callee-saved registers we'll clobber.
            "push rbx",
            "push rbp",
            "push r12",
            "push r13",
            "push r14",
            "push r15",
            // Build SyscallArgs on the stack.
            // SyscallArgs { number, arg0..arg5 }
            // rcx was overwritten by SYSCALL (user RIP), so arg3 is in r10.
            "push r9",        // arg5
            "push r8",        // arg4
            "push r10",       // arg3
            "push rdx",       // arg2
            "push rsi",       // arg1
            "push rdi",       // arg0
            "push rax",       // syscall number
            // Call the Rust dispatcher with pointer to SyscallArgs.
            "mov rdi, rsp",   // rdi = &SyscallArgs
            "call {dispatch}",
            // Result is in RAX (SyscallResult).
            // Pop SyscallArgs (7 * 8 = 56 bytes).
            "add rsp, 56",
            // Restore callee-saved registers.
            "pop r15",
            "pop r14",
            "pop r13",
            "pop r12",
            "pop rbp",
            "pop rbx",
            // Restore user RFLAGS and RIP.
            "pop r11",        // user RFLAGS
            "pop rcx",        // user RIP
            // Swap GS back before returning to user space.
            "swapgs",
            // Return to user space.
            "sysretq",
            dispatch = sym syscall_dispatch_wrapper,
            options(noreturn),
        );
    }
}

/// Wrapper that calls into the syscall dispatcher.
///
/// This is called from the assembly stub with RDI pointing to the
/// `SyscallArgs` struct on the stack.
#[unsafe(no_mangle)]
extern "C" fn syscall_dispatch_wrapper(args: *const oncrix_syscall::dispatch::SyscallArgs) -> i64 {
    // SAFETY: The assembly stub guarantees `args` points to a valid
    // SyscallArgs struct on the kernel stack.
    let args = unsafe { &*args };
    oncrix_syscall::dispatch::dispatch(args)
}
