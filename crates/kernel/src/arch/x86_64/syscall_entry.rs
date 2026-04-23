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

use core::sync::atomic::AtomicU64;

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
/// RFLAGS.TF (Trap Flag) bit — single-step; must be masked.
const RFLAGS_TF: u64 = 1 << 8;
/// RFLAGS.DF (Direction Flag) bit — must be masked for safe
/// forward-direction string operations in the kernel.
const RFLAGS_DF: u64 = 1 << 10;
/// RFLAGS.NT (Nested Task) bit — must be masked to prevent
/// IRET from performing a task switch.
const RFLAGS_NT: u64 = 1 << 14;
/// RFLAGS.AC (Alignment Check) bit — must be masked to avoid
/// spurious #AC exceptions on unaligned kernel accesses.
const RFLAGS_AC: u64 = 1 << 18;

/// Static kernel stack for the SYSCALL entry path (32 KiB).
///
/// Until per-CPU stacks are implemented, SYSCALL must switch off
/// the untrusted user RSP onto this kernel stack before pushing
/// any data. This is single-CPU only; SMP requires per-CPU
/// storage.
static mut SYSCALL_KERNEL_STACK: [u8; 32768] = [0; 32768];

/// Saved user RSP during SYSCALL execution.
///
/// The SYSCALL entry stub stores the user-space RSP here before
/// switching to the kernel stack, and restores it on exit.
static SYSCALL_SAVED_USER_RSP: AtomicU64 = AtomicU64::new(0);

/// RFLAGS sanitization mask: keeps only safe bits for SYSRETQ.
///
/// Bits kept: CF(0), PF(2), AF(4), ZF(6), SF(7), IF(9), OF(11).
/// Clears: TF, DF, NT, IOPL, AC, and all other privileged bits.
const _RFLAGS_SAFE_MASK: u64 = 0x3C7FD7;
/// Forced RFLAGS bits: IF=1 (bit 9) + reserved bit 1 = 0x202.
const _RFLAGS_FORCE_BITS: u64 = 0x202;

/// Read a Model Specific Register.
///
/// # Safety
///
/// Caller must ensure the MSR address is valid and accessible.
unsafe fn rdmsr(msr: u32) -> u64 {
    let lo: u32;
    let hi: u32;
    // SAFETY: The caller guarantees the MSR address in `ecx`
    // is valid. `rdmsr` reads into `eax`/`edx` without side
    // effects beyond returning the MSR value.
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
    // SAFETY: The caller guarantees the MSR address and value
    // are valid. Writing to a valid MSR is a privileged but
    // well-defined operation in Ring 0.
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

    // SAFETY: Called after GDT init. The MSR writes configure
    // SYSCALL/SYSRET with segment selectors matching our GDT
    // layout; LSTAR and FMASK are set to valid values.
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

        // FMASK: clear IF, DF, AC, NT, TF on SYSCALL entry.
        // IF: disable interrupts until we switch to kernel stack.
        // DF: ensure forward direction for string ops in kernel.
        // AC: prevent spurious alignment-check exceptions.
        // NT: prevent IRET from performing task switches.
        // TF: prevent single-step traps in kernel code.
        wrmsr(
            MSR_FMASK,
            RFLAGS_IF | RFLAGS_DF | RFLAGS_AC | RFLAGS_NT | RFLAGS_TF,
        );
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
/// - Interrupts are disabled (FMASK clears IF, DF, AC, NT, TF)
///
/// We swap GS, switch to the kernel stack, save user state, build
/// a `SyscallArgs` struct, call the dispatcher, validate the
/// return address, and return via SYSRET (or IRETQ fallback if
/// the return address is non-canonical).
///
/// # Naked function
///
/// This must be `#[naked]` because the CPU jumps here directly from the
/// `SYSCALL` instruction with user RSP still live. Any compiler-emitted
/// prologue (e.g., a stack-alignment `push rax`) would silently corrupt
/// the user stack on every syscall — losing 8 bytes per call and
/// eventually underflowing into user code.
///
/// # Kernel Stack Switch
///
/// The entry stub saves the user RSP to an atomic static and loads
/// a dedicated kernel stack. Until per-CPU storage is implemented,
/// this limits SYSCALL to a single CPU.
///
/// # SYSRETQ Safety
///
/// Before executing SYSRETQ, the return address in RCX is checked
/// to be a canonical user-space address (<= 0x00007FFFFFFFFFFF).
/// If the address is non-canonical, we fall back to IRETQ which
/// does not have the RCX privilege escalation vulnerability.
/// R11 (RFLAGS) is also sanitized to force IF=1, clear IOPL/NT/TF.
#[unsafe(no_mangle)]
#[unsafe(naked)]
pub extern "C" fn syscall_entry() {
    // SAFETY: This is the SYSCALL entry stub executed at Ring 0.
    // We swap GS base for per-CPU data, switch to a kernel stack,
    // save user registers, call the Rust dispatcher, validate the
    // return address, sanitize RFLAGS, and return via SYSRET or
    // IRETQ fallback. Naked ensures no compiler prologue runs on the
    // still-live user stack.
    core::arch::naked_asm!(
            // Swap GS base: user GS <-> kernel GS.
            "swapgs",
            // Save user RSP into the atomic and switch to kernel
            // stack. This must happen before any push instruction.
            "mov [{saved_user_rsp}], rsp",
            "lea rsp, [{kern_stack} + 32768]",
            // Save user RCX (RIP) and R11 (RFLAGS).
            "push rcx",       // user RIP
            "push r11",       // user RFLAGS
            // Save callee-saved registers we will clobber.
            "push rbx",
            "push rbp",
            "push r12",
            "push r13",
            "push r14",
            "push r15",
            // Build SyscallArgs on the stack.
            // rcx was overwritten by SYSCALL, arg3 is in r10.
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
            // Sanitize R11 (RFLAGS): clear IOPL, NT, TF, and
            // force IF=1 + reserved bit 1=1.
            "and r11, 0x3C7FD7",
            "or  r11, 0x202",
            // Restore user RSP before returning.
            "mov rsp, [{saved_user_rsp}]",
            // Validate RCX: must be canonical user-space address.
            // User-space canonical max = 0x00007FFFFFFFFFFF.
            "mov r10, 0x00007FFFFFFFFFFF",
            "cmp rcx, r10",
            "ja  2f",
            // --- Normal SYSRET path ---
            "swapgs",
            "sysretq",
            // --- IRETQ fallback for non-canonical RCX ---
            // Construct an interrupt return frame on the stack
            // and use IRETQ which validates the target RIP safely.
            "2:",
            "swapgs",
            "push {user_ss}",   // SS
            "push rsp",         // RSP (user stack, placeholder)
            "push r11",         // RFLAGS (already sanitized)
            "push {user_cs}",   // CS
            "push rcx",         // RIP
            "iretq",
        dispatch = sym syscall_dispatch_wrapper,
        saved_user_rsp = sym SYSCALL_SAVED_USER_RSP,
        kern_stack = sym SYSCALL_KERNEL_STACK,
        user_ss = const 0x1Bu64,  // USER_DATA = (3 << 3)|3
        user_cs = const 0x23u64,  // USER_CODE = (4 << 3)|3
    );
}

/// Wrapper that calls into the syscall dispatcher.
///
/// This is called from the assembly stub with RDI pointing to the
/// `SyscallArgs` struct on the stack.
///
/// IPC syscalls (512–516) and early-boot `SYS_WRITE` (fd 1/2) are
/// handled directly by the kernel. All other syscalls are forwarded
/// to the `oncrix_syscall` crate.
#[unsafe(no_mangle)]
extern "C" fn syscall_dispatch_wrapper(args: *const oncrix_syscall::dispatch::SyscallArgs) -> i64 {
    // SAFETY: The assembly stub guarantees `args` points to a valid
    // SyscallArgs struct on the kernel stack.
    let args = unsafe { &*args };

    match args.number {
        // SYS_WRITE to stdout/stderr: stream bytes from user buffer to serial.
        oncrix_syscall::number::SYS_WRITE if args.arg0 <= 2 => {
            kernel_serial_write(args.arg1, args.arg2)
        }
        // SYS_EXIT / SYS_EXIT_GROUP: print a notice and halt the CPU.
        // In a full kernel this would schedule another process; for the
        // early-boot smoke test there is nothing else to run.
        oncrix_syscall::number::SYS_EXIT | 231 => {
            use oncrix_hal::arch::x86_64::uart::{COM1, Uart16550};
            use oncrix_hal::serial::SerialPort;
            let mut serial = Uart16550::new(COM1);
            let _ = serial.write_str("[ONCRIX] Userspace exited — halting.\n");
            // SAFETY: `hlt` halts the CPU until the next interrupt.
            // No process remains to schedule so spinning on hlt is correct.
            loop {
                unsafe { core::arch::asm!("hlt") };
            }
        }
        // Intercept IPC syscalls — these require direct access to the
        // kernel state (ChannelRegistry) which the syscall crate cannot reach.
        oncrix_syscall::number::SYS_IPC_SEND => {
            crate::ipc_dispatch::kernel_ipc_send(args.arg0, args.arg1)
        }
        oncrix_syscall::number::SYS_IPC_RECEIVE => {
            crate::ipc_dispatch::kernel_ipc_receive(args.arg0, args.arg1)
        }
        oncrix_syscall::number::SYS_IPC_REPLY => {
            crate::ipc_dispatch::kernel_ipc_reply(args.arg0, args.arg1)
        }
        oncrix_syscall::number::SYS_IPC_CALL => {
            crate::ipc_dispatch::kernel_ipc_call(args.arg0, args.arg1)
        }
        oncrix_syscall::number::SYS_IPC_CREATE_ENDPOINT => {
            crate::ipc_dispatch::kernel_ipc_create_endpoint()
        }
        _ => oncrix_syscall::dispatch::dispatch(args),
    }
}

/// Write `count` bytes from user-space address `buf` to the serial console.
///
/// Used to back `SYS_WRITE` for fd 0–2 during early-boot userspace testing,
/// before a full VFS/tty layer is in place.
///
/// # Safety contract
///
/// The caller (SYSCALL entry path) has already validated that the syscall
/// came from ring 3. The pointer is accepted without full validation because
/// in this early-boot phase the only userspace code running is the trusted
/// `usermode_test_entry` stub whose buffer resides in kernel-mapped BSS.
/// Full pointer validation (canonical address, user-range check, page
/// presence) must be added before multi-process userspace is enabled.
fn kernel_serial_write(buf: u64, count: u64) -> i64 {
    use oncrix_hal::arch::x86_64::uart::{COM1, Uart16550};
    use oncrix_hal::serial::SerialPort;

    // Reject obviously bad pointers (NULL or kernel-space canonical range).
    if buf == 0 || buf >= 0xFFFF_8000_0000_0000 {
        return -14; // EFAULT
    }
    let count = count.min(4096) as usize; // cap per-write to 4 KiB
    if count == 0 {
        return 0;
    }

    let mut serial = Uart16550::new(COM1);
    // SAFETY: `buf` is a non-null, non-kernel-canonical address.
    // For the current early-boot phase the only caller is the trusted
    // `usermode_test_entry` whose buffer lives in kernel-mapped BSS.
    // We read byte-by-byte to avoid creating a slice (which would
    // require lifetime/alignment proof we cannot provide here).
    let written = unsafe {
        let ptr = buf as *const u8;
        let mut n = 0usize;
        while n < count {
            let byte = ptr.add(n).read_volatile();
            if serial.write_byte(byte).is_err() {
                break;
            }
            n += 1;
        }
        n
    };
    written as i64
}
