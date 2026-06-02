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

use core::sync::atomic::{AtomicU64, Ordering};

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
/// EFER.NXE (No-Execute Enable) bit.
///
/// When clear, the CPU treats PTE bit 63 as reserved and raises a
/// "reserved bit set" #PF (err.bit3=1) on any access through such a
/// PTE. ONCRIX's anonymous-mmap code sets bit 63 when the caller
/// omits `PROT_EXEC`, so NXE must be enabled for those mappings to
/// fault correctly only on instruction fetch.
const EFER_NXE: u64 = 1 << 11;

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

/// Static fallback kernel stack for the SYSCALL entry path (32 KiB).
///
/// Used only before the scheduler installs the first per-thread
/// kernel stack via `switch_tss_rsp0`. After that, [`CURRENT_KSTACK_TOP`]
/// holds the live thread's private stack top and SYSCALL entry
/// switches onto it — necessary so that a sleeping thread's saved
/// kernel-call frames are not clobbered by another thread's SYSCALL
/// reusing the same buffer.
static mut SYSCALL_KERNEL_STACK: [u8; 32768] = [0; 32768];

/// Top (highest address + 1) of the currently running thread's
/// private kernel stack, mirrored from `TSS.RSP0` by
/// [`crate::arch::x86_64::init::switch_tss_rsp0`].
///
/// `0` means "fall back to the static SYSCALL_KERNEL_STACK top".
/// The SYSCALL entry asm reads this atomic and — if non-zero —
/// loads its value into RSP so each thread's syscall work lives
/// on its own private 16 KiB kstack.
pub static CURRENT_KSTACK_TOP: AtomicU64 = AtomicU64::new(0);

/// Publish the current thread's per-thread kernel-stack top to
/// [`CURRENT_KSTACK_TOP`].
///
/// `0` reverts to the static fallback stack.
pub fn set_current_kstack_top(top: u64) {
    CURRENT_KSTACK_TOP.store(top, Ordering::Relaxed);
}

/// Saved user RSP during SYSCALL execution.
///
/// The SYSCALL entry stub stores the user-space RSP here before
/// switching to the kernel stack, and restores it on exit.
pub static SYSCALL_SAVED_USER_RSP: AtomicU64 = AtomicU64::new(0);

/// Saved user RIP during SYSCALL execution.
///
/// On `SYSCALL`, the CPU places the user return address (the
/// instruction after `SYSCALL`) into `RCX`. The entry stub saves
/// it here immediately so that fork/exec handlers can snapshot the
/// user instruction pointer without needing a full register frame.
///
/// Must be read before calling any Rust code that might clobber `RCX`.
pub static SYSCALL_SAVED_USER_RIP: AtomicU64 = AtomicU64::new(0);

/// Saved user RFLAGS during SYSCALL execution.
///
/// On `SYSCALL`, the CPU places the user RFLAGS into `R11`. The
/// entry stub saves it here alongside [`SYSCALL_SAVED_USER_RIP`]
/// so fork/exec can reconstruct the parent's full user register
/// state without walking a stack frame.
pub static SYSCALL_SAVED_USER_RFLAGS: AtomicU64 = AtomicU64::new(0);

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
        // Enable SYSCALL/SYSRET and the NX bit in EFER. NXE is required
        // for `mmap_anonymous` to legally set PTE bit 63 when
        // `PROT_EXEC` is omitted; without it those PTEs would raise a
        // reserved-bit page fault on first access.
        let efer = rdmsr(MSR_EFER);
        wrmsr(MSR_EFER, efer | EFER_SCE | EFER_NXE);

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
            // Prefer the running thread's private kernel stack (as
            // mirrored by `switch_tss_rsp0` into CURRENT_KSTACK_TOP).
            // If it is zero (very early boot, before the scheduler has
            // installed the first thread), fall back to the static
            // SYSCALL_KERNEL_STACK so that early-boot syscalls still
            // work.
            "mov rsp, [{cur_kstack_top}]",
            "test rsp, rsp",
            "jnz 3f",
            "lea rsp, [{kern_stack} + 32768]",
            "3:",
            // Save user RCX (return RIP) and R11 (user RFLAGS) into
            // their per-atomic-static slots so that fork/exec handlers
            // can snapshot the parent's user register state.
            // These writes happen BEFORE any Rust call that might
            // clobber RCX or R11 through the C ABI.
            "mov [{saved_user_rip}], rcx",
            "mov [{saved_user_rflags}], r11",
            // Push RCX and R11 onto the kernel stack for restoration.
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
            // Result is in RAX (SyscallResult). Pop SyscallArgs in
            // reverse push order, restoring the user-mode caller-saved
            // registers (rdi, rsi, rdx, r10, r8, r9) so the user
            // observes them unchanged across the syscall — required by
            // the System V AMD64 ABI for arguments and by the Rust
            // compiler's expectation that RSI/RDI survive across an
            // inline `syscall` instruction. Without this restore the
            // user sees garbage in those registers and any subsequent
            // syscall using them as arguments (e.g. wait4's wstatus
            // pointer in rsi) traps in user space.
            "add rsp, 8",     // discard pushed syscall number; rax already holds return value
            "pop rdi",
            "pop rsi",
            "pop rdx",
            "pop r10",
            "pop r8",
            "pop r9",
            // Restore callee-saved registers.
            "pop r15",
            "pop r14",
            "pop r13",
            "pop r12",
            "pop rbp",
            "pop rbx",
            // Discard the two stacked copies of RCX/R11 (we read the
            // authoritative values from the atomics below). After this
            // the kernel-stack frame is fully unwound.
            "add rsp, 16",
            // Restore user RFLAGS and RIP. Read from atomics rather
            // than from the stack so that exec-style handlers can
            // redirect return-to-user by updating the atomics.
            "mov rcx, [{saved_user_rip}]",
            // Validate RCX: must be a canonical user-space address
            // (<= 0x00007FFFFFFFFFFF). r11 is still free here — it has
            // NOT yet been loaded with the user RFLAGS — so use it as the
            // scratch for the 64-bit compare and branch IMMEDIATELY, before
            // any flag-modifying instruction runs. Using r10 as the scratch
            // (as a previous revision did) clobbered the user r10 already
            // restored by `pop r10` above; a program that keeps a live
            // value in r10 across the `syscall` (e.g. /bin/rmdir's argv
            // loop counter) then read garbage and faulted #GP on the next
            // r10-indexed access.
            "mov r11, 0x00007FFFFFFFFFFF",
            "cmp rcx, r11",
            "ja  2f",
            // --- Normal SYSRET path ---
            // Load and sanitize the user RFLAGS into r11: clear IOPL, NT,
            // TF, force IF=1 + reserved bit 1=1. Restore user RSP last.
            "mov r11, [{saved_user_rflags}]",
            "and r11, 0x3C7FD7",
            "or  r11, 0x202",
            "mov rsp, [{saved_user_rsp}]",
            "swapgs",
            "sysretq",
            // --- IRETQ fallback for non-canonical RCX ---
            // Construct an interrupt return frame on the stack and use
            // IRETQ which validates the target RIP safely. RFLAGS is
            // sanitized identically to the SYSRET path.
            "2:",
            "mov r11, [{saved_user_rflags}]",
            "and r11, 0x3C7FD7",
            "or  r11, 0x202",
            "mov rsp, [{saved_user_rsp}]",
            "swapgs",
            "push {user_ss}",   // SS
            "push rsp",         // RSP (user stack, placeholder)
            "push r11",         // RFLAGS (already sanitized)
            "push {user_cs}",   // CS
            "push rcx",         // RIP
            "iretq",
        dispatch = sym syscall_dispatch_wrapper,
        saved_user_rsp = sym SYSCALL_SAVED_USER_RSP,
        saved_user_rip = sym SYSCALL_SAVED_USER_RIP,
        saved_user_rflags = sym SYSCALL_SAVED_USER_RFLAGS,
        kern_stack = sym SYSCALL_KERNEL_STACK,
        cur_kstack_top = sym CURRENT_KSTACK_TOP,
        user_ss = const 0x1Bu64,  // USER_DATA = (3 << 3)|3
        user_cs = const 0x23u64,  // USER_CODE = (4 << 3)|3
    );
}

/// Wrapper that calls into the syscall dispatcher.
///
/// This is called from the assembly stub with RDI pointing to the
/// `SyscallArgs` struct on the stack.
///
/// VFS syscalls (open/read/write/close/lseek), process management
/// syscalls (fork/wait4/execve/exit), and IPC syscalls (512–516) are
/// handled directly by the kernel.  All other syscalls are forwarded
/// to the `oncrix_syscall` crate.
///
/// # Phase 12 VFS routing
///
/// `SYS_READ` and `SYS_WRITE` now go through the per-process fd table
/// ([`crate::fd_table`]) rather than the legacy `kernel_serial_write`
/// fast path.  fd 0/1/2 are pre-installed as console handles at init
/// time so stdout/stderr still work.  The legacy `kernel_serial_write`
/// function is kept as a fallback for pathological early-boot cases
/// (e.g. before [`crate::fd_table::install_stdio`] has been called)
/// but is no longer the matched branch for fd 0–2.
#[unsafe(no_mangle)]
extern "C" fn syscall_dispatch_wrapper(args: *mut oncrix_syscall::dispatch::SyscallArgs) -> i64 {
    // SAFETY: The assembly stub guarantees `args` points to a valid
    // SyscallArgs struct on the kernel stack. We retain the raw `*mut`
    // pointer so the signal-delivery epilogue can plant `arg0` =
    // signum into the live stack slot before the SYSRET `pop rdi`.
    let args_ptr: *mut oncrix_syscall::dispatch::SyscallArgs = args;
    let args = unsafe { &*args };

    let result: i64 = match args.number {
        // ── VFS I/O syscalls ─────────────────────────────────────

        // SYS_READ (0): read from file descriptor into user buffer.
        // POSIX.1-2024 read(3p).
        oncrix_syscall::number::SYS_READ => {
            // SAFETY: Single-CPU SYSCALL dispatch; fd_table is the sole
            // accessor of CURRENT_FD_TABLE in this context.
            unsafe {
                crate::fd_table::dispatch_read(
                    args.arg0 as usize, // fd
                    args.arg1,          // buf *
                    args.arg2,          // count
                )
            }
        }

        // SYS_WRITE (1): write from user buffer to file descriptor.
        // POSIX.1-2024 write(3p).
        // Phase 12: routes through the fd table for ALL file descriptors
        // including 0/1/2 (which point at the console handle).  The
        // legacy `kernel_serial_write` fast path is kept as a fallback
        // only if the fd table is not yet initialised (i.e. the fd slot
        // is None — dispatch_write returns -9 EBADF, caught below).
        oncrix_syscall::number::SYS_WRITE => {
            // SAFETY: see SYS_READ above.
            let ret = unsafe {
                crate::fd_table::dispatch_write(
                    args.arg0 as usize, // fd
                    args.arg1,          // buf *
                    args.arg2,          // count
                )
            };
            // Defensive fallback: if for any reason fd 0/1/2 is not yet
            // installed (boot ordering bug or future reorganisation),
            // forward to the legacy serial path so the first diagnostic
            // line is never silently lost. In normal operation this branch
            // is unreachable because `install_stdio` runs in `main.rs`
            // before the init ELF is launched.
            if ret == -9 && args.arg0 <= 2 {
                kernel_serial_write(args.arg1, args.arg2)
            } else {
                ret
            }
        }

        // SYS_OPEN (2): open or create a file and return an fd.
        // POSIX.1-2024 open(3p).
        oncrix_syscall::number::SYS_OPEN => {
            // SAFETY: see SYS_READ above.
            unsafe { sys_open(args.arg0, args.arg1, args.arg2) }
        }

        // SYS_CLOSE (3): close a file descriptor.
        // POSIX.1-2024 close(3p).
        oncrix_syscall::number::SYS_CLOSE => {
            // SAFETY: see SYS_READ above.
            unsafe {
                crate::fd_table::fd_close(args.arg0 as usize)
                    .map(|_| 0i64)
                    .unwrap_or(-9)
            }
        }

        // SYS_STAT (4): get file status by pathname.
        // POSIX.1-2024 stat(3p).
        oncrix_syscall::number::SYS_STAT => {
            // SAFETY: Single-CPU SYSCALL dispatch path.
            unsafe { crate::fs_syscalls::sys_stat(args.arg0, args.arg1) }
        }

        // SYS_FSTAT (5): get file status by file descriptor.
        // POSIX.1-2024 fstat(3p).
        oncrix_syscall::number::SYS_FSTAT => {
            // SAFETY: Single-CPU SYSCALL dispatch path.
            unsafe { crate::fs_syscalls::sys_fstat(args.arg0 as i32, args.arg1) }
        }

        // SYS_LSTAT (6): get file status without following symlinks.
        // POSIX.1-2024 lstat(3p).
        oncrix_syscall::number::SYS_LSTAT => {
            // SAFETY: Single-CPU SYSCALL dispatch path.
            unsafe { crate::fs_syscalls::sys_lstat(args.arg0, args.arg1) }
        }

        // SYS_LSEEK (8): reposition the file offset.
        // POSIX.1-2024 lseek(3p).
        oncrix_syscall::number::SYS_LSEEK => {
            // SAFETY: see SYS_READ above.
            unsafe {
                crate::fd_table::dispatch_lseek(
                    args.arg0 as usize, // fd
                    args.arg1 as i64,   // offset
                    args.arg2 as i32,   // whence
                )
            }
        }
        // SYS_PREAD64 (17) / SYS_PWRITE64 (18): positional I/O — read/write
        // at an offset without moving the file position.
        oncrix_syscall::number::SYS_PREAD64 => {
            // SAFETY: see SYS_READ above.
            unsafe {
                crate::fd_table::dispatch_pread(args.arg0 as usize, args.arg1, args.arg2, args.arg3)
            }
        }
        oncrix_syscall::number::SYS_PWRITE64 => {
            // SAFETY: see SYS_READ above.
            unsafe {
                crate::fd_table::dispatch_pwrite(
                    args.arg0 as usize,
                    args.arg1,
                    args.arg2,
                    args.arg3,
                )
            }
        }
        // SYS_READV (19) / SYS_WRITEV (20): scatter/gather vectored I/O.
        oncrix_syscall::number::SYS_READV => {
            // SAFETY: see SYS_READ above.
            unsafe { crate::fd_table::dispatch_readv(args.arg0 as usize, args.arg1, args.arg2) }
        }
        oncrix_syscall::number::SYS_WRITEV => {
            // SAFETY: see SYS_READ above.
            unsafe { crate::fd_table::dispatch_writev(args.arg0 as usize, args.arg1, args.arg2) }
        }

        // SYS_FACCESSAT (269): check file accessibility relative to a directory fd.
        // POSIX.1-2024 faccessat(3p). Only AT_FDCWD is modelled; arbitrary dirfds
        // return EBADF. flags (arg3) are accepted but ignored on ramfs.
        oncrix_syscall::number::SYS_FACCESSAT => {
            // SAFETY: Single-CPU SYSCALL dispatch path.
            unsafe {
                crate::fs_syscalls::sys_faccessat(args.arg0 as i64, args.arg1, args.arg2, args.arg3)
            }
        }

        // SYS_FCHMODAT (268): fchmodat(dirfd, pathname, mode, flags) — chmod relative to dir fd.
        // POSIX.1-2024 fchmodat(3p).
        oncrix_syscall::number::SYS_FCHMODAT => {
            // SAFETY: Single-CPU SYSCALL dispatch path; arg1 is a user-space path pointer.
            unsafe {
                crate::fs_syscalls::sys_fchmodat(args.arg0 as i64, args.arg1, args.arg2, args.arg3)
            }
        }

        // SYS_FCHOWNAT (260): fchownat(dirfd, pathname, uid, gid, flags).
        // POSIX.1-2024 fchownat(3p). Only AT_FDCWD is supported; other dirfd
        // values return -EBADF until dirfd-relative path resolution is modelled.
        oncrix_syscall::number::SYS_FCHOWNAT => {
            // SAFETY: Single-CPU SYSCALL dispatch path; arg1 is a user-space
            // pointer to a NUL-terminated pathname forwarded unchanged to sys_chown.
            unsafe {
                crate::fs_syscalls::sys_fchownat(
                    args.arg0 as i64,
                    args.arg1,
                    args.arg2,
                    args.arg3,
                    args.arg4,
                )
            }
        }

        oncrix_syscall::number::SYS_MKDIRAT => {
            // SAFETY: Single-CPU SYSCALL dispatch path.
            unsafe { crate::fs_syscalls::sys_mkdirat(args.arg0 as i64, args.arg1, args.arg2) }
        }

        // SYS_UNLINKAT (263): remove a directory entry relative to a directory fd.
        // POSIX.1-2024 unlinkat(3p). AT_FDCWD only; cross-dir not yet implemented.
        oncrix_syscall::number::SYS_UNLINKAT => {
            // SAFETY: Single-CPU SYSCALL dispatch path; arg1 is the user pathname pointer.
            unsafe { crate::fs_syscalls::sys_unlinkat(args.arg0 as i64, args.arg1, args.arg2) }
        }

        oncrix_syscall::number::SYS_RENAMEAT => {
            // SAFETY: Single-CPU SYSCALL dispatch path; arg1/arg3 are NUL-terminated
            // user-space path pointers, arg0/arg2 are dirfds (AT_FDCWD or open fds).
            unsafe {
                crate::fs_syscalls::sys_renameat(
                    args.arg0 as i64,
                    args.arg1,
                    args.arg2 as i64,
                    args.arg3,
                )
            }
        }

        // SYS_READLINKAT (267): read symlink target relative to a directory fd.
        // Delegates to sys_readlinkat which enforces AT_FDCWD-only semantics.
        oncrix_syscall::number::SYS_READLINKAT => {
            // SAFETY: Single-CPU SYSCALL dispatch path; pointer validation is
            // performed inside sys_readlinkat / sys_readlink.
            unsafe {
                crate::fs_syscalls::sys_readlinkat(
                    args.arg0 as i64,
                    args.arg1,
                    args.arg2,
                    args.arg3,
                )
            }
        }

        oncrix_syscall::number::SYS_SYMLINKAT => {
            // SAFETY: Single-CPU SYSCALL dispatch path; arg0 = target ptr (u64),
            // arg1 = newdirfd (i64), arg2 = linkpath ptr (u64).
            unsafe { crate::fs_syscalls::sys_symlinkat(args.arg0, args.arg1 as i64, args.arg2) }
        }

        oncrix_syscall::number::SYS_NEWFSTATAT => {
            // SAFETY: Single-CPU SYSCALL dispatch path; arg0=dirfd (i64), arg1=pathname,
            // arg2=statbuf, arg3=flags.  sys_newfstatat validates all pointers internally.
            unsafe {
                crate::fs_syscalls::sys_newfstatat(
                    args.arg0 as i64, // dirfd
                    args.arg1,        // pathname ptr
                    args.arg2,        // statbuf ptr
                    args.arg3,        // flags
                )
            }
        }

        // ── Process management syscalls ──────────────────────────

        // SYS_EXIT / SYS_EXIT_GROUP: mark process as exited and reschedule.
        oncrix_syscall::number::SYS_EXIT | 231 => {
            // SAFETY: Single-CPU SYSCALL dispatch path; interrupts effectively
            // disabled (FMASK cleared IF). sys_exit does not return.
            unsafe { crate::fork_dispatch::sys_exit(args.arg0) }
        }

        // ── IPC syscalls ─────────────────────────────────────────
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

        // ── Process creation / management syscalls ───────────────
        oncrix_syscall::number::SYS_FORK => {
            // SAFETY: Single-CPU SYSCALL dispatch path.
            unsafe { crate::fork_dispatch::sys_fork() }
        }
        oncrix_syscall::number::SYS_WAIT4 => {
            // SAFETY: see SYS_FORK above.
            unsafe { crate::fork_dispatch::sys_wait4(args.arg0, args.arg1, args.arg2, args.arg3) }
        }
        // SYS_WAITID (247): wait for a child by idtype/id, fill siginfo_t.
        oncrix_syscall::number::SYS_WAITID => {
            // SAFETY: see SYS_FORK above.
            unsafe { crate::fork_dispatch::sys_waitid(args.arg0, args.arg1, args.arg2, args.arg3) }
        }
        oncrix_syscall::number::SYS_EXECVE => {
            // SAFETY: see SYS_FORK above.
            unsafe { crate::fork_dispatch::sys_execve(args.arg0, args.arg1, args.arg2) }
        }

        // ── Process identity syscalls ────────────────────────────
        // SYS_GETPID (39): POSIX.1-2024 getpid(3p) — always succeeds.
        oncrix_syscall::number::SYS_GETPID => {
            crate::current::current_thread()
                .map(|t| t.pid().as_u64() as i64)
                .unwrap_or(-3) // ESRCH
        }

        // SYS_GETPPID (110): POSIX.1-2024 getppid(3p).
        // Looks up the parent PID in the global process table.
        oncrix_syscall::number::SYS_GETPPID => {
            // SAFETY: single-CPU SYSCALL dispatch path; no concurrent table access.
            unsafe { crate::fork_dispatch::sys_getppid() }
        }

        // SYS_GETTID (186): returns the thread ID of the calling thread.
        oncrix_syscall::number::SYS_GETTID => {
            crate::current::current_thread()
                .map(|t| t.tid().as_u64() as i64)
                .unwrap_or(-3) // ESRCH
        }

        // SYS_BRK (12): POSIX.1-2024 brk(3p) / Linux brk(2).
        // Non-zero arg is ENOSYS; arg==0 returns current break (0 = stub).
        oncrix_syscall::number::SYS_BRK => {
            if args.arg0 == 0 { 0 } else { -38 } // ENOSYS for non-zero
        }

        // ── Pipe syscalls ────────────────────────────────────────

        // SYS_PIPE2 (293): create a pipe with optional flags.
        // POSIX.1-2024 pipe(3p) / Linux pipe2(2).
        // arg0 = fildes[2] (user pointer), arg1 = flags.
        oncrix_syscall::number::SYS_PIPE2 => {
            // SAFETY: Single-CPU SYSCALL dispatch path.
            unsafe { crate::pipe::sys_pipe2(args.arg0, args.arg1) }
        }

        // ── Socket syscalls ──────────────────────────────────────

        // SYS_SOCKET (41): create a socket.
        // POSIX.1-2024 socket(3p).
        oncrix_syscall::number::SYS_SOCKET => {
            // SAFETY: Single-CPU SYSCALL dispatch path.
            unsafe { crate::socket::sys_socket(args.arg0, args.arg1, args.arg2) }
        }

        // SYS_CONNECT (42): connect a socket to an address.
        // POSIX.1-2024 connect(3p).
        oncrix_syscall::number::SYS_CONNECT => {
            // SAFETY: Single-CPU SYSCALL dispatch path.
            unsafe { crate::socket::sys_connect(args.arg0, args.arg1, args.arg2) }
        }

        // SYS_ACCEPT (43): accept a connection on a listening socket.
        // POSIX.1-2024 accept(3p).
        oncrix_syscall::number::SYS_ACCEPT => {
            // SAFETY: Single-CPU SYSCALL dispatch path.
            unsafe { crate::socket::sys_accept(args.arg0, args.arg1, args.arg2) }
        }

        // SYS_SENDTO (44): send data through a socket.
        // POSIX.1-2024 sendmsg(3p) / send(3p).
        oncrix_syscall::number::SYS_SENDTO => {
            // SAFETY: Single-CPU SYSCALL dispatch path.
            unsafe {
                crate::socket::sys_sendto(
                    args.arg0, args.arg1, args.arg2, args.arg3, args.arg4, args.arg5,
                )
            }
        }

        // SYS_RECVFROM (45): receive data from a socket.
        // POSIX.1-2024 recvmsg(3p) / recv(3p).
        oncrix_syscall::number::SYS_RECVFROM => {
            // SAFETY: Single-CPU SYSCALL dispatch path.
            unsafe {
                crate::socket::sys_recvfrom(
                    args.arg0, args.arg1, args.arg2, args.arg3, args.arg4, args.arg5,
                )
            }
        }

        // SYS_BIND (49): bind a socket to a local address.
        // POSIX.1-2024 bind(3p).
        oncrix_syscall::number::SYS_BIND => {
            // SAFETY: Single-CPU SYSCALL dispatch path.
            unsafe { crate::socket::sys_bind(args.arg0, args.arg1, args.arg2) }
        }

        // SYS_LISTEN (50): mark a socket as listening.
        // POSIX.1-2024 listen(3p).
        oncrix_syscall::number::SYS_LISTEN => {
            // SAFETY: Single-CPU SYSCALL dispatch path.
            unsafe { crate::socket::sys_listen(args.arg0, args.arg1) }
        }

        // ── Filesystem management syscalls ───────────────────────

        // SYS_MKDIR (83): create a directory.
        // POSIX.1-2024 mkdir(3p).
        oncrix_syscall::number::SYS_MKDIR => {
            // SAFETY: Single-CPU SYSCALL dispatch path.
            unsafe { crate::fs_syscalls::sys_mkdir(args.arg0, args.arg1) }
        }

        // SYS_UNLINK (87): remove a filesystem name.
        // POSIX.1-2024 unlink(3p).
        oncrix_syscall::number::SYS_UNLINK => {
            // SAFETY: Single-CPU SYSCALL dispatch path.
            unsafe { crate::fs_syscalls::sys_unlink(args.arg0) }
        }

        // SYS_RENAME (82): rename/move a filesystem name.
        // POSIX.1-2024 rename(3p).
        oncrix_syscall::number::SYS_RENAME => {
            // SAFETY: Single-CPU SYSCALL dispatch path.
            unsafe { crate::fs_syscalls::sys_rename(args.arg0, args.arg1) }
        }

        // SYS_CHMOD (90): change file permission bits.
        // POSIX.1-2024 chmod(3p).
        oncrix_syscall::number::SYS_CHMOD => {
            // SAFETY: Single-CPU SYSCALL dispatch path.
            unsafe { crate::fs_syscalls::sys_chmod(args.arg0, args.arg1) }
        }

        // SYS_LINK (86): create a hard link.
        // POSIX.1-2024 link(3p).
        oncrix_syscall::number::SYS_LINK => {
            // SAFETY: Single-CPU SYSCALL dispatch path.
            unsafe { crate::fs_syscalls::sys_link(args.arg0, args.arg1) }
        }

        // SYS_CHOWN (92): change file owner/group.
        // POSIX.1-2024 chown(3p).
        oncrix_syscall::number::SYS_CHOWN => {
            // SAFETY: Single-CPU SYSCALL dispatch path.
            unsafe { crate::fs_syscalls::sys_chown(args.arg0, args.arg1, args.arg2) }
        }

        // SYS_ACCESS (21): check file accessibility.
        // POSIX.1-2024 access(3p). ramfs has no permission enforcement;
        // the handler checks existence only.
        oncrix_syscall::number::SYS_ACCESS => {
            // SAFETY: Single-CPU SYSCALL dispatch path.
            unsafe { crate::fs_syscalls::sys_access(args.arg0, args.arg1) }
        }

        // SYS_FSYNC (74) / SYS_FDATASYNC (75): synchronize file state with
        // backing store. POSIX.1-2024 fsync(3p) / fdatasync(3p). ramfs is
        // in-memory — nothing to flush; return success (mirrors SYS_SYNC).
        oncrix_syscall::number::SYS_FSYNC | oncrix_syscall::number::SYS_FDATASYNC => 0,

        // SYS_STATFS (137): get filesystem statistics by path.
        // POSIX.1-2024 statfs(2).
        oncrix_syscall::number::SYS_STATFS => {
            // SAFETY: Single-CPU SYSCALL dispatch path.
            unsafe { crate::fs_syscalls::sys_statfs(args.arg0, args.arg1) }
        }

        // SYS_FSTATFS (138): get filesystem statistics by file descriptor.
        // POSIX.1-2024 fstatfs(2).
        oncrix_syscall::number::SYS_FSTATFS => {
            // SAFETY: Single-CPU SYSCALL dispatch path.
            unsafe { crate::fs_syscalls::sys_fstatfs(args.arg0 as i32, args.arg1) }
        }

        // SYS_SYSINFO (99): fill struct sysinfo for the caller.
        oncrix_syscall::number::SYS_SYSINFO => {
            // SAFETY: Single-CPU SYSCALL dispatch path.
            unsafe { crate::fs_syscalls::sys_sysinfo(args.arg0) }
        }

        // SYS_GETRANDOM (318): fill user buffer with pseudo-random bytes.
        // flags GRND_NONBLOCK/GRND_RANDOM are accepted and ignored.
        oncrix_syscall::number::SYS_GETRANDOM => {
            // SAFETY: Single-CPU SYSCALL dispatch path.
            unsafe { crate::random_syscall::sys_getrandom(args.arg0, args.arg1, args.arg2) }
        }

        // SYS_SYNC (162): flush filesystem buffers.
        // POSIX.1-2024 sync(3p). ramfs is in-memory, so there is nothing
        // to flush — return success immediately.
        oncrix_syscall::number::SYS_SYNC => 0,

        // SYS_FLOCK (73): advisory whole-file lock. Single-user in-memory VFS;
        // always succeeds after validating that `fd` is open (EBADF check).
        // POSIX.1-2024 / Linux flock(2).
        oncrix_syscall::number::SYS_FLOCK => {
            // SAFETY: Single-CPU SYSCALL dispatch path.
            unsafe { crate::fs_syscalls::sys_flock(args.arg0 as i32, args.arg1 as i32) }
        }

        // SYS_MSYNC (26): sync memory mapping with backing store.
        // ramfs has no backing store; always succeed. POSIX.1-2024 msync(3p).
        oncrix_syscall::number::SYS_MSYNC => 0,

        // SYS_MADVISE (28): advise the kernel on memory-use patterns.
        // No page cache or VM on ONCRIX; advice is accepted and ignored.
        // POSIX.1-2024 madvise(3p).
        oncrix_syscall::number::SYS_MADVISE => 0,

        // SYS_MLOCK (149) / SYS_MUNLOCK (150): lock/unlock pages in memory.
        // ONCRIX does not swap pages out, so these are always no-ops.
        oncrix_syscall::number::SYS_MLOCK => 0,
        oncrix_syscall::number::SYS_MUNLOCK => 0,

        // SYS_MLOCKALL (151) / SYS_MUNLOCKALL (152): lock/unlock all process
        // pages. No-op on ONCRIX (no page-out, no swap). POSIX.1-2024.
        oncrix_syscall::number::SYS_MLOCKALL => 0,
        oncrix_syscall::number::SYS_MUNLOCKALL => 0,

        // SYS_GETPGRP (111): equivalent to getpgid(0) per POSIX.1-2024.
        oncrix_syscall::number::SYS_GETPGRP => {
            // SAFETY: Single-CPU SYSCALL dispatch path.
            unsafe { crate::sched_syscalls::sys_getpgid(0) }
        }

        // SYS_GETCPU (309): query current CPU + NUMA node (always 0 on ONCRIX).
        oncrix_syscall::number::SYS_GETCPU => {
            // SAFETY: Single-CPU SYSCALL dispatch path.
            unsafe { crate::sched_syscalls::sys_getcpu(args.arg0, args.arg1, args.arg2) }
        }

        // SYS_SCHED_GET_PRIORITY_MAX (146) / SYS_SCHED_GET_PRIORITY_MIN (147):
        // POSIX.1-2024 sched_get_priority_max(3p) / sched_get_priority_min(3p).
        oncrix_syscall::number::SYS_SCHED_GET_PRIORITY_MAX => {
            // SAFETY: Single-CPU SYSCALL dispatch path.
            unsafe { crate::sched_syscalls::sys_sched_get_priority_max(args.arg0 as i64) }
        }
        oncrix_syscall::number::SYS_SCHED_GET_PRIORITY_MIN => {
            // SAFETY: Single-CPU SYSCALL dispatch path.
            unsafe { crate::sched_syscalls::sys_sched_get_priority_min(args.arg0 as i64) }
        }

        // SYS_FADVISE64 (221): posix_fadvise — access-pattern hint; no backing store
        // to tune on ramfs; validate fd and return 0.
        oncrix_syscall::number::SYS_FADVISE64 => {
            // SAFETY: Single-CPU SYSCALL dispatch path.
            unsafe {
                crate::fs_syscalls::sys_fadvise64(
                    args.arg0 as i32,
                    args.arg1,
                    args.arg2,
                    args.arg3 as i32,
                )
            }
        }

        // SYS_READAHEAD (187): initiate read-ahead; ramfs is always resident,
        // so validate fd and return 0.
        oncrix_syscall::number::SYS_READAHEAD => {
            // SAFETY: Single-CPU SYSCALL dispatch path.
            unsafe {
                crate::fs_syscalls::sys_readahead(args.arg0 as i32, args.arg1, args.arg2 as usize)
            }
        }

        // SYS_SYNC_FILE_RANGE (277): sync a file segment to backing store;
        // ramfs has no backing store — validate fd and return 0.
        oncrix_syscall::number::SYS_SYNC_FILE_RANGE => {
            // SAFETY: Single-CPU SYSCALL dispatch path.
            unsafe {
                crate::fs_syscalls::sys_sync_file_range(
                    args.arg0 as i32,
                    args.arg1,
                    args.arg2,
                    args.arg3 as u32,
                )
            }
        }

        // SYS_FALLOCATE (285): pre-allocate / extend file space.
        // mode==0 extends the file to offset+len; non-zero mode is a no-op on ramfs.
        oncrix_syscall::number::SYS_FALLOCATE => {
            // SAFETY: Single-CPU SYSCALL dispatch path.
            unsafe {
                crate::fs_syscalls::sys_fallocate(
                    args.arg0 as i32,
                    args.arg1 as i32,
                    args.arg2,
                    args.arg3,
                )
            }
        }

        // SYS_SYMLINK (88): create a symbolic link.
        // POSIX.1-2024 symlink(3p).
        oncrix_syscall::number::SYS_SYMLINK => {
            // SAFETY: Single-CPU SYSCALL dispatch path.
            unsafe { crate::fs_syscalls::sys_symlink(args.arg0, args.arg1) }
        }

        // SYS_READLINK (89): read a symbolic link target.
        // POSIX.1-2024 readlink(3p).
        oncrix_syscall::number::SYS_READLINK => {
            // SAFETY: Single-CPU SYSCALL dispatch path.
            unsafe { crate::fs_syscalls::sys_readlink(args.arg0, args.arg1, args.arg2) }
        }

        // SYS_TRUNCATE (76): set file length.
        // POSIX.1-2024 truncate(3p).
        oncrix_syscall::number::SYS_TRUNCATE => {
            // SAFETY: Single-CPU SYSCALL dispatch path.
            unsafe { crate::fs_syscalls::sys_truncate(args.arg0, args.arg1) }
        }

        // SYS_RMDIR (84): remove an empty directory.
        // POSIX.1-2024 rmdir(3p).
        oncrix_syscall::number::SYS_RMDIR => {
            // SAFETY: Single-CPU SYSCALL dispatch path.
            unsafe { crate::fs_syscalls::sys_rmdir(args.arg0) }
        }

        // SYS_MKNOD (133): create a FIFO node (mkfifo subset).
        // POSIX.1-2024 mkfifo(3p).
        oncrix_syscall::number::SYS_MKNOD => {
            // SAFETY: Single-CPU SYSCALL dispatch path.
            unsafe { crate::fs_syscalls::sys_mknod(args.arg0, args.arg1) }
        }

        // SYS_GETDENTS64 (217): read directory entries.
        // Linux getdents64(2) / POSIX.1-2024 readdir(3p) equivalent.
        oncrix_syscall::number::SYS_GETDENTS64 => {
            // SAFETY: Single-CPU SYSCALL dispatch path.
            unsafe { crate::fs_syscalls::sys_getdents64(args.arg0 as usize, args.arg1, args.arg2) }
        }

        // SYS_DUP (32): duplicate `oldfd` to the lowest available fd.
        // POSIX.1-2024 dup(3p). New descriptor does not inherit FD_CLOEXEC.
        oncrix_syscall::number::SYS_DUP => {
            // SAFETY: Single-CPU SYSCALL dispatch path.
            unsafe { crate::fd_table::sys_dup(args.arg0 as usize) }
        }

        // SYS_CLOSE_RANGE (436): close all open fds in [first, last].
        // Linux close_range(2); flags=0 or CLOSE_RANGE_CLOEXEC(4).
        oncrix_syscall::number::SYS_CLOSE_RANGE => {
            // SAFETY: Single-CPU SYSCALL dispatch path.
            unsafe {
                crate::fd_table::sys_close_range(
                    args.arg0 as usize,
                    args.arg1 as usize,
                    args.arg2 as u32,
                )
            }
        }

        // SYS_SETXATTR (188) / SYS_LSETXATTR (189) / SYS_FSETXATTR (190):
        // Set an extended attribute. ONCRIX ramfs carries no xattr store;
        // POSIX.1-2024 permits returning ENOTSUP (-95) when the filesystem
        // does not support extended attributes.
        oncrix_syscall::number::SYS_SETXATTR
        | oncrix_syscall::number::SYS_LSETXATTR
        | oncrix_syscall::number::SYS_FSETXATTR => -95,

        // SYS_GETXATTR (191) / SYS_LGETXATTR (192) / SYS_FGETXATTR (193):
        // Get an extended attribute. With no xattr store the named attribute
        // is always absent; return ENODATA (-61) per Linux / POSIX convention.
        oncrix_syscall::number::SYS_GETXATTR
        | oncrix_syscall::number::SYS_LGETXATTR
        | oncrix_syscall::number::SYS_FGETXATTR => -61,

        // SYS_LISTXATTR (194) / SYS_LLISTXATTR (195) / SYS_FLISTXATTR (196):
        // List extended attribute names. The attribute list is empty; return 0
        // (zero bytes written) without touching the user buffer.
        oncrix_syscall::number::SYS_LISTXATTR
        | oncrix_syscall::number::SYS_LLISTXATTR
        | oncrix_syscall::number::SYS_FLISTXATTR => 0,

        // SYS_REMOVEXATTR (197) / SYS_LREMOVEXATTR (198) / SYS_FREMOVEXATTR (199):
        // Remove an extended attribute. Attribute is always absent on ramfs;
        // return ENODATA (-61).
        oncrix_syscall::number::SYS_REMOVEXATTR
        | oncrix_syscall::number::SYS_LREMOVEXATTR
        | oncrix_syscall::number::SYS_FREMOVEXATTR => -61,

        // SYS_SENDFILE (40): copy data between file descriptors in the kernel.
        // POSIX-adjacent; Linux sendfile(2). Both fds must be RamfsFile.
        oncrix_syscall::number::SYS_SENDFILE => {
            // SAFETY: Single-CPU SYSCALL dispatch path.
            unsafe { crate::fs_syscalls::sys_sendfile(args.arg0, args.arg1, args.arg2, args.arg3) }
        }

        // SYS_COPY_FILE_RANGE (326): in-kernel file-to-file range copy.
        // Linux copy_file_range(2). Both fds must be RamfsFile; flags must
        // be zero.
        oncrix_syscall::number::SYS_COPY_FILE_RANGE => {
            // SAFETY: Single-CPU SYSCALL dispatch path.
            unsafe {
                crate::fs_syscalls::sys_copy_file_range(
                    args.arg0, args.arg1, args.arg2, args.arg3, args.arg4, args.arg5,
                )
            }
        }

        // ── Signal syscalls ──────────────────────────────────────

        // Superseded by the full rt_sigaction below (sched_syscalls path
        // with sigsetsize). Old 3-arg stub kept out of the dispatch table.

        // SYS_RT_SIGRETURN (15): return from a user-mode signal handler.
        // Reads the kernel-pushed UserSignalFrame at `arg0` and restores
        // the saved user context for SYSRET.
        oncrix_syscall::number::SYS_RT_SIGRETURN => {
            // SAFETY: Single-CPU SYSCALL dispatch path; do_sigreturn
            // validates the frame magic before touching saved-user atomics.
            unsafe { crate::signal_dispatch::do_sigreturn(args.arg0) }
        }

        // SYS_KILL (62): send a signal to a process.
        // POSIX.1-2024 kill(3p).
        oncrix_syscall::number::SYS_KILL => {
            // SAFETY: Single-CPU SYSCALL dispatch path.
            unsafe { crate::fork_dispatch::sys_kill(args.arg0, args.arg1) }
        }

        // SYS_TKILL (200): send signal to a specific thread.
        // ONCRIX is single-thread-per-process (tid == pid), so delegate
        // directly to sys_kill(tid, sig).
        // SYS_RT_SIGPENDING (127): copy the pending-signal set to user space.
        oncrix_syscall::number::SYS_RT_SIGPENDING => {
            // SAFETY: Single-CPU SYSCALL dispatch path.
            unsafe { crate::fork_dispatch::sys_rt_sigpending(args.arg0, args.arg1) }
        }
        // SYS_SIGALTSTACK (131): set/query the alternate signal stack (no-op).
        oncrix_syscall::number::SYS_SIGALTSTACK => {
            // SAFETY: Single-CPU SYSCALL dispatch path.
            unsafe { crate::fork_dispatch::sys_sigaltstack(args.arg0, args.arg1) }
        }
        // SYS_RT_SIGQUEUEINFO (129): queue a signal (delegates to kill).
        oncrix_syscall::number::SYS_RT_SIGQUEUEINFO => {
            // SAFETY: Single-CPU SYSCALL dispatch path.
            unsafe { crate::fork_dispatch::sys_rt_sigqueueinfo(args.arg0, args.arg1, args.arg2) }
        }

        oncrix_syscall::number::SYS_TKILL => {
            // SAFETY: Single-CPU SYSCALL dispatch path.
            unsafe { crate::fork_dispatch::sys_kill(args.arg0, args.arg1) }
        }

        // SYS_TGKILL (234): send signal to thread `tid` in thread group `tgid`.
        // ONCRIX is single-thread-per-process, so tgid must equal tid.
        // If tgid != tid there is no matching thread; return -ESRCH (-3).
        oncrix_syscall::number::SYS_TGKILL => {
            let tgid = args.arg0;
            let tid = args.arg1;
            let sig = args.arg2;
            if tgid != tid {
                -3 // ESRCH — no such thread in that group
            } else {
                // SAFETY: Single-CPU SYSCALL dispatch path.
                unsafe { crate::fork_dispatch::sys_kill(tid, sig) }
            }
        }

        // SYS_SCHED_RR_GET_INTERVAL (148): POSIX.1-2024 sched_rr_get_interval(3p).
        // Writes the 10 ms round-robin quantum to the user timespec pointer.
        oncrix_syscall::number::SYS_SCHED_RR_GET_INTERVAL => {
            // SAFETY: Single-CPU SYSCALL dispatch path.
            unsafe { crate::sched_syscalls::sys_sched_rr_get_interval(args.arg0, args.arg1) }
        }

        // SYS_DUP2 (33): duplicate `oldfd` onto `newfd`, atomically
        // closing `newfd` if it was already open.
        // POSIX.1-2024 dup2(3p).
        oncrix_syscall::number::SYS_DUP2 => {
            // SAFETY: Single-CPU SYSCALL dispatch path.
            unsafe { crate::fd_table::fd_dup2(args.arg0 as usize, args.arg1 as usize) }
        }

        // SYS_UMASK (95): set the file-mode creation mask. POSIX.1-2024.
        oncrix_syscall::number::SYS_UMASK => {
            // SAFETY: Single-CPU SYSCALL dispatch path.
            unsafe { crate::sched_syscalls::sys_umask(args.arg0) }
        }

        // SYS_FTRUNCATE (77): truncate the regular file referenced by fd.
        oncrix_syscall::number::SYS_FTRUNCATE => {
            // SAFETY: Single-CPU SYSCALL dispatch path.
            unsafe { crate::fs_syscalls::sys_ftruncate(args.arg0, args.arg1) }
        }

        // SYS_FCHMOD (91) / SYS_FCHOWN (93): chmod/chown by descriptor.
        oncrix_syscall::number::SYS_FCHMOD => {
            // SAFETY: Single-CPU SYSCALL dispatch path.
            unsafe { crate::fs_syscalls::sys_fchmod(args.arg0 as i32, args.arg1 as u32) }
        }
        oncrix_syscall::number::SYS_FCHOWN => {
            // SAFETY: Single-CPU SYSCALL dispatch path.
            unsafe {
                crate::fs_syscalls::sys_fchown(args.arg0 as i32, args.arg1 as u32, args.arg2 as u32)
            }
        }

        // SYS_DUP3 (292): like dup2 but takes an O_CLOEXEC flag and rejects
        // oldfd==newfd with EINVAL. POSIX.1-2024 dup3(2).
        oncrix_syscall::number::SYS_DUP3 => {
            // SAFETY: Single-CPU SYSCALL dispatch path.
            unsafe {
                crate::fd_table::sys_dup3(args.arg0 as usize, args.arg1 as usize, args.arg2 as u32)
            }
        }

        // ── Working directory syscalls ────────────────────────────

        // SYS_GETCWD (79): copy current working directory to user buffer.
        // POSIX.1-2024 getcwd(3p).
        oncrix_syscall::number::SYS_GETCWD => {
            // SAFETY: Single-CPU SYSCALL dispatch path.
            unsafe { crate::fork_dispatch::sys_getcwd(args.arg0, args.arg1) }
        }

        // SYS_CHDIR (80): change the process working directory.
        // POSIX.1-2024 chdir(3p).
        oncrix_syscall::number::SYS_CHDIR => {
            // SAFETY: Single-CPU SYSCALL dispatch path.
            unsafe { crate::fork_dispatch::sys_chdir(args.arg0) }
        }

        // SYS_MMAP (9): map anonymous (or file-backed in future phases)
        // memory into the calling process's address space. POSIX.1-2024
        // mmap(3p). The Phase 14 kernel handler only supports
        // anonymous, private, fd=-1 mappings; everything else returns
        // -EINVAL.
        oncrix_syscall::number::SYS_MMAP => {
            // SAFETY: Single-CPU SYSCALL dispatch path.
            unsafe {
                crate::mmap_dispatch::sys_mmap(
                    args.arg0, args.arg1, args.arg2, args.arg3, args.arg4, args.arg5,
                )
            }
        }

        // ── Time syscalls ─────────────────────────────────────────

        // SYS_TIME (201): seconds since boot. POSIX.1-2024 time(3p)
        // (deviates: no RTC, so reference is boot not the Epoch).
        oncrix_syscall::number::SYS_TIME => {
            // SAFETY: Single-CPU SYSCALL dispatch path.
            unsafe { crate::time_syscalls::sys_time(args.arg0) }
        }

        // SYS_CLOCK_GETTIME (228): write timespec for the requested
        // clock. POSIX.1-2024 clock_gettime(3p).
        oncrix_syscall::number::SYS_CLOCK_GETTIME => {
            // SAFETY: Single-CPU SYSCALL dispatch path.
            unsafe { crate::time_syscalls::sys_clock_gettime(args.arg0 as u32, args.arg1) }
        }

        // SYS_UNAME (63): fill struct utsname with system identification.
        // POSIX.1-2024 uname(3p). nodename/domainname reflect the mutable globals.
        oncrix_syscall::number::SYS_UNAME => {
            // SAFETY: Single-CPU SYSCALL dispatch path.
            unsafe { crate::sysid_syscall::sys_uname(args.arg0) }
        }

        // SYS_SETHOSTNAME (170): set the system hostname (up to 64 bytes).
        oncrix_syscall::number::SYS_SETHOSTNAME => {
            // SAFETY: Single-CPU SYSCALL dispatch path.
            unsafe { crate::sysid_syscall::sys_sethostname(args.arg0, args.arg1) }
        }

        // SYS_SETDOMAINNAME (171): set the NIS/YP domain name (up to 64 bytes).
        oncrix_syscall::number::SYS_SETDOMAINNAME => {
            // SAFETY: Single-CPU SYSCALL dispatch path.
            unsafe { crate::sysid_syscall::sys_setdomainname(args.arg0, args.arg1) }
        }

        // SYS_GETTIMEOFDAY (96): write struct timeval from PIT tick counter;
        // zero-fill optional struct timezone. POSIX.1-2024 gettimeofday(3p)
        // (marked obsolescent — use clock_gettime instead).
        oncrix_syscall::number::SYS_GETTIMEOFDAY => {
            // SAFETY: Single-CPU SYSCALL dispatch path.
            unsafe { crate::time_syscalls::sys_gettimeofday(args.arg0, args.arg1) }
        }

        // SYS_SETTIMEOFDAY (164): ONCRIX has no settable RTC; always -EPERM.
        // POSIX.1-2024 settimeofday(3p).
        oncrix_syscall::number::SYS_SETTIMEOFDAY => {
            // SAFETY: Single-CPU SYSCALL dispatch path; no pointer is dereferenced.
            unsafe { crate::time_syscalls::sys_settimeofday(args.arg0, args.arg1) }
        }

        // SYS_CLOCK_GETRES (229): report PIT clock resolution (10 ms / 10_000_000 ns).
        // POSIX.1-2024 clock_getres(3p).
        oncrix_syscall::number::SYS_CLOCK_GETRES => {
            // SAFETY: Single-CPU SYSCALL dispatch path.
            unsafe { crate::time_syscalls::sys_clock_getres(args.arg0 as u32, args.arg1) }
        }

        // SYS_CAPGET (125): retrieve capability sets for the calling thread.
        // ONCRIX has no capability model; data is zero-filled. POSIX.1-2024 / Linux capget(2).
        oncrix_syscall::number::SYS_CAPGET => {
            // SAFETY: Single-CPU SYSCALL dispatch path.
            unsafe { crate::fs_syscalls::sys_capget(args.arg0, args.arg1) }
        }

        // SYS_CAPSET (126): set capability sets for the calling thread.
        // No-op on ONCRIX (no capability enforcement). Linux capset(2).
        oncrix_syscall::number::SYS_CAPSET => {
            // SAFETY: Single-CPU SYSCALL dispatch path.
            unsafe { crate::fs_syscalls::sys_capset(args.arg0, args.arg1) }
        }

        // SYS_GETGROUPS (115): get supplementary group IDs.
        // ONCRIX has no supplementary groups; always returns 0. POSIX.1-2024 getgroups(3p).
        oncrix_syscall::number::SYS_GETGROUPS => {
            // SAFETY: Single-CPU SYSCALL dispatch path.
            unsafe { crate::fs_syscalls::sys_getgroups(args.arg0 as i64, args.arg1) }
        }

        // SYS_SETGROUPS (116): set supplementary group IDs.
        // Refused with EPERM for size>0; size==0 is a no-op. POSIX.1-2024 setgroups(3p).
        oncrix_syscall::number::SYS_SETGROUPS => {
            // SAFETY: Single-CPU SYSCALL dispatch path.
            unsafe { crate::fs_syscalls::sys_setgroups(args.arg0 as i64, args.arg1) }
        }

        // SYS_PERSONALITY (135): query or set execution domain.
        // ONCRIX supports PER_LINUX only; always returns 0. Linux personality(2).
        oncrix_syscall::number::SYS_PERSONALITY => {
            // SAFETY: Single-CPU SYSCALL dispatch path.
            unsafe { crate::fs_syscalls::sys_personality(args.arg0) }
        }

        // SYS_NANOSLEEP (35): block for the requested duration via
        // cooperative yield_now polling. POSIX.1-2024 nanosleep(3p).
        oncrix_syscall::number::SYS_NANOSLEEP => {
            // SAFETY: Single-CPU SYSCALL dispatch path.
            unsafe { crate::time_syscalls::sys_nanosleep(args.arg0, args.arg1) }
        }

        // SYS_GETPRIORITY (140) / SYS_SETPRIORITY (141) / SYS_NICE (34):
        // POSIX.1-2024 process scheduling priority. Handlers live in the
        // kernel sched_syscalls module and operate on the current thread.
        oncrix_syscall::number::SYS_GETPRIORITY => {
            // SAFETY: Single-CPU SYSCALL dispatch path.
            unsafe { crate::sched_syscalls::sys_getpriority(args.arg0 as i64, args.arg1 as i64) }
        }
        oncrix_syscall::number::SYS_SETPRIORITY => {
            // SAFETY: Single-CPU SYSCALL dispatch path.
            unsafe {
                crate::sched_syscalls::sys_setpriority(
                    args.arg0 as i64,
                    args.arg1 as i64,
                    args.arg2 as i64,
                )
            }
        }
        oncrix_syscall::number::SYS_NICE => {
            // SAFETY: Single-CPU SYSCALL dispatch path.
            unsafe { crate::sched_syscalls::sys_nice(args.arg0 as i64) }
        }

        // SYS_FCNTL (72): file/descriptor control — F_DUPFD, F_GETFD/SETFD
        // (FD_CLOEXEC), F_GETFL/SETFL (O_NONBLOCK/O_APPEND). POSIX.1-2024.
        oncrix_syscall::number::SYS_FCNTL => {
            // SAFETY: Single-CPU SYSCALL dispatch path.
            unsafe { crate::fd_table::sys_fcntl(args.arg0 as usize, args.arg1 as i32, args.arg2) }
        }

        // SYS_SCHED_* (24/142-145): POSIX.1-2024 scheduling policy/params.
        // pid is treated as the calling thread (no cross-pid lookup yet).
        oncrix_syscall::number::SYS_SCHED_YIELD => {
            // SAFETY: Single-CPU SYSCALL dispatch path.
            unsafe { crate::sched_syscalls::sys_sched_yield() }
        }
        oncrix_syscall::number::SYS_SCHED_SETSCHEDULER => {
            // SAFETY: Single-CPU SYSCALL dispatch path.
            unsafe {
                crate::sched_syscalls::sys_sched_setscheduler(
                    args.arg0 as i64,
                    args.arg1 as i64,
                    args.arg2,
                )
            }
        }
        oncrix_syscall::number::SYS_SCHED_GETSCHEDULER => {
            // SAFETY: Single-CPU SYSCALL dispatch path.
            unsafe { crate::sched_syscalls::sys_sched_getscheduler(args.arg0 as i64) }
        }
        oncrix_syscall::number::SYS_SCHED_GETPARAM => {
            // SAFETY: Single-CPU SYSCALL dispatch path.
            unsafe { crate::sched_syscalls::sys_sched_getparam(args.arg0 as i64, args.arg1) }
        }
        oncrix_syscall::number::SYS_SCHED_SETPARAM => {
            // SAFETY: Single-CPU SYSCALL dispatch path.
            unsafe { crate::sched_syscalls::sys_sched_setparam(args.arg0 as i64, args.arg1) }
        }

        // SYS_POLL (7): wait for readiness on a set of fds. POSIX.1-2024.
        oncrix_syscall::number::SYS_POLL => {
            // SAFETY: Single-CPU SYSCALL dispatch path.
            unsafe { crate::fd_table::sys_poll(args.arg0, args.arg1, args.arg2 as i64) }
        }

        // SYS_CLOCK_NANOSLEEP (230): sleep against a clock, relative or
        // TIMER_ABSTIME. POSIX.1-2024 clock_nanosleep(3p).
        oncrix_syscall::number::SYS_CLOCK_NANOSLEEP => {
            // SAFETY: Single-CPU SYSCALL dispatch path.
            unsafe {
                crate::time_syscalls::sys_clock_nanosleep(
                    args.arg0 as u32,
                    args.arg1 as i32,
                    args.arg2,
                    args.arg3,
                )
            }
        }

        // SYS_SETPGID (109) / SYS_GETPGID (121) / SYS_SETSID (112) /
        // SYS_GETSID (124): POSIX.1-2024 process group + session API.
        oncrix_syscall::number::SYS_SETPGID => {
            // SAFETY: Single-CPU SYSCALL dispatch path.
            unsafe { crate::sched_syscalls::sys_setpgid(args.arg0, args.arg1) }
        }
        oncrix_syscall::number::SYS_GETPGID => {
            // SAFETY: Single-CPU SYSCALL dispatch path.
            unsafe { crate::sched_syscalls::sys_getpgid(args.arg0) }
        }
        oncrix_syscall::number::SYS_SETSID => {
            // SAFETY: Single-CPU SYSCALL dispatch path.
            unsafe { crate::sched_syscalls::sys_setsid() }
        }
        oncrix_syscall::number::SYS_GETSID => {
            // SAFETY: Single-CPU SYSCALL dispatch path.
            unsafe { crate::sched_syscalls::sys_getsid(args.arg0) }
        }

        // SYS_PRLIMIT64 (302) / SYS_GETRLIMIT (97) / SYS_SETRLIMIT (160):
        // POSIX.1-2024 resource limits.
        oncrix_syscall::number::SYS_PRLIMIT64 => {
            // SAFETY: Single-CPU SYSCALL dispatch path.
            unsafe {
                crate::sched_syscalls::sys_prlimit64(args.arg0, args.arg1, args.arg2, args.arg3)
            }
        }
        oncrix_syscall::number::SYS_GETRLIMIT => {
            // SAFETY: Single-CPU SYSCALL dispatch path.
            unsafe { crate::sched_syscalls::sys_getrlimit(args.arg0, args.arg1) }
        }
        oncrix_syscall::number::SYS_SETRLIMIT => {
            // SAFETY: Single-CPU SYSCALL dispatch path.
            unsafe { crate::sched_syscalls::sys_setrlimit(args.arg0, args.arg1) }
        }

        // SYS_RT_SIGACTION (13) / SYS_RT_SIGPROCMASK (14): per-process
        // signal disposition + per-thread blocked-signal mask.
        oncrix_syscall::number::SYS_RT_SIGACTION => {
            // SAFETY: Single-CPU SYSCALL dispatch path.
            unsafe {
                crate::sched_syscalls::sys_rt_sigaction(
                    args.arg0 as i64,
                    args.arg1,
                    args.arg2,
                    args.arg3,
                )
            }
        }
        oncrix_syscall::number::SYS_RT_SIGPROCMASK => {
            // SAFETY: Single-CPU SYSCALL dispatch path.
            unsafe {
                crate::sched_syscalls::sys_rt_sigprocmask(
                    args.arg0 as i64,
                    args.arg1,
                    args.arg2,
                    args.arg3,
                )
            }
        }

        // SYS_EVENTFD2 (290): create a pollable u64 counter fd.
        oncrix_syscall::number::SYS_EVENTFD2 => {
            // SAFETY: Single-CPU SYSCALL dispatch path.
            unsafe { crate::fd_table::sys_eventfd2(args.arg0, args.arg1 as u32) }
        }

        // SYS_SOCKETPAIR (53): connected AF_UNIX descriptor pair.
        oncrix_syscall::number::SYS_SOCKETPAIR => {
            // SAFETY: Single-CPU SYSCALL dispatch path.
            unsafe {
                crate::fd_table::sys_socketpair(
                    args.arg0 as i64,
                    args.arg1 as i64,
                    args.arg2 as i64,
                    args.arg3,
                )
            }
        }

        // SYS_SIGNALFD4 (289): pollable signal file descriptor.
        oncrix_syscall::number::SYS_SIGNALFD4 => {
            // SAFETY: Single-CPU SYSCALL dispatch path.
            unsafe {
                crate::fd_table::sys_signalfd4(
                    args.arg0 as i32,
                    args.arg1,
                    args.arg2,
                    args.arg3 as i32,
                )
            }
        }

        // SYS_TIMERFD_* (283/286/287): pollable timer file descriptors.
        oncrix_syscall::number::SYS_TIMERFD_CREATE => {
            // SAFETY: Single-CPU SYSCALL dispatch path.
            unsafe { crate::fd_table::sys_timerfd_create(args.arg0 as i32, args.arg1 as i32) }
        }
        oncrix_syscall::number::SYS_TIMERFD_SETTIME => {
            // SAFETY: Single-CPU SYSCALL dispatch path.
            unsafe {
                crate::fd_table::sys_timerfd_settime(
                    args.arg0 as usize,
                    args.arg1 as i32,
                    args.arg2,
                    args.arg3,
                )
            }
        }
        oncrix_syscall::number::SYS_TIMERFD_GETTIME => {
            // SAFETY: Single-CPU SYSCALL dispatch path.
            unsafe { crate::fd_table::sys_timerfd_gettime(args.arg0 as usize, args.arg1) }
        }

        // SYS_EPOLL_* (291/233/232): scalable I/O event notification.
        oncrix_syscall::number::SYS_EPOLL_CREATE1 => {
            // SAFETY: Single-CPU SYSCALL dispatch path.
            unsafe { crate::fd_table::sys_epoll_create1(args.arg0 as i32) }
        }
        oncrix_syscall::number::SYS_EPOLL_CTL => {
            // SAFETY: Single-CPU SYSCALL dispatch path.
            unsafe {
                crate::fd_table::sys_epoll_ctl(
                    args.arg0 as usize,
                    args.arg1 as i32,
                    args.arg2 as usize,
                    args.arg3,
                )
            }
        }
        oncrix_syscall::number::SYS_EPOLL_WAIT => {
            // SAFETY: Single-CPU SYSCALL dispatch path.
            unsafe {
                crate::fd_table::sys_epoll_wait(
                    args.arg0 as usize,
                    args.arg1,
                    args.arg2 as i32,
                    args.arg3 as i64,
                )
            }
        }

        // SYS_ALARM (37) / SYS_SETITIMER (38) / SYS_GETITIMER (36):
        // ITIMER_REAL interval timers; expiry raises SIGALRM. POSIX.1-2024.
        oncrix_syscall::number::SYS_ALARM => {
            // SAFETY: Single-CPU SYSCALL dispatch path.
            unsafe { crate::sched_syscalls::sys_alarm(args.arg0) }
        }
        oncrix_syscall::number::SYS_SETITIMER => {
            // SAFETY: Single-CPU SYSCALL dispatch path.
            unsafe { crate::sched_syscalls::sys_setitimer(args.arg0 as i64, args.arg1, args.arg2) }
        }
        oncrix_syscall::number::SYS_GETITIMER => {
            // SAFETY: Single-CPU SYSCALL dispatch path.
            unsafe { crate::sched_syscalls::sys_getitimer(args.arg0 as i64, args.arg1) }
        }

        // SYS_SELECT (23): synchronous I/O multiplexing over fd_set bitmaps.
        oncrix_syscall::number::SYS_SELECT => {
            // SAFETY: Single-CPU SYSCALL dispatch path.
            unsafe {
                crate::fd_table::sys_select(
                    args.arg0 as i64,
                    args.arg1,
                    args.arg2,
                    args.arg3,
                    args.arg4,
                )
            }
        }

        // SYS_TIMES (100) / SYS_GETRUSAGE (98): process CPU-time accounting.
        oncrix_syscall::number::SYS_TIMES => {
            // SAFETY: Single-CPU SYSCALL dispatch path.
            unsafe { crate::sched_syscalls::sys_times(args.arg0) }
        }
        oncrix_syscall::number::SYS_GETRUSAGE => {
            // SAFETY: Single-CPU SYSCALL dispatch path.
            unsafe { crate::sched_syscalls::sys_getrusage(args.arg0 as i64, args.arg1) }
        }

        // SYS_SCHED_GETAFFINITY (204) / SYS_SCHED_SETAFFINITY (203): CPU
        // affinity. Single-CPU system, so the only valid mask is {CPU 0}.
        oncrix_syscall::number::SYS_SCHED_GETAFFINITY => {
            // SAFETY: Single-CPU SYSCALL dispatch path.
            unsafe {
                crate::sched_syscalls::sys_sched_getaffinity(args.arg0 as i64, args.arg1, args.arg2)
            }
        }
        oncrix_syscall::number::SYS_SCHED_SETAFFINITY => {
            // SAFETY: Single-CPU SYSCALL dispatch path.
            unsafe {
                crate::sched_syscalls::sys_sched_setaffinity(args.arg0 as i64, args.arg1, args.arg2)
            }
        }

        // ── Everything else ──────────────────────────────────────
        _ => oncrix_syscall::dispatch::dispatch(args),
    };

    // SYSCALL epilogue: deliver any pending signals before returning
    // to user space. This is the canonical "check for signals on
    // return-to-user" point. Terminate-class signals call sys_exit
    // and never return; ignore-class signals just clear pending bits.
    //
    // SAFETY: single-CPU SYSCALL context with interrupts effectively
    // disabled (FMASK cleared IF on entry and we have not re-enabled
    // them in this Rust frame). This is the only context in which
    // the global PROCESS_TABLE may be mutated without further sync.
    unsafe { crate::signal_dispatch::deliver_pending_signals(args_ptr) };

    result
}

// ── VFS syscall implementations ──────────────────────────────────

/// Maximum path length accepted from user space for `open(2)`.
const MAX_OPEN_PATH: usize = 256;

/// Resolve a user-supplied path against the calling process's cwd.
///
/// If `path` starts with `/`, returns a slice pointing into `abs_buf`
/// with a copy of `path`.  Otherwise prepends the current thread's cwd
/// and returns the combined absolute path.  Returns `None` on overflow
/// or an empty path.
///
/// `abs_buf` must be at least `MAX_OPEN_PATH + 1` bytes.
///
/// # Safety
///
/// `path` must be a valid slice read from user space.
unsafe fn resolve_to_abs<'b>(
    path: &[u8],
    abs_buf: &'b mut [u8; MAX_OPEN_PATH],
) -> Option<&'b [u8]> {
    if path.is_empty() {
        return None;
    }
    if path[0] == b'/' {
        // Already absolute — just copy.
        let len = path.len().min(MAX_OPEN_PATH - 1);
        abs_buf[..len].copy_from_slice(&path[..len]);
        return Some(&abs_buf[..len]);
    }
    // Relative: prepend cwd.
    let (cwd_ptr, cwd_len) = crate::current::current_thread()
        .map(|t| {
            let s = t.cwd();
            (s.as_ptr(), s.len())
        })
        .unwrap_or((b"/".as_ptr(), 1));
    // SAFETY: cwd slice is always within the thread's own cwd buffer.
    let cwd = unsafe { core::slice::from_raw_parts(cwd_ptr, cwd_len) };

    let copy_cwd = cwd.len().min(MAX_OPEN_PATH - 1);
    abs_buf[..copy_cwd].copy_from_slice(&cwd[..copy_cwd]);
    let mut out = copy_cwd;
    if out < MAX_OPEN_PATH - 1 && (out == 0 || abs_buf[out - 1] != b'/') {
        abs_buf[out] = b'/';
        out += 1;
    }
    let copy_path = path.len().min(MAX_OPEN_PATH - 1 - out);
    abs_buf[out..out + copy_path].copy_from_slice(&path[..copy_path]);
    out += copy_path;
    if out >= MAX_OPEN_PATH {
        return None; // ENAMETOOLONG
    }
    Some(&abs_buf[..out])
}

/// Kernel handler for `SYS_OPEN` (Linux number 2).
///
/// POSIX.1-2024 `open(3p)` semantics:
/// - Resolves `pathname_ptr` against the calling process's cwd (supports
///   both absolute and relative paths).
/// - Creates the file if `O_CREAT` is set and the file does not exist.
/// - Allocates the lowest available fd and installs the handle.
///
/// Phase 12 simplifications:
/// - No permission checks (all files are accessible as uid=0).
/// - No `O_EXCL`, `O_NOCTTY`, `O_DIRECTORY` handling.
///
/// # Safety
///
/// Must be called from the SYSCALL dispatch path.
unsafe fn sys_open(pathname_ptr: u64, flags: u64, mode: u64) -> i64 {
    // Validate the pathname pointer.
    if pathname_ptr == 0 || pathname_ptr >= 0xFFFF_8000_0000_0000 {
        return -22; // EINVAL
    }

    // Copy the null-terminated path from user space (bounded copy).
    static mut PATH_BUF: [u8; MAX_OPEN_PATH] = [0u8; MAX_OPEN_PATH];
    static mut ABS_BUF: [u8; MAX_OPEN_PATH] = [0u8; MAX_OPEN_PATH];
    // SAFETY: single-CPU SYSCALL context; PATH_BUF/ABS_BUF exclusively owned here.
    #[allow(static_mut_refs)]
    let abs_path: &[u8] = unsafe {
        let buf = &mut PATH_BUF;
        let base = pathname_ptr as *const u8;
        let mut i = 0usize;
        loop {
            if i >= MAX_OPEN_PATH - 1 {
                return -36; // ENAMETOOLONG
            }
            let byte = base.add(i).read_volatile();
            if byte == 0 {
                break;
            }
            buf[i] = byte;
            i += 1;
        }
        let path_bytes = &buf[..i];
        match resolve_to_abs(path_bytes, &mut ABS_BUF) {
            Some(p) => p,
            None => return -36, // ENAMETOOLONG or empty
        }
    };

    if abs_path.is_empty() {
        return -22; // EINVAL
    }

    // Fast path: intercept /dev/null and /dev/zero before touching the ramfs.
    // These are synthetic devices with no backing inode — reads and writes
    // are handled entirely in the fd dispatch layer.
    if let Some(dev_kind) = oncrix_vfs::devfs::classify_dev_path(abs_path) {
        let fd_kind = match dev_kind {
            oncrix_vfs::devfs::DevKind::Null => crate::fd_table::DevFileKind::Null,
            oncrix_vfs::devfs::DevKind::Zero => crate::fd_table::DevFileKind::Zero,
        };
        let handle_flags = crate::fd_table::HandleFlags(flags as u32);
        let handle = crate::fd_table::FileHandle::dev_file(fd_kind, handle_flags);
        // SAFETY: single-CPU SYSCALL context.
        return match unsafe { crate::fd_table::fd_install(handle) } {
            Ok(fd) => fd as i64,
            Err(_) => -24, // EMFILE
        };
    }

    // Fast path: intercept /proc/uptime, /proc/version, /proc/meminfo.
    // Reads are synthesized by procfs_dispatch; the ramfs stub inode exists
    // only so that `ls /proc` lists the entries via getdents64.
    if let Some(proc_kind) = oncrix_vfs::procfs::classify_proc_path(abs_path) {
        let fd_kind = match proc_kind {
            oncrix_vfs::procfs::ProcKind::Uptime => crate::fd_table::ProcFileKind::Uptime,
            oncrix_vfs::procfs::ProcKind::Version => crate::fd_table::ProcFileKind::Version,
            oncrix_vfs::procfs::ProcKind::Meminfo => crate::fd_table::ProcFileKind::Meminfo,
        };
        let handle_flags = crate::fd_table::HandleFlags(flags as u32);
        let handle = crate::fd_table::FileHandle::proc_file(fd_kind, handle_flags);
        // SAFETY: single-CPU SYSCALL context.
        return match unsafe { crate::fd_table::fd_install(handle) } {
            Ok(fd) => fd as i64,
            Err(_) => -24, // EMFILE
        };
    }

    // Attempt to open / create the file in the global VFS.
    let result =
        crate::state::with_global_mut(|s| s.vfs.open_path(abs_path, flags as u32, mode as u32));

    match result {
        Some(Ok(inode)) => {
            // FIFO: route to the pipe-backed open path instead of a ramfs handle.
            if inode.file_type == oncrix_vfs::inode::FileType::Fifo {
                // SAFETY: single-CPU SYSCALL context.
                return unsafe { crate::fd_table::open_fifo(inode.ino, flags as u32) };
            }
            // Build a FileHandle for the ramfs inode.
            let handle_flags = crate::fd_table::HandleFlags(flags as u32);
            let handle = crate::fd_table::FileHandle::ramfs_file(inode.ino, handle_flags);

            // Install in the current fd table.
            // SAFETY: single-CPU SYSCALL context.
            match unsafe { crate::fd_table::fd_install(handle) } {
                Ok(fd) => fd as i64,
                Err(_) => -24, // EMFILE
            }
        }
        Some(Err(oncrix_lib::Error::NotFound)) => -2, // ENOENT
        Some(Err(oncrix_lib::Error::AlreadyExists)) => -17, // EEXIST
        Some(Err(oncrix_lib::Error::OutOfMemory)) => -12, // ENOMEM
        Some(Err(_)) => -22,                          // EINVAL
        None => -5,                                   // EIO — VFS not initialised
    }
}

// ── Saved-register accessors (for fork / execve handlers) ───────

/// Read the user-mode RIP saved by the SYSCALL entry stub.
///
/// Must be called from within the SYSCALL dispatch path (i.e. while
/// the current CPU is serving a SYSCALL), otherwise the value is
/// stale from a previous call.
pub fn saved_user_rip() -> u64 {
    SYSCALL_SAVED_USER_RIP.load(Ordering::Relaxed)
}

/// Read the user-mode RFLAGS saved by the SYSCALL entry stub.
///
/// Same timing contract as [`saved_user_rip`].
pub fn saved_user_rflags() -> u64 {
    SYSCALL_SAVED_USER_RFLAGS.load(Ordering::Relaxed)
}

/// Read the user-mode RSP saved by the SYSCALL entry stub.
pub fn saved_user_rsp() -> u64 {
    SYSCALL_SAVED_USER_RSP.load(Ordering::Relaxed)
}

/// Overwrite the saved user-mode RIP.
///
/// The SYSCALL epilogue restores RCX from [`SYSCALL_SAVED_USER_RIP`],
/// so writing here redirects the post-syscall return-to-user address.
/// Used by `execve` to jump to the new program entry point.
pub fn set_saved_user_rip(rip: u64) {
    SYSCALL_SAVED_USER_RIP.store(rip, Ordering::Relaxed);
}

/// Overwrite the saved user-mode RFLAGS.
pub fn set_saved_user_rflags(rflags: u64) {
    SYSCALL_SAVED_USER_RFLAGS.store(rflags, Ordering::Relaxed);
}

/// Overwrite the saved user-mode RSP.
pub fn set_saved_user_rsp(rsp: u64) {
    SYSCALL_SAVED_USER_RSP.store(rsp, Ordering::Relaxed);
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
