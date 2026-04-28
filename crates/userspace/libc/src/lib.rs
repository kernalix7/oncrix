// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Minimal `no_std` libc shim for ONCRIX userspace programs.
//!
//! Exposes thin wrappers around the kernel SYSCALL interface using the
//! x86-64 System V ABI calling convention.  Each function issues the
//! corresponding syscall number via the `syscall` instruction and returns
//! the raw kernel result (negative errno on error).

#![no_std]

// Re-export error helpers so callers can check for POSIX errno values.

/// POSIX errno: operation not permitted.
pub const EPERM: i64 = 1;
/// POSIX errno: no such file or directory.
pub const ENOENT: i64 = 2;
/// POSIX errno: interrupted system call.
pub const EINTR: i64 = 4;
/// POSIX errno: bad file descriptor.
pub const EBADF: i64 = 9;
/// POSIX errno: no child processes.
pub const ECHILD: i64 = 10;
/// POSIX errno: resource temporarily unavailable.
pub const EAGAIN: i64 = 11;
/// POSIX errno: not enough memory.
pub const ENOMEM: i64 = 12;
/// POSIX errno: permission denied.
pub const EACCES: i64 = 13;
/// POSIX errno: bad address.
pub const EFAULT: i64 = 14;
/// POSIX errno: invalid argument.
pub const EINVAL: i64 = 22;
/// POSIX errno: function not implemented.
pub const ENOSYS: i64 = 38;

// ---------------------------------------------------------------------------
// Syscall numbers (x86-64 Linux ABI — compatible with ONCRIX)
// ---------------------------------------------------------------------------

const SYS_READ: u64 = 0;
const SYS_WRITE: u64 = 1;
const SYS_OPEN: u64 = 2;
const SYS_CLOSE: u64 = 3;
const SYS_GETPID: u64 = 39;
const SYS_FORK: u64 = 57;
const SYS_EXECVE: u64 = 59;
const SYS_EXIT: u64 = 60;
const SYS_WAIT4: u64 = 61;

// ---------------------------------------------------------------------------
// Raw syscall wrappers
// ---------------------------------------------------------------------------

/// Issue a 1-argument syscall.
///
/// # Safety
///
/// The syscall number and argument must be valid per the ONCRIX ABI.
unsafe fn syscall1(nr: u64, a0: u64) -> i64 {
    let ret: i64;
    // SAFETY: `syscall` traps into the kernel. The caller guarantees
    // the syscall number and arguments are valid.
    unsafe {
        core::arch::asm!(
            "syscall",
            in("rax") nr,
            in("rdi") a0,
            lateout("rax") ret,
            // SYSCALL clobbers rcx and r11 per ABI.
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );
    }
    ret
}

/// Issue a 3-argument syscall.
///
/// # Safety
///
/// The syscall number and arguments must be valid per the ONCRIX ABI.
unsafe fn syscall3(nr: u64, a0: u64, a1: u64, a2: u64) -> i64 {
    let ret: i64;
    // SAFETY: `syscall` traps into the kernel. The caller guarantees
    // the syscall number and arguments are valid.
    unsafe {
        core::arch::asm!(
            "syscall",
            in("rax") nr,
            in("rdi") a0,
            in("rsi") a1,
            in("rdx") a2,
            lateout("rax") ret,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );
    }
    ret
}

/// Issue a 4-argument syscall.
///
/// # Safety
///
/// The syscall number and arguments must be valid per the ONCRIX ABI.
unsafe fn syscall4(nr: u64, a0: u64, a1: u64, a2: u64, a3: u64) -> i64 {
    let ret: i64;
    // SAFETY: `syscall` traps into the kernel. The caller guarantees
    // the syscall number and arguments are valid.
    unsafe {
        core::arch::asm!(
            "syscall",
            in("rax") nr,
            in("rdi") a0,
            in("rsi") a1,
            in("rdx") a2,
            in("r10") a3,
            lateout("rax") ret,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );
    }
    ret
}

// ---------------------------------------------------------------------------
// Public POSIX wrappers
// ---------------------------------------------------------------------------

/// `write(2)` — write up to `count` bytes from `buf` to `fd`.
///
/// Returns the number of bytes written, or a negative errno value.
///
/// # Safety
///
/// `buf` must point to at least `count` readable bytes.
pub unsafe fn write(fd: i32, buf: *const u8, count: usize) -> i64 {
    // SAFETY: The caller guarantees `buf` is valid for `count` bytes.
    unsafe { syscall3(SYS_WRITE, fd as u64, buf as u64, count as u64) }
}

/// `read(2)` — read up to `count` bytes from `fd` into `buf`.
///
/// Returns the number of bytes read, 0 on EOF, or a negative errno value.
///
/// # Safety
///
/// `buf` must point to at least `count` writable bytes.
pub unsafe fn read(fd: i32, buf: *mut u8, count: usize) -> i64 {
    // SAFETY: The caller guarantees `buf` is valid for `count` writable bytes.
    unsafe { syscall3(SYS_READ, fd as u64, buf as u64, count as u64) }
}

/// `open(2)` — open a file.
///
/// `path` must be a null-terminated C string.
/// Returns a file descriptor >= 0, or a negative errno value.
///
/// # Safety
///
/// `path` must be a valid null-terminated string pointer.
pub unsafe fn open(path: *const u8, flags: i32, mode: u32) -> i64 {
    // SAFETY: The caller guarantees `path` is null-terminated.
    unsafe { syscall3(SYS_OPEN, path as u64, flags as u64, mode as u64) }
}

/// `close(2)` — close a file descriptor.
///
/// Returns 0 on success, or a negative errno value.
pub fn close(fd: i32) -> i64 {
    // SAFETY: SYS_CLOSE with a single integer argument is always safe.
    unsafe { syscall1(SYS_CLOSE, fd as u64) }
}

/// `getpid(2)` — return the PID of the calling process.
pub fn getpid() -> i64 {
    // SAFETY: getpid() takes no arguments and is always safe to call.
    unsafe { syscall1(SYS_GETPID, 0) }
}

/// `fork(2)` — create a child process.
///
/// Returns the child PID in the parent, 0 in the child, or a negative errno.
pub fn fork() -> i64 {
    // SAFETY: fork() takes no arguments; the kernel copies the process.
    unsafe { syscall1(SYS_FORK, 0) }
}

/// `execve(2)` — execute a program.
///
/// On success this call does not return. Returns a negative errno on error.
///
/// # Safety
///
/// `pathname`, `argv`, and `envp` must be valid null-terminated pointers.
pub unsafe fn execve(pathname: *const u8, argv: *const *const u8, envp: *const *const u8) -> i64 {
    // SAFETY: The caller guarantees all pointer arguments are valid.
    unsafe { syscall3(SYS_EXECVE, pathname as u64, argv as u64, envp as u64) }
}

/// `exit(2)` — terminate the calling process.
///
/// This function does not return.
pub fn exit(status: i32) -> ! {
    // SAFETY: SYS_EXIT terminates the process; `ud2` immediately after is
    // unreachable but tells the compiler that control diverges here.
    // `noreturn` disallows output operands, so we use separate asm blocks:
    // the first issues the syscall (in case it somehow returns on a stub),
    // and the second `ud2` diverges unconditionally.
    unsafe {
        core::arch::asm!(
            "syscall",
            in("rax") SYS_EXIT,
            in("rdi") status as u64,
            options(nostack),
        );
        core::arch::asm!("ud2", options(noreturn, nostack));
    }
}

/// `waitpid(2)` — wait for a child process.
///
/// Returns the PID of the reaped child, or a negative errno value.
///
/// # Safety
///
/// `status` must be a valid pointer to an `i32` if non-null.
pub unsafe fn waitpid(pid: i64, status: *mut i32, options: i32) -> i64 {
    // SAFETY: The caller guarantees `status` is valid if non-null.
    unsafe {
        syscall4(
            SYS_WAIT4,
            pid as u64,
            status as u64,
            options as u64,
            0, // rusage = NULL
        )
    }
}
