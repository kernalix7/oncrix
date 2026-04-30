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
const SYS_DUP2: u64 = 33;
const SYS_GETPID: u64 = 39;
const SYS_GETCWD: u64 = 79;
const SYS_CHDIR: u64 = 80;
const SYS_MKDIR: u64 = 83;
const SYS_UNLINK: u64 = 87;
const SYS_FORK: u64 = 57;
const SYS_EXECVE: u64 = 59;
const SYS_EXIT: u64 = 60;
const SYS_WAIT4: u64 = 61;
const SYS_GETDENTS64: u64 = 217;
const SYS_PIPE2: u64 = 293;

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

/// Issue a 2-argument syscall.
///
/// # Safety
///
/// The syscall number and arguments must be valid per the ONCRIX ABI.
unsafe fn syscall2(nr: u64, a0: u64, a1: u64) -> i64 {
    let ret: i64;
    // SAFETY: `syscall` traps into the kernel. The caller guarantees
    // the syscall number and arguments are valid.
    unsafe {
        core::arch::asm!(
            "syscall",
            in("rax") nr,
            in("rdi") a0,
            in("rsi") a1,
            lateout("rax") ret,
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

/// `mkdir(2)` — create a directory.
///
/// Returns 0 on success, or a negative errno value.
///
/// # Safety
///
/// `path` must be a valid null-terminated string pointer.
pub unsafe fn mkdir(path: *const u8, mode: u32) -> i64 {
    // SAFETY: The caller guarantees `path` is null-terminated.
    unsafe { syscall2(SYS_MKDIR, path as u64, mode as u64) }
}

/// `unlink(2)` — delete a name from the filesystem.
///
/// Returns 0 on success, or a negative errno value.
///
/// # Safety
///
/// `path` must be a valid null-terminated string pointer.
pub unsafe fn unlink(path: *const u8) -> i64 {
    // SAFETY: The caller guarantees `path` is null-terminated.
    unsafe { syscall1(SYS_UNLINK, path as u64) }
}

/// `getdents64(2)` — get directory entries.
///
/// Returns the number of bytes read into `buf`, 0 at end of directory,
/// or a negative errno value.
///
/// # Safety
///
/// `buf` must point to at least `count` writable bytes.
pub unsafe fn getdents64(fd: i32, buf: *mut u8, count: usize) -> i64 {
    // SAFETY: The caller guarantees `buf` is valid for `count` writable bytes.
    unsafe { syscall3(SYS_GETDENTS64, fd as u64, buf as u64, count as u64) }
}

/// `dup2(2)` — duplicate `oldfd` to `newfd`, closing `newfd` first if open.
///
/// Returns `newfd` on success, or a negative errno value.
///
/// # Safety
///
/// Both `oldfd` and `newfd` must be valid file descriptor values (>= 0).
pub unsafe fn dup2(oldfd: i32, newfd: i32) -> i64 {
    // SAFETY: The caller guarantees both fd arguments are non-negative integers.
    unsafe { syscall2(SYS_DUP2, oldfd as u64, newfd as u64) }
}

/// `pipe2(2)` — create a pipe, writing read and write fds into `fildes[0..2]`.
///
/// Returns 0 on success, or a negative errno value.
///
/// # Safety
///
/// `fildes` must point to at least two writable `i32` slots.
pub unsafe fn pipe2(fildes: *mut i32, flags: u32) -> i64 {
    // SAFETY: The caller guarantees `fildes` is valid for two i32 writes.
    unsafe { syscall2(SYS_PIPE2, fildes as u64, flags as u64) }
}

/// `chdir(2)` — change the working directory of the calling process.
///
/// Returns 0 on success, or a negative errno value.
///
/// # Safety
///
/// `path` must be a valid null-terminated string pointer.
pub unsafe fn chdir(path: *const u8) -> i64 {
    // SAFETY: The caller guarantees `path` is null-terminated.
    unsafe { syscall1(SYS_CHDIR, path as u64) }
}

/// `getcwd(3)` — copy the current working directory path into `buf`.
///
/// Returns the number of bytes written (including the null terminator)
/// on success, or a negative errno value.
///
/// # Safety
///
/// `buf` must point to at least `size` writable bytes.
pub unsafe fn getcwd(buf: *mut u8, size: usize) -> i64 {
    // SAFETY: The caller guarantees `buf` is valid for `size` writable bytes.
    unsafe { syscall2(SYS_GETCWD, buf as u64, size as u64) }
}
