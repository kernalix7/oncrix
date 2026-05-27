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
const SYS_STAT: u64 = 4;
const SYS_LSTAT: u64 = 6;
const SYS_FSTAT: u64 = 5;
const SYS_MMAP: u64 = 9;
const SYS_RT_SIGACTION: u64 = 13;
const SYS_ACCESS: u64 = 21;
const SYS_FSYNC: u64 = 74;
const SYS_DUP2: u64 = 33;
const SYS_GETPID: u64 = 39;
const SYS_GETCWD: u64 = 79;
const SYS_CHDIR: u64 = 80;
const SYS_MKDIR: u64 = 83;
const SYS_UNLINK: u64 = 87;
const SYS_RENAME: u64 = 82;
const SYS_CHMOD: u64 = 90;
const SYS_LINK: u64 = 86;
const SYS_CHOWN: u64 = 92;
const SYS_SYNC: u64 = 162;
const SYS_SYMLINK: u64 = 88;
const SYS_READLINK: u64 = 89;
const SYS_TRUNCATE: u64 = 76;
const SYS_RMDIR: u64 = 84;
const SYS_MKNOD: u64 = 133;
const SYS_FORK: u64 = 57;
const SYS_EXECVE: u64 = 59;
const SYS_EXIT: u64 = 60;
const SYS_WAIT4: u64 = 61;
const SYS_KILL: u64 = 62;
const SYS_GETDENTS64: u64 = 217;
const SYS_PIPE2: u64 = 293;
const SYS_NANOSLEEP: u64 = 35;
const SYS_CLOCK_GETTIME: u64 = 228;
const SYS_TIME: u64 = 201;

// ---------------------------------------------------------------------------
// Signal numbers
// ---------------------------------------------------------------------------

/// `SIGHUP` — hangup detected on controlling terminal.
pub const SIGHUP: i32 = 1;
/// `SIGINT` — interrupt from keyboard (Ctrl-C).
pub const SIGINT: i32 = 2;
/// `SIGQUIT` — quit from keyboard (Ctrl-\).
pub const SIGQUIT: i32 = 3;
/// `SIGKILL` — sure kill, cannot be caught or ignored.
pub const SIGKILL: i32 = 9;
/// `SIGTERM` — termination request.
pub const SIGTERM: i32 = 15;
/// `SIGCHLD` — child process status change.
pub const SIGCHLD: i32 = 17;

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

/// Issue a 6-argument syscall.
///
/// # Safety
///
/// The syscall number and arguments must be valid per the ONCRIX ABI.
unsafe fn syscall6(nr: u64, a0: u64, a1: u64, a2: u64, a3: u64, a4: u64, a5: u64) -> i64 {
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
            in("r8") a4,
            in("r9") a5,
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

/// `kill(2)` — send a signal to a process.
///
/// Returns 0 on success, or a negative errno value:
/// - `-3` (`ESRCH`) — no such process.
/// - `-22` (`EINVAL`) — invalid signal number.
///
/// `sig == 0` performs an existence check without delivering a signal.
pub fn kill(pid: i64, sig: i32) -> i64 {
    // SAFETY: SYS_KILL takes scalar arguments only; no pointers.
    unsafe { syscall2(SYS_KILL, pid as u64, sig as u64) }
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

/// `rename(2)` — rename/move a filesystem name.
///
/// Returns 0 on success, or a negative errno value.
///
/// # Safety
///
/// `oldpath` and `newpath` must be valid null-terminated string pointers.
pub unsafe fn rename(oldpath: *const u8, newpath: *const u8) -> i64 {
    // SAFETY: The caller guarantees both paths are null-terminated.
    unsafe { syscall2(SYS_RENAME, oldpath as u64, newpath as u64) }
}

/// `chmod(2)` — change file permission bits.
///
/// Returns 0 on success, or a negative errno value.
///
/// # Safety
///
/// `path` must be a valid null-terminated string pointer.
pub unsafe fn chmod(path: *const u8, mode: u32) -> i64 {
    // SAFETY: The caller guarantees `path` is null-terminated.
    unsafe { syscall2(SYS_CHMOD, path as u64, mode as u64) }
}

/// `link(2)` — create a hard link.
///
/// Returns 0 on success, or a negative errno value.
///
/// # Safety
///
/// `oldpath` and `newpath` must be valid null-terminated string pointers.
pub unsafe fn link(oldpath: *const u8, newpath: *const u8) -> i64 {
    // SAFETY: The caller guarantees both paths are null-terminated.
    unsafe { syscall2(SYS_LINK, oldpath as u64, newpath as u64) }
}

/// `chown(2)` — change file owner/group.
///
/// A `uid`/`gid` of `u32::MAX` (`(uid_t)-1`) leaves that id unchanged.
/// Returns 0 on success, or a negative errno value.
///
/// # Safety
///
/// `path` must be a valid null-terminated string pointer.
pub unsafe fn chown(path: *const u8, uid: u32, gid: u32) -> i64 {
    // SAFETY: The caller guarantees `path` is null-terminated.
    unsafe { syscall3(SYS_CHOWN, path as u64, uid as u64, gid as u64) }
}

/// `access(2)` — check file accessibility.
///
/// POSIX.1-2024 `access(3p)`. On ONCRIX ramfs, only existence is checked;
/// permission bits (R_OK / W_OK / X_OK) are accepted but not enforced.
/// Returns 0 on success, or a negative errno value.
///
/// # Safety
///
/// `path` must be a valid null-terminated string pointer.
pub unsafe fn access(path: *const u8, mode: i32) -> i64 {
    // SAFETY: The caller guarantees `path` is null-terminated.
    unsafe { syscall2(SYS_ACCESS, path as u64, mode as u64) }
}

/// `fsync(2)` — synchronize file state with backing store.
///
/// On ONCRIX's in-memory ramfs this always succeeds immediately.
/// Returns 0.
pub fn fsync(fd: i32) -> i64 {
    // SAFETY: SYS_FSYNC is idempotent on ramfs; no user pointers involved.
    unsafe { syscall1(SYS_FSYNC, fd as u64) }
}

/// `sync(2)` — flush filesystem buffers.
///
/// On ONCRIX's in-memory ramfs this always succeeds immediately.
/// Returns 0.
pub fn sync() -> i64 {
    // SAFETY: SYS_SYNC takes no arguments; the kernel ignores the dummy.
    unsafe { syscall1(SYS_SYNC, 0) }
}

/// `symlink(2)` — create a symbolic link `linkpath` with value `target`.
///
/// Returns 0 on success, or a negative errno value.
///
/// # Safety
///
/// `target` and `linkpath` must be valid null-terminated string pointers.
pub unsafe fn symlink(target: *const u8, linkpath: *const u8) -> i64 {
    // SAFETY: The caller guarantees both strings are null-terminated.
    unsafe { syscall2(SYS_SYMLINK, target as u64, linkpath as u64) }
}

/// `readlink(2)` — read the target of symbolic link `path`.
///
/// Copies up to `bufsiz` bytes (no NUL terminator) into `buf`. Returns
/// the byte count on success, or a negative errno value.
///
/// # Safety
///
/// `path` must be null-terminated; `buf` must be writable for `bufsiz` bytes.
pub unsafe fn readlink(path: *const u8, buf: *mut u8, bufsiz: usize) -> i64 {
    // SAFETY: caller guarantees the buffer and path validity.
    unsafe { syscall3(SYS_READLINK, path as u64, buf as u64, bufsiz as u64) }
}

/// `truncate(2)` — set the length of the file at `path` to `length`.
///
/// Returns 0 on success, or a negative errno value.
///
/// # Safety
///
/// `path` must be a valid null-terminated string pointer.
pub unsafe fn truncate(path: *const u8, length: u64) -> i64 {
    // SAFETY: The caller guarantees `path` is null-terminated.
    unsafe { syscall2(SYS_TRUNCATE, path as u64, length) }
}

/// `rmdir(2)` — remove the empty directory at `path`.
///
/// Returns 0 on success, or a negative errno value.
///
/// # Safety
///
/// `path` must be a valid null-terminated string pointer.
pub unsafe fn rmdir(path: *const u8) -> i64 {
    // SAFETY: The caller guarantees `path` is null-terminated.
    unsafe { syscall1(SYS_RMDIR, path as u64) }
}

/// `mkfifo(3)` — create a named pipe (FIFO) at `path` with `mode`.
///
/// Implemented via `mknod(2)` (`SYS_MKNOD`) with the FIFO type bit set.
/// Returns 0 on success, or a negative errno value.
///
/// # Safety
///
/// `path` must be a valid null-terminated string pointer.
pub unsafe fn mkfifo(path: *const u8, mode: u32) -> i64 {
    // SAFETY: `path` is null-terminated; SYS_MKNOD creates a FIFO node.
    unsafe { syscall2(SYS_MKNOD, path as u64, (mode | S_IFIFO) as u64) }
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

// ---------------------------------------------------------------------------
// open(2) flag constants (Linux/POSIX values)
// ---------------------------------------------------------------------------

/// `O_RDONLY` — open for reading only.
pub const O_RDONLY: i32 = 0;
/// `O_WRONLY` — open for writing only.
pub const O_WRONLY: i32 = 1;
/// `O_RDWR` — open for reading and writing.
pub const O_RDWR: i32 = 2;
/// `O_CREAT` — create file if it does not exist.
pub const O_CREAT: i32 = 0o100;
/// `O_TRUNC` — truncate file to zero length on open.
pub const O_TRUNC: i32 = 0o1000;
/// `O_APPEND` — writes always append to end of file.
pub const O_APPEND: i32 = 0o2000;

// ---------------------------------------------------------------------------
// mmap protection / flag constants (POSIX values)
// ---------------------------------------------------------------------------

/// `PROT_READ` — page can be read.
pub const PROT_READ: u32 = 1;
/// `PROT_WRITE` — page can be written.
pub const PROT_WRITE: u32 = 2;
/// `PROT_EXEC` — page can be executed.
pub const PROT_EXEC: u32 = 4;

/// `MAP_PRIVATE` — modifications are private to the calling process.
pub const MAP_PRIVATE: u32 = 0x02;
/// `MAP_ANONYMOUS` — mapping is not backed by a file.
pub const MAP_ANONYMOUS: u32 = 0x20;

/// Sentinel returned by [`mmap`] on failure.
///
/// Callers should compare the returned pointer against this value
/// (`(*mut u8) -1`) to detect errors. POSIX uses the same sentinel
/// (`MAP_FAILED == (void *)-1`).
pub const MAP_FAILED: *mut u8 = !0_usize as *mut u8;

/// `mmap(2)` — create a new mapping in the virtual address space of the
/// calling process.
///
/// Returns a pointer to the mapped area, or [`MAP_FAILED`] on error.
///
/// # Safety
///
/// Call sites are required to honour the kernel-imposed restrictions
/// for the current ONCRIX phase: anonymous + private + `fd == -1`,
/// `addr == NULL`, `off == 0`. Other combinations return `MAP_FAILED`
/// with errno encoded as a negative pointer value.
pub unsafe fn mmap(addr: *mut u8, len: usize, prot: i32, flags: i32, fd: i32, off: i64) -> *mut u8 {
    // SAFETY: caller upholds the kernel-side validity contract.
    let raw = unsafe {
        syscall6(
            SYS_MMAP,
            addr as u64,
            len as u64,
            prot as u64,
            flags as u64,
            fd as u64,
            off as u64,
        )
    };
    if raw < 0 {
        return MAP_FAILED;
    }
    raw as u64 as *mut u8
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

// ---------------------------------------------------------------------------
// File status (stat/fstat)
// ---------------------------------------------------------------------------

/// POSIX `struct stat` — kernel ABI mirror (x86-64 Linux layout, 144 bytes).
///
/// Field layout matches the kernel's `fill_stat_buf` exactly so that the
/// kernel can write directly into this struct without any conversion.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Stat {
    /// Device ID.
    pub st_dev: u64,
    /// Inode number.
    pub st_ino: u64,
    /// Hard link count.
    pub st_nlink: u64,
    /// File mode (type + permission bits).
    pub st_mode: u32,
    /// Owner UID.
    pub st_uid: u32,
    /// Owner GID.
    pub st_gid: u32,
    /// Padding.
    pub __pad0: u32,
    /// Device ID (for special files).
    pub st_rdev: u64,
    /// File size in bytes.
    pub st_size: i64,
    /// Preferred block size for I/O.
    pub st_blksize: i64,
    /// Number of 512-byte blocks allocated.
    pub st_blocks: i64,
    /// Last access time (seconds).
    pub st_atime: u64,
    /// Last access time (nanoseconds).
    pub st_atime_ns: u64,
    /// Last modification time (seconds).
    pub st_mtime: u64,
    /// Last modification time (nanoseconds).
    pub st_mtime_ns: u64,
    /// Last status change time (seconds).
    pub st_ctime: u64,
    /// Last status change time (nanoseconds).
    pub st_ctime_ns: u64,
    /// Reserved.
    pub __unused: [u64; 3],
}

// S_IF* file type constants (POSIX.1-2024 §sys/stat.h)

/// File type mask: isolates the type bits from `st_mode`.
pub const S_IFMT: u32 = 0o170000;
/// Regular file.
pub const S_IFREG: u32 = 0o100000;
/// Directory.
pub const S_IFDIR: u32 = 0o040000;
/// Symbolic link.
pub const S_IFLNK: u32 = 0o120000;
/// Character device.
pub const S_IFCHR: u32 = 0o020000;
/// Block device.
pub const S_IFBLK: u32 = 0o060000;
/// Named pipe (FIFO).
pub const S_IFIFO: u32 = 0o010000;
/// Unix domain socket.
pub const S_IFSOCK: u32 = 0o140000;

/// Returns `true` if `mode` describes a directory.
pub const fn s_isdir(mode: u32) -> bool {
    (mode & S_IFMT) == S_IFDIR
}

/// Returns `true` if `mode` describes a regular file.
pub const fn s_isreg(mode: u32) -> bool {
    (mode & S_IFMT) == S_IFREG
}

/// Returns `true` if `mode` describes a symbolic link.
pub const fn s_islnk(mode: u32) -> bool {
    (mode & S_IFMT) == S_IFLNK
}

/// Returns `true` if `mode` describes a FIFO (named pipe).
pub const fn s_isfifo(mode: u32) -> bool {
    (mode & S_IFMT) == S_IFIFO
}

/// `stat(2)` — get file status by pathname.
///
/// Returns 0 on success, or a negative errno value.
///
/// # Safety
///
/// `path` must be a valid null-terminated string pointer.
/// `buf` must be a valid pointer to a writable [`Stat`].
pub unsafe fn stat(path: *const u8, buf: *mut Stat) -> i64 {
    // SAFETY: caller guarantees both pointers are valid.
    unsafe { syscall2(SYS_STAT, path as u64, buf as u64) }
}

/// `lstat(2)` — get file status without following a terminal symlink.
///
/// Returns 0 on success, or a negative errno value.
///
/// # Safety
///
/// `path` must be a valid null-terminated string pointer.
/// `buf` must be a valid pointer to a writable [`Stat`].
pub unsafe fn lstat(path: *const u8, buf: *mut Stat) -> i64 {
    // SAFETY: caller guarantees both pointers are valid.
    unsafe { syscall2(SYS_LSTAT, path as u64, buf as u64) }
}

/// `fstat(2)` — get file status by file descriptor.
///
/// Returns 0 on success, or a negative errno value.
///
/// # Safety
///
/// `buf` must be a valid pointer to a writable [`Stat`].
pub unsafe fn fstat(fd: i32, buf: *mut Stat) -> i64 {
    // SAFETY: caller guarantees `buf` is valid.
    unsafe { syscall2(SYS_FSTAT, fd as u64, buf as u64) }
}

// ---------------------------------------------------------------------------
// Signals
// ---------------------------------------------------------------------------

/// POSIX `struct sigaction` — kernel ABI mirror.
///
/// Field order matches `KernelSigaction` in
/// `crates/kernel/src/signal_syscall.rs` exactly. Both `act` and
/// `oldact` arguments to [`sigaction`] are read/written byte-by-byte
/// by the kernel, so any layout change must be mirrored on both sides.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Sigaction {
    /// Handler entry point. `0` = `SIG_DFL`, `1` = `SIG_IGN`.
    pub sa_handler: u64,
    /// `SA_*` flags.
    pub sa_flags: u64,
    /// Restorer trampoline — currently ignored by the kernel (it always
    /// uses its own in-process trampoline at user VA `0x5FE000`).
    pub sa_restorer: u64,
    /// Signal mask while the handler runs.
    pub sa_mask: u64,
}

/// `sigaction(2)` — install a per-process disposition for a signal.
///
/// Returns 0 on success, or a negative errno value.
///
/// # Safety
///
/// `act` and `oldact` must each be either null or a valid pointer to a
/// [`Sigaction`] struct in the calling process's address space.
pub unsafe fn sigaction(signum: i32, act: *const Sigaction, oldact: *mut Sigaction) -> i64 {
    // SAFETY: caller upholds the pointer validity contract.
    unsafe { syscall3(SYS_RT_SIGACTION, signum as u64, act as u64, oldact as u64) }
}

// ---------------------------------------------------------------------------
// Time syscalls
// ---------------------------------------------------------------------------

/// `CLOCK_REALTIME` — system-wide wall clock (currently identical to
/// `CLOCK_MONOTONIC` on ONCRIX since there is no RTC source).
pub const CLOCK_REALTIME: i32 = 0;
/// `CLOCK_MONOTONIC` — monotonic time since boot.
pub const CLOCK_MONOTONIC: i32 = 1;

/// POSIX `struct timespec` — second + nanosecond pair.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct Timespec {
    /// Whole seconds.
    pub tv_sec: i64,
    /// Nanoseconds in `[0, 999_999_999]`.
    pub tv_nsec: i64,
}

/// `time(tloc)` — return seconds since boot.
///
/// On ONCRIX this is "since boot", not "since the POSIX Epoch" — the
/// kernel has no RTC source. If `tloc` is non-null the same value is
/// also written to `*tloc`.
///
/// # Safety
///
/// `tloc` must be either null or a valid `*mut i64` in the calling
/// process's address space.
pub unsafe fn time(tloc: *mut i64) -> i64 {
    // SAFETY: caller upholds the pointer contract.
    unsafe { syscall1(SYS_TIME, tloc as u64) }
}

/// `clock_gettime(clk_id, tp)` — write the current time of `clk_id`
/// into `*tp`.
///
/// Supported clocks: `CLOCK_REALTIME` (0), `CLOCK_MONOTONIC` (1).
///
/// # Safety
///
/// `tp` must be a valid `*mut Timespec` in the calling process's
/// address space.
pub unsafe fn clock_gettime(clk_id: i32, tp: *mut Timespec) -> i64 {
    // SAFETY: caller upholds the pointer contract.
    unsafe { syscall2(SYS_CLOCK_GETTIME, clk_id as u64, tp as u64) }
}

// ---------------------------------------------------------------------------
// Wait status decoding (POSIX §sys/wait.h)
// ---------------------------------------------------------------------------

/// Returns `true` if the child terminated normally (not via a signal).
pub const fn wifexited(status: i32) -> bool {
    (status & 0x7f) == 0
}

/// Extract the exit code from a normally-terminated child status.
///
/// Only meaningful when [`wifexited`] returns `true`.
pub const fn wexitstatus(status: i32) -> i32 {
    (status >> 8) & 0xff
}

/// Returns `true` if the child was terminated by a signal.
pub const fn wifsignaled(status: i32) -> bool {
    let term = status & 0x7f;
    term != 0 && ((term + 1) >> 1) > 0
}

/// Extract the signal number that terminated the child.
///
/// Only meaningful when [`wifsignaled`] returns `true`.
pub const fn wtermsig(status: i32) -> i32 {
    status & 0x7f
}

/// `nanosleep(req, rem)` — block the calling thread for at least
/// the duration in `*req`.
///
/// Returns 0 on success. ONCRIX has no signal-interrupt mechanism
/// for sleep yet, so the call always sleeps the full duration and
/// `*rem` (if non-null) is always written `(0, 0)`.
///
/// # Safety
///
/// `req` must point to a valid `Timespec`. `rem` must be null or a
/// valid `*mut Timespec`.
pub unsafe fn nanosleep(req: *const Timespec, rem: *mut Timespec) -> i64 {
    // SAFETY: caller upholds the pointer contracts.
    unsafe { syscall2(SYS_NANOSLEEP, req as u64, rem as u64) }
}
