// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Minimal POSIX libc shim for the ONCRIX operating system.
//!
//! Provides kernel-side definitions of libc structures and constants
//! that user-space programs would use: errno values, open/mmap/signal
//! constants, wait-status macros, and syscall argument marshalling.

use oncrix_lib::{Error, Result};

// ── POSIX errno constants (Linux x86_64 ABI) ──────────────────────

/// Operation not permitted.
pub const EPERM: i32 = 1;
/// No such file or directory.
pub const ENOENT: i32 = 2;
/// No such process.
pub const ESRCH: i32 = 3;
/// Interrupted system call.
pub const EINTR: i32 = 4;
/// I/O error.
pub const EIO: i32 = 5;
/// No such device or address.
pub const ENXIO: i32 = 6;
/// Argument list too long.
pub const E2BIG: i32 = 7;
/// Exec format error.
pub const ENOEXEC: i32 = 8;
/// Bad file descriptor.
pub const EBADF: i32 = 9;
/// No child processes.
pub const ECHILD: i32 = 10;
/// Try again (resource temporarily unavailable).
pub const EAGAIN: i32 = 11;
/// Out of memory.
pub const ENOMEM: i32 = 12;
/// Permission denied.
pub const EACCES: i32 = 13;
/// Bad address.
pub const EFAULT: i32 = 14;
/// Block device required.
pub const ENOTBLK: i32 = 15;
/// Device or resource busy.
pub const EBUSY: i32 = 16;
/// File exists.
pub const EEXIST: i32 = 17;
/// Cross-device link.
pub const EXDEV: i32 = 18;
/// No such device.
pub const ENODEV: i32 = 19;
/// Not a directory.
pub const ENOTDIR: i32 = 20;
/// Is a directory.
pub const EISDIR: i32 = 21;
/// Invalid argument.
pub const EINVAL: i32 = 22;
/// File table overflow.
pub const ENFILE: i32 = 23;
/// Too many open files.
pub const EMFILE: i32 = 24;
/// Not a typewriter (inappropriate ioctl for device).
pub const ENOTTY: i32 = 25;
/// Text file busy.
pub const ETXTBSY: i32 = 26;
/// File too large.
pub const EFBIG: i32 = 27;
/// No space left on device.
pub const ENOSPC: i32 = 28;
/// Illegal seek.
pub const ESPIPE: i32 = 29;
/// Read-only file system.
pub const EROFS: i32 = 30;
/// Too many links.
pub const EMLINK: i32 = 31;
/// Broken pipe.
pub const EPIPE: i32 = 32;
/// Function not implemented.
pub const ENOSYS: i32 = 38;
/// Operation would block (same as [`EAGAIN`] on Linux).
pub const EWOULDBLOCK: i32 = 11;

// ── Error conversion ──────────────────────────────────────────────

/// Convert an [`Error`] to a POSIX errno value.
pub fn error_to_errno(err: Error) -> i32 {
    match err {
        Error::PermissionDenied => EPERM,
        Error::NotFound => ENOENT,
        Error::OutOfMemory => ENOMEM,
        Error::InvalidArgument => EINVAL,
        Error::Busy => EBUSY,
        Error::WouldBlock => EAGAIN,
        Error::Interrupted => EINTR,
        Error::IoError => EIO,
        Error::NotImplemented => ENOSYS,
        Error::AlreadyExists => EEXIST,
    }
}

/// Convert a POSIX errno value to an [`Error`].
///
/// Unknown errno values are mapped to [`Error::InvalidArgument`].
pub fn errno_to_error(errno: i32) -> Error {
    match errno {
        EPERM | EACCES => Error::PermissionDenied,
        ENOENT | ESRCH => Error::NotFound,
        EINTR => Error::Interrupted,
        EIO => Error::IoError,
        ENOMEM => Error::OutOfMemory,
        EINVAL => Error::InvalidArgument,
        EBUSY => Error::Busy,
        EAGAIN => Error::WouldBlock,
        EEXIST => Error::AlreadyExists,
        ENOSYS => Error::NotImplemented,
        _ => Error::InvalidArgument,
    }
}

// ── Open flags (O_*) ──────────────────────────────────────────────

/// Open for reading only.
pub const O_RDONLY: u32 = 0;
/// Open for writing only.
pub const O_WRONLY: u32 = 1;
/// Open for reading and writing.
pub const O_RDWR: u32 = 2;
/// Create file if it does not exist.
pub const O_CREAT: u32 = 0x40;
/// Fail if file already exists (with `O_CREAT`).
pub const O_EXCL: u32 = 0x80;
/// Truncate file to zero length.
pub const O_TRUNC: u32 = 0x200;
/// Append mode — writes always go to end of file.
pub const O_APPEND: u32 = 0x400;
/// Non-blocking mode.
pub const O_NONBLOCK: u32 = 0x800;
/// Set close-on-exec flag on the new file descriptor.
pub const O_CLOEXEC: u32 = 0x80000;
/// Must be a directory.
pub const O_DIRECTORY: u32 = 0x10000;

// ── Seek constants ────────────────────────────────────────────────

/// Seek relative to the beginning of the file.
pub const SEEK_SET: i32 = 0;
/// Seek relative to the current file position.
pub const SEEK_CUR: i32 = 1;
/// Seek relative to the end of the file.
pub const SEEK_END: i32 = 2;

// ── Signal constants (Linux x86_64 ABI) ───────────────────────────

/// Hangup detected on controlling terminal.
pub const SIGHUP: i32 = 1;
/// Interrupt from keyboard (Ctrl-C).
pub const SIGINT: i32 = 2;
/// Quit from keyboard (Ctrl-\).
pub const SIGQUIT: i32 = 3;
/// Illegal instruction.
pub const SIGILL: i32 = 4;
/// Trace/breakpoint trap.
pub const SIGTRAP: i32 = 5;
/// Abort signal from `abort(3)`.
pub const SIGABRT: i32 = 6;
/// Bus error (bad memory access).
pub const SIGBUS: i32 = 7;
/// Floating-point exception.
pub const SIGFPE: i32 = 8;
/// Kill signal (cannot be caught or ignored).
pub const SIGKILL: i32 = 9;
/// User-defined signal 1.
pub const SIGUSR1: i32 = 10;
/// Segmentation violation (invalid memory reference).
pub const SIGSEGV: i32 = 11;
/// User-defined signal 2.
pub const SIGUSR2: i32 = 12;
/// Broken pipe: write to pipe with no readers.
pub const SIGPIPE: i32 = 13;
/// Timer signal from `alarm(2)`.
pub const SIGALRM: i32 = 14;
/// Termination signal.
pub const SIGTERM: i32 = 15;
/// Stack fault on coprocessor (unused on modern systems).
pub const SIGSTKFLT: i32 = 16;
/// Child stopped or terminated.
pub const SIGCHLD: i32 = 17;
/// Continue if stopped.
pub const SIGCONT: i32 = 18;
/// Stop process (cannot be caught or ignored).
pub const SIGSTOP: i32 = 19;
/// Stop typed at terminal (Ctrl-Z).
pub const SIGTSTP: i32 = 20;
/// Terminal input for background process.
pub const SIGTTIN: i32 = 21;
/// Terminal output for background process.
pub const SIGTTOU: i32 = 22;
/// Urgent condition on socket.
pub const SIGURG: i32 = 23;
/// CPU time limit exceeded.
pub const SIGXCPU: i32 = 24;
/// File size limit exceeded.
pub const SIGXFSZ: i32 = 25;
/// Virtual alarm clock.
pub const SIGVTALRM: i32 = 26;
/// Profiling timer expired.
pub const SIGPROF: i32 = 27;
/// Window resize signal.
pub const SIGWINCH: i32 = 28;
/// I/O now possible.
pub const SIGIO: i32 = 29;
/// Power failure.
pub const SIGPWR: i32 = 30;
/// Bad system call (invalid syscall number).
pub const SIGSYS: i32 = 31;
/// First real-time signal.
pub const SIGRTMIN: i32 = 34;

// ── Wait status macros ────────────────────────────────────────────

/// Returns `true` if the child terminated normally via `_exit()` or
/// `exit()`.
pub const fn wifexited(status: i32) -> bool {
    (status & 0x7f) == 0
}

/// Returns the low-order 8 bits of the exit status (only meaningful
/// when [`wifexited`] returns `true`).
pub const fn wexitstatus(status: i32) -> i32 {
    (status >> 8) & 0xff
}

/// Returns `true` if the child was terminated by a signal.
pub const fn wifsignaled(status: i32) -> bool {
    let sig = status & 0x7f;
    sig != 0 && sig != 0x7f
}

/// Returns the signal number that caused the child to terminate
/// (only meaningful when [`wifsignaled`] returns `true`).
pub const fn wtermsig(status: i32) -> i32 {
    status & 0x7f
}

/// Returns `true` if the child is currently stopped.
pub const fn wifstopped(status: i32) -> bool {
    (status & 0xff) == 0x7f
}

/// Returns the signal number that caused the child to stop (only
/// meaningful when [`wifstopped`] returns `true`).
pub const fn wstopsig(status: i32) -> i32 {
    (status >> 8) & 0xff
}

// ── mmap constants ────────────────────────────────────────────────

/// Page may not be accessed.
pub const PROT_NONE: u32 = 0;
/// Page may be read.
pub const PROT_READ: u32 = 1;
/// Page may be written.
pub const PROT_WRITE: u32 = 2;
/// Page may be executed.
pub const PROT_EXEC: u32 = 4;
/// Share changes with other mappings.
pub const MAP_SHARED: u32 = 1;
/// Create a private copy-on-write mapping.
pub const MAP_PRIVATE: u32 = 2;
/// Place the mapping at exactly the specified address.
pub const MAP_FIXED: u32 = 0x10;
/// Anonymous mapping (not backed by any file).
pub const MAP_ANONYMOUS: u32 = 0x20;
/// Sentinel value indicating `mmap` failure.
pub const MAP_FAILED: u64 = u64::MAX;

// ── fcntl commands ────────────────────────────────────────────────

/// Duplicate a file descriptor (lowest available >= arg).
pub const F_DUPFD: i32 = 0;
/// Get file descriptor flags.
pub const F_GETFD: i32 = 1;
/// Set file descriptor flags.
pub const F_SETFD: i32 = 2;
/// Get file status flags.
pub const F_GETFL: i32 = 3;
/// Set file status flags.
pub const F_SETFL: i32 = 4;
/// Close-on-exec file descriptor flag.
pub const FD_CLOEXEC: i32 = 1;

// ── Syscall argument marshalling ──────────────────────────────────

/// Raw system call arguments matching the x86_64 ABI.
///
/// The six argument registers are `rdi`, `rsi`, `rdx`, `r10`, `r8`,
/// and `r9` respectively; the syscall number is passed in `rax`.
#[derive(Debug, Clone, Copy)]
pub struct SyscallArgs {
    /// Syscall number (passed in `rax`).
    pub number: u64,
    /// First argument (`rdi`).
    pub arg0: u64,
    /// Second argument (`rsi`).
    pub arg1: u64,
    /// Third argument (`rdx`).
    pub arg2: u64,
    /// Fourth argument (`r10`).
    pub arg3: u64,
    /// Fifth argument (`r8`).
    pub arg4: u64,
    /// Sixth argument (`r9`).
    pub arg5: u64,
}

/// Convert a kernel [`Result<u64>`] to a Linux-style syscall return
/// value.
///
/// `Ok(val)` maps to `val as i64` and `Err(e)` maps to the negated
/// errno (e.g., `-EINVAL`).
pub fn syscall_return(result: Result<u64>) -> i64 {
    match result {
        Ok(val) => val as i64,
        Err(e) => -(error_to_errno(e) as i64),
    }
}

/// Parse a Linux-style syscall return value back into a kernel
/// [`Result<u64>`].
///
/// Non-negative values become `Ok(ret as u64)`. Negative values in
/// the range `-4095..=-1` are treated as negated errno codes and
/// converted to `Err`.
pub fn parse_syscall_return(ret: i64) -> Result<u64> {
    if ret >= 0 {
        Ok(ret as u64)
    } else {
        let errno = (-ret) as i32;
        Err(errno_to_error(errno))
    }
}
