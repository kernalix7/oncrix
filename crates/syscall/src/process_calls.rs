// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Process management syscall handlers.
//!
//! Implements `clone3`, `fork`, `vfork`, `wait4`, `waitid`, `exit`,
//! and `exit_group` per POSIX.1-2024 and Linux extensions.

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Clone flags (Linux clone3 ABI, u64)
// ---------------------------------------------------------------------------

/// Share virtual memory with the parent.
pub const CLONE_VM: u64 = 0x0000_0100;
/// Share filesystem information (cwd, root, umask).
pub const CLONE_FS: u64 = 0x0000_0200;
/// Share the file descriptor table.
pub const CLONE_FILES: u64 = 0x0000_0400;
/// Share signal handlers.
pub const CLONE_SIGHAND: u64 = 0x0000_0800;
/// Place child in the same thread group as the caller.
pub const CLONE_THREAD: u64 = 0x0001_0000;
/// Create the child in a new mount namespace.
pub const CLONE_NEWNS: u64 = 0x0002_0000;
/// Create the child in a new PID namespace.
pub const CLONE_NEWPID: u64 = 0x2000_0000;
/// Create the child in a new network namespace.
pub const CLONE_NEWNET: u64 = 0x4000_0000;
/// Create the child in a new user namespace.
pub const CLONE_NEWUSER: u64 = 0x1000_0000;
/// Set the parent of the child to the caller's parent.
pub const CLONE_PARENT: u64 = 0x0000_8000;
/// Execution of the calling process is suspended until the child exits.
pub const CLONE_VFORK: u64 = 0x0000_4000;
/// Return a pidfd for the child process.
pub const CLONE_PIDFD: u64 = 0x0000_1000;
/// Place child in the specified cgroup.
pub const CLONE_INTO_CGROUP: u64 = 0x0200_0000_0000_0000;

/// All recognised clone flags combined.
const CLONE_FLAGS_KNOWN: u64 = CLONE_VM
    | CLONE_FS
    | CLONE_FILES
    | CLONE_SIGHAND
    | CLONE_THREAD
    | CLONE_NEWNS
    | CLONE_NEWPID
    | CLONE_NEWNET
    | CLONE_NEWUSER
    | CLONE_PARENT
    | CLONE_VFORK
    | CLONE_PIDFD
    | CLONE_INTO_CGROUP;

// ---------------------------------------------------------------------------
// Wait options (i32, POSIX + Linux extensions)
// ---------------------------------------------------------------------------

/// Return immediately if no child has exited.
pub const WNOHANG: i32 = 0x0000_0001;
/// Also report stopped (but not yet traced) children.
pub const WUNTRACED: i32 = 0x0000_0002;
/// Also report continued children.
pub const WCONTINUED: i32 = 0x0000_0008;
/// Leave the child in a waitable state (do not consume the event).
pub const WNOWAIT: i32 = 0x0100_0000;
/// Wait for exited children (`waitid`-specific).
pub const WEXITED: i32 = 0x0000_0004;
/// Wait for stopped children (`waitid`-specific).
pub const WSTOPPED: i32 = 0x0000_0002;
/// Wait for continued children (`waitid`-specific, distinct from `WCONTINUED`).
pub const WCONTINUED_W: i32 = 0x0000_0008;

/// All recognised `wait4` option bits.
const WAIT4_OPTIONS_KNOWN: i32 = WNOHANG | WUNTRACED | WCONTINUED;

/// All recognised `waitid` option bits.
const WAITID_OPTIONS_KNOWN: i32 = WNOHANG | WEXITED | WSTOPPED | WCONTINUED_W | WNOWAIT;

// ---------------------------------------------------------------------------
// Wait status extraction helpers (const fn, mirrors <sys/wait.h>)
// ---------------------------------------------------------------------------

/// Extract the exit code from a wait status value.
pub const fn wexitstatus(status: i32) -> i32 {
    (status >> 8) & 0xFF
}

/// Extract the signal number that caused termination.
pub const fn wtermsig(status: i32) -> i32 {
    status & 0x7F
}

/// Returns `true` if the child exited normally.
pub const fn wifexited(status: i32) -> bool {
    wtermsig(status) == 0
}

/// Returns `true` if the child was terminated by a signal.
pub const fn wifsignaled(status: i32) -> bool {
    let sig = wtermsig(status);
    sig != 0 && sig != 0x7F
}

/// Returns `true` if the child is currently stopped.
pub const fn wifstopped(status: i32) -> bool {
    (status & 0xFF) == 0x7F
}

// ---------------------------------------------------------------------------
// CloneArgs
// ---------------------------------------------------------------------------

/// Arguments for the `clone3` system call (`struct clone_args`).
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct CloneArgs {
    /// Clone flags (bitwise OR of `CLONE_*` constants).
    pub flags: u64,
    /// File descriptor for the child's pidfd (when `CLONE_PIDFD` is set).
    pub pidfd: u64,
    /// Address where the child TID is stored (user-space pointer).
    pub child_tid: u64,
    /// Address where the parent TID is stored (user-space pointer).
    pub parent_tid: u64,
    /// Signal sent to the parent when the child exits.
    pub exit_signal: u64,
    /// Pointer to the lowest byte of the child stack.
    pub stack: u64,
    /// Size of the child stack in bytes.
    pub stack_size: u64,
    /// TLS (Thread Local Storage) descriptor.
    pub tls: u64,
    /// Pointer to array of TIDs to set in new PID namespaces.
    pub set_tid: u64,
    /// Number of elements in the `set_tid` array.
    pub set_tid_size: u64,
    /// Target cgroup file descriptor (when `CLONE_INTO_CGROUP` is set).
    pub cgroup: u64,
}

impl CloneArgs {
    /// Validate the clone arguments.
    ///
    /// Returns `Err(Error::InvalidArgument)` when:
    /// - Unknown flags are set.
    /// - `CLONE_THREAD` is set without `CLONE_SIGHAND`.
    /// - `CLONE_SIGHAND` is set without `CLONE_VM`.
    /// - `exit_signal` exceeds the signal number range (1..=64).
    pub fn validate(&self) -> Result<()> {
        // Reject unknown flags.
        if self.flags & !CLONE_FLAGS_KNOWN != 0 {
            return Err(Error::InvalidArgument);
        }

        // CLONE_THREAD requires CLONE_SIGHAND.
        if self.flags & CLONE_THREAD != 0 && self.flags & CLONE_SIGHAND == 0 {
            return Err(Error::InvalidArgument);
        }

        // CLONE_SIGHAND requires CLONE_VM.
        if self.flags & CLONE_SIGHAND != 0 && self.flags & CLONE_VM == 0 {
            return Err(Error::InvalidArgument);
        }

        // exit_signal must be 0 (none) or a valid signal number (1..=64).
        if self.exit_signal > 64 {
            return Err(Error::InvalidArgument);
        }

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// WaitStatus
// ---------------------------------------------------------------------------

/// Decoded wait status value.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct WaitStatus {
    /// Raw wait status as returned by the kernel.
    pub raw: i32,
}

impl WaitStatus {
    /// Construct a status indicating normal exit with the given code.
    pub const fn exited(code: i32) -> Self {
        Self {
            raw: (code & 0xFF) << 8,
        }
    }

    /// Construct a status indicating termination by a signal.
    pub const fn signaled(sig: i32) -> Self {
        Self { raw: sig & 0x7F }
    }

    /// Construct a status indicating the child was stopped by a signal.
    pub const fn stopped(sig: i32) -> Self {
        Self {
            raw: 0x7F | ((sig & 0xFF) << 8),
        }
    }

    /// Returns `true` if the child exited normally.
    pub const fn is_exited(&self) -> bool {
        wifexited(self.raw)
    }

    /// Returns the exit code (meaningful only when `is_exited()` is `true`).
    pub const fn exit_code(&self) -> i32 {
        wexitstatus(self.raw)
    }

    /// Returns `true` if the child was terminated by a signal.
    pub const fn is_signaled(&self) -> bool {
        wifsignaled(self.raw)
    }

    /// Returns the signal that caused termination.
    pub const fn term_signal(&self) -> i32 {
        wtermsig(self.raw)
    }

    /// Returns `true` if the child is currently stopped.
    pub const fn is_stopped(&self) -> bool {
        wifstopped(self.raw)
    }

    /// Returns the signal that caused the child to stop.
    pub const fn stop_signal(&self) -> i32 {
        wexitstatus(self.raw)
    }
}

// ---------------------------------------------------------------------------
// SigInfo
// ---------------------------------------------------------------------------

/// Abbreviated `siginfo_t` returned by `waitid`.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct SigInfo {
    /// Signal number (e.g. `SIGCHLD`).
    pub si_signo: i32,
    /// Error number associated with this signal.
    pub si_errno: i32,
    /// Signal code (e.g. `CLD_EXITED`, `CLD_KILLED`).
    pub si_code: i32,
    /// PID of the sending process / child.
    pub si_pid: u32,
    /// Real UID of the sending process.
    pub si_uid: u32,
    /// Exit status or signal number.
    pub si_status: i32,
}

// ---------------------------------------------------------------------------
// IdType
// ---------------------------------------------------------------------------

/// Identifier type for `waitid`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum IdType {
    /// Wait for the child whose PID equals `id`.
    PId,
    /// Wait for any child whose process group ID equals `id`.
    PGid,
    /// Wait for any child.
    #[default]
    PAll,
}

// ---------------------------------------------------------------------------
// Syscall handlers
// ---------------------------------------------------------------------------

/// `clone3` — create a new process or thread (Linux 5.3+).
///
/// Validates `args` and allocates a new child. Returns the child PID
/// on success.
///
/// Stub: validates arguments and returns a monotonically increasing PID.
pub fn do_clone3(args: &CloneArgs) -> Result<u64> {
    args.validate()?;

    // Stub: a real kernel would duplicate the process, set up the
    // stack, TLS, pidfd, etc.  We return a placeholder child PID.
    Ok(2)
}

/// `fork` — create a child process (POSIX).
///
/// Equivalent to `clone3` with no flags and `exit_signal = SIGCHLD`.
///
/// Stub: returns a placeholder child PID.
pub fn do_fork() -> Result<u64> {
    let args = CloneArgs {
        exit_signal: 17, // SIGCHLD on x86_64
        ..CloneArgs::default()
    };
    do_clone3(&args)
}

/// `vfork` — create a child that shares the parent's address space.
///
/// The parent is suspended until the child calls `execve` or `_exit`.
///
/// Stub: returns a placeholder child PID.
pub fn do_vfork() -> Result<u64> {
    let args = CloneArgs {
        flags: CLONE_VM | CLONE_VFORK,
        exit_signal: 17, // SIGCHLD
        ..CloneArgs::default()
    };
    do_clone3(&args)
}

/// `wait4` — wait for a child process to change state.
///
/// `pid` semantics:
/// - `> 0` — wait for the child whose PID equals `pid`.
/// - `0`   — wait for any child in the same process group.
/// - `-1`  — wait for any child.
/// - `< -1`— wait for any child whose PGID equals `|pid|`.
///
/// Returns `(child_pid, status)` or `(0, _)` when `WNOHANG` is set
/// and no child has changed state.
///
/// Stub: when `WNOHANG` is set returns 0 (no child ready); otherwise
/// returns a placeholder exited child.
pub fn do_wait4(pid: i64, options: i32) -> Result<(u64, WaitStatus)> {
    // Reject unknown option bits.
    if options & !WAIT4_OPTIONS_KNOWN != 0 {
        return Err(Error::InvalidArgument);
    }

    // Validate the pid argument (must not be i64::MIN due to overflow
    // when negating).
    if pid == i64::MIN {
        return Err(Error::InvalidArgument);
    }

    if options & WNOHANG != 0 {
        // Non-blocking: no child ready yet.
        return Ok((0, WaitStatus::default()));
    }

    // Stub: a real kernel would block until a matching child exits.
    // Return a placeholder child that exited with code 0.
    let _ = pid;
    Ok((2, WaitStatus::exited(0)))
}

/// `waitid` — wait for a child process (extended, POSIX).
///
/// `id_type` + `id` select which children to wait for:
/// - `P_PID`  — child with PID == `id`
/// - `P_PGID` — any child in PGID == `id`
/// - `P_ALL`  — any child (`id` is ignored)
///
/// Returns a populated `SigInfo` on success.
///
/// Stub: when `WNOHANG` is set returns an empty `SigInfo`; otherwise
/// returns a placeholder exited child.
pub fn do_waitid(id_type: IdType, id: u64, options: i32) -> Result<SigInfo> {
    // Reject unknown option bits.
    if options & !WAITID_OPTIONS_KNOWN != 0 {
        return Err(Error::InvalidArgument);
    }

    // At least one of WEXITED, WSTOPPED, WCONTINUED_W must be set.
    if options & (WEXITED | WSTOPPED | WCONTINUED_W) == 0 {
        return Err(Error::InvalidArgument);
    }

    // Validate id when a specific process/group is targeted.
    match id_type {
        IdType::PId | IdType::PGid => {
            if id == 0 {
                return Err(Error::InvalidArgument);
            }
        }
        IdType::PAll => { /* id is ignored */ }
    }

    if options & WNOHANG != 0 {
        return Ok(SigInfo::default());
    }

    // Stub: return a placeholder child that exited with code 0.
    // SIGCHLD = 17, CLD_EXITED = 1.
    let _ = id;
    Ok(SigInfo {
        si_signo: 17,
        si_code: 1,
        si_pid: 2,
        si_status: 0,
        ..SigInfo::default()
    })
}

/// `exit` — terminate the calling thread / process.
///
/// Stub: records the exit code. A real kernel would:
/// 1. Set the exit code on the current task.
/// 2. Release resources (file descriptors, memory mappings).
/// 3. Reparent children to init.
/// 4. Wake any waiters.
/// 5. Schedule another task.
pub fn do_exit(code: i32) -> Result<()> {
    let _exit_code = code;
    Ok(())
}

/// `exit_group` — terminate all threads in the calling thread group.
///
/// Stub: behaves identically to [`do_exit`] in the current
/// single-threaded stub implementation.
pub fn do_exit_group(code: i32) -> Result<()> {
    do_exit(code)
}
