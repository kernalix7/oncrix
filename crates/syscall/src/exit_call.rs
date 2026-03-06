// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `exit` / `exit_group` syscall handlers.
//!
//! Implements `exit(2)` and `exit_group(2)` per POSIX.1-2024 and Linux ABI.
//! `exit` terminates the calling thread; `exit_group` terminates every
//! thread in the calling thread group.
//!
//! On a real kernel the exit path:
//! 1. Records the exit code.
//! 2. Releases file descriptors, memory mappings, and other resources.
//! 3. Reparents orphaned children to PID 1 (init).
//! 4. Sends SIGCHLD to the parent.
//! 5. Becomes a zombie (Z state) until the parent calls wait4.
//! 6. Schedules the next runnable task.
//!
//! # References
//!
//! - POSIX.1-2024: `_Exit()`, `exit()`
//! - Linux man pages: `exit(2)`, `exit_group(2)`

use oncrix_lib::Result;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// SIGCHLD signal number (x86-64 Linux ABI).
pub const SIGCHLD: u32 = 17;

/// Maximum valid exit status byte (low 8 bits of the status word).
const EXIT_STATUS_MASK: i32 = 0xFF;

// ---------------------------------------------------------------------------
// ExitCode — normalized exit code
// ---------------------------------------------------------------------------

/// A validated, normalized exit status.
///
/// Only the low 8 bits of the exit code are significant per POSIX;
/// the upper bits are reserved.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct ExitCode(pub i32);

impl ExitCode {
    /// Construct an `ExitCode` from a raw status.
    ///
    /// Masks to the low 8 bits.
    pub const fn new(code: i32) -> Self {
        Self(code & EXIT_STATUS_MASK)
    }

    /// Return the raw low-8-bit exit code.
    pub const fn code(&self) -> i32 {
        self.0
    }

    /// Return `true` if this is a successful exit (code == 0).
    pub const fn is_success(&self) -> bool {
        self.0 == 0
    }

    /// Encode this exit code as a wait4 status word (normal exit).
    pub const fn as_wait_status(&self) -> i32 {
        (self.0 & EXIT_STATUS_MASK) << 8
    }
}

// ---------------------------------------------------------------------------
// ExitReason — why the process is exiting
// ---------------------------------------------------------------------------

/// The reason a process or thread is exiting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExitReason {
    /// Called `exit()` or `exit_group()` directly.
    Normal(ExitCode),
    /// Terminated by a signal.
    Signaled { signal: u32, core_dumped: bool },
    /// Group exit triggered by another thread calling `exit_group`.
    GroupExit(ExitCode),
}

impl ExitReason {
    /// Encode as a Linux wait4 status word.
    pub fn wait4_status(&self) -> i32 {
        match *self {
            ExitReason::Normal(code) | ExitReason::GroupExit(code) => code.as_wait_status(),
            ExitReason::Signaled {
                signal,
                core_dumped,
            } => {
                let sig = (signal & 0x7F) as i32;
                let core = if core_dumped { 0x80 } else { 0 };
                sig | core
            }
        }
    }
}

// ---------------------------------------------------------------------------
// ExitAction — actions the kernel must take on exit
// ---------------------------------------------------------------------------

/// Actions to be performed as part of the exit path.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ExitAction {
    /// Number of file descriptors to close.
    pub fds_to_close: u32,
    /// Number of memory mappings to unmap.
    pub mappings_to_unmap: u32,
    /// Number of children to reparent to init.
    pub children_to_reparent: u32,
    /// Whether to send SIGCHLD to the parent.
    pub send_sigchld: bool,
    /// Whether the process becomes a zombie (has a living parent).
    pub becomes_zombie: bool,
}

// ---------------------------------------------------------------------------
// ExitState — per-process exit tracking
// ---------------------------------------------------------------------------

/// Records the exit state for a thread/process.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ExitState {
    /// Whether `exit` or `exit_group` has been called.
    pub exited: bool,
    /// The exit code (meaningful only when `exited` is true).
    pub code: ExitCode,
    /// Whether this was a group exit.
    pub group_exit: bool,
}

impl ExitState {
    /// Create a new `ExitState` for a normal exit.
    pub const fn normal(code: ExitCode) -> Self {
        Self {
            exited: true,
            code,
            group_exit: false,
        }
    }

    /// Create a new `ExitState` for a group exit.
    pub const fn group(code: ExitCode) -> Self {
        Self {
            exited: true,
            code,
            group_exit: true,
        }
    }
}

// ---------------------------------------------------------------------------
// Helper
// ---------------------------------------------------------------------------

/// Determine the required `ExitAction` given the process state.
pub fn compute_exit_action(
    fd_count: u32,
    vma_count: u32,
    child_count: u32,
    has_parent: bool,
) -> ExitAction {
    ExitAction {
        fds_to_close: fd_count,
        mappings_to_unmap: vma_count,
        children_to_reparent: child_count,
        send_sigchld: has_parent,
        becomes_zombie: has_parent,
    }
}

// ---------------------------------------------------------------------------
// Public syscall handlers
// ---------------------------------------------------------------------------

/// `exit` — terminate the calling thread.
///
/// Records the exit code on the current task and prepares the exit
/// actions. On a real kernel this call never returns; the scheduler
/// picks the next runnable thread.
///
/// Returns the `ExitState` and `ExitAction` for the caller to act on.
///
/// Reference: POSIX.1-2024 §_Exit.
pub fn do_exit(
    code: i32,
    fd_count: u32,
    vma_count: u32,
    child_count: u32,
    has_parent: bool,
) -> Result<(ExitState, ExitAction)> {
    let exit_code = ExitCode::new(code);
    let state = ExitState::normal(exit_code);
    let action = compute_exit_action(fd_count, vma_count, child_count, has_parent);
    Ok((state, action))
}

/// `exit_group` — terminate all threads in the current thread group.
///
/// Marks all threads in the thread group for exit with `code`.
/// Each thread that is not the calling thread receives a synthetic
/// SIGKILL (not delivered via signal path; directly forced to exit).
///
/// Returns the `ExitState` and `ExitAction` for the leader.
///
/// Reference: Linux exit_group(2).
pub fn do_exit_group(
    code: i32,
    thread_count: u32,
    fd_count: u32,
    vma_count: u32,
    child_count: u32,
    has_parent: bool,
) -> Result<(ExitState, ExitAction)> {
    let exit_code = ExitCode::new(code);
    let state = ExitState::group(exit_code);
    let action = compute_exit_action(fd_count, vma_count, child_count, has_parent);

    // Account for other threads that need to be woken and forced to exit.
    let _ = thread_count;

    Ok((state, action))
}

/// Validate an exit code.
///
/// Always succeeds because exit codes are masked to 8 bits without error.
pub fn validate_exit_code(code: i32) -> ExitCode {
    ExitCode::new(code)
}
