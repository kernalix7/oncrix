// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `wait4` / `waitpid` syscall handlers.
//!
//! Implements `wait4(2)` per Linux ABI and POSIX.1-2024 `waitpid()`.
//! `wait4` waits for a child process to change state, optionally fills
//! in the `struct rusage` for the child, and reaps zombie children.
//!
//! # References
//!
//! - POSIX.1-2024: `waitpid()`
//! - Linux man pages: `wait4(2)`, `waitpid(2)`, `wait(2)`

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Wait options (POSIX + Linux extensions)
// ---------------------------------------------------------------------------

/// Return immediately if no child has changed state.
pub const WNOHANG: i32 = 0x0000_0001;
/// Also report children stopped by a signal (not yet traced).
pub const WUNTRACED: i32 = 0x0000_0002;
/// Also report children that have been continued (SIGCONT).
pub const WCONTINUED: i32 = 0x0000_0008;
/// Do not reap — leave the child in a waitable state.
pub const WNOWAIT: i32 = 0x0100_0000;
/// Wait for children in any state (internal kernel flag).
pub const WEXITED: i32 = 0x0000_0004;

/// Mask of all recognised options for wait4.
const WAIT4_OPTIONS_KNOWN: i32 = WNOHANG | WUNTRACED | WCONTINUED | WNOWAIT | WEXITED;

// ---------------------------------------------------------------------------
// WaitStatus — wait status word (mirrors <sys/wait.h> macros)
// ---------------------------------------------------------------------------

/// Decoded wait status returned by `wait4`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct WaitStatus {
    /// Raw status word as returned by the kernel.
    pub raw: i32,
}

impl WaitStatus {
    /// Construct a status indicating normal exit with `code`.
    pub const fn exited(code: i32) -> Self {
        Self {
            raw: (code & 0xFF) << 8,
        }
    }

    /// Construct a status indicating termination by signal `sig`.
    pub const fn signaled(sig: i32) -> Self {
        Self { raw: sig & 0x7F }
    }

    /// Construct a status indicating the child was stopped by signal `sig`.
    pub const fn stopped(sig: i32) -> Self {
        Self {
            raw: 0x7F | ((sig & 0xFF) << 8),
        }
    }

    /// Construct a status indicating the child was continued (SIGCONT).
    pub const fn continued() -> Self {
        Self { raw: 0xFFFF }
    }

    /// Return `true` if the child exited normally.
    pub const fn is_exited(&self) -> bool {
        (self.raw & 0x7F) == 0
    }

    /// Return the exit code (valid when `is_exited()` is true).
    pub const fn exit_code(&self) -> i32 {
        (self.raw >> 8) & 0xFF
    }

    /// Return `true` if the child was terminated by a signal.
    pub const fn is_signaled(&self) -> bool {
        let lower = self.raw & 0x7F;
        lower != 0 && lower != 0x7F
    }

    /// Return the signal that terminated the child (valid when `is_signaled()`).
    pub const fn term_signal(&self) -> i32 {
        self.raw & 0x7F
    }

    /// Return `true` if the child is currently stopped.
    pub const fn is_stopped(&self) -> bool {
        (self.raw & 0xFF) == 0x7F
    }

    /// Return the signal that stopped the child (valid when `is_stopped()`).
    pub const fn stop_signal(&self) -> i32 {
        (self.raw >> 8) & 0xFF
    }

    /// Return `true` if the child was continued.
    pub const fn is_continued(&self) -> bool {
        self.raw == 0xFFFF
    }
}

// ---------------------------------------------------------------------------
// Rusage — resource usage for the child
// ---------------------------------------------------------------------------

/// Abbreviated `struct rusage` for `wait4`.
///
/// A full implementation would include all fields from `<sys/resource.h>`.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Rusage {
    /// User time consumed in seconds.
    pub utime_sec: i64,
    /// User time consumed in microseconds.
    pub utime_usec: i64,
    /// System time consumed in seconds.
    pub stime_sec: i64,
    /// System time consumed in microseconds.
    pub stime_usec: i64,
    /// Maximum resident set size in kilobytes.
    pub maxrss: i64,
    /// Number of involuntary context switches.
    pub nivcsw: i64,
    /// Number of voluntary context switches.
    pub nvcsw: i64,
}

// ---------------------------------------------------------------------------
// ChildState — state of a child process
// ---------------------------------------------------------------------------

/// The current state of a child process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChildState {
    /// Running normally.
    Running,
    /// Zombie (has exited, not yet reaped).
    Zombie(WaitStatus),
    /// Stopped by a signal.
    Stopped(i32),
    /// Continued by SIGCONT.
    Continued,
}

// ---------------------------------------------------------------------------
// ChildInfo — per-child record
// ---------------------------------------------------------------------------

/// Information about a single child process.
#[derive(Debug, Clone, Copy)]
pub struct ChildInfo {
    /// PID of the child.
    pub pid: u64,
    /// Process group ID of the child.
    pub pgid: u64,
    /// Current state.
    pub state: ChildState,
    /// Accumulated resource usage.
    pub rusage: Rusage,
}

impl ChildInfo {
    /// Construct a zombie child.
    pub fn zombie(pid: u64, pgid: u64, status: WaitStatus) -> Self {
        Self {
            pid,
            pgid,
            state: ChildState::Zombie(status),
            rusage: Rusage::default(),
        }
    }

    /// Return `true` if this child matches the `pid` argument to wait4.
    ///
    /// - `pid > 0`: wait for exactly that PID.
    /// - `pid == 0`: wait for any child in the same process group.
    /// - `pid == -1`: wait for any child.
    /// - `pid < -1`: wait for any child in PGID == `-pid`.
    pub fn matches_pid(&self, pid: i64, caller_pgid: u64) -> bool {
        match pid {
            p if p > 0 => self.pid == p as u64,
            0 => self.pgid == caller_pgid,
            -1 => true,
            p => self.pgid == (-p) as u64,
        }
    }
}

// ---------------------------------------------------------------------------
// Wait4Result
// ---------------------------------------------------------------------------

/// Outcome of a `wait4` call.
#[derive(Debug, Clone, Copy, Default)]
pub struct Wait4Result {
    /// PID of the child that changed state (0 if WNOHANG and none ready).
    pub pid: u64,
    /// Wait status word.
    pub status: WaitStatus,
    /// Resource usage of the child.
    pub rusage: Rusage,
}

// ---------------------------------------------------------------------------
// Validation helpers
// ---------------------------------------------------------------------------

/// Validate `wait4` options.
fn validate_options(options: i32) -> Result<()> {
    if options & !WAIT4_OPTIONS_KNOWN != 0 {
        return Err(Error::InvalidArgument);
    }
    Ok(())
}

/// Validate the `pid` argument.
fn validate_pid(pid: i64) -> Result<()> {
    // pid == i64::MIN is invalid (negating it overflows).
    if pid == i64::MIN {
        return Err(Error::InvalidArgument);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Public syscall handlers
// ---------------------------------------------------------------------------

/// `wait4` — wait for a child process to change state.
///
/// `pid` semantics:
/// - `> 0`  — wait for the specific PID.
/// - `0`    — wait for any child in the same process group.
/// - `-1`   — wait for any child.
/// - `< -1` — wait for any child in PGID == `-pid`.
///
/// `options` may be:
/// - `WNOHANG` — return immediately if no child is ready.
/// - `WUNTRACED` — also report stopped children.
/// - `WCONTINUED` — also report continued children.
///
/// Returns `(child_pid, status, rusage)`. If `WNOHANG` is set and no
/// child is ready, returns `(0, _, _)`.
///
/// Reference: POSIX.1-2024 §waitpid, Linux wait4(2).
pub fn do_wait4(
    pid: i64,
    options: i32,
    caller_pgid: u64,
    children: &[ChildInfo],
) -> Result<Wait4Result> {
    validate_pid(pid)?;
    validate_options(options)?;

    // Find a matching child that has changed state.
    for child in children {
        if !child.matches_pid(pid, caller_pgid) {
            continue;
        }

        match child.state {
            ChildState::Zombie(status) => {
                // Reap the zombie.
                return Ok(Wait4Result {
                    pid: child.pid,
                    status,
                    rusage: child.rusage,
                });
            }
            ChildState::Stopped(sig) if options & WUNTRACED != 0 => {
                return Ok(Wait4Result {
                    pid: child.pid,
                    status: WaitStatus::stopped(sig),
                    rusage: child.rusage,
                });
            }
            ChildState::Continued if options & WCONTINUED != 0 => {
                return Ok(Wait4Result {
                    pid: child.pid,
                    status: WaitStatus::continued(),
                    rusage: child.rusage,
                });
            }
            _ => {}
        }
    }

    // No matching child in a waitable state.
    if options & WNOHANG != 0 {
        return Ok(Wait4Result::default());
    }

    // Blocking wait: stub returns not-implemented.
    Err(Error::NotImplemented)
}

/// `waitpid` — wait for a specific child (simplified POSIX form).
///
/// Equivalent to `wait4(pid, options, caller_pgid, children)` without
/// resource usage collection.
pub fn do_waitpid(
    pid: i64,
    options: i32,
    caller_pgid: u64,
    children: &[ChildInfo],
) -> Result<(u64, WaitStatus)> {
    let result = do_wait4(pid, options, caller_pgid, children)?;
    Ok((result.pid, result.status))
}

/// Validate `wait4` arguments without performing the wait.
pub fn validate_wait4_args(pid: i64, options: i32) -> Result<()> {
    validate_pid(pid)?;
    validate_options(options)
}
