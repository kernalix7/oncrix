// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Extended pidfd operations — info queries, fd stealing, wait with
//! rusage, and poll state machine.
//!
//! Extends the base [`super::pidfd`] subsystem with richer process
//! introspection and fd-transfer capabilities:
//!
//! - **[`PidfdInfo`]** — detailed process metadata (pid, tgid, ppid,
//!   uid, gid, exit code, state) in a `repr(C)` layout suitable for
//!   passing across the syscall boundary.
//! - **[`PidfdGetfd`]** — steal or duplicate a file descriptor from
//!   another process by specifying source pid and source fd.
//! - **[`PidfdWaitResult`]** — wait result carrying exit status and
//!   resource usage fields (utime, stime).
//! - **[`PidfdPollState`]** — fine-grained process poll state (Running,
//!   Exited, Signaled, Stopped).
//!
//! # Architecture
//!
//! ```text
//! ┌────────────────────────────────────────────────────────┐
//! │           PidfdExtRegistry (128 entries)                │
//! │  ┌───────────┐  ┌───────────┐       ┌───────────┐    │
//! │  │ entry 0   │  │ entry 1   │  ...  │ entry 127 │    │
//! │  │ PidfdInfo │  │ PidfdInfo │       │ PidfdInfo │    │
//! │  │ PollState │  │ PollState │       │ PollState │    │
//! │  └───────────┘  └───────────┘       └───────────┘    │
//! └────────────────────────────────────────────────────────┘
//! ```

use oncrix_lib::{Error, Result};

// ── Constants ────────────────────────────────────────────────────

/// Maximum number of extended pidfd entries system-wide.
const MAX_PIDFD_EXT_ENTRIES: usize = 128;

/// Flag: duplicate the fd (default, no special behavior).
const _PIDFD_GETFD_DEFAULT: u32 = 0;

/// Flag: close the source fd in the target process after duplication.
const PIDFD_GETFD_CLOEXEC: u32 = 1 << 0;

// ── PidfdPollState ───────────────────────────────────────────────

/// Fine-grained poll state of a process referenced by a pidfd.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum PidfdPollState {
    /// The process is actively running or runnable.
    #[default]
    Running,
    /// The process has exited normally.
    Exited,
    /// The process was terminated by a signal.
    Signaled,
    /// The process is stopped (e.g., by SIGSTOP or ptrace).
    Stopped,
}

// ── PidfdInfo ────────────────────────────────────────────────────

/// Detailed process metadata retrieved via a pidfd.
///
/// Laid out as a C-compatible structure so it can be copied across
/// the user-kernel boundary via `copy_to_user`.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct PidfdInfo {
    /// Process ID.
    pub pid: u64,
    /// Thread group ID (main thread PID).
    pub tgid: u64,
    /// Parent process ID.
    pub ppid: u64,
    /// Real user ID of the process.
    pub uid: u32,
    /// Real group ID of the process.
    pub gid: u32,
    /// Exit code (meaningful only when state is `Exited` or
    /// `Signaled`).
    pub exit_code: i32,
    /// Current process state.
    pub state: u8,
    /// Padding for alignment.
    _pad: [u8; 3],
}

impl PidfdInfo {
    /// Create a new `PidfdInfo` for a running process.
    pub const fn new(pid: u64, tgid: u64, ppid: u64, uid: u32, gid: u32) -> Self {
        Self {
            pid,
            tgid,
            ppid,
            uid,
            gid,
            exit_code: 0,
            state: 0, // Running
            _pad: [0; 3],
        }
    }

    /// Return the poll state derived from the `state` field.
    pub const fn poll_state(&self) -> PidfdPollState {
        match self.state {
            1 => PidfdPollState::Exited,
            2 => PidfdPollState::Signaled,
            3 => PidfdPollState::Stopped,
            _ => PidfdPollState::Running,
        }
    }

    /// Set the exit state.
    pub fn set_exited(&mut self, exit_code: i32) {
        self.state = 1;
        self.exit_code = exit_code;
    }

    /// Set the signaled state.
    pub fn set_signaled(&mut self, signal: i32) {
        self.state = 2;
        self.exit_code = signal;
    }

    /// Set the stopped state.
    pub fn set_stopped(&mut self) {
        self.state = 3;
    }

    /// Reset to running state.
    pub fn set_running(&mut self) {
        self.state = 0;
        self.exit_code = 0;
    }
}

impl Default for PidfdInfo {
    fn default() -> Self {
        Self::new(0, 0, 0, 0, 0)
    }
}

// ── PidfdGetfd ───────────────────────────────────────────────────

/// Request to steal or duplicate a file descriptor from another
/// process via its pidfd.
///
/// This corresponds to the Linux `pidfd_getfd(2)` syscall. The
/// caller specifies the source process (by pid), the fd number
/// within that process, and flags controlling the operation.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct PidfdGetfd {
    /// PID of the source process.
    pub source_pid: u64,
    /// File descriptor number in the source process.
    pub source_fd: i32,
    /// Flags controlling the operation (e.g.,
    /// `PIDFD_GETFD_CLOEXEC`).
    pub flags: u32,
}

impl PidfdGetfd {
    /// Create a new getfd request.
    pub const fn new(source_pid: u64, source_fd: i32, flags: u32) -> Self {
        Self {
            source_pid,
            source_fd,
            flags,
        }
    }

    /// Validate the request parameters.
    pub const fn validate(&self) -> Result<()> {
        if self.source_pid == 0 {
            return Err(Error::InvalidArgument);
        }
        if self.source_fd < 0 {
            return Err(Error::InvalidArgument);
        }
        // Only known flags are allowed.
        if self.flags & !PIDFD_GETFD_CLOEXEC != 0 {
            return Err(Error::InvalidArgument);
        }
        Ok(())
    }

    /// Check whether `PIDFD_GETFD_CLOEXEC` is set.
    pub const fn cloexec(&self) -> bool {
        self.flags & PIDFD_GETFD_CLOEXEC != 0
    }
}

// ── PidfdWaitResult ──────────────────────────────────────────────

/// Result of waiting for a process via its pidfd.
///
/// Extends the basic `(pid, exit_code)` wait result with resource
/// usage fields mirroring `struct rusage` from POSIX `wait4(2)`.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct PidfdWaitResult {
    /// PID of the waited-for process.
    pub pid: u64,
    /// Exit status (as returned by `waitpid`).
    pub exit_status: i32,
    /// User CPU time consumed in microseconds.
    pub utime: u64,
    /// System CPU time consumed in microseconds.
    pub stime: u64,
}

impl PidfdWaitResult {
    /// Create a new wait result.
    pub const fn new(pid: u64, exit_status: i32, utime: u64, stime: u64) -> Self {
        Self {
            pid,
            exit_status,
            utime,
            stime,
        }
    }

    /// Check whether the process exited normally.
    pub const fn exited_normally(&self) -> bool {
        // Conventional: bits 7..0 are zero for normal exit.
        self.exit_status & 0x7f == 0
    }

    /// Return the exit code (bits 15..8 of exit_status).
    pub const fn exit_code(&self) -> i32 {
        (self.exit_status >> 8) & 0xff
    }

    /// Return total CPU time (user + system) in microseconds.
    pub const fn total_cpu_time(&self) -> u64 {
        self.utime.saturating_add(self.stime)
    }
}

impl Default for PidfdWaitResult {
    fn default() -> Self {
        Self::new(0, 0, 0, 0)
    }
}

// ── PidfdExtEntry ────────────────────────────────────────────────

/// Internal entry combining info and poll state for a pidfd.
struct PidfdExtEntry {
    /// Process information.
    info: PidfdInfo,
    /// Current poll state.
    poll_state: PidfdPollState,
    /// Accumulated user CPU time in microseconds.
    utime: u64,
    /// Accumulated system CPU time in microseconds.
    stime: u64,
    /// Whether this slot is in use.
    active: bool,
}

impl PidfdExtEntry {
    /// Create an empty, inactive entry.
    const fn empty() -> Self {
        Self {
            info: PidfdInfo::new(0, 0, 0, 0, 0),
            poll_state: PidfdPollState::Running,
            utime: 0,
            stime: 0,
            active: false,
        }
    }
}

// ── PidfdExtRegistry ─────────────────────────────────────────────

/// Registry of extended pidfd entries.
///
/// Provides higher-level operations on pidfds including process info
/// queries, fd stealing, wait-with-rusage, and fine-grained poll state.
pub struct PidfdExtRegistry {
    /// Fixed array of pidfd extension entries.
    entries: [PidfdExtEntry; MAX_PIDFD_EXT_ENTRIES],
    /// Number of active entries.
    count: usize,
}

impl Default for PidfdExtRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl PidfdExtRegistry {
    /// Create an empty registry.
    pub const fn new() -> Self {
        Self {
            entries: [const { PidfdExtEntry::empty() }; MAX_PIDFD_EXT_ENTRIES],
            count: 0,
        }
    }

    /// Register a process for extended pidfd operations.
    ///
    /// Returns the entry index on success. Fails with `OutOfMemory`
    /// if all slots are occupied, or `InvalidArgument` if `pid` is
    /// zero.
    pub fn register(
        &mut self,
        pid: u64,
        tgid: u64,
        ppid: u64,
        uid: u32,
        gid: u32,
    ) -> Result<usize> {
        if pid == 0 {
            return Err(Error::InvalidArgument);
        }

        for (idx, entry) in self.entries.iter_mut().enumerate() {
            if !entry.active {
                entry.info = PidfdInfo::new(pid, tgid, ppid, uid, gid);
                entry.poll_state = PidfdPollState::Running;
                entry.utime = 0;
                entry.stime = 0;
                entry.active = true;
                self.count = self.count.saturating_add(1);
                return Ok(idx);
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Obtain a duplicate of a file descriptor from a target process.
    ///
    /// This is a stub — full implementation requires VFS and
    /// process fd-table integration. Currently validates the
    /// request and returns the same fd number.
    pub fn pidfd_getfd(&self, id: usize, req: &PidfdGetfd) -> Result<i32> {
        req.validate()?;
        let entry = self.get_entry(id)?;

        if entry.info.pid != req.source_pid {
            return Err(Error::InvalidArgument);
        }
        if entry.poll_state == PidfdPollState::Exited
            || entry.poll_state == PidfdPollState::Signaled
        {
            return Err(Error::InvalidArgument);
        }

        // Stub: return the source fd. A real implementation would
        // duplicate the fd from the target process's fd table.
        Ok(req.source_fd)
    }

    /// Wait for a process to exit and retrieve its exit status and
    /// resource usage.
    ///
    /// Returns `Err(WouldBlock)` if the process has not yet exited.
    pub fn pidfd_wait(&self, id: usize) -> Result<PidfdWaitResult> {
        let entry = self.get_entry(id)?;

        if entry.poll_state != PidfdPollState::Exited
            && entry.poll_state != PidfdPollState::Signaled
        {
            return Err(Error::WouldBlock);
        }

        Ok(PidfdWaitResult::new(
            entry.info.pid,
            entry.info.exit_code,
            entry.utime,
            entry.stime,
        ))
    }

    /// Poll the current state of a process.
    pub fn pidfd_poll(&self, id: usize) -> Result<PidfdPollState> {
        let entry = self.get_entry(id)?;
        Ok(entry.poll_state)
    }

    /// Retrieve detailed process information.
    pub fn pidfd_info(&self, id: usize) -> Result<PidfdInfo> {
        let entry = self.get_entry(id)?;
        Ok(entry.info)
    }

    /// Notify the registry that a process has exited normally.
    pub fn notify_exit(&mut self, pid: u64, exit_code: i32) {
        for entry in &mut self.entries {
            if entry.active && entry.info.pid == pid {
                entry.info.set_exited(exit_code);
                entry.poll_state = PidfdPollState::Exited;
            }
        }
    }

    /// Notify the registry that a process was killed by a signal.
    pub fn notify_signaled(&mut self, pid: u64, signal: i32) {
        for entry in &mut self.entries {
            if entry.active && entry.info.pid == pid {
                entry.info.set_signaled(signal);
                entry.poll_state = PidfdPollState::Signaled;
            }
        }
    }

    /// Notify the registry that a process has been stopped.
    pub fn notify_stopped(&mut self, pid: u64) {
        for entry in &mut self.entries {
            if entry.active && entry.info.pid == pid {
                entry.info.set_stopped();
                entry.poll_state = PidfdPollState::Stopped;
            }
        }
    }

    /// Update resource usage counters for a process.
    pub fn update_rusage(&mut self, id: usize, utime: u64, stime: u64) -> Result<()> {
        let entry = self.get_entry_mut(id)?;
        entry.utime = utime;
        entry.stime = stime;
        Ok(())
    }

    /// Unregister a pidfd entry, freeing its slot.
    pub fn unregister(&mut self, id: usize) -> Result<()> {
        let entry = self.get_entry_mut(id)?;
        *entry = PidfdExtEntry::empty();
        self.count = self.count.saturating_sub(1);
        Ok(())
    }

    /// Return the number of active entries.
    pub const fn len(&self) -> usize {
        self.count
    }

    /// Return whether the registry is empty.
    pub const fn is_empty(&self) -> bool {
        self.count == 0
    }

    // ── Private helpers ──────────────────────────────────────────

    /// Get a shared reference to an active entry.
    fn get_entry(&self, id: usize) -> Result<&PidfdExtEntry> {
        let entry = self.entries.get(id).ok_or(Error::InvalidArgument)?;
        if !entry.active {
            return Err(Error::NotFound);
        }
        Ok(entry)
    }

    /// Get a mutable reference to an active entry.
    fn get_entry_mut(&mut self, id: usize) -> Result<&mut PidfdExtEntry> {
        let entry = self.entries.get_mut(id).ok_or(Error::InvalidArgument)?;
        if !entry.active {
            return Err(Error::NotFound);
        }
        Ok(entry)
    }
}
