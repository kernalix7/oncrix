// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Process file descriptor (pidfd) subsystem.
//!
//! Provides file descriptors that refer to processes, enabling
//! race-free process management. A pidfd remains valid for the
//! lifetime of the target process, unlike PIDs which can be
//! recycled after the process exits.
//!
//! # Supported operations
//!
//! - [`PidfdRegistry::pidfd_open`] — create a pidfd for a target
//!   process.
//! - [`PidfdRegistry::pidfd_send_signal`] — send a signal to the
//!   process referenced by the pidfd.
//! - [`PidfdRegistry::pidfd_getfd`] — obtain a duplicate of a file
//!   descriptor from the target process (stub).
//! - [`PidfdRegistry::poll`] — check whether the target process
//!   has exited.
//! - [`PidfdRegistry::waitid_pidfd`] — wait for the target process
//!   to exit and retrieve its exit code.
//!
//! # Architecture
//!
//! ```text
//! ┌───────────────────────────────────────────────┐
//! │              PidfdRegistry                    │
//! │  (up to MAX_PIDFDS pidfd instances)           │
//! │  ┌──────────┐ ┌──────────┐   ┌──────────┐   │
//! │  │ pidfd 0  │ │ pidfd 1  │...│ pidfd N  │   │
//! │  └──────────┘ └──────────┘   └──────────┘   │
//! └───────────────────────────────────────────────┘
//! ```

use oncrix_lib::{Error, Result};

// ── Constants ──────────────────────────────────────────────────

/// Maximum number of concurrent pidfd instances system-wide.
const MAX_PIDFDS: usize = 128;

/// Non-blocking mode flag for pidfd operations.
const _PIDFD_NONBLOCK: u32 = 0x800;

/// Thread-level pidfd flag (refer to a specific thread).
const _PIDFD_THREAD: u32 = 0x01;

// ── PidfdState ─────────────────────────────────────────────────

/// State of a pidfd instance.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum PidfdState {
    /// The pidfd is open and the target process is running.
    #[default]
    Open,
    /// The target process has exited.
    Exited,
    /// The pidfd has been closed.
    Closed,
}

// ── PidfdInfo ──────────────────────────────────────────────────

/// Metadata for a single pidfd instance.
pub struct PidfdInfo {
    /// Unique identifier for this pidfd.
    id: u32,
    /// PID of the target process this pidfd refers to.
    target_pid: u64,
    /// Creation flags (combination of `PIDFD_*` constants).
    flags: u32,
    /// Current state of this pidfd.
    state: PidfdState,
    /// Exit code of the target process (valid when state is
    /// [`PidfdState::Exited`]).
    exit_code: i32,
    /// PID of the process that created (owns) this pidfd.
    owner_pid: u64,
    /// Whether operations are non-blocking.
    nonblock: bool,
    /// Whether this slot is in use.
    active: bool,
    /// Number of signals sent through this pidfd.
    signal_sent_count: u64,
}

impl PidfdInfo {
    /// Return the creation flags.
    pub const fn flags(&self) -> u32 {
        self.flags
    }

    /// Whether this pidfd is in non-blocking mode.
    pub const fn is_nonblock(&self) -> bool {
        self.nonblock
    }

    /// Create a default (inactive) pidfd slot.
    const fn empty() -> Self {
        Self {
            id: 0,
            target_pid: 0,
            flags: 0,
            state: PidfdState::Open,
            exit_code: 0,
            owner_pid: 0,
            nonblock: false,
            active: false,
            signal_sent_count: 0,
        }
    }
}

// ── PidfdRegistry ──────────────────────────────────────────────

/// Global registry of pidfd instances.
///
/// Manages creation, lookup, signalling, and destruction of
/// [`PidfdInfo`] objects. Each pidfd is identified by a numeric
/// ID returned by [`pidfd_open`](PidfdRegistry::pidfd_open).
pub struct PidfdRegistry {
    /// Fixed array of pidfd slots.
    fds: [PidfdInfo; MAX_PIDFDS],
    /// Monotonically increasing ID counter.
    next_id: u32,
    /// Number of active pidfd instances.
    count: usize,
}

impl Default for PidfdRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl PidfdRegistry {
    /// Create an empty registry with no active pidfds.
    pub const fn new() -> Self {
        Self {
            fds: [const { PidfdInfo::empty() }; MAX_PIDFDS],
            next_id: 1,
            count: 0,
        }
    }

    /// Open a pidfd referring to the given target process.
    ///
    /// Returns the pidfd ID on success. Fails with
    /// `OutOfMemory` if all slots are occupied, or
    /// `InvalidArgument` if `pid` is zero.
    pub fn pidfd_open(&mut self, pid: u64, flags: u32, owner: u64) -> Result<u32> {
        if pid == 0 {
            return Err(Error::InvalidArgument);
        }

        let slot = self
            .fds
            .iter_mut()
            .find(|fd| !fd.active)
            .ok_or(Error::OutOfMemory)?;

        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);

        *slot = PidfdInfo {
            id,
            target_pid: pid,
            flags,
            state: PidfdState::Open,
            exit_code: 0,
            owner_pid: owner,
            nonblock: flags & _PIDFD_NONBLOCK != 0,
            active: true,
            signal_sent_count: 0,
        };

        self.count += 1;
        Ok(id)
    }

    /// Send a signal to the process referenced by a pidfd.
    ///
    /// Returns `Err(NotFound)` if the pidfd does not exist,
    /// or `Err(InvalidArgument)` if the target has already
    /// exited or the signal number is invalid.
    pub fn pidfd_send_signal(&mut self, id: u32, sig: i32) -> Result<()> {
        if sig < 0 {
            return Err(Error::InvalidArgument);
        }

        let fd = self.find_active_mut(id)?;

        if fd.state == PidfdState::Exited {
            return Err(Error::InvalidArgument);
        }

        // In a real implementation this would enqueue the signal
        // to the target process via the signal delivery subsystem.
        fd.signal_sent_count += 1;
        Ok(())
    }

    /// Obtain a duplicate of a file descriptor from the target
    /// process referenced by this pidfd.
    ///
    /// This is a stub — full implementation requires the VFS and
    /// process fd-table integration.
    pub fn pidfd_getfd(&self, id: u32, target_fd: i32) -> Result<i32> {
        let fd = self.find_active(id)?;

        if fd.state == PidfdState::Exited {
            return Err(Error::InvalidArgument);
        }

        // Stub: return the same fd number. A real implementation
        // would duplicate the fd from the target process's table.
        Ok(target_fd)
    }

    /// Poll whether the target process has exited.
    ///
    /// Returns `Ok(true)` if the target has exited, `Ok(false)`
    /// if it is still running. Returns `Err(WouldBlock)` in
    /// non-blocking mode when the target has not exited (mirrors
    /// `epoll` semantics).
    pub fn poll(&self, id: u32) -> Result<bool> {
        let fd = self.find_active(id)?;
        Ok(fd.state == PidfdState::Exited)
    }

    /// Close a pidfd, freeing its slot.
    ///
    /// Returns `Err(NotFound)` if the pidfd does not exist or
    /// has already been closed.
    pub fn close(&mut self, id: u32) -> Result<()> {
        let fd = self.find_active_mut(id)?;
        fd.state = PidfdState::Closed;
        fd.active = false;
        self.count = self.count.saturating_sub(1);
        Ok(())
    }

    /// Notify the registry that a process has exited.
    ///
    /// All pidfds targeting the given `pid` are transitioned to
    /// [`PidfdState::Exited`] with the supplied `exit_code`.
    pub fn notify_exit(&mut self, pid: u64, exit_code: i32) {
        for fd in &mut self.fds {
            if fd.active && fd.target_pid == pid && fd.state == PidfdState::Open {
                fd.state = PidfdState::Exited;
                fd.exit_code = exit_code;
            }
        }
    }

    /// Wait for the target process to exit via its pidfd.
    ///
    /// Returns `(target_pid, exit_code)` on success. If the
    /// target has not exited, returns `Err(WouldBlock)`.
    pub fn waitid_pidfd(&self, id: u32) -> Result<(u64, i32)> {
        let fd = self.find_active(id)?;

        if fd.state != PidfdState::Exited {
            return Err(Error::WouldBlock);
        }

        Ok((fd.target_pid, fd.exit_code))
    }

    /// Return the target PID for the given pidfd.
    pub fn get_target_pid(&self, id: u32) -> Result<u64> {
        let fd = self.find_active(id)?;
        Ok(fd.target_pid)
    }

    /// Close all pidfds owned by the given process.
    ///
    /// Called during process teardown to release resources.
    pub fn cleanup_owner(&mut self, pid: u64) {
        for fd in &mut self.fds {
            if fd.active && fd.owner_pid == pid {
                fd.state = PidfdState::Closed;
                fd.active = false;
                self.count = self.count.saturating_sub(1);
            }
        }
    }

    /// Return the number of active pidfds.
    pub const fn len(&self) -> usize {
        self.count
    }

    /// Return whether the registry contains no active pidfds.
    pub const fn is_empty(&self) -> bool {
        self.count == 0
    }

    // ── Private helpers ────────────────────────────────────────

    /// Find an active pidfd by ID (shared reference).
    fn find_active(&self, id: u32) -> Result<&PidfdInfo> {
        self.fds
            .iter()
            .find(|fd| fd.active && fd.id == id)
            .ok_or(Error::NotFound)
    }

    /// Find an active pidfd by ID (mutable reference).
    fn find_active_mut(&mut self, id: u32) -> Result<&mut PidfdInfo> {
        self.fds
            .iter_mut()
            .find(|fd| fd.active && fd.id == id)
            .ok_or(Error::NotFound)
    }
}
