// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! pidfs — file descriptor-based process identification.
//!
//! pidfs provides stable, race-free process references via file descriptors.
//! Unlike PID numbers (which can be recycled after a process exits), a pidfs
//! file descriptor refers to a specific process instance. It becomes invalid
//! (yields ESRCH) when the process exits, regardless of PID reuse.
//!
//! # Usage
//!
//! A pidfd is obtained via:
//! - `pidfd_open(pid, flags)` — opens a pidfd for an existing process.
//! - `clone(CLONE_PIDFD, ...)` — atomically creates a process and its pidfd.
//!
//! Once open, the pidfd can be used with:
//! - `waitid(P_PIDFD, ...)` — wait for process state changes.
//! - `pidfd_send_signal(pidfd, sig, ...)` — send a signal without race.
//! - `pidfd_getfd(pidfd, targetfd, ...)` — duplicate a fd from another process.
//! - `poll()` — becomes readable when the process exits (POLLIN | POLLHUP).

use oncrix_lib::{Error, Result};

/// Flags for `pidfd_open`.
pub mod pidfd_flags {
    /// Non-blocking flag (O_NONBLOCK semantics for pidfd).
    pub const PIDFD_NONBLOCK: u32 = 0x00000800;
    /// Thread-level pidfd (refers to a thread, not a thread group leader).
    pub const PIDFD_THREAD: u32 = 0x00000001;
}

/// State of a process referenced by a pidfd.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PidState {
    /// Process is alive and running.
    Alive,
    /// Process has exited but not yet waited on (zombie).
    Zombie,
    /// Process has been reaped; pidfd is stale.
    Dead,
}

impl Default for PidState {
    fn default() -> Self {
        Self::Dead
    }
}

/// A pidfd inode — represents a specific process instance.
#[derive(Clone, Copy, Default)]
pub struct PidfdInode {
    /// The PID of the referenced process.
    pub pid: u32,
    /// Unique process instance cookie (monotonically increasing per fork).
    pub instance_id: u64,
    /// Current state of the process.
    pub state: PidState,
    /// Exit status (valid when state == Zombie or Dead).
    pub exit_code: i32,
    /// User namespace ID that owns this pidfd.
    pub user_ns_id: u32,
    /// Whether this pidfd refers to a thread (vs. thread group leader).
    pub is_thread: bool,
    /// Reference count (number of open file descriptors).
    pub ref_count: u32,
}

impl PidfdInode {
    /// Creates a new pidfd inode for a live process.
    pub fn new(pid: u32, instance_id: u64, user_ns_id: u32, is_thread: bool) -> Self {
        Self {
            pid,
            instance_id,
            state: PidState::Alive,
            exit_code: 0,
            user_ns_id,
            is_thread,
            ref_count: 1,
        }
    }

    /// Returns `true` if the process is still alive.
    pub const fn is_alive(&self) -> bool {
        matches!(self.state, PidState::Alive)
    }

    /// Returns `true` if the pidfd is pollable for readiness (process exited).
    pub const fn poll_readable(&self) -> bool {
        !self.is_alive()
    }

    /// Marks the process as having exited with `exit_code`.
    pub fn mark_exited(&mut self, exit_code: i32) {
        self.state = PidState::Zombie;
        self.exit_code = exit_code;
    }

    /// Marks the process as reaped.
    pub fn mark_dead(&mut self) {
        self.state = PidState::Dead;
    }

    /// Increments the reference count.
    pub fn get(&mut self) {
        self.ref_count = self.ref_count.saturating_add(1);
    }

    /// Decrements the reference count.
    ///
    /// Returns `true` if the inode should be freed.
    pub fn put(&mut self) -> bool {
        if self.ref_count > 0 {
            self.ref_count -= 1;
        }
        self.ref_count == 0
    }
}

/// The pidfs inode table.
pub struct PidfsTable {
    inodes: [PidfdInode; 512],
    count: usize,
    next_instance_id: u64,
}

impl Default for PidfsTable {
    fn default() -> Self {
        Self {
            inodes: [PidfdInode::default(); 512],
            count: 0,
            next_instance_id: 1,
        }
    }
}

impl PidfsTable {
    /// Creates a new empty table.
    pub const fn new() -> Self {
        Self {
            inodes: [PidfdInode {
                pid: 0,
                instance_id: 0,
                state: PidState::Dead,
                exit_code: 0,
                user_ns_id: 0,
                is_thread: false,
                ref_count: 0,
            }; 512],
            count: 0,
            next_instance_id: 1,
        }
    }

    /// Opens a pidfd for the process with `pid`.
    ///
    /// If an inode already exists for this pid+instance_id, increments its
    /// ref count. Otherwise allocates a new inode.
    ///
    /// Returns the index into the inode table.
    pub fn open(&mut self, pid: u32, user_ns_id: u32, flags: u32) -> Result<usize> {
        if self.count >= 512 {
            return Err(Error::OutOfMemory);
        }
        let is_thread = flags & pidfd_flags::PIDFD_THREAD != 0;
        let instance_id = self.next_instance_id;
        self.next_instance_id += 1;
        let inode = PidfdInode::new(pid, instance_id, user_ns_id, is_thread);
        let idx = self.count;
        self.inodes[idx] = inode;
        self.count += 1;
        Ok(idx)
    }

    /// Finds the inode for `pid` with the given `instance_id`.
    pub fn find(&self, pid: u32, instance_id: u64) -> Option<&PidfdInode> {
        self.inodes[..self.count]
            .iter()
            .find(|i| i.pid == pid && i.instance_id == instance_id)
    }

    /// Finds a mutable inode.
    pub fn find_mut(&mut self, pid: u32, instance_id: u64) -> Option<&mut PidfdInode> {
        let count = self.count;
        self.inodes[..count]
            .iter_mut()
            .find(|i| i.pid == pid && i.instance_id == instance_id)
    }

    /// Notifies all pidfds for `pid` that the process has exited.
    pub fn notify_exit(&mut self, pid: u32, exit_code: i32) {
        for inode in &mut self.inodes[..self.count] {
            if inode.pid == pid && inode.is_alive() {
                inode.mark_exited(exit_code);
            }
        }
    }

    /// Attempts to send signal `sig` to the process referenced by the inode at `idx`.
    ///
    /// Returns `Err(NotFound)` if the process is no longer alive.
    pub fn send_signal(&self, idx: usize, _sig: u32) -> Result<()> {
        if idx >= self.count {
            return Err(Error::InvalidArgument);
        }
        if !self.inodes[idx].is_alive() {
            return Err(Error::NotFound);
        }
        // Signal delivery is handled by the process/signal subsystem.
        Ok(())
    }
}
