// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Process representation and lifecycle management.

use crate::pid::{Pid, Tid};

/// Maximum number of threads per process.
pub const MAX_THREADS_PER_PROCESS: usize = 64;

/// Process execution state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessState {
    /// Process is alive and has at least one runnable thread.
    Active,
    /// Process has exited and is awaiting cleanup.
    Exited,
}

/// A process — the unit of isolation and resource ownership.
///
/// Each process has its own virtual address space and a set of
/// threads. In the ONCRIX microkernel, user-space services
/// (drivers, VFS, networking) are separate processes communicating
/// via IPC.
#[derive(Debug)]
pub struct Process {
    /// Process identifier.
    pid: Pid,
    /// Current process state.
    state: ProcessState,
    /// Thread IDs belonging to this process.
    threads: [Option<Tid>; MAX_THREADS_PER_PROCESS],
    /// Number of active threads.
    thread_count: usize,
}

impl Process {
    /// Create a new process with no threads.
    pub const fn new(pid: Pid) -> Self {
        Self {
            pid,
            state: ProcessState::Active,
            threads: [None; MAX_THREADS_PER_PROCESS],
            thread_count: 0,
        }
    }

    /// Return the process ID.
    pub const fn pid(&self) -> Pid {
        self.pid
    }

    /// Return the current process state.
    pub const fn state(&self) -> ProcessState {
        self.state
    }

    /// Return the number of active threads.
    pub const fn thread_count(&self) -> usize {
        self.thread_count
    }

    /// Add a thread to this process.
    ///
    /// Returns `Err(InvalidArgument)` if the thread limit is reached.
    pub fn add_thread(&mut self, tid: Tid) -> oncrix_lib::Result<()> {
        if self.thread_count >= MAX_THREADS_PER_PROCESS {
            return Err(oncrix_lib::Error::InvalidArgument);
        }
        self.threads[self.thread_count] = Some(tid);
        self.thread_count += 1;
        Ok(())
    }

    /// Mark the process as exited.
    pub fn exit(&mut self) {
        self.state = ProcessState::Exited;
    }

    /// Return an iterator over active thread IDs.
    pub fn thread_ids(&self) -> impl Iterator<Item = Tid> + '_ {
        self.threads[..self.thread_count].iter().filter_map(|t| *t)
    }
}
