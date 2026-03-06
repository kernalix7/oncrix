// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Global process table.
//!
//! Maps [`Pid`] → [`ProcessEntry`] for all active processes in the system.
//! Provides O(1) lookup by PID, insertion, removal, and iteration.
//!
//! The table uses a fixed-size array indexed by PID value. This avoids
//! heap allocation and keeps the implementation `no_std`-friendly.
//! The maximum number of concurrent processes is [`MAX_PROCESSES`].

use crate::pid::Pid;
use crate::process::{Process, ProcessState};
use crate::signal::SignalState;
use oncrix_lib::{Error, Result};

/// Maximum number of concurrent processes.
pub const MAX_PROCESSES: usize = 256;

/// Exit status of a terminated process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExitStatus(i32);

impl ExitStatus {
    /// Exited normally with the given code.
    pub const fn code(code: i32) -> Self {
        Self(code)
    }

    /// Killed by a signal.
    pub const fn signal(sig: u8) -> Self {
        // Encode signal death as 128 + signal number (POSIX convention).
        Self(128 + sig as i32)
    }

    /// Return the raw exit status value.
    pub const fn raw(self) -> i32 {
        self.0
    }

    /// Check if the process was killed by a signal (status >= 128).
    pub const fn was_signaled(self) -> bool {
        self.0 >= 128
    }
}

impl core::fmt::Display for ExitStatus {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        if self.was_signaled() {
            write!(f, "signal({})", self.0 - 128)
        } else {
            write!(f, "exit({})", self.0)
        }
    }
}

/// A process entry in the global process table.
///
/// Extends [`Process`] with parent relationship, signal state,
/// and exit information needed by `wait4` and `kill`.
#[derive(Debug)]
pub struct ProcessEntry {
    /// The process itself (PID, threads, state).
    pub process: Process,
    /// Parent process ID (`Pid::KERNEL` for init).
    pub parent: Pid,
    /// Per-process signal state.
    pub signals: SignalState,
    /// Exit status, set when the process terminates.
    pub exit_status: Option<ExitStatus>,
}

impl ProcessEntry {
    /// Create a new process entry.
    pub fn new(process: Process, parent: Pid) -> Self {
        Self {
            process,
            parent,
            signals: SignalState::new(),
            exit_status: None,
        }
    }

    /// Return the PID.
    pub fn pid(&self) -> Pid {
        self.process.pid()
    }

    /// Check if this process has exited and has a status to report.
    pub fn is_zombie(&self) -> bool {
        self.process.state() == ProcessState::Exited && self.exit_status.is_some()
    }
}

/// Global process table — maps PID → ProcessEntry.
///
/// Indexed by `Pid::as_u64() % MAX_PROCESSES` for O(1) access.
/// Since PIDs are unique and monotonically increasing, collisions
/// only occur after PID wraparound (not currently implemented).
pub struct ProcessTable {
    /// Process slots.
    entries: [Option<ProcessEntry>; MAX_PROCESSES],
    /// Number of active entries.
    count: usize,
}

impl core::fmt::Debug for ProcessTable {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ProcessTable")
            .field("count", &self.count)
            .field("capacity", &MAX_PROCESSES)
            .finish()
    }
}

impl Default for ProcessTable {
    fn default() -> Self {
        Self::new()
    }
}

impl ProcessTable {
    /// Create an empty process table.
    pub const fn new() -> Self {
        const NONE: Option<ProcessEntry> = None;
        Self {
            entries: [NONE; MAX_PROCESSES],
            count: 0,
        }
    }

    /// Insert a process into the table.
    ///
    /// Returns `AlreadyExists` if a process with the same PID is
    /// already present, or `OutOfMemory` if the table is full.
    pub fn insert(&mut self, entry: ProcessEntry) -> Result<()> {
        let idx = Self::pid_to_index(entry.pid());

        if let Some(existing) = &self.entries[idx] {
            if existing.pid() == entry.pid() {
                return Err(Error::AlreadyExists);
            }
            // Slot collision — scan for a free slot.
            return self.insert_scan(entry);
        }

        self.entries[idx] = Some(entry);
        self.count += 1;
        Ok(())
    }

    /// Look up a process by PID.
    pub fn get(&self, pid: Pid) -> Option<&ProcessEntry> {
        let idx = Self::pid_to_index(pid);

        // Fast path: check the indexed slot first.
        if let Some(entry) = &self.entries[idx] {
            if entry.pid() == pid {
                return Some(entry);
            }
        }

        // Slow path: linear scan (needed only after collisions).
        self.entries
            .iter()
            .filter_map(|s| s.as_ref())
            .find(|e| e.pid() == pid)
    }

    /// Look up a process by PID (mutable).
    pub fn get_mut(&mut self, pid: Pid) -> Option<&mut ProcessEntry> {
        let idx = Self::pid_to_index(pid);

        // Fast path: check indexed slot.
        if let Some(entry) = &self.entries[idx] {
            if entry.pid() == pid {
                return self.entries[idx].as_mut();
            }
        }

        // Slow path: linear scan.
        self.entries
            .iter_mut()
            .filter_map(|s| s.as_mut())
            .find(|e| e.pid() == pid)
    }

    /// Remove a process from the table.
    ///
    /// Returns the removed entry, or `None` if not found.
    pub fn remove(&mut self, pid: Pid) -> Option<ProcessEntry> {
        let idx = Self::pid_to_index(pid);

        // Fast path.
        if let Some(entry) = &self.entries[idx] {
            if entry.pid() == pid {
                self.count = self.count.saturating_sub(1);
                return self.entries[idx].take();
            }
        }

        // Slow path.
        for slot in self.entries.iter_mut() {
            if let Some(entry) = slot {
                if entry.pid() == pid {
                    self.count = self.count.saturating_sub(1);
                    return slot.take();
                }
            }
        }

        None
    }

    /// Find all children of a given parent PID.
    pub fn children(&self, parent: Pid) -> impl Iterator<Item = &ProcessEntry> {
        self.entries
            .iter()
            .filter_map(|s| s.as_ref())
            .filter(move |e| e.parent == parent)
    }

    /// Find zombie children of a given parent (for `wait4`).
    pub fn zombie_children(&self, parent: Pid) -> impl Iterator<Item = &ProcessEntry> {
        self.entries
            .iter()
            .filter_map(|s| s.as_ref())
            .filter(move |e| e.parent == parent && e.is_zombie())
    }

    /// Iterate over all active processes.
    pub fn iter(&self) -> impl Iterator<Item = &ProcessEntry> {
        self.entries.iter().filter_map(|s| s.as_ref())
    }

    /// Iterate over all active processes (mutable).
    pub fn iter_mut(&mut self) -> impl Iterator<Item = &mut ProcessEntry> {
        self.entries.iter_mut().filter_map(|s| s.as_mut())
    }

    /// Return the number of active processes.
    pub fn count(&self) -> usize {
        self.count
    }

    /// Check if the table is full.
    pub fn is_full(&self) -> bool {
        self.count >= MAX_PROCESSES
    }

    /// Map PID to table index.
    fn pid_to_index(pid: Pid) -> usize {
        (pid.as_u64() as usize) % MAX_PROCESSES
    }

    /// Insert by scanning for a free slot (collision fallback).
    fn insert_scan(&mut self, entry: ProcessEntry) -> Result<()> {
        if self.count >= MAX_PROCESSES {
            return Err(Error::OutOfMemory);
        }
        for slot in self.entries.iter_mut() {
            if slot.is_none() {
                *slot = Some(entry);
                self.count += 1;
                return Ok(());
            }
        }
        Err(Error::OutOfMemory)
    }
}
