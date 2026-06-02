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
/// Per-process `ITIMER_REAL` interval timer state (`setitimer(2)` /
/// `alarm(2)`).
///
/// Counted down in PIT ticks by the timer interrupt. When `value_ticks`
/// reaches zero the kernel raises `SIGALRM` on the owning process and, if
/// `interval_ticks` is non-zero, reloads `value_ticks` from it (periodic
/// timer); otherwise the timer disarms (`value_ticks` stays `0`).
///
/// All durations are stored in PIT ticks (100 Hz) rather than `timeval`s
/// so the timer-tick decrement is a single subtraction. A `value_ticks`
/// of `0` means "disarmed".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ItimerReal {
    /// Ticks remaining until the next `SIGALRM`. `0` = disarmed.
    pub value_ticks: u64,
    /// Reload value in ticks for a periodic timer. `0` = one-shot.
    pub interval_ticks: u64,
}

impl ItimerReal {
    /// Create a disarmed timer.
    pub const fn new() -> Self {
        Self {
            value_ticks: 0,
            interval_ticks: 0,
        }
    }

    /// Returns `true` if the timer is currently armed (counting down).
    pub const fn is_armed(&self) -> bool {
        self.value_ticks != 0
    }

    /// Advance the timer by one PIT tick.
    ///
    /// Returns `true` if the timer expired on this tick (the caller must
    /// then raise `SIGALRM`). On expiry the timer reloads from
    /// `interval_ticks` for a periodic timer, or disarms for a one-shot.
    /// A disarmed timer is a no-op and returns `false`.
    pub fn tick(&mut self) -> bool {
        if self.value_ticks == 0 {
            return false;
        }
        self.value_ticks -= 1;
        if self.value_ticks == 0 {
            // Expired: reload for periodic, else stay disarmed.
            self.value_ticks = self.interval_ticks;
            true
        } else {
            false
        }
    }
}

/// A single resource limit, as reported by `getrlimit(2)` / set by
/// `setrlimit(2)` / `prlimit64(2)`.
///
/// `rlim_cur` is the soft limit (the value the kernel enforces), and
/// `rlim_max` is the hard limit (the ceiling to which an unprivileged
/// process may raise the soft limit). [`RLIM_INFINITY`] means "no limit".
#[derive(Debug, Clone, Copy)]
pub struct Rlimit {
    /// Soft limit (enforced value).
    pub rlim_cur: u64,
    /// Hard limit (ceiling for `rlim_cur`).
    pub rlim_max: u64,
}

/// `RLIM_INFINITY` — sentinel meaning "no limit".
pub const RLIM_INFINITY: u64 = u64::MAX;

/// Number of modelled resource-limit slots (`RLIMIT_*` indices `0..16`).
pub const RLIMIT_NLIMITS: usize = 16;

/// `RLIMIT_NOFILE` index — maximum number of open file descriptors.
pub const RLIMIT_NOFILE: usize = 7;

/// Default soft/hard cap for `RLIMIT_NOFILE`, matching the per-process
/// file-descriptor table capacity.
pub const RLIMIT_NOFILE_DEFAULT: u64 = 256;

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
    /// `ITIMER_REAL` interval timer (`setitimer`/`alarm`).
    pub itimer_real: ItimerReal,
    /// Process group ID (`getpgid(2)`/`setpgid(2)`).
    ///
    /// At construction this is initialised to the process's own PID, so
    /// a brand-new process is in its own process group (and is therefore
    /// the leader of that group). `sys_fork` is responsible for
    /// overwriting this with the parent's `pgid` so children inherit
    /// the group POSIX-correctly; `setpgid(2)` mutates it explicitly.
    pub pgid: Pid,
    /// Session ID (`getsid(2)`/`setsid(2)`).
    ///
    /// Initialised to the process's own PID — same inheritance rule as
    /// [`pgid`](Self::pgid): the fork path must propagate the parent's
    /// `sid`. `setsid(2)` creates a new session and resets both fields
    /// to the caller's PID.
    pub sid: Pid,
    /// Per-process resource limits, indexed by `RLIMIT_*` resource id
    /// (`getrlimit`/`setrlimit`/`prlimit64`). All default to
    /// [`RLIM_INFINITY`] except `RLIMIT_NOFILE`. Stored for query/retrieval;
    /// enforcement is not yet wired into the allocators.
    pub rlimits: [Rlimit; RLIMIT_NLIMITS],
    /// `umask(2)` — file-mode creation mask. Bits set here are CLEARED on
    /// newly created files (`open`/`creat`/`mkdir`). Standard default is
    /// `0o022` (group / others write bits are stripped).
    pub umask: u32,
}

impl ProcessEntry {
    /// Create a new process entry.
    ///
    /// `pgid` and `sid` default to the process's own PID, matching the
    /// "every process is initially its own session/group leader"
    /// convenience used at boot. The fork path overrides these to
    /// inherit from the parent before insertion.
    pub fn new(process: Process, parent: Pid) -> Self {
        let pid = process.pid();
        Self {
            process,
            parent,
            signals: SignalState::new(),
            exit_status: None,
            itimer_real: ItimerReal::new(),
            pgid: pid,
            sid: pid,
            rlimits: {
                let mut limits = [Rlimit {
                    rlim_cur: RLIM_INFINITY,
                    rlim_max: RLIM_INFINITY,
                }; RLIMIT_NLIMITS];
                limits[RLIMIT_NOFILE] = Rlimit {
                    rlim_cur: RLIMIT_NOFILE_DEFAULT,
                    rlim_max: RLIMIT_NOFILE_DEFAULT,
                };
                limits
            },
            umask: 0o022,
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
