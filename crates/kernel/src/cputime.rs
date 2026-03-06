// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Per-process and per-CPU time accounting.
//!
//! Provides time tracking for individual CPUs (user, system, idle,
//! iowait, irq, softirq, steal, guest) and per-process CPU time
//! accounting compatible with POSIX `clock_gettime(CLOCK_PROCESS_-
//! CPUTIME_ID)` and `clock_gettime(CLOCK_THREAD_CPUTIME_ID)`.
//!
//! # Architecture
//!
//! ```text
//! ┌───────────────────────────────────────────────┐
//! │         PerCpuAccounting                      │
//! │  [CpuTime; MAX_CPUS] — per-CPU statistics     │
//! └───────────────────────────────────────────────┘
//! ┌───────────────────────────────────────────────┐
//! │         ProcessTimeTable                      │
//! │  [ProcessCpuTime; MAX_TRACKED_PIDS]           │
//! │  register / unregister / account / query      │
//! └───────────────────────────────────────────────┘
//! ```

use oncrix_lib::{Error, Result};

// ── Constants ──────────────────────────────────────────────────

/// Maximum number of CPUs supported for time accounting.
pub const MAX_CPUS: usize = 64;

/// Maximum number of concurrently tracked process entries.
pub const MAX_TRACKED_PIDS: usize = 256;

/// Nanoseconds per second.
pub const _NANOS_PER_SEC: u64 = 1_000_000_000;

/// Nanoseconds per microsecond.
pub const _NANOS_PER_USEC: u64 = 1000;

// ── CpuTimeType ────────────────────────────────────────────────

/// Classification of CPU time for accounting purposes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CpuTimeType {
    /// Time spent executing user-space code.
    User,
    /// Time spent executing kernel code on behalf of a process.
    System,
    /// Time spent idle with no runnable tasks.
    #[default]
    Idle,
    /// Time spent waiting for I/O completion.
    IoWait,
    /// Time spent servicing hardware interrupts.
    Irq,
    /// Time spent servicing software interrupts.
    SoftIrq,
    /// Time stolen by a hypervisor for other guests.
    Steal,
    /// Time spent running a virtual CPU for a guest OS.
    Guest,
}

// ── CpuTime ────────────────────────────────────────────────────

/// Accumulated CPU time broken down by category.
#[derive(Debug, Clone, Copy, Default)]
pub struct CpuTime {
    /// Nanoseconds spent in user mode.
    pub user_ns: u64,
    /// Nanoseconds spent in system (kernel) mode.
    pub system_ns: u64,
    /// Nanoseconds spent idle.
    pub idle_ns: u64,
    /// Nanoseconds spent waiting for I/O.
    pub iowait_ns: u64,
    /// Nanoseconds spent servicing hardware interrupts.
    pub irq_ns: u64,
    /// Nanoseconds spent servicing software interrupts.
    pub softirq_ns: u64,
    /// Nanoseconds stolen by a hypervisor.
    pub steal_ns: u64,
    /// Nanoseconds spent running a guest virtual CPU.
    pub guest_ns: u64,
}

impl CpuTime {
    /// Returns the total time across all categories.
    pub fn total(&self) -> u64 {
        self.user_ns
            .saturating_add(self.system_ns)
            .saturating_add(self.idle_ns)
            .saturating_add(self.iowait_ns)
            .saturating_add(self.irq_ns)
            .saturating_add(self.softirq_ns)
            .saturating_add(self.steal_ns)
            .saturating_add(self.guest_ns)
    }

    /// Returns the busy (non-idle, non-iowait) time.
    pub fn busy(&self) -> u64 {
        self.total()
            .saturating_sub(self.idle_ns)
            .saturating_sub(self.iowait_ns)
    }
}

// ── ProcessCpuTime ─────────────────────────────────────────────

/// Per-process CPU time accounting entry.
#[derive(Debug, Clone, Copy, Default)]
pub struct ProcessCpuTime {
    /// Process identifier.
    pub pid: u64,
    /// User-mode CPU time in nanoseconds.
    pub utime_ns: u64,
    /// System-mode CPU time in nanoseconds.
    pub stime_ns: u64,
    /// Accumulated user time of waited-for children (ns).
    pub cutime_ns: u64,
    /// Accumulated system time of waited-for children (ns).
    pub cstime_ns: u64,
    /// Monotonic timestamp when the process started (ns).
    pub start_time_ns: u64,
    /// Whether this entry is currently in use.
    pub active: bool,
}

// ── PerCpuAccounting ───────────────────────────────────────────

/// System-wide per-CPU time accounting table.
pub struct PerCpuAccounting {
    /// Per-CPU time statistics.
    per_cpu: [CpuTime; MAX_CPUS],
    /// Number of CPUs present in the system.
    cpu_count: usize,
}

impl Default for PerCpuAccounting {
    fn default() -> Self {
        Self::new()
    }
}

impl PerCpuAccounting {
    /// Creates a new, zeroed per-CPU accounting table.
    pub const fn new() -> Self {
        const ZERO: CpuTime = CpuTime {
            user_ns: 0,
            system_ns: 0,
            idle_ns: 0,
            iowait_ns: 0,
            irq_ns: 0,
            softirq_ns: 0,
            steal_ns: 0,
            guest_ns: 0,
        };
        Self {
            per_cpu: [ZERO; MAX_CPUS],
            cpu_count: 0,
        }
    }

    /// Accounts `ns` nanoseconds of the given `time_type` to `cpu`.
    ///
    /// Silently ignored if `cpu` is out of range.
    pub fn account(&mut self, cpu: usize, time_type: CpuTimeType, ns: u64) {
        if cpu >= MAX_CPUS {
            return;
        }
        if cpu >= self.cpu_count {
            self.cpu_count = cpu + 1;
        }
        let entry = &mut self.per_cpu[cpu];
        match time_type {
            CpuTimeType::User => {
                entry.user_ns = entry.user_ns.saturating_add(ns);
            }
            CpuTimeType::System => {
                entry.system_ns = entry.system_ns.saturating_add(ns);
            }
            CpuTimeType::Idle => {
                entry.idle_ns = entry.idle_ns.saturating_add(ns);
            }
            CpuTimeType::IoWait => {
                entry.iowait_ns = entry.iowait_ns.saturating_add(ns);
            }
            CpuTimeType::Irq => {
                entry.irq_ns = entry.irq_ns.saturating_add(ns);
            }
            CpuTimeType::SoftIrq => {
                entry.softirq_ns = entry.softirq_ns.saturating_add(ns);
            }
            CpuTimeType::Steal => {
                entry.steal_ns = entry.steal_ns.saturating_add(ns);
            }
            CpuTimeType::Guest => {
                entry.guest_ns = entry.guest_ns.saturating_add(ns);
            }
        }
    }

    /// Returns a reference to the time statistics for `cpu`.
    ///
    /// Returns `None` if `cpu` is out of range.
    pub fn get_cpu(&self, cpu: usize) -> Option<&CpuTime> {
        if cpu >= MAX_CPUS {
            return None;
        }
        Some(&self.per_cpu[cpu])
    }

    /// Returns aggregate time across all CPUs.
    pub fn total(&self) -> CpuTime {
        let mut agg = CpuTime::default();
        for i in 0..self.cpu_count {
            let c = &self.per_cpu[i];
            agg.user_ns = agg.user_ns.saturating_add(c.user_ns);
            agg.system_ns = agg.system_ns.saturating_add(c.system_ns);
            agg.idle_ns = agg.idle_ns.saturating_add(c.idle_ns);
            agg.iowait_ns = agg.iowait_ns.saturating_add(c.iowait_ns);
            agg.irq_ns = agg.irq_ns.saturating_add(c.irq_ns);
            agg.softirq_ns = agg.softirq_ns.saturating_add(c.softirq_ns);
            agg.steal_ns = agg.steal_ns.saturating_add(c.steal_ns);
            agg.guest_ns = agg.guest_ns.saturating_add(c.guest_ns);
        }
        agg
    }
}

// ── ProcessTimeTable ───────────────────────────────────────────

/// Table tracking per-process CPU time for up to
/// [`MAX_TRACKED_PIDS`] processes.
pub struct ProcessTimeTable {
    /// Fixed-size array of process time entries.
    entries: [ProcessCpuTime; MAX_TRACKED_PIDS],
    /// Number of active entries.
    count: usize,
}

impl Default for ProcessTimeTable {
    fn default() -> Self {
        Self::new()
    }
}

impl ProcessTimeTable {
    /// Creates a new, empty process time table.
    pub const fn new() -> Self {
        const ZERO: ProcessCpuTime = ProcessCpuTime {
            pid: 0,
            utime_ns: 0,
            stime_ns: 0,
            cutime_ns: 0,
            cstime_ns: 0,
            start_time_ns: 0,
            active: false,
        };
        Self {
            entries: [ZERO; MAX_TRACKED_PIDS],
            count: 0,
        }
    }

    /// Registers a new process for time tracking.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the table is full, or
    /// [`Error::AlreadyExists`] if `pid` is already registered.
    pub fn register(&mut self, pid: u64, start_ns: u64) -> Result<()> {
        // Check for duplicates.
        if self.find_index(pid).is_some() {
            return Err(Error::AlreadyExists);
        }
        // Find a free slot.
        let slot = self
            .entries
            .iter()
            .position(|e| !e.active)
            .ok_or(Error::OutOfMemory)?;
        self.entries[slot] = ProcessCpuTime {
            pid,
            utime_ns: 0,
            stime_ns: 0,
            cutime_ns: 0,
            cstime_ns: 0,
            start_time_ns: start_ns,
            active: true,
        };
        self.count = self.count.saturating_add(1);
        Ok(())
    }

    /// Unregisters a process, freeing its slot.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if `pid` is not registered.
    pub fn unregister(&mut self, pid: u64) -> Result<()> {
        let idx = self.find_index(pid).ok_or(Error::NotFound)?;
        self.entries[idx].active = false;
        self.count = self.count.saturating_sub(1);
        Ok(())
    }

    /// Accounts `ns` nanoseconds of user-mode time for `pid`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if `pid` is not registered.
    pub fn account_user(&mut self, pid: u64, ns: u64) -> Result<()> {
        let idx = self.find_index(pid).ok_or(Error::NotFound)?;
        self.entries[idx].utime_ns = self.entries[idx].utime_ns.saturating_add(ns);
        Ok(())
    }

    /// Accounts `ns` nanoseconds of system-mode time for `pid`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if `pid` is not registered.
    pub fn account_system(&mut self, pid: u64, ns: u64) -> Result<()> {
        let idx = self.find_index(pid).ok_or(Error::NotFound)?;
        self.entries[idx].stime_ns = self.entries[idx].stime_ns.saturating_add(ns);
        Ok(())
    }

    /// Accounts accumulated children CPU time for `pid`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if `pid` is not registered.
    pub fn account_children(&mut self, pid: u64, utime: u64, stime: u64) -> Result<()> {
        let idx = self.find_index(pid).ok_or(Error::NotFound)?;
        self.entries[idx].cutime_ns = self.entries[idx].cutime_ns.saturating_add(utime);
        self.entries[idx].cstime_ns = self.entries[idx].cstime_ns.saturating_add(stime);
        Ok(())
    }

    /// Returns a reference to the time entry for `pid`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if `pid` is not registered.
    pub fn get_times(&self, pid: u64) -> Result<&ProcessCpuTime> {
        let idx = self.find_index(pid).ok_or(Error::NotFound)?;
        Ok(&self.entries[idx])
    }

    /// Returns the total CPU time (user + system) for `pid`,
    /// compatible with `CLOCK_PROCESS_CPUTIME_ID`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if `pid` is not registered.
    pub fn clock_gettime_process(&self, pid: u64) -> Result<u64> {
        let t = self.get_times(pid)?;
        Ok(t.utime_ns.saturating_add(t.stime_ns))
    }

    /// Returns the total CPU time for a thread identified by
    /// `pid`, compatible with `CLOCK_THREAD_CPUTIME_ID`.
    ///
    /// Currently a stub that returns the same value as
    /// [`clock_gettime_process`](Self::clock_gettime_process).
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if `pid` is not registered.
    pub fn clock_gettime_thread(&self, pid: u64) -> Result<u64> {
        self.clock_gettime_process(pid)
    }

    /// Returns the number of active entries.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Returns `true` if no processes are being tracked.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Finds the index of an active entry with the given `pid`.
    fn find_index(&self, pid: u64) -> Option<usize> {
        self.entries.iter().position(|e| e.active && e.pid == pid)
    }
}
