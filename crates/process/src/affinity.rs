// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! CPU affinity management for processes and threads.
//!
//! Implements `sched_setaffinity` / `sched_getaffinity` semantics,
//! allowing processes to be pinned to specific CPUs. The scheduler
//! consults the affinity mask when selecting a CPU for a thread.
//!
//! # Data Structures
//!
//! - [`CpuSet`] — bitmask of allowed CPUs (up to 64)
//! - [`AffinityTable`] — per-PID affinity storage

use oncrix_lib::{Error, Result};

use crate::pid::Pid;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum CPUs supported.
pub const MAX_CPUS: usize = 64;

/// Maximum tracked affinity entries.
const MAX_AFFINITY_ENTRIES: usize = 256;

// ---------------------------------------------------------------------------
// CpuSet
// ---------------------------------------------------------------------------

/// Bitmask representing a set of CPUs.
///
/// Each bit position corresponds to a CPU ID (0..63).
/// A set bit means the CPU is included in the set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(transparent)]
pub struct CpuSet(u64);

impl CpuSet {
    /// Empty set (no CPUs).
    pub const EMPTY: Self = Self(0);

    /// All CPUs set.
    pub const ALL: Self = Self(u64::MAX);

    /// Create a set with a single CPU.
    pub const fn single(cpu: usize) -> Self {
        if cpu < MAX_CPUS {
            Self(1u64 << cpu)
        } else {
            Self(0)
        }
    }

    /// Create from raw bitmask.
    pub const fn from_bits(bits: u64) -> Self {
        Self(bits)
    }

    /// Return raw bitmask.
    pub const fn bits(self) -> u64 {
        self.0
    }

    /// Add a CPU to the set.
    pub fn set(&mut self, cpu: usize) {
        if cpu < MAX_CPUS {
            self.0 |= 1u64 << cpu;
        }
    }

    /// Remove a CPU from the set.
    pub fn clear(&mut self, cpu: usize) {
        if cpu < MAX_CPUS {
            self.0 &= !(1u64 << cpu);
        }
    }

    /// Check if a CPU is in the set.
    pub const fn contains(self, cpu: usize) -> bool {
        if cpu < MAX_CPUS {
            (self.0 >> cpu) & 1 != 0
        } else {
            false
        }
    }

    /// Returns the number of CPUs in the set.
    pub const fn count(self) -> u32 {
        self.0.count_ones()
    }

    /// Returns `true` if the set is empty.
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// Compute the intersection of two sets.
    pub const fn and(self, other: Self) -> Self {
        Self(self.0 & other.0)
    }

    /// Compute the union of two sets.
    pub const fn or(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// Returns the lowest-numbered CPU in the set, or `None`.
    pub const fn first(self) -> Option<usize> {
        if self.0 == 0 {
            None
        } else {
            Some(self.0.trailing_zeros() as usize)
        }
    }

    /// Create a set from a range of CPUs `[start, end)`.
    pub fn from_range(start: usize, end: usize) -> Self {
        let mut bits = 0u64;
        let clamped_end = end.min(MAX_CPUS);
        let mut cpu = start;
        while cpu < clamped_end {
            bits |= 1u64 << cpu;
            cpu += 1;
        }
        Self(bits)
    }

    /// Returns the number of CPUs in the set up to `online`,
    /// representing the effective set given the number of online CPUs.
    pub fn effective_count(self, online: usize) -> u32 {
        let mask = if online >= MAX_CPUS {
            u64::MAX
        } else {
            (1u64 << online) - 1
        };
        (self.0 & mask).count_ones()
    }
}

impl Default for CpuSet {
    fn default() -> Self {
        Self::ALL
    }
}

// ---------------------------------------------------------------------------
// Affinity Entry
// ---------------------------------------------------------------------------

/// Per-process CPU affinity entry.
#[derive(Debug, Clone, Copy)]
struct AffinityEntry {
    /// Process ID.
    pid: Pid,
    /// Allowed CPU set.
    cpuset: CpuSet,
    /// Whether this slot is active.
    active: bool,
}

impl Default for AffinityEntry {
    fn default() -> Self {
        Self {
            pid: Pid::new(0),
            cpuset: CpuSet::ALL,
            active: false,
        }
    }
}

// ---------------------------------------------------------------------------
// Affinity Table
// ---------------------------------------------------------------------------

/// Global table of per-process CPU affinity masks.
pub struct AffinityTable {
    /// Affinity entries.
    entries: [AffinityEntry; MAX_AFFINITY_ENTRIES],
    /// Number of active entries.
    count: usize,
}

impl AffinityTable {
    /// Create an empty affinity table.
    pub const fn new() -> Self {
        const EMPTY: AffinityEntry = AffinityEntry {
            pid: Pid::new(0),
            cpuset: CpuSet::ALL,
            active: false,
        };
        Self {
            entries: [EMPTY; MAX_AFFINITY_ENTRIES],
            count: 0,
        }
    }

    /// Set the CPU affinity for a process.
    ///
    /// If the process already has an affinity entry, it is updated.
    /// Otherwise a new entry is created.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `cpuset` is empty.
    /// Returns [`Error::OutOfMemory`] if the table is full.
    pub fn set_affinity(&mut self, pid: Pid, cpuset: CpuSet) -> Result<()> {
        if cpuset.is_empty() {
            return Err(Error::InvalidArgument);
        }

        // Update existing
        for entry in &mut self.entries {
            if entry.active && entry.pid == pid {
                entry.cpuset = cpuset;
                return Ok(());
            }
        }

        // Insert new
        let idx = self
            .entries
            .iter()
            .position(|e| !e.active)
            .ok_or(Error::OutOfMemory)?;
        self.entries[idx] = AffinityEntry {
            pid,
            cpuset,
            active: true,
        };
        self.count += 1;
        Ok(())
    }

    /// Get the CPU affinity for a process.
    ///
    /// Returns [`CpuSet::ALL`] if no affinity has been set (default).
    pub fn get_affinity(&self, pid: Pid) -> CpuSet {
        self.entries
            .iter()
            .find(|e| e.active && e.pid == pid)
            .map(|e| e.cpuset)
            .unwrap_or(CpuSet::ALL)
    }

    /// Remove the affinity entry for a process (reset to default).
    pub fn remove(&mut self, pid: Pid) {
        for entry in &mut self.entries {
            if entry.active && entry.pid == pid {
                entry.active = false;
                self.count = self.count.saturating_sub(1);
                return;
            }
        }
    }

    /// Check if a process is allowed to run on a given CPU.
    pub fn is_allowed(&self, pid: Pid, cpu: usize) -> bool {
        self.get_affinity(pid).contains(cpu)
    }

    /// Select the best CPU for a process from `online_cpus`,
    /// respecting its affinity mask. Returns the lowest available CPU.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if no CPU in the affinity
    /// set is online.
    pub fn select_cpu(&self, pid: Pid, online_cpus: CpuSet) -> Result<usize> {
        let affinity = self.get_affinity(pid);
        let candidates = affinity.and(online_cpus);
        candidates.first().ok_or(Error::InvalidArgument)
    }

    /// Returns the number of active affinity entries.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Returns `true` if no affinity entries are set.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
}

impl Default for AffinityTable {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Syscall Interface
// ---------------------------------------------------------------------------

/// Handle `sched_setaffinity(pid, cpusetsize, mask)`.
///
/// Sets the CPU affinity mask for the specified process.
///
/// # Errors
///
/// Returns [`Error::InvalidArgument`] if the mask is empty or
/// `cpusetsize` is 0.
pub fn do_sched_setaffinity(table: &mut AffinityTable, pid: Pid, cpuset: CpuSet) -> Result<()> {
    table.set_affinity(pid, cpuset)
}

/// Handle `sched_getaffinity(pid, cpusetsize, mask)`.
///
/// Returns the current CPU affinity mask for the process.
pub fn do_sched_getaffinity(table: &AffinityTable, pid: Pid) -> CpuSet {
    table.get_affinity(pid)
}
