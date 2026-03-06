// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! CPU affinity management.
//!
//! Provides the kernel infrastructure for `sched_setaffinity(2)` and
//! `sched_getaffinity(2)`. Each task has a CPU affinity mask that
//! constrains which CPUs the scheduler may place it on.
//!
//! # Design
//!
//! ```text
//! AffinityManager
//!  ├── entries: [AffinityEntry; MAX_TASKS]
//!  ├── online_mask: CpuMask
//!  └── nr_entries: usize
//!
//! CpuMask
//!  └── bits: [u64; MASK_WORDS]
//!      (bit N set → CPU N is in the mask)
//! ```
//!
//! The scheduler must intersect a task's affinity mask with the set
//! of online CPUs before making placement decisions.

use oncrix_lib::{Error, Result};

// ======================================================================
// Constants
// ======================================================================

/// Maximum CPUs supported.
const MAX_CPUS: usize = 256;

/// Number of u64 words in the CPU mask.
const MASK_WORDS: usize = MAX_CPUS / 64;

/// Maximum tasks with affinity tracking.
const MAX_TASKS: usize = 4096;

// ======================================================================
// Types
// ======================================================================

/// A bitmask representing a set of CPUs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CpuMask {
    /// Bit array: bit N set means CPU N is included.
    pub bits: [u64; MASK_WORDS],
}

impl CpuMask {
    /// Creates an empty CPU mask (no CPUs selected).
    pub const fn new() -> Self {
        Self {
            bits: [0u64; MASK_WORDS],
        }
    }

    /// Creates a mask with all CPUs selected.
    pub const fn all() -> Self {
        Self {
            bits: [u64::MAX; MASK_WORDS],
        }
    }

    /// Sets a specific CPU in the mask.
    pub fn set(&mut self, cpu: usize) -> Result<()> {
        if cpu >= MAX_CPUS {
            return Err(Error::InvalidArgument);
        }
        self.bits[cpu / 64] |= 1u64 << (cpu % 64);
        Ok(())
    }

    /// Clears a specific CPU from the mask.
    pub fn clear(&mut self, cpu: usize) -> Result<()> {
        if cpu >= MAX_CPUS {
            return Err(Error::InvalidArgument);
        }
        self.bits[cpu / 64] &= !(1u64 << (cpu % 64));
        Ok(())
    }

    /// Tests whether a specific CPU is in the mask.
    pub fn test(&self, cpu: usize) -> bool {
        if cpu >= MAX_CPUS {
            return false;
        }
        (self.bits[cpu / 64] & (1u64 << (cpu % 64))) != 0
    }

    /// Returns the number of CPUs set in the mask.
    pub fn count(&self) -> u32 {
        let mut total = 0u32;
        for word in &self.bits {
            total += word.count_ones();
        }
        total
    }

    /// Returns whether the mask is empty.
    pub fn is_empty(&self) -> bool {
        self.bits.iter().all(|&w| w == 0)
    }

    /// Computes the intersection of two masks.
    pub fn intersect(&self, other: &CpuMask) -> CpuMask {
        let mut result = CpuMask::new();
        for i in 0..MASK_WORDS {
            result.bits[i] = self.bits[i] & other.bits[i];
        }
        result
    }

    /// Computes the union of two masks.
    pub fn union(&self, other: &CpuMask) -> CpuMask {
        let mut result = CpuMask::new();
        for i in 0..MASK_WORDS {
            result.bits[i] = self.bits[i] | other.bits[i];
        }
        result
    }

    /// Returns the first CPU set in the mask, or None.
    pub fn first_set(&self) -> Option<usize> {
        for (i, &word) in self.bits.iter().enumerate() {
            if word != 0 {
                return Some(i * 64 + word.trailing_zeros() as usize);
            }
        }
        None
    }
}

impl Default for CpuMask {
    fn default() -> Self {
        Self::new()
    }
}

/// Per-task affinity entry.
#[derive(Debug, Clone, Copy)]
pub struct AffinityEntry {
    /// PID of the task.
    pub pid: u64,
    /// CPU affinity mask.
    pub mask: CpuMask,
    /// Whether this entry is active.
    pub active: bool,
}

impl AffinityEntry {
    /// Creates an empty affinity entry.
    pub const fn new() -> Self {
        Self {
            pid: 0,
            mask: CpuMask::new(),
            active: false,
        }
    }
}

impl Default for AffinityEntry {
    fn default() -> Self {
        Self::new()
    }
}

/// Manages CPU affinity for all tasks.
pub struct AffinityManager {
    /// Per-task affinity entries.
    entries: [AffinityEntry; MAX_TASKS],
    /// Number of active entries.
    nr_entries: usize,
    /// Mask of online CPUs.
    online_mask: CpuMask,
}

impl AffinityManager {
    /// Creates a new affinity manager.
    pub const fn new() -> Self {
        Self {
            entries: [AffinityEntry::new(); MAX_TASKS],
            nr_entries: 0,
            online_mask: CpuMask::new(),
        }
    }

    /// Sets the online CPU mask.
    pub fn set_online_mask(&mut self, mask: CpuMask) -> Result<()> {
        if mask.is_empty() {
            return Err(Error::InvalidArgument);
        }
        self.online_mask = mask;
        Ok(())
    }

    /// Registers a task with a default all-CPUs affinity.
    pub fn register_task(&mut self, pid: u64) -> Result<()> {
        if self.find_entry(pid).is_some() {
            return Err(Error::AlreadyExists);
        }
        if self.nr_entries >= MAX_TASKS {
            return Err(Error::OutOfMemory);
        }
        for entry in &mut self.entries {
            if !entry.active {
                entry.pid = pid;
                entry.mask = CpuMask::all();
                entry.active = true;
                self.nr_entries += 1;
                return Ok(());
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Unregisters a task.
    pub fn unregister_task(&mut self, pid: u64) -> Result<()> {
        let idx = self.find_entry(pid).ok_or(Error::NotFound)?;
        self.entries[idx].active = false;
        self.nr_entries = self.nr_entries.saturating_sub(1);
        Ok(())
    }

    /// Sets the affinity mask for a task.
    ///
    /// The requested mask is intersected with the online mask. If
    /// the result is empty, `InvalidArgument` is returned.
    pub fn set_affinity(&mut self, pid: u64, mask: CpuMask) -> Result<()> {
        let effective = mask.intersect(&self.online_mask);
        if effective.is_empty() {
            return Err(Error::InvalidArgument);
        }
        let idx = self.find_entry(pid).ok_or(Error::NotFound)?;
        self.entries[idx].mask = effective;
        Ok(())
    }

    /// Gets the affinity mask for a task.
    pub fn get_affinity(&self, pid: u64) -> Result<CpuMask> {
        let idx = self.find_entry(pid).ok_or(Error::NotFound)?;
        Ok(self.entries[idx].mask)
    }

    /// Returns the effective mask (affinity AND online) for a task.
    pub fn effective_mask(&self, pid: u64) -> Result<CpuMask> {
        let idx = self.find_entry(pid).ok_or(Error::NotFound)?;
        Ok(self.entries[idx].mask.intersect(&self.online_mask))
    }

    /// Returns the number of registered tasks.
    pub fn nr_entries(&self) -> usize {
        self.nr_entries
    }

    /// Returns a reference to the online mask.
    pub fn online_mask(&self) -> &CpuMask {
        &self.online_mask
    }

    // ------------------------------------------------------------------
    // Internal
    // ------------------------------------------------------------------

    fn find_entry(&self, pid: u64) -> Option<usize> {
        self.entries.iter().position(|e| e.active && e.pid == pid)
    }
}

impl Default for AffinityManager {
    fn default() -> Self {
        Self::new()
    }
}
