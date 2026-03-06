// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! CPU topology discovery and enumeration.
//!
//! Parses the hardware topology of the processor complex into a hierarchy
//! of packages, dies, cores, and logical threads. The information is used
//! by the scheduler, NUMA subsystem, and power management to make informed
//! decisions about task placement and frequency scaling.
//!
//! # Hierarchy
//!
//! ```text
//! CpuPackage  (physical socket)
//!   └─ CpuCore  (physical core)
//!       └─ CpuThread  (logical CPU / hardware thread)
//! ```
//!
//! Topology data is typically derived from CPUID leaves 0x0B/0x1F
//! (Extended Topology) or from ACPI SRAT/PPTT tables.
//!
//! Reference: Intel SDM Vol. 3A §8.9 "Topology Enumeration".

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum logical CPU threads tracked.
const MAX_THREADS: usize = 64;

/// Maximum physical cores tracked.
const MAX_CORES: usize = 32;

/// Maximum physical packages (sockets).
const MAX_PACKAGES: usize = 4;

/// Maximum threads per physical core.
const MAX_THREADS_PER_CORE: usize = 4;

/// Maximum cores per package.
const MAX_CORES_PER_PACKAGE: usize = 16;

/// Sentinel value for an unset topology ID.
const INVALID_ID: u8 = u8::MAX;

// ---------------------------------------------------------------------------
// CpuTopologyLevel
// ---------------------------------------------------------------------------

/// Level in the CPU topology hierarchy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CpuTopologyLevel {
    /// Logical processor / hardware thread (SMT sibling).
    Thread,
    /// Physical core (shares L1/L2 cache between its threads).
    Core,
    /// Physical package / die group (shares L3 cache, power domain).
    Package,
    /// Die within a multi-die package (chiplet topology).
    Die,
    /// Cluster of cores sharing a mid-level cache.
    Cluster,
}

// ---------------------------------------------------------------------------
// CpuThread
// ---------------------------------------------------------------------------

/// A single logical CPU (hardware thread).
#[derive(Debug, Clone, Copy)]
pub struct CpuThread {
    /// OS-visible logical CPU ID (APIC / core index).
    pub logical_id: u8,
    /// Physical CPU ID from CPUID (initial APIC ID or x2APIC ID low byte).
    pub physical_id: u8,
    /// Physical core ID within the package.
    pub core_id: u8,
    /// Physical package ID.
    pub package_id: u8,
    /// Die ID within the package (0 if single-die).
    pub die_id: u8,
    /// Whether this thread slot is populated.
    pub valid: bool,
}

impl CpuThread {
    /// Create an invalid (placeholder) thread entry.
    pub const fn new() -> Self {
        Self {
            logical_id: 0,
            physical_id: INVALID_ID,
            core_id: INVALID_ID,
            package_id: INVALID_ID,
            die_id: 0,
            valid: false,
        }
    }
}

impl Default for CpuThread {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// CpuCore
// ---------------------------------------------------------------------------

/// A physical CPU core, consisting of one or more hardware threads.
#[derive(Debug, Clone, Copy)]
pub struct CpuCore {
    /// Core ID within its package.
    pub core_id: u8,
    /// Package that contains this core.
    pub package_id: u8,
    /// Number of hardware threads in this core (1 = no SMT).
    pub thread_count: u8,
    /// Logical IDs of the threads belonging to this core.
    pub thread_ids: [u8; MAX_THREADS_PER_CORE],
    /// Whether this core slot is populated.
    pub valid: bool,
}

impl CpuCore {
    /// Create an empty core entry.
    pub const fn new() -> Self {
        Self {
            core_id: INVALID_ID,
            package_id: INVALID_ID,
            thread_count: 0,
            thread_ids: [INVALID_ID; MAX_THREADS_PER_CORE],
            valid: false,
        }
    }

    /// Add a thread to this core.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the per-core thread array is full.
    pub fn add_thread(&mut self, logical_id: u8) -> Result<()> {
        if self.thread_count as usize >= MAX_THREADS_PER_CORE {
            return Err(Error::OutOfMemory);
        }
        self.thread_ids[self.thread_count as usize] = logical_id;
        self.thread_count += 1;
        Ok(())
    }
}

impl Default for CpuCore {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// CpuPackage
// ---------------------------------------------------------------------------

/// A physical processor package (socket), containing one or more cores.
#[derive(Debug, Clone, Copy)]
pub struct CpuPackage {
    /// Package ID (APIC package ID field).
    pub package_id: u8,
    /// Number of physical cores in this package.
    pub core_count: u8,
    /// Physical cores belonging to this package.
    pub cores: [CpuCore; MAX_CORES_PER_PACKAGE],
    /// Whether this package slot is populated.
    pub valid: bool,
}

impl CpuPackage {
    /// Create an empty package entry.
    pub const fn new() -> Self {
        Self {
            package_id: INVALID_ID,
            core_count: 0,
            cores: [const { CpuCore::new() }; MAX_CORES_PER_PACKAGE],
            valid: false,
        }
    }

    /// Add a core to this package.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the per-package core array is full.
    pub fn add_core(&mut self, core: CpuCore) -> Result<usize> {
        if self.core_count as usize >= MAX_CORES_PER_PACKAGE {
            return Err(Error::OutOfMemory);
        }
        let idx = self.core_count as usize;
        self.cores[idx] = core;
        self.core_count += 1;
        Ok(idx)
    }

    /// Find a core by `core_id`.
    pub fn find_core(&self, core_id: u8) -> Option<&CpuCore> {
        self.cores[..self.core_count as usize]
            .iter()
            .find(|c| c.core_id == core_id)
    }

    /// Find a core by `core_id` (mutable).
    pub fn find_core_mut(&mut self, core_id: u8) -> Option<&mut CpuCore> {
        let count = self.core_count as usize;
        self.cores[..count]
            .iter_mut()
            .find(|c| c.core_id == core_id)
    }
}

impl Default for CpuPackage {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// TopologyStats
// ---------------------------------------------------------------------------

/// Summary statistics for the discovered topology.
#[derive(Debug, Clone, Copy, Default)]
pub struct TopologyStats {
    /// Number of physical packages (sockets).
    pub packages: u8,
    /// Total physical cores across all packages.
    pub cores: u8,
    /// Total logical threads (online CPUs).
    pub threads: u8,
    /// Whether Hyper-Threading / SMT is enabled (any core has > 1 thread).
    pub ht_enabled: bool,
}

impl TopologyStats {
    /// Create a zeroed stats structure.
    pub const fn new() -> Self {
        Self {
            packages: 0,
            cores: 0,
            threads: 0,
            ht_enabled: false,
        }
    }
}

// ---------------------------------------------------------------------------
// CpuTopology
// ---------------------------------------------------------------------------

/// Full CPU topology for the system.
pub struct CpuTopology {
    threads: [CpuThread; MAX_THREADS],
    thread_count: usize,
    cores: [CpuCore; MAX_CORES],
    core_count: usize,
    packages: [CpuPackage; MAX_PACKAGES],
    package_count: usize,
    stats: TopologyStats,
}

impl CpuTopology {
    /// Create an empty topology.
    pub const fn new() -> Self {
        Self {
            threads: [const { CpuThread::new() }; MAX_THREADS],
            thread_count: 0,
            cores: [const { CpuCore::new() }; MAX_CORES],
            core_count: 0,
            packages: [const { CpuPackage::new() }; MAX_PACKAGES],
            package_count: 0,
            stats: TopologyStats::new(),
        }
    }

    // -----------------------------------------------------------------------
    // Discovery
    // -----------------------------------------------------------------------

    /// Register a logical CPU thread with its topology identifiers.
    ///
    /// Automatically creates the containing core and package entries if they
    /// do not yet exist. Recalculates [`TopologyStats`] after each insertion.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if any of the fixed-size tables are
    /// full, or [`Error::AlreadyExists`] if `logical_id` is already registered.
    pub fn discover(&mut self, thread: CpuThread) -> Result<()> {
        if !thread.valid {
            return Err(Error::InvalidArgument);
        }
        if self.thread_count >= MAX_THREADS {
            return Err(Error::OutOfMemory);
        }
        // Check for duplicate logical ID.
        if self.find_thread(thread.logical_id).is_some() {
            return Err(Error::AlreadyExists);
        }

        // Ensure the package exists.
        if !self.has_package(thread.package_id) {
            if self.package_count >= MAX_PACKAGES {
                return Err(Error::OutOfMemory);
            }
            let mut pkg = CpuPackage::new();
            pkg.package_id = thread.package_id;
            pkg.valid = true;
            self.packages[self.package_count] = pkg;
            self.package_count += 1;
        }

        // Ensure the core exists (in the flat core list).
        if !self.has_core(thread.core_id, thread.package_id) {
            if self.core_count >= MAX_CORES {
                return Err(Error::OutOfMemory);
            }
            let mut core = CpuCore::new();
            core.core_id = thread.core_id;
            core.package_id = thread.package_id;
            core.valid = true;
            self.cores[self.core_count] = core;
            self.core_count += 1;
        }

        // Add the thread to its core.
        let core_pos = (0..self.core_count)
            .find(|&i| {
                self.cores[i].core_id == thread.core_id
                    && self.cores[i].package_id == thread.package_id
            })
            .ok_or(Error::NotFound)?;
        self.cores[core_pos].add_thread(thread.logical_id)?;

        // Also add the core to its package if not already there.
        let pkg_pos = (0..self.package_count)
            .find(|&i| self.packages[i].package_id == thread.package_id)
            .ok_or(Error::NotFound)?;
        if self.packages[pkg_pos].find_core(thread.core_id).is_none() {
            let core_snapshot = self.cores[core_pos];
            self.packages[pkg_pos].add_core(core_snapshot)?;
        } else {
            // Update the package's copy of the core so the thread_ids stay in sync.
            let core_snapshot = self.cores[core_pos];
            if let Some(pkg_core) = self.packages[pkg_pos].find_core_mut(thread.core_id) {
                *pkg_core = core_snapshot;
            }
        }

        // Store the thread.
        self.threads[self.thread_count] = thread;
        self.thread_count += 1;

        // Recompute stats.
        self.recompute_stats();

        Ok(())
    }

    // -----------------------------------------------------------------------
    // Sibling queries
    // -----------------------------------------------------------------------

    /// Return a bitmask of logical CPU IDs that are siblings of `logical_id`
    /// at the given topology `level`.
    ///
    /// - `Thread` level: siblings share the same physical core (SMT peers).
    /// - `Core` level: siblings share the same package.
    /// - `Package` level: all threads in the system.
    /// - `Die` / `Cluster`: all threads with the same die_id / package (approximated).
    ///
    /// The bit at position `logical_id` itself is included.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if `logical_id` is not registered.
    pub fn siblings_mask(&self, logical_id: u8, level: CpuTopologyLevel) -> Result<u64> {
        let source = self.find_thread(logical_id).ok_or(Error::NotFound)?;
        let mut mask: u64 = 0;

        for t in self.threads[..self.thread_count].iter() {
            if !t.valid {
                continue;
            }
            let is_sibling = match level {
                CpuTopologyLevel::Thread => {
                    t.core_id == source.core_id && t.package_id == source.package_id
                }
                CpuTopologyLevel::Core => t.package_id == source.package_id,
                CpuTopologyLevel::Package => true,
                CpuTopologyLevel::Die => {
                    t.die_id == source.die_id && t.package_id == source.package_id
                }
                CpuTopologyLevel::Cluster => t.package_id == source.package_id,
            };
            if is_sibling && (t.logical_id as usize) < 64 {
                mask |= 1u64 << t.logical_id;
            }
        }

        Ok(mask)
    }

    // -----------------------------------------------------------------------
    // Lookup helpers
    // -----------------------------------------------------------------------

    /// Look up a thread by logical ID.
    pub fn find_thread(&self, logical_id: u8) -> Option<&CpuThread> {
        self.threads[..self.thread_count]
            .iter()
            .find(|t| t.valid && t.logical_id == logical_id)
    }

    /// Look up a core by (core_id, package_id).
    pub fn find_core(&self, core_id: u8, package_id: u8) -> Option<&CpuCore> {
        self.cores[..self.core_count]
            .iter()
            .find(|c| c.valid && c.core_id == core_id && c.package_id == package_id)
    }

    /// Look up a package by package_id.
    pub fn find_package(&self, package_id: u8) -> Option<&CpuPackage> {
        self.packages[..self.package_count]
            .iter()
            .find(|p| p.valid && p.package_id == package_id)
    }

    /// Return the total number of registered logical threads.
    pub fn thread_count(&self) -> usize {
        self.thread_count
    }

    /// Return the total number of physical cores.
    pub fn core_count(&self) -> usize {
        self.core_count
    }

    /// Return the total number of physical packages.
    pub fn package_count(&self) -> usize {
        self.package_count
    }

    /// Return a snapshot of the topology statistics.
    pub fn stats(&self) -> TopologyStats {
        self.stats
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    fn has_package(&self, package_id: u8) -> bool {
        self.packages[..self.package_count]
            .iter()
            .any(|p| p.valid && p.package_id == package_id)
    }

    fn has_core(&self, core_id: u8, package_id: u8) -> bool {
        self.cores[..self.core_count]
            .iter()
            .any(|c| c.valid && c.core_id == core_id && c.package_id == package_id)
    }

    /// Recompute `TopologyStats` from the current tables.
    fn recompute_stats(&mut self) {
        let packages = self.packages[..self.package_count]
            .iter()
            .filter(|p| p.valid)
            .count() as u8;
        let cores = self.cores[..self.core_count]
            .iter()
            .filter(|c| c.valid)
            .count() as u8;
        let threads = self.threads[..self.thread_count]
            .iter()
            .filter(|t| t.valid)
            .count() as u8;
        let ht_enabled = self.cores[..self.core_count]
            .iter()
            .any(|c| c.valid && c.thread_count > 1);
        self.stats = TopologyStats {
            packages,
            cores,
            threads,
            ht_enabled,
        };
    }
}

impl Default for CpuTopology {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Convenience builder helper
// ---------------------------------------------------------------------------

/// Build a [`CpuThread`] with the specified identifiers.
///
/// The resulting thread has `valid = true`.
pub fn make_thread(logical_id: u8, physical_id: u8, core_id: u8, package_id: u8) -> CpuThread {
    CpuThread {
        logical_id,
        physical_id,
        core_id,
        package_id,
        die_id: 0,
        valid: true,
    }
}
