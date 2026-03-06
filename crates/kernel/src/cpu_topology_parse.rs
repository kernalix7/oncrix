// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! CPU topology discovery and representation — parse physical
//! package, core, and SMT thread topology, build sibling masks
//! and cache sharing maps.
//!
//! This module provides the data model and parsing logic for
//! discovering the hierarchical CPU topology: sockets (packages),
//! physical cores within each socket, and hardware threads (SMT /
//! hyper-threading) within each core. Cache-sharing relationships
//! are tracked so the scheduler can make topology-aware placement
//! decisions.
//!
//! # Architecture
//!
//! ```text
//! CpuTopologyMap
//!  ├── cpus[MAX_CPUS]
//!  │    └── CpuTopologyEntry
//!  │         ├── logical_id, package_id, core_id, thread_id
//!  │         ├── sibling_mask, core_sibling_mask
//!  │         └── cache_id[MAX_CACHE_LEVELS]
//!  ├── packages[MAX_PACKAGES]
//!  │    └── PackageInfo
//!  │         ├── package_id, core_count, thread_count
//!  │         └── cpu_mask
//!  ├── caches[MAX_CACHE_ENTRIES]
//!  │    └── CacheShareInfo
//!  │         ├── level, cache_type, size_kb
//!  │         └── shared_cpu_mask
//!  └── stats: TopologyStats
//! ```
//!
//! # Discovery
//!
//! On x86-64 the topology is parsed from CPUID leaf 0x0B
//! (extended topology enumeration) and leaf 0x04 (deterministic
//! cache parameters). On AArch64 the ACPI PPTT table or
//! device-tree `cpu-map` node is used. This module provides
//! the registration API; architecture-specific code calls
//! `register_cpu()` for each discovered logical processor.
//!
//! Reference: Linux `drivers/base/arch_topology.c`,
//! `arch/x86/kernel/cpu/topology.c`.

use oncrix_lib::{Error, Result};

// ══════════════════════════════════════════════════════════════
// Constants
// ══════════════════════════════════════════════════════════════

/// Maximum logical CPUs in the system.
const MAX_CPUS: usize = 256;

/// Maximum physical packages (sockets).
const MAX_PACKAGES: usize = 8;

/// Maximum cache descriptor entries.
const MAX_CACHE_ENTRIES: usize = 64;

/// Maximum cache hierarchy levels tracked per CPU.
const MAX_CACHE_LEVELS: usize = 4;

/// Number of u64 words for a CPU bitmask (256 bits / 64).
const MASK_WORDS: usize = MAX_CPUS / 64;

// ══════════════════════════════════════════════════════════════
// CpuMask — bitmask for CPU sets
// ══════════════════════════════════════════════════════════════

/// Fixed-size bitmask representing a set of logical CPUs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CpuMask {
    /// Bitmask words.
    bits: [u64; MASK_WORDS],
}

impl Default for CpuMask {
    fn default() -> Self {
        Self::empty()
    }
}

impl CpuMask {
    /// Create an empty (all-zero) mask.
    pub const fn empty() -> Self {
        Self {
            bits: [0u64; MASK_WORDS],
        }
    }

    /// Set bit for CPU `id`.
    pub fn set(&mut self, id: usize) {
        if id < MAX_CPUS {
            self.bits[id / 64] |= 1u64 << (id % 64);
        }
    }

    /// Clear bit for CPU `id`.
    pub fn clear(&mut self, id: usize) {
        if id < MAX_CPUS {
            self.bits[id / 64] &= !(1u64 << (id % 64));
        }
    }

    /// Test whether CPU `id` is in the set.
    pub fn test(&self, id: usize) -> bool {
        if id >= MAX_CPUS {
            return false;
        }
        (self.bits[id / 64] >> (id % 64)) & 1 == 1
    }

    /// Return the number of CPUs in the set.
    pub fn count(&self) -> u32 {
        self.bits.iter().map(|w| w.count_ones()).sum()
    }

    /// Compute the intersection of two masks.
    pub fn and(&self, other: &Self) -> Self {
        let mut result = Self::empty();
        for (i, word) in result.bits.iter_mut().enumerate() {
            *word = self.bits[i] & other.bits[i];
        }
        result
    }

    /// Compute the union of two masks.
    pub fn or(&self, other: &Self) -> Self {
        let mut result = Self::empty();
        for (i, word) in result.bits.iter_mut().enumerate() {
            *word = self.bits[i] | other.bits[i];
        }
        result
    }

    /// Return the index of the first set bit, or None.
    pub fn first_set(&self) -> Option<usize> {
        for (i, &word) in self.bits.iter().enumerate() {
            if word != 0 {
                return Some(i * 64 + word.trailing_zeros() as usize);
            }
        }
        None
    }
}

// ══════════════════════════════════════════════════════════════
// CacheType
// ══════════════════════════════════════════════════════════════

/// Type of cache.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u8)]
pub enum CacheType {
    /// Unified (data + instruction).
    #[default]
    Unified = 0,
    /// Instruction cache.
    Instruction = 1,
    /// Data cache.
    Data = 2,
}

// ══════════════════════════════════════════════════════════════
// CacheShareInfo
// ══════════════════════════════════════════════════════════════

/// Describes a cache level and which CPUs share it.
#[derive(Debug, Clone, Copy)]
pub struct CacheShareInfo {
    /// Cache descriptor ID (unique across all entries).
    pub cache_id: u32,
    /// Cache hierarchy level (1=L1, 2=L2, 3=L3, etc.).
    pub level: u8,
    /// Cache type (data, instruction, unified).
    pub cache_type: CacheType,
    /// Cache size in kilobytes.
    pub size_kb: u32,
    /// Cache line size in bytes.
    pub line_size: u32,
    /// Associativity (ways).
    pub ways: u32,
    /// Number of sets.
    pub sets: u32,
    /// Bitmask of CPUs sharing this cache.
    pub shared_cpu_mask: CpuMask,
    /// Whether this entry is in use.
    active: bool,
}

impl CacheShareInfo {
    /// Create an empty entry.
    const fn empty() -> Self {
        Self {
            cache_id: 0,
            level: 0,
            cache_type: CacheType::Unified,
            size_kb: 0,
            line_size: 0,
            ways: 0,
            sets: 0,
            shared_cpu_mask: CpuMask::empty(),
            active: false,
        }
    }
}

// ══════════════════════════════════════════════════════════════
// CacheDescriptor — parameter struct for register_cache
// ══════════════════════════════════════════════════════════════

/// Parameters for registering a cache sharing descriptor.
#[derive(Debug, Clone, Copy)]
pub struct CacheDescriptor {
    /// Cache hierarchy level (1=L1, 2=L2, 3=L3, etc.).
    pub level: u8,
    /// Cache type (data, instruction, unified).
    pub cache_type: CacheType,
    /// Cache size in kilobytes.
    pub size_kb: u32,
    /// Cache line size in bytes.
    pub line_size: u32,
    /// Associativity (ways).
    pub ways: u32,
    /// Number of sets.
    pub sets: u32,
    /// Bitmask of CPUs sharing this cache.
    pub shared_cpu_mask: CpuMask,
}

// ══════════════════════════════════════════════════════════════
// CpuTopologyEntry — per-CPU topology record
// ══════════════════════════════════════════════════════════════

/// Topology information for a single logical CPU.
#[derive(Debug, Clone, Copy)]
pub struct CpuTopologyEntry {
    /// Logical CPU ID (0-based, OS-assigned).
    pub logical_id: u32,
    /// Physical package (socket) ID.
    pub package_id: u32,
    /// Physical core ID within the package.
    pub core_id: u32,
    /// SMT thread ID within the core.
    pub thread_id: u32,
    /// Bitmask of sibling threads sharing the same core.
    pub thread_sibling_mask: CpuMask,
    /// Bitmask of CPUs in the same package.
    pub core_sibling_mask: CpuMask,
    /// Cache IDs per level (index 0=L1, 1=L2, ...).
    pub cache_id: [u32; MAX_CACHE_LEVELS],
    /// Whether this CPU is currently online.
    pub online: bool,
    /// Whether this entry is populated.
    active: bool,
}

impl CpuTopologyEntry {
    /// Create an empty entry.
    const fn empty() -> Self {
        Self {
            logical_id: 0,
            package_id: 0,
            core_id: 0,
            thread_id: 0,
            thread_sibling_mask: CpuMask::empty(),
            core_sibling_mask: CpuMask::empty(),
            cache_id: [0u32; MAX_CACHE_LEVELS],
            online: false,
            active: false,
        }
    }
}

// ══════════════════════════════════════════════════════════════
// PackageInfo — per-socket summary
// ══════════════════════════════════════════════════════════════

/// Summary information for a physical CPU package (socket).
#[derive(Debug, Clone, Copy)]
pub struct PackageInfo {
    /// Package (socket) ID.
    pub package_id: u32,
    /// Number of physical cores in this package.
    pub core_count: u32,
    /// Number of logical threads (including SMT).
    pub thread_count: u32,
    /// Bitmask of logical CPUs in this package.
    pub cpu_mask: CpuMask,
    /// Whether this entry is populated.
    active: bool,
}

impl PackageInfo {
    /// Create an empty entry.
    const fn empty() -> Self {
        Self {
            package_id: 0,
            core_count: 0,
            thread_count: 0,
            cpu_mask: CpuMask::empty(),
            active: false,
        }
    }
}

// ══════════════════════════════════════════════════════════════
// TopologyStats
// ══════════════════════════════════════════════════════════════

/// Summary statistics for the discovered topology.
#[derive(Debug, Clone, Copy, Default)]
pub struct TopologyStats {
    /// Total logical CPUs registered.
    pub total_cpus: u32,
    /// Total online CPUs.
    pub online_cpus: u32,
    /// Total physical packages.
    pub total_packages: u32,
    /// Total cache descriptors.
    pub total_caches: u32,
    /// Maximum SMT threads per core observed.
    pub max_smt_threads: u32,
}

// ══════════════════════════════════════════════════════════════
// CpuTopologyMap — the main data structure
// ══════════════════════════════════════════════════════════════

/// Complete CPU topology map of the system.
pub struct CpuTopologyMap {
    /// Per-CPU topology entries.
    cpus: [CpuTopologyEntry; MAX_CPUS],
    /// Per-package summary.
    packages: [PackageInfo; MAX_PACKAGES],
    /// Cache sharing descriptors.
    caches: [CacheShareInfo; MAX_CACHE_ENTRIES],
    /// Next cache ID to assign.
    next_cache_id: u32,
    /// Accumulated statistics.
    stats: TopologyStats,
}

impl Default for CpuTopologyMap {
    fn default() -> Self {
        Self::new()
    }
}

impl CpuTopologyMap {
    /// Create an empty topology map.
    pub const fn new() -> Self {
        Self {
            cpus: [const { CpuTopologyEntry::empty() }; MAX_CPUS],
            packages: [const { PackageInfo::empty() }; MAX_PACKAGES],
            caches: [const { CacheShareInfo::empty() }; MAX_CACHE_ENTRIES],
            next_cache_id: 1,
            stats: TopologyStats {
                total_cpus: 0,
                online_cpus: 0,
                total_packages: 0,
                total_caches: 0,
                max_smt_threads: 0,
            },
        }
    }

    /// Return topology statistics.
    pub fn stats(&self) -> &TopologyStats {
        &self.stats
    }

    /// Register a logical CPU in the topology.
    pub fn register_cpu(
        &mut self,
        logical_id: u32,
        package_id: u32,
        core_id: u32,
        thread_id: u32,
    ) -> Result<()> {
        let lid = logical_id as usize;
        if lid >= MAX_CPUS {
            return Err(Error::InvalidArgument);
        }
        if self.cpus[lid].active {
            return Err(Error::AlreadyExists);
        }

        let entry = &mut self.cpus[lid];
        entry.logical_id = logical_id;
        entry.package_id = package_id;
        entry.core_id = core_id;
        entry.thread_id = thread_id;
        entry.online = true;
        entry.active = true;
        entry.thread_sibling_mask.set(lid);
        entry.core_sibling_mask.set(lid);

        self.stats.total_cpus += 1;
        self.stats.online_cpus += 1;

        // Update package info.
        self.ensure_package(package_id, logical_id)?;

        // Update sibling masks for all existing CPUs.
        self.rebuild_sibling_masks(lid);

        // Track max SMT depth.
        if thread_id + 1 > self.stats.max_smt_threads {
            self.stats.max_smt_threads = thread_id + 1;
        }

        Ok(())
    }

    /// Ensure a package entry exists and add the CPU to it.
    fn ensure_package(&mut self, package_id: u32, logical_id: u32) -> Result<()> {
        // Find existing package.
        if let Some(pos) = self
            .packages
            .iter()
            .position(|p| p.active && p.package_id == package_id)
        {
            // Compute core count before taking mutable borrow.
            let core_count = self.count_cores_in_package(package_id);
            let pkg = &mut self.packages[pos];
            pkg.cpu_mask.set(logical_id as usize);
            pkg.thread_count += 1;
            pkg.core_count = core_count;
            return Ok(());
        }

        // Allocate new package.
        let pos = self
            .packages
            .iter()
            .position(|p| !p.active)
            .ok_or(Error::OutOfMemory)?;

        let pkg = &mut self.packages[pos];
        pkg.package_id = package_id;
        pkg.core_count = 1;
        pkg.thread_count = 1;
        pkg.cpu_mask = CpuMask::empty();
        pkg.cpu_mask.set(logical_id as usize);
        pkg.active = true;

        self.stats.total_packages += 1;
        Ok(())
    }

    /// Count unique core_ids among CPUs in a package.
    fn count_cores_in_package(&self, package_id: u32) -> u32 {
        let mut seen = [false; MAX_CPUS];
        let mut count = 0u32;
        for cpu in &self.cpus {
            if cpu.active && cpu.package_id == package_id {
                let cid = cpu.core_id as usize;
                if cid < MAX_CPUS && !seen[cid] {
                    seen[cid] = true;
                    count += 1;
                }
            }
        }
        count
    }

    /// Rebuild thread_sibling_mask and core_sibling_mask for
    /// the CPU at `target_idx` and all related CPUs.
    fn rebuild_sibling_masks(&mut self, target_idx: usize) {
        let target_pkg = self.cpus[target_idx].package_id;
        let target_core = self.cpus[target_idx].core_id;

        for i in 0..MAX_CPUS {
            if !self.cpus[i].active {
                continue;
            }

            // Same package → core siblings.
            if self.cpus[i].package_id == target_pkg {
                self.cpus[i].core_sibling_mask.set(target_idx);
                self.cpus[target_idx].core_sibling_mask.set(i);

                // Same core → thread siblings.
                if self.cpus[i].core_id == target_core {
                    self.cpus[i].thread_sibling_mask.set(target_idx);
                    self.cpus[target_idx].thread_sibling_mask.set(i);
                }
            }
        }
    }

    /// Register a cache sharing descriptor.
    pub fn register_cache(&mut self, desc: &CacheDescriptor) -> Result<u32> {
        let pos = self
            .caches
            .iter()
            .position(|c| !c.active)
            .ok_or(Error::OutOfMemory)?;

        let cid = self.next_cache_id;
        self.next_cache_id += 1;

        let entry = &mut self.caches[pos];
        entry.cache_id = cid;
        entry.level = desc.level;
        entry.cache_type = desc.cache_type;
        entry.size_kb = desc.size_kb;
        entry.line_size = desc.line_size;
        entry.ways = desc.ways;
        entry.sets = desc.sets;
        entry.shared_cpu_mask = desc.shared_cpu_mask;
        entry.active = true;

        self.stats.total_caches += 1;

        // Update cache_id in CPU entries.
        let lvl_idx = (desc.level as usize).saturating_sub(1);
        if lvl_idx < MAX_CACHE_LEVELS {
            for cpu_idx in 0..MAX_CPUS {
                if desc.shared_cpu_mask.test(cpu_idx) && self.cpus[cpu_idx].active {
                    self.cpus[cpu_idx].cache_id[lvl_idx] = cid;
                }
            }
        }

        Ok(cid)
    }

    /// Look up topology for a logical CPU.
    pub fn get_cpu(&self, logical_id: u32) -> Result<&CpuTopologyEntry> {
        let lid = logical_id as usize;
        if lid >= MAX_CPUS {
            return Err(Error::InvalidArgument);
        }
        let entry = &self.cpus[lid];
        if !entry.active {
            return Err(Error::NotFound);
        }
        Ok(entry)
    }

    /// Look up package information.
    pub fn get_package(&self, package_id: u32) -> Result<&PackageInfo> {
        self.packages
            .iter()
            .find(|p| p.active && p.package_id == package_id)
            .ok_or(Error::NotFound)
    }

    /// Look up cache descriptor by cache_id.
    pub fn get_cache(&self, cache_id: u32) -> Result<&CacheShareInfo> {
        self.caches
            .iter()
            .find(|c| c.active && c.cache_id == cache_id)
            .ok_or(Error::NotFound)
    }

    /// Mark a CPU as offline.
    pub fn set_cpu_offline(&mut self, logical_id: u32) -> Result<()> {
        let lid = logical_id as usize;
        if lid >= MAX_CPUS {
            return Err(Error::InvalidArgument);
        }
        let entry = &mut self.cpus[lid];
        if !entry.active {
            return Err(Error::NotFound);
        }
        if !entry.online {
            return Err(Error::AlreadyExists);
        }
        entry.online = false;
        self.stats.online_cpus = self.stats.online_cpus.saturating_sub(1);
        Ok(())
    }

    /// Mark a CPU as online.
    pub fn set_cpu_online(&mut self, logical_id: u32) -> Result<()> {
        let lid = logical_id as usize;
        if lid >= MAX_CPUS {
            return Err(Error::InvalidArgument);
        }
        let entry = &mut self.cpus[lid];
        if !entry.active {
            return Err(Error::NotFound);
        }
        if entry.online {
            return Err(Error::AlreadyExists);
        }
        entry.online = true;
        self.stats.online_cpus += 1;
        Ok(())
    }

    /// Return the CPU mask of all online CPUs.
    pub fn online_mask(&self) -> CpuMask {
        let mut mask = CpuMask::empty();
        for (i, cpu) in self.cpus.iter().enumerate() {
            if cpu.active && cpu.online {
                mask.set(i);
            }
        }
        mask
    }

    /// Check whether two CPUs share a cache at the given level.
    pub fn share_cache(&self, cpu_a: u32, cpu_b: u32, level: u8) -> Result<bool> {
        let lvl_idx = (level as usize).saturating_sub(1);
        if lvl_idx >= MAX_CACHE_LEVELS {
            return Err(Error::InvalidArgument);
        }
        let a = self.get_cpu(cpu_a)?;
        let b = self.get_cpu(cpu_b)?;
        Ok(a.cache_id[lvl_idx] != 0 && a.cache_id[lvl_idx] == b.cache_id[lvl_idx])
    }
}
