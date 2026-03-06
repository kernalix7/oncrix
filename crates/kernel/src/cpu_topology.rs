// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! CPU topology discovery and modelling.
//!
//! Represents the hierarchical structure of the processor complex:
//! physical packages (sockets), cores, logical threads (SMT),
//! cache levels, and NUMA distances.  The scheduler uses this
//! information for topology-aware task placement.
//!
//! # Architecture
//!
//! ```text
//! CpuTopology
//!  +-- packages: [Package; MAX_PACKAGES]
//!  |    +-- id, core_count, thread_count, online
//!  |    +-- core_ids[MAX_CORES_PER_PKG]
//!  +-- cores: [CoreInfo; MAX_CORES]
//!  |    +-- core_id, package_id, thread_ids, cache_ids
//!  |    +-- frequency_khz, online
//!  +-- caches: [CacheDesc; MAX_CACHES]
//!  |    +-- level, cache_type, size_kb, line_size
//!  |    +-- ways, shared_mask
//!  +-- nodes: [NumaNode; MAX_NODES]
//!       +-- node_id, package_ids, distance_map
//! ```
//!
//! On x86_64 the topology is populated from CPUID leaves 0x0B
//! and 0x04.  On AArch64 it comes from DT or ACPI PPTT.  This
//! module provides the data model; architecture code calls the
//! registration APIs.
//!
//! Reference: Linux `drivers/base/topology.c`,
//! `arch/x86/kernel/cpu/topology.c`.

use oncrix_lib::{Error, Result};

// ── Constants ──────────────────────────────────────────────────────

/// Maximum physical packages (sockets).
const MAX_PACKAGES: usize = 8;

/// Maximum physical cores across all packages.
const MAX_CORES: usize = 256;

/// Maximum logical threads per core (SMT width).
const MAX_THREADS_PER_CORE: usize = 4;

/// Maximum cores per package.
const MAX_CORES_PER_PKG: usize = 128;

/// Maximum cache descriptors.
const MAX_CACHES: usize = 64;

/// Maximum NUMA nodes.
const MAX_NODES: usize = 16;

/// Maximum packages per NUMA node.
const MAX_PKGS_PER_NODE: usize = 8;

/// Local NUMA distance (same node).
const NUMA_DIST_LOCAL: u16 = 10;

/// Remote NUMA distance (default).
const _NUMA_DIST_REMOTE: u16 = 20;

// ── CacheType ──────────────────────────────────────────────────────

/// Type of a CPU cache.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CacheType {
    /// Data cache.
    Data,
    /// Instruction cache.
    Instruction,
    /// Unified (data + instruction) cache.
    Unified,
}

// ── CacheDesc ──────────────────────────────────────────────────────

/// Descriptor for a single cache level.
#[derive(Clone, Copy)]
pub struct CacheDesc {
    /// Cache level (1 = L1, 2 = L2, 3 = L3).
    level: u8,
    /// Cache type.
    cache_type: CacheType,
    /// Size in KiB.
    size_kb: u32,
    /// Cache line size in bytes.
    line_size: u16,
    /// Associativity (ways).
    ways: u16,
    /// Bitmask of logical CPUs sharing this cache.
    shared_mask: u64,
    /// Whether this descriptor slot is occupied.
    occupied: bool,
}

impl CacheDesc {
    /// Creates an empty cache descriptor.
    pub const fn new() -> Self {
        Self {
            level: 0,
            cache_type: CacheType::Unified,
            size_kb: 0,
            line_size: 0,
            ways: 0,
            shared_mask: 0,
            occupied: false,
        }
    }

    /// Returns the cache level.
    pub const fn level(&self) -> u8 {
        self.level
    }

    /// Returns the cache type.
    pub const fn cache_type(&self) -> CacheType {
        self.cache_type
    }

    /// Returns the size in KiB.
    pub const fn size_kb(&self) -> u32 {
        self.size_kb
    }

    /// Returns the line size.
    pub const fn line_size(&self) -> u16 {
        self.line_size
    }

    /// Returns the associativity.
    pub const fn ways(&self) -> u16 {
        self.ways
    }

    /// Returns the shared CPU mask.
    pub const fn shared_mask(&self) -> u64 {
        self.shared_mask
    }
}

// ── CoreInfo ───────────────────────────────────────────────────────

/// Information about a physical core.
#[derive(Clone, Copy)]
pub struct CoreInfo {
    /// Core identifier (unique system-wide).
    core_id: u32,
    /// Parent package identifier.
    package_id: u32,
    /// Logical thread (CPU) ids for this core.
    thread_ids: [u32; MAX_THREADS_PER_CORE],
    /// Number of threads on this core.
    nr_threads: u8,
    /// Current frequency in kHz.
    frequency_khz: u32,
    /// Whether this core is online.
    online: bool,
    /// Whether this slot is occupied.
    occupied: bool,
}

impl CoreInfo {
    /// Creates an empty core slot.
    pub const fn new() -> Self {
        Self {
            core_id: 0,
            package_id: 0,
            thread_ids: [0u32; MAX_THREADS_PER_CORE],
            nr_threads: 0,
            frequency_khz: 0,
            online: false,
            occupied: false,
        }
    }

    /// Returns the core identifier.
    pub const fn core_id(&self) -> u32 {
        self.core_id
    }

    /// Returns the parent package identifier.
    pub const fn package_id(&self) -> u32 {
        self.package_id
    }

    /// Returns the number of threads.
    pub const fn nr_threads(&self) -> u8 {
        self.nr_threads
    }

    /// Returns the frequency in kHz.
    pub const fn frequency_khz(&self) -> u32 {
        self.frequency_khz
    }

    /// Returns whether the core is online.
    pub const fn online(&self) -> bool {
        self.online
    }

    /// Returns the thread ids slice.
    pub fn thread_ids(&self) -> &[u32] {
        &self.thread_ids[..self.nr_threads as usize]
    }
}

// ── Package ────────────────────────────────────────────────────────

/// A physical processor package (socket).
#[derive(Clone, Copy)]
pub struct Package {
    /// Package identifier.
    pkg_id: u32,
    /// Core identifiers belonging to this package.
    core_ids: [u32; MAX_CORES_PER_PKG],
    /// Number of cores.
    nr_cores: u16,
    /// Total logical threads.
    nr_threads: u16,
    /// Whether the package is online.
    online: bool,
    /// Whether this slot is occupied.
    occupied: bool,
}

impl Package {
    /// Creates an empty package slot.
    pub const fn new() -> Self {
        Self {
            pkg_id: 0,
            core_ids: [0u32; MAX_CORES_PER_PKG],
            nr_cores: 0,
            nr_threads: 0,
            online: false,
            occupied: false,
        }
    }

    /// Returns the package identifier.
    pub const fn pkg_id(&self) -> u32 {
        self.pkg_id
    }

    /// Returns the number of cores.
    pub const fn nr_cores(&self) -> u16 {
        self.nr_cores
    }

    /// Returns the total thread count.
    pub const fn nr_threads(&self) -> u16 {
        self.nr_threads
    }

    /// Returns whether the package is online.
    pub const fn online(&self) -> bool {
        self.online
    }
}

// ── NumaNode ───────────────────────────────────────────────────────

/// A NUMA node grouping packages.
#[derive(Clone, Copy)]
pub struct NumaNode {
    /// Node identifier.
    node_id: u32,
    /// Package ids in this node.
    package_ids: [u32; MAX_PKGS_PER_NODE],
    /// Number of packages.
    nr_packages: u8,
    /// Distance to every other node.
    distances: [u16; MAX_NODES],
    /// Whether this slot is occupied.
    occupied: bool,
}

impl NumaNode {
    /// Creates an empty NUMA node.
    pub const fn new() -> Self {
        Self {
            node_id: 0,
            package_ids: [0u32; MAX_PKGS_PER_NODE],
            nr_packages: 0,
            distances: [0u16; MAX_NODES],
            occupied: false,
        }
    }

    /// Returns the node identifier.
    pub const fn node_id(&self) -> u32 {
        self.node_id
    }

    /// Returns the number of packages.
    pub const fn nr_packages(&self) -> u8 {
        self.nr_packages
    }

    /// Returns the distance to another node.
    pub fn distance_to(&self, other_node: u32) -> u16 {
        if (other_node as usize) < MAX_NODES {
            self.distances[other_node as usize]
        } else {
            u16::MAX
        }
    }
}

// ── TopologyStats ──────────────────────────────────────────────────

/// Summary statistics for the CPU topology.
#[derive(Clone, Copy)]
pub struct TopologyStats {
    /// Total packages registered.
    pub nr_packages: u32,
    /// Total cores registered.
    pub nr_cores: u32,
    /// Total logical CPUs (threads).
    pub nr_cpus: u32,
    /// Total NUMA nodes.
    pub nr_nodes: u32,
    /// Total cache descriptors.
    pub nr_caches: u32,
}

impl TopologyStats {
    /// Creates zeroed statistics.
    pub const fn new() -> Self {
        Self {
            nr_packages: 0,
            nr_cores: 0,
            nr_cpus: 0,
            nr_nodes: 0,
            nr_caches: 0,
        }
    }
}

// ── CpuTopology ────────────────────────────────────────────────────

/// System-wide CPU topology database.
pub struct CpuTopology {
    /// Physical packages.
    packages: [Package; MAX_PACKAGES],
    /// Core information.
    cores: [CoreInfo; MAX_CORES],
    /// Cache descriptors.
    caches: [CacheDesc; MAX_CACHES],
    /// NUMA nodes.
    nodes: [NumaNode; MAX_NODES],
    /// Aggregate statistics.
    stats: TopologyStats,
}

impl CpuTopology {
    /// Creates an empty topology.
    pub const fn new() -> Self {
        Self {
            packages: [const { Package::new() }; MAX_PACKAGES],
            cores: [const { CoreInfo::new() }; MAX_CORES],
            caches: [const { CacheDesc::new() }; MAX_CACHES],
            nodes: [const { NumaNode::new() }; MAX_NODES],
            stats: TopologyStats::new(),
        }
    }

    /// Registers a physical package.
    pub fn register_package(&mut self, pkg_id: u32) -> Result<()> {
        if self
            .packages
            .iter()
            .any(|p| p.occupied && p.pkg_id == pkg_id)
        {
            return Err(Error::AlreadyExists);
        }
        let slot = self
            .packages
            .iter()
            .position(|p| !p.occupied)
            .ok_or(Error::OutOfMemory)?;

        self.packages[slot].pkg_id = pkg_id;
        self.packages[slot].online = true;
        self.packages[slot].occupied = true;
        self.stats.nr_packages += 1;
        Ok(())
    }

    /// Registers a physical core.
    pub fn register_core(&mut self, core_id: u32, package_id: u32) -> Result<()> {
        // Validate package exists.
        let pkg_idx = self
            .packages
            .iter()
            .position(|p| p.occupied && p.pkg_id == package_id)
            .ok_or(Error::NotFound)?;

        if self
            .cores
            .iter()
            .any(|c| c.occupied && c.core_id == core_id)
        {
            return Err(Error::AlreadyExists);
        }

        let slot = self
            .cores
            .iter()
            .position(|c| !c.occupied)
            .ok_or(Error::OutOfMemory)?;

        self.cores[slot].core_id = core_id;
        self.cores[slot].package_id = package_id;
        self.cores[slot].online = true;
        self.cores[slot].occupied = true;
        self.stats.nr_cores += 1;

        // Add core to package.
        let pkg = &mut self.packages[pkg_idx];
        let cidx = pkg.nr_cores as usize;
        if cidx < MAX_CORES_PER_PKG {
            pkg.core_ids[cidx] = core_id;
            pkg.nr_cores += 1;
        }
        Ok(())
    }

    /// Registers a logical thread (hardware thread / SMT sibling).
    pub fn register_thread(&mut self, core_id: u32, thread_id: u32) -> Result<()> {
        let core_idx = self
            .cores
            .iter()
            .position(|c| c.occupied && c.core_id == core_id)
            .ok_or(Error::NotFound)?;

        let core = &mut self.cores[core_idx];
        if core.nr_threads as usize >= MAX_THREADS_PER_CORE {
            return Err(Error::OutOfMemory);
        }
        core.thread_ids[core.nr_threads as usize] = thread_id;
        core.nr_threads += 1;
        self.stats.nr_cpus += 1;

        // Update package thread count.
        let pkg_id = core.package_id;
        if let Some(pkg) = self
            .packages
            .iter_mut()
            .find(|p| p.occupied && p.pkg_id == pkg_id)
        {
            pkg.nr_threads += 1;
        }
        Ok(())
    }

    /// Registers a cache descriptor.
    pub fn register_cache(
        &mut self,
        level: u8,
        cache_type: CacheType,
        size_kb: u32,
        line_size: u16,
        ways: u16,
        shared_mask: u64,
    ) -> Result<()> {
        let slot = self
            .caches
            .iter()
            .position(|c| !c.occupied)
            .ok_or(Error::OutOfMemory)?;

        self.caches[slot] = CacheDesc {
            level,
            cache_type,
            size_kb,
            line_size,
            ways,
            shared_mask,
            occupied: true,
        };
        self.stats.nr_caches += 1;
        Ok(())
    }

    /// Registers a NUMA node.
    pub fn register_node(&mut self, node_id: u32) -> Result<()> {
        if self
            .nodes
            .iter()
            .any(|n| n.occupied && n.node_id == node_id)
        {
            return Err(Error::AlreadyExists);
        }
        let slot = self
            .nodes
            .iter()
            .position(|n| !n.occupied)
            .ok_or(Error::OutOfMemory)?;

        self.nodes[slot].node_id = node_id;
        self.nodes[slot].occupied = true;
        // Self-distance is always local.
        if (node_id as usize) < MAX_NODES {
            self.nodes[slot].distances[node_id as usize] = NUMA_DIST_LOCAL;
        }
        self.stats.nr_nodes += 1;
        Ok(())
    }

    /// Assigns a package to a NUMA node.
    pub fn assign_package_to_node(&mut self, node_id: u32, pkg_id: u32) -> Result<()> {
        let nidx = self
            .nodes
            .iter()
            .position(|n| n.occupied && n.node_id == node_id)
            .ok_or(Error::NotFound)?;

        let node = &mut self.nodes[nidx];
        if node.nr_packages as usize >= MAX_PKGS_PER_NODE {
            return Err(Error::OutOfMemory);
        }
        node.package_ids[node.nr_packages as usize] = pkg_id;
        node.nr_packages += 1;
        Ok(())
    }

    /// Sets the NUMA distance between two nodes.
    pub fn set_numa_distance(&mut self, from: u32, to: u32, distance: u16) -> Result<()> {
        let fidx = self
            .nodes
            .iter()
            .position(|n| n.occupied && n.node_id == from)
            .ok_or(Error::NotFound)?;
        let tidx = self
            .nodes
            .iter()
            .position(|n| n.occupied && n.node_id == to)
            .ok_or(Error::NotFound)?;

        if (to as usize) < MAX_NODES {
            self.nodes[fidx].distances[to as usize] = distance;
        }
        if (from as usize) < MAX_NODES {
            self.nodes[tidx].distances[from as usize] = distance;
        }
        Ok(())
    }

    /// Sets the frequency (kHz) of a core.
    pub fn set_core_frequency(&mut self, core_id: u32, freq_khz: u32) -> Result<()> {
        let idx = self
            .cores
            .iter()
            .position(|c| c.occupied && c.core_id == core_id)
            .ok_or(Error::NotFound)?;
        self.cores[idx].frequency_khz = freq_khz;
        Ok(())
    }

    /// Queries whether two logical CPUs share a given cache level.
    pub fn share_cache(&self, cpu_a: u32, cpu_b: u32, level: u8) -> bool {
        for cache in &self.caches {
            if !cache.occupied || cache.level != level {
                continue;
            }
            let mask_a = (cache.shared_mask >> cpu_a as u32) & 1 == 1;
            let mask_b = (cache.shared_mask >> cpu_b as u32) & 1 == 1;
            if mask_a && mask_b {
                return true;
            }
        }
        false
    }

    /// Queries whether two cores are on the same package.
    pub fn same_package(&self, core_a: u32, core_b: u32) -> bool {
        let pkg_a = self
            .cores
            .iter()
            .find(|c| c.occupied && c.core_id == core_a)
            .map(|c| c.package_id);
        let pkg_b = self
            .cores
            .iter()
            .find(|c| c.occupied && c.core_id == core_b)
            .map(|c| c.package_id);
        match (pkg_a, pkg_b) {
            (Some(a), Some(b)) => a == b,
            _ => false,
        }
    }

    /// Returns the NUMA distance between two nodes.
    pub fn numa_distance(&self, from: u32, to: u32) -> Result<u16> {
        let nidx = self
            .nodes
            .iter()
            .position(|n| n.occupied && n.node_id == from)
            .ok_or(Error::NotFound)?;
        Ok(self.nodes[nidx].distance_to(to))
    }

    /// Returns a read-only reference to the topology statistics.
    pub const fn stats(&self) -> &TopologyStats {
        &self.stats
    }
}
