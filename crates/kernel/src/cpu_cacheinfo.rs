// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! CPU cache information and topology subsystem.
//!
//! Provides discovery and management of CPU cache hierarchies
//! including L1 instruction/data, L2 unified, and L3 shared
//! caches. Used by the scheduler for cache-aware task placement
//! and by memory management for cache coloring decisions.

use oncrix_lib::{Error, Result};

/// Maximum number of CPUs supported.
const MAX_CPUS: usize = 256;

/// Maximum cache levels supported (L1, L2, L3, L4).
const MAX_CACHE_LEVELS: usize = 4;

/// Maximum number of cache entries across all CPUs.
const MAX_CACHE_ENTRIES: usize = 1024;

/// Cache type classification.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum CacheType {
    /// Data cache.
    Data,
    /// Instruction cache.
    Instruction,
    /// Unified (data + instruction) cache.
    Unified,
    /// Trace cache.
    Trace,
}

impl CacheType {
    /// Returns a human-readable name for the cache type.
    pub const fn name(&self) -> &'static str {
        match self {
            Self::Data => "Data",
            Self::Instruction => "Instruction",
            Self::Unified => "Unified",
            Self::Trace => "Trace",
        }
    }
}

/// Write-back policy for a cache.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum WritePolicy {
    /// Write-back: writes go to cache, flushed lazily.
    WriteBack,
    /// Write-through: writes go to cache and memory.
    WriteThrough,
    /// Write-allocate: allocate on write miss.
    WriteAllocate,
}

/// Allocation policy for a cache.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum AllocPolicy {
    /// Read-allocate only.
    ReadAllocate,
    /// Write-allocate only.
    WriteAllocate,
    /// Read and write allocate.
    ReadWriteAllocate,
}

/// Describes a single cache level for a CPU.
#[derive(Clone, Copy)]
pub struct CacheInfo {
    /// Cache level (1 = L1, 2 = L2, etc.).
    level: u8,
    /// Cache type.
    cache_type: CacheType,
    /// Total cache size in bytes.
    size_bytes: u64,
    /// Cache line size in bytes.
    line_size: u32,
    /// Number of sets.
    num_sets: u32,
    /// Associativity (ways).
    ways_of_associativity: u32,
    /// Number of CPUs sharing this cache.
    shared_cpu_count: u32,
    /// Write policy.
    write_policy: WritePolicy,
    /// Allocation policy.
    alloc_policy: AllocPolicy,
    /// Whether the cache is inclusive of lower levels.
    inclusive: bool,
    /// Physical line partitions.
    physical_line_partition: u32,
}

impl CacheInfo {
    /// Creates a new cache info entry.
    pub const fn new() -> Self {
        Self {
            level: 0,
            cache_type: CacheType::Unified,
            size_bytes: 0,
            line_size: 0,
            num_sets: 0,
            ways_of_associativity: 0,
            shared_cpu_count: 0,
            write_policy: WritePolicy::WriteBack,
            alloc_policy: AllocPolicy::ReadWriteAllocate,
            inclusive: false,
            physical_line_partition: 1,
        }
    }

    /// Creates a cache info with basic parameters.
    pub const fn with_params(
        level: u8,
        cache_type: CacheType,
        size_bytes: u64,
        line_size: u32,
        ways: u32,
    ) -> Self {
        let num_sets = if line_size > 0 && ways > 0 {
            (size_bytes / (line_size as u64 * ways as u64)) as u32
        } else {
            0
        };
        Self {
            level,
            cache_type,
            size_bytes,
            line_size,
            num_sets,
            ways_of_associativity: ways,
            shared_cpu_count: 1,
            write_policy: WritePolicy::WriteBack,
            alloc_policy: AllocPolicy::ReadWriteAllocate,
            inclusive: false,
            physical_line_partition: 1,
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

    /// Returns the total size in bytes.
    pub const fn size_bytes(&self) -> u64 {
        self.size_bytes
    }

    /// Returns the cache line size in bytes.
    pub const fn line_size(&self) -> u32 {
        self.line_size
    }

    /// Returns the associativity.
    pub const fn ways(&self) -> u32 {
        self.ways_of_associativity
    }

    /// Returns the number of CPUs sharing this cache.
    pub const fn shared_cpu_count(&self) -> u32 {
        self.shared_cpu_count
    }

    /// Sets the number of CPUs sharing this cache.
    pub fn set_shared_cpu_count(&mut self, count: u32) {
        self.shared_cpu_count = count;
    }

    /// Returns whether this cache is inclusive.
    pub const fn is_inclusive(&self) -> bool {
        self.inclusive
    }
}

impl Default for CacheInfo {
    fn default() -> Self {
        Self::new()
    }
}

/// Per-CPU cache topology information.
#[derive(Clone, Copy)]
pub struct CpuCacheTopology {
    /// CPU identifier.
    cpu_id: u32,
    /// Cache info per level.
    levels: [CacheInfo; MAX_CACHE_LEVELS],
    /// Number of valid cache levels.
    num_levels: u8,
}

impl CpuCacheTopology {
    /// Creates a new CPU cache topology entry.
    pub const fn new() -> Self {
        Self {
            cpu_id: 0,
            levels: [const { CacheInfo::new() }; MAX_CACHE_LEVELS],
            num_levels: 0,
        }
    }

    /// Returns the CPU identifier.
    pub const fn cpu_id(&self) -> u32 {
        self.cpu_id
    }

    /// Returns the number of cache levels.
    pub const fn num_levels(&self) -> u8 {
        self.num_levels
    }

    /// Returns cache info for a given level (1-based).
    pub fn get_level(&self, level: u8) -> Result<&CacheInfo> {
        if level == 0 || level > self.num_levels {
            return Err(Error::InvalidArgument);
        }
        Ok(&self.levels[(level - 1) as usize])
    }

    /// Adds a cache level to this CPU.
    pub fn add_level(&mut self, info: CacheInfo) -> Result<()> {
        if (self.num_levels as usize) >= MAX_CACHE_LEVELS {
            return Err(Error::OutOfMemory);
        }
        self.levels[self.num_levels as usize] = info;
        self.num_levels += 1;
        Ok(())
    }

    /// Returns the total cache size across all levels.
    pub fn total_cache_size(&self) -> u64 {
        let mut total = 0u64;
        for i in 0..self.num_levels as usize {
            total += self.levels[i].size_bytes;
        }
        total
    }
}

impl Default for CpuCacheTopology {
    fn default() -> Self {
        Self::new()
    }
}

/// System-wide cache information manager.
pub struct CacheInfoManager {
    /// Per-CPU cache topology.
    cpus: [CpuCacheTopology; MAX_CPUS],
    /// Number of registered CPUs.
    cpu_count: usize,
    /// Global cache entries for lookup.
    entries: [CacheInfo; MAX_CACHE_ENTRIES],
    /// Number of global entries.
    entry_count: usize,
}

impl CacheInfoManager {
    /// Creates a new cache information manager.
    pub const fn new() -> Self {
        Self {
            cpus: [const { CpuCacheTopology::new() }; MAX_CPUS],
            cpu_count: 0,
            entries: [const { CacheInfo::new() }; MAX_CACHE_ENTRIES],
            entry_count: 0,
        }
    }

    /// Registers a CPU with its cache topology.
    pub fn register_cpu(&mut self, cpu_id: u32, topology: CpuCacheTopology) -> Result<()> {
        if self.cpu_count >= MAX_CPUS {
            return Err(Error::OutOfMemory);
        }
        let mut topo = topology;
        topo.cpu_id = cpu_id;
        self.cpus[self.cpu_count] = topo;
        self.cpu_count += 1;
        Ok(())
    }

    /// Returns cache topology for a given CPU.
    pub fn get_cpu_topology(&self, cpu_id: u32) -> Result<&CpuCacheTopology> {
        self.cpus[..self.cpu_count]
            .iter()
            .find(|c| c.cpu_id == cpu_id)
            .ok_or(Error::NotFound)
    }

    /// Returns the number of registered CPUs.
    pub const fn cpu_count(&self) -> usize {
        self.cpu_count
    }

    /// Checks if two CPUs share a cache at the given level.
    pub fn cpus_share_cache(&self, cpu_a: u32, cpu_b: u32, level: u8) -> Result<bool> {
        let _topo_a = self.get_cpu_topology(cpu_a)?;
        let _topo_b = self.get_cpu_topology(cpu_b)?;
        // In a real implementation, this would check shared
        // cache IDs. For now, CPUs on the same socket share L3.
        if level >= 3 {
            Ok(true)
        } else {
            Ok(cpu_a == cpu_b)
        }
    }

    /// Finds the smallest shared cache level between two CPUs.
    pub fn smallest_shared_level(&self, cpu_a: u32, cpu_b: u32) -> Result<u8> {
        if cpu_a == cpu_b {
            return Ok(1);
        }
        for level in 2..=MAX_CACHE_LEVELS as u8 {
            if self.cpus_share_cache(cpu_a, cpu_b, level)? {
                return Ok(level);
            }
        }
        Err(Error::NotFound)
    }
}

impl Default for CacheInfoManager {
    fn default() -> Self {
        Self::new()
    }
}
