// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Cpuset partition management.
//!
//! Manages CPU and memory node partitions within the cpuset cgroup
//! controller. Supports exclusive partitions where CPUs are dedicated
//! to specific cgroups, preventing other tasks from using them.
//! Implements the partition root and member hierarchy.

use oncrix_lib::{Error, Result};

// ── Constants ────────────────────────────────────────────────────────

/// Maximum number of cpuset partitions.
const MAX_PARTITIONS: usize = 64;

/// Maximum CPUs in the system.
const MAX_CPUS: usize = 128;

/// Maximum memory nodes.
const MAX_MEM_NODES: usize = 16;

/// CPU mask array size (128 CPUs / 64 bits per word).
const CPU_MASK_WORDS: usize = (MAX_CPUS + 63) / 64;

// ── Types ────────────────────────────────────────────────────────────

/// Partition type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PartitionType {
    /// Member partition (shares CPUs with parent).
    Member,
    /// Root partition (owns CPUs exclusively).
    Root,
    /// Isolated root (no load balancing within).
    IsolatedRoot,
    /// Invalid partition state.
    Invalid,
}

impl Default for PartitionType {
    fn default() -> Self {
        Self::Member
    }
}

/// Identifies a cpuset partition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PartitionId(u32);

impl PartitionId {
    /// Creates a new partition identifier.
    pub const fn new(id: u32) -> Self {
        Self(id)
    }

    /// Returns the raw identifier.
    pub const fn as_u32(self) -> u32 {
        self.0
    }
}

/// CPU bitmask for partition assignment.
#[derive(Debug, Clone)]
pub struct CpuMask {
    /// Bitmask words.
    bits: [u64; CPU_MASK_WORDS],
}

impl CpuMask {
    /// Creates an empty CPU mask.
    pub const fn new() -> Self {
        Self {
            bits: [0u64; CPU_MASK_WORDS],
        }
    }

    /// Sets a CPU in the mask.
    pub fn set(&mut self, cpu: u32) -> Result<()> {
        let idx = (cpu as usize) / 64;
        let bit = (cpu as usize) % 64;
        if idx >= CPU_MASK_WORDS {
            return Err(Error::InvalidArgument);
        }
        self.bits[idx] |= 1u64 << bit;
        Ok(())
    }

    /// Clears a CPU from the mask.
    pub fn clear(&mut self, cpu: u32) -> Result<()> {
        let idx = (cpu as usize) / 64;
        let bit = (cpu as usize) % 64;
        if idx >= CPU_MASK_WORDS {
            return Err(Error::InvalidArgument);
        }
        self.bits[idx] &= !(1u64 << bit);
        Ok(())
    }

    /// Tests whether a CPU is in the mask.
    pub fn test(&self, cpu: u32) -> bool {
        let idx = (cpu as usize) / 64;
        let bit = (cpu as usize) % 64;
        if idx >= CPU_MASK_WORDS {
            return false;
        }
        self.bits[idx] & (1u64 << bit) != 0
    }

    /// Counts the number of CPUs in the mask.
    pub fn count(&self) -> u32 {
        self.bits.iter().map(|w| w.count_ones()).sum()
    }

    /// Returns whether the mask is empty.
    pub fn is_empty(&self) -> bool {
        self.bits.iter().all(|&w| w == 0)
    }
}

impl Default for CpuMask {
    fn default() -> Self {
        Self::new()
    }
}

/// A cpuset partition definition.
#[derive(Debug)]
pub struct CpusetPartition {
    /// Partition identifier.
    id: PartitionId,
    /// Parent partition identifier.
    parent_id: PartitionId,
    /// Partition type.
    partition_type: PartitionType,
    /// CPUs assigned to this partition.
    cpu_mask: CpuMask,
    /// Effective CPUs (after parent constraints).
    effective_cpus: CpuMask,
    /// Memory nodes assigned.
    mem_nodes: [bool; MAX_MEM_NODES],
    /// Whether CPU exclusivity is enforced.
    cpu_exclusive: bool,
    /// Whether memory exclusivity is enforced.
    mem_exclusive: bool,
    /// Number of child partitions.
    child_count: u32,
    /// Whether this partition is active.
    active: bool,
}

impl CpusetPartition {
    /// Creates a new cpuset partition.
    pub const fn new(
        id: PartitionId,
        parent_id: PartitionId,
        partition_type: PartitionType,
    ) -> Self {
        Self {
            id,
            parent_id,
            partition_type,
            cpu_mask: CpuMask::new(),
            effective_cpus: CpuMask::new(),
            mem_nodes: [false; MAX_MEM_NODES],
            cpu_exclusive: false,
            mem_exclusive: false,
            child_count: 0,
            active: true,
        }
    }

    /// Returns the partition type.
    pub const fn partition_type(&self) -> PartitionType {
        self.partition_type
    }

    /// Returns whether CPU exclusivity is enforced.
    pub const fn is_cpu_exclusive(&self) -> bool {
        self.cpu_exclusive
    }

    /// Returns whether the partition is active.
    pub const fn is_active(&self) -> bool {
        self.active
    }
}

/// Cpuset partition statistics.
#[derive(Debug, Clone)]
pub struct CpusetPartitionStats {
    /// Total partitions.
    pub total_partitions: u32,
    /// Root partitions.
    pub root_partitions: u32,
    /// Member partitions.
    pub member_partitions: u32,
    /// Total CPUs allocated to partitions.
    pub total_allocated_cpus: u32,
    /// CPUs in exclusive use.
    pub exclusive_cpus: u32,
}

impl Default for CpusetPartitionStats {
    fn default() -> Self {
        Self::new()
    }
}

impl CpusetPartitionStats {
    /// Creates zeroed statistics.
    pub const fn new() -> Self {
        Self {
            total_partitions: 0,
            root_partitions: 0,
            member_partitions: 0,
            total_allocated_cpus: 0,
            exclusive_cpus: 0,
        }
    }
}

/// Central cpuset partition manager.
#[derive(Debug)]
pub struct CpusetPartitionManager {
    /// Partitions.
    partitions: [Option<CpusetPartition>; MAX_PARTITIONS],
    /// Number of partitions.
    partition_count: usize,
    /// Next partition identifier.
    next_id: u32,
    /// Global CPU mask (all available CPUs).
    global_cpus: CpuMask,
}

impl Default for CpusetPartitionManager {
    fn default() -> Self {
        Self::new()
    }
}

impl CpusetPartitionManager {
    /// Creates a new cpuset partition manager.
    pub const fn new() -> Self {
        Self {
            partitions: [const { None }; MAX_PARTITIONS],
            partition_count: 0,
            next_id: 1,
            global_cpus: CpuMask::new(),
        }
    }

    /// Creates a new partition.
    pub fn create_partition(
        &mut self,
        parent_id: PartitionId,
        partition_type: PartitionType,
    ) -> Result<PartitionId> {
        if self.partition_count >= MAX_PARTITIONS {
            return Err(Error::OutOfMemory);
        }
        let id = PartitionId::new(self.next_id);
        self.next_id += 1;
        let partition = CpusetPartition::new(id, parent_id, partition_type);
        if let Some(slot) = self.partitions.iter_mut().find(|s| s.is_none()) {
            *slot = Some(partition);
            self.partition_count += 1;
            Ok(id)
        } else {
            Err(Error::OutOfMemory)
        }
    }

    /// Assigns CPUs to a partition.
    pub fn assign_cpus(&mut self, partition_id: PartitionId, cpus: &[u32]) -> Result<()> {
        let part = self
            .partitions
            .iter_mut()
            .flatten()
            .find(|p| p.id == partition_id)
            .ok_or(Error::NotFound)?;
        for &cpu in cpus {
            part.cpu_mask.set(cpu)?;
            part.effective_cpus.set(cpu)?;
        }
        Ok(())
    }

    /// Sets CPU exclusivity for a partition.
    pub fn set_cpu_exclusive(&mut self, partition_id: PartitionId, exclusive: bool) -> Result<()> {
        let part = self
            .partitions
            .iter_mut()
            .flatten()
            .find(|p| p.id == partition_id)
            .ok_or(Error::NotFound)?;
        part.cpu_exclusive = exclusive;
        Ok(())
    }

    /// Assigns memory nodes to a partition.
    pub fn assign_mem_nodes(&mut self, partition_id: PartitionId, nodes: &[usize]) -> Result<()> {
        let part = self
            .partitions
            .iter_mut()
            .flatten()
            .find(|p| p.id == partition_id)
            .ok_or(Error::NotFound)?;
        for &node in nodes {
            if node >= MAX_MEM_NODES {
                return Err(Error::InvalidArgument);
            }
            part.mem_nodes[node] = true;
        }
        Ok(())
    }

    /// Removes a partition.
    pub fn remove_partition(&mut self, partition_id: PartitionId) -> Result<()> {
        let slot = self
            .partitions
            .iter_mut()
            .find(|s| s.as_ref().map_or(false, |p| p.id == partition_id))
            .ok_or(Error::NotFound)?;
        *slot = None;
        self.partition_count -= 1;
        Ok(())
    }

    /// Sets the global available CPU mask.
    pub fn set_global_cpus(&mut self, cpus: &[u32]) -> Result<()> {
        self.global_cpus = CpuMask::new();
        for &cpu in cpus {
            self.global_cpus.set(cpu)?;
        }
        Ok(())
    }

    /// Returns partition statistics.
    pub fn stats(&self) -> CpusetPartitionStats {
        let mut s = CpusetPartitionStats::new();
        for part in self.partitions.iter().flatten() {
            s.total_partitions += 1;
            match part.partition_type {
                PartitionType::Root | PartitionType::IsolatedRoot => {
                    s.root_partitions += 1;
                }
                PartitionType::Member => {
                    s.member_partitions += 1;
                }
                _ => {}
            }
            s.total_allocated_cpus += part.cpu_mask.count();
            if part.cpu_exclusive {
                s.exclusive_cpus += part.cpu_mask.count();
            }
        }
        s
    }

    /// Returns the number of partitions.
    pub const fn partition_count(&self) -> usize {
        self.partition_count
    }
}
