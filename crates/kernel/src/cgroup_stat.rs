// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Cgroup statistics aggregation.
//!
//! Provides a centralized framework for collecting, aggregating, and
//! reporting statistics across cgroup hierarchies. Supports per-cgroup
//! resource usage tracking for CPU, memory, I/O, and PID subsystems
//! with hierarchical roll-up.

use oncrix_lib::{Error, Result};

// ── Constants ────────────────────────────────────────────────────────

/// Maximum number of cgroups tracked.
const MAX_CGROUPS: usize = 256;

/// Maximum depth of the cgroup hierarchy.
const MAX_HIERARCHY_DEPTH: usize = 16;

/// Maximum number of stat keys per cgroup.
const MAX_STAT_KEYS: usize = 32;

/// Stat flush interval in milliseconds.
const _STAT_FLUSH_INTERVAL_MS: u64 = 1000;

// ── Types ────────────────────────────────────────────────────────────

/// Identifies a cgroup in the statistics system.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CgroupStatId(u64);

impl CgroupStatId {
    /// Creates a new cgroup stat identifier.
    pub const fn new(id: u64) -> Self {
        Self(id)
    }

    /// Returns the raw identifier.
    pub const fn as_u64(self) -> u64 {
        self.0
    }
}

/// Type of resource being tracked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResourceType {
    /// CPU usage in nanoseconds.
    Cpu,
    /// Memory usage in bytes.
    Memory,
    /// I/O bytes read.
    IoRead,
    /// I/O bytes written.
    IoWrite,
    /// Number of processes.
    Pids,
    /// Network bytes sent.
    NetTx,
    /// Network bytes received.
    NetRx,
}

/// A single statistic key-value pair.
#[derive(Debug, Clone)]
pub struct StatEntry {
    /// Resource type.
    resource: ResourceType,
    /// Current value.
    current: u64,
    /// Peak value observed.
    peak: u64,
    /// Cumulative total.
    cumulative: u64,
    /// Number of updates.
    update_count: u64,
}

impl StatEntry {
    /// Creates a new stat entry.
    pub const fn new(resource: ResourceType) -> Self {
        Self {
            resource,
            current: 0,
            peak: 0,
            cumulative: 0,
            update_count: 0,
        }
    }

    /// Returns the current value.
    pub const fn current(&self) -> u64 {
        self.current
    }

    /// Returns the peak value.
    pub const fn peak(&self) -> u64 {
        self.peak
    }

    /// Returns the resource type.
    pub const fn resource(&self) -> ResourceType {
        self.resource
    }
}

/// Per-cgroup statistics record.
#[derive(Debug)]
pub struct CgroupStatRecord {
    /// Cgroup identifier.
    id: CgroupStatId,
    /// Parent cgroup identifier (0 for root).
    parent_id: CgroupStatId,
    /// Depth in the hierarchy.
    depth: u32,
    /// Stat entries for this cgroup.
    entries: [Option<StatEntry>; MAX_STAT_KEYS],
    /// Number of stat entries.
    entry_count: usize,
    /// Number of child cgroups.
    child_count: u32,
    /// Whether this cgroup is active.
    active: bool,
    /// Last flush timestamp in nanoseconds.
    last_flush_ns: u64,
}

impl CgroupStatRecord {
    /// Creates a new cgroup stat record.
    pub const fn new(id: CgroupStatId, parent_id: CgroupStatId, depth: u32) -> Self {
        Self {
            id,
            parent_id,
            depth,
            entries: [const { None }; MAX_STAT_KEYS],
            entry_count: 0,
            child_count: 0,
            active: true,
            last_flush_ns: 0,
        }
    }

    /// Returns whether this is the root cgroup.
    pub const fn is_root(&self) -> bool {
        self.parent_id.as_u64() == 0
    }

    /// Returns the hierarchy depth.
    pub const fn depth(&self) -> u32 {
        self.depth
    }

    /// Returns whether the cgroup is active.
    pub const fn is_active(&self) -> bool {
        self.active
    }
}

/// Aggregated statistics across a hierarchy subtree.
#[derive(Debug, Clone)]
pub struct AggregatedStats {
    /// Cgroup identifier of the subtree root.
    pub root_id: CgroupStatId,
    /// Total CPU time in nanoseconds.
    pub total_cpu_ns: u64,
    /// Total memory usage in bytes.
    pub total_memory_bytes: u64,
    /// Total I/O read bytes.
    pub total_io_read: u64,
    /// Total I/O write bytes.
    pub total_io_write: u64,
    /// Total number of processes.
    pub total_pids: u64,
    /// Number of cgroups included in aggregation.
    pub cgroup_count: u32,
}

impl Default for AggregatedStats {
    fn default() -> Self {
        Self::new(CgroupStatId::new(0))
    }
}

impl AggregatedStats {
    /// Creates empty aggregated statistics.
    pub const fn new(root_id: CgroupStatId) -> Self {
        Self {
            root_id,
            total_cpu_ns: 0,
            total_memory_bytes: 0,
            total_io_read: 0,
            total_io_write: 0,
            total_pids: 0,
            cgroup_count: 0,
        }
    }
}

/// Central cgroup statistics manager.
#[derive(Debug)]
pub struct CgroupStatManager {
    /// Per-cgroup stat records.
    records: [Option<CgroupStatRecord>; MAX_CGROUPS],
    /// Number of tracked cgroups.
    cgroup_count: usize,
    /// Next identifier to assign.
    next_id: u64,
    /// Total stat updates performed.
    total_updates: u64,
    /// Total flushes performed.
    total_flushes: u64,
}

impl Default for CgroupStatManager {
    fn default() -> Self {
        Self::new()
    }
}

impl CgroupStatManager {
    /// Creates a new cgroup statistics manager.
    pub const fn new() -> Self {
        Self {
            records: [const { None }; MAX_CGROUPS],
            cgroup_count: 0,
            next_id: 1,
            total_updates: 0,
            total_flushes: 0,
        }
    }

    /// Registers a new cgroup for statistics tracking.
    pub fn register_cgroup(&mut self, parent_id: CgroupStatId, depth: u32) -> Result<CgroupStatId> {
        if self.cgroup_count >= MAX_CGROUPS {
            return Err(Error::OutOfMemory);
        }
        if (depth as usize) >= MAX_HIERARCHY_DEPTH {
            return Err(Error::InvalidArgument);
        }
        let id = CgroupStatId::new(self.next_id);
        self.next_id += 1;
        let record = CgroupStatRecord::new(id, parent_id, depth);
        if let Some(slot) = self.records.iter_mut().find(|s| s.is_none()) {
            *slot = Some(record);
            self.cgroup_count += 1;
            // Increment parent's child count.
            if parent_id.as_u64() != 0 {
                if let Some(parent) = self
                    .records
                    .iter_mut()
                    .flatten()
                    .find(|r| r.id == parent_id)
                {
                    parent.child_count += 1;
                }
            }
            Ok(id)
        } else {
            Err(Error::OutOfMemory)
        }
    }

    /// Updates a statistic for a given cgroup.
    pub fn update_stat(
        &mut self,
        cgroup_id: CgroupStatId,
        resource: ResourceType,
        value: u64,
    ) -> Result<()> {
        let record = self
            .records
            .iter_mut()
            .flatten()
            .find(|r| r.id == cgroup_id)
            .ok_or(Error::NotFound)?;
        // Find existing entry or create new one.
        let existing = record.entries.iter_mut().flatten().find(|e| {
            matches!(
                (&e.resource, &resource),
                (ResourceType::Cpu, ResourceType::Cpu)
                    | (ResourceType::Memory, ResourceType::Memory)
                    | (ResourceType::IoRead, ResourceType::IoRead)
                    | (ResourceType::IoWrite, ResourceType::IoWrite)
                    | (ResourceType::Pids, ResourceType::Pids)
                    | (ResourceType::NetTx, ResourceType::NetTx)
                    | (ResourceType::NetRx, ResourceType::NetRx)
            )
        });
        if let Some(entry) = existing {
            entry.current = value;
            if value > entry.peak {
                entry.peak = value;
            }
            entry.cumulative += value;
            entry.update_count += 1;
        } else {
            if record.entry_count >= MAX_STAT_KEYS {
                return Err(Error::OutOfMemory);
            }
            let mut new_entry = StatEntry::new(resource);
            new_entry.current = value;
            new_entry.peak = value;
            new_entry.cumulative = value;
            new_entry.update_count = 1;
            if let Some(slot) = record.entries.iter_mut().find(|s| s.is_none()) {
                *slot = Some(new_entry);
                record.entry_count += 1;
            }
        }
        self.total_updates += 1;
        Ok(())
    }

    /// Reads a stat value for a cgroup and resource type.
    pub fn read_stat(&self, cgroup_id: CgroupStatId, resource: ResourceType) -> Result<u64> {
        let record = self
            .records
            .iter()
            .flatten()
            .find(|r| r.id == cgroup_id)
            .ok_or(Error::NotFound)?;
        let entry = record
            .entries
            .iter()
            .flatten()
            .find(|e| {
                matches!(
                    (&e.resource, &resource),
                    (ResourceType::Cpu, ResourceType::Cpu)
                        | (ResourceType::Memory, ResourceType::Memory)
                        | (ResourceType::IoRead, ResourceType::IoRead)
                        | (ResourceType::IoWrite, ResourceType::IoWrite)
                        | (ResourceType::Pids, ResourceType::Pids)
                        | (ResourceType::NetTx, ResourceType::NetTx)
                        | (ResourceType::NetRx, ResourceType::NetRx)
                )
            })
            .ok_or(Error::NotFound)?;
        Ok(entry.current)
    }

    /// Unregisters a cgroup from statistics tracking.
    pub fn unregister_cgroup(&mut self, cgroup_id: CgroupStatId) -> Result<()> {
        let slot = self
            .records
            .iter_mut()
            .find(|s| s.as_ref().map_or(false, |r| r.id == cgroup_id))
            .ok_or(Error::NotFound)?;
        *slot = None;
        self.cgroup_count -= 1;
        Ok(())
    }

    /// Returns the number of tracked cgroups.
    pub const fn cgroup_count(&self) -> usize {
        self.cgroup_count
    }

    /// Returns the total number of stat updates.
    pub const fn total_updates(&self) -> u64 {
        self.total_updates
    }
}
