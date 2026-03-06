// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Scheduler group management — hierarchical CPU grouping for load balancing.
//!
//! Scheduler groups represent sets of CPUs that share scheduling domains.
//! The scheduler uses groups to balance load across NUMA nodes, LLC
//! clusters, and physical cores.
//!
//! # Architecture
//!
//! ```text
//! ┌──────────────────────────────────────────────────────────────┐
//! │                   SchedGroupSubsystem                        │
//! │                                                              │
//! │  SchedGroup[0..MAX_GROUPS]  (CPU groups)                     │
//! │  ┌────────────────────────────────────────────────────────┐  │
//! │  │  group_id: u16                                         │  │
//! │  │  cpu_mask: u64                                         │  │
//! │  │  group_type: SchedGroupType                            │  │
//! │  │  capacity: u32                                         │  │
//! │  │  load: u64                                             │  │
//! │  └────────────────────────────────────────────────────────┘  │
//! │                                                              │
//! │  GroupCapacity[0..MAX_GROUPS]  (cached capacity info)         │
//! └──────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Reference
//!
//! Linux `kernel/sched/topology.c`, `include/linux/sched/topology.h`.

use oncrix_lib::{Error, Result};

// ══════════════════════════════════════════════════════════════
// Constants
// ══════════════════════════════════════════════════════════════

/// Maximum scheduler groups.
const MAX_GROUPS: usize = 128;

/// Maximum CPUs per group (bitmask width).
const _MAX_CPUS: usize = 64;

/// Default group capacity (1024 = one full CPU).
const SCHED_CAPACITY_SCALE: u32 = 1024;

// ══════════════════════════════════════════════════════════════
// SchedGroupType
// ══════════════════════════════════════════════════════════════

/// Type of scheduler group.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SchedGroupType {
    /// SMT siblings (hyperthreads on the same core).
    Smt = 0,
    /// Physical cores sharing an LLC.
    Cluster = 1,
    /// All cores on the same die/package.
    Die = 2,
    /// NUMA node group.
    Numa = 3,
    /// System-wide group.
    System = 4,
}

impl SchedGroupType {
    /// Display name.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Smt => "smt",
            Self::Cluster => "cluster",
            Self::Die => "die",
            Self::Numa => "numa",
            Self::System => "system",
        }
    }
}

// ══════════════════════════════════════════════════════════════
// GroupFlags
// ══════════════════════════════════════════════════════════════

/// Flags indicating group state for load balancing decisions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum GroupFlags {
    /// Group is idle (all CPUs idle).
    Idle = 0,
    /// Group has spare capacity.
    HasSpare = 1,
    /// Group is fully busy.
    FullyBusy = 2,
    /// Group is overloaded.
    Overloaded = 3,
    /// Group is imbalanced.
    Imbalanced = 4,
    /// Group has misfit tasks.
    Misfit = 5,
}

// ══════════════════════════════════════════════════════════════
// SchedGroup
// ══════════════════════════════════════════════════════════════

/// A scheduler group of CPUs.
#[derive(Debug, Clone, Copy)]
pub struct SchedGroup {
    /// Group identifier.
    pub group_id: u16,
    /// Bitmask of CPUs in this group.
    pub cpu_mask: u64,
    /// Group type (topology level).
    pub group_type: SchedGroupType,
    /// Total compute capacity (sum of per-CPU capacities).
    pub capacity: u32,
    /// Current load (sum of per-CPU loads).
    pub load: u64,
    /// Number of runnable tasks.
    pub nr_running: u32,
    /// Group flags for balancing.
    pub flags: GroupFlags,
    /// Whether the group is registered.
    pub registered: bool,
    /// Parent group ID (0 = root).
    pub parent_id: u16,
}

impl SchedGroup {
    /// Create an empty group.
    const fn empty() -> Self {
        Self {
            group_id: 0,
            cpu_mask: 0,
            group_type: SchedGroupType::System,
            capacity: 0,
            load: 0,
            nr_running: 0,
            flags: GroupFlags::Idle,
            registered: false,
            parent_id: 0,
        }
    }

    /// Return the number of CPUs in this group.
    pub fn cpu_count(&self) -> u32 {
        self.cpu_mask.count_ones()
    }

    /// Check if a CPU is in this group.
    pub const fn has_cpu(&self, cpu: usize) -> bool {
        (cpu < 64) && ((self.cpu_mask >> cpu) & 1) != 0
    }
}

// ══════════════════════════════════════════════════════════════
// GroupCapacity
// ══════════════════════════════════════════════════════════════

/// Cached capacity information for a group.
#[derive(Debug, Clone, Copy)]
pub struct GroupCapacity {
    /// Total capacity.
    pub capacity: u32,
    /// Minimum per-CPU capacity in the group.
    pub min_capacity: u32,
    /// Maximum per-CPU capacity in the group.
    pub max_capacity: u32,
    /// Number of idle CPUs.
    pub idle_cpus: u32,
}

impl GroupCapacity {
    const fn empty() -> Self {
        Self {
            capacity: 0,
            min_capacity: 0,
            max_capacity: 0,
            idle_cpus: 0,
        }
    }
}

// ══════════════════════════════════════════════════════════════
// SchedGroupStats
// ══════════════════════════════════════════════════════════════

/// Statistics for the scheduler group subsystem.
#[derive(Debug, Clone, Copy)]
pub struct SchedGroupStats {
    /// Total load balance iterations.
    pub total_balance_iterations: u64,
    /// Total tasks migrated between groups.
    pub total_migrations: u64,
    /// Total capacity updates.
    pub total_capacity_updates: u64,
    /// Total group overload events.
    pub total_overloads: u64,
}

impl SchedGroupStats {
    const fn new() -> Self {
        Self {
            total_balance_iterations: 0,
            total_migrations: 0,
            total_capacity_updates: 0,
            total_overloads: 0,
        }
    }
}

// ══════════════════════════════════════════════════════════════
// SchedGroupSubsystem
// ══════════════════════════════════════════════════════════════

/// Top-level scheduler group subsystem.
pub struct SchedGroupSubsystem {
    /// Registered groups.
    groups: [SchedGroup; MAX_GROUPS],
    /// Cached capacity per group.
    capacities: [GroupCapacity; MAX_GROUPS],
    /// Statistics.
    stats: SchedGroupStats,
    /// Next group ID.
    next_group_id: u16,
    /// Whether the subsystem is initialised.
    initialised: bool,
}

impl Default for SchedGroupSubsystem {
    fn default() -> Self {
        Self::new()
    }
}

impl SchedGroupSubsystem {
    /// Create a new scheduler group subsystem.
    pub const fn new() -> Self {
        Self {
            groups: [const { SchedGroup::empty() }; MAX_GROUPS],
            capacities: [const { GroupCapacity::empty() }; MAX_GROUPS],
            stats: SchedGroupStats::new(),
            next_group_id: 1,
            initialised: false,
        }
    }

    /// Initialise the subsystem.
    pub fn init(&mut self) -> Result<()> {
        if self.initialised {
            return Err(Error::AlreadyExists);
        }
        self.initialised = true;
        Ok(())
    }

    // ── Group management ─────────────────────────────────────

    /// Register a new scheduler group.
    ///
    /// Returns the group slot index.
    pub fn register(
        &mut self,
        cpu_mask: u64,
        group_type: SchedGroupType,
        parent_id: u16,
    ) -> Result<usize> {
        if cpu_mask == 0 {
            return Err(Error::InvalidArgument);
        }

        let slot = self
            .groups
            .iter()
            .position(|g| !g.registered)
            .ok_or(Error::OutOfMemory)?;

        let group_id = self.next_group_id;
        self.next_group_id += 1;

        let cpu_count = cpu_mask.count_ones();

        self.groups[slot] = SchedGroup {
            group_id,
            cpu_mask,
            group_type,
            capacity: cpu_count * SCHED_CAPACITY_SCALE,
            load: 0,
            nr_running: 0,
            flags: GroupFlags::Idle,
            registered: true,
            parent_id,
        };

        self.capacities[slot] = GroupCapacity {
            capacity: cpu_count * SCHED_CAPACITY_SCALE,
            min_capacity: SCHED_CAPACITY_SCALE,
            max_capacity: SCHED_CAPACITY_SCALE,
            idle_cpus: cpu_count,
        };

        Ok(slot)
    }

    /// Unregister a group.
    pub fn unregister(&mut self, slot: usize) -> Result<()> {
        if slot >= MAX_GROUPS || !self.groups[slot].registered {
            return Err(Error::NotFound);
        }
        self.groups[slot] = SchedGroup::empty();
        self.capacities[slot] = GroupCapacity::empty();
        Ok(())
    }

    // ── Load updates ─────────────────────────────────────────

    /// Update the load and runnable count for a group.
    pub fn update_load(&mut self, slot: usize, load: u64, nr_running: u32) -> Result<()> {
        if slot >= MAX_GROUPS || !self.groups[slot].registered {
            return Err(Error::InvalidArgument);
        }

        self.groups[slot].load = load;
        self.groups[slot].nr_running = nr_running;

        // Update flags based on load.
        let cap = self.groups[slot].capacity as u64;
        self.groups[slot].flags = if nr_running == 0 {
            GroupFlags::Idle
        } else if load > cap {
            self.stats.total_overloads += 1;
            GroupFlags::Overloaded
        } else if load > cap * 80 / 100 {
            GroupFlags::FullyBusy
        } else {
            GroupFlags::HasSpare
        };

        Ok(())
    }

    /// Update capacity for a group.
    pub fn update_capacity(&mut self, slot: usize, capacity: u32) -> Result<()> {
        if slot >= MAX_GROUPS || !self.groups[slot].registered {
            return Err(Error::InvalidArgument);
        }
        self.groups[slot].capacity = capacity;
        self.capacities[slot].capacity = capacity;
        self.stats.total_capacity_updates += 1;
        Ok(())
    }

    /// Record a migration between groups.
    pub fn record_migration(&mut self) {
        self.stats.total_migrations += 1;
    }

    /// Record a load balance iteration.
    pub fn record_balance_iteration(&mut self) {
        self.stats.total_balance_iterations += 1;
    }

    // ── Query ────────────────────────────────────────────────

    /// Return a group by slot.
    pub fn group(&self, slot: usize) -> Result<&SchedGroup> {
        if slot >= MAX_GROUPS || !self.groups[slot].registered {
            return Err(Error::NotFound);
        }
        Ok(&self.groups[slot])
    }

    /// Return cached capacity for a group.
    pub fn capacity(&self, slot: usize) -> Result<&GroupCapacity> {
        if slot >= MAX_GROUPS || !self.groups[slot].registered {
            return Err(Error::NotFound);
        }
        Ok(&self.capacities[slot])
    }

    /// Return statistics.
    pub fn stats(&self) -> SchedGroupStats {
        self.stats
    }

    /// Return the number of registered groups.
    pub fn group_count(&self) -> usize {
        self.groups.iter().filter(|g| g.registered).count()
    }

    /// Find the busiest group of a given type.
    pub fn find_busiest(&self, group_type: SchedGroupType) -> Option<usize> {
        let mut busiest_slot = None;
        let mut max_load = 0u64;
        for (i, grp) in self.groups.iter().enumerate() {
            if grp.registered && grp.group_type as u8 == group_type as u8 && grp.load > max_load {
                max_load = grp.load;
                busiest_slot = Some(i);
            }
        }
        busiest_slot
    }
}
