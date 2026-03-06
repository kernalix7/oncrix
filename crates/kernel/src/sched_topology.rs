// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Scheduler topology — CPU domains and groups for load balancing.
//!
//! Models the physical CPU topology (SMT threads, cores, packages,
//! NUMA nodes) as a hierarchy of scheduling domains. The scheduler
//! uses this hierarchy to make load-balancing and wake-affinity
//! decisions that respect cache locality and memory access costs.
//!
//! # Architecture
//!
//! ```text
//! ┌──────────────────────────────────────────────────────────────────┐
//! │                    SchedTopology                                  │
//! │                                                                  │
//! │  ┌──────────────────────────────────────────────┐                │
//! │  │  NUMA Domain (level 3)                       │                │
//! │  │  span: all CPUs in the node                  │                │
//! │  │  ┌──────────────────────────────────────┐    │                │
//! │  │  │  MC Domain (level 2)                 │    │                │
//! │  │  │  span: CPUs sharing L3 cache         │    │                │
//! │  │  │  ┌──────────────────────────────┐    │    │                │
//! │  │  │  │  SMT Domain (level 1)        │    │    │                │
//! │  │  │  │  span: sibling HW threads    │    │    │                │
//! │  │  │  │  SchedGroup → capacity, load │    │    │                │
//! │  │  │  └──────────────────────────────┘    │    │                │
//! │  │  └──────────────────────────────────────┘    │                │
//! │  └──────────────────────────────────────────────┘                │
//! │                                                                  │
//! │  find_busiest_group() — load balance                             │
//! │  wake_affine() — where to place waking tasks                     │
//! └──────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Domain Levels
//!
//! | Level | Name | Span | Key Property |
//! |-------|------|------|--------------|
//! | 0 | CPU | Single CPU | No domain |
//! | 1 | SMT | Sibling HW threads | Shared L1/L2 |
//! | 2 | MC  | Multi-core (same package) | Shared L3 |
//! | 3 | NUMA | Same NUMA node | Same memory controller |
//! | 4 | NUMA-remote | Cross-node | High latency |
//!
//! # Reference
//!
//! Linux `kernel/sched/topology.c`, `include/linux/sched/topology.h`,
//! `kernel/sched/fair.c` (find_busiest_group, wake_affine).

use oncrix_lib::{Error, Result};

// ── Constants ────────────────────────────────────────────────────────────────

/// Maximum number of CPUs in the system.
const MAX_CPUS: usize = 256;

/// Maximum number of scheduling domains.
const MAX_DOMAINS: usize = 64;

/// Maximum number of scheduling groups per domain.
const MAX_GROUPS_PER_DOMAIN: usize = 16;

/// Maximum number of NUMA nodes.
const MAX_NUMA_NODES: usize = 8;

/// Number of domain levels (SMT, MC, NUMA, NUMA-remote).
const MAX_LEVELS: usize = 5;

/// Maximum CPUs that can be represented in a bitmask word.
const CPUMASK_WORDS: usize = (MAX_CPUS + 63) / 64;

/// Imbalance threshold percentage for load balancing.
const IMBALANCE_THRESHOLD_PCT: u32 = 125;

/// Minimum imbalance to trigger migration.
const MIN_IMBALANCE: u64 = 1;

/// Cache hot threshold (nanoseconds).
const CACHE_HOT_NS: u64 = 2_500_000;

/// Wake-affine threshold (load ratio).
const WAKE_AFFINE_THRESHOLD: u64 = 60;

// ── Scheduling Domain Flags ─────────────────────────────────────────────────

/// Flags controlling scheduler behavior within a domain.
#[derive(Debug, Clone, Copy)]
pub struct DomainFlags(u32);

impl DomainFlags {
    /// Enable load balancing in this domain.
    pub const LOAD_BALANCE: u32 = 1 << 0;
    /// Balance on wake-up paths.
    pub const BALANCE_WAKE: u32 = 1 << 1;
    /// Balance on fork.
    pub const BALANCE_FORK: u32 = 1 << 2;
    /// Balance on exec.
    pub const BALANCE_EXEC: u32 = 1 << 3;
    /// Allow wake affine decisions.
    pub const WAKE_AFFINE: u32 = 1 << 4;
    /// Prefer to keep tasks on this CPU (sharing caches).
    pub const PREFER_LOCAL: u32 = 1 << 5;
    /// Share power domain (frequency scaling).
    pub const SHARE_POWER: u32 = 1 << 6;
    /// Share package-level resources.
    pub const SHARE_PKG: u32 = 1 << 7;
    /// NUMA topology aware.
    pub const NUMA: u32 = 1 << 8;
    /// Overlap allowed (for asymmetric topologies).
    pub const OVERLAP: u32 = 1 << 9;
    /// Consider CPU capacity differences (big.LITTLE).
    pub const ASYM_CPUCAPACITY: u32 = 1 << 10;
    /// Prefer to spread tasks across CPUs in this domain.
    pub const SPREAD: u32 = 1 << 11;

    /// Create flags with the given raw value.
    pub const fn new(raw: u32) -> Self {
        Self(raw)
    }

    /// Check if a flag is set.
    pub fn has(self, flag: u32) -> bool {
        self.0 & flag != 0
    }

    /// Get the raw value.
    pub fn raw(self) -> u32 {
        self.0
    }

    /// Default flags for an SMT domain.
    pub fn default_smt() -> Self {
        Self(
            Self::LOAD_BALANCE
                | Self::BALANCE_WAKE
                | Self::WAKE_AFFINE
                | Self::PREFER_LOCAL
                | Self::SHARE_POWER,
        )
    }

    /// Default flags for an MC (multi-core) domain.
    pub fn default_mc() -> Self {
        Self(
            Self::LOAD_BALANCE
                | Self::BALANCE_WAKE
                | Self::BALANCE_FORK
                | Self::BALANCE_EXEC
                | Self::WAKE_AFFINE
                | Self::SHARE_PKG,
        )
    }

    /// Default flags for a NUMA domain.
    pub fn default_numa() -> Self {
        Self(Self::LOAD_BALANCE | Self::BALANCE_FORK | Self::BALANCE_EXEC | Self::NUMA)
    }
}

// ── CPU Mask ────────────────────────────────────────────────────────────────

/// Bitmask representing a set of CPUs.
#[derive(Debug, Clone, Copy)]
pub struct CpuMask {
    /// Bitmask words (each bit = one CPU).
    bits: [u64; CPUMASK_WORDS],
}

impl CpuMask {
    /// Create an empty CPU mask.
    pub const fn empty() -> Self {
        Self {
            bits: [0u64; CPUMASK_WORDS],
        }
    }

    /// Create a mask with a single CPU set.
    pub fn single(cpu: usize) -> Self {
        let mut mask = Self::empty();
        mask.set(cpu);
        mask
    }

    /// Set a CPU bit.
    pub fn set(&mut self, cpu: usize) {
        if cpu < MAX_CPUS {
            self.bits[cpu / 64] |= 1u64 << (cpu % 64);
        }
    }

    /// Clear a CPU bit.
    pub fn clear(&mut self, cpu: usize) {
        if cpu < MAX_CPUS {
            self.bits[cpu / 64] &= !(1u64 << (cpu % 64));
        }
    }

    /// Test if a CPU is set.
    pub fn test(&self, cpu: usize) -> bool {
        if cpu < MAX_CPUS {
            self.bits[cpu / 64] & (1u64 << (cpu % 64)) != 0
        } else {
            false
        }
    }

    /// Count the number of set CPUs.
    pub fn weight(&self) -> u32 {
        let mut count = 0u32;
        for &word in &self.bits {
            count += word.count_ones();
        }
        count
    }

    /// Check if the mask is empty.
    pub fn is_empty(&self) -> bool {
        self.bits.iter().all(|&w| w == 0)
    }

    /// Compute the intersection with another mask.
    pub fn and(&self, other: &CpuMask) -> CpuMask {
        let mut result = CpuMask::empty();
        for i in 0..CPUMASK_WORDS {
            result.bits[i] = self.bits[i] & other.bits[i];
        }
        result
    }

    /// Compute the union with another mask.
    pub fn or(&self, other: &CpuMask) -> CpuMask {
        let mut result = CpuMask::empty();
        for i in 0..CPUMASK_WORDS {
            result.bits[i] = self.bits[i] | other.bits[i];
        }
        result
    }

    /// Find the first set CPU (lowest numbered).
    pub fn first_set(&self) -> Option<usize> {
        for (i, &word) in self.bits.iter().enumerate() {
            if word != 0 {
                return Some(i * 64 + word.trailing_zeros() as usize);
            }
        }
        None
    }

    /// Check if this mask is a subset of another.
    pub fn is_subset_of(&self, other: &CpuMask) -> bool {
        for i in 0..CPUMASK_WORDS {
            if self.bits[i] & !other.bits[i] != 0 {
                return false;
            }
        }
        true
    }
}

// ── Domain Level ────────────────────────────────────────────────────────────

/// Scheduling domain level in the hierarchy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum DomainLevel {
    /// Single CPU (no domain).
    Cpu = 0,
    /// Simultaneous multi-threading (hyperthreads).
    Smt = 1,
    /// Multi-core (same physical package).
    Mc = 2,
    /// NUMA node.
    Numa = 3,
    /// Cross-NUMA (remote nodes).
    NumaRemote = 4,
}

impl DomainLevel {
    /// Get a human-readable name.
    pub fn name(self) -> &'static str {
        match self {
            Self::Cpu => "CPU",
            Self::Smt => "SMT",
            Self::Mc => "MC",
            Self::Numa => "NUMA",
            Self::NumaRemote => "NUMA-remote",
        }
    }

    /// Get the default flags for this level.
    pub fn default_flags(self) -> DomainFlags {
        match self {
            Self::Cpu => DomainFlags::new(0),
            Self::Smt => DomainFlags::default_smt(),
            Self::Mc => DomainFlags::default_mc(),
            Self::Numa | Self::NumaRemote => DomainFlags::default_numa(),
        }
    }
}

// ── Scheduling Group ────────────────────────────────────────────────────────

/// Group state for load balancing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GroupState {
    /// Group has spare capacity.
    HasSpare,
    /// Group is fully busy.
    FullyBusy,
    /// Group is overloaded (more tasks than capacity).
    Overloaded,
    /// Group is imbalanced (uneven distribution within).
    Imbalanced,
}

/// A scheduling group within a domain.
///
/// Groups represent a cluster of CPUs that are treated as a unit
/// for load balancing decisions. Each group has aggregate capacity
/// and load metrics.
#[derive(Debug, Clone, Copy)]
pub struct SchedGroup {
    /// Whether this group slot is in use.
    pub active: bool,
    /// Group index within the domain.
    pub group_index: u16,
    /// CPUs in this group.
    pub span: CpuMask,
    /// Total compute capacity of the group (sum of CPU capacities).
    pub capacity: u64,
    /// Original (maximum) capacity.
    pub capacity_orig: u64,
    /// Current aggregate load (sum of CPU loads).
    pub load: u64,
    /// Number of running tasks.
    pub nr_running: u32,
    /// Number of idle CPUs.
    pub idle_cpus: u32,
    /// Group state classification.
    pub state: GroupState,
    /// Average load per task.
    pub avg_load_per_task: u64,
    /// Whether this group contains the local CPU.
    pub is_local: bool,
}

impl SchedGroup {
    /// Create an empty scheduling group.
    pub const fn new() -> Self {
        Self {
            active: false,
            group_index: 0,
            span: CpuMask::empty(),
            capacity: 0,
            capacity_orig: 0,
            load: 0,
            nr_running: 0,
            idle_cpus: 0,
            state: GroupState::HasSpare,
            avg_load_per_task: 0,
            is_local: false,
        }
    }

    /// Update the group state classification.
    pub fn update_state(&mut self) {
        let nr_cpus = self.span.weight();
        if nr_cpus == 0 {
            self.state = GroupState::HasSpare;
            return;
        }
        if self.nr_running > nr_cpus {
            self.state = GroupState::Overloaded;
        } else if self.nr_running == nr_cpus {
            self.state = GroupState::FullyBusy;
        } else if self.idle_cpus == 0 && self.nr_running > 0 {
            self.state = GroupState::Imbalanced;
        } else {
            self.state = GroupState::HasSpare;
        }
    }

    /// Compute the load-to-capacity ratio (percentage).
    pub fn load_capacity_ratio(&self) -> u64 {
        if self.capacity == 0 {
            return 0;
        }
        (self.load * 100) / self.capacity
    }

    /// Whether this group has idle capacity.
    pub fn has_idle_capacity(&self) -> bool {
        self.idle_cpus > 0
    }
}

// ── Scheduling Domain ───────────────────────────────────────────────────────

/// Load balance statistics for a domain.
#[derive(Debug, Clone, Copy)]
pub struct DomainBalanceStats {
    /// Total balance attempts.
    pub balance_count: u64,
    /// Successful migrations.
    pub migrations: u64,
    /// Failed balance attempts (no imbalance found).
    pub no_imbalance: u64,
    /// Failed because task was cache-hot.
    pub cache_hot_failures: u64,
    /// Wake-affine decisions made.
    pub wake_affine_count: u64,
    /// Wake-affine decisions that chose the waking CPU.
    pub wake_affine_accepted: u64,
}

impl DomainBalanceStats {
    /// Create zeroed statistics.
    pub const fn new() -> Self {
        Self {
            balance_count: 0,
            migrations: 0,
            no_imbalance: 0,
            cache_hot_failures: 0,
            wake_affine_count: 0,
            wake_affine_accepted: 0,
        }
    }
}

/// A scheduling domain in the topology hierarchy.
pub struct SchedDomain {
    /// Whether this domain slot is in use.
    active: bool,
    /// Domain index.
    domain_id: u16,
    /// Hierarchy level.
    level: DomainLevel,
    /// CPUs spanned by this domain.
    span: CpuMask,
    /// Domain flags.
    flags: DomainFlags,
    /// Groups within this domain.
    groups: [SchedGroup; MAX_GROUPS_PER_DOMAIN],
    /// Number of active groups.
    group_count: usize,
    /// Parent domain index (higher level), or u16::MAX if none.
    parent: u16,
    /// Child domain index (lower level), or u16::MAX if none.
    child: u16,
    /// Balance interval (in ticks).
    balance_interval: u32,
    /// Minimum balance interval.
    min_interval: u32,
    /// Maximum balance interval.
    max_interval: u32,
    /// Load decay factor (percentage, 0-100).
    decay_factor: u32,
    /// Number of balance failures before interval increase.
    busy_factor: u32,
    /// Cache-hot threshold (nanoseconds).
    cache_nice_tries: u32,
    /// Balance statistics.
    stats: DomainBalanceStats,
}

impl SchedDomain {
    /// Create a new scheduling domain.
    pub const fn new() -> Self {
        Self {
            active: false,
            domain_id: 0,
            level: DomainLevel::Cpu,
            span: CpuMask::empty(),
            flags: DomainFlags::new(0),
            groups: [const { SchedGroup::new() }; MAX_GROUPS_PER_DOMAIN],
            group_count: 0,
            parent: u16::MAX,
            child: u16::MAX,
            balance_interval: 1,
            min_interval: 1,
            max_interval: 64,
            decay_factor: 80,
            busy_factor: 32,
            cache_nice_tries: 2,
            stats: DomainBalanceStats::new(),
        }
    }

    /// Get the domain level.
    pub fn level(&self) -> DomainLevel {
        self.level
    }

    /// Get the CPU span.
    pub fn span(&self) -> &CpuMask {
        &self.span
    }

    /// Get the domain flags.
    pub fn flags(&self) -> DomainFlags {
        self.flags
    }

    /// Get the number of groups.
    pub fn group_count(&self) -> usize {
        self.group_count
    }

    /// Get a reference to a group.
    pub fn get_group(&self, idx: usize) -> Option<&SchedGroup> {
        if idx < self.group_count && self.groups[idx].active {
            Some(&self.groups[idx])
        } else {
            None
        }
    }

    /// Get the parent domain index.
    pub fn parent(&self) -> Option<u16> {
        if self.parent == u16::MAX {
            None
        } else {
            Some(self.parent)
        }
    }

    /// Get the child domain index.
    pub fn child(&self) -> Option<u16> {
        if self.child == u16::MAX {
            None
        } else {
            Some(self.child)
        }
    }

    /// Get the balance statistics.
    pub fn stats(&self) -> &DomainBalanceStats {
        &self.stats
    }

    /// Add a scheduling group to this domain.
    pub fn add_group(&mut self, group: SchedGroup) -> Result<usize> {
        if self.group_count >= MAX_GROUPS_PER_DOMAIN {
            return Err(Error::OutOfMemory);
        }
        let idx = self.group_count;
        self.groups[idx] = group;
        self.groups[idx].active = true;
        self.groups[idx].group_index = idx as u16;
        self.group_count += 1;
        Ok(idx)
    }

    /// Update load/capacity for a group.
    pub fn update_group_load(
        &mut self,
        group_idx: usize,
        load: u64,
        nr_running: u32,
        idle_cpus: u32,
    ) -> Result<()> {
        if group_idx >= self.group_count || !self.groups[group_idx].active {
            return Err(Error::NotFound);
        }
        self.groups[group_idx].load = load;
        self.groups[group_idx].nr_running = nr_running;
        self.groups[group_idx].idle_cpus = idle_cpus;
        if nr_running > 0 {
            self.groups[group_idx].avg_load_per_task = load / nr_running as u64;
        } else {
            self.groups[group_idx].avg_load_per_task = 0;
        }
        self.groups[group_idx].update_state();
        Ok(())
    }

    /// Find the busiest group in this domain for load balancing.
    ///
    /// Returns the group index and the computed imbalance, or `None`
    /// if no group is significantly busier than the local group.
    pub fn find_busiest_group(&mut self, local_group_idx: usize) -> Option<(usize, u64)> {
        self.stats.balance_count += 1;

        if local_group_idx >= self.group_count {
            return None;
        }
        let local_load = self.groups[local_group_idx].load;
        let local_capacity = self.groups[local_group_idx].capacity;
        if local_capacity == 0 {
            return None;
        }

        let mut busiest_idx = None;
        let mut busiest_load_ratio = 0u64;
        let mut busiest_imbalance = 0u64;

        for i in 0..self.group_count {
            if i == local_group_idx || !self.groups[i].active {
                continue;
            }
            let grp_capacity = self.groups[i].capacity;
            if grp_capacity == 0 {
                continue;
            }
            let grp_load = self.groups[i].load;
            let load_ratio = (grp_load * 100) / grp_capacity;
            let local_ratio = (local_load * 100) / local_capacity;

            // Check if this group is significantly busier
            if load_ratio > (local_ratio * IMBALANCE_THRESHOLD_PCT as u64) / 100
                && load_ratio > busiest_load_ratio
            {
                // Compute imbalance: excess load that should be migrated
                let avg_load = (grp_load + local_load) / 2;
                let imbalance = if grp_load > avg_load {
                    grp_load - avg_load
                } else {
                    0
                };
                if imbalance >= MIN_IMBALANCE {
                    busiest_idx = Some(i);
                    busiest_load_ratio = load_ratio;
                    busiest_imbalance = imbalance;
                }
            }
        }

        if busiest_idx.is_none() {
            self.stats.no_imbalance += 1;
        }
        busiest_idx.map(|idx| (idx, busiest_imbalance))
    }

    /// Wake-affine heuristic: should a waking task run on the waker's
    /// CPU rather than its previous CPU?
    ///
    /// Returns `true` if the waking CPU (in `waker_group_idx`) is
    /// preferred.
    pub fn wake_affine(
        &mut self,
        waker_group_idx: usize,
        prev_group_idx: usize,
        task_load: u64,
    ) -> bool {
        self.stats.wake_affine_count += 1;

        if !self.flags.has(DomainFlags::WAKE_AFFINE) {
            return false;
        }
        if waker_group_idx >= self.group_count || prev_group_idx >= self.group_count {
            return false;
        }

        let waker_grp = &self.groups[waker_group_idx];
        let prev_grp = &self.groups[prev_group_idx];

        // Prefer waker's CPU if:
        // 1. Waker group has spare capacity
        // 2. Moving the task won't overload the waker group
        // 3. The load ratio is favorable
        let waker_load_after = waker_grp.load + task_load;
        let waker_capacity = waker_grp.capacity;
        if waker_capacity == 0 {
            return false;
        }
        let waker_ratio_after = (waker_load_after * 100) / waker_capacity;
        let prev_capacity = prev_grp.capacity;
        let prev_ratio = if prev_capacity > 0 {
            (prev_grp.load * 100) / prev_capacity
        } else {
            0
        };

        let affine = waker_grp.has_idle_capacity()
            && waker_ratio_after < WAKE_AFFINE_THRESHOLD
            && waker_ratio_after <= prev_ratio;

        if affine {
            self.stats.wake_affine_accepted += 1;
        }
        affine
    }

    /// Record a successful migration.
    pub fn record_migration(&mut self) {
        self.stats.migrations += 1;
    }

    /// Record a cache-hot failure.
    pub fn record_cache_hot_failure(&mut self) {
        self.stats.cache_hot_failures += 1;
    }
}

// ── CPU Topology Info ───────────────────────────────────────────────────────

/// Per-CPU topology information.
#[derive(Debug, Clone, Copy)]
pub struct CpuTopologyInfo {
    /// Whether this CPU slot is populated.
    pub online: bool,
    /// CPU ID.
    pub cpu_id: u32,
    /// Physical core ID.
    pub core_id: u32,
    /// Physical package (socket) ID.
    pub package_id: u32,
    /// NUMA node ID.
    pub numa_node: u32,
    /// Compute capacity (1024 = full single-CPU capacity).
    pub capacity: u64,
    /// SMT siblings (CPUs sharing the same core).
    pub smt_siblings: CpuMask,
    /// Core siblings (CPUs sharing the same package/L3).
    pub core_siblings: CpuMask,
    /// NUMA siblings (CPUs on the same NUMA node).
    pub numa_siblings: CpuMask,
}

impl CpuTopologyInfo {
    /// Create a default (offline) CPU topology entry.
    pub const fn new() -> Self {
        Self {
            online: false,
            cpu_id: 0,
            core_id: 0,
            package_id: 0,
            numa_node: 0,
            capacity: 1024,
            smt_siblings: CpuMask::empty(),
            core_siblings: CpuMask::empty(),
            numa_siblings: CpuMask::empty(),
        }
    }
}

// ── NUMA Distance ───────────────────────────────────────────────────────────

/// NUMA distance matrix (lower triangle stored).
#[derive(Debug)]
pub struct NumaDistanceMatrix {
    /// Distance values [node_a][node_b] (0-255).
    distances: [[u8; MAX_NUMA_NODES]; MAX_NUMA_NODES],
    /// Number of nodes.
    node_count: usize,
}

impl NumaDistanceMatrix {
    /// Create a new distance matrix with all-local distances.
    pub const fn new() -> Self {
        Self {
            distances: [[10u8; MAX_NUMA_NODES]; MAX_NUMA_NODES],
            node_count: 0,
        }
    }

    /// Set the number of NUMA nodes.
    pub fn set_node_count(&mut self, count: usize) -> Result<()> {
        if count > MAX_NUMA_NODES {
            return Err(Error::InvalidArgument);
        }
        self.node_count = count;
        Ok(())
    }

    /// Set the distance between two nodes.
    pub fn set_distance(&mut self, node_a: usize, node_b: usize, distance: u8) -> Result<()> {
        if node_a >= MAX_NUMA_NODES || node_b >= MAX_NUMA_NODES {
            return Err(Error::InvalidArgument);
        }
        self.distances[node_a][node_b] = distance;
        self.distances[node_b][node_a] = distance;
        Ok(())
    }

    /// Get the distance between two nodes.
    pub fn distance(&self, node_a: usize, node_b: usize) -> u8 {
        if node_a < MAX_NUMA_NODES && node_b < MAX_NUMA_NODES {
            self.distances[node_a][node_b]
        } else {
            255
        }
    }

    /// Check if two nodes are local (same node).
    pub fn is_local(&self, node_a: usize, node_b: usize) -> bool {
        self.distance(node_a, node_b) <= 10
    }
}

// ── Scheduler Topology ──────────────────────────────────────────────────────

/// Statistics for the topology subsystem.
#[derive(Debug, Clone, Copy)]
pub struct TopologyStats {
    /// Number of online CPUs.
    pub online_cpus: u32,
    /// Number of active domains.
    pub active_domains: u32,
    /// Number of NUMA nodes.
    pub numa_nodes: u32,
    /// Total load-balance operations.
    pub total_balances: u64,
    /// Total migrations.
    pub total_migrations: u64,
}

/// The global scheduler topology.
///
/// Maintains the CPU topology hierarchy and scheduling domains,
/// providing load-balancing and placement decision support.
pub struct SchedTopology {
    /// Per-CPU topology information.
    cpu_info: [CpuTopologyInfo; MAX_CPUS],
    /// Number of online CPUs.
    online_cpus: u32,
    /// Scheduling domains.
    domains: [SchedDomain; MAX_DOMAINS],
    /// Number of active domains.
    domain_count: usize,
    /// NUMA distance matrix.
    numa_distances: NumaDistanceMatrix,
    /// Per-CPU domain chain: for each CPU, the domain at each level.
    /// `cpu_domains[cpu][level]` = domain index or u16::MAX.
    cpu_domains: [[u16; MAX_LEVELS]; MAX_CPUS],
    /// Whether the topology has been built.
    built: bool,
}

impl SchedTopology {
    /// Create a new scheduler topology.
    pub const fn new() -> Self {
        Self {
            cpu_info: [const { CpuTopologyInfo::new() }; MAX_CPUS],
            online_cpus: 0,
            domains: [const { SchedDomain::new() }; MAX_DOMAINS],
            domain_count: 0,
            numa_distances: NumaDistanceMatrix::new(),
            cpu_domains: [[u16::MAX; MAX_LEVELS]; MAX_CPUS],
            built: false,
        }
    }

    /// Register a CPU with its topology information.
    pub fn register_cpu(&mut self, info: CpuTopologyInfo) -> Result<()> {
        let cpu = info.cpu_id as usize;
        if cpu >= MAX_CPUS {
            return Err(Error::InvalidArgument);
        }
        self.cpu_info[cpu] = info;
        self.cpu_info[cpu].online = true;
        self.online_cpus += 1;
        Ok(())
    }

    /// Get CPU topology info.
    pub fn get_cpu_info(&self, cpu: usize) -> Option<&CpuTopologyInfo> {
        if cpu < MAX_CPUS && self.cpu_info[cpu].online {
            Some(&self.cpu_info[cpu])
        } else {
            None
        }
    }

    /// Get the number of online CPUs.
    pub fn online_cpus(&self) -> u32 {
        self.online_cpus
    }

    /// Get a reference to the NUMA distance matrix.
    pub fn numa_distances(&self) -> &NumaDistanceMatrix {
        &self.numa_distances
    }

    /// Get a mutable reference to the NUMA distance matrix.
    pub fn numa_distances_mut(&mut self) -> &mut NumaDistanceMatrix {
        &mut self.numa_distances
    }

    /// Build the scheduling domain hierarchy from topology info.
    ///
    /// Creates SMT, MC, and NUMA domains based on the registered
    /// CPU topology and NUMA distances.
    pub fn build_domains(&mut self) -> Result<()> {
        if self.online_cpus == 0 {
            return Err(Error::InvalidArgument);
        }
        self.domain_count = 0;

        // Build SMT domains
        self.build_level_domains(DomainLevel::Smt)?;
        // Build MC domains
        self.build_level_domains(DomainLevel::Mc)?;
        // Build NUMA domains
        self.build_level_domains(DomainLevel::Numa)?;

        // Link parent/child relationships
        self.link_domain_hierarchy();

        self.built = true;
        Ok(())
    }

    /// Build domains for a specific level.
    fn build_level_domains(&mut self, level: DomainLevel) -> Result<()> {
        // Collect unique spans for this level
        let mut seen_spans: [CpuMask; MAX_CPUS] = [const { CpuMask::empty() }; MAX_CPUS];
        let mut span_count = 0;

        for cpu in 0..MAX_CPUS {
            if !self.cpu_info[cpu].online {
                continue;
            }
            let span = match level {
                DomainLevel::Smt => self.cpu_info[cpu].smt_siblings,
                DomainLevel::Mc => self.cpu_info[cpu].core_siblings,
                DomainLevel::Numa => self.cpu_info[cpu].numa_siblings,
                _ => continue,
            };
            if span.is_empty() {
                continue;
            }
            // Check if we already have this span
            let already_seen = (0..span_count).any(|i| {
                seen_spans[i].weight() == span.weight() && span.is_subset_of(&seen_spans[i])
            });
            if already_seen {
                continue;
            }
            if span_count < MAX_CPUS {
                seen_spans[span_count] = span;
                span_count += 1;
            }

            // Create a domain for this span
            if self.domain_count >= MAX_DOMAINS {
                return Err(Error::OutOfMemory);
            }
            let did = self.domain_count;
            let domain = &mut self.domains[did];
            domain.active = true;
            domain.domain_id = did as u16;
            domain.level = level;
            domain.span = span;
            domain.flags = level.default_flags();
            domain.group_count = 0;
            domain.parent = u16::MAX;
            domain.child = u16::MAX;

            // Create one group per CPU in the span for simplicity
            // (real implementation would group by sub-topology)
            let mut group = SchedGroup::new();
            group.active = true;
            group.span = span;
            group.capacity = span.weight() as u64 * 1024;
            group.capacity_orig = group.capacity;
            domain.groups[0] = group;
            domain.group_count = 1;

            self.domain_count += 1;

            // Assign to CPUs
            for c in 0..MAX_CPUS {
                if span.test(c) {
                    let lvl = level as usize;
                    if lvl < MAX_LEVELS {
                        self.cpu_domains[c][lvl] = did as u16;
                    }
                }
            }
        }
        Ok(())
    }

    /// Link parent/child relationships between domain levels.
    fn link_domain_hierarchy(&mut self) {
        for cpu in 0..MAX_CPUS {
            if !self.cpu_info[cpu].online {
                continue;
            }
            let mut prev_level_domain = u16::MAX;
            for lvl in 0..MAX_LEVELS {
                let did = self.cpu_domains[cpu][lvl];
                if did == u16::MAX {
                    continue;
                }
                if prev_level_domain != u16::MAX {
                    let prev = prev_level_domain as usize;
                    let curr = did as usize;
                    if prev < MAX_DOMAINS && curr < MAX_DOMAINS {
                        self.domains[prev].parent = did;
                        self.domains[curr].child = prev_level_domain;
                    }
                }
                prev_level_domain = did;
            }
        }
    }

    /// Get the scheduling domain for a CPU at a given level.
    pub fn cpu_domain(&self, cpu: usize, level: DomainLevel) -> Option<&SchedDomain> {
        if cpu >= MAX_CPUS {
            return None;
        }
        let lvl = level as usize;
        if lvl >= MAX_LEVELS {
            return None;
        }
        let did = self.cpu_domains[cpu][lvl];
        if did == u16::MAX {
            return None;
        }
        let idx = did as usize;
        if idx < MAX_DOMAINS && self.domains[idx].active {
            Some(&self.domains[idx])
        } else {
            None
        }
    }

    /// Get a mutable reference to a domain by index.
    pub fn get_domain_mut(&mut self, domain_idx: usize) -> Option<&mut SchedDomain> {
        if domain_idx < MAX_DOMAINS && self.domains[domain_idx].active {
            Some(&mut self.domains[domain_idx])
        } else {
            None
        }
    }

    /// Check if a task migration is cache-hot.
    ///
    /// Returns `true` if the task has run recently enough that its
    /// cache footprint is likely still warm.
    pub fn is_cache_hot(&self, task_last_run_ns: u64, current_ns: u64) -> bool {
        if current_ns <= task_last_run_ns {
            return true;
        }
        (current_ns - task_last_run_ns) < CACHE_HOT_NS
    }

    /// Whether the topology has been built.
    pub fn is_built(&self) -> bool {
        self.built
    }

    /// Get the number of active domains.
    pub fn domain_count(&self) -> usize {
        self.domain_count
    }

    /// Get statistics.
    pub fn stats(&self) -> TopologyStats {
        let mut total_balances = 0u64;
        let mut total_migrations = 0u64;
        for i in 0..self.domain_count {
            if self.domains[i].active {
                total_balances += self.domains[i].stats.balance_count;
                total_migrations += self.domains[i].stats.migrations;
            }
        }
        TopologyStats {
            online_cpus: self.online_cpus,
            active_domains: self.domain_count as u32,
            numa_nodes: self.numa_distances.node_count as u32,
            total_balances,
            total_migrations,
        }
    }
}
