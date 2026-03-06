// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! NUMA-aware scheduler balancing.
//!
//! Tracks memory access patterns per task and periodically migrates
//! tasks (and optionally their memory) to the NUMA node where the
//! majority of their accesses land. This reduces remote-node memory
//! latency and interconnect traffic.
//!
//! # Architecture
//!
//! ```text
//! ┌──────────────────────────────────────────────────────────────────┐
//! │                    NumaBalancer                                   │
//! │                                                                  │
//! │  [NumaNode; MAX_NODES]  — per-node topology + load              │
//! │  ┌────────────────────────────────────────────────────────────┐  │
//! │  │  NumaNode                                                  │  │
//! │  │    node_id, cpu_mask, capacity_weight                      │  │
//! │  │    load / running / mem_pressure                            │  │
//! │  └────────────────────────────────────────────────────────────┘  │
//! │                                                                  │
//! │  [TaskNumaInfo; MAX_TASKS]  — per-task NUMA statistics           │
//! │  ┌────────────────────────────────────────────────────────────┐  │
//! │  │  TaskNumaInfo                                              │  │
//! │  │    pid, current_node, preferred_node                       │  │
//! │  │    fault_counts[MAX_NODES] — recent fault heatmap          │  │
//! │  │    scan_period_ns — adaptive scan interval                 │  │
//! │  └────────────────────────────────────────────────────────────┘  │
//! │                                                                  │
//! │  [NodeDistance; MAX_NODES * MAX_NODES] — distance matrix         │
//! │  NumaBalancerStats — global counters                             │
//! └──────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Balancing Algorithm
//!
//! 1. **Fault scanning**: Periodically unmap a few pages of each task
//!    so that future accesses cause NUMA hinting faults.
//! 2. **Fault recording**: On each fault, increment the task's
//!    `fault_counts[node]` counter.
//! 3. **Preferred node**: The node with the highest fault count is the
//!    task's "preferred" node.
//! 4. **Migration decision**: If preferred != current, compute a
//!    cost/benefit score. Migrate if beneficial.
//! 5. **Group balancing**: Tasks sharing memory (numa_group) are
//!    co-located on the same node if possible.
//!
//! # Reference
//!
//! Linux `kernel/sched/numa.c`, `kernel/sched/fair.c` (task_numa_*),
//! `Documentation/scheduler/numa-scheduling.rst`.

use oncrix_lib::{Error, Result};

// ── Constants ────────────────────────────────────────────────────────────────

/// Maximum NUMA nodes.
const MAX_NODES: usize = 8;

/// Maximum tasks tracked for NUMA balancing.
const MAX_TASKS: usize = 512;

/// Maximum NUMA groups (sets of tasks sharing memory).
const MAX_GROUPS: usize = 64;

/// Maximum tasks per NUMA group.
const MAX_GROUP_MEMBERS: usize = 16;

/// Default scan period in nanoseconds (1 second).
const DEFAULT_SCAN_PERIOD_NS: u64 = 1_000_000_000;

/// Minimum scan period (100 ms).
const MIN_SCAN_PERIOD_NS: u64 = 100_000_000;

/// Maximum scan period (60 seconds).
const MAX_SCAN_PERIOD_NS: u64 = 60_000_000_000;

/// Scan period backoff multiplier (shift right by 1 = ×2).
const SCAN_PERIOD_GROW_SHIFT: u32 = 1;

/// Score threshold to trigger migration.
const MIGRATION_THRESHOLD: i64 = 10;

/// Maximum distance value in the distance matrix.
const MAX_DISTANCE: u32 = 255;

/// Local node distance (same node).
const LOCAL_DISTANCE: u32 = 10;

/// Remote node distance (default for different nodes).
const REMOTE_DISTANCE: u32 = 20;

/// Fault count decay factor (shift right by this amount each period).
const FAULT_DECAY_SHIFT: u32 = 1;

/// Maximum capacity weight per node.
const MAX_CAPACITY: u32 = 1024;

// ── NodeState ───────────────────────────────────────────────────────────────

/// State of a NUMA node.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeState {
    /// Node slot is unused.
    Offline,
    /// Node is online and available.
    Online,
    /// Node is online but memory-only (no CPUs).
    MemoryOnly,
    /// Node is being hot-removed.
    HotRemove,
}

impl Default for NodeState {
    fn default() -> Self {
        Self::Offline
    }
}

// ── NumaNode ────────────────────────────────────────────────────────────────

/// Per-node topology and load information.
#[derive(Debug, Clone, Copy)]
pub struct NumaNode {
    /// Node identifier (0..MAX_NODES-1).
    node_id: u32,
    /// Current state.
    state: NodeState,
    /// Bitmask of CPUs on this node (bit N = CPU N).
    cpu_mask: u64,
    /// Capacity weight (higher = more compute).
    capacity_weight: u32,
    /// Current aggregate load on this node.
    load: u64,
    /// Number of runnable tasks on this node.
    running_tasks: u32,
    /// Memory pressure indicator (0-100).
    mem_pressure: u32,
    /// Total memory in pages.
    total_pages: u64,
    /// Free memory in pages.
    free_pages: u64,
}

impl NumaNode {
    /// Create an offline node.
    const fn new() -> Self {
        Self {
            node_id: 0,
            state: NodeState::Offline,
            cpu_mask: 0,
            capacity_weight: 0,
            load: 0,
            running_tasks: 0,
            mem_pressure: 0,
            total_pages: 0,
            free_pages: 0,
        }
    }

    /// Check whether this node is online.
    pub fn is_online(&self) -> bool {
        matches!(self.state, NodeState::Online | NodeState::MemoryOnly)
    }

    /// Count the number of CPUs on this node.
    pub fn cpu_count(&self) -> u32 {
        self.cpu_mask.count_ones()
    }

    /// Get the node ID.
    pub fn node_id(&self) -> u32 {
        self.node_id
    }

    /// Get the capacity weight.
    pub fn capacity(&self) -> u32 {
        self.capacity_weight
    }
}

// ── TaskNumaState ───────────────────────────────────────────────────────────

/// Per-task NUMA balancing state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskNumaState {
    /// Slot is free.
    Free,
    /// Task is being tracked.
    Active,
    /// Task is scheduled for migration.
    Migrating,
    /// Task has been removed from tracking.
    Removed,
}

impl Default for TaskNumaState {
    fn default() -> Self {
        Self::Free
    }
}

// ── TaskNumaInfo ────────────────────────────────────────────────────────────

/// Per-task NUMA statistics and placement info.
#[derive(Debug, Clone, Copy)]
pub struct TaskNumaInfo {
    /// Task PID.
    pid: u64,
    /// Current state.
    state: TaskNumaState,
    /// Node the task is currently running on.
    current_node: u32,
    /// Preferred node (highest fault count).
    preferred_node: u32,
    /// Fault counts per node (recent faults).
    fault_counts: [u64; MAX_NODES],
    /// Total faults across all nodes.
    total_faults: u64,
    /// Adaptive scan period in nanoseconds.
    scan_period_ns: u64,
    /// Timestamp of last scan.
    last_scan_ns: u64,
    /// Number of migrations performed.
    migration_count: u64,
    /// Number of migration attempts that were rejected.
    migration_rejected: u64,
    /// NUMA group index (0 = no group).
    group_idx: usize,
    /// Score for the current placement (higher = better).
    placement_score: i64,
    /// Whether this task has ever been scanned.
    scanned: bool,
}

impl TaskNumaInfo {
    /// Create an empty task info slot.
    const fn new() -> Self {
        Self {
            pid: 0,
            state: TaskNumaState::Free,
            current_node: 0,
            preferred_node: 0,
            fault_counts: [0u64; MAX_NODES],
            total_faults: 0,
            scan_period_ns: DEFAULT_SCAN_PERIOD_NS,
            last_scan_ns: 0,
            migration_count: 0,
            migration_rejected: 0,
            group_idx: 0,
            placement_score: 0,
            scanned: false,
        }
    }

    /// Check whether this slot is free.
    fn is_free(&self) -> bool {
        matches!(self.state, TaskNumaState::Free | TaskNumaState::Removed)
    }

    /// Get the task PID.
    pub fn pid(&self) -> u64 {
        self.pid
    }

    /// Get the preferred node.
    pub fn preferred_node(&self) -> u32 {
        self.preferred_node
    }

    /// Get the current node.
    pub fn current_node(&self) -> u32 {
        self.current_node
    }

    /// Get fault counts slice.
    pub fn fault_counts(&self) -> &[u64; MAX_NODES] {
        &self.fault_counts
    }
}

// ── NumaGroup ───────────────────────────────────────────────────────────────

/// A NUMA group — a set of tasks that share significant memory.
///
/// Tasks in the same group should ideally be placed on the same node.
#[derive(Debug, Clone, Copy)]
pub struct NumaGroup {
    /// Group identifier.
    id: u64,
    /// Whether this group is active.
    active: bool,
    /// Member task PIDs.
    members: [u64; MAX_GROUP_MEMBERS],
    /// Number of members.
    member_count: usize,
    /// Aggregate fault counts per node.
    group_faults: [u64; MAX_NODES],
    /// Preferred node for the group.
    preferred_node: u32,
    /// Total shared page faults.
    shared_faults: u64,
}

impl NumaGroup {
    /// Create an empty group.
    const fn new() -> Self {
        Self {
            id: 0,
            active: false,
            members: [0u64; MAX_GROUP_MEMBERS],
            member_count: 0,
            group_faults: [0u64; MAX_NODES],
            preferred_node: 0,
            shared_faults: 0,
        }
    }

    /// Check whether this group is active.
    pub fn is_active(&self) -> bool {
        self.active
    }

    /// Get the preferred node.
    pub fn preferred_node(&self) -> u32 {
        self.preferred_node
    }

    /// Get the number of members.
    pub fn member_count(&self) -> usize {
        self.member_count
    }
}

// ── MigrationDecision ───────────────────────────────────────────────────────

/// Result of a migration cost/benefit analysis.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MigrationDecision {
    /// Stay on the current node.
    Stay,
    /// Migrate to the preferred node.
    Migrate,
    /// Swap with another task on the target node.
    Swap,
}

// ── NumaBalancerStats ───────────────────────────────────────────────────────

/// Global statistics for the NUMA balancer.
#[derive(Debug, Clone, Copy)]
pub struct NumaBalancerStats {
    /// Total NUMA hinting faults recorded.
    pub total_faults: u64,
    /// Local faults (task already on preferred node).
    pub local_faults: u64,
    /// Remote faults (task on wrong node).
    pub remote_faults: u64,
    /// Tasks migrated.
    pub migrations: u64,
    /// Migration attempts rejected.
    pub migrations_rejected: u64,
    /// Task swaps performed.
    pub swaps: u64,
    /// Pages migrated.
    pub pages_migrated: u64,
    /// Scan periods completed.
    pub scans_completed: u64,
    /// Groups created.
    pub groups_created: u64,
    /// Groups dissolved.
    pub groups_dissolved: u64,
}

impl NumaBalancerStats {
    /// Create zeroed statistics.
    const fn new() -> Self {
        Self {
            total_faults: 0,
            local_faults: 0,
            remote_faults: 0,
            migrations: 0,
            migrations_rejected: 0,
            swaps: 0,
            pages_migrated: 0,
            scans_completed: 0,
            groups_created: 0,
            groups_dissolved: 0,
        }
    }
}

// ── NumaBalancer ────────────────────────────────────────────────────────────

/// Top-level NUMA balancing subsystem.
///
/// Orchestrates hinting fault recording, preferred-node computation,
/// migration decisions, and group management.
pub struct NumaBalancer {
    /// Per-node topology.
    nodes: [NumaNode; MAX_NODES],
    /// Number of online nodes.
    online_count: u32,
    /// Distance matrix (flattened MAX_NODES × MAX_NODES).
    distances: [u32; MAX_NODES * MAX_NODES],
    /// Per-task NUMA info.
    tasks: [TaskNumaInfo; MAX_TASKS],
    /// NUMA groups.
    groups: [NumaGroup; MAX_GROUPS],
    /// Next group ID.
    next_group_id: u64,
    /// Global statistics.
    stats: NumaBalancerStats,
    /// Whether balancing is enabled.
    enabled: bool,
    /// Current time in nanoseconds.
    now_ns: u64,
}

impl NumaBalancer {
    /// Create a new NUMA balancer (disabled by default).
    pub const fn new() -> Self {
        Self {
            nodes: [const { NumaNode::new() }; MAX_NODES],
            online_count: 0,
            distances: [0u32; MAX_NODES * MAX_NODES],
            tasks: [const { TaskNumaInfo::new() }; MAX_TASKS],
            groups: [const { NumaGroup::new() }; MAX_GROUPS],
            next_group_id: 1,
            stats: NumaBalancerStats::new(),
            enabled: false,
            now_ns: 0,
        }
    }

    /// Update the internal time reference.
    pub fn set_time_ns(&mut self, ns: u64) {
        self.now_ns = ns;
    }

    /// Enable or disable the balancer.
    pub fn set_enabled(&mut self, on: bool) {
        self.enabled = on;
    }

    /// Check whether the balancer is enabled.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Get the global statistics.
    pub fn stats(&self) -> &NumaBalancerStats {
        &self.stats
    }

    // ── Node topology ───────────────────────────────────────────────

    /// Register a NUMA node.
    pub fn register_node(
        &mut self,
        node_id: u32,
        cpu_mask: u64,
        capacity: u32,
        total_pages: u64,
    ) -> Result<()> {
        if node_id as usize >= MAX_NODES {
            return Err(Error::InvalidArgument);
        }
        if capacity > MAX_CAPACITY {
            return Err(Error::InvalidArgument);
        }
        let node = &mut self.nodes[node_id as usize];
        if node.is_online() {
            return Err(Error::AlreadyExists);
        }
        node.node_id = node_id;
        node.state = NodeState::Online;
        node.cpu_mask = cpu_mask;
        node.capacity_weight = capacity;
        node.total_pages = total_pages;
        node.free_pages = total_pages;
        self.online_count += 1;

        // Set default distances.
        for j in 0..MAX_NODES {
            let dist = if j == node_id as usize {
                LOCAL_DISTANCE
            } else {
                REMOTE_DISTANCE
            };
            self.distances[node_id as usize * MAX_NODES + j] = dist;
            self.distances[j * MAX_NODES + node_id as usize] = dist;
        }

        Ok(())
    }

    /// Take a node offline.
    pub fn offline_node(&mut self, node_id: u32) -> Result<()> {
        if node_id as usize >= MAX_NODES {
            return Err(Error::InvalidArgument);
        }
        let node = &mut self.nodes[node_id as usize];
        if !node.is_online() {
            return Err(Error::NotFound);
        }
        node.state = NodeState::Offline;
        self.online_count = self.online_count.saturating_sub(1);
        Ok(())
    }

    /// Set the distance between two nodes.
    pub fn set_distance(&mut self, from: u32, to: u32, dist: u32) -> Result<()> {
        if from as usize >= MAX_NODES || to as usize >= MAX_NODES {
            return Err(Error::InvalidArgument);
        }
        if dist > MAX_DISTANCE {
            return Err(Error::InvalidArgument);
        }
        self.distances[from as usize * MAX_NODES + to as usize] = dist;
        self.distances[to as usize * MAX_NODES + from as usize] = dist;
        Ok(())
    }

    /// Get the distance between two nodes.
    pub fn distance(&self, from: u32, to: u32) -> Result<u32> {
        if from as usize >= MAX_NODES || to as usize >= MAX_NODES {
            return Err(Error::InvalidArgument);
        }
        Ok(self.distances[from as usize * MAX_NODES + to as usize])
    }

    /// Get a reference to a node.
    pub fn node(&self, node_id: u32) -> Result<&NumaNode> {
        if node_id as usize >= MAX_NODES {
            return Err(Error::InvalidArgument);
        }
        Ok(&self.nodes[node_id as usize])
    }

    /// Update node load metrics.
    pub fn update_node_load(
        &mut self,
        node_id: u32,
        load: u64,
        running: u32,
        mem_pressure: u32,
        free_pages: u64,
    ) -> Result<()> {
        if node_id as usize >= MAX_NODES {
            return Err(Error::InvalidArgument);
        }
        let node = &mut self.nodes[node_id as usize];
        if !node.is_online() {
            return Err(Error::NotFound);
        }
        node.load = load;
        node.running_tasks = running;
        node.mem_pressure = mem_pressure.min(100);
        node.free_pages = free_pages;
        Ok(())
    }

    // ── Task tracking ───────────────────────────────────────────────

    /// Start tracking a task for NUMA balancing.
    pub fn track_task(&mut self, pid: u64, current_node: u32) -> Result<usize> {
        if current_node as usize >= MAX_NODES {
            return Err(Error::InvalidArgument);
        }
        // Check for duplicate.
        if self.find_task(pid).is_some() {
            return Err(Error::AlreadyExists);
        }

        let idx = self
            .tasks
            .iter()
            .position(|t| t.is_free())
            .ok_or(Error::OutOfMemory)?;

        self.tasks[idx] = TaskNumaInfo {
            pid,
            state: TaskNumaState::Active,
            current_node,
            preferred_node: current_node,
            fault_counts: [0u64; MAX_NODES],
            total_faults: 0,
            scan_period_ns: DEFAULT_SCAN_PERIOD_NS,
            last_scan_ns: self.now_ns,
            migration_count: 0,
            migration_rejected: 0,
            group_idx: 0,
            placement_score: 0,
            scanned: false,
        };

        Ok(idx)
    }

    /// Stop tracking a task.
    pub fn untrack_task(&mut self, pid: u64) -> Result<()> {
        let idx = self.find_task(pid).ok_or(Error::NotFound)?;
        // Remove from group if present.
        let group_idx = self.tasks[idx].group_idx;
        if group_idx > 0 {
            self.remove_from_group(group_idx - 1, pid);
        }
        self.tasks[idx].state = TaskNumaState::Removed;
        Ok(())
    }

    /// Get task NUMA info by PID.
    pub fn task_info(&self, pid: u64) -> Result<&TaskNumaInfo> {
        let idx = self.find_task(pid).ok_or(Error::NotFound)?;
        Ok(&self.tasks[idx])
    }

    // ── Fault recording ─────────────────────────────────────────────

    /// Record a NUMA hinting fault for a task.
    ///
    /// Called from the page fault handler when a NUMA hinting fault
    /// (unmapped-for-scanning page) is trapped.
    pub fn record_fault(&mut self, pid: u64, fault_node: u32) -> Result<()> {
        if !self.enabled {
            return Ok(());
        }
        if fault_node as usize >= MAX_NODES {
            return Err(Error::InvalidArgument);
        }

        let idx = self.find_task(pid).ok_or(Error::NotFound)?;

        self.tasks[idx].fault_counts[fault_node as usize] += 1;
        self.tasks[idx].total_faults += 1;
        self.stats.total_faults += 1;

        let current_node = self.tasks[idx].current_node;
        if fault_node == current_node {
            self.stats.local_faults += 1;
        } else {
            self.stats.remote_faults += 1;
        }

        // Update preferred node.
        self.recompute_preferred(idx);

        // Update group faults if in a group.
        let group_idx = self.tasks[idx].group_idx;
        if group_idx > 0 {
            let gi = group_idx - 1;
            if gi < MAX_GROUPS && self.groups[gi].active {
                self.groups[gi].group_faults[fault_node as usize] += 1;
            }
        }

        Ok(())
    }

    /// Recompute the preferred node for a task.
    fn recompute_preferred(&mut self, idx: usize) {
        let task = &self.tasks[idx];
        let mut best_node = task.current_node;
        let mut best_count = 0u64;

        for (n, &count) in task.fault_counts.iter().enumerate() {
            if n < MAX_NODES && self.nodes[n].is_online() && count > best_count {
                best_count = count;
                best_node = n as u32;
            }
        }
        self.tasks[idx].preferred_node = best_node;
    }

    // ── Scan period management ──────────────────────────────────────

    /// Check whether a task is due for a scan.
    pub fn needs_scan(&self, pid: u64) -> Result<bool> {
        if !self.enabled {
            return Ok(false);
        }
        let idx = self.find_task(pid).ok_or(Error::NotFound)?;
        let task = &self.tasks[idx];
        let elapsed = self.now_ns.saturating_sub(task.last_scan_ns);
        Ok(elapsed >= task.scan_period_ns)
    }

    /// Mark a task as scanned and adapt its scan period.
    pub fn complete_scan(&mut self, pid: u64) -> Result<()> {
        let idx = self.find_task(pid).ok_or(Error::NotFound)?;
        let task = &mut self.tasks[idx];

        task.last_scan_ns = self.now_ns;
        task.scanned = true;
        self.stats.scans_completed += 1;

        // Adapt scan period: if task is on its preferred node and
        // has been there a while, slow down scanning.
        if task.current_node == task.preferred_node {
            task.scan_period_ns =
                (task.scan_period_ns << SCAN_PERIOD_GROW_SHIFT).min(MAX_SCAN_PERIOD_NS);
        } else {
            // Task is misplaced — scan more frequently.
            task.scan_period_ns =
                (task.scan_period_ns >> SCAN_PERIOD_GROW_SHIFT).max(MIN_SCAN_PERIOD_NS);
        }

        // Decay old fault counts.
        for count in &mut task.fault_counts {
            *count >>= FAULT_DECAY_SHIFT;
        }
        task.total_faults >>= FAULT_DECAY_SHIFT;

        Ok(())
    }

    // ── Migration decision ──────────────────────────────────────────

    /// Evaluate whether a task should be migrated.
    pub fn evaluate_migration(&mut self, pid: u64) -> Result<MigrationDecision> {
        if !self.enabled {
            return Ok(MigrationDecision::Stay);
        }

        let idx = self.find_task(pid).ok_or(Error::NotFound)?;
        let task = &self.tasks[idx];

        if task.current_node == task.preferred_node {
            return Ok(MigrationDecision::Stay);
        }
        if !self.nodes[task.preferred_node as usize].is_online() {
            return Ok(MigrationDecision::Stay);
        }

        let score = self.compute_migration_score(idx);
        self.tasks[idx].placement_score = score;

        if score >= MIGRATION_THRESHOLD {
            Ok(MigrationDecision::Migrate)
        } else if score > 0 {
            // Marginal benefit — check if swap is better.
            Ok(MigrationDecision::Swap)
        } else {
            Ok(MigrationDecision::Stay)
        }
    }

    /// Compute a migration score (positive = migration is beneficial).
    fn compute_migration_score(&self, idx: usize) -> i64 {
        let task = &self.tasks[idx];
        let cur = task.current_node as usize;
        let pref = task.preferred_node as usize;

        // Faults on preferred node minus faults on current node.
        let fault_diff = task.fault_counts[pref] as i64 - task.fault_counts[cur] as i64;

        // Penalize for high load on the target node.
        let load_penalty = if self.nodes[pref].running_tasks > 0 {
            self.nodes[pref].load as i64 / self.nodes[pref].running_tasks as i64
        } else {
            0
        };

        // Bonus for moving closer (lower distance).
        let distance = self.distances[cur * MAX_NODES + pref];
        let distance_bonus = distance as i64;

        fault_diff - load_penalty + distance_bonus
    }

    /// Execute a migration: move a task to its preferred node.
    pub fn migrate_task(&mut self, pid: u64) -> Result<u32> {
        let idx = self.find_task(pid).ok_or(Error::NotFound)?;
        let task = &self.tasks[idx];

        if task.current_node == task.preferred_node {
            return Ok(task.current_node);
        }

        let target = task.preferred_node;
        if !self.nodes[target as usize].is_online() {
            self.tasks[idx].migration_rejected += 1;
            self.stats.migrations_rejected += 1;
            return Err(Error::NotFound);
        }

        self.tasks[idx].current_node = target;
        self.tasks[idx].migration_count += 1;
        self.tasks[idx].state = TaskNumaState::Active;
        self.stats.migrations += 1;

        Ok(target)
    }

    // ── Group management ────────────────────────────────────────────

    /// Create a new NUMA group.
    pub fn create_group(&mut self) -> Result<usize> {
        let idx = self
            .groups
            .iter()
            .position(|g| !g.active)
            .ok_or(Error::OutOfMemory)?;

        self.groups[idx] = NumaGroup {
            id: self.next_group_id,
            active: true,
            members: [0u64; MAX_GROUP_MEMBERS],
            member_count: 0,
            group_faults: [0u64; MAX_NODES],
            preferred_node: 0,
            shared_faults: 0,
        };
        self.next_group_id += 1;
        self.stats.groups_created += 1;
        Ok(idx)
    }

    /// Add a task to a NUMA group.
    pub fn add_to_group(&mut self, group_idx: usize, pid: u64) -> Result<()> {
        if group_idx >= MAX_GROUPS {
            return Err(Error::InvalidArgument);
        }
        let group = &mut self.groups[group_idx];
        if !group.active {
            return Err(Error::NotFound);
        }
        if group.member_count >= MAX_GROUP_MEMBERS {
            return Err(Error::OutOfMemory);
        }
        // Check duplicate.
        if group.members[..group.member_count].contains(&pid) {
            return Err(Error::AlreadyExists);
        }
        group.members[group.member_count] = pid;
        group.member_count += 1;

        // Update task's group index (1-based to distinguish from 0=none).
        if let Some(task_idx) = self.find_task(pid) {
            self.tasks[task_idx].group_idx = group_idx + 1;
        }

        Ok(())
    }

    /// Remove a task from a NUMA group.
    fn remove_from_group(&mut self, group_idx: usize, pid: u64) {
        if group_idx >= MAX_GROUPS {
            return;
        }
        let group = &mut self.groups[group_idx];
        if let Some(pos) = group.members[..group.member_count]
            .iter()
            .position(|&m| m == pid)
        {
            // Shift remaining members.
            for i in pos..group.member_count.saturating_sub(1) {
                group.members[i] = group.members[i + 1];
            }
            if group.member_count > 0 {
                group.members[group.member_count - 1] = 0;
            }
            group.member_count = group.member_count.saturating_sub(1);

            if group.member_count == 0 {
                group.active = false;
                self.stats.groups_dissolved += 1;
            }
        }
    }

    /// Recompute the preferred node for a group.
    pub fn recompute_group_preferred(&mut self, group_idx: usize) -> Result<u32> {
        if group_idx >= MAX_GROUPS {
            return Err(Error::InvalidArgument);
        }
        let group = &self.groups[group_idx];
        if !group.active {
            return Err(Error::NotFound);
        }

        let mut best_node = 0u32;
        let mut best_faults = 0u64;
        for (n, &faults) in group.group_faults.iter().enumerate() {
            if n < MAX_NODES && self.nodes[n].is_online() && faults > best_faults {
                best_faults = faults;
                best_node = n as u32;
            }
        }
        self.groups[group_idx].preferred_node = best_node;
        Ok(best_node)
    }

    /// Get a reference to a group.
    pub fn group(&self, idx: usize) -> Result<&NumaGroup> {
        if idx >= MAX_GROUPS {
            return Err(Error::InvalidArgument);
        }
        if !self.groups[idx].active {
            return Err(Error::NotFound);
        }
        Ok(&self.groups[idx])
    }

    // ── Bulk operations ─────────────────────────────────────────────

    /// Run one balancing pass over all tracked tasks.
    ///
    /// Scans tasks that are due and evaluates migration for tasks
    /// not on their preferred node. Returns the number of migrations
    /// performed.
    pub fn balance_pass(&mut self) -> Result<u32> {
        if !self.enabled {
            return Ok(0);
        }

        let mut migrated = 0u32;

        for i in 0..MAX_TASKS {
            if !matches!(self.tasks[i].state, TaskNumaState::Active) {
                continue;
            }

            let _pid = self.tasks[i].pid;

            // Check scan.
            let elapsed = self.now_ns.saturating_sub(self.tasks[i].last_scan_ns);
            if elapsed >= self.tasks[i].scan_period_ns {
                self.tasks[i].last_scan_ns = self.now_ns;
                self.tasks[i].scanned = true;
                self.stats.scans_completed += 1;

                // Decay.
                for count in &mut self.tasks[i].fault_counts {
                    *count >>= FAULT_DECAY_SHIFT;
                }
                self.tasks[i].total_faults >>= FAULT_DECAY_SHIFT;
            }

            // Evaluate migration.
            self.recompute_preferred(i);
            if self.tasks[i].current_node != self.tasks[i].preferred_node {
                let score = self.compute_migration_score(i);
                if score >= MIGRATION_THRESHOLD {
                    let target = self.tasks[i].preferred_node;
                    if self.nodes[target as usize].is_online() {
                        self.tasks[i].current_node = target;
                        self.tasks[i].migration_count += 1;
                        self.stats.migrations += 1;
                        migrated += 1;
                    }
                }
            }
        }

        Ok(migrated)
    }

    /// Get the number of online nodes.
    pub fn online_count(&self) -> u32 {
        self.online_count
    }

    // ── Internal helpers ────────────────────────────────────────────

    /// Find a task slot by PID.
    fn find_task(&self, pid: u64) -> Option<usize> {
        self.tasks.iter().position(|t| {
            matches!(t.state, TaskNumaState::Active | TaskNumaState::Migrating) && t.pid == pid
        })
    }
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_balancer() -> NumaBalancer {
        let mut b = NumaBalancer::new();
        b.set_enabled(true);
        b.register_node(0, 0x0F, 256, 1024).unwrap();
        b.register_node(1, 0xF0, 256, 1024).unwrap();
        b
    }

    #[test]
    fn test_register_nodes() {
        let b = make_balancer();
        assert_eq!(b.online_count(), 2);
        assert_eq!(b.distance(0, 1).unwrap(), REMOTE_DISTANCE);
        assert_eq!(b.distance(0, 0).unwrap(), LOCAL_DISTANCE);
    }

    #[test]
    fn test_track_and_fault() {
        let mut b = make_balancer();
        b.track_task(1, 0).unwrap();
        b.record_fault(1, 1).unwrap();
        b.record_fault(1, 1).unwrap();
        b.record_fault(1, 0).unwrap();
        let info = b.task_info(1).unwrap();
        assert_eq!(info.preferred_node(), 1);
    }

    #[test]
    fn test_migration() {
        let mut b = make_balancer();
        b.track_task(10, 0).unwrap();
        // Create heavy faults on node 1.
        for _ in 0..20 {
            b.record_fault(10, 1).unwrap();
        }
        let decision = b.evaluate_migration(10).unwrap();
        assert_ne!(decision, MigrationDecision::Stay);
    }

    #[test]
    fn test_group() {
        let mut b = make_balancer();
        b.track_task(1, 0).unwrap();
        b.track_task(2, 0).unwrap();
        let gi = b.create_group().unwrap();
        b.add_to_group(gi, 1).unwrap();
        b.add_to_group(gi, 2).unwrap();
        assert_eq!(b.group(gi).unwrap().member_count(), 2);
    }

    #[test]
    fn test_balance_pass() {
        let mut b = make_balancer();
        b.set_time_ns(0);
        b.track_task(1, 0).unwrap();
        for _ in 0..50 {
            b.record_fault(1, 1).unwrap();
        }
        b.set_time_ns(DEFAULT_SCAN_PERIOD_NS + 1);
        let count = b.balance_pass().unwrap();
        assert!(count >= 1);
    }
}
