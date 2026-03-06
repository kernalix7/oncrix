// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! NUMA balancing — automatic page migration.
//!
//! Implements automatic NUMA page migration, tracking access patterns and
//! migrating pages to the NUMA node where they are most frequently accessed.
//!
//! # Architecture
//!
//! | Component             | Purpose                                              |
//! |-----------------------|------------------------------------------------------|
//! | [`NumaNode`]          | Represents a NUMA node with memory and CPU info      |
//! | [`PageAccessRecord`]  | Tracks per-page NUMA access counts                   |
//! | [`TaskNumaState`]     | Per-task NUMA locality state                         |
//! | [`NumaBalancer`]      | Central balancer orchestrating migration decisions   |
//!
//! # Migration Strategy
//!
//! 1. Pages are initially allocated on the node that faults them.
//! 2. Access records track which NUMA node accesses each page.
//! 3. When a page's remote access count exceeds a threshold, it becomes a
//!    migration candidate.
//! 4. The balancer migrates candidates to the node with highest access count,
//!    subject to memory pressure limits.

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum number of NUMA nodes supported.
pub const MAX_NUMA_NODES: usize = 8;

/// Maximum number of page access records tracked simultaneously.
pub const MAX_TRACKED_PAGES: usize = 1024;

/// Maximum number of tasks tracked for NUMA locality.
pub const MAX_TRACKED_TASKS: usize = 256;

/// Access count threshold before a page is considered for migration.
pub const MIGRATION_THRESHOLD: u32 = 4;

/// Minimum interval between scans for a task, in nanoseconds (1 second).
pub const SCAN_INTERVAL_NS: u64 = 1_000_000_000;

/// Maximum pages migrated per balancing round.
pub const MAX_MIGRATIONS_PER_ROUND: usize = 64;

// ---------------------------------------------------------------------------
// NUMA node
// ---------------------------------------------------------------------------

/// Represents a single NUMA node.
#[derive(Debug, Clone, Copy)]
pub struct NumaNode {
    /// Node identifier.
    pub id: u8,
    /// Number of online CPUs on this node.
    pub cpu_count: u16,
    /// Total memory in pages.
    pub total_pages: u64,
    /// Currently free pages.
    pub free_pages: u64,
    /// Pages migrated away from this node.
    pub migrated_out: u64,
    /// Pages migrated to this node.
    pub migrated_in: u64,
}

impl NumaNode {
    /// Create a new NUMA node descriptor.
    pub const fn new(id: u8, cpu_count: u16, total_pages: u64) -> Self {
        Self {
            id,
            cpu_count,
            total_pages,
            free_pages: total_pages,
            migrated_out: 0,
            migrated_in: 0,
        }
    }

    /// Returns true if the node has enough free pages to accept a migration.
    pub fn has_capacity(&self, pages: u64) -> bool {
        self.free_pages >= pages
    }

    /// Memory pressure ratio as a value 0–100.
    pub fn pressure_pct(&self) -> u8 {
        if self.total_pages == 0 {
            return 100;
        }
        let used = self.total_pages.saturating_sub(self.free_pages);
        ((used * 100) / self.total_pages).min(100) as u8
    }
}

impl Default for NumaNode {
    fn default() -> Self {
        Self::new(0, 0, 0)
    }
}

// ---------------------------------------------------------------------------
// Page access record
// ---------------------------------------------------------------------------

/// Physical page frame number type alias.
pub type Pfn = u64;

/// Per-node access count entry.
#[derive(Debug, Clone, Copy, Default)]
pub struct NodeAccess {
    /// NUMA node id.
    pub node_id: u8,
    /// Number of accesses from this node.
    pub count: u32,
}

/// Tracks access patterns for a single physical page.
#[derive(Debug, Clone, Copy)]
pub struct PageAccessRecord {
    /// Physical frame number of the tracked page.
    pub pfn: Pfn,
    /// Current home NUMA node.
    pub home_node: u8,
    /// Per-node access counts (indexed by node id).
    pub accesses: [NodeAccess; MAX_NUMA_NODES],
    /// Total remote accesses (from nodes other than home_node).
    pub remote_accesses: u32,
    /// Generation counter for LRU replacement.
    pub generation: u32,
}

impl PageAccessRecord {
    /// Create a new page access record.
    pub const fn new(pfn: Pfn, home_node: u8) -> Self {
        Self {
            pfn,
            home_node,
            accesses: [NodeAccess {
                node_id: 0,
                count: 0,
            }; MAX_NUMA_NODES],
            remote_accesses: 0,
            generation: 0,
        }
    }

    /// Record an access from the given NUMA node.
    pub fn record_access(&mut self, node_id: u8) {
        if (node_id as usize) < MAX_NUMA_NODES {
            self.accesses[node_id as usize].node_id = node_id;
            self.accesses[node_id as usize].count =
                self.accesses[node_id as usize].count.saturating_add(1);
            if node_id != self.home_node {
                self.remote_accesses = self.remote_accesses.saturating_add(1);
            }
        }
    }

    /// Returns the node id with the highest access count.
    pub fn best_node(&self) -> u8 {
        let mut best_node = self.home_node;
        let mut best_count = 0u32;
        for entry in &self.accesses {
            if entry.count > best_count {
                best_count = entry.count;
                best_node = entry.node_id;
            }
        }
        best_node
    }

    /// Returns true if this page is a migration candidate.
    pub fn is_migration_candidate(&self) -> bool {
        self.remote_accesses >= MIGRATION_THRESHOLD
    }

    /// Reset access counters (called after migration).
    pub fn reset(&mut self, new_home: u8) {
        self.home_node = new_home;
        self.remote_accesses = 0;
        for entry in self.accesses.iter_mut() {
            entry.count = 0;
        }
    }
}

impl Default for PageAccessRecord {
    fn default() -> Self {
        Self::new(0, 0)
    }
}

// ---------------------------------------------------------------------------
// Task NUMA state
// ---------------------------------------------------------------------------

/// Per-task NUMA locality tracking.
#[derive(Debug, Clone, Copy)]
pub struct TaskNumaState {
    /// Task PID.
    pub pid: u64,
    /// Preferred NUMA node for this task.
    pub preferred_node: u8,
    /// Last scan timestamp in nanoseconds.
    pub last_scan_ns: u64,
    /// Number of faults on preferred node.
    pub local_faults: u64,
    /// Number of faults on remote nodes.
    pub remote_faults: u64,
    /// Whether this task is active.
    pub active: bool,
}

impl TaskNumaState {
    /// Create a new task NUMA state.
    pub const fn new(pid: u64) -> Self {
        Self {
            pid,
            preferred_node: 0,
            last_scan_ns: 0,
            local_faults: 0,
            remote_faults: 0,
            active: false,
        }
    }

    /// Record a page fault on the given node.
    pub fn record_fault(&mut self, node_id: u8) {
        if node_id == self.preferred_node {
            self.local_faults = self.local_faults.saturating_add(1);
        } else {
            self.remote_faults = self.remote_faults.saturating_add(1);
        }
    }

    /// Locality ratio as a percentage (0–100, higher = better).
    pub fn locality_pct(&self) -> u8 {
        let total = self.local_faults + self.remote_faults;
        if total == 0 {
            return 100;
        }
        ((self.local_faults * 100) / total).min(100) as u8
    }

    /// Returns true if a rescan is due.
    pub fn scan_due(&self, now_ns: u64) -> bool {
        now_ns.saturating_sub(self.last_scan_ns) >= SCAN_INTERVAL_NS
    }
}

impl Default for TaskNumaState {
    fn default() -> Self {
        Self::new(0)
    }
}

// ---------------------------------------------------------------------------
// Migration request
// ---------------------------------------------------------------------------

/// A single page migration request.
#[derive(Debug, Clone, Copy)]
pub struct MigrationRequest {
    /// Physical frame number to migrate.
    pub pfn: Pfn,
    /// Source NUMA node.
    pub src_node: u8,
    /// Destination NUMA node.
    pub dst_node: u8,
}

// ---------------------------------------------------------------------------
// NUMA balancer
// ---------------------------------------------------------------------------

/// Central NUMA balancing engine.
pub struct NumaBalancer {
    /// Registered NUMA nodes.
    nodes: [NumaNode; MAX_NUMA_NODES],
    /// Number of active nodes.
    node_count: usize,
    /// Page access records.
    records: [PageAccessRecord; MAX_TRACKED_PAGES],
    /// Number of active records.
    record_count: usize,
    /// Per-task NUMA states.
    tasks: [TaskNumaState; MAX_TRACKED_TASKS],
    /// Number of tracked tasks.
    task_count: usize,
    /// Global generation counter (incremented per scan).
    generation: u32,
    /// Total migrations performed.
    total_migrations: u64,
    /// Whether balancing is enabled.
    enabled: bool,
}

impl NumaBalancer {
    /// Create a new NUMA balancer (disabled by default).
    pub const fn new() -> Self {
        Self {
            nodes: [NumaNode {
                id: 0,
                cpu_count: 0,
                total_pages: 0,
                free_pages: 0,
                migrated_out: 0,
                migrated_in: 0,
            }; MAX_NUMA_NODES],
            records: [PageAccessRecord {
                pfn: 0,
                home_node: 0,
                accesses: [NodeAccess {
                    node_id: 0,
                    count: 0,
                }; MAX_NUMA_NODES],
                remote_accesses: 0,
                generation: 0,
            }; MAX_TRACKED_PAGES],
            tasks: [TaskNumaState {
                pid: 0,
                preferred_node: 0,
                last_scan_ns: 0,
                local_faults: 0,
                remote_faults: 0,
                active: false,
            }; MAX_TRACKED_TASKS],
            node_count: 0,
            record_count: 0,
            task_count: 0,
            generation: 0,
            total_migrations: 0,
            enabled: false,
        }
    }

    /// Enable or disable NUMA balancing.
    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }

    /// Returns true if balancing is enabled.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Register a NUMA node.
    pub fn register_node(&mut self, node: NumaNode) -> Result<()> {
        if self.node_count >= MAX_NUMA_NODES {
            return Err(Error::OutOfMemory);
        }
        let idx = node.id as usize;
        if idx >= MAX_NUMA_NODES {
            return Err(Error::InvalidArgument);
        }
        self.nodes[idx] = node;
        self.node_count += 1;
        Ok(())
    }

    /// Record a page access from the given NUMA node.
    pub fn record_access(&mut self, pfn: Pfn, accessing_node: u8) -> Result<()> {
        // Find existing record.
        for i in 0..self.record_count {
            if self.records[i].pfn == pfn {
                self.records[i].record_access(accessing_node);
                return Ok(());
            }
        }
        // Allocate new record.
        if self.record_count >= MAX_TRACKED_PAGES {
            // Evict oldest record (simple LRU by generation).
            let mut oldest_idx = 0;
            let mut oldest_gen = u32::MAX;
            for i in 0..self.record_count {
                if self.records[i].generation < oldest_gen {
                    oldest_gen = self.records[i].generation;
                    oldest_idx = i;
                }
            }
            self.records[oldest_idx] = PageAccessRecord::new(pfn, accessing_node);
            self.records[oldest_idx].generation = self.generation;
            self.records[oldest_idx].record_access(accessing_node);
        } else {
            let idx = self.record_count;
            self.records[idx] = PageAccessRecord::new(pfn, accessing_node);
            self.records[idx].generation = self.generation;
            self.records[idx].record_access(accessing_node);
            self.record_count += 1;
        }
        Ok(())
    }

    /// Register a task for NUMA tracking.
    pub fn register_task(&mut self, pid: u64) -> Result<()> {
        if self.task_count >= MAX_TRACKED_TASKS {
            return Err(Error::OutOfMemory);
        }
        let idx = self.task_count;
        self.tasks[idx] = TaskNumaState::new(pid);
        self.tasks[idx].active = true;
        self.task_count += 1;
        Ok(())
    }

    /// Unregister a task.
    pub fn unregister_task(&mut self, pid: u64) {
        for i in 0..self.task_count {
            if self.tasks[i].pid == pid {
                self.tasks[i].active = false;
                break;
            }
        }
    }

    /// Run one balancing round: collect migration candidates and emit requests.
    ///
    /// Returns the number of migration requests written into `out`.
    pub fn balance(&mut self, out: &mut [MigrationRequest]) -> usize {
        if !self.enabled {
            return 0;
        }
        self.generation = self.generation.wrapping_add(1);
        let mut count = 0;
        let limit = out.len().min(MAX_MIGRATIONS_PER_ROUND);

        for i in 0..self.record_count {
            if count >= limit {
                break;
            }
            let record = &self.records[i];
            if !record.is_migration_candidate() {
                continue;
            }
            let dst = record.best_node();
            if dst == record.home_node {
                continue;
            }
            // Check destination has capacity.
            if dst as usize >= MAX_NUMA_NODES {
                continue;
            }
            if !self.nodes[dst as usize].has_capacity(1) {
                continue;
            }
            out[count] = MigrationRequest {
                pfn: record.pfn,
                src_node: record.home_node,
                dst_node: dst,
            };
            count += 1;
        }
        // Update stats and reset migrated records.
        for req in &out[..count] {
            self.total_migrations = self.total_migrations.saturating_add(1);
            if (req.src_node as usize) < MAX_NUMA_NODES {
                self.nodes[req.src_node as usize].migrated_out = self.nodes[req.src_node as usize]
                    .migrated_out
                    .saturating_add(1);
                self.nodes[req.src_node as usize].free_pages = self.nodes[req.src_node as usize]
                    .free_pages
                    .saturating_add(1);
            }
            if (req.dst_node as usize) < MAX_NUMA_NODES {
                self.nodes[req.dst_node as usize].migrated_in = self.nodes[req.dst_node as usize]
                    .migrated_in
                    .saturating_add(1);
                self.nodes[req.dst_node as usize].free_pages = self.nodes[req.dst_node as usize]
                    .free_pages
                    .saturating_sub(1);
            }
            // Reset access record for migrated page.
            for i in 0..self.record_count {
                if self.records[i].pfn == req.pfn {
                    self.records[i].reset(req.dst_node);
                    break;
                }
            }
        }
        count
    }

    /// Return the total number of migrations performed.
    pub fn total_migrations(&self) -> u64 {
        self.total_migrations
    }

    /// Return node info for a given node id.
    pub fn node(&self, id: u8) -> Option<&NumaNode> {
        if (id as usize) < MAX_NUMA_NODES && self.nodes[id as usize].cpu_count > 0 {
            Some(&self.nodes[id as usize])
        } else {
            None
        }
    }
}

impl Default for NumaBalancer {
    fn default() -> Self {
        Self::new()
    }
}
