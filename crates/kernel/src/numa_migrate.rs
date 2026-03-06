// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! NUMA page migration — moving pages between NUMA nodes for locality.
//!
//! When the scheduler moves a task to a different NUMA node, its
//! memory pages may be on a remote node causing high access latency.
//! This subsystem handles migrating pages closer to where they are
//! being accessed.
//!
//! # Architecture
//!
//! ```text
//! ┌──────────────────────────────────────────────────────────────┐
//! │                    NumaMigrator                               │
//! │                                                              │
//! │  MigrationRequest[0..MAX_REQUESTS]  (pending migrations)     │
//! │  ┌────────────────────────────────────────────────────────┐  │
//! │  │  pid: u64                                              │  │
//! │  │  source_node: u16                                      │  │
//! │  │  dest_node: u16                                        │  │
//! │  │  page_count: usize                                     │  │
//! │  │  state: MigrationState                                 │  │
//! │  └────────────────────────────────────────────────────────┘  │
//! │                                                              │
//! │  NodeStats[0..MAX_NODES]  (per-node migration statistics)    │
//! └──────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Reference
//!
//! Linux `mm/migrate.c`, `mm/memory-failure.c`.

use oncrix_lib::{Error, Result};

// ══════════════════════════════════════════════════════════════
// Constants
// ══════════════════════════════════════════════════════════════

/// Maximum NUMA nodes.
const MAX_NODES: usize = 16;

/// Maximum pending migration requests.
const MAX_REQUESTS: usize = 256;

/// Maximum pages per migration request.
const MAX_PAGES_PER_REQUEST: usize = 4096;

/// Default migration rate limit (pages per second).
const DEFAULT_RATE_LIMIT: u64 = 32768;

// ══════════════════════════════════════════════════════════════
// MigrationState
// ══════════════════════════════════════════════════════════════

/// State of a migration request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum MigrationState {
    /// Slot is free.
    Free = 0,
    /// Request is queued.
    Queued = 1,
    /// Migration is in progress.
    InProgress = 2,
    /// Migration completed successfully.
    Completed = 3,
    /// Migration failed.
    Failed = 4,
}

// ══════════════════════════════════════════════════════════════
// MigrationReason
// ══════════════════════════════════════════════════════════════

/// Reason for initiating a page migration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum MigrationReason {
    /// Task moved to a different NUMA node by the scheduler.
    TaskMigration = 0,
    /// NUMA balancing detected remote access patterns.
    NumaBalancing = 1,
    /// Memory compaction needs to relocate pages.
    Compaction = 2,
    /// Memory hotplug: node going offline.
    Hotplug = 3,
    /// Explicit user request via `move_pages` syscall.
    UserRequest = 4,
    /// Memory policy change (e.g., `mbind`).
    PolicyChange = 5,
}

impl MigrationReason {
    /// Display name.
    pub const fn name(self) -> &'static str {
        match self {
            Self::TaskMigration => "task_migration",
            Self::NumaBalancing => "numa_balancing",
            Self::Compaction => "compaction",
            Self::Hotplug => "hotplug",
            Self::UserRequest => "user_request",
            Self::PolicyChange => "policy_change",
        }
    }
}

// ══════════════════════════════════════════════════════════════
// MigrationRequest
// ══════════════════════════════════════════════════════════════

/// A pending or completed page migration request.
#[derive(Debug, Clone, Copy)]
pub struct MigrationRequest {
    /// PID of the owning process (0 for kernel pages).
    pub pid: u64,
    /// Source NUMA node.
    pub source_node: u16,
    /// Destination NUMA node.
    pub dest_node: u16,
    /// Number of pages to migrate.
    pub page_count: usize,
    /// Pages successfully migrated.
    pub pages_migrated: usize,
    /// Pages that failed migration.
    pub pages_failed: usize,
    /// Current state.
    pub state: MigrationState,
    /// Reason for migration.
    pub reason: MigrationReason,
    /// Request identifier.
    pub request_id: u64,
}

impl MigrationRequest {
    /// Create a free request slot.
    const fn empty() -> Self {
        Self {
            pid: 0,
            source_node: 0,
            dest_node: 0,
            page_count: 0,
            pages_migrated: 0,
            pages_failed: 0,
            state: MigrationState::Free,
            reason: MigrationReason::TaskMigration,
            request_id: 0,
        }
    }

    /// Returns `true` if this slot is in use.
    pub const fn is_active(&self) -> bool {
        !matches!(self.state, MigrationState::Free)
    }
}

// ══════════════════════════════════════════════════════════════
// NodeStats — per-NUMA-node statistics
// ══════════════════════════════════════════════════════════════

/// Per-node migration statistics.
#[derive(Debug, Clone, Copy)]
pub struct NodeStats {
    /// Pages migrated away from this node.
    pub pages_out: u64,
    /// Pages migrated into this node.
    pub pages_in: u64,
    /// Failed migration attempts from this node.
    pub failures_out: u64,
    /// Failed migration attempts to this node.
    pub failures_in: u64,
}

impl NodeStats {
    const fn new() -> Self {
        Self {
            pages_out: 0,
            pages_in: 0,
            failures_out: 0,
            failures_in: 0,
        }
    }
}

// ══════════════════════════════════════════════════════════════
// NumaMigrateStats — global statistics
// ══════════════════════════════════════════════════════════════

/// Global migration statistics.
#[derive(Debug, Clone, Copy)]
pub struct NumaMigrateStats {
    /// Total migration requests submitted.
    pub total_requests: u64,
    /// Total requests completed successfully.
    pub total_completed: u64,
    /// Total requests that failed.
    pub total_failed: u64,
    /// Total pages migrated.
    pub total_pages_migrated: u64,
    /// Total pages that failed migration.
    pub total_pages_failed: u64,
}

impl NumaMigrateStats {
    const fn new() -> Self {
        Self {
            total_requests: 0,
            total_completed: 0,
            total_failed: 0,
            total_pages_migrated: 0,
            total_pages_failed: 0,
        }
    }
}

// ══════════════════════════════════════════════════════════════
// NumaMigrator
// ══════════════════════════════════════════════════════════════

/// Top-level NUMA page migration subsystem.
pub struct NumaMigrator {
    /// Pending and recent migration requests.
    requests: [MigrationRequest; MAX_REQUESTS],
    /// Per-node statistics.
    node_stats: [NodeStats; MAX_NODES],
    /// Global statistics.
    stats: NumaMigrateStats,
    /// Migration rate limit (pages per second).
    rate_limit: u64,
    /// Next request ID.
    next_request_id: u64,
    /// Whether the subsystem is initialised.
    initialised: bool,
}

impl Default for NumaMigrator {
    fn default() -> Self {
        Self::new()
    }
}

impl NumaMigrator {
    /// Create a new NUMA migrator.
    pub const fn new() -> Self {
        Self {
            requests: [const { MigrationRequest::empty() }; MAX_REQUESTS],
            node_stats: [const { NodeStats::new() }; MAX_NODES],
            stats: NumaMigrateStats::new(),
            rate_limit: DEFAULT_RATE_LIMIT,
            next_request_id: 1,
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

    /// Set the migration rate limit.
    pub fn set_rate_limit(&mut self, pages_per_sec: u64) -> Result<()> {
        if pages_per_sec == 0 {
            return Err(Error::InvalidArgument);
        }
        self.rate_limit = pages_per_sec;
        Ok(())
    }

    // ── Migration requests ───────────────────────────────────

    /// Submit a new migration request.
    ///
    /// Returns the request ID.
    pub fn submit(
        &mut self,
        pid: u64,
        source_node: u16,
        dest_node: u16,
        page_count: usize,
        reason: MigrationReason,
    ) -> Result<u64> {
        if (source_node as usize) >= MAX_NODES || (dest_node as usize) >= MAX_NODES {
            return Err(Error::InvalidArgument);
        }
        if source_node == dest_node {
            return Err(Error::InvalidArgument);
        }
        if page_count == 0 || page_count > MAX_PAGES_PER_REQUEST {
            return Err(Error::InvalidArgument);
        }

        let slot = self.find_free_slot()?;
        let request_id = self.next_request_id;
        self.next_request_id += 1;

        self.requests[slot] = MigrationRequest {
            pid,
            source_node,
            dest_node,
            page_count,
            pages_migrated: 0,
            pages_failed: 0,
            state: MigrationState::Queued,
            reason,
            request_id,
        };

        self.stats.total_requests += 1;
        Ok(request_id)
    }

    /// Start processing a queued migration request.
    pub fn start(&mut self, request_id: u64) -> Result<()> {
        let slot = self.find_request(request_id)?;
        if !matches!(self.requests[slot].state, MigrationState::Queued) {
            return Err(Error::InvalidArgument);
        }
        self.requests[slot].state = MigrationState::InProgress;
        Ok(())
    }

    /// Complete a migration request with results.
    pub fn complete(
        &mut self,
        request_id: u64,
        pages_migrated: usize,
        pages_failed: usize,
    ) -> Result<()> {
        let slot = self.find_request(request_id)?;
        if !matches!(self.requests[slot].state, MigrationState::InProgress) {
            return Err(Error::InvalidArgument);
        }

        let src = self.requests[slot].source_node as usize;
        let dst = self.requests[slot].dest_node as usize;

        self.requests[slot].pages_migrated = pages_migrated;
        self.requests[slot].pages_failed = pages_failed;

        if pages_failed == 0 {
            self.requests[slot].state = MigrationState::Completed;
            self.stats.total_completed += 1;
        } else {
            self.requests[slot].state = MigrationState::Failed;
            self.stats.total_failed += 1;
        }

        self.stats.total_pages_migrated += pages_migrated as u64;
        self.stats.total_pages_failed += pages_failed as u64;

        self.node_stats[src].pages_out += pages_migrated as u64;
        self.node_stats[src].failures_out += pages_failed as u64;
        self.node_stats[dst].pages_in += pages_migrated as u64;
        self.node_stats[dst].failures_in += pages_failed as u64;

        Ok(())
    }

    /// Release a completed/failed request slot.
    pub fn release(&mut self, request_id: u64) -> Result<()> {
        let slot = self.find_request(request_id)?;
        if matches!(
            self.requests[slot].state,
            MigrationState::Queued | MigrationState::InProgress
        ) {
            return Err(Error::Busy);
        }
        self.requests[slot] = MigrationRequest::empty();
        Ok(())
    }

    // ── Query ────────────────────────────────────────────────

    /// Return global statistics.
    pub fn stats(&self) -> NumaMigrateStats {
        self.stats
    }

    /// Return per-node statistics.
    pub fn node_stats(&self, node: usize) -> Result<&NodeStats> {
        if node >= MAX_NODES {
            return Err(Error::InvalidArgument);
        }
        Ok(&self.node_stats[node])
    }

    /// Return the number of queued requests.
    pub fn queued_count(&self) -> usize {
        self.requests
            .iter()
            .filter(|r| matches!(r.state, MigrationState::Queued))
            .count()
    }

    /// Return the configured rate limit.
    pub fn rate_limit(&self) -> u64 {
        self.rate_limit
    }

    // ── Internal ─────────────────────────────────────────────

    fn find_free_slot(&self) -> Result<usize> {
        self.requests
            .iter()
            .position(|r| matches!(r.state, MigrationState::Free))
            .ok_or(Error::OutOfMemory)
    }

    fn find_request(&self, request_id: u64) -> Result<usize> {
        self.requests
            .iter()
            .position(|r| r.is_active() && r.request_id == request_id)
            .ok_or(Error::NotFound)
    }
}
