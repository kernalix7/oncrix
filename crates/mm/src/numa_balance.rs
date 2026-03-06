// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! NUMA balancing and automatic page migration.
//!
//! Tracks per-process NUMA access patterns and automatically migrates
//! pages to the node where they are most frequently accessed. This
//! improves memory locality and reduces cross-node memory latency.
//!
//! - [`NumaFaultType`] — classification of a NUMA page fault
//! - [`NumaFaultInfo`] — recorded fault event with source/destination
//! - [`NumaAccessPattern`] — per-node access histogram for a process
//! - [`NumaMigrateRequest`] — queued page migration descriptor
//! - [`NumaBalancer`] — main balancing engine with pattern tracking
//!   and migration queue

use crate::numa::MAX_NUMA_NODES;
use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Maximum number of per-PID access patterns tracked.
const MAX_PATTERNS: usize = 256;

/// Maximum number of pending migration requests.
const MAX_MIGRATE_QUEUE: usize = 128;

/// Default scan period in milliseconds.
const DEFAULT_SCAN_PERIOD_MS: u64 = 1000;

/// Default minimum faults before considering migration.
const DEFAULT_MIN_FAULTS: u32 = 4;

/// Locality score threshold: above this value, the page is
/// considered well-placed.
const LOCALITY_GOOD_THRESHOLD: u8 = 75;

// -------------------------------------------------------------------
// NumaFaultType
// -------------------------------------------------------------------

/// Classification of a NUMA page fault.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum NumaFaultType {
    /// Access was local to the page's home node.
    #[default]
    Local,
    /// Access was from a remote node.
    Remote,
    /// Access triggered a migration decision.
    Migrate,
    /// Access was local within a task group.
    GroupLocal,
}

// -------------------------------------------------------------------
// NumaFaultInfo
// -------------------------------------------------------------------

/// Recorded NUMA page fault event.
#[derive(Debug, Clone, Copy)]
pub struct NumaFaultInfo {
    /// Process ID that triggered the fault.
    pub pid: u64,
    /// Virtual address that was accessed.
    pub vaddr: u64,
    /// NUMA node where the page currently resides.
    pub from_node: u32,
    /// NUMA node where the access originated.
    pub to_node: u32,
    /// Classification of this fault.
    pub fault_type: NumaFaultType,
    /// Timestamp (e.g. TSC or jiffies) when the fault occurred.
    pub timestamp: u64,
}

// -------------------------------------------------------------------
// NumaAccessPattern
// -------------------------------------------------------------------

/// Per-node access histogram for a single process.
///
/// Tracks how many accesses a process makes from each NUMA node,
/// enabling the balancer to determine the preferred node for that
/// process's pages.
#[derive(Debug, Clone, Copy)]
pub struct NumaAccessPattern {
    /// Node ID this pattern is associated with (or the PID slot index).
    pub node_id: u32,
    /// Per-node access counts (histogram over up to 8 NUMA nodes).
    pub access_count: [u64; MAX_NUMA_NODES],
    /// Sum of all entries in `access_count`.
    pub total_accesses: u64,
    /// Currently computed preferred node.
    pub preferred_node: u32,
}

impl Default for NumaAccessPattern {
    fn default() -> Self {
        Self::empty()
    }
}

impl NumaAccessPattern {
    /// Creates a zeroed access pattern.
    const fn empty() -> Self {
        Self {
            node_id: 0,
            access_count: [0u64; MAX_NUMA_NODES],
            total_accesses: 0,
            preferred_node: 0,
        }
    }

    /// Record an access from `from_node`.
    ///
    /// Out-of-range node IDs are silently ignored.
    pub fn record_access(&mut self, from_node: u32) {
        let idx = from_node as usize;
        if idx >= MAX_NUMA_NODES {
            return;
        }
        self.access_count[idx] = self.access_count[idx].saturating_add(1);
        self.total_accesses = self.total_accesses.saturating_add(1);
    }

    /// Compute and return the preferred node (node with highest
    /// access count).
    ///
    /// Also updates `self.preferred_node` as a side effect.
    pub fn compute_preferred(&mut self) -> u32 {
        let mut best_node: u32 = 0;
        let mut best_count: u64 = 0;

        for (i, &count) in self.access_count.iter().enumerate() {
            if count > best_count {
                best_count = count;
                best_node = i as u32;
            }
        }

        self.preferred_node = best_node;
        best_node
    }

    /// Compute a locality score from 0 to 100.
    ///
    /// Returns the percentage of total accesses that come from the
    /// preferred node. A score of 100 means all accesses are local.
    /// Returns 0 if there have been no accesses.
    pub fn locality_score(&self) -> u8 {
        if self.total_accesses == 0 {
            return 0;
        }
        let preferred_idx = self.preferred_node as usize;
        if preferred_idx >= MAX_NUMA_NODES {
            return 0;
        }
        let preferred_count = self.access_count[preferred_idx];
        // percentage = (preferred_count * 100) / total_accesses
        let score = preferred_count.saturating_mul(100) / self.total_accesses;
        if score > 100 { 100 } else { score as u8 }
    }
}

// -------------------------------------------------------------------
// NumaMigrateRequest
// -------------------------------------------------------------------

/// Queued page migration request.
#[derive(Debug, Clone, Copy)]
pub struct NumaMigrateRequest {
    /// Process ID that owns the page.
    pub pid: u64,
    /// Physical address of the page to migrate.
    pub page_addr: u64,
    /// Source NUMA node.
    pub src_node: u32,
    /// Destination NUMA node.
    pub dst_node: u32,
    /// Migration priority (lower = higher priority).
    pub priority: u8,
}

impl Default for NumaMigrateRequest {
    fn default() -> Self {
        Self::empty()
    }
}

impl NumaMigrateRequest {
    /// Creates a zeroed migration request.
    const fn empty() -> Self {
        Self {
            pid: 0,
            page_addr: 0,
            src_node: 0,
            dst_node: 0,
            priority: 0,
        }
    }
}

// -------------------------------------------------------------------
// NumaBalancer
// -------------------------------------------------------------------

/// NUMA balancing engine.
///
/// Tracks per-PID access patterns and maintains a migration queue.
/// Periodically scans patterns and enqueues migration requests for
/// pages that would benefit from relocation to a more local node.
pub struct NumaBalancer {
    /// Per-PID access patterns (indexed by slot, not PID).
    patterns: [NumaAccessPattern; MAX_PATTERNS],
    /// Number of active pattern entries.
    pattern_count: usize,
    /// PID associated with each pattern slot (0 = unused).
    pattern_pids: [u64; MAX_PATTERNS],
    /// Circular migration request queue.
    migrate_queue: [NumaMigrateRequest; MAX_MIGRATE_QUEUE],
    /// Queue head index (next dequeue position).
    mq_head: usize,
    /// Queue tail index (next enqueue position).
    mq_tail: usize,
    /// Number of entries currently in the queue.
    mq_count: usize,
    /// Scan period in milliseconds.
    scan_period_ms: u64,
    /// Minimum fault count before migration is considered.
    min_faults_for_migrate: u32,
    /// Whether the balancer is active.
    enabled: bool,
}

impl Default for NumaBalancer {
    fn default() -> Self {
        Self::new()
    }
}

impl NumaBalancer {
    /// Creates a new NUMA balancer with default settings.
    pub const fn new() -> Self {
        Self {
            patterns: [NumaAccessPattern::empty(); MAX_PATTERNS],
            pattern_count: 0,
            pattern_pids: [0u64; MAX_PATTERNS],
            migrate_queue: [NumaMigrateRequest::empty(); MAX_MIGRATE_QUEUE],
            mq_head: 0,
            mq_tail: 0,
            mq_count: 0,
            scan_period_ms: DEFAULT_SCAN_PERIOD_MS,
            min_faults_for_migrate: DEFAULT_MIN_FAULTS,
            enabled: true,
        }
    }

    /// Record a NUMA fault, updating the access pattern for the
    /// faulting PID.
    ///
    /// If the PID does not yet have a pattern slot, one is allocated.
    /// If all slots are full, the fault is silently dropped.
    pub fn record_fault(&mut self, info: &NumaFaultInfo) {
        if !self.enabled {
            return;
        }

        let slot = match self.find_or_create_slot(info.pid) {
            Some(s) => s,
            None => return,
        };

        self.patterns[slot].record_access(info.to_node);
    }

    /// Analyze the access pattern for `pid` and suggest a preferred
    /// NUMA node.
    ///
    /// Returns `None` if the PID is not tracked or has insufficient
    /// data (fewer than `min_faults_for_migrate` accesses).
    pub fn analyze_pid(&mut self, pid: u64) -> Option<u32> {
        let slot = self.find_slot(pid)?;
        let pattern = &mut self.patterns[slot];

        if pattern.total_accesses < self.min_faults_for_migrate as u64 {
            return None;
        }

        Some(pattern.compute_preferred())
    }

    /// Enqueue a page migration request.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the migration queue is full.
    pub fn enqueue_migrate(&mut self, req: NumaMigrateRequest) -> Result<()> {
        if self.mq_count >= MAX_MIGRATE_QUEUE {
            return Err(Error::OutOfMemory);
        }
        self.migrate_queue[self.mq_tail] = req;
        self.mq_tail = (self.mq_tail + 1) % MAX_MIGRATE_QUEUE;
        self.mq_count += 1;
        Ok(())
    }

    /// Dequeue the next pending migration request.
    ///
    /// Returns `None` if the queue is empty.
    pub fn dequeue_migrate(&mut self) -> Option<NumaMigrateRequest> {
        if self.mq_count == 0 {
            return None;
        }
        let req = self.migrate_queue[self.mq_head];
        self.mq_head = (self.mq_head + 1) % MAX_MIGRATE_QUEUE;
        self.mq_count -= 1;
        Some(req)
    }

    /// Scan all tracked patterns and enqueue migration requests for
    /// processes whose pages are not on their preferred node.
    ///
    /// Only processes with sufficient access data and poor locality
    /// (score below [`LOCALITY_GOOD_THRESHOLD`]) are considered.
    pub fn scan_and_balance(&mut self) {
        if !self.enabled {
            return;
        }

        for i in 0..self.pattern_count {
            let pid = self.pattern_pids[i];
            if pid == 0 {
                continue;
            }

            let pattern = &mut self.patterns[i];

            if pattern.total_accesses < self.min_faults_for_migrate as u64 {
                continue;
            }

            let preferred = pattern.compute_preferred();
            let score = pattern.locality_score();

            // Only migrate if locality is poor.
            if score >= LOCALITY_GOOD_THRESHOLD {
                continue;
            }

            // The current node_id field tracks where pages currently
            // reside. If preferred differs, enqueue a migration.
            if pattern.node_id == preferred {
                continue;
            }

            let req = NumaMigrateRequest {
                pid,
                page_addr: 0, // Stub: real implementation resolves pages.
                src_node: pattern.node_id,
                dst_node: preferred,
                priority: 100_u8.saturating_sub(score),
            };

            // Best-effort: ignore full-queue errors during scan.
            let _ = self.enqueue_migrate(req);
        }
    }

    /// Set the scan period in milliseconds.
    pub fn set_scan_period(&mut self, ms: u64) {
        self.scan_period_ms = ms;
    }

    /// Set the minimum number of faults required before considering
    /// migration.
    pub fn set_min_faults(&mut self, n: u32) {
        self.min_faults_for_migrate = n;
    }

    /// Enable the NUMA balancer.
    pub fn enable(&mut self) {
        self.enabled = true;
    }

    /// Disable the NUMA balancer.
    pub fn disable(&mut self) {
        self.enabled = false;
    }

    /// Get the access pattern for a specific PID.
    ///
    /// Returns `None` if the PID is not tracked.
    pub fn get_pattern(&self, pid: u64) -> Option<&NumaAccessPattern> {
        let slot = self.find_slot(pid)?;
        Some(&self.patterns[slot])
    }

    /// Returns summary statistics.
    ///
    /// Returns `(migrations_pending, patterns_tracked)`.
    pub fn stats(&self) -> (usize, usize) {
        (self.mq_count, self.pattern_count)
    }

    /// Returns the current scan period in milliseconds.
    pub fn scan_period(&self) -> u64 {
        self.scan_period_ms
    }

    /// Returns whether the balancer is enabled.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    // ---------------------------------------------------------------
    // Internal helpers
    // ---------------------------------------------------------------

    /// Find the pattern slot for `pid`, or `None` if not tracked.
    fn find_slot(&self, pid: u64) -> Option<usize> {
        self.pattern_pids[..self.pattern_count]
            .iter()
            .position(|&p| p == pid)
    }

    /// Find the pattern slot for `pid`, allocating a new one if the
    /// PID is not yet tracked. Returns `None` if there are no free
    /// slots.
    fn find_or_create_slot(&mut self, pid: u64) -> Option<usize> {
        // Check existing slots first.
        if let Some(slot) = self.find_slot(pid) {
            return Some(slot);
        }
        // Allocate a new slot if space remains.
        if self.pattern_count >= MAX_PATTERNS {
            return None;
        }
        let slot = self.pattern_count;
        self.pattern_pids[slot] = pid;
        self.patterns[slot] = NumaAccessPattern::empty();
        self.pattern_count += 1;
        Some(slot)
    }
}
