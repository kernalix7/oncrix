// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Memory tiering subsystem.
//!
//! Provides infrastructure for managing heterogeneous memory types
//! (DRAM, CXL, PMEM) organized into tiers ordered by performance.
//! Pages can be promoted to faster tiers or demoted to slower tiers
//! based on access frequency, memory pressure, and tier capacity.
//!
//! This builds on the NUMA topology (`crate::numa`) for node-level
//! allocation and the page migration engine (`crate::migrate`) for
//! physically moving pages between tiers.
//!
//! # Architecture
//!
//! - [`MemoryTierType`] — classification of memory media
//! - [`TierNode`] — a NUMA node with tier metadata (latency, bandwidth)
//! - [`MemoryTier`] — a tier containing one or more nodes of similar
//!   performance
//! - [`MigrationPath`] — directional promotion/demotion path between
//!   tiers
//! - [`TierMigrationRequest`] — request to move a page between tiers
//! - [`TierStats`] — per-tier and aggregate statistics
//! - [`TierRegistry`] — central registry managing all tiers and
//!   migration paths
//!
//! Reference: Linux `mm/memory-tiers.c`, `include/linux/memory-tiers.h`.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Maximum number of memory tiers.
const MAX_TIERS: usize = 8;

/// Maximum number of nodes per tier.
const MAX_NODES_PER_TIER: usize = 16;

/// Maximum number of migration paths.
const MAX_MIGRATION_PATHS: usize = 16;

/// Maximum pending migration requests.
const MAX_MIGRATION_REQUESTS: usize = 256;

/// Default promotion threshold (access count above which a page is
/// promoted to a faster tier).
const DEFAULT_PROMOTE_THRESHOLD: u64 = 16;

/// Default demotion threshold (idle cycles after which a page is
/// demoted to a slower tier).
const DEFAULT_DEMOTE_THRESHOLD: u64 = 64;

/// Standard page size in bytes (4 KiB).
const PAGE_SIZE: u64 = 4096;

// -------------------------------------------------------------------
// MemoryTierType
// -------------------------------------------------------------------

/// Classification of the physical memory medium backing a tier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum MemoryTierType {
    /// Dynamic Random-Access Memory — fastest, most expensive.
    #[default]
    Dram,
    /// High Bandwidth Memory — GPU/accelerator attached.
    Hbm,
    /// Compute Express Link attached memory — lower latency than
    /// PMEM, higher capacity than DRAM.
    Cxl,
    /// Persistent Memory (e.g., Intel Optane) — byte-addressable
    /// NVRAM with higher latency than DRAM.
    Pmem,
}

// -------------------------------------------------------------------
// TierNode
// -------------------------------------------------------------------

/// A NUMA node associated with a specific memory tier.
///
/// Each node has performance characteristics (latency, bandwidth)
/// and capacity tracking. Multiple nodes of similar performance
/// can belong to the same tier.
#[derive(Debug, Clone, Copy)]
pub struct TierNode {
    /// NUMA node identifier.
    pub node_id: u8,
    /// Read latency in nanoseconds.
    pub read_latency_ns: u32,
    /// Write latency in nanoseconds.
    pub write_latency_ns: u32,
    /// Read bandwidth in MiB/s.
    pub read_bandwidth_mbs: u32,
    /// Write bandwidth in MiB/s.
    pub write_bandwidth_mbs: u32,
    /// Total capacity of this node in pages.
    pub total_pages: u64,
    /// Currently used pages on this node.
    pub used_pages: u64,
    /// Whether this node slot is active.
    pub active: bool,
}

impl TierNode {
    /// Creates an empty, inactive node slot.
    const fn empty() -> Self {
        Self {
            node_id: 0,
            read_latency_ns: 0,
            write_latency_ns: 0,
            read_bandwidth_mbs: 0,
            write_bandwidth_mbs: 0,
            total_pages: 0,
            used_pages: 0,
            active: false,
        }
    }

    /// Returns the number of free pages on this node.
    pub const fn free_pages(&self) -> u64 {
        self.total_pages.saturating_sub(self.used_pages)
    }

    /// Returns `true` if the node has available capacity.
    pub const fn has_capacity(&self) -> bool {
        self.used_pages < self.total_pages
    }
}

// -------------------------------------------------------------------
// MemoryTier
// -------------------------------------------------------------------

/// A memory tier grouping nodes with similar performance
/// characteristics.
///
/// Tiers are ordered by `rank` (lower rank = faster/closer memory).
/// DRAM is typically rank 0, CXL rank 1, PMEM rank 2.
#[derive(Debug, Clone, Copy)]
pub struct MemoryTier {
    /// Unique tier identifier.
    pub id: u8,
    /// Performance rank (0 = fastest).
    pub rank: u8,
    /// Type of memory medium.
    pub tier_type: MemoryTierType,
    /// Nodes belonging to this tier.
    pub nodes: [TierNode; MAX_NODES_PER_TIER],
    /// Number of active nodes in this tier.
    pub node_count: usize,
    /// Total pages across all nodes in this tier.
    pub total_pages: u64,
    /// Total used pages across all nodes.
    pub used_pages: u64,
    /// Whether this tier slot is active.
    pub active: bool,
}

impl MemoryTier {
    /// Creates an empty, inactive tier slot.
    const fn empty() -> Self {
        Self {
            id: 0,
            rank: 0,
            tier_type: MemoryTierType::Dram,
            nodes: [TierNode::empty(); MAX_NODES_PER_TIER],
            node_count: 0,
            total_pages: 0,
            used_pages: 0,
            active: false,
        }
    }

    /// Returns the total free pages across all nodes.
    pub const fn free_pages(&self) -> u64 {
        self.total_pages.saturating_sub(self.used_pages)
    }

    /// Returns the utilization ratio as a percentage (0-100).
    pub fn utilization_pct(&self) -> u8 {
        if self.total_pages == 0 {
            return 0;
        }
        let pct = self.used_pages.saturating_mul(100) / self.total_pages;
        if pct > 100 { 100 } else { pct as u8 }
    }

    /// Adds a node to this tier.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the tier has no free node
    /// slots.
    /// Returns [`Error::AlreadyExists`] if the node ID is already
    /// present.
    fn add_node(&mut self, node: TierNode) -> Result<()> {
        // Check for duplicate node ID.
        for i in 0..self.node_count {
            if self.nodes[i].active && self.nodes[i].node_id == node.node_id {
                return Err(Error::AlreadyExists);
            }
        }
        if self.node_count >= MAX_NODES_PER_TIER {
            return Err(Error::OutOfMemory);
        }
        self.nodes[self.node_count] = node;
        self.nodes[self.node_count].active = true;
        self.node_count += 1;
        self.total_pages = self.total_pages.saturating_add(node.total_pages);
        self.used_pages = self.used_pages.saturating_add(node.used_pages);
        Ok(())
    }

    /// Removes a node from this tier by NUMA node ID.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the node is not in this tier.
    fn remove_node(&mut self, node_id: u8) -> Result<()> {
        let pos = (0..self.node_count)
            .find(|&i| self.nodes[i].active && self.nodes[i].node_id == node_id)
            .ok_or(Error::NotFound)?;

        let removed = self.nodes[pos];
        self.total_pages = self.total_pages.saturating_sub(removed.total_pages);
        self.used_pages = self.used_pages.saturating_sub(removed.used_pages);

        // Swap-remove.
        self.node_count -= 1;
        if pos < self.node_count {
            self.nodes[pos] = self.nodes[self.node_count];
        }
        self.nodes[self.node_count] = TierNode::empty();
        Ok(())
    }

    /// Selects the best node in this tier for demotion target
    /// (most free capacity).
    fn best_demotion_target(&self) -> Option<u8> {
        let mut best_id: Option<u8> = None;
        let mut best_free: u64 = 0;

        for i in 0..self.node_count {
            let node = &self.nodes[i];
            if !node.active {
                continue;
            }
            let free = node.free_pages();
            if free > best_free {
                best_free = free;
                best_id = Some(node.node_id);
            }
        }
        best_id
    }
}

// -------------------------------------------------------------------
// MigrationDirection
// -------------------------------------------------------------------

/// Direction of a tier migration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum MigrationDirection {
    /// Move page to a faster tier (lower rank).
    #[default]
    Promote,
    /// Move page to a slower tier (higher rank).
    Demote,
}

// -------------------------------------------------------------------
// MigrationPath
// -------------------------------------------------------------------

/// A directional migration path between two tiers.
///
/// Paths define valid promotion and demotion routes. For example,
/// DRAM (tier 0) <-> CXL (tier 1) <-> PMEM (tier 2).
#[derive(Debug, Clone, Copy)]
pub struct MigrationPath {
    /// Source tier ID.
    pub src_tier: u8,
    /// Destination tier ID.
    pub dst_tier: u8,
    /// Direction of this path.
    pub direction: MigrationDirection,
    /// Whether this path is enabled.
    pub enabled: bool,
}

impl MigrationPath {
    /// Creates an empty, disabled path.
    const fn empty() -> Self {
        Self {
            src_tier: 0,
            dst_tier: 0,
            direction: MigrationDirection::Promote,
            enabled: false,
        }
    }
}

// -------------------------------------------------------------------
// TierMigrationStatus
// -------------------------------------------------------------------

/// Status of a tier migration request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TierMigrationStatus {
    /// Request is queued and waiting to be processed.
    #[default]
    Pending,
    /// Migration completed successfully.
    Success,
    /// Migration failed (no capacity, page pinned, etc.).
    Failed,
}

// -------------------------------------------------------------------
// TierMigrationRequest
// -------------------------------------------------------------------

/// A request to migrate a page between memory tiers.
#[derive(Debug, Clone, Copy)]
pub struct TierMigrationRequest {
    /// Physical frame number of the page.
    pub pfn: u64,
    /// Source tier ID.
    pub src_tier: u8,
    /// Destination tier ID.
    pub dst_tier: u8,
    /// Direction (promote or demote).
    pub direction: MigrationDirection,
    /// Number of access hits (for promotion decisions).
    pub access_count: u64,
    /// Number of idle cycles (for demotion decisions).
    pub idle_cycles: u64,
    /// Current status.
    pub status: TierMigrationStatus,
}

impl TierMigrationRequest {
    /// Creates an empty, pending request.
    const fn empty() -> Self {
        Self {
            pfn: 0,
            src_tier: 0,
            dst_tier: 0,
            direction: MigrationDirection::Promote,
            access_count: 0,
            idle_cycles: 0,
            status: TierMigrationStatus::Pending,
        }
    }
}

// -------------------------------------------------------------------
// TierStats
// -------------------------------------------------------------------

/// Aggregate and per-tier migration statistics.
#[derive(Debug, Clone, Copy, Default)]
pub struct TierStats {
    /// Total promotion attempts.
    pub promotions_attempted: u64,
    /// Successful promotions.
    pub promotions_succeeded: u64,
    /// Failed promotions (no capacity in target tier, etc.).
    pub promotions_failed: u64,
    /// Total demotion attempts.
    pub demotions_attempted: u64,
    /// Successful demotions.
    pub demotions_succeeded: u64,
    /// Failed demotions.
    pub demotions_failed: u64,
    /// Total pages migrated (bytes = pages * PAGE_SIZE).
    pub pages_migrated: u64,
}

// -------------------------------------------------------------------
// TierRegistry
// -------------------------------------------------------------------

/// Central registry managing all memory tiers, migration paths,
/// and pending migration requests.
///
/// The registry enforces tier ordering by rank, validates migration
/// paths, and processes promotion/demotion requests.
pub struct TierRegistry {
    /// Registered memory tiers.
    tiers: [MemoryTier; MAX_TIERS],
    /// Number of active tiers.
    tier_count: usize,
    /// Migration paths between tiers.
    paths: [MigrationPath; MAX_MIGRATION_PATHS],
    /// Number of active paths.
    path_count: usize,
    /// Pending migration requests.
    requests: [TierMigrationRequest; MAX_MIGRATION_REQUESTS],
    /// Number of pending requests.
    request_count: usize,
    /// Promotion threshold (access count).
    promote_threshold: u64,
    /// Demotion threshold (idle cycles).
    demote_threshold: u64,
    /// Aggregate statistics.
    stats: TierStats,
}

impl Default for TierRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl TierRegistry {
    /// Creates a new, empty tier registry with default thresholds.
    pub const fn new() -> Self {
        Self {
            tiers: [MemoryTier::empty(); MAX_TIERS],
            tier_count: 0,
            paths: [MigrationPath::empty(); MAX_MIGRATION_PATHS],
            path_count: 0,
            requests: [TierMigrationRequest::empty(); MAX_MIGRATION_REQUESTS],
            request_count: 0,
            promote_threshold: DEFAULT_PROMOTE_THRESHOLD,
            demote_threshold: DEFAULT_DEMOTE_THRESHOLD,
            stats: TierStats {
                promotions_attempted: 0,
                promotions_succeeded: 0,
                promotions_failed: 0,
                demotions_attempted: 0,
                demotions_succeeded: 0,
                demotions_failed: 0,
                pages_migrated: 0,
            },
        }
    }

    // ---------------------------------------------------------------
    // Tier management
    // ---------------------------------------------------------------

    /// Registers a new memory tier.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if all tier slots are full.
    /// Returns [`Error::AlreadyExists`] if a tier with the same ID
    /// already exists.
    pub fn register_tier(&mut self, id: u8, rank: u8, tier_type: MemoryTierType) -> Result<()> {
        if self.tier_count >= MAX_TIERS {
            return Err(Error::OutOfMemory);
        }
        // Check for duplicate ID.
        if self.find_tier_index(id).is_some() {
            return Err(Error::AlreadyExists);
        }

        let slot = self
            .tiers
            .iter_mut()
            .find(|t| !t.active)
            .ok_or(Error::OutOfMemory)?;

        *slot = MemoryTier::empty();
        slot.id = id;
        slot.rank = rank;
        slot.tier_type = tier_type;
        slot.active = true;

        self.tier_count += 1;
        Ok(())
    }

    /// Unregisters a memory tier by ID.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if no tier with the given ID
    /// exists.
    /// Returns [`Error::Busy`] if the tier still has nodes attached.
    pub fn unregister_tier(&mut self, id: u8) -> Result<()> {
        let idx = self.find_tier_index(id).ok_or(Error::NotFound)?;
        if self.tiers[idx].node_count > 0 {
            return Err(Error::Busy);
        }
        self.tiers[idx].active = false;
        self.tier_count = self.tier_count.saturating_sub(1);
        Ok(())
    }

    /// Adds a NUMA node to a tier.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the tier does not exist.
    /// Returns [`Error::OutOfMemory`] if the tier has no free node
    /// slots.
    /// Returns [`Error::AlreadyExists`] if the node is already in
    /// the tier.
    pub fn add_node_to_tier(&mut self, tier_id: u8, node: TierNode) -> Result<()> {
        let idx = self.find_tier_index(tier_id).ok_or(Error::NotFound)?;
        self.tiers[idx].add_node(node)
    }

    /// Removes a NUMA node from a tier.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the tier or node does not exist.
    pub fn remove_node_from_tier(&mut self, tier_id: u8, node_id: u8) -> Result<()> {
        let idx = self.find_tier_index(tier_id).ok_or(Error::NotFound)?;
        self.tiers[idx].remove_node(node_id)
    }

    // ---------------------------------------------------------------
    // Migration path management
    // ---------------------------------------------------------------

    /// Registers a migration path between two tiers.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if all path slots are full.
    /// Returns [`Error::NotFound`] if either tier does not exist.
    /// Returns [`Error::InvalidArgument`] if `src_tier == dst_tier`.
    pub fn add_migration_path(
        &mut self,
        src_tier: u8,
        dst_tier: u8,
        direction: MigrationDirection,
    ) -> Result<()> {
        if src_tier == dst_tier {
            return Err(Error::InvalidArgument);
        }
        if self.find_tier_index(src_tier).is_none() {
            return Err(Error::NotFound);
        }
        if self.find_tier_index(dst_tier).is_none() {
            return Err(Error::NotFound);
        }
        if self.path_count >= MAX_MIGRATION_PATHS {
            return Err(Error::OutOfMemory);
        }

        let slot = self
            .paths
            .iter_mut()
            .find(|p| !p.enabled)
            .ok_or(Error::OutOfMemory)?;

        *slot = MigrationPath {
            src_tier,
            dst_tier,
            direction,
            enabled: true,
        };

        self.path_count += 1;
        Ok(())
    }

    /// Disables a migration path between two tiers.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if no matching path exists.
    pub fn remove_migration_path(
        &mut self,
        src_tier: u8,
        dst_tier: u8,
        direction: MigrationDirection,
    ) -> Result<()> {
        let path = self.paths[..MAX_MIGRATION_PATHS]
            .iter_mut()
            .find(|p| {
                p.enabled
                    && p.src_tier == src_tier
                    && p.dst_tier == dst_tier
                    && p.direction == direction
            })
            .ok_or(Error::NotFound)?;

        path.enabled = false;
        self.path_count = self.path_count.saturating_sub(1);
        Ok(())
    }

    // ---------------------------------------------------------------
    // Demotion target selection
    // ---------------------------------------------------------------

    /// Selects the best demotion target tier for pages in the given
    /// tier.
    ///
    /// Walks registered demotion paths and returns the tier ID with
    /// the most available capacity among valid demotion targets.
    ///
    /// Returns `None` if no valid demotion target exists.
    pub fn select_demotion_target(&self, src_tier: u8) -> Option<u8> {
        let mut best_tier: Option<u8> = None;
        let mut best_free: u64 = 0;

        for path in &self.paths[..MAX_MIGRATION_PATHS] {
            if !path.enabled {
                continue;
            }
            if path.src_tier != src_tier {
                continue;
            }
            if path.direction != MigrationDirection::Demote {
                continue;
            }
            if let Some(idx) = self.find_tier_index(path.dst_tier) {
                let free = self.tiers[idx].free_pages();
                if free > best_free {
                    best_free = free;
                    best_tier = Some(path.dst_tier);
                }
            }
        }
        best_tier
    }

    /// Selects the best promotion target tier for pages in the given
    /// tier.
    ///
    /// Returns `None` if no valid promotion target exists.
    pub fn select_promotion_target(&self, src_tier: u8) -> Option<u8> {
        let mut best_tier: Option<u8> = None;
        let mut best_rank: u8 = u8::MAX;

        for path in &self.paths[..MAX_MIGRATION_PATHS] {
            if !path.enabled {
                continue;
            }
            if path.src_tier != src_tier {
                continue;
            }
            if path.direction != MigrationDirection::Promote {
                continue;
            }
            if let Some(idx) = self.find_tier_index(path.dst_tier) {
                let tier = &self.tiers[idx];
                if tier.free_pages() > 0 && tier.rank < best_rank {
                    best_rank = tier.rank;
                    best_tier = Some(path.dst_tier);
                }
            }
        }
        best_tier
    }

    /// Finds the demotion target node within a destination tier.
    ///
    /// Returns the NUMA node ID with the most free capacity in the
    /// target tier, or `None` if the tier has no available nodes.
    pub fn demotion_target_node(&self, dst_tier: u8) -> Option<u8> {
        let idx = self.find_tier_index(dst_tier)?;
        self.tiers[idx].best_demotion_target()
    }

    // ---------------------------------------------------------------
    // Migration request management
    // ---------------------------------------------------------------

    /// Queues a promotion request for a page.
    ///
    /// The page at `pfn` in `src_tier` will be promoted to the best
    /// available faster tier.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the request queue is full.
    /// Returns [`Error::NotFound`] if no promotion target exists.
    pub fn request_promote(&mut self, pfn: u64, src_tier: u8, access_count: u64) -> Result<()> {
        let dst_tier = self
            .select_promotion_target(src_tier)
            .ok_or(Error::NotFound)?;

        self.enqueue_request(TierMigrationRequest {
            pfn,
            src_tier,
            dst_tier,
            direction: MigrationDirection::Promote,
            access_count,
            idle_cycles: 0,
            status: TierMigrationStatus::Pending,
        })
    }

    /// Queues a demotion request for a page.
    ///
    /// The page at `pfn` in `src_tier` will be demoted to the best
    /// available slower tier.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the request queue is full.
    /// Returns [`Error::NotFound`] if no demotion target exists.
    pub fn request_demote(&mut self, pfn: u64, src_tier: u8, idle_cycles: u64) -> Result<()> {
        let dst_tier = self
            .select_demotion_target(src_tier)
            .ok_or(Error::NotFound)?;

        self.enqueue_request(TierMigrationRequest {
            pfn,
            src_tier,
            dst_tier,
            direction: MigrationDirection::Demote,
            access_count: 0,
            idle_cycles,
            status: TierMigrationStatus::Pending,
        })
    }

    /// Processes all pending migration requests.
    ///
    /// For each pending request, checks whether the destination tier
    /// has capacity. If so, marks the request as successful and
    /// updates page counts. Otherwise, marks it as failed.
    ///
    /// Returns `(promoted, demoted, failed)`.
    pub fn process_requests(&mut self) -> (usize, usize, usize) {
        let mut promoted = 0_usize;
        let mut demoted = 0_usize;
        let mut failed = 0_usize;

        for i in 0..self.request_count {
            let req = &self.requests[i];
            if req.status != TierMigrationStatus::Pending {
                continue;
            }

            let dst_tier_id = req.dst_tier;
            let src_tier_id = req.src_tier;
            let direction = req.direction;

            // Check destination capacity.
            let dst_has_capacity = self
                .find_tier_index(dst_tier_id)
                .map(|idx| self.tiers[idx].free_pages() > 0)
                .unwrap_or(false);

            if !dst_has_capacity {
                self.requests[i].status = TierMigrationStatus::Failed;
                match direction {
                    MigrationDirection::Promote => {
                        self.stats.promotions_attempted += 1;
                        self.stats.promotions_failed += 1;
                    }
                    MigrationDirection::Demote => {
                        self.stats.demotions_attempted += 1;
                        self.stats.demotions_failed += 1;
                    }
                }
                failed += 1;
                continue;
            }

            // Simulate the migration: decrement source, increment
            // destination.
            if let Some(src_idx) = self.find_tier_index(src_tier_id) {
                self.tiers[src_idx].used_pages = self.tiers[src_idx].used_pages.saturating_sub(1);
            }
            if let Some(dst_idx) = self.find_tier_index(dst_tier_id) {
                self.tiers[dst_idx].used_pages = self.tiers[dst_idx].used_pages.saturating_add(1);
            }

            self.requests[i].status = TierMigrationStatus::Success;
            self.stats.pages_migrated += 1;

            match direction {
                MigrationDirection::Promote => {
                    self.stats.promotions_attempted += 1;
                    self.stats.promotions_succeeded += 1;
                    promoted += 1;
                }
                MigrationDirection::Demote => {
                    self.stats.demotions_attempted += 1;
                    self.stats.demotions_succeeded += 1;
                    demoted += 1;
                }
            }
        }

        (promoted, demoted, failed)
    }

    /// Clears all completed and failed requests from the queue.
    pub fn drain_completed(&mut self) {
        let mut write = 0_usize;
        for read in 0..self.request_count {
            if self.requests[read].status == TierMigrationStatus::Pending {
                if write != read {
                    self.requests[write] = self.requests[read];
                }
                write += 1;
            }
        }
        // Zero out remaining slots.
        for i in write..self.request_count {
            self.requests[i] = TierMigrationRequest::empty();
        }
        self.request_count = write;
    }

    // ---------------------------------------------------------------
    // Threshold configuration
    // ---------------------------------------------------------------

    /// Sets the promotion threshold (access count).
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `threshold` is zero.
    pub fn set_promote_threshold(&mut self, threshold: u64) -> Result<()> {
        if threshold == 0 {
            return Err(Error::InvalidArgument);
        }
        self.promote_threshold = threshold;
        Ok(())
    }

    /// Sets the demotion threshold (idle cycles).
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `threshold` is zero.
    pub fn set_demote_threshold(&mut self, threshold: u64) -> Result<()> {
        if threshold == 0 {
            return Err(Error::InvalidArgument);
        }
        self.demote_threshold = threshold;
        Ok(())
    }

    /// Returns the current promotion threshold.
    pub const fn promote_threshold(&self) -> u64 {
        self.promote_threshold
    }

    /// Returns the current demotion threshold.
    pub const fn demote_threshold(&self) -> u64 {
        self.demote_threshold
    }

    // ---------------------------------------------------------------
    // Accessors
    // ---------------------------------------------------------------

    /// Returns the number of registered tiers.
    pub const fn tier_count(&self) -> usize {
        self.tier_count
    }

    /// Returns a reference to a tier by ID.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if no tier with the given ID
    /// exists.
    pub fn get_tier(&self, id: u8) -> Result<&MemoryTier> {
        let idx = self.find_tier_index(id).ok_or(Error::NotFound)?;
        Ok(&self.tiers[idx])
    }

    /// Returns the number of pending migration requests.
    pub const fn pending_requests(&self) -> usize {
        self.request_count
    }

    /// Returns the number of registered migration paths.
    pub const fn path_count(&self) -> usize {
        self.path_count
    }

    /// Returns aggregate statistics.
    pub const fn stats(&self) -> &TierStats {
        &self.stats
    }

    /// Returns the total pages migrated (in bytes).
    pub const fn migrated_bytes(&self) -> u64 {
        self.stats.pages_migrated.saturating_mul(PAGE_SIZE)
    }

    /// Checks whether a page should be promoted based on access
    /// count.
    pub const fn should_promote(&self, access_count: u64) -> bool {
        access_count >= self.promote_threshold
    }

    /// Checks whether a page should be demoted based on idle cycles.
    pub const fn should_demote(&self, idle_cycles: u64) -> bool {
        idle_cycles >= self.demote_threshold
    }

    /// Returns the tier ID for a given rank, if one exists.
    pub fn tier_for_rank(&self, rank: u8) -> Option<u8> {
        for tier in &self.tiers {
            if tier.active && tier.rank == rank {
                return Some(tier.id);
            }
        }
        None
    }

    /// Returns `true` if the registry has no registered tiers.
    pub const fn is_empty(&self) -> bool {
        self.tier_count == 0
    }

    // ---------------------------------------------------------------
    // Internal helpers
    // ---------------------------------------------------------------

    /// Finds the array index of a tier by ID.
    fn find_tier_index(&self, id: u8) -> Option<usize> {
        self.tiers.iter().position(|t| t.active && t.id == id)
    }

    /// Enqueues a migration request.
    fn enqueue_request(&mut self, req: TierMigrationRequest) -> Result<()> {
        if self.request_count >= MAX_MIGRATION_REQUESTS {
            return Err(Error::OutOfMemory);
        }
        self.requests[self.request_count] = req;
        self.request_count += 1;
        Ok(())
    }
}
