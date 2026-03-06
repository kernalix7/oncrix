// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! NUMA statistics tracking.
//!
//! Maintains per-node and per-zone memory statistics for NUMA-aware
//! allocation and balancing decisions. Counters track allocations,
//! remote accesses, migration events, and memory pressure to guide
//! the NUMA balancer and page placement policies.
//!
//! # Design
//!
//! ```text
//! ┌──────────────┐
//! │  NumaStats    │  global aggregator
//! │              │
//! │ nodes[]──────┼──▶ NodeStats[0]  ← per-node counters
//! │              │    NodeStats[1]
//! │              │    ...
//! │              │    NodeStats[N-1]
//! └──────────────┘
//! ```
//!
//! # Key Types
//!
//! - [`NodeStats`] — per-node allocation and access counters
//! - [`NumaStats`] — aggregator over all NUMA nodes
//! - [`NumaEvent`] — discrete event types for accounting
//!
//! Reference: Linux `mm/vmstat.c`, `include/linux/mmzone.h`.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Maximum supported NUMA nodes.
const MAX_NODES: usize = 16;

/// Maximum zones per node.
const MAX_ZONES_PER_NODE: usize = 4;

// -------------------------------------------------------------------
// NumaEvent
// -------------------------------------------------------------------

/// Types of NUMA events tracked by the statistics engine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NumaEvent {
    /// Page allocated on the local node.
    LocalAlloc,
    /// Page allocated on a remote node.
    RemoteAlloc,
    /// Page migrated to this node.
    MigrateIn,
    /// Page migrated away from this node.
    MigrateOut,
    /// Page fault resolved locally.
    LocalFault,
    /// Page fault resolved remotely.
    RemoteFault,
    /// Interleaved allocation.
    Interleave,
}

impl Default for NumaEvent {
    fn default() -> Self {
        Self::LocalAlloc
    }
}

// -------------------------------------------------------------------
// ZoneStats
// -------------------------------------------------------------------

/// Per-zone counters within a NUMA node.
#[derive(Debug, Clone, Copy)]
pub struct ZoneStats {
    /// Free pages in this zone.
    pub free_pages: u64,
    /// Pages allocated from this zone.
    pub alloc_count: u64,
    /// Pages freed back to this zone.
    pub free_count: u64,
    /// High watermark for this zone.
    pub high_watermark: u64,
    /// Low watermark for this zone.
    pub low_watermark: u64,
}

impl ZoneStats {
    /// Creates new zone stats.
    pub const fn new() -> Self {
        Self {
            free_pages: 0,
            alloc_count: 0,
            free_count: 0,
            high_watermark: 0,
            low_watermark: 0,
        }
    }

    /// Returns `true` if the zone is under pressure.
    pub const fn under_pressure(&self) -> bool {
        self.free_pages < self.low_watermark
    }

    /// Records an allocation.
    pub fn record_alloc(&mut self) {
        self.alloc_count = self.alloc_count.saturating_add(1);
        self.free_pages = self.free_pages.saturating_sub(1);
    }

    /// Records a free.
    pub fn record_free(&mut self) {
        self.free_count = self.free_count.saturating_add(1);
        self.free_pages = self.free_pages.saturating_add(1);
    }
}

impl Default for ZoneStats {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// NodeStats
// -------------------------------------------------------------------

/// Per-node NUMA statistics.
#[derive(Debug, Clone, Copy)]
pub struct NodeStats {
    /// Node identifier.
    node_id: u32,
    /// Local allocations.
    local_allocs: u64,
    /// Remote allocations (from other nodes).
    remote_allocs: u64,
    /// Pages migrated into this node.
    migrate_in: u64,
    /// Pages migrated out of this node.
    migrate_out: u64,
    /// Local page faults.
    local_faults: u64,
    /// Remote page faults.
    remote_faults: u64,
    /// Interleaved allocations.
    interleave_allocs: u64,
    /// Per-zone statistics.
    zones: [ZoneStats; MAX_ZONES_PER_NODE],
    /// Number of active zones.
    nr_zones: usize,
    /// Whether this node is online.
    online: bool,
}

impl NodeStats {
    /// Creates stats for a node.
    pub const fn new(node_id: u32) -> Self {
        Self {
            node_id,
            local_allocs: 0,
            remote_allocs: 0,
            migrate_in: 0,
            migrate_out: 0,
            local_faults: 0,
            remote_faults: 0,
            interleave_allocs: 0,
            zones: [const { ZoneStats::new() }; MAX_ZONES_PER_NODE],
            nr_zones: 0,
            online: false,
        }
    }

    /// Returns the node ID.
    pub const fn node_id(&self) -> u32 {
        self.node_id
    }

    /// Returns total allocations (local + remote).
    pub const fn total_allocs(&self) -> u64 {
        self.local_allocs + self.remote_allocs
    }

    /// Returns the locality ratio (0..100).
    pub const fn locality_percent(&self) -> u64 {
        let total = self.local_allocs + self.remote_allocs;
        if total == 0 {
            return 100;
        }
        self.local_allocs * 100 / total
    }

    /// Returns the number of active zones.
    pub const fn nr_zones(&self) -> usize {
        self.nr_zones
    }

    /// Records an event for this node.
    pub fn record_event(&mut self, event: NumaEvent) {
        match event {
            NumaEvent::LocalAlloc => {
                self.local_allocs = self.local_allocs.saturating_add(1);
            }
            NumaEvent::RemoteAlloc => {
                self.remote_allocs = self.remote_allocs.saturating_add(1);
            }
            NumaEvent::MigrateIn => {
                self.migrate_in = self.migrate_in.saturating_add(1);
            }
            NumaEvent::MigrateOut => {
                self.migrate_out = self.migrate_out.saturating_add(1);
            }
            NumaEvent::LocalFault => {
                self.local_faults = self.local_faults.saturating_add(1);
            }
            NumaEvent::RemoteFault => {
                self.remote_faults = self.remote_faults.saturating_add(1);
            }
            NumaEvent::Interleave => {
                self.interleave_allocs = self.interleave_allocs.saturating_add(1);
            }
        }
    }

    /// Adds a zone with the given free pages and watermarks.
    pub fn add_zone(&mut self, free: u64, low: u64, high: u64) -> Result<()> {
        if self.nr_zones >= MAX_ZONES_PER_NODE {
            return Err(Error::OutOfMemory);
        }
        self.zones[self.nr_zones] = ZoneStats {
            free_pages: free,
            alloc_count: 0,
            free_count: 0,
            high_watermark: high,
            low_watermark: low,
        };
        self.nr_zones += 1;
        Ok(())
    }

    /// Returns the zone stats.
    pub fn zones(&self) -> &[ZoneStats] {
        &self.zones[..self.nr_zones]
    }

    /// Resets all counters.
    pub fn reset(&mut self) {
        self.local_allocs = 0;
        self.remote_allocs = 0;
        self.migrate_in = 0;
        self.migrate_out = 0;
        self.local_faults = 0;
        self.remote_faults = 0;
        self.interleave_allocs = 0;
    }
}

impl Default for NodeStats {
    fn default() -> Self {
        Self::new(0)
    }
}

// -------------------------------------------------------------------
// NumaStats
// -------------------------------------------------------------------

/// Aggregated NUMA statistics across all nodes.
pub struct NumaStats {
    /// Per-node statistics.
    nodes: [NodeStats; MAX_NODES],
    /// Number of online nodes.
    nr_nodes: usize,
}

impl NumaStats {
    /// Creates an empty NUMA stats aggregator.
    pub const fn new() -> Self {
        Self {
            nodes: [const { NodeStats::new(0) }; MAX_NODES],
            nr_nodes: 0,
        }
    }

    /// Registers a NUMA node.
    pub fn register_node(&mut self, node_id: u32) -> Result<()> {
        if self.nr_nodes >= MAX_NODES {
            return Err(Error::OutOfMemory);
        }
        // Check duplicate.
        for i in 0..self.nr_nodes {
            if self.nodes[i].node_id == node_id {
                return Err(Error::AlreadyExists);
            }
        }
        self.nodes[self.nr_nodes] = NodeStats::new(node_id);
        self.nodes[self.nr_nodes].online = true;
        self.nr_nodes += 1;
        Ok(())
    }

    /// Returns the number of online nodes.
    pub const fn nr_nodes(&self) -> usize {
        self.nr_nodes
    }

    /// Returns per-node stats.
    pub fn node_stats(&self) -> &[NodeStats] {
        &self.nodes[..self.nr_nodes]
    }

    /// Records an event for a specific node.
    pub fn record_event(&mut self, node_id: u32, event: NumaEvent) -> Result<()> {
        for i in 0..self.nr_nodes {
            if self.nodes[i].node_id == node_id {
                self.nodes[i].record_event(event);
                return Ok(());
            }
        }
        Err(Error::NotFound)
    }

    /// Returns the global locality ratio across all nodes.
    pub fn global_locality(&self) -> u64 {
        let mut total_local: u64 = 0;
        let mut total_all: u64 = 0;
        for i in 0..self.nr_nodes {
            total_local = total_local.saturating_add(self.nodes[i].local_allocs);
            total_all = total_all.saturating_add(self.nodes[i].total_allocs());
        }
        if total_all == 0 {
            return 100;
        }
        total_local * 100 / total_all
    }

    /// Resets all per-node counters.
    pub fn reset_all(&mut self) {
        for i in 0..self.nr_nodes {
            self.nodes[i].reset();
        }
    }
}

impl Default for NumaStats {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// Public helpers
// -------------------------------------------------------------------

/// Creates a NUMA stats aggregator and registers nodes.
pub fn create_numa_stats(node_ids: &[u32]) -> Result<NumaStats> {
    let mut stats = NumaStats::new();
    for &id in node_ids {
        stats.register_node(id)?;
    }
    Ok(stats)
}

/// Records an event and returns the updated node locality percentage.
pub fn record_and_report(stats: &mut NumaStats, node_id: u32, event: NumaEvent) -> Result<u64> {
    stats.record_event(node_id, event)?;
    Ok(stats.global_locality())
}

/// Returns the global locality ratio.
pub fn global_locality(stats: &NumaStats) -> u64 {
    stats.global_locality()
}
