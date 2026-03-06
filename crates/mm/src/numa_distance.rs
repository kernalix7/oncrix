// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! NUMA distance matrix and topology.
//!
//! NUMA (Non-Uniform Memory Access) systems have varying memory access
//! latencies depending on which CPU accesses which memory node. The
//! firmware (ACPI SLIT) provides a distance matrix that the kernel uses
//! for placement decisions. This module parses, stores, and queries the
//! distance matrix and derives the sorted fallback order for each node.
//!
//! # Design
//!
//! ```text
//!  ACPI SLIT → NumaDistanceMatrix::init(distances)
//!
//!  alloc_pages(node=2, gfp)
//!       └─ NumaDistanceMatrix::fallback_order(2) → [2, 1, 3, 0]
//!            → try node 2 first, then nearest neighbours
//! ```
//!
//! # Key Types
//!
//! - [`NumaDistanceMatrix`] — the N×N distance matrix
//! - [`NodeInfo`] — per-node metadata
//! - [`FallbackOrder`] — sorted fallback allocation order
//! - [`NumaTopologyStats`] — topology statistics
//!
//! Reference: Linux `drivers/acpi/numa/slit.c`, `mm/mempolicy.c`.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Maximum NUMA nodes.
const MAX_NODES: usize = 16;

/// Distance to self (ACPI SLIT local distance).
const LOCAL_DISTANCE: u8 = 10;

/// Distance indicating unreachable / not connected.
const REMOTE_DISTANCE_MAX: u8 = 255;

/// Threshold for "near" nodes.
const NEAR_THRESHOLD: u8 = 20;

// -------------------------------------------------------------------
// NodeInfo
// -------------------------------------------------------------------

/// Per-NUMA-node metadata.
#[derive(Debug, Clone, Copy)]
pub struct NodeInfo {
    /// Node identifier.
    node_id: u8,
    /// Whether this node is online.
    online: bool,
    /// Total memory on this node (pages).
    total_pages: u64,
    /// Free memory on this node (pages).
    free_pages: u64,
    /// Number of CPUs on this node.
    nr_cpus: u32,
}

impl NodeInfo {
    /// Create a new node info.
    pub const fn new(node_id: u8, total_pages: u64, nr_cpus: u32) -> Self {
        Self {
            node_id,
            online: true,
            total_pages,
            free_pages: total_pages,
            nr_cpus,
        }
    }

    /// Return the node identifier.
    pub const fn node_id(&self) -> u8 {
        self.node_id
    }

    /// Check whether the node is online.
    pub const fn is_online(&self) -> bool {
        self.online
    }

    /// Return total memory in pages.
    pub const fn total_pages(&self) -> u64 {
        self.total_pages
    }

    /// Return free memory in pages.
    pub const fn free_pages(&self) -> u64 {
        self.free_pages
    }

    /// Return the number of CPUs.
    pub const fn nr_cpus(&self) -> u32 {
        self.nr_cpus
    }

    /// Set the free page count.
    pub fn set_free_pages(&mut self, count: u64) {
        self.free_pages = count;
    }

    /// Take the node offline.
    pub fn set_offline(&mut self) {
        self.online = false;
    }
}

impl Default for NodeInfo {
    fn default() -> Self {
        Self {
            node_id: 0,
            online: false,
            total_pages: 0,
            free_pages: 0,
            nr_cpus: 0,
        }
    }
}

// -------------------------------------------------------------------
// FallbackOrder
// -------------------------------------------------------------------

/// Sorted fallback allocation order for a given node.
#[derive(Debug, Clone, Copy)]
pub struct FallbackOrder {
    /// Source node.
    source: u8,
    /// Ordered list of target nodes (nearest first).
    order: [u8; MAX_NODES],
    /// Number of valid entries.
    count: usize,
}

impl FallbackOrder {
    /// Create an empty fallback order.
    pub const fn new(source: u8) -> Self {
        Self {
            source,
            order: [0u8; MAX_NODES],
            count: 0,
        }
    }

    /// Return the source node.
    pub const fn source(&self) -> u8 {
        self.source
    }

    /// Return the number of fallback entries.
    pub const fn count(&self) -> usize {
        self.count
    }

    /// Get the nth fallback node.
    pub fn get(&self, index: usize) -> Result<u8> {
        if index >= self.count {
            return Err(Error::InvalidArgument);
        }
        Ok(self.order[index])
    }

    /// Push a node onto the order.
    fn push(&mut self, node: u8) {
        if self.count < MAX_NODES {
            self.order[self.count] = node;
            self.count += 1;
        }
    }
}

impl Default for FallbackOrder {
    fn default() -> Self {
        Self::new(0)
    }
}

// -------------------------------------------------------------------
// NumaTopologyStats
// -------------------------------------------------------------------

/// NUMA topology statistics.
#[derive(Debug, Clone, Copy)]
pub struct NumaTopologyStats {
    /// Number of online nodes.
    pub online_nodes: u32,
    /// Total system memory (pages).
    pub total_pages: u64,
    /// Maximum distance in the matrix.
    pub max_distance: u8,
    /// Minimum non-local distance.
    pub min_remote_distance: u8,
    /// Number of near node pairs.
    pub near_pairs: u32,
}

impl NumaTopologyStats {
    /// Create zero stats.
    pub const fn new() -> Self {
        Self {
            online_nodes: 0,
            total_pages: 0,
            max_distance: 0,
            min_remote_distance: REMOTE_DISTANCE_MAX,
            near_pairs: 0,
        }
    }
}

impl Default for NumaTopologyStats {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// NumaDistanceMatrix
// -------------------------------------------------------------------

/// The N×N NUMA distance matrix.
pub struct NumaDistanceMatrix {
    /// Distance values [src][dst].
    distances: [[u8; MAX_NODES]; MAX_NODES],
    /// Per-node metadata.
    nodes: [NodeInfo; MAX_NODES],
    /// Number of nodes.
    node_count: usize,
    /// Statistics.
    stats: NumaTopologyStats,
}

impl NumaDistanceMatrix {
    /// Create a new distance matrix.
    pub const fn new() -> Self {
        Self {
            distances: [[0u8; MAX_NODES]; MAX_NODES],
            nodes: [const {
                NodeInfo {
                    node_id: 0,
                    online: false,
                    total_pages: 0,
                    free_pages: 0,
                    nr_cpus: 0,
                }
            }; MAX_NODES],
            node_count: 0,
            stats: NumaTopologyStats::new(),
        }
    }

    /// Return the number of nodes.
    pub const fn node_count(&self) -> usize {
        self.node_count
    }

    /// Return the statistics.
    pub const fn stats(&self) -> &NumaTopologyStats {
        &self.stats
    }

    /// Add a node to the matrix.
    pub fn add_node(&mut self, info: NodeInfo) -> Result<()> {
        if self.node_count >= MAX_NODES {
            return Err(Error::OutOfMemory);
        }
        let idx = self.node_count;
        self.nodes[idx] = info;
        self.distances[idx][idx] = LOCAL_DISTANCE;
        self.node_count += 1;
        self.stats.online_nodes += 1;
        self.stats.total_pages += info.total_pages();
        Ok(())
    }

    /// Set the distance between two nodes.
    pub fn set_distance(&mut self, src: usize, dst: usize, dist: u8) -> Result<()> {
        if src >= self.node_count || dst >= self.node_count {
            return Err(Error::InvalidArgument);
        }
        self.distances[src][dst] = dist;
        self.distances[dst][src] = dist;

        if dist > self.stats.max_distance {
            self.stats.max_distance = dist;
        }
        if src != dst && dist < self.stats.min_remote_distance {
            self.stats.min_remote_distance = dist;
        }
        if src != dst && dist <= NEAR_THRESHOLD {
            self.stats.near_pairs += 1;
        }
        Ok(())
    }

    /// Get the distance between two nodes.
    pub fn get_distance(&self, src: usize, dst: usize) -> Result<u8> {
        if src >= self.node_count || dst >= self.node_count {
            return Err(Error::InvalidArgument);
        }
        Ok(self.distances[src][dst])
    }

    /// Compute the fallback order for a given node.
    pub fn fallback_order(&self, node: usize) -> Result<FallbackOrder> {
        if node >= self.node_count {
            return Err(Error::InvalidArgument);
        }

        let mut order = FallbackOrder::new(node as u8);
        order.push(node as u8);

        // Collect distances to other online nodes.
        let mut pairs: [(u8, u8); MAX_NODES] = [(0, 0); MAX_NODES];
        let mut pair_count = 0;
        for idx in 0..self.node_count {
            if idx != node && self.nodes[idx].is_online() {
                pairs[pair_count] = (self.distances[node][idx], idx as u8);
                pair_count += 1;
            }
        }

        // Simple insertion sort by distance.
        for i in 1..pair_count {
            let key = pairs[i];
            let mut j = i;
            while j > 0 && pairs[j - 1].0 > key.0 {
                pairs[j] = pairs[j - 1];
                j -= 1;
            }
            pairs[j] = key;
        }

        for idx in 0..pair_count {
            order.push(pairs[idx].1);
        }

        Ok(order)
    }

    /// Get node info by index.
    pub fn node_info(&self, index: usize) -> Result<&NodeInfo> {
        if index >= self.node_count {
            return Err(Error::InvalidArgument);
        }
        Ok(&self.nodes[index])
    }
}

impl Default for NumaDistanceMatrix {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// Public helpers
// -------------------------------------------------------------------

/// Check whether two nodes are near each other.
pub fn nodes_near(matrix: &NumaDistanceMatrix, a: usize, b: usize) -> bool {
    match matrix.get_distance(a, b) {
        Ok(d) => d <= NEAR_THRESHOLD,
        Err(_) => false,
    }
}

/// Return the nearest online node to the given node.
pub fn nearest_node(matrix: &NumaDistanceMatrix, node: usize) -> Result<u8> {
    let order = matrix.fallback_order(node)?;
    if order.count() > 1 {
        order.get(1) // index 0 is self
    } else {
        Ok(node as u8)
    }
}

/// Return the local distance constant.
pub const fn local_distance() -> u8 {
    LOCAL_DISTANCE
}
