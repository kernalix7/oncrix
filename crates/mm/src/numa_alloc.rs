// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! NUMA-aware allocation policy.
//!
//! On NUMA systems, memory access latency depends on which node the
//! page resides on relative to the accessing CPU. This module implements
//! allocation policies that respect node affinity: prefer local node,
//! fall back to nearby nodes ordered by distance, and support explicit
//! bind/interleave/preferred policies.
//!
//! # Design
//!
//! ```text
//!  Allocation request
//!       │
//!       ▼
//!  NumaPolicy::select_node(preferred, nodemask)
//!       │
//!       ├─ Preferred  → try preferred, then nearest
//!       ├─ Bind       → only nodes in mask
//!       ├─ Interleave → round-robin across mask
//!       └─ Local      → current CPU's node
//! ```
//!
//! # Key Types
//!
//! - [`NumaNodeMask`] — bitmask of allowed nodes
//! - [`NumaPolicy`] — allocation policy descriptor
//! - [`NumaDistanceMap`] — inter-node distance table
//! - [`NumaAllocator`] — policy-aware allocator front-end
//!
//! Reference: Linux `mm/mempolicy.c`, `include/linux/mempolicy.h`.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Maximum NUMA nodes.
const MAX_NODES: usize = 64;

/// Local distance value.
const LOCAL_DISTANCE: u8 = 10;

/// Remote distance (far).
const REMOTE_DISTANCE: u8 = 20;

/// Unreachable.
const UNREACHABLE: u8 = 255;

/// Per-node page capacity (simplified).
const NODE_CAPACITY: u64 = 1 << 20; // 4 GiB worth of pages

// -------------------------------------------------------------------
// NumaNodeMask
// -------------------------------------------------------------------

/// A bitmask selecting a subset of NUMA nodes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NumaNodeMask(u64);

impl NumaNodeMask {
    /// Empty mask (no nodes).
    pub const fn empty() -> Self {
        Self(0)
    }

    /// All nodes (up to MAX_NODES).
    pub const fn all() -> Self {
        Self(u64::MAX)
    }

    /// Single node.
    pub const fn single(node: usize) -> Self {
        if node < 64 {
            Self(1u64 << node)
        } else {
            Self(0)
        }
    }

    /// Check whether a node is in the mask.
    pub const fn contains(&self, node: usize) -> bool {
        if node >= 64 {
            return false;
        }
        (self.0 & (1u64 << node)) != 0
    }

    /// Add a node to the mask.
    pub const fn with_node(self, node: usize) -> Self {
        if node >= 64 {
            return self;
        }
        Self(self.0 | (1u64 << node))
    }

    /// Remove a node from the mask.
    pub const fn without_node(self, node: usize) -> Self {
        if node >= 64 {
            return self;
        }
        Self(self.0 & !(1u64 << node))
    }

    /// Count the number of nodes in the mask.
    pub const fn count(&self) -> u32 {
        self.0.count_ones()
    }

    /// Check whether the mask is empty.
    pub const fn is_empty(&self) -> bool {
        self.0 == 0
    }

    /// Return raw bits.
    pub const fn bits(&self) -> u64 {
        self.0
    }

    /// Find the first set node.
    pub const fn first(&self) -> Option<usize> {
        if self.0 == 0 {
            None
        } else {
            Some(self.0.trailing_zeros() as usize)
        }
    }
}

impl Default for NumaNodeMask {
    fn default() -> Self {
        Self::all()
    }
}

// -------------------------------------------------------------------
// NumaPolicy
// -------------------------------------------------------------------

/// NUMA allocation policy mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyMode {
    /// Use the default (local) node.
    Default,
    /// Prefer a specific node, fall back to others.
    Preferred,
    /// Allocate only from nodes in the mask.
    Bind,
    /// Round-robin across nodes in the mask.
    Interleave,
    /// Always use the local (current CPU's) node.
    Local,
}

impl Default for PolicyMode {
    fn default() -> Self {
        Self::Default
    }
}

/// NUMA allocation policy.
#[derive(Debug, Clone, Copy)]
pub struct NumaPolicy {
    /// Policy mode.
    mode: PolicyMode,
    /// Allowed/preferred node mask.
    nodemask: NumaNodeMask,
    /// Preferred node (for Preferred mode).
    preferred_node: usize,
    /// Interleave counter.
    interleave_idx: usize,
}

impl NumaPolicy {
    /// Create a default policy.
    pub const fn new() -> Self {
        Self {
            mode: PolicyMode::Default,
            nodemask: NumaNodeMask::all(),
            preferred_node: 0,
            interleave_idx: 0,
        }
    }

    /// Create a preferred-node policy.
    pub const fn preferred(node: usize) -> Self {
        Self {
            mode: PolicyMode::Preferred,
            nodemask: NumaNodeMask::all(),
            preferred_node: node,
            interleave_idx: 0,
        }
    }

    /// Create a bind policy.
    pub const fn bind(mask: NumaNodeMask) -> Self {
        Self {
            mode: PolicyMode::Bind,
            nodemask: mask,
            preferred_node: 0,
            interleave_idx: 0,
        }
    }

    /// Create an interleave policy.
    pub const fn interleave(mask: NumaNodeMask) -> Self {
        Self {
            mode: PolicyMode::Interleave,
            nodemask: mask,
            preferred_node: 0,
            interleave_idx: 0,
        }
    }

    /// Return the mode.
    pub const fn mode(&self) -> PolicyMode {
        self.mode
    }

    /// Return the node mask.
    pub const fn nodemask(&self) -> NumaNodeMask {
        self.nodemask
    }

    /// Return the preferred node.
    pub const fn preferred_node(&self) -> usize {
        self.preferred_node
    }

    /// Select the next node for allocation.
    pub fn select_node(&mut self, local_node: usize) -> usize {
        match self.mode {
            PolicyMode::Default | PolicyMode::Local => local_node,
            PolicyMode::Preferred => {
                if self.nodemask.contains(self.preferred_node) {
                    self.preferred_node
                } else {
                    local_node
                }
            }
            PolicyMode::Bind => {
                if self.nodemask.contains(local_node) {
                    local_node
                } else {
                    self.nodemask.first().unwrap_or(0)
                }
            }
            PolicyMode::Interleave => {
                let start = self.interleave_idx;
                for offset in 0..MAX_NODES {
                    let node = (start + offset) % MAX_NODES;
                    if self.nodemask.contains(node) {
                        self.interleave_idx = node + 1;
                        return node;
                    }
                }
                local_node
            }
        }
    }
}

impl Default for NumaPolicy {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// NumaDistanceMap
// -------------------------------------------------------------------

/// Inter-node distance table.
pub struct NumaDistanceMap {
    /// Distance matrix [from][to].
    distances: [[u8; MAX_NODES]; MAX_NODES],
    /// Number of nodes.
    node_count: usize,
}

impl NumaDistanceMap {
    /// Create a distance map with all local distances.
    pub const fn new(node_count: usize) -> Self {
        let mut distances = [[UNREACHABLE; MAX_NODES]; MAX_NODES];
        let mut i = 0;
        while i < MAX_NODES {
            distances[i][i] = LOCAL_DISTANCE;
            i += 1;
        }
        Self {
            distances,
            node_count,
        }
    }

    /// Set the distance between two nodes.
    pub fn set_distance(&mut self, from: usize, to: usize, distance: u8) -> Result<()> {
        if from >= self.node_count || to >= self.node_count {
            return Err(Error::InvalidArgument);
        }
        self.distances[from][to] = distance;
        self.distances[to][from] = distance;
        Ok(())
    }

    /// Return the distance between two nodes.
    pub fn distance(&self, from: usize, to: usize) -> u8 {
        if from >= MAX_NODES || to >= MAX_NODES {
            return UNREACHABLE;
        }
        self.distances[from][to]
    }

    /// Return nodes sorted by distance from a source node.
    pub fn nearest_nodes(&self, from: usize, out: &mut [usize]) -> usize {
        let mut count = 0;
        // Collect valid nodes.
        let mut nodes = [0usize; MAX_NODES];
        let mut dists = [UNREACHABLE; MAX_NODES];
        for to in 0..self.node_count {
            if to != from {
                nodes[count] = to;
                dists[count] = self.distances[from][to];
                count += 1;
            }
        }
        // Simple insertion sort by distance.
        for i in 1..count {
            let key_node = nodes[i];
            let key_dist = dists[i];
            let mut j = i;
            while j > 0 && dists[j - 1] > key_dist {
                nodes[j] = nodes[j - 1];
                dists[j] = dists[j - 1];
                j -= 1;
            }
            nodes[j] = key_node;
            dists[j] = key_dist;
        }
        let to_copy = count.min(out.len());
        out[..to_copy].copy_from_slice(&nodes[..to_copy]);
        to_copy
    }

    /// Return the node count.
    pub const fn node_count(&self) -> usize {
        self.node_count
    }
}

impl Default for NumaDistanceMap {
    fn default() -> Self {
        Self::new(1)
    }
}

// -------------------------------------------------------------------
// NumaAllocator
// -------------------------------------------------------------------

/// NUMA-aware allocator front-end.
pub struct NumaAllocator {
    /// Per-node free page counts.
    free_pages: [u64; MAX_NODES],
    /// Number of nodes.
    node_count: usize,
    /// Total allocations.
    total_allocs: u64,
    /// Allocations that fell back to a non-preferred node.
    fallback_allocs: u64,
}

impl NumaAllocator {
    /// Create a new allocator with `n` nodes.
    pub const fn new(node_count: usize) -> Self {
        Self {
            free_pages: [NODE_CAPACITY; MAX_NODES],
            node_count,
            total_allocs: 0,
            fallback_allocs: 0,
        }
    }

    /// Return free pages on a node.
    pub fn free_pages(&self, node: usize) -> u64 {
        if node >= MAX_NODES {
            return 0;
        }
        self.free_pages[node]
    }

    /// Allocate pages using the given policy.
    pub fn alloc(
        &mut self,
        policy: &mut NumaPolicy,
        local_node: usize,
        count: u64,
    ) -> Result<usize> {
        let preferred = policy.select_node(local_node);

        // Try preferred node first.
        if preferred < self.node_count && self.free_pages[preferred] >= count {
            self.free_pages[preferred] -= count;
            self.total_allocs += 1;
            return Ok(preferred);
        }

        // Fallback: try other nodes in order.
        for node in 0..self.node_count {
            if node != preferred
                && policy.nodemask().contains(node)
                && self.free_pages[node] >= count
            {
                self.free_pages[node] -= count;
                self.total_allocs += 1;
                self.fallback_allocs += 1;
                return Ok(node);
            }
        }

        Err(Error::OutOfMemory)
    }

    /// Free pages back to a node.
    pub fn free(&mut self, node: usize, count: u64) -> Result<()> {
        if node >= self.node_count {
            return Err(Error::InvalidArgument);
        }
        self.free_pages[node] += count;
        Ok(())
    }

    /// Return total allocations.
    pub const fn total_allocs(&self) -> u64 {
        self.total_allocs
    }

    /// Return fallback allocation count.
    pub const fn fallback_allocs(&self) -> u64 {
        self.fallback_allocs
    }
}

impl Default for NumaAllocator {
    fn default() -> Self {
        Self::new(1)
    }
}

// -------------------------------------------------------------------
// Public helpers
// -------------------------------------------------------------------

/// Allocate pages with a preferred-node policy.
pub fn alloc_preferred(alloc: &mut NumaAllocator, node: usize, count: u64) -> Result<usize> {
    let mut policy = NumaPolicy::preferred(node);
    alloc.alloc(&mut policy, node, count)
}

/// Allocate pages with local-node policy.
pub fn alloc_local(alloc: &mut NumaAllocator, local_node: usize, count: u64) -> Result<usize> {
    let mut policy = NumaPolicy::new();
    alloc.alloc(&mut policy, local_node, count)
}

/// Return the fallback rate as a percentage.
pub fn fallback_rate(alloc: &NumaAllocator) -> u64 {
    if alloc.total_allocs() == 0 {
        return 0;
    }
    alloc.fallback_allocs() * 100 / alloc.total_allocs()
}
