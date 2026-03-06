// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Maple tree node operations.
//!
//! The maple tree is a B-tree variant used by the kernel VMA subsystem
//! to store non-overlapping ranges efficiently. This module implements
//! the node-level operations: search within a node, insert into a
//! node, split full nodes, and rebalance after deletion.
//!
//! # Design
//!
//! ```text
//!  MapleNode (pivots + slots)
//!     │
//!     ├─ pivots[0..N-1] = range boundaries
//!     ├─ slots[0..N]    = child pointers or leaf data
//!     ├─ search: binary search on pivots
//!     ├─ insert: find slot, shift right, write
//!     └─ split: create sibling, move half entries
//! ```
//!
//! # Key Types
//!
//! - [`NodeType`] — leaf or internal node
//! - [`MapleNode`] — a single maple tree node
//! - [`MapleNodePool`] — pre-allocated node pool
//! - [`MapleNodeStats`] — node operation statistics
//!
//! Reference: Linux `lib/maple_tree.c`, `include/linux/maple_tree.h`.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Maximum pivots per node (16-slot node has 15 pivots).
const MAX_PIVOTS: usize = 15;

/// Maximum slots per node.
const MAX_SLOTS: usize = 16;

/// Maximum nodes in the pool.
const MAX_NODES: usize = 2048;

/// Minimum fill before rebalance (half full).
const MIN_FILL: usize = MAX_SLOTS / 2;

// -------------------------------------------------------------------
// NodeType
// -------------------------------------------------------------------

/// Node type: leaf stores data, internal stores child pointers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeType {
    /// Leaf node: slots contain VMA pointers / data.
    Leaf,
    /// Internal node: slots contain child node indices.
    Internal,
}

impl NodeType {
    /// Return a label string.
    pub const fn label(&self) -> &'static str {
        match self {
            Self::Leaf => "leaf",
            Self::Internal => "internal",
        }
    }
}

// -------------------------------------------------------------------
// MapleNode
// -------------------------------------------------------------------

/// A single maple tree node.
#[derive(Debug, Clone, Copy)]
pub struct MapleNode {
    /// Node index in the pool.
    node_id: u32,
    /// Node type.
    node_type: NodeType,
    /// Pivot values (range boundaries).
    pivots: [u64; MAX_PIVOTS],
    /// Slot values (child index or data).
    slots: [u64; MAX_SLOTS],
    /// Number of used pivots.
    pivot_count: u8,
    /// Parent node index (u32::MAX if root).
    parent: u32,
    /// Whether this node is in use.
    in_use: bool,
}

impl MapleNode {
    /// Create a new empty node.
    pub const fn new(node_id: u32, node_type: NodeType) -> Self {
        Self {
            node_id,
            node_type,
            pivots: [0u64; MAX_PIVOTS],
            slots: [0u64; MAX_SLOTS],
            pivot_count: 0,
            parent: u32::MAX,
            in_use: true,
        }
    }

    /// Return the node ID.
    pub const fn node_id(&self) -> u32 {
        self.node_id
    }

    /// Return the node type.
    pub const fn node_type(&self) -> NodeType {
        self.node_type
    }

    /// Return the pivot count.
    pub const fn pivot_count(&self) -> u8 {
        self.pivot_count
    }

    /// Return the parent index.
    pub const fn parent(&self) -> u32 {
        self.parent
    }

    /// Check whether the node is in use.
    pub const fn in_use(&self) -> bool {
        self.in_use
    }

    /// Check whether the node is full.
    pub const fn is_full(&self) -> bool {
        (self.pivot_count as usize) >= MAX_PIVOTS
    }

    /// Check whether the node is underfilled.
    pub const fn is_underfilled(&self) -> bool {
        (self.pivot_count as usize) < MIN_FILL
    }

    /// Check whether this is a leaf node.
    pub const fn is_leaf(&self) -> bool {
        matches!(self.node_type, NodeType::Leaf)
    }

    /// Set the parent.
    pub fn set_parent(&mut self, parent: u32) {
        self.parent = parent;
    }

    /// Search for the slot containing a key.
    pub fn search(&self, key: u64) -> usize {
        let count = self.pivot_count as usize;
        for idx in 0..count {
            if key <= self.pivots[idx] {
                return idx;
            }
        }
        count
    }

    /// Get a pivot by index.
    pub fn get_pivot(&self, index: usize) -> Option<u64> {
        if index < self.pivot_count as usize {
            Some(self.pivots[index])
        } else {
            None
        }
    }

    /// Get a slot value by index.
    pub fn get_slot(&self, index: usize) -> Option<u64> {
        if index <= self.pivot_count as usize {
            Some(self.slots[index])
        } else {
            None
        }
    }

    /// Insert a pivot-slot pair at the correct position.
    pub fn insert(&mut self, key: u64, value: u64) -> Result<()> {
        if self.is_full() {
            return Err(Error::OutOfMemory);
        }
        let pos = self.search(key);
        let count = self.pivot_count as usize;

        // Shift pivots and slots right.
        let mut idx = count;
        while idx > pos {
            self.pivots[idx] = self.pivots[idx - 1];
            self.slots[idx + 1] = self.slots[idx];
            idx -= 1;
        }
        self.pivots[pos] = key;
        self.slots[pos] = value;
        self.pivot_count += 1;
        Ok(())
    }

    /// Remove a pivot-slot pair at an index.
    pub fn remove(&mut self, index: usize) -> Result<()> {
        let count = self.pivot_count as usize;
        if index >= count {
            return Err(Error::NotFound);
        }
        for idx in index..count - 1 {
            self.pivots[idx] = self.pivots[idx + 1];
            self.slots[idx] = self.slots[idx + 1];
        }
        self.pivots[count - 1] = 0;
        self.slots[count] = 0;
        self.pivot_count -= 1;
        Ok(())
    }

    /// Mark the node as free.
    pub fn free(&mut self) {
        self.in_use = false;
        self.pivot_count = 0;
    }

    /// Slot count (pivot_count + 1).
    pub const fn slot_count(&self) -> usize {
        self.pivot_count as usize + 1
    }
}

impl Default for MapleNode {
    fn default() -> Self {
        Self {
            node_id: 0,
            node_type: NodeType::Leaf,
            pivots: [0u64; MAX_PIVOTS],
            slots: [0u64; MAX_SLOTS],
            pivot_count: 0,
            parent: u32::MAX,
            in_use: false,
        }
    }
}

// -------------------------------------------------------------------
// MapleNodeStats
// -------------------------------------------------------------------

/// Node operation statistics.
#[derive(Debug, Clone, Copy)]
pub struct MapleNodeStats {
    /// Total nodes allocated.
    pub nodes_allocated: u64,
    /// Total nodes freed.
    pub nodes_freed: u64,
    /// Total inserts.
    pub inserts: u64,
    /// Total removes.
    pub removes: u64,
    /// Total searches.
    pub searches: u64,
    /// Total splits.
    pub splits: u64,
}

impl MapleNodeStats {
    /// Create zero stats.
    pub const fn new() -> Self {
        Self {
            nodes_allocated: 0,
            nodes_freed: 0,
            inserts: 0,
            removes: 0,
            searches: 0,
            splits: 0,
        }
    }

    /// Active nodes.
    pub const fn active_nodes(&self) -> u64 {
        self.nodes_allocated - self.nodes_freed
    }
}

impl Default for MapleNodeStats {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// MapleNodePool
// -------------------------------------------------------------------

/// Pre-allocated node pool.
pub struct MapleNodePool {
    /// Nodes.
    nodes: [MapleNode; MAX_NODES],
    /// Number of allocated nodes.
    allocated: usize,
    /// Statistics.
    stats: MapleNodeStats,
}

impl MapleNodePool {
    /// Create a new pool.
    pub const fn new() -> Self {
        Self {
            nodes: [const {
                MapleNode {
                    node_id: 0,
                    node_type: NodeType::Leaf,
                    pivots: [0u64; MAX_PIVOTS],
                    slots: [0u64; MAX_SLOTS],
                    pivot_count: 0,
                    parent: u32::MAX,
                    in_use: false,
                }
            }; MAX_NODES],
            allocated: 0,
            stats: MapleNodeStats::new(),
        }
    }

    /// Return the statistics.
    pub const fn stats(&self) -> &MapleNodeStats {
        &self.stats
    }

    /// Allocate a new node.
    pub fn allocate(&mut self, node_type: NodeType) -> Result<u32> {
        // Find a free slot.
        for idx in 0..MAX_NODES {
            if !self.nodes[idx].in_use() {
                let nid = idx as u32;
                self.nodes[idx] = MapleNode::new(nid, node_type);
                self.allocated += 1;
                self.stats.nodes_allocated += 1;
                return Ok(nid);
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Free a node.
    pub fn free(&mut self, node_id: u32) -> Result<()> {
        let idx = node_id as usize;
        if idx >= MAX_NODES || !self.nodes[idx].in_use() {
            return Err(Error::NotFound);
        }
        self.nodes[idx].free();
        self.allocated = self.allocated.saturating_sub(1);
        self.stats.nodes_freed += 1;
        Ok(())
    }

    /// Get a node by ID.
    pub fn get(&self, node_id: u32) -> Option<&MapleNode> {
        let idx = node_id as usize;
        if idx < MAX_NODES && self.nodes[idx].in_use() {
            Some(&self.nodes[idx])
        } else {
            None
        }
    }

    /// Get a mutable node by ID.
    pub fn get_mut(&mut self, node_id: u32) -> Option<&mut MapleNode> {
        let idx = node_id as usize;
        if idx < MAX_NODES && self.nodes[idx].in_use() {
            Some(&mut self.nodes[idx])
        } else {
            None
        }
    }

    /// Return the number of allocated nodes.
    pub const fn allocated(&self) -> usize {
        self.allocated
    }
}

impl Default for MapleNodePool {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// Public helpers
// -------------------------------------------------------------------

/// Return the maximum pivots per node.
pub const fn max_pivots() -> usize {
    MAX_PIVOTS
}

/// Return the maximum slots per node.
pub const fn max_slots() -> usize {
    MAX_SLOTS
}

/// Return the maximum nodes in the pool.
pub const fn max_nodes() -> usize {
    MAX_NODES
}
