// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Maple tree (B-tree variant for ranges).
//!
//! The maple tree is an RCU-safe B-tree variant used as the primary
//! data structure for VMA management in the Linux kernel. It stores
//! ranges indexed by unsigned long keys, supporting efficient
//! insert, lookup, and iteration by range.
//!
//! # Node Types
//!
//! ```text
//! MapleNode
//! ├── Leaf (stores values directly)
//! │   pivots: [p0, p1, p2, ..., pN-1]
//! │   slots:  [v0, v1, v2, ..., vN]
//! │   Range [0, p0] → v0
//! │   Range [p0+1, p1] → v1
//! │   Range [p1+1, p2] → v2
//! │   ...
//! │
//! └── Internal (stores child node pointers)
//!     pivots: [p0, p1, ..., pN-1]
//!     children: [c0, c1, ..., cN]
//!     Keys in [0, p0] → descend into c0
//!     Keys in [p0+1, p1] → descend into c1
//!     ...
//! ```
//!
//! # Maple State (MAS)
//!
//! Operations use a `MapleState` cursor that tracks the current
//! position in the tree, avoiding repeated traversals.
//!
//! # Reference
//!
//! Linux `lib/maple_tree.c`, `include/linux/maple_tree.h`.

use oncrix_lib::{Error, Result};

// ======================================================================
// Constants
// ======================================================================

/// Maximum number of pivots per node (fanout - 1).
const MAPLE_NODE_SLOTS: usize = 16;

/// Maximum pivots per node.
const MAPLE_PIVOTS: usize = MAPLE_NODE_SLOTS - 1;

/// Maximum nodes in the tree.
const MAX_MAPLE_NODES: usize = 2048;

/// Empty pivot sentinel.
const PIVOT_NONE: u64 = u64::MAX;

/// Empty slot value.
const SLOT_EMPTY: u64 = 0;

/// Maximum tree depth.
const MAX_DEPTH: usize = 16;

// ======================================================================
// Maple state
// ======================================================================

/// State of a maple tree walk.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MasState {
    /// Walk has not started.
    Start,
    /// Walk is at a valid position.
    Active,
    /// Walk has been paused.
    Pause,
    /// Walk reached the end of the tree.
    None,
    /// Error state.
    Error,
}

/// Maple tree cursor / walk state.
#[derive(Debug, Clone, Copy)]
pub struct MapleState {
    /// Current state.
    state: MasState,
    /// Current node index.
    node: u32,
    /// Current index (key being operated on).
    index: u64,
    /// Last index in the current range.
    last: u64,
    /// Minimum of the current range.
    range_min: u64,
    /// Maximum of the current range.
    range_max: u64,
    /// Depth in the tree.
    depth: u8,
    /// Slot offset within the current node.
    offset: u8,
}

impl MapleState {
    /// Creates a new maple state positioned at a key.
    pub const fn new(index: u64) -> Self {
        Self {
            state: MasState::Start,
            node: 0,
            index,
            last: index,
            range_min: 0,
            range_max: PIVOT_NONE,
            depth: 0,
            offset: 0,
        }
    }

    /// Creates a state for a range operation.
    pub const fn new_range(index: u64, last: u64) -> Self {
        Self {
            state: MasState::Start,
            node: 0,
            index,
            last,
            range_min: 0,
            range_max: PIVOT_NONE,
            depth: 0,
            offset: 0,
        }
    }

    /// Returns the current state.
    pub fn state(&self) -> MasState {
        self.state
    }

    /// Returns the current index.
    pub fn index(&self) -> u64 {
        self.index
    }

    /// Returns the last index.
    pub fn last(&self) -> u64 {
        self.last
    }

    /// Pauses the walk.
    pub fn pause(&mut self) {
        self.state = MasState::Pause;
    }

    /// Resets the walk.
    pub fn reset(&mut self, index: u64) {
        self.state = MasState::Start;
        self.index = index;
        self.last = index;
        self.depth = 0;
    }
}

// ======================================================================
// Node type
// ======================================================================

/// Type of a maple tree node.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MapleNodeType {
    /// Leaf node (stores values directly).
    Leaf,
    /// Internal node (stores child node indices).
    Internal,
}

// ======================================================================
// Maple node
// ======================================================================

/// A node in the maple tree.
pub struct MapleNode {
    /// Pivot values (define ranges between slots).
    pivots: [u64; MAPLE_PIVOTS],
    /// Slot values (leaves: user values; internal: child
    /// node_index+1).
    slots: [u64; MAPLE_NODE_SLOTS],
    /// Node type.
    node_type: MapleNodeType,
    /// Number of populated slots.
    nr_slots: u8,
    /// Parent node index (0 if root).
    parent: u16,
    /// Offset within parent.
    parent_offset: u8,
    /// Whether this node is in use.
    in_use: bool,
    /// Minimum key covered by this node.
    min: u64,
    /// Maximum key covered by this node.
    max: u64,
}

impl MapleNode {
    /// Creates an empty maple node.
    pub const fn new() -> Self {
        Self {
            pivots: [PIVOT_NONE; MAPLE_PIVOTS],
            slots: [SLOT_EMPTY; MAPLE_NODE_SLOTS],
            node_type: MapleNodeType::Leaf,
            nr_slots: 0,
            parent: 0,
            parent_offset: 0,
            in_use: false,
            min: 0,
            max: PIVOT_NONE,
        }
    }

    /// Returns the node type.
    pub fn node_type(&self) -> MapleNodeType {
        self.node_type
    }

    /// Returns the number of slots.
    pub fn nr_slots(&self) -> u8 {
        self.nr_slots
    }

    /// Returns the minimum key.
    pub fn min(&self) -> u64 {
        self.min
    }

    /// Returns the maximum key.
    pub fn max(&self) -> u64 {
        self.max
    }

    /// Finds the slot for a given key.
    pub fn find_slot(&self, key: u64) -> u8 {
        for i in 0..self.nr_slots as usize {
            if i < MAPLE_PIVOTS && self.pivots[i] != PIVOT_NONE && key <= self.pivots[i] {
                return i as u8;
            }
        }
        // Last slot catches everything above the last pivot.
        if self.nr_slots > 0 {
            self.nr_slots - 1
        } else {
            0
        }
    }

    /// Returns the range [min, max] covered by a slot.
    pub fn slot_range(&self, slot: usize) -> (u64, u64) {
        let slot_min = if slot == 0 {
            self.min
        } else if slot - 1 < MAPLE_PIVOTS && self.pivots[slot - 1] != PIVOT_NONE {
            self.pivots[slot - 1].saturating_add(1)
        } else {
            self.min
        };
        let slot_max = if slot < MAPLE_PIVOTS && self.pivots[slot] != PIVOT_NONE {
            self.pivots[slot]
        } else {
            self.max
        };
        (slot_min, slot_max)
    }
}

// ======================================================================
// Maple tree
// ======================================================================

/// The maple tree.
pub struct MapleTree {
    /// Root node index + 1 (0 = empty).
    root: u64,
    /// Node pool.
    nodes: [MapleNode; MAX_MAPLE_NODES],
    /// Number of allocated nodes.
    nr_nodes: usize,
    /// Number of entries.
    nr_entries: usize,
    /// Tree depth.
    depth: usize,
}

impl MapleTree {
    /// Creates a new empty maple tree.
    pub const fn new() -> Self {
        Self {
            root: SLOT_EMPTY,
            nodes: [const { MapleNode::new() }; MAX_MAPLE_NODES],
            nr_nodes: 0,
            nr_entries: 0,
            depth: 0,
        }
    }

    /// Returns the number of entries.
    pub fn len(&self) -> usize {
        self.nr_entries
    }

    /// Returns whether the tree is empty.
    pub fn is_empty(&self) -> bool {
        self.nr_entries == 0
    }

    /// Returns the tree depth.
    pub fn depth(&self) -> usize {
        self.depth
    }

    /// Returns the number of allocated nodes.
    pub fn node_count(&self) -> usize {
        self.nr_nodes
    }

    /// Looks up a value by key.
    pub fn lookup(&self, key: u64) -> Option<u64> {
        if self.root == SLOT_EMPTY {
            return None;
        }
        let root_idx = (self.root - 1) as usize;
        self.walk_to(root_idx, key)
    }

    /// Inserts a value for a single key.
    pub fn insert(&mut self, key: u64, value: u64) -> Result<()> {
        self.insert_range(key, key, value)
    }

    /// Inserts a value for a range [first, last].
    pub fn insert_range(&mut self, first: u64, last: u64, value: u64) -> Result<()> {
        if value == SLOT_EMPTY || first > last {
            return Err(Error::InvalidArgument);
        }
        if self.root == SLOT_EMPTY {
            let node_idx = self.alloc_node()?;
            self.nodes[node_idx].node_type = MapleNodeType::Leaf;
            self.nodes[node_idx].min = 0;
            self.nodes[node_idx].max = PIVOT_NONE;
            self.root = (node_idx + 1) as u64;
            self.depth = 1;
        }
        let root_idx = (self.root - 1) as usize;
        self.insert_into_leaf(root_idx, first, last, value)?;
        self.nr_entries += 1;
        Ok(())
    }

    /// Erases a key from the tree.
    pub fn erase(&mut self, key: u64) -> Option<u64> {
        if self.root == SLOT_EMPTY {
            return None;
        }
        let root_idx = (self.root - 1) as usize;
        let old = self.erase_from_leaf(root_idx, key);
        if old.is_some() {
            self.nr_entries = self.nr_entries.saturating_sub(1);
        }
        old
    }

    /// Walks the tree using a maple state.
    pub fn walk(&self, mas: &mut MapleState) -> Option<u64> {
        if self.root == SLOT_EMPTY {
            mas.state = MasState::None;
            return None;
        }
        mas.state = MasState::Active;
        let root_idx = (self.root - 1) as usize;
        let result = self.walk_to(root_idx, mas.index);
        if result.is_none() {
            mas.state = MasState::None;
        }
        result
    }

    /// Advances to the next entry.
    pub fn next(&self, mas: &mut MapleState) -> Option<u64> {
        let next_key = mas.index.checked_add(1)?;
        mas.index = next_key;
        mas.last = next_key;
        self.walk(mas)
    }

    /// Moves to the previous entry.
    pub fn prev(&self, mas: &mut MapleState) -> Option<u64> {
        if mas.index == 0 {
            mas.state = MasState::None;
            return None;
        }
        mas.index -= 1;
        mas.last = mas.index;
        self.walk(mas)
    }

    // --- Internal helpers ---

    /// Allocates a node.
    fn alloc_node(&mut self) -> Result<usize> {
        let slot = self
            .nodes
            .iter()
            .position(|n| !n.in_use)
            .ok_or(Error::OutOfMemory)?;
        self.nodes[slot] = MapleNode::new();
        self.nodes[slot].in_use = true;
        self.nr_nodes += 1;
        Ok(slot)
    }

    /// Walks to a key, returning the value at that position.
    fn walk_to(&self, node_idx: usize, key: u64) -> Option<u64> {
        if node_idx >= MAX_MAPLE_NODES || !self.nodes[node_idx].in_use {
            return None;
        }
        let slot = self.nodes[node_idx].find_slot(key) as usize;
        let val = self.nodes[node_idx].slots[slot];
        if val == SLOT_EMPTY {
            return None;
        }
        match self.nodes[node_idx].node_type {
            MapleNodeType::Leaf => Some(val),
            MapleNodeType::Internal => {
                let child = (val - 1) as usize;
                self.walk_to(child, key)
            }
        }
    }

    /// Inserts into a leaf node.
    fn insert_into_leaf(
        &mut self,
        node_idx: usize,
        first: u64,
        last: u64,
        value: u64,
    ) -> Result<()> {
        if node_idx >= MAX_MAPLE_NODES || !self.nodes[node_idx].in_use {
            return Err(Error::NotFound);
        }
        if self.nodes[node_idx].node_type == MapleNodeType::Internal {
            // Find the child and recurse.
            let slot = self.nodes[node_idx].find_slot(first) as usize;
            let child_ref = self.nodes[node_idx].slots[slot];
            if child_ref == SLOT_EMPTY {
                // Create a new leaf child.
                let child = self.alloc_node()?;
                let (smin, smax) = self.nodes[node_idx].slot_range(slot);
                self.nodes[child].node_type = MapleNodeType::Leaf;
                self.nodes[child].min = smin;
                self.nodes[child].max = smax;
                self.nodes[child].parent = node_idx as u16;
                self.nodes[node_idx].slots[slot] = (child + 1) as u64;
                if self.nodes[node_idx].nr_slots <= slot as u8 {
                    self.nodes[node_idx].nr_slots = slot as u8 + 1;
                }
                return self.insert_into_leaf(child, first, last, value);
            }
            let child_idx = (child_ref - 1) as usize;
            return self.insert_into_leaf(child_idx, first, last, value);
        }
        // Leaf node — find or create a slot.
        let nr = self.nodes[node_idx].nr_slots as usize;
        if nr >= MAPLE_NODE_SLOTS {
            // Node is full — need to split.
            return self.split_and_insert(node_idx, first, last, value);
        }
        // Find insertion position.
        let mut pos = nr;
        for i in 0..nr {
            if i < MAPLE_PIVOTS
                && self.nodes[node_idx].pivots[i] != PIVOT_NONE
                && first <= self.nodes[node_idx].pivots[i]
            {
                pos = i;
                break;
            }
        }
        // Shift existing entries to make room.
        if pos < nr {
            // Shift slots right.
            let mut i = nr.min(MAPLE_NODE_SLOTS - 1);
            while i > pos {
                self.nodes[node_idx].slots[i] = self.nodes[node_idx].slots[i - 1];
                if i - 1 < MAPLE_PIVOTS && i < MAPLE_PIVOTS {
                    self.nodes[node_idx].pivots[i] = self.nodes[node_idx].pivots[i - 1];
                }
                i -= 1;
            }
        }
        // Insert.
        self.nodes[node_idx].slots[pos] = value;
        if pos < MAPLE_PIVOTS {
            self.nodes[node_idx].pivots[pos] = last;
        }
        if nr < MAPLE_NODE_SLOTS {
            self.nodes[node_idx].nr_slots = (nr + 1) as u8;
        }
        Ok(())
    }

    /// Splits a full leaf node and inserts.
    fn split_and_insert(
        &mut self,
        node_idx: usize,
        first: u64,
        _last: u64,
        value: u64,
    ) -> Result<()> {
        // Simple split: create a new node and move half the entries.
        let new_node = self.alloc_node()?;
        let nr = self.nodes[node_idx].nr_slots as usize;
        let split_point = nr / 2;

        self.nodes[new_node].node_type = MapleNodeType::Leaf;
        self.nodes[new_node].parent = self.nodes[node_idx].parent;
        self.nodes[new_node].in_use = true;

        // Move upper half to new node.
        let mut new_count = 0u8;
        for i in split_point..nr {
            self.nodes[new_node].slots[new_count as usize] = self.nodes[node_idx].slots[i];
            if i < MAPLE_PIVOTS && new_count as usize + 1 < MAPLE_PIVOTS {
                self.nodes[new_node].pivots[new_count as usize] = self.nodes[node_idx].pivots[i];
            }
            self.nodes[node_idx].slots[i] = SLOT_EMPTY;
            if i < MAPLE_PIVOTS {
                self.nodes[node_idx].pivots[i] = PIVOT_NONE;
            }
            new_count += 1;
        }
        self.nodes[new_node].nr_slots = new_count;
        self.nodes[node_idx].nr_slots = split_point as u8;

        // Set ranges.
        if split_point > 0 && split_point - 1 < MAPLE_PIVOTS {
            let split_key = self.nodes[node_idx].pivots[split_point - 1];
            self.nodes[new_node].min = split_key.saturating_add(1);
            self.nodes[new_node].max = self.nodes[node_idx].max;
            self.nodes[node_idx].max = split_key;
        }

        // Insert into the appropriate half.
        if first <= self.nodes[node_idx].max {
            self.insert_into_leaf(node_idx, first, first, value)
        } else {
            self.insert_into_leaf(new_node, first, first, value)
        }
    }

    /// Erases from a leaf node.
    fn erase_from_leaf(&mut self, node_idx: usize, key: u64) -> Option<u64> {
        if node_idx >= MAX_MAPLE_NODES || !self.nodes[node_idx].in_use {
            return None;
        }
        match self.nodes[node_idx].node_type {
            MapleNodeType::Internal => {
                let slot = self.nodes[node_idx].find_slot(key) as usize;
                let child_ref = self.nodes[node_idx].slots[slot];
                if child_ref == SLOT_EMPTY {
                    return None;
                }
                let child_idx = (child_ref - 1) as usize;
                self.erase_from_leaf(child_idx, key)
            }
            MapleNodeType::Leaf => {
                let slot = self.nodes[node_idx].find_slot(key) as usize;
                let val = self.nodes[node_idx].slots[slot];
                if val == SLOT_EMPTY {
                    return None;
                }
                // Verify the key is in range for this slot.
                let (smin, smax) = self.nodes[node_idx].slot_range(slot);
                if key < smin || key > smax {
                    return None;
                }
                self.nodes[node_idx].slots[slot] = SLOT_EMPTY;
                Some(val)
            }
        }
    }
}
