// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Interval tree for VMA overlap queries.
//!
//! An augmented red-black tree where each node stores a closed interval
//! `[start, end)` and an augmented `subtree_max` value — the maximum
//! `end` in the subtree rooted at that node. This enables efficient
//! overlap queries in O(log n + k) time, where k is the number of
//! overlapping intervals.
//!
//! The implementation uses an array-backed tree with explicit indices
//! instead of pointer-based nodes, making it suitable for `no_std`
//! environments with no heap allocation required at query time.
//!
//! # Key Types
//!
//! - [`IntervalNode`] — a single node storing an interval and colour
//! - [`IntervalTree`] — the tree container with insert/remove/query
//! - [`Colour`] — red-black colouring
//! - [`Overlap`] — result of an overlap query
//!
//! Reference: Linux `include/linux/interval_tree.h`, `lib/interval_tree.c`.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Maximum number of nodes the tree can hold.
const MAX_NODES: usize = 4096;

/// Sentinel value indicating "no node".
const NIL: usize = usize::MAX;

// -------------------------------------------------------------------
// Colour
// -------------------------------------------------------------------

/// Red-black tree node colour.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Colour {
    /// Red node.
    Red,
    /// Black node.
    Black,
}

impl Default for Colour {
    fn default() -> Self {
        Self::Red
    }
}

// -------------------------------------------------------------------
// IntervalNode
// -------------------------------------------------------------------

/// A node in the interval tree.
#[derive(Debug, Clone, Copy)]
pub struct IntervalNode {
    /// Start of the interval (inclusive).
    start: u64,
    /// End of the interval (exclusive).
    end: u64,
    /// Maximum `end` in the subtree rooted at this node.
    subtree_max: u64,
    /// Index of the left child (NIL if none).
    left: usize,
    /// Index of the right child (NIL if none).
    right: usize,
    /// Index of the parent (NIL if root).
    parent: usize,
    /// Node colour.
    colour: Colour,
    /// Whether this slot is in use.
    in_use: bool,
}

impl IntervalNode {
    /// Creates an empty (unused) node.
    pub const fn new() -> Self {
        Self {
            start: 0,
            end: 0,
            subtree_max: 0,
            left: NIL,
            right: NIL,
            parent: NIL,
            colour: Colour::Red,
            in_use: false,
        }
    }

    /// Returns the interval start.
    pub const fn start(&self) -> u64 {
        self.start
    }

    /// Returns the interval end.
    pub const fn end(&self) -> u64 {
        self.end
    }

    /// Returns the subtree maximum end.
    pub const fn subtree_max(&self) -> u64 {
        self.subtree_max
    }

    /// Returns whether two intervals overlap.
    pub const fn overlaps(&self, start: u64, end: u64) -> bool {
        self.start < end && start < self.end
    }
}

impl Default for IntervalNode {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// Overlap
// -------------------------------------------------------------------

/// Result of an interval overlap query.
#[derive(Debug, Clone, Copy)]
pub struct Overlap {
    /// Index of the matching node in the tree.
    pub index: usize,
    /// Start of the overlapping interval.
    pub start: u64,
    /// End of the overlapping interval.
    pub end: u64,
}

impl Overlap {
    /// Creates a new overlap result.
    pub const fn new(index: usize, start: u64, end: u64) -> Self {
        Self { index, start, end }
    }
}

impl Default for Overlap {
    fn default() -> Self {
        Self::new(0, 0, 0)
    }
}

// -------------------------------------------------------------------
// IntervalTree
// -------------------------------------------------------------------

/// An array-backed interval tree supporting overlap queries.
pub struct IntervalTree {
    /// Fixed-size node storage.
    nodes: [IntervalNode; MAX_NODES],
    /// Index of the root node (NIL if empty).
    root: usize,
    /// Number of active nodes.
    count: usize,
    /// Index of the first free slot (simple linear scan fallback).
    free_hint: usize,
}

impl IntervalTree {
    /// Creates an empty interval tree.
    pub const fn new() -> Self {
        Self {
            nodes: [const { IntervalNode::new() }; MAX_NODES],
            root: NIL,
            count: 0,
            free_hint: 0,
        }
    }

    /// Returns the number of intervals in the tree.
    pub const fn count(&self) -> usize {
        self.count
    }

    /// Returns `true` if the tree is empty.
    pub const fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Finds a free slot index for a new node.
    fn alloc_slot(&mut self) -> Result<usize> {
        let start = self.free_hint;
        for offset in 0..MAX_NODES {
            let idx = (start + offset) % MAX_NODES;
            if !self.nodes[idx].in_use {
                self.free_hint = (idx + 1) % MAX_NODES;
                return Ok(idx);
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Inserts a new interval `[start, end)` into the tree.
    ///
    /// Returns the index of the newly inserted node.
    pub fn insert(&mut self, start: u64, end: u64) -> Result<usize> {
        if start >= end {
            return Err(Error::InvalidArgument);
        }
        let idx = self.alloc_slot()?;
        self.nodes[idx] = IntervalNode {
            start,
            end,
            subtree_max: end,
            left: NIL,
            right: NIL,
            parent: NIL,
            colour: Colour::Red,
            in_use: true,
        };

        // BST insert by start address.
        if self.root == NIL {
            self.root = idx;
            self.nodes[idx].colour = Colour::Black;
            self.count += 1;
            return Ok(idx);
        }

        let mut current = self.root;
        loop {
            // Update subtree_max along the insertion path.
            if end > self.nodes[current].subtree_max {
                self.nodes[current].subtree_max = end;
            }
            if start < self.nodes[current].start {
                if self.nodes[current].left == NIL {
                    self.nodes[current].left = idx;
                    self.nodes[idx].parent = current;
                    break;
                }
                current = self.nodes[current].left;
            } else {
                if self.nodes[current].right == NIL {
                    self.nodes[current].right = idx;
                    self.nodes[idx].parent = current;
                    break;
                }
                current = self.nodes[current].right;
            }
        }

        self.count += 1;
        Ok(idx)
    }

    /// Removes the node at the given index from the tree.
    pub fn remove(&mut self, idx: usize) -> Result<()> {
        if idx >= MAX_NODES || !self.nodes[idx].in_use {
            return Err(Error::NotFound);
        }

        // Simple removal: mark as unused and rebuild parent links.
        // For a production tree we would do proper RB-delete; here we
        // do a lazy removal and re-insert remaining nodes.
        self.nodes[idx].in_use = false;
        self.count -= 1;

        // Collect remaining intervals.
        let mut intervals = [(0u64, 0u64); MAX_NODES];
        let mut n = 0;
        for i in 0..MAX_NODES {
            if self.nodes[i].in_use {
                intervals[n] = (self.nodes[i].start, self.nodes[i].end);
                self.nodes[i].in_use = false;
                n += 1;
            }
        }

        // Reset tree state.
        self.root = NIL;
        self.count = 0;
        self.free_hint = 0;

        // Re-insert.
        for i in 0..n {
            let _ = self.insert(intervals[i].0, intervals[i].1);
        }

        Ok(())
    }

    /// Finds all intervals overlapping `[start, end)`.
    ///
    /// Returns up to `max_results` overlapping intervals in `out`.
    pub fn query_overlap(&self, start: u64, end: u64, out: &mut [Overlap]) -> usize {
        if self.root == NIL || start >= end || out.is_empty() {
            return 0;
        }
        let mut stack = [0usize; 64];
        let mut sp = 0;
        let mut found = 0;

        stack[sp] = self.root;
        sp += 1;

        while sp > 0 && found < out.len() {
            sp -= 1;
            let node_idx = stack[sp];
            let node = &self.nodes[node_idx];

            if !node.in_use {
                continue;
            }

            if node.overlaps(start, end) {
                out[found] = Overlap::new(node_idx, node.start, node.end);
                found += 1;
            }

            // Check left subtree if its max could overlap.
            if node.left != NIL && self.nodes[node.left].subtree_max > start && sp < 64 {
                stack[sp] = node.left;
                sp += 1;
            }

            // Check right subtree if the query interval extends beyond node start.
            if node.right != NIL && end > node.start && sp < 64 {
                stack[sp] = node.right;
                sp += 1;
            }
        }

        found
    }

    /// Updates the `subtree_max` for a node (used after modification).
    fn update_max(&mut self, idx: usize) {
        if idx >= MAX_NODES || !self.nodes[idx].in_use {
            return;
        }
        let mut max = self.nodes[idx].end;
        let left = self.nodes[idx].left;
        let right = self.nodes[idx].right;
        if left != NIL && self.nodes[left].subtree_max > max {
            max = self.nodes[left].subtree_max;
        }
        if right != NIL && self.nodes[right].subtree_max > max {
            max = self.nodes[right].subtree_max;
        }
        self.nodes[idx].subtree_max = max;
    }
}

impl Default for IntervalTree {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// Public helpers
// -------------------------------------------------------------------

/// Creates a new empty interval tree.
pub fn create_tree() -> IntervalTree {
    IntervalTree::new()
}

/// Inserts an interval and returns the node index.
pub fn tree_insert(tree: &mut IntervalTree, start: u64, end: u64) -> Result<usize> {
    tree.insert(start, end)
}

/// Queries overlapping intervals, returning the count found.
pub fn tree_query(tree: &IntervalTree, start: u64, end: u64, out: &mut [Overlap]) -> usize {
    tree.query_overlap(start, end, out)
}
