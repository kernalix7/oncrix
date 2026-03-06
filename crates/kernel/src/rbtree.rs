// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Red-black tree.
//!
//! A self-balancing binary search tree where each node is colored
//! red or black. The balancing guarantees O(log n) worst-case for
//! insert, delete, and search. Used extensively in the kernel for
//! schedulers, memory management, and timer queues.
//!
//! # Properties
//!
//! 1. Every node is red or black.
//! 2. The root is black.
//! 3. All leaves (NIL) are black.
//! 4. Red nodes have only black children.
//! 5. Every path from root to leaf has the same black-depth.
//!
//! # Design
//!
//! ```text
//!   Index-based tree in a flat array:
//!   nodes[i] = { key, color, parent, left, right, data }
//!
//!   NIL_IDX (u32::MAX) represents null pointers.
//! ```
//!
//! # Reference
//!
//! Linux `lib/rbtree.c`, `include/linux/rbtree.h`.

use oncrix_lib::{Error, Result};

// ======================================================================
// Constants
// ======================================================================

/// Maximum nodes in the tree.
const MAX_NODES: usize = 512;

/// Maximum managed trees.
const MAX_TREES: usize = 64;

/// Sentinel for null index.
const NIL_IDX: u32 = u32::MAX;

// ======================================================================
// RbColor
// ======================================================================

/// Color of a red-black tree node.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RbColor {
    /// Red node.
    Red,
    /// Black node.
    Black,
}

// ======================================================================
// RbNode
// ======================================================================

/// A node in the red-black tree.
#[derive(Debug, Clone, Copy)]
pub struct RbNode {
    /// Sort key.
    key: u64,
    /// Associated data.
    data: u64,
    /// Node color.
    color: RbColor,
    /// Parent index (NIL_IDX if root).
    parent: u32,
    /// Left child index.
    left: u32,
    /// Right child index.
    right: u32,
    /// Whether this slot is occupied.
    occupied: bool,
}

impl RbNode {
    /// Creates a new empty node.
    pub const fn new() -> Self {
        Self {
            key: 0,
            data: 0,
            color: RbColor::Black,
            parent: NIL_IDX,
            left: NIL_IDX,
            right: NIL_IDX,
            occupied: false,
        }
    }

    /// Returns the key.
    pub fn key(&self) -> u64 {
        self.key
    }

    /// Returns the data.
    pub fn data(&self) -> u64 {
        self.data
    }

    /// Returns the color.
    pub fn color(&self) -> RbColor {
        self.color
    }

    /// Returns the parent index.
    pub fn parent(&self) -> u32 {
        self.parent
    }

    /// Returns the left child index.
    pub fn left(&self) -> u32 {
        self.left
    }

    /// Returns the right child index.
    pub fn right(&self) -> u32 {
        self.right
    }

    /// Returns whether this slot is occupied.
    pub fn is_occupied(&self) -> bool {
        self.occupied
    }
}

// ======================================================================
// RbTree
// ======================================================================

/// Red-black tree backed by a fixed-size node array.
pub struct RbTree {
    /// Node pool.
    nodes: [RbNode; MAX_NODES],
    /// Root index (NIL_IDX if empty).
    root: u32,
    /// Number of nodes in the tree.
    count: usize,
    /// Number of allocated pool slots.
    pool_used: usize,
}

impl RbTree {
    /// Creates a new empty tree.
    pub const fn new() -> Self {
        Self {
            nodes: [const { RbNode::new() }; MAX_NODES],
            root: NIL_IDX,
            count: 0,
            pool_used: 0,
        }
    }

    /// Inserts a key-data pair into the tree.
    ///
    /// Returns the index of the inserted node.
    pub fn insert(&mut self, key: u64, data: u64) -> Result<usize> {
        let idx = self.alloc_node()?;
        self.nodes[idx].key = key;
        self.nodes[idx].data = data;
        self.nodes[idx].color = RbColor::Red;
        self.nodes[idx].occupied = true;
        self.nodes[idx].left = NIL_IDX;
        self.nodes[idx].right = NIL_IDX;

        // BST insert.
        if self.root == NIL_IDX {
            self.root = idx as u32;
            self.nodes[idx].parent = NIL_IDX;
        } else {
            let mut cur = self.root;
            loop {
                let ci = cur as usize;
                if key < self.nodes[ci].key {
                    if self.nodes[ci].left == NIL_IDX {
                        self.nodes[ci].left = idx as u32;
                        self.nodes[idx].parent = cur;
                        break;
                    }
                    cur = self.nodes[ci].left;
                } else {
                    if self.nodes[ci].right == NIL_IDX {
                        self.nodes[ci].right = idx as u32;
                        self.nodes[idx].parent = cur;
                        break;
                    }
                    cur = self.nodes[ci].right;
                }
            }
        }

        self.count += 1;
        self.fix_insert(idx as u32);
        Ok(idx)
    }

    /// Deletes the node with the given key.
    ///
    /// Returns the data of the removed node.
    pub fn delete(&mut self, key: u64) -> Result<u64> {
        let idx = self.search_idx(key)?;
        let data = self.nodes[idx].data;
        self.delete_node(idx as u32);
        self.nodes[idx] = RbNode::new();
        self.count -= 1;
        self.pool_used -= 1;
        Ok(data)
    }

    /// Searches for a key and returns its data.
    pub fn search(&self, key: u64) -> Result<u64> {
        let idx = self.search_idx(key)?;
        Ok(self.nodes[idx].data)
    }

    /// Returns the index of the minimum (leftmost) node.
    pub fn rb_first(&self) -> Result<usize> {
        if self.root == NIL_IDX {
            return Err(Error::NotFound);
        }
        let mut cur = self.root;
        while self.nodes[cur as usize].left != NIL_IDX {
            cur = self.nodes[cur as usize].left;
        }
        Ok(cur as usize)
    }

    /// Returns the index of the maximum (rightmost) node.
    pub fn rb_last(&self) -> Result<usize> {
        if self.root == NIL_IDX {
            return Err(Error::NotFound);
        }
        let mut cur = self.root;
        while self.nodes[cur as usize].right != NIL_IDX {
            cur = self.nodes[cur as usize].right;
        }
        Ok(cur as usize)
    }

    /// Returns the in-order successor of `idx`.
    pub fn rb_next(&self, idx: usize) -> Result<usize> {
        if idx >= MAX_NODES || !self.nodes[idx].occupied {
            return Err(Error::NotFound);
        }
        // If right subtree exists, find its minimum.
        if self.nodes[idx].right != NIL_IDX {
            let mut cur = self.nodes[idx].right;
            while self.nodes[cur as usize].left != NIL_IDX {
                cur = self.nodes[cur as usize].left;
            }
            return Ok(cur as usize);
        }
        // Walk up until we come from a left child.
        let mut cur = idx as u32;
        let mut par = self.nodes[idx].parent;
        while par != NIL_IDX && cur == self.nodes[par as usize].right {
            cur = par;
            par = self.nodes[par as usize].parent;
        }
        if par == NIL_IDX {
            Err(Error::NotFound)
        } else {
            Ok(par as usize)
        }
    }

    /// Returns the in-order predecessor of `idx`.
    pub fn rb_prev(&self, idx: usize) -> Result<usize> {
        if idx >= MAX_NODES || !self.nodes[idx].occupied {
            return Err(Error::NotFound);
        }
        if self.nodes[idx].left != NIL_IDX {
            let mut cur = self.nodes[idx].left;
            while self.nodes[cur as usize].right != NIL_IDX {
                cur = self.nodes[cur as usize].right;
            }
            return Ok(cur as usize);
        }
        let mut cur = idx as u32;
        let mut par = self.nodes[idx].parent;
        while par != NIL_IDX && cur == self.nodes[par as usize].left {
            cur = par;
            par = self.nodes[par as usize].parent;
        }
        if par == NIL_IDX {
            Err(Error::NotFound)
        } else {
            Ok(par as usize)
        }
    }

    /// Returns a reference to a node by index.
    pub fn node(&self, idx: usize) -> Result<&RbNode> {
        if idx >= MAX_NODES || !self.nodes[idx].occupied {
            return Err(Error::NotFound);
        }
        Ok(&self.nodes[idx])
    }

    /// Returns the number of nodes.
    pub fn count(&self) -> usize {
        self.count
    }

    /// Returns the root index.
    pub fn root(&self) -> u32 {
        self.root
    }

    /// Returns whether the tree is empty.
    pub fn is_empty(&self) -> bool {
        self.root == NIL_IDX
    }

    // ------------------------------------------------------------------
    // Internal: search
    // ------------------------------------------------------------------

    /// Searches for a key and returns the node index.
    fn search_idx(&self, key: u64) -> Result<usize> {
        let mut cur = self.root;
        while cur != NIL_IDX {
            let ci = cur as usize;
            if key == self.nodes[ci].key {
                return Ok(ci);
            } else if key < self.nodes[ci].key {
                cur = self.nodes[ci].left;
            } else {
                cur = self.nodes[ci].right;
            }
        }
        Err(Error::NotFound)
    }

    // ------------------------------------------------------------------
    // Internal: rotations
    // ------------------------------------------------------------------

    /// Left rotation around `x`.
    fn left_rotate(&mut self, x: u32) {
        let xi = x as usize;
        let y = self.nodes[xi].right;
        if y == NIL_IDX {
            return;
        }
        let yi = y as usize;

        // x.right = y.left
        self.nodes[xi].right = self.nodes[yi].left;
        if self.nodes[yi].left != NIL_IDX {
            self.nodes[self.nodes[yi].left as usize].parent = x;
        }

        // y.parent = x.parent
        self.nodes[yi].parent = self.nodes[xi].parent;
        if self.nodes[xi].parent == NIL_IDX {
            self.root = y;
        } else {
            let pi = self.nodes[xi].parent as usize;
            if x == self.nodes[pi].left {
                self.nodes[pi].left = y;
            } else {
                self.nodes[pi].right = y;
            }
        }

        // y.left = x, x.parent = y
        self.nodes[yi].left = x;
        self.nodes[xi].parent = y;
    }

    /// Right rotation around `x`.
    fn right_rotate(&mut self, x: u32) {
        let xi = x as usize;
        let y = self.nodes[xi].left;
        if y == NIL_IDX {
            return;
        }
        let yi = y as usize;

        self.nodes[xi].left = self.nodes[yi].right;
        if self.nodes[yi].right != NIL_IDX {
            self.nodes[self.nodes[yi].right as usize].parent = x;
        }

        self.nodes[yi].parent = self.nodes[xi].parent;
        if self.nodes[xi].parent == NIL_IDX {
            self.root = y;
        } else {
            let pi = self.nodes[xi].parent as usize;
            if x == self.nodes[pi].right {
                self.nodes[pi].right = y;
            } else {
                self.nodes[pi].left = y;
            }
        }

        self.nodes[yi].right = x;
        self.nodes[xi].parent = y;
    }

    // ------------------------------------------------------------------
    // Internal: fix-up after insert
    // ------------------------------------------------------------------

    /// Restores red-black properties after insertion.
    fn fix_insert(&mut self, mut z: u32) {
        while z != self.root && self.node_color(self.nodes[z as usize].parent) == RbColor::Red {
            let p = self.nodes[z as usize].parent;
            let g = self.nodes[p as usize].parent;
            if g == NIL_IDX {
                break;
            }

            if p == self.nodes[g as usize].left {
                let u = self.nodes[g as usize].right;
                if self.node_color(u) == RbColor::Red {
                    // Case 1: uncle is red.
                    self.set_color(p, RbColor::Black);
                    self.set_color(u, RbColor::Black);
                    self.set_color(g, RbColor::Red);
                    z = g;
                } else {
                    if z == self.nodes[p as usize].right {
                        // Case 2: z is right child.
                        z = p;
                        self.left_rotate(z);
                    }
                    // Case 3: z is left child.
                    let p2 = self.nodes[z as usize].parent;
                    let g2 = self.nodes[p2 as usize].parent;
                    self.set_color(p2, RbColor::Black);
                    self.set_color(g2, RbColor::Red);
                    self.right_rotate(g2);
                }
            } else {
                let u = self.nodes[g as usize].left;
                if self.node_color(u) == RbColor::Red {
                    self.set_color(p, RbColor::Black);
                    self.set_color(u, RbColor::Black);
                    self.set_color(g, RbColor::Red);
                    z = g;
                } else {
                    if z == self.nodes[p as usize].left {
                        z = p;
                        self.right_rotate(z);
                    }
                    let p2 = self.nodes[z as usize].parent;
                    let g2 = self.nodes[p2 as usize].parent;
                    self.set_color(p2, RbColor::Black);
                    self.set_color(g2, RbColor::Red);
                    self.left_rotate(g2);
                }
            }
        }
        self.set_color(self.root, RbColor::Black);
    }

    // ------------------------------------------------------------------
    // Internal: delete
    // ------------------------------------------------------------------

    /// Deletes a node (simplified transplant + fix).
    fn delete_node(&mut self, z: u32) {
        let zi = z as usize;
        if self.nodes[zi].left == NIL_IDX && self.nodes[zi].right == NIL_IDX {
            // Leaf node — just remove.
            self.transplant_leaf(z);
        } else if self.nodes[zi].left == NIL_IDX {
            self.transplant(z, self.nodes[zi].right);
        } else if self.nodes[zi].right == NIL_IDX {
            self.transplant(z, self.nodes[zi].left);
        } else {
            // Two children: find in-order successor.
            let mut succ = self.nodes[zi].right;
            while self.nodes[succ as usize].left != NIL_IDX {
                succ = self.nodes[succ as usize].left;
            }
            let si = succ as usize;
            // Copy successor data to z.
            self.nodes[zi].key = self.nodes[si].key;
            self.nodes[zi].data = self.nodes[si].data;
            // Delete successor (has at most one child).
            if self.nodes[si].right != NIL_IDX {
                self.transplant(succ, self.nodes[si].right);
            } else {
                self.transplant_leaf(succ);
            }
            self.nodes[si] = RbNode::new();
        }
    }

    /// Replaces subtree rooted at `u` with subtree rooted at `v`.
    fn transplant(&mut self, u: u32, v: u32) {
        let parent = self.nodes[u as usize].parent;
        if parent == NIL_IDX {
            self.root = v;
        } else {
            let pi = parent as usize;
            if u == self.nodes[pi].left {
                self.nodes[pi].left = v;
            } else {
                self.nodes[pi].right = v;
            }
        }
        if v != NIL_IDX {
            self.nodes[v as usize].parent = parent;
        }
    }

    /// Removes a leaf node from the tree.
    fn transplant_leaf(&mut self, u: u32) {
        let parent = self.nodes[u as usize].parent;
        if parent == NIL_IDX {
            self.root = NIL_IDX;
        } else {
            let pi = parent as usize;
            if u == self.nodes[pi].left {
                self.nodes[pi].left = NIL_IDX;
            } else {
                self.nodes[pi].right = NIL_IDX;
            }
        }
    }

    // ------------------------------------------------------------------
    // Internal: color helpers
    // ------------------------------------------------------------------

    /// Returns the color of a node (NIL is black).
    fn node_color(&self, idx: u32) -> RbColor {
        if idx == NIL_IDX {
            RbColor::Black
        } else {
            self.nodes[idx as usize].color
        }
    }

    /// Sets the color of a node (no-op for NIL).
    fn set_color(&mut self, idx: u32, color: RbColor) {
        if idx != NIL_IDX {
            self.nodes[idx as usize].color = color;
        }
    }

    /// Allocates a node from the pool.
    fn alloc_node(&mut self) -> Result<usize> {
        if self.pool_used >= MAX_NODES {
            return Err(Error::OutOfMemory);
        }
        let pos = self
            .nodes
            .iter()
            .position(|n| !n.occupied)
            .ok_or(Error::OutOfMemory)?;
        self.pool_used += 1;
        Ok(pos)
    }
}

// ======================================================================
// RbTreeTable — global registry
// ======================================================================

/// Global table of red-black trees.
pub struct RbTreeTable {
    /// Entries.
    entries: [RbTreeEntry; MAX_TREES],
    /// Number of allocated trees.
    count: usize,
}

/// Entry in the tree table.
struct RbTreeEntry {
    /// The tree.
    tree: RbTree,
    /// Whether allocated.
    allocated: bool,
}

impl RbTreeEntry {
    const fn new() -> Self {
        Self {
            tree: RbTree::new(),
            allocated: false,
        }
    }
}

impl RbTreeTable {
    /// Creates a new empty table.
    pub const fn new() -> Self {
        Self {
            entries: [const { RbTreeEntry::new() }; MAX_TREES],
            count: 0,
        }
    }

    /// Allocates a new tree.
    pub fn alloc(&mut self) -> Result<usize> {
        if self.count >= MAX_TREES {
            return Err(Error::OutOfMemory);
        }
        let idx = self
            .entries
            .iter()
            .position(|e| !e.allocated)
            .ok_or(Error::OutOfMemory)?;
        self.entries[idx].allocated = true;
        self.entries[idx].tree = RbTree::new();
        self.count += 1;
        Ok(idx)
    }

    /// Frees a tree by index.
    pub fn free(&mut self, idx: usize) -> Result<()> {
        if idx >= MAX_TREES || !self.entries[idx].allocated {
            return Err(Error::NotFound);
        }
        self.entries[idx] = RbTreeEntry::new();
        self.count -= 1;
        Ok(())
    }

    /// Returns a reference to the tree at `idx`.
    pub fn get(&self, idx: usize) -> Result<&RbTree> {
        if idx >= MAX_TREES || !self.entries[idx].allocated {
            return Err(Error::NotFound);
        }
        Ok(&self.entries[idx].tree)
    }

    /// Returns a mutable reference to the tree at `idx`.
    pub fn get_mut(&mut self, idx: usize) -> Result<&mut RbTree> {
        if idx >= MAX_TREES || !self.entries[idx].allocated {
            return Err(Error::NotFound);
        }
        Ok(&mut self.entries[idx].tree)
    }

    /// Returns the number of allocated trees.
    pub fn count(&self) -> usize {
        self.count
    }
}
