// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Radix tree data structure.
//!
//! A radix tree (compact trie) provides efficient lookup, insertion,
//! and deletion of values indexed by unsigned integer keys. Each
//! internal node has up to `RADIX_TREE_MAP_SIZE` slots, and the
//! tree height grows as needed for larger keys.
//!
//! # Structure
//!
//! ```text
//!   RadixTree (root)
//!   └── node (height 2, shift 12)
//!       ├── slot[0] → node (height 1, shift 6)
//!       │   ├── slot[0] → leaf value
//!       │   ├── slot[1] → leaf value
//!       │   └── ...
//!       ├── slot[1] → node (height 1, shift 6)
//!       └── ...
//!
//!   Key decomposition (6 bits per level):
//!   key = 0x123 → level2[0x0] → level1[0x04] → slot[0x23]
//! ```
//!
//! # Tags
//!
//! Each entry can have up to 3 tags (dirty, writeback, towrite)
//! tracked as bitmasks per node, enabling efficient tagged lookups
//! (e.g., "find all dirty pages").
//!
//! # Reference
//!
//! Linux `lib/radix-tree.c`, `include/linux/radix-tree.h`.

use oncrix_lib::{Error, Result};

// ======================================================================
// Constants
// ======================================================================

/// Bits per radix tree level (6 → 64 slots per node).
const RADIX_TREE_MAP_SHIFT: usize = 6;

/// Number of slots per node.
const RADIX_TREE_MAP_SIZE: usize = 1 << RADIX_TREE_MAP_SHIFT;

/// Mask for extracting slot index at one level.
const RADIX_TREE_MAP_MASK: u64 = (RADIX_TREE_MAP_SIZE - 1) as u64;

/// Maximum tree height (64-bit keys / 6 bits per level).
const RADIX_TREE_MAX_HEIGHT: usize = 11;

/// Maximum total nodes in the tree.
const MAX_NODES: usize = 1024;

/// Number of tags.
const RADIX_TREE_MAX_TAGS: usize = 3;

/// Tag: page cache dirty.
pub const PAGECACHE_TAG_DIRTY: usize = 0;
/// Tag: page cache writeback.
pub const PAGECACHE_TAG_WRITEBACK: usize = 1;
/// Tag: page cache to-write.
pub const PAGECACHE_TAG_TOWRITE: usize = 2;

/// Empty slot sentinel.
const SLOT_EMPTY: u64 = 0;

// ======================================================================
// Radix tree node
// ======================================================================

/// A node in the radix tree.
pub struct RadixTreeNode {
    /// Slot values (leaf: user value, internal: node index + 1).
    slots: [u64; RADIX_TREE_MAP_SIZE],
    /// Tag bitmasks (one u64 per tag, bit N = slot N).
    tags: [u64; RADIX_TREE_MAX_TAGS],
    /// Number of occupied slots.
    count: u8,
    /// Offset of this node within the parent.
    offset: u8,
    /// Parent node index (0 = root or no parent).
    parent: u16,
    /// Height/shift for this node.
    shift: u8,
    /// Whether this node is in use.
    in_use: bool,
}

impl RadixTreeNode {
    /// Creates an empty node.
    pub const fn new() -> Self {
        Self {
            slots: [SLOT_EMPTY; RADIX_TREE_MAP_SIZE],
            tags: [0u64; RADIX_TREE_MAX_TAGS],
            count: 0,
            offset: 0,
            parent: 0,
            shift: 0,
            in_use: false,
        }
    }

    /// Returns the number of occupied slots.
    pub fn count(&self) -> u8 {
        self.count
    }

    /// Returns whether the node has no entries.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Returns whether a specific tag is set on a slot.
    pub fn tag_get(&self, slot: usize, tag: usize) -> bool {
        if slot >= RADIX_TREE_MAP_SIZE || tag >= RADIX_TREE_MAX_TAGS {
            return false;
        }
        (self.tags[tag] & (1u64 << slot)) != 0
    }

    /// Sets a tag on a slot.
    pub fn tag_set(&mut self, slot: usize, tag: usize) {
        if slot < RADIX_TREE_MAP_SIZE && tag < RADIX_TREE_MAX_TAGS {
            self.tags[tag] |= 1u64 << slot;
        }
    }

    /// Clears a tag on a slot.
    pub fn tag_clear(&mut self, slot: usize, tag: usize) {
        if slot < RADIX_TREE_MAP_SIZE && tag < RADIX_TREE_MAX_TAGS {
            self.tags[tag] &= !(1u64 << slot);
        }
    }

    /// Returns whether any slot has a given tag.
    pub fn any_tag(&self, tag: usize) -> bool {
        if tag >= RADIX_TREE_MAX_TAGS {
            return false;
        }
        self.tags[tag] != 0
    }
}

// ======================================================================
// Node pool
// ======================================================================

/// Pool of radix tree nodes.
struct NodePool {
    /// Node storage.
    nodes: [RadixTreeNode; MAX_NODES],
    /// Number of allocated nodes.
    allocated: usize,
}

impl NodePool {
    /// Creates a new node pool.
    const fn new() -> Self {
        Self {
            nodes: [const { RadixTreeNode::new() }; MAX_NODES],
            allocated: 0,
        }
    }

    /// Allocates a node, returning its index.
    fn alloc(&mut self) -> Result<usize> {
        let slot = self
            .nodes
            .iter()
            .position(|n| !n.in_use)
            .ok_or(Error::OutOfMemory)?;
        self.nodes[slot] = RadixTreeNode::new();
        self.nodes[slot].in_use = true;
        self.allocated += 1;
        Ok(slot)
    }

    /// Frees a node.
    fn free(&mut self, index: usize) {
        if index < MAX_NODES && self.nodes[index].in_use {
            self.nodes[index].in_use = false;
            self.allocated = self.allocated.saturating_sub(1);
        }
    }
}

// ======================================================================
// Radix tree
// ======================================================================

/// A radix tree indexed by u64 keys.
pub struct RadixTree {
    /// Root node index (0 if tree is empty, node_index + 1 when
    /// populated).
    root: u64,
    /// Current tree height.
    height: usize,
    /// Node pool.
    pool: NodePool,
    /// Number of entries in the tree.
    nr_entries: usize,
}

impl RadixTree {
    /// Creates a new empty radix tree.
    pub const fn new() -> Self {
        Self {
            root: SLOT_EMPTY,
            height: 0,
            pool: NodePool::new(),
            nr_entries: 0,
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

    /// Returns the tree height.
    pub fn height(&self) -> usize {
        self.height
    }

    /// Returns the number of allocated nodes.
    pub fn node_count(&self) -> usize {
        self.pool.allocated
    }

    /// Looks up a value by key.
    pub fn lookup(&self, key: u64) -> Option<u64> {
        if self.root == SLOT_EMPTY {
            return None;
        }
        let root_idx = (self.root - 1) as usize;
        if root_idx >= MAX_NODES || !self.pool.nodes[root_idx].in_use {
            return None;
        }
        self.descend(root_idx, key)
    }

    /// Inserts a key-value pair.
    pub fn insert(&mut self, key: u64, value: u64) -> Result<()> {
        if value == SLOT_EMPTY {
            return Err(Error::InvalidArgument);
        }
        // Ensure the tree is tall enough.
        self.ensure_height(key)?;
        if self.root == SLOT_EMPTY {
            let node_idx = self.pool.alloc()?;
            self.pool.nodes[node_idx].shift = 0;
            self.root = (node_idx + 1) as u64;
            self.height = 1;
        }
        let root_idx = (self.root - 1) as usize;
        self.insert_into(root_idx, key, value)?;
        self.nr_entries += 1;
        Ok(())
    }

    /// Deletes a key, returning the old value if present.
    pub fn delete(&mut self, key: u64) -> Option<u64> {
        if self.root == SLOT_EMPTY {
            return None;
        }
        let root_idx = (self.root - 1) as usize;
        let old = self.delete_from(root_idx, key);
        if old.is_some() {
            self.nr_entries = self.nr_entries.saturating_sub(1);
        }
        old
    }

    /// Sets a tag on a key.
    pub fn tag_set(&mut self, key: u64, tag: usize) -> Result<()> {
        if tag >= RADIX_TREE_MAX_TAGS {
            return Err(Error::InvalidArgument);
        }
        if self.root == SLOT_EMPTY {
            return Err(Error::NotFound);
        }
        let root_idx = (self.root - 1) as usize;
        self.set_tag_at(root_idx, key, tag)
    }

    /// Clears a tag on a key.
    pub fn tag_clear(&mut self, key: u64, tag: usize) -> Result<()> {
        if tag >= RADIX_TREE_MAX_TAGS {
            return Err(Error::InvalidArgument);
        }
        if self.root == SLOT_EMPTY {
            return Err(Error::NotFound);
        }
        let root_idx = (self.root - 1) as usize;
        self.clear_tag_at(root_idx, key, tag)
    }

    /// Gang lookup: finds up to `max_items` entries starting from
    /// `first_key`. Returns the number of items found and fills
    /// `keys` and `values`.
    pub fn gang_lookup(
        &self,
        first_key: u64,
        keys: &mut [u64],
        values: &mut [u64],
        max_items: usize,
    ) -> usize {
        let limit = max_items.min(keys.len()).min(values.len());
        let mut found = 0;
        let mut key = first_key;
        // Simple linear scan — in a real implementation this would
        // walk the tree more efficiently.
        while found < limit {
            if let Some(val) = self.lookup(key) {
                keys[found] = key;
                values[found] = val;
                found += 1;
            }
            key = match key.checked_add(1) {
                Some(k) => k,
                None => break,
            };
            // Limit scan range to avoid excessive iteration.
            if key > first_key.saturating_add((limit * 64) as u64) {
                break;
            }
        }
        found
    }

    // --- Internal helpers ---

    /// Descends from a node to find a value for a key.
    fn descend(&self, node_idx: usize, key: u64) -> Option<u64> {
        if node_idx >= MAX_NODES {
            return None;
        }
        let shift = self.pool.nodes[node_idx].shift as u64;
        let slot_idx = ((key >> shift) & RADIX_TREE_MAP_MASK) as usize;
        let slot_val = self.pool.nodes[node_idx].slots[slot_idx];
        if slot_val == SLOT_EMPTY {
            return None;
        }
        if shift == 0 {
            // Leaf level — slot_val is the stored value.
            return Some(slot_val);
        }
        // Internal — slot_val is node_index + 1.
        let child_idx = (slot_val - 1) as usize;
        self.descend(child_idx, key)
    }

    /// Inserts into the subtree rooted at `node_idx`.
    fn insert_into(&mut self, node_idx: usize, key: u64, value: u64) -> Result<()> {
        let shift = self.pool.nodes[node_idx].shift as u64;
        let slot_idx = ((key >> shift) & RADIX_TREE_MAP_MASK) as usize;
        if shift == 0 {
            // Leaf level.
            if self.pool.nodes[node_idx].slots[slot_idx] == SLOT_EMPTY {
                self.pool.nodes[node_idx].count += 1;
            }
            self.pool.nodes[node_idx].slots[slot_idx] = value;
            return Ok(());
        }
        // Internal level — ensure child exists.
        if self.pool.nodes[node_idx].slots[slot_idx] == SLOT_EMPTY {
            let child = self.pool.alloc()?;
            self.pool.nodes[child].shift = (shift - RADIX_TREE_MAP_SHIFT as u64) as u8;
            self.pool.nodes[child].parent = node_idx as u16;
            self.pool.nodes[child].offset = slot_idx as u8;
            self.pool.nodes[node_idx].slots[slot_idx] = (child + 1) as u64;
            self.pool.nodes[node_idx].count += 1;
        }
        let child_idx = (self.pool.nodes[node_idx].slots[slot_idx] - 1) as usize;
        self.insert_into(child_idx, key, value)
    }

    /// Deletes from the subtree rooted at `node_idx`.
    fn delete_from(&mut self, node_idx: usize, key: u64) -> Option<u64> {
        if node_idx >= MAX_NODES || !self.pool.nodes[node_idx].in_use {
            return None;
        }
        let shift = self.pool.nodes[node_idx].shift as u64;
        let slot_idx = ((key >> shift) & RADIX_TREE_MAP_MASK) as usize;
        let slot_val = self.pool.nodes[node_idx].slots[slot_idx];
        if slot_val == SLOT_EMPTY {
            return None;
        }
        if shift == 0 {
            self.pool.nodes[node_idx].slots[slot_idx] = SLOT_EMPTY;
            self.pool.nodes[node_idx].count = self.pool.nodes[node_idx].count.saturating_sub(1);
            // Clear tags.
            for tag in 0..RADIX_TREE_MAX_TAGS {
                self.pool.nodes[node_idx].tag_clear(slot_idx, tag);
            }
            return Some(slot_val);
        }
        let child_idx = (slot_val - 1) as usize;
        let result = self.delete_from(child_idx, key);
        // If child is now empty, free it.
        if result.is_some() && child_idx < MAX_NODES && self.pool.nodes[child_idx].is_empty() {
            self.pool.free(child_idx);
            self.pool.nodes[node_idx].slots[slot_idx] = SLOT_EMPTY;
            self.pool.nodes[node_idx].count = self.pool.nodes[node_idx].count.saturating_sub(1);
        }
        result
    }

    /// Ensures the tree has enough height for a given key.
    fn ensure_height(&mut self, key: u64) -> Result<()> {
        let needed = if key == 0 {
            1
        } else {
            let bits = 64 - key.leading_zeros() as usize;
            (bits + RADIX_TREE_MAP_SHIFT - 1) / RADIX_TREE_MAP_SHIFT
        };
        if needed > RADIX_TREE_MAX_HEIGHT {
            return Err(Error::InvalidArgument);
        }
        // Grow the tree if needed.
        while self.height < needed && self.root != SLOT_EMPTY {
            let new_root = self.pool.alloc()?;
            let new_shift = self.height * RADIX_TREE_MAP_SHIFT;
            self.pool.nodes[new_root].shift = new_shift as u8;
            self.pool.nodes[new_root].slots[0] = self.root;
            self.pool.nodes[new_root].count = 1;
            self.root = (new_root + 1) as u64;
            self.height += 1;
        }
        if self.height < needed {
            self.height = needed;
        }
        Ok(())
    }

    /// Sets a tag at a specific key.
    fn set_tag_at(&mut self, node_idx: usize, key: u64, tag: usize) -> Result<()> {
        if node_idx >= MAX_NODES {
            return Err(Error::NotFound);
        }
        let shift = self.pool.nodes[node_idx].shift as u64;
        let slot_idx = ((key >> shift) & RADIX_TREE_MAP_MASK) as usize;
        if self.pool.nodes[node_idx].slots[slot_idx] == SLOT_EMPTY {
            return Err(Error::NotFound);
        }
        self.pool.nodes[node_idx].tag_set(slot_idx, tag);
        if shift > 0 {
            let child = (self.pool.nodes[node_idx].slots[slot_idx] - 1) as usize;
            self.set_tag_at(child, key, tag)?;
        }
        Ok(())
    }

    /// Clears a tag at a specific key.
    fn clear_tag_at(&mut self, node_idx: usize, key: u64, tag: usize) -> Result<()> {
        if node_idx >= MAX_NODES {
            return Err(Error::NotFound);
        }
        let shift = self.pool.nodes[node_idx].shift as u64;
        let slot_idx = ((key >> shift) & RADIX_TREE_MAP_MASK) as usize;
        if self.pool.nodes[node_idx].slots[slot_idx] == SLOT_EMPTY {
            return Err(Error::NotFound);
        }
        if shift == 0 {
            self.pool.nodes[node_idx].tag_clear(slot_idx, tag);
        } else {
            let child = (self.pool.nodes[node_idx].slots[slot_idx] - 1) as usize;
            self.clear_tag_at(child, key, tag)?;
            // Propagate: clear parent tag if no child has it.
            if child < MAX_NODES && !self.pool.nodes[child].any_tag(tag) {
                self.pool.nodes[node_idx].tag_clear(slot_idx, tag);
            }
        }
        Ok(())
    }
}
