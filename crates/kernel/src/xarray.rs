// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! XArray data structure.
//!
//! The XArray is the modern replacement for the radix tree in the
//! Linux kernel. It provides an automatically-resizing array indexed
//! by unsigned long keys, with support for marks (tags), multi-index
//! entries, and efficient iteration.
//!
//! # Design
//!
//! ```text
//! XArray
//! ├── xa_head → XaNode (or direct value for small trees)
//! │   ├── slots[0] → value
//! │   ├── slots[1] → value
//! │   ├── slots[2] → XaNode (subtree)
//! │   │   ├── slots[0] → value
//! │   │   └── ...
//! │   └── ...
//! └── xa_flags (GFP flags, lock state)
//!
//! Marks: XA_MARK_0, XA_MARK_1, XA_MARK_2
//!   - Per-entry marks propagated through internal nodes
//!   - Used for tagged iteration (e.g., dirty page lookup)
//! ```
//!
//! # Reference
//!
//! Linux `lib/xarray.c`, `include/linux/xarray.h`.

use oncrix_lib::{Error, Result};

// ======================================================================
// Constants
// ======================================================================

/// Bits per XArray level (same as radix tree: 6).
const XA_CHUNK_SHIFT: usize = 6;

/// Slots per node.
const XA_CHUNK_SIZE: usize = 1 << XA_CHUNK_SHIFT;

/// Slot index mask.
const XA_CHUNK_MASK: u64 = (XA_CHUNK_SIZE - 1) as u64;

/// Maximum tree height.
const _XA_MAX_HEIGHT: usize = 11;

/// Maximum nodes.
const MAX_XA_NODES: usize = 1024;

/// Number of mark types.
const XA_MAX_MARKS: usize = 3;

/// Mark indices.
pub const XA_MARK_0: usize = 0;
pub const XA_MARK_1: usize = 1;
pub const XA_MARK_2: usize = 2;

/// Empty value sentinel.
const XA_EMPTY: u64 = 0;

/// Value encoding: values are stored directly if the low bit is set
/// (internal node pointers always have low bits clear due to
/// alignment).
const _XA_VALUE_BIT: u64 = 1;

/// Maximum index for the xarray.
const _XA_MAX_INDEX: u64 = u64::MAX;

// ======================================================================
// XArray flags
// ======================================================================

/// XArray allocation flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XaFlags {
    /// Normal allocation.
    Normal,
    /// Allocate with ID tracking (auto-assign indices).
    Alloc,
    /// Allocate starting from index 1 (skip 0).
    Alloc1,
}

// ======================================================================
// XArray node
// ======================================================================

/// An internal node in the XArray.
pub struct XaNode {
    /// Slot values.
    slots: [u64; XA_CHUNK_SIZE],
    /// Mark bitmasks per mark type.
    marks: [u64; XA_MAX_MARKS],
    /// Number of occupied slots.
    count: u8,
    /// Number of slots that are values (not nodes).
    nr_values: u8,
    /// Parent node index (0 = root).
    parent: u16,
    /// Offset within parent.
    offset: u8,
    /// Shift (bits to shift key at this level).
    shift: u8,
    /// Whether this node is in use.
    in_use: bool,
}

impl XaNode {
    /// Creates an empty XArray node.
    pub const fn new() -> Self {
        Self {
            slots: [XA_EMPTY; XA_CHUNK_SIZE],
            marks: [0u64; XA_MAX_MARKS],
            count: 0,
            nr_values: 0,
            parent: 0,
            offset: 0,
            shift: 0,
            in_use: false,
        }
    }

    /// Returns the slot count.
    pub fn count(&self) -> u8 {
        self.count
    }

    /// Returns whether a mark is set on a slot.
    pub fn get_mark(&self, slot: usize, mark: usize) -> bool {
        if slot >= XA_CHUNK_SIZE || mark >= XA_MAX_MARKS {
            return false;
        }
        (self.marks[mark] & (1u64 << slot)) != 0
    }

    /// Sets a mark on a slot.
    pub fn set_mark(&mut self, slot: usize, mark: usize) {
        if slot < XA_CHUNK_SIZE && mark < XA_MAX_MARKS {
            self.marks[mark] |= 1u64 << slot;
        }
    }

    /// Clears a mark on a slot.
    pub fn clear_mark(&mut self, slot: usize, mark: usize) {
        if slot < XA_CHUNK_SIZE && mark < XA_MAX_MARKS {
            self.marks[mark] &= !(1u64 << slot);
        }
    }

    /// Returns whether any slot has a given mark.
    pub fn any_mark(&self, mark: usize) -> bool {
        if mark >= XA_MAX_MARKS {
            return false;
        }
        self.marks[mark] != 0
    }

    /// Returns the first slot index with a given mark set.
    pub fn find_marked_slot(&self, mark: usize, start: usize) -> Option<usize> {
        if mark >= XA_MAX_MARKS {
            return None;
        }
        let mask = self.marks[mark] >> start;
        if mask == 0 {
            return None;
        }
        let bit = mask.trailing_zeros() as usize + start;
        if bit < XA_CHUNK_SIZE { Some(bit) } else { None }
    }
}

// ======================================================================
// XArray
// ======================================================================

/// The XArray data structure.
pub struct XArray {
    /// Root node index + 1 (0 = empty).
    xa_head: u64,
    /// Flags.
    xa_flags: XaFlags,
    /// Node pool.
    nodes: [XaNode; MAX_XA_NODES],
    /// Number of allocated nodes.
    nr_nodes: usize,
    /// Tree height.
    height: usize,
    /// Number of stored entries.
    nr_entries: usize,
    /// Next ID for Alloc mode.
    next_alloc_id: u64,
}

impl XArray {
    /// Creates a new empty XArray.
    pub const fn new() -> Self {
        Self {
            xa_head: XA_EMPTY,
            xa_flags: XaFlags::Normal,
            nodes: [const { XaNode::new() }; MAX_XA_NODES],
            nr_nodes: 0,
            height: 0,
            nr_entries: 0,
            next_alloc_id: 0,
        }
    }

    /// Creates an XArray with specific flags.
    pub const fn with_flags(flags: XaFlags) -> Self {
        let next_id = match flags {
            XaFlags::Alloc1 => 1,
            _ => 0,
        };
        Self {
            xa_head: XA_EMPTY,
            xa_flags: flags,
            nodes: [const { XaNode::new() }; MAX_XA_NODES],
            nr_nodes: 0,
            height: 0,
            nr_entries: 0,
            next_alloc_id: next_id,
        }
    }

    /// Returns the number of entries.
    pub fn len(&self) -> usize {
        self.nr_entries
    }

    /// Returns whether the xarray is empty.
    pub fn is_empty(&self) -> bool {
        self.nr_entries == 0
    }

    /// Returns the flags.
    pub fn flags(&self) -> XaFlags {
        self.xa_flags
    }

    /// Returns the number of allocated nodes.
    pub fn node_count(&self) -> usize {
        self.nr_nodes
    }

    /// Stores a value at an index.
    pub fn xa_store(&mut self, index: u64, value: u64) -> Result<Option<u64>> {
        if value == XA_EMPTY {
            return Err(Error::InvalidArgument);
        }
        self.ensure_height(index)?;
        if self.xa_head == XA_EMPTY {
            let node_idx = self.alloc_node()?;
            self.nodes[node_idx].shift = 0;
            self.xa_head = (node_idx + 1) as u64;
            self.height = 1;
        }
        let root_idx = (self.xa_head - 1) as usize;
        let old = self.store_into(root_idx, index, value)?;
        if old.is_none() {
            self.nr_entries += 1;
        }
        Ok(old)
    }

    /// Loads a value from an index.
    pub fn xa_load(&self, index: u64) -> Option<u64> {
        if self.xa_head == XA_EMPTY {
            return None;
        }
        let root_idx = (self.xa_head - 1) as usize;
        self.load_from(root_idx, index)
    }

    /// Erases a value at an index, returning it.
    pub fn xa_erase(&mut self, index: u64) -> Option<u64> {
        if self.xa_head == XA_EMPTY {
            return None;
        }
        let root_idx = (self.xa_head - 1) as usize;
        let old = self.erase_from(root_idx, index);
        if old.is_some() {
            self.nr_entries = self.nr_entries.saturating_sub(1);
        }
        old
    }

    /// Allocates an index and stores a value (for Alloc mode).
    pub fn xa_alloc(&mut self, value: u64) -> Result<u64> {
        let id = self.next_alloc_id;
        self.xa_store(id, value)?;
        self.next_alloc_id = self.next_alloc_id.wrapping_add(1);
        Ok(id)
    }

    /// Finds the first entry at or after `index`.
    pub fn xa_find(&self, index: u64) -> Option<(u64, u64)> {
        // Simple linear scan from index.
        let mut key = index;
        let max_scan = 4096u64; // Limit scan range.
        while key < index.saturating_add(max_scan) {
            if let Some(val) = self.xa_load(key) {
                return Some((key, val));
            }
            key = match key.checked_add(1) {
                Some(k) => k,
                None => break,
            };
        }
        None
    }

    /// Finds the first entry strictly after `index`.
    pub fn xa_find_after(&self, index: u64) -> Option<(u64, u64)> {
        let start = match index.checked_add(1) {
            Some(s) => s,
            None => return None,
        };
        self.xa_find(start)
    }

    /// Sets a mark on an entry.
    pub fn xa_set_mark(&mut self, index: u64, mark: usize) -> Result<()> {
        if mark >= XA_MAX_MARKS {
            return Err(Error::InvalidArgument);
        }
        if self.xa_head == XA_EMPTY {
            return Err(Error::NotFound);
        }
        let root_idx = (self.xa_head - 1) as usize;
        self.set_mark_at(root_idx, index, mark)
    }

    /// Clears a mark on an entry.
    pub fn xa_clear_mark(&mut self, index: u64, mark: usize) -> Result<()> {
        if mark >= XA_MAX_MARKS {
            return Err(Error::InvalidArgument);
        }
        if self.xa_head == XA_EMPTY {
            return Err(Error::NotFound);
        }
        let root_idx = (self.xa_head - 1) as usize;
        self.clear_mark_at(root_idx, index, mark)
    }

    /// Checks if a mark is set on an entry.
    pub fn xa_get_mark(&self, index: u64, mark: usize) -> bool {
        if mark >= XA_MAX_MARKS || self.xa_head == XA_EMPTY {
            return false;
        }
        let root_idx = (self.xa_head - 1) as usize;
        self.get_mark_at(root_idx, index, mark)
    }

    // --- Internal helpers ---

    /// Allocates a node from the pool.
    fn alloc_node(&mut self) -> Result<usize> {
        let slot = self
            .nodes
            .iter()
            .position(|n| !n.in_use)
            .ok_or(Error::OutOfMemory)?;
        self.nodes[slot] = XaNode::new();
        self.nodes[slot].in_use = true;
        self.nr_nodes += 1;
        Ok(slot)
    }

    /// Frees a node back to the pool.
    fn free_node(&mut self, idx: usize) {
        if idx < MAX_XA_NODES && self.nodes[idx].in_use {
            self.nodes[idx].in_use = false;
            self.nr_nodes = self.nr_nodes.saturating_sub(1);
        }
    }

    /// Ensures the tree can hold `index`.
    fn ensure_height(&mut self, index: u64) -> Result<()> {
        let needed = if index == 0 {
            1
        } else {
            let bits = 64 - index.leading_zeros() as usize;
            (bits + XA_CHUNK_SHIFT - 1) / XA_CHUNK_SHIFT
        };
        while self.height < needed && self.xa_head != XA_EMPTY {
            let new_root = self.alloc_node()?;
            let new_shift = self.height * XA_CHUNK_SHIFT;
            self.nodes[new_root].shift = new_shift as u8;
            self.nodes[new_root].slots[0] = self.xa_head;
            self.nodes[new_root].count = 1;
            self.xa_head = (new_root + 1) as u64;
            self.height += 1;
        }
        if self.height < needed {
            self.height = needed;
        }
        Ok(())
    }

    /// Stores into a subtree.
    fn store_into(&mut self, node_idx: usize, index: u64, value: u64) -> Result<Option<u64>> {
        let shift = self.nodes[node_idx].shift as u64;
        let slot = ((index >> shift) & XA_CHUNK_MASK) as usize;
        if shift == 0 {
            let old = self.nodes[node_idx].slots[slot];
            if old == XA_EMPTY {
                self.nodes[node_idx].count += 1;
                self.nodes[node_idx].nr_values += 1;
            }
            self.nodes[node_idx].slots[slot] = value;
            return Ok(if old != XA_EMPTY { Some(old) } else { None });
        }
        if self.nodes[node_idx].slots[slot] == XA_EMPTY {
            let child = self.alloc_node()?;
            self.nodes[child].shift = (shift - XA_CHUNK_SHIFT as u64) as u8;
            self.nodes[child].parent = node_idx as u16;
            self.nodes[child].offset = slot as u8;
            self.nodes[node_idx].slots[slot] = (child + 1) as u64;
            self.nodes[node_idx].count += 1;
        }
        let child_idx = (self.nodes[node_idx].slots[slot] - 1) as usize;
        self.store_into(child_idx, index, value)
    }

    /// Loads from a subtree.
    fn load_from(&self, node_idx: usize, index: u64) -> Option<u64> {
        if node_idx >= MAX_XA_NODES || !self.nodes[node_idx].in_use {
            return None;
        }
        let shift = self.nodes[node_idx].shift as u64;
        let slot = ((index >> shift) & XA_CHUNK_MASK) as usize;
        let val = self.nodes[node_idx].slots[slot];
        if val == XA_EMPTY {
            return None;
        }
        if shift == 0 {
            return Some(val);
        }
        self.load_from((val - 1) as usize, index)
    }

    /// Erases from a subtree.
    fn erase_from(&mut self, node_idx: usize, index: u64) -> Option<u64> {
        if node_idx >= MAX_XA_NODES || !self.nodes[node_idx].in_use {
            return None;
        }
        let shift = self.nodes[node_idx].shift as u64;
        let slot = ((index >> shift) & XA_CHUNK_MASK) as usize;
        let val = self.nodes[node_idx].slots[slot];
        if val == XA_EMPTY {
            return None;
        }
        if shift == 0 {
            self.nodes[node_idx].slots[slot] = XA_EMPTY;
            self.nodes[node_idx].count = self.nodes[node_idx].count.saturating_sub(1);
            self.nodes[node_idx].nr_values = self.nodes[node_idx].nr_values.saturating_sub(1);
            for mark in 0..XA_MAX_MARKS {
                self.nodes[node_idx].clear_mark(slot, mark);
            }
            return Some(val);
        }
        let child_idx = (val - 1) as usize;
        let result = self.erase_from(child_idx, index);
        if result.is_some() && child_idx < MAX_XA_NODES && self.nodes[child_idx].count == 0 {
            self.free_node(child_idx);
            self.nodes[node_idx].slots[slot] = XA_EMPTY;
            self.nodes[node_idx].count = self.nodes[node_idx].count.saturating_sub(1);
        }
        result
    }

    /// Sets a mark in the subtree.
    fn set_mark_at(&mut self, node_idx: usize, index: u64, mark: usize) -> Result<()> {
        if node_idx >= MAX_XA_NODES {
            return Err(Error::NotFound);
        }
        let shift = self.nodes[node_idx].shift as u64;
        let slot = ((index >> shift) & XA_CHUNK_MASK) as usize;
        if self.nodes[node_idx].slots[slot] == XA_EMPTY {
            return Err(Error::NotFound);
        }
        self.nodes[node_idx].set_mark(slot, mark);
        if shift > 0 {
            let child = (self.nodes[node_idx].slots[slot] - 1) as usize;
            self.set_mark_at(child, index, mark)?;
        }
        Ok(())
    }

    /// Clears a mark in the subtree.
    fn clear_mark_at(&mut self, node_idx: usize, index: u64, mark: usize) -> Result<()> {
        if node_idx >= MAX_XA_NODES {
            return Err(Error::NotFound);
        }
        let shift = self.nodes[node_idx].shift as u64;
        let slot = ((index >> shift) & XA_CHUNK_MASK) as usize;
        if self.nodes[node_idx].slots[slot] == XA_EMPTY {
            return Err(Error::NotFound);
        }
        if shift == 0 {
            self.nodes[node_idx].clear_mark(slot, mark);
        } else {
            let child = (self.nodes[node_idx].slots[slot] - 1) as usize;
            self.clear_mark_at(child, index, mark)?;
            if child < MAX_XA_NODES && !self.nodes[child].any_mark(mark) {
                self.nodes[node_idx].clear_mark(slot, mark);
            }
        }
        Ok(())
    }

    /// Gets a mark in the subtree.
    fn get_mark_at(&self, node_idx: usize, index: u64, mark: usize) -> bool {
        if node_idx >= MAX_XA_NODES || !self.nodes[node_idx].in_use {
            return false;
        }
        let shift = self.nodes[node_idx].shift as u64;
        let slot = ((index >> shift) & XA_CHUNK_MASK) as usize;
        self.nodes[node_idx].get_mark(slot, mark)
    }
}
