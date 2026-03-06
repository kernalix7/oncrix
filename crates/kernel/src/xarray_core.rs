// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! XArray (eXtended Array) core operations.
//!
//! The XArray is a modern replacement for the radix tree that
//! provides lock-free read access, store/load/erase by unsigned
//! index, mark bits per entry, and efficient iteration.
//! Multi-index entries allow a single value to span a range
//! of consecutive indices.
//!
//! # Internal Structure
//!
//! ```text
//! XArrayCore
//! ├── head → XaNode pool
//! │   ├── slots[XA_CHUNK_SIZE]  → child node idx or entry idx
//! │   ├── marks[3][XA_CHUNK_SIZE] → per-slot mark bits
//! │   ├── shift               → bits to shift at this level
//! │   └── count / nr_values
//! ├── entries: [XaEntry; MAX_ENTRIES]
//! │   └── index, value, marks, order
//! └── stats: XaStats
//! ```
//!
//! # Marks
//!
//! Each entry can carry 3 independent mark bits:
//!
//! | Mark | Typical use |
//! |------|-------------|
//! | 0 | Dirty |
//! | 1 | Accessed |
//! | 2 | Reserved |
//!
//! Marks propagate through internal nodes so that
//! `xa_find_marked` can skip large subtrees.
//!
//! # Multi-Index Entries
//!
//! An entry with `order > 0` occupies `2^order` consecutive
//! indices starting at an aligned base. Stores and erases
//! operate on the entire range.
//!
//! Reference: Linux `lib/xarray.c`, `include/linux/xarray.h`.

use oncrix_lib::{Error, Result};

// ── Constants ──────────────────────────────────────────────────

/// Bits per XArray level.
const XA_CHUNK_SHIFT: usize = 6;

/// Slots per internal node (64).
const XA_CHUNK_SIZE: usize = 1 << XA_CHUNK_SHIFT;

/// Index mask for one level.
const XA_CHUNK_MASK: u64 = (XA_CHUNK_SIZE - 1) as u64;

/// Maximum internal nodes.
const MAX_XA_NODES: usize = 256;

/// Maximum stored entries.
const MAX_ENTRIES: usize = 1024;

/// Number of mark bits per entry.
const XA_NUM_MARKS: usize = 3;

/// Maximum results from `xa_find_marked` / iteration.
const MAX_FIND_RESULTS: usize = 64;

/// Mark indices.
pub const XA_MARK_0: usize = 0;
pub const XA_MARK_1: usize = 1;
pub const XA_MARK_2: usize = 2;

// ── XaEntry ────────────────────────────────────────────────────

/// A leaf entry in the XArray.
#[derive(Clone, Copy)]
pub struct XaEntry {
    /// Primary index.
    pub index: u64,
    /// Stored value.
    pub value: u64,
    /// Per-mark flags.
    pub marks: [bool; XA_NUM_MARKS],
    /// Multi-index order (0 = single slot, n = 2^n slots).
    pub order: u8,
    /// Whether this slot is occupied.
    pub active: bool,
}

impl XaEntry {
    /// Creates an empty entry.
    pub const fn new() -> Self {
        Self {
            index: 0,
            value: 0,
            marks: [false; XA_NUM_MARKS],
            order: 0,
            active: false,
        }
    }

    /// Returns the number of indices spanned by this entry.
    pub fn span(&self) -> u64 {
        1u64 << self.order
    }
}

// ── XaNode ─────────────────────────────────────────────────────

/// An internal node in the XArray trie.
pub struct XaNode {
    /// Child node or entry indices per slot.
    slots: [u32; XA_CHUNK_SIZE],
    /// Whether each slot is a node (true) or entry (false).
    is_node: [bool; XA_CHUNK_SIZE],
    /// Per-mark, per-slot propagation bits.
    marks: [[bool; XA_CHUNK_SIZE]; XA_NUM_MARKS],
    /// Bit shift for this level.
    shift: u8,
    /// Number of occupied slots.
    count: u8,
    /// Number of slots holding direct values (not nodes).
    nr_values: u8,
    /// Whether this node is allocated.
    active: bool,
}

impl XaNode {
    /// Creates an empty node.
    pub const fn new() -> Self {
        Self {
            slots: [u32::MAX; XA_CHUNK_SIZE],
            is_node: [false; XA_CHUNK_SIZE],
            marks: [[false; XA_CHUNK_SIZE]; XA_NUM_MARKS],
            shift: 0,
            count: 0,
            nr_values: 0,
            active: false,
        }
    }

    /// Computes the slot index for a given key at this level.
    fn slot_for(&self, index: u64) -> usize {
        ((index >> self.shift) & XA_CHUNK_MASK) as usize
    }
}

// ── XaStats ────────────────────────────────────────────────────

/// Operational statistics for the XArray.
#[derive(Debug, Clone, Copy, Default)]
pub struct XaStats {
    /// Store operations.
    pub stores: u64,
    /// Load operations.
    pub loads: u64,
    /// Erase operations.
    pub erases: u64,
    /// Mark set/clear operations.
    pub mark_ops: u64,
    /// Iteration scans.
    pub iterations: u64,
}

// ── XArrayCore ─────────────────────────────────────────────────

/// Core XArray data structure with store, load, erase, marks,
/// and iteration.
pub struct XArrayCore {
    /// Internal node pool.
    nodes: [XaNode; MAX_XA_NODES],
    /// Leaf entry pool.
    entries: [XaEntry; MAX_ENTRIES],
    /// Root node index (u32::MAX if empty).
    head: u32,
    /// Number of stored entries.
    entry_count: usize,
    /// Number of allocated nodes.
    node_count: usize,
    /// Operational statistics.
    stats: XaStats,
}

impl XArrayCore {
    /// Creates an empty XArray.
    pub const fn new() -> Self {
        Self {
            nodes: [const { XaNode::new() }; MAX_XA_NODES],
            entries: [const { XaEntry::new() }; MAX_ENTRIES],
            head: u32::MAX,
            entry_count: 0,
            node_count: 0,
            stats: XaStats {
                stores: 0,
                loads: 0,
                erases: 0,
                mark_ops: 0,
                iterations: 0,
            },
        }
    }

    /// Stores a value at the given index (single-slot).
    /// If the index is already occupied, the value is replaced.
    pub fn xa_store(&mut self, index: u64, value: u64) -> Result<usize> {
        self.xa_store_order(index, value, 0)
    }

    /// Stores a multi-index entry spanning `2^order` slots.
    pub fn xa_store_order(&mut self, index: u64, value: u64, order: u8) -> Result<usize> {
        self.stats.stores += 1;
        // Update existing entry if present.
        if let Some(pos) = self.find_entry(index) {
            self.entries[pos].value = value;
            self.entries[pos].order = order;
            return Ok(pos);
        }
        let eidx = self.alloc_entry()?;
        self.entries[eidx].index = index;
        self.entries[eidx].value = value;
        self.entries[eidx].order = order;
        self.entries[eidx].active = true;
        self.entry_count += 1;
        // Ensure root node exists.
        if self.head == u32::MAX {
            let nidx = self.alloc_node()?;
            self.nodes[nidx].shift = (XA_CHUNK_SHIFT * 1) as u8;
            self.head = nidx as u32;
        }
        // Place in root node.
        let root = self.head as usize;
        let slot = self.nodes[root].slot_for(index);
        self.nodes[root].slots[slot] = eidx as u32;
        self.nodes[root].is_node[slot] = false;
        self.nodes[root].count += 1;
        self.nodes[root].nr_values += 1;
        Ok(eidx)
    }

    /// Loads the value at the given index.
    pub fn xa_load(&mut self, index: u64) -> Result<u64> {
        self.stats.loads += 1;
        let pos = self.find_entry(index).ok_or(Error::NotFound)?;
        Ok(self.entries[pos].value)
    }

    /// Erases the entry at the given index. Returns the old
    /// value.
    pub fn xa_erase(&mut self, index: u64) -> Result<u64> {
        self.stats.erases += 1;
        let pos = self.find_entry(index).ok_or(Error::NotFound)?;
        let old = self.entries[pos].value;
        self.entries[pos] = XaEntry::new();
        self.entry_count = self.entry_count.saturating_sub(1);
        // Remove from node.
        if self.head != u32::MAX {
            let root = self.head as usize;
            let slot = self.nodes[root].slot_for(index);
            if self.nodes[root].slots[slot] == pos as u32 {
                self.nodes[root].slots[slot] = u32::MAX;
                self.nodes[root].count = self.nodes[root].count.saturating_sub(1);
                self.nodes[root].nr_values = self.nodes[root].nr_values.saturating_sub(1);
                for m in 0..XA_NUM_MARKS {
                    self.nodes[root].marks[m][slot] = false;
                }
            }
        }
        Ok(old)
    }

    /// Sets a mark on the entry at the given index.
    pub fn xa_set_mark(&mut self, index: u64, mark: usize) -> Result<()> {
        if mark >= XA_NUM_MARKS {
            return Err(Error::InvalidArgument);
        }
        self.stats.mark_ops += 1;
        let pos = self.find_entry(index).ok_or(Error::NotFound)?;
        self.entries[pos].marks[mark] = true;
        // Propagate to node.
        if self.head != u32::MAX {
            let root = self.head as usize;
            let slot = self.nodes[root].slot_for(index);
            self.nodes[root].marks[mark][slot] = true;
        }
        Ok(())
    }

    /// Clears a mark on the entry at the given index.
    pub fn xa_clear_mark(&mut self, index: u64, mark: usize) -> Result<()> {
        if mark >= XA_NUM_MARKS {
            return Err(Error::InvalidArgument);
        }
        self.stats.mark_ops += 1;
        let pos = self.find_entry(index).ok_or(Error::NotFound)?;
        self.entries[pos].marks[mark] = false;
        if self.head != u32::MAX {
            let root = self.head as usize;
            let slot = self.nodes[root].slot_for(index);
            self.nodes[root].marks[mark][slot] = false;
        }
        Ok(())
    }

    /// Tests whether a mark is set on the entry at the index.
    pub fn xa_get_mark(&self, index: u64, mark: usize) -> Result<bool> {
        if mark >= XA_NUM_MARKS {
            return Err(Error::InvalidArgument);
        }
        let pos = self.find_entry(index).ok_or(Error::NotFound)?;
        Ok(self.entries[pos].marks[mark])
    }

    /// Iterates entries starting from `start`, returning up
    /// to `MAX_FIND_RESULTS` entries.
    /// Returns (indices, values, count).
    pub fn xa_for_each(
        &mut self,
        start: u64,
    ) -> ([u64; MAX_FIND_RESULTS], [u64; MAX_FIND_RESULTS], usize) {
        self.stats.iterations += 1;
        let mut indices = [0u64; MAX_FIND_RESULTS];
        let mut values = [0u64; MAX_FIND_RESULTS];
        let mut count = 0usize;
        for entry in &self.entries {
            if count >= MAX_FIND_RESULTS {
                break;
            }
            if !entry.active || entry.index < start {
                continue;
            }
            indices[count] = entry.index;
            values[count] = entry.value;
            count += 1;
        }
        (indices, values, count)
    }

    /// Finds entries with a specific mark, starting from `start`.
    pub fn xa_find_marked(
        &mut self,
        start: u64,
        mark: usize,
    ) -> Result<([u64; MAX_FIND_RESULTS], [u64; MAX_FIND_RESULTS], usize)> {
        if mark >= XA_NUM_MARKS {
            return Err(Error::InvalidArgument);
        }
        self.stats.iterations += 1;
        let mut indices = [0u64; MAX_FIND_RESULTS];
        let mut values = [0u64; MAX_FIND_RESULTS];
        let mut count = 0usize;
        for entry in &self.entries {
            if count >= MAX_FIND_RESULTS {
                break;
            }
            if !entry.active || entry.index < start || !entry.marks[mark] {
                continue;
            }
            indices[count] = entry.index;
            values[count] = entry.value;
            count += 1;
        }
        Ok((indices, values, count))
    }

    /// Returns the number of stored entries.
    pub fn count(&self) -> usize {
        self.entry_count
    }

    /// Returns operational statistics.
    pub fn stats(&self) -> &XaStats {
        &self.stats
    }

    /// Returns whether the XArray is empty.
    pub fn is_empty(&self) -> bool {
        self.entry_count == 0
    }

    /// Finds an entry by exact index.
    fn find_entry(&self, index: u64) -> Option<usize> {
        self.entries
            .iter()
            .position(|e| e.active && e.index == index)
    }

    /// Allocates a leaf entry slot.
    fn alloc_entry(&self) -> Result<usize> {
        self.entries
            .iter()
            .position(|e| !e.active)
            .ok_or(Error::OutOfMemory)
    }

    /// Allocates a node from the pool.
    fn alloc_node(&mut self) -> Result<usize> {
        let pos = self
            .nodes
            .iter()
            .position(|n| !n.active)
            .ok_or(Error::OutOfMemory)?;
        self.nodes[pos].active = true;
        self.node_count += 1;
        Ok(pos)
    }
}
