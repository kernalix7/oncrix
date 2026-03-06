// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Lock-less linked list.
//!
//! An index-based singly-linked list designed for lock-free
//! single-producer patterns. The list uses array indices instead
//! of pointers, making it safe in `#![no_std]` environments.
//!
//! # Design
//!
//! ```text
//!   LlistHead
//!   +-------+
//!   | first |---> nodes[2] ---> nodes[0] ---> nodes[5] ---> NONE
//!   +-------+
//!
//!   Pool: [LlistNode; MAX_NODES]
//!   Each node has: next (index), data, occupied
//! ```
//!
//! # Operations
//!
//! - `llist_add()` — prepends to the list (single-producer safe).
//! - `llist_del_all()` — atomically consumes the entire list.
//! - `llist_empty()` — check if empty.
//! - `llist_for_each()` — iterate (via callback index collection).
//! - `reverse()` — reverse the list in place.
//!
//! # Reference
//!
//! Linux `include/linux/llist.h`,
//! `lib/llist.c`.

use oncrix_lib::{Error, Result};

// ======================================================================
// Constants
// ======================================================================

/// Maximum nodes in a lock-less list.
const MAX_NODES: usize = 256;

/// Maximum managed lists.
const MAX_LLISTS: usize = 128;

/// Sentinel for "no next node".
const NONE_IDX: u32 = u32::MAX;

// ======================================================================
// LlistNode
// ======================================================================

/// A node in the lock-less linked list.
#[derive(Debug, Clone, Copy)]
pub struct LlistNode {
    /// Index of the next node (NONE_IDX if tail).
    next: u32,
    /// Data payload.
    data: u64,
    /// Whether this node is in use.
    occupied: bool,
    /// Sequence number (for ordering verification).
    seq: u64,
}

impl LlistNode {
    /// Creates a new empty node.
    pub const fn new() -> Self {
        Self {
            next: NONE_IDX,
            data: 0,
            occupied: false,
            seq: 0,
        }
    }

    /// Returns the next-node index.
    pub fn next(&self) -> u32 {
        self.next
    }

    /// Returns the data payload.
    pub fn data(&self) -> u64 {
        self.data
    }

    /// Returns whether this node is occupied.
    pub fn is_occupied(&self) -> bool {
        self.occupied
    }

    /// Returns the sequence number.
    pub fn seq(&self) -> u64 {
        self.seq
    }
}

// ======================================================================
// LlistHead
// ======================================================================

/// Head of a lock-less linked list with an embedded node pool.
pub struct LlistHead {
    /// Index of the first node (NONE_IDX if empty).
    first: u32,
    /// Node pool.
    nodes: [LlistNode; MAX_NODES],
    /// Number of nodes in the list.
    count: usize,
    /// Total allocated nodes from the pool.
    pool_used: usize,
    /// Monotonic sequence counter.
    seq_counter: u64,
    /// Statistics: total adds.
    stats_adds: u64,
    /// Statistics: total del_all calls.
    stats_del_alls: u64,
}

impl LlistHead {
    /// Creates a new empty list.
    pub const fn new() -> Self {
        Self {
            first: NONE_IDX,
            nodes: [const { LlistNode::new() }; MAX_NODES],
            count: 0,
            pool_used: 0,
            seq_counter: 0,
            stats_adds: 0,
            stats_del_alls: 0,
        }
    }

    /// Adds a value to the head of the list (prepend).
    ///
    /// This is the single-producer add operation.
    pub fn llist_add(&mut self, data: u64) -> Result<usize> {
        let idx = self.alloc_node()?;
        self.nodes[idx].data = data;
        self.nodes[idx].occupied = true;
        self.nodes[idx].seq = self.seq_counter;
        self.seq_counter += 1;
        self.nodes[idx].next = self.first;
        self.first = idx as u32;
        self.count += 1;
        self.stats_adds += 1;
        Ok(idx)
    }

    /// Atomically removes all nodes from the list.
    ///
    /// Returns a collected array of (index, data) pairs and the
    /// count. The list is left empty.
    pub fn llist_del_all(&mut self, out: &mut [(usize, u64)]) -> usize {
        self.stats_del_alls += 1;
        let mut collected = 0;
        let mut cur = self.first;
        while cur != NONE_IDX && collected < out.len() {
            let ci = cur as usize;
            if ci < MAX_NODES && self.nodes[ci].occupied {
                out[collected] = (ci, self.nodes[ci].data);
                collected += 1;
                let next = self.nodes[ci].next;
                self.nodes[ci] = LlistNode::new();
                cur = next;
            } else {
                break;
            }
        }
        self.first = NONE_IDX;
        self.count = 0;
        self.pool_used -= collected.min(self.pool_used);
        collected
    }

    /// Returns whether the list is empty.
    pub fn llist_empty(&self) -> bool {
        self.first == NONE_IDX
    }

    /// Iterates over the list, collecting indices into `out`.
    ///
    /// Returns the number of indices collected.
    pub fn llist_for_each(&self, out: &mut [usize]) -> usize {
        let mut collected = 0;
        let mut cur = self.first;
        while cur != NONE_IDX && collected < out.len() {
            let ci = cur as usize;
            if ci < MAX_NODES && self.nodes[ci].occupied {
                out[collected] = ci;
                collected += 1;
                cur = self.nodes[ci].next;
            } else {
                break;
            }
        }
        collected
    }

    /// Reverses the list in place.
    pub fn reverse(&mut self) {
        let mut prev = NONE_IDX;
        let mut cur = self.first;
        while cur != NONE_IDX {
            let ci = cur as usize;
            if ci >= MAX_NODES {
                break;
            }
            let next = self.nodes[ci].next;
            self.nodes[ci].next = prev;
            prev = cur;
            cur = next;
        }
        self.first = prev;
    }

    /// Returns the number of nodes in the list.
    pub fn count(&self) -> usize {
        self.count
    }

    /// Returns a reference to a node by index.
    pub fn node(&self, idx: usize) -> Result<&LlistNode> {
        if idx >= MAX_NODES || !self.nodes[idx].occupied {
            return Err(Error::NotFound);
        }
        Ok(&self.nodes[idx])
    }

    /// Returns total adds.
    pub fn stats_adds(&self) -> u64 {
        self.stats_adds
    }

    /// Returns total del_all calls.
    pub fn stats_del_alls(&self) -> u64 {
        self.stats_del_alls
    }

    // ------------------------------------------------------------------
    // Internal helpers
    // ------------------------------------------------------------------

    /// Allocates a node from the pool.
    fn alloc_node(&mut self) -> Result<usize> {
        if self.pool_used >= MAX_NODES {
            return Err(Error::OutOfMemory);
        }
        // Find first free node.
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
// LlistTable — global registry
// ======================================================================

/// Global table of lock-less lists.
pub struct LlistTable {
    /// Entries.
    entries: [LlistTableEntry; MAX_LLISTS],
    /// Number of allocated lists.
    count: usize,
}

/// Entry in the list table.
struct LlistTableEntry {
    /// The list head.
    head: LlistHead,
    /// Whether allocated.
    allocated: bool,
}

impl LlistTableEntry {
    const fn new() -> Self {
        Self {
            head: LlistHead::new(),
            allocated: false,
        }
    }
}

impl LlistTable {
    /// Creates a new empty table.
    pub const fn new() -> Self {
        Self {
            entries: [const { LlistTableEntry::new() }; MAX_LLISTS],
            count: 0,
        }
    }

    /// Allocates a new list.
    pub fn alloc(&mut self) -> Result<usize> {
        if self.count >= MAX_LLISTS {
            return Err(Error::OutOfMemory);
        }
        let idx = self
            .entries
            .iter()
            .position(|e| !e.allocated)
            .ok_or(Error::OutOfMemory)?;
        self.entries[idx].allocated = true;
        self.entries[idx].head = LlistHead::new();
        self.count += 1;
        Ok(idx)
    }

    /// Frees a list by index.
    pub fn free(&mut self, idx: usize) -> Result<()> {
        if idx >= MAX_LLISTS || !self.entries[idx].allocated {
            return Err(Error::NotFound);
        }
        self.entries[idx] = LlistTableEntry::new();
        self.count -= 1;
        Ok(())
    }

    /// Returns a reference to the list at `idx`.
    pub fn get(&self, idx: usize) -> Result<&LlistHead> {
        if idx >= MAX_LLISTS || !self.entries[idx].allocated {
            return Err(Error::NotFound);
        }
        Ok(&self.entries[idx].head)
    }

    /// Returns a mutable reference to the list at `idx`.
    pub fn get_mut(&mut self, idx: usize) -> Result<&mut LlistHead> {
        if idx >= MAX_LLISTS || !self.entries[idx].allocated {
            return Err(Error::NotFound);
        }
        Ok(&mut self.entries[idx].head)
    }

    /// Returns the number of allocated lists.
    pub fn count(&self) -> usize {
        self.count
    }
}
