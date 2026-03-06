// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Btrfs delayed inode operations.
//!
//! Rather than immediately inserting or updating inode items in the B-tree on
//! every metadata change, Btrfs batches these updates via a per-transaction
//! "delayed node" queue.  At commit time (or when memory pressure demands it)
//! the delayed items are flushed in bulk, amortising the cost of B-tree
//! modifications.
//!
//! # Design
//!
//! - [`DelayedOp`] — the type of deferred change (insert / update / delete)
//! - [`DelayedItem`] — a single deferred inode-item modification
//! - [`DelayedNode`] — per-inode container holding the pending item list
//! - [`DelayedRoot`] — global registry of all delayed nodes
//! - `flush_delayed_items` — drain and apply all pending items
//!
//! # References
//!
//! - Linux `fs/btrfs/delayed-inode.c`, `fs/btrfs/delayed-inode.h`

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum number of delayed nodes registered in [`DelayedRoot`].
pub const MAX_DELAYED_NODES: usize = 512;

/// Maximum items queued per [`DelayedNode`] before a forced flush.
pub const MAX_ITEMS_PER_NODE: usize = 64;

/// Sentinel inode number meaning "unused slot".
pub const DELAYED_NODE_EMPTY: u64 = 0;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// The kind of deferred operation pending on an inode item.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DelayedOp {
    /// Insert a new inode item into the B-tree.
    Insert,
    /// Update an existing inode item in the B-tree.
    Update,
    /// Delete an inode item from the B-tree.
    Delete,
}

/// A single deferred inode-item modification.
#[derive(Debug, Clone, Copy)]
pub struct DelayedItem {
    /// Object ID (inode number) this item belongs to.
    pub objectid: u64,
    /// The operation to apply.
    pub op: DelayedOp,
    /// Sequence number within this node for ordering.
    pub seq: u32,
    /// Packed inode size (used for update/insert items).
    pub inode_size: u64,
    /// Packed modification timestamp (seconds since epoch).
    pub mtime_sec: i64,
    /// Whether this item has been applied to the B-tree.
    pub applied: bool,
}

impl DelayedItem {
    /// Create a new delayed item for `objectid`.
    pub fn new(objectid: u64, op: DelayedOp, seq: u32) -> Self {
        Self {
            objectid,
            op,
            seq,
            inode_size: 0,
            mtime_sec: 0,
            applied: false,
        }
    }
}

/// Per-inode container for deferred B-tree modifications.
#[derive(Debug)]
pub struct DelayedNode {
    /// Inode number this node is attached to; `DELAYED_NODE_EMPTY` if unused.
    pub inode_id: u64,
    /// Items queued for this inode (fixed-size ring — oldest overwritten on overflow).
    items: [DelayedItem; MAX_ITEMS_PER_NODE],
    /// Number of valid items currently stored.
    count: usize,
    /// Monotonically increasing sequence counter for item ordering.
    next_seq: u32,
    /// Whether this node needs to be flushed before the next transaction commit.
    pub needs_flush: bool,
}

impl Default for DelayedNode {
    fn default() -> Self {
        let placeholder = DelayedItem {
            objectid: 0,
            op: DelayedOp::Insert,
            seq: 0,
            inode_size: 0,
            mtime_sec: 0,
            applied: false,
        };
        Self {
            inode_id: DELAYED_NODE_EMPTY,
            items: [placeholder; MAX_ITEMS_PER_NODE],
            count: 0,
            next_seq: 0,
            needs_flush: false,
        }
    }
}

impl DelayedNode {
    /// Initialise a node for `inode_id`.
    pub fn new(inode_id: u64) -> Self {
        let mut node = Self::default();
        node.inode_id = inode_id;
        node
    }

    /// Returns `true` when no items are queued.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Queue a delayed operation.  Returns [`Error::Busy`] when full.
    pub fn push(&mut self, op: DelayedOp) -> Result<()> {
        if self.count >= MAX_ITEMS_PER_NODE {
            return Err(Error::Busy);
        }
        let seq = self.next_seq;
        self.next_seq = self.next_seq.wrapping_add(1);
        self.items[self.count] = DelayedItem::new(self.inode_id, op, seq);
        self.count += 1;
        self.needs_flush = true;
        Ok(())
    }

    /// Flush (apply) all pending items via `apply_fn`, then clear the queue.
    ///
    /// `apply_fn` receives each [`DelayedItem`] and should write the change to
    /// the B-tree.  If it returns an error the flush is aborted.
    pub fn flush<F>(&mut self, mut apply_fn: F) -> Result<()>
    where
        F: FnMut(&DelayedItem) -> Result<()>,
    {
        for idx in 0..self.count {
            apply_fn(&self.items[idx])?;
            self.items[idx].applied = true;
        }
        self.count = 0;
        self.needs_flush = false;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Delayed root
// ---------------------------------------------------------------------------

/// Global registry of all active delayed nodes for a Btrfs filesystem.
pub struct DelayedRoot {
    nodes: [DelayedNode; MAX_DELAYED_NODES],
    /// Number of occupied slots.
    count: usize,
    /// Total unapplied items across all nodes.
    total_items: usize,
}

impl Default for DelayedRoot {
    fn default() -> Self {
        Self::new()
    }
}

impl DelayedRoot {
    /// Create an empty delayed root.
    pub fn new() -> Self {
        Self {
            nodes: core::array::from_fn(|_| DelayedNode::default()),
            count: 0,
            total_items: 0,
        }
    }

    /// Look up or create the delayed node for `inode_id`.
    ///
    /// Returns the slot index, or [`Error::OutOfMemory`] when the table is full.
    pub fn get_or_create(&mut self, inode_id: u64) -> Result<usize> {
        // Check for existing entry.
        if let Some(pos) = self.nodes[..self.count]
            .iter()
            .position(|n| n.inode_id == inode_id)
        {
            return Ok(pos);
        }
        // Allocate new slot.
        if self.count >= MAX_DELAYED_NODES {
            return Err(Error::OutOfMemory);
        }
        self.nodes[self.count] = DelayedNode::new(inode_id);
        let pos = self.count;
        self.count += 1;
        Ok(pos)
    }

    /// Queue a delayed operation on `inode_id`.
    pub fn queue_op(&mut self, inode_id: u64, op: DelayedOp) -> Result<()> {
        let pos = self.get_or_create(inode_id)?;
        let prev_count = self.nodes[pos].count;
        self.nodes[pos].push(op)?;
        let new_count = self.nodes[pos].count;
        self.total_items += new_count - prev_count;
        Ok(())
    }

    /// Flush all delayed items via `apply_fn`.
    ///
    /// Nodes that flush successfully are left empty but retained in the table.
    /// If a node fails, flushing continues for the remaining nodes and the
    /// first error is returned at the end.
    pub fn flush_all<F>(&mut self, mut apply_fn: F) -> Result<()>
    where
        F: FnMut(&DelayedItem) -> Result<()>,
    {
        let mut first_err: Option<Error> = None;
        for node in self.nodes[..self.count].iter_mut() {
            if node.needs_flush {
                if let Err(e) = node.flush(&mut apply_fn) {
                    if first_err.is_none() {
                        first_err = Some(e);
                    }
                }
            }
        }
        self.total_items = 0;
        match first_err {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }

    /// Remove the delayed node for `inode_id` (called when an inode is evicted).
    pub fn remove(&mut self, inode_id: u64) {
        if let Some(pos) = self.nodes[..self.count]
            .iter()
            .position(|n| n.inode_id == inode_id)
        {
            self.total_items = self.total_items.saturating_sub(self.nodes[pos].count);
            // Swap-remove to keep the array compact.
            let last = self.count - 1;
            self.nodes.swap(pos, last);
            self.nodes[last] = DelayedNode::default();
            self.count -= 1;
        }
    }

    /// Return the total number of unapplied delayed items.
    pub fn total_pending(&self) -> usize {
        self.total_items
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn queue_and_flush() {
        let mut root = DelayedRoot::new();
        root.queue_op(1, DelayedOp::Insert).unwrap();
        root.queue_op(1, DelayedOp::Update).unwrap();
        root.queue_op(2, DelayedOp::Delete).unwrap();

        let mut flushed = 0usize;
        root.flush_all(|_item| {
            flushed += 1;
            Ok(())
        })
        .unwrap();

        assert_eq!(flushed, 3);
        assert_eq!(root.total_pending(), 0);
    }

    #[test]
    fn remove_node() {
        let mut root = DelayedRoot::new();
        root.queue_op(10, DelayedOp::Insert).unwrap();
        root.remove(10);
        assert_eq!(root.count, 0);
    }

    #[test]
    fn node_full_returns_busy() {
        let mut node = DelayedNode::new(99);
        for _ in 0..MAX_ITEMS_PER_NODE {
            node.push(DelayedOp::Update).unwrap();
        }
        assert!(matches!(node.push(DelayedOp::Update), Err(Error::Busy)));
    }
}
