// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Btrfs Copy-on-Write B-tree engine.
//!
//! Implements the transactional CoW B-tree layer that underpins the btrfs
//! filesystem.  Every write to a node produces a new copy; the old version
//! is retained until the transaction commits, enabling atomic snapshots and
//! crash recovery.
//!
//! # Architecture
//!
//! ```text
//! Transaction
//!   └─ CowTree (root bytenr per generation)
//!        ├─ InternalNode  (key + child bytenr pairs)
//!        │    └─ InternalNode  …
//!        └─ LeafNode      (key + inline-data items, level 0)
//! ```
//!
//! # Copy-on-Write Mechanics
//!
//! 1. `cow_insert` / `cow_delete` never modify a node in place.
//! 2. The node is copied into a fresh pool slot.
//! 3. The modification is applied to the copy.
//! 4. The parent's child pointer is updated to the new slot index.
//! 5. This propagates to the root, yielding a new root per transaction.
//! 6. Snapshots are taken by recording the old root before the write.
//!
//! # Structures
//!
//! - [`CowKey`] — `(objectid, item_type, offset)` search key
//! - [`CowItem`] — inline-data item stored in leaf nodes
//! - [`LeafNode`] — level-0 node holding up to [`MAX_LEAF_ITEMS`] items
//! - [`InternalNode`] — level-N node holding up to [`MAX_INTERNAL_KEYS`] keys
//! - [`CowNode`] — union of leaf or internal node plus its level
//! - [`NodePool`] — fixed slab of [`MAX_POOL_NODES`] nodes (no heap alloc)
//! - [`CowSnapshot`] — saved root pointer for point-in-time reads
//! - [`CowTransaction`] — wraps a generation number and dirty-node tracking
//! - [`CowTree`] — the top-level B-tree with snapshot and transaction support

#![allow(dead_code)]

use oncrix_lib::{Error, Result};

// ── Constants ───────────────────────────────────────────────────

/// Maximum items stored in a single leaf node.
const MAX_LEAF_ITEMS: usize = 32;

/// Maximum key/child pairs stored in a single internal node.
const MAX_INTERNAL_KEYS: usize = 32;

/// Maximum nodes in the node pool (slab allocator).
const MAX_POOL_NODES: usize = 512;

/// Maximum snapshots retained simultaneously.
const MAX_SNAPSHOTS: usize = 16;

/// Maximum name length for a snapshot label.
const MAX_SNAPSHOT_LABEL: usize = 64;

/// Sentinel index used to represent a null child pointer.
const NULL_INDEX: u32 = u32::MAX;

// ── CowKey ──────────────────────────────────────────────────────

/// Btrfs-style search key: `(objectid, item_type, offset)`.
///
/// Keys are ordered lexicographically — objectid first, then item_type,
/// then offset — so a simple three-way compare gives total ordering.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CowKey {
    /// Object identifier (inode number, subvolume ID, …).
    pub objectid: u64,
    /// Discriminator byte identifying the item type.
    pub item_type: u8,
    /// Type-specific offset (byte position, name hash, …).
    pub offset: u64,
}

impl CowKey {
    /// Create a new key.
    pub const fn new(objectid: u64, item_type: u8, offset: u64) -> Self {
        Self {
            objectid,
            item_type,
            offset,
        }
    }

    /// Minimum representable key.
    pub const fn min() -> Self {
        Self {
            objectid: 0,
            item_type: 0,
            offset: 0,
        }
    }

    /// Maximum representable key.
    pub const fn max() -> Self {
        Self {
            objectid: u64::MAX,
            item_type: u8::MAX,
            offset: u64::MAX,
        }
    }
}

impl PartialOrd for CowKey {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for CowKey {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.objectid
            .cmp(&other.objectid)
            .then(self.item_type.cmp(&other.item_type))
            .then(self.offset.cmp(&other.offset))
    }
}

// ── CowItem ─────────────────────────────────────────────────────

/// Maximum inline data stored per item (256 bytes).
const MAX_ITEM_DATA: usize = 256;

/// A key-value item stored inside a leaf node.
#[derive(Debug, Clone, Copy)]
pub struct CowItem {
    /// Lookup key.
    pub key: CowKey,
    /// Inline payload.
    pub data: [u8; MAX_ITEM_DATA],
    /// Number of valid bytes in `data`.
    pub data_len: usize,
    /// Whether this slot holds a live item.
    pub in_use: bool,
}

impl CowItem {
    /// Create an empty (unused) item slot.
    const fn empty() -> Self {
        Self {
            key: CowKey::min(),
            data: [0u8; MAX_ITEM_DATA],
            data_len: 0,
            in_use: false,
        }
    }

    /// Create a new item from a key and data slice.
    ///
    /// # Errors
    ///
    /// Returns `InvalidArgument` if `data.len() > MAX_ITEM_DATA`.
    pub fn new(key: CowKey, data: &[u8]) -> Result<Self> {
        if data.len() > MAX_ITEM_DATA {
            return Err(Error::InvalidArgument);
        }
        let mut item = Self::empty();
        item.key = key;
        item.data[..data.len()].copy_from_slice(data);
        item.data_len = data.len();
        item.in_use = true;
        Ok(item)
    }

    /// Return a slice of the valid data.
    pub fn data(&self) -> &[u8] {
        &self.data[..self.data_len]
    }
}

impl Default for CowItem {
    fn default() -> Self {
        Self::empty()
    }
}

// ── LeafNode ────────────────────────────────────────────────────

/// A B-tree leaf node (level 0).
///
/// Contains up to [`MAX_LEAF_ITEMS`] [`CowItem`]s kept in ascending key
/// order.  Insertions maintain the sorted invariant; deletions leave the
/// order intact.
#[derive(Debug, Clone)]
pub struct LeafNode {
    /// Transaction generation that last wrote this node.
    pub generation: u64,
    /// Logical byte address (for on-disk mapping).
    pub bytenr: u64,
    /// Sorted item array; unused slots have `in_use == false`.
    pub items: [CowItem; MAX_LEAF_ITEMS],
    /// Number of live items.
    pub nritems: usize,
}

impl LeafNode {
    /// Create an empty leaf node.
    pub fn new(generation: u64, bytenr: u64) -> Self {
        const EMPTY: CowItem = CowItem::empty();
        Self {
            generation,
            bytenr,
            items: [EMPTY; MAX_LEAF_ITEMS],
            nritems: 0,
        }
    }

    /// Find the slot index for `key`, or the insertion point.
    ///
    /// Returns `Ok(idx)` if an exact match exists; `Err(idx)` gives the
    /// position at which `key` should be inserted.
    pub fn search(&self, key: &CowKey) -> core::result::Result<usize, usize> {
        let live: &[_] = &self.items[..self.nritems];
        live.binary_search_by(|item| item.key.cmp(key))
    }

    /// Insert `item` into this leaf, maintaining sorted order.
    ///
    /// # Errors
    ///
    /// - `AlreadyExists` if an item with the same key is already present.
    /// - `OutOfMemory` if the leaf is full.
    pub fn insert(&mut self, item: CowItem) -> Result<()> {
        match self.search(&item.key) {
            Ok(_) => Err(Error::AlreadyExists),
            Err(pos) => {
                if self.nritems >= MAX_LEAF_ITEMS {
                    return Err(Error::OutOfMemory);
                }
                // Shift items right to make room.
                self.items.copy_within(pos..self.nritems, pos + 1);
                self.items[pos] = item;
                self.nritems += 1;
                Ok(())
            }
        }
    }

    /// Delete the item with `key`.
    ///
    /// # Errors
    ///
    /// - `NotFound` if no item with `key` exists.
    pub fn delete(&mut self, key: &CowKey) -> Result<()> {
        match self.search(key) {
            Err(_) => Err(Error::NotFound),
            Ok(pos) => {
                self.items.copy_within(pos + 1..self.nritems, pos);
                self.items[self.nritems - 1] = CowItem::empty();
                self.nritems -= 1;
                Ok(())
            }
        }
    }

    /// Lookup the item with `key`.
    ///
    /// # Errors
    ///
    /// - `NotFound` if no match exists.
    pub fn lookup(&self, key: &CowKey) -> Result<&CowItem> {
        match self.search(key) {
            Ok(pos) => Ok(&self.items[pos]),
            Err(_) => Err(Error::NotFound),
        }
    }

    /// Whether the leaf is full.
    pub fn is_full(&self) -> bool {
        self.nritems >= MAX_LEAF_ITEMS
    }

    /// Smallest key in this leaf, if any.
    pub fn min_key(&self) -> Option<CowKey> {
        if self.nritems == 0 {
            None
        } else {
            Some(self.items[0].key)
        }
    }

    /// Largest key in this leaf, if any.
    pub fn max_key(&self) -> Option<CowKey> {
        if self.nritems == 0 {
            None
        } else {
            Some(self.items[self.nritems - 1].key)
        }
    }
}

// ── InternalNode ────────────────────────────────────────────────

/// A key/child-pointer pair inside an internal node.
#[derive(Debug, Clone, Copy)]
pub struct KeyPtr {
    /// Smallest key reachable via `child_idx`.
    pub key: CowKey,
    /// Pool index of the child node.
    pub child_idx: u32,
}

impl KeyPtr {
    const fn null() -> Self {
        Self {
            key: CowKey::min(),
            child_idx: NULL_INDEX,
        }
    }
}

impl Default for KeyPtr {
    fn default() -> Self {
        Self::null()
    }
}

/// A B-tree internal node (level ≥ 1).
///
/// Contains up to [`MAX_INTERNAL_KEYS`] key/child-pointer pairs.  The
/// B-tree invariant is: all keys in child `i` are ≥ `ptrs[i].key` and
/// < `ptrs[i+1].key`.
#[derive(Debug, Clone)]
pub struct InternalNode {
    /// Transaction generation.
    pub generation: u64,
    /// Logical byte address.
    pub bytenr: u64,
    /// Tree level (always ≥ 1).
    pub level: u8,
    /// Key/child pairs sorted by key.
    pub ptrs: [KeyPtr; MAX_INTERNAL_KEYS],
    /// Number of valid entries.
    pub nritems: usize,
}

impl InternalNode {
    /// Create a new empty internal node.
    pub fn new(generation: u64, bytenr: u64, level: u8) -> Self {
        const EMPTY: KeyPtr = KeyPtr::null();
        Self {
            generation,
            bytenr,
            level,
            ptrs: [EMPTY; MAX_INTERNAL_KEYS],
            nritems: 0,
        }
    }

    /// Find the child index that should contain `key`.
    ///
    /// Returns the slot whose key is the greatest key ≤ `key`.
    pub fn find_child(&self, key: &CowKey) -> usize {
        if self.nritems == 0 {
            return 0;
        }
        // Binary search for the rightmost slot whose key ≤ target.
        let mut lo = 0usize;
        let mut hi = self.nritems;
        while lo < hi {
            let mid = lo + (hi - lo) / 2;
            if self.ptrs[mid].key <= *key {
                lo = mid + 1;
            } else {
                hi = mid;
            }
        }
        // lo-1 is the last slot whose key ≤ key (saturating at 0).
        lo.saturating_sub(1)
    }

    /// Insert a new key/child pointer in sorted order.
    ///
    /// # Errors
    ///
    /// - `OutOfMemory` if the node is full.
    pub fn insert(&mut self, key: CowKey, child_idx: u32) -> Result<()> {
        if self.nritems >= MAX_INTERNAL_KEYS {
            return Err(Error::OutOfMemory);
        }
        // Find insertion position.
        let pos = {
            let mut p = self.nritems;
            for (i, ptr) in self.ptrs[..self.nritems].iter().enumerate() {
                if ptr.key > key {
                    p = i;
                    break;
                }
            }
            p
        };
        self.ptrs.copy_within(pos..self.nritems, pos + 1);
        self.ptrs[pos] = KeyPtr { key, child_idx };
        self.nritems += 1;
        Ok(())
    }

    /// Update the child pointer for an existing key slot at `slot`.
    pub fn update_child(&mut self, slot: usize, new_child: u32) {
        if slot < self.nritems {
            self.ptrs[slot].child_idx = new_child;
        }
    }

    /// Whether the internal node is full.
    pub fn is_full(&self) -> bool {
        self.nritems >= MAX_INTERNAL_KEYS
    }
}

// ── CowNode (pool element) ───────────────────────────────────────

/// Tag discriminating leaf vs internal pool entries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeKind {
    /// Level-0 node holding items.
    Leaf,
    /// Level-≥1 node holding key/child pairs.
    Internal,
}

/// A single slot in the node pool.
///
/// Holds either a [`LeafNode`] or an [`InternalNode`], plus pool
/// bookkeeping fields.
pub struct CowNode {
    /// Whether this pool slot is occupied.
    pub in_use: bool,
    /// Node kind (leaf or internal).
    pub kind: NodeKind,
    /// Leaf payload (valid when `kind == Leaf`).
    pub leaf: LeafNode,
    /// Internal payload (valid when `kind == Internal`).
    pub internal: InternalNode,
}

impl CowNode {
    /// Create an empty (unused) pool slot.
    fn empty() -> Self {
        Self {
            in_use: false,
            kind: NodeKind::Leaf,
            leaf: LeafNode::new(0, 0),
            internal: InternalNode::new(0, 0, 1),
        }
    }

    /// Wrap a leaf node into a pool slot.
    fn from_leaf(leaf: LeafNode) -> Self {
        Self {
            in_use: true,
            kind: NodeKind::Leaf,
            leaf,
            internal: InternalNode::new(0, 0, 1),
        }
    }

    /// Wrap an internal node into a pool slot.
    fn from_internal(internal: InternalNode) -> Self {
        Self {
            in_use: true,
            kind: NodeKind::Internal,
            leaf: LeafNode::new(0, 0),
            internal,
        }
    }
}

// ── NodePool ────────────────────────────────────────────────────

/// Fixed-size slab allocator for B-tree nodes.
///
/// Holds up to [`MAX_POOL_NODES`] [`CowNode`] slots.  Because every CoW
/// write allocates a fresh slot, the pool can fill up; callers should
/// periodically garbage-collect unreachable nodes.
pub struct NodePool {
    /// Node storage.
    nodes: alloc::vec::Vec<CowNode>,
    /// Next logical byte address to hand out.
    next_bytenr: u64,
    /// Total allocated (including freed) slots.
    allocated: usize,
    /// Currently live (in-use) slots.
    live: usize,
}

extern crate alloc;

impl NodePool {
    /// Create an empty node pool.
    pub fn new() -> Self {
        let mut nodes = alloc::vec::Vec::with_capacity(MAX_POOL_NODES);
        for _ in 0..MAX_POOL_NODES {
            nodes.push(CowNode::empty());
        }
        Self {
            nodes,
            next_bytenr: 4096,
            allocated: 0,
            live: 0,
        }
    }

    /// Allocate a slot for a new leaf node.
    ///
    /// # Errors
    ///
    /// - `OutOfMemory` if the pool is exhausted.
    pub fn alloc_leaf(&mut self, generation: u64) -> Result<u32> {
        let bytenr = self.next_bytenr;
        self.next_bytenr = self.next_bytenr.wrapping_add(4096);
        self.alloc_node(CowNode::from_leaf(LeafNode::new(generation, bytenr)))
    }

    /// Allocate a slot for a new internal node.
    ///
    /// # Errors
    ///
    /// - `OutOfMemory` if the pool is exhausted.
    pub fn alloc_internal(&mut self, generation: u64, level: u8) -> Result<u32> {
        let bytenr = self.next_bytenr;
        self.next_bytenr = self.next_bytenr.wrapping_add(4096);
        self.alloc_node(CowNode::from_internal(InternalNode::new(
            generation, bytenr, level,
        )))
    }

    fn alloc_node(&mut self, node: CowNode) -> Result<u32> {
        if self.allocated >= MAX_POOL_NODES {
            return Err(Error::OutOfMemory);
        }
        for (idx, slot) in self.nodes.iter_mut().enumerate() {
            if !slot.in_use {
                *slot = node;
                self.allocated += 1;
                self.live += 1;
                return Ok(idx as u32);
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Clone an existing node into a fresh pool slot (CoW copy).
    ///
    /// The new slot gets the caller-supplied `generation`.
    ///
    /// # Errors
    ///
    /// - `NotFound` if `src` is an invalid/unused slot.
    /// - `OutOfMemory` if the pool is full.
    pub fn cow_clone(&mut self, src: u32, generation: u64) -> Result<u32> {
        let src_idx = src as usize;
        if src_idx >= MAX_POOL_NODES || !self.nodes[src_idx].in_use {
            return Err(Error::NotFound);
        }
        let bytenr = self.next_bytenr;
        self.next_bytenr = self.next_bytenr.wrapping_add(4096);

        let kind = self.nodes[src_idx].kind;
        let new_node = match kind {
            NodeKind::Leaf => {
                let mut leaf = self.nodes[src_idx].leaf.clone();
                leaf.generation = generation;
                leaf.bytenr = bytenr;
                CowNode::from_leaf(leaf)
            }
            NodeKind::Internal => {
                let mut internal = self.nodes[src_idx].internal.clone();
                internal.generation = generation;
                internal.bytenr = bytenr;
                CowNode::from_internal(internal)
            }
        };
        self.alloc_node(new_node)
    }

    /// Free a pool slot.
    ///
    /// Does nothing if the slot is already free.
    pub fn free(&mut self, idx: u32) {
        let i = idx as usize;
        if i < MAX_POOL_NODES && self.nodes[i].in_use {
            self.nodes[i].in_use = false;
            self.live = self.live.saturating_sub(1);
        }
    }

    /// Get an immutable reference to a node.
    ///
    /// # Errors
    ///
    /// - `NotFound` if the index is invalid or the slot is unused.
    pub fn get(&self, idx: u32) -> Result<&CowNode> {
        let i = idx as usize;
        if i >= MAX_POOL_NODES || !self.nodes[i].in_use {
            return Err(Error::NotFound);
        }
        Ok(&self.nodes[i])
    }

    /// Get a mutable reference to a node.
    ///
    /// # Errors
    ///
    /// - `NotFound` if the index is invalid or the slot is unused.
    pub fn get_mut(&mut self, idx: u32) -> Result<&mut CowNode> {
        let i = idx as usize;
        if i >= MAX_POOL_NODES || !self.nodes[i].in_use {
            return Err(Error::NotFound);
        }
        Ok(&mut self.nodes[i])
    }

    /// Number of live (allocated and in-use) nodes.
    pub fn live_count(&self) -> usize {
        self.live
    }
}

impl Default for NodePool {
    fn default() -> Self {
        Self::new()
    }
}

// ── CowSnapshot ─────────────────────────────────────────────────

/// A snapshot preserving a point-in-time view of the tree.
///
/// A snapshot is taken by recording the root pool index and generation
/// before a modifying transaction.  As long as the snapshot is alive,
/// nodes reachable from `root_idx` must not be freed.
#[derive(Debug, Clone, Copy)]
pub struct CowSnapshot {
    /// Pool index of the snapshot root node.
    pub root_idx: u32,
    /// Generation number at snapshot creation.
    pub generation: u64,
    /// ASCII label for user identification (NUL-padded).
    pub label: [u8; MAX_SNAPSHOT_LABEL],
    /// Length of the label.
    pub label_len: usize,
    /// Whether this snapshot slot is live.
    pub active: bool,
}

impl CowSnapshot {
    /// Create an inactive snapshot slot.
    const fn empty() -> Self {
        Self {
            root_idx: NULL_INDEX,
            generation: 0,
            label: [0u8; MAX_SNAPSHOT_LABEL],
            label_len: 0,
            active: false,
        }
    }

    /// Create a named snapshot at the given root.
    ///
    /// # Errors
    ///
    /// Returns `InvalidArgument` if `label` exceeds [`MAX_SNAPSHOT_LABEL`].
    pub fn new(root_idx: u32, generation: u64, label: &[u8]) -> Result<Self> {
        if label.len() > MAX_SNAPSHOT_LABEL {
            return Err(Error::InvalidArgument);
        }
        let mut snap = Self::empty();
        snap.root_idx = root_idx;
        snap.generation = generation;
        snap.label[..label.len()].copy_from_slice(label);
        snap.label_len = label.len();
        snap.active = true;
        Ok(snap)
    }

    /// Return the label as a byte slice.
    pub fn label(&self) -> &[u8] {
        &self.label[..self.label_len]
    }
}

// ── CowTransaction ──────────────────────────────────────────────

/// Maximum dirty nodes tracked per transaction.
const MAX_DIRTY_NODES: usize = 128;

/// An open write transaction.
///
/// Tracks the generation number and the set of newly-allocated pool
/// indices.  On commit, dirty nodes become the new tree; on abort, they
/// are freed.
pub struct CowTransaction {
    /// Generation number for all nodes written in this transaction.
    pub generation: u64,
    /// Pool indices of nodes written (CoW copies) this transaction.
    dirty: [u32; MAX_DIRTY_NODES],
    /// Number of dirty entries recorded.
    dirty_count: usize,
    /// Whether this transaction is still open.
    pub open: bool,
}

impl CowTransaction {
    /// Begin a new transaction.
    pub fn begin(generation: u64) -> Self {
        Self {
            generation,
            dirty: [NULL_INDEX; MAX_DIRTY_NODES],
            dirty_count: 0,
            open: true,
        }
    }

    /// Record a newly-written pool index as dirty.
    ///
    /// # Errors
    ///
    /// - `OutOfMemory` if the dirty list is full.
    pub fn mark_dirty(&mut self, idx: u32) -> Result<()> {
        if self.dirty_count >= MAX_DIRTY_NODES {
            return Err(Error::OutOfMemory);
        }
        self.dirty[self.dirty_count] = idx;
        self.dirty_count += 1;
        Ok(())
    }

    /// Iterate over all dirty node indices.
    pub fn dirty_nodes(&self) -> &[u32] {
        &self.dirty[..self.dirty_count]
    }

    /// Commit this transaction (marks it closed without freeing nodes).
    pub fn commit(&mut self) {
        self.open = false;
    }

    /// Abort this transaction, returning the list of nodes to free.
    ///
    /// The caller is responsible for calling `NodePool::free` on each.
    pub fn abort(&mut self) -> &[u32] {
        self.open = false;
        &self.dirty[..self.dirty_count]
    }
}

// ── CowTree ─────────────────────────────────────────────────────

/// A CoW B-tree with snapshot and transaction support.
///
/// # Single-level design
///
/// For simplicity this implementation is single-level (height ≤ 1): the
/// root is always a [`LeafNode`].  Callers needing multi-level trees can
/// extend by promoting the root to an `InternalNode` on overflow.
pub struct CowTree {
    /// Shared node pool.
    pool: NodePool,
    /// Pool index of the current root node.
    root_idx: u32,
    /// Current committed generation.
    generation: u64,
    /// Snapshot table.
    snapshots: [CowSnapshot; MAX_SNAPSHOTS],
    /// Number of live snapshots.
    snap_count: usize,
}

impl CowTree {
    /// Create an empty CoW tree.
    ///
    /// # Errors
    ///
    /// Returns `OutOfMemory` if the initial root leaf cannot be allocated.
    pub fn new() -> Result<Self> {
        let mut pool = NodePool::new();
        let root_idx = pool.alloc_leaf(1)?;
        const EMPTY_SNAP: CowSnapshot = CowSnapshot::empty();
        Ok(Self {
            pool,
            root_idx,
            generation: 1,
            snapshots: [EMPTY_SNAP; MAX_SNAPSHOTS],
            snap_count: 0,
        })
    }

    /// Return the current generation number.
    pub fn generation(&self) -> u64 {
        self.generation
    }

    /// Return the pool index of the current root.
    pub fn root_idx(&self) -> u32 {
        self.root_idx
    }

    // ── Snapshot ────────────────────────────────────────────────

    /// Take a snapshot of the current tree state.
    ///
    /// # Errors
    ///
    /// - `OutOfMemory` if the snapshot table is full.
    /// - `InvalidArgument` if the label is too long.
    pub fn snapshot(&mut self, label: &[u8]) -> Result<usize> {
        if self.snap_count >= MAX_SNAPSHOTS {
            return Err(Error::OutOfMemory);
        }
        let snap = CowSnapshot::new(self.root_idx, self.generation, label)?;
        for (i, slot) in self.snapshots.iter_mut().enumerate() {
            if !slot.active {
                *slot = snap;
                self.snap_count += 1;
                return Ok(i);
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Drop (delete) a snapshot by index.
    ///
    /// # Errors
    ///
    /// - `NotFound` if the index is out of range or not active.
    pub fn drop_snapshot(&mut self, idx: usize) -> Result<()> {
        if idx >= MAX_SNAPSHOTS || !self.snapshots[idx].active {
            return Err(Error::NotFound);
        }
        self.snapshots[idx] = CowSnapshot::empty();
        self.snap_count = self.snap_count.saturating_sub(1);
        Ok(())
    }

    /// Return a reference to a snapshot by index.
    ///
    /// # Errors
    ///
    /// - `NotFound` if the index is invalid or inactive.
    pub fn get_snapshot(&self, idx: usize) -> Result<&CowSnapshot> {
        if idx >= MAX_SNAPSHOTS || !self.snapshots[idx].active {
            return Err(Error::NotFound);
        }
        Ok(&self.snapshots[idx])
    }

    /// Number of live snapshots.
    pub fn snapshot_count(&self) -> usize {
        self.snap_count
    }

    // ── CoW lookup ──────────────────────────────────────────────

    /// Lookup an item by key in the current tree.
    ///
    /// # Errors
    ///
    /// - `NotFound` if no matching item exists.
    /// - `IoError` if the root node is corrupt.
    pub fn lookup(&self, key: &CowKey) -> Result<&CowItem> {
        let node = self.pool.get(self.root_idx)?;
        if node.kind != NodeKind::Leaf {
            return Err(Error::IoError);
        }
        node.leaf.lookup(key)
    }

    /// Lookup an item by key in a snapshot.
    ///
    /// # Errors
    ///
    /// - `NotFound` if the snapshot or key does not exist.
    /// - `IoError` if the snapshot root is corrupt.
    pub fn lookup_snapshot(&self, snap_idx: usize, key: &CowKey) -> Result<&CowItem> {
        let snap = self.get_snapshot(snap_idx)?;
        let node = self.pool.get(snap.root_idx)?;
        if node.kind != NodeKind::Leaf {
            return Err(Error::IoError);
        }
        node.leaf.lookup(key)
    }

    // ── CoW insert ──────────────────────────────────────────────

    /// Insert a key/value item using copy-on-write semantics.
    ///
    /// A new leaf copy is created, the item is inserted into it, and the
    /// tree root is updated atomically.  The generation is incremented.
    ///
    /// # Errors
    ///
    /// - `AlreadyExists` if a matching key already exists.
    /// - `OutOfMemory` if the leaf is full or the pool is exhausted.
    pub fn cow_insert(&mut self, key: CowKey, data: &[u8]) -> Result<()> {
        let new_gen = self.generation.wrapping_add(1);
        // CoW-clone the current root leaf.
        let new_root = self.pool.cow_clone(self.root_idx, new_gen)?;
        // Insert into the new copy.
        let item = CowItem::new(key, data)?;
        {
            let node = self.pool.get_mut(new_root)?;
            node.leaf.insert(item)?;
            node.leaf.generation = new_gen;
        }
        // Commit: advance generation and root pointer.
        self.root_idx = new_root;
        self.generation = new_gen;
        Ok(())
    }

    // ── CoW delete ──────────────────────────────────────────────

    /// Delete an item by key using copy-on-write semantics.
    ///
    /// A new leaf copy is created, the item is removed from it, and the
    /// tree root is updated atomically.  The generation is incremented.
    ///
    /// # Errors
    ///
    /// - `NotFound` if no matching key exists.
    /// - `OutOfMemory` if the pool is exhausted.
    pub fn cow_delete(&mut self, key: &CowKey) -> Result<()> {
        let new_gen = self.generation.wrapping_add(1);
        let new_root = self.pool.cow_clone(self.root_idx, new_gen)?;
        {
            let node = self.pool.get_mut(new_root)?;
            node.leaf.delete(key)?;
            node.leaf.generation = new_gen;
        }
        self.root_idx = new_root;
        self.generation = new_gen;
        Ok(())
    }

    // ── Transactional batch ──────────────────────────────────────

    /// Begin a write transaction.
    pub fn begin_transaction(&self) -> CowTransaction {
        CowTransaction::begin(self.generation.wrapping_add(1))
    }

    /// Commit a transaction: advance the generation and root pointer.
    ///
    /// `new_root` must be the pool index produced by the transaction's
    /// final CoW operation.
    pub fn commit_transaction(&mut self, txn: &mut CowTransaction, new_root: u32) {
        self.root_idx = new_root;
        self.generation = txn.generation;
        txn.commit();
    }

    /// Abort a transaction, freeing all nodes it allocated.
    pub fn abort_transaction(&mut self, txn: &mut CowTransaction) {
        for &idx in txn.abort() {
            self.pool.free(idx);
        }
    }

    // ── Pool stats ──────────────────────────────────────────────

    /// Number of live nodes in the pool.
    pub fn pool_live_count(&self) -> usize {
        self.pool.live_count()
    }
}
