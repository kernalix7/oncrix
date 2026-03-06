// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! XFS per-AG B-tree bulk operations — split, merge, cursor traversal.
//!
//! Builds on top of the generic XFS B-tree block layout defined in
//! `xfs_btree.rs` and provides the higher-level algorithms needed by the
//! allocation group (AG) subsystem:
//!
//! | Operation | Description |
//! |-----------|-------------|
//! | [`BtreeCursor`] | Stateful iterator over a B-tree |
//! | [`split_node`]  | Split a full node and re-parent |
//! | [`merge_nodes`] | Merge an under-full node into a sibling |
//! | [`bulk_insert`] | Load-sorted bulk insert (used by mkfs/repair) |
//! | [`range_delete`]| Delete all keys in `[lo, hi]` inclusive |
//!
//! # AG B-tree variants
//!
//! XFS maintains four B-trees per allocation group:
//!
//! 1. **ABTB** — free space indexed by block number
//! 2. **ABTC** — free space indexed by block count
//! 3. **INOBT** — inode allocation B-tree
//! 4. **FINOBT** — free-inode B-tree (optional)
//!
//! All four share the same node layout and therefore the same split/merge
//! algorithms implemented here.
//!
//! # References
//!
//! - Linux `fs/xfs/libxfs/xfs_btree.c`, `xfs_btree_multi.c`
//! - XFS Algorithms and Data Structures (Dave Chinner et al.)

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum number of keys per B-tree node.
///
/// Sized to fit a 512-byte node (header=32 + 16 keys×8 + 16 ptrs×8 = 288).
pub const BTREE_MAX_KEYS: usize = 16;

/// Minimum fill threshold: nodes below this are eligible for merge.
pub const BTREE_MIN_KEYS: usize = BTREE_MAX_KEYS / 2;

/// Maximum B-tree depth (height) supported by this implementation.
pub const BTREE_MAX_DEPTH: usize = 8;

/// Sentinel value meaning "no sibling in this direction".
pub const BTREE_NULL_PTR: u64 = u64::MAX;

// ---------------------------------------------------------------------------
// Core B-tree block types (same layout as xfs_btree.rs, redefined here to
// keep this module self-contained)
// ---------------------------------------------------------------------------

/// A single B-tree key (64-bit).
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct BtKey(pub u64);

/// A B-tree child pointer (physical block number).
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct BtPtr(pub u64);

/// On-disk representation of a B-tree node (leaf or internal).
///
/// A leaf node stores `(key, value)` pairs in `keys` and `ptrs` respectively.
/// An internal node stores `key` separators in `keys` and child block numbers
/// in `ptrs`.
#[derive(Clone, Debug)]
pub struct BtNode {
    /// XFS B-tree block magic number (identifies tree type).
    pub magic: u32,
    /// Number of valid records in this node.
    pub numrecs: u16,
    /// Node level: `0` = leaf, `> 0` = internal.
    pub level: u16,
    /// Left-sibling block pointer (leaf nodes only; `BTREE_NULL_PTR` if none).
    pub leftsib: u64,
    /// Right-sibling block pointer (leaf nodes only; `BTREE_NULL_PTR` if none).
    pub rightsib: u64,
    /// Key array.
    pub keys: [BtKey; BTREE_MAX_KEYS],
    /// Value / child-pointer array.
    pub ptrs: [BtPtr; BTREE_MAX_KEYS],
}

impl BtNode {
    /// Construct an empty leaf node with the given magic number.
    pub const fn empty_leaf(magic: u32) -> Self {
        Self {
            magic,
            numrecs: 0,
            level: 0,
            leftsib: BTREE_NULL_PTR,
            rightsib: BTREE_NULL_PTR,
            keys: [const { BtKey(0) }; BTREE_MAX_KEYS],
            ptrs: [const { BtPtr(0) }; BTREE_MAX_KEYS],
        }
    }

    /// Construct an empty internal node with the given magic number.
    pub const fn empty_internal(magic: u32, level: u16) -> Self {
        Self {
            magic,
            numrecs: 0,
            level,
            leftsib: BTREE_NULL_PTR,
            rightsib: BTREE_NULL_PTR,
            keys: [const { BtKey(0) }; BTREE_MAX_KEYS],
            ptrs: [const { BtPtr(0) }; BTREE_MAX_KEYS],
        }
    }

    /// Return `true` if this is a leaf node.
    pub fn is_leaf(&self) -> bool {
        self.level == 0
    }

    /// Return `true` if this node is completely full.
    pub fn is_full(&self) -> bool {
        self.numrecs as usize >= BTREE_MAX_KEYS
    }

    /// Return `true` if this node is under-full (eligible for merge).
    pub fn is_underfull(&self) -> bool {
        (self.numrecs as usize) < BTREE_MIN_KEYS
    }

    /// Find the insertion index for `key` using binary search.
    ///
    /// Returns `Ok(idx)` where the key is found, or `Err(idx)` for the
    /// position where it should be inserted.
    pub fn search(&self, key: BtKey) -> core::result::Result<usize, usize> {
        let recs = self.numrecs as usize;
        self.keys[..recs].binary_search(&key)
    }

    /// Insert `(key, ptr)` at position `idx`, shifting subsequent entries.
    ///
    /// Returns `Err(OutOfMemory)` if the node is full.
    pub fn insert_at(&mut self, idx: usize, key: BtKey, ptr: BtPtr) -> Result<()> {
        if self.is_full() {
            return Err(Error::OutOfMemory);
        }
        let n = self.numrecs as usize;
        // Shift entries right to make room.
        for i in (idx..n).rev() {
            self.keys[i + 1] = self.keys[i];
            self.ptrs[i + 1] = self.ptrs[i];
        }
        self.keys[idx] = key;
        self.ptrs[idx] = ptr;
        self.numrecs += 1;
        Ok(())
    }

    /// Remove the entry at position `idx`, shifting subsequent entries left.
    ///
    /// Returns `Err(NotFound)` if `idx` is out of range.
    pub fn remove_at(&mut self, idx: usize) -> Result<(BtKey, BtPtr)> {
        let n = self.numrecs as usize;
        if idx >= n {
            return Err(Error::NotFound);
        }
        let key = self.keys[idx];
        let ptr = self.ptrs[idx];
        for i in idx..n - 1 {
            self.keys[i] = self.keys[i + 1];
            self.ptrs[i] = self.ptrs[i + 1];
        }
        self.numrecs -= 1;
        Ok((key, ptr))
    }

    /// Smallest key in this node.
    pub fn min_key(&self) -> Option<BtKey> {
        if self.numrecs == 0 {
            None
        } else {
            Some(self.keys[0])
        }
    }

    /// Largest key in this node.
    pub fn max_key(&self) -> Option<BtKey> {
        let n = self.numrecs as usize;
        if n == 0 { None } else { Some(self.keys[n - 1]) }
    }
}

// ---------------------------------------------------------------------------
// In-memory B-tree (array of nodes, root at index 0)
// ---------------------------------------------------------------------------

/// Maximum number of nodes in the in-memory node pool.
pub const MAX_NODES: usize = 256;

/// In-memory XFS AG B-tree (simulates the disk tree).
///
/// Nodes are allocated from a fixed-size pool.  Node index 0 is always the
/// root.  Child pointers store node indices as `u64` values.
#[derive(Debug)]
pub struct AgBtree {
    /// Magic number for this tree type.
    pub magic: u32,
    /// Number of allocated nodes (pool watermark).
    pub node_count: usize,
    /// Node pool.
    pub nodes: [Option<BtNode>; MAX_NODES],
    /// Current root node index.
    pub root: usize,
    /// Number of levels in the tree (1 = root only).
    pub depth: usize,
}

impl AgBtree {
    /// Create a new empty B-tree with a single empty leaf root.
    pub fn new(magic: u32) -> Self {
        let mut tree = Self {
            magic,
            node_count: 0,
            nodes: core::array::from_fn(|_| None),
            root: 0,
            depth: 1,
        };
        let root = BtNode::empty_leaf(magic);
        tree.nodes[0] = Some(root);
        tree.node_count = 1;
        tree
    }

    /// Allocate a new node, returning its index.
    fn alloc_node(&mut self, node: BtNode) -> Result<usize> {
        // Find a free slot.
        let idx = (self.node_count..MAX_NODES)
            .find(|&i| self.nodes[i].is_none())
            .or_else(|| (0..self.node_count).find(|&i| self.nodes[i].is_none()))
            .ok_or(Error::OutOfMemory)?;
        self.nodes[idx] = Some(node);
        if idx >= self.node_count {
            self.node_count = idx + 1;
        }
        Ok(idx)
    }

    /// Look up `key` in the B-tree, returning the associated `BtPtr` value.
    ///
    /// Returns `Err(NotFound)` if the key is absent.
    pub fn lookup(&self, key: BtKey) -> Result<BtPtr> {
        let mut idx = self.root;
        loop {
            let node = self.nodes[idx].as_ref().ok_or(Error::IoError)?;
            match node.search(key) {
                Ok(pos) => {
                    if node.is_leaf() {
                        return Ok(node.ptrs[pos]);
                    }
                    // Internal node: descend into child at pos+1.
                    idx = node.ptrs[pos + 1].0 as usize;
                }
                Err(pos) => {
                    if node.is_leaf() {
                        return Err(Error::NotFound);
                    }
                    // Descend into the appropriate child.
                    let child_pos = if pos == 0 { 0 } else { pos - 1 };
                    idx = node.ptrs[child_pos].0 as usize;
                }
            }
        }
    }

    /// Insert `(key, value)` into the B-tree.
    ///
    /// Returns `Err(AlreadyExists)` if the key is already present.
    pub fn insert(&mut self, key: BtKey, value: BtPtr) -> Result<()> {
        // Check for duplicate.
        if self.lookup(key).is_ok() {
            return Err(Error::AlreadyExists);
        }
        let root_idx = self.root;
        if let Some(split) = self.insert_recursive(root_idx, key, value)? {
            // Root was split — create a new root.
            let old_root_min = self.nodes[root_idx]
                .as_ref()
                .and_then(|n| n.min_key())
                .unwrap_or(BtKey(0));
            let new_root_level = (self.nodes[root_idx].as_ref().map(|n| n.level).unwrap_or(0)) + 1;
            let mut new_root = BtNode::empty_internal(self.magic, new_root_level);
            new_root.insert_at(0, old_root_min, BtPtr(root_idx as u64))?;
            new_root.insert_at(1, split.sep_key, BtPtr(split.right_idx as u64))?;
            let new_root_idx = self.alloc_node(new_root)?;
            self.root = new_root_idx;
            self.depth += 1;
        }
        Ok(())
    }

    /// Delete `key` from the B-tree.
    ///
    /// Returns `Err(NotFound)` if the key is absent.
    pub fn delete(&mut self, key: BtKey) -> Result<()> {
        let root_idx = self.root;
        self.delete_recursive(root_idx, key)?;
        // If root is internal and has only one child, collapse.
        let should_collapse = self.nodes[self.root]
            .as_ref()
            .map(|n| !n.is_leaf() && n.numrecs == 1)
            .unwrap_or(false);
        if should_collapse {
            let child_ptr = self.nodes[self.root]
                .as_ref()
                .map(|n| n.ptrs[0].0 as usize)
                .ok_or(Error::IoError)?;
            self.nodes[self.root] = None;
            self.root = child_ptr;
            if self.depth > 1 {
                self.depth -= 1;
            }
        }
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Private recursive helpers
    // -----------------------------------------------------------------------

    /// Recursive insert. Returns `Some(SplitResult)` if the node was split.
    fn insert_recursive(
        &mut self,
        idx: usize,
        key: BtKey,
        value: BtPtr,
    ) -> Result<Option<SplitResult>> {
        let is_leaf = self.nodes[idx].as_ref().ok_or(Error::IoError)?.is_leaf();

        if is_leaf {
            // Leaf node: attempt direct insert.
            let insert_pos = match self.nodes[idx].as_ref().ok_or(Error::IoError)?.search(key) {
                Ok(_) => return Err(Error::AlreadyExists),
                Err(pos) => pos,
            };
            if !self.nodes[idx].as_ref().ok_or(Error::IoError)?.is_full() {
                self.nodes[idx]
                    .as_mut()
                    .ok_or(Error::IoError)?
                    .insert_at(insert_pos, key, value)?;
                return Ok(None);
            }
            // Node is full — split.
            return Ok(Some(self.split_leaf(idx, insert_pos, key, value)?));
        }

        // Internal node: find the right child and recurse.
        let child_pos = {
            let node = self.nodes[idx].as_ref().ok_or(Error::IoError)?;
            let n = node.numrecs as usize;
            let mut pos = 0;
            for i in 0..n {
                if node.keys[i] <= key {
                    pos = i;
                } else {
                    break;
                }
            }
            pos
        };
        let child_idx = self.nodes[idx].as_ref().ok_or(Error::IoError)?.ptrs[child_pos].0 as usize;
        let maybe_split = self.insert_recursive(child_idx, key, value)?;
        if let Some(split) = maybe_split {
            // Insert separator into this internal node.
            let node = self.nodes[idx].as_mut().ok_or(Error::IoError)?;
            let ins_pos = child_pos + 1;
            if !node.is_full() {
                node.insert_at(ins_pos, split.sep_key, BtPtr(split.right_idx as u64))?;
                return Ok(None);
            }
            // Internal node is full — split it.
            return Ok(Some(self.split_internal(
                idx,
                ins_pos,
                split.sep_key,
                split.right_idx,
            )?));
        }
        Ok(None)
    }

    /// Recursive delete.
    fn delete_recursive(&mut self, idx: usize, key: BtKey) -> Result<()> {
        let is_leaf = self.nodes[idx].as_ref().ok_or(Error::IoError)?.is_leaf();

        if is_leaf {
            let pos = self.nodes[idx]
                .as_ref()
                .ok_or(Error::IoError)?
                .search(key)
                .map_err(|_| Error::NotFound)?;
            self.nodes[idx]
                .as_mut()
                .ok_or(Error::IoError)?
                .remove_at(pos)?;
            return Ok(());
        }

        // Internal node: find the child and recurse.
        let child_pos = {
            let node = self.nodes[idx].as_ref().ok_or(Error::IoError)?;
            let n = node.numrecs as usize;
            let mut pos = 0;
            for i in 0..n {
                if node.keys[i] <= key {
                    pos = i;
                } else {
                    break;
                }
            }
            pos
        };
        let child_idx = self.nodes[idx].as_ref().ok_or(Error::IoError)?.ptrs[child_pos].0 as usize;
        self.delete_recursive(child_idx, key)?;
        // Attempt merge if child is under-full.
        let child_underfull = self.nodes[child_idx]
            .as_ref()
            .map(|n| n.is_underfull())
            .unwrap_or(false);
        if child_underfull {
            let _ = self.try_merge(idx, child_pos);
        }
        Ok(())
    }

    /// Split a full leaf node at the given insertion position.
    fn split_leaf(
        &mut self,
        idx: usize,
        ins_pos: usize,
        key: BtKey,
        value: BtPtr,
    ) -> Result<SplitResult> {
        let mid = BTREE_MAX_KEYS / 2;
        let mut right = BtNode::empty_leaf(self.magic);
        let n = self.nodes[idx].as_ref().ok_or(Error::IoError)?.numrecs as usize;
        // Copy upper half to right node.
        for i in mid..n {
            right.keys[i - mid] = self.nodes[idx].as_ref().ok_or(Error::IoError)?.keys[i];
            right.ptrs[i - mid] = self.nodes[idx].as_ref().ok_or(Error::IoError)?.ptrs[i];
        }
        right.numrecs = (n - mid) as u16;
        self.nodes[idx].as_mut().ok_or(Error::IoError)?.numrecs = mid as u16;
        // Insert the new key into the appropriate half.
        if ins_pos < mid {
            self.nodes[idx]
                .as_mut()
                .ok_or(Error::IoError)?
                .insert_at(ins_pos, key, value)?;
        } else {
            right.insert_at(ins_pos - mid, key, value)?;
        }
        let sep_key = right.keys[0];
        let right_idx = self.alloc_node(right)?;
        Ok(SplitResult { sep_key, right_idx })
    }

    /// Split a full internal node, inserting `(sep_key, right_ptr)` at `ins_pos`.
    fn split_internal(
        &mut self,
        idx: usize,
        ins_pos: usize,
        sep_key: BtKey,
        right_ptr: usize,
    ) -> Result<SplitResult> {
        let mid = BTREE_MAX_KEYS / 2;
        let level = self.nodes[idx].as_ref().ok_or(Error::IoError)?.level;
        let mut right = BtNode::empty_internal(self.magic, level);
        let n = self.nodes[idx].as_ref().ok_or(Error::IoError)?.numrecs as usize;
        for i in mid..n {
            right.keys[i - mid] = self.nodes[idx].as_ref().ok_or(Error::IoError)?.keys[i];
            right.ptrs[i - mid] = self.nodes[idx].as_ref().ok_or(Error::IoError)?.ptrs[i];
        }
        right.numrecs = (n - mid) as u16;
        self.nodes[idx].as_mut().ok_or(Error::IoError)?.numrecs = mid as u16;
        if ins_pos <= mid {
            self.nodes[idx].as_mut().ok_or(Error::IoError)?.insert_at(
                ins_pos,
                sep_key,
                BtPtr(right_ptr as u64),
            )?;
        } else {
            right.insert_at(ins_pos - mid, sep_key, BtPtr(right_ptr as u64))?;
        }
        let promote = right.keys[0];
        let right_idx = self.alloc_node(right)?;
        Ok(SplitResult {
            sep_key: promote,
            right_idx,
        })
    }

    /// Attempt to merge an under-full child at `child_pos` with a sibling.
    fn try_merge(&mut self, parent_idx: usize, child_pos: usize) -> Result<()> {
        let parent_n = self.nodes[parent_idx]
            .as_ref()
            .ok_or(Error::IoError)?
            .numrecs as usize;
        // Try merging with the right sibling if available.
        if child_pos + 1 < parent_n {
            let left_idx =
                self.nodes[parent_idx].as_ref().ok_or(Error::IoError)?.ptrs[child_pos].0 as usize;
            let right_idx = self.nodes[parent_idx].as_ref().ok_or(Error::IoError)?.ptrs
                [child_pos + 1]
                .0 as usize;
            let combined = {
                let l = self.nodes[left_idx].as_ref().ok_or(Error::IoError)?;
                let r = self.nodes[right_idx].as_ref().ok_or(Error::IoError)?;
                (l.numrecs + r.numrecs) as usize
            };
            if combined <= BTREE_MAX_KEYS {
                // Merge right into left.
                let r_n = self.nodes[right_idx]
                    .as_ref()
                    .ok_or(Error::IoError)?
                    .numrecs as usize;
                let l_n = self.nodes[left_idx].as_ref().ok_or(Error::IoError)?.numrecs as usize;
                for i in 0..r_n {
                    let k = self.nodes[right_idx].as_ref().ok_or(Error::IoError)?.keys[i];
                    let p = self.nodes[right_idx].as_ref().ok_or(Error::IoError)?.ptrs[i];
                    self.nodes[left_idx].as_mut().ok_or(Error::IoError)?.keys[l_n + i] = k;
                    self.nodes[left_idx].as_mut().ok_or(Error::IoError)?.ptrs[l_n + i] = p;
                }
                self.nodes[left_idx].as_mut().ok_or(Error::IoError)?.numrecs = combined as u16;
                self.nodes[right_idx] = None;
                self.nodes[parent_idx]
                    .as_mut()
                    .ok_or(Error::IoError)?
                    .remove_at(child_pos + 1)?;
            }
        }
        Ok(())
    }
}

/// Internal structure returned when a B-tree node is split.
struct SplitResult {
    /// Separator key to be promoted to the parent.
    sep_key: BtKey,
    /// Index of the newly created right node.
    right_idx: usize,
}

// ---------------------------------------------------------------------------
// B-tree cursor
// ---------------------------------------------------------------------------

/// A stateful cursor for iterating over B-tree leaf records in key order.
///
/// The cursor maintains a path from root to the current leaf position.
#[derive(Debug)]
pub struct BtreeCursor {
    /// Node indices along the path from root (index 0) to the leaf.
    pub path: [usize; BTREE_MAX_DEPTH],
    /// Per-level record position within the node.
    pub pos: [usize; BTREE_MAX_DEPTH],
    /// Current depth (length of path used).
    pub depth: usize,
    /// Whether the cursor is positioned on a valid record.
    pub valid: bool,
}

impl BtreeCursor {
    /// Create an uninitialised cursor.
    pub const fn new() -> Self {
        Self {
            path: [0; BTREE_MAX_DEPTH],
            pos: [0; BTREE_MAX_DEPTH],
            depth: 0,
            valid: false,
        }
    }

    /// Position the cursor on the first record `>= key`.
    pub fn seek(&mut self, tree: &AgBtree, key: BtKey) -> Result<bool> {
        let mut idx = tree.root;
        let mut level = 0;
        loop {
            let node = tree.nodes[idx].as_ref().ok_or(Error::IoError)?;
            let pos = match node.search(key) {
                Ok(p) => p,
                Err(p) => {
                    if node.is_leaf() {
                        // p is the insertion point; record at p (if any) is >= key.
                        self.path[level] = idx;
                        self.pos[level] = p;
                        self.depth = level + 1;
                        self.valid = p < node.numrecs as usize;
                        return Ok(self.valid);
                    }
                    if p == 0 { 0 } else { p - 1 }
                }
            };
            if node.is_leaf() {
                self.path[level] = idx;
                self.pos[level] = pos;
                self.depth = level + 1;
                self.valid = pos < node.numrecs as usize;
                return Ok(self.valid);
            }
            self.path[level] = idx;
            self.pos[level] = pos;
            idx = node.ptrs[pos].0 as usize;
            level += 1;
            if level >= BTREE_MAX_DEPTH {
                return Err(Error::IoError);
            }
        }
    }

    /// Return the key and value at the current cursor position.
    pub fn current<'a>(&self, tree: &'a AgBtree) -> Result<(BtKey, &'a BtPtr)> {
        if !self.valid || self.depth == 0 {
            return Err(Error::NotFound);
        }
        let leaf_level = self.depth - 1;
        let node = tree.nodes[self.path[leaf_level]]
            .as_ref()
            .ok_or(Error::IoError)?;
        let pos = self.pos[leaf_level];
        if pos >= node.numrecs as usize {
            return Err(Error::NotFound);
        }
        Ok((node.keys[pos], &node.ptrs[pos]))
    }

    /// Advance the cursor to the next record in key order.
    pub fn advance(&mut self, tree: &AgBtree) -> Result<bool> {
        if !self.valid || self.depth == 0 {
            return Ok(false);
        }
        let leaf_level = self.depth - 1;
        let next_pos = self.pos[leaf_level] + 1;
        let n = tree.nodes[self.path[leaf_level]]
            .as_ref()
            .ok_or(Error::IoError)?
            .numrecs as usize;
        if next_pos < n {
            self.pos[leaf_level] = next_pos;
            return Ok(true);
        }
        // Move to the right sibling leaf via the parent.
        let right_sib = tree.nodes[self.path[leaf_level]]
            .as_ref()
            .ok_or(Error::IoError)?
            .rightsib;
        if right_sib == BTREE_NULL_PTR {
            self.valid = false;
            return Ok(false);
        }
        self.path[leaf_level] = right_sib as usize;
        self.pos[leaf_level] = 0;
        Ok(true)
    }
}

impl Default for BtreeCursor {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Bulk insert (sorted order)
// ---------------------------------------------------------------------------

/// Insert a sorted slice of `(key, value)` pairs into the tree efficiently.
///
/// The slice **must** be sorted in ascending key order and contain no
/// duplicates.  Violating this invariant results in `Err(InvalidArgument)`.
pub fn bulk_insert(tree: &mut AgBtree, pairs: &[(BtKey, BtPtr)]) -> Result<()> {
    // Validate ordering.
    for w in pairs.windows(2) {
        if w[0].0 >= w[1].0 {
            return Err(Error::InvalidArgument);
        }
    }
    for &(k, v) in pairs {
        tree.insert(k, v)?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Range delete
// ---------------------------------------------------------------------------

/// Delete all keys in the inclusive range `[lo, hi]` from the tree.
///
/// Returns the number of keys deleted.
pub fn range_delete(tree: &mut AgBtree, lo: BtKey, hi: BtKey) -> Result<usize> {
    if lo > hi {
        return Err(Error::InvalidArgument);
    }
    // Collect keys to delete first to avoid borrow issues.
    let mut to_delete: [BtKey; MAX_NODES] = [const { BtKey(0) }; MAX_NODES];
    let mut count = 0usize;
    let mut cursor = BtreeCursor::new();
    if !cursor.seek(tree, lo)? {
        return Ok(0);
    }
    loop {
        let (k, _) = cursor.current(tree)?;
        if k > hi {
            break;
        }
        if count >= MAX_NODES {
            return Err(Error::OutOfMemory);
        }
        to_delete[count] = k;
        count += 1;
        if !cursor.advance(tree)? {
            break;
        }
    }
    for i in 0..count {
        tree.delete(to_delete[i])?;
    }
    Ok(count)
}
