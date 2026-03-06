// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Btrfs B-tree operations.
//!
//! Implements the core Btrfs B-tree data structures and algorithms:
//! - [`BtrfsKey`] — composite tree key `(objectid, item_type, offset)`
//! - [`BtrfsHeader`] — node header (csum, fsid, bytenr, flags, level, nritems)
//! - [`BtrfsItem`] — item descriptor `(key, data_offset, data_size)`
//! - [`search_slot`] — binary-search for a key, returning path + index
//! - [`insert_item`] — insert a key/value pair into the tree leaf
//! - [`delete_item`] — remove an item from a leaf by key
//! - Path walk: traverse from root to target leaf following key comparisons
//!
//! # Tree Layout
//!
//! Internal nodes hold `(key, child_ptr)` pairs. Leaf nodes hold
//! `(BtrfsItem, data)` pairs. All nodes are fixed at `NODE_SIZE` bytes.
//! This module uses a flat pool of nodes indexed by `NodeId`.
//!
//! # References
//! - Linux `fs/btrfs/ctree.c`, `fs/btrfs/ctree.h`

extern crate alloc;
use alloc::vec::Vec;
use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum items per leaf node.
const MAX_LEAF_ITEMS: usize = 32;

/// Maximum key pointers per internal node.
const MAX_KEYS_PER_NODE: usize = 32;

/// Maximum depth of the B-tree (including root).
const MAX_TREE_DEPTH: usize = 8;

/// Maximum total nodes in the node pool.
const MAX_NODES: usize = 256;

/// Maximum item data payload in bytes (per item).
const MAX_ITEM_DATA: usize = 512;

/// Btrfs leaf node level (0 = leaf).
const BTRFS_LEAF_LEVEL: u8 = 0;

/// Btrfs FSID length.
const BTRFS_FSID_SIZE: usize = 16;

/// Btrfs CSUM size.
const BTRFS_CSUM_SIZE: usize = 32;

// ---------------------------------------------------------------------------
// BtrfsKey
// ---------------------------------------------------------------------------

/// Btrfs composite B-tree key.
///
/// Keys are ordered first by `objectid`, then `item_type`, then `offset`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BtrfsKey {
    /// Object ID (inode number, extent bytenr, etc.).
    pub objectid: u64,
    /// Item type discriminant (BTRFS_*_KEY constants).
    pub item_type: u8,
    /// Type-specific offset (file offset, block offset, 0 for inodes, etc.).
    pub offset: u64,
}

impl BtrfsKey {
    /// Create a new Btrfs key.
    pub fn new(objectid: u64, item_type: u8, offset: u64) -> Self {
        Self {
            objectid,
            item_type,
            offset,
        }
    }

    /// Ordering: compare by (objectid, item_type, offset).
    pub fn cmp_key(&self, other: &Self) -> core::cmp::Ordering {
        self.objectid
            .cmp(&other.objectid)
            .then(self.item_type.cmp(&other.item_type))
            .then(self.offset.cmp(&other.offset))
    }
}

impl PartialOrd for BtrfsKey {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp_key(other))
    }
}

impl Ord for BtrfsKey {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.cmp_key(other)
    }
}

// ---------------------------------------------------------------------------
// BtrfsHeader
// ---------------------------------------------------------------------------

/// Btrfs node/leaf header.
///
/// Every tree node (leaf or internal) starts with this 101-byte header.
#[derive(Debug, Clone, Copy)]
pub struct BtrfsHeader {
    /// Checksum of the node (first `BTRFS_CSUM_SIZE` bytes).
    pub csum: [u8; BTRFS_CSUM_SIZE],
    /// Filesystem UUID.
    pub fsid: [u8; BTRFS_FSID_SIZE],
    /// Logical byte number of this node on disk.
    pub bytenr: u64,
    /// Node flags (BTRFS_HEADER_FLAG_*).
    pub flags: u64,
    /// Chunk tree UUID.
    pub chunk_tree_uuid: [u8; BTRFS_FSID_SIZE],
    /// Generation (transaction ID) when this node was written.
    pub generation: u64,
    /// Owner tree's object ID.
    pub owner: u64,
    /// Number of items (leaf) or key pointers (internal) in this node.
    pub nritems: u32,
    /// Tree level (0 = leaf, higher = internal).
    pub level: u8,
}

impl BtrfsHeader {
    /// Create a new node header.
    pub fn new(bytenr: u64, level: u8, generation: u64) -> Self {
        Self {
            csum: [0u8; BTRFS_CSUM_SIZE],
            fsid: [0u8; BTRFS_FSID_SIZE],
            bytenr,
            flags: 0,
            chunk_tree_uuid: [0u8; BTRFS_FSID_SIZE],
            generation,
            owner: 5, // FS_TREE_OBJECTID
            nritems: 0,
            level,
        }
    }
}

// ---------------------------------------------------------------------------
// BtrfsItem
// ---------------------------------------------------------------------------

/// Btrfs leaf item descriptor.
///
/// Describes a single item's key, data offset, and data size within a leaf.
#[derive(Debug, Clone, Copy)]
pub struct BtrfsItem {
    /// Item key.
    pub key: BtrfsKey,
    /// Offset into the leaf's data area.
    pub data_offset: u32,
    /// Size of the item data.
    pub data_size: u32,
}

impl BtrfsItem {
    /// Create a new item descriptor.
    pub fn new(key: BtrfsKey, data_offset: u32, data_size: u32) -> Self {
        Self {
            key,
            data_offset,
            data_size,
        }
    }
}

// ---------------------------------------------------------------------------
// KeyPtr — used in internal nodes
// ---------------------------------------------------------------------------

/// Internal node key pointer: (key, child node index).
#[derive(Debug, Clone, Copy)]
struct KeyPtr {
    key: BtrfsKey,
    /// Index into the node pool for the child node.
    child_node_id: usize,
    /// Generation of child node.
    generation: u64,
}

// ---------------------------------------------------------------------------
// Node — leaf or internal
// ---------------------------------------------------------------------------

/// A single B-tree node (leaf or internal).
pub struct BtrfsNode {
    /// Node header.
    pub header: BtrfsHeader,
    /// Leaf items (valid when `header.level == 0`).
    leaf_items: [Option<BtrfsItem>; MAX_LEAF_ITEMS],
    /// Leaf item data payloads.
    leaf_data: [[u8; MAX_ITEM_DATA]; MAX_LEAF_ITEMS],
    /// Internal node key pointers (valid when `header.level > 0`).
    key_ptrs: [Option<KeyPtr>; MAX_KEYS_PER_NODE],
}

impl BtrfsNode {
    /// Create a new leaf node.
    fn new_leaf(bytenr: u64, generation: u64) -> Self {
        Self {
            header: BtrfsHeader::new(bytenr, BTRFS_LEAF_LEVEL, generation),
            leaf_items: core::array::from_fn(|_| None),
            leaf_data: [[0u8; MAX_ITEM_DATA]; MAX_LEAF_ITEMS],
            key_ptrs: core::array::from_fn(|_| None),
        }
    }

    /// Create a new internal node at the given level.
    fn new_internal(bytenr: u64, level: u8, generation: u64) -> Self {
        Self {
            header: BtrfsHeader::new(bytenr, level, generation),
            leaf_items: core::array::from_fn(|_| None),
            leaf_data: [[0u8; MAX_ITEM_DATA]; MAX_LEAF_ITEMS],
            key_ptrs: core::array::from_fn(|_| None),
        }
    }

    /// Return true if this is a leaf node.
    pub fn is_leaf(&self) -> bool {
        self.header.level == BTRFS_LEAF_LEVEL
    }

    /// Binary-search leaf items for `key`. Returns the index of the first
    /// item with key >= `key`, or `nritems` if all items are smaller.
    fn leaf_search(&self, key: &BtrfsKey) -> usize {
        let n = self.header.nritems as usize;
        let mut lo = 0usize;
        let mut hi = n;
        while lo < hi {
            let mid = lo + (hi - lo) / 2;
            if let Some(item) = &self.leaf_items[mid] {
                match item.key.cmp_key(key) {
                    core::cmp::Ordering::Less => lo = mid + 1,
                    _ => hi = mid,
                }
            } else {
                hi = mid;
            }
        }
        lo
    }

    /// Binary-search internal key pointers for a child that may contain `key`.
    fn internal_search(&self, key: &BtrfsKey) -> usize {
        let n = self.header.nritems as usize;
        if n == 0 {
            return 0;
        }
        let mut lo = 0usize;
        let mut hi = n - 1;
        while lo < hi {
            let mid = lo + (hi - lo + 1) / 2;
            if let Some(kp) = &self.key_ptrs[mid] {
                if kp.key.cmp_key(key) != core::cmp::Ordering::Greater {
                    lo = mid;
                } else {
                    if mid == 0 {
                        break;
                    }
                    hi = mid - 1;
                }
            } else {
                break;
            }
        }
        lo
    }
}

// ---------------------------------------------------------------------------
// BtrfsNodePool
// ---------------------------------------------------------------------------

/// Fixed pool of B-tree nodes.
pub struct BtrfsNodePool {
    nodes: [Option<BtrfsNode>; MAX_NODES],
    count: usize,
    next_bytenr: u64,
}

impl BtrfsNodePool {
    /// Create an empty node pool.
    pub fn new() -> Self {
        Self {
            nodes: core::array::from_fn(|_| None),
            count: 0,
            next_bytenr: 4096,
        }
    }

    /// Allocate a new leaf node. Returns its index in the pool.
    pub fn alloc_leaf(&mut self, generation: u64) -> Result<usize> {
        if self.count >= MAX_NODES {
            return Err(Error::OutOfMemory);
        }
        let bytenr = self.next_bytenr;
        self.next_bytenr += 4096;
        let idx = self.count;
        self.nodes[idx] = Some(BtrfsNode::new_leaf(bytenr, generation));
        self.count += 1;
        Ok(idx)
    }

    /// Allocate a new internal node. Returns its index in the pool.
    pub fn alloc_internal(&mut self, level: u8, generation: u64) -> Result<usize> {
        if self.count >= MAX_NODES {
            return Err(Error::OutOfMemory);
        }
        let bytenr = self.next_bytenr;
        self.next_bytenr += 4096;
        let idx = self.count;
        self.nodes[idx] = Some(BtrfsNode::new_internal(bytenr, level, generation));
        self.count += 1;
        Ok(idx)
    }
}

impl Default for BtrfsNodePool {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// BtrfsPath — result of search_slot
// ---------------------------------------------------------------------------

/// Path from root to leaf, tracking the slot in each node.
#[derive(Debug, Clone)]
pub struct BtrfsPath {
    /// Node indices from root down to leaf.
    pub nodes: [usize; MAX_TREE_DEPTH],
    /// Slot index within each node at the corresponding depth.
    pub slots: [usize; MAX_TREE_DEPTH],
    /// Actual depth of the path (number of valid entries).
    pub depth: usize,
    /// Index within the leaf of the matched/insertion slot.
    pub leaf_slot: usize,
    /// True if the search found an exact key match.
    pub exact_match: bool,
}

impl BtrfsPath {
    fn new() -> Self {
        Self {
            nodes: [0usize; MAX_TREE_DEPTH],
            slots: [0usize; MAX_TREE_DEPTH],
            depth: 0,
            leaf_slot: 0,
            exact_match: false,
        }
    }
}

// ---------------------------------------------------------------------------
// BtrfsTree
// ---------------------------------------------------------------------------

/// A single Btrfs B-tree (e.g., the filesystem tree, extent tree).
pub struct BtrfsTree {
    /// Node pool shared across trees.
    pool: BtrfsNodePool,
    /// Index of the root node in the pool.
    root_idx: usize,
    /// Current generation (transaction ID).
    generation: u64,
}

impl BtrfsTree {
    /// Create a new empty B-tree with a single empty leaf as root.
    pub fn new() -> Result<Self> {
        let mut pool = BtrfsNodePool::new();
        let root_idx = pool.alloc_leaf(1)?;
        Ok(Self {
            pool,
            root_idx,
            generation: 1,
        })
    }

    /// Search for `key` in the tree, returning a [`BtrfsPath`].
    ///
    /// `path.exact_match` indicates whether the key was found exactly.
    /// `path.leaf_slot` is the insertion/found position in the leaf.
    pub fn search_slot(&self, key: &BtrfsKey) -> Result<BtrfsPath> {
        let mut path = BtrfsPath::new();
        let mut node_idx = self.root_idx;
        loop {
            if node_idx >= self.pool.count {
                return Err(Error::IoError);
            }
            let node = self.pool.nodes[node_idx].as_ref().ok_or(Error::IoError)?;
            path.nodes[path.depth] = node_idx;

            if node.is_leaf() {
                let slot = node.leaf_search(key);
                path.leaf_slot = slot;
                let nritems = node.header.nritems as usize;
                path.exact_match = slot < nritems
                    && node.leaf_items[slot]
                        .as_ref()
                        .map(|i| &i.key == key)
                        .unwrap_or(false);
                path.depth += 1;
                return Ok(path);
            }

            // Internal node: descend.
            let slot = node.internal_search(key);
            path.slots[path.depth] = slot;
            if let Some(kp) = &node.key_ptrs[slot] {
                let child = kp.child_node_id;
                path.depth += 1;
                if path.depth >= MAX_TREE_DEPTH {
                    return Err(Error::IoError);
                }
                node_idx = child;
            } else {
                path.depth += 1;
                return Ok(path);
            }
        }
    }

    /// Insert a new key/value pair into the tree.
    ///
    /// Returns `Err(AlreadyExists)` if the key already exists.
    /// Returns `Err(OutOfMemory)` if the leaf is full.
    pub fn insert_item(&mut self, key: BtrfsKey, data: &[u8]) -> Result<()> {
        if data.len() > MAX_ITEM_DATA {
            return Err(Error::InvalidArgument);
        }
        let path = self.search_slot(&key)?;
        if path.exact_match {
            return Err(Error::AlreadyExists);
        }

        // We only support single-level (root = leaf) for simplicity here.
        let leaf_idx = path.nodes[path.depth.saturating_sub(1)];
        let leaf = self.pool.nodes[leaf_idx].as_mut().ok_or(Error::IoError)?;

        if !leaf.is_leaf() {
            return Err(Error::NotImplemented);
        }
        let nritems = leaf.header.nritems as usize;
        if nritems >= MAX_LEAF_ITEMS {
            return Err(Error::OutOfMemory);
        }

        let slot = path.leaf_slot;
        // Shift items right to make room.
        for i in (slot..nritems).rev() {
            leaf.leaf_items.swap(i, i + 1);
            // Swap data arrays.
            let (lo, hi) = leaf.leaf_data.split_at_mut(i + 1);
            lo[i].swap_with_slice(&mut hi[0]);
        }

        let item = BtrfsItem::new(key, 0, data.len() as u32);
        leaf.leaf_items[slot] = Some(item);
        leaf.leaf_data[slot][..data.len()].copy_from_slice(data);
        leaf.header.nritems += 1;
        self.generation += 1;
        Ok(())
    }

    /// Read the data payload for an exact key match.
    ///
    /// Returns `Err(NotFound)` if the key is absent.
    pub fn read_item(&self, key: &BtrfsKey) -> Result<Vec<u8>> {
        let path = self.search_slot(key)?;
        if !path.exact_match {
            return Err(Error::NotFound);
        }
        let leaf_idx = path.nodes[path.depth.saturating_sub(1)];
        let leaf = self.pool.nodes[leaf_idx].as_ref().ok_or(Error::IoError)?;
        let item = leaf.leaf_items[path.leaf_slot]
            .as_ref()
            .ok_or(Error::NotFound)?;
        Ok(leaf.leaf_data[path.leaf_slot][..item.data_size as usize].to_vec())
    }

    /// Delete an item by key.
    ///
    /// Returns `Err(NotFound)` if the key is absent.
    pub fn delete_item(&mut self, key: &BtrfsKey) -> Result<()> {
        let path = self.search_slot(key)?;
        if !path.exact_match {
            return Err(Error::NotFound);
        }
        let leaf_idx = path.nodes[path.depth.saturating_sub(1)];
        let leaf = self.pool.nodes[leaf_idx].as_mut().ok_or(Error::IoError)?;
        let nritems = leaf.header.nritems as usize;
        let slot = path.leaf_slot;

        // Shift items left.
        for i in slot..nritems - 1 {
            leaf.leaf_items.swap(i, i + 1);
            let (lo, hi) = leaf.leaf_data.split_at_mut(i + 1);
            lo[i].swap_with_slice(&mut hi[0]);
        }
        leaf.leaf_items[nritems - 1] = None;
        leaf.header.nritems -= 1;
        self.generation += 1;
        Ok(())
    }
}

impl Default for BtrfsTree {
    fn default() -> Self {
        Self::new().expect("BtrfsTree::default")
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_insert_search_delete() {
        let mut tree = BtrfsTree::new().unwrap();
        let k = BtrfsKey::new(256, 1, 0);
        tree.insert_item(k, b"inode_data").unwrap();
        let data = tree.read_item(&k).unwrap();
        assert_eq!(data, b"inode_data");
        tree.delete_item(&k).unwrap();
        assert!(tree.read_item(&k).is_err());
    }

    #[test]
    fn test_duplicate_key_rejected() {
        let mut tree = BtrfsTree::new().unwrap();
        let k = BtrfsKey::new(1, 1, 0);
        tree.insert_item(k, b"a").unwrap();
        assert!(matches!(
            tree.insert_item(k, b"b"),
            Err(Error::AlreadyExists)
        ));
    }

    #[test]
    fn test_key_ordering() {
        let k1 = BtrfsKey::new(1, 0, 0);
        let k2 = BtrfsKey::new(2, 0, 0);
        assert!(k1 < k2);
    }
}
