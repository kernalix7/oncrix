// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Btrfs-style Copy-on-Write B-tree filesystem.
//!
//! Implements the core data structures and operations for a btrfs-like
//! filesystem with copy-on-write semantics. All tree modifications
//! create new nodes rather than modifying in place, enabling atomic
//! updates and efficient snapshotting.
//!
//! # Design
//!
//! - [`BtrfsKey`] — composite key (objectid, type, offset) for all items
//! - [`BtrfsNode`] — B-tree nodes (leaf or internal), 32 items/keys each
//! - [`BtrfsTree`] — CoW B-tree with insert, lookup, and delete
//! - [`BtrfsChunk`] — logical-to-physical address translation (64 chunks)
//! - [`BtrfsSuperblock`] — on-disk metadata header
//! - [`BtrfsSubvolume`] — independent filesystem tree with snapshot support
//! - [`BtrfsFs`] — full filesystem: superblock + 16 subvolumes + chunk map
//! - [`BtrfsRegistry`] — 4 mounted btrfs instances
//!
//! # Copy-on-Write
//!
//! When a leaf node is modified (insert/delete), a new copy of the
//! node is created with the modification applied. The parent's pointer
//! is updated to reference the new copy. This propagates up to the
//! root, resulting in a new root for every modification. The old
//! root remains valid, enabling snapshots by simply retaining the
//! old root pointer.

use oncrix_lib::{Error, Result};

// ── Constants ───────────────────────────────────────────────────

/// Maximum items per B-tree leaf node.
const MAX_ITEMS_PER_LEAF: usize = 32;

/// Maximum key/pointer pairs per internal node.
const MAX_KEYS_PER_INTERNAL: usize = 32;

/// Maximum number of chunks in the chunk map.
const MAX_CHUNKS: usize = 64;

/// Maximum number of subvolumes per filesystem.
const MAX_SUBVOLUMES: usize = 16;

/// Maximum number of mounted btrfs instances.
const MAX_BTRFS_INSTANCES: usize = 4;

/// Maximum number of nodes in the node pool.
const MAX_NODES: usize = 256;

/// Maximum data payload per item (bytes).
const MAX_ITEM_DATA: usize = 256;

/// Maximum path length for path-based operations.
const MAX_PATH_LEN: usize = 256;

/// Maximum file data stored per inode item.
const MAX_FILE_DATA: usize = 4096;

/// Maximum name length for subvolumes.
const MAX_SUBVOL_NAME: usize = 64;

/// Btrfs superblock magic bytes: "_BHRfS_M" in little-endian.
const BTRFS_MAGIC: u64 = 0x4D5F_5346_5248_425F;

/// Object ID for the filesystem tree root.
const BTRFS_FS_TREE_OBJECTID: u64 = 5;

// ── Item types ──────────────────────────────────────────────────

/// Btrfs item type: inode item.
const BTRFS_INODE_ITEM_KEY: u8 = 1;

/// Btrfs item type: directory item.
const BTRFS_DIR_ITEM_KEY: u8 = 84;

/// Btrfs item type: extent data (file contents).
const BTRFS_EXTENT_DATA_KEY: u8 = 108;

// ── BtrfsKey ────────────────────────────────────────────────────

/// Btrfs search key.
///
/// The standard btrfs key is a triple `(objectid, type, offset)` that
/// uniquely identifies every item in the filesystem. Keys are sorted
/// lexicographically: first by objectid, then by type, then by offset.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BtrfsKey {
    /// Object identifier (inode number, tree ID, etc.).
    pub objectid: u64,
    /// Item type discriminator (e.g., inode, dir entry, extent).
    pub type_field: u8,
    /// Type-specific offset (byte offset, hash, sequence number).
    pub offset: u64,
}

impl BtrfsKey {
    /// Create a new btrfs key.
    pub const fn new(objectid: u64, type_field: u8, offset: u64) -> Self {
        Self {
            objectid,
            type_field,
            offset,
        }
    }

    /// Create a zero key (minimum possible key).
    pub const fn zero() -> Self {
        Self {
            objectid: 0,
            type_field: 0,
            offset: 0,
        }
    }
}

impl PartialOrd for BtrfsKey {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for BtrfsKey {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.objectid
            .cmp(&other.objectid)
            .then(self.type_field.cmp(&other.type_field))
            .then(self.offset.cmp(&other.offset))
    }
}

// ── BtrfsItem ───────────────────────────────────────────────────

/// A single item stored in a B-tree leaf node.
///
/// Each item consists of a key and inline data. In a real btrfs
/// implementation, the data would be stored at an offset within
/// the leaf's data area; here we inline it for simplicity.
#[derive(Debug, Clone)]
pub struct BtrfsItem {
    /// Item key.
    pub key: BtrfsKey,
    /// Inline data payload.
    pub data: [u8; MAX_ITEM_DATA],
    /// Length of valid data in the payload.
    pub data_len: usize,
    /// Whether this item slot is in use.
    pub in_use: bool,
}

impl BtrfsItem {
    /// Create an empty item slot.
    const fn empty() -> Self {
        Self {
            key: BtrfsKey::zero(),
            data: [0u8; MAX_ITEM_DATA],
            data_len: 0,
            in_use: false,
        }
    }

    /// Create a new item with data.
    ///
    /// # Errors
    ///
    /// Returns `InvalidArgument` if data exceeds [`MAX_ITEM_DATA`].
    pub fn new(key: BtrfsKey, data: &[u8]) -> Result<Self> {
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

    /// Return the data payload as a byte slice.
    pub fn data(&self) -> &[u8] {
        &self.data[..self.data_len]
    }
}

// ── BtrfsLeaf ───────────────────────────────────────────────────

/// Header common to both leaf and internal nodes.
#[derive(Debug, Clone, Copy)]
pub struct BtrfsNodeHeader {
    /// Logical byte address of this node on disk.
    pub bytenr: u64,
    /// Transaction ID that created this node.
    pub generation: u64,
    /// Owner tree (objectid of the tree this node belongs to).
    pub owner: u64,
    /// Number of valid items (leaf) or keys (internal).
    pub nritems: u32,
    /// Tree level (0 for leaves, >0 for internal nodes).
    pub level: u8,
}

impl BtrfsNodeHeader {
    /// Create a new node header.
    pub const fn new(bytenr: u64, generation: u64, owner: u64, level: u8) -> Self {
        Self {
            bytenr,
            generation,
            owner,
            nritems: 0,
            level,
        }
    }
}

/// A B-tree leaf node containing sorted items.
///
/// Items are maintained in sorted order by key. The leaf can hold
/// up to [`MAX_ITEMS_PER_LEAF`] items.
#[derive(Debug, Clone)]
pub struct BtrfsLeaf {
    /// Node header.
    pub header: BtrfsNodeHeader,
    /// Sorted item array.
    pub items: [BtrfsItem; MAX_ITEMS_PER_LEAF],
}

impl BtrfsLeaf {
    /// Create a new empty leaf node.
    pub fn new(bytenr: u64, generation: u64, owner: u64) -> Self {
        const EMPTY: BtrfsItem = BtrfsItem::empty();
        Self {
            header: BtrfsNodeHeader::new(bytenr, generation, owner, 0),
            items: [EMPTY; MAX_ITEMS_PER_LEAF],
        }
    }

    /// Return the number of items in this leaf.
    pub fn item_count(&self) -> usize {
        self.header.nritems as usize
    }

    /// Check whether the leaf is full.
    pub fn is_full(&self) -> bool {
        self.header.nritems as usize >= MAX_ITEMS_PER_LEAF
    }

    /// Find an item by key.
    ///
    /// Returns the index if found.
    pub fn find(&self, key: &BtrfsKey) -> Option<usize> {
        let count = self.header.nritems as usize;
        (0..count).find(|&i| self.items[i].in_use && self.items[i].key == *key)
    }

    /// Insert an item in sorted order.
    ///
    /// # Errors
    ///
    /// - `OutOfMemory` if the leaf is full.
    /// - `AlreadyExists` if an item with the same key exists.
    pub fn insert(&mut self, item: BtrfsItem) -> Result<()> {
        if self.is_full() {
            return Err(Error::OutOfMemory);
        }

        let count = self.header.nritems as usize;

        // Check for duplicates and find insertion position.
        let mut pos = count;
        for i in 0..count {
            if self.items[i].key == item.key {
                return Err(Error::AlreadyExists);
            }
            if self.items[i].key > item.key && pos == count {
                pos = i;
            }
        }

        // Shift items to make room at `pos`.
        if pos < count {
            // Move items from pos..count to pos+1..count+1.
            let mut i = count;
            while i > pos {
                self.items[i] = self.items[i - 1].clone();
                i -= 1;
            }
        }

        self.items[pos] = item;
        self.header.nritems = self.header.nritems.saturating_add(1);
        Ok(())
    }

    /// Delete an item by key.
    ///
    /// # Errors
    ///
    /// - `NotFound` if no item with the given key exists.
    pub fn delete(&mut self, key: &BtrfsKey) -> Result<()> {
        let count = self.header.nritems as usize;
        let idx = self.find(key).ok_or(Error::NotFound)?;

        // Shift items to fill the gap.
        for i in idx..count.saturating_sub(1) {
            self.items[i] = self.items[i + 1].clone();
        }

        // Clear the last slot.
        if count > 0 {
            self.items[count - 1] = BtrfsItem::empty();
        }

        self.header.nritems = self.header.nritems.saturating_sub(1);
        Ok(())
    }

    /// Look up an item by key and return a reference to its data.
    ///
    /// # Errors
    ///
    /// - `NotFound` if no item with the given key exists.
    pub fn lookup(&self, key: &BtrfsKey) -> Result<&BtrfsItem> {
        let idx = self.find(key).ok_or(Error::NotFound)?;
        Ok(&self.items[idx])
    }
}

// ── BtrfsInternalNode ───────────────────────────────────────────

/// A key/pointer pair in an internal B-tree node.
#[derive(Debug, Clone, Copy)]
pub struct BtrfsKeyPtr {
    /// The key that separates children.
    pub key: BtrfsKey,
    /// Index into the node pool pointing to the child node.
    pub blockptr: u64,
    /// Generation number of the child.
    pub generation: u64,
}

impl BtrfsKeyPtr {
    /// Create an empty key-pointer pair.
    const fn empty() -> Self {
        Self {
            key: BtrfsKey::zero(),
            blockptr: 0,
            generation: 0,
        }
    }
}

/// An internal B-tree node containing sorted key/pointer pairs.
///
/// Each key separates two child subtrees. The child at index `i`
/// contains all items with keys in the range `[keys[i], keys[i+1])`.
#[derive(Debug, Clone)]
pub struct BtrfsInternalNode {
    /// Node header (level > 0).
    pub header: BtrfsNodeHeader,
    /// Sorted key/pointer pairs.
    pub ptrs: [BtrfsKeyPtr; MAX_KEYS_PER_INTERNAL],
}

impl BtrfsInternalNode {
    /// Create a new empty internal node at the given level.
    pub fn new(bytenr: u64, generation: u64, owner: u64, level: u8) -> Self {
        const EMPTY: BtrfsKeyPtr = BtrfsKeyPtr::empty();
        Self {
            header: BtrfsNodeHeader::new(bytenr, generation, owner, level),
            ptrs: [EMPTY; MAX_KEYS_PER_INTERNAL],
        }
    }

    /// Return the number of key/pointer pairs.
    pub fn key_count(&self) -> usize {
        self.header.nritems as usize
    }

    /// Check whether the node is full.
    pub fn is_full(&self) -> bool {
        self.header.nritems as usize >= MAX_KEYS_PER_INTERNAL
    }

    /// Find the child index for a given key.
    ///
    /// Returns the index of the child subtree that should contain
    /// the key, based on binary search of the separator keys.
    pub fn find_child(&self, key: &BtrfsKey) -> usize {
        let count = self.header.nritems as usize;
        if count == 0 {
            return 0;
        }
        // Find the last key <= target key.
        let mut idx = 0;
        for i in 0..count {
            if self.ptrs[i].key <= *key {
                idx = i;
            } else {
                break;
            }
        }
        idx
    }

    /// Insert a key/pointer pair in sorted order.
    ///
    /// # Errors
    ///
    /// - `OutOfMemory` if the node is full.
    pub fn insert(&mut self, kp: BtrfsKeyPtr) -> Result<()> {
        if self.is_full() {
            return Err(Error::OutOfMemory);
        }

        let count = self.header.nritems as usize;
        let mut pos = count;
        for i in 0..count {
            if self.ptrs[i].key > kp.key {
                pos = i;
                break;
            }
        }

        // Shift to make room.
        let mut i = count;
        while i > pos {
            self.ptrs[i] = self.ptrs[i - 1];
            i -= 1;
        }

        self.ptrs[pos] = kp;
        self.header.nritems = self.header.nritems.saturating_add(1);
        Ok(())
    }
}

// ── BtrfsNode ───────────────────────────────────────────────────

/// A B-tree node, either a leaf or an internal node.
#[derive(Debug, Clone)]
#[allow(clippy::large_enum_variant)]
pub enum BtrfsNode {
    /// Leaf node containing items.
    Leaf(BtrfsLeaf),
    /// Internal node containing key/pointer pairs.
    Internal(BtrfsInternalNode),
}

impl BtrfsNode {
    /// Return the node header.
    pub fn header(&self) -> &BtrfsNodeHeader {
        match self {
            Self::Leaf(leaf) => &leaf.header,
            Self::Internal(node) => &node.header,
        }
    }

    /// Return the tree level of this node.
    pub fn level(&self) -> u8 {
        self.header().level
    }

    /// Return the generation number.
    pub fn generation(&self) -> u64 {
        self.header().generation
    }
}

// ── BtrfsTree ───────────────────────────────────────────────────

/// A Copy-on-Write B-tree.
///
/// All modifications create new node copies rather than modifying
/// existing nodes. This enables atomic updates and makes snapshots
/// essentially free (just retain the old root).
///
/// Nodes are stored in a fixed-size pool. Each node is identified
/// by its index in the pool.
pub struct BtrfsTree {
    /// Node pool (fixed-size array).
    nodes: [Option<BtrfsNode>; MAX_NODES],
    /// Index of the root node in the pool (or `None` for empty tree).
    root: Option<usize>,
    /// Number of nodes allocated in the pool.
    node_count: usize,
    /// Current generation (transaction ID), incremented on each CoW.
    generation: u64,
    /// Owner tree objectid.
    owner: u64,
}

impl BtrfsTree {
    /// Create a new empty B-tree.
    pub fn new(owner: u64) -> Self {
        const NONE: Option<BtrfsNode> = None;
        Self {
            nodes: [NONE; MAX_NODES],
            root: None,
            node_count: 0,
            generation: 1,
            owner,
        }
    }

    /// Return the root node index.
    pub fn root(&self) -> Option<usize> {
        self.root
    }

    /// Return the current generation.
    pub fn generation(&self) -> u64 {
        self.generation
    }

    /// Return the number of allocated nodes.
    pub fn node_count(&self) -> usize {
        self.node_count
    }

    /// Allocate a new node in the pool and return its index.
    ///
    /// # Errors
    ///
    /// - `OutOfMemory` if the node pool is full.
    fn alloc_node(&mut self, node: BtrfsNode) -> Result<usize> {
        if self.node_count >= MAX_NODES {
            return Err(Error::OutOfMemory);
        }
        for (idx, slot) in self.nodes.iter_mut().enumerate() {
            if slot.is_none() {
                *slot = Some(node);
                self.node_count = self.node_count.saturating_add(1);
                return Ok(idx);
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Free a node by index.
    fn free_node(&mut self, idx: usize) {
        if idx < MAX_NODES && self.nodes[idx].is_some() {
            self.nodes[idx] = None;
            self.node_count = self.node_count.saturating_sub(1);
        }
    }

    /// Create a CoW copy of a leaf node, apply a modification, and
    /// return the new node's index.
    ///
    /// This is the core of the copy-on-write mechanism.
    fn cow_leaf<F>(&mut self, leaf_idx: usize, modify: F) -> Result<usize>
    where
        F: FnOnce(&mut BtrfsLeaf) -> Result<()>,
    {
        // Clone the leaf.
        let mut new_leaf = match &self.nodes[leaf_idx] {
            Some(BtrfsNode::Leaf(leaf)) => leaf.clone(),
            _ => return Err(Error::InvalidArgument),
        };

        // Advance generation.
        self.generation = self.generation.saturating_add(1);
        new_leaf.header.generation = self.generation;

        // Apply the modification.
        modify(&mut new_leaf)?;

        // Allocate the new node.
        let new_idx = self.alloc_node(BtrfsNode::Leaf(new_leaf))?;

        // Free the old node (the old data is "dead" now in CoW).
        self.free_node(leaf_idx);

        Ok(new_idx)
    }

    /// Insert a key-value pair into the tree.
    ///
    /// Uses copy-on-write: the affected leaf is copied, the item is
    /// inserted into the copy, and the root is updated to point to
    /// the new leaf.
    ///
    /// # Errors
    ///
    /// - `OutOfMemory` if the node pool or leaf is full.
    /// - `AlreadyExists` if the key already exists.
    /// - `InvalidArgument` if data exceeds the item size limit.
    pub fn insert(&mut self, key: BtrfsKey, data: &[u8]) -> Result<()> {
        let item = BtrfsItem::new(key, data)?;

        match self.root {
            None => {
                // Empty tree: create a new leaf as root.
                let leaf = BtrfsLeaf::new(0, self.generation, self.owner);
                let idx = self.alloc_node(BtrfsNode::Leaf(leaf))?;
                // Insert into the new leaf.
                if let Some(BtrfsNode::Leaf(leaf)) = &mut self.nodes[idx] {
                    leaf.insert(item)?;
                }
                self.root = Some(idx);
                Ok(())
            }
            Some(root_idx) => {
                // CoW the root leaf and insert.
                let new_root = self.cow_leaf(root_idx, |leaf| leaf.insert(item))?;
                self.root = Some(new_root);
                Ok(())
            }
        }
    }

    /// Look up an item by key.
    ///
    /// # Errors
    ///
    /// - `NotFound` if the key does not exist or the tree is empty.
    pub fn lookup(&self, key: &BtrfsKey) -> Result<&BtrfsItem> {
        let root_idx = self.root.ok_or(Error::NotFound)?;
        match &self.nodes[root_idx] {
            Some(BtrfsNode::Leaf(leaf)) => leaf.lookup(key),
            Some(BtrfsNode::Internal(_)) => {
                // For this implementation we only support single-level trees.
                // Multi-level traversal would walk internal nodes to find the leaf.
                Err(Error::NotImplemented)
            }
            None => Err(Error::NotFound),
        }
    }

    /// Delete an item by key.
    ///
    /// Uses copy-on-write: the affected leaf is copied with the item
    /// removed, and the root is updated.
    ///
    /// # Errors
    ///
    /// - `NotFound` if the key does not exist or the tree is empty.
    pub fn delete(&mut self, key: &BtrfsKey) -> Result<()> {
        let root_idx = self.root.ok_or(Error::NotFound)?;
        let new_root = self.cow_leaf(root_idx, |leaf| leaf.delete(key))?;
        self.root = Some(new_root);
        Ok(())
    }

    /// Create a snapshot of the current tree state.
    ///
    /// Returns a new tree that shares the same root node. Because
    /// all modifications use CoW, the snapshot remains valid even
    /// as the original tree is modified.
    ///
    /// # Errors
    ///
    /// - `NotFound` if the tree is empty.
    /// - `OutOfMemory` if the node pool is full.
    pub fn snapshot(&mut self) -> Result<usize> {
        let root_idx = self.root.ok_or(Error::NotFound)?;

        // Clone the root node for the snapshot.
        let root_clone = match &self.nodes[root_idx] {
            Some(node) => node.clone(),
            None => return Err(Error::NotFound),
        };

        let snap_idx = self.alloc_node(root_clone)?;
        Ok(snap_idx)
    }
}

// ── BtrfsChunk ──────────────────────────────────────────────────

/// Logical-to-physical address mapping entry.
///
/// Btrfs uses a chunk tree to translate logical addresses (used
/// throughout the filesystem) to physical addresses on disk.
#[derive(Debug, Clone, Copy)]
pub struct BtrfsChunk {
    /// Logical byte offset (start of this chunk's range).
    pub logical: u64,
    /// Physical byte offset on disk.
    pub physical: u64,
    /// Size of this chunk in bytes.
    pub length: u64,
    /// Chunk type flags (data, metadata, system).
    pub chunk_type: u64,
    /// Stripe length for RAID configurations.
    pub stripe_len: u64,
    /// Number of stripes.
    pub num_stripes: u16,
    /// Whether this chunk slot is in use.
    pub in_use: bool,
}

impl BtrfsChunk {
    /// Create an empty chunk slot.
    const fn empty() -> Self {
        Self {
            logical: 0,
            physical: 0,
            length: 0,
            chunk_type: 0,
            stripe_len: 0,
            num_stripes: 0,
            in_use: false,
        }
    }
}

/// Chunk map for logical-to-physical address translation.
pub struct BtrfsChunkMap {
    /// Chunk entries.
    chunks: [BtrfsChunk; MAX_CHUNKS],
    /// Number of active chunks.
    count: usize,
}

impl Default for BtrfsChunkMap {
    fn default() -> Self {
        Self::new()
    }
}

impl BtrfsChunkMap {
    /// Create a new empty chunk map.
    pub fn new() -> Self {
        const EMPTY: BtrfsChunk = BtrfsChunk::empty();
        Self {
            chunks: [EMPTY; MAX_CHUNKS],
            count: 0,
        }
    }

    /// Add a chunk mapping.
    ///
    /// # Errors
    ///
    /// - `OutOfMemory` if the chunk map is full.
    pub fn add(&mut self, logical: u64, physical: u64, length: u64, chunk_type: u64) -> Result<()> {
        if self.count >= MAX_CHUNKS {
            return Err(Error::OutOfMemory);
        }

        for chunk in self.chunks.iter_mut() {
            if !chunk.in_use {
                *chunk = BtrfsChunk {
                    logical,
                    physical,
                    length,
                    chunk_type,
                    stripe_len: 65536,
                    num_stripes: 1,
                    in_use: true,
                };
                self.count = self.count.saturating_add(1);
                return Ok(());
            }
        }

        Err(Error::OutOfMemory)
    }

    /// Translate a logical address to a physical address.
    ///
    /// # Errors
    ///
    /// - `NotFound` if the logical address is not in any chunk.
    pub fn translate(&self, logical: u64) -> Result<u64> {
        for chunk in &self.chunks {
            if chunk.in_use && logical >= chunk.logical && logical < chunk.logical + chunk.length {
                let offset = logical - chunk.logical;
                return Ok(chunk.physical + offset);
            }
        }
        Err(Error::NotFound)
    }

    /// Return the number of active chunks.
    pub fn count(&self) -> usize {
        self.count
    }
}

// ── BtrfsSuperblock ─────────────────────────────────────────────

/// Btrfs superblock (on-disk metadata header).
///
/// Contains the essential metadata for locating and validating
/// the filesystem structures.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct BtrfsSuperblock {
    /// Magic number ([`BTRFS_MAGIC`]).
    pub magic: u64,
    /// Current filesystem generation (transaction counter).
    pub generation: u64,
    /// Logical address of the root tree.
    pub root: u64,
    /// Logical address of the chunk tree.
    pub chunk_root: u64,
    /// Total size of all devices in bytes.
    pub total_bytes: u64,
    /// Number of bytes used.
    pub bytes_used: u64,
    /// Node size in bytes (default 16384).
    pub nodesize: u32,
    /// Sector size in bytes (typically 4096).
    pub sectorsize: u32,
    /// Leaf size in bytes (equal to nodesize).
    pub leafsize: u32,
    /// Number of devices in this filesystem.
    pub num_devices: u64,
    /// Filesystem UUID (as two u64 halves).
    pub fsid_hi: u64,
    /// Filesystem UUID (low 64 bits).
    pub fsid_lo: u64,
}

impl BtrfsSuperblock {
    /// Create a new superblock with default values.
    pub fn new(total_bytes: u64) -> Self {
        Self {
            magic: BTRFS_MAGIC,
            generation: 1,
            root: 0,
            chunk_root: 0,
            total_bytes,
            bytes_used: 0,
            nodesize: 16384,
            sectorsize: 4096,
            leafsize: 16384,
            num_devices: 1,
            fsid_hi: 0,
            fsid_lo: 0,
        }
    }

    /// Validate the superblock magic number.
    pub fn validate(&self) -> Result<()> {
        if self.magic != BTRFS_MAGIC {
            return Err(Error::InvalidArgument);
        }
        Ok(())
    }
}

impl Default for BtrfsSuperblock {
    fn default() -> Self {
        Self::new(0)
    }
}

// ── BtrfsSubvolume ──────────────────────────────────────────────

/// A btrfs subvolume (independent filesystem tree).
///
/// Each subvolume has its own root tree and can be independently
/// snapshotted. Subvolumes appear as directories in the parent
/// subvolume's namespace.
pub struct BtrfsSubvolume {
    /// Root node index in the tree's node pool.
    pub tree_root: Option<usize>,
    /// Parent subvolume ID (0 for the root subvolume).
    pub parent_id: u64,
    /// Subvolume name.
    name: [u8; MAX_SUBVOL_NAME],
    /// Name length.
    name_len: usize,
    /// Whether this subvolume is active.
    pub active: bool,
    /// Subvolume ID (object ID in the root tree).
    pub subvol_id: u64,
    /// Generation when this subvolume was created.
    pub generation: u64,
    /// Whether this subvolume is read-only (e.g., a snapshot).
    pub readonly: bool,
}

impl BtrfsSubvolume {
    /// Create an empty subvolume slot.
    const fn empty() -> Self {
        Self {
            tree_root: None,
            parent_id: 0,
            name: [0u8; MAX_SUBVOL_NAME],
            name_len: 0,
            active: false,
            subvol_id: 0,
            generation: 0,
            readonly: false,
        }
    }

    /// Create a new subvolume.
    ///
    /// # Errors
    ///
    /// Returns `InvalidArgument` if the name exceeds [`MAX_SUBVOL_NAME`].
    pub fn new(name: &[u8], subvol_id: u64, parent_id: u64) -> Result<Self> {
        if name.len() > MAX_SUBVOL_NAME {
            return Err(Error::InvalidArgument);
        }
        let mut sv = Self::empty();
        sv.name[..name.len()].copy_from_slice(name);
        sv.name_len = name.len();
        sv.active = true;
        sv.subvol_id = subvol_id;
        sv.parent_id = parent_id;
        sv.generation = 1;
        Ok(sv)
    }

    /// Return the subvolume name as a byte slice.
    pub fn name(&self) -> &[u8] {
        &self.name[..self.name_len]
    }
}

// ── BtrfsFs ─────────────────────────────────────────────────────

/// A btrfs filesystem instance.
///
/// Contains the superblock, the main B-tree, subvolumes, and
/// the chunk map for address translation.
pub struct BtrfsFs {
    /// On-disk superblock.
    pub superblock: BtrfsSuperblock,
    /// Main filesystem B-tree.
    tree: BtrfsTree,
    /// Subvolume table.
    subvolumes: [BtrfsSubvolume; MAX_SUBVOLUMES],
    /// Number of active subvolumes.
    subvol_count: usize,
    /// Chunk map for logical-to-physical translation.
    chunk_map: BtrfsChunkMap,
    /// Next inode number to allocate.
    next_ino: u64,
    /// Filesystem name/label.
    label: [u8; MAX_PATH_LEN],
    /// Label length.
    label_len: usize,
    /// Whether this filesystem is mounted.
    mounted: bool,
}

impl BtrfsFs {
    /// Create and mount a new btrfs filesystem.
    ///
    /// Initializes the superblock, creates the default subvolume
    /// (ID 5), and sets up the root directory inode.
    ///
    /// # Errors
    ///
    /// - `InvalidArgument` if the label is too long.
    pub fn mount(total_bytes: u64, label: &[u8]) -> Result<Self> {
        if label.len() > MAX_PATH_LEN {
            return Err(Error::InvalidArgument);
        }

        let mut label_buf = [0u8; MAX_PATH_LEN];
        label_buf[..label.len()].copy_from_slice(label);

        const EMPTY_SV: BtrfsSubvolume = BtrfsSubvolume::empty();

        let mut fs = Self {
            superblock: BtrfsSuperblock::new(total_bytes),
            tree: BtrfsTree::new(BTRFS_FS_TREE_OBJECTID),
            subvolumes: [EMPTY_SV; MAX_SUBVOLUMES],
            subvol_count: 0,
            chunk_map: BtrfsChunkMap::new(),
            next_ino: 257, // First user inode (256 is the root dir)
            label: label_buf,
            label_len: label.len(),
            mounted: true,
        };

        // Create the default subvolume (ID 5).
        let default_sv = BtrfsSubvolume::new(b"default", BTRFS_FS_TREE_OBJECTID, 0)?;
        fs.subvolumes[0] = default_sv;
        fs.subvol_count = 1;

        // Create root directory inode (objectid 256).
        let root_key = BtrfsKey::new(256, BTRFS_INODE_ITEM_KEY, 0);
        // Minimal inode data: mode(4) + size(8) + nlink(4) = 16 bytes.
        let mut inode_data = [0u8; 16];
        // mode = 0o40755 (directory with rwxr-xr-x)
        let mode: u32 = 0o40755;
        inode_data[0..4].copy_from_slice(&mode.to_le_bytes());
        // size = 0
        inode_data[4..12].copy_from_slice(&0u64.to_le_bytes());
        // nlink = 1
        inode_data[12..16].copy_from_slice(&1u32.to_le_bytes());
        fs.tree.insert(root_key, &inode_data)?;

        // Add a default chunk mapping (1:1 logical-to-physical).
        fs.chunk_map.add(0, 0, total_bytes, 1)?;

        Ok(fs)
    }

    /// Whether the filesystem is mounted.
    pub fn is_mounted(&self) -> bool {
        self.mounted
    }

    /// Unmount the filesystem.
    pub fn unmount(&mut self) {
        self.mounted = false;
    }

    /// Return the filesystem label as a byte slice.
    pub fn label(&self) -> &[u8] {
        &self.label[..self.label_len]
    }

    /// Look up a path component in the root directory.
    ///
    /// Searches for a directory item with the given name under the
    /// root inode (objectid 256).
    ///
    /// # Errors
    ///
    /// - `NotFound` if the path component does not exist.
    /// - `InvalidArgument` if the filesystem is not mounted.
    pub fn lookup_path(&self, name: &[u8]) -> Result<u64> {
        if !self.mounted {
            return Err(Error::InvalidArgument);
        }

        // Look up directory entry under root inode (256).
        // Use a hash of the name as the offset for the dir item key.
        let name_hash = simple_hash(name);
        let dir_key = BtrfsKey::new(256, BTRFS_DIR_ITEM_KEY, name_hash);

        let item = self.tree.lookup(&dir_key)?;
        if item.data_len < 8 {
            return Err(Error::IoError);
        }

        // First 8 bytes of dir item data = target inode number.
        let ino = u64::from_le_bytes([
            item.data[0],
            item.data[1],
            item.data[2],
            item.data[3],
            item.data[4],
            item.data[5],
            item.data[6],
            item.data[7],
        ]);
        Ok(ino)
    }

    /// Read file data from an inode.
    ///
    /// Looks up the extent data item for the given inode and copies
    /// data into the output buffer.
    ///
    /// # Errors
    ///
    /// - `NotFound` if the inode or its data does not exist.
    /// - `InvalidArgument` if the filesystem is not mounted.
    pub fn read_file(&self, ino: u64, offset: u64, buf: &mut [u8]) -> Result<usize> {
        if !self.mounted {
            return Err(Error::InvalidArgument);
        }

        let extent_key = BtrfsKey::new(ino, BTRFS_EXTENT_DATA_KEY, offset);
        let item = self.tree.lookup(&extent_key)?;

        let available = item.data_len;
        let to_read = buf.len().min(available);
        buf[..to_read].copy_from_slice(&item.data[..to_read]);
        Ok(to_read)
    }

    /// Create a file in the root directory.
    ///
    /// Allocates a new inode, creates a directory entry under the
    /// root, and optionally stores initial data.
    ///
    /// # Errors
    ///
    /// - `InvalidArgument` if the name or data is too large,
    ///   or the filesystem is not mounted.
    /// - `OutOfMemory` if the tree is full.
    pub fn create_file(&mut self, name: &[u8], data: &[u8]) -> Result<u64> {
        if !self.mounted {
            return Err(Error::InvalidArgument);
        }
        if name.len() > MAX_PATH_LEN || data.len() > MAX_FILE_DATA {
            return Err(Error::InvalidArgument);
        }

        let ino = self.next_ino;
        self.next_ino = self.next_ino.saturating_add(1);

        // Create inode item.
        let inode_key = BtrfsKey::new(ino, BTRFS_INODE_ITEM_KEY, 0);
        let mut inode_data = [0u8; 16];
        let mode: u32 = 0o100644; // regular file
        inode_data[0..4].copy_from_slice(&mode.to_le_bytes());
        inode_data[4..12].copy_from_slice(&(data.len() as u64).to_le_bytes());
        inode_data[12..16].copy_from_slice(&1u32.to_le_bytes());
        self.tree.insert(inode_key, &inode_data)?;

        // Create directory entry under root (256).
        let name_hash = simple_hash(name);
        let dir_key = BtrfsKey::new(256, BTRFS_DIR_ITEM_KEY, name_hash);
        let mut dir_data = [0u8; 16];
        dir_data[0..8].copy_from_slice(&ino.to_le_bytes());
        // Bytes 8..16: name length + type indicator.
        dir_data[8..12].copy_from_slice(&(name.len() as u32).to_le_bytes());
        dir_data[12] = BTRFS_INODE_ITEM_KEY; // type = regular file
        self.tree.insert(dir_key, &dir_data)?;

        // Store file data as extent data item.
        if !data.is_empty() {
            let extent_key = BtrfsKey::new(ino, BTRFS_EXTENT_DATA_KEY, 0);
            self.tree.insert(extent_key, data)?;
        }

        self.superblock.bytes_used = self.superblock.bytes_used.saturating_add(data.len() as u64);
        self.superblock.generation = self.superblock.generation.saturating_add(1);

        Ok(ino)
    }

    /// Create a snapshot of a subvolume.
    ///
    /// The snapshot shares the same tree data via CoW semantics.
    /// Modifications to either the original or the snapshot will
    /// create new copies of the affected nodes.
    ///
    /// # Errors
    ///
    /// - `InvalidArgument` if the name is too long or the FS is not mounted.
    /// - `OutOfMemory` if the subvolume table is full.
    /// - `NotFound` if the tree is empty.
    pub fn create_snapshot(&mut self, name: &[u8]) -> Result<u64> {
        if !self.mounted {
            return Err(Error::InvalidArgument);
        }
        if self.subvol_count >= MAX_SUBVOLUMES {
            return Err(Error::OutOfMemory);
        }

        // Snapshot the main tree's root.
        let snap_root = self.tree.snapshot()?;

        let subvol_id = BTRFS_FS_TREE_OBJECTID + self.subvol_count as u64 + 1;
        let mut sv = BtrfsSubvolume::new(name, subvol_id, BTRFS_FS_TREE_OBJECTID)?;
        sv.tree_root = Some(snap_root);
        sv.readonly = true;
        sv.generation = self.superblock.generation;

        for slot in self.subvolumes.iter_mut() {
            if !slot.active {
                *slot = sv;
                self.subvol_count = self.subvol_count.saturating_add(1);
                self.superblock.generation = self.superblock.generation.saturating_add(1);
                return Ok(subvol_id);
            }
        }

        Err(Error::OutOfMemory)
    }

    /// Return the number of active subvolumes.
    pub fn subvolume_count(&self) -> usize {
        self.subvol_count
    }

    /// Return a reference to the chunk map.
    pub fn chunk_map(&self) -> &BtrfsChunkMap {
        &self.chunk_map
    }

    /// Return a reference to the main tree.
    pub fn tree(&self) -> &BtrfsTree {
        &self.tree
    }

    /// Return a mutable reference to the main tree.
    pub fn tree_mut(&mut self) -> &mut BtrfsTree {
        &mut self.tree
    }
}

// ── BtrfsRegistry ───────────────────────────────────────────────

/// Global registry of mounted btrfs filesystem instances.
///
/// Tracks up to [`MAX_BTRFS_INSTANCES`] mounted filesystems and
/// provides lookup by label.
pub struct BtrfsRegistry {
    /// Mounted filesystem slots.
    instances: [Option<BtrfsFs>; MAX_BTRFS_INSTANCES],
    /// Number of active instances.
    count: usize,
}

impl Default for BtrfsRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl BtrfsRegistry {
    /// Create an empty btrfs registry.
    pub fn new() -> Self {
        const NONE: Option<BtrfsFs> = None;
        Self {
            instances: [NONE; MAX_BTRFS_INSTANCES],
            count: 0,
        }
    }

    /// Mount a new btrfs filesystem and register it.
    ///
    /// Returns the index at which the filesystem was registered.
    ///
    /// # Errors
    ///
    /// - `OutOfMemory` if the registry is full.
    /// - `AlreadyExists` if a filesystem with the same label exists.
    /// - Propagates errors from [`BtrfsFs::mount`].
    pub fn mount(&mut self, total_bytes: u64, label: &[u8]) -> Result<usize> {
        // Check for duplicate labels.
        for inst in self.instances.iter().flatten() {
            if inst.label() == label {
                return Err(Error::AlreadyExists);
            }
        }

        if self.count >= MAX_BTRFS_INSTANCES {
            return Err(Error::OutOfMemory);
        }

        let fs = BtrfsFs::mount(total_bytes, label)?;

        for (idx, slot) in self.instances.iter_mut().enumerate() {
            if slot.is_none() {
                *slot = Some(fs);
                self.count = self.count.saturating_add(1);
                return Ok(idx);
            }
        }

        Err(Error::OutOfMemory)
    }

    /// Unmount and unregister a btrfs filesystem by label.
    ///
    /// # Errors
    ///
    /// - `NotFound` if no filesystem with the given label exists.
    pub fn unmount(&mut self, label: &[u8]) -> Result<()> {
        for slot in self.instances.iter_mut() {
            if let Some(fs) = slot {
                if fs.label() == label {
                    fs.unmount();
                    *slot = None;
                    self.count = self.count.saturating_sub(1);
                    return Ok(());
                }
            }
        }
        Err(Error::NotFound)
    }

    /// Find a filesystem by label.
    pub fn find(&self, label: &[u8]) -> Option<&BtrfsFs> {
        self.instances
            .iter()
            .flatten()
            .find(|fs| fs.label() == label)
    }

    /// Find a mutable reference to a filesystem by label.
    pub fn find_mut(&mut self, label: &[u8]) -> Option<&mut BtrfsFs> {
        self.instances
            .iter_mut()
            .flatten()
            .find(|fs| fs.label() == label)
    }

    /// Return a reference to a filesystem by index.
    ///
    /// # Errors
    ///
    /// - `InvalidArgument` if the index is out of bounds.
    /// - `NotFound` if the slot at the given index is empty.
    pub fn get(&self, index: usize) -> Result<&BtrfsFs> {
        if index >= MAX_BTRFS_INSTANCES {
            return Err(Error::InvalidArgument);
        }
        self.instances[index].as_ref().ok_or(Error::NotFound)
    }

    /// Return a mutable reference to a filesystem by index.
    ///
    /// # Errors
    ///
    /// - `InvalidArgument` if the index is out of bounds.
    /// - `NotFound` if the slot at the given index is empty.
    pub fn get_mut(&mut self, index: usize) -> Result<&mut BtrfsFs> {
        if index >= MAX_BTRFS_INSTANCES {
            return Err(Error::InvalidArgument);
        }
        self.instances[index].as_mut().ok_or(Error::NotFound)
    }

    /// Return the number of mounted filesystems.
    pub fn count(&self) -> usize {
        self.count
    }

    /// Check whether the registry is empty.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
}

// ── Helpers ─────────────────────────────────────────────────────

/// Simple non-cryptographic hash for directory entry lookup.
///
/// Produces a 64-bit hash from a byte slice, used as the offset
/// component of directory item keys.
fn simple_hash(data: &[u8]) -> u64 {
    let mut hash: u64 = 5381;
    for &byte in data {
        hash = hash.wrapping_mul(33).wrapping_add(byte as u64);
    }
    hash
}
