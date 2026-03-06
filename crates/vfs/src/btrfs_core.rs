// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Btrfs core data structures: copy-on-write B-trees, chunk allocation,
//! and extent management.
//!
//! This module provides the fundamental on-disk and in-memory data
//! structures for a btrfs-style filesystem. Unlike [`crate::btrfs`]
//! (which implements the full filesystem layer) and [`crate::btrfs_cow`]
//! (which implements the transactional CoW engine), this module focuses
//! on the core building blocks: the composite key, item types, chunk
//! map, extent items, and the B-tree search/iteration infrastructure.
//!
//! # Architecture
//!
//! ```text
//! BtrfsTree
//!   ├── BtrfsItem[0..N]   — key + inline data
//!   └── child pointers    — for internal nodes
//!
//! BtrfsChunkMap
//!   └── BtrfsChunk[0..MAX_CHUNKS]  — logical → physical mapping
//!
//! ExtentAllocator
//!   └── ExtentItem[0..MAX_EXTENTS] — physical extent tracking
//! ```
//!
//! # Key Design
//!
//! Every object in btrfs is addressed by a [`BtrfsKey`] triple:
//! `(objectid, item_type, offset)`. The key space is totally ordered
//! and all B-tree operations use this ordering.
//!
//! # References
//!
//! - Linux `fs/btrfs/ctree.h`, `fs/btrfs/volumes.c`
//! - Btrfs wiki: on-disk format specification

#![allow(dead_code)]

use oncrix_lib::{Error, Result};

// ── Constants ───────────────────────────────────────────────────

/// Maximum items per B-tree leaf node.
const MAX_LEAF_ITEMS: usize = 48;

/// Maximum key/child pairs per internal B-tree node.
const MAX_INTERNAL_KEYS: usize = 48;

/// Maximum nodes in a B-tree (fixed pool, no heap).
const MAX_TREE_NODES: usize = 256;

/// Maximum chunks in the chunk map.
const MAX_CHUNKS: usize = 128;

/// Maximum extents tracked by the allocator.
const MAX_EXTENTS: usize = 512;

/// Maximum inline data per item (bytes).
const MAX_ITEM_DATA: usize = 128;

/// Btrfs superblock magic: "_BHRfS_M" in little-endian.
pub const BTRFS_MAGIC: u64 = 0x4D5F_5348_5266_4842;

/// Sentinel index for null pointers.
const NULL_IDX: u32 = u32::MAX;

// ── Item Types ──────────────────────────────────────────────────

/// Btrfs item type discriminants.
///
/// Each item type has a unique u8 value stored in the key's
/// `item_type` field. This determines how the item's data payload
/// is interpreted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum BtrfsItemType {
    /// Inode item (type 1).
    InodeItem = 1,
    /// Inode reference (parent link) (type 12).
    InodeRef = 12,
    /// Directory item (type 84).
    DirItem = 84,
    /// Directory index entry (type 96).
    DirIndex = 96,
    /// Extent data (type 108).
    ExtentData = 108,
    /// Extent item in the extent tree (type 168).
    ExtentItem = 168,
    /// Block group item (type 192).
    BlockGroupItem = 192,
    /// Chunk item in the chunk tree (type 228).
    ChunkItem = 228,
    /// Device item (type 216).
    DevItem = 216,
    /// Root item (type 132).
    RootItem = 132,
}

impl BtrfsItemType {
    /// Parse from a raw u8 value.
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(Self::InodeItem),
            12 => Some(Self::InodeRef),
            84 => Some(Self::DirItem),
            96 => Some(Self::DirIndex),
            108 => Some(Self::ExtentData),
            168 => Some(Self::ExtentItem),
            192 => Some(Self::BlockGroupItem),
            228 => Some(Self::ChunkItem),
            216 => Some(Self::DevItem),
            132 => Some(Self::RootItem),
            _ => None,
        }
    }
}

// ── BtrfsKey ────────────────────────────────────────────────────

/// Btrfs composite search key: `(objectid, item_type, offset)`.
///
/// All B-tree lookups use this key for total ordering. The fields
/// are compared lexicographically: objectid first, then item_type,
/// then offset.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BtrfsKey {
    /// Object identifier (inode number, root id, device id, ...).
    pub objectid: u64,
    /// Item type discriminant (see [`BtrfsItemType`]).
    pub item_type: u8,
    /// Type-specific offset (byte position, name hash, ...).
    pub offset: u64,
}

impl BtrfsKey {
    /// Create a new key.
    pub const fn new(objectid: u64, item_type: u8, offset: u64) -> Self {
        Self {
            objectid,
            item_type,
            offset,
        }
    }

    /// The minimum representable key.
    pub const fn min() -> Self {
        Self {
            objectid: 0,
            item_type: 0,
            offset: 0,
        }
    }

    /// The maximum representable key.
    pub const fn max() -> Self {
        Self {
            objectid: u64::MAX,
            item_type: u8::MAX,
            offset: u64::MAX,
        }
    }

    /// Parse a key from a 17-byte little-endian buffer.
    pub fn from_bytes(buf: &[u8]) -> Result<Self> {
        if buf.len() < 17 {
            return Err(Error::InvalidArgument);
        }
        Ok(Self {
            objectid: u64::from_le_bytes([
                buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7],
            ]),
            item_type: buf[8],
            offset: u64::from_le_bytes([
                buf[9], buf[10], buf[11], buf[12], buf[13], buf[14], buf[15], buf[16],
            ]),
        })
    }

    /// Serialize the key to a 17-byte little-endian buffer.
    pub fn to_bytes(&self, buf: &mut [u8]) -> Result<()> {
        if buf.len() < 17 {
            return Err(Error::InvalidArgument);
        }
        buf[0..8].copy_from_slice(&self.objectid.to_le_bytes());
        buf[8] = self.item_type;
        buf[9..17].copy_from_slice(&self.offset.to_le_bytes());
        Ok(())
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
            .then(self.item_type.cmp(&other.item_type))
            .then(self.offset.cmp(&other.offset))
    }
}

// ── BtrfsItem ───────────────────────────────────────────────────

/// A key-value item stored in a B-tree leaf node.
///
/// Each item carries up to [`MAX_ITEM_DATA`] bytes of inline data.
/// For larger payloads the data field holds a reference (byte
/// offset + length) to an out-of-line extent.
#[derive(Debug, Clone, Copy)]
pub struct BtrfsItem {
    /// Lookup key.
    pub key: BtrfsKey,
    /// Inline data payload.
    pub data: [u8; MAX_ITEM_DATA],
    /// Number of valid bytes in `data`.
    pub data_len: usize,
    /// Whether this slot is occupied.
    pub in_use: bool,
}

impl BtrfsItem {
    /// Create an empty (unused) item slot.
    const fn empty() -> Self {
        Self {
            key: BtrfsKey::min(),
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

    /// Return a slice of the valid inline data.
    pub fn data(&self) -> &[u8] {
        &self.data[..self.data_len]
    }
}

impl Default for BtrfsItem {
    fn default() -> Self {
        Self::empty()
    }
}

// ── LeafNode ────────────────────────────────────────────────────

/// A B-tree leaf node (level 0) holding sorted [`BtrfsItem`]s.
///
/// Items are maintained in ascending key order. Insertions preserve
/// the sorted invariant via binary search.
#[derive(Debug, Clone)]
pub struct LeafNode {
    /// Transaction generation that last wrote this node.
    pub generation: u64,
    /// Logical byte address on disk.
    pub bytenr: u64,
    /// Sorted item slots.
    pub items: [BtrfsItem; MAX_LEAF_ITEMS],
    /// Number of live items.
    pub nritems: usize,
}

impl LeafNode {
    /// Create an empty leaf node.
    pub fn new(generation: u64, bytenr: u64) -> Self {
        const EMPTY: BtrfsItem = BtrfsItem::empty();
        Self {
            generation,
            bytenr,
            items: [EMPTY; MAX_LEAF_ITEMS],
            nritems: 0,
        }
    }

    /// Binary search for a key.
    ///
    /// Returns `Ok(idx)` for an exact match, `Err(idx)` for the
    /// insertion point.
    pub fn search(&self, key: &BtrfsKey) -> core::result::Result<usize, usize> {
        self.items[..self.nritems].binary_search_by(|item| item.key.cmp(key))
    }

    /// Insert an item in sorted order.
    ///
    /// # Errors
    ///
    /// - `AlreadyExists` if the key is already present.
    /// - `OutOfMemory` if the leaf is full.
    pub fn insert(&mut self, item: BtrfsItem) -> Result<()> {
        match self.search(&item.key) {
            Ok(_) => Err(Error::AlreadyExists),
            Err(pos) => {
                if self.nritems >= MAX_LEAF_ITEMS {
                    return Err(Error::OutOfMemory);
                }
                self.items.copy_within(pos..self.nritems, pos + 1);
                self.items[pos] = item;
                self.nritems += 1;
                Ok(())
            }
        }
    }

    /// Delete an item by key.
    ///
    /// # Errors
    ///
    /// - `NotFound` if the key does not exist.
    pub fn delete(&mut self, key: &BtrfsKey) -> Result<()> {
        match self.search(key) {
            Err(_) => Err(Error::NotFound),
            Ok(pos) => {
                self.items.copy_within(pos + 1..self.nritems, pos);
                self.items[self.nritems - 1] = BtrfsItem::empty();
                self.nritems -= 1;
                Ok(())
            }
        }
    }

    /// Lookup an item by key.
    pub fn lookup(&self, key: &BtrfsKey) -> Result<&BtrfsItem> {
        match self.search(key) {
            Ok(pos) => Ok(&self.items[pos]),
            Err(_) => Err(Error::NotFound),
        }
    }

    /// Whether the leaf is full.
    pub fn is_full(&self) -> bool {
        self.nritems >= MAX_LEAF_ITEMS
    }

    /// Smallest key in this leaf.
    pub fn min_key(&self) -> Option<BtrfsKey> {
        if self.nritems > 0 {
            Some(self.items[0].key)
        } else {
            None
        }
    }

    /// Largest key in this leaf.
    pub fn max_key(&self) -> Option<BtrfsKey> {
        if self.nritems > 0 {
            Some(self.items[self.nritems - 1].key)
        } else {
            None
        }
    }
}

// ── InternalNode ────────────────────────────────────────────────

/// A key/child pointer pair in an internal B-tree node.
#[derive(Debug, Clone, Copy)]
pub struct KeyPtr {
    /// Smallest key reachable through `child_idx`.
    pub key: BtrfsKey,
    /// Pool index of the child node.
    pub child_idx: u32,
}

impl KeyPtr {
    const fn null() -> Self {
        Self {
            key: BtrfsKey::min(),
            child_idx: NULL_IDX,
        }
    }
}

impl Default for KeyPtr {
    fn default() -> Self {
        Self::null()
    }
}

/// A B-tree internal node (level >= 1).
///
/// Contains up to [`MAX_INTERNAL_KEYS`] key/child pointer pairs in
/// sorted order by key.
#[derive(Debug, Clone)]
pub struct InternalNode {
    /// Transaction generation.
    pub generation: u64,
    /// Logical byte address.
    pub bytenr: u64,
    /// Tree level (always >= 1).
    pub level: u8,
    /// Key/child pointer pairs.
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

    /// Find the child index for the given key.
    ///
    /// Returns the slot whose key is the greatest key <= `key`.
    pub fn find_child(&self, key: &BtrfsKey) -> usize {
        if self.nritems == 0 {
            return 0;
        }
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
        lo.saturating_sub(1)
    }

    /// Insert a key/child pointer in sorted order.
    pub fn insert(&mut self, key: BtrfsKey, child_idx: u32) -> Result<()> {
        if self.nritems >= MAX_INTERNAL_KEYS {
            return Err(Error::OutOfMemory);
        }
        let mut pos = self.nritems;
        for (i, ptr) in self.ptrs[..self.nritems].iter().enumerate() {
            if ptr.key > key {
                pos = i;
                break;
            }
        }
        self.ptrs.copy_within(pos..self.nritems, pos + 1);
        self.ptrs[pos] = KeyPtr { key, child_idx };
        self.nritems += 1;
        Ok(())
    }

    /// Whether the internal node is full.
    pub fn is_full(&self) -> bool {
        self.nritems >= MAX_INTERNAL_KEYS
    }
}

// ── BtrfsTree ───────────────────────────────────────────────────

/// Tag discriminating leaf vs internal pool entries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeKind {
    /// Level-0 node holding items.
    Leaf,
    /// Level >= 1 node holding key/child pairs.
    Internal,
}

/// Pool slot holding either a leaf or internal node.
pub struct TreeNode {
    /// Whether this slot is occupied.
    pub in_use: bool,
    /// Node kind.
    pub kind: NodeKind,
    /// Leaf payload.
    pub leaf: LeafNode,
    /// Internal payload.
    pub internal: InternalNode,
}

impl TreeNode {
    fn empty() -> Self {
        Self {
            in_use: false,
            kind: NodeKind::Leaf,
            leaf: LeafNode::new(0, 0),
            internal: InternalNode::new(0, 0, 1),
        }
    }

    fn from_leaf(leaf: LeafNode) -> Self {
        Self {
            in_use: true,
            kind: NodeKind::Leaf,
            leaf,
            internal: InternalNode::new(0, 0, 1),
        }
    }
}

/// Fixed-size B-tree with insert, lookup, and delete.
///
/// Manages a pool of [`TreeNode`] slots and a root pointer. All
/// operations are single-level (root is always a leaf) in this
/// implementation.
pub struct BtrfsTree {
    /// Node pool.
    nodes: [Option<TreeNode>; MAX_TREE_NODES],
    /// Pool index of the root node.
    root_idx: u32,
    /// Current generation counter.
    generation: u64,
    /// Number of live nodes.
    live_count: usize,
    /// Next byte address for new nodes.
    next_bytenr: u64,
}

impl BtrfsTree {
    /// Create a new empty B-tree.
    pub fn new() -> Result<Self> {
        const NONE: Option<TreeNode> = None;
        let mut tree = Self {
            nodes: [NONE; MAX_TREE_NODES],
            root_idx: 0,
            generation: 1,
            live_count: 0,
            next_bytenr: 4096,
        };
        let leaf = LeafNode::new(1, 0);
        tree.nodes[0] = Some(TreeNode::from_leaf(leaf));
        tree.live_count = 1;
        Ok(tree)
    }

    /// Current generation number.
    pub fn generation(&self) -> u64 {
        self.generation
    }

    /// Number of live nodes in the pool.
    pub fn live_count(&self) -> usize {
        self.live_count
    }

    /// Insert a key/value pair into the tree.
    pub fn insert(&mut self, key: BtrfsKey, data: &[u8]) -> Result<()> {
        let item = BtrfsItem::new(key, data)?;
        let root = self.root_mut()?;
        root.leaf.insert(item)
    }

    /// Lookup an item by key.
    pub fn lookup(&self, key: &BtrfsKey) -> Result<&BtrfsItem> {
        let root = self.root_ref()?;
        root.leaf.lookup(key)
    }

    /// Delete an item by key.
    pub fn delete(&mut self, key: &BtrfsKey) -> Result<()> {
        let root = self.root_mut()?;
        root.leaf.delete(key)
    }

    /// Return the number of items in the root leaf.
    pub fn item_count(&self) -> usize {
        match &self.nodes[self.root_idx as usize] {
            Some(node) if node.in_use => node.leaf.nritems,
            _ => 0,
        }
    }

    /// Advance the generation counter.
    pub fn next_generation(&mut self) -> u64 {
        self.generation = self.generation.wrapping_add(1);
        self.generation
    }

    fn root_ref(&self) -> Result<&TreeNode> {
        let idx = self.root_idx as usize;
        match &self.nodes[idx] {
            Some(node) if node.in_use => Ok(node),
            _ => Err(Error::IoError),
        }
    }

    fn root_mut(&mut self) -> Result<&mut TreeNode> {
        let idx = self.root_idx as usize;
        match &mut self.nodes[idx] {
            Some(node) if node.in_use => Ok(node),
            _ => Err(Error::IoError),
        }
    }
}

impl Default for BtrfsTree {
    fn default() -> Self {
        Self::new().unwrap_or_else(|_| {
            const NONE: Option<TreeNode> = None;
            Self {
                nodes: [NONE; MAX_TREE_NODES],
                root_idx: 0,
                generation: 0,
                live_count: 0,
                next_bytenr: 0,
            }
        })
    }
}

// ── BtrfsChunk ──────────────────────────────────────────────────

/// Chunk profile (data redundancy type).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ChunkProfile {
    /// Single copy (no redundancy).
    Single = 0,
    /// Two copies on different devices (RAID1).
    Raid1 = 1,
    /// Striped across devices (RAID0).
    Raid0 = 2,
    /// Striped + parity (RAID5).
    Raid5 = 5,
    /// Striped + double parity (RAID6).
    Raid6 = 6,
    /// Three copies (RAID1C3).
    Raid1c3 = 7,
}

impl ChunkProfile {
    /// Parse from a raw u8 value.
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::Single),
            1 => Some(Self::Raid1),
            2 => Some(Self::Raid0),
            5 => Some(Self::Raid5),
            6 => Some(Self::Raid6),
            7 => Some(Self::Raid1c3),
            _ => None,
        }
    }

    /// Number of data copies for this profile.
    pub fn copies(&self) -> u8 {
        match self {
            Self::Single | Self::Raid0 => 1,
            Self::Raid1 => 2,
            Self::Raid1c3 => 3,
            Self::Raid5 | Self::Raid6 => 1,
        }
    }
}

/// A chunk mapping logical address space to physical address space.
///
/// Each chunk covers a contiguous range of logical bytes and maps
/// them to one or more physical locations depending on the profile.
#[derive(Debug, Clone, Copy)]
pub struct BtrfsChunk {
    /// Logical byte offset (key offset in the chunk tree).
    pub logical: u64,
    /// Size of this chunk in bytes.
    pub size: u64,
    /// Physical byte offset on the target device.
    pub physical: u64,
    /// Device ID hosting this chunk.
    pub dev_id: u64,
    /// Redundancy profile.
    pub profile: ChunkProfile,
    /// Whether this chunk slot is active.
    pub active: bool,
}

impl BtrfsChunk {
    /// Create an empty (inactive) chunk slot.
    pub const fn empty() -> Self {
        Self {
            logical: 0,
            size: 0,
            physical: 0,
            dev_id: 0,
            profile: ChunkProfile::Single,
            active: false,
        }
    }

    /// Create a new chunk mapping.
    pub fn new(logical: u64, size: u64, physical: u64, dev_id: u64, profile: ChunkProfile) -> Self {
        Self {
            logical,
            size,
            physical,
            dev_id,
            profile,
            active: true,
        }
    }

    /// Whether the given logical byte offset falls within this chunk.
    pub fn contains(&self, logical_offset: u64) -> bool {
        self.active
            && logical_offset >= self.logical
            && logical_offset < self.logical.saturating_add(self.size)
    }

    /// Translate a logical offset to a physical offset.
    ///
    /// Returns `None` if the offset is not within this chunk.
    pub fn translate(&self, logical_offset: u64) -> Option<u64> {
        if self.contains(logical_offset) {
            Some(self.physical + (logical_offset - self.logical))
        } else {
            None
        }
    }
}

// ── BtrfsChunkMap ───────────────────────────────────────────────

/// Chunk allocation map translating logical to physical addresses.
///
/// Holds up to [`MAX_CHUNKS`] chunk entries. Chunks are allocated
/// sequentially and can be freed individually.
pub struct BtrfsChunkMap {
    /// Chunk entries.
    chunks: [BtrfsChunk; MAX_CHUNKS],
    /// Number of active chunks.
    count: usize,
    /// Next logical address for allocation.
    next_logical: u64,
}

impl BtrfsChunkMap {
    /// Create an empty chunk map.
    pub fn new() -> Self {
        Self {
            chunks: [const { BtrfsChunk::empty() }; MAX_CHUNKS],
            count: 0,
            next_logical: 0,
        }
    }

    /// Allocate a new chunk.
    ///
    /// Returns the index of the allocated chunk.
    pub fn allocate(
        &mut self,
        size: u64,
        physical: u64,
        dev_id: u64,
        profile: ChunkProfile,
    ) -> Result<usize> {
        if self.count >= MAX_CHUNKS {
            return Err(Error::OutOfMemory);
        }
        for (i, slot) in self.chunks.iter_mut().enumerate() {
            if !slot.active {
                let logical = self.next_logical;
                *slot = BtrfsChunk::new(logical, size, physical, dev_id, profile);
                self.next_logical = self.next_logical.saturating_add(size);
                self.count += 1;
                return Ok(i);
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Free a chunk by index.
    pub fn free(&mut self, index: usize) -> Result<()> {
        if index >= MAX_CHUNKS {
            return Err(Error::InvalidArgument);
        }
        if !self.chunks[index].active {
            return Err(Error::NotFound);
        }
        self.chunks[index] = BtrfsChunk::empty();
        self.count = self.count.saturating_sub(1);
        Ok(())
    }

    /// Translate a logical offset to a physical offset.
    pub fn translate(&self, logical: u64) -> Result<u64> {
        for chunk in &self.chunks {
            if let Some(phys) = chunk.translate(logical) {
                return Ok(phys);
            }
        }
        Err(Error::NotFound)
    }

    /// Return the chunk at the given index.
    pub fn get(&self, index: usize) -> Result<&BtrfsChunk> {
        if index >= MAX_CHUNKS {
            return Err(Error::InvalidArgument);
        }
        if !self.chunks[index].active {
            return Err(Error::NotFound);
        }
        Ok(&self.chunks[index])
    }

    /// Number of active chunks.
    pub fn count(&self) -> usize {
        self.count
    }

    /// Total logical space covered by all active chunks.
    pub fn total_logical_bytes(&self) -> u64 {
        self.chunks
            .iter()
            .filter(|c| c.active)
            .map(|c| c.size)
            .sum()
    }
}

impl Default for BtrfsChunkMap {
    fn default() -> Self {
        Self::new()
    }
}

// ── ExtentItem ──────────────────────────────────────────────────

/// Extent reference type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExtentRefType {
    /// Tree block reference (for metadata extents).
    TreeBlock,
    /// Shared data reference (for data extents).
    SharedData,
    /// Extent data reference (normal data back-reference).
    ExtentData,
}

/// A physical extent tracked by the extent allocator.
///
/// Each extent represents a contiguous range of physical blocks and
/// tracks its reference count for CoW sharing.
#[derive(Debug, Clone, Copy)]
pub struct ExtentItem {
    /// Physical byte offset.
    pub bytenr: u64,
    /// Length in bytes.
    pub length: u64,
    /// Reference count (number of trees pointing to this extent).
    pub refs: u32,
    /// Generation when this extent was allocated.
    pub generation: u64,
    /// Reference type.
    pub ref_type: ExtentRefType,
    /// Whether this slot is active.
    pub active: bool,
}

impl ExtentItem {
    /// Create an empty (inactive) extent slot.
    pub const fn empty() -> Self {
        Self {
            bytenr: 0,
            length: 0,
            refs: 0,
            generation: 0,
            ref_type: ExtentRefType::ExtentData,
            active: false,
        }
    }

    /// Create a new extent item.
    pub fn new(bytenr: u64, length: u64, generation: u64, ref_type: ExtentRefType) -> Self {
        Self {
            bytenr,
            length,
            refs: 1,
            generation,
            ref_type,
            active: true,
        }
    }

    /// Whether this extent contains the given byte offset.
    pub fn contains(&self, offset: u64) -> bool {
        self.active && offset >= self.bytenr && offset < self.bytenr.saturating_add(self.length)
    }

    /// Increment the reference count.
    pub fn add_ref(&mut self) {
        self.refs = self.refs.saturating_add(1);
    }

    /// Decrement the reference count; returns `true` if it reached zero.
    pub fn drop_ref(&mut self) -> bool {
        self.refs = self.refs.saturating_sub(1);
        self.refs == 0
    }
}

// ── ExtentAllocator ─────────────────────────────────────────────

/// Extent allocator tracking physical extent allocation and refcounts.
///
/// Holds up to [`MAX_EXTENTS`] extent items. Provides allocation,
/// reference counting, and free-space lookup.
pub struct ExtentAllocator {
    /// Extent items.
    extents: [ExtentItem; MAX_EXTENTS],
    /// Number of active extents.
    count: usize,
    /// Next physical byte offset for allocation.
    next_bytenr: u64,
    /// Total bytes allocated.
    allocated_bytes: u64,
}

impl ExtentAllocator {
    /// Create a new empty allocator.
    pub fn new() -> Self {
        Self {
            extents: [const { ExtentItem::empty() }; MAX_EXTENTS],
            count: 0,
            next_bytenr: 0,
            allocated_bytes: 0,
        }
    }

    /// Allocate a new extent of the given length.
    ///
    /// Returns the index of the allocated extent.
    pub fn allocate(
        &mut self,
        length: u64,
        generation: u64,
        ref_type: ExtentRefType,
    ) -> Result<usize> {
        if self.count >= MAX_EXTENTS {
            return Err(Error::OutOfMemory);
        }
        for (i, slot) in self.extents.iter_mut().enumerate() {
            if !slot.active {
                let bytenr = self.next_bytenr;
                *slot = ExtentItem::new(bytenr, length, generation, ref_type);
                self.next_bytenr = self.next_bytenr.saturating_add(length);
                self.allocated_bytes = self.allocated_bytes.saturating_add(length);
                self.count += 1;
                return Ok(i);
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Free an extent by index, decrementing its refcount.
    ///
    /// The extent is only reclaimed when its refcount reaches zero.
    pub fn release(&mut self, index: usize) -> Result<()> {
        if index >= MAX_EXTENTS {
            return Err(Error::InvalidArgument);
        }
        if !self.extents[index].active {
            return Err(Error::NotFound);
        }
        if self.extents[index].drop_ref() {
            self.allocated_bytes = self
                .allocated_bytes
                .saturating_sub(self.extents[index].length);
            self.extents[index] = ExtentItem::empty();
            self.count = self.count.saturating_sub(1);
        }
        Ok(())
    }

    /// Add a reference to an existing extent.
    pub fn add_ref(&mut self, index: usize) -> Result<()> {
        if index >= MAX_EXTENTS {
            return Err(Error::InvalidArgument);
        }
        if !self.extents[index].active {
            return Err(Error::NotFound);
        }
        self.extents[index].add_ref();
        Ok(())
    }

    /// Look up an extent by its physical byte offset.
    pub fn find_by_bytenr(&self, bytenr: u64) -> Option<usize> {
        self.extents
            .iter()
            .position(|e| e.active && e.bytenr == bytenr)
    }

    /// Return the extent at the given index.
    pub fn get(&self, index: usize) -> Result<&ExtentItem> {
        if index >= MAX_EXTENTS || !self.extents[index].active {
            return Err(Error::NotFound);
        }
        Ok(&self.extents[index])
    }

    /// Number of active extents.
    pub fn count(&self) -> usize {
        self.count
    }

    /// Total bytes currently allocated.
    pub fn allocated_bytes(&self) -> u64 {
        self.allocated_bytes
    }
}

impl Default for ExtentAllocator {
    fn default() -> Self {
        Self::new()
    }
}
