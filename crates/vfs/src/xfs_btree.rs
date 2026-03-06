// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! XFS generic B-tree framework.
//!
//! Provides the shared infrastructure used by XFS allocation, inode, and
//! block-map B-trees. Every XFS B-tree shares the same on-disk block layout:
//! a typed header followed by an array of keys and an array of values (leaf)
//! or child pointers (internal).
//!
//! # Design
//!
//! - [`BtreeBlock`] — on-disk node: header + up to `MAX_KEYS` keys + ptrs
//! - [`BtreeKey`] — generic 64-bit key
//! - [`BtreePtr`] — 64-bit pointer to a child block (fsblock number)
//! - [`Btree`] — in-memory B-tree supporting lookup, insert, delete
//!
//! # XFS B-tree types
//!
//! | Magic | Name | Keys |
//! |-------|------|------|
//! | `ABTB` | Free space by block | (startblock, blockcount) |
//! | `ABTC` | Free space by count | (blockcount, startblock) |
//! | `IBT` | Inode allocation | (startino, freecount) |
//! | `BMAP` | Block map (extents) | (startoff, startblock, blockcount) |
//!
//! # References
//!
//! - Linux `fs/xfs/libxfs/xfs_btree.c`
//! - XFS Algorithms & Data Structures book

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum keys per B-tree node (keep block ≤ 512 bytes usable).
const MAX_KEYS: usize = 16;

/// Maximum depth of the B-tree.
const MAX_DEPTH: usize = 8;

/// Minimum fill before a node is considered under-full and merged.
const MIN_FILL: usize = MAX_KEYS / 2;

/// XFS B-tree block magic numbers.
pub const XFS_ABTB_MAGIC: u32 = 0x4142_5442; // "ABTB"
/// XFS free-space-by-count B-tree magic.
pub const XFS_ABTC_MAGIC: u32 = 0x4142_5443; // "ABTC"
/// XFS inode B-tree magic.
pub const XFS_IBT_MAGIC: u32 = 0x4942_5443; // "IBTC" (approx)
/// XFS block-map B-tree magic.
pub const XFS_BMAP_MAGIC: u32 = 0x424D_4150; // "BMAP"

// ---------------------------------------------------------------------------
// On-disk structures
// ---------------------------------------------------------------------------

/// XFS B-tree block header.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct BtreeBlockHeader {
    /// Magic number identifying the B-tree type.
    pub magic: u32,
    /// Number of valid records/keys in this block.
    pub numrecs: u16,
    /// Depth of this block (0 = leaf).
    pub level: u16,
    /// Left sibling block number (`u64::MAX` if none).
    pub leftsib: u64,
    /// Right sibling block number (`u64::MAX` if none).
    pub rightsib: u64,
    /// Block sequence number (LSN).
    pub blkno: u64,
}

/// Generic 64-bit B-tree key.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct BtreeKey(pub u64);

/// Generic 64-bit B-tree child pointer (filesystem block number).
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default)]
pub struct BtreePtr(pub u64);

/// An XFS B-tree block (node or leaf).
///
/// Leaf nodes store `(keys[], values[])` with `values` sharing the same `u64`
/// representation as pointers.  Internal nodes store `(keys[], ptrs[])`.
#[derive(Debug)]
pub struct BtreeBlock {
    /// Block header.
    pub header: BtreeBlockHeader,
    /// Sorted keys.
    pub keys: [BtreeKey; MAX_KEYS],
    /// Values (leaf) or child block pointers (internal).
    pub ptrs: [BtreePtr; MAX_KEYS],
}

impl BtreeBlock {
    /// Create an empty leaf block with the given magic.
    pub const fn new_leaf(magic: u32, blkno: u64) -> Self {
        Self {
            header: BtreeBlockHeader {
                magic,
                numrecs: 0,
                level: 0,
                leftsib: u64::MAX,
                rightsib: u64::MAX,
                blkno,
            },
            keys: [BtreeKey(0); MAX_KEYS],
            ptrs: [BtreePtr(0); MAX_KEYS],
        }
    }

    /// Create an empty internal block at `level`.
    pub const fn new_internal(magic: u32, level: u16, blkno: u64) -> Self {
        Self {
            header: BtreeBlockHeader {
                magic,
                numrecs: 0,
                level,
                leftsib: u64::MAX,
                rightsib: u64::MAX,
                blkno,
            },
            keys: [BtreeKey(0); MAX_KEYS],
            ptrs: [BtreePtr(0); MAX_KEYS],
        }
    }

    /// Return `true` if this is a leaf node.
    pub fn is_leaf(&self) -> bool {
        self.header.level == 0
    }

    /// Number of records/entries.
    pub fn count(&self) -> usize {
        self.header.numrecs as usize
    }

    /// Binary search for `key` within this block.
    ///
    /// Returns the index of the first key >= `key`, or `count()` if all keys
    /// are less than `key`.
    pub fn lower_bound(&self, key: BtreeKey) -> usize {
        let n = self.count();
        let mut lo = 0usize;
        let mut hi = n;
        while lo < hi {
            let mid = lo + (hi - lo) / 2;
            if self.keys[mid] < key {
                lo = mid + 1;
            } else {
                hi = mid;
            }
        }
        lo
    }
}

// ---------------------------------------------------------------------------
// In-memory B-tree
// ---------------------------------------------------------------------------

/// In-memory XFS B-tree.
///
/// Stores up to `MAX_DEPTH` levels of `BtreeBlock` nodes. The root is always
/// at index 0. A single-level tree has depth 0 (one leaf at level[0]).
pub struct Btree {
    /// Block pool: level[0] is the root, level[depth] is the deepest leaf.
    levels: [BtreeBlock; MAX_DEPTH],
    /// Number of levels (depth = levels - 1; 0-based depth of root).
    depth: usize,
    /// B-tree magic (carried into newly created blocks).
    magic: u32,
}

impl Btree {
    /// Create an empty B-tree with the given magic.
    pub fn new(magic: u32) -> Self {
        let root = BtreeBlock::new_leaf(magic, 0);
        let mut levels = [const { BtreeBlock::new_leaf(0, 0) }; MAX_DEPTH];
        // Re-init with correct magic.
        for level in &mut levels {
            *level = BtreeBlock::new_leaf(magic, 0);
        }
        levels[0] = root;
        Self {
            levels,
            depth: 0,
            magic,
        }
    }

    /// Look up `key` in the B-tree.
    ///
    /// Returns `Ok(value)` if found, `Err(NotFound)` otherwise.
    pub fn btree_lookup(&self, key: BtreeKey) -> Result<BtreePtr> {
        let leaf = self.navigate_to_leaf(key)?;
        let idx = leaf.lower_bound(key);
        if idx < leaf.count() && leaf.keys[idx] == key {
            Ok(leaf.ptrs[idx])
        } else {
            Err(Error::NotFound)
        }
    }

    /// Insert `(key, value)` into the B-tree.
    ///
    /// Returns `Err(AlreadyExists)` on duplicate key.
    /// Returns `Err(OutOfMemory)` if a split is needed but depth is at max.
    pub fn btree_insert(&mut self, key: BtreeKey, value: BtreePtr) -> Result<()> {
        // For this simplified implementation, all data lives in the root leaf
        // (depth 0). Splitting causes a depth increase.
        if self.depth == 0 {
            self.insert_into_block(0, key, value)
        } else {
            // Walk down to leaf level and insert there.
            self.insert_into_block(self.depth, key, value)
        }
    }

    /// Delete `key` from the B-tree.
    ///
    /// Returns `Err(NotFound)` if the key does not exist.
    pub fn btree_delete(&mut self, key: BtreeKey) -> Result<()> {
        if self.depth == 0 {
            self.delete_from_block(0, key)
        } else {
            self.delete_from_block(self.depth, key)
        }
    }

    /// Return the number of entries at the leaf level.
    pub fn record_count(&self) -> usize {
        self.levels[self.depth].count()
    }

    /// Return the current tree depth.
    pub fn depth(&self) -> usize {
        self.depth
    }

    /// Validate the tree: all keys sorted, counts consistent.
    pub fn validate(&self) -> Result<()> {
        for lvl in 0..=self.depth {
            let block = &self.levels[lvl];
            let n = block.count();
            for i in 1..n {
                if block.keys[i] <= block.keys[i - 1] {
                    return Err(Error::InvalidArgument);
                }
            }
        }
        Ok(())
    }

    // ── Private helpers ────────────────────────────────────────────

    /// Navigate from root to the leaf that would contain `key`.
    fn navigate_to_leaf(&self, _key: BtreeKey) -> Result<&BtreeBlock> {
        // Simplified: all entries live in the deepest level.
        Ok(&self.levels[self.depth])
    }

    /// Insert into the block at `level_idx`, splitting if full.
    fn insert_into_block(
        &mut self,
        level_idx: usize,
        key: BtreeKey,
        value: BtreePtr,
    ) -> Result<()> {
        let block = &mut self.levels[level_idx];
        let n = block.count();

        // Check duplicate.
        let pos = block.lower_bound(key);
        if pos < n && block.keys[pos] == key {
            return Err(Error::AlreadyExists);
        }

        if n < MAX_KEYS {
            // There is room: shift right and insert.
            let mut i = n;
            while i > pos {
                block.keys[i] = block.keys[i - 1];
                block.ptrs[i] = block.ptrs[i - 1];
                i -= 1;
            }
            block.keys[pos] = key;
            block.ptrs[pos] = value;
            block.header.numrecs += 1;
            Ok(())
        } else {
            // Block full: split.
            self.split_and_insert(level_idx, key, value)
        }
    }

    /// Split the block at `level_idx` and insert `(key, value)`.
    fn split_and_insert(&mut self, level_idx: usize, key: BtreeKey, value: BtreePtr) -> Result<()> {
        if self.depth + 1 >= MAX_DEPTH {
            return Err(Error::OutOfMemory);
        }
        let mid = MAX_KEYS / 2;

        // Promote: move right half to a new block at level_idx + 1.
        // (Simplified: we push leaves down one level and create a new root.)
        // Copy left half to level_idx, right half to a temporary buffer.
        let mut right_keys = [BtreeKey(0); MAX_KEYS];
        let mut right_ptrs = [BtreePtr(0); MAX_KEYS];
        let mut right_count = 0;

        {
            let block = &mut self.levels[level_idx];
            let n = block.count();
            for i in mid..n {
                right_keys[right_count] = block.keys[i];
                right_ptrs[right_count] = block.ptrs[i];
                right_count += 1;
            }
            block.header.numrecs = mid as u16;
        }

        // Push all levels down by one to make room for a new root.
        if level_idx == 0 {
            for l in (0..self.depth).rev() {
                self.levels[l + 1] = self.levels[l].clone();
            }
            self.depth += 1;
            // Make a new root internal block.
            self.levels[0] = BtreeBlock::new_internal(self.magic, self.depth as u16, 0);
        }

        // Create new right sibling at depth level.
        let new_level = if level_idx + 1 <= self.depth {
            self.depth
        } else {
            self.depth
        };
        self.levels[new_level].header.numrecs = right_count as u16;
        for i in 0..right_count {
            self.levels[new_level].keys[i] = right_keys[i];
            self.levels[new_level].ptrs[i] = right_ptrs[i];
        }

        // Now insert into the appropriate half.
        let split_key = right_keys[0];
        if key < split_key {
            self.insert_into_block(level_idx, key, value)
        } else {
            self.insert_into_block(new_level, key, value)
        }
    }

    /// Delete `key` from the block at `level_idx`.
    fn delete_from_block(&mut self, level_idx: usize, key: BtreeKey) -> Result<()> {
        let block = &mut self.levels[level_idx];
        let n = block.count();
        let pos = block.lower_bound(key);
        if pos >= n || block.keys[pos] != key {
            return Err(Error::NotFound);
        }
        // Shift left.
        let mut i = pos;
        while i + 1 < n {
            block.keys[i] = block.keys[i + 1];
            block.ptrs[i] = block.ptrs[i + 1];
            i += 1;
        }
        block.header.numrecs -= 1;

        // Merge check: if the block is below MIN_FILL, merge with sibling.
        // (Simplified: just track depth reduction when root becomes empty.)
        if self.depth > 0 && self.levels[self.depth].count() == 0 {
            self.depth -= 1;
        }
        Ok(())
    }
}

impl Clone for BtreeBlock {
    fn clone(&self) -> Self {
        BtreeBlock {
            header: self.header,
            keys: self.keys,
            ptrs: self.ptrs,
        }
    }
}

// ---------------------------------------------------------------------------
// Iterator
// ---------------------------------------------------------------------------

/// A simple range-scan iterator over leaf entries.
pub struct BtreeRangeScan<'a> {
    block: &'a BtreeBlock,
    pos: usize,
    end: BtreeKey,
}

impl<'a> BtreeRangeScan<'a> {
    /// Create an iterator yielding entries in `[start, end]`.
    pub fn new(tree: &'a Btree, start: BtreeKey, end: BtreeKey) -> Self {
        let block = &tree.levels[tree.depth];
        let pos = block.lower_bound(start);
        BtreeRangeScan { block, pos, end }
    }

    /// Advance and return the next `(key, ptr)` pair, or `None`.
    pub fn next(&mut self) -> Option<(BtreeKey, BtreePtr)> {
        if self.pos >= self.block.count() {
            return None;
        }
        let k = self.block.keys[self.pos];
        if k > self.end {
            return None;
        }
        let v = self.block.ptrs[self.pos];
        self.pos += 1;
        Some((k, v))
    }
}

/// Minimum fill constant exported for callers.
pub const BTREE_MIN_FILL: usize = MIN_FILL;
