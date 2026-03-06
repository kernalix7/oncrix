// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! ext4 extent tree implementation.
//!
//! Implements the extent tree used by ext4 to map logical file blocks to
//! physical disk blocks. The tree is stored inline in the inode's `i_block`
//! field (60 bytes) and can fan out to external extent index blocks.
//!
//! # Structure
//!
//! - [`ExtentHeader`] — identifies a node as leaf or internal, tracks entry count
//! - [`ExtentIndex`] — internal node entry: logical block → child block pointer
//! - [`Extent`] — leaf node entry: logical block → physical block run
//! - [`ExtentTree`] — tree state and operations (lookup, insert, remove)
//!
//! # References
//!
//! - Linux `fs/ext4/extents.c` and `include/linux/ext4.h`
//! - ext4 wiki: <https://ext4.wiki.kernel.org/index.php/Ext4_Disk_Layout#Extent_Tree>

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Magic number embedded in every [`ExtentHeader`].
const EXT4_EXT_MAGIC: u16 = 0xF30A;

/// Maximum depth of the extent tree (from Linux `EXT_MAX_LEVELS`).
const EXT_MAX_LEVELS: u16 = 5;

/// Maximum number of extents in an inline (inode-embedded) leaf node.
/// The inode's `i_block` is 60 bytes; header is 12 bytes → 48 bytes left
/// → 4 × 12-byte extents.
const EXT_INLINE_MAX_EXTENTS: usize = 4;

/// Maximum number of index entries per inline internal node.
const EXT_INLINE_MAX_INDEXES: usize = 4;

/// Maximum extents held in our in-memory tree representation.
const MAX_EXTENTS: usize = 64;

/// Sentinel: EOF cluster marker for an extent.
const EXT4_EXT_UNWRITTEN_MASK: u32 = 1 << 15;

// ---------------------------------------------------------------------------
// On-disk structures (repr(C) for binary compatibility)
// ---------------------------------------------------------------------------

/// ext4 extent tree node header.
///
/// Placed at the start of every internal and leaf extent block.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct ExtentHeader {
    /// Magic number (`EXT4_EXT_MAGIC = 0xF30A`).
    pub eh_magic: u16,
    /// Number of valid entries following the header.
    pub eh_entries: u16,
    /// Maximum number of entries that could follow the header.
    pub eh_max: u16,
    /// Depth of this tree node (0 = leaf).
    pub eh_depth: u16,
    /// Generation: incremented on every tree modification.
    pub eh_generation: u32,
}

impl ExtentHeader {
    /// Create a new header for a leaf node.
    pub const fn new_leaf(max: u16, generation: u32) -> Self {
        Self {
            eh_magic: EXT4_EXT_MAGIC,
            eh_entries: 0,
            eh_max: max,
            eh_depth: 0,
            eh_generation: generation,
        }
    }

    /// Create a new header for an internal node at the given depth.
    pub const fn new_internal(max: u16, depth: u16, generation: u32) -> Self {
        Self {
            eh_magic: EXT4_EXT_MAGIC,
            eh_entries: 0,
            eh_max: max,
            eh_depth: depth,
            eh_generation: generation,
        }
    }

    /// Return `true` if the magic field is valid.
    pub fn is_valid(&self) -> bool {
        self.eh_magic == EXT4_EXT_MAGIC
    }

    /// Return `true` if this is a leaf node.
    pub fn is_leaf(&self) -> bool {
        self.eh_depth == 0
    }
}

/// ext4 extent index entry (internal tree node).
///
/// Maps the first logical block in its subtree to the physical block that
/// holds the child extent node.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct ExtentIndex {
    /// First logical block covered by this index entry.
    pub ei_block: u32,
    /// Low 32 bits of the physical leaf block pointer.
    pub ei_leaf_lo: u32,
    /// High 16 bits of the physical leaf block pointer.
    pub ei_leaf_hi: u16,
    /// Reserved.
    pub ei_unused: u16,
}

impl ExtentIndex {
    /// Reconstruct the 48-bit physical leaf block number.
    pub fn leaf_block(&self) -> u64 {
        ((self.ei_leaf_hi as u64) << 32) | (self.ei_leaf_lo as u64)
    }
}

/// ext4 leaf extent entry.
///
/// Maps a contiguous run of logical blocks to a contiguous run of physical
/// blocks.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct Extent {
    /// First logical block number in this extent.
    pub ee_block: u32,
    /// Length in blocks (high bit = unwritten flag).
    pub ee_len: u16,
    /// High 16 bits of the starting physical block.
    pub ee_start_hi: u16,
    /// Low 32 bits of the starting physical block.
    pub ee_start_lo: u32,
}

impl Extent {
    /// Return the 48-bit physical starting block.
    pub fn start_block(&self) -> u64 {
        ((self.ee_start_hi as u64) << 32) | (self.ee_start_lo as u64)
    }

    /// Return the actual length in blocks (mask off unwritten bit).
    pub fn length(&self) -> u16 {
        self.ee_len & !(EXT4_EXT_UNWRITTEN_MASK as u16)
    }

    /// Return `true` if this extent is unwritten (pre-allocated).
    pub fn is_unwritten(&self) -> bool {
        self.ee_len & (EXT4_EXT_UNWRITTEN_MASK as u16) != 0
    }

    /// Return `true` if `logical` falls within this extent.
    pub fn contains(&self, logical: u32) -> bool {
        logical >= self.ee_block && logical < self.ee_block + self.length() as u32
    }
}

// ---------------------------------------------------------------------------
// In-memory extent tree
// ---------------------------------------------------------------------------

/// In-memory extent tree for a single inode.
///
/// Caches all extents from the inode and any child blocks in a flat array
/// for quick lookup and modification. Operations maintain sorted order.
pub struct ExtentTree {
    /// Sorted array of extents (by `ee_block`).
    extents: [Extent; MAX_EXTENTS],
    /// Number of valid extents in `extents`.
    count: usize,
    /// Current tree depth (0 = single leaf inline in inode).
    depth: u16,
    /// Monotonically increasing generation counter.
    generation: u32,
}

impl ExtentTree {
    /// Create an empty extent tree.
    pub const fn new() -> Self {
        Self {
            extents: [Extent {
                ee_block: 0,
                ee_len: 0,
                ee_start_hi: 0,
                ee_start_lo: 0,
            }; MAX_EXTENTS],
            count: 0,
            depth: 0,
            generation: 0,
        }
    }

    /// Build the tree from a slice of on-disk extents (sorted, no overlap).
    ///
    /// Returns `Err(InvalidArgument)` if `extents.len() > MAX_EXTENTS`.
    pub fn from_extents(&mut self, src: &[Extent]) -> Result<()> {
        if src.len() > MAX_EXTENTS {
            return Err(Error::InvalidArgument);
        }
        for (i, e) in src.iter().enumerate() {
            self.extents[i] = *e;
        }
        self.count = src.len();
        Ok(())
    }

    /// Binary-search for the extent that covers `logical_block`.
    ///
    /// Returns `Ok(&Extent)` on hit, `Err(NotFound)` otherwise.
    pub fn ext4_ext_find_extent(&self, logical_block: u32) -> Result<&Extent> {
        if self.count == 0 {
            return Err(Error::NotFound);
        }
        // Binary search: find last extent whose ee_block <= logical_block.
        let mut lo = 0usize;
        let mut hi = self.count;
        while lo < hi {
            let mid = lo + (hi - lo) / 2;
            if self.extents[mid].ee_block <= logical_block {
                lo = mid + 1;
            } else {
                hi = mid;
            }
        }
        // `lo` now points one past the candidate.
        if lo == 0 {
            return Err(Error::NotFound);
        }
        let candidate = &self.extents[lo - 1];
        if candidate.contains(logical_block) {
            Ok(candidate)
        } else {
            Err(Error::NotFound)
        }
    }

    /// Insert a new extent into the tree.
    ///
    /// The extent must not overlap any existing extent.
    /// Returns `Err(AlreadyExists)` on overlap, `Err(OutOfMemory)` if full.
    pub fn ext4_ext_insert(&mut self, ext: Extent) -> Result<()> {
        if self.count >= MAX_EXTENTS {
            return Err(Error::OutOfMemory);
        }
        // Find insertion position (keep sorted by ee_block).
        let pos = self.find_insert_position(ext.ee_block)?;
        // Check for overlap with the entry just before `pos`.
        if pos > 0 {
            let prev = &self.extents[pos - 1];
            if prev.ee_block + prev.length() as u32 > ext.ee_block {
                return Err(Error::AlreadyExists);
            }
        }
        // Check for overlap with the entry at `pos`.
        if pos < self.count && self.extents[pos].ee_block < ext.ee_block + ext.length() as u32 {
            return Err(Error::AlreadyExists);
        }
        // Shift entries right to make room.
        let mut i = self.count;
        while i > pos {
            self.extents[i] = self.extents[i - 1];
            i -= 1;
        }
        self.extents[pos] = ext;
        self.count += 1;
        self.generation = self.generation.wrapping_add(1);
        Ok(())
    }

    /// Remove the extent covering `logical_block`.
    ///
    /// Returns `Err(NotFound)` if no such extent exists.
    pub fn ext4_ext_remove(&mut self, logical_block: u32) -> Result<()> {
        let idx = self.find_extent_index(logical_block)?;
        // Shift entries left.
        let mut i = idx;
        while i + 1 < self.count {
            self.extents[i] = self.extents[i + 1];
            i += 1;
        }
        self.count -= 1;
        self.generation = self.generation.wrapping_add(1);
        Ok(())
    }

    /// Translate a logical block to its physical block.
    ///
    /// Returns `Ok(physical_block)` or `Err(NotFound)`.
    pub fn logical_to_physical(&self, logical_block: u32) -> Result<u64> {
        let ext = self.ext4_ext_find_extent(logical_block)?;
        let offset = logical_block - ext.ee_block;
        Ok(ext.start_block() + offset as u64)
    }

    /// Return the current tree depth.
    pub fn depth(&self) -> u16 {
        self.depth
    }

    /// Return the number of extents stored.
    pub fn extent_count(&self) -> usize {
        self.count
    }

    /// Return the current generation.
    pub fn generation(&self) -> u32 {
        self.generation
    }

    /// Build an `ExtentHeader` reflecting current tree state.
    pub fn build_header(&self) -> ExtentHeader {
        if self.depth == 0 {
            ExtentHeader::new_leaf(EXT_INLINE_MAX_EXTENTS as u16, self.generation)
        } else {
            ExtentHeader::new_internal(EXT_INLINE_MAX_INDEXES as u16, self.depth, self.generation)
        }
    }

    // ── Private helpers ────────────────────────────────────────────

    /// Binary search: return the index where `block` should be inserted.
    fn find_insert_position(&self, block: u32) -> Result<usize> {
        let mut lo = 0usize;
        let mut hi = self.count;
        while lo < hi {
            let mid = lo + (hi - lo) / 2;
            if self.extents[mid].ee_block < block {
                lo = mid + 1;
            } else {
                hi = mid;
            }
        }
        Ok(lo)
    }

    /// Find the index of the extent covering `logical_block`.
    fn find_extent_index(&self, logical_block: u32) -> Result<usize> {
        for i in 0..self.count {
            if self.extents[i].contains(logical_block) {
                return Ok(i);
            }
        }
        Err(Error::NotFound)
    }
}

// ---------------------------------------------------------------------------
// Tree depth management
// ---------------------------------------------------------------------------

/// Increase the tree depth by one level.
///
/// In a real ext4 implementation this allocates a new index block and
/// promotes the root. Here we simply track the depth change.
///
/// Returns `Err(InvalidArgument)` if depth would exceed `EXT_MAX_LEVELS`.
pub fn ext4_ext_grow_tree(tree: &mut ExtentTree) -> Result<()> {
    if tree.depth >= EXT_MAX_LEVELS {
        return Err(Error::InvalidArgument);
    }
    tree.depth += 1;
    tree.generation = tree.generation.wrapping_add(1);
    Ok(())
}

/// Reduce the tree depth by one level.
///
/// Only valid when the tree has a single root leaf that fits inline.
/// Returns `Err(InvalidArgument)` if the tree is already a plain leaf.
pub fn ext4_ext_shrink_tree(tree: &mut ExtentTree) -> Result<()> {
    if tree.depth == 0 {
        return Err(Error::InvalidArgument);
    }
    tree.depth -= 1;
    tree.generation = tree.generation.wrapping_add(1);
    Ok(())
}

// ---------------------------------------------------------------------------
// Unit-style self-checks
// ---------------------------------------------------------------------------

/// Validate the tree invariants: sorted, non-overlapping extents.
///
/// Returns `Ok(())` if valid, `Err(InvalidArgument)` otherwise.
pub fn ext4_ext_validate(tree: &ExtentTree) -> Result<()> {
    for i in 1..tree.count {
        let prev = &tree.extents[i - 1];
        let curr = &tree.extents[i];
        if prev.ee_block + prev.length() as u32 > curr.ee_block {
            return Err(Error::InvalidArgument);
        }
    }
    Ok(())
}
