// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! ext4 extent tree management — B-tree mapping logical to physical blocks.
//!
//! ext4 replaces the classic indirect-block mapping of ext2/ext3 with an
//! extent tree.  Each extent maps a contiguous range of logical blocks
//! to a contiguous range of physical blocks, dramatically reducing metadata
//! overhead for large files.
//!
//! # On-disk layout
//!
//! The 60-byte `i_block[]` area of an ext4 inode holds the root of the
//! extent tree:
//!
//! ```text
//! +----------------------------------------------------------+
//! |  Extent Header (12 bytes)                                |
//! |    magic=0xF30A, entries, max, depth, generation         |
//! +----------------------------------------------------------+
//! |  If depth == 0:  Extent Leaf entries (12 bytes each)     |
//! |    [logical_block, length, physical_block_hi/lo]         |
//! +----------------------------------------------------------+
//! |  If depth > 0:   Extent Index entries (12 bytes each)    |
//! |    [logical_block, leaf_block_hi/lo]                     |
//! +----------------------------------------------------------+
//! ```
//!
//! At depth 0, the tree is a flat list of up to 4 extents in the
//! inode itself.  At greater depths, internal index nodes point to
//! child blocks that hold further index or leaf nodes.
//!
//! # Maximum file size
//!
//! With a 4 KiB block size and 4-level extent tree, ext4 can address
//! up to 16 TiB of physical storage per file (limited by the 48-bit
//! physical block address space).
//!
//! # Operations
//!
//! - **Lookup**: Given a logical block number, walk the tree to find
//!   the extent that covers it (or determine it is a hole).
//! - **Insert**: Add a new extent mapping (may require splits).
//! - **Remove**: Remove an extent mapping (may require merging).
//! - **Split**: Split an extent when a write occurs in the middle.
//!
//! # Reference
//!
//! Linux `fs/ext4/extents.c`, `include/ext4_extents.h`,
//! <https://ext4.wiki.kernel.org/index.php/Ext4_Disk_Layout#Extent_Tree>.

extern crate alloc;

use oncrix_lib::{Error, Result};

// ── Constants ────────────────────────────────────────────────────────────────

/// Extent header magic number.
const EXT4_EXT_MAGIC: u16 = 0xF30A;

/// Maximum depth of an extent tree.
const MAX_DEPTH: u16 = 5;

/// Maximum extents in the inode root node (60 bytes / 12 bytes each,
/// minus 12-byte header = 4 extents).
const ROOT_MAX_ENTRIES: u16 = 4;

/// Maximum extents in a non-root leaf/index block (for 4 KiB blocks:
/// (4096 - 12) / 12 = 340).
const BLOCK_MAX_ENTRIES: u16 = 340;

/// Maximum blocks in the extent tree cache.
const MAX_CACHED_BLOCKS: usize = 64;

/// Maximum extents tracked in a flat extent list (for the simplified model).
const MAX_EXTENTS: usize = 256;

/// Maximum index entries tracked.
const MAX_INDEX_ENTRIES: usize = 128;

/// Block size in bytes.
const BLOCK_SIZE: u64 = 4096;

/// Extent header size in bytes.
const HEADER_SIZE: usize = 12;

/// Extent/index entry size in bytes.
const ENTRY_SIZE: usize = 12;

/// Maximum physical block address (48-bit).
const MAX_PHYSICAL_BLOCK: u64 = (1u64 << 48) - 1;

/// Marker for uninitialised extents (upper bit of length).
const EXT_UNINIT_FLAG: u16 = 0x8000;

/// Maximum extent length (excluding uninitialised flag).
const MAX_EXTENT_LEN: u16 = 0x7FFF;

// ── ExtentHeader ─────────────────────────────────────────────────────────────

/// ext4 extent tree header (12 bytes on disk).
///
/// Appears at the start of every extent tree node (both the inode root
/// and allocated tree blocks).
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct ExtentHeader {
    /// Magic number (must be `EXT4_EXT_MAGIC`).
    pub magic: u16,
    /// Number of valid entries following this header.
    pub entries: u16,
    /// Maximum number of entries that can fit.
    pub max_entries: u16,
    /// Depth of this node (0 = leaf, >0 = internal index).
    pub depth: u16,
    /// Generation of the tree (for COW / snapshot).
    pub generation: u32,
}

impl ExtentHeader {
    /// Create a new extent header.
    pub const fn new(max_entries: u16, depth: u16) -> Self {
        Self {
            magic: EXT4_EXT_MAGIC,
            entries: 0,
            max_entries,
            depth,
            generation: 0,
        }
    }

    /// Parse an extent header from a 12-byte buffer.
    pub fn from_bytes(buf: &[u8]) -> Result<Self> {
        if buf.len() < HEADER_SIZE {
            return Err(Error::InvalidArgument);
        }
        let magic = read_u16(buf, 0);
        if magic != EXT4_EXT_MAGIC {
            return Err(Error::InvalidArgument);
        }
        Ok(Self {
            magic,
            entries: read_u16(buf, 2),
            max_entries: read_u16(buf, 4),
            depth: read_u16(buf, 6),
            generation: read_u32(buf, 8),
        })
    }

    /// Validate the header.
    pub fn validate(&self) -> Result<()> {
        if self.magic != EXT4_EXT_MAGIC {
            return Err(Error::InvalidArgument);
        }
        if self.entries > self.max_entries {
            return Err(Error::InvalidArgument);
        }
        if self.depth > MAX_DEPTH {
            return Err(Error::InvalidArgument);
        }
        Ok(())
    }

    /// Whether this node is a leaf (depth == 0).
    pub fn is_leaf(&self) -> bool {
        self.depth == 0
    }

    /// Whether this node has room for more entries.
    pub fn has_room(&self) -> bool {
        self.entries < self.max_entries
    }
}

// ── Extent (leaf entry) ──────────────────────────────────────────────────────

/// ext4 extent leaf entry (12 bytes on disk).
///
/// Maps a contiguous range of logical blocks to physical blocks.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct Extent {
    /// First logical block covered by this extent.
    pub logical_block: u32,
    /// Length in blocks (bit 15 = uninitialised flag).
    pub length: u16,
    /// Upper 16 bits of the 48-bit physical block address.
    pub physical_hi: u16,
    /// Lower 32 bits of the 48-bit physical block address.
    pub physical_lo: u32,
}

impl Extent {
    /// Create a new extent.
    pub const fn new(logical_block: u32, length: u16, physical_block: u64) -> Self {
        Self {
            logical_block,
            length,
            physical_hi: (physical_block >> 32) as u16,
            physical_lo: physical_block as u32,
        }
    }

    /// Create an empty extent.
    pub const fn empty() -> Self {
        Self {
            logical_block: 0,
            length: 0,
            physical_hi: 0,
            physical_lo: 0,
        }
    }

    /// Parse an extent from a 12-byte buffer.
    pub fn from_bytes(buf: &[u8]) -> Result<Self> {
        if buf.len() < ENTRY_SIZE {
            return Err(Error::InvalidArgument);
        }
        Ok(Self {
            logical_block: read_u32(buf, 0),
            length: read_u16(buf, 4),
            physical_hi: read_u16(buf, 6),
            physical_lo: read_u32(buf, 8),
        })
    }

    /// Full 48-bit physical block address.
    pub fn physical_block(&self) -> u64 {
        ((self.physical_hi as u64) << 32) | (self.physical_lo as u64)
    }

    /// Actual length in blocks (masking out the uninitialised flag).
    pub fn actual_length(&self) -> u32 {
        (self.length & MAX_EXTENT_LEN) as u32
    }

    /// Whether this extent is marked as uninitialised.
    pub fn is_uninit(&self) -> bool {
        self.length & EXT_UNINIT_FLAG != 0
    }

    /// Last logical block covered by this extent (inclusive).
    pub fn last_logical_block(&self) -> u32 {
        self.logical_block + self.actual_length() - 1
    }

    /// Whether a given logical block falls within this extent.
    pub fn contains_block(&self, block: u32) -> bool {
        block >= self.logical_block && block < self.logical_block + self.actual_length()
    }

    /// Map a logical block to its physical block address.
    ///
    /// Returns `None` if the block is not within this extent.
    pub fn map_block(&self, logical: u32) -> Option<u64> {
        if !self.contains_block(logical) {
            return None;
        }
        let offset = (logical - self.logical_block) as u64;
        Some(self.physical_block() + offset)
    }

    /// Whether this extent can be merged with the given extent
    /// (contiguous in both logical and physical space).
    pub fn can_merge_with(&self, other: &Extent) -> bool {
        let self_end_logical = self.logical_block + self.actual_length();
        let self_end_physical = self.physical_block() + self.actual_length() as u64;

        self_end_logical == other.logical_block
            && self_end_physical == other.physical_block()
            && self.is_uninit() == other.is_uninit()
            && (self.actual_length() + other.actual_length()) <= MAX_EXTENT_LEN as u32
    }
}

// ── ExtentIdx (index entry) ──────────────────────────────────────────────────

/// ext4 extent index entry (12 bytes on disk).
///
/// Points from an internal node to a child node (leaf or further index).
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct ExtentIdx {
    /// First logical block covered by the subtree rooted at this index.
    pub logical_block: u32,
    /// Lower 32 bits of the child block address.
    pub leaf_lo: u32,
    /// Upper 16 bits of the child block address.
    pub leaf_hi: u16,
    /// Padding.
    pub _pad: u16,
}

impl ExtentIdx {
    /// Create a new index entry.
    pub const fn new(logical_block: u32, child_block: u64) -> Self {
        Self {
            logical_block,
            leaf_lo: child_block as u32,
            leaf_hi: (child_block >> 32) as u16,
            _pad: 0,
        }
    }

    /// Create an empty index entry.
    pub const fn empty() -> Self {
        Self {
            logical_block: 0,
            leaf_lo: 0,
            leaf_hi: 0,
            _pad: 0,
        }
    }

    /// Parse an index entry from a 12-byte buffer.
    pub fn from_bytes(buf: &[u8]) -> Result<Self> {
        if buf.len() < ENTRY_SIZE {
            return Err(Error::InvalidArgument);
        }
        Ok(Self {
            logical_block: read_u32(buf, 0),
            leaf_lo: read_u32(buf, 4),
            leaf_hi: read_u16(buf, 8),
            _pad: 0,
        })
    }

    /// Full 48-bit child block address.
    pub fn child_block(&self) -> u64 {
        ((self.leaf_hi as u64) << 32) | (self.leaf_lo as u64)
    }
}

// ── ExtentLeaf (combined entry for in-memory use) ────────────────────────────

/// In-memory extent leaf with additional metadata.
#[derive(Debug, Clone, Copy)]
pub struct ExtentLeaf {
    /// The on-disk extent data.
    pub extent: Extent,
    /// Tree depth at which this leaf resides.
    pub depth: u16,
    /// Index within the parent node.
    pub parent_idx: u16,
    /// Whether this entry is valid.
    pub valid: bool,
}

impl ExtentLeaf {
    /// Create an empty, invalid leaf.
    pub const fn empty() -> Self {
        Self {
            extent: Extent::empty(),
            depth: 0,
            parent_idx: 0,
            valid: false,
        }
    }
}

// ── LookupResult ─────────────────────────────────────────────────────────────

/// Result of an extent tree lookup for a given logical block.
#[derive(Debug, Clone, Copy)]
pub enum LookupResult {
    /// The block is mapped by the given extent.
    Mapped {
        /// Physical block address.
        physical: u64,
        /// Remaining blocks in the extent from this point.
        remaining: u32,
        /// Whether the extent is uninitialised.
        uninit: bool,
    },
    /// The block falls in a hole (no extent covers it).
    Hole {
        /// Logical block that was looked up.
        logical: u32,
        /// Number of blocks until the next extent (or end of file).
        hole_length: u32,
    },
}

// ── ExtentTree ───────────────────────────────────────────────────────────────

/// In-memory representation of an ext4 extent tree.
///
/// Maintains a flat list of all extents for efficient lookup and
/// modification.  For the kernel model, we keep extents in sorted
/// order by logical block.
pub struct ExtentTree {
    /// Tree root header.
    header: ExtentHeader,
    /// Sorted list of leaf extents.
    extents: [Extent; MAX_EXTENTS],
    /// Number of valid extents.
    extent_count: usize,
    /// Index entries (for trees with depth > 0).
    indices: [ExtentIdx; MAX_INDEX_ENTRIES],
    /// Number of valid index entries.
    index_count: usize,
    /// Inode number this tree belongs to.
    inode: u64,
    /// File size in bytes (for hole calculation).
    file_size: u64,
    /// Block size in bytes.
    block_size: u64,
    /// Whether the tree has been modified.
    dirty: bool,
}

impl ExtentTree {
    /// Create a new empty extent tree for an inode.
    pub const fn new(inode: u64) -> Self {
        Self {
            header: ExtentHeader::new(ROOT_MAX_ENTRIES, 0),
            extents: [const { Extent::empty() }; MAX_EXTENTS],
            extent_count: 0,
            indices: [const { ExtentIdx::empty() }; MAX_INDEX_ENTRIES],
            index_count: 0,
            inode,
            file_size: 0,
            block_size: BLOCK_SIZE,
            dirty: false,
        }
    }

    /// Create an extent tree with a specified block size.
    pub fn with_block_size(inode: u64, block_size: u64) -> Self {
        let mut tree = Self::new(inode);
        tree.block_size = block_size;
        tree
    }

    /// Set the file size.
    pub fn set_file_size(&mut self, size: u64) {
        self.file_size = size;
    }

    /// Whether the tree has been modified since last flush.
    pub fn is_dirty(&self) -> bool {
        self.dirty
    }

    /// Mark the tree as clean.
    pub fn mark_clean(&mut self) {
        self.dirty = false;
    }

    /// Number of extents in the tree.
    pub fn extent_count(&self) -> usize {
        self.extent_count
    }

    /// Tree depth.
    pub fn depth(&self) -> u16 {
        self.header.depth
    }

    // ── Lookup ───────────────────────────────────────────────────

    /// Look up the physical block for a given logical block.
    pub fn lookup_extent(&self, logical_block: u32) -> LookupResult {
        // Binary search through sorted extents.
        if self.extent_count == 0 {
            let total_blocks = if self.block_size > 0 {
                (self.file_size / self.block_size) as u32
            } else {
                0
            };
            return LookupResult::Hole {
                logical: logical_block,
                hole_length: total_blocks.saturating_sub(logical_block),
            };
        }

        // Find the extent that may contain this block.
        let mut lo = 0usize;
        let mut hi = self.extent_count;

        while lo < hi {
            let mid = lo + (hi - lo) / 2;
            let ext = &self.extents[mid];
            if logical_block < ext.logical_block {
                hi = mid;
            } else if logical_block > ext.last_logical_block() {
                lo = mid + 1;
            } else {
                // Found: block is within this extent.
                let offset = logical_block - ext.logical_block;
                let remaining = ext.actual_length() - offset;
                return LookupResult::Mapped {
                    physical: ext.physical_block() + offset as u64,
                    remaining,
                    uninit: ext.is_uninit(),
                };
            }
        }

        // Block is in a hole. Compute hole length.
        let next_logical = if lo < self.extent_count {
            self.extents[lo].logical_block
        } else {
            let total_blocks = if self.block_size > 0 {
                (self.file_size / self.block_size) as u32
            } else {
                0
            };
            total_blocks
        };

        LookupResult::Hole {
            logical: logical_block,
            hole_length: next_logical.saturating_sub(logical_block),
        }
    }

    /// Get the physical block address for a logical block.
    ///
    /// Returns `None` for holes.
    pub fn get_block(&self, logical_block: u32) -> Option<u64> {
        match self.lookup_extent(logical_block) {
            LookupResult::Mapped { physical, .. } => Some(physical),
            LookupResult::Hole { .. } => None,
        }
    }

    // ── Insert ───────────────────────────────────────────────────

    /// Insert a new extent into the tree.
    ///
    /// Attempts to merge with adjacent extents if possible.
    pub fn insert_extent(&mut self, extent: Extent) -> Result<()> {
        if extent.actual_length() == 0 {
            return Err(Error::InvalidArgument);
        }
        if extent.physical_block() > MAX_PHYSICAL_BLOCK {
            return Err(Error::InvalidArgument);
        }

        // Check for overlap with existing extents.
        for i in 0..self.extent_count {
            let existing = &self.extents[i];
            if extent.logical_block < existing.logical_block + existing.actual_length()
                && existing.logical_block < extent.logical_block + extent.actual_length()
            {
                return Err(Error::AlreadyExists);
            }
        }

        // Try to merge with the previous extent.
        let insert_pos = self.find_insert_position(extent.logical_block);

        if insert_pos > 0 {
            let prev = &self.extents[insert_pos - 1];
            if prev.can_merge_with(&extent) {
                let new_len = prev.actual_length() + extent.actual_length();
                self.extents[insert_pos - 1].length = if prev.is_uninit() {
                    (new_len as u16) | EXT_UNINIT_FLAG
                } else {
                    new_len as u16
                };
                self.dirty = true;

                // Also try to merge with the next extent.
                if insert_pos < self.extent_count {
                    let merged = self.extents[insert_pos - 1];
                    if merged.can_merge_with(&self.extents[insert_pos]) {
                        let total =
                            merged.actual_length() + self.extents[insert_pos].actual_length();
                        self.extents[insert_pos - 1].length = if merged.is_uninit() {
                            (total as u16) | EXT_UNINIT_FLAG
                        } else {
                            total as u16
                        };
                        self.remove_at(insert_pos);
                    }
                }

                return Ok(());
            }
        }

        // Try to merge with the next extent.
        if insert_pos < self.extent_count {
            if extent.can_merge_with(&self.extents[insert_pos]) {
                let next = &self.extents[insert_pos];
                let new_len = extent.actual_length() + next.actual_length();
                self.extents[insert_pos].logical_block = extent.logical_block;
                self.extents[insert_pos].physical_hi = extent.physical_hi;
                self.extents[insert_pos].physical_lo = extent.physical_lo;
                self.extents[insert_pos].length = if extent.is_uninit() {
                    (new_len as u16) | EXT_UNINIT_FLAG
                } else {
                    new_len as u16
                };
                self.dirty = true;
                return Ok(());
            }
        }

        // No merge possible — insert new extent.
        if self.extent_count >= MAX_EXTENTS {
            return Err(Error::OutOfMemory);
        }

        // Shift entries to make room.
        let ec = self.extent_count;
        for i in (insert_pos..ec).rev() {
            self.extents[i + 1] = self.extents[i];
        }
        self.extents[insert_pos] = extent;
        self.extent_count += 1;
        self.header.entries = self.extent_count as u16;
        self.dirty = true;

        Ok(())
    }

    // ── Remove ───────────────────────────────────────────────────

    /// Remove an extent covering the given logical block.
    ///
    /// If the block is in the middle of an extent, the extent is split
    /// into two (before and after the removed block).
    pub fn remove_extent(&mut self, logical_block: u32) -> Result<()> {
        let idx = self
            .find_extent_index(logical_block)
            .ok_or(Error::NotFound)?;
        let ext = self.extents[idx];

        if ext.actual_length() == 1 {
            // Single-block extent: remove entirely.
            self.remove_at(idx);
            self.dirty = true;
            return Ok(());
        }

        if logical_block == ext.logical_block {
            // Remove from the beginning.
            self.extents[idx].logical_block += 1;
            let pb = ext.physical_block() + 1;
            self.extents[idx].physical_hi = (pb >> 32) as u16;
            self.extents[idx].physical_lo = pb as u32;
            let new_len = ext.actual_length() - 1;
            self.extents[idx].length = if ext.is_uninit() {
                (new_len as u16) | EXT_UNINIT_FLAG
            } else {
                new_len as u16
            };
        } else if logical_block == ext.last_logical_block() {
            // Remove from the end.
            let new_len = ext.actual_length() - 1;
            self.extents[idx].length = if ext.is_uninit() {
                (new_len as u16) | EXT_UNINIT_FLAG
            } else {
                new_len as u16
            };
        } else {
            // Split in the middle.
            self.split_extent(idx, logical_block)?;
            // After splitting, remove the block from the second part.
            // The split places the second half at idx+1.
            // The second half starts at logical_block, so trim its start.
            let new_idx = idx + 1;
            self.extents[new_idx].logical_block += 1;
            let pb = self.extents[new_idx].physical_block() + 1;
            self.extents[new_idx].physical_hi = (pb >> 32) as u16;
            self.extents[new_idx].physical_lo = pb as u32;
            let new_len = self.extents[new_idx].actual_length() - 1;
            self.extents[new_idx].length = if self.extents[new_idx].is_uninit() {
                (new_len as u16) | EXT_UNINIT_FLAG
            } else {
                new_len as u16
            };
            if new_len == 0 {
                self.remove_at(new_idx);
            }
        }

        self.dirty = true;
        Ok(())
    }

    // ── Split ────────────────────────────────────────────────────

    /// Split an extent at the given logical block.
    ///
    /// The original extent is truncated to end before `at_block`, and
    /// a new extent starting at `at_block` is inserted.
    pub fn split_extent(&mut self, extent_idx: usize, at_block: u32) -> Result<()> {
        if extent_idx >= self.extent_count {
            return Err(Error::InvalidArgument);
        }
        if self.extent_count >= MAX_EXTENTS {
            return Err(Error::OutOfMemory);
        }

        let ext = self.extents[extent_idx];
        if !ext.contains_block(at_block) || at_block == ext.logical_block {
            return Err(Error::InvalidArgument);
        }

        let offset = at_block - ext.logical_block;
        let first_len = offset;
        let second_len = ext.actual_length() - offset;
        let second_phys = ext.physical_block() + offset as u64;

        // Truncate the first extent.
        self.extents[extent_idx].length = if ext.is_uninit() {
            (first_len as u16) | EXT_UNINIT_FLAG
        } else {
            first_len as u16
        };

        // Create the second extent.
        let second = Extent::new(at_block, second_len as u16, second_phys);

        // Insert the second extent right after the first.
        let insert_pos = extent_idx + 1;
        let ec = self.extent_count;
        for i in (insert_pos..ec).rev() {
            self.extents[i + 1] = self.extents[i];
        }
        self.extents[insert_pos] = second;
        // Preserve uninit flag.
        if ext.is_uninit() {
            self.extents[insert_pos].length = (second_len as u16) | EXT_UNINIT_FLAG;
        }
        self.extent_count += 1;
        self.header.entries = self.extent_count as u16;
        self.dirty = true;

        Ok(())
    }

    // ── Iteration ────────────────────────────────────────────────

    /// Iterate over all extents, invoking a callback for each.
    ///
    /// Extents are visited in logical block order.
    pub fn for_each_extent<F>(&self, mut f: F)
    where
        F: FnMut(usize, &Extent),
    {
        for i in 0..self.extent_count {
            f(i, &self.extents[i]);
        }
    }

    /// Return the extent at the given index (if valid).
    pub fn get_extent(&self, index: usize) -> Option<&Extent> {
        if index < self.extent_count {
            Some(&self.extents[index])
        } else {
            None
        }
    }

    /// Total number of physical blocks mapped by all extents.
    pub fn total_mapped_blocks(&self) -> u64 {
        let mut total = 0u64;
        for i in 0..self.extent_count {
            total += self.extents[i].actual_length() as u64;
        }
        total
    }

    /// Total number of file blocks (including holes).
    pub fn total_file_blocks(&self) -> u64 {
        if self.block_size == 0 {
            return 0;
        }
        (self.file_size + self.block_size - 1) / self.block_size
    }

    /// Number of holes (unmapped blocks) in the file.
    pub fn hole_count(&self) -> u64 {
        self.total_file_blocks()
            .saturating_sub(self.total_mapped_blocks())
    }

    // ── Internal helpers ─────────────────────────────────────────

    /// Find the insertion position (sorted order) for a logical block.
    fn find_insert_position(&self, logical_block: u32) -> usize {
        let mut lo = 0usize;
        let mut hi = self.extent_count;
        while lo < hi {
            let mid = lo + (hi - lo) / 2;
            if self.extents[mid].logical_block < logical_block {
                lo = mid + 1;
            } else {
                hi = mid;
            }
        }
        lo
    }

    /// Find the index of the extent containing a logical block.
    fn find_extent_index(&self, logical_block: u32) -> Option<usize> {
        for i in 0..self.extent_count {
            if self.extents[i].contains_block(logical_block) {
                return Some(i);
            }
        }
        None
    }

    /// Remove the extent at the given index, shifting subsequent entries.
    fn remove_at(&mut self, idx: usize) {
        if idx >= self.extent_count {
            return;
        }
        let ec = self.extent_count;
        for i in idx..(ec - 1) {
            self.extents[i] = self.extents[i + 1];
        }
        self.extents[ec - 1] = Extent::empty();
        self.extent_count -= 1;
        self.header.entries = self.extent_count as u16;
    }
}

// ── Byte-reading helpers ─────────────────────────────────────────────────────

/// Read a little-endian `u16` from `buf` at byte offset `off`.
fn read_u16(buf: &[u8], off: usize) -> u16 {
    u16::from_le_bytes([buf[off], buf[off + 1]])
}

/// Read a little-endian `u32` from `buf` at byte offset `off`.
fn read_u32(buf: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]])
}
