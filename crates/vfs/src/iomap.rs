// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Block I/O mapping framework — replaces buffer_head for modern filesystems.
//!
//! The iomap layer provides a clean abstraction between filesystems and the
//! block I/O subsystem.  Instead of tracking individual buffer heads, a
//! filesystem describes a contiguous range of logical file offsets as a single
//! [`IoMap`], which the core layer then uses to drive page-level read, write,
//! zero, and truncate operations.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────┐
//! │  VFS / page cache                                                   │
//! │       │  iomap_readpage / iomap_writepage / iomap_zero_range        │
//! │       ▼                                                             │
//! │  ┌─────────────────────────────────────────────────────────────┐   │
//! │  │  IoMap subsystem (this module)                              │   │
//! │  │  ┌────────────────┐  ┌──────────────────────────────────┐  │   │
//! │  │  │  IoMapSubsystem│  │  active mapping table (256)      │  │   │
//! │  │  │  map / unmap   │  │  [IoMapEntry]                    │  │   │
//! │  │  │  iter_advance  │  └──────────────────────────────────┘  │   │
//! │  │  └────────────────┘                                        │   │
//! │  └─────────────────────────────────────────────────────────────┘   │
//! │       │  IoMapOps::map_blocks (filesystem callback)                 │
//! │       ▼                                                             │
//! │  Filesystem (ext4, xfs, f2fs …)                                     │
//! └─────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # References
//!
//! - Linux `fs/iomap/apply.c`, `fs/iomap/buffered-io.c`
//! - Linux `include/linux/iomap.h`

use oncrix_lib::{Error, Result};

// ── Constants ─────────────────────────────────────────────────────────────────

/// Maximum number of simultaneously active iomap mappings.
const MAX_ACTIVE_IOMAPS: usize = 256;

/// Page size assumed by the iomap layer.
const IOMAP_PAGE_SIZE: u64 = 4096;

/// Sentinel value meaning "no block mapped" (equivalent to `IOMAP_NULL_ADDR`).
pub const IOMAP_NULL_ADDR: u64 = u64::MAX;

// ── IoMapType ─────────────────────────────────────────────────────────────────

/// Classifies the kind of block mapping returned by a filesystem.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IoMapType {
    /// The range contains a hole (no blocks allocated).
    Hole,
    /// The range is delayed-allocated (not yet assigned physical blocks).
    Delalloc,
    /// The range is mapped to physical blocks and contains valid data.
    Mapped,
    /// The range is mapped but contains unwritten (zeroed) data.
    Unwritten,
    /// The range is stored inline in the inode itself.
    Inline,
}

impl Default for IoMapType {
    fn default() -> Self {
        Self::Hole
    }
}

// ── IoMapFlags ────────────────────────────────────────────────────────────────

/// Modifier flags attached to an [`IoMap`].
#[derive(Debug, Clone, Copy, Default)]
pub struct IoMapFlags(pub u32);

impl IoMapFlags {
    /// Mapping was newly allocated during this operation.
    pub const NEW: u32 = 0x01;
    /// Mapping covers dirty (modified) data.
    pub const DIRTY: u32 = 0x02;
    /// Mapping is shared (CoW semantics may apply).
    pub const SHARED: u32 = 0x04;
    /// Mapping was merged with an adjacent mapping.
    pub const MERGED: u32 = 0x08;
    /// The caller prefers buffer_head-style I/O for this mapping.
    pub const BUFFER_HEAD: u32 = 0x10;

    /// Returns `true` if the NEW flag is set.
    pub fn is_new(self) -> bool {
        self.0 & Self::NEW != 0
    }

    /// Returns `true` if the DIRTY flag is set.
    pub fn is_dirty(self) -> bool {
        self.0 & Self::DIRTY != 0
    }

    /// Returns `true` if the SHARED flag is set.
    pub fn is_shared(self) -> bool {
        self.0 & Self::SHARED != 0
    }

    /// Returns `true` if the MERGED flag is set.
    pub fn is_merged(self) -> bool {
        self.0 & Self::MERGED != 0
    }
}

// ── IoMap ─────────────────────────────────────────────────────────────────────

/// A single iomap mapping: describes a contiguous range of logical file
/// offsets and their corresponding physical block address (if any).
#[derive(Debug, Clone, Copy, Default)]
pub struct IoMap {
    /// Physical block start address (in bytes), or [`IOMAP_NULL_ADDR`] for holes.
    pub addr: u64,
    /// Logical file offset (in bytes) at which this mapping begins.
    pub offset: u64,
    /// Length of the mapping in bytes.
    pub length: u64,
    /// Classification of the block range.
    pub map_type: IoMapType,
    /// Modifier flags.
    pub flags: IoMapFlags,
    /// First block number on the block device (block-addressed alias for `addr`).
    pub block_start: u64,
}

impl IoMap {
    /// Construct a hole mapping covering `[offset, offset + length)`.
    pub const fn hole(offset: u64, length: u64) -> Self {
        Self {
            addr: IOMAP_NULL_ADDR,
            offset,
            length,
            map_type: IoMapType::Hole,
            flags: IoMapFlags(0),
            block_start: 0,
        }
    }

    /// Construct a mapped (data-backed) mapping.
    pub const fn mapped(offset: u64, length: u64, addr: u64, block_start: u64) -> Self {
        Self {
            addr,
            offset,
            length,
            map_type: IoMapType::Mapped,
            flags: IoMapFlags(0),
            block_start,
        }
    }

    /// Returns `true` if this mapping covers a file hole.
    pub fn is_hole(&self) -> bool {
        self.map_type == IoMapType::Hole
    }

    /// Returns `true` if this mapping is backed by physical blocks.
    pub fn is_mapped(&self) -> bool {
        matches!(self.map_type, IoMapType::Mapped | IoMapType::Unwritten)
    }

    /// Returns `true` if the given `pos` falls within this mapping.
    pub fn contains(&self, pos: u64) -> bool {
        pos >= self.offset && pos < self.offset + self.length
    }
}

// ── IoMapOps ──────────────────────────────────────────────────────────────────

/// Filesystem-provided callbacks required by the iomap layer.
pub trait IoMapOps {
    /// Map file blocks in `[offset, offset + length)` and fill `iomap`.
    ///
    /// The filesystem must fill in `iomap.addr`, `iomap.length`,
    /// `iomap.map_type`, and optionally `iomap.flags`.  The returned
    /// length may be shorter than requested if the mapping ends before
    /// `offset + length`.
    fn map_blocks(&self, inode_id: u64, offset: u64, length: u64, iomap: &mut IoMap) -> Result<()>;

    /// Called after a page-level I/O operation completes.
    ///
    /// Allows the filesystem to update metadata (e.g., convert unwritten
    /// extents to written extents after a write).
    fn end_io(&self, inode_id: u64, iomap: &IoMap, written: u64) -> Result<()>;

    /// Punch a hole in the range `[offset, offset + length)`.
    ///
    /// The filesystem deallocates blocks in the given range.
    fn punch_hole(&self, inode_id: u64, offset: u64, length: u64) -> Result<()>;
}

// ── IoMapIter ─────────────────────────────────────────────────────────────────

/// Iterator state for walking a file range using successive iomap calls.
///
/// Callers advance the iterator by calling [`IoMapIter::advance`] after
/// processing each mapping returned by the filesystem.
#[derive(Debug, Clone, Copy)]
pub struct IoMapIter {
    /// The current mapping returned by the filesystem.
    pub iomap: IoMap,
    /// Current file position (bytes), advances as the iterator is consumed.
    pub pos: u64,
    /// Remaining length (bytes) to cover from `pos` onward.
    pub len: u64,
    /// Bytes processed so far (informational).
    pub processed: u64,
}

impl IoMapIter {
    /// Create a new iterator starting at `pos` and covering `len` bytes.
    pub const fn new(pos: u64, len: u64) -> Self {
        Self {
            iomap: IoMap {
                addr: IOMAP_NULL_ADDR,
                offset: 0,
                length: 0,
                map_type: IoMapType::Hole,
                flags: IoMapFlags(0),
                block_start: 0,
            },
            pos,
            len,
            processed: 0,
        }
    }

    /// Returns `true` if there is more range left to iterate.
    pub fn has_more(&self) -> bool {
        self.len > 0
    }

    /// Advance the iterator by `bytes` bytes.
    ///
    /// Moves `pos` forward and reduces `len` accordingly.  Saturates at
    /// zero to avoid underflow.
    pub fn advance(&mut self, bytes: u64) {
        let step = bytes.min(self.len);
        self.pos += step;
        self.len -= step;
        self.processed += step;
    }
}

// ── IoMapEntry (internal pool entry) ─────────────────────────────────────────

/// Internal pool entry tracking an active iomap allocation.
#[derive(Debug, Clone, Copy)]
struct IoMapEntry {
    /// Inode that owns this mapping.
    inode_id: u64,
    /// The mapping itself.
    iomap: IoMap,
    /// Whether this slot is occupied.
    in_use: bool,
}

impl IoMapEntry {
    const fn empty() -> Self {
        Self {
            inode_id: 0,
            iomap: IoMap {
                addr: IOMAP_NULL_ADDR,
                offset: 0,
                length: 0,
                map_type: IoMapType::Hole,
                flags: IoMapFlags(0),
                block_start: 0,
            },
            in_use: false,
        }
    }
}

// ── IoMapStats ────────────────────────────────────────────────────────────────

/// Counters for iomap subsystem activity.
#[derive(Debug, Clone, Copy, Default)]
pub struct IoMapStats {
    /// Number of readpage operations dispatched.
    pub reads: u64,
    /// Number of writepage operations dispatched.
    pub writes: u64,
    /// Number of zero-range operations dispatched.
    pub zeros: u64,
    /// Number of hole ranges skipped during iteration.
    pub holes_skipped: u64,
}

// ── IoMapSubsystem ────────────────────────────────────────────────────────────

/// Central iomap subsystem: manages the active-mapping pool and dispatches
/// page-level I/O via filesystem-provided [`IoMapOps`].
pub struct IoMapSubsystem {
    /// Pool of active iomap entries.
    entries: [IoMapEntry; MAX_ACTIVE_IOMAPS],
    /// Accumulated operational statistics.
    pub stats: IoMapStats,
}

impl IoMapSubsystem {
    /// Construct a new, empty iomap subsystem.
    pub const fn new() -> Self {
        Self {
            entries: [const { IoMapEntry::empty() }; MAX_ACTIVE_IOMAPS],
            stats: IoMapStats {
                reads: 0,
                writes: 0,
                zeros: 0,
                holes_skipped: 0,
            },
        }
    }

    /// Record a mapping for `inode_id`.
    ///
    /// Returns the slot index on success, or [`Error::OutOfMemory`] if the
    /// pool is exhausted.
    pub fn map(&mut self, inode_id: u64, iomap: IoMap) -> Result<usize> {
        for (idx, entry) in self.entries.iter_mut().enumerate() {
            if !entry.in_use {
                entry.inode_id = inode_id;
                entry.iomap = iomap;
                entry.in_use = true;
                return Ok(idx);
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Release the mapping at `slot_idx`.
    ///
    /// Returns [`Error::InvalidArgument`] if the index is out of range or the
    /// slot is not currently in use.
    pub fn unmap(&mut self, slot_idx: usize) -> Result<()> {
        if slot_idx >= MAX_ACTIVE_IOMAPS {
            return Err(Error::InvalidArgument);
        }
        let entry = &mut self.entries[slot_idx];
        if !entry.in_use {
            return Err(Error::InvalidArgument);
        }
        *entry = IoMapEntry::empty();
        Ok(())
    }

    /// Advance the iterator over the active mapping at `slot_idx`.
    ///
    /// Moves the iterator forward by the amount already covered by the
    /// current iomap.  Returns the number of bytes advanced.
    pub fn iter_advance(&self, iter: &mut IoMapIter, slot_idx: usize) -> Result<u64> {
        if slot_idx >= MAX_ACTIVE_IOMAPS {
            return Err(Error::InvalidArgument);
        }
        let entry = &self.entries[slot_idx];
        if !entry.in_use {
            return Err(Error::InvalidArgument);
        }
        let remaining = (entry.iomap.offset + entry.iomap.length).saturating_sub(iter.pos);
        let step = remaining.min(iter.len);
        iter.advance(step);
        Ok(step)
    }

    /// Return the number of currently occupied mapping slots.
    pub fn active_count(&self) -> usize {
        self.entries.iter().filter(|e| e.in_use).count()
    }
}

impl Default for IoMapSubsystem {
    fn default() -> Self {
        Self::new()
    }
}

// ── Top-level iomap operations ─────────────────────────────────────────────────

/// Read a single page (aligned to `IOMAP_PAGE_SIZE`) from a file using iomap.
///
/// The filesystem's [`IoMapOps::map_blocks`] is called to determine whether
/// the page is a hole or backed by physical blocks.  For a hole, the buffer
/// is zeroed; for a mapped page, the caller is expected to submit the actual
/// block I/O using `iomap.addr`.
///
/// Returns the [`IoMap`] describing the page.
pub fn iomap_readpage<F: IoMapOps>(
    ops: &F,
    inode_id: u64,
    file_offset: u64,
    buf: &mut [u8],
    stats: &mut IoMapStats,
) -> Result<IoMap> {
    if buf.len() < IOMAP_PAGE_SIZE as usize {
        return Err(Error::InvalidArgument);
    }
    let aligned = file_offset & !(IOMAP_PAGE_SIZE - 1);
    let mut iomap = IoMap::default();
    ops.map_blocks(inode_id, aligned, IOMAP_PAGE_SIZE, &mut iomap)?;
    if iomap.is_hole() {
        for byte in buf.iter_mut().take(IOMAP_PAGE_SIZE as usize) {
            *byte = 0;
        }
        stats.holes_skipped += 1;
    }
    stats.reads += 1;
    Ok(iomap)
}

/// Write a single page of data to a file using iomap.
///
/// The filesystem's [`IoMapOps::map_blocks`] is called to obtain or allocate
/// physical blocks for the page.  After the (simulated) I/O,
/// [`IoMapOps::end_io`] is invoked to allow the filesystem to convert
/// unwritten extents to written.
///
/// Returns the [`IoMap`] used for the write.
pub fn iomap_writepage<F: IoMapOps>(
    ops: &F,
    inode_id: u64,
    file_offset: u64,
    data: &[u8],
    stats: &mut IoMapStats,
) -> Result<IoMap> {
    if data.len() < IOMAP_PAGE_SIZE as usize {
        return Err(Error::InvalidArgument);
    }
    let aligned = file_offset & !(IOMAP_PAGE_SIZE - 1);
    let mut iomap = IoMap::default();
    ops.map_blocks(inode_id, aligned, IOMAP_PAGE_SIZE, &mut iomap)?;
    let written = IOMAP_PAGE_SIZE;
    ops.end_io(inode_id, &iomap, written)?;
    stats.writes += 1;
    Ok(iomap)
}

/// Zero a byte range in a file using iomap.
///
/// Iterates over the range `[offset, offset + length)` in page-aligned
/// chunks, calling [`IoMapOps::map_blocks`] for each chunk.  Hole chunks
/// are skipped; mapped / unwritten chunks are queued for zeroing.
///
/// Returns the total number of bytes zeroed.
pub fn iomap_zero_range<F: IoMapOps>(
    ops: &F,
    inode_id: u64,
    offset: u64,
    length: u64,
    stats: &mut IoMapStats,
) -> Result<u64> {
    if length == 0 {
        return Ok(0);
    }
    let mut pos = offset;
    let end = offset + length;
    let mut zeroed: u64 = 0;
    while pos < end {
        let chunk = (end - pos).min(IOMAP_PAGE_SIZE);
        let mut iomap = IoMap::default();
        ops.map_blocks(inode_id, pos, chunk, &mut iomap)?;
        let covered = chunk.min(iomap.length);
        if iomap.is_hole() {
            stats.holes_skipped += 1;
        } else {
            zeroed += covered;
            stats.zeros += 1;
        }
        pos += covered.max(1);
    }
    Ok(zeroed)
}

/// Truncate the last partial page when a file is shortened.
///
/// If the new EOF `new_size` falls in the middle of a page, the bytes
/// from `new_size` to the end of the page must be zeroed so that a
/// subsequent file extension does not expose stale data.
///
/// Returns the number of bytes zeroed (0 if `new_size` is already page-aligned).
pub fn iomap_truncate_page<F: IoMapOps>(
    ops: &F,
    inode_id: u64,
    new_size: u64,
    stats: &mut IoMapStats,
) -> Result<u64> {
    let offset_in_page = new_size & (IOMAP_PAGE_SIZE - 1);
    if offset_in_page == 0 {
        return Ok(0);
    }
    let tail_len = IOMAP_PAGE_SIZE - offset_in_page;
    iomap_zero_range(ops, inode_id, new_size, tail_len, stats)
}
