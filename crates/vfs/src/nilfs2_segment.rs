// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! NILFS2 segment management.
//!
//! Implements the NILFS2 log-structured filesystem segment manager:
//!
//! - [`Segment`] — a segment with sequence number and block list
//! - [`SegmentBuffer`] — write buffer that accumulates blocks before flush
//! - `segment_write` — append a block to the current segment
//! - `segment_collect` — garbage collection: reclaim obsolete segments
//! - `segment_usage` — compute usage statistics across all segments
//!
//! # NILFS2 Design
//!
//! NILFS2 is a log-structured filesystem that never overwrites data.
//! Instead, all writes go to the "current segment". When a segment is full,
//! it is finalized and a new segment is allocated. Old segments become
//! reclaimable via garbage collection once they contain only obsolete data.
//!
//! # Reference
//!
//! Linux `fs/nilfs2/segment.c`, `fs/nilfs2/segbuf.c`.

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum number of segments.
const MAX_SEGMENTS: usize = 512;

/// Maximum blocks per segment.
const BLOCKS_PER_SEGMENT: usize = 256;

/// Block size in bytes.
const BLOCK_SIZE: usize = 4096;

/// Segment write buffer capacity in blocks.
const SEGMENT_BUFFER_CAPACITY: usize = 256;

/// Minimum segments to keep before GC can reclaim.
const MIN_CLEAN_SEGMENTS: usize = 4;

/// Sequence number of an invalid/unallocated segment.
const INVALID_SEQ: u64 = u64::MAX;

// ---------------------------------------------------------------------------
// Block descriptor
// ---------------------------------------------------------------------------

/// A single block within a segment.
#[derive(Debug, Clone, Copy)]
pub struct SegmentBlock {
    /// Virtual block number (VBN) for this data.
    pub vbn: u64,
    /// Physical block number within the segment.
    pub pbn: u64,
    /// Block data hash (simplified — first 8 bytes).
    pub hash: u64,
    /// Whether this block is still live (referenced by active checkpoint).
    pub live: bool,
}

impl SegmentBlock {
    /// Creates a new live block.
    pub const fn new(vbn: u64, pbn: u64) -> Self {
        Self {
            vbn,
            pbn,
            hash: 0,
            live: true,
        }
    }

    /// Marks this block as obsolete (can be reclaimed by GC).
    pub fn make_obsolete(&mut self) {
        self.live = false;
    }
}

// ---------------------------------------------------------------------------
// Segment
// ---------------------------------------------------------------------------

/// A NILFS2 segment.
#[derive(Debug)]
pub struct Segment {
    /// Segment index.
    pub index: usize,
    /// Sequence number (monotonically increasing).
    pub seq: u64,
    /// Blocks in this segment.
    pub blocks: [Option<SegmentBlock>; BLOCKS_PER_SEGMENT],
    /// Number of written blocks.
    pub block_count: usize,
    /// Whether this segment is finalized (sealed).
    pub finalized: bool,
    /// Whether this segment is eligible for GC.
    pub gc_eligible: bool,
    /// Number of live blocks.
    pub live_blocks: usize,
    /// Checkpoint ID that owns this segment.
    pub checkpoint_id: u64,
}

impl Segment {
    /// Creates a new empty segment.
    pub fn new(index: usize, seq: u64) -> Self {
        Self {
            index,
            seq,
            blocks: core::array::from_fn(|_| None),
            block_count: 0,
            finalized: false,
            gc_eligible: false,
            live_blocks: 0,
            checkpoint_id: 0,
        }
    }

    /// Returns whether the segment is full.
    pub fn is_full(&self) -> bool {
        self.block_count >= BLOCKS_PER_SEGMENT
    }

    /// Returns whether the segment is empty.
    pub fn is_empty(&self) -> bool {
        self.block_count == 0
    }

    /// Returns the number of free slots.
    pub fn free_slots(&self) -> usize {
        BLOCKS_PER_SEGMENT - self.block_count
    }

    /// Returns the usage ratio (0.0 - 1.0 scaled to 0..1000).
    pub fn usage_ppt(&self) -> u32 {
        if BLOCKS_PER_SEGMENT == 0 {
            return 0;
        }
        (self.block_count as u32 * 1000) / BLOCKS_PER_SEGMENT as u32
    }

    /// Returns the live block ratio (0..1000).
    pub fn live_ppt(&self) -> u32 {
        if self.block_count == 0 {
            return 0;
        }
        (self.live_blocks as u32 * 1000) / self.block_count as u32
    }

    /// Appends a block to this segment.
    pub fn append_block(&mut self, block: SegmentBlock) -> Result<()> {
        if self.finalized {
            return Err(Error::Busy);
        }
        if self.is_full() {
            return Err(Error::OutOfMemory);
        }
        let pbn = self.index as u64 * BLOCKS_PER_SEGMENT as u64 + self.block_count as u64;
        let mut b = block;
        b.pbn = pbn;
        self.blocks[self.block_count] = Some(b);
        self.block_count += 1;
        if b.live {
            self.live_blocks += 1;
        }
        Ok(())
    }

    /// Finalizes this segment (no more writes allowed).
    pub fn finalize(&mut self) {
        self.finalized = true;
    }

    /// Marks all blocks with the given VBN as obsolete.
    pub fn obsolete_vbn(&mut self, vbn: u64) {
        for slot in self.blocks[..self.block_count].iter_mut().flatten() {
            if slot.vbn == vbn && slot.live {
                slot.make_obsolete();
                self.live_blocks = self.live_blocks.saturating_sub(1);
            }
        }
        // Mark GC-eligible if no live blocks remain.
        if self.live_blocks == 0 && self.finalized {
            self.gc_eligible = true;
        }
    }
}

// ---------------------------------------------------------------------------
// Segment buffer
// ---------------------------------------------------------------------------

/// Log-structured write buffer that accumulates blocks before flushing to a segment.
pub struct SegmentBuffer {
    /// Pending blocks awaiting flush.
    pending: [Option<SegmentBlock>; SEGMENT_BUFFER_CAPACITY],
    /// Number of pending blocks.
    pending_count: usize,
    /// Current write generation.
    pub write_generation: u64,
    /// Total bytes buffered.
    pub bytes_buffered: u64,
}

impl SegmentBuffer {
    /// Creates an empty segment buffer.
    pub fn new() -> Self {
        Self {
            pending: core::array::from_fn(|_| None),
            pending_count: 0,
            write_generation: 0,
            bytes_buffered: 0,
        }
    }

    /// Returns the number of pending blocks.
    pub fn pending_count(&self) -> usize {
        self.pending_count
    }

    /// Adds a block to the pending buffer.
    pub fn add_block(&mut self, vbn: u64, _data: &[u8; BLOCK_SIZE]) -> Result<()> {
        if self.pending_count >= SEGMENT_BUFFER_CAPACITY {
            return Err(Error::OutOfMemory);
        }
        let block = SegmentBlock::new(vbn, 0);
        for slot in &mut self.pending {
            if slot.is_none() {
                *slot = Some(block);
                self.pending_count += 1;
                self.bytes_buffered += BLOCK_SIZE as u64;
                return Ok(());
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Flushes pending blocks to a segment.
    pub fn flush_to_segment(&mut self, seg: &mut Segment) -> Result<usize> {
        let mut flushed = 0;
        for slot in &mut self.pending {
            if slot.is_none() {
                continue;
            }
            let block = slot.take().unwrap();
            seg.append_block(block)?;
            flushed += 1;
            self.pending_count = self.pending_count.saturating_sub(1);
        }
        self.write_generation += 1;
        Ok(flushed)
    }

    /// Discards all pending blocks.
    pub fn discard(&mut self) {
        for slot in &mut self.pending {
            *slot = None;
        }
        self.pending_count = 0;
    }
}

impl Default for SegmentBuffer {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Segment manager
// ---------------------------------------------------------------------------

/// NILFS2 segment manager.
pub struct SegmentManager {
    /// All segments.
    segments: [Option<Segment>; MAX_SEGMENTS],
    /// Number of allocated segments.
    count: usize,
    /// Index of the current (active) segment.
    current_seg: usize,
    /// Global sequence counter.
    seq: u64,
    /// Total blocks ever written.
    pub total_blocks_written: u64,
    /// Total GC reclaims.
    pub gc_reclaims: u64,
}

impl SegmentManager {
    /// Creates a new segment manager with one initial segment.
    pub fn new() -> Self {
        let mut mgr = Self {
            segments: core::array::from_fn(|_| None),
            count: 0,
            current_seg: 0,
            seq: 1,
            total_blocks_written: 0,
            gc_reclaims: 0,
        };
        // Initialize the first segment.
        let first = Segment::new(0, mgr.seq);
        mgr.segments[0] = Some(first);
        mgr.count = 1;
        mgr.seq += 1;
        mgr
    }

    /// Returns the current segment.
    pub fn current(&self) -> Option<&Segment> {
        self.segments[self.current_seg].as_ref()
    }

    /// Returns a mutable reference to the current segment.
    pub fn current_mut(&mut self) -> Option<&mut Segment> {
        self.segments[self.current_seg].as_mut()
    }

    /// Allocates a new segment and makes it current.
    pub fn alloc_segment(&mut self) -> Result<usize> {
        if self.count >= MAX_SEGMENTS {
            return Err(Error::OutOfMemory);
        }
        let idx = self.find_free_slot().ok_or(Error::OutOfMemory)?;
        let seg = Segment::new(idx, self.seq);
        self.seq += 1;
        self.segments[idx] = Some(seg);
        self.count += 1;
        Ok(idx)
    }

    fn find_free_slot(&self) -> Option<usize> {
        self.segments.iter().position(|s| s.is_none())
    }

    /// Rotates to a new segment, finalizing the current one.
    pub fn rotate_segment(&mut self) -> Result<()> {
        // Finalize current.
        if let Some(seg) = self.current_mut() {
            seg.finalize();
        }
        let new_idx = self.alloc_segment()?;
        self.current_seg = new_idx;
        Ok(())
    }
}

impl Default for SegmentManager {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Public operations
// ---------------------------------------------------------------------------

/// Writes a block to the current segment, rotating if needed.
pub fn segment_write(
    mgr: &mut SegmentManager,
    buf: &mut SegmentBuffer,
    vbn: u64,
    data: &[u8; BLOCK_SIZE],
) -> Result<()> {
    buf.add_block(vbn, data)?;

    // Flush if buffer is getting full.
    if buf.pending_count() >= SEGMENT_BUFFER_CAPACITY / 2 {
        let needs_rotate = mgr.current().map(|s| s.is_full()).unwrap_or(true);
        if needs_rotate {
            mgr.rotate_segment()?;
        }
        let seg = mgr.current_mut().ok_or(Error::NotFound)?;
        let flushed = buf.flush_to_segment(seg)?;
        mgr.total_blocks_written += flushed as u64;
    }
    Ok(())
}

/// Runs a GC pass, reclaiming segments that have no live blocks.
///
/// Returns the number of segments reclaimed.
pub fn segment_collect(mgr: &mut SegmentManager) -> usize {
    let current_seq = mgr.current().map(|s| s.seq).unwrap_or(0);
    let mut reclaimed = 0;

    for slot in &mut mgr.segments {
        if let Some(seg) = slot.as_ref() {
            if seg.gc_eligible && seg.finalized && seg.seq < current_seq {
                *slot = None;
                reclaimed += 1;
                mgr.count = mgr.count.saturating_sub(1);
            }
        }
    }
    mgr.gc_reclaims += reclaimed as u64;
    reclaimed
}

/// Computes segment usage statistics.
pub fn segment_usage(mgr: &SegmentManager) -> SegmentUsageStats {
    let mut total = 0u64;
    let mut live = 0u64;
    let mut finalized = 0;
    let mut gc_eligible = 0;

    for seg in mgr.segments.iter().flatten() {
        total += seg.block_count as u64;
        live += seg.live_blocks as u64;
        if seg.finalized {
            finalized += 1;
        }
        if seg.gc_eligible {
            gc_eligible += 1;
        }
    }

    SegmentUsageStats {
        total_segments: mgr.count,
        finalized_segments: finalized,
        gc_eligible_segments: gc_eligible,
        total_blocks: total,
        live_blocks: live,
        dead_blocks: total.saturating_sub(live),
    }
}

/// Segment usage statistics.
#[derive(Debug, Clone, Copy)]
pub struct SegmentUsageStats {
    /// Total number of segments.
    pub total_segments: usize,
    /// Finalized segments.
    pub finalized_segments: usize,
    /// Segments eligible for GC.
    pub gc_eligible_segments: usize,
    /// Total blocks across all segments.
    pub total_blocks: u64,
    /// Live (referenced) blocks.
    pub live_blocks: u64,
    /// Obsolete blocks.
    pub dead_blocks: u64,
}
