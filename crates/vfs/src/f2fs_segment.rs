// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! F2FS segment management.
//!
//! F2FS (Flash-Friendly File System) uses a log-structured approach with
//! segments as the unit of space management. Segments are grouped into
//! sections, and sections are grouped into zones. The Segment Information
//! Table (SIT) tracks validity of each segment.

use oncrix_lib::{Error, Result};

/// Block size for F2FS (4096 bytes).
pub const F2FS_BLKSIZE: u32 = 4096;

/// Blocks per segment (512 blocks = 2 MB segments).
pub const BLOCKS_PER_SEG: u32 = 512;

/// Segments per section.
pub const SEGS_PER_SEC: u32 = 1;

/// Sections per zone.
pub const SECS_PER_ZONE: u32 = 1;

/// Maximum number of segments in the SIT.
pub const MAX_SEGMENTS: usize = 65536;

/// Total blocks per section.
pub const BLOCKS_PER_SEC: u32 = BLOCKS_PER_SEG * SEGS_PER_SEC;

/// Segment type constants.
pub const CURSEG_HOT_DATA: u8 = 0;
pub const CURSEG_WARM_DATA: u8 = 1;
pub const CURSEG_COLD_DATA: u8 = 2;
pub const CURSEG_HOT_NODE: u8 = 3;
pub const CURSEG_WARM_NODE: u8 = 4;
pub const CURSEG_COLD_NODE: u8 = 5;
pub const NR_CURSEG_TYPE: usize = 6;

/// Segment state in the SIT.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SegState {
    /// Segment is part of the free list.
    Free = 0,
    /// Segment is currently being written (current segment).
    Current = 1,
    /// Segment has been written and may contain valid blocks.
    Used = 2,
    /// Segment is being garbage collected.
    Prefree = 3,
}

/// SIT (Segment Information Table) entry for one segment.
#[derive(Debug, Clone, Copy)]
pub struct SitEntry {
    /// Segment state.
    pub state: SegState,
    /// Number of valid blocks in this segment (0..=BLOCKS_PER_SEG).
    pub valid_blocks: u16,
    /// Last modified checkpoint sequence.
    pub mtime: u64,
    /// Validity bitmap — 1 bit per block.
    pub valid_map: [u64; 8], // 8 * 64 = 512 bits
}

impl SitEntry {
    /// Create a new empty SIT entry.
    pub const fn new() -> Self {
        Self {
            state: SegState::Free,
            valid_blocks: 0,
            mtime: 0,
            valid_map: [0u64; 8],
        }
    }

    /// Set block at offset `blkoff` as valid.
    pub fn set_valid(&mut self, blkoff: u32) {
        if blkoff < BLOCKS_PER_SEG {
            self.valid_map[blkoff as usize / 64] |= 1u64 << (blkoff % 64);
            self.valid_blocks = self.valid_blocks.saturating_add(1);
        }
    }

    /// Clear block at offset `blkoff` (invalidate).
    pub fn clear_valid(&mut self, blkoff: u32) {
        if blkoff < BLOCKS_PER_SEG {
            let was_set = self.valid_map[blkoff as usize / 64] & (1u64 << (blkoff % 64)) != 0;
            self.valid_map[blkoff as usize / 64] &= !(1u64 << (blkoff % 64));
            if was_set {
                self.valid_blocks = self.valid_blocks.saturating_sub(1);
            }
        }
    }

    /// Check whether block at offset `blkoff` is valid.
    pub fn is_valid(&self, blkoff: u32) -> bool {
        if blkoff >= BLOCKS_PER_SEG {
            return false;
        }
        self.valid_map[blkoff as usize / 64] & (1u64 << (blkoff % 64)) != 0
    }

    /// Return the number of free (invalid) blocks.
    pub fn free_blocks(&self) -> u16 {
        BLOCKS_PER_SEG as u16 - self.valid_blocks
    }
}

impl Default for SitEntry {
    fn default() -> Self {
        Self::new()
    }
}

/// Current segment (curseg) context.
///
/// The curseg tracks the current write position within a segment type.
#[derive(Debug, Clone)]
pub struct CurSeg {
    /// Segment type (CURSEG_HOT_DATA, etc.).
    pub seg_type: u8,
    /// Current segment number.
    pub segno: u32,
    /// Next block offset to write within the segment.
    pub next_blkoff: u32,
    /// Allocated but not yet flushed block addresses.
    pub alloc_type: u8,
    /// Sum block for this curseg.
    pub sum_blk: u32,
}

impl CurSeg {
    /// Create a new curseg.
    pub const fn new(seg_type: u8) -> Self {
        Self {
            seg_type,
            segno: 0,
            next_blkoff: 0,
            alloc_type: 0,
            sum_blk: 0,
        }
    }

    /// Return true if the curseg is full.
    pub fn is_full(&self) -> bool {
        self.next_blkoff >= BLOCKS_PER_SEG
    }

    /// Advance the write pointer, returning the block address just allocated.
    pub fn advance(&mut self, blksize: u64) -> u64 {
        let blkno = self.segno as u64 * BLOCKS_PER_SEG as u64 + self.next_blkoff as u64;
        self.next_blkoff += 1;
        blkno * blksize as u64
    }
}

/// Free segment manager.
#[derive(Debug)]
pub struct FreeSegMgr {
    /// Free segment count.
    pub free_segments: u32,
    /// Total segment count.
    pub total_segments: u32,
    /// Next free segment hint.
    pub next_free: u32,
    /// Bitmap of free segments (1 = free).
    free_bitmap: [u64; 1024], // 1024 * 64 = 65536 bits
}

impl FreeSegMgr {
    /// Create a new free segment manager.
    pub const fn new(total: u32) -> Self {
        Self {
            free_segments: total,
            total_segments: total,
            next_free: 0,
            free_bitmap: [u64::MAX; 1024],
        }
    }

    /// Allocate the next free segment.
    pub fn alloc_segment(&mut self) -> Result<u32> {
        if self.free_segments == 0 {
            return Err(Error::OutOfMemory);
        }
        // Linear scan from next_free hint.
        let start = self.next_free as usize;
        let total = self.total_segments as usize;
        for i in 0..total {
            let idx = (start + i) % total;
            let word = idx / 64;
            let bit = idx % 64;
            if self.free_bitmap[word] & (1u64 << bit) != 0 {
                self.free_bitmap[word] &= !(1u64 << bit);
                self.free_segments -= 1;
                self.next_free = ((idx + 1) % total) as u32;
                return Ok(idx as u32);
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Return a segment to the free pool.
    pub fn free_segment(&mut self, segno: u32) -> Result<()> {
        if segno >= self.total_segments {
            return Err(Error::InvalidArgument);
        }
        let word = segno as usize / 64;
        let bit = segno as usize % 64;
        if self.free_bitmap[word] & (1u64 << bit) == 0 {
            self.free_bitmap[word] |= 1u64 << bit;
            self.free_segments += 1;
        }
        Ok(())
    }

    /// Check if a segment is free.
    pub fn is_free(&self, segno: u32) -> bool {
        if segno >= self.total_segments {
            return false;
        }
        let word = segno as usize / 64;
        let bit = segno as usize % 64;
        self.free_bitmap[word] & (1u64 << bit) != 0
    }
}

/// F2FS segment manager (SMgr).
///
/// Owns the SIT table, curseg array, and free segment list.
#[derive(Debug)]
pub struct SegmentManager {
    /// SIT entries (one per segment).
    pub sit: [SitEntry; MAX_SEGMENTS],
    /// Current segments for each stream type.
    pub curseg: [CurSeg; NR_CURSEG_TYPE],
    /// Free segment manager.
    pub free_mgr: FreeSegMgr,
    /// Dirty SIT bitmap — 1 bit per segment.
    dirty_sit: [u64; 1024],
}

impl SegmentManager {
    /// Create a new segment manager for `total_segs` segments.
    pub fn new(total_segs: u32) -> Self {
        Self {
            sit: [const { SitEntry::new() }; MAX_SEGMENTS],
            curseg: [
                CurSeg::new(CURSEG_HOT_DATA),
                CurSeg::new(CURSEG_WARM_DATA),
                CurSeg::new(CURSEG_COLD_DATA),
                CurSeg::new(CURSEG_HOT_NODE),
                CurSeg::new(CURSEG_WARM_NODE),
                CurSeg::new(CURSEG_COLD_NODE),
            ],
            free_mgr: FreeSegMgr::new(total_segs),
            dirty_sit: [0u64; 1024],
        }
    }

    /// Allocate a new block for `seg_type` stream.
    ///
    /// Returns the logical block address.
    pub fn alloc_block(&mut self, seg_type: u8) -> Result<u64> {
        if seg_type as usize >= NR_CURSEG_TYPE {
            return Err(Error::InvalidArgument);
        }
        let curseg = &mut self.curseg[seg_type as usize];
        if curseg.is_full() {
            // Rotate to a new segment.
            let new_segno = self.free_mgr.alloc_segment()?;
            let old_segno = curseg.segno;
            curseg.segno = new_segno;
            curseg.next_blkoff = 0;
            // Mark old segment as used in SIT.
            if old_segno < MAX_SEGMENTS as u32 {
                self.sit[old_segno as usize].state = SegState::Used;
                self.mark_sit_dirty(old_segno);
            }
            if new_segno < MAX_SEGMENTS as u32 {
                self.sit[new_segno as usize].state = SegState::Current;
                self.mark_sit_dirty(new_segno);
            }
        }
        let curseg = &mut self.curseg[seg_type as usize];
        let blkoff = curseg.next_blkoff;
        let segno = curseg.segno;
        curseg.next_blkoff += 1;

        if segno < MAX_SEGMENTS as u32 {
            self.sit[segno as usize].set_valid(blkoff);
        }
        Ok(segno as u64 * BLOCKS_PER_SEG as u64 + blkoff as u64)
    }

    /// Invalidate a block (logical block address).
    pub fn invalidate_block(&mut self, blkaddr: u64) -> Result<()> {
        let segno = (blkaddr / BLOCKS_PER_SEG as u64) as u32;
        let blkoff = (blkaddr % BLOCKS_PER_SEG as u64) as u32;
        if segno >= MAX_SEGMENTS as u32 {
            return Err(Error::InvalidArgument);
        }
        self.sit[segno as usize].clear_valid(blkoff);
        self.mark_sit_dirty(segno);
        Ok(())
    }

    fn mark_sit_dirty(&mut self, segno: u32) {
        let word = segno as usize / 64;
        let bit = segno as usize % 64;
        if word < self.dirty_sit.len() {
            self.dirty_sit[word] |= 1u64 << bit;
        }
    }

    /// Return the count of free segments.
    pub fn free_segment_count(&self) -> u32 {
        self.free_mgr.free_segments
    }

    /// Estimate utilization percentage (0..=100).
    pub fn utilization(&self) -> u32 {
        let total = self.free_mgr.total_segments;
        if total == 0 {
            return 0;
        }
        let used = total - self.free_mgr.free_segments;
        used * 100 / total
    }
}

/// Garbage collection victim selection policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GcPolicy {
    /// Greedy: pick segment with fewest valid blocks.
    Greedy,
    /// Cost-benefit: balance reclaim gain against age.
    CostBenefit,
}

/// Find the best GC victim segment using the given policy.
///
/// Returns the segment number to collect, or an error if none qualify.
pub fn pick_gc_victim(sm: &SegmentManager, policy: GcPolicy, min_threshold: u16) -> Result<u32> {
    let total = sm.free_mgr.total_segments as usize;
    let mut best: Option<(u32, u64)> = None;

    for segno in 0..total {
        let entry = &sm.sit[segno];
        if entry.state != SegState::Used {
            continue;
        }
        if entry.valid_blocks > min_threshold {
            continue;
        }
        let score = match policy {
            GcPolicy::Greedy => {
                // Lower valid_blocks = better victim.
                u64::MAX - entry.valid_blocks as u64
            }
            GcPolicy::CostBenefit => {
                let free_gain = BLOCKS_PER_SEG as u64 - entry.valid_blocks as u64;
                let age = sm.free_mgr.total_segments as u64 - entry.mtime;
                free_gain.saturating_mul(age)
            }
        };
        match best {
            None => best = Some((segno as u32, score)),
            Some((_, best_score)) if score > best_score => {
                best = Some((segno as u32, score));
            }
            _ => {}
        }
    }

    best.map(|(segno, _)| segno).ok_or(Error::NotFound)
}
