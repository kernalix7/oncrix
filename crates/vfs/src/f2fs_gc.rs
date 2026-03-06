// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! F2FS garbage collection.
//!
//! F2FS (Flash-Friendly File System) uses a log-structured layout with
//! segments. Garbage collection (GC) reclaims dirty segments by migrating
//! valid blocks to clean segments and invalidating the old segment.
//!
//! # GC Modes
//!
//! | Mode    | Description                                          |
//! |---------|------------------------------------------------------|
//! | FG GC   | Foreground GC — triggered when free segments are low |
//! | BG GC   | Background GC — periodic cleaning via kthread        |
//!
//! # Victim Segment Selection
//!
//! Two policies are available:
//! - **Greedy**: Choose the segment with the fewest valid blocks (cheapest GC).
//! - **Cost-Benefit**: Balance segment utility and age for wear leveling.
//!
//! # References
//!
//! - Linux `fs/f2fs/gc.c`, `fs/f2fs/gc.h`
//! - F2FS design: `Documentation/filesystems/f2fs.rst`

use oncrix_lib::{Error, Result};

/// Number of segments in the simulated segment table.
pub const MAX_SEGMENTS: usize = 1024;
/// Number of blocks per segment.
pub const BLOCKS_PER_SEG: u32 = 512;

/// GC mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GcMode {
    /// Foreground GC — synchronous, higher priority.
    Foreground,
    /// Background GC — asynchronous, lower priority.
    Background,
}

/// Victim selection policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VictimPolicy {
    /// Greedy — minimum valid blocks.
    Greedy,
    /// Cost-benefit — minimum cost considering age.
    CostBenefit,
}

/// State of one segment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SegmentState {
    /// Segment has free blocks and is being written.
    Current,
    /// Segment is full and contains valid data.
    Dirty,
    /// Segment has been GC'd and all blocks are invalid.
    Free,
}

/// Per-segment metadata.
#[derive(Debug, Clone, Copy)]
pub struct SegmentInfo {
    /// Segment index.
    pub segno: u32,
    /// Number of valid (live) blocks in this segment.
    pub valid_blocks: u32,
    /// Last write time (logical monotonic counter).
    pub mtime: u64,
    /// Segment state.
    pub state: SegmentState,
}

impl SegmentInfo {
    /// Create a new full segment (all blocks valid).
    pub fn new_dirty(segno: u32, mtime: u64) -> Self {
        Self {
            segno,
            valid_blocks: BLOCKS_PER_SEG,
            mtime,
            state: SegmentState::Dirty,
        }
    }

    /// Create a free segment.
    pub fn new_free(segno: u32) -> Self {
        Self {
            segno,
            valid_blocks: 0,
            mtime: 0,
            state: SegmentState::Free,
        }
    }

    /// Utilization ratio (0.0 = empty, 1.0 = full).
    pub fn utilization(&self) -> f64 {
        if BLOCKS_PER_SEG == 0 {
            return 0.0;
        }
        self.valid_blocks as f64 / BLOCKS_PER_SEG as f64
    }

    /// GC cost for cost-benefit policy (lower = better victim).
    ///
    /// Cost ≈ (1 - utilization) / age
    pub fn gc_cost(&self, current_time: u64) -> f64 {
        let age = current_time.saturating_sub(self.mtime).max(1) as f64;
        let invalid_ratio = 1.0 - self.utilization();
        invalid_ratio / age
    }
}

/// GC statistics.
#[derive(Debug, Clone, Copy, Default)]
pub struct GcStats {
    /// Number of segments reclaimed.
    pub segments_reclaimed: u64,
    /// Number of blocks migrated.
    pub blocks_migrated: u64,
    /// Number of GC passes (rounds).
    pub gc_rounds: u64,
    /// Number of blocks that failed migration (I/O error).
    pub migration_errors: u64,
}

/// F2FS garbage collector.
pub struct F2fsGc {
    segments: [SegmentInfo; MAX_SEGMENTS],
    seg_count: usize,
    /// Logical time counter (incremented each GC round).
    pub current_time: u64,
    /// GC statistics.
    pub stats: GcStats,
    /// Default victim policy.
    pub policy: VictimPolicy,
    /// Free segment threshold — GC triggers when free segs fall below this.
    pub gc_threshold: usize,
}

impl F2fsGc {
    /// Create a new GC state with `total_segs` segments all free.
    pub fn new(total_segs: usize, policy: VictimPolicy, gc_threshold: usize) -> Result<Self> {
        if total_segs > MAX_SEGMENTS {
            return Err(Error::InvalidArgument);
        }
        let mut gc = Self {
            segments: [SegmentInfo::new_free(0); MAX_SEGMENTS],
            seg_count: total_segs,
            current_time: 0,
            stats: GcStats::default(),
            policy,
            gc_threshold,
        };
        for i in 0..total_segs {
            gc.segments[i] = SegmentInfo::new_free(i as u32);
        }
        Ok(gc)
    }

    /// Mark segment `segno` as dirty (written but not GC'd) with `valid_blocks`.
    pub fn mark_dirty(&mut self, segno: u32, valid_blocks: u32) -> Result<()> {
        let idx = segno as usize;
        if idx >= self.seg_count {
            return Err(Error::InvalidArgument);
        }
        if valid_blocks > BLOCKS_PER_SEG {
            return Err(Error::InvalidArgument);
        }
        self.segments[idx] = SegmentInfo {
            segno,
            valid_blocks,
            mtime: self.current_time,
            state: SegmentState::Dirty,
        };
        Ok(())
    }

    /// Invalidate `count` blocks in segment `segno` (blocks were deleted/overwritten).
    pub fn invalidate_blocks(&mut self, segno: u32, count: u32) -> Result<()> {
        let idx = segno as usize;
        if idx >= self.seg_count {
            return Err(Error::InvalidArgument);
        }
        self.segments[idx].valid_blocks = self.segments[idx].valid_blocks.saturating_sub(count);
        Ok(())
    }

    /// Select the best victim segment using the configured policy.
    ///
    /// Returns the segment index, or `NotFound` if no dirty segment exists.
    pub fn select_victim(&self) -> Result<usize> {
        match self.policy {
            VictimPolicy::Greedy => self.select_victim_greedy(),
            VictimPolicy::CostBenefit => self.select_victim_cost_benefit(),
        }
    }

    fn select_victim_greedy(&self) -> Result<usize> {
        let mut best_idx = None;
        let mut best_valid = u32::MAX;
        for i in 0..self.seg_count {
            let seg = &self.segments[i];
            if seg.state == SegmentState::Dirty && seg.valid_blocks < best_valid {
                best_valid = seg.valid_blocks;
                best_idx = Some(i);
            }
        }
        best_idx.ok_or(Error::NotFound)
    }

    fn select_victim_cost_benefit(&self) -> Result<usize> {
        let mut best_idx = None;
        // Highest cost-benefit ratio (most "worth GC-ing").
        let mut best_score = -1.0f64;
        for i in 0..self.seg_count {
            let seg = &self.segments[i];
            if seg.state != SegmentState::Dirty {
                continue;
            }
            let score = seg.gc_cost(self.current_time);
            if score > best_score {
                best_score = score;
                best_idx = Some(i);
            }
        }
        best_idx.ok_or(Error::NotFound)
    }

    /// Perform one GC round: select victim, migrate valid blocks, free segment.
    ///
    /// `migrate_fn` is called with `(from_segno, valid_block_count)` and must
    /// return `Ok(migrated_count)` on success.
    pub fn run_once<F>(&mut self, _mode: GcMode, mut migrate_fn: F) -> Result<()>
    where
        F: FnMut(u32, u32) -> Result<u32>,
    {
        self.current_time += 1;
        self.stats.gc_rounds += 1;

        let victim_idx = self.select_victim()?;
        let seg = &self.segments[victim_idx];
        let segno = seg.segno;
        let valid = seg.valid_blocks;

        match migrate_fn(segno, valid) {
            Ok(migrated) => {
                self.stats.blocks_migrated += migrated as u64;
                self.segments[victim_idx] = SegmentInfo::new_free(segno);
                self.stats.segments_reclaimed += 1;
            }
            Err(_) => {
                self.stats.migration_errors += 1;
                return Err(Error::IoError);
            }
        }
        Ok(())
    }

    /// Count of free segments.
    pub fn free_segment_count(&self) -> usize {
        self.segments[..self.seg_count]
            .iter()
            .filter(|s| s.state == SegmentState::Free)
            .count()
    }

    /// Whether GC should be triggered (free segments below threshold).
    pub fn should_gc(&self) -> bool {
        self.free_segment_count() < self.gc_threshold
    }
}
