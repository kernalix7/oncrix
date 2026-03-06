// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! RCU segmented callback list.
//!
//! Manages RCU callbacks in a segmented list partitioned by grace
//! period number. Each segment corresponds to a range of grace
//! periods, allowing efficient batch advancement and extraction
//! of mature callbacks.
//!
//! # Segment Structure
//!
//! ```text
//! ┌──────────────────────────────────────────────────────────┐
//! │                   RcuSegCbList                            │
//! │                                                          │
//! │  Segment 0 (DONE)     ← callbacks whose GP completed    │
//! │  ┌────────────────────────────────────────┐              │
//! │  │ cb cb cb cb ...                         │              │
//! │  └────────────────────────────────────────┘              │
//! │                                                          │
//! │  Segment 1 (WAIT_TAIL) ← waiting for current GP         │
//! │  ┌────────────────────────────────────────┐              │
//! │  │ cb cb ...                               │              │
//! │  └────────────────────────────────────────┘              │
//! │                                                          │
//! │  Segment 2 (NEXT_TAIL) ← waiting for next GP            │
//! │  ┌────────────────────────────────────────┐              │
//! │  │ cb cb cb ...                            │              │
//! │  └────────────────────────────────────────┘              │
//! │                                                          │
//! │  Segment 3 (NEXT_READY) ← not yet assigned a GP         │
//! │  ┌────────────────────────────────────────┐              │
//! │  │ cb cb ...                               │              │
//! │  └────────────────────────────────────────┘              │
//! └──────────────────────────────────────────────────────────┘
//! ```
//!
//! # Advancement
//!
//! When a grace period completes (GP number N), all callbacks in
//! segment 1 (waiting for GP N) move to segment 0 (DONE).
//! Segment 2 slides into segment 1, etc.
//!
//! # Reference
//!
//! Linux `kernel/rcu/rcu_segcblist.h`, `kernel/rcu/rcu_segcblist.c`.

use oncrix_lib::{Error, Result};

// ======================================================================
// Constants
// ======================================================================

/// Number of segments in the callback list.
const NUM_SEGMENTS: usize = 4;

/// Maximum callbacks per segment.
const MAX_CBS_PER_SEGMENT: usize = 256;

/// Total maximum callbacks across all segments.
const MAX_TOTAL_CBS: usize = NUM_SEGMENTS * MAX_CBS_PER_SEGMENT;

/// Segment index: callbacks whose grace period has completed.
const SEG_DONE: usize = 0;

/// Segment index: callbacks waiting for the current grace period.
const SEG_WAIT: usize = 1;

/// Segment index: callbacks waiting for the next grace period.
const SEG_NEXT: usize = 2;

/// Segment index: callbacks not yet assigned a grace period.
const SEG_READY: usize = 3;

// ======================================================================
// SegmentState — lifecycle state of a segment
// ======================================================================

/// State of a callback segment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SegmentState {
    /// Segment contains no callbacks.
    #[default]
    Empty,
    /// Segment is accumulating new callbacks.
    Accumulating,
    /// Segment is waiting for a grace period.
    WaitingGp,
    /// Grace period completed; callbacks ready for invocation.
    Done,
}

// ======================================================================
// CallbackEntry — a single RCU callback
// ======================================================================

/// A single RCU callback entry.
#[derive(Debug, Clone, Copy)]
pub struct CallbackEntry {
    /// Unique callback ID.
    pub id: u64,
    /// Function identifier (used to dispatch to the actual handler).
    pub func_id: u64,
    /// Opaque data passed to the callback.
    pub data: u64,
    /// Grace period number this callback is associated with.
    pub gp_num: u64,
    /// Whether this entry is in use.
    pub active: bool,
}

impl CallbackEntry {
    /// Create an empty (inactive) callback entry.
    const fn empty() -> Self {
        Self {
            id: 0,
            func_id: 0,
            data: 0,
            gp_num: 0,
            active: false,
        }
    }
}

// ======================================================================
// CbSegment — one segment of the callback list
// ======================================================================

/// A single segment of the RCU segmented callback list.
#[derive(Debug, Clone, Copy)]
pub struct CbSegment {
    /// Callbacks in this segment.
    callbacks: [CallbackEntry; MAX_CBS_PER_SEGMENT],
    /// Number of active callbacks.
    count: usize,
    /// Segment lifecycle state.
    state: SegmentState,
    /// Grace period number this segment is associated with.
    gp_num: u64,
}

impl CbSegment {
    /// Create an empty segment.
    const fn empty() -> Self {
        Self {
            callbacks: [const { CallbackEntry::empty() }; MAX_CBS_PER_SEGMENT],
            count: 0,
            state: SegmentState::Empty,
            gp_num: 0,
        }
    }

    /// Add a callback to this segment.
    fn push(&mut self, entry: CallbackEntry) -> Result<()> {
        if self.count >= MAX_CBS_PER_SEGMENT {
            return Err(Error::OutOfMemory);
        }
        self.callbacks[self.count] = entry;
        self.count += 1;
        if self.state == SegmentState::Empty {
            self.state = SegmentState::Accumulating;
        }
        Ok(())
    }

    /// Remove and return all callbacks, resetting the segment.
    fn drain(&mut self) -> (usize, u64) {
        let count = self.count;
        let gp = self.gp_num;
        // Mark all entries inactive.
        for i in 0..self.count {
            self.callbacks[i].active = false;
        }
        self.count = 0;
        self.state = SegmentState::Empty;
        self.gp_num = 0;
        (count, gp)
    }

    /// Number of active callbacks in this segment.
    fn len(&self) -> usize {
        self.count
    }

    /// Whether this segment has no callbacks.
    fn is_empty(&self) -> bool {
        self.count == 0
    }
}

/// Move all active callbacks from `segments[src]` into
/// `segments[dst]`, then clear the source segment.
///
/// Uses `split_at_mut` to obtain disjoint mutable borrows.
fn move_segment(segments: &mut [CbSegment; NUM_SEGMENTS], dst: usize, src: usize) -> Result<()> {
    if dst == src {
        return Ok(());
    }

    // Collect source callbacks into a local buffer to avoid
    // aliasing issues.
    let src_count = segments[src].count;
    let mut buf = [const { CallbackEntry::empty() }; MAX_CBS_PER_SEGMENT];
    let mut buf_count = 0usize;
    for i in 0..src_count {
        if segments[src].callbacks[i].active {
            buf[buf_count] = segments[src].callbacks[i];
            buf_count += 1;
        }
    }

    // Clear source.
    segments[src].count = 0;
    segments[src].state = SegmentState::Empty;

    // Push into destination.
    for i in 0..buf_count {
        segments[dst].push(buf[i])?;
    }

    Ok(())
}

// ======================================================================
// SegCbStats — statistics for the segmented callback list
// ======================================================================

/// Statistics for the RCU segmented callback list.
#[derive(Debug, Clone, Copy)]
pub struct SegCbStats {
    /// Total callbacks enqueued since creation.
    pub total_enqueued: u64,
    /// Total callbacks extracted (invoked).
    pub total_extracted: u64,
    /// Total segment advancements.
    pub total_advances: u64,
    /// Total accelerations (early GP assignment).
    pub total_accelerations: u64,
    /// Peak total callback count.
    pub peak_count: usize,
    /// Current total callback count.
    pub current_count: usize,
}

impl SegCbStats {
    /// Create zeroed statistics.
    const fn new() -> Self {
        Self {
            total_enqueued: 0,
            total_extracted: 0,
            total_advances: 0,
            total_accelerations: 0,
            peak_count: 0,
            current_count: 0,
        }
    }

    /// Update peak count if current exceeds it.
    fn update_peak(&mut self) {
        if self.current_count > self.peak_count {
            self.peak_count = self.current_count;
        }
    }
}

// ======================================================================
// RcuSegCbList — the segmented callback list
// ======================================================================

/// RCU segmented callback list.
///
/// Manages callbacks across [`NUM_SEGMENTS`] segments for efficient
/// grace-period-based batch processing.
pub struct RcuSegCbList {
    /// The four segments.
    segments: [CbSegment; NUM_SEGMENTS],
    /// Next unique callback ID.
    next_id: u64,
    /// Current grace period number.
    current_gp: u64,
    /// Statistics.
    stats: SegCbStats,
    /// Whether the list is enabled (accepts new callbacks).
    enabled: bool,
    /// Extraction buffer for done callbacks.
    extract_buf: [CallbackEntry; MAX_CBS_PER_SEGMENT],
    /// Number of entries in the extraction buffer.
    extract_count: usize,
}

impl RcuSegCbList {
    /// Create a new empty segmented callback list.
    pub const fn new() -> Self {
        Self {
            segments: [const { CbSegment::empty() }; NUM_SEGMENTS],
            next_id: 1,
            current_gp: 0,
            stats: SegCbStats::new(),
            enabled: true,
            extract_buf: [const { CallbackEntry::empty() }; MAX_CBS_PER_SEGMENT],
            extract_count: 0,
        }
    }

    /// Enqueue a new callback.
    ///
    /// The callback is placed in the READY segment (not yet assigned
    /// to a grace period). Returns the unique callback ID.
    pub fn enqueue(&mut self, func_id: u64, data: u64) -> Result<u64> {
        if !self.enabled {
            return Err(Error::PermissionDenied);
        }

        let total = self.total_pending();
        if total >= MAX_TOTAL_CBS {
            return Err(Error::OutOfMemory);
        }

        let id = self.next_id;
        self.next_id += 1;

        let entry = CallbackEntry {
            id,
            func_id,
            data,
            gp_num: 0, // Not yet assigned.
            active: true,
        };

        self.segments[SEG_READY].push(entry)?;

        self.stats.total_enqueued += 1;
        self.stats.current_count += 1;
        self.stats.update_peak();

        Ok(id)
    }

    /// Advance segments after a grace period completes.
    ///
    /// `completed_gp` is the grace period number that just finished.
    /// Callbacks in WAIT (segment 1) move to DONE (segment 0).
    /// NEXT (segment 2) moves to WAIT (segment 1), etc.
    pub fn advance_segments(&mut self, completed_gp: u64) -> Result<usize> {
        if completed_gp < self.current_gp {
            return Err(Error::InvalidArgument);
        }
        self.current_gp = completed_gp;

        // Move WAIT -> DONE.
        if self.segments[SEG_WAIT].state == SegmentState::WaitingGp
            && self.segments[SEG_WAIT].gp_num <= completed_gp
        {
            move_segment(&mut self.segments, SEG_DONE, SEG_WAIT)?;
            self.segments[SEG_DONE].state = SegmentState::Done;
        }

        // Move NEXT -> WAIT.
        if !self.segments[SEG_NEXT].is_empty() {
            let next_gp = completed_gp + 1;
            move_segment(&mut self.segments, SEG_WAIT, SEG_NEXT)?;
            self.segments[SEG_WAIT].state = SegmentState::WaitingGp;
            self.segments[SEG_WAIT].gp_num = next_gp;
        }

        // Move READY -> NEXT.
        if !self.segments[SEG_READY].is_empty() {
            let next_next_gp = completed_gp + 2;
            move_segment(&mut self.segments, SEG_NEXT, SEG_READY)?;
            self.segments[SEG_NEXT].state = SegmentState::WaitingGp;
            self.segments[SEG_NEXT].gp_num = next_next_gp;
        }

        self.stats.total_advances += 1;
        Ok(self.segments[SEG_DONE].len())
    }

    /// Extract completed (DONE) callbacks.
    ///
    /// Returns the number of callbacks extracted. The extracted
    /// callbacks can be retrieved via [`get_extracted`].
    pub fn extract_done(&mut self) -> usize {
        self.extract_count = 0;

        let count = self.segments[SEG_DONE].len();

        for i in 0..count {
            if self.segments[SEG_DONE].callbacks[i].active {
                self.extract_buf[self.extract_count] = self.segments[SEG_DONE].callbacks[i];
                self.extract_count += 1;
            }
        }

        self.segments[SEG_DONE].drain();

        if self.stats.current_count >= self.extract_count {
            self.stats.current_count -= self.extract_count;
        } else {
            self.stats.current_count = 0;
        }
        self.stats.total_extracted += self.extract_count as u64;

        self.extract_count
    }

    /// Get a reference to an extracted callback by index.
    pub fn get_extracted(&self, index: usize) -> Result<&CallbackEntry> {
        if index >= self.extract_count {
            return Err(Error::InvalidArgument);
        }
        Ok(&self.extract_buf[index])
    }

    /// Count the total number of pending callbacks across all
    /// segments.
    pub fn count_pending(&self) -> usize {
        self.total_pending()
    }

    /// Internal helper to compute total pending callbacks.
    fn total_pending(&self) -> usize {
        self.segments.iter().map(|s| s.len()).sum()
    }

    /// Count callbacks in a specific segment.
    pub fn count_segment(&self, segment: usize) -> Result<usize> {
        if segment >= NUM_SEGMENTS {
            return Err(Error::InvalidArgument);
        }
        Ok(self.segments[segment].len())
    }

    /// Accelerate callbacks by moving READY directly to NEXT.
    ///
    /// Called when a new grace period is starting and we want to
    /// assign not-yet-assigned callbacks to it immediately.
    pub fn accelerate(&mut self, gp_num: u64) -> Result<usize> {
        if self.segments[SEG_READY].is_empty() {
            return Ok(0);
        }

        let count = self.segments[SEG_READY].len();

        // Assign the current GP to ready callbacks and move to NEXT.
        if self.segments[SEG_NEXT].is_empty() {
            // Move directly: READY into NEXT.
            move_segment(&mut self.segments, SEG_NEXT, SEG_READY)?;
            self.segments[SEG_NEXT].state = SegmentState::WaitingGp;
            self.segments[SEG_NEXT].gp_num = gp_num;
        } else {
            // NEXT is occupied; assign to NEXT's GP and merge.
            move_segment(&mut self.segments, SEG_NEXT, SEG_READY)?;
        }

        self.stats.total_accelerations += 1;
        Ok(count)
    }

    /// Get the state of a segment.
    pub fn segment_state(&self, segment: usize) -> Result<SegmentState> {
        if segment >= NUM_SEGMENTS {
            return Err(Error::InvalidArgument);
        }
        Ok(self.segments[segment].state)
    }

    /// Get the grace period number associated with a segment.
    pub fn segment_gp(&self, segment: usize) -> Result<u64> {
        if segment >= NUM_SEGMENTS {
            return Err(Error::InvalidArgument);
        }
        Ok(self.segments[segment].gp_num)
    }

    /// Get a reference to the statistics.
    pub fn list_stats(&self) -> &SegCbStats {
        &self.stats
    }

    /// Get the current grace period number.
    pub fn current_gp(&self) -> u64 {
        self.current_gp
    }

    /// Enable the callback list (allow new enqueues).
    pub fn enable(&mut self) {
        self.enabled = true;
    }

    /// Disable the callback list (reject new enqueues).
    pub fn disable(&mut self) {
        self.enabled = false;
    }

    /// Check whether the list is enabled.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Check whether there are any done callbacks ready to extract.
    pub fn has_done(&self) -> bool {
        !self.segments[SEG_DONE].is_empty()
    }

    /// Check whether there are any callbacks waiting for a GP.
    pub fn has_waiting(&self) -> bool {
        !self.segments[SEG_WAIT].is_empty() || !self.segments[SEG_NEXT].is_empty()
    }

    /// Check whether the list is completely empty.
    pub fn is_empty(&self) -> bool {
        self.total_pending() == 0
    }

    /// Get the number of extracted callbacks from the last
    /// `extract_done()` call.
    pub fn extracted_count(&self) -> usize {
        self.extract_count
    }

    /// Flush all segments, discarding all pending callbacks.
    pub fn flush(&mut self) {
        for seg in &mut self.segments {
            seg.drain();
        }
        self.stats.current_count = 0;
    }

    /// Get a summary of per-segment counts.
    pub fn segment_counts(&self) -> [usize; NUM_SEGMENTS] {
        [
            self.segments[SEG_DONE].len(),
            self.segments[SEG_WAIT].len(),
            self.segments[SEG_NEXT].len(),
            self.segments[SEG_READY].len(),
        ]
    }
}
