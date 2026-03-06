// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Address space mapping writeback control.
//!
//! Manages the writeback of dirty pages from address space mappings
//! (file-backed and anonymous) to their backing store. Coordinates
//! writeback scheduling, bandwidth throttling, and dirty page
//! tracking per mapping.
//!
//! - [`WritebackState`] — writeback lifecycle state
//! - [`WritebackControl`] — per-writeback-request parameters
//! - [`MappingWriteback`] — per-mapping writeback state
//! - [`WritebackStats`] — aggregate writeback statistics
//! - [`WritebackScheduler`] — schedules writeback across mappings
//!
//! Reference: Linux `mm/page-writeback.c`, `fs/fs-writeback.c`.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Maximum mappings tracked.
const MAX_MAPPINGS: usize = 128;

/// Default dirty ratio (percentage × 10, i.e., 200 = 20%).
const DEFAULT_DIRTY_RATIO: u32 = 200;

/// Default writeback batch size in pages.
const DEFAULT_BATCH_PAGES: u64 = 32;

/// Default bandwidth limit in pages per second.
const DEFAULT_BW_LIMIT: u64 = 4096;

// -------------------------------------------------------------------
// WritebackState
// -------------------------------------------------------------------

/// Writeback lifecycle state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum WritebackState {
    /// No writeback in progress.
    #[default]
    Idle,
    /// Writeback is scheduled.
    Scheduled,
    /// Writeback is in progress.
    InProgress,
    /// Writeback completed.
    Completed,
    /// Writeback failed.
    Failed,
}

// -------------------------------------------------------------------
// WritebackControl
// -------------------------------------------------------------------

/// Parameters for a single writeback request.
#[derive(Debug, Clone, Copy)]
pub struct WritebackControl {
    /// Maximum pages to write.
    pub nr_to_write: u64,
    /// Pages written so far.
    pub pages_written: u64,
    /// Whether this is a sync writeback.
    pub sync_mode: bool,
    /// Whether to write pages in range only.
    pub range_start: u64,
    /// End of the range (0 = entire mapping).
    pub range_end: u64,
    /// Whether to skip pages under writeback.
    pub skip_writeback: bool,
}

impl Default for WritebackControl {
    fn default() -> Self {
        Self {
            nr_to_write: DEFAULT_BATCH_PAGES,
            pages_written: 0,
            sync_mode: false,
            range_start: 0,
            range_end: 0,
            skip_writeback: true,
        }
    }
}

impl WritebackControl {
    /// Returns `true` if the writeback request is complete.
    pub fn is_done(&self) -> bool {
        self.pages_written >= self.nr_to_write
    }

    /// Records pages written.
    pub fn account(&mut self, nr_pages: u64) {
        self.pages_written = self.pages_written.saturating_add(nr_pages);
    }
}

// -------------------------------------------------------------------
// MappingWriteback
// -------------------------------------------------------------------

/// Per-mapping writeback tracking state.
#[derive(Debug, Clone, Copy, Default)]
pub struct MappingWriteback {
    /// Mapping identifier (inode number or anonymous ID).
    pub mapping_id: u64,
    /// Number of dirty pages.
    pub dirty_pages: u64,
    /// Number of pages under writeback.
    pub writeback_pages: u64,
    /// Current writeback state.
    pub state: WritebackState,
    /// Total pages written back since creation.
    pub total_written: u64,
    /// Whether this mapping is active.
    pub active: bool,
}

impl MappingWriteback {
    /// Creates a new mapping writeback tracker.
    pub fn new(mapping_id: u64) -> Self {
        Self {
            mapping_id,
            dirty_pages: 0,
            writeback_pages: 0,
            state: WritebackState::Idle,
            total_written: 0,
            active: true,
        }
    }

    /// Marks pages as dirty.
    pub fn mark_dirty(&mut self, nr_pages: u64) {
        self.dirty_pages = self.dirty_pages.saturating_add(nr_pages);
    }

    /// Starts writeback for a batch of dirty pages.
    pub fn start_writeback(&mut self, nr_pages: u64) -> u64 {
        let to_write = nr_pages.min(self.dirty_pages);
        self.dirty_pages -= to_write;
        self.writeback_pages = self.writeback_pages.saturating_add(to_write);
        self.state = WritebackState::InProgress;
        to_write
    }

    /// Completes writeback for a batch of pages.
    pub fn complete_writeback(&mut self, nr_pages: u64) {
        let completed = nr_pages.min(self.writeback_pages);
        self.writeback_pages -= completed;
        self.total_written = self.total_written.saturating_add(completed);
        if self.writeback_pages == 0 {
            self.state = WritebackState::Idle;
        }
    }

    /// Returns the dirty ratio (per-mille).
    pub fn dirty_ratio(&self, total_pages: u64) -> u32 {
        if total_pages == 0 {
            return 0;
        }
        ((self.dirty_pages * 1000) / total_pages) as u32
    }
}

// -------------------------------------------------------------------
// WritebackStats
// -------------------------------------------------------------------

/// Aggregate writeback statistics.
#[derive(Debug, Clone, Copy, Default)]
pub struct WritebackStats {
    /// Total writeback operations started.
    pub wb_started: u64,
    /// Total writeback operations completed.
    pub wb_completed: u64,
    /// Total pages written back.
    pub pages_written: u64,
    /// Throttle events (bandwidth exceeded).
    pub throttle_events: u64,
    /// Dirty ratio limit hits.
    pub dirty_limit_hits: u64,
}

impl WritebackStats {
    /// Resets all counters.
    pub fn reset(&mut self) {
        *self = Self::default();
    }
}

// -------------------------------------------------------------------
// WritebackScheduler
// -------------------------------------------------------------------

/// Schedules writeback across multiple mappings.
pub struct WritebackScheduler {
    /// Tracked mappings.
    mappings: [MappingWriteback; MAX_MAPPINGS],
    /// Number of active mappings.
    count: usize,
    /// Dirty ratio threshold (per-mille).
    dirty_ratio: u32,
    /// Bandwidth limit (pages per second).
    bw_limit: u64,
    /// Pages written in current bandwidth window.
    bw_current: u64,
    /// Statistics.
    stats: WritebackStats,
}

impl Default for WritebackScheduler {
    fn default() -> Self {
        Self {
            mappings: [MappingWriteback::default(); MAX_MAPPINGS],
            count: 0,
            dirty_ratio: DEFAULT_DIRTY_RATIO,
            bw_limit: DEFAULT_BW_LIMIT,
            bw_current: 0,
            stats: WritebackStats::default(),
        }
    }
}

impl WritebackScheduler {
    /// Creates a new writeback scheduler.
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers a mapping for writeback tracking.
    pub fn register_mapping(&mut self, mapping_id: u64) -> Result<usize> {
        if self.count >= MAX_MAPPINGS {
            return Err(Error::OutOfMemory);
        }
        let idx = self.count;
        self.mappings[idx] = MappingWriteback::new(mapping_id);
        self.count += 1;
        Ok(idx)
    }

    /// Unregisters a mapping.
    pub fn unregister_mapping(&mut self, idx: usize) -> Result<()> {
        if idx >= self.count || !self.mappings[idx].active {
            return Err(Error::NotFound);
        }
        self.mappings[idx].active = false;
        Ok(())
    }

    /// Schedules writeback for mappings that exceed the dirty ratio.
    pub fn schedule(&mut self, total_pages: u64) -> u64 {
        let mut total_written = 0u64;

        for i in 0..self.count {
            if !self.mappings[i].active {
                continue;
            }
            if self.mappings[i].dirty_ratio(total_pages) < self.dirty_ratio {
                continue;
            }
            if self.bw_current >= self.bw_limit {
                self.stats.throttle_events += 1;
                break;
            }
            let batch = DEFAULT_BATCH_PAGES.min(self.bw_limit.saturating_sub(self.bw_current));
            let written = self.mappings[i].start_writeback(batch);
            self.mappings[i].complete_writeback(written);
            self.bw_current = self.bw_current.saturating_add(written);
            total_written += written;
            self.stats.wb_started += 1;
            self.stats.wb_completed += 1;
        }

        self.stats.pages_written += total_written;
        total_written
    }

    /// Resets the bandwidth window.
    pub fn reset_bandwidth(&mut self) {
        self.bw_current = 0;
    }

    /// Returns the number of tracked mappings.
    pub fn mapping_count(&self) -> usize {
        self.count
    }

    /// Returns statistics.
    pub fn stats(&self) -> &WritebackStats {
        &self.stats
    }

    /// Resets statistics.
    pub fn reset_stats(&mut self) {
        self.stats.reset();
    }
}
