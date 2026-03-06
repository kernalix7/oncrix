// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Readahead state tracking.
//!
//! Implements the per-file readahead state machine that adaptively
//! adjusts the readahead window based on access patterns. Detects
//! sequential reads, random reads, and thrashing (when readahead
//! pages are evicted before use).
//!
//! - [`FileRaState`] — per-file readahead state
//! - [`RaEvent`] — readahead events (hit, miss, thrash)
//! - [`ReadaheadStats`] — aggregate statistics
//! - [`ReadaheadManager`] — manages readahead for multiple files
//!
//! Reference: `.kernelORG/` — `mm/readahead.c`, `include/linux/fs.h`
//! (`struct file_ra_state`).

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Default initial readahead size (in pages).
const DEFAULT_RA_PAGES: u64 = 32;

/// Maximum readahead window (in pages).
const MAX_RA_PAGES: u64 = 256;

/// Minimum readahead window (in pages).
const MIN_RA_PAGES: u64 = 4;

/// Maximum number of tracked files.
const MAX_TRACKED_FILES: usize = 64;

/// Maximum readahead event log entries.
const MAX_RA_EVENTS: usize = 128;

/// Thrashing threshold: if this fraction of RA pages are evicted
/// before use, reduce the window.
const THRASH_THRESHOLD_PERCENT: u64 = 50;

// -------------------------------------------------------------------
// RaEvent
// -------------------------------------------------------------------

/// A readahead event for logging.
#[derive(Debug, Clone, Copy, Default)]
pub struct RaEvent {
    /// File identifier.
    pub file_id: u64,
    /// Page offset that triggered the event.
    pub pgoff: u64,
    /// Readahead window at the time of the event.
    pub ra_size: u64,
    /// Event type.
    pub event_type: RaEventType,
    /// Timestamp (monotonic ns).
    pub timestamp_ns: u64,
}

/// Type of readahead event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RaEventType {
    /// Readahead page was used before eviction (hit).
    #[default]
    Hit,
    /// Readahead page was not in cache when needed (miss).
    Miss,
    /// Readahead page was evicted before use (thrash).
    Thrash,
    /// New readahead window started.
    WindowStart,
    /// Readahead window was expanded (sequential detected).
    WindowExpand,
    /// Readahead window was shrunk (thrash detected).
    WindowShrink,
    /// Random access detected — readahead disabled.
    RandomDetect,
}

// -------------------------------------------------------------------
// FileRaState
// -------------------------------------------------------------------

/// Per-file readahead state.
#[derive(Debug, Clone, Copy, Default)]
pub struct FileRaState {
    /// Start of the current readahead window (page offset).
    pub start: u64,
    /// Size of the current readahead window (pages).
    pub size: u64,
    /// Async readahead size: trigger next RA when this many pages
    /// remain unread.
    pub async_size: u64,
    /// Previous read position (page offset).
    pub prev_pos: u64,
    /// File identifier.
    pub file_id: u64,
    /// Maximum allowed readahead (pages).
    pub ra_max: u64,
    /// Whether readahead is active.
    pub active: bool,
    /// Number of sequential reads detected.
    pub sequential_count: u64,
    /// Number of thrashed (evicted-before-use) pages.
    pub thrash_count: u64,
    /// Total pages read ahead.
    pub total_ra_pages: u64,
}

impl FileRaState {
    /// Creates a new readahead state for a file.
    pub fn new(file_id: u64) -> Self {
        Self {
            file_id,
            size: DEFAULT_RA_PAGES,
            async_size: DEFAULT_RA_PAGES / 4,
            ra_max: MAX_RA_PAGES,
            active: true,
            ..Self::default()
        }
    }

    /// Sets the maximum readahead window.
    pub fn set_max(&mut self, max_pages: u64) {
        self.ra_max = max_pages.min(MAX_RA_PAGES);
    }

    /// Returns `true` if the access at `pgoff` is sequential.
    fn is_sequential(&self, pgoff: u64) -> bool {
        // Within the current or next expected position.
        let expected = self.prev_pos + 1;
        pgoff == expected || (pgoff >= self.start && pgoff < self.start + self.size)
    }

    /// Handles an on-demand readahead trigger.
    ///
    /// Returns the recommended readahead window (start, size).
    pub fn ondemand_readahead(&mut self, pgoff: u64) -> (u64, u64) {
        if self.is_sequential(pgoff) {
            self.sequential_count += 1;
            // Expand window (double, capped at max).
            let new_size = (self.size * 2).min(self.ra_max);
            self.start = pgoff;
            self.size = new_size;
            self.async_size = new_size / 4;
        } else {
            // Random or seek — reset to initial.
            self.sequential_count = 0;
            self.start = pgoff;
            self.size = DEFAULT_RA_PAGES;
            self.async_size = DEFAULT_RA_PAGES / 4;
        }

        self.prev_pos = pgoff;
        self.total_ra_pages += self.size;
        (self.start, self.size)
    }

    /// Handles the initial readahead when the file is first opened.
    pub fn initial_readahead(&mut self) -> (u64, u64) {
        self.start = 0;
        self.size = DEFAULT_RA_PAGES;
        self.async_size = DEFAULT_RA_PAGES / 4;
        self.prev_pos = 0;
        self.total_ra_pages += self.size;
        (0, self.size)
    }

    /// Records a thrash event (RA page evicted before use).
    pub fn record_thrash(&mut self) {
        self.thrash_count += 1;
        // Shrink window if thrashing is excessive.
        if self.size > MIN_RA_PAGES
            && self.thrash_count * 100 > self.total_ra_pages * THRASH_THRESHOLD_PERCENT
        {
            self.size = (self.size / 2).max(MIN_RA_PAGES);
            self.async_size = self.size / 4;
        }
    }

    /// Returns the async trigger offset: when the reader reaches
    /// (start + size - async_size), trigger the next readahead.
    pub fn async_trigger_offset(&self) -> u64 {
        self.start + self.size.saturating_sub(self.async_size)
    }
}

// -------------------------------------------------------------------
// ReadaheadStats
// -------------------------------------------------------------------

/// Aggregate readahead statistics.
#[derive(Debug, Clone, Copy, Default)]
pub struct ReadaheadStats {
    /// Total readahead triggers.
    pub triggers: u64,
    /// Readahead hits.
    pub hits: u64,
    /// Readahead misses.
    pub misses: u64,
    /// Thrash events.
    pub thrashes: u64,
    /// Window expansions.
    pub expansions: u64,
    /// Window shrinks.
    pub shrinks: u64,
    /// Total pages read ahead.
    pub total_pages: u64,
    /// Random access detections.
    pub random_detects: u64,
}

impl ReadaheadStats {
    /// Resets all counters.
    pub fn reset(&mut self) {
        *self = Self::default();
    }
}

// -------------------------------------------------------------------
// ReadaheadManager
// -------------------------------------------------------------------

/// Manages readahead state for multiple files.
pub struct ReadaheadManager {
    /// Per-file readahead states.
    files: [FileRaState; MAX_TRACKED_FILES],
    /// Number of tracked files.
    file_count: usize,
    /// Event log.
    events: [RaEvent; MAX_RA_EVENTS],
    /// Event log count.
    event_count: usize,
    /// Aggregate statistics.
    stats: ReadaheadStats,
}

impl Default for ReadaheadManager {
    fn default() -> Self {
        Self {
            files: [FileRaState::default(); MAX_TRACKED_FILES],
            file_count: 0,
            events: [RaEvent::default(); MAX_RA_EVENTS],
            event_count: 0,
            stats: ReadaheadStats::default(),
        }
    }
}

impl ReadaheadManager {
    /// Creates a new readahead manager.
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers a file for readahead tracking.
    pub fn register_file(&mut self, file_id: u64) -> Result<usize> {
        if self.file_count >= MAX_TRACKED_FILES {
            return Err(Error::OutOfMemory);
        }
        let idx = self.file_count;
        self.files[idx] = FileRaState::new(file_id);
        self.file_count += 1;
        Ok(idx)
    }

    /// Handles an on-demand readahead for the given file.
    pub fn on_demand(
        &mut self,
        file_idx: usize,
        pgoff: u64,
        timestamp_ns: u64,
    ) -> Result<(u64, u64)> {
        if file_idx >= self.file_count {
            return Err(Error::InvalidArgument);
        }

        let old_size = self.files[file_idx].size;
        let (start, size) = self.files[file_idx].ondemand_readahead(pgoff);

        self.stats.triggers += 1;
        self.stats.total_pages += size;

        let event_type = if size > old_size {
            self.stats.expansions += 1;
            RaEventType::WindowExpand
        } else if size < old_size {
            self.stats.shrinks += 1;
            RaEventType::WindowShrink
        } else {
            RaEventType::WindowStart
        };

        self.log_event(RaEvent {
            file_id: self.files[file_idx].file_id,
            pgoff,
            ra_size: size,
            event_type,
            timestamp_ns,
        });

        Ok((start, size))
    }

    /// Records a readahead hit.
    pub fn record_hit(&mut self, file_idx: usize, pgoff: u64, timestamp_ns: u64) -> Result<()> {
        if file_idx >= self.file_count {
            return Err(Error::InvalidArgument);
        }
        self.stats.hits += 1;
        self.log_event(RaEvent {
            file_id: self.files[file_idx].file_id,
            pgoff,
            ra_size: self.files[file_idx].size,
            event_type: RaEventType::Hit,
            timestamp_ns,
        });
        Ok(())
    }

    /// Records a readahead thrash.
    pub fn record_thrash(&mut self, file_idx: usize, pgoff: u64, timestamp_ns: u64) -> Result<()> {
        if file_idx >= self.file_count {
            return Err(Error::InvalidArgument);
        }
        self.files[file_idx].record_thrash();
        self.stats.thrashes += 1;
        self.log_event(RaEvent {
            file_id: self.files[file_idx].file_id,
            pgoff,
            ra_size: self.files[file_idx].size,
            event_type: RaEventType::Thrash,
            timestamp_ns,
        });
        Ok(())
    }

    /// Sets the max readahead for a file.
    pub fn ra_set_pages(&mut self, file_idx: usize, max_pages: u64) -> Result<()> {
        if file_idx >= self.file_count {
            return Err(Error::InvalidArgument);
        }
        self.files[file_idx].set_max(max_pages);
        Ok(())
    }

    /// Returns the readahead state for a file.
    pub fn get_state(&self, file_idx: usize) -> Option<&FileRaState> {
        if file_idx < self.file_count {
            Some(&self.files[file_idx])
        } else {
            None
        }
    }

    /// Returns aggregate statistics.
    pub fn stats(&self) -> &ReadaheadStats {
        &self.stats
    }

    /// Returns the event count.
    pub fn event_count(&self) -> usize {
        self.event_count
    }

    /// Logs a readahead event.
    fn log_event(&mut self, event: RaEvent) {
        if self.event_count < MAX_RA_EVENTS {
            self.events[self.event_count] = event;
            self.event_count += 1;
        }
    }
}
