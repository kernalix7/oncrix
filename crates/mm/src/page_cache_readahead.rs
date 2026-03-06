// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Page cache readahead.
//!
//! Implements adaptive readahead for the page cache, pre-fetching
//! file pages before they are explicitly requested. This reduces
//! I/O latency for sequential and strided access patterns.
//!
//! # Design
//!
//! The readahead algorithm maintains per-file state tracking:
//! - Current readahead window (start offset, size)
//! - Lookahead marker (triggers async readahead)
//! - Access pattern detection (sequential, random, strided)
//!
//! When a page fault or `read()` hits the lookahead page, the window
//! is extended and new pages are submitted for asynchronous I/O.
//! Random accesses shrink the window; sequential accesses grow it.
//!
//! # Types
//!
//! - [`ReadaheadPattern`] — detected access pattern
//! - [`ReadaheadWindow`] — current readahead window state
//! - [`ReadaheadRequest`] — a request to read pages ahead
//! - [`ReadaheadFileState`] — per-file readahead state
//! - [`ReadaheadConfig`] — global readahead configuration
//! - [`ReadaheadManager`] — top-level readahead manager
//! - [`ReadaheadStats`] — summary statistics
//! - [`ReadaheadPageState`] — state of a readahead page
//!
//! Reference: Linux `mm/readahead.c`, `mm/filemap.c`.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Standard page size (4 KiB).
const PAGE_SIZE: u64 = 4096;

/// Default initial readahead window in pages.
const DEFAULT_INITIAL_WINDOW: u32 = 4;

/// Default maximum readahead window in pages.
const DEFAULT_MAX_WINDOW: u32 = 256;

/// Minimum readahead window in pages.
const MIN_WINDOW: u32 = 2;

/// Maximum number of tracked files.
const MAX_FILES: usize = 256;

/// Maximum readahead requests per batch.
const MAX_BATCH_REQUESTS: usize = 64;

/// Sequential threshold: if last N accesses were sequential.
const SEQUENTIAL_THRESHOLD: u32 = 4;

/// Maximum stride length to detect (in pages).
const MAX_STRIDE: u64 = 64;

/// Maximum number of readahead pages in flight.
const MAX_PAGES_IN_FLIGHT: usize = 512;

/// History depth for pattern detection.
const HISTORY_DEPTH: usize = 8;

// -------------------------------------------------------------------
// ReadaheadPattern
// -------------------------------------------------------------------

/// Detected file access pattern.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ReadaheadPattern {
    /// Sequential access (most common for file reads).
    #[default]
    Sequential,
    /// Random access — readahead is suppressed.
    Random,
    /// Strided access (regular intervals).
    Strided,
    /// Interleaved access (multiple sequential streams).
    Interleaved,
    /// Unknown or not enough data.
    Unknown,
}

// -------------------------------------------------------------------
// ReadaheadWindow
// -------------------------------------------------------------------

/// Current readahead window state for a file.
#[derive(Debug, Clone, Copy, Default)]
pub struct ReadaheadWindow {
    /// Start offset of the current window (in pages).
    pub start: u64,
    /// Size of the current window (in pages).
    pub size: u32,
    /// Async readahead trigger offset (in pages).
    pub async_size: u32,
    /// Previous window start.
    pub prev_start: u64,
    /// Previous window size.
    pub prev_size: u32,
}

impl ReadaheadWindow {
    /// Returns the end of the window (exclusive, in pages).
    pub const fn end(&self) -> u64 {
        self.start + self.size as u64
    }

    /// Returns the lookahead offset (in pages).
    pub const fn lookahead_offset(&self) -> u64 {
        self.start + self.size as u64 - self.async_size as u64
    }

    /// Returns whether `page_offset` is within the window.
    pub const fn contains(&self, page_offset: u64) -> bool {
        page_offset >= self.start && page_offset < self.start + self.size as u64
    }

    /// Returns whether `page_offset` hits the lookahead marker.
    pub fn hits_lookahead(&self, page_offset: u64) -> bool {
        if self.async_size == 0 {
            return false;
        }
        page_offset >= self.lookahead_offset() && page_offset < self.end()
    }
}

// -------------------------------------------------------------------
// ReadaheadPageState
// -------------------------------------------------------------------

/// State of a single readahead page.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ReadaheadPageState {
    /// Not yet submitted.
    #[default]
    Pending,
    /// I/O submitted, waiting for completion.
    InFlight,
    /// Successfully read into page cache.
    Cached,
    /// I/O error occurred.
    Failed,
}

// -------------------------------------------------------------------
// ReadaheadRequest
// -------------------------------------------------------------------

/// A request to read pages ahead into the page cache.
#[derive(Debug, Clone, Copy)]
pub struct ReadaheadRequest {
    /// File ID.
    pub file_id: u32,
    /// Start page offset.
    pub start: u64,
    /// Number of pages to read.
    pub nr_pages: u32,
    /// Whether this is an asynchronous readahead.
    pub is_async: bool,
    /// Detected pattern.
    pub pattern: ReadaheadPattern,
}

impl Default for ReadaheadRequest {
    fn default() -> Self {
        Self {
            file_id: 0,
            start: 0,
            nr_pages: 0,
            is_async: false,
            pattern: ReadaheadPattern::Sequential,
        }
    }
}

// -------------------------------------------------------------------
// ReadaheadFileState
// -------------------------------------------------------------------

/// Per-file readahead tracking state.
#[derive(Clone, Copy)]
pub struct ReadaheadFileState {
    /// File identifier.
    pub file_id: u32,
    /// Whether this entry is active.
    pub active: bool,
    /// Current readahead window.
    pub window: ReadaheadWindow,
    /// Detected access pattern.
    pub pattern: ReadaheadPattern,
    /// Recent access history (page offsets).
    pub history: [u64; HISTORY_DEPTH],
    /// Number of valid history entries.
    pub history_len: usize,
    /// Current history write index.
    pub history_idx: usize,
    /// Number of consecutive sequential accesses.
    pub sequential_count: u32,
    /// Detected stride length (in pages).
    pub stride: u64,
    /// Total pages readahead for this file.
    pub total_readahead: u64,
    /// Readahead pages that were actually used.
    pub useful_readahead: u64,
    /// Readahead pages evicted before use.
    pub wasted_readahead: u64,
    /// Whether readahead is disabled for this file.
    pub disabled: bool,
}

impl ReadaheadFileState {
    /// Creates an empty, inactive file state.
    const fn empty() -> Self {
        Self {
            file_id: 0,
            active: false,
            window: ReadaheadWindow {
                start: 0,
                size: 0,
                async_size: 0,
                prev_start: 0,
                prev_size: 0,
            },
            pattern: ReadaheadPattern::Unknown,
            history: [0; HISTORY_DEPTH],
            history_len: 0,
            history_idx: 0,
            sequential_count: 0,
            stride: 0,
            total_readahead: 0,
            useful_readahead: 0,
            wasted_readahead: 0,
            disabled: false,
        }
    }

    /// Records a page access and updates pattern detection.
    fn record_access(&mut self, page_offset: u64) {
        // Store in history ring.
        self.history[self.history_idx] = page_offset;
        self.history_idx = (self.history_idx + 1) % HISTORY_DEPTH;
        if self.history_len < HISTORY_DEPTH {
            self.history_len += 1;
        }
        self.detect_pattern();
    }

    /// Detects the access pattern from recent history.
    fn detect_pattern(&mut self) {
        if self.history_len < 2 {
            self.pattern = ReadaheadPattern::Unknown;
            return;
        }
        // Check for sequential access.
        let mut sequential = 0u32;
        let len = self.history_len;
        for i in 1..len {
            let prev_idx = if self.history_idx >= i + 1 {
                self.history_idx - i - 1
            } else {
                HISTORY_DEPTH + self.history_idx - i - 1
            };
            let curr_idx = if self.history_idx >= i {
                self.history_idx - i
            } else {
                HISTORY_DEPTH + self.history_idx - i
            };
            let prev = self.history[prev_idx % HISTORY_DEPTH];
            let curr = self.history[curr_idx % HISTORY_DEPTH];
            if curr == prev + 1 {
                sequential += 1;
            }
        }
        if sequential >= SEQUENTIAL_THRESHOLD {
            self.pattern = ReadaheadPattern::Sequential;
            self.sequential_count = sequential;
            return;
        }
        // Check for strided access.
        if self.history_len >= 3 {
            let mut strides_match = true;
            let first_stride = self.stride_between(0, 1);
            if first_stride > 0 && first_stride <= MAX_STRIDE {
                for i in 1..self.history_len - 1 {
                    if self.stride_between(i, i + 1) != first_stride {
                        strides_match = false;
                        break;
                    }
                }
                if strides_match {
                    self.pattern = ReadaheadPattern::Strided;
                    self.stride = first_stride;
                    return;
                }
            }
        }
        // Default to random if not sequential or strided.
        self.pattern = ReadaheadPattern::Random;
        self.sequential_count = 0;
    }

    /// Returns the stride between two history entries.
    fn stride_between(&self, older: usize, newer: usize) -> u64 {
        if older >= self.history_len || newer >= self.history_len {
            return 0;
        }
        let oi = if self.history_idx > older {
            self.history_idx - older - 1
        } else {
            HISTORY_DEPTH + self.history_idx - older - 1
        };
        let ni = if self.history_idx > newer {
            self.history_idx - newer - 1
        } else {
            HISTORY_DEPTH + self.history_idx - newer - 1
        };
        let o_val = self.history[oi % HISTORY_DEPTH];
        let n_val = self.history[ni % HISTORY_DEPTH];
        if n_val > o_val {
            n_val - o_val
        } else {
            o_val - n_val
        }
    }

    /// Computes the hit rate (0..100).
    pub fn hit_rate(&self) -> u32 {
        if self.total_readahead == 0 {
            return 0;
        }
        ((self.useful_readahead * 100) / self.total_readahead) as u32
    }
}

impl Default for ReadaheadFileState {
    fn default() -> Self {
        Self::empty()
    }
}

// -------------------------------------------------------------------
// ReadaheadConfig
// -------------------------------------------------------------------

/// Global readahead configuration.
#[derive(Debug, Clone, Copy)]
pub struct ReadaheadConfig {
    /// Initial readahead window size in pages.
    pub initial_window: u32,
    /// Maximum readahead window size in pages.
    pub max_window: u32,
    /// Whether readahead is globally enabled.
    pub enabled: bool,
    /// Whether to use adaptive window sizing.
    pub adaptive: bool,
    /// Window shrink factor for random access (divisor).
    pub random_shrink: u32,
    /// Window growth factor for sequential access (multiplier).
    pub sequential_growth: u32,
}

impl Default for ReadaheadConfig {
    fn default() -> Self {
        Self {
            initial_window: DEFAULT_INITIAL_WINDOW,
            max_window: DEFAULT_MAX_WINDOW,
            enabled: true,
            adaptive: true,
            random_shrink: 4,
            sequential_growth: 2,
        }
    }
}

// -------------------------------------------------------------------
// ReadaheadStats
// -------------------------------------------------------------------

/// Summary statistics for the readahead manager.
#[derive(Debug, Clone, Copy, Default)]
pub struct ReadaheadStats {
    /// Total readahead requests submitted.
    pub total_requests: u64,
    /// Total sync readahead requests.
    pub sync_requests: u64,
    /// Total async readahead requests.
    pub async_requests: u64,
    /// Total pages submitted for readahead.
    pub total_pages: u64,
    /// Total pages that were used (cache hit after readahead).
    pub useful_pages: u64,
    /// Total pages evicted before use (wasted).
    pub wasted_pages: u64,
    /// Number of window expansions.
    pub window_expansions: u64,
    /// Number of window contractions.
    pub window_contractions: u64,
    /// Number of active files tracked.
    pub active_files: u32,
    /// Pages currently in flight.
    pub pages_in_flight: u32,
}

// -------------------------------------------------------------------
// ReadaheadManager
// -------------------------------------------------------------------

/// Top-level readahead manager.
///
/// Manages per-file readahead state, processes page accesses, and
/// generates readahead requests for the I/O subsystem.
pub struct ReadaheadManager {
    /// Per-file state.
    files: [ReadaheadFileState; MAX_FILES],
    /// Global configuration.
    config: ReadaheadConfig,
    /// Pending readahead requests.
    pending: [ReadaheadRequest; MAX_BATCH_REQUESTS],
    /// Number of pending requests.
    nr_pending: usize,
    /// Statistics.
    stats: ReadaheadStats,
    /// Pages currently in flight (file_id, page_offset) pairs.
    in_flight: [(u32, u64); MAX_PAGES_IN_FLIGHT],
    /// Number of pages in flight.
    nr_in_flight: usize,
}

impl ReadaheadManager {
    /// Creates a new readahead manager with default configuration.
    pub fn new() -> Self {
        Self {
            files: [ReadaheadFileState::empty(); MAX_FILES],
            config: ReadaheadConfig::default(),
            pending: [ReadaheadRequest::default(); MAX_BATCH_REQUESTS],
            nr_pending: 0,
            stats: ReadaheadStats::default(),
            in_flight: [(0, 0); MAX_PAGES_IN_FLIGHT],
            nr_in_flight: 0,
        }
    }

    /// Creates a manager with custom configuration.
    pub fn with_config(config: ReadaheadConfig) -> Self {
        let mut mgr = Self::new();
        mgr.config = config;
        mgr
    }

    /// Registers a file for readahead tracking.
    pub fn register_file(&mut self, file_id: u32) -> Result<usize> {
        // Check for duplicates.
        for i in 0..MAX_FILES {
            if self.files[i].active && self.files[i].file_id == file_id {
                return Err(Error::AlreadyExists);
            }
        }
        let idx = self.find_free_file_slot()?;
        self.files[idx] = ReadaheadFileState::empty();
        self.files[idx].file_id = file_id;
        self.files[idx].active = true;
        self.files[idx].window.size = self.config.initial_window;
        self.files[idx].window.async_size = self.config.initial_window / 2;
        self.stats.active_files += 1;
        Ok(idx)
    }

    /// Unregisters a file.
    pub fn unregister_file(&mut self, file_id: u32) -> Result<()> {
        let idx = self.find_file(file_id)?;
        self.files[idx] = ReadaheadFileState::empty();
        self.stats.active_files = self.stats.active_files.saturating_sub(1);
        Ok(())
    }

    /// Called when a page is accessed (read/fault).
    ///
    /// Updates the file's readahead state and may generate readahead
    /// requests.
    pub fn on_page_access(&mut self, file_id: u32, page_offset: u64) -> Result<()> {
        if !self.config.enabled {
            return Ok(());
        }
        let idx = self.find_file(file_id)?;
        if self.files[idx].disabled {
            return Ok(());
        }
        self.files[idx].record_access(page_offset);
        // Check if we hit the lookahead marker.
        if self.files[idx].window.hits_lookahead(page_offset) {
            self.trigger_async_readahead(idx)?;
        }
        // If outside the window, trigger sync readahead.
        if !self.files[idx].window.contains(page_offset) {
            self.trigger_sync_readahead(idx, page_offset)?;
        }
        Ok(())
    }

    /// Marks a readahead page as having been used.
    pub fn mark_page_used(&mut self, file_id: u32, _page_offset: u64) -> Result<()> {
        let idx = self.find_file(file_id)?;
        self.files[idx].useful_readahead += 1;
        self.stats.useful_pages += 1;
        Ok(())
    }

    /// Marks a readahead page as wasted (evicted before use).
    pub fn mark_page_wasted(&mut self, file_id: u32, _page_offset: u64) -> Result<()> {
        let idx = self.find_file(file_id)?;
        self.files[idx].wasted_readahead += 1;
        self.stats.wasted_pages += 1;
        Ok(())
    }

    /// Takes the next pending readahead request.
    pub fn take_pending(&mut self) -> Option<ReadaheadRequest> {
        if self.nr_pending == 0 {
            return None;
        }
        self.nr_pending -= 1;
        Some(self.pending[self.nr_pending])
    }

    /// Returns the number of pending readahead requests.
    pub const fn nr_pending(&self) -> usize {
        self.nr_pending
    }

    /// Completes an in-flight readahead page.
    pub fn complete_page(&mut self, file_id: u32, page_offset: u64) -> Result<()> {
        for i in 0..self.nr_in_flight {
            if self.in_flight[i] == (file_id, page_offset) {
                let last = self.nr_in_flight - 1;
                self.in_flight[i] = self.in_flight[last];
                self.nr_in_flight -= 1;
                self.stats.pages_in_flight = self.stats.pages_in_flight.saturating_sub(1);
                return Ok(());
            }
        }
        Err(Error::NotFound)
    }

    /// Returns the readahead state for a file.
    pub fn file_state(&self, file_id: u32) -> Result<&ReadaheadFileState> {
        let idx = self.find_file(file_id)?;
        Ok(&self.files[idx])
    }

    /// Enables or disables readahead for a specific file.
    pub fn set_file_enabled(&mut self, file_id: u32, enabled: bool) -> Result<()> {
        let idx = self.find_file(file_id)?;
        self.files[idx].disabled = !enabled;
        Ok(())
    }

    /// Updates the global configuration.
    pub fn set_config(&mut self, config: ReadaheadConfig) {
        self.config = config;
    }

    /// Returns the global configuration.
    pub const fn config(&self) -> &ReadaheadConfig {
        &self.config
    }

    /// Returns summary statistics.
    pub const fn stats(&self) -> &ReadaheadStats {
        &self.stats
    }

    /// Resets all state.
    pub fn reset(&mut self) {
        *self = Self::new();
    }

    // ---------------------------------------------------------------
    // Private helpers
    // ---------------------------------------------------------------

    /// Triggers synchronous readahead at the given offset.
    fn trigger_sync_readahead(&mut self, file_idx: usize, page_offset: u64) -> Result<()> {
        let window_size = self.compute_window_size(file_idx);
        let async_size = window_size / 2;
        // Save previous window.
        self.files[file_idx].window.prev_start = self.files[file_idx].window.start;
        self.files[file_idx].window.prev_size = self.files[file_idx].window.size;
        // Set new window.
        self.files[file_idx].window.start = page_offset;
        self.files[file_idx].window.size = window_size;
        self.files[file_idx].window.async_size = async_size;
        self.submit_readahead(file_idx, page_offset, window_size, false)
    }

    /// Triggers asynchronous readahead at the window end.
    fn trigger_async_readahead(&mut self, file_idx: usize) -> Result<()> {
        let window_size = self.compute_window_size(file_idx);
        let async_size = window_size / 2;
        let start = self.files[file_idx].window.end();
        // Extend the window.
        self.files[file_idx].window.prev_start = self.files[file_idx].window.start;
        self.files[file_idx].window.prev_size = self.files[file_idx].window.size;
        self.files[file_idx].window.start = start;
        self.files[file_idx].window.size = window_size;
        self.files[file_idx].window.async_size = async_size;
        self.submit_readahead(file_idx, start, window_size, true)
    }

    /// Computes the optimal window size for a file based on pattern.
    fn compute_window_size(&mut self, file_idx: usize) -> u32 {
        let current = self.files[file_idx].window.size;
        if !self.config.adaptive {
            return self.config.initial_window;
        }
        let new_size = match self.files[file_idx].pattern {
            ReadaheadPattern::Sequential => {
                let grown = current.saturating_mul(self.config.sequential_growth);
                self.stats.window_expansions += 1;
                grown
            }
            ReadaheadPattern::Random => {
                let shrunk = current / self.config.random_shrink;
                self.stats.window_contractions += 1;
                shrunk
            }
            ReadaheadPattern::Strided => {
                // Use stride to determine pages to fetch.
                let stride = self.files[file_idx].stride;
                if stride > 0 {
                    let pages = (current as u64 * stride / PAGE_SIZE) as u32;
                    if pages > MIN_WINDOW { pages } else { current }
                } else {
                    current
                }
            }
            _ => current,
        };
        // Clamp to [MIN_WINDOW, max_window].
        if new_size < MIN_WINDOW {
            MIN_WINDOW
        } else if new_size > self.config.max_window {
            self.config.max_window
        } else {
            new_size
        }
    }

    /// Submits a readahead request.
    fn submit_readahead(
        &mut self,
        file_idx: usize,
        start: u64,
        nr_pages: u32,
        is_async: bool,
    ) -> Result<()> {
        if self.nr_pending >= MAX_BATCH_REQUESTS {
            return Err(Error::Busy);
        }
        let file_id = self.files[file_idx].file_id;
        let pattern = self.files[file_idx].pattern;
        self.pending[self.nr_pending] = ReadaheadRequest {
            file_id,
            start,
            nr_pages,
            is_async,
            pattern,
        };
        self.nr_pending += 1;
        // Track in-flight pages.
        for p in 0..nr_pages as u64 {
            if self.nr_in_flight < MAX_PAGES_IN_FLIGHT {
                self.in_flight[self.nr_in_flight] = (file_id, start + p);
                self.nr_in_flight += 1;
                self.stats.pages_in_flight += 1;
            }
        }
        self.files[file_idx].total_readahead += nr_pages as u64;
        self.stats.total_requests += 1;
        self.stats.total_pages += nr_pages as u64;
        if is_async {
            self.stats.async_requests += 1;
        } else {
            self.stats.sync_requests += 1;
        }
        Ok(())
    }

    fn find_file(&self, file_id: u32) -> Result<usize> {
        for i in 0..MAX_FILES {
            if self.files[i].active && self.files[i].file_id == file_id {
                return Ok(i);
            }
        }
        Err(Error::NotFound)
    }

    fn find_free_file_slot(&self) -> Result<usize> {
        for i in 0..MAX_FILES {
            if !self.files[i].active {
                return Ok(i);
            }
        }
        Err(Error::OutOfMemory)
    }
}

impl Default for ReadaheadManager {
    fn default() -> Self {
        Self::new()
    }
}
