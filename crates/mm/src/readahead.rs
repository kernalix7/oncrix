// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Readahead engine for the ONCRIX page cache.
//!
//! Implements the core readahead engine that pre-fetches file pages before
//! they are explicitly requested by user-space. The engine detects access
//! patterns (sequential, random, strided) and adjusts the readahead window
//! size accordingly to minimize I/O latency while avoiding wasteful prefetch.
//!
//! # Algorithm
//!
//! The readahead engine maintains per-file state:
//! - **Readahead window**: the range of pages currently being prefetched
//! - **Lookahead marker**: the page index at which the next async readahead
//!   is triggered before the current window is exhausted
//! - **Pattern detection**: sequential vs. random access tracking
//!
//! On each page access, the engine checks if the accessed page falls within
//! the current window. If it hits the lookahead marker, a new async readahead
//! is submitted for the next window. Random accesses shrink the window;
//! sequential accesses grow it up to a configured maximum.
//!
//! # Types
//!
//! - [`AccessPattern`] — detected access pattern
//! - [`ReadaheadWindow`] — current window state
//! - [`ReadaheadRequest`] — submitted readahead I/O request
//! - [`FileReadaheadState`] — per-file readahead tracking state
//! - [`ReadaheadConfig`] — global tunable parameters
//! - [`ReadaheadStats`] — aggregate engine statistics
//! - [`ReadaheadEngine`] — top-level engine managing all per-file state
//!
//! Reference: Linux `mm/readahead.c`, `include/linux/mm.h` (ra_state).

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Default initial readahead window size in pages.
const DEFAULT_INITIAL_WINDOW: usize = 8;

/// Default maximum readahead window size in pages (128 KiB at 4 KiB/page).
const DEFAULT_MAX_WINDOW: usize = 32;

/// Minimum readahead window size in pages.
const MIN_WINDOW_PAGES: usize = 1;

/// Maximum number of pages in one readahead request.
const MAX_REQUEST_PAGES: usize = 256;

/// Maximum number of per-file readahead states tracked.
const MAX_FILE_STATES: usize = 128;

/// Maximum number of pending readahead requests.
const MAX_PENDING_REQUESTS: usize = 64;

/// Number of sequential accesses required to grow the window.
const SEQUENTIAL_THRESHOLD: u32 = 2;

/// Factor by which window grows on confirmed sequential access (x2).
const WINDOW_GROW_FACTOR: usize = 2;

/// Factor by which window shrinks on random access (halved).
const WINDOW_SHRINK_FACTOR: usize = 2;

// -------------------------------------------------------------------
// Access pattern
// -------------------------------------------------------------------

/// Detected file access pattern.
///
/// The engine classifies each access to determine whether to grow,
/// shrink, or maintain the readahead window.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AccessPattern {
    /// Access pattern is not yet determined.
    #[default]
    Unknown,
    /// Pages are being read in order — grow window.
    Sequential,
    /// Accesses jump around — shrink window.
    Random,
    /// Pages are accessed at a fixed stride.
    Strided,
}

// -------------------------------------------------------------------
// ReadaheadWindow
// -------------------------------------------------------------------

/// Describes the current readahead window for a file.
///
/// The window spans [`start_page`..`start_page + size`). When the
/// page at `lookahead_index` is accessed, the next window is
/// asynchronously prefetched.
#[derive(Debug, Clone, Copy, Default)]
pub struct ReadaheadWindow {
    /// First page index covered by the current window.
    pub start_page: u64,
    /// Number of pages in the current window.
    pub size: usize,
    /// Page index within the window that triggers the next readahead.
    pub lookahead_index: u64,
    /// Whether the current window was submitted asynchronously.
    pub is_async: bool,
}

impl ReadaheadWindow {
    /// Creates an empty readahead window.
    pub const fn new() -> Self {
        Self {
            start_page: 0,
            size: 0,
            lookahead_index: 0,
            is_async: false,
        }
    }

    /// Returns the exclusive end page index of the window.
    pub fn end_page(&self) -> u64 {
        self.start_page.saturating_add(self.size as u64)
    }

    /// Returns `true` if `page` falls within this window.
    pub fn contains(&self, page: u64) -> bool {
        page >= self.start_page && page < self.end_page()
    }

    /// Returns `true` if `page` is at or beyond the lookahead marker.
    pub fn at_lookahead(&self, page: u64) -> bool {
        page >= self.lookahead_index
    }
}

// -------------------------------------------------------------------
// ReadaheadRequest
// -------------------------------------------------------------------

/// A readahead I/O request submitted by the engine.
///
/// Represents the intent to pre-fetch a contiguous range of pages
/// from backing storage into the page cache.
#[derive(Debug, Clone, Copy)]
pub struct ReadaheadRequest {
    /// Inode/file identifier.
    pub file_id: u64,
    /// Starting page index of the request.
    pub start_page: u64,
    /// Number of pages to prefetch.
    pub nr_pages: usize,
    /// Whether this request is asynchronous.
    pub is_async: bool,
    /// Request generation number for ordering.
    pub generation: u64,
}

impl ReadaheadRequest {
    /// Creates a new readahead request.
    pub const fn new(
        file_id: u64,
        start_page: u64,
        nr_pages: usize,
        is_async: bool,
        generation: u64,
    ) -> Self {
        Self {
            file_id,
            start_page,
            nr_pages,
            is_async,
            generation,
        }
    }
}

// -------------------------------------------------------------------
// FileReadaheadState
// -------------------------------------------------------------------

/// Per-file readahead tracking state.
///
/// Maintained in-memory alongside each open file's metadata. Tracks
/// the current window, the previous access position for pattern
/// detection, and the number of sequential misses.
#[derive(Debug, Clone)]
pub struct FileReadaheadState {
    /// Unique file identifier.
    pub file_id: u64,
    /// Current readahead window.
    pub window: ReadaheadWindow,
    /// Page index of the previous access (for pattern detection).
    pub prev_page: u64,
    /// Detected access pattern.
    pub pattern: AccessPattern,
    /// Number of consecutive sequential accesses.
    pub sequential_count: u32,
    /// Number of consecutive random accesses.
    pub random_count: u32,
    /// Detected stride length (for strided access).
    pub stride: u64,
    /// Whether this state slot is in use.
    pub active: bool,
    /// Generation counter incremented on each window reset.
    pub generation: u64,
}

impl FileReadaheadState {
    /// Creates an empty, inactive state slot.
    pub const fn new() -> Self {
        Self {
            file_id: 0,
            window: ReadaheadWindow::new(),
            prev_page: 0,
            pattern: AccessPattern::Unknown,
            sequential_count: 0,
            random_count: 0,
            stride: 0,
            active: false,
            generation: 0,
        }
    }

    /// Initializes this state for a new file.
    pub fn init(&mut self, file_id: u64, initial_window: usize) {
        self.file_id = file_id;
        self.window = ReadaheadWindow {
            start_page: 0,
            size: initial_window,
            lookahead_index: 0,
            is_async: false,
        };
        self.prev_page = u64::MAX;
        self.pattern = AccessPattern::Unknown;
        self.sequential_count = 0;
        self.random_count = 0;
        self.stride = 0;
        self.active = true;
        self.generation = self.generation.wrapping_add(1);
    }

    /// Classifies the access to `page` and updates pattern tracking.
    pub fn classify_access(&mut self, page: u64) {
        if self.prev_page == u64::MAX {
            self.prev_page = page;
            return;
        }

        let delta = page.wrapping_sub(self.prev_page);
        if delta == 1 {
            self.sequential_count = self.sequential_count.saturating_add(1);
            self.random_count = 0;
            if self.sequential_count >= SEQUENTIAL_THRESHOLD as u32 {
                self.pattern = AccessPattern::Sequential;
            }
        } else if self.stride != 0 && delta == self.stride {
            self.pattern = AccessPattern::Strided;
            self.sequential_count = 0;
        } else {
            self.random_count = self.random_count.saturating_add(1);
            self.sequential_count = 0;
            if self.random_count >= 2 {
                self.pattern = AccessPattern::Random;
            }
            // Detect stride
            if self.stride == 0 && delta > 1 && delta < 64 {
                self.stride = delta;
            }
        }
        self.prev_page = page;
    }
}

impl Default for FileReadaheadState {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// ReadaheadConfig
// -------------------------------------------------------------------

/// Global readahead configuration.
///
/// Tunable parameters controlling readahead behaviour across all files.
#[derive(Debug, Clone)]
pub struct ReadaheadConfig {
    /// Initial window size in pages when a file is first accessed.
    pub initial_window_pages: usize,
    /// Maximum window size in pages.
    pub max_window_pages: usize,
    /// Whether readahead is globally enabled.
    pub enabled: bool,
    /// Whether asynchronous readahead is enabled.
    pub async_enabled: bool,
    /// Lookahead fraction: lookahead triggers at `window_size * lookahead_frac / 16`.
    pub lookahead_frac: usize,
}

impl ReadaheadConfig {
    /// Creates the default readahead configuration.
    pub const fn new() -> Self {
        Self {
            initial_window_pages: DEFAULT_INITIAL_WINDOW,
            max_window_pages: DEFAULT_MAX_WINDOW,
            enabled: true,
            async_enabled: true,
            lookahead_frac: 12, // trigger at 75% of window consumed
        }
    }
}

impl Default for ReadaheadConfig {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// ReadaheadStats
// -------------------------------------------------------------------

/// Aggregate readahead engine statistics.
#[derive(Debug, Default, Clone, Copy)]
pub struct ReadaheadStats {
    /// Total readahead requests submitted.
    pub requests_submitted: u64,
    /// Pages prefetched (hit before eviction).
    pub pages_hit: u64,
    /// Pages prefetched but never accessed (wasted).
    pub pages_wasted: u64,
    /// Synchronous readahead requests.
    pub sync_requests: u64,
    /// Asynchronous readahead requests.
    pub async_requests: u64,
    /// Window growth events.
    pub window_grows: u64,
    /// Window shrink events.
    pub window_shrinks: u64,
}

impl ReadaheadStats {
    /// Creates zeroed statistics.
    pub const fn new() -> Self {
        Self {
            requests_submitted: 0,
            pages_hit: 0,
            pages_wasted: 0,
            sync_requests: 0,
            async_requests: 0,
            window_grows: 0,
            window_shrinks: 0,
        }
    }

    /// Readahead hit rate as a percentage (0–100).
    pub fn hit_rate_pct(&self) -> u8 {
        let total = self.pages_hit + self.pages_wasted;
        if total == 0 {
            return 0;
        }
        ((self.pages_hit * 100) / total).min(100) as u8
    }
}

// -------------------------------------------------------------------
// ReadaheadEngine
// -------------------------------------------------------------------

/// The readahead engine — top-level manager.
///
/// Maintains per-file state for up to [`MAX_FILE_STATES`] open files
/// and a queue of pending readahead requests up to
/// [`MAX_PENDING_REQUESTS`].
pub struct ReadaheadEngine {
    config: ReadaheadConfig,
    states: [FileReadaheadState; MAX_FILE_STATES],
    pending: [Option<ReadaheadRequest>; MAX_PENDING_REQUESTS],
    pending_count: usize,
    stats: ReadaheadStats,
    request_gen: u64,
}

impl ReadaheadEngine {
    /// Creates a new readahead engine with default configuration.
    pub const fn new() -> Self {
        Self {
            config: ReadaheadConfig::new(),
            states: [const { FileReadaheadState::new() }; MAX_FILE_STATES],
            pending: [const { None }; MAX_PENDING_REQUESTS],
            pending_count: 0,
            stats: ReadaheadStats::new(),
            request_gen: 0,
        }
    }

    /// Registers a file for readahead tracking.
    ///
    /// Returns `Err(AlreadyExists)` if the file is already registered or
    /// `Err(OutOfMemory)` if the state table is full.
    pub fn register_file(&mut self, file_id: u64) -> Result<()> {
        // Check for duplicate
        for slot in self.states.iter() {
            if slot.active && slot.file_id == file_id {
                return Err(Error::AlreadyExists);
            }
        }
        // Find empty slot
        for slot in self.states.iter_mut() {
            if !slot.active {
                slot.init(file_id, self.config.initial_window_pages);
                return Ok(());
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Unregisters a file, freeing its state slot.
    pub fn unregister_file(&mut self, file_id: u64) -> Result<()> {
        for slot in self.states.iter_mut() {
            if slot.active && slot.file_id == file_id {
                slot.active = false;
                return Ok(());
            }
        }
        Err(Error::NotFound)
    }

    /// Notifies the engine that `page` was accessed for `file_id`.
    ///
    /// The engine updates the access pattern, possibly adjusts the window,
    /// and enqueues a readahead request if the lookahead marker was hit.
    pub fn on_page_access(&mut self, file_id: u64, page: u64) -> Result<()> {
        if !self.config.enabled {
            return Ok(());
        }

        let state_idx = self.find_state(file_id).ok_or(Error::NotFound)?;
        self.states[state_idx].classify_access(page);

        let pattern = self.states[state_idx].pattern;
        let window = self.states[state_idx].window;
        let max_window = self.config.max_window_pages;
        let initial_window = self.config.initial_window_pages;
        let lookahead_frac = self.config.lookahead_frac;

        // Adjust window based on pattern
        let new_size = match pattern {
            AccessPattern::Sequential => {
                if window.contains(page) && window.at_lookahead(page) {
                    let grown = (window.size * WINDOW_GROW_FACTOR).min(max_window);
                    self.stats.window_grows += 1;
                    grown
                } else {
                    window.size
                }
            }
            AccessPattern::Random => {
                let shrunk = (window.size / WINDOW_SHRINK_FACTOR).max(MIN_WINDOW_PAGES);
                if shrunk < window.size {
                    self.stats.window_shrinks += 1;
                }
                shrunk
            }
            _ => window.size,
        };

        // Build next window
        let next_start = page.saturating_add(1);
        let lookahead_offset = (new_size * lookahead_frac / 16).max(1) as u64;
        let lookahead = next_start.saturating_add(lookahead_offset);

        let new_window = ReadaheadWindow {
            start_page: next_start,
            size: new_size,
            lookahead_index: lookahead,
            is_async: self.config.async_enabled,
        };
        self.states[state_idx].window = new_window;

        // Submit readahead if sequential or strided
        if matches!(pattern, AccessPattern::Sequential | AccessPattern::Strided) {
            let nr = new_size.min(MAX_REQUEST_PAGES).min(initial_window * 2);
            self.submit_request(file_id, next_start, nr, self.config.async_enabled)?;
        }

        Ok(())
    }

    /// Adjusts the configuration.
    pub fn configure(&mut self, config: ReadaheadConfig) -> Result<()> {
        if config.initial_window_pages < MIN_WINDOW_PAGES
            || config.initial_window_pages > MAX_REQUEST_PAGES
            || config.max_window_pages < config.initial_window_pages
        {
            return Err(Error::InvalidArgument);
        }
        self.config = config;
        Ok(())
    }

    /// Drains all pending readahead requests into `out`, returning the count.
    ///
    /// `out` must have capacity for at least [`MAX_PENDING_REQUESTS`] entries.
    pub fn drain_pending(&mut self, out: &mut [ReadaheadRequest]) -> usize {
        let mut count = 0;
        for slot in self.pending.iter_mut() {
            if count >= out.len() {
                break;
            }
            if let Some(req) = slot.take() {
                out[count] = req;
                count += 1;
            }
        }
        self.pending_count = self.pending_count.saturating_sub(count);
        count
    }

    /// Records that `nr_hit` prefetched pages were actually used and
    /// `nr_wasted` were evicted without being accessed.
    pub fn record_hit_miss(&mut self, nr_hit: u64, nr_wasted: u64) {
        self.stats.pages_hit = self.stats.pages_hit.saturating_add(nr_hit);
        self.stats.pages_wasted = self.stats.pages_wasted.saturating_add(nr_wasted);
    }

    /// Returns a snapshot of the engine statistics.
    pub fn stats(&self) -> ReadaheadStats {
        self.stats
    }

    /// Returns the current configuration.
    pub fn config(&self) -> &ReadaheadConfig {
        &self.config
    }

    /// Returns the per-file state for `file_id`, if registered.
    pub fn file_state(&self, file_id: u64) -> Option<&FileReadaheadState> {
        self.states
            .iter()
            .find(|s| s.active && s.file_id == file_id)
    }

    // --- private helpers ---

    fn find_state(&self, file_id: u64) -> Option<usize> {
        self.states
            .iter()
            .position(|s| s.active && s.file_id == file_id)
    }

    fn submit_request(
        &mut self,
        file_id: u64,
        start_page: u64,
        nr_pages: usize,
        is_async: bool,
    ) -> Result<()> {
        if self.pending_count >= MAX_PENDING_REQUESTS {
            return Err(Error::Busy);
        }
        self.request_gen = self.request_gen.wrapping_add(1);
        let req = ReadaheadRequest::new(file_id, start_page, nr_pages, is_async, self.request_gen);

        for slot in self.pending.iter_mut() {
            if slot.is_none() {
                *slot = Some(req);
                self.pending_count += 1;
                if is_async {
                    self.stats.async_requests += 1;
                } else {
                    self.stats.sync_requests += 1;
                }
                self.stats.requests_submitted += 1;
                return Ok(());
            }
        }
        Err(Error::OutOfMemory)
    }
}

impl Default for ReadaheadEngine {
    fn default() -> Self {
        Self::new()
    }
}
