// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Read-ahead optimization for the VFS page cache.
//!
//! Detects sequential and strided access patterns and pre-fetches data
//! into the page cache before the application requests it, hiding I/O
//! latency for streaming workloads.
//!
//! # State machine
//!
//! ```text
//!                ┌─────────┐
//!      ┌────────│  Initial │
//!      │        └────┬─────┘
//!      │             │ sequential access detected
//!      │             ▼
//!      │        ┌─────────┐
//!      │  ┌─────│  Async  │◄──── window doubles on hits
//!      │  │     └────┬────┘
//!      │  │          │ window > max_pages
//!      │  │          ▼
//!      │  │     ┌──────────┐
//!      │  │     │ Oversize │──── capped at ra_pages
//!      │  │     └──────────┘
//!      │  │          │
//!      │  │          │ random access / seek
//!      │  └──────────┼──────────┐
//!      │             ▼          │
//!      │        ┌─────────┐    │
//!      └───────►│  Reset  │◄───┘
//!               └─────────┘
//! ```
//!
//! ## Initial state
//!
//! The first read triggers a synchronous read of a small window
//! (typically 2-4 pages).  If the next access is sequential, the
//! state machine transitions to async read-ahead.
//!
//! ## Async state
//!
//! The read-ahead window doubles on each cache hit (up to `ra_pages`).
//! A background I/O is issued when the application crosses into the
//! read-ahead window, so data is ready before it is needed.
//!
//! ## Oversize state
//!
//! The window has reached the per-file maximum (`ra_pages`).
//! Read-ahead continues at the capped size.
//!
//! ## Reset
//!
//! A random seek or large gap between accesses resets the state
//! machine back to Initial.
//!
//! # On-demand read-ahead
//!
//! When the page cache misses on a page that falls within an active
//! read-ahead window, the system triggers an *on-demand* read-ahead
//! using a marker page mechanism (READAHEAD flag on the first page
//! of each async batch).
//!
//! # Mmap read-ahead
//!
//! Memory-mapped file accesses trigger read-ahead through the page
//! fault handler.  The fault address is converted to a file offset
//! and fed into the same state machine.
//!
//! # Reference
//!
//! Linux `mm/readahead.c`, `include/linux/backing-dev.h`.

extern crate alloc;

use oncrix_lib::{Error, Result};

// ── Constants ────────────────────────────────────────────────────────────────

/// Default maximum read-ahead window in pages.
pub const DEFAULT_RA_PAGES: u32 = 32;

/// Minimum read-ahead window (initial sync read size).
const MIN_RA_PAGES: u32 = 2;

/// Maximum supported read-ahead window.
const MAX_RA_PAGES: u32 = 256;

/// Number of sequential accesses needed to confirm sequential pattern.
const SEQ_THRESHOLD: u32 = 2;

/// Maximum number of tracked file contexts.
const MAX_RA_CONTEXTS: usize = 128;

/// Page size in bytes (matches VFS page cache).
const PAGE_SIZE: u64 = 4096;

/// Marker value indicating no valid page index.
const INVALID_PAGE: u64 = u64::MAX;

// ── Read-ahead state machine ─────────────────────────────────────────────────

/// Current phase of the read-ahead state machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RaState {
    /// No pattern detected yet; first read is synchronous.
    Initial,
    /// Sequential pattern detected; async read-ahead active.
    Async,
    /// Window has reached maximum; capped read-ahead.
    Oversize,
    /// State machine reset (random access detected).
    Reset,
}

// ── Readahead control ────────────────────────────────────────────────────────

/// Control structure for a single read-ahead batch.
///
/// Passed to the filesystem's `readahead` callback to describe which
/// pages should be fetched.
#[derive(Debug, Clone, Copy)]
pub struct ReadaheadControl {
    /// Inode number of the file.
    pub inode: u64,
    /// Starting page index for this batch.
    pub start: u64,
    /// Number of pages to read in this batch.
    pub nr_pages: u32,
    /// Whether this is an async (background) request.
    pub is_async: bool,
}

impl ReadaheadControl {
    /// Create a new readahead control.
    pub const fn new(inode: u64, start: u64, nr_pages: u32, is_async: bool) -> Self {
        Self {
            inode,
            start,
            nr_pages,
            is_async,
        }
    }

    /// Return the byte offset of the start of this batch.
    pub fn start_offset(&self) -> u64 {
        self.start * PAGE_SIZE
    }

    /// Return the total byte length of this batch.
    pub fn length(&self) -> u64 {
        self.nr_pages as u64 * PAGE_SIZE
    }
}

// ── Per-file read-ahead state ────────────────────────────────────────────────

/// Read-ahead state for a single open file.
///
/// Tracks the sequential access pattern and current read-ahead window.
struct RaFileState {
    /// Inode number of the tracked file.
    inode: u64,
    /// File descriptor or unique handle for this open instance.
    handle: u64,
    /// Current state machine phase.
    state: RaState,
    /// Maximum read-ahead window for this file (in pages).
    ra_pages: u32,
    /// Current read-ahead window size (in pages).
    window_size: u32,
    /// Start page index of the current read-ahead window.
    window_start: u64,
    /// Page index of the next expected sequential access.
    next_expected: u64,
    /// Count of consecutive sequential accesses.
    seq_count: u32,
    /// Last page index accessed by the application.
    last_access: u64,
    /// Number of async read-ahead batches issued.
    async_batches: u64,
    /// Page index where the async trigger fires.
    async_trigger: u64,
    /// Total pages pre-fetched for this file.
    pages_prefetched: u64,
    /// Whether this slot is in use.
    in_use: bool,
}

impl RaFileState {
    /// Create an empty, unused slot.
    const fn empty() -> Self {
        Self {
            inode: 0,
            handle: 0,
            state: RaState::Initial,
            ra_pages: DEFAULT_RA_PAGES,
            window_size: MIN_RA_PAGES,
            window_start: 0,
            next_expected: 0,
            seq_count: 0,
            last_access: INVALID_PAGE,
            async_batches: 0,
            async_trigger: INVALID_PAGE,
            pages_prefetched: 0,
            in_use: false,
        }
    }

    /// Reset the state machine on random access.
    fn reset(&mut self) {
        self.state = RaState::Reset;
        self.window_size = MIN_RA_PAGES;
        self.seq_count = 0;
        self.async_trigger = INVALID_PAGE;
    }

    /// Double the window size, capping at `ra_pages`.
    fn grow_window(&mut self) {
        let new_size = self.window_size.saturating_mul(2);
        if new_size >= self.ra_pages {
            self.window_size = self.ra_pages;
            self.state = RaState::Oversize;
        } else {
            self.window_size = new_size;
        }
    }
}

// ── Statistics ───────────────────────────────────────────────────────────────

/// Read-ahead subsystem statistics.
#[derive(Debug, Clone, Copy)]
pub struct ReadaheadStats {
    /// Total synchronous (initial) reads.
    pub sync_reads: u64,
    /// Total async read-ahead batches submitted.
    pub async_reads: u64,
    /// Read-ahead hits (page was already cached).
    pub hits: u64,
    /// Read-ahead misses (triggered on-demand RA).
    pub misses: u64,
    /// Total pages pre-fetched.
    pub pages_prefetched: u64,
    /// Number of state resets (random access detected).
    pub resets: u64,
    /// Mmap-triggered read-ahead events.
    pub mmap_readahead: u64,
}

impl ReadaheadStats {
    /// Create zeroed statistics.
    const fn new() -> Self {
        Self {
            sync_reads: 0,
            async_reads: 0,
            hits: 0,
            misses: 0,
            pages_prefetched: 0,
            resets: 0,
            mmap_readahead: 0,
        }
    }
}

// ── Readahead manager ────────────────────────────────────────────────────────

/// The read-ahead manager.
///
/// Tracks per-file read-ahead state and generates read-ahead control
/// structures for the filesystem to execute.
pub struct ReadaheadManager {
    /// Per-file read-ahead states.
    contexts: [RaFileState; MAX_RA_CONTEXTS],
    /// Global default `ra_pages` value.
    default_ra_pages: u32,
    /// Cumulative statistics.
    stats: ReadaheadStats,
}

impl ReadaheadManager {
    /// Create a new read-ahead manager.
    pub fn new() -> Self {
        Self {
            contexts: [const { RaFileState::empty() }; MAX_RA_CONTEXTS],
            default_ra_pages: DEFAULT_RA_PAGES,
            stats: ReadaheadStats::new(),
        }
    }

    /// Set the global default read-ahead window size.
    pub fn set_default_ra_pages(&mut self, pages: u32) -> Result<()> {
        if pages < MIN_RA_PAGES || pages > MAX_RA_PAGES {
            return Err(Error::InvalidArgument);
        }
        self.default_ra_pages = pages;
        Ok(())
    }

    /// Register a file for read-ahead tracking.
    ///
    /// Returns a context index for subsequent operations.
    pub fn register_file(&mut self, inode: u64, handle: u64) -> Result<usize> {
        // Check for existing registration.
        for (idx, ctx) in self.contexts.iter().enumerate() {
            if ctx.in_use && ctx.inode == inode && ctx.handle == handle {
                return Ok(idx);
            }
        }

        let (idx, slot) = self
            .contexts
            .iter_mut()
            .enumerate()
            .find(|(_, c)| !c.in_use)
            .ok_or(Error::OutOfMemory)?;

        slot.inode = inode;
        slot.handle = handle;
        slot.state = RaState::Initial;
        slot.ra_pages = self.default_ra_pages;
        slot.window_size = MIN_RA_PAGES;
        slot.window_start = 0;
        slot.next_expected = 0;
        slot.seq_count = 0;
        slot.last_access = INVALID_PAGE;
        slot.async_batches = 0;
        slot.async_trigger = INVALID_PAGE;
        slot.pages_prefetched = 0;
        slot.in_use = true;

        Ok(idx)
    }

    /// Unregister a file from read-ahead tracking.
    pub fn unregister_file(&mut self, ctx_idx: usize) -> Result<()> {
        if ctx_idx >= MAX_RA_CONTEXTS || !self.contexts[ctx_idx].in_use {
            return Err(Error::NotFound);
        }
        self.contexts[ctx_idx].in_use = false;
        Ok(())
    }

    /// Set the per-file read-ahead window maximum.
    pub fn set_file_ra_pages(&mut self, ctx_idx: usize, pages: u32) -> Result<()> {
        if ctx_idx >= MAX_RA_CONTEXTS || !self.contexts[ctx_idx].in_use {
            return Err(Error::NotFound);
        }
        if pages < MIN_RA_PAGES || pages > MAX_RA_PAGES {
            return Err(Error::InvalidArgument);
        }
        self.contexts[ctx_idx].ra_pages = pages;
        Ok(())
    }

    /// Notify the read-ahead manager of a page access.
    ///
    /// Returns `Some(ReadaheadControl)` if read-ahead should be triggered,
    /// or `None` if no pre-fetch is needed.
    pub fn on_page_access(
        &mut self,
        ctx_idx: usize,
        page_index: u64,
        cache_hit: bool,
    ) -> Result<Option<ReadaheadControl>> {
        if ctx_idx >= MAX_RA_CONTEXTS || !self.contexts[ctx_idx].in_use {
            return Err(Error::NotFound);
        }

        let inode;
        let result;
        {
            let ctx = &mut self.contexts[ctx_idx];
            inode = ctx.inode;

            if cache_hit {
                self.stats.hits += 1;
            } else {
                self.stats.misses += 1;
            }

            // Check if access is sequential.
            let is_sequential = ctx.last_access == INVALID_PAGE
                || page_index == ctx.next_expected
                || (page_index > ctx.last_access && page_index <= ctx.last_access + 2);

            ctx.last_access = page_index;
            ctx.next_expected = page_index + 1;

            if !is_sequential {
                ctx.reset();
                self.stats.resets += 1;
                return Ok(None);
            }

            ctx.seq_count = ctx.seq_count.saturating_add(1);

            result = match ctx.state {
                RaState::Initial | RaState::Reset => {
                    if ctx.seq_count >= SEQ_THRESHOLD {
                        // Transition to async read-ahead.
                        ctx.state = RaState::Async;
                        ctx.window_start = page_index + 1;
                        ctx.window_size = MIN_RA_PAGES;
                        let nr = ctx.window_size;
                        let start = ctx.window_start;
                        ctx.async_trigger = start + nr as u64 / 2;
                        ctx.pages_prefetched += nr as u64;
                        self.stats.sync_reads += 1;
                        Some(ReadaheadControl::new(inode, start, nr, false))
                    } else {
                        None
                    }
                }
                RaState::Async | RaState::Oversize => {
                    // Check if we crossed the async trigger point.
                    if ctx.async_trigger != INVALID_PAGE && page_index >= ctx.async_trigger {
                        ctx.grow_window();
                        let start = ctx.window_start + ctx.window_size as u64;
                        let nr = ctx.window_size;
                        ctx.window_start = start;
                        ctx.async_trigger = start + nr as u64 / 2;
                        ctx.async_batches += 1;
                        ctx.pages_prefetched += nr as u64;
                        self.stats.async_reads += 1;
                        Some(ReadaheadControl::new(inode, start, nr, true))
                    } else {
                        None
                    }
                }
            };
        }

        if let Some(ref ctrl) = result {
            self.stats.pages_prefetched += ctrl.nr_pages as u64;
        }

        Ok(result)
    }

    /// Handle an on-demand read-ahead triggered by a page cache miss.
    ///
    /// This is called when the page cache misses on a page within an
    /// active read-ahead window (identified by a READAHEAD marker page).
    pub fn on_demand_readahead(
        &mut self,
        ctx_idx: usize,
        page_index: u64,
    ) -> Result<Option<ReadaheadControl>> {
        if ctx_idx >= MAX_RA_CONTEXTS || !self.contexts[ctx_idx].in_use {
            return Err(Error::NotFound);
        }

        let ctx = &mut self.contexts[ctx_idx];

        if ctx.state == RaState::Initial || ctx.state == RaState::Reset {
            // Start fresh with a sync read from the missed page.
            ctx.state = RaState::Async;
            ctx.window_start = page_index;
            ctx.window_size = MIN_RA_PAGES;
            ctx.seq_count = 1;
            let nr = ctx.window_size;
            ctx.async_trigger = page_index + nr as u64 / 2;
            ctx.pages_prefetched += nr as u64;
            self.stats.sync_reads += 1;
            return Ok(Some(ReadaheadControl::new(
                ctx.inode, page_index, nr, false,
            )));
        }

        // Already in async/oversize — extend the window.
        ctx.grow_window();
        let start = page_index;
        let nr = ctx.window_size;
        ctx.window_start = start;
        ctx.async_trigger = start + nr as u64 / 2;
        ctx.async_batches += 1;
        ctx.pages_prefetched += nr as u64;
        self.stats.async_reads += 1;
        Ok(Some(ReadaheadControl::new(ctx.inode, start, nr, true)))
    }

    /// Handle mmap page fault read-ahead.
    ///
    /// Converts a fault address to a page index and triggers the
    /// normal state machine, tagged as mmap-originated.
    pub fn mmap_readahead(
        &mut self,
        ctx_idx: usize,
        fault_offset: u64,
        cache_hit: bool,
    ) -> Result<Option<ReadaheadControl>> {
        let page_index = fault_offset / PAGE_SIZE;
        self.stats.mmap_readahead += 1;
        self.on_page_access(ctx_idx, page_index, cache_hit)
    }

    /// Force a synchronous read-ahead of a specific range.
    ///
    /// Used by `posix_fadvise(POSIX_FADV_WILLNEED)` and similar hints.
    pub fn force_readahead(
        &mut self,
        ctx_idx: usize,
        start_page: u64,
        nr_pages: u32,
    ) -> Result<ReadaheadControl> {
        if ctx_idx >= MAX_RA_CONTEXTS || !self.contexts[ctx_idx].in_use {
            return Err(Error::NotFound);
        }
        if nr_pages == 0 || nr_pages > MAX_RA_PAGES {
            return Err(Error::InvalidArgument);
        }

        let ctx = &mut self.contexts[ctx_idx];
        ctx.pages_prefetched += nr_pages as u64;
        self.stats.sync_reads += 1;
        self.stats.pages_prefetched += nr_pages as u64;
        Ok(ReadaheadControl::new(
            ctx.inode, start_page, nr_pages, false,
        ))
    }

    /// Get the current read-ahead state for a file context.
    pub fn file_state(&self, ctx_idx: usize) -> Result<RaState> {
        if ctx_idx >= MAX_RA_CONTEXTS || !self.contexts[ctx_idx].in_use {
            return Err(Error::NotFound);
        }
        Ok(self.contexts[ctx_idx].state)
    }

    /// Get the current window size for a file context.
    pub fn file_window_size(&self, ctx_idx: usize) -> Result<u32> {
        if ctx_idx >= MAX_RA_CONTEXTS || !self.contexts[ctx_idx].in_use {
            return Err(Error::NotFound);
        }
        Ok(self.contexts[ctx_idx].window_size)
    }

    /// Return read-ahead statistics.
    pub fn stats(&self) -> ReadaheadStats {
        self.stats
    }

    /// Reset statistics counters.
    pub fn reset_stats(&mut self) {
        self.stats = ReadaheadStats::new();
    }
}
