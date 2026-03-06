// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! File read-ahead control and algorithm.
//!
//! Manages the readahead algorithm for sequential file access: detects
//! sequential read patterns, scales the async readahead window, and
//! handles cache misses with on-demand readahead.
//!
//! # State machine
//!
//! ```text
//! ┌──────────────┐
//! │   Cold       │  (no history, first access)
//! └──────┬───────┘
//!        │ sequential hit
//!        ▼
//! ┌──────────────┐
//! │   Warming    │  (building confidence in sequential pattern)
//! └──────┬───────┘
//!        │ confidence >= threshold
//!        ▼
//! ┌──────────────┐            ┌──────────────┐
//! │   Active     │───window──►│   Capped     │
//! │  (doubling)  │  >= max    │  (at ra_max) │
//! └──────┬───────┘            └──────┬───────┘
//!        │ random seek                │ random seek
//!        ▼                            ▼
//! ┌──────────────┐
//! │   Cold       │  (reset)
//! └──────────────┘
//! ```
//!
//! # Interaction with page cache
//!
//! The readahead control generates [`ReadaheadWindow`] descriptors that
//! tell the page cache subsystem which pages to pre-fetch.  The actual
//! I/O submission is done by the caller (page cache or filesystem).
//!
//! # Reference
//!
//! Linux `mm/readahead.c`, `include/linux/readahead.h`.

use oncrix_lib::{Error, Result};

// ── Constants ─────────────────────────────────────────────────────────────────

/// Default maximum readahead window in pages.
pub const DEFAULT_RA_MAX: u32 = 128;

/// Minimum readahead window in pages.
const MIN_RA_WINDOW: u32 = 2;

/// Maximum supported readahead window.
const MAX_RA_WINDOW: u32 = 512;

/// Sequential hit count threshold to transition from Warming to Active.
const WARMUP_THRESHOLD: u32 = 3;

/// Maximum number of tracked readahead contexts (open files).
const MAX_CONTEXTS: usize = 256;

/// Page size in bytes.
const PAGE_SIZE: u64 = 4096;

/// Sentinel page index meaning "no valid page".
const INVALID_PAGE: u64 = u64::MAX;

/// Maximum gap (in pages) before declaring a random seek.
const MAX_SEQ_GAP: u64 = 2;

// ── RaState ───────────────────────────────────────────────────────────────────

/// Current phase of the readahead state machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RaState {
    /// No access history; next read is synchronous.
    Cold,
    /// Sequential pattern suspected; building confidence.
    Warming,
    /// Confirmed sequential; async readahead active, window doubling.
    Active,
    /// Window has reached maximum; readahead continues at capped size.
    Capped,
}

// ── IoHint ────────────────────────────────────────────────────────────────────

/// Hint describing the nature of an I/O request.
///
/// The readahead algorithm uses these hints to make better decisions
/// about pre-fetching strategy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IoHint {
    /// Normal read (default).
    Normal,
    /// Random access declared by the application (e.g., `fadvise(RANDOM)`).
    Random,
    /// Application expects sequential access (`fadvise(SEQUENTIAL)`).
    Sequential,
    /// Memory-mapped file fault.
    MmapFault,
    /// Application will need the data soon (`fadvise(WILLNEED)`).
    WillNeed,
    /// Application will not need cached data (`fadvise(DONTNEED)`).
    DontNeed,
}

// ── ReadaheadWindow ───────────────────────────────────────────────────────────

/// Describes a window of pages to be pre-fetched.
///
/// Produced by the readahead algorithm and consumed by the page cache
/// or filesystem to submit actual I/O.
#[derive(Debug, Clone, Copy)]
pub struct ReadaheadWindow {
    /// Inode number of the file.
    pub inode: u64,
    /// Starting page index.
    pub start: u64,
    /// Number of pages to read.
    pub nr_pages: u32,
    /// Whether this is an async (background) read.
    pub is_async: bool,
    /// The I/O hint that triggered this readahead.
    pub hint: IoHint,
}

impl ReadaheadWindow {
    /// Create a new readahead window.
    pub const fn new(inode: u64, start: u64, nr_pages: u32, is_async: bool, hint: IoHint) -> Self {
        Self {
            inode,
            start,
            nr_pages,
            is_async,
            hint,
        }
    }

    /// Return the byte offset of the start of this window.
    pub const fn start_offset(&self) -> u64 {
        self.start * PAGE_SIZE
    }

    /// Return the total byte length of this window.
    pub const fn byte_length(&self) -> u64 {
        self.nr_pages as u64 * PAGE_SIZE
    }

    /// Return the page index one past the end of this window.
    pub const fn end_page(&self) -> u64 {
        self.start + self.nr_pages as u64
    }
}

// ── Per-file readahead context ────────────────────────────────────────────────

/// Readahead state for a single open file.
struct RaContext {
    /// Inode number.
    inode: u64,
    /// Unique file handle / descriptor.
    handle: u64,
    /// Current state machine phase.
    state: RaState,
    /// Maximum readahead window for this file (in pages).
    ra_max: u32,
    /// Current window size (in pages).
    window_size: u32,
    /// Start page of the current readahead window.
    window_start: u64,
    /// Page index where async readahead should trigger next.
    trigger_page: u64,
    /// Last page accessed by the application.
    last_page: u64,
    /// Next expected sequential page.
    next_expected: u64,
    /// Count of consecutive sequential accesses.
    seq_hits: u32,
    /// Total pages pre-fetched for this file.
    pages_issued: u64,
    /// Total async batches issued.
    async_batches: u64,
    /// Application-supplied I/O hint override.
    hint_override: Option<IoHint>,
    /// Whether this slot is in use.
    in_use: bool,
}

impl RaContext {
    const fn empty() -> Self {
        Self {
            inode: 0,
            handle: 0,
            state: RaState::Cold,
            ra_max: DEFAULT_RA_MAX,
            window_size: MIN_RA_WINDOW,
            window_start: 0,
            trigger_page: INVALID_PAGE,
            last_page: INVALID_PAGE,
            next_expected: 0,
            seq_hits: 0,
            pages_issued: 0,
            async_batches: 0,
            hint_override: None,
            in_use: false,
        }
    }

    /// Reset to cold state (random seek detected).
    fn reset(&mut self) {
        self.state = RaState::Cold;
        self.window_size = MIN_RA_WINDOW;
        self.seq_hits = 0;
        self.trigger_page = INVALID_PAGE;
    }

    /// Double the window, transitioning to Capped if at max.
    fn grow_window(&mut self) {
        let new_size = self.window_size.saturating_mul(2);
        if new_size >= self.ra_max {
            self.window_size = self.ra_max;
            self.state = RaState::Capped;
        } else {
            self.window_size = new_size;
        }
    }

    /// Determine if an access at `page` is sequential.
    fn is_sequential(&self, page: u64) -> bool {
        if self.last_page == INVALID_PAGE {
            return true; // First access is considered sequential.
        }
        page == self.next_expected
            || (page > self.last_page && page <= self.last_page + MAX_SEQ_GAP)
    }
}

// ── ReadaheadStats ────────────────────────────────────────────────────────────

/// Readahead subsystem statistics.
#[derive(Debug, Clone, Copy)]
pub struct ReadaheadStats {
    /// Total synchronous (initial) reads issued.
    pub sync_reads: u64,
    /// Total async readahead batches issued.
    pub async_reads: u64,
    /// Cache hits during readahead decision.
    pub cache_hits: u64,
    /// Cache misses triggering on-demand readahead.
    pub cache_misses: u64,
    /// Total pages pre-fetched.
    pub pages_issued: u64,
    /// State machine resets (random seek detected).
    pub resets: u64,
    /// Hint-driven readahead events.
    pub hint_reads: u64,
}

impl ReadaheadStats {
    const fn new() -> Self {
        Self {
            sync_reads: 0,
            async_reads: 0,
            cache_hits: 0,
            cache_misses: 0,
            pages_issued: 0,
            resets: 0,
            hint_reads: 0,
        }
    }
}

// ── ReadaheadControl (main manager) ───────────────────────────────────────────

/// The readahead control manager.
///
/// Tracks per-file readahead state and produces [`ReadaheadWindow`]
/// descriptors when pre-fetching should be initiated.
pub struct ReadaheadControl {
    /// Per-file readahead contexts.
    contexts: [RaContext; MAX_CONTEXTS],
    /// Global default ra_max.
    default_ra_max: u32,
    /// Cumulative statistics.
    stats: ReadaheadStats,
}

impl ReadaheadControl {
    /// Create a new readahead control manager.
    pub fn new() -> Self {
        Self {
            contexts: [const { RaContext::empty() }; MAX_CONTEXTS],
            default_ra_max: DEFAULT_RA_MAX,
            stats: ReadaheadStats::new(),
        }
    }

    /// Set the global default maximum readahead window.
    pub fn set_default_ra_max(&mut self, pages: u32) -> Result<()> {
        if pages < MIN_RA_WINDOW || pages > MAX_RA_WINDOW {
            return Err(Error::InvalidArgument);
        }
        self.default_ra_max = pages;
        Ok(())
    }

    /// Register a file for readahead tracking.
    ///
    /// Returns the context index.
    pub fn register(&mut self, inode: u64, handle: u64) -> Result<usize> {
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

        *slot = RaContext::empty();
        slot.inode = inode;
        slot.handle = handle;
        slot.ra_max = self.default_ra_max;
        slot.in_use = true;

        Ok(idx)
    }

    /// Unregister a file from readahead tracking.
    pub fn unregister(&mut self, idx: usize) -> Result<()> {
        if idx >= MAX_CONTEXTS || !self.contexts[idx].in_use {
            return Err(Error::NotFound);
        }
        self.contexts[idx].in_use = false;
        Ok(())
    }

    /// Set the per-file maximum readahead window.
    pub fn set_file_ra_max(&mut self, idx: usize, pages: u32) -> Result<()> {
        let ctx = self.get_ctx_mut(idx)?;
        if pages < MIN_RA_WINDOW || pages > MAX_RA_WINDOW {
            return Err(Error::InvalidArgument);
        }
        ctx.ra_max = pages;
        Ok(())
    }

    /// Apply an I/O hint for a file context.
    pub fn apply_hint(&mut self, idx: usize, hint: IoHint) -> Result<()> {
        let ctx = self.get_ctx_mut(idx)?;
        match hint {
            IoHint::Random => {
                // Disable readahead.
                ctx.hint_override = Some(IoHint::Random);
                ctx.reset();
            }
            IoHint::Sequential => {
                // Boost readahead.
                ctx.hint_override = Some(IoHint::Sequential);
                if ctx.state == RaState::Cold {
                    ctx.state = RaState::Warming;
                    ctx.seq_hits = WARMUP_THRESHOLD;
                }
            }
            IoHint::DontNeed => {
                ctx.hint_override = Some(IoHint::DontNeed);
            }
            _ => {
                ctx.hint_override = Some(hint);
            }
        }
        Ok(())
    }

    /// Notify the readahead controller of a page access.
    ///
    /// Returns `Some(ReadaheadWindow)` if readahead should be triggered,
    /// or `None` if no pre-fetch is needed.
    pub fn on_access(
        &mut self,
        idx: usize,
        page: u64,
        cache_hit: bool,
    ) -> Result<Option<ReadaheadWindow>> {
        // Validate context index directly (avoids holding &mut self via get_ctx_mut).
        let ci = idx as usize;
        if ci >= MAX_CONTEXTS || !self.contexts[ci].in_use {
            return Err(Error::NotFound);
        }

        // Random hint disables readahead.
        if self.contexts[ci].hint_override == Some(IoHint::Random) {
            return Ok(None);
        }

        if cache_hit {
            self.stats.cache_hits += 1;
        } else {
            self.stats.cache_misses += 1;
        }

        let is_seq = self.contexts[ci].is_sequential(page);
        let inode = self.contexts[ci].inode;
        self.contexts[ci].last_page = page;
        self.contexts[ci].next_expected = page + 1;

        if !is_seq {
            self.contexts[ci].reset();
            self.stats.resets += 1;
            return Ok(None);
        }

        self.contexts[ci].seq_hits = self.contexts[ci].seq_hits.saturating_add(1);

        let window = match self.contexts[ci].state {
            RaState::Cold => {
                if self.contexts[ci].seq_hits >= WARMUP_THRESHOLD
                    || self.contexts[ci].hint_override == Some(IoHint::Sequential)
                {
                    self.contexts[ci].state = RaState::Active;
                    self.contexts[ci].window_start = page + 1;
                    self.contexts[ci].window_size = MIN_RA_WINDOW;
                    let nr = self.contexts[ci].window_size;
                    self.contexts[ci].trigger_page = self.contexts[ci].window_start + nr as u64 / 2;
                    self.contexts[ci].pages_issued += nr as u64;
                    self.stats.sync_reads += 1;
                    self.stats.pages_issued += nr as u64;
                    Some(ReadaheadWindow::new(
                        inode,
                        self.contexts[ci].window_start,
                        nr,
                        false,
                        IoHint::Normal,
                    ))
                } else {
                    self.contexts[ci].state = RaState::Warming;
                    None
                }
            }
            RaState::Warming => {
                if self.contexts[ci].seq_hits >= WARMUP_THRESHOLD {
                    self.contexts[ci].state = RaState::Active;
                    self.contexts[ci].window_start = page + 1;
                    self.contexts[ci].window_size = MIN_RA_WINDOW;
                    let nr = self.contexts[ci].window_size;
                    self.contexts[ci].trigger_page = self.contexts[ci].window_start + nr as u64 / 2;
                    self.contexts[ci].pages_issued += nr as u64;
                    self.stats.sync_reads += 1;
                    self.stats.pages_issued += nr as u64;
                    Some(ReadaheadWindow::new(
                        inode,
                        self.contexts[ci].window_start,
                        nr,
                        false,
                        IoHint::Normal,
                    ))
                } else {
                    None
                }
            }
            RaState::Active | RaState::Capped => {
                if self.contexts[ci].trigger_page != INVALID_PAGE
                    && page >= self.contexts[ci].trigger_page
                {
                    self.contexts[ci].grow_window();
                    let start =
                        self.contexts[ci].window_start + self.contexts[ci].window_size as u64;
                    let nr = self.contexts[ci].window_size;
                    self.contexts[ci].window_start = start;
                    self.contexts[ci].trigger_page = start + nr as u64 / 2;
                    self.contexts[ci].async_batches += 1;
                    self.contexts[ci].pages_issued += nr as u64;
                    self.stats.async_reads += 1;
                    self.stats.pages_issued += nr as u64;
                    Some(ReadaheadWindow::new(inode, start, nr, true, IoHint::Normal))
                } else {
                    None
                }
            }
        };

        Ok(window)
    }

    /// Handle an on-demand readahead triggered by a cache miss within
    /// an active readahead window.
    pub fn on_demand(&mut self, idx: usize, page: u64) -> Result<Option<ReadaheadWindow>> {
        let ctx = self.get_ctx_mut(idx)?;
        let inode = ctx.inode;

        match ctx.state {
            RaState::Cold | RaState::Warming => {
                // Start fresh.
                ctx.state = RaState::Active;
                ctx.window_start = page;
                ctx.window_size = MIN_RA_WINDOW;
                ctx.seq_hits = 1;
                let nr = ctx.window_size;
                ctx.trigger_page = page + nr as u64 / 2;
                ctx.pages_issued += nr as u64;
                self.stats.sync_reads += 1;
                self.stats.pages_issued += nr as u64;
                Ok(Some(ReadaheadWindow::new(
                    inode,
                    page,
                    nr,
                    false,
                    IoHint::Normal,
                )))
            }
            RaState::Active | RaState::Capped => {
                ctx.grow_window();
                let nr = ctx.window_size;
                ctx.window_start = page;
                ctx.trigger_page = page + nr as u64 / 2;
                ctx.async_batches += 1;
                ctx.pages_issued += nr as u64;
                self.stats.async_reads += 1;
                self.stats.pages_issued += nr as u64;
                Ok(Some(ReadaheadWindow::new(
                    inode,
                    page,
                    nr,
                    true,
                    IoHint::Normal,
                )))
            }
        }
    }

    /// Force a synchronous readahead of a specific range.
    ///
    /// Used by `posix_fadvise(POSIX_FADV_WILLNEED)` and similar.
    pub fn force_readahead(
        &mut self,
        idx: usize,
        start_page: u64,
        nr_pages: u32,
    ) -> Result<ReadaheadWindow> {
        let ctx = self.get_ctx_mut(idx)?;
        if nr_pages == 0 || nr_pages > MAX_RA_WINDOW {
            return Err(Error::InvalidArgument);
        }
        let inode = ctx.inode;
        ctx.pages_issued += nr_pages as u64;
        self.stats.hint_reads += 1;
        self.stats.pages_issued += nr_pages as u64;
        Ok(ReadaheadWindow::new(
            inode,
            start_page,
            nr_pages,
            false,
            IoHint::WillNeed,
        ))
    }

    /// Handle a memory-mapped file page fault.
    pub fn on_mmap_fault(
        &mut self,
        idx: usize,
        fault_offset: u64,
        cache_hit: bool,
    ) -> Result<Option<ReadaheadWindow>> {
        let page = fault_offset / PAGE_SIZE;
        self.on_access(idx, page, cache_hit)
    }

    // ── Query methods ─────────────────────────────────────────────────────────

    /// Get the current state for a file context.
    pub fn file_state(&self, idx: usize) -> Result<RaState> {
        let ctx = self.get_ctx(idx)?;
        Ok(ctx.state)
    }

    /// Get the current window size for a file context.
    pub fn file_window_size(&self, idx: usize) -> Result<u32> {
        let ctx = self.get_ctx(idx)?;
        Ok(ctx.window_size)
    }

    /// Get the total pages pre-fetched for a file context.
    pub fn file_pages_issued(&self, idx: usize) -> Result<u64> {
        let ctx = self.get_ctx(idx)?;
        Ok(ctx.pages_issued)
    }

    /// Return readahead statistics.
    pub fn stats(&self) -> ReadaheadStats {
        self.stats
    }

    /// Reset statistics.
    pub fn reset_stats(&mut self) {
        self.stats = ReadaheadStats::new();
    }

    // ── Internal ──────────────────────────────────────────────────────────────

    fn get_ctx(&self, idx: usize) -> Result<&RaContext> {
        if idx >= MAX_CONTEXTS {
            return Err(Error::InvalidArgument);
        }
        if !self.contexts[idx].in_use {
            return Err(Error::NotFound);
        }
        Ok(&self.contexts[idx])
    }

    fn get_ctx_mut(&mut self, idx: usize) -> Result<&mut RaContext> {
        if idx >= MAX_CONTEXTS {
            return Err(Error::InvalidArgument);
        }
        if !self.contexts[idx].in_use {
            return Err(Error::NotFound);
        }
        Ok(&mut self.contexts[idx])
    }
}

impl Default for ReadaheadControl {
    fn default() -> Self {
        Self::new()
    }
}
