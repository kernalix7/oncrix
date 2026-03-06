// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Page cache truncation subsystem.
//!
//! Removes pages from the page cache during truncate, hole-punch, and
//! invalidation operations. When a file is truncated or a range is
//! punched out, the corresponding cached pages must be freed to avoid
//! stale data and reclaim memory.
//!
//! Three modes of operation:
//!
//! - **Truncate** — free all pages beyond a new file size
//! - **HolePunch** — free pages within a specific byte range
//! - **InvalidateRange** — try to free all pages (skip busy ones)
//!
//! Partial pages (where the truncation point falls mid-page) are
//! zeroed from the truncation offset to the end of the page but
//! retained in the cache.
//!
//! - [`TruncateMode`] — operation type
//! - [`TruncateRange`] — describes the range to truncate
//! - [`TruncateState`] — per-operation progress state
//! - [`CachedPage`] — simulated page cache entry
//! - [`TruncateSubsystem`] — the truncation engine
//! - [`TruncateStats`] — aggregate statistics
//!
//! Reference: Linux `mm/truncate.c` — `truncate_inode_pages()`,
//! `truncate_inode_pages_range()`, `invalidate_inode_pages2()`.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Standard page size in bytes (4 KiB).
const PAGE_SIZE: u64 = 4096;

/// Maximum number of concurrent truncation operations.
const MAX_TRUNCATIONS: usize = 32;

/// Maximum number of cached pages tracked per inode.
const MAX_CACHED_PAGES: usize = 512;

/// Maximum number of inodes tracked.
const MAX_INODES: usize = 64;

/// Sentinel value for "truncate to end of file".
pub const TRUNCATE_TO_END: u64 = u64::MAX;

// -------------------------------------------------------------------
// TruncateMode
// -------------------------------------------------------------------

/// Mode of a truncation operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TruncateMode {
    /// Remove all pages beyond a new file size.
    #[default]
    Truncate,
    /// Remove pages within a specific range (hole punch).
    HolePunch,
    /// Attempt to invalidate all pages (skip busy).
    InvalidateRange,
}

// -------------------------------------------------------------------
// TruncateRange
// -------------------------------------------------------------------

/// Describes the byte range to be truncated.
#[derive(Debug, Clone, Copy)]
pub struct TruncateRange {
    /// Inode identifier.
    pub inode_id: u32,
    /// Start byte offset (page-aligned for full pages).
    pub start_offset: u64,
    /// End byte offset (exclusive, or [`TRUNCATE_TO_END`]).
    pub end_offset: u64,
    /// Operation mode.
    pub mode: TruncateMode,
}

impl TruncateRange {
    /// Creates a truncate range for truncating a file to `new_size`.
    pub const fn truncate(inode_id: u32, new_size: u64) -> Self {
        Self {
            inode_id,
            start_offset: new_size,
            end_offset: TRUNCATE_TO_END,
            mode: TruncateMode::Truncate,
        }
    }

    /// Creates a truncate range for punching a hole.
    pub const fn hole_punch(inode_id: u32, start: u64, end: u64) -> Self {
        Self {
            inode_id,
            start_offset: start,
            end_offset: end,
            mode: TruncateMode::HolePunch,
        }
    }

    /// Creates a truncate range for invalidating all pages.
    pub const fn invalidate(inode_id: u32) -> Self {
        Self {
            inode_id,
            start_offset: 0,
            end_offset: TRUNCATE_TO_END,
            mode: TruncateMode::InvalidateRange,
        }
    }

    /// Returns the start page index (inclusive).
    pub fn start_page(&self) -> u64 {
        self.start_offset / PAGE_SIZE
    }

    /// Returns the end page index (exclusive).
    pub fn end_page(&self) -> u64 {
        if self.end_offset == TRUNCATE_TO_END {
            TRUNCATE_TO_END
        } else {
            (self.end_offset + PAGE_SIZE - 1) / PAGE_SIZE
        }
    }

    /// Returns `true` if the start offset is not page-aligned,
    /// indicating that a partial page needs to be zeroed.
    pub fn has_partial_start(&self) -> bool {
        self.start_offset % PAGE_SIZE != 0
    }
}

// -------------------------------------------------------------------
// TruncateState
// -------------------------------------------------------------------

/// Progress state for a single truncation operation.
#[derive(Debug, Clone, Copy, Default)]
pub struct TruncateState {
    /// Number of full pages freed.
    pub pages_freed: u64,
    /// Number of pages skipped (dirty, locked, or busy).
    pub pages_skipped: u64,
    /// Number of partial pages zeroed (but retained).
    pub partial_pages: u64,
    /// Whether the operation has completed.
    pub completed: bool,
    /// Whether an error occurred.
    pub error: bool,
}

// -------------------------------------------------------------------
// CachedPage
// -------------------------------------------------------------------

/// A simulated page cache entry for a single page.
#[derive(Debug, Clone, Copy)]
pub struct CachedPage {
    /// Inode this page belongs to.
    pub inode_id: u32,
    /// Page index within the file (offset / PAGE_SIZE).
    pub page_index: u64,
    /// Whether this page is dirty.
    pub dirty: bool,
    /// Whether this page is locked (under I/O).
    pub locked: bool,
    /// Whether this page is under writeback.
    pub writeback: bool,
    /// Reference count.
    pub ref_count: u32,
    /// Whether this slot is in use.
    pub in_use: bool,
    /// Byte offset of valid data within the page (for partial pages).
    pub valid_bytes: u32,
}

impl CachedPage {
    /// Creates an empty, unused cached page entry.
    const fn empty() -> Self {
        Self {
            inode_id: 0,
            page_index: 0,
            dirty: false,
            locked: false,
            writeback: false,
            ref_count: 0,
            in_use: false,
            valid_bytes: PAGE_SIZE as u32,
        }
    }

    /// Returns `true` if this page can be freed immediately.
    ///
    /// A page is freeable if it is not dirty, not locked, not under
    /// writeback, and has no external references.
    pub fn is_freeable(&self) -> bool {
        self.in_use && !self.dirty && !self.locked && !self.writeback && self.ref_count <= 1
    }

    /// Returns `true` if this page is busy and should be skipped
    /// during invalidation.
    pub fn is_busy(&self) -> bool {
        self.locked || self.writeback || self.ref_count > 1
    }
}

// -------------------------------------------------------------------
// TruncationEntry
// -------------------------------------------------------------------

/// Bookkeeping for a single active truncation operation.
#[derive(Debug, Clone, Copy)]
struct TruncationEntry {
    /// The range being truncated.
    range: TruncateRange,
    /// Current progress state.
    state: TruncateState,
    /// Whether this entry is active.
    active: bool,
    /// Truncation operation identifier.
    op_id: u32,
}

impl TruncationEntry {
    /// Creates an empty, inactive entry.
    const fn empty() -> Self {
        Self {
            range: TruncateRange {
                inode_id: 0,
                start_offset: 0,
                end_offset: 0,
                mode: TruncateMode::Truncate,
            },
            state: TruncateState {
                pages_freed: 0,
                pages_skipped: 0,
                partial_pages: 0,
                completed: false,
                error: false,
            },
            active: false,
            op_id: 0,
        }
    }
}

// -------------------------------------------------------------------
// TruncateStats
// -------------------------------------------------------------------

/// Aggregate truncation statistics.
#[derive(Debug, Clone, Copy, Default)]
pub struct TruncateStats {
    /// Total truncation operations performed.
    pub total_truncations: u64,
    /// Total pages freed across all operations.
    pub pages_freed: u64,
    /// Total partial pages zeroed.
    pub partial_zeroed: u64,
    /// Total pages skipped (busy/dirty/locked).
    pub pages_skipped: u64,
    /// Total hole-punch operations.
    pub hole_punches: u64,
    /// Total invalidation operations.
    pub invalidations: u64,
}

// -------------------------------------------------------------------
// TruncateSubsystem
// -------------------------------------------------------------------

/// Page cache truncation engine.
///
/// Manages a simulated page cache and performs truncation, hole-punch,
/// and invalidation operations on cached pages.
pub struct TruncateSubsystem {
    /// Active truncation operations.
    operations: [TruncationEntry; MAX_TRUNCATIONS],
    /// Number of active operations.
    op_count: usize,
    /// Simulated page cache.
    cache: [CachedPage; MAX_CACHED_PAGES],
    /// Number of cached pages.
    cache_count: usize,
    /// Next operation identifier.
    next_op_id: u32,
    /// Aggregate statistics.
    stats: TruncateStats,
}

impl Default for TruncateSubsystem {
    fn default() -> Self {
        Self::new()
    }
}

impl TruncateSubsystem {
    /// Creates a new truncation subsystem with an empty page cache.
    pub const fn new() -> Self {
        Self {
            operations: [TruncationEntry::empty(); MAX_TRUNCATIONS],
            op_count: 0,
            cache: [CachedPage::empty(); MAX_CACHED_PAGES],
            cache_count: 0,
            next_op_id: 1,
            stats: TruncateStats {
                total_truncations: 0,
                pages_freed: 0,
                partial_zeroed: 0,
                pages_skipped: 0,
                hole_punches: 0,
                invalidations: 0,
            },
        }
    }

    /// Adds a page to the simulated cache.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the cache is full.
    pub fn add_cached_page(&mut self, inode_id: u32, page_index: u64) -> Result<usize> {
        if self.cache_count >= MAX_CACHED_PAGES {
            return Err(Error::OutOfMemory);
        }

        let idx = self.find_free_cache_slot();
        self.cache[idx] = CachedPage {
            inode_id,
            page_index,
            dirty: false,
            locked: false,
            writeback: false,
            ref_count: 1,
            in_use: true,
            valid_bytes: PAGE_SIZE as u32,
        };
        self.cache_count += 1;
        Ok(idx)
    }

    /// Marks a cached page as dirty.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if the index is invalid.
    pub fn mark_dirty(&mut self, idx: usize) -> Result<()> {
        if idx >= MAX_CACHED_PAGES || !self.cache[idx].in_use {
            return Err(Error::InvalidArgument);
        }
        self.cache[idx].dirty = true;
        Ok(())
    }

    /// Marks a cached page as locked.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if the index is invalid.
    pub fn mark_locked(&mut self, idx: usize) -> Result<()> {
        if idx >= MAX_CACHED_PAGES || !self.cache[idx].in_use {
            return Err(Error::InvalidArgument);
        }
        self.cache[idx].locked = true;
        Ok(())
    }

    /// Truncates all pages for `inode_id` beyond `new_size`.
    ///
    /// Pages entirely beyond `new_size` are freed. If `new_size`
    /// falls within a page, the remainder is zeroed and the page
    /// is retained.
    ///
    /// Returns the operation state after completion.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the operation table is full.
    pub fn truncate_inode_pages(&mut self, inode_id: u32, new_size: u64) -> Result<TruncateState> {
        let range = TruncateRange::truncate(inode_id, new_size);
        self.execute_truncation(range)
    }

    /// Truncates pages in a specific byte range for `inode_id`.
    ///
    /// Frees pages whose indices fall within `[start, end)`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `start >= end`.
    /// Returns [`Error::OutOfMemory`] if the operation table is full.
    pub fn truncate_inode_pages_range(
        &mut self,
        inode_id: u32,
        start: u64,
        end: u64,
    ) -> Result<TruncateState> {
        if start >= end {
            return Err(Error::InvalidArgument);
        }
        let range = TruncateRange::hole_punch(inode_id, start, end);
        self.execute_truncation(range)
    }

    /// Attempts to invalidate (free) all pages for `inode_id`.
    ///
    /// Busy pages (locked, under writeback, or with external
    /// references) are skipped rather than waited on.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the operation table is full.
    pub fn invalidate_inode_pages(&mut self, inode_id: u32) -> Result<TruncateState> {
        let range = TruncateRange::invalidate(inode_id);
        self.execute_truncation(range)
    }

    /// Returns the number of cached pages for an inode.
    pub fn inode_page_count(&self, inode_id: u32) -> usize {
        let mut count = 0;
        for i in 0..MAX_CACHED_PAGES {
            if self.cache[i].in_use && self.cache[i].inode_id == inode_id {
                count += 1;
            }
        }
        count
    }

    /// Returns the total number of cached pages.
    pub fn total_cached(&self) -> usize {
        self.cache_count
    }

    /// Returns a cached page by index.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if the index is out of range.
    pub fn get_cached(&self, idx: usize) -> Result<&CachedPage> {
        if idx >= MAX_CACHED_PAGES {
            return Err(Error::InvalidArgument);
        }
        Ok(&self.cache[idx])
    }

    /// Returns aggregate truncation statistics.
    pub fn stats(&self) -> TruncateStats {
        self.stats
    }

    /// Returns the number of active truncation operations.
    pub fn active_operations(&self) -> usize {
        let mut count = 0;
        for i in 0..self.op_count {
            if self.operations[i].active {
                count += 1;
            }
        }
        count
    }

    /// Executes a truncation operation.
    fn execute_truncation(&mut self, range: TruncateRange) -> Result<TruncateState> {
        if self.op_count >= MAX_TRUNCATIONS {
            return Err(Error::OutOfMemory);
        }

        let op_id = self.next_op_id;
        self.next_op_id += 1;

        let mut state = TruncateState::default();
        let start_page = range.start_page();
        let end_page = range.end_page();

        // Handle partial first page for truncate mode.
        if range.has_partial_start() && range.mode == TruncateMode::Truncate {
            let partial_page_idx = start_page;
            if let Some(cache_idx) = self.find_cached_page(range.inode_id, partial_page_idx) {
                // Zero from the truncation offset to page end.
                let offset_in_page = (range.start_offset % PAGE_SIZE) as u32;
                self.cache[cache_idx].valid_bytes = offset_in_page;
                state.partial_pages += 1;
                self.stats.partial_zeroed += 1;
            }
        }

        // Free full pages in the range.
        // We scan the cache and check each page.
        let mut idx = 0;
        while idx < MAX_CACHED_PAGES {
            let page = &self.cache[idx];
            if !page.in_use || page.inode_id != range.inode_id {
                idx += 1;
                continue;
            }

            let page_idx = page.page_index;

            // Determine if this page falls in the truncation range.
            let in_range = if end_page == TRUNCATE_TO_END {
                // For partial start, the partial page itself is kept.
                if range.has_partial_start() && range.mode == TruncateMode::Truncate {
                    page_idx > start_page
                } else {
                    page_idx >= start_page
                }
            } else {
                page_idx >= start_page && page_idx < end_page
            };

            if !in_range {
                idx += 1;
                continue;
            }

            // For invalidation, skip busy pages.
            if range.mode == TruncateMode::InvalidateRange && page.is_busy() {
                state.pages_skipped += 1;
                self.stats.pages_skipped += 1;
                idx += 1;
                continue;
            }

            // For truncate/hole-punch, also skip locked/writeback pages.
            if page.locked || page.writeback {
                state.pages_skipped += 1;
                self.stats.pages_skipped += 1;
                idx += 1;
                continue;
            }

            // Free the page.
            self.cache[idx] = CachedPage::empty();
            self.cache_count -= 1;
            state.pages_freed += 1;
            self.stats.pages_freed += 1;

            // Do not advance idx — the slot is now free and we might
            // have shifted nothing, so check same index again is fine
            // since we marked it empty.
            idx += 1;
        }

        state.completed = true;

        // Update mode-specific stats.
        self.stats.total_truncations += 1;
        match range.mode {
            TruncateMode::HolePunch => self.stats.hole_punches += 1,
            TruncateMode::InvalidateRange => self.stats.invalidations += 1,
            TruncateMode::Truncate => {}
        }

        // Record the operation.
        let slot = self.find_free_op_slot();
        self.operations[slot] = TruncationEntry {
            range,
            state,
            active: false, // Already completed.
            op_id,
        };
        if slot >= self.op_count {
            self.op_count = slot + 1;
        }

        Ok(state)
    }

    /// Finds a cached page by inode ID and page index.
    fn find_cached_page(&self, inode_id: u32, page_index: u64) -> Option<usize> {
        for i in 0..MAX_CACHED_PAGES {
            if self.cache[i].in_use
                && self.cache[i].inode_id == inode_id
                && self.cache[i].page_index == page_index
            {
                return Some(i);
            }
        }
        None
    }

    /// Finds a free slot in the cache array.
    fn find_free_cache_slot(&self) -> usize {
        for i in 0..MAX_CACHED_PAGES {
            if !self.cache[i].in_use {
                return i;
            }
        }
        // Fallback: overwrite last slot (should not happen if count < max).
        MAX_CACHED_PAGES - 1
    }

    /// Finds a free operation slot.
    fn find_free_op_slot(&self) -> usize {
        for i in 0..self.op_count {
            if !self.operations[i].active {
                return i;
            }
        }
        self.op_count
    }
}
