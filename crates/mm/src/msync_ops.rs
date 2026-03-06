// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! msync operations for the ONCRIX memory management subsystem.
//!
//! Implements the `msync(2)` system call, which synchronizes memory-
//! mapped files with their backing storage. Supports asynchronous,
//! synchronous, and invalidate modes.
//!
//! - [`MsyncFlags`] — sync mode flags (ASYNC, SYNC, INVALIDATE)
//! - [`MsyncOps`] — main msync handler with VMA tracking
//! - [`MsyncResult`] — outcome of a sync operation
//! - [`MsyncStats`] — operation statistics
//!
//! Reference: `.kernelORG/` — `mm/msync.c`, POSIX `msync(2)`.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Standard page size (4 KiB).
const PAGE_SIZE: u64 = 4096;

/// Maximum number of VMAs tracked for msync.
const MAX_VMAS: usize = 256;

/// Maximum number of dirty pages tracked per VMA.
const MAX_DIRTY_PAGES: usize = 128;

// -------------------------------------------------------------------
// MsyncFlags
// -------------------------------------------------------------------

/// Flags for the msync operation.
pub struct MsyncFlags;

impl MsyncFlags {
    /// Initiate writeback but don't wait for completion.
    pub const ASYNC: u32 = 1 << 0;
    /// Initiate writeback and wait for completion.
    pub const SYNC: u32 = 1 << 1;
    /// Invalidate cached data after sync.
    pub const INVALIDATE: u32 = 1 << 2;
}

// -------------------------------------------------------------------
// SyncMode
// -------------------------------------------------------------------

/// Sync mode derived from msync flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SyncMode {
    /// No sync (NOP for clean pages).
    #[default]
    None,
    /// Asynchronous writeback (queue and return).
    Async,
    /// Synchronous writeback (wait for completion).
    Sync,
}

// -------------------------------------------------------------------
// DirtyPage
// -------------------------------------------------------------------

/// Tracks a dirty page within a VMA.
#[derive(Debug, Clone, Copy, Default)]
pub struct DirtyPage {
    /// Page offset within the VMA.
    pub offset: u64,
    /// Whether the page is dirty.
    pub dirty: bool,
    /// Whether writeback has been initiated.
    pub writeback_started: bool,
    /// Whether writeback has completed.
    pub writeback_done: bool,
}

impl DirtyPage {
    /// Create an empty dirty page entry.
    pub const fn empty() -> Self {
        Self {
            offset: 0,
            dirty: false,
            writeback_started: false,
            writeback_done: false,
        }
    }

    /// Check if this page needs writeback.
    pub fn needs_writeback(&self) -> bool {
        self.dirty && !self.writeback_started
    }
}

// -------------------------------------------------------------------
// MsyncVma
// -------------------------------------------------------------------

/// A VMA entry tracked for msync operations.
#[derive(Debug, Clone, Copy)]
pub struct MsyncVma {
    /// Start address (page-aligned).
    pub start: u64,
    /// End address (page-aligned, exclusive).
    pub end: u64,
    /// Whether this VMA is file-backed.
    pub file_backed: bool,
    /// Whether this VMA is shared.
    pub shared: bool,
    /// Number of dirty pages.
    pub dirty_count: u32,
    /// Dirty page tracking.
    dirty_pages: [DirtyPage; MAX_DIRTY_PAGES],
    /// Whether this VMA is active.
    pub active: bool,
}

impl MsyncVma {
    /// Create an empty VMA.
    pub const fn empty() -> Self {
        Self {
            start: 0,
            end: 0,
            file_backed: false,
            shared: false,
            dirty_count: 0,
            dirty_pages: [DirtyPage::empty(); MAX_DIRTY_PAGES],
            active: false,
        }
    }

    /// Size of the VMA in bytes.
    pub fn size(&self) -> u64 {
        self.end.saturating_sub(self.start)
    }

    /// Number of pages in the VMA.
    pub fn page_count(&self) -> u64 {
        self.size() / PAGE_SIZE
    }

    /// Check if this VMA needs sync (file-backed and has dirty pages).
    pub fn needs_sync(&self) -> bool {
        self.active && self.file_backed && self.dirty_count > 0
    }

    /// Check if the VMA overlaps the given range.
    pub fn overlaps(&self, start: u64, end: u64) -> bool {
        self.active && self.start < end && self.end > start
    }

    /// Mark a page as dirty within this VMA.
    pub fn mark_dirty(&mut self, page_offset: u64) -> bool {
        if (self.dirty_count as usize) >= MAX_DIRTY_PAGES {
            return false;
        }
        let idx = self.dirty_count as usize;
        self.dirty_pages[idx] = DirtyPage {
            offset: page_offset,
            dirty: true,
            writeback_started: false,
            writeback_done: false,
        };
        self.dirty_count += 1;
        true
    }

    /// Initiate writeback for all dirty pages.
    fn initiate_writeback(&mut self) -> u32 {
        let mut initiated = 0u32;
        for i in 0..(self.dirty_count as usize) {
            if self.dirty_pages[i].needs_writeback() {
                self.dirty_pages[i].writeback_started = true;
                initiated += 1;
            }
        }
        initiated
    }

    /// Complete writeback for all pages with started writeback.
    fn complete_writeback(&mut self) -> u32 {
        let mut completed = 0u32;
        for i in 0..(self.dirty_count as usize) {
            if self.dirty_pages[i].writeback_started && !self.dirty_pages[i].writeback_done {
                self.dirty_pages[i].writeback_done = true;
                self.dirty_pages[i].dirty = false;
                completed += 1;
            }
        }
        // Compact: remove completed entries.
        let mut write_idx = 0usize;
        for read_idx in 0..(self.dirty_count as usize) {
            if self.dirty_pages[read_idx].dirty {
                self.dirty_pages[write_idx] = self.dirty_pages[read_idx];
                write_idx += 1;
            }
        }
        self.dirty_count = write_idx as u32;
        completed
    }

    /// Invalidate cached pages in the range.
    fn invalidate_range(&mut self, start: u64, end: u64) -> u32 {
        let vma_start = self.start;
        let mut invalidated = 0u32;

        let mut write_idx = 0usize;
        for read_idx in 0..(self.dirty_count as usize) {
            let page_addr = vma_start + self.dirty_pages[read_idx].offset;
            if page_addr >= start && page_addr < end {
                invalidated += 1;
            } else {
                self.dirty_pages[write_idx] = self.dirty_pages[read_idx];
                write_idx += 1;
            }
        }
        self.dirty_count = write_idx as u32;
        invalidated
    }
}

// -------------------------------------------------------------------
// MsyncResult
// -------------------------------------------------------------------

/// Outcome of an msync operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MsyncResult {
    /// Sync completed successfully.
    Synced {
        /// Number of pages written back.
        pages_synced: u32,
    },
    /// Async writeback initiated.
    WritebackInitiated {
        /// Number of pages queued for writeback.
        pages_queued: u32,
    },
    /// No dirty pages needed syncing.
    Clean,
    /// Pages were invalidated.
    Invalidated {
        /// Number of pages invalidated.
        pages_invalidated: u32,
    },
}

// -------------------------------------------------------------------
// MsyncStats
// -------------------------------------------------------------------

/// Statistics for msync operations.
#[derive(Debug, Clone, Copy, Default)]
pub struct MsyncStats {
    /// Total msync calls.
    pub total_calls: u64,
    /// Number of synchronous syncs.
    pub sync_calls: u64,
    /// Number of asynchronous syncs.
    pub async_calls: u64,
    /// Number of invalidate operations.
    pub invalidate_calls: u64,
    /// Total pages synced (written back).
    pub pages_synced: u64,
    /// Total pages invalidated.
    pub pages_invalidated: u64,
    /// Number of no-op calls (no dirty pages).
    pub noop_calls: u64,
    /// Number of failures.
    pub failures: u64,
}

// -------------------------------------------------------------------
// MsyncOps
// -------------------------------------------------------------------

/// Main msync handler.
///
/// Processes msync requests by walking VMAs in the specified range,
/// checking for dirty file-backed pages, and initiating or completing
/// writeback.
pub struct MsyncOps {
    /// VMA table.
    vmas: [MsyncVma; MAX_VMAS],
    /// Number of VMAs.
    vma_count: usize,
    /// Statistics.
    stats: MsyncStats,
}

impl MsyncOps {
    /// Create a new msync handler.
    pub fn new() -> Self {
        Self {
            vmas: [MsyncVma::empty(); MAX_VMAS],
            vma_count: 0,
            stats: MsyncStats::default(),
        }
    }

    /// Register a VMA for msync tracking.
    ///
    /// # Errors
    ///
    /// Returns `OutOfMemory` if the VMA table is full, or
    /// `InvalidArgument` if the range is invalid.
    pub fn register_vma(
        &mut self,
        start: u64,
        end: u64,
        file_backed: bool,
        shared: bool,
    ) -> Result<usize> {
        if start >= end || start % PAGE_SIZE != 0 || end % PAGE_SIZE != 0 {
            return Err(Error::InvalidArgument);
        }
        if self.vma_count >= MAX_VMAS {
            return Err(Error::OutOfMemory);
        }

        let idx = self.vma_count;
        self.vmas[idx] = MsyncVma {
            start,
            end,
            file_backed,
            shared,
            dirty_count: 0,
            dirty_pages: [DirtyPage::empty(); MAX_DIRTY_PAGES],
            active: true,
        };
        self.vma_count += 1;
        Ok(idx)
    }

    /// Mark a page as dirty in the appropriate VMA.
    ///
    /// # Errors
    ///
    /// Returns `NotFound` if no VMA contains the address.
    pub fn mark_page_dirty(&mut self, addr: u64) -> Result<()> {
        let page_addr = addr & !(PAGE_SIZE - 1);

        for i in 0..self.vma_count {
            let vma = &self.vmas[i];
            if vma.active && page_addr >= vma.start && page_addr < vma.end {
                let offset = page_addr - vma.start;
                if !self.vmas[i].mark_dirty(offset) {
                    return Err(Error::OutOfMemory);
                }
                return Ok(());
            }
        }
        Err(Error::NotFound)
    }

    /// Perform an msync operation on the specified range.
    ///
    /// Walks all VMAs overlapping the range and, for file-backed
    /// VMAs with dirty pages, initiates or waits for writeback.
    ///
    /// # Errors
    ///
    /// Returns `InvalidArgument` if the range or flags are invalid.
    pub fn do_msync(&mut self, start: u64, len: u64, flags: u32) -> Result<MsyncResult> {
        if len == 0 || start % PAGE_SIZE != 0 {
            return Err(Error::InvalidArgument);
        }

        // MS_ASYNC and MS_SYNC are mutually exclusive.
        let is_async = flags & MsyncFlags::ASYNC != 0;
        let is_sync = flags & MsyncFlags::SYNC != 0;
        let is_invalidate = flags & MsyncFlags::INVALIDATE != 0;

        if is_async && is_sync {
            return Err(Error::InvalidArgument);
        }

        let end = start.saturating_add(len);
        let aligned_end = (end + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);

        self.stats.total_calls += 1;

        // Determine sync mode.
        let mode = if is_sync {
            self.stats.sync_calls += 1;
            SyncMode::Sync
        } else if is_async {
            self.stats.async_calls += 1;
            SyncMode::Async
        } else {
            SyncMode::None
        };

        let mut total_synced = 0u32;
        let mut total_invalidated = 0u32;
        let mut any_dirty = false;

        // Walk VMAs.
        for i in 0..self.vma_count {
            if !self.vmas[i].overlaps(start, aligned_end) {
                continue;
            }
            if !self.vmas[i].needs_sync() {
                continue;
            }

            any_dirty = true;

            match mode {
                SyncMode::Sync => {
                    let initiated = self.vmas[i].initiate_writeback();
                    let completed = self.vmas[i].complete_writeback();
                    total_synced += initiated.max(completed);
                }
                SyncMode::Async => {
                    let initiated = self.vmas[i].initiate_writeback();
                    total_synced += initiated;
                }
                SyncMode::None => {}
            }

            if is_invalidate {
                let inv = self.vmas[i].invalidate_range(start, aligned_end);
                total_invalidated += inv;
                self.stats.invalidate_calls += 1;
            }
        }

        if !any_dirty && !is_invalidate {
            self.stats.noop_calls += 1;
            return Ok(MsyncResult::Clean);
        }

        self.stats.pages_synced += total_synced as u64;
        self.stats.pages_invalidated += total_invalidated as u64;

        if is_invalidate && total_invalidated > 0 {
            return Ok(MsyncResult::Invalidated {
                pages_invalidated: total_invalidated,
            });
        }

        match mode {
            SyncMode::Sync => Ok(MsyncResult::Synced {
                pages_synced: total_synced,
            }),
            SyncMode::Async => Ok(MsyncResult::WritebackInitiated {
                pages_queued: total_synced,
            }),
            SyncMode::None => Ok(MsyncResult::Clean),
        }
    }

    /// Get statistics.
    pub fn statistics(&self) -> &MsyncStats {
        &self.stats
    }

    /// Get the number of active VMAs.
    pub fn vma_count(&self) -> usize {
        self.vmas
            .iter()
            .take(self.vma_count)
            .filter(|v| v.active)
            .count()
    }

    /// Get a VMA by index.
    ///
    /// # Errors
    ///
    /// Returns `InvalidArgument` if the index is out of bounds.
    pub fn get_vma(&self, idx: usize) -> Result<&MsyncVma> {
        if idx >= self.vma_count {
            return Err(Error::InvalidArgument);
        }
        Ok(&self.vmas[idx])
    }

    /// Get the total number of dirty pages across all VMAs.
    pub fn total_dirty_pages(&self) -> u32 {
        let mut total = 0u32;
        for i in 0..self.vma_count {
            if self.vmas[i].active {
                total += self.vmas[i].dirty_count;
            }
        }
        total
    }
}
