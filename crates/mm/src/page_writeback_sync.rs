// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Synchronous page writeback.
//!
//! Implements synchronous writeback of dirty pages, used by `fsync()`,
//! `msync()`, and the periodic writeback timer. Ensures dirty pages
//! are flushed to their backing store within bounded time.
//!
//! - [`SyncMode`] — writeback synchronization modes
//! - [`SyncRange`] — range of pages to synchronize
//! - [`SyncRequest`] — a pending sync request
//! - [`SyncStats`] — writeback statistics
//! - [`PageWritebackSync`] — the sync engine
//!
//! Reference: Linux `mm/page-writeback.c` (sync paths).

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Page size (4 KiB).
const PAGE_SIZE: u64 = 4096;

/// Maximum pending sync requests.
const MAX_REQUESTS: usize = 128;

/// Default writeback batch size.
const DEFAULT_BATCH: u64 = 64;

// -------------------------------------------------------------------
// SyncMode
// -------------------------------------------------------------------

/// Writeback synchronization modes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SyncMode {
    /// No sync — just schedule writeback.
    #[default]
    None,
    /// Data integrity — wait for I/O completion.
    DataIntegrity,
    /// Write-for-data-integrity — write but don't wait.
    WriteSync,
}

// -------------------------------------------------------------------
// SyncRange
// -------------------------------------------------------------------

/// Range of pages to synchronize.
#[derive(Debug, Clone, Copy, Default)]
pub struct SyncRange {
    /// Start page index.
    pub start_page: u64,
    /// End page index (exclusive).
    pub end_page: u64,
}

impl SyncRange {
    /// Creates a new sync range.
    pub fn new(start_page: u64, end_page: u64) -> Result<Self> {
        if start_page >= end_page {
            return Err(Error::InvalidArgument);
        }
        Ok(Self {
            start_page,
            end_page,
        })
    }

    /// Returns the number of pages in the range.
    pub fn nr_pages(&self) -> u64 {
        self.end_page.saturating_sub(self.start_page)
    }

    /// Returns the byte range start.
    pub fn byte_start(&self) -> u64 {
        self.start_page * PAGE_SIZE
    }

    /// Returns the byte range end.
    pub fn byte_end(&self) -> u64 {
        self.end_page * PAGE_SIZE
    }
}

// -------------------------------------------------------------------
// SyncRequest
// -------------------------------------------------------------------

/// A pending sync request.
#[derive(Debug, Clone, Copy, Default)]
pub struct SyncRequest {
    /// Mapping ID (inode or anon).
    pub mapping_id: u64,
    /// Range to sync.
    pub range: SyncRange,
    /// Sync mode.
    pub mode: SyncMode,
    /// Pages written so far.
    pub pages_written: u64,
    /// Whether the request is complete.
    pub complete: bool,
    /// Whether this slot is active.
    pub active: bool,
}

// -------------------------------------------------------------------
// SyncStats
// -------------------------------------------------------------------

/// Synchronous writeback statistics.
#[derive(Debug, Clone, Copy, Default)]
pub struct SyncStats {
    /// Total sync requests.
    pub requests: u64,
    /// Completed requests.
    pub completed: u64,
    /// Total pages written.
    pub pages_written: u64,
    /// Data integrity syncs.
    pub data_integrity_syncs: u64,
    /// Total bytes written.
    pub bytes_written: u64,
}

impl SyncStats {
    /// Resets all counters.
    pub fn reset(&mut self) {
        *self = Self::default();
    }
}

// -------------------------------------------------------------------
// PageWritebackSync
// -------------------------------------------------------------------

/// The synchronous page writeback engine.
pub struct PageWritebackSync {
    /// Pending requests.
    requests: [SyncRequest; MAX_REQUESTS],
    /// Number of requests.
    count: usize,
    /// Batch size.
    batch_size: u64,
    /// Statistics.
    stats: SyncStats,
}

impl Default for PageWritebackSync {
    fn default() -> Self {
        Self {
            requests: [SyncRequest::default(); MAX_REQUESTS],
            count: 0,
            batch_size: DEFAULT_BATCH,
            stats: SyncStats::default(),
        }
    }
}

impl PageWritebackSync {
    /// Creates a new sync engine.
    pub fn new() -> Self {
        Self::default()
    }

    /// Submits a sync request.
    pub fn submit(
        &mut self,
        mapping_id: u64,
        start_page: u64,
        end_page: u64,
        mode: SyncMode,
    ) -> Result<usize> {
        if self.count >= MAX_REQUESTS {
            return Err(Error::OutOfMemory);
        }
        let range = SyncRange::new(start_page, end_page)?;
        let idx = self.count;
        self.requests[idx] = SyncRequest {
            mapping_id,
            range,
            mode,
            pages_written: 0,
            complete: false,
            active: true,
        };
        self.count += 1;
        self.stats.requests += 1;
        if mode == SyncMode::DataIntegrity {
            self.stats.data_integrity_syncs += 1;
        }
        Ok(idx)
    }

    /// Processes a sync request (writes dirty pages in batch).
    pub fn process(&mut self, idx: usize) -> Result<u64> {
        if idx >= self.count || !self.requests[idx].active {
            return Err(Error::NotFound);
        }
        if self.requests[idx].complete {
            return Ok(0);
        }

        let remaining = self.requests[idx]
            .range
            .nr_pages()
            .saturating_sub(self.requests[idx].pages_written);
        let to_write = remaining.min(self.batch_size);

        self.requests[idx].pages_written += to_write;
        self.stats.pages_written += to_write;
        self.stats.bytes_written += to_write * PAGE_SIZE;

        if self.requests[idx].pages_written >= self.requests[idx].range.nr_pages() {
            self.requests[idx].complete = true;
            self.stats.completed += 1;
        }

        Ok(to_write)
    }

    /// Processes all pending requests.
    pub fn process_all(&mut self) -> u64 {
        let mut total = 0u64;
        for i in 0..self.count {
            if self.requests[i].active && !self.requests[i].complete {
                if let Ok(written) = self.process(i) {
                    total += written;
                }
            }
        }
        total
    }

    /// Returns the number of pending (incomplete) requests.
    pub fn pending_count(&self) -> usize {
        self.requests[..self.count]
            .iter()
            .filter(|r| r.active && !r.complete)
            .count()
    }

    /// Returns statistics.
    pub fn stats(&self) -> &SyncStats {
        &self.stats
    }

    /// Resets statistics.
    pub fn reset_stats(&mut self) {
        self.stats.reset();
    }
}
