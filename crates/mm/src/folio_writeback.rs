// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Folio writeback management.
//!
//! Manages writeback for folios (compound page groups) used by the
//! page cache. Tracks folio dirty/writeback state, handles folio
//! completion callbacks, and coordinates multi-page writeback for
//! folios larger than a single base page.
//!
//! - [`FolioState`] — folio writeback lifecycle state
//! - [`FolioWbEntry`] — a folio under writeback
//! - [`FolioWbStats`] — writeback statistics
//! - [`FolioWritebackCtx`] — the folio writeback context
//!
//! Reference: Linux `mm/folio-compat.c`, `mm/page-writeback.c`.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Maximum folios tracked.
const MAX_FOLIOS: usize = 256;

/// Default writeback batch.
const DEFAULT_BATCH: usize = 16;

// -------------------------------------------------------------------
// FolioState
// -------------------------------------------------------------------

/// Folio writeback lifecycle state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum FolioState {
    /// Clean — no dirty pages.
    #[default]
    Clean,
    /// Dirty — needs writeback.
    Dirty,
    /// Under writeback.
    Writeback,
    /// Writeback complete — waiting for cleanup.
    Complete,
    /// Error during writeback.
    Error,
}

// -------------------------------------------------------------------
// FolioWbEntry
// -------------------------------------------------------------------

/// A folio under writeback tracking.
#[derive(Debug, Clone, Copy, Default)]
pub struct FolioWbEntry {
    /// Folio index (page cache index).
    pub index: u64,
    /// Folio order (0 = single page, 9 = 2 MiB).
    pub order: u32,
    /// Number of base pages in this folio.
    pub nr_pages: u32,
    /// Mapping ID (inode).
    pub mapping_id: u64,
    /// Current state.
    pub state: FolioState,
    /// Pages written so far.
    pub pages_written: u32,
    /// Whether this entry is active.
    pub active: bool,
}

impl FolioWbEntry {
    /// Creates a new folio writeback entry.
    pub fn new(index: u64, order: u32, mapping_id: u64) -> Self {
        Self {
            index,
            order,
            nr_pages: 1u32.wrapping_shl(order),
            mapping_id,
            state: FolioState::Dirty,
            pages_written: 0,
            active: true,
        }
    }

    /// Returns `true` if all pages have been written.
    pub fn is_complete(&self) -> bool {
        self.pages_written >= self.nr_pages
    }

    /// Returns the progress ratio (per-mille).
    pub fn progress(&self) -> u32 {
        if self.nr_pages == 0 {
            return 1000;
        }
        (self.pages_written as u64 * 1000 / self.nr_pages as u64) as u32
    }
}

// -------------------------------------------------------------------
// FolioWbStats
// -------------------------------------------------------------------

/// Folio writeback statistics.
#[derive(Debug, Clone, Copy, Default)]
pub struct FolioWbStats {
    /// Total folios submitted for writeback.
    pub submitted: u64,
    /// Total folios completed.
    pub completed: u64,
    /// Total folios with errors.
    pub errors: u64,
    /// Total pages written.
    pub pages_written: u64,
    /// Total large folios (order > 0) written.
    pub large_folios: u64,
}

impl FolioWbStats {
    /// Resets all counters.
    pub fn reset(&mut self) {
        *self = Self::default();
    }
}

// -------------------------------------------------------------------
// FolioWritebackCtx
// -------------------------------------------------------------------

/// The folio writeback context.
pub struct FolioWritebackCtx {
    /// Tracked folios.
    folios: [FolioWbEntry; MAX_FOLIOS],
    /// Number of tracked folios.
    count: usize,
    /// Writeback batch size (folios per pass).
    batch_size: usize,
    /// Statistics.
    stats: FolioWbStats,
}

impl Default for FolioWritebackCtx {
    fn default() -> Self {
        Self {
            folios: [FolioWbEntry::default(); MAX_FOLIOS],
            count: 0,
            batch_size: DEFAULT_BATCH,
            stats: FolioWbStats::default(),
        }
    }
}

impl FolioWritebackCtx {
    /// Creates a new folio writeback context.
    pub fn new() -> Self {
        Self::default()
    }

    /// Marks a folio as dirty and submits for writeback.
    pub fn submit(&mut self, index: u64, order: u32, mapping_id: u64) -> Result<usize> {
        if self.count >= MAX_FOLIOS {
            return Err(Error::OutOfMemory);
        }
        let idx = self.count;
        self.folios[idx] = FolioWbEntry::new(index, order, mapping_id);
        self.count += 1;
        self.stats.submitted += 1;
        if order > 0 {
            self.stats.large_folios += 1;
        }
        Ok(idx)
    }

    /// Processes writeback for a single folio.
    pub fn writeback(&mut self, idx: usize) -> Result<u32> {
        if idx >= self.count || !self.folios[idx].active {
            return Err(Error::NotFound);
        }
        if self.folios[idx].state == FolioState::Complete {
            return Ok(0);
        }

        self.folios[idx].state = FolioState::Writeback;
        let remaining = self.folios[idx]
            .nr_pages
            .saturating_sub(self.folios[idx].pages_written);
        self.folios[idx].pages_written += remaining;
        self.stats.pages_written += remaining as u64;

        if self.folios[idx].is_complete() {
            self.folios[idx].state = FolioState::Complete;
            self.stats.completed += 1;
        }
        Ok(remaining)
    }

    /// Processes a batch of folios.
    pub fn writeback_batch(&mut self) -> u64 {
        let mut total = 0u64;
        let mut processed = 0;

        for i in 0..self.count {
            if processed >= self.batch_size {
                break;
            }
            if !self.folios[i].active || self.folios[i].state == FolioState::Complete {
                continue;
            }
            if let Ok(written) = self.writeback(i) {
                total += written as u64;
                processed += 1;
            }
        }
        total
    }

    /// Marks a folio as having an error.
    pub fn mark_error(&mut self, idx: usize) -> Result<()> {
        if idx >= self.count || !self.folios[idx].active {
            return Err(Error::NotFound);
        }
        self.folios[idx].state = FolioState::Error;
        self.stats.errors += 1;
        Ok(())
    }

    /// Returns the number of dirty folios.
    pub fn dirty_count(&self) -> usize {
        self.folios[..self.count]
            .iter()
            .filter(|f| f.active && f.state == FolioState::Dirty)
            .count()
    }

    /// Returns statistics.
    pub fn stats(&self) -> &FolioWbStats {
        &self.stats
    }

    /// Resets statistics.
    pub fn reset_stats(&mut self) {
        self.stats.reset();
    }
}
