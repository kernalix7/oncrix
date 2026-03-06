// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Batched folio operations.
//!
//! Folios are the modern abstraction for multi-page allocations. This
//! module provides a batch container (`FolioBatch`) that accumulates
//! folios for deferred bulk operations such as page-cache release,
//! writeback submission, or LRU list manipulation. Batching amortizes
//! per-folio overhead (lock acquisitions, TLB flushes, etc.).
//!
//! # Design
//!
//! ```text
//!  add() ──▶ ┌─────────────────────┐
//!            │  FolioBatch          │
//!            │  [folio0, folio1, …] │  ← up to BATCH_SIZE
//!            └──────────┬──────────┘
//!                       │ flush()
//!         ┌─────────────┴─────────────┐
//!         ▼                           ▼
//!   release_pages()            writeback_submit()
//! ```
//!
//! # Key Types
//!
//! - [`FolioRef`] — a lightweight reference to a folio (PFN + order)
//! - [`FolioBatch`] — accumulates folios for bulk processing
//! - [`FolioBatchOp`] — operation to perform on flush
//! - [`BatchStats`] — batch processing statistics
//!
//! Reference: Linux `include/linux/pagevec.h`, `mm/swap.c`.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Maximum folios in a single batch.
const BATCH_SIZE: usize = 31;

/// Maximum batches tracked for statistics.
const MAX_BATCH_HISTORY: usize = 64;

// -------------------------------------------------------------------
// FolioRef
// -------------------------------------------------------------------

/// A lightweight reference to a folio.
#[derive(Debug, Clone, Copy)]
pub struct FolioRef {
    /// Physical frame number of the head page.
    pfn: u64,
    /// Allocation order (0 = single page, 1 = 2 pages, etc.).
    order: u8,
    /// Reference count.
    refcount: u32,
    /// Whether this folio is dirty.
    dirty: bool,
}

impl FolioRef {
    /// Creates a new folio reference.
    pub const fn new(pfn: u64, order: u8) -> Self {
        Self {
            pfn,
            order,
            refcount: 1,
            dirty: false,
        }
    }

    /// Creates an empty folio reference.
    pub const fn empty() -> Self {
        Self {
            pfn: 0,
            order: 0,
            refcount: 0,
            dirty: false,
        }
    }

    /// Returns the PFN.
    pub const fn pfn(&self) -> u64 {
        self.pfn
    }

    /// Returns the order.
    pub const fn order(&self) -> u8 {
        self.order
    }

    /// Returns the number of pages in this folio.
    pub const fn nr_pages(&self) -> usize {
        1 << self.order
    }

    /// Returns the reference count.
    pub const fn refcount(&self) -> u32 {
        self.refcount
    }

    /// Returns whether this folio is dirty.
    pub const fn is_dirty(&self) -> bool {
        self.dirty
    }

    /// Marks the folio as dirty.
    pub fn set_dirty(&mut self) {
        self.dirty = true;
    }

    /// Increments the reference count.
    pub fn get(&mut self) {
        self.refcount = self.refcount.saturating_add(1);
    }

    /// Decrements the reference count. Returns `true` if it reached zero.
    pub fn put(&mut self) -> bool {
        self.refcount = self.refcount.saturating_sub(1);
        self.refcount == 0
    }
}

impl Default for FolioRef {
    fn default() -> Self {
        Self::empty()
    }
}

// -------------------------------------------------------------------
// FolioBatchOp
// -------------------------------------------------------------------

/// Operation to perform when a batch is flushed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FolioBatchOp {
    /// Release (put) the folios.
    Release,
    /// Move folios to the inactive LRU list.
    Deactivate,
    /// Move folios to the active LRU list.
    Activate,
    /// Submit folios for writeback.
    Writeback,
    /// Mark folios as accessed.
    MarkAccessed,
}

impl Default for FolioBatchOp {
    fn default() -> Self {
        Self::Release
    }
}

// -------------------------------------------------------------------
// BatchStats
// -------------------------------------------------------------------

/// Statistics for batch processing.
#[derive(Debug, Clone, Copy)]
pub struct BatchStats {
    /// Total flushes performed.
    pub total_flushes: u64,
    /// Total folios processed.
    pub total_folios: u64,
    /// Total folios freed (refcount reached zero).
    pub total_freed: u64,
    /// Average batch size at flush time.
    pub avg_batch_size: u64,
}

impl BatchStats {
    /// Creates empty statistics.
    pub const fn new() -> Self {
        Self {
            total_flushes: 0,
            total_folios: 0,
            total_freed: 0,
            avg_batch_size: 0,
        }
    }

    /// Updates the average batch size.
    pub fn update_avg(&mut self) {
        if self.total_flushes > 0 {
            self.avg_batch_size = self.total_folios / self.total_flushes;
        }
    }
}

impl Default for BatchStats {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// FolioBatch
// -------------------------------------------------------------------

/// Accumulates folios for deferred bulk processing.
pub struct FolioBatch {
    /// Batch buffer.
    folios: [FolioRef; BATCH_SIZE],
    /// Current number of folios in the batch.
    count: usize,
    /// Operation to perform on flush.
    op: FolioBatchOp,
    /// Statistics.
    stats: BatchStats,
}

impl FolioBatch {
    /// Creates a new empty batch.
    pub const fn new(op: FolioBatchOp) -> Self {
        Self {
            folios: [const { FolioRef::empty() }; BATCH_SIZE],
            count: 0,
            op,
            stats: BatchStats::new(),
        }
    }

    /// Returns the number of folios in the batch.
    pub const fn count(&self) -> usize {
        self.count
    }

    /// Returns `true` if the batch is full.
    pub const fn is_full(&self) -> bool {
        self.count >= BATCH_SIZE
    }

    /// Returns `true` if the batch is empty.
    pub const fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Returns the batch operation.
    pub const fn op(&self) -> FolioBatchOp {
        self.op
    }

    /// Returns the statistics.
    pub const fn stats(&self) -> &BatchStats {
        &self.stats
    }

    /// Adds a folio to the batch. Returns `Err(Busy)` if full.
    pub fn add(&mut self, folio: FolioRef) -> Result<()> {
        if self.count >= BATCH_SIZE {
            return Err(Error::Busy);
        }
        self.folios[self.count] = folio;
        self.count += 1;
        Ok(())
    }

    /// Adds a folio, auto-flushing if the batch is full.
    ///
    /// Returns the number of folios freed if a flush occurred.
    pub fn add_and_flush(&mut self, folio: FolioRef) -> Result<usize> {
        let freed = if self.is_full() { self.flush() } else { 0 };
        self.add(folio)?;
        Ok(freed)
    }

    /// Flushes the batch, performing the configured operation on all
    /// accumulated folios. Returns the number of folios freed.
    pub fn flush(&mut self) -> usize {
        if self.count == 0 {
            return 0;
        }

        let mut freed = 0;
        let batch_count = self.count;

        for i in 0..batch_count {
            match self.op {
                FolioBatchOp::Release => {
                    if self.folios[i].put() {
                        freed += 1;
                    }
                }
                FolioBatchOp::Deactivate | FolioBatchOp::Activate | FolioBatchOp::MarkAccessed => {
                    // These are list-movement operations — no freeing.
                }
                FolioBatchOp::Writeback => {
                    // Mark clean after writeback.
                    self.folios[i].dirty = false;
                }
            }
        }

        self.stats.total_flushes = self.stats.total_flushes.saturating_add(1);
        self.stats.total_folios = self.stats.total_folios.saturating_add(batch_count as u64);
        self.stats.total_freed = self.stats.total_freed.saturating_add(freed as u64);
        self.stats.update_avg();

        self.count = 0;
        freed
    }

    /// Returns the folios currently in the batch.
    pub fn folios(&self) -> &[FolioRef] {
        &self.folios[..self.count]
    }
}

impl Default for FolioBatch {
    fn default() -> Self {
        Self::new(FolioBatchOp::Release)
    }
}

// -------------------------------------------------------------------
// Public helpers
// -------------------------------------------------------------------

/// Creates a new folio batch for the given operation.
pub fn create_batch(op: FolioBatchOp) -> FolioBatch {
    FolioBatch::new(op)
}

/// Adds a folio to a batch, flushing first if full.
pub fn batch_add(batch: &mut FolioBatch, folio: FolioRef) -> Result<usize> {
    batch.add_and_flush(folio)
}

/// Flushes a batch and returns the number of folios freed.
pub fn batch_flush(batch: &mut FolioBatch) -> usize {
    batch.flush()
}
