// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Batched page operations.
//!
//! Many memory subsystems need to perform operations on sets of pages
//! (e.g., freeing, zeroing, flushing). Processing pages one at a time
//! incurs overhead from repeated lock acquisitions and TLB flushes.
//! This module provides a page batch that accumulates pages and
//! processes them in bulk.
//!
//! # Design
//!
//! ```text
//!  Caller
//!   │
//!   ├─ PageBatch::add(pfn)  × N
//!   │
//!   └─ PageBatch::drain(callback)
//!        └─ process all pages in one pass
//! ```
//!
//! # Key Types
//!
//! - [`PageBatch`] — accumulates PFNs for batch processing
//! - [`BatchOp`] — type of batch operation
//! - [`BatchStats`] — statistics for batch processing
//!
//! Reference: Linux `include/linux/pagevec.h`, `mm/swap.c` (pagevec).

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Maximum pages in a single batch.
const BATCH_CAPACITY: usize = 64;

/// Maximum batches tracked for statistics.
const MAX_BATCH_HISTORY: usize = 256;

// -------------------------------------------------------------------
// BatchOp
// -------------------------------------------------------------------

/// Type of batch operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BatchOp {
    /// Free pages back to the allocator.
    Free,
    /// Zero page contents.
    Zero,
    /// Flush pages from cache.
    CacheFlush,
    /// Move pages to a different LRU list.
    LruMove,
    /// Unmap pages from page tables.
    Unmap,
}

impl BatchOp {
    /// Return a human-readable name.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Free => "free",
            Self::Zero => "zero",
            Self::CacheFlush => "cache_flush",
            Self::LruMove => "lru_move",
            Self::Unmap => "unmap",
        }
    }
}

// -------------------------------------------------------------------
// PageBatch
// -------------------------------------------------------------------

/// A batch of pages accumulated for bulk processing.
pub struct PageBatch {
    /// PFNs in the batch.
    pfns: [u64; BATCH_CAPACITY],
    /// Number of pages in the batch.
    count: usize,
    /// Operation to perform.
    operation: BatchOp,
}

impl PageBatch {
    /// Create a new empty batch for the given operation.
    pub const fn new(operation: BatchOp) -> Self {
        Self {
            pfns: [0u64; BATCH_CAPACITY],
            count: 0,
            operation,
        }
    }

    /// Return the number of pages in the batch.
    pub const fn len(&self) -> usize {
        self.count
    }

    /// Check whether the batch is empty.
    pub const fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Check whether the batch is full.
    pub const fn is_full(&self) -> bool {
        self.count >= BATCH_CAPACITY
    }

    /// Return the operation type.
    pub const fn operation(&self) -> BatchOp {
        self.operation
    }

    /// Return the capacity.
    pub const fn capacity(&self) -> usize {
        BATCH_CAPACITY
    }

    /// Add a page to the batch. Returns Err if full.
    pub fn add(&mut self, pfn: u64) -> Result<()> {
        if self.is_full() {
            return Err(Error::WouldBlock);
        }
        self.pfns[self.count] = pfn;
        self.count += 1;
        Ok(())
    }

    /// Get the PFN at the given index.
    pub fn get(&self, index: usize) -> Option<u64> {
        if index < self.count {
            Some(self.pfns[index])
        } else {
            None
        }
    }

    /// Drain all pages from the batch and return the count.
    pub fn drain(&mut self) -> usize {
        let count = self.count;
        self.count = 0;
        count
    }

    /// Peek at the batch contents as a slice.
    pub fn as_slice(&self) -> &[u64] {
        &self.pfns[..self.count]
    }

    /// Remove and return the last PFN.
    pub fn pop(&mut self) -> Option<u64> {
        if self.count == 0 {
            return None;
        }
        self.count -= 1;
        Some(self.pfns[self.count])
    }

    /// Reset the batch for a new operation type.
    pub fn reset(&mut self, operation: BatchOp) {
        self.count = 0;
        self.operation = operation;
    }
}

impl Default for PageBatch {
    fn default() -> Self {
        Self::new(BatchOp::Free)
    }
}

// -------------------------------------------------------------------
// BatchStats
// -------------------------------------------------------------------

/// Statistics for batch processing.
#[derive(Debug, Clone, Copy)]
pub struct BatchStats {
    /// Total batches processed.
    pub total_batches: u64,
    /// Total pages processed.
    pub total_pages: u64,
    /// Average batch size.
    pub avg_batch_size: u64,
    /// Maximum batch size seen.
    pub max_batch_size: usize,
    /// Per-operation counts.
    pub op_counts: [u64; 5],
}

impl BatchStats {
    /// Create zero-initialised stats.
    pub const fn new() -> Self {
        Self {
            total_batches: 0,
            total_pages: 0,
            avg_batch_size: 0,
            max_batch_size: 0,
            op_counts: [0u64; 5],
        }
    }

    /// Record a batch completion.
    pub fn record(&mut self, batch_size: usize, operation: BatchOp) {
        self.total_batches += 1;
        self.total_pages += batch_size as u64;
        if batch_size > self.max_batch_size {
            self.max_batch_size = batch_size;
        }
        self.avg_batch_size = if self.total_batches > 0 {
            self.total_pages / self.total_batches
        } else {
            0
        };
        let op_idx = operation as usize;
        if op_idx < self.op_counts.len() {
            self.op_counts[op_idx] += 1;
        }
    }
}

impl Default for BatchStats {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// BatchProcessor
// -------------------------------------------------------------------

/// Processor that manages batch operations and statistics.
pub struct BatchProcessor {
    /// Current batch.
    current: PageBatch,
    /// Statistics.
    stats: BatchStats,
    /// Auto-flush threshold.
    auto_flush_threshold: usize,
}

impl BatchProcessor {
    /// Create a new processor for the given operation.
    pub const fn new(operation: BatchOp) -> Self {
        Self {
            current: PageBatch::new(operation),
            stats: BatchStats::new(),
            auto_flush_threshold: BATCH_CAPACITY,
        }
    }

    /// Set the auto-flush threshold.
    pub fn set_auto_flush(&mut self, threshold: usize) {
        self.auto_flush_threshold = threshold.min(BATCH_CAPACITY);
    }

    /// Add a page, auto-flushing if the threshold is reached.
    pub fn add(&mut self, pfn: u64) -> Result<bool> {
        self.current.add(pfn)?;
        if self.current.len() >= self.auto_flush_threshold {
            self.flush();
            return Ok(true);
        }
        Ok(false)
    }

    /// Flush the current batch.
    pub fn flush(&mut self) -> usize {
        let count = self.current.len();
        if count > 0 {
            self.stats.record(count, self.current.operation());
            self.current.drain();
        }
        count
    }

    /// Return statistics.
    pub const fn stats(&self) -> &BatchStats {
        &self.stats
    }

    /// Return the current batch size.
    pub const fn pending(&self) -> usize {
        self.current.len()
    }
}

impl Default for BatchProcessor {
    fn default() -> Self {
        Self::new(BatchOp::Free)
    }
}

// -------------------------------------------------------------------
// Public helpers
// -------------------------------------------------------------------

/// Create a free-page batch and add pages to it.
pub fn create_free_batch(pfns: &[u64]) -> Result<PageBatch> {
    let mut batch = PageBatch::new(BatchOp::Free);
    for pfn in pfns {
        batch.add(*pfn)?;
    }
    Ok(batch)
}

/// Process a batch of pages and return statistics.
pub fn process_batch(batch: &mut PageBatch) -> (usize, BatchOp) {
    let op = batch.operation();
    let count = batch.drain();
    (count, op)
}

/// Return a summary of batch statistics.
pub fn batch_summary(stats: &BatchStats) -> &'static str {
    if stats.total_batches == 0 {
        "page batching: idle"
    } else if stats.avg_batch_size >= (BATCH_CAPACITY as u64 / 2) {
        "page batching: efficient (large batches)"
    } else {
        "page batching: active (small batches)"
    }
}
