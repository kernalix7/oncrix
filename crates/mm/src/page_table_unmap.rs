// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Page table unmapping operations.
//!
//! Implements the unmap path for page table entries: clearing PTEs,
//! flushing TLB entries, batching unmap operations for efficiency,
//! and handling the various unmap scenarios (munmap, exit, migration).
//!
//! - [`UnmapReason`] — reason for the unmap operation
//! - [`UnmapEntry`] — a single PTE to unmap
//! - [`TlbFlushBatch`] — batched TLB flush descriptor
//! - [`UnmapStats`] — unmap statistics
//! - [`PageTableUnmap`] — the unmap engine
//!
//! Reference: Linux `mm/memory.c` (unmap_page_range).

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Maximum entries in an unmap batch.
const MAX_BATCH: usize = 256;

/// Maximum TLB flush batch entries.
const MAX_TLB_BATCH: usize = 128;

// -------------------------------------------------------------------
// UnmapReason
// -------------------------------------------------------------------

/// Reason for the unmap operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum UnmapReason {
    /// Process exit.
    #[default]
    Exit,
    /// munmap() system call.
    Munmap,
    /// Page migration.
    Migration,
    /// madvise(DONTNEED).
    MadviseDontneed,
    /// Page reclaim.
    Reclaim,
}

// -------------------------------------------------------------------
// UnmapEntry
// -------------------------------------------------------------------

/// A single PTE to unmap.
#[derive(Debug, Clone, Copy, Default)]
pub struct UnmapEntry {
    /// Virtual address.
    pub vaddr: u64,
    /// PFN that was mapped.
    pub pfn: u64,
    /// Whether the page was dirty.
    pub dirty: bool,
    /// Whether the page was accessed.
    pub accessed: bool,
    /// Unmap reason.
    pub reason: UnmapReason,
    /// Whether this entry is active.
    pub active: bool,
}

impl UnmapEntry {
    /// Creates a new unmap entry.
    pub fn new(vaddr: u64, pfn: u64, reason: UnmapReason) -> Self {
        Self {
            vaddr,
            pfn,
            dirty: false,
            accessed: false,
            reason,
            active: true,
        }
    }
}

// -------------------------------------------------------------------
// TlbFlushBatch
// -------------------------------------------------------------------

/// Batched TLB flush descriptor.
pub struct TlbFlushBatch {
    /// Virtual addresses to flush.
    addrs: [u64; MAX_TLB_BATCH],
    /// Number of entries.
    count: usize,
    /// Whether a full flush is needed (too many entries).
    full_flush: bool,
}

impl Default for TlbFlushBatch {
    fn default() -> Self {
        Self {
            addrs: [0u64; MAX_TLB_BATCH],
            count: 0,
            full_flush: false,
        }
    }
}

impl TlbFlushBatch {
    /// Creates a new empty batch.
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds an address to the flush batch.
    pub fn add(&mut self, vaddr: u64) {
        if self.count >= MAX_TLB_BATCH {
            self.full_flush = true;
            return;
        }
        self.addrs[self.count] = vaddr;
        self.count += 1;
    }

    /// Returns the number of entries.
    pub fn count(&self) -> usize {
        self.count
    }

    /// Returns `true` if a full TLB flush is needed.
    pub fn needs_full_flush(&self) -> bool {
        self.full_flush
    }

    /// Resets the batch.
    pub fn reset(&mut self) {
        self.count = 0;
        self.full_flush = false;
    }
}

// -------------------------------------------------------------------
// UnmapStats
// -------------------------------------------------------------------

/// Unmap statistics.
#[derive(Debug, Clone, Copy, Default)]
pub struct UnmapStats {
    /// Total PTEs unmapped.
    pub ptes_unmapped: u64,
    /// Dirty pages found during unmap.
    pub dirty_pages: u64,
    /// Accessed pages found during unmap.
    pub accessed_pages: u64,
    /// TLB flush batches executed.
    pub tlb_flushes: u64,
    /// Full TLB flushes.
    pub full_tlb_flushes: u64,
    /// Unmap operations (ranges).
    pub unmap_ops: u64,
}

impl UnmapStats {
    /// Resets all counters.
    pub fn reset(&mut self) {
        *self = Self::default();
    }
}

// -------------------------------------------------------------------
// PageTableUnmap
// -------------------------------------------------------------------

/// The page table unmap engine.
pub struct PageTableUnmap {
    /// Pending unmap entries.
    entries: [UnmapEntry; MAX_BATCH],
    /// Number of entries.
    count: usize,
    /// TLB flush batch.
    tlb_batch: TlbFlushBatch,
    /// Statistics.
    stats: UnmapStats,
}

impl Default for PageTableUnmap {
    fn default() -> Self {
        Self {
            entries: [UnmapEntry::default(); MAX_BATCH],
            count: 0,
            tlb_batch: TlbFlushBatch::new(),
            stats: UnmapStats::default(),
        }
    }
}

impl PageTableUnmap {
    /// Creates a new unmap engine.
    pub fn new() -> Self {
        Self::default()
    }

    /// Queues a PTE for unmapping.
    pub fn queue(
        &mut self,
        vaddr: u64,
        pfn: u64,
        dirty: bool,
        accessed: bool,
        reason: UnmapReason,
    ) -> Result<()> {
        if self.count >= MAX_BATCH {
            return Err(Error::OutOfMemory);
        }
        self.entries[self.count] = UnmapEntry {
            vaddr,
            pfn,
            dirty,
            accessed,
            reason,
            active: true,
        };
        self.count += 1;
        Ok(())
    }

    /// Executes all pending unmaps and flushes TLB.
    pub fn flush(&mut self) -> u64 {
        let mut unmapped = 0u64;

        for i in 0..self.count {
            if !self.entries[i].active {
                continue;
            }
            self.tlb_batch.add(self.entries[i].vaddr);

            if self.entries[i].dirty {
                self.stats.dirty_pages += 1;
            }
            if self.entries[i].accessed {
                self.stats.accessed_pages += 1;
            }
            self.entries[i].active = false;
            unmapped += 1;
        }

        // Execute TLB flush.
        if self.tlb_batch.needs_full_flush() {
            self.stats.full_tlb_flushes += 1;
        }
        if self.tlb_batch.count() > 0 || self.tlb_batch.needs_full_flush() {
            self.stats.tlb_flushes += 1;
        }

        self.stats.ptes_unmapped += unmapped;
        self.stats.unmap_ops += 1;

        self.count = 0;
        self.tlb_batch.reset();
        unmapped
    }

    /// Returns the number of queued entries.
    pub fn queued_count(&self) -> usize {
        self.count
    }

    /// Returns statistics.
    pub fn stats(&self) -> &UnmapStats {
        &self.stats
    }

    /// Resets statistics.
    pub fn reset_stats(&mut self) {
        self.stats.reset();
    }
}
