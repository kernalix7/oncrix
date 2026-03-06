// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Batch page migration operations.
//!
//! Implements the `migrate_pages()` path: collecting a set of source
//! pages, allocating destination frames in bulk, unmapping source
//! pages, copying page contents, remapping to new locations, and
//! performing batch TLB invalidation. If any step fails for a subset
//! of pages the operation rolls back those individual migrations while
//! allowing the rest to succeed.
//!
//! # Key Types
//!
//! - [`MigrateBatchMode`] — synchronous or async migration
//! - [`MigratePageState`] — lifecycle of a single page migration
//! - [`MigrateBatchEntry`] — per-page source/destination descriptor
//! - [`TlbFlushEntry`] — a queued TLB invalidation
//! - [`MigrateBatchList`] — the batch of pages being migrated
//! - [`BatchMigrator`] — top-level migration engine
//! - [`MigrateBatchStats`] — cumulative statistics
//!
//! Reference: Linux `mm/migrate.c` (`migrate_pages`,
//! `unmap_and_move`, `move_to_new_folio`).

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Standard page size (4 KiB).
const PAGE_SIZE: u64 = 4096;

/// Maximum pages in a single migration batch.
const MAX_BATCH_ENTRIES: usize = 256;

/// Maximum TLB flush entries queued before forced flush.
const MAX_TLB_FLUSH_QUEUE: usize = 256;

/// Retry limit for a single page migration before giving up.
const MAX_RETRY_PER_PAGE: u8 = 3;

/// Maximum number of migration batches tracked for rollback.
const MAX_ROLLBACK_ENTRIES: usize = 256;

// -------------------------------------------------------------------
// MigrateBatchMode
// -------------------------------------------------------------------

/// Migration synchronization mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum MigrateBatchMode {
    /// Fully synchronous — block until all pages are migrated.
    #[default]
    SyncFull,
    /// Light synchronous — skip pages that would block.
    SyncLight,
    /// Asynchronous — never block, skip contended pages.
    Async,
}

// -------------------------------------------------------------------
// MigratePageState
// -------------------------------------------------------------------

/// Lifecycle state of a single page in the migration batch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum MigratePageState {
    /// Page is queued for migration but not yet processed.
    #[default]
    Pending,
    /// Source page has been unmapped.
    Unmapped,
    /// Destination frame has been allocated.
    DestAllocated,
    /// Page contents have been copied to destination.
    Copied,
    /// Destination has been remapped into page tables.
    Remapped,
    /// Migration completed successfully.
    Completed,
    /// Migration failed and was rolled back.
    RolledBack,
    /// Migration was skipped (contended, pinned, etc).
    Skipped,
}

// -------------------------------------------------------------------
// MigrateBatchEntry
// -------------------------------------------------------------------

/// Descriptor for a single page within a migration batch.
#[derive(Debug, Clone, Copy)]
pub struct MigrateBatchEntry {
    /// Source page frame number.
    pub src_pfn: u64,
    /// Destination page frame number (0 if not yet allocated).
    pub dst_pfn: u64,
    /// Virtual address this page is mapped at (0 if anonymous).
    pub vaddr: u64,
    /// Current migration state.
    pub state: MigratePageState,
    /// Number of retries attempted.
    pub retries: u8,
    /// Page reference count at time of collection.
    pub refcount: u32,
    /// Whether the page is a compound (huge) page.
    pub compound: bool,
    /// Page order (0 for base pages, 9 for 2 MiB THP).
    pub order: u8,
}

impl Default for MigrateBatchEntry {
    fn default() -> Self {
        Self {
            src_pfn: 0,
            dst_pfn: 0,
            vaddr: 0,
            state: MigratePageState::Pending,
            retries: 0,
            refcount: 0,
            compound: false,
            order: 0,
        }
    }
}

impl MigrateBatchEntry {
    /// Returns the number of base pages this entry covers.
    pub fn nr_pages(&self) -> u64 {
        1u64 << self.order
    }

    /// Returns the byte size of the migrated region.
    pub fn byte_size(&self) -> u64 {
        self.nr_pages() * PAGE_SIZE
    }
}

// -------------------------------------------------------------------
// TlbFlushEntry
// -------------------------------------------------------------------

/// A queued TLB invalidation for a migrated page.
#[derive(Debug, Clone, Copy, Default)]
pub struct TlbFlushEntry {
    /// Virtual address to invalidate.
    pub vaddr: u64,
    /// Number of pages at this address.
    pub nr_pages: u64,
    /// Whether this covers a huge page mapping.
    pub huge: bool,
}

// -------------------------------------------------------------------
// MigrateBatchStats
// -------------------------------------------------------------------

/// Cumulative statistics for batch migration operations.
#[derive(Debug, Clone, Copy, Default)]
pub struct MigrateBatchStats {
    /// Total pages successfully migrated.
    pub pages_migrated: u64,
    /// Total pages that failed migration.
    pub pages_failed: u64,
    /// Total pages skipped (contended, pinned).
    pub pages_skipped: u64,
    /// Total pages rolled back after partial failure.
    pub pages_rolled_back: u64,
    /// Total bytes copied during migration.
    pub bytes_copied: u64,
    /// Total TLB flushes performed.
    pub tlb_flushes: u64,
    /// Total batches processed.
    pub batches_processed: u64,
    /// Total retries across all pages.
    pub total_retries: u64,
}

// -------------------------------------------------------------------
// MigrateBatchList
// -------------------------------------------------------------------

/// A batch of pages collected for migration.
pub struct MigrateBatchList {
    /// Entries in the batch.
    entries: [MigrateBatchEntry; MAX_BATCH_ENTRIES],
    /// Number of valid entries.
    nr_entries: usize,
}

impl MigrateBatchList {
    /// Creates a new empty batch list.
    pub fn new() -> Self {
        Self {
            entries: [const {
                MigrateBatchEntry {
                    src_pfn: 0,
                    dst_pfn: 0,
                    vaddr: 0,
                    state: MigratePageState::Pending,
                    retries: 0,
                    refcount: 0,
                    compound: false,
                    order: 0,
                }
            }; MAX_BATCH_ENTRIES],
            nr_entries: 0,
        }
    }

    /// Adds a page to the batch.
    pub fn add(&mut self, src_pfn: u64, vaddr: u64, refcount: u32, order: u8) -> Result<()> {
        if self.nr_entries >= MAX_BATCH_ENTRIES {
            return Err(Error::OutOfMemory);
        }
        self.entries[self.nr_entries] = MigrateBatchEntry {
            src_pfn,
            dst_pfn: 0,
            vaddr,
            state: MigratePageState::Pending,
            retries: 0,
            refcount,
            compound: order > 0,
            order,
        };
        self.nr_entries += 1;
        Ok(())
    }

    /// Returns the number of entries.
    pub fn len(&self) -> usize {
        self.nr_entries
    }

    /// Returns true if the batch is empty.
    pub fn is_empty(&self) -> bool {
        self.nr_entries == 0
    }

    /// Clears the batch.
    pub fn clear(&mut self) {
        self.nr_entries = 0;
    }
}

// -------------------------------------------------------------------
// BatchMigrator
// -------------------------------------------------------------------

/// Top-level migration engine that processes batch migrations.
///
/// Coordinates the unmap-allocate-copy-remap-flush pipeline and
/// handles per-page rollback on failure.
pub struct BatchMigrator {
    /// Current migration mode.
    mode: MigrateBatchMode,
    /// The current batch of pages being migrated.
    batch: MigrateBatchList,
    /// TLB flush queue.
    tlb_queue: [TlbFlushEntry; MAX_TLB_FLUSH_QUEUE],
    /// Number of queued TLB flushes.
    tlb_queue_len: usize,
    /// Next available destination PFN from the free pool.
    next_free_pfn: u64,
    /// Total free pages available for destination allocation.
    free_pages_avail: u64,
    /// Cumulative statistics.
    stats: MigrateBatchStats,
}

impl BatchMigrator {
    /// Creates a new batch migrator.
    ///
    /// `free_start_pfn` and `free_nr_pages` define the pool of
    /// destination frames.
    pub fn new(mode: MigrateBatchMode, free_start_pfn: u64, free_nr_pages: u64) -> Self {
        Self {
            mode,
            batch: MigrateBatchList::new(),
            tlb_queue: [const {
                TlbFlushEntry {
                    vaddr: 0,
                    nr_pages: 0,
                    huge: false,
                }
            }; MAX_TLB_FLUSH_QUEUE],
            tlb_queue_len: 0,
            next_free_pfn: free_start_pfn,
            free_pages_avail: free_nr_pages,
            stats: MigrateBatchStats::default(),
        }
    }

    /// Returns current statistics.
    pub fn stats(&self) -> &MigrateBatchStats {
        &self.stats
    }

    /// Returns the migration mode.
    pub fn mode(&self) -> MigrateBatchMode {
        self.mode
    }

    /// Collects a page into the current batch.
    pub fn collect_page(
        &mut self,
        src_pfn: u64,
        vaddr: u64,
        refcount: u32,
        order: u8,
    ) -> Result<()> {
        self.batch.add(src_pfn, vaddr, refcount, order)
    }

    /// Allocates destination frames for all pending entries.
    fn alloc_destinations(&mut self) -> Result<usize> {
        let mut allocated = 0usize;
        for i in 0..self.batch.nr_entries {
            if self.batch.entries[i].state != MigratePageState::Pending {
                continue;
            }
            let nr = self.batch.entries[i].nr_pages();
            if nr > self.free_pages_avail {
                self.batch.entries[i].state = MigratePageState::Skipped;
                self.stats.pages_skipped += 1;
                continue;
            }
            self.batch.entries[i].dst_pfn = self.next_free_pfn;
            self.next_free_pfn += nr;
            self.free_pages_avail -= nr;
            self.batch.entries[i].state = MigratePageState::DestAllocated;
            allocated += 1;
        }
        Ok(allocated)
    }

    /// Unmaps all source pages in the batch.
    fn unmap_sources(&mut self) -> usize {
        let mut unmapped = 0usize;
        for i in 0..self.batch.nr_entries {
            if self.batch.entries[i].state != MigratePageState::DestAllocated {
                continue;
            }
            // In a real implementation this would clear PTEs
            // and add to TLB flush batch.
            self.batch.entries[i].state = MigratePageState::Unmapped;
            unmapped += 1;
        }
        unmapped
    }

    /// Copies page contents from source to destination.
    fn copy_pages(&mut self) -> usize {
        let mut copied = 0usize;
        for i in 0..self.batch.nr_entries {
            if self.batch.entries[i].state != MigratePageState::Unmapped {
                continue;
            }
            // Simulated copy — real impl would memcpy.
            let bytes = self.batch.entries[i].byte_size();
            self.stats.bytes_copied += bytes;
            self.batch.entries[i].state = MigratePageState::Copied;
            copied += 1;
        }
        copied
    }

    /// Remaps all copied pages to their new destinations.
    fn remap_destinations(&mut self) -> usize {
        let mut remapped = 0usize;
        for i in 0..self.batch.nr_entries {
            if self.batch.entries[i].state != MigratePageState::Copied {
                continue;
            }
            // Queue TLB flush for the old mapping.
            if self.tlb_queue_len < MAX_TLB_FLUSH_QUEUE {
                self.tlb_queue[self.tlb_queue_len] = TlbFlushEntry {
                    vaddr: self.batch.entries[i].vaddr,
                    nr_pages: self.batch.entries[i].nr_pages(),
                    huge: self.batch.entries[i].compound,
                };
                self.tlb_queue_len += 1;
            }
            self.batch.entries[i].state = MigratePageState::Remapped;
            remapped += 1;
        }
        remapped
    }

    /// Performs a batch TLB flush for all queued entries.
    fn flush_tlb_batch(&mut self) {
        if self.tlb_queue_len > 0 {
            // Real implementation would issue invlpg or
            // full TLB shootdown IPI.
            self.stats.tlb_flushes += 1;
            self.tlb_queue_len = 0;
        }
    }

    /// Finalizes all remapped entries as completed.
    fn finalize_batch(&mut self) -> u64 {
        let mut completed = 0u64;
        for i in 0..self.batch.nr_entries {
            if self.batch.entries[i].state == MigratePageState::Remapped {
                self.batch.entries[i].state = MigratePageState::Completed;
                completed += self.batch.entries[i].nr_pages();
                self.stats.pages_migrated += self.batch.entries[i].nr_pages();
            }
        }
        completed
    }

    /// Rolls back entries that did not complete successfully.
    fn rollback_failures(&mut self) -> u64 {
        let mut rolled_back = 0u64;
        for i in 0..self.batch.nr_entries {
            let entry = &mut self.batch.entries[i];
            match entry.state {
                MigratePageState::Completed
                | MigratePageState::Skipped
                | MigratePageState::RolledBack => {}
                _ => {
                    if entry.dst_pfn != 0 {
                        // Return destination PFN to free pool.
                        self.free_pages_avail += entry.nr_pages();
                    }
                    let nr = entry.nr_pages();
                    entry.state = MigratePageState::RolledBack;
                    rolled_back += nr;
                    self.stats.pages_rolled_back += nr;
                    self.stats.pages_failed += nr;
                }
            }
        }
        rolled_back
    }

    /// Executes the full batch migration pipeline.
    ///
    /// Returns the number of pages successfully migrated.
    pub fn migrate_batch(&mut self) -> Result<u64> {
        if self.batch.is_empty() {
            return Ok(0);
        }

        // Step 1: Allocate destination frames.
        self.alloc_destinations()?;

        // Step 2: Unmap source pages.
        self.unmap_sources();

        // Step 3: Copy page contents.
        self.copy_pages();

        // Step 4: Remap to new locations.
        self.remap_destinations();

        // Step 5: Batch TLB flush.
        self.flush_tlb_batch();

        // Step 6: Finalize completed entries.
        let completed = self.finalize_batch();

        // Step 7: Roll back any failures.
        self.rollback_failures();

        self.stats.batches_processed += 1;
        self.batch.clear();

        Ok(completed)
    }

    /// Retries migration for pages that failed on the first attempt.
    ///
    /// Only pages in `RolledBack` state with retries remaining are
    /// re-attempted. Returns the number of pages recovered.
    pub fn retry_failed(&mut self) -> Result<u64> {
        let mut retry_batch = MigrateBatchList::new();
        for i in 0..self.batch.nr_entries {
            let entry = &mut self.batch.entries[i];
            if entry.state == MigratePageState::RolledBack && entry.retries < MAX_RETRY_PER_PAGE {
                entry.retries += 1;
                entry.state = MigratePageState::Pending;
                entry.dst_pfn = 0;
                self.stats.total_retries += 1;
                let _ = retry_batch.add(entry.src_pfn, entry.vaddr, entry.refcount, entry.order);
            }
        }
        if retry_batch.is_empty() {
            return Ok(0);
        }
        self.batch = retry_batch;
        self.migrate_batch()
    }

    /// Returns the number of free destination pages remaining.
    pub fn free_pages(&self) -> u64 {
        self.free_pages_avail
    }

    /// Returns the number of pages in the current batch.
    pub fn batch_size(&self) -> usize {
        self.batch.len()
    }
}
