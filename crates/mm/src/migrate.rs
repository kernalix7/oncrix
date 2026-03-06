// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Page migration subsystem.
//!
//! Provides infrastructure for migrating physical pages between frames,
//! used by compaction, NUMA rebalancing, memory hotplug, CMA allocation,
//! and memory policy enforcement.
//!
//! - [`MigrateType`] — classification of page mobility
//! - [`MigrateReason`] — why a migration was requested
//! - [`MigratePage`] — descriptor for a single page migration
//! - [`MigrateList`] — fixed-capacity list of pending migrations
//! - [`PageMigrator`] — engine that executes page migrations
//! - [`MigrateStats`] — aggregate migration statistics

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Maximum number of pages in a single migration batch.
const MAX_MIGRATE_PAGES: usize = 256;

/// Standard page size in bytes (4 KiB).
const PAGE_SIZE: usize = 4096;

/// Number of `u64` words in the simulated free-frame bitmap.
const FREE_BITMAP_WORDS: usize = MAX_MIGRATE_PAGES / 64;

// -------------------------------------------------------------------
// MigrateType
// -------------------------------------------------------------------

/// Classification of a page's mobility for migration purposes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum MigrateType {
    /// Page can be freely moved to a different physical frame.
    #[default]
    Movable,
    /// Page is pinned and cannot be migrated (e.g., DMA target).
    Unmovable,
    /// Page is reclaimable (e.g., page cache) and can be discarded
    /// instead of migrated.
    Reclaimable,
}

// -------------------------------------------------------------------
// MigrateReason
// -------------------------------------------------------------------

/// Reason a page migration was initiated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum MigrateReason {
    /// Memory compaction (defragmentation).
    #[default]
    Compaction,
    /// NUMA rebalancing to improve locality.
    NumaRebalance,
    /// Memory hotplug — pages must vacate an offlining section.
    MemoryHotplug,
    /// CMA allocation requires a contiguous range.
    CmaAlloc,
    /// Memory policy enforcement (e.g., `mbind`).
    Mempolicy,
}

// -------------------------------------------------------------------
// MigrateStatus
// -------------------------------------------------------------------

/// Status of an individual page migration operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum MigrateStatus {
    /// Migration has not yet been attempted.
    #[default]
    Pending,
    /// Migration completed successfully.
    Success,
    /// Migration failed (page pinned, no destination, etc.).
    Failed,
}

// -------------------------------------------------------------------
// MigratePage
// -------------------------------------------------------------------

/// Descriptor for a single page migration operation.
#[derive(Debug, Clone, Copy)]
pub struct MigratePage {
    /// Source page frame number.
    pub src_pfn: u64,
    /// Destination page frame number (0 = not yet assigned).
    pub dst_pfn: u64,
    /// Mobility classification of the page.
    pub migrate_type: MigrateType,
    /// Why this migration was requested.
    pub reason: MigrateReason,
    /// Current status of this migration entry.
    pub status: MigrateStatus,
}

impl MigratePage {
    /// Creates a zeroed, pending migration descriptor.
    const fn empty() -> Self {
        Self {
            src_pfn: 0,
            dst_pfn: 0,
            migrate_type: MigrateType::Movable,
            reason: MigrateReason::Compaction,
            status: MigrateStatus::Pending,
        }
    }

    /// Creates a new migration descriptor for the given source PFN.
    pub const fn new(src_pfn: u64, migrate_type: MigrateType, reason: MigrateReason) -> Self {
        Self {
            src_pfn,
            dst_pfn: 0,
            migrate_type,
            reason,
            status: MigrateStatus::Pending,
        }
    }
}

// -------------------------------------------------------------------
// MigrateList
// -------------------------------------------------------------------

/// Fixed-capacity list of pending page migration descriptors.
///
/// Holds up to [`MAX_MIGRATE_PAGES`] entries and supports
/// add, remove, clear, and status-filtered counting.
pub struct MigrateList {
    /// Migration entries.
    entries: [MigratePage; MAX_MIGRATE_PAGES],
    /// Number of valid entries.
    count: usize,
}

impl Default for MigrateList {
    fn default() -> Self {
        Self::new()
    }
}

impl MigrateList {
    /// Creates an empty migration list.
    pub const fn new() -> Self {
        Self {
            entries: [MigratePage::empty(); MAX_MIGRATE_PAGES],
            count: 0,
        }
    }

    /// Adds a migration descriptor to the list.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the list is full.
    pub fn add(&mut self, page: MigratePage) -> Result<()> {
        if self.count >= MAX_MIGRATE_PAGES {
            return Err(Error::OutOfMemory);
        }
        self.entries[self.count] = page;
        self.count += 1;
        Ok(())
    }

    /// Removes the entry at `index` by swapping with the last entry.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `index` is out of range.
    pub fn remove(&mut self, index: usize) -> Result<()> {
        if index >= self.count {
            return Err(Error::InvalidArgument);
        }
        self.count -= 1;
        if index < self.count {
            self.entries[index] = self.entries[self.count];
        }
        self.entries[self.count] = MigratePage::empty();
        Ok(())
    }

    /// Removes all entries from the list.
    pub fn clear(&mut self) {
        for i in 0..self.count {
            self.entries[i] = MigratePage::empty();
        }
        self.count = 0;
    }

    /// Returns the number of entries with the given status.
    pub fn count_by_status(&self, status: MigrateStatus) -> usize {
        let mut n = 0;
        for i in 0..self.count {
            if self.entries[i].status == status {
                n += 1;
            }
        }
        n
    }

    /// Returns the total number of entries.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Returns `true` if the list is empty.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Returns a shared reference to the entry at `index`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `index` is out of range.
    pub fn get(&self, index: usize) -> Result<&MigratePage> {
        if index >= self.count {
            return Err(Error::InvalidArgument);
        }
        Ok(&self.entries[index])
    }

    /// Returns a mutable reference to the entry at `index`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `index` is out of range.
    pub fn get_mut(&mut self, index: usize) -> Result<&mut MigratePage> {
        if index >= self.count {
            return Err(Error::InvalidArgument);
        }
        Ok(&mut self.entries[index])
    }
}

// -------------------------------------------------------------------
// MigrateStats
// -------------------------------------------------------------------

/// Aggregate page migration statistics.
#[derive(Debug, Clone, Copy, Default)]
pub struct MigrateStats {
    /// Total pages where migration was attempted.
    pub attempted: u64,
    /// Pages successfully migrated.
    pub succeeded: u64,
    /// Pages that failed migration.
    pub failed: u64,
    /// Transparent huge pages that were split before migration.
    pub thp_split: u64,
    /// Total pages physically moved (may differ from `succeeded`
    /// when huge pages are involved).
    pub pages_moved: u64,
}

// -------------------------------------------------------------------
// PageMigrator
// -------------------------------------------------------------------

/// Engine that executes page migration operations.
///
/// Manages a [`MigrateList`] and a simulated free-frame bitmap to
/// allocate destination frames. Provides single-page and batch
/// migration, plus page-table update stubs.
pub struct PageMigrator {
    /// Pending migration list.
    list: MigrateList,
    /// Simulated free-frame bitmap for destination allocation.
    /// Bit 0 = free, bit 1 = used.
    free_bitmap: [u64; FREE_BITMAP_WORDS],
    /// Total frames tracked by the free bitmap.
    free_total: usize,
    /// Aggregate statistics.
    stats: MigrateStats,
}

impl Default for PageMigrator {
    fn default() -> Self {
        Self::new()
    }
}

impl PageMigrator {
    /// Creates a new migrator with an empty list and all frames free.
    pub const fn new() -> Self {
        Self {
            list: MigrateList::new(),
            free_bitmap: [0u64; FREE_BITMAP_WORDS],
            free_total: MAX_MIGRATE_PAGES,
            stats: MigrateStats {
                attempted: 0,
                succeeded: 0,
                failed: 0,
                thp_split: 0,
                pages_moved: 0,
            },
        }
    }

    /// Returns a shared reference to the migration list.
    pub fn list(&self) -> &MigrateList {
        &self.list
    }

    /// Returns a mutable reference to the migration list.
    pub fn list_mut(&mut self) -> &mut MigrateList {
        &mut self.list
    }

    /// Migrates a single page described by the entry at `index`.
    ///
    /// Allocates a destination frame, copies the page contents
    /// (simulated), and updates the page-table mapping.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `index` is out of range,
    /// or [`Error::OutOfMemory`] if no free destination frame is
    /// available.
    pub fn migrate_page(&mut self, index: usize) -> Result<()> {
        // Read fields we need before taking any mutable borrows.
        let entry = self.list.get(index)?;
        let migrate_type = entry.migrate_type;
        let src_pfn = entry.src_pfn;

        // Unmovable pages cannot be migrated.
        if migrate_type == MigrateType::Unmovable {
            self.list.get_mut(index)?.status = MigrateStatus::Failed;
            self.stats.attempted += 1;
            self.stats.failed += 1;
            return Err(Error::InvalidArgument);
        }

        let dst = self.allocate_dst()?;

        self.list.get_mut(index)?.dst_pfn = dst;

        // Copy page contents (simulated — no real memory access).
        self.copy_page(src_pfn, dst);

        // Update page-table entry from old to new mapping.
        self.update_pte(src_pfn, dst);

        self.list.get_mut(index)?.status = MigrateStatus::Success;
        self.stats.attempted += 1;
        self.stats.succeeded += 1;
        self.stats.pages_moved += 1;

        Ok(())
    }

    /// Migrates all pending pages in the list.
    ///
    /// Returns `(success_count, fail_count)`.
    pub fn migrate_pages(&mut self) -> (usize, usize) {
        let mut success = 0_usize;
        let mut fail = 0_usize;
        let count = self.list.len();

        for i in 0..count {
            if self.migrate_page(i).is_ok() {
                success += 1;
            } else {
                fail += 1;
            }
        }

        (success, fail)
    }

    /// Allocates a free destination frame from the internal bitmap.
    ///
    /// Uses a first-fit scan. Returns the PFN of the allocated frame.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if no free frame is available.
    pub fn allocate_dst(&mut self) -> Result<u64> {
        for (word_idx, word) in self.free_bitmap.iter_mut().enumerate() {
            if *word == !0u64 {
                continue;
            }
            let bit = (*word).trailing_ones() as usize;
            let pfn = word_idx * 64 + bit;
            if pfn >= self.free_total {
                return Err(Error::OutOfMemory);
            }
            *word |= 1 << bit;
            return Ok(pfn as u64);
        }
        Err(Error::OutOfMemory)
    }

    /// Copies the contents of one 4 KiB page frame to another.
    ///
    /// This is a stub: in a real kernel this would perform a
    /// physical-memory copy via a temporary mapping.
    pub fn copy_page(&self, _src_pfn: u64, _dst_pfn: u64) {
        // Stub: real implementation would temporarily map both
        // frames and copy PAGE_SIZE bytes.
        let _ = PAGE_SIZE;
    }

    /// Updates the page-table entry, remapping `old_pfn` to
    /// `new_pfn`.
    ///
    /// This is a stub: in a real kernel this would walk the owning
    /// process's page tables, update the PTE, and flush the TLB.
    pub fn update_pte(&self, _old_pfn: u64, _new_pfn: u64) {
        // Stub: walk page tables, update PTE, flush TLB.
    }

    /// Returns aggregate migration statistics.
    pub fn stats(&self) -> MigrateStats {
        self.stats
    }

    /// Marks a frame as free in the internal bitmap so it can be
    /// used as a migration destination.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `pfn` is out of range.
    pub fn mark_frame_free(&mut self, pfn: u64) -> Result<()> {
        let idx = pfn as usize;
        if idx >= self.free_total {
            return Err(Error::InvalidArgument);
        }
        let word = idx / 64;
        let bit = idx % 64;
        self.free_bitmap[word] &= !(1u64 << bit);
        Ok(())
    }
}
