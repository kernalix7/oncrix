// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Page migration for NUMA balancing and memory compaction.
//!
//! This module implements the mechanics of moving physical pages from one
//! memory node (or zone) to another. Page migration is used by:
//!
//! - NUMA auto-balancing (move pages closer to the accessing CPU)
//! - Memory compaction (consolidate free pages for huge-page allocation)
//! - Memory hotplug (evacuate pages before offline)
//! - CMA allocation (free pages in a contiguous region)
//!
//! # Migration Flow
//!
//! 1. **Isolation**: Remove the page from all reverse-maps (RMAP) and
//!    page-table entries (PTEs) so no new references can be created.
//! 2. **Allocation**: Obtain a new physical page on the destination node.
//! 3. **Copy**: Transfer page content and metadata to the new page.
//! 4. **Re-map**: Install the new page into all affected PTEs and update
//!    reverse-map structures.
//! 5. **Release**: Free the original page back to the page allocator.
//!
//! # Key types
//!
//! - [`MigrationMode`] — async vs. sync migration
//! - [`MigrationReason`] — why migration was triggered
//! - [`PageMigrationRequest`] — a request to migrate one page
//! - [`MigrationResult`] — outcome of a single page migration
//! - [`MigrationBatch`] — a batch of migration requests
//! - [`MigrateStats`] — aggregate statistics

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Maximum pages per migration batch.
pub const MIGRATE_BATCH_MAX: usize = 512;

/// Page size in bytes.
pub const MIGRATE_PAGE_SIZE: u64 = 4096;

/// Maximum number of retry attempts per page before giving up.
pub const MIGRATE_MAX_RETRIES: u32 = 10;

/// Delay in microseconds between retry attempts.
pub const MIGRATE_RETRY_DELAY_US: u64 = 100;

// -------------------------------------------------------------------
// MigrationMode
// -------------------------------------------------------------------

/// Whether migration is synchronous or may yield.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MigrationMode {
    /// Migrate synchronously; wait for I/O writeback if needed.
    Sync,
    /// Migrate without blocking; skip pages that require I/O.
    Async,
    /// Synchronous, but specifically for memory compaction.
    SyncLight,
}

// -------------------------------------------------------------------
// MigrationReason
// -------------------------------------------------------------------

/// Why a page migration was requested.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MigrationReason {
    /// NUMA balancing: move page closer to accessing CPU.
    NumaBalance,
    /// Memory compaction: consolidate free space.
    Compaction,
    /// Memory hotplug: evacuate pages for offline.
    Hotplug,
    /// CMA allocation: free a contiguous region.
    Cma,
    /// Explicit syscall (`move_pages(2)`).
    Syscall,
    /// Memory isolation for KFENCE or other debug tools.
    Isolation,
}

// -------------------------------------------------------------------
// MigrationStatus
// -------------------------------------------------------------------

/// Result status of a single page migration attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MigrationStatus {
    /// Page was successfully migrated.
    Success,
    /// Page was skipped (e.g., already on target node).
    Skipped,
    /// Page could not be isolated (someone else holds a reference).
    IsolationFailed,
    /// No suitable destination page could be allocated.
    AllocationFailed,
    /// The page required I/O writeback but mode is async.
    WouldBlock,
    /// Migration failed after all retries.
    Failed,
}

// -------------------------------------------------------------------
// PageMigrationRequest
// -------------------------------------------------------------------

/// A request to migrate a single physical page.
#[derive(Debug, Clone, Copy)]
pub struct PageMigrationRequest {
    /// Source physical frame number.
    pub src_pfn: u64,
    /// Target NUMA node (or `u32::MAX` for any node).
    pub dst_node: u32,
    /// Migration mode for this request.
    pub mode: MigrationMode,
    /// Reason for migration.
    pub reason: MigrationReason,
}

impl PageMigrationRequest {
    /// Create a NUMA-balance migration request.
    pub const fn numa_balance(src_pfn: u64, dst_node: u32) -> Self {
        Self {
            src_pfn,
            dst_node,
            mode: MigrationMode::Async,
            reason: MigrationReason::NumaBalance,
        }
    }

    /// Create a compaction migration request.
    pub const fn compaction(src_pfn: u64) -> Self {
        Self {
            src_pfn,
            dst_node: u32::MAX,
            mode: MigrationMode::SyncLight,
            reason: MigrationReason::Compaction,
        }
    }
}

// -------------------------------------------------------------------
// MigrationResult
// -------------------------------------------------------------------

/// Outcome of a single page migration attempt.
#[derive(Debug, Clone, Copy)]
pub struct MigrationResult {
    /// Source PFN that was the subject of migration.
    pub src_pfn: u64,
    /// Destination PFN (0 if migration did not succeed).
    pub dst_pfn: u64,
    /// Final status.
    pub status: MigrationStatus,
    /// Number of retries consumed.
    pub retries: u32,
}

impl MigrationResult {
    /// Create a successful result.
    pub const fn success(src_pfn: u64, dst_pfn: u64, retries: u32) -> Self {
        Self {
            src_pfn,
            dst_pfn,
            status: MigrationStatus::Success,
            retries,
        }
    }

    /// Create a failed result.
    pub const fn failed(src_pfn: u64, status: MigrationStatus) -> Self {
        Self {
            src_pfn,
            dst_pfn: 0,
            status,
            retries: 0,
        }
    }
}

// -------------------------------------------------------------------
// PageFlags (simplified)
// -------------------------------------------------------------------

/// Simplified page flags relevant to migration.
#[derive(Debug, Clone, Copy, Default)]
pub struct PageFlags(u32);

impl PageFlags {
    /// Page is locked (under I/O or locked by caller).
    pub const LOCKED: Self = Self(1 << 0);
    /// Page is dirty (needs writeback before migration).
    pub const DIRTY: Self = Self(1 << 1);
    /// Page is in use by a hardware device (DMA in progress).
    pub const DMA: Self = Self(1 << 2);
    /// Page is mapped by one or more processes.
    pub const MAPPED: Self = Self(1 << 3);
    /// Page is a huge page.
    pub const HUGE: Self = Self(1 << 4);
    /// Page has been isolated from the buddy allocator.
    pub const ISOLATED: Self = Self(1 << 5);

    /// Test a flag.
    pub fn contains(self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }

    /// Set a flag.
    pub fn set(&mut self, flag: Self) {
        self.0 |= flag.0;
    }

    /// Clear a flag.
    pub fn clear(&mut self, flag: Self) {
        self.0 &= !flag.0;
    }
}

// -------------------------------------------------------------------
// PageDescriptor
// -------------------------------------------------------------------

/// Simplified descriptor for a physical page, used during migration.
#[derive(Debug, Clone, Copy)]
pub struct PageDescriptor {
    /// Physical frame number.
    pub pfn: u64,
    /// NUMA node this page belongs to.
    pub node: u32,
    /// Current reference count.
    pub ref_count: u32,
    /// Page control flags.
    pub flags: PageFlags,
}

impl PageDescriptor {
    /// Create a new page descriptor.
    pub const fn new(pfn: u64, node: u32) -> Self {
        Self {
            pfn,
            node,
            ref_count: 1,
            flags: PageFlags(0),
        }
    }

    /// Returns `true` if the page can be isolated for migration.
    pub fn is_migratable(&self) -> bool {
        !self.flags.contains(PageFlags::DMA)
            && !self.flags.contains(PageFlags::ISOLATED)
            && self.ref_count < 64
    }
}

// -------------------------------------------------------------------
// MigrateStats
// -------------------------------------------------------------------

/// Aggregate statistics for the page migration subsystem.
#[derive(Debug, Clone, Copy, Default)]
pub struct MigrateStats {
    /// Total pages successfully migrated.
    pub success: u64,
    /// Pages skipped.
    pub skipped: u64,
    /// Pages that failed to isolate.
    pub isolation_failed: u64,
    /// Pages where allocation of the destination failed.
    pub alloc_failed: u64,
    /// Pages that would have blocked (async mode).
    pub would_block: u64,
    /// Pages that failed after all retries.
    pub failed: u64,
    /// Total bytes of content copied between pages.
    pub bytes_copied: u64,
}

// -------------------------------------------------------------------
// MigrationBatch
// -------------------------------------------------------------------

/// A batch of page migration requests.
#[derive(Debug)]
pub struct MigrationBatch {
    /// Individual requests.
    requests: [Option<PageMigrationRequest>; MIGRATE_BATCH_MAX],
    /// Results (populated after processing).
    results: [Option<MigrationResult>; MIGRATE_BATCH_MAX],
    /// Number of populated requests.
    count: usize,
}

impl MigrationBatch {
    /// Create an empty migration batch.
    pub const fn new() -> Self {
        Self {
            requests: [const { None }; MIGRATE_BATCH_MAX],
            results: [const { None }; MIGRATE_BATCH_MAX],
            count: 0,
        }
    }

    /// Add a migration request to the batch.
    pub fn add(&mut self, req: PageMigrationRequest) -> Result<()> {
        if self.count >= MIGRATE_BATCH_MAX {
            return Err(Error::OutOfMemory);
        }
        self.requests[self.count] = Some(req);
        self.count += 1;
        Ok(())
    }

    /// Return the number of requests in the batch.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Return `true` if the batch is empty.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Return the result for request `i`, if populated.
    pub fn result(&self, i: usize) -> Option<&MigrationResult> {
        self.results.get(i)?.as_ref()
    }

    /// Return the request at index `i`.
    pub fn request(&self, i: usize) -> Option<&PageMigrationRequest> {
        self.requests.get(i)?.as_ref()
    }
}

impl Default for MigrationBatch {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// PageMigrator
// -------------------------------------------------------------------

/// Top-level page migration engine.
///
/// Processes [`MigrationBatch`] objects, performing isolation, copy, and
/// re-map for each page. Maintains running statistics.
#[derive(Debug)]
pub struct PageMigrator {
    /// Aggregate statistics.
    stats: MigrateStats,
    /// Simulated destination PFN counter (real impl would use page allocator).
    next_dst_pfn: u64,
}

impl PageMigrator {
    /// Create a new page migrator.
    pub const fn new() -> Self {
        Self {
            stats: MigrateStats {
                success: 0,
                skipped: 0,
                isolation_failed: 0,
                alloc_failed: 0,
                would_block: 0,
                failed: 0,
                bytes_copied: 0,
            },
            next_dst_pfn: 0x1_0000,
        }
    }

    /// Process a migration batch.
    ///
    /// Each request in the batch is processed in order. Results are stored
    /// back into the batch for the caller to inspect.
    pub fn migrate_batch(&mut self, batch: &mut MigrationBatch) -> Result<()> {
        for i in 0..batch.count {
            let req = match batch.requests[i] {
                Some(r) => r,
                None => continue,
            };
            let result = self.migrate_one(&req);
            batch.results[i] = Some(result);
        }
        Ok(())
    }

    /// Migrate a single page described by `req`.
    ///
    /// The actual memory copy is simulated here; a real implementation
    /// would read the page flags, perform writeback if dirty, copy page
    /// content, and update all PTEs via the RMAP.
    pub fn migrate_one(&mut self, req: &PageMigrationRequest) -> MigrationResult {
        // Simulate isolation failure for PFN 0 (reserved page).
        if req.src_pfn == 0 {
            self.stats.isolation_failed += 1;
            return MigrationResult::failed(req.src_pfn, MigrationStatus::IsolationFailed);
        }

        // Simulate that dirty async pages would block.
        if req.mode == MigrationMode::Async && req.src_pfn % 17 == 0 {
            self.stats.would_block += 1;
            return MigrationResult::failed(req.src_pfn, MigrationStatus::WouldBlock);
        }

        // Allocate a destination page.
        let dst_pfn = self.alloc_dst_page();

        // Simulate the page copy.
        self.stats.bytes_copied += MIGRATE_PAGE_SIZE;
        self.stats.success += 1;
        MigrationResult::success(req.src_pfn, dst_pfn, 0)
    }

    /// Return aggregate migration statistics.
    pub fn stats(&self) -> &MigrateStats {
        &self.stats
    }

    // ------------------------------------------------------------------
    // Private helpers
    // ------------------------------------------------------------------

    /// Allocate the next available destination PFN (simulated).
    fn alloc_dst_page(&mut self) -> u64 {
        let pfn = self.next_dst_pfn;
        self.next_dst_pfn += 1;
        pfn
    }
}

impl Default for PageMigrator {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// Helper: migrate a single page-table mapped page
// -------------------------------------------------------------------

/// Attempt to migrate one PTE-mapped page to `dst_node`.
///
/// This is a convenience wrapper for callers that have a single page
/// to migrate and do not need batch semantics.
pub fn migrate_page(
    migrator: &mut PageMigrator,
    src_pfn: u64,
    dst_node: u32,
    reason: MigrationReason,
) -> Result<MigrationResult> {
    let req = PageMigrationRequest {
        src_pfn,
        dst_node,
        mode: MigrationMode::Sync,
        reason,
    };
    Ok(migrator.migrate_one(&req))
}

// -------------------------------------------------------------------
// Tests
// -------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_migrate_single_success() {
        let mut migrator = PageMigrator::new();
        let result = migrate_page(&mut migrator, 42, 0, MigrationReason::NumaBalance).unwrap();
        assert_eq!(result.status, MigrationStatus::Success);
        assert_eq!(migrator.stats().success, 1);
    }

    #[test]
    fn test_migrate_reserved_page_fails() {
        let mut migrator = PageMigrator::new();
        let result = migrate_page(&mut migrator, 0, 0, MigrationReason::Compaction).unwrap();
        assert_eq!(result.status, MigrationStatus::IsolationFailed);
    }

    #[test]
    fn test_batch_migration() {
        let mut migrator = PageMigrator::new();
        let mut batch = MigrationBatch::new();
        batch
            .add(PageMigrationRequest::numa_balance(10, 1))
            .unwrap();
        batch.add(PageMigrationRequest::compaction(20)).unwrap();
        migrator.migrate_batch(&mut batch).unwrap();
        assert_eq!(migrator.stats().success, 2);
    }
}
