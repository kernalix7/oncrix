// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Memory hot-remove subsystem.
//!
//! Implements online-to-offline memory removal, the counterpart to
//! memory hotplug. When a memory block needs to be physically removed
//! (e.g., in a virtualized environment or for hardware maintenance),
//! pages must first be migrated out of the target range before the
//! memory can be safely offlined.
//!
//! The hot-remove process follows these phases:
//!
//! 1. **Isolation** — mark the PFN range as going-offline
//! 2. **Migration** — move movable pages to other zones
//! 3. **Verification** — confirm the range is empty
//! 4. **Removal** — release the memory block
//!
//! Unmovable pages (kernel, pinned, active LRU) cause the removal
//! to fail unless they can be reclaimed first.
//!
//! - [`HotRemovePhase`] — lifecycle phase of a removal request
//! - [`OfflineRequest`] — descriptor for a pending offline operation
//! - [`PageMigrationTarget`] — source/destination pair for migration
//! - [`HotRemoveSubsystem`] — the removal engine
//! - [`HotRemoveStats`] — aggregate statistics
//!
//! Reference: Linux `mm/memory_hotplug.c` — `offline_pages()`,
//! `__offline_pages()`, `do_migrate_range()`.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Maximum number of concurrent offline requests.
const MAX_REQUESTS: usize = 16;

/// Maximum number of migration target pairs per request.
const MAX_MIGRATION_TARGETS: usize = 256;

/// Standard page size in bytes (4 KiB).
const PAGE_SIZE: u64 = 4096;

/// Maximum retry count before declaring failure.
const MAX_RETRIES: u32 = 5;

/// Page flag: page is pinned (cannot be migrated).
const PAGE_PINNED: u8 = 1 << 0;

/// Page flag: page is on active LRU list.
const PAGE_LRU_ACTIVE: u8 = 1 << 1;

/// Page flag: page belongs to kernel slab.
const PAGE_KERNEL_SLAB: u8 = 1 << 2;

/// Page flag: page is unmovable.
const PAGE_UNMOVABLE: u8 = 1 << 3;

/// Page flag: page is free (not allocated).
const PAGE_FREE: u8 = 1 << 4;

// -------------------------------------------------------------------
// HotRemovePhase
// -------------------------------------------------------------------

/// Lifecycle phase of a memory hot-remove operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum HotRemovePhase {
    /// Range is being isolated from allocations.
    #[default]
    Isolation,
    /// Pages are being migrated out of the range.
    Migration,
    /// Verifying that the range is completely empty.
    Verification,
    /// Range is being removed from the system.
    Removal,
    /// Operation completed successfully.
    Complete,
    /// Operation failed and was rolled back.
    Failed,
}

// -------------------------------------------------------------------
// OfflineRequest
// -------------------------------------------------------------------

/// Descriptor for a pending memory offline (hot-remove) request.
#[derive(Debug, Clone, Copy)]
pub struct OfflineRequest {
    /// Starting page frame number of the range.
    pub start_pfn: u64,
    /// Number of pages in the range.
    pub nr_pages: u64,
    /// Current phase of the offline operation.
    pub phase: HotRemovePhase,
    /// Number of retries attempted so far.
    pub retry_count: u32,
    /// Whether this request slot is active.
    pub active: bool,
    /// Request identifier.
    pub request_id: u32,
    /// Number of pages successfully migrated.
    pub pages_migrated: u64,
    /// Number of pages skipped (unmovable).
    pub pages_skipped: u64,
    /// Number of pages still remaining in the range.
    pub pages_remaining: u64,
    /// Whether isolation has been applied.
    pub isolated: bool,
}

impl OfflineRequest {
    /// Creates an empty, inactive request.
    const fn empty() -> Self {
        Self {
            start_pfn: 0,
            nr_pages: 0,
            phase: HotRemovePhase::Isolation,
            retry_count: 0,
            active: false,
            request_id: 0,
            pages_migrated: 0,
            pages_skipped: 0,
            pages_remaining: 0,
            isolated: false,
        }
    }

    /// Returns the end PFN (exclusive) of this request's range.
    pub fn end_pfn(&self) -> u64 {
        self.start_pfn + self.nr_pages
    }

    /// Returns the byte range covered by this request.
    pub fn byte_range(&self) -> (u64, u64) {
        (self.start_pfn * PAGE_SIZE, self.end_pfn() * PAGE_SIZE)
    }
}

// -------------------------------------------------------------------
// PageMigrationTarget
// -------------------------------------------------------------------

/// Source/destination pair for page migration during hot-remove.
#[derive(Debug, Clone, Copy)]
pub struct PageMigrationTarget {
    /// Source page frame number (within the offline range).
    pub source_pfn: u64,
    /// Destination page frame number (outside the offline range).
    pub dest_pfn: u64,
    /// Whether this page has been successfully migrated.
    pub migrated: bool,
    /// Page flags at the source (used to determine moveability).
    pub page_flags: u8,
    /// Whether this target slot is active.
    pub active: bool,
}

impl PageMigrationTarget {
    /// Creates an empty, inactive migration target.
    const fn empty() -> Self {
        Self {
            source_pfn: 0,
            dest_pfn: 0,
            migrated: false,
            page_flags: 0,
            active: false,
        }
    }

    /// Returns `true` if this page can be migrated.
    ///
    /// Pages that are pinned, in kernel slab, or marked unmovable
    /// cannot be migrated.
    pub fn is_movable(&self) -> bool {
        let unmovable_mask = PAGE_PINNED | PAGE_KERNEL_SLAB | PAGE_UNMOVABLE;
        self.page_flags & unmovable_mask == 0
    }

    /// Returns `true` if this page is free and needs no migration.
    pub fn is_free(&self) -> bool {
        self.page_flags & PAGE_FREE != 0
    }
}

// -------------------------------------------------------------------
// HotRemoveStats
// -------------------------------------------------------------------

/// Aggregate statistics for the hot-remove subsystem.
#[derive(Debug, Clone, Copy, Default)]
pub struct HotRemoveStats {
    /// Total offline requests submitted.
    pub requests: u64,
    /// Requests that completed successfully.
    pub completed: u64,
    /// Requests that failed.
    pub failed: u64,
    /// Total pages successfully migrated.
    pub pages_migrated: u64,
    /// Total pages skipped (unmovable).
    pub pages_skipped: u64,
    /// Total isolation operations performed.
    pub isolations: u64,
    /// Total rollback operations performed.
    pub rollbacks: u64,
}

// -------------------------------------------------------------------
// HotRemoveSubsystem
// -------------------------------------------------------------------

/// Memory hot-remove subsystem.
///
/// Manages concurrent offline requests and coordinates the
/// isolation-migration-verification-removal pipeline.
pub struct HotRemoveSubsystem {
    /// Active offline requests.
    requests: [OfflineRequest; MAX_REQUESTS],
    /// Number of active requests.
    request_count: usize,
    /// Migration target pairs for the current operation.
    targets: [PageMigrationTarget; MAX_MIGRATION_TARGETS],
    /// Number of active migration targets.
    target_count: usize,
    /// Next request identifier.
    next_request_id: u32,
    /// Aggregate statistics.
    stats: HotRemoveStats,
}

impl Default for HotRemoveSubsystem {
    fn default() -> Self {
        Self::new()
    }
}

impl HotRemoveSubsystem {
    /// Creates a new hot-remove subsystem with no active requests.
    pub const fn new() -> Self {
        Self {
            requests: [OfflineRequest::empty(); MAX_REQUESTS],
            request_count: 0,
            targets: [PageMigrationTarget::empty(); MAX_MIGRATION_TARGETS],
            target_count: 0,
            next_request_id: 1,
            stats: HotRemoveStats {
                requests: 0,
                completed: 0,
                failed: 0,
                pages_migrated: 0,
                pages_skipped: 0,
                isolations: 0,
                rollbacks: 0,
            },
        }
    }

    /// Submits a new offline request for the given PFN range.
    ///
    /// The request enters the Isolation phase and must be driven
    /// through subsequent phases by calling [`advance_request`].
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the request table is full.
    /// Returns [`Error::InvalidArgument`] if `nr_pages` is zero.
    /// Returns [`Error::AlreadyExists`] if the range overlaps an
    /// existing active request.
    pub fn request_offline(&mut self, start_pfn: u64, nr_pages: u64) -> Result<u32> {
        if nr_pages == 0 {
            return Err(Error::InvalidArgument);
        }
        if self.request_count >= MAX_REQUESTS {
            return Err(Error::OutOfMemory);
        }

        // Check for overlapping requests.
        let end_pfn = start_pfn + nr_pages;
        for i in 0..self.request_count {
            let req = &self.requests[i];
            if req.active && start_pfn < req.end_pfn() && end_pfn > req.start_pfn {
                return Err(Error::AlreadyExists);
            }
        }

        let id = self.next_request_id;
        self.next_request_id += 1;

        // Find an empty slot or append.
        let slot = self.find_free_request_slot();
        self.requests[slot] = OfflineRequest {
            start_pfn,
            nr_pages,
            phase: HotRemovePhase::Isolation,
            retry_count: 0,
            active: true,
            request_id: id,
            pages_migrated: 0,
            pages_skipped: 0,
            pages_remaining: nr_pages,
            isolated: false,
        };
        if slot >= self.request_count {
            self.request_count = slot + 1;
        }

        self.stats.requests += 1;
        Ok(id)
    }

    /// Isolates the PFN range for the given request.
    ///
    /// Marks the range so that the page allocator will not hand out
    /// pages from this range. Must be called before migration.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the request ID is not found.
    /// Returns [`Error::InvalidArgument`] if the request is not in
    /// the Isolation phase.
    pub fn isolate_range(&mut self, request_id: u32) -> Result<()> {
        let idx = self.find_request(request_id)?;

        if self.requests[idx].phase != HotRemovePhase::Isolation {
            return Err(Error::InvalidArgument);
        }

        // Mark the range as isolated (stub: set flag).
        self.requests[idx].isolated = true;
        self.requests[idx].phase = HotRemovePhase::Migration;
        self.stats.isolations += 1;

        Ok(())
    }

    /// Migrates pages out of the offline range.
    ///
    /// Scans the PFN range, identifies movable pages, and pairs them
    /// with destination PFNs outside the range. Free and unmovable
    /// pages are handled appropriately.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the request ID is not found.
    /// Returns [`Error::InvalidArgument`] if the request is not in
    /// the Migration phase.
    pub fn migrate_pages(&mut self, request_id: u32) -> Result<(u64, u64)> {
        let idx = self.find_request(request_id)?;

        if self.requests[idx].phase != HotRemovePhase::Migration {
            return Err(Error::InvalidArgument);
        }

        let start = self.requests[idx].start_pfn;
        let nr = self.requests[idx].nr_pages;

        // Build migration targets.
        self.target_count = 0;
        let mut migrated = 0_u64;
        let mut skipped = 0_u64;
        let mut dest_base = start + nr; // Destinations start after the range.

        let limit = if nr as usize > MAX_MIGRATION_TARGETS {
            MAX_MIGRATION_TARGETS
        } else {
            nr as usize
        };

        for i in 0..limit {
            let pfn = start + i as u64;

            // Stub: simulate page flags. Every 8th page is pinned,
            // every 5th is free, rest are movable.
            let flags = if pfn % 8 == 0 {
                PAGE_PINNED
            } else if pfn % 5 == 0 {
                PAGE_FREE
            } else {
                0
            };

            let target = PageMigrationTarget {
                source_pfn: pfn,
                dest_pfn: dest_base,
                migrated: false,
                page_flags: flags,
                active: true,
            };

            if target.is_free() {
                // Free pages need no migration.
                continue;
            }

            if !target.is_movable() {
                skipped += 1;
                if self.target_count < MAX_MIGRATION_TARGETS {
                    self.targets[self.target_count] = PageMigrationTarget {
                        source_pfn: pfn,
                        dest_pfn: 0,
                        migrated: false,
                        page_flags: flags,
                        active: true,
                    };
                    self.target_count += 1;
                }
                continue;
            }

            // Migrate the page.
            if self.target_count < MAX_MIGRATION_TARGETS {
                self.targets[self.target_count] = PageMigrationTarget {
                    source_pfn: pfn,
                    dest_pfn: dest_base,
                    migrated: true,
                    page_flags: flags,
                    active: true,
                };
                self.target_count += 1;
            }
            migrated += 1;
            dest_base += 1;
        }

        self.requests[idx].pages_migrated += migrated;
        self.requests[idx].pages_skipped += skipped;
        self.requests[idx].pages_remaining =
            self.requests[idx].pages_remaining.saturating_sub(migrated);

        self.stats.pages_migrated += migrated;
        self.stats.pages_skipped += skipped;

        // If all movable pages are migrated, advance to verification.
        if skipped == 0 {
            self.requests[idx].phase = HotRemovePhase::Verification;
        } else {
            // Retry if we haven't exceeded max retries.
            self.requests[idx].retry_count += 1;
            if self.requests[idx].retry_count >= MAX_RETRIES {
                self.requests[idx].phase = HotRemovePhase::Failed;
            }
        }

        Ok((migrated, skipped))
    }

    /// Verifies that the offline range is completely empty.
    ///
    /// All pages must either be free or successfully migrated.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the request ID is not found.
    /// Returns [`Error::InvalidArgument`] if the request is not in
    /// the Verification phase.
    /// Returns [`Error::Busy`] if unmovable pages remain.
    pub fn verify_empty(&mut self, request_id: u32) -> Result<()> {
        let idx = self.find_request(request_id)?;

        if self.requests[idx].phase != HotRemovePhase::Verification {
            return Err(Error::InvalidArgument);
        }

        // Check if any unmovable pages were skipped.
        if self.requests[idx].pages_skipped > 0 {
            return Err(Error::Busy);
        }

        self.requests[idx].phase = HotRemovePhase::Removal;
        Ok(())
    }

    /// Completes the offline removal.
    ///
    /// Releases the memory block from the system. After this call,
    /// the PFN range is no longer available.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the request ID is not found.
    /// Returns [`Error::InvalidArgument`] if the request is not in
    /// the Removal phase.
    pub fn complete_remove(&mut self, request_id: u32) -> Result<()> {
        let idx = self.find_request(request_id)?;

        if self.requests[idx].phase != HotRemovePhase::Removal {
            return Err(Error::InvalidArgument);
        }

        self.requests[idx].phase = HotRemovePhase::Complete;
        self.requests[idx].active = false;
        self.stats.completed += 1;

        Ok(())
    }

    /// Advances a request through its lifecycle phases.
    ///
    /// Calls the appropriate phase handler based on the request's
    /// current phase. This is the main driver for the hot-remove
    /// state machine.
    ///
    /// # Errors
    ///
    /// Returns errors from the underlying phase handlers.
    pub fn advance_request(&mut self, request_id: u32) -> Result<HotRemovePhase> {
        let idx = self.find_request(request_id)?;
        let phase = self.requests[idx].phase;

        match phase {
            HotRemovePhase::Isolation => {
                self.isolate_range(request_id)?;
                Ok(HotRemovePhase::Migration)
            }
            HotRemovePhase::Migration => {
                self.migrate_pages(request_id)?;
                let new_idx = self.find_request(request_id)?;
                Ok(self.requests[new_idx].phase)
            }
            HotRemovePhase::Verification => {
                self.verify_empty(request_id)?;
                Ok(HotRemovePhase::Removal)
            }
            HotRemovePhase::Removal => {
                self.complete_remove(request_id)?;
                Ok(HotRemovePhase::Complete)
            }
            HotRemovePhase::Complete => Ok(HotRemovePhase::Complete),
            HotRemovePhase::Failed => {
                self.undo_isolation(request_id)?;
                Ok(HotRemovePhase::Failed)
            }
        }
    }

    /// Rolls back isolation for a failed request.
    ///
    /// Restores the PFN range to normal allocation eligibility.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the request ID is not found.
    pub fn undo_isolation(&mut self, request_id: u32) -> Result<()> {
        let idx = self.find_request(request_id)?;

        if self.requests[idx].isolated {
            self.requests[idx].isolated = false;
            self.stats.rollbacks += 1;
        }

        self.requests[idx].active = false;
        self.stats.failed += 1;

        Ok(())
    }

    /// Returns the current phase of a request.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the request ID is not found.
    pub fn request_phase(&self, request_id: u32) -> Result<HotRemovePhase> {
        let idx = self.find_request(request_id)?;
        Ok(self.requests[idx].phase)
    }

    /// Returns a copy of the request descriptor.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the request ID is not found.
    pub fn get_request(&self, request_id: u32) -> Result<OfflineRequest> {
        let idx = self.find_request(request_id)?;
        Ok(self.requests[idx])
    }

    /// Returns the number of active requests.
    pub fn active_count(&self) -> usize {
        let mut count = 0;
        for i in 0..self.request_count {
            if self.requests[i].active {
                count += 1;
            }
        }
        count
    }

    /// Returns aggregate statistics.
    pub fn stats(&self) -> HotRemoveStats {
        self.stats
    }

    /// Returns the number of migration targets from the last operation.
    pub fn migration_target_count(&self) -> usize {
        self.target_count
    }

    /// Returns a migration target by index.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if the index is out of range.
    pub fn get_target(&self, idx: usize) -> Result<&PageMigrationTarget> {
        if idx >= self.target_count {
            return Err(Error::InvalidArgument);
        }
        Ok(&self.targets[idx])
    }

    /// Cancels an active request, rolling back any isolation.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the request ID is not found.
    pub fn cancel_request(&mut self, request_id: u32) -> Result<()> {
        let idx = self.find_request(request_id)?;

        if !self.requests[idx].active {
            return Err(Error::NotFound);
        }

        if self.requests[idx].isolated {
            self.requests[idx].isolated = false;
            self.stats.rollbacks += 1;
        }

        self.requests[idx].phase = HotRemovePhase::Failed;
        self.requests[idx].active = false;
        self.stats.failed += 1;

        Ok(())
    }

    /// Finds a request by its identifier.
    fn find_request(&self, request_id: u32) -> Result<usize> {
        for i in 0..self.request_count {
            if self.requests[i].request_id == request_id {
                return Ok(i);
            }
        }
        Err(Error::NotFound)
    }

    /// Finds the first free (inactive) request slot, or appends at the end.
    fn find_free_request_slot(&self) -> usize {
        for i in 0..self.request_count {
            if !self.requests[i].active {
                return i;
            }
        }
        self.request_count
    }
}
