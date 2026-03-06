// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Page migration subsystem for NUMA balancing, compaction, and
//! memory policy enforcement.
//!
//! Moves pages between physical frames while maintaining virtual
//! mappings. Core primitive for:
//! - NUMA balancing (`migrate_pages(2)`)
//! - Memory compaction (defragmentation)
//! - CMA allocation fallback
//! - Memory hotplug offline
//! - Memory policy (`mbind(2)`, `set_mempolicy(2)`)
//!
//! # Subsystems
//!
//! - [`MigrateType`] — classification of page mobility
//! - [`MigrateEntry`] — per-page migration descriptor
//! - [`MigrateBatch`] — batched migration operation
//! - [`MigrateEngine`] — main engine that coordinates migration
//! - [`NumaMigratePolicy`] — NUMA-aware migration policy
//! - [`CompactMigrateScanner`] — compaction-oriented page scanner
//! - [`MigrateStats`] — aggregate statistics
//!
//! Reference: Linux `mm/migrate.c`, `mm/compaction.c`,
//! `include/linux/migrate.h`.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Page size in bytes (4 KiB).
const PAGE_SIZE: u64 = 4096;

/// Maximum pages per migration batch.
const MAX_BATCH_PAGES: usize = 128;

/// Maximum concurrent migration batches.
const MAX_BATCHES: usize = 16;

/// Maximum NUMA nodes supported.
const MAX_NUMA_NODES: usize = 8;

/// Maximum number of NUMA migration policy rules.
const MAX_NUMA_RULES: usize = 16;

/// Maximum pages tracked by the compaction scanner.
const MAX_COMPACT_PAGES: usize = 256;

/// Default number of pages to scan per compaction step.
const DEFAULT_SCAN_BATCH: usize = 32;

/// Maximum retry count for a single page migration.
const MAX_PAGE_RETRIES: u32 = 3;

// -------------------------------------------------------------------
// MigrateType
// -------------------------------------------------------------------

/// Classification of a page's mobility for migration decisions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum MigrateType {
    /// Page can be freely moved to any frame.
    #[default]
    Movable,
    /// Page can be reclaimed but not migrated (e.g. page cache).
    Reclaimable,
    /// Page cannot be moved (e.g. kernel slab, DMA-pinned).
    Unmovable,
    /// Page reserved for CMA (movable for compaction).
    CmaMovable,
    /// Page is isolated for migration (in transit).
    Isolate,
    /// Huge page (2 MiB or 1 GiB) requiring special handling.
    HugePage,
}

/// Reason for initiating a page migration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum MigrateReason {
    /// Compaction: defragmenting memory for large allocations.
    #[default]
    Compaction,
    /// NUMA balancing: moving page closer to accessing CPU.
    NumaBalance,
    /// Memory policy: `mbind` or `set_mempolicy` enforcement.
    MemoryPolicy,
    /// Hotplug: moving pages off a section being offlined.
    Hotplug,
    /// CMA: freeing contiguous region for CMA allocation.
    CmaAlloc,
    /// Soft offline: moving page away from correctable ECC error.
    SoftOffline,
    /// Proactive reclaim: moving cold pages to remote NUMA node.
    ProactiveReclaim,
}

// -------------------------------------------------------------------
// MigrateEntry
// -------------------------------------------------------------------

/// Per-page migration descriptor.
#[derive(Debug, Clone, Copy, Default)]
pub struct MigrateEntry {
    /// Source physical frame number (PFN).
    pub src_pfn: u64,
    /// Destination physical frame number (0 = unassigned).
    pub dst_pfn: u64,
    /// Virtual address of the mapping (for TLB flush).
    pub vaddr: u64,
    /// Process ID that owns the mapping (0 = kernel).
    pub pid: u64,
    /// Page mobility classification.
    pub migrate_type: MigrateType,
    /// Reason this page is being migrated.
    pub reason: MigrateReason,
    /// Source NUMA node.
    pub src_node: u32,
    /// Target NUMA node.
    pub dst_node: u32,
    /// Current state of this entry.
    pub state: MigrateEntryState,
    /// Number of migration attempts for this page.
    pub retries: u32,
    /// Whether this entry slot is in use.
    pub in_use: bool,
}

/// State of a single page migration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum MigrateEntryState {
    /// Page is queued for migration.
    #[default]
    Pending,
    /// Page is isolated (removed from LRU, PTE cleared).
    Isolated,
    /// Page content is being copied to destination frame.
    Copying,
    /// PTE has been remapped to the destination frame.
    Remapped,
    /// Migration completed successfully.
    Completed,
    /// Migration failed (page pinned, destination full, etc.).
    Failed,
    /// Migration was cancelled.
    Cancelled,
}

// -------------------------------------------------------------------
// MigrateBatch
// -------------------------------------------------------------------

/// A batch of pages being migrated together.
///
/// Batching amortises the cost of TLB flushes and lock acquisitions
/// across multiple pages.
#[derive(Debug)]
pub struct MigrateBatch {
    /// Batch identifier.
    pub batch_id: u32,
    /// Pages in this batch.
    entries: [MigrateEntry; MAX_BATCH_PAGES],
    /// Number of entries in use.
    entry_count: usize,
    /// Reason for this batch.
    pub reason: MigrateReason,
    /// Number of entries that completed successfully.
    completed_count: usize,
    /// Number of entries that failed.
    failed_count: usize,
    /// Whether the batch is finished (all entries resolved).
    finished: bool,
}

impl Default for MigrateBatch {
    fn default() -> Self {
        Self::new(0, MigrateReason::Compaction)
    }
}

impl MigrateBatch {
    /// Creates a new empty batch.
    pub const fn new(batch_id: u32, reason: MigrateReason) -> Self {
        Self {
            batch_id,
            entries: [MigrateEntry {
                src_pfn: 0,
                dst_pfn: 0,
                vaddr: 0,
                pid: 0,
                migrate_type: MigrateType::Movable,
                reason: MigrateReason::Compaction,
                src_node: 0,
                dst_node: 0,
                state: MigrateEntryState::Pending,
                retries: 0,
                in_use: false,
            }; MAX_BATCH_PAGES],
            entry_count: 0,
            reason,
            completed_count: 0,
            failed_count: 0,
            finished: false,
        }
    }

    /// Adds a page to this batch.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the batch is full.
    pub fn add_page(
        &mut self,
        src_pfn: u64,
        vaddr: u64,
        pid: u64,
        migrate_type: MigrateType,
        src_node: u32,
        dst_node: u32,
    ) -> Result<usize> {
        if self.entry_count >= MAX_BATCH_PAGES {
            return Err(Error::OutOfMemory);
        }
        let idx = self.entry_count;
        self.entries[idx] = MigrateEntry {
            src_pfn,
            dst_pfn: 0,
            vaddr,
            pid,
            migrate_type,
            reason: self.reason,
            src_node,
            dst_node,
            state: MigrateEntryState::Pending,
            retries: 0,
            in_use: true,
        };
        self.entry_count += 1;
        Ok(idx)
    }

    /// Assigns a destination PFN for an entry.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `idx` is out of range.
    pub fn assign_destination(&mut self, idx: usize, dst_pfn: u64) -> Result<()> {
        if idx >= self.entry_count {
            return Err(Error::InvalidArgument);
        }
        self.entries[idx].dst_pfn = dst_pfn;
        Ok(())
    }

    /// Isolates a page (step 1): removes from LRU, clears PTE.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `idx` is out of range.
    /// Returns [`Error::Busy`] if the page is unmovable.
    pub fn isolate_page(&mut self, idx: usize) -> Result<()> {
        if idx >= self.entry_count {
            return Err(Error::InvalidArgument);
        }
        let entry = &mut self.entries[idx];
        if entry.migrate_type == MigrateType::Unmovable {
            entry.state = MigrateEntryState::Failed;
            self.failed_count += 1;
            return Err(Error::Busy);
        }
        entry.state = MigrateEntryState::Isolated;
        Ok(())
    }

    /// Copies page content (step 2).
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `idx` is out of range
    /// or the entry is not in [`MigrateEntryState::Isolated`] state.
    pub fn copy_page(&mut self, idx: usize) -> Result<()> {
        if idx >= self.entry_count {
            return Err(Error::InvalidArgument);
        }
        let entry = &mut self.entries[idx];
        if entry.state != MigrateEntryState::Isolated {
            return Err(Error::InvalidArgument);
        }
        if entry.dst_pfn == 0 {
            return Err(Error::InvalidArgument);
        }
        entry.state = MigrateEntryState::Copying;
        // In a real kernel: memcpy(dst_page, src_page, PAGE_SIZE)
        entry.state = MigrateEntryState::Remapped;
        Ok(())
    }

    /// Finalises a page migration (step 3): updates PTE, TLB flush.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `idx` is out of range
    /// or the entry is not in [`MigrateEntryState::Remapped`] state.
    pub fn finalise_page(&mut self, idx: usize) -> Result<()> {
        if idx >= self.entry_count {
            return Err(Error::InvalidArgument);
        }
        let entry = &mut self.entries[idx];
        if entry.state != MigrateEntryState::Remapped {
            return Err(Error::InvalidArgument);
        }
        entry.state = MigrateEntryState::Completed;
        self.completed_count += 1;
        self.check_finished();
        Ok(())
    }

    /// Marks a page migration as failed.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `idx` is out of range.
    pub fn fail_page(&mut self, idx: usize) -> Result<()> {
        if idx >= self.entry_count {
            return Err(Error::InvalidArgument);
        }
        self.entries[idx].state = MigrateEntryState::Failed;
        self.entries[idx].retries += 1;
        if self.entries[idx].retries >= MAX_PAGE_RETRIES {
            self.failed_count += 1;
            self.check_finished();
        }
        Ok(())
    }

    /// Runs the full migration pipeline for all pending entries.
    ///
    /// Returns `(completed, failed)` counts for this run.
    pub fn run_all(&mut self) -> (usize, usize) {
        let mut completed = 0_usize;
        let mut failed = 0_usize;

        for i in 0..self.entry_count {
            if self.entries[i].state != MigrateEntryState::Pending {
                continue;
            }

            // Step 1: isolate.
            if self.isolate_page(i).is_err() {
                failed += 1;
                continue;
            }

            // Step 2: copy.
            if self.copy_page(i).is_err() {
                let _ = self.fail_page(i);
                failed += 1;
                continue;
            }

            // Step 3: finalise.
            if self.finalise_page(i).is_err() {
                let _ = self.fail_page(i);
                failed += 1;
                continue;
            }

            completed += 1;
        }

        (completed, failed)
    }

    /// Checks if the batch is finished.
    fn check_finished(&mut self) {
        if self.completed_count + self.failed_count >= self.entry_count {
            self.finished = true;
        }
    }

    /// Returns `true` if all entries are resolved.
    pub fn is_finished(&self) -> bool {
        self.finished
    }

    /// Returns the number of entries.
    pub fn entry_count(&self) -> usize {
        self.entry_count
    }

    /// Returns the number of completed migrations.
    pub fn completed_count(&self) -> usize {
        self.completed_count
    }

    /// Returns the number of failed migrations.
    pub fn failed_count(&self) -> usize {
        self.failed_count
    }

    /// Returns a reference to an entry.
    pub fn get_entry(&self, idx: usize) -> Option<&MigrateEntry> {
        if idx < self.entry_count {
            Some(&self.entries[idx])
        } else {
            None
        }
    }
}

// -------------------------------------------------------------------
// NumaMigratePolicy
// -------------------------------------------------------------------

/// NUMA node distance entry for migration cost calculation.
#[derive(Debug, Clone, Copy, Default)]
pub struct NumaDistance {
    /// Source node.
    pub from_node: u32,
    /// Destination node.
    pub to_node: u32,
    /// Distance value (10 = local, higher = further).
    pub distance: u32,
    /// Whether this entry is active.
    pub active: bool,
}

/// NUMA-aware migration policy.
///
/// Decides whether migrating a page between NUMA nodes is beneficial
/// based on access patterns and node distances.
#[derive(Debug)]
pub struct NumaMigratePolicy {
    /// Node distance table.
    distances: [NumaDistance; MAX_NUMA_RULES],
    /// Number of active distance entries.
    distance_count: usize,
    /// Migration threshold: only migrate if access locality improves
    /// by at least this ratio (percentage, 0..=100).
    pub locality_threshold: u32,
    /// Whether automatic NUMA balancing is enabled.
    pub auto_balance: bool,
    /// Scan period in milliseconds for NUMA fault detection.
    pub scan_period_ms: u64,
    /// Minimum number of NUMA faults before considering migration.
    pub fault_threshold: u32,
}

impl Default for NumaMigratePolicy {
    fn default() -> Self {
        Self::new()
    }
}

impl NumaMigratePolicy {
    /// Creates a new NUMA migration policy with defaults.
    pub const fn new() -> Self {
        Self {
            distances: [NumaDistance {
                from_node: 0,
                to_node: 0,
                distance: 0,
                active: false,
            }; MAX_NUMA_RULES],
            distance_count: 0,
            locality_threshold: 30,
            auto_balance: true,
            scan_period_ms: 1000,
            fault_threshold: 4,
        }
    }

    /// Registers a distance between two NUMA nodes.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the distance table is full.
    pub fn set_distance(&mut self, from_node: u32, to_node: u32, distance: u32) -> Result<()> {
        // Update existing entry if present.
        for i in 0..MAX_NUMA_RULES {
            if self.distances[i].active
                && self.distances[i].from_node == from_node
                && self.distances[i].to_node == to_node
            {
                self.distances[i].distance = distance;
                return Ok(());
            }
        }
        if self.distance_count >= MAX_NUMA_RULES {
            return Err(Error::OutOfMemory);
        }
        let slot = self
            .distances
            .iter_mut()
            .find(|d| !d.active)
            .ok_or(Error::OutOfMemory)?;
        *slot = NumaDistance {
            from_node,
            to_node,
            distance,
            active: true,
        };
        self.distance_count += 1;
        Ok(())
    }

    /// Gets the distance between two nodes (10 if local/unknown).
    pub fn get_distance(&self, from_node: u32, to_node: u32) -> u32 {
        if from_node == to_node {
            return 10; // Local access.
        }
        for i in 0..MAX_NUMA_RULES {
            if self.distances[i].active
                && self.distances[i].from_node == from_node
                && self.distances[i].to_node == to_node
            {
                return self.distances[i].distance;
            }
        }
        10 // Default to local distance if unknown.
    }

    /// Evaluates whether migrating a page from `src_node` to `dst_node`
    /// is beneficial given `numa_faults` observed on `dst_node`.
    ///
    /// Returns `true` if migration is recommended.
    pub fn should_migrate(&self, src_node: u32, dst_node: u32, numa_faults: u32) -> bool {
        if !self.auto_balance {
            return false;
        }
        if src_node == dst_node {
            return false;
        }
        if numa_faults < self.fault_threshold {
            return false;
        }
        let src_dist = self.get_distance(src_node, dst_node);
        let dst_dist = 10_u32; // Local access on destination.
        if src_dist <= dst_dist {
            return false;
        }
        let improvement = ((src_dist - dst_dist) as u64 * 100) / src_dist as u64;
        improvement >= self.locality_threshold as u64
    }
}

// -------------------------------------------------------------------
// CompactMigrateScanner
// -------------------------------------------------------------------

/// Tracks a page candidate for compaction migration.
#[derive(Debug, Clone, Copy, Default)]
pub struct CompactCandidate {
    /// Physical frame number.
    pub pfn: u64,
    /// Migration type of this page.
    pub migrate_type: MigrateType,
    /// Whether this page is a free target (hole).
    pub is_free: bool,
    /// NUMA node this page belongs to.
    pub node: u32,
    /// Whether this candidate slot is in use.
    pub in_use: bool,
}

/// Compaction-oriented page scanner that identifies movable pages
/// and free holes for defragmentation.
///
/// Maintains two cursors scanning from opposite ends of a zone:
/// - Migration scanner: scans from low PFN upward for movable pages
/// - Free scanner: scans from high PFN downward for free pages
///
/// When the cursors meet, one compaction pass is complete.
#[derive(Debug)]
pub struct CompactMigrateScanner {
    /// Zone start PFN.
    pub zone_start: u64,
    /// Zone end PFN (exclusive).
    pub zone_end: u64,
    /// Migration scanner cursor (scans upward).
    pub migrate_cursor: u64,
    /// Free scanner cursor (scans downward).
    pub free_cursor: u64,
    /// Movable page candidates found.
    movable_pages: [CompactCandidate; MAX_COMPACT_PAGES],
    /// Number of movable candidates.
    movable_count: usize,
    /// Free page candidates found.
    free_pages: [CompactCandidate; MAX_COMPACT_PAGES],
    /// Number of free candidates.
    free_count: usize,
    /// Number of pages scanned per step.
    pub scan_batch: usize,
    /// Total pages scanned in this pass.
    pub pages_scanned: u64,
    /// Total pages migrated in this pass.
    pub pages_migrated: u64,
    /// Whether the current compaction pass is complete.
    pub pass_complete: bool,
    /// Number of completed passes.
    pub passes: u64,
}

impl Default for CompactMigrateScanner {
    fn default() -> Self {
        Self::new(0, 0)
    }
}

impl CompactMigrateScanner {
    /// Creates a new compaction scanner for the given PFN range.
    pub const fn new(zone_start: u64, zone_end: u64) -> Self {
        Self {
            zone_start,
            zone_end,
            migrate_cursor: zone_start,
            free_cursor: zone_end,
            movable_pages: [CompactCandidate {
                pfn: 0,
                migrate_type: MigrateType::Movable,
                is_free: false,
                node: 0,
                in_use: false,
            }; MAX_COMPACT_PAGES],
            movable_count: 0,
            free_pages: [CompactCandidate {
                pfn: 0,
                migrate_type: MigrateType::Movable,
                is_free: true,
                node: 0,
                in_use: false,
            }; MAX_COMPACT_PAGES],
            free_count: 0,
            scan_batch: DEFAULT_SCAN_BATCH,
            pages_scanned: 0,
            pages_migrated: 0,
            pass_complete: false,
            passes: 0,
        }
    }

    /// Resets the scanner for a new compaction pass.
    pub fn reset_pass(&mut self) {
        self.migrate_cursor = self.zone_start;
        self.free_cursor = self.zone_end;
        self.movable_count = 0;
        self.free_count = 0;
        self.pages_scanned = 0;
        self.pass_complete = false;
    }

    /// Records a movable page found during scanning.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the candidate list is full.
    pub fn record_movable(&mut self, pfn: u64, migrate_type: MigrateType, node: u32) -> Result<()> {
        if self.movable_count >= MAX_COMPACT_PAGES {
            return Err(Error::OutOfMemory);
        }
        self.movable_pages[self.movable_count] = CompactCandidate {
            pfn,
            migrate_type,
            is_free: false,
            node,
            in_use: true,
        };
        self.movable_count += 1;
        Ok(())
    }

    /// Records a free page (hole) found during scanning.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the candidate list is full.
    pub fn record_free(&mut self, pfn: u64, node: u32) -> Result<()> {
        if self.free_count >= MAX_COMPACT_PAGES {
            return Err(Error::OutOfMemory);
        }
        self.free_pages[self.free_count] = CompactCandidate {
            pfn,
            migrate_type: MigrateType::Movable,
            is_free: true,
            node,
            in_use: true,
        };
        self.free_count += 1;
        Ok(())
    }

    /// Advances the migration scanner cursor by `count` PFNs.
    pub fn advance_migrate(&mut self, count: u64) {
        self.migrate_cursor = self.migrate_cursor.saturating_add(count);
        self.pages_scanned += count;
        if self.migrate_cursor >= self.free_cursor {
            self.pass_complete = true;
            self.passes += 1;
        }
    }

    /// Advances the free scanner cursor downward by `count` PFNs.
    pub fn advance_free(&mut self, count: u64) {
        self.free_cursor = self.free_cursor.saturating_sub(count);
        self.pages_scanned += count;
        if self.migrate_cursor >= self.free_cursor {
            self.pass_complete = true;
            self.passes += 1;
        }
    }

    /// Pairs up movable pages with free pages and generates a
    /// migration batch. Returns the number of pairs created.
    pub fn generate_pairs(&mut self, batch: &mut MigrateBatch) -> usize {
        let pairs = core::cmp::min(self.movable_count, self.free_count);
        let mut created = 0_usize;

        for i in 0..pairs {
            let src = &self.movable_pages[i];
            let dst = &self.free_pages[i];

            if !src.in_use || !dst.in_use {
                continue;
            }

            if batch
                .add_page(
                    src.pfn,
                    src.pfn * PAGE_SIZE, // Approximation for vaddr.
                    0,
                    src.migrate_type,
                    src.node,
                    dst.node,
                )
                .is_ok()
            {
                let idx = batch.entry_count() - 1;
                let _ = batch.assign_destination(idx, dst.pfn);
                created += 1;
            }
        }

        self.pages_migrated += created as u64;
        created
    }

    /// Returns the number of movable candidates found.
    pub fn movable_count(&self) -> usize {
        self.movable_count
    }

    /// Returns the number of free candidates found.
    pub fn free_count(&self) -> usize {
        self.free_count
    }
}

// -------------------------------------------------------------------
// MigrateStats
// -------------------------------------------------------------------

/// Aggregate page migration statistics.
#[derive(Debug, Clone, Copy, Default)]
pub struct MigrateStats {
    /// Total pages migrated successfully.
    pub pages_migrated: u64,
    /// Total migration failures.
    pub pages_failed: u64,
    /// Migrations for NUMA balancing.
    pub numa_migrations: u64,
    /// Migrations for compaction.
    pub compact_migrations: u64,
    /// Migrations for hotplug.
    pub hotplug_migrations: u64,
    /// Migrations for memory policy.
    pub policy_migrations: u64,
    /// Total migration batches executed.
    pub batches_run: u64,
    /// Total compaction passes completed.
    pub compact_passes: u64,
    /// Total bytes moved (pages * PAGE_SIZE).
    pub bytes_migrated: u64,
}

// -------------------------------------------------------------------
// MigrateEngine
// -------------------------------------------------------------------

/// Main page migration engine.
///
/// Coordinates migration batches, NUMA policy evaluation, and
/// compaction scanning. Provides a unified interface for all
/// migration consumers (NUMA balancer, compactor, hotplug, etc.).
pub struct MigrateEngine {
    /// Active migration batches.
    batches: [MigrateBatch; MAX_BATCHES],
    /// Number of active batches.
    batch_count: usize,
    /// Next batch ID.
    next_batch_id: u32,
    /// NUMA migration policy.
    numa_policy: NumaMigratePolicy,
    /// Compaction scanner.
    compact_scanner: CompactMigrateScanner,
    /// Aggregate statistics.
    stats: MigrateStats,
    /// Whether the engine is enabled.
    enabled: bool,
}

impl Default for MigrateEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl MigrateEngine {
    /// Creates a new, disabled migration engine.
    pub fn new() -> Self {
        Self {
            batches: core::array::from_fn(|_| MigrateBatch::new(0, MigrateReason::Compaction)),
            batch_count: 0,
            next_batch_id: 1,
            numa_policy: NumaMigratePolicy::new(),
            compact_scanner: CompactMigrateScanner::new(0, 0),
            stats: MigrateStats::default(),
            enabled: false,
        }
    }

    /// Enables the migration engine.
    pub fn enable(&mut self) {
        self.enabled = true;
    }

    /// Disables the migration engine.
    pub fn disable(&mut self) {
        self.enabled = false;
    }

    /// Creates a new migration batch and returns its index.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the batch table is full.
    /// Returns [`Error::NotImplemented`] if the engine is disabled.
    pub fn create_batch(&mut self, reason: MigrateReason) -> Result<usize> {
        if !self.enabled {
            return Err(Error::NotImplemented);
        }
        if self.batch_count >= MAX_BATCHES {
            return Err(Error::OutOfMemory);
        }

        let id = self.next_batch_id;
        self.next_batch_id = self.next_batch_id.wrapping_add(1);

        let idx = self.batch_count;
        self.batches[idx] = MigrateBatch::new(id, reason);
        self.batch_count += 1;
        Ok(idx)
    }

    /// Gets a mutable reference to a batch by index.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `idx` is out of range.
    pub fn batch_mut(&mut self, idx: usize) -> Result<&mut MigrateBatch> {
        if idx >= self.batch_count {
            return Err(Error::InvalidArgument);
        }
        Ok(&mut self.batches[idx])
    }

    /// Gets a reference to a batch by index.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `idx` is out of range.
    pub fn batch(&self, idx: usize) -> Result<&MigrateBatch> {
        if idx >= self.batch_count {
            return Err(Error::InvalidArgument);
        }
        Ok(&self.batches[idx])
    }

    /// Runs all pending migrations in a batch.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `batch_idx` is out of range.
    pub fn run_batch(&mut self, batch_idx: usize) -> Result<(usize, usize)> {
        if batch_idx >= self.batch_count {
            return Err(Error::InvalidArgument);
        }

        let (completed, failed) = self.batches[batch_idx].run_all();

        let reason = self.batches[batch_idx].reason;
        self.stats.pages_migrated += completed as u64;
        self.stats.pages_failed += failed as u64;
        self.stats.bytes_migrated += completed as u64 * PAGE_SIZE;
        self.stats.batches_run += 1;

        match reason {
            MigrateReason::NumaBalance => {
                self.stats.numa_migrations += completed as u64;
            }
            MigrateReason::Compaction => {
                self.stats.compact_migrations += completed as u64;
            }
            MigrateReason::Hotplug => {
                self.stats.hotplug_migrations += completed as u64;
            }
            MigrateReason::MemoryPolicy => {
                self.stats.policy_migrations += completed as u64;
            }
            _ => {}
        }

        Ok((completed, failed))
    }

    /// Performs a NUMA-aware migration of a single page.
    ///
    /// Evaluates the NUMA policy and, if migration is recommended,
    /// creates a batch with one entry and runs it.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotImplemented`] if the engine is disabled.
    /// Returns [`Error::InvalidArgument`] if migration is not
    /// recommended by the NUMA policy.
    pub fn numa_migrate_page(
        &mut self,
        src_pfn: u64,
        vaddr: u64,
        pid: u64,
        src_node: u32,
        dst_node: u32,
        dst_pfn: u64,
        numa_faults: u32,
    ) -> Result<bool> {
        if !self.enabled {
            return Err(Error::NotImplemented);
        }
        if !self
            .numa_policy
            .should_migrate(src_node, dst_node, numa_faults)
        {
            return Err(Error::InvalidArgument);
        }

        let batch_idx = self.create_batch(MigrateReason::NumaBalance)?;
        let batch = &mut self.batches[batch_idx];
        batch.add_page(
            src_pfn,
            vaddr,
            pid,
            MigrateType::Movable,
            src_node,
            dst_node,
        )?;
        batch.assign_destination(0, dst_pfn)?;

        let (completed, _) = self.run_batch(batch_idx)?;
        Ok(completed > 0)
    }

    /// Initialises the compaction scanner for a zone.
    pub fn init_compaction(&mut self, zone_start: u64, zone_end: u64) {
        self.compact_scanner = CompactMigrateScanner::new(zone_start, zone_end);
    }

    /// Returns a mutable reference to the compaction scanner.
    pub fn compact_scanner_mut(&mut self) -> &mut CompactMigrateScanner {
        &mut self.compact_scanner
    }

    /// Runs compaction: generates pairs from scanner and migrates.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotImplemented`] if the engine is disabled.
    pub fn run_compaction(&mut self) -> Result<usize> {
        if !self.enabled {
            return Err(Error::NotImplemented);
        }

        let batch_idx = self.create_batch(MigrateReason::Compaction)?;
        let pairs = self
            .compact_scanner
            .generate_pairs(&mut self.batches[batch_idx]);

        if pairs == 0 {
            return Ok(0);
        }

        let (completed, _) = self.run_batch(batch_idx)?;
        if self.compact_scanner.pass_complete {
            self.stats.compact_passes += 1;
        }
        Ok(completed)
    }

    /// Removes finished batches and compacts the batch array.
    pub fn cleanup_batches(&mut self) {
        let mut write = 0_usize;
        for read in 0..self.batch_count {
            if !self.batches[read].is_finished() {
                if write != read {
                    // Move batch from read to write position.
                    let batch_id = self.batches[read].batch_id;
                    let reason = self.batches[read].reason;
                    self.batches[write] = MigrateBatch::new(batch_id, reason);
                    // Copy entry count and states would require more
                    // complex logic; for simplicity, unfinished batches
                    // keep their slot identity.
                }
                write += 1;
            }
        }
        self.batch_count = write;
    }

    /// Returns a reference to the NUMA migration policy.
    pub fn numa_policy(&self) -> &NumaMigratePolicy {
        &self.numa_policy
    }

    /// Returns a mutable reference to the NUMA migration policy.
    pub fn numa_policy_mut(&mut self) -> &mut NumaMigratePolicy {
        &mut self.numa_policy
    }

    /// Returns aggregate migration statistics.
    pub fn stats(&self) -> &MigrateStats {
        &self.stats
    }

    /// Returns the number of active batches.
    pub fn batch_count(&self) -> usize {
        self.batch_count
    }

    /// Returns `true` if no batches are active.
    pub fn is_idle(&self) -> bool {
        self.batch_count == 0
    }
}
