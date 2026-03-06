// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! NUMA page migration.
//!
//! Implements page migration between NUMA nodes. Pages can be migrated
//! to improve locality when a task is found to frequently access pages
//! on a remote node. Migration involves isolating the page, copying its
//! data and metadata to a new frame on the target node, and updating
//! all page table entries that reference it.
//!
//! - [`MigrateStatus`] — per-page migration outcome
//! - [`MigrateEntry`] — describes one page to migrate
//! - [`MigrateBatch`] — batch of pages to migrate
//! - [`NumaMigrator`] — the main migration engine
//! - [`MigrateStats`] — migration statistics
//!
//! Reference: `.kernelORG/` — `mm/migrate.c`, `mm/mempolicy.c`.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Page size (4 KiB).
const PAGE_SIZE: usize = 4096;

/// Maximum pages in a single migration batch.
const MAX_BATCH_SIZE: usize = 64;

/// Maximum NUMA nodes.
const MAX_NODES: usize = 16;

/// Migration retry limit per page.
const MAX_RETRIES: u32 = 3;

/// NUMA distance threshold for triggering migration.
const MIGRATE_DISTANCE_THRESHOLD: u8 = 30;

/// Scan period (in ticks) for NUMA balancing.
const NUMA_SCAN_PERIOD_DEFAULT: u64 = 1000;

/// Minimum scan period.
const NUMA_SCAN_PERIOD_MIN: u64 = 100;

/// Maximum scan period.
const NUMA_SCAN_PERIOD_MAX: u64 = 60000;

// -------------------------------------------------------------------
// MigrateStatus
// -------------------------------------------------------------------

/// Outcome of a single page migration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum MigrateStatus {
    /// Migration pending (not yet attempted).
    #[default]
    Pending,
    /// Successfully migrated.
    Success,
    /// Failed: page was busy (locked or under I/O).
    Busy,
    /// Failed: could not allocate target frame.
    NoMemory,
    /// Failed: page could not be isolated.
    IsolationFailed,
    /// Failed: page type not migratable (e.g., kernel slab).
    NotMigratable,
    /// Skipped: page already on target node.
    AlreadyLocal,
    /// Failed after maximum retries.
    RetryExhausted,
}

impl MigrateStatus {
    /// Returns true if migration succeeded.
    pub fn is_success(self) -> bool {
        self == MigrateStatus::Success
    }

    /// Returns true if the page can be retried.
    pub fn is_retryable(self) -> bool {
        matches!(self, MigrateStatus::Busy | MigrateStatus::IsolationFailed)
    }
}

// -------------------------------------------------------------------
// MigrateEntry
// -------------------------------------------------------------------

/// Describes a single page to migrate.
#[derive(Debug, Clone, Copy)]
pub struct MigrateEntry {
    /// Source page frame number.
    pub pfn: u64,
    /// Source NUMA node.
    pub src_node: u16,
    /// Target NUMA node.
    pub target_node: u16,
    /// Migration status.
    pub status: MigrateStatus,
    /// Number of retries so far.
    pub retries: u32,
    /// Whether the page is anonymous (vs. file-backed).
    pub is_anon: bool,
    /// Whether the page is mapped by multiple PTEs.
    pub is_shared: bool,
}

impl MigrateEntry {
    /// Creates a new migration entry.
    pub fn new(pfn: u64, src_node: u16, target_node: u16) -> Self {
        Self {
            pfn,
            src_node,
            target_node,
            status: MigrateStatus::Pending,
            retries: 0,
            is_anon: true,
            is_shared: false,
        }
    }

    /// Marks the entry as successfully migrated.
    pub fn mark_success(&mut self) {
        self.status = MigrateStatus::Success;
    }

    /// Marks the entry as failed with the given status.
    pub fn mark_failed(&mut self, status: MigrateStatus) {
        self.status = status;
    }

    /// Returns true if the page is already on the target node.
    pub fn is_local(&self) -> bool {
        self.src_node == self.target_node
    }
}

impl Default for MigrateEntry {
    fn default() -> Self {
        Self {
            pfn: 0,
            src_node: 0,
            target_node: 0,
            status: MigrateStatus::Pending,
            retries: 0,
            is_anon: true,
            is_shared: false,
        }
    }
}

// -------------------------------------------------------------------
// MigrateBatch
// -------------------------------------------------------------------

/// A batch of pages to migrate.
pub struct MigrateBatch {
    /// Entries in this batch.
    entries: [MigrateEntry; MAX_BATCH_SIZE],
    /// Number of valid entries.
    len: usize,
}

impl MigrateBatch {
    /// Creates an empty batch.
    pub fn new() -> Self {
        Self {
            entries: [MigrateEntry::default(); MAX_BATCH_SIZE],
            len: 0,
        }
    }

    /// Adds a page to the batch.
    pub fn add(&mut self, entry: MigrateEntry) -> Result<()> {
        if self.len >= MAX_BATCH_SIZE {
            return Err(Error::OutOfMemory);
        }
        self.entries[self.len] = entry;
        self.len += 1;
        Ok(())
    }

    /// Returns the entries as a slice.
    pub fn entries(&self) -> &[MigrateEntry] {
        &self.entries[..self.len]
    }

    /// Returns the entries as a mutable slice.
    pub fn entries_mut(&mut self) -> &mut [MigrateEntry] {
        &mut self.entries[..self.len]
    }

    /// Returns the number of entries.
    pub fn len(&self) -> usize {
        self.len
    }

    /// Returns true if the batch is empty.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Clears the batch.
    pub fn clear(&mut self) {
        self.len = 0;
    }

    /// Counts entries with the given status.
    pub fn count_status(&self, status: MigrateStatus) -> usize {
        self.entries[..self.len]
            .iter()
            .filter(|e| e.status == status)
            .count()
    }

    /// Returns the number of successful migrations.
    pub fn nr_succeeded(&self) -> usize {
        self.count_status(MigrateStatus::Success)
    }
}

impl Default for MigrateBatch {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// MigrateStats
// -------------------------------------------------------------------

/// Migration statistics.
#[derive(Debug, Clone, Copy, Default)]
pub struct MigrateStats {
    /// Total pages attempted.
    pub pages_attempted: u64,
    /// Successfully migrated.
    pub pages_migrated: u64,
    /// Failed migrations.
    pub pages_failed: u64,
    /// Pages skipped (already local).
    pub pages_skipped: u64,
    /// Total batches processed.
    pub batches: u64,
    /// Total data copied (bytes).
    pub bytes_copied: u64,
    /// Pages isolated for migration.
    pub pages_isolated: u64,
    /// Retries performed.
    pub retries: u64,
}

impl MigrateStats {
    /// Creates new statistics.
    pub fn new() -> Self {
        Self::default()
    }

    /// Resets all statistics.
    pub fn reset(&mut self) {
        *self = Self::default();
    }

    /// Returns the success rate (0-100).
    pub fn success_rate(&self) -> u64 {
        if self.pages_attempted == 0 {
            return 0;
        }
        self.pages_migrated * 100 / self.pages_attempted
    }
}

// -------------------------------------------------------------------
// NumaPlacement
// -------------------------------------------------------------------

/// NUMA placement decision for a task.
#[derive(Debug, Clone, Copy, Default)]
pub struct NumaPlacement {
    /// Current node of the task.
    pub current_node: u16,
    /// Best node based on access patterns.
    pub best_node: u16,
    /// Number of local page accesses.
    pub local_accesses: u64,
    /// Number of remote page accesses.
    pub remote_accesses: u64,
    /// Current scan period.
    pub scan_period: u64,
    /// Whether migration is recommended.
    pub should_migrate: bool,
}

impl NumaPlacement {
    /// Creates a new placement state for the given node.
    pub fn new(node: u16) -> Self {
        Self {
            current_node: node,
            best_node: node,
            local_accesses: 0,
            remote_accesses: 0,
            scan_period: NUMA_SCAN_PERIOD_DEFAULT,
            should_migrate: false,
        }
    }

    /// Records an access from the given node.
    pub fn record_access(&mut self, access_node: u16) {
        if access_node == self.current_node {
            self.local_accesses += 1;
        } else {
            self.remote_accesses += 1;
        }
    }

    /// Evaluates the placement decision.
    pub fn evaluate(&mut self) {
        let total = self.local_accesses + self.remote_accesses;
        if total == 0 {
            self.should_migrate = false;
            return;
        }
        // If more than 60% of accesses are remote, recommend migration.
        self.should_migrate = self.remote_accesses * 100 / total > 60;

        // Adjust scan period based on access pattern.
        if self.should_migrate {
            // More remote -> scan faster.
            self.scan_period = (self.scan_period / 2).max(NUMA_SCAN_PERIOD_MIN);
        } else {
            // Mostly local -> scan slower.
            self.scan_period = (self.scan_period.saturating_mul(2)).min(NUMA_SCAN_PERIOD_MAX);
        }
    }

    /// Resets access counters for a new period.
    pub fn reset_counters(&mut self) {
        self.local_accesses = 0;
        self.remote_accesses = 0;
    }

    /// Returns the locality ratio (0-100, higher = more local).
    pub fn locality_ratio(&self) -> u64 {
        let total = self.local_accesses + self.remote_accesses;
        if total == 0 {
            return 100;
        }
        self.local_accesses * 100 / total
    }
}

// -------------------------------------------------------------------
// NumaMigrator
// -------------------------------------------------------------------

/// NUMA page migration engine.
///
/// Handles batch page migration between NUMA nodes. Each migration
/// involves: isolating the source page, allocating a frame on the
/// target node, copying data and metadata, and updating page tables.
pub struct NumaMigrator {
    /// NUMA distances (node x node).
    distances: [[u8; MAX_NODES]; MAX_NODES],
    /// Number of NUMA nodes.
    nr_nodes: usize,
    /// Migration statistics.
    stats: MigrateStats,
    /// Distance threshold for migration.
    distance_threshold: u8,
}

impl NumaMigrator {
    /// Creates a new NUMA migrator.
    pub fn new(nr_nodes: usize) -> Self {
        let nr = nr_nodes.min(MAX_NODES);
        let mut distances = [[255u8; MAX_NODES]; MAX_NODES];
        for (i, row) in distances.iter_mut().enumerate().take(nr) {
            row[i] = 10; // local distance
        }
        Self {
            distances,
            nr_nodes: nr,
            stats: MigrateStats::new(),
            distance_threshold: MIGRATE_DISTANCE_THRESHOLD,
        }
    }

    /// Sets NUMA distance between two nodes.
    pub fn set_distance(&mut self, from: usize, to: usize, distance: u8) {
        if from < MAX_NODES && to < MAX_NODES {
            self.distances[from][to] = distance;
            self.distances[to][from] = distance;
        }
    }

    /// Returns NUMA distance between two nodes.
    pub fn distance(&self, from: usize, to: usize) -> u8 {
        if from < MAX_NODES && to < MAX_NODES {
            self.distances[from][to]
        } else {
            255
        }
    }

    /// Migrates a batch of pages.
    ///
    /// For each entry in the batch:
    /// 1. Check if the page is already local (skip).
    /// 2. Attempt to isolate the source page.
    /// 3. Allocate a frame on the target node.
    /// 4. Copy page data and metadata.
    /// 5. Update status.
    pub fn migrate_pages(&mut self, batch: &mut MigrateBatch) -> Result<usize> {
        if batch.is_empty() {
            return Ok(0);
        }

        self.stats.batches += 1;
        let mut nr_migrated = 0;

        for i in 0..batch.len() {
            self.stats.pages_attempted += 1;

            // Skip already local pages.
            if batch.entries()[i].is_local() {
                batch.entries_mut()[i].status = MigrateStatus::AlreadyLocal;
                self.stats.pages_skipped += 1;
                continue;
            }

            // Attempt migration with retries.
            let mut migrated = false;
            for _retry in 0..MAX_RETRIES {
                match self.try_migrate_page(batch.entries()[i].pfn, batch.entries()[i].target_node)
                {
                    Ok(()) => {
                        batch.entries_mut()[i].mark_success();
                        self.stats.pages_migrated += 1;
                        self.stats.bytes_copied += PAGE_SIZE as u64;
                        nr_migrated += 1;
                        migrated = true;
                        break;
                    }
                    Err(_) => {
                        batch.entries_mut()[i].retries += 1;
                        self.stats.retries += 1;
                    }
                }
            }

            if !migrated {
                batch.entries_mut()[i].mark_failed(MigrateStatus::RetryExhausted);
                self.stats.pages_failed += 1;
            }
        }

        Ok(nr_migrated)
    }

    /// Attempts to migrate a single page.
    fn try_migrate_page(&mut self, _pfn: u64, _target_node: u16) -> Result<()> {
        // Step 1: Isolate page (stub — in real kernel, remove from LRU).
        self.stats.pages_isolated += 1;

        // Step 2: Allocate target frame (stub).
        // Step 3: Copy data (migrate_page_copy stub).
        // Step 4: Remap PTEs (stub).

        Ok(())
    }

    /// Copies page data from source to destination frame.
    ///
    /// In a real kernel this would use `copy_highpage` or similar.
    pub fn migrate_page_copy(dst: &mut [u8; PAGE_SIZE], src: &[u8; PAGE_SIZE]) {
        dst.copy_from_slice(src);
    }

    /// Checks whether a page should be migrated based on NUMA distance.
    pub fn should_migrate(&self, src_node: usize, target_node: usize) -> bool {
        if src_node == target_node {
            return false;
        }
        self.distance(src_node, target_node) >= self.distance_threshold
    }

    /// Evaluates task NUMA placement and decides migration.
    pub fn task_numa_placement(&self, placement: &mut NumaPlacement) -> bool {
        placement.evaluate();
        placement.should_migrate
    }

    /// Returns migration statistics.
    pub fn stats(&self) -> &MigrateStats {
        &self.stats
    }

    /// Resets migration statistics.
    pub fn reset_stats(&mut self) {
        self.stats.reset();
    }

    /// Returns the number of NUMA nodes.
    pub fn nr_nodes(&self) -> usize {
        self.nr_nodes
    }

    /// Sets the distance threshold for migration.
    pub fn set_distance_threshold(&mut self, threshold: u8) {
        self.distance_threshold = threshold;
    }
}
