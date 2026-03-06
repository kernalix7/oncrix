// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Balloon compaction support.
//!
//! Extends the balloon driver with compaction-awareness: balloon pages
//! are registered as movable so that the memory compaction subsystem
//! can migrate them to consolidate free memory. This allows the
//! balloon to coexist with high-order allocation requirements.
//!
//! - [`BalloonPageState`] — balloon page lifecycle
//! - [`BalloonPage`] — a single balloon-tracked page
//! - [`BalloonMigrateResult`] — outcome of migrating a balloon page
//! - [`BalloonDevice`] — the balloon device with compaction support
//! - [`BalloonCompactionStats`] — aggregate statistics
//!
//! Reference: `.kernelORG/` — `mm/balloon_compaction.c`,
//! `include/linux/balloon_compaction.h`.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Maximum number of balloon pages.
const MAX_BALLOON_PAGES: usize = 1024;

/// Maximum pages per inflate/deflate operation.
const MAX_PAGES_PER_OP: usize = 64;

/// Page size (4 KiB).
const _PAGE_SIZE: u64 = 4096;

// -------------------------------------------------------------------
// BalloonPageState
// -------------------------------------------------------------------

/// Balloon page lifecycle state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum BalloonPageState {
    /// Page is free (not tracked by balloon).
    #[default]
    Free,
    /// Page has been inflated (reclaimed by balloon).
    Inflated,
    /// Page is being migrated (isolated for compaction).
    Migrating,
    /// Page has been deflated (returned to guest).
    Deflated,
}

// -------------------------------------------------------------------
// BalloonPage
// -------------------------------------------------------------------

/// A single balloon-tracked page.
#[derive(Debug, Clone, Copy, Default)]
pub struct BalloonPage {
    /// Page frame number.
    pub pfn: u64,
    /// Current state.
    pub state: BalloonPageState,
    /// Whether this page is registered as movable.
    pub movable: bool,
    /// Migration count (times this page has been migrated).
    pub migration_count: u32,
    /// Whether this slot is in use.
    pub active: bool,
}

// -------------------------------------------------------------------
// BalloonMigrateResult
// -------------------------------------------------------------------

/// Outcome of migrating a balloon page.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum BalloonMigrateResult {
    /// Migration succeeded.
    #[default]
    Success,
    /// Page is not in a migratable state.
    NotMigratable,
    /// No target page available.
    NoTarget,
    /// Page is pinned and cannot be migrated.
    Pinned,
}

// -------------------------------------------------------------------
// BalloonCompactionStats
// -------------------------------------------------------------------

/// Aggregate balloon compaction statistics.
#[derive(Debug, Clone, Copy, Default)]
pub struct BalloonCompactionStats {
    /// Total inflate operations.
    pub inflate_ops: u64,
    /// Total pages inflated.
    pub pages_inflated: u64,
    /// Total deflate operations.
    pub deflate_ops: u64,
    /// Total pages deflated.
    pub pages_deflated: u64,
    /// Isolation attempts for migration.
    pub isolate_attempts: u64,
    /// Successful isolations.
    pub isolate_success: u64,
    /// Migration attempts.
    pub migrate_attempts: u64,
    /// Successful migrations.
    pub migrate_success: u64,
    /// Failed migrations.
    pub migrate_failures: u64,
}

impl BalloonCompactionStats {
    /// Resets all counters.
    pub fn reset(&mut self) {
        *self = Self::default();
    }
}

// -------------------------------------------------------------------
// BalloonDevice
// -------------------------------------------------------------------

/// The balloon device with compaction support.
pub struct BalloonDevice {
    /// Balloon page storage.
    pages: [BalloonPage; MAX_BALLOON_PAGES],
    /// Number of active balloon pages.
    count: usize,
    /// Number of inflated pages.
    inflated_pages: usize,
    /// Number of deflated pages.
    deflated_pages: usize,
    /// Statistics.
    stats: BalloonCompactionStats,
    /// Next PFN for simulated page allocation.
    next_pfn: u64,
}

impl Default for BalloonDevice {
    fn default() -> Self {
        Self {
            pages: [BalloonPage::default(); MAX_BALLOON_PAGES],
            count: 0,
            inflated_pages: 0,
            deflated_pages: 0,
            stats: BalloonCompactionStats::default(),
            next_pfn: 0x2000,
        }
    }
}

impl BalloonDevice {
    /// Creates a new balloon device.
    pub fn new() -> Self {
        Self::default()
    }

    /// Allocates a page for the balloon (inflate operation).
    pub fn balloon_page_alloc(&mut self) -> Result<usize> {
        if self.count >= MAX_BALLOON_PAGES {
            return Err(Error::OutOfMemory);
        }
        let pfn = self.next_pfn;
        self.next_pfn += 1;

        let idx = self.count;
        self.pages[idx] = BalloonPage {
            pfn,
            state: BalloonPageState::Inflated,
            movable: true,
            migration_count: 0,
            active: true,
        };
        self.count += 1;
        self.inflated_pages += 1;
        self.stats.pages_inflated += 1;
        Ok(idx)
    }

    /// Frees a balloon page (deflate operation).
    pub fn balloon_page_free(&mut self, index: usize) -> Result<u64> {
        if index >= self.count || !self.pages[index].active {
            return Err(Error::NotFound);
        }
        let pfn = self.pages[index].pfn;
        self.pages[index].state = BalloonPageState::Deflated;
        self.pages[index].active = false;
        self.deflated_pages += 1;
        if self.inflated_pages > 0 {
            self.inflated_pages -= 1;
        }
        self.stats.pages_deflated += 1;
        Ok(pfn)
    }

    /// Inflates the balloon by the given number of pages.
    pub fn inflate(&mut self, nr_pages: usize) -> Result<usize> {
        let to_inflate = nr_pages.min(MAX_PAGES_PER_OP);
        let mut inflated = 0;

        for _ in 0..to_inflate {
            match self.balloon_page_alloc() {
                Ok(_) => inflated += 1,
                Err(_) => break,
            }
        }

        self.stats.inflate_ops += 1;
        Ok(inflated)
    }

    /// Deflates the balloon by freeing the given number of pages.
    pub fn deflate(&mut self, nr_pages: usize) -> Result<usize> {
        let to_deflate = nr_pages.min(MAX_PAGES_PER_OP);
        let mut deflated = 0;

        for i in 0..self.count {
            if deflated >= to_deflate {
                break;
            }
            if self.pages[i].active && self.pages[i].state == BalloonPageState::Inflated {
                let _ = self.balloon_page_free(i);
                deflated += 1;
            }
        }

        self.stats.deflate_ops += 1;
        Ok(deflated)
    }

    /// Checks if a balloon page is movable (for compaction).
    pub fn balloon_page_movable(&self, index: usize) -> bool {
        if index >= self.count {
            return false;
        }
        self.pages[index].active
            && self.pages[index].movable
            && self.pages[index].state == BalloonPageState::Inflated
    }

    /// Isolates a balloon page for migration.
    pub fn isolate(&mut self, index: usize) -> BalloonMigrateResult {
        self.stats.isolate_attempts += 1;

        if !self.balloon_page_movable(index) {
            return BalloonMigrateResult::NotMigratable;
        }

        self.pages[index].state = BalloonPageState::Migrating;
        self.stats.isolate_success += 1;
        BalloonMigrateResult::Success
    }

    /// Migrates a balloon page to a new PFN.
    pub fn migrate(&mut self, index: usize, new_pfn: u64) -> BalloonMigrateResult {
        self.stats.migrate_attempts += 1;

        if index >= self.count || !self.pages[index].active {
            self.stats.migrate_failures += 1;
            return BalloonMigrateResult::NotMigratable;
        }

        if self.pages[index].state != BalloonPageState::Migrating {
            self.stats.migrate_failures += 1;
            return BalloonMigrateResult::NotMigratable;
        }

        self.pages[index].pfn = new_pfn;
        self.pages[index].state = BalloonPageState::Inflated;
        self.pages[index].migration_count += 1;
        self.stats.migrate_success += 1;
        BalloonMigrateResult::Success
    }

    /// Puts back a page that was isolated but not migrated.
    pub fn putback(&mut self, index: usize) -> Result<()> {
        if index >= self.count || !self.pages[index].active {
            return Err(Error::NotFound);
        }
        if self.pages[index].state == BalloonPageState::Migrating {
            self.pages[index].state = BalloonPageState::Inflated;
        }
        Ok(())
    }

    /// Returns the number of inflated pages.
    pub fn inflated_count(&self) -> usize {
        self.inflated_pages
    }

    /// Returns the number of deflated pages.
    pub fn deflated_count(&self) -> usize {
        self.deflated_pages
    }

    /// Returns total tracked pages.
    pub fn total_count(&self) -> usize {
        self.count
    }

    /// Returns statistics.
    pub fn stats(&self) -> &BalloonCompactionStats {
        &self.stats
    }

    /// Returns a reference to a page.
    pub fn get_page(&self, index: usize) -> Option<&BalloonPage> {
        if index < self.count && self.pages[index].active {
            Some(&self.pages[index])
        } else {
            None
        }
    }

    /// Resets statistics.
    pub fn reset_stats(&mut self) {
        self.stats.reset();
    }
}
