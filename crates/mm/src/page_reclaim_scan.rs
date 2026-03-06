// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Page reclaim scanning.
//!
//! Implements the page reclaim scanner that walks LRU lists to find
//! pages to evict. The scanner uses a priority-based approach where
//! lower priority means more aggressive scanning. Scan ratios between
//! anonymous and file-backed pages are computed based on workload
//! heuristics, swap pressure, and cgroup memory limits.
//!
//! - [`ScanControl`] — parameters for a reclaim scan
//! - [`ScanRatio`] — anon vs. file scan ratio
//! - [`LruType`] — LRU list classification
//! - [`ScanResult`] — outcome of a scan pass
//! - [`ReclaimScanner`] — the main reclaim scanner
//!
//! Reference: `.kernelORG/` — `mm/vmscan.c`, `include/linux/mmzone.h`.

// oncrix_lib used indirectly via crate types.

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Default scan priority (lower = more aggressive).
const DEF_PRIORITY: u32 = 12;

/// Maximum scan priority.
const MAX_PRIORITY: u32 = 12;

/// Minimum scan priority (most aggressive).
const MIN_PRIORITY: u32 = 0;

/// Maximum pages to scan in a single pass.
const MAX_NR_TO_SCAN: u64 = 4096;

/// Default anon/file scan ratio (percentage towards anon).
const DEFAULT_SWAPPINESS: u32 = 60;

/// Maximum swap pressure value.
const MAX_SWAP_PRESSURE: u32 = 200;

/// Scan batch size.
const SCAN_BATCH: u64 = 32;

/// Maximum LRU lists tracked.
const NR_LRU_LISTS: usize = 5;

/// Inactive ratio denominator.
const INACTIVE_RATIO: u64 = 3;

// -------------------------------------------------------------------
// LruType
// -------------------------------------------------------------------

/// LRU list classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum LruType {
    /// Inactive anonymous pages.
    #[default]
    InactiveAnon = 0,
    /// Active anonymous pages.
    ActiveAnon = 1,
    /// Inactive file-backed pages.
    InactiveFile = 2,
    /// Active file-backed pages.
    ActiveFile = 3,
    /// Unevictable pages.
    Unevictable = 4,
}

impl LruType {
    /// Returns the index for this LRU type.
    pub fn as_index(self) -> usize {
        self as usize
    }

    /// Returns true if this is an anonymous LRU.
    pub fn is_anon(self) -> bool {
        matches!(self, LruType::InactiveAnon | LruType::ActiveAnon)
    }

    /// Returns true if this is a file-backed LRU.
    pub fn is_file(self) -> bool {
        matches!(self, LruType::InactiveFile | LruType::ActiveFile)
    }

    /// Returns true if this is an active list.
    pub fn is_active(self) -> bool {
        matches!(self, LruType::ActiveAnon | LruType::ActiveFile)
    }

    /// Returns the inactive counterpart.
    pub fn to_inactive(self) -> Self {
        match self {
            LruType::ActiveAnon => LruType::InactiveAnon,
            LruType::ActiveFile => LruType::InactiveFile,
            other => other,
        }
    }
}

// -------------------------------------------------------------------
// ScanControl
// -------------------------------------------------------------------

/// Parameters controlling a page reclaim scan.
#[derive(Debug, Clone)]
pub struct ScanControl {
    /// Number of pages to scan.
    pub nr_to_scan: u64,
    /// Number of pages reclaimed so far.
    pub nr_reclaimed: u64,
    /// Current priority level (0 = most aggressive, 12 = lightest).
    pub priority: u32,
    /// Target memory cgroup ID (0 = global reclaim).
    pub target_memcg: u64,
    /// Whether writeback (page cleaning) is allowed.
    pub may_writepage: bool,
    /// Whether swap-out is allowed.
    pub may_swap: bool,
    /// Whether unmapping (rmap walk) is allowed.
    pub may_unmap: bool,
    /// Swappiness value (0-200).
    pub swappiness: u32,
    /// Whether this is a compaction-driven reclaim.
    pub compaction_ready: bool,
    /// Order of allocation that triggered reclaim.
    pub order: u32,
    /// GFP flags from the allocation.
    pub gfp_flags: u32,
}

impl ScanControl {
    /// Creates a default scan control.
    pub fn new() -> Self {
        Self {
            nr_to_scan: MAX_NR_TO_SCAN,
            nr_reclaimed: 0,
            priority: DEF_PRIORITY,
            target_memcg: 0,
            may_writepage: true,
            may_swap: true,
            may_unmap: true,
            swappiness: DEFAULT_SWAPPINESS,
            compaction_ready: false,
            order: 0,
            gfp_flags: 0,
        }
    }

    /// Creates a scan control for cgroup-targeted reclaim.
    pub fn for_memcg(memcg_id: u64) -> Self {
        let mut sc = Self::new();
        sc.target_memcg = memcg_id;
        sc
    }

    /// Returns true if this is a global (non-cgroup) reclaim.
    pub fn is_global(&self) -> bool {
        self.target_memcg == 0
    }

    /// Increases priority (makes scanning more aggressive).
    pub fn raise_priority(&mut self) {
        if self.priority > MIN_PRIORITY {
            self.priority -= 1;
        }
    }

    /// Decreases priority (makes scanning less aggressive).
    pub fn lower_priority(&mut self) {
        if self.priority < MAX_PRIORITY {
            self.priority += 1;
        }
    }

    /// Returns the fraction of pages to scan at this priority.
    ///
    /// At priority 12, scan 1/4096 of pages; at priority 0, scan all.
    pub fn scan_fraction(&self) -> u64 {
        if self.priority == 0 {
            return 1; // scan everything
        }
        1u64 << self.priority
    }
}

impl Default for ScanControl {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// ScanRatio
// -------------------------------------------------------------------

/// Anon vs. file scan ratio.
#[derive(Debug, Clone, Copy, Default)]
pub struct ScanRatio {
    /// Number of anonymous pages to scan.
    pub anon_scan: u64,
    /// Number of file-backed pages to scan.
    pub file_scan: u64,
}

impl ScanRatio {
    /// Creates a new scan ratio.
    pub fn new(anon_scan: u64, file_scan: u64) -> Self {
        Self {
            anon_scan,
            file_scan,
        }
    }

    /// Returns the total pages to scan.
    pub fn total(&self) -> u64 {
        self.anon_scan + self.file_scan
    }

    /// Returns the anon percentage (0-100).
    pub fn anon_pct(&self) -> u64 {
        let total = self.total();
        if total == 0 {
            return 50;
        }
        self.anon_scan * 100 / total
    }
}

// -------------------------------------------------------------------
// LruSizes
// -------------------------------------------------------------------

/// Page counts on each LRU list.
#[derive(Debug, Clone, Copy, Default)]
pub struct LruSizes {
    /// Per-LRU page counts.
    pub counts: [u64; NR_LRU_LISTS],
}

impl LruSizes {
    /// Returns the count for a given LRU.
    pub fn get(&self, lru: LruType) -> u64 {
        self.counts[lru.as_index()]
    }

    /// Sets the count for a given LRU.
    pub fn set(&mut self, lru: LruType, count: u64) {
        self.counts[lru.as_index()] = count;
    }

    /// Returns total anonymous pages (active + inactive).
    pub fn total_anon(&self) -> u64 {
        self.counts[LruType::InactiveAnon.as_index()] + self.counts[LruType::ActiveAnon.as_index()]
    }

    /// Returns total file-backed pages (active + inactive).
    pub fn total_file(&self) -> u64 {
        self.counts[LruType::InactiveFile.as_index()] + self.counts[LruType::ActiveFile.as_index()]
    }

    /// Returns total reclaimable pages.
    pub fn total_reclaimable(&self) -> u64 {
        self.total_anon() + self.total_file()
    }
}

// -------------------------------------------------------------------
// ScanResult
// -------------------------------------------------------------------

/// Outcome of a reclaim scan pass.
#[derive(Debug, Clone, Copy, Default)]
pub struct ScanResult {
    /// Pages scanned.
    pub nr_scanned: u64,
    /// Pages reclaimed.
    pub nr_reclaimed: u64,
    /// Pages that could not be reclaimed (pinned/dirty).
    pub nr_skipped: u64,
    /// Pages that were activated (moved to active list).
    pub nr_activated: u64,
    /// Pages written back.
    pub nr_writeback: u64,
    /// Whether the scan was truncated (hit scan limit).
    pub truncated: bool,
}

impl ScanResult {
    /// Returns the reclaim ratio (0-100).
    pub fn reclaim_ratio(&self) -> u64 {
        if self.nr_scanned == 0 {
            return 0;
        }
        self.nr_reclaimed * 100 / self.nr_scanned
    }
}

// -------------------------------------------------------------------
// ReclaimScanner
// -------------------------------------------------------------------

/// Page reclaim scanner.
///
/// Walks LRU lists to identify and reclaim pages. Uses priority-based
/// scanning with configurable anon/file ratios.
pub struct ReclaimScanner {
    /// LRU list sizes.
    lru_sizes: LruSizes,
    /// Scan control parameters.
    control: ScanControl,
    /// Cumulative scan result.
    result: ScanResult,
}

impl ReclaimScanner {
    /// Creates a new reclaim scanner.
    pub fn new(control: ScanControl, lru_sizes: LruSizes) -> Self {
        Self {
            lru_sizes,
            control,
            result: ScanResult::default(),
        }
    }

    /// Computes the scan count (how many pages of each type to scan).
    ///
    /// Uses swappiness to balance between anon and file pages.
    /// At swappiness 0, only file pages are scanned (no swap).
    /// At swappiness 200, strongly prefer scanning anon pages.
    pub fn get_scan_count(&self) -> ScanRatio {
        let total_anon = self.lru_sizes.total_anon();
        let total_file = self.lru_sizes.total_file();
        let fraction = self.control.scan_fraction();

        if !self.control.may_swap || self.control.swappiness == 0 {
            // No swap: scan only file pages.
            let file_scan = (total_file / fraction).max(1).min(MAX_NR_TO_SCAN);
            return ScanRatio::new(0, file_scan);
        }

        let swappiness = self.control.swappiness as u64;

        // Weighted scan counts based on swappiness.
        // anon_weight = swappiness, file_weight = 200 - swappiness
        let anon_weight = swappiness;
        let file_weight = 200u64.saturating_sub(swappiness);

        let anon_scan = if total_anon > 0 && anon_weight > 0 {
            let raw = total_anon * anon_weight / 200;
            (raw / fraction).max(1).min(MAX_NR_TO_SCAN)
        } else {
            0
        };

        let file_scan = if total_file > 0 && file_weight > 0 {
            let raw = total_file * file_weight / 200;
            (raw / fraction).max(1).min(MAX_NR_TO_SCAN)
        } else {
            0
        };

        ScanRatio::new(anon_scan, file_scan)
    }

    /// Shrinks a single LRU list.
    ///
    /// Scans up to `nr_to_scan` pages from the given list and attempts
    /// to reclaim them.
    pub fn shrink_list(&mut self, lru: LruType, nr_to_scan: u64) -> ScanResult {
        let mut result = ScanResult::default();
        let available = self.lru_sizes.get(lru);
        let to_scan = nr_to_scan.min(available);

        let mut scanned = 0u64;
        while scanned < to_scan {
            let batch = SCAN_BATCH.min(to_scan - scanned);
            scanned += batch;
            result.nr_scanned += batch;

            // Model: reclaim ~50% of scanned pages (simplified).
            let reclaimed = batch / 2;
            result.nr_reclaimed += reclaimed;

            // Some pages get activated instead.
            let activated = batch / 8;
            result.nr_activated += activated;

            // Remaining are skipped.
            result.nr_skipped += batch - reclaimed - activated;
        }

        // Update LRU sizes.
        let current = self.lru_sizes.get(lru);
        self.lru_sizes
            .set(lru, current.saturating_sub(result.nr_reclaimed));

        // Accumulate into scanner totals.
        self.result.nr_scanned += result.nr_scanned;
        self.result.nr_reclaimed += result.nr_reclaimed;
        self.result.nr_skipped += result.nr_skipped;
        self.result.nr_activated += result.nr_activated;

        result
    }

    /// Runs a complete reclaim scan pass.
    ///
    /// Computes scan ratios, then shrinks both anon and file LRU lists.
    pub fn scan(&mut self) -> ScanResult {
        let ratio = self.get_scan_count();

        // Shrink inactive file list.
        if ratio.file_scan > 0 {
            self.shrink_list(LruType::InactiveFile, ratio.file_scan);
        }

        // Shrink inactive anon list.
        if ratio.anon_scan > 0 {
            self.shrink_list(LruType::InactiveAnon, ratio.anon_scan);
        }

        // If not enough reclaimed, try active lists.
        if self.result.nr_reclaimed < self.control.nr_to_scan / 4 {
            let extra_file = ratio.file_scan / 4;
            if extra_file > 0 {
                self.shrink_list(LruType::ActiveFile, extra_file);
            }
        }

        self.result
    }

    /// Returns the cumulative scan result.
    pub fn result(&self) -> &ScanResult {
        &self.result
    }

    /// Returns the current LRU sizes.
    pub fn lru_sizes(&self) -> &LruSizes {
        &self.lru_sizes
    }

    /// Returns the scan control.
    pub fn control(&self) -> &ScanControl {
        &self.control
    }

    /// Updates the scan control.
    pub fn set_control(&mut self, control: ScanControl) {
        self.control = control;
    }

    /// Resets the scan result.
    pub fn reset_result(&mut self) {
        self.result = ScanResult::default();
    }
}
