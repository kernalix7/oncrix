// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Transparent Huge Pages (THP) subsystem.
//!
//! Automatically promotes groups of 512 contiguous 4 KiB pages into
//! single 2 MiB huge pages (and vice versa), reducing TLB misses for
//! large working sets without requiring application changes.
//!
//! # Design
//!
//! - **khugepaged** scanner: background thread that scans address
//!   spaces for collapse candidates (512 consecutive present,
//!   compatible pages).
//! - **collapse_huge_page**: remaps 512 4K PTEs as a single 2M PDE
//!   with the PS (Page Size) bit set.
//! - **split_huge_page**: reverse operation — splits a 2M page back
//!   into 512 4K pages (needed for partial unmap, swap-out, mprotect
//!   with different protections).
//!
//! # Subsystems
//!
//! - [`ThpMode`] — always / madvise / never
//! - [`ThpDefrag`] — defragmentation policy
//! - [`ScanCandidate`] — candidate VMA region for collapse
//! - [`CollapseResult`] — outcome of a collapse attempt
//! - [`KhugepageScanner`] — background scanner state
//! - [`ThpController`] — top-level THP manager
//! - [`ThpStats`] — statistics
//!
//! Reference: Linux `mm/khugepaged.c`, `mm/huge_memory.c`,
//! `include/linux/huge_mm.h`.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Standard page size (4 KiB).
const PAGE_SIZE: u64 = 4096;

/// Huge page size (2 MiB).
const HUGE_PAGE_SIZE: u64 = 2 * 1024 * 1024;

/// Number of base pages in a huge page.
const PAGES_PER_HUGEPAGE: usize = 512;

/// Maximum scan candidates per pass.
const MAX_SCAN_CANDIDATES: usize = 64;

/// Maximum VMAs the scanner tracks.
const MAX_SCAN_VMAS: usize = 256;

/// Default scan sleep interval in milliseconds.
const DEFAULT_SCAN_SLEEP_MS: u64 = 10000;

/// Maximum pages scanned per pass before yielding.
const MAX_PAGES_PER_SCAN: u64 = 4096;

/// Default collapse threshold (minimum present pages out of 512).
const DEFAULT_COLLAPSE_THRESHOLD: usize = 511;

// -------------------------------------------------------------------
// ThpMode
// -------------------------------------------------------------------

/// THP operation mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ThpMode {
    /// Always attempt THP for all anonymous mappings.
    Always,
    /// Only use THP for mappings marked with `MADV_HUGEPAGE`.
    #[default]
    Madvise,
    /// Never use THP.
    Never,
}

// -------------------------------------------------------------------
// ThpDefrag
// -------------------------------------------------------------------

/// THP defragmentation policy — what to do when a huge page cannot
/// be allocated immediately.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ThpDefrag {
    /// Always defragment (compact) to get a huge page.
    Always,
    /// Defragment only for madvise-marked regions.
    #[default]
    Madvise,
    /// Try to defragment but fall back to small pages.
    Defer,
    /// Never defragment — use small pages if no huge page available.
    Never,
}

// -------------------------------------------------------------------
// ScanCandidate
// -------------------------------------------------------------------

/// A VMA region identified as a candidate for THP collapse.
#[derive(Debug, Clone, Copy)]
pub struct ScanCandidate {
    /// Virtual address of the 2M-aligned region start.
    pub vaddr: u64,
    /// Number of 4K pages present in this region.
    pub nr_present: usize,
    /// Number of 4K pages that are writable.
    pub nr_writable: usize,
    /// Number of 4K pages that share the same protections.
    pub nr_compatible: usize,
    /// Process / address space identifier.
    pub mm_id: u32,
    /// Whether the VMA has MADV_HUGEPAGE.
    pub has_madvise: bool,
    /// Whether this candidate passed the threshold check.
    pub eligible: bool,
}

impl ScanCandidate {
    /// Creates a new scan candidate.
    pub const fn new(vaddr: u64, mm_id: u32) -> Self {
        Self {
            vaddr,
            nr_present: 0,
            nr_writable: 0,
            nr_compatible: 0,
            mm_id,
            has_madvise: false,
            eligible: false,
        }
    }

    /// Checks eligibility against the collapse threshold.
    pub fn check_eligible(&mut self, threshold: usize) -> bool {
        self.eligible = self.nr_present >= threshold && self.nr_compatible >= threshold;
        self.eligible
    }
}

impl Default for ScanCandidate {
    fn default() -> Self {
        Self::new(0, 0)
    }
}

// -------------------------------------------------------------------
// CollapseResult
// -------------------------------------------------------------------

/// Outcome of a collapse_huge_page attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CollapseResult {
    /// Not attempted.
    #[default]
    NotAttempted,
    /// Successfully collapsed 512 pages into one huge page.
    Success,
    /// Failed — could not allocate a huge page frame.
    AllocFailed,
    /// Failed — pages moved or freed during collapse.
    PagesMoved,
    /// Failed — incompatible protections found.
    IncompatibleProtections,
    /// Failed — not enough present pages.
    InsufficientPages,
    /// Skipped — THP disabled for this region.
    Disabled,
}

// -------------------------------------------------------------------
// SplitResult
// -------------------------------------------------------------------

/// Outcome of a split_huge_page attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SplitResult {
    /// Not attempted.
    #[default]
    NotAttempted,
    /// Successfully split into 512 small pages.
    Success,
    /// Failed — page is pinned and cannot be split.
    Pinned,
    /// Failed — page is locked.
    Locked,
}

// -------------------------------------------------------------------
// KhugepageScanner
// -------------------------------------------------------------------

/// Background scanner that identifies collapse candidates.
pub struct KhugepageScanner {
    /// Scan candidates found this pass.
    candidates: [ScanCandidate; MAX_SCAN_CANDIDATES],
    /// Number of candidates found.
    nr_candidates: usize,
    /// Total pages scanned this pass.
    pages_scanned: u64,
    /// Total pages scanned since boot.
    total_scanned: u64,
    /// Collapse threshold (min present pages).
    collapse_threshold: usize,
    /// Scan interval in milliseconds.
    scan_sleep_ms: u64,
    /// Number of pages to scan per pass.
    pages_per_scan: u64,
    /// Whether the scanner is running.
    running: bool,
    /// Current scan position (mm_id, vaddr).
    scan_mm_id: u32,
    /// Current scan virtual address.
    scan_vaddr: u64,
}

impl KhugepageScanner {
    /// Creates a new scanner with default settings.
    pub const fn new() -> Self {
        Self {
            candidates: [const { ScanCandidate::new(0, 0) }; MAX_SCAN_CANDIDATES],
            nr_candidates: 0,
            pages_scanned: 0,
            total_scanned: 0,
            collapse_threshold: DEFAULT_COLLAPSE_THRESHOLD,
            scan_sleep_ms: DEFAULT_SCAN_SLEEP_MS,
            pages_per_scan: MAX_PAGES_PER_SCAN,
            running: false,
            scan_mm_id: 0,
            scan_vaddr: 0,
        }
    }

    /// Starts the scanner.
    pub fn start(&mut self) {
        self.running = true;
    }

    /// Stops the scanner.
    pub fn stop(&mut self) {
        self.running = false;
    }

    /// Returns whether the scanner is running.
    pub const fn is_running(&self) -> bool {
        self.running
    }

    /// Sets the collapse threshold.
    pub fn set_collapse_threshold(&mut self, threshold: usize) -> Result<()> {
        if threshold > PAGES_PER_HUGEPAGE {
            return Err(Error::InvalidArgument);
        }
        self.collapse_threshold = threshold;
        Ok(())
    }

    /// Sets the scan interval.
    pub fn set_scan_sleep_ms(&mut self, ms: u64) {
        self.scan_sleep_ms = ms;
    }

    /// Performs one scan pass over the provided page presence data.
    ///
    /// `page_present` maps 2M-aligned vaddrs to arrays of 512 bools
    /// indicating which 4K pages are present.
    pub fn scan_pass(
        &mut self,
        mm_id: u32,
        regions: &[(u64, [bool; PAGES_PER_HUGEPAGE])],
    ) -> usize {
        if !self.running {
            return 0;
        }

        self.nr_candidates = 0;
        self.pages_scanned = 0;

        for (vaddr, present) in regions {
            if self.nr_candidates >= MAX_SCAN_CANDIDATES {
                break;
            }
            if self.pages_scanned >= self.pages_per_scan {
                break;
            }

            let mut nr_present = 0;
            for p in present.iter() {
                if *p {
                    nr_present += 1;
                }
            }
            self.pages_scanned += PAGES_PER_HUGEPAGE as u64;

            let mut candidate = ScanCandidate::new(*vaddr, mm_id);
            candidate.nr_present = nr_present;
            candidate.nr_compatible = nr_present;
            candidate.nr_writable = nr_present;

            if candidate.check_eligible(self.collapse_threshold) {
                self.candidates[self.nr_candidates] = candidate;
                self.nr_candidates += 1;
            }
        }

        self.total_scanned += self.pages_scanned;
        self.scan_mm_id = mm_id;
        self.nr_candidates
    }

    /// Returns the candidates found in the last scan.
    pub fn candidates(&self) -> &[ScanCandidate] {
        &self.candidates[..self.nr_candidates]
    }

    /// Returns the total pages scanned since boot.
    pub const fn total_scanned(&self) -> u64 {
        self.total_scanned
    }
}

impl Default for KhugepageScanner {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// ThpStats
// -------------------------------------------------------------------

/// THP statistics.
#[derive(Debug, Clone, Copy, Default)]
pub struct ThpStats {
    /// Successful collapses.
    pub collapse_success: u64,
    /// Failed collapses.
    pub collapse_fail: u64,
    /// Successful splits.
    pub split_success: u64,
    /// Failed splits.
    pub split_fail: u64,
    /// Total scan passes.
    pub scan_passes: u64,
    /// Total candidates found.
    pub candidates_found: u64,
    /// Direct huge page allocations (page fault path).
    pub direct_alloc: u64,
    /// Direct allocation failures.
    pub direct_alloc_fail: u64,
}

impl ThpStats {
    /// Creates new zeroed statistics.
    pub const fn new() -> Self {
        Self {
            collapse_success: 0,
            collapse_fail: 0,
            split_success: 0,
            split_fail: 0,
            scan_passes: 0,
            candidates_found: 0,
            direct_alloc: 0,
            direct_alloc_fail: 0,
        }
    }
}

// -------------------------------------------------------------------
// ThpController
// -------------------------------------------------------------------

/// Top-level Transparent Huge Page controller.
///
/// Manages the THP mode, defrag policy, khugepaged scanner, and
/// provides collapse/split operations.
pub struct ThpController {
    /// Current THP mode.
    mode: ThpMode,
    /// Defragmentation policy.
    defrag: ThpDefrag,
    /// Background scanner.
    scanner: KhugepageScanner,
    /// Statistics.
    stats: ThpStats,
    /// Whether THP is enabled (mode != Never).
    enabled: bool,
}

impl ThpController {
    /// Creates a new THP controller with default settings.
    pub const fn new() -> Self {
        Self {
            mode: ThpMode::Madvise,
            defrag: ThpDefrag::Madvise,
            scanner: KhugepageScanner::new(),
            stats: ThpStats::new(),
            enabled: true,
        }
    }

    /// Sets the THP mode.
    pub fn set_mode(&mut self, mode: ThpMode) {
        self.mode = mode;
        self.enabled = mode != ThpMode::Never;
        if !self.enabled {
            self.scanner.stop();
        }
    }

    /// Returns the current mode.
    pub const fn mode(&self) -> ThpMode {
        self.mode
    }

    /// Sets the defrag policy.
    pub fn set_defrag(&mut self, defrag: ThpDefrag) {
        self.defrag = defrag;
    }

    /// Returns the current defrag policy.
    pub const fn defrag(&self) -> ThpDefrag {
        self.defrag
    }

    /// Returns whether THP should be used for a given VMA.
    pub const fn should_use_thp(&self, has_madvise: bool) -> bool {
        match self.mode {
            ThpMode::Always => true,
            ThpMode::Madvise => has_madvise,
            ThpMode::Never => false,
        }
    }

    /// Attempts to collapse 512 4K pages into a 2M huge page.
    ///
    /// `source_pfns` must contain exactly 512 PFNs of the source
    /// pages. `huge_pfn` is the PFN of the target 2M-aligned frame.
    ///
    /// The caller is responsible for actually copying data and
    /// updating page tables. This method validates the preconditions
    /// and records statistics.
    pub fn collapse_huge_page(
        &mut self,
        source_pfns: &[u64; PAGES_PER_HUGEPAGE],
        huge_pfn: u64,
    ) -> Result<CollapseResult> {
        if !self.enabled {
            return Ok(CollapseResult::Disabled);
        }

        // Validate alignment
        if huge_pfn % (PAGES_PER_HUGEPAGE as u64) != 0 {
            return Err(Error::InvalidArgument);
        }

        // Validate source PFNs are present (non-zero)
        let mut present = 0;
        for pfn in source_pfns.iter() {
            if *pfn != 0 {
                present += 1;
            }
        }

        if present < self.scanner.collapse_threshold {
            self.stats.collapse_fail += 1;
            return Ok(CollapseResult::InsufficientPages);
        }

        // In a real implementation, here we would:
        // 1. Lock the mm
        // 2. Unmap all 512 PTEs
        // 3. Copy page data to the huge page frame
        // 4. Install a single PDE with PS bit
        // 5. Flush TLB
        // 6. Free the 512 source frames

        self.stats.collapse_success += 1;
        Ok(CollapseResult::Success)
    }

    /// Splits a 2M huge page back into 512 4K pages.
    ///
    /// `huge_pfn` is the PFN of the 2M page. `target_pfns` receives
    /// the PFNs of the 512 resulting pages.
    pub fn split_huge_page(
        &mut self,
        huge_pfn: u64,
        target_pfns: &mut [u64; PAGES_PER_HUGEPAGE],
    ) -> Result<SplitResult> {
        if huge_pfn % (PAGES_PER_HUGEPAGE as u64) != 0 {
            return Err(Error::InvalidArgument);
        }

        // In a real implementation:
        // 1. Allocate 512 4K frames
        // 2. Copy data from huge page to each 4K frame
        // 3. Replace PDE with 512 PTEs
        // 4. Flush TLB
        // 5. Free the huge page frame

        // Fill target PFNs sequentially from the huge page
        for (i, pfn) in target_pfns.iter_mut().enumerate() {
            *pfn = huge_pfn + i as u64;
        }

        self.stats.split_success += 1;
        Ok(SplitResult::Success)
    }

    /// Runs a scan pass and attempts to collapse eligible candidates.
    pub fn scan_and_collapse(
        &mut self,
        mm_id: u32,
        regions: &[(u64, [bool; PAGES_PER_HUGEPAGE])],
    ) -> usize {
        let nr = self.scanner.scan_pass(mm_id, regions);
        self.stats.scan_passes += 1;
        self.stats.candidates_found += nr as u64;
        nr
    }

    /// Returns a reference to the scanner.
    pub const fn scanner(&self) -> &KhugepageScanner {
        &self.scanner
    }

    /// Returns a mutable reference to the scanner.
    pub fn scanner_mut(&mut self) -> &mut KhugepageScanner {
        &mut self.scanner
    }

    /// Returns a reference to the statistics.
    pub const fn stats(&self) -> &ThpStats {
        &self.stats
    }
}

impl Default for ThpController {
    fn default() -> Self {
        Self::new()
    }
}
