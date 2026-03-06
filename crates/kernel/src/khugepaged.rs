// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Kernel huge-page daemon (khugepaged).
//!
//! Background kernel thread that scans process address spaces for
//! opportunities to collapse contiguous small pages into huge pages
//! (typically 2 MiB on x86_64). This reduces TLB pressure and
//! improves memory access performance for large working sets.
//!
//! # Algorithm
//!
//! 1. Walk each process VMA list looking for anonymous mappings.
//! 2. For each 2 MiB-aligned range check if all 512 base pages
//!    are present, not shared, and not pinned.
//! 3. Allocate a compound huge page, copy data, update page tables.
//! 4. Free the 512 base pages.
//!
//! # Architecture
//!
//! ```text
//! KhugepagedState
//!  ├── config: KhugepagedConfig
//!  ├── scan_cursor: ScanCursor
//!  ├── stats: KhugepagedStats
//!  └── collapse_queue: [CollapseRequest; MAX_REQUESTS]
//! ```

use oncrix_lib::{Error, Result};

// ======================================================================
// Constants
// ======================================================================

/// Maximum processes to scan per wake-up cycle.
const MAX_SCAN_PER_CYCLE: usize = 64;

/// Maximum pending collapse requests.
const MAX_COLLAPSE_REQUESTS: usize = 128;

/// Default scan interval in milliseconds.
const DEFAULT_SCAN_INTERVAL_MS: u64 = 10_000;

/// Number of base pages in one huge page (2 MiB / 4 KiB).
const PAGES_PER_HUGEPAGE: usize = 512;

/// Default maximum processes to scan per cycle.
const DEFAULT_PAGES_TO_SCAN: u32 = 4096;

// ======================================================================
// Types
// ======================================================================

/// Result of a collapse attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CollapseResult {
    /// Successfully collapsed into a huge page.
    Success,
    /// Some base pages were missing (not present).
    PagesMissing,
    /// Alignment requirements not met.
    Misaligned,
    /// Pages are shared (refcount > 1).
    SharedPages,
    /// Could not allocate a huge page.
    AllocationFailed,
    /// Region is pinned and cannot be collapsed.
    Pinned,
}

impl Default for CollapseResult {
    fn default() -> Self {
        Self::Success
    }
}

/// Configuration for the khugepaged daemon.
#[derive(Debug, Clone, Copy)]
pub struct KhugepagedConfig {
    /// Whether khugepaged is enabled.
    pub enabled: bool,
    /// Interval between scan cycles (ms).
    pub scan_interval_ms: u64,
    /// Maximum pages to scan per cycle.
    pub pages_to_scan: u32,
    /// Whether to defragment on allocation failure.
    pub defrag: bool,
    /// Maximum process memory (in pages) to consider for collapse.
    pub max_process_pages: u64,
}

impl KhugepagedConfig {
    /// Creates a default configuration.
    pub const fn new() -> Self {
        Self {
            enabled: true,
            scan_interval_ms: DEFAULT_SCAN_INTERVAL_MS,
            pages_to_scan: DEFAULT_PAGES_TO_SCAN,
            defrag: true,
            max_process_pages: 0,
        }
    }
}

impl Default for KhugepagedConfig {
    fn default() -> Self {
        Self::new()
    }
}

/// Scan cursor tracking progress across processes.
#[derive(Debug, Clone, Copy)]
pub struct ScanCursor {
    /// PID of the process currently being scanned.
    pub current_pid: u64,
    /// Virtual address within the current process.
    pub current_addr: u64,
    /// Total pages scanned in the current cycle.
    pub pages_scanned: u32,
    /// Whether the full scan has wrapped around.
    pub wrapped: bool,
}

impl ScanCursor {
    /// Creates a new cursor starting from PID 1, address 0.
    pub const fn new() -> Self {
        Self {
            current_pid: 1,
            current_addr: 0,
            pages_scanned: 0,
            wrapped: false,
        }
    }

    /// Resets the cursor for a new scan cycle.
    pub fn reset_cycle(&mut self) {
        self.pages_scanned = 0;
        self.wrapped = false;
    }
}

impl Default for ScanCursor {
    fn default() -> Self {
        Self::new()
    }
}

/// A pending collapse request.
#[derive(Debug, Clone, Copy)]
pub struct CollapseRequest {
    /// PID of the target process.
    pub pid: u64,
    /// Virtual address of the 2 MiB region to collapse.
    pub vaddr: u64,
    /// Number of base pages confirmed present.
    pub present_count: u16,
    /// Whether the request is active.
    pub active: bool,
    /// Result of the collapse attempt.
    pub result: CollapseResult,
}

impl CollapseRequest {
    /// Creates an empty collapse request.
    pub const fn new() -> Self {
        Self {
            pid: 0,
            vaddr: 0,
            present_count: 0,
            active: false,
            result: CollapseResult::Success,
        }
    }
}

impl Default for CollapseRequest {
    fn default() -> Self {
        Self::new()
    }
}

/// Runtime statistics for khugepaged.
#[derive(Debug, Clone, Copy)]
pub struct KhugepagedStats {
    /// Total scan cycles executed.
    pub scan_cycles: u64,
    /// Total collapse attempts.
    pub collapse_attempts: u64,
    /// Successful collapses.
    pub collapse_success: u64,
    /// Failed collapses.
    pub collapse_failed: u64,
    /// Total pages scanned.
    pub pages_scanned: u64,
    /// Total huge pages created.
    pub hugepages_created: u64,
}

impl KhugepagedStats {
    /// Creates zeroed stats.
    pub const fn new() -> Self {
        Self {
            scan_cycles: 0,
            collapse_attempts: 0,
            collapse_success: 0,
            collapse_failed: 0,
            pages_scanned: 0,
            hugepages_created: 0,
        }
    }
}

impl Default for KhugepagedStats {
    fn default() -> Self {
        Self::new()
    }
}

/// The khugepaged daemon state.
pub struct KhugepagedState {
    /// Configuration.
    config: KhugepagedConfig,
    /// Scan cursor.
    cursor: ScanCursor,
    /// Runtime statistics.
    stats: KhugepagedStats,
    /// Pending collapse requests.
    requests: [CollapseRequest; MAX_COLLAPSE_REQUESTS],
    /// Number of active requests.
    nr_requests: usize,
}

impl KhugepagedState {
    /// Creates a new khugepaged state.
    pub const fn new() -> Self {
        Self {
            config: KhugepagedConfig::new(),
            cursor: ScanCursor::new(),
            stats: KhugepagedStats::new(),
            requests: [CollapseRequest::new(); MAX_COLLAPSE_REQUESTS],
            nr_requests: 0,
        }
    }

    /// Enables or disables khugepaged.
    pub fn set_enabled(&mut self, enabled: bool) {
        self.config.enabled = enabled;
    }

    /// Updates the scan interval.
    pub fn set_scan_interval(&mut self, ms: u64) -> Result<()> {
        if ms == 0 {
            return Err(Error::InvalidArgument);
        }
        self.config.scan_interval_ms = ms;
        Ok(())
    }

    /// Submits a collapse request for a 2 MiB-aligned region.
    pub fn submit_collapse(&mut self, pid: u64, vaddr: u64, present_count: u16) -> Result<usize> {
        if vaddr & ((PAGES_PER_HUGEPAGE * 4096 - 1) as u64) != 0 {
            return Err(Error::InvalidArgument);
        }
        if self.nr_requests >= MAX_COLLAPSE_REQUESTS {
            return Err(Error::OutOfMemory);
        }
        for (i, req) in self.requests.iter_mut().enumerate() {
            if !req.active {
                *req = CollapseRequest {
                    pid,
                    vaddr,
                    present_count,
                    active: true,
                    result: CollapseResult::Success,
                };
                self.nr_requests += 1;
                return Ok(i);
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Completes a collapse request with the given result.
    pub fn complete_collapse(&mut self, index: usize, result: CollapseResult) -> Result<()> {
        if index >= MAX_COLLAPSE_REQUESTS {
            return Err(Error::InvalidArgument);
        }
        if !self.requests[index].active {
            return Err(Error::NotFound);
        }
        self.requests[index].result = result;
        self.requests[index].active = false;
        self.nr_requests = self.nr_requests.saturating_sub(1);

        self.stats.collapse_attempts += 1;
        if result == CollapseResult::Success {
            self.stats.collapse_success += 1;
            self.stats.hugepages_created += 1;
        } else {
            self.stats.collapse_failed += 1;
        }
        Ok(())
    }

    /// Advances the scan cursor by `pages` and updates statistics.
    pub fn advance_scan(&mut self, pages: u32) {
        self.cursor.pages_scanned += pages;
        self.stats.pages_scanned += pages as u64;

        if self.cursor.pages_scanned >= self.config.pages_to_scan {
            self.stats.scan_cycles += 1;
            self.cursor.reset_cycle();
        }
    }

    /// Returns a reference to the current statistics.
    pub fn stats(&self) -> &KhugepagedStats {
        &self.stats
    }

    /// Returns a reference to the configuration.
    pub fn config(&self) -> &KhugepagedConfig {
        &self.config
    }

    /// Returns the number of pending requests.
    pub fn nr_pending_requests(&self) -> usize {
        self.nr_requests
    }
}

impl Default for KhugepagedState {
    fn default() -> Self {
        Self::new()
    }
}
