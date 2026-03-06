// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Memory cgroup writeback throttling.
//!
//! When a memory cgroup generates dirty pages faster than they can be
//! written back, the kernel must throttle the dirtying process to
//! prevent unbounded growth. This module implements per-cgroup dirty
//! page limits, writeback bandwidth estimation, and throttle logic.
//!
//! # Design
//!
//! ```text
//!  write() → mark page dirty → CgroupWriteback::account_dirty(cg)
//!       │
//!       ├─ dirty < threshold    → no throttle
//!       ├─ dirty >= threshold   → balance_dirty_pages(cg) → sleep
//!       └─ dirty >= hard_limit  → block until writeback completes
//!
//!  writeback thread → CgroupWriteback::complete_writeback(cg, pages)
//! ```
//!
//! # Key Types
//!
//! - [`CgroupDirtyLimit`] — per-cgroup dirty page limits
//! - [`CgroupWbBandwidth`] — estimated writeback bandwidth
//! - [`CgroupWriteback`] — the main writeback tracker
//! - [`WbThrottleStats`] — throttle statistics
//!
//! Reference: Linux `mm/page-writeback.c`, `mm/memcontrol.c`.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Maximum tracked cgroups.
const MAX_CGROUPS: usize = 128;

/// Default dirty ratio (percent of cgroup memory limit).
const DEFAULT_DIRTY_RATIO: u64 = 20;

/// Default background dirty ratio.
const DEFAULT_BG_RATIO: u64 = 10;

/// Minimum writeback bandwidth estimate (pages/second).
const MIN_WB_BANDWIDTH: u64 = 16;

/// Bandwidth estimation window (ticks).
const BW_WINDOW: u64 = 100;

// -------------------------------------------------------------------
// CgroupDirtyLimit
// -------------------------------------------------------------------

/// Per-cgroup dirty page limits.
#[derive(Debug, Clone, Copy)]
pub struct CgroupDirtyLimit {
    /// Cgroup identifier.
    cg_id: u64,
    /// Memory limit for this cgroup (pages).
    mem_limit: u64,
    /// Dirty ratio (percent of mem_limit).
    dirty_ratio: u64,
    /// Background dirty ratio.
    bg_ratio: u64,
    /// Current dirty page count.
    dirty_pages: u64,
    /// Current writeback page count.
    writeback_pages: u64,
}

impl CgroupDirtyLimit {
    /// Create limits for a cgroup.
    pub const fn new(cg_id: u64, mem_limit: u64) -> Self {
        Self {
            cg_id,
            mem_limit,
            dirty_ratio: DEFAULT_DIRTY_RATIO,
            bg_ratio: DEFAULT_BG_RATIO,
            dirty_pages: 0,
            writeback_pages: 0,
        }
    }

    /// Return the cgroup identifier.
    pub const fn cg_id(&self) -> u64 {
        self.cg_id
    }

    /// Return the memory limit.
    pub const fn mem_limit(&self) -> u64 {
        self.mem_limit
    }

    /// Return the dirty threshold (pages).
    pub const fn dirty_thresh(&self) -> u64 {
        self.mem_limit * self.dirty_ratio / 100
    }

    /// Return the background dirty threshold (pages).
    pub const fn bg_thresh(&self) -> u64 {
        self.mem_limit * self.bg_ratio / 100
    }

    /// Return the current dirty page count.
    pub const fn dirty_pages(&self) -> u64 {
        self.dirty_pages
    }

    /// Return the current writeback page count.
    pub const fn writeback_pages(&self) -> u64 {
        self.writeback_pages
    }

    /// Check whether throttling is needed.
    pub const fn needs_throttle(&self) -> bool {
        self.dirty_pages >= self.dirty_thresh()
    }

    /// Check whether background writeback should start.
    pub const fn needs_bg_writeback(&self) -> bool {
        self.dirty_pages >= self.bg_thresh()
    }

    /// Account a newly dirtied page.
    pub fn account_dirty(&mut self) {
        self.dirty_pages += 1;
    }

    /// Account a page entering writeback.
    pub fn account_writeback(&mut self) {
        self.writeback_pages += 1;
        self.dirty_pages = self.dirty_pages.saturating_sub(1);
    }

    /// Account a completed writeback page.
    pub fn complete_writeback(&mut self) {
        self.writeback_pages = self.writeback_pages.saturating_sub(1);
    }

    /// Set the dirty ratio.
    pub fn set_dirty_ratio(&mut self, ratio: u64) -> Result<()> {
        if ratio > 100 {
            return Err(Error::InvalidArgument);
        }
        self.dirty_ratio = ratio;
        Ok(())
    }
}

impl Default for CgroupDirtyLimit {
    fn default() -> Self {
        Self {
            cg_id: 0,
            mem_limit: 0,
            dirty_ratio: DEFAULT_DIRTY_RATIO,
            bg_ratio: DEFAULT_BG_RATIO,
            dirty_pages: 0,
            writeback_pages: 0,
        }
    }
}

// -------------------------------------------------------------------
// CgroupWbBandwidth
// -------------------------------------------------------------------

/// Estimated writeback bandwidth for a cgroup.
#[derive(Debug, Clone, Copy)]
pub struct CgroupWbBandwidth {
    /// Cgroup identifier.
    cg_id: u64,
    /// Estimated bandwidth in pages per tick window.
    bandwidth: u64,
    /// Pages written in current window.
    window_written: u64,
    /// Elapsed ticks in current window.
    window_elapsed: u64,
}

impl CgroupWbBandwidth {
    /// Create a new bandwidth tracker.
    pub const fn new(cg_id: u64) -> Self {
        Self {
            cg_id,
            bandwidth: MIN_WB_BANDWIDTH,
            window_written: 0,
            window_elapsed: 0,
        }
    }

    /// Return the cgroup identifier.
    pub const fn cg_id(&self) -> u64 {
        self.cg_id
    }

    /// Return the estimated bandwidth.
    pub const fn bandwidth(&self) -> u64 {
        self.bandwidth
    }

    /// Record written pages.
    pub fn record_written(&mut self, pages: u64) {
        self.window_written += pages;
    }

    /// Advance the tick counter and possibly update the estimate.
    pub fn tick(&mut self, elapsed: u64) {
        self.window_elapsed += elapsed;
        if self.window_elapsed >= BW_WINDOW {
            let measured = self.window_written * BW_WINDOW / self.window_elapsed;
            // Exponential moving average.
            self.bandwidth = (self.bandwidth * 3 + measured) / 4;
            if self.bandwidth < MIN_WB_BANDWIDTH {
                self.bandwidth = MIN_WB_BANDWIDTH;
            }
            self.window_written = 0;
            self.window_elapsed = 0;
        }
    }

    /// Estimate the pause time in ticks to balance dirty pages.
    pub const fn pause_ticks(&self, excess_pages: u64) -> u64 {
        if self.bandwidth == 0 {
            return BW_WINDOW;
        }
        excess_pages * BW_WINDOW / self.bandwidth
    }
}

impl Default for CgroupWbBandwidth {
    fn default() -> Self {
        Self::new(0)
    }
}

// -------------------------------------------------------------------
// WbThrottleStats
// -------------------------------------------------------------------

/// Throttle statistics.
#[derive(Debug, Clone, Copy)]
pub struct WbThrottleStats {
    /// Total throttle events.
    pub throttle_count: u64,
    /// Total ticks spent throttled.
    pub throttle_ticks: u64,
    /// Total pages written back.
    pub pages_written: u64,
    /// Background writeback triggers.
    pub bg_triggers: u64,
}

impl WbThrottleStats {
    /// Create zero statistics.
    pub const fn new() -> Self {
        Self {
            throttle_count: 0,
            throttle_ticks: 0,
            pages_written: 0,
            bg_triggers: 0,
        }
    }
}

impl Default for WbThrottleStats {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// CgroupWriteback
// -------------------------------------------------------------------

/// The main per-cgroup writeback tracker.
pub struct CgroupWriteback {
    /// Per-cgroup dirty limits.
    limits: [CgroupDirtyLimit; MAX_CGROUPS],
    /// Per-cgroup bandwidth estimators.
    bandwidths: [CgroupWbBandwidth; MAX_CGROUPS],
    /// Number of tracked cgroups.
    count: usize,
    /// Statistics.
    stats: WbThrottleStats,
}

impl CgroupWriteback {
    /// Create a new writeback tracker.
    pub const fn new() -> Self {
        Self {
            limits: [const {
                CgroupDirtyLimit {
                    cg_id: 0,
                    mem_limit: 0,
                    dirty_ratio: DEFAULT_DIRTY_RATIO,
                    bg_ratio: DEFAULT_BG_RATIO,
                    dirty_pages: 0,
                    writeback_pages: 0,
                }
            }; MAX_CGROUPS],
            bandwidths: [const {
                CgroupWbBandwidth {
                    cg_id: 0,
                    bandwidth: MIN_WB_BANDWIDTH,
                    window_written: 0,
                    window_elapsed: 0,
                }
            }; MAX_CGROUPS],
            count: 0,
            stats: WbThrottleStats::new(),
        }
    }

    /// Return the statistics.
    pub const fn stats(&self) -> &WbThrottleStats {
        &self.stats
    }

    /// Register a cgroup.
    pub fn register(&mut self, cg_id: u64, mem_limit: u64) -> Result<()> {
        if self.count >= MAX_CGROUPS {
            return Err(Error::OutOfMemory);
        }
        self.limits[self.count] = CgroupDirtyLimit::new(cg_id, mem_limit);
        self.bandwidths[self.count] = CgroupWbBandwidth::new(cg_id);
        self.count += 1;
        Ok(())
    }

    /// Account a dirty page for a cgroup.
    pub fn account_dirty(&mut self, cg_id: u64) -> Result<bool> {
        for idx in 0..self.count {
            if self.limits[idx].cg_id() == cg_id {
                self.limits[idx].account_dirty();
                let throttle = self.limits[idx].needs_throttle();
                if throttle {
                    self.stats.throttle_count += 1;
                }
                if self.limits[idx].needs_bg_writeback() {
                    self.stats.bg_triggers += 1;
                }
                return Ok(throttle);
            }
        }
        Err(Error::NotFound)
    }

    /// Account completed writeback pages.
    pub fn complete_writeback(&mut self, cg_id: u64, pages: u64) -> Result<()> {
        for idx in 0..self.count {
            if self.limits[idx].cg_id() == cg_id {
                for _ in 0..pages {
                    self.limits[idx].complete_writeback();
                }
                self.bandwidths[idx].record_written(pages);
                self.stats.pages_written += pages;
                return Ok(());
            }
        }
        Err(Error::NotFound)
    }

    /// Return the number of tracked cgroups.
    pub const fn count(&self) -> usize {
        self.count
    }
}

impl Default for CgroupWriteback {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// Public helpers
// -------------------------------------------------------------------

/// Check whether a cgroup needs dirty page throttling.
pub fn should_throttle(wb: &CgroupWriteback, cg_id: u64) -> bool {
    for idx in 0..wb.count() {
        if wb.limits[idx].cg_id() == cg_id {
            return wb.limits[idx].needs_throttle();
        }
    }
    false
}

/// Return the dirty page count for a cgroup.
pub fn dirty_pages(wb: &CgroupWriteback, cg_id: u64) -> u64 {
    for idx in 0..wb.count() {
        if wb.limits[idx].cg_id() == cg_id {
            return wb.limits[idx].dirty_pages();
        }
    }
    0
}

/// Return the estimated writeback bandwidth for a cgroup.
pub fn wb_bandwidth(wb: &CgroupWriteback, cg_id: u64) -> u64 {
    for idx in 0..wb.count() {
        if wb.bandwidths[idx].cg_id() == cg_id {
            return wb.bandwidths[idx].bandwidth();
        }
    }
    0
}
