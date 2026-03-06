// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Page writeback throttle control.
//!
//! Implements dirty page writeback throttling to prevent the system
//! from being overwhelmed by dirty pages. Controls when and how fast
//! dirty pages are written back to disk.
//!
//! # Key Types
//!
//! - [`WbSyncMode`] — writeback synchronisation mode
//! - [`WritebackControl`] — per-writeback-request control block
//! - [`DirtyThrottleControl`] — throttle state for a BDI
//! - [`DirtyLimits`] — global dirty page limits
//! - [`BandwidthEstimator`] — smoothed write bandwidth tracker
//! - [`WritebackThrottler`] — central throttle controller
//! - [`WritebackStats`] — throttling statistics
//!
//! Reference: Linux `mm/page-writeback.c`, `include/linux/writeback.h`,
//! `mm/backing-dev.c`.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Standard page size (4 KiB).
const PAGE_SIZE: u64 = 4096;

/// Default dirty_ratio: fraction of memory that can be dirty (percent).
const DEFAULT_DIRTY_RATIO: u32 = 20;

/// Default dirty_background_ratio (percent).
const DEFAULT_DIRTY_BACKGROUND_RATIO: u32 = 10;

/// Maximum number of BDI (backing device info) entries.
const MAX_BDIS: usize = 32;

/// Bandwidth estimation smoothing window (number of samples).
const BW_SMOOTHING_WINDOW: usize = 16;

/// Minimum write bandwidth estimate (pages/sec).
const MIN_BW_ESTIMATE: u64 = 1;

/// Maximum number of writeback control blocks tracked.
const MAX_WBC: usize = 64;

/// Freerun threshold: below this fraction, no throttling.
const FREERUN_FRACTION_NUM: u64 = 1;

/// Freerun threshold denominator.
const FREERUN_FRACTION_DEN: u64 = 8;

// -------------------------------------------------------------------
// WbSyncMode
// -------------------------------------------------------------------

/// Writeback synchronisation mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum WbSyncMode {
    /// No synchronisation — best effort writeback.
    #[default]
    None,
    /// Synchronous writeback (e.g. fsync).
    WbSync,
    /// Asynchronous writeback (background flusher).
    WbAsync,
}

// -------------------------------------------------------------------
// WritebackFlags
// -------------------------------------------------------------------

/// Flags for writeback control blocks.
pub struct WritebackFlags;

impl WritebackFlags {
    /// Writeback is for periodic kupdate flusher.
    pub const FOR_KUPDATE: u32 = 1 << 0;
    /// Writeback is for background dirty threshold.
    pub const FOR_BACKGROUND: u32 = 1 << 1;
    /// Writeback is triggered by memory reclaim.
    pub const FOR_RECLAIM: u32 = 1 << 2;
    /// Use tagged writepages (only write pages dirtied before start).
    pub const TAGGED_WRITEPAGES: u32 = 1 << 3;
    /// Range writeback (specific byte range).
    pub const RANGE_WRITEBACK: u32 = 1 << 4;
    /// No write congestion wait.
    pub const NO_CONG_WAIT: u32 = 1 << 5;
}

// -------------------------------------------------------------------
// WritebackControl
// -------------------------------------------------------------------

/// Per-writeback-request control block.
///
/// Passed to the filesystem's `writepages` callback to specify
/// how many pages to write and under what conditions.
#[derive(Debug, Clone, Copy)]
pub struct WritebackControl {
    /// Number of pages remaining to write.
    pub nr_to_write: i64,
    /// Number of pages skipped (e.g. locked or under writeback).
    pub pages_skipped: u64,
    /// Synchronisation mode.
    pub sync_mode: WbSyncMode,
    /// Start of the byte range to write back.
    pub range_start: u64,
    /// End of the byte range to write back (inclusive).
    pub range_end: u64,
    /// Writeback flags.
    pub flags: u32,
    /// BDI index this writeback targets.
    pub bdi_index: u32,
    /// Unique WBC ID.
    pub wbc_id: u32,
    /// Whether this control block is active.
    active: bool,
}

impl WritebackControl {
    /// Create an empty/inactive control block.
    const fn empty() -> Self {
        Self {
            nr_to_write: 0,
            pages_skipped: 0,
            sync_mode: WbSyncMode::None,
            range_start: 0,
            range_end: u64::MAX,
            flags: 0,
            bdi_index: 0,
            wbc_id: 0,
            active: false,
        }
    }

    /// Create a new writeback control block.
    pub const fn new(nr_to_write: i64, sync_mode: WbSyncMode, flags: u32) -> Self {
        Self {
            nr_to_write,
            pages_skipped: 0,
            sync_mode,
            range_start: 0,
            range_end: u64::MAX,
            flags,
            bdi_index: 0,
            wbc_id: 0,
            active: true,
        }
    }

    /// Whether this is a kupdate writeback.
    pub const fn for_kupdate(&self) -> bool {
        self.flags & WritebackFlags::FOR_KUPDATE != 0
    }

    /// Whether this is a background writeback.
    pub const fn for_background(&self) -> bool {
        self.flags & WritebackFlags::FOR_BACKGROUND != 0
    }

    /// Whether this is a reclaim-triggered writeback.
    pub const fn for_reclaim(&self) -> bool {
        self.flags & WritebackFlags::FOR_RECLAIM != 0
    }

    /// Whether tagged writepages is enabled.
    pub const fn tagged_writepages(&self) -> bool {
        self.flags & WritebackFlags::TAGGED_WRITEPAGES != 0
    }

    /// Mark pages as written.
    pub fn account_written(&mut self, pages: u64) {
        self.nr_to_write -= pages as i64;
    }

    /// Mark pages as skipped.
    pub fn account_skipped(&mut self, pages: u64) {
        self.pages_skipped += pages;
    }

    /// Whether there are more pages to write.
    pub const fn has_more(&self) -> bool {
        self.nr_to_write > 0
    }
}

// -------------------------------------------------------------------
// DirtyLimits
// -------------------------------------------------------------------

/// Global dirty page limits.
///
/// These correspond to the `vm.dirty_ratio` and
/// `vm.dirty_background_ratio` sysctl knobs.
#[derive(Debug, Clone, Copy)]
pub struct DirtyLimits {
    /// Total system memory in pages.
    pub total_pages: u64,
    /// Dirty ratio (percent, 1..100).
    pub dirty_ratio: u32,
    /// Background dirty ratio (percent, 1..100).
    pub dirty_background_ratio: u32,
    /// Absolute dirty threshold override (0 = use ratio).
    pub dirty_bytes: u64,
    /// Absolute background dirty threshold override (0 = use ratio).
    pub dirty_background_bytes: u64,
}

impl DirtyLimits {
    /// Create limits with default ratios.
    pub const fn new(total_pages: u64) -> Self {
        Self {
            total_pages,
            dirty_ratio: DEFAULT_DIRTY_RATIO,
            dirty_background_ratio: DEFAULT_DIRTY_BACKGROUND_RATIO,
            dirty_bytes: 0,
            dirty_background_bytes: 0,
        }
    }

    /// Compute the dirty threshold in pages.
    pub const fn dirty_threshold(&self) -> u64 {
        if self.dirty_bytes > 0 {
            self.dirty_bytes / PAGE_SIZE
        } else {
            self.total_pages * self.dirty_ratio as u64 / 100
        }
    }

    /// Compute the background dirty threshold in pages.
    pub const fn background_threshold(&self) -> u64 {
        if self.dirty_background_bytes > 0 {
            self.dirty_background_bytes / PAGE_SIZE
        } else {
            self.total_pages * self.dirty_background_ratio as u64 / 100
        }
    }

    /// Compute the freerun threshold (below which no throttling).
    pub const fn freerun_threshold(&self) -> u64 {
        let dt = self.dirty_threshold();
        let bg = self.background_threshold();
        // Freerun = background + (dirty - background) / 8
        bg + (dt - bg) * FREERUN_FRACTION_NUM / FREERUN_FRACTION_DEN
    }
}

// -------------------------------------------------------------------
// BandwidthEstimator
// -------------------------------------------------------------------

/// Smoothed write bandwidth estimator for a BDI.
///
/// Uses a sliding window of recent write rates to produce a
/// smoothed bandwidth estimate.
#[derive(Clone)]
pub struct BandwidthEstimator {
    /// Recent bandwidth samples (pages/sec).
    samples: [u64; BW_SMOOTHING_WINDOW],
    /// Number of valid samples.
    sample_count: usize,
    /// Index for the next sample.
    next_index: usize,
    /// Smoothed average bandwidth.
    avg_write_bandwidth: u64,
}

impl BandwidthEstimator {
    /// Create a new estimator.
    pub const fn new() -> Self {
        Self {
            samples: [0u64; BW_SMOOTHING_WINDOW],
            sample_count: 0,
            next_index: 0,
            avg_write_bandwidth: MIN_BW_ESTIMATE,
        }
    }

    /// Record a bandwidth sample.
    pub fn record_sample(&mut self, bw_pages_per_sec: u64) {
        self.samples[self.next_index] = bw_pages_per_sec;
        self.next_index = (self.next_index + 1) % BW_SMOOTHING_WINDOW;
        if self.sample_count < BW_SMOOTHING_WINDOW {
            self.sample_count += 1;
        }
        self.recompute_avg();
    }

    /// Recompute the smoothed average.
    fn recompute_avg(&mut self) {
        if self.sample_count == 0 {
            self.avg_write_bandwidth = MIN_BW_ESTIMATE;
            return;
        }
        let mut sum: u64 = 0;
        for i in 0..self.sample_count {
            sum = sum.saturating_add(self.samples[i]);
        }
        let avg = sum / self.sample_count as u64;
        self.avg_write_bandwidth = if avg < MIN_BW_ESTIMATE {
            MIN_BW_ESTIMATE
        } else {
            avg
        };
    }

    /// Return the current smoothed bandwidth estimate.
    pub const fn avg_write_bandwidth(&self) -> u64 {
        self.avg_write_bandwidth
    }
}

// -------------------------------------------------------------------
// DirtyThrottleControl
// -------------------------------------------------------------------

/// Per-BDI dirty throttle control state.
///
/// Tracks the position ratio and base bandwidth for throttle
/// calculations in `balance_dirty_pages`.
#[derive(Clone)]
pub struct DirtyThrottleControl {
    /// BDI index.
    pub bdi_index: u32,
    /// Position ratio: how far between background and dirty threshold.
    /// 0 = at freerun, 1.0 (scaled as 1024) = at dirty threshold.
    pub pos_ratio: u64,
    /// Base bandwidth for this BDI (pages/sec).
    pub base_bw: u64,
    /// Current dirty pages on this BDI.
    pub dirty_pages: u64,
    /// Write bandwidth estimator.
    pub bw_estimator: BandwidthEstimator,
    /// Whether this BDI entry is active.
    active: bool,
}

impl DirtyThrottleControl {
    /// Create an empty throttle control.
    const fn empty() -> Self {
        Self {
            bdi_index: 0,
            pos_ratio: 0,
            base_bw: 0,
            dirty_pages: 0,
            bw_estimator: BandwidthEstimator::new(),
            active: false,
        }
    }

    /// Compute the position ratio given global dirty state.
    ///
    /// `pos_ratio` = (dirty - freerun) * 1024 / (threshold - freerun).
    /// Clamped to 0..1024.
    pub fn compute_pos_ratio(&mut self, limits: &DirtyLimits) {
        let thresh = limits.dirty_threshold();
        let freerun = limits.freerun_threshold();

        if self.dirty_pages <= freerun || thresh <= freerun {
            self.pos_ratio = 0;
            return;
        }
        let num = (self.dirty_pages - freerun).min(thresh - freerun);
        let den = thresh - freerun;
        if den == 0 {
            self.pos_ratio = 1024;
        } else {
            self.pos_ratio = num * 1024 / den;
        }
        if self.pos_ratio > 1024 {
            self.pos_ratio = 1024;
        }
    }

    /// Compute the throttle bandwidth (pages/sec allowed).
    ///
    /// Allowed BW = avg_write_bw * (1024 - pos_ratio) / 1024.
    pub fn throttled_bw(&self) -> u64 {
        let avg = self.bw_estimator.avg_write_bandwidth();
        let factor = 1024u64.saturating_sub(self.pos_ratio);
        avg * factor / 1024
    }
}

// -------------------------------------------------------------------
// WritebackStats
// -------------------------------------------------------------------

/// Writeback throttling statistics.
#[derive(Debug, Clone, Copy, Default)]
pub struct WritebackStats {
    /// Total balance_dirty_pages calls.
    pub balance_calls: u64,
    /// Total times a task was throttled.
    pub throttle_count: u64,
    /// Total pages written back.
    pub pages_written: u64,
    /// Total pages skipped.
    pub pages_skipped: u64,
    /// Current global dirty pages.
    pub global_dirty: u64,
    /// Current global writeback pages.
    pub global_writeback: u64,
}

// -------------------------------------------------------------------
// WritebackThrottler
// -------------------------------------------------------------------

/// Central writeback throttle controller.
///
/// Manages global dirty limits, per-BDI throttle controls,
/// writeback control blocks, and bandwidth estimation.
pub struct WritebackThrottler {
    /// Global dirty limits.
    limits: DirtyLimits,
    /// Per-BDI throttle controls.
    bdis: [DirtyThrottleControl; MAX_BDIS],
    /// Writeback control blocks.
    wbcs: [WritebackControl; MAX_WBC],
    /// Next WBC ID.
    next_wbc_id: u32,
    /// Global dirty page count.
    global_dirty: u64,
    /// Global writeback page count.
    global_writeback: u64,
    /// Statistics.
    stats: WritebackStats,
}

impl WritebackThrottler {
    /// Create a new throttler.
    pub const fn new(total_pages: u64) -> Self {
        Self {
            limits: DirtyLimits::new(total_pages),
            bdis: [const { DirtyThrottleControl::empty() }; MAX_BDIS],
            wbcs: [const { WritebackControl::empty() }; MAX_WBC],
            next_wbc_id: 1,
            global_dirty: 0,
            global_writeback: 0,
            stats: WritebackStats {
                balance_calls: 0,
                throttle_count: 0,
                pages_written: 0,
                pages_skipped: 0,
                global_dirty: 0,
                global_writeback: 0,
            },
        }
    }

    /// Register a BDI for throttle tracking.
    ///
    /// # Errors
    /// - `InvalidArgument` — bdi_index out of range.
    /// - `AlreadyExists` — BDI already registered.
    pub fn register_bdi(&mut self, bdi_index: u32) -> Result<()> {
        let idx = bdi_index as usize;
        if idx >= MAX_BDIS {
            return Err(Error::InvalidArgument);
        }
        if self.bdis[idx].active {
            return Err(Error::AlreadyExists);
        }
        self.bdis[idx] = DirtyThrottleControl {
            bdi_index,
            pos_ratio: 0,
            base_bw: 0,
            dirty_pages: 0,
            bw_estimator: BandwidthEstimator::new(),
            active: true,
        };
        Ok(())
    }

    /// Unregister a BDI.
    ///
    /// # Errors
    /// - `InvalidArgument` — bdi_index out of range.
    /// - `NotFound` — BDI not registered.
    pub fn unregister_bdi(&mut self, bdi_index: u32) -> Result<()> {
        let idx = bdi_index as usize;
        if idx >= MAX_BDIS {
            return Err(Error::InvalidArgument);
        }
        if !self.bdis[idx].active {
            return Err(Error::NotFound);
        }
        self.bdis[idx] = DirtyThrottleControl::empty();
        Ok(())
    }

    /// Update the dirty page count for a BDI.
    ///
    /// # Errors
    /// - `InvalidArgument` — bdi_index out of range or not active.
    pub fn set_bdi_dirty(&mut self, bdi_index: u32, dirty_pages: u64) -> Result<()> {
        let idx = bdi_index as usize;
        if idx >= MAX_BDIS || !self.bdis[idx].active {
            return Err(Error::InvalidArgument);
        }
        self.bdis[idx].dirty_pages = dirty_pages;
        Ok(())
    }

    /// Record a bandwidth sample for a BDI.
    ///
    /// # Errors
    /// - `InvalidArgument` — bdi_index out of range or not active.
    pub fn record_bw_sample(&mut self, bdi_index: u32, bw_pages_per_sec: u64) -> Result<()> {
        let idx = bdi_index as usize;
        if idx >= MAX_BDIS || !self.bdis[idx].active {
            return Err(Error::InvalidArgument);
        }
        self.bdis[idx].bw_estimator.record_sample(bw_pages_per_sec);
        self.bdis[idx].base_bw = self.bdis[idx].bw_estimator.avg_write_bandwidth();
        Ok(())
    }

    /// Balance dirty pages: the main throttle entry point.
    ///
    /// Checks if global dirty pages exceed the threshold and
    /// computes per-BDI throttle ratios.
    ///
    /// Returns `true` if the caller should be throttled (sleep).
    pub fn balance_dirty_pages(&mut self) -> bool {
        self.stats.balance_calls += 1;

        // Update global counts.
        self.recompute_global_dirty();

        let freerun = self.limits.freerun_threshold();
        if self.global_dirty <= freerun {
            // Under freerun — no throttling needed.
            return false;
        }

        // Above freerun — compute pos_ratio for each BDI.
        for i in 0..MAX_BDIS {
            if self.bdis[i].active {
                self.bdis[i].compute_pos_ratio(&self.limits);
            }
        }

        self.stats.throttle_count += 1;
        true
    }

    /// Recompute global dirty count from all BDIs.
    fn recompute_global_dirty(&mut self) {
        let mut total = 0u64;
        for i in 0..MAX_BDIS {
            if self.bdis[i].active {
                total += self.bdis[i].dirty_pages;
            }
        }
        self.global_dirty = total;
        self.stats.global_dirty = total;
    }

    /// Set the global writeback count.
    pub fn set_global_writeback(&mut self, pages: u64) {
        self.global_writeback = pages;
        self.stats.global_writeback = pages;
    }

    /// Create a new writeback control block.
    ///
    /// # Errors
    /// - `OutOfMemory` — no free WBC slots.
    pub fn create_wbc(
        &mut self,
        nr_to_write: i64,
        sync_mode: WbSyncMode,
        flags: u32,
        bdi_index: u32,
    ) -> Result<u32> {
        for i in 0..MAX_WBC {
            if !self.wbcs[i].active {
                let wbc_id = self.next_wbc_id;
                self.next_wbc_id += 1;
                self.wbcs[i] = WritebackControl::new(nr_to_write, sync_mode, flags);
                self.wbcs[i].bdi_index = bdi_index;
                self.wbcs[i].wbc_id = wbc_id;
                return Ok(wbc_id);
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Complete a writeback control block.
    ///
    /// # Errors
    /// - `NotFound` — no WBC with this ID.
    pub fn complete_wbc(
        &mut self,
        wbc_id: u32,
        pages_written: u64,
        pages_skipped: u64,
    ) -> Result<()> {
        for i in 0..MAX_WBC {
            if self.wbcs[i].active && self.wbcs[i].wbc_id == wbc_id {
                self.wbcs[i].active = false;
                self.stats.pages_written += pages_written;
                self.stats.pages_skipped += pages_skipped;
                return Ok(());
            }
        }
        Err(Error::NotFound)
    }

    /// Set the global dirty limits.
    pub fn set_limits(&mut self, limits: DirtyLimits) {
        self.limits = limits;
    }

    /// Return the current dirty limits.
    pub const fn limits(&self) -> &DirtyLimits {
        &self.limits
    }

    /// Return the current global dirty page count.
    pub const fn global_dirty(&self) -> u64 {
        self.global_dirty
    }

    /// Query the throttle bandwidth for a BDI.
    ///
    /// # Errors
    /// - `InvalidArgument` — bdi_index out of range or not active.
    pub fn throttled_bw(&self, bdi_index: u32) -> Result<u64> {
        let idx = bdi_index as usize;
        if idx >= MAX_BDIS || !self.bdis[idx].active {
            return Err(Error::InvalidArgument);
        }
        Ok(self.bdis[idx].throttled_bw())
    }

    /// Return current statistics.
    pub const fn stats(&self) -> &WritebackStats {
        &self.stats
    }
}
