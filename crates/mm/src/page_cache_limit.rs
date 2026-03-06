// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Page cache pressure control.
//!
//! Controls page cache size under memory pressure by implementing:
//!
//! - **Dirty page ratio tracking** — monitors the proportion of
//!   physical memory occupied by dirty pages.
//! - **Writeback thresholds** — defines background and foreground
//!   thresholds that trigger asynchronous or synchronous writeback.
//! - **Flusher wakeup** — determines when the background flusher
//!   (analogous to Linux's `pdflush` / `bdi-flush`) should be
//!   activated.
//! - **Cache pressure scoring** — computes a numeric pressure index
//!   that the reclaim path uses to decide how aggressively to evict
//!   page cache pages versus anonymous pages.
//!
//! # Design
//!
//! The subsystem is modelled on Linux's `vm.dirty_ratio`,
//! `vm.dirty_background_ratio`, and `vm.vfs_cache_pressure` sysctls.
//! A [`CacheLimit`] instance tracks global and per-device dirty page
//! state, and exposes a [`CacheLimit::check_pressure`] method that
//! returns a [`CachePressure`] verdict.
//!
//! Reference: Linux `mm/page-writeback.c`, `include/linux/writeback.h`.

use oncrix_lib::{Error, Result};

// ── Constants ───────────────────────────────────────────────────────────────

/// Standard page size in bytes (4 KiB).
const PAGE_SIZE: u64 = 4096;

/// Default foreground dirty ratio — percentage of total pages.
///
/// When dirty pages exceed this, writers are throttled synchronously.
const DEFAULT_DIRTY_RATIO: u32 = 20;

/// Default background dirty ratio — percentage of total pages.
///
/// When dirty pages exceed this, background writeback is started.
const DEFAULT_DIRTY_BG_RATIO: u32 = 10;

/// Default VFS cache pressure (100 = neutral, >100 = more aggressive).
const DEFAULT_CACHE_PRESSURE: u32 = 100;

/// Minimum writeback interval in milliseconds.
const MIN_WRITEBACK_INTERVAL_MS: u64 = 100;

/// Default writeback interval in milliseconds (5 s).
const DEFAULT_WRITEBACK_INTERVAL_MS: u64 = 5000;

/// Maximum number of backing devices tracked.
const MAX_BDI: usize = 16;

/// Maximum number of writeback events recorded for rate estimation.
const MAX_WRITEBACK_HISTORY: usize = 32;

/// Dirty page expire age in milliseconds (30 s).
const DEFAULT_DIRTY_EXPIRE_MS: u64 = 30_000;

/// Bandwidth estimation smoothing factor (EMA weight = 1/SMOOTH).
const BW_SMOOTH_FACTOR: u64 = 8;

// ── DirtyThreshold ──────────────────────────────────────────────────────────

/// Configurable thresholds that govern writeback behaviour.
#[derive(Debug, Clone, Copy)]
pub struct DirtyThreshold {
    /// Foreground dirty ratio (percentage, 1..100).
    pub dirty_ratio: u32,
    /// Background dirty ratio (percentage, 1..dirty_ratio).
    pub dirty_bg_ratio: u32,
    /// VFS cache pressure tunable (0..1000).
    pub cache_pressure: u32,
    /// Writeback interval in milliseconds.
    pub writeback_interval_ms: u64,
    /// Dirty page expire time in milliseconds.
    pub dirty_expire_ms: u64,
}

impl Default for DirtyThreshold {
    fn default() -> Self {
        Self {
            dirty_ratio: DEFAULT_DIRTY_RATIO,
            dirty_bg_ratio: DEFAULT_DIRTY_BG_RATIO,
            cache_pressure: DEFAULT_CACHE_PRESSURE,
            writeback_interval_ms: DEFAULT_WRITEBACK_INTERVAL_MS,
            dirty_expire_ms: DEFAULT_DIRTY_EXPIRE_MS,
        }
    }
}

impl DirtyThreshold {
    /// Validate threshold consistency.
    pub fn validate(&self) -> Result<()> {
        if self.dirty_ratio == 0 || self.dirty_ratio > 100 {
            return Err(Error::InvalidArgument);
        }
        if self.dirty_bg_ratio == 0 || self.dirty_bg_ratio > self.dirty_ratio {
            return Err(Error::InvalidArgument);
        }
        if self.writeback_interval_ms < MIN_WRITEBACK_INTERVAL_MS {
            return Err(Error::InvalidArgument);
        }
        if self.cache_pressure > 1000 {
            return Err(Error::InvalidArgument);
        }
        Ok(())
    }
}

// ── CachePressure ───────────────────────────────────────────────────────────

/// Verdict returned by [`CacheLimit::check_pressure`].
///
/// Tells the caller what action, if any, should be taken in response
/// to the current dirty page ratio.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CachePressure {
    /// No action needed — dirty pages are within acceptable limits.
    None,
    /// Background writeback should be started or continued.
    Background,
    /// Foreground (synchronous) writeback is required — the caller
    /// should block until dirty pages drop below the threshold.
    Foreground,
    /// Critical memory pressure — aggressive reclaim is needed.
    Critical,
}

impl Default for CachePressure {
    fn default() -> Self {
        Self::None
    }
}

// ── WritebackControl ────────────────────────────────────────────────────────

/// Per-device writeback control state.
///
/// Tracks dirty page count and writeback bandwidth for a single
/// backing device (block device or swap area).
#[derive(Debug, Clone, Copy)]
pub struct WritebackControl {
    /// Backing device identifier.
    pub bdi_id: u32,
    /// Number of dirty pages attributed to this device.
    pub dirty_pages: u64,
    /// Number of pages currently under writeback.
    pub writeback_pages: u64,
    /// Estimated write bandwidth in pages per second.
    pub write_bandwidth: u64,
    /// Timestamp of the last writeback start (ms since boot).
    pub last_writeback_ms: u64,
    /// Number of pages written in the current writeback window.
    pub pages_written: u64,
    /// Whether this device entry is active.
    pub active: bool,
}

impl WritebackControl {
    /// Creates an empty (inactive) writeback control entry.
    const fn empty() -> Self {
        Self {
            bdi_id: 0,
            dirty_pages: 0,
            writeback_pages: 0,
            write_bandwidth: 0,
            last_writeback_ms: 0,
            pages_written: 0,
            active: false,
        }
    }

    /// Returns the proportion of this device's pages that are dirty
    /// as a percentage of `total_pages`.
    pub const fn dirty_ratio(&self, total_pages: u64) -> u32 {
        if total_pages == 0 {
            return 0;
        }
        (self.dirty_pages * 100 / total_pages) as u32
    }
}

// ── WritebackEvent ──────────────────────────────────────────────────────────

/// Records a single writeback event for bandwidth estimation.
#[derive(Debug, Clone, Copy)]
struct WritebackEvent {
    /// Timestamp when the writeback completed (ms since boot).
    timestamp_ms: u64,
    /// Number of pages written.
    pages_written: u64,
    /// Duration of the writeback in milliseconds.
    duration_ms: u64,
}

impl WritebackEvent {
    /// Creates an empty event.
    const fn empty() -> Self {
        Self {
            timestamp_ms: 0,
            pages_written: 0,
            duration_ms: 0,
        }
    }
}

// ── CacheLimitStats ─────────────────────────────────────────────────────────

/// Aggregate statistics for the cache pressure controller.
#[derive(Debug, Clone, Copy)]
pub struct CacheLimitStats {
    /// Number of times background writeback was triggered.
    pub bg_writeback_triggers: u64,
    /// Number of times foreground writeback was triggered.
    pub fg_writeback_triggers: u64,
    /// Number of times critical pressure was reported.
    pub critical_triggers: u64,
    /// Total pages written across all writeback events.
    pub total_pages_written: u64,
    /// Current global dirty page count.
    pub global_dirty_pages: u64,
    /// Current global writeback page count.
    pub global_writeback_pages: u64,
    /// Total memory in pages.
    pub total_pages: u64,
    /// Number of threshold adjustments made.
    pub threshold_adjustments: u64,
}

impl CacheLimitStats {
    /// Creates zeroed statistics.
    const fn new() -> Self {
        Self {
            bg_writeback_triggers: 0,
            fg_writeback_triggers: 0,
            critical_triggers: 0,
            total_pages_written: 0,
            global_dirty_pages: 0,
            global_writeback_pages: 0,
            total_pages: 0,
            threshold_adjustments: 0,
        }
    }
}

// ── CacheLimit ──────────────────────────────────────────────────────────────

/// Page cache pressure controller.
///
/// Tracks global and per-device dirty page ratios and decides when
/// to trigger background or foreground writeback, or report critical
/// memory pressure.
pub struct CacheLimit {
    /// Active threshold configuration.
    threshold: DirtyThreshold,
    /// Per-device writeback control entries.
    devices: [WritebackControl; MAX_BDI],
    /// Number of registered devices.
    device_count: usize,
    /// Total system memory in pages.
    total_pages: u64,
    /// Total dirty pages across all devices.
    global_dirty: u64,
    /// Total pages under active writeback.
    global_writeback: u64,
    /// Writeback event history for bandwidth estimation.
    wb_history: [WritebackEvent; MAX_WRITEBACK_HISTORY],
    /// Next write index in the circular history buffer.
    wb_history_idx: usize,
    /// Estimated global write bandwidth (pages per second).
    estimated_bandwidth: u64,
    /// Statistics.
    stats: CacheLimitStats,
    /// Whether the controller is initialised.
    initialised: bool,
}

impl CacheLimit {
    /// Creates an uninitialised controller.
    pub const fn new() -> Self {
        Self {
            threshold: DirtyThreshold {
                dirty_ratio: DEFAULT_DIRTY_RATIO,
                dirty_bg_ratio: DEFAULT_DIRTY_BG_RATIO,
                cache_pressure: DEFAULT_CACHE_PRESSURE,
                writeback_interval_ms: DEFAULT_WRITEBACK_INTERVAL_MS,
                dirty_expire_ms: DEFAULT_DIRTY_EXPIRE_MS,
            },
            devices: [const { WritebackControl::empty() }; MAX_BDI],
            device_count: 0,
            total_pages: 0,
            global_dirty: 0,
            global_writeback: 0,
            wb_history: [const { WritebackEvent::empty() }; MAX_WRITEBACK_HISTORY],
            wb_history_idx: 0,
            estimated_bandwidth: 0,
            stats: CacheLimitStats::new(),
            initialised: false,
        }
    }

    /// Initialise the controller with the system's total page count
    /// and an initial threshold configuration.
    pub fn init(&mut self, total_pages: u64, threshold: DirtyThreshold) -> Result<()> {
        if total_pages == 0 {
            return Err(Error::InvalidArgument);
        }
        threshold.validate()?;
        self.total_pages = total_pages;
        self.threshold = threshold;
        self.stats.total_pages = total_pages;
        self.initialised = true;
        Ok(())
    }

    /// Check the current memory pressure level.
    ///
    /// Returns a [`CachePressure`] verdict indicating what action, if
    /// any, the caller should take.
    pub fn check_pressure(&mut self) -> Result<CachePressure> {
        if !self.initialised {
            return Err(Error::InvalidArgument);
        }

        self.recompute_global_dirty();

        let dirty_pct = self.get_dirty_ratio();

        // Scale by cache_pressure tunable (100 = neutral).
        let scaled_pct = (dirty_pct as u64) * (self.threshold.cache_pressure as u64) / 100;

        let pressure = if scaled_pct >= (self.threshold.dirty_ratio as u64) * 2 {
            self.stats.critical_triggers += 1;
            CachePressure::Critical
        } else if dirty_pct >= self.threshold.dirty_ratio {
            self.stats.fg_writeback_triggers += 1;
            CachePressure::Foreground
        } else if dirty_pct >= self.threshold.dirty_bg_ratio {
            self.stats.bg_writeback_triggers += 1;
            CachePressure::Background
        } else {
            CachePressure::None
        };

        Ok(pressure)
    }

    /// Signal the start of writeback for a device.
    ///
    /// `bdi_id` — backing device identifier.
    /// `nr_pages` — number of pages to write back.
    /// `now_ms` — current time in milliseconds since boot.
    pub fn start_writeback(&mut self, bdi_id: u32, nr_pages: u64, now_ms: u64) -> Result<()> {
        if !self.initialised {
            return Err(Error::InvalidArgument);
        }

        let dev = self.find_or_create_device(bdi_id)?;
        dev.writeback_pages += nr_pages;
        dev.last_writeback_ms = now_ms;
        self.global_writeback += nr_pages;
        self.stats.global_writeback_pages = self.global_writeback;

        Ok(())
    }

    /// Signal completion of writeback for a device.
    ///
    /// `bdi_id` — backing device identifier.
    /// `nr_pages` — number of pages actually written.
    /// `duration_ms` — wall-clock time the writeback took.
    /// `now_ms` — current time in milliseconds since boot.
    pub fn complete_writeback(
        &mut self,
        bdi_id: u32,
        nr_pages: u64,
        duration_ms: u64,
        now_ms: u64,
    ) -> Result<()> {
        if !self.initialised {
            return Err(Error::InvalidArgument);
        }

        // Update the device.
        for dev in &mut self.devices {
            if dev.active && dev.bdi_id == bdi_id {
                dev.writeback_pages = dev.writeback_pages.saturating_sub(nr_pages);
                dev.dirty_pages = dev.dirty_pages.saturating_sub(nr_pages);
                dev.pages_written += nr_pages;
                // Inline bandwidth update (avoids &self borrow conflict).
                if duration_ms > 0 {
                    let bw = nr_pages * 1000 / duration_ms;
                    if dev.write_bandwidth == 0 {
                        dev.write_bandwidth = bw;
                    } else {
                        dev.write_bandwidth = dev.write_bandwidth
                            - dev.write_bandwidth / BW_SMOOTH_FACTOR
                            + bw / BW_SMOOTH_FACTOR;
                    }
                }
                break;
            }
        }

        self.global_writeback = self.global_writeback.saturating_sub(nr_pages);
        self.global_dirty = self.global_dirty.saturating_sub(nr_pages);
        self.stats.total_pages_written += nr_pages;
        self.stats.global_writeback_pages = self.global_writeback;
        self.stats.global_dirty_pages = self.global_dirty;

        // Record event for bandwidth estimation.
        self.record_writeback_event(now_ms, nr_pages, duration_ms);

        Ok(())
    }

    /// Adjust thresholds dynamically.
    ///
    /// Returns [`Error::InvalidArgument`] if the new thresholds are
    /// inconsistent.
    pub fn adjust_threshold(&mut self, new_threshold: DirtyThreshold) -> Result<()> {
        new_threshold.validate()?;
        self.threshold = new_threshold;
        self.stats.threshold_adjustments += 1;
        Ok(())
    }

    /// Returns the current global dirty ratio as a percentage (0..100).
    pub fn get_dirty_ratio(&self) -> u32 {
        if self.total_pages == 0 {
            return 0;
        }
        (self.global_dirty * 100 / self.total_pages) as u32
    }

    /// Mark pages as dirty for a given device.
    pub fn mark_dirty(&mut self, bdi_id: u32, nr_pages: u64) -> Result<()> {
        if !self.initialised {
            return Err(Error::InvalidArgument);
        }
        let dev = self.find_or_create_device(bdi_id)?;
        dev.dirty_pages += nr_pages;
        self.global_dirty += nr_pages;
        self.stats.global_dirty_pages = self.global_dirty;
        Ok(())
    }

    /// Returns a snapshot of statistics.
    pub const fn stats(&self) -> &CacheLimitStats {
        &self.stats
    }

    /// Returns the current threshold configuration.
    pub const fn threshold(&self) -> &DirtyThreshold {
        &self.threshold
    }

    /// Returns the estimated global write bandwidth (pages/s).
    pub const fn estimated_bandwidth(&self) -> u64 {
        self.estimated_bandwidth
    }

    /// Returns the number of registered devices.
    pub const fn device_count(&self) -> usize {
        self.device_count
    }

    /// Returns `true` if the controller is initialised.
    pub const fn is_initialised(&self) -> bool {
        self.initialised
    }

    /// Returns total system pages.
    pub const fn total_pages(&self) -> u64 {
        self.total_pages
    }

    /// Returns global dirty page count.
    pub const fn global_dirty(&self) -> u64 {
        self.global_dirty
    }

    /// Returns the page size constant used by the controller.
    pub const fn page_size() -> u64 {
        PAGE_SIZE
    }

    // ── Private helpers ─────────────────────────────────────────────

    /// Recompute global dirty count from per-device state.
    fn recompute_global_dirty(&mut self) {
        let mut total = 0u64;
        for dev in &self.devices {
            if dev.active {
                total += dev.dirty_pages;
            }
        }
        self.global_dirty = total;
        self.stats.global_dirty_pages = total;
    }

    /// Find an existing device entry or create a new one.
    fn find_or_create_device(&mut self, bdi_id: u32) -> Result<&mut WritebackControl> {
        // Look for existing — index-based to avoid double borrow.
        let existing = self
            .devices
            .iter()
            .position(|d| d.active && d.bdi_id == bdi_id);
        if let Some(idx) = existing {
            return Ok(&mut self.devices[idx]);
        }

        // Create new.
        if self.device_count >= MAX_BDI {
            return Err(Error::OutOfMemory);
        }
        let free_idx = self.devices.iter().position(|d| !d.active);
        if let Some(idx) = free_idx {
            self.devices[idx].bdi_id = bdi_id;
            self.devices[idx].active = true;
            self.device_count += 1;
            return Ok(&mut self.devices[idx]);
        }

        Err(Error::OutOfMemory)
    }

    /// Update per-device bandwidth estimate using EMA.
    fn update_device_bandwidth(&self, dev: &mut WritebackControl, nr_pages: u64, duration_ms: u64) {
        if duration_ms == 0 {
            return;
        }
        let bw = nr_pages * 1000 / duration_ms;
        if dev.write_bandwidth == 0 {
            dev.write_bandwidth = bw;
        } else {
            // Exponential moving average.
            dev.write_bandwidth = dev.write_bandwidth - dev.write_bandwidth / BW_SMOOTH_FACTOR
                + bw / BW_SMOOTH_FACTOR;
        }
    }

    /// Record a writeback event in the circular history buffer.
    fn record_writeback_event(&mut self, timestamp_ms: u64, pages_written: u64, duration_ms: u64) {
        let evt = &mut self.wb_history[self.wb_history_idx];
        evt.timestamp_ms = timestamp_ms;
        evt.pages_written = pages_written;
        evt.duration_ms = duration_ms;
        self.wb_history_idx = (self.wb_history_idx + 1) % MAX_WRITEBACK_HISTORY;

        // Recompute global estimated bandwidth from recent events.
        let mut total_pages = 0u64;
        let mut total_ms = 0u64;
        for e in &self.wb_history {
            if e.duration_ms > 0 {
                total_pages += e.pages_written;
                total_ms += e.duration_ms;
            }
        }
        if total_ms > 0 {
            self.estimated_bandwidth = total_pages * 1000 / total_ms;
        }
    }
}
