// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Page writeback rate control.
//!
//! Controls the rate at which dirty pages are written back to backing
//! storage. The goal is to balance between holding dirty pages in memory
//! (for write coalescing) and flushing them timely (to limit data loss
//! on crash and keep free memory available for new allocations).
//!
//! # Design
//!
//! ```text
//!  WritebackRateController
//!       │
//!       ├─ measure dirty ratio = dirty_pages / total_pages
//!       │
//!       ├─ below background threshold → no writeback
//!       ├─ between background and threshold → background writeback
//!       └─ above threshold → throttle writers + synchronous writeback
//! ```
//!
//! # Key Types
//!
//! - [`WritebackThresholds`] — configurable thresholds
//! - [`WritebackRateController`] — the rate controller
//! - [`WritebackBandwidth`] — bandwidth estimation
//! - [`WritebackRateDecision`] — decision from the controller
//!
//! Reference: Linux `mm/page-writeback.c`, `include/linux/writeback.h`.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Default background writeback threshold (percent of total).
const DEFAULT_BG_THRESHOLD_PCT: u64 = 10;

/// Default throttle threshold (percent of total).
const DEFAULT_THRESHOLD_PCT: u64 = 20;

/// Minimum bandwidth (pages per tick).
const MIN_BANDWIDTH: u64 = 1;

/// Maximum bandwidth (pages per tick).
const MAX_BANDWIDTH: u64 = 65536;

/// Smoothing factor for bandwidth estimation (numerator/16).
const SMOOTH_FACTOR: u64 = 12; // 75% old + 25% new

// -------------------------------------------------------------------
// WritebackThresholds
// -------------------------------------------------------------------

/// Writeback threshold configuration.
#[derive(Debug, Clone, Copy)]
pub struct WritebackThresholds {
    /// Background writeback starts when dirty ratio exceeds this (percent).
    pub background_pct: u64,
    /// Writer throttling starts when dirty ratio exceeds this (percent).
    pub throttle_pct: u64,
}

impl WritebackThresholds {
    /// Create default thresholds.
    pub const fn new() -> Self {
        Self {
            background_pct: DEFAULT_BG_THRESHOLD_PCT,
            throttle_pct: DEFAULT_THRESHOLD_PCT,
        }
    }

    /// Validate thresholds.
    pub fn validate(&self) -> Result<()> {
        if self.background_pct >= self.throttle_pct {
            return Err(Error::InvalidArgument);
        }
        if self.throttle_pct > 80 {
            return Err(Error::InvalidArgument);
        }
        Ok(())
    }
}

impl Default for WritebackThresholds {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// WritebackRateDecision
// -------------------------------------------------------------------

/// Decision from the rate controller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WritebackAction {
    /// No writeback needed.
    None,
    /// Start background writeback at the estimated bandwidth.
    Background,
    /// Throttle writers and flush synchronously.
    Throttle,
}

impl WritebackAction {
    /// Return a human-readable name.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Background => "background",
            Self::Throttle => "throttle",
        }
    }
}

/// Full decision with context.
#[derive(Debug, Clone, Copy)]
pub struct WritebackRateDecision {
    /// Recommended action.
    pub action: WritebackAction,
    /// Dirty ratio (percent).
    pub dirty_ratio: u64,
    /// Suggested writeback pages per tick.
    pub pages_per_tick: u64,
    /// Suggested throttle delay (microseconds, 0 if not throttling).
    pub throttle_delay_us: u64,
}

impl WritebackRateDecision {
    /// Create a no-action decision.
    pub const fn none(dirty_ratio: u64) -> Self {
        Self {
            action: WritebackAction::None,
            dirty_ratio,
            pages_per_tick: 0,
            throttle_delay_us: 0,
        }
    }
}

// -------------------------------------------------------------------
// WritebackBandwidth
// -------------------------------------------------------------------

/// Bandwidth estimator for writeback.
#[derive(Debug, Clone, Copy)]
pub struct WritebackBandwidth {
    /// Current estimated bandwidth (pages per tick).
    estimated: u64,
    /// Peak observed bandwidth.
    peak: u64,
    /// Total pages written.
    total_written: u64,
    /// Total ticks observed.
    total_ticks: u64,
}

impl WritebackBandwidth {
    /// Create a new estimator.
    pub const fn new() -> Self {
        Self {
            estimated: MIN_BANDWIDTH,
            peak: MIN_BANDWIDTH,
            total_written: 0,
            total_ticks: 0,
        }
    }

    /// Return the current estimated bandwidth.
    pub const fn estimated(&self) -> u64 {
        self.estimated
    }

    /// Return the peak bandwidth.
    pub const fn peak(&self) -> u64 {
        self.peak
    }

    /// Update with a new observation.
    pub fn update(&mut self, pages_written: u64, ticks: u64) {
        if ticks == 0 {
            return;
        }
        let observed = pages_written / ticks;
        // Exponential moving average.
        self.estimated = (self.estimated * SMOOTH_FACTOR + observed * (16 - SMOOTH_FACTOR)) / 16;
        self.estimated = self.estimated.max(MIN_BANDWIDTH).min(MAX_BANDWIDTH);
        if observed > self.peak {
            self.peak = observed;
        }
        self.total_written += pages_written;
        self.total_ticks += ticks;
    }

    /// Return average bandwidth.
    pub const fn average(&self) -> u64 {
        if self.total_ticks == 0 {
            return MIN_BANDWIDTH;
        }
        self.total_written / self.total_ticks
    }
}

impl Default for WritebackBandwidth {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// WritebackRateController
// -------------------------------------------------------------------

/// Controls the rate of dirty page writeback.
pub struct WritebackRateController {
    /// Thresholds.
    thresholds: WritebackThresholds,
    /// Bandwidth estimator.
    bandwidth: WritebackBandwidth,
    /// Total dirty pages observed.
    dirty_pages: u64,
    /// Total pages in the system.
    total_pages: u64,
    /// Total throttle events.
    throttle_events: u64,
    /// Total background writeback events.
    background_events: u64,
}

impl WritebackRateController {
    /// Create a new controller with default thresholds.
    pub const fn new() -> Self {
        Self {
            thresholds: WritebackThresholds::new(),
            bandwidth: WritebackBandwidth::new(),
            dirty_pages: 0,
            total_pages: 0,
            throttle_events: 0,
            background_events: 0,
        }
    }

    /// Create with custom thresholds.
    pub fn with_thresholds(thresholds: WritebackThresholds) -> Result<Self> {
        thresholds.validate()?;
        Ok(Self {
            thresholds,
            ..Self::new()
        })
    }

    /// Return the thresholds.
    pub const fn thresholds(&self) -> &WritebackThresholds {
        &self.thresholds
    }

    /// Return the bandwidth estimator.
    pub const fn bandwidth(&self) -> &WritebackBandwidth {
        &self.bandwidth
    }

    /// Return total throttle events.
    pub const fn throttle_events(&self) -> u64 {
        self.throttle_events
    }

    /// Return total background events.
    pub const fn background_events(&self) -> u64 {
        self.background_events
    }

    /// Set current memory state.
    pub fn set_memory_state(&mut self, dirty: u64, total: u64) {
        self.dirty_pages = dirty;
        self.total_pages = total;
    }

    /// Report writeback completion for bandwidth estimation.
    pub fn report_writeback(&mut self, pages: u64, ticks: u64) {
        self.bandwidth.update(pages, ticks);
    }

    /// Evaluate and return the writeback decision.
    pub fn evaluate(&mut self) -> WritebackRateDecision {
        if self.total_pages == 0 {
            return WritebackRateDecision::none(0);
        }

        let dirty_ratio = self.dirty_pages * 100 / self.total_pages;

        if dirty_ratio >= self.thresholds.throttle_pct {
            self.throttle_events += 1;
            // Calculate throttle delay: more dirty → longer delay.
            let overage = dirty_ratio - self.thresholds.throttle_pct;
            let delay = (overage * 1000).min(100_000); // 0-100ms
            WritebackRateDecision {
                action: WritebackAction::Throttle,
                dirty_ratio,
                pages_per_tick: self.bandwidth.estimated(),
                throttle_delay_us: delay,
            }
        } else if dirty_ratio >= self.thresholds.background_pct {
            self.background_events += 1;
            WritebackRateDecision {
                action: WritebackAction::Background,
                dirty_ratio,
                pages_per_tick: self.bandwidth.estimated(),
                throttle_delay_us: 0,
            }
        } else {
            WritebackRateDecision::none(dirty_ratio)
        }
    }

    /// Update thresholds.
    pub fn set_thresholds(&mut self, thresholds: WritebackThresholds) -> Result<()> {
        thresholds.validate()?;
        self.thresholds = thresholds;
        Ok(())
    }
}

impl Default for WritebackRateController {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// Public helpers
// -------------------------------------------------------------------

/// Quick evaluation: should we start writeback?
pub fn should_writeback(dirty: u64, total: u64) -> bool {
    if total == 0 {
        return false;
    }
    let ratio = dirty * 100 / total;
    ratio >= DEFAULT_BG_THRESHOLD_PCT
}

/// Quick evaluation: should we throttle writers?
pub fn should_throttle_writers(dirty: u64, total: u64) -> bool {
    if total == 0 {
        return false;
    }
    let ratio = dirty * 100 / total;
    ratio >= DEFAULT_THRESHOLD_PCT
}

/// Return a summary of writeback state.
pub fn writeback_rate_summary(controller: &WritebackRateController) -> &'static str {
    if controller.throttle_events() > 0 {
        "writeback rate: throttling active"
    } else if controller.background_events() > 0 {
        "writeback rate: background active"
    } else {
        "writeback rate: idle"
    }
}
