// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Zone watermark management.
//!
//! Implements watermark levels (MIN, LOW, HIGH, PROMO) that control
//! the page allocator's reclaim behaviour. When free pages drop below
//! LOW, kswapd is woken; below MIN, only emergency allocations
//! succeed. The PROMO level controls proactive reclaim for NUMA
//! promotion.
//!
//! - [`WatermarkLevel`] — named watermark levels
//! - [`WatermarkConfig`] — per-zone watermark thresholds
//! - [`WatermarkBoost`] — temporary watermark boost after compaction
//! - [`WatermarkChecker`] — the main watermark evaluation engine
//! - [`WatermarkEvent`] — events triggered by watermark crossings
//! - [`WatermarkStats`] — aggregate watermark statistics
//!
//! Reference: `.kernelORG/` — `mm/page_alloc.c` (`setup_per_zone_wmarks`),
//! `include/linux/mmzone.h`.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Standard page size (4 KiB).
const PAGE_SIZE: u64 = 4096;

/// Default min_free_kbytes.
const DEFAULT_MIN_FREE_KBYTES: u64 = 16384;

/// Maximum number of zones.
const MAX_ZONES: usize = 5;

/// Maximum watermark events in the ring buffer.
const MAX_WATERMARK_EVENTS: usize = 64;

/// Watermark boost decay rate (per tick).
const BOOST_DECAY_RATE: u64 = 256;

/// Maximum boost value (pages).
const MAX_BOOST: u64 = 65536;

// -------------------------------------------------------------------
// WatermarkLevel
// -------------------------------------------------------------------

/// Named watermark levels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum WatermarkLevel {
    /// Minimum — only emergency/GFP_ATOMIC allocations below this.
    #[default]
    Min = 0,
    /// Low — kswapd wakes up when free pages drop below.
    Low = 1,
    /// High — kswapd goes back to sleep when free pages rise above.
    High = 2,
    /// Promo — proactive reclaim for NUMA promotion.
    Promo = 3,
}

// -------------------------------------------------------------------
// WatermarkConfig
// -------------------------------------------------------------------

/// Per-zone watermark thresholds (in pages).
#[derive(Debug, Clone, Copy, Default)]
pub struct WatermarkConfig {
    /// Zone identifier.
    pub zone_id: usize,
    /// Managed pages in this zone.
    pub managed_pages: u64,
    /// MIN watermark.
    pub wmark_min: u64,
    /// LOW watermark.
    pub wmark_low: u64,
    /// HIGH watermark.
    pub wmark_high: u64,
    /// PROMO watermark.
    pub wmark_promo: u64,
    /// Current temporary boost (pages).
    pub boost: u64,
}

impl WatermarkConfig {
    /// Computes watermarks from min_free_kbytes and managed_pages.
    ///
    /// The algorithm follows Linux: MIN is proportional to
    /// min_free_kbytes, LOW = MIN × 5/4, HIGH = MIN × 3/2.
    pub fn compute(zone_id: usize, managed_pages: u64, min_free_kbytes: u64) -> Self {
        let total_min_pages = min_free_kbytes * 1024 / PAGE_SIZE;
        // Each zone gets a share proportional to its managed_pages.
        let wmark_min = if managed_pages > 0 {
            total_min_pages.min(managed_pages / 4)
        } else {
            0
        };
        let wmark_low = wmark_min + wmark_min / 4;
        let wmark_high = wmark_min + wmark_min / 2;
        let wmark_promo = wmark_high + wmark_min / 4;

        Self {
            zone_id,
            managed_pages,
            wmark_min,
            wmark_low,
            wmark_high,
            wmark_promo,
            boost: 0,
        }
    }

    /// Returns the effective watermark at the given level,
    /// including any boost.
    pub fn effective(&self, level: WatermarkLevel) -> u64 {
        let base = match level {
            WatermarkLevel::Min => self.wmark_min,
            WatermarkLevel::Low => self.wmark_low,
            WatermarkLevel::High => self.wmark_high,
            WatermarkLevel::Promo => self.wmark_promo,
        };
        base + self.boost
    }
}

// -------------------------------------------------------------------
// WatermarkBoost
// -------------------------------------------------------------------

/// Temporary watermark boost state (applied after compaction).
#[derive(Debug, Clone, Copy, Default)]
pub struct WatermarkBoost {
    /// Current boost value (pages).
    pub current: u64,
    /// Maximum boost allowed.
    pub max_boost: u64,
    /// Number of boost applications.
    pub applications: u64,
    /// Number of decay ticks.
    pub decay_ticks: u64,
}

impl WatermarkBoost {
    /// Creates a new boost tracker.
    pub fn new(max_boost: u64) -> Self {
        Self {
            max_boost,
            ..Self::default()
        }
    }

    /// Applies a boost of the given amount.
    pub fn apply(&mut self, amount: u64) {
        self.current = (self.current + amount).min(self.max_boost);
        self.applications += 1;
    }

    /// Decays the boost by one tick.
    pub fn decay(&mut self) {
        if self.current > 0 {
            self.current = self.current.saturating_sub(BOOST_DECAY_RATE);
            self.decay_ticks += 1;
        }
    }

    /// Resets the boost to zero.
    pub fn reset(&mut self) {
        self.current = 0;
    }
}

// -------------------------------------------------------------------
// WatermarkEvent
// -------------------------------------------------------------------

/// An event triggered by a watermark crossing.
#[derive(Debug, Clone, Copy, Default)]
pub struct WatermarkEvent {
    /// Zone that triggered the event.
    pub zone_id: usize,
    /// Watermark level crossed.
    pub level: WatermarkLevel,
    /// Whether this is a downward crossing (true) or upward (false).
    pub below: bool,
    /// Free pages at the time of the event.
    pub free_pages: u64,
    /// Timestamp (monotonic ns).
    pub timestamp_ns: u64,
}

// -------------------------------------------------------------------
// WatermarkStats
// -------------------------------------------------------------------

/// Aggregate watermark statistics.
#[derive(Debug, Clone, Copy, Default)]
pub struct WatermarkStats {
    /// Number of MIN crossings (downward).
    pub min_crossings: u64,
    /// Number of LOW crossings (downward — kswapd wakeups).
    pub low_crossings: u64,
    /// Number of HIGH crossings (upward — kswapd sleeps).
    pub high_crossings: u64,
    /// Number of fast-path watermark checks that passed.
    pub fast_checks_pass: u64,
    /// Number of fast-path watermark checks that failed.
    pub fast_checks_fail: u64,
    /// Total kswapd wakeups.
    pub kswapd_wakeups: u64,
}

impl WatermarkStats {
    /// Resets all counters.
    pub fn reset(&mut self) {
        *self = Self::default();
    }
}

// -------------------------------------------------------------------
// WatermarkChecker
// -------------------------------------------------------------------

/// The main watermark evaluation engine.
///
/// Stores per-zone watermark configurations, boost state, and an
/// event ring buffer for watermark crossings.
pub struct WatermarkChecker {
    /// Per-zone watermark configurations.
    configs: [WatermarkConfig; MAX_ZONES],
    /// Per-zone boost state.
    boosts: [WatermarkBoost; MAX_ZONES],
    /// Event ring buffer.
    events: [WatermarkEvent; MAX_WATERMARK_EVENTS],
    /// Event write position.
    event_head: usize,
    /// Number of events recorded.
    event_count: usize,
    /// Aggregate statistics.
    stats: WatermarkStats,
    /// Global min_free_kbytes.
    min_free_kbytes: u64,
    /// Number of initialised zones.
    nr_zones: usize,
}

impl Default for WatermarkChecker {
    fn default() -> Self {
        Self {
            configs: [WatermarkConfig::default(); MAX_ZONES],
            boosts: [const {
                WatermarkBoost {
                    current: 0,
                    max_boost: 0,
                    applications: 0,
                    decay_ticks: 0,
                }
            }; MAX_ZONES],
            events: [WatermarkEvent::default(); MAX_WATERMARK_EVENTS],
            event_head: 0,
            event_count: 0,
            stats: WatermarkStats::default(),
            min_free_kbytes: DEFAULT_MIN_FREE_KBYTES,
            nr_zones: 0,
        }
    }
}

impl WatermarkChecker {
    /// Creates a new watermark checker.
    pub fn new() -> Self {
        Self::default()
    }

    /// Initialises a zone's watermarks.
    pub fn setup_zone(&mut self, zone_id: usize, managed_pages: u64) -> Result<()> {
        if zone_id >= MAX_ZONES {
            return Err(Error::InvalidArgument);
        }
        self.configs[zone_id] =
            WatermarkConfig::compute(zone_id, managed_pages, self.min_free_kbytes);
        self.boosts[zone_id] = WatermarkBoost::new(MAX_BOOST);
        if zone_id >= self.nr_zones {
            self.nr_zones = zone_id + 1;
        }
        Ok(())
    }

    /// Sets min_free_kbytes and recomputes all watermarks.
    pub fn set_min_free_kbytes(&mut self, kbytes: u64) -> Result<()> {
        self.min_free_kbytes = kbytes;
        for i in 0..self.nr_zones {
            let managed = self.configs[i].managed_pages;
            self.configs[i] = WatermarkConfig::compute(i, managed, kbytes);
        }
        Ok(())
    }

    /// Fast watermark check: is the zone above MIN?
    pub fn zone_watermark_fast(&mut self, zone_id: usize, free_pages: u64) -> bool {
        if zone_id >= self.nr_zones {
            return false;
        }
        let ok = free_pages > self.configs[zone_id].effective(WatermarkLevel::Min);
        if ok {
            self.stats.fast_checks_pass += 1;
        } else {
            self.stats.fast_checks_fail += 1;
        }
        ok
    }

    /// Full watermark check at a given level.
    pub fn zone_watermark_ok(
        &self,
        zone_id: usize,
        free_pages: u64,
        level: WatermarkLevel,
    ) -> bool {
        if zone_id >= self.nr_zones {
            return false;
        }
        free_pages >= self.configs[zone_id].effective(level)
    }

    /// Checks if kswapd should be woken for the given zone.
    pub fn should_wake_kswapd(
        &mut self,
        zone_id: usize,
        free_pages: u64,
        timestamp_ns: u64,
    ) -> bool {
        if zone_id >= self.nr_zones {
            return false;
        }
        let below_low = !self.zone_watermark_ok(zone_id, free_pages, WatermarkLevel::Low);
        if below_low {
            self.stats.low_crossings += 1;
            self.stats.kswapd_wakeups += 1;
            self.record_event(WatermarkEvent {
                zone_id,
                level: WatermarkLevel::Low,
                below: true,
                free_pages,
                timestamp_ns,
            });
        }
        below_low
    }

    /// Checks if kswapd can go back to sleep.
    pub fn kswapd_can_sleep(&self, zone_id: usize, free_pages: u64) -> bool {
        self.zone_watermark_ok(zone_id, free_pages, WatermarkLevel::High)
    }

    /// Applies a watermark boost to the given zone.
    pub fn boost_zone(&mut self, zone_id: usize, amount: u64) -> Result<()> {
        if zone_id >= self.nr_zones {
            return Err(Error::InvalidArgument);
        }
        self.boosts[zone_id].apply(amount);
        self.configs[zone_id].boost = self.boosts[zone_id].current;
        Ok(())
    }

    /// Decays watermark boosts (called periodically).
    pub fn decay_boosts(&mut self) {
        for i in 0..self.nr_zones {
            self.boosts[i].decay();
            self.configs[i].boost = self.boosts[i].current;
        }
    }

    /// Returns the configuration for a zone.
    pub fn config(&self, zone_id: usize) -> Option<&WatermarkConfig> {
        if zone_id < self.nr_zones {
            Some(&self.configs[zone_id])
        } else {
            None
        }
    }

    /// Returns aggregate statistics.
    pub fn stats(&self) -> &WatermarkStats {
        &self.stats
    }

    /// Returns the number of recorded events.
    pub fn event_count(&self) -> usize {
        self.event_count
    }

    /// Records a watermark event.
    fn record_event(&mut self, event: WatermarkEvent) {
        self.events[self.event_head] = event;
        self.event_head = (self.event_head + 1) % MAX_WATERMARK_EVENTS;
        if self.event_count < MAX_WATERMARK_EVENTS {
            self.event_count += 1;
        }
    }
}
