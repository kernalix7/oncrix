// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Cgroup v2 event notification and pressure stall information (PSI).
//!
//! Provides event notification for cgroup lifecycle and threshold
//! transitions, plus per-cgroup Pressure Stall Information (PSI)
//! collection and exponential moving averages.
//!
//! # Architecture
//!
//! ```text
//! ┌──────────────────────────────────────────────────────────────┐
//! │                  CgroupEventSubsystem                        │
//! │                                                              │
//! │  CgroupEventNotifier                                         │
//! │  ┌────────────────────────────────────────────────────────┐  │
//! │  │  watchers[0..MAX_CGROUPS][0..MAX_WATCHERS_PER_CG]     │  │
//! │  │  event_ring[0..EVENT_RING_SIZE]                        │  │
//! │  │  ring_head / ring_tail                                 │  │
//! │  └────────────────────────────────────────────────────────┘  │
//! │                                                              │
//! │  PsiCollector                                                │
//! │  ┌────────────────────────────────────────────────────────┐  │
//! │  │  metrics[0..MAX_CGROUPS][0..NUM_PSI_RESOURCES]         │  │
//! │  │  record_stall / compute_averages / get_psi             │  │
//! │  └────────────────────────────────────────────────────────┘  │
//! │                                                              │
//! │  CgroupEventStats (global counters)                          │
//! │  - total_events, psi_updates, oom_kills_reported             │
//! └──────────────────────────────────────────────────────────────┘
//! ```
//!
//! # PSI Metrics
//!
//! For each resource (CPU, memory, I/O), PSI tracks:
//! - `some_avg10/60/300` — percentage of time *some* tasks were stalled
//!   (10s, 60s, 300s exponential moving averages, fixed-point ×100)
//! - `full_avg10/60/300` — percentage of time *all* tasks were stalled
//! - `total_us` — cumulative stall time in microseconds
//!
//! # Reference
//!
//! Linux `kernel/cgroup/`, `include/linux/psi_types.h`,
//! `Documentation/accounting/psi.rst`.

use oncrix_lib::{Error, Result};

// ══════════════════════════════════════════════════════════════
// Constants
// ══════════════════════════════════════════════════════════════

/// Maximum cgroups tracked.
const MAX_CGROUPS: usize = 64;

/// Maximum event watchers per cgroup.
const MAX_WATCHERS_PER_CG: usize = 16;

/// Event ring buffer size.
const EVENT_RING_SIZE: usize = 128;

/// Number of PSI resource types.
const NUM_PSI_RESOURCES: usize = 3;

/// PSI averaging period — 10 seconds.
const _PSI_AVG10_PERIOD: u64 = 10;

/// PSI averaging period — 60 seconds.
const _PSI_AVG60_PERIOD: u64 = 60;

/// PSI averaging period — 300 seconds (5 minutes).
const _PSI_AVG300_PERIOD: u64 = 300;

/// EMA decay factor numerator for 10-second window (fixed-point).
const EMA_10S_DECAY: u32 = 921; // ~0.9 * 1024

/// EMA decay factor numerator for 60-second window.
const EMA_60S_DECAY: u32 = 1007; // ~0.983 * 1024

/// EMA decay factor numerator for 300-second window.
const EMA_300S_DECAY: u32 = 1021; // ~0.997 * 1024

/// EMA fixed-point scale (1024 = 1.0).
const EMA_SCALE: u32 = 1024;

/// Maximum pressure level thresholds.
const PRESSURE_LOW_PCT: u32 = 10;
const PRESSURE_MEDIUM_PCT: u32 = 40;

// ══════════════════════════════════════════════════════════════
// CgroupEvent
// ══════════════════════════════════════════════════════════════

/// Types of cgroup events that can be reported.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CgroupEvent {
    /// Cgroup became populated (has at least one task).
    Populated,
    /// Cgroup was frozen.
    Frozen,
    /// A resource threshold was crossed.
    ThresholdCrossed,
    /// An OOM kill occurred in this cgroup.
    OomKill,
    /// A resource `max` limit was exceeded.
    MaxExceeded,
}

// ══════════════════════════════════════════════════════════════
// PressureLevel
// ══════════════════════════════════════════════════════════════

/// Pressure level classification for PSI monitoring.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum PressureLevel {
    /// Low pressure — occasional stalls.
    Low,
    /// Medium pressure — noticeable performance impact.
    Medium,
    /// Critical pressure — severe resource contention.
    Critical,
}

impl PressureLevel {
    /// Classify pressure from a percentage (×100 fixed-point).
    pub fn from_percentage(pct_x100: u32) -> Self {
        if pct_x100 >= PRESSURE_MEDIUM_PCT * 100 {
            Self::Critical
        } else if pct_x100 >= PRESSURE_LOW_PCT * 100 {
            Self::Medium
        } else {
            Self::Low
        }
    }
}

impl Default for PressureLevel {
    fn default() -> Self {
        Self::Low
    }
}

// ══════════════════════════════════════════════════════════════
// PsiResource
// ══════════════════════════════════════════════════════════════

/// Resource types tracked by PSI.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PsiResource {
    /// CPU stalls — tasks waiting to run.
    Cpu = 0,
    /// Memory stalls — tasks waiting on reclaim/swap.
    Memory = 1,
    /// I/O stalls — tasks waiting on block I/O.
    Io = 2,
}

impl PsiResource {
    /// Convert from index to resource type.
    pub fn from_index(idx: usize) -> Result<Self> {
        match idx {
            0 => Ok(Self::Cpu),
            1 => Ok(Self::Memory),
            2 => Ok(Self::Io),
            _ => Err(Error::InvalidArgument),
        }
    }

    /// Get the array index for this resource.
    pub const fn index(self) -> usize {
        self as usize
    }
}

// ══════════════════════════════════════════════════════════════
// PsiMetrics
// ══════════════════════════════════════════════════════════════

/// PSI metrics for a single resource within a cgroup.
///
/// Averages are stored as fixed-point percentages (× 100),
/// so a value of 1234 means 12.34%.
#[derive(Clone, Copy)]
pub struct PsiMetrics {
    /// 10-second EMA of "some" stall percentage (× 100).
    pub some_avg10: u32,
    /// 60-second EMA of "some" stall percentage (× 100).
    pub some_avg60: u32,
    /// 300-second EMA of "some" stall percentage (× 100).
    pub some_avg300: u32,
    /// 10-second EMA of "full" stall percentage (× 100).
    pub full_avg10: u32,
    /// 60-second EMA of "full" stall percentage (× 100).
    pub full_avg60: u32,
    /// 300-second EMA of "full" stall percentage (× 100).
    pub full_avg300: u32,
    /// Cumulative total stall time (microseconds).
    pub total_us: u64,
    /// Last sample timestamp (for interval computation).
    pub last_sample_tick: u64,
    /// Stall time accumulated since last average update.
    pub some_stall_us: u64,
    /// Full stall time accumulated since last update.
    pub full_stall_us: u64,
    /// Elapsed time since last average update (microseconds).
    pub sample_window_us: u64,
}

impl PsiMetrics {
    /// Create zeroed PSI metrics.
    pub const fn new() -> Self {
        Self {
            some_avg10: 0,
            some_avg60: 0,
            some_avg300: 0,
            full_avg10: 0,
            full_avg60: 0,
            full_avg300: 0,
            total_us: 0,
            last_sample_tick: 0,
            some_stall_us: 0,
            full_stall_us: 0,
            sample_window_us: 0,
        }
    }

    /// Record a stall event.
    pub fn record_stall(&mut self, duration_us: u64, is_full: bool) {
        self.some_stall_us += duration_us;
        if is_full {
            self.full_stall_us += duration_us;
        }
        self.total_us += duration_us;
    }

    /// Compute EMA averages given the elapsed window.
    ///
    /// Call this periodically (e.g., every 2 seconds) to update
    /// the exponential moving averages.
    pub fn compute_averages(&mut self, window_us: u64) {
        if window_us == 0 {
            return;
        }
        self.sample_window_us = window_us;

        // Compute instantaneous percentage (× 100) for this window.
        let some_pct = (self.some_stall_us * 100 * 100)
            .checked_div(window_us)
            .unwrap_or(0) as u32;
        let full_pct = (self.full_stall_us * 100 * 100)
            .checked_div(window_us)
            .unwrap_or(0) as u32;

        // Update EMAs for each time window.
        self.some_avg10 = ema_update(self.some_avg10, some_pct, EMA_10S_DECAY);
        self.some_avg60 = ema_update(self.some_avg60, some_pct, EMA_60S_DECAY);
        self.some_avg300 = ema_update(self.some_avg300, some_pct, EMA_300S_DECAY);

        self.full_avg10 = ema_update(self.full_avg10, full_pct, EMA_10S_DECAY);
        self.full_avg60 = ema_update(self.full_avg60, full_pct, EMA_60S_DECAY);
        self.full_avg300 = ema_update(self.full_avg300, full_pct, EMA_300S_DECAY);

        // Reset accumulators.
        self.some_stall_us = 0;
        self.full_stall_us = 0;
    }

    /// Get the current pressure level based on 10s average.
    pub fn pressure_level(&self) -> PressureLevel {
        let max_some = self.some_avg10;
        PressureLevel::from_percentage(max_some)
    }
}

impl Default for PsiMetrics {
    fn default() -> Self {
        Self::new()
    }
}

/// Exponential moving average update.
///
/// `prev` is the previous EMA value, `sample` is the new data point,
/// `decay` is the decay factor numerator (over `EMA_SCALE`).
fn ema_update(prev: u32, sample: u32, decay: u32) -> u32 {
    // EMA = decay * prev + (1 - decay) * sample
    let weighted_prev = (prev as u64 * decay as u64) / EMA_SCALE as u64;
    let weighted_sample = (sample as u64 * (EMA_SCALE - decay) as u64) / EMA_SCALE as u64;
    (weighted_prev + weighted_sample) as u32
}

// ══════════════════════════════════════════════════════════════
// EventWatcher
// ══════════════════════════════════════════════════════════════

/// A subscription to cgroup events.
#[derive(Clone, Copy)]
pub struct EventWatcher {
    /// Unique watcher ID.
    pub watcher_id: u32,
    /// PID of the subscribing process.
    pub subscriber_pid: u64,
    /// Event types this watcher is interested in (bitmask).
    pub event_mask: u32,
    /// Whether this watcher slot is active.
    pub active: bool,
}

impl EventWatcher {
    /// Create an empty watcher.
    pub const fn new() -> Self {
        Self {
            watcher_id: 0,
            subscriber_pid: 0,
            event_mask: 0,
            active: false,
        }
    }
}

impl Default for EventWatcher {
    fn default() -> Self {
        Self::new()
    }
}

/// Convert a cgroup event to its bitmask position.
const fn event_to_bit(event: CgroupEvent) -> u32 {
    match event {
        CgroupEvent::Populated => 1 << 0,
        CgroupEvent::Frozen => 1 << 1,
        CgroupEvent::ThresholdCrossed => 1 << 2,
        CgroupEvent::OomKill => 1 << 3,
        CgroupEvent::MaxExceeded => 1 << 4,
    }
}

// ══════════════════════════════════════════════════════════════
// EventRingEntry
// ══════════════════════════════════════════════════════════════

/// An entry in the event ring buffer.
#[derive(Clone, Copy)]
pub struct EventRingEntry {
    /// Cgroup ID that generated the event.
    pub cgroup_id: u32,
    /// Event type.
    pub event: CgroupEvent,
    /// Timestamp (tick) when the event was generated.
    pub timestamp: u64,
    /// Associated data (e.g., PID for OOM kill, threshold value).
    pub data: u64,
    /// Whether this slot is occupied.
    pub valid: bool,
}

impl EventRingEntry {
    /// Create an empty ring entry.
    pub const fn new() -> Self {
        Self {
            cgroup_id: 0,
            event: CgroupEvent::Populated,
            timestamp: 0,
            data: 0,
            valid: false,
        }
    }
}

impl Default for EventRingEntry {
    fn default() -> Self {
        Self::new()
    }
}

// ══════════════════════════════════════════════════════════════
// CgroupEventNotifier
// ══════════════════════════════════════════════════════════════

/// Event notification subsystem for cgroups.
///
/// Manages per-cgroup watcher subscriptions and a global event
/// ring buffer for event delivery.
pub struct CgroupEventNotifier {
    /// Per-cgroup watchers.
    pub watchers: [[EventWatcher; MAX_WATCHERS_PER_CG]; MAX_CGROUPS],
    /// Number of active watchers per cgroup.
    pub watcher_counts: [u8; MAX_CGROUPS],
    /// Event ring buffer.
    pub event_ring: [EventRingEntry; EVENT_RING_SIZE],
    /// Ring buffer head (write position).
    pub ring_head: usize,
    /// Ring buffer tail (read position).
    pub ring_tail: usize,
    /// Next watcher ID to assign.
    pub next_watcher_id: u32,
    /// Number of cgroups that are active.
    pub active_cgroups: u32,
}

impl CgroupEventNotifier {
    /// Create a new event notifier.
    pub const fn new() -> Self {
        Self {
            watchers: [[const { EventWatcher::new() }; MAX_WATCHERS_PER_CG]; MAX_CGROUPS],
            watcher_counts: [0u8; MAX_CGROUPS],
            event_ring: [const { EventRingEntry::new() }; EVENT_RING_SIZE],
            ring_head: 0,
            ring_tail: 0,
            next_watcher_id: 1,
            active_cgroups: 0,
        }
    }

    /// Subscribe to events for a cgroup.
    pub fn subscribe(
        &mut self,
        cgroup_id: u32,
        subscriber_pid: u64,
        event_mask: u32,
    ) -> Result<u32> {
        if cgroup_id as usize >= MAX_CGROUPS {
            return Err(Error::InvalidArgument);
        }
        let cg = cgroup_id as usize;
        let count = self.watcher_counts[cg] as usize;
        if count >= MAX_WATCHERS_PER_CG {
            return Err(Error::OutOfMemory);
        }

        let watcher_id = self.next_watcher_id;
        self.next_watcher_id += 1;

        self.watchers[cg][count] = EventWatcher {
            watcher_id,
            subscriber_pid,
            event_mask,
            active: true,
        };
        self.watcher_counts[cg] += 1;
        Ok(watcher_id)
    }

    /// Unsubscribe a watcher by its ID.
    pub fn unsubscribe(&mut self, cgroup_id: u32, watcher_id: u32) -> Result<()> {
        if cgroup_id as usize >= MAX_CGROUPS {
            return Err(Error::InvalidArgument);
        }
        let cg = cgroup_id as usize;
        let count = self.watcher_counts[cg] as usize;
        let pos = self.watchers[cg][..count]
            .iter()
            .position(|w| w.active && w.watcher_id == watcher_id);

        match pos {
            Some(idx) => {
                // Compact by shifting.
                let last = count - 1;
                if idx != last {
                    self.watchers[cg][idx] = self.watchers[cg][last];
                }
                self.watchers[cg][last] = EventWatcher::new();
                self.watcher_counts[cg] -= 1;
                Ok(())
            }
            None => Err(Error::NotFound),
        }
    }

    /// Notify watchers of an event in a cgroup.
    pub fn notify(
        &mut self,
        cgroup_id: u32,
        event: CgroupEvent,
        timestamp: u64,
        data: u64,
    ) -> Result<u32> {
        if cgroup_id as usize >= MAX_CGROUPS {
            return Err(Error::InvalidArgument);
        }

        // Add to event ring.
        self.event_ring[self.ring_head] = EventRingEntry {
            cgroup_id,
            event,
            timestamp,
            data,
            valid: true,
        };
        self.ring_head = (self.ring_head + 1) % EVENT_RING_SIZE;
        if self.ring_head == self.ring_tail {
            // Overwrite oldest.
            self.ring_tail = (self.ring_tail + 1) % EVENT_RING_SIZE;
        }

        // Count watchers that match.
        let cg = cgroup_id as usize;
        let count = self.watcher_counts[cg] as usize;
        let event_bit = event_to_bit(event);
        let mut notified = 0u32;
        for watcher in &self.watchers[cg][..count] {
            if watcher.active && (watcher.event_mask & event_bit) != 0 {
                notified += 1;
            }
        }
        Ok(notified)
    }

    /// Poll for pending events, returning up to `max_events`.
    pub fn poll_events(&mut self, out: &mut [EventRingEntry]) -> usize {
        let mut count = 0usize;
        while self.ring_tail != self.ring_head && count < out.len() {
            let entry = &self.event_ring[self.ring_tail];
            if entry.valid {
                out[count] = *entry;
                count += 1;
            }
            self.ring_tail = (self.ring_tail + 1) % EVENT_RING_SIZE;
        }
        count
    }

    /// Get the number of pending events.
    pub fn pending_count(&self) -> usize {
        if self.ring_head >= self.ring_tail {
            self.ring_head - self.ring_tail
        } else {
            EVENT_RING_SIZE - self.ring_tail + self.ring_head
        }
    }
}

impl Default for CgroupEventNotifier {
    fn default() -> Self {
        Self::new()
    }
}

// ══════════════════════════════════════════════════════════════
// PsiCollector
// ══════════════════════════════════════════════════════════════

/// Per-cgroup PSI metrics collector.
///
/// Tracks pressure stall information for each resource type
/// across all cgroups.
pub struct PsiCollector {
    /// Per-cgroup, per-resource PSI metrics.
    pub metrics: [[PsiMetrics; NUM_PSI_RESOURCES]; MAX_CGROUPS],
    /// Number of active cgroups being tracked.
    pub active_count: u32,
    /// Total PSI update cycles.
    pub update_count: u64,
}

impl PsiCollector {
    /// Create a new PSI collector.
    pub const fn new() -> Self {
        Self {
            metrics: [[const { PsiMetrics::new() }; NUM_PSI_RESOURCES]; MAX_CGROUPS],
            active_count: 0,
            update_count: 0,
        }
    }

    /// Record a resource stall for a cgroup.
    pub fn record_stall(
        &mut self,
        cgroup_id: u32,
        resource: PsiResource,
        duration_us: u64,
        is_full: bool,
    ) -> Result<()> {
        if cgroup_id as usize >= MAX_CGROUPS {
            return Err(Error::InvalidArgument);
        }
        let cg = cgroup_id as usize;
        let res = resource.index();
        self.metrics[cg][res].record_stall(duration_us, is_full);
        Ok(())
    }

    /// Compute averages for all cgroups and resources.
    pub fn compute_all_averages(&mut self, window_us: u64) {
        self.update_count += 1;
        for cg in 0..MAX_CGROUPS {
            for res in 0..NUM_PSI_RESOURCES {
                self.metrics[cg][res].compute_averages(window_us);
            }
        }
    }

    /// Compute averages for a single cgroup.
    pub fn compute_cgroup_averages(&mut self, cgroup_id: u32, window_us: u64) -> Result<()> {
        if cgroup_id as usize >= MAX_CGROUPS {
            return Err(Error::InvalidArgument);
        }
        self.update_count += 1;
        let cg = cgroup_id as usize;
        for res in 0..NUM_PSI_RESOURCES {
            self.metrics[cg][res].compute_averages(window_us);
        }
        Ok(())
    }

    /// Get PSI metrics for a specific cgroup and resource.
    pub fn get_psi(&self, cgroup_id: u32, resource: PsiResource) -> Result<&PsiMetrics> {
        if cgroup_id as usize >= MAX_CGROUPS {
            return Err(Error::InvalidArgument);
        }
        Ok(&self.metrics[cgroup_id as usize][resource.index()])
    }

    /// Get the pressure level for a cgroup's resource.
    pub fn pressure_level(&self, cgroup_id: u32, resource: PsiResource) -> Result<PressureLevel> {
        let metrics = self.get_psi(cgroup_id, resource)?;
        Ok(metrics.pressure_level())
    }
}

impl Default for PsiCollector {
    fn default() -> Self {
        Self::new()
    }
}

// ══════════════════════════════════════════════════════════════
// CgroupEventStats
// ══════════════════════════════════════════════════════════════

/// Global statistics for the cgroup event subsystem.
#[derive(Clone, Copy)]
pub struct CgroupEventStats {
    /// Total events generated.
    pub total_events: u64,
    /// Total PSI update cycles.
    pub psi_updates: u64,
    /// Total OOM kills reported.
    pub oom_kills_reported: u64,
    /// Total threshold crossings.
    pub threshold_crossings: u64,
    /// Total watchers currently subscribed.
    pub active_watchers: u32,
    /// Total events dropped (ring overflow).
    pub events_dropped: u64,
}

impl CgroupEventStats {
    /// Create zeroed statistics.
    pub const fn new() -> Self {
        Self {
            total_events: 0,
            psi_updates: 0,
            oom_kills_reported: 0,
            threshold_crossings: 0,
            active_watchers: 0,
            events_dropped: 0,
        }
    }
}

impl Default for CgroupEventStats {
    fn default() -> Self {
        Self::new()
    }
}

// ══════════════════════════════════════════════════════════════
// CgroupEventSubsystem
// ══════════════════════════════════════════════════════════════

/// Top-level cgroup v2 event notification and PSI subsystem.
///
/// Combines the event notifier and PSI collector with global
/// statistics tracking.
pub struct CgroupEventSubsystem {
    /// Event notification engine.
    pub notifier: CgroupEventNotifier,
    /// PSI metrics collector.
    pub psi: PsiCollector,
    /// Global statistics.
    pub stats: CgroupEventStats,
    /// Whether the subsystem is initialized.
    pub initialized: bool,
}

impl CgroupEventSubsystem {
    /// Create a new cgroup event subsystem.
    pub const fn new() -> Self {
        Self {
            notifier: CgroupEventNotifier::new(),
            psi: PsiCollector::new(),
            stats: CgroupEventStats::new(),
            initialized: false,
        }
    }

    /// Initialize the subsystem.
    pub fn init(&mut self) -> Result<()> {
        if self.initialized {
            return Err(Error::AlreadyExists);
        }
        self.initialized = true;
        Ok(())
    }

    /// Subscribe to events for a cgroup.
    pub fn subscribe(
        &mut self,
        cgroup_id: u32,
        subscriber_pid: u64,
        event_mask: u32,
    ) -> Result<u32> {
        if !self.initialized {
            return Err(Error::InvalidArgument);
        }
        let watcher_id = self
            .notifier
            .subscribe(cgroup_id, subscriber_pid, event_mask)?;
        self.stats.active_watchers += 1;
        Ok(watcher_id)
    }

    /// Unsubscribe from events.
    pub fn unsubscribe(&mut self, cgroup_id: u32, watcher_id: u32) -> Result<()> {
        self.notifier.unsubscribe(cgroup_id, watcher_id)?;
        self.stats.active_watchers = self.stats.active_watchers.saturating_sub(1);
        Ok(())
    }

    /// Notify an event in a cgroup.
    pub fn notify(
        &mut self,
        cgroup_id: u32,
        event: CgroupEvent,
        timestamp: u64,
        data: u64,
    ) -> Result<u32> {
        if !self.initialized {
            return Err(Error::InvalidArgument);
        }
        self.stats.total_events += 1;

        match event {
            CgroupEvent::OomKill => {
                self.stats.oom_kills_reported += 1;
            }
            CgroupEvent::ThresholdCrossed => {
                self.stats.threshold_crossings += 1;
            }
            _ => {}
        }

        self.notifier.notify(cgroup_id, event, timestamp, data)
    }

    /// Record a PSI stall for a cgroup resource.
    pub fn record_psi_stall(
        &mut self,
        cgroup_id: u32,
        resource: PsiResource,
        duration_us: u64,
        is_full: bool,
    ) -> Result<()> {
        self.psi
            .record_stall(cgroup_id, resource, duration_us, is_full)
    }

    /// Update PSI averages for a cgroup.
    pub fn update_psi(&mut self, cgroup_id: u32, window_us: u64) -> Result<()> {
        self.stats.psi_updates += 1;
        self.psi.compute_cgroup_averages(cgroup_id, window_us)
    }

    /// Update PSI averages for all cgroups.
    pub fn update_all_psi(&mut self, window_us: u64) {
        self.stats.psi_updates += 1;
        self.psi.compute_all_averages(window_us);
    }

    /// Get PSI metrics for a cgroup resource.
    pub fn get_psi(&self, cgroup_id: u32, resource: PsiResource) -> Result<&PsiMetrics> {
        self.psi.get_psi(cgroup_id, resource)
    }

    /// Poll for pending events.
    pub fn poll_events(&mut self, out: &mut [EventRingEntry]) -> usize {
        self.notifier.poll_events(out)
    }

    /// Get global statistics.
    pub fn get_stats(&self) -> &CgroupEventStats {
        &self.stats
    }

    /// Reset all statistics.
    pub fn reset_stats(&mut self) {
        self.stats = CgroupEventStats::new();
    }
}

impl Default for CgroupEventSubsystem {
    fn default() -> Self {
        Self::new()
    }
}

/// Format PSI information for a cgroup resource into a buffer.
///
/// Writes a human-readable PSI summary matching the Linux
/// `/proc/pressure/*` format into `buf`.
pub fn format_psi(metrics: &PsiMetrics, buf: &mut [u8]) -> usize {
    // Format: "some avg10=X.XX avg60=X.XX avg300=X.XX total=N\n"
    //         "full avg10=X.XX avg60=X.XX avg300=X.XX total=N\n"
    let mut pos = 0usize;

    let header_some = b"some avg10=";
    let copy_len = header_some.len().min(buf.len() - pos);
    buf[pos..pos + copy_len].copy_from_slice(&header_some[..copy_len]);
    pos += copy_len;

    // Write some_avg10 as decimal.
    pos += write_fixed_decimal(&mut buf[pos..], metrics.some_avg10);

    if pos + 7 <= buf.len() {
        buf[pos..pos + 7].copy_from_slice(b" avg60=");
        pos += 7;
    }
    pos += write_fixed_decimal(&mut buf[pos..], metrics.some_avg60);

    if pos + 8 <= buf.len() {
        buf[pos..pos + 8].copy_from_slice(b" avg300=");
        pos += 8;
    }
    pos += write_fixed_decimal(&mut buf[pos..], metrics.some_avg300);

    if pos + 7 <= buf.len() {
        buf[pos..pos + 7].copy_from_slice(b" total=");
        pos += 7;
    }
    pos += write_u64(&mut buf[pos..], metrics.total_us);

    if pos < buf.len() {
        buf[pos] = b'\n';
        pos += 1;
    }

    pos
}

/// Write a fixed-point value (×100) as "X.XX" into a buffer.
fn write_fixed_decimal(buf: &mut [u8], value: u32) -> usize {
    if buf.is_empty() {
        return 0;
    }
    let integer = value / 100;
    let frac = value % 100;
    let mut pos = write_u32(buf, integer);
    if pos + 3 <= buf.len() {
        buf[pos] = b'.';
        buf[pos + 1] = b'0' + (frac / 10) as u8;
        buf[pos + 2] = b'0' + (frac % 10) as u8;
        pos += 3;
    }
    pos
}

/// Write a u32 as decimal digits into a buffer.
fn write_u32(buf: &mut [u8], value: u32) -> usize {
    if buf.is_empty() {
        return 0;
    }
    if value == 0 {
        buf[0] = b'0';
        return 1;
    }
    let mut tmp = [0u8; 10];
    let mut n = value;
    let mut len = 0;
    while n > 0 {
        tmp[len] = b'0' + (n % 10) as u8;
        n /= 10;
        len += 1;
    }
    let copy_len = len.min(buf.len());
    for i in 0..copy_len {
        buf[i] = tmp[len - 1 - i];
    }
    copy_len
}

/// Write a u64 as decimal digits into a buffer.
fn write_u64(buf: &mut [u8], value: u64) -> usize {
    if buf.is_empty() {
        return 0;
    }
    if value == 0 {
        buf[0] = b'0';
        return 1;
    }
    let mut tmp = [0u8; 20];
    let mut n = value;
    let mut len = 0;
    while n > 0 {
        tmp[len] = b'0' + (n % 10) as u8;
        n /= 10;
        len += 1;
    }
    let copy_len = len.min(buf.len());
    for i in 0..copy_len {
        buf[i] = tmp[len - 1 - i];
    }
    copy_len
}
