// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Memory pressure notification framework.
//!
//! Monitors system-wide and per-cgroup memory pressure and notifies
//! registered watchers when pressure thresholds are crossed. This
//! enables user-space daemons and kernel subsystems to proactively
//! free caches and reduce memory footprint before OOM is triggered.
//!
//! # Design
//!
//! ```text
//!  Memory allocators
//!       │
//!       ▼
//!  PressureMonitor::update(free, total)
//!       │
//!       ├─ level=None  → no action
//!       ├─ level=Low   → notify watchers (advisory)
//!       ├─ level=Medium→ notify + suggest reclaim
//!       └─ level=Critical → notify + trigger emergency reclaim
//! ```
//!
//! # Key Types
//!
//! - [`PressureLevel`] — severity levels
//! - [`PressureWatcher`] — a registered callback descriptor
//! - [`PressureMonitor`] — the main monitor
//! - [`PressureEvent`] — emitted when level changes
//!
//! Reference: Linux `include/linux/memcontrol.h`, PSI (`pressure.c`).

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Maximum registered watchers.
const MAX_WATCHERS: usize = 64;

/// Low pressure threshold (percent of total memory free).
const LOW_THRESHOLD_PCT: u64 = 20;

/// Medium pressure threshold.
const MEDIUM_THRESHOLD_PCT: u64 = 10;

/// Critical pressure threshold.
const CRITICAL_THRESHOLD_PCT: u64 = 5;

// -------------------------------------------------------------------
// PressureLevel
// -------------------------------------------------------------------

/// Severity level of memory pressure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum PressureLevel {
    /// No pressure — free memory is abundant.
    None,
    /// Low pressure — some reclaim recommended.
    Low,
    /// Medium pressure — active reclaim needed.
    Medium,
    /// Critical — near OOM, emergency measures.
    Critical,
}

impl PressureLevel {
    /// Return a human-readable name.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::Critical => "critical",
        }
    }
}

impl Default for PressureLevel {
    fn default() -> Self {
        Self::None
    }
}

// -------------------------------------------------------------------
// PressureEvent
// -------------------------------------------------------------------

/// An event emitted when the pressure level changes.
#[derive(Debug, Clone, Copy)]
pub struct PressureEvent {
    /// Previous level.
    pub prev_level: PressureLevel,
    /// New level.
    pub new_level: PressureLevel,
    /// Current free pages.
    pub free_pages: u64,
    /// Total pages.
    pub total_pages: u64,
    /// Timestamp (tick).
    pub timestamp: u64,
}

impl PressureEvent {
    /// Create a new event.
    pub const fn new(
        prev_level: PressureLevel,
        new_level: PressureLevel,
        free_pages: u64,
        total_pages: u64,
        timestamp: u64,
    ) -> Self {
        Self {
            prev_level,
            new_level,
            free_pages,
            total_pages,
            timestamp,
        }
    }

    /// Check whether pressure is increasing.
    pub fn is_escalating(&self) -> bool {
        self.new_level > self.prev_level
    }
}

// -------------------------------------------------------------------
// PressureWatcher
// -------------------------------------------------------------------

/// Minimum level a watcher is interested in.
#[derive(Debug, Clone, Copy)]
pub struct PressureWatcher {
    /// Watcher identifier.
    watcher_id: u32,
    /// Minimum level to trigger notification.
    min_level: PressureLevel,
    /// Whether this watcher is active.
    active: bool,
    /// Count of events delivered to this watcher.
    event_count: u64,
}

impl PressureWatcher {
    /// Create a new watcher.
    pub const fn new(watcher_id: u32, min_level: PressureLevel) -> Self {
        Self {
            watcher_id,
            min_level,
            active: true,
            event_count: 0,
        }
    }

    /// Return the watcher ID.
    pub const fn watcher_id(&self) -> u32 {
        self.watcher_id
    }

    /// Return the minimum level.
    pub const fn min_level(&self) -> PressureLevel {
        self.min_level
    }

    /// Check whether this watcher is active.
    pub const fn is_active(&self) -> bool {
        self.active
    }

    /// Deactivate this watcher.
    pub fn deactivate(&mut self) {
        self.active = false;
    }

    /// Return events delivered count.
    pub const fn event_count(&self) -> u64 {
        self.event_count
    }

    /// Deliver an event if the level meets the threshold.
    pub fn maybe_notify(&mut self, level: PressureLevel) -> bool {
        if self.active && level >= self.min_level {
            self.event_count += 1;
            return true;
        }
        false
    }
}

impl Default for PressureWatcher {
    fn default() -> Self {
        Self::new(0, PressureLevel::Low)
    }
}

// -------------------------------------------------------------------
// PressureMonitor
// -------------------------------------------------------------------

/// The memory pressure monitor.
pub struct PressureMonitor {
    /// Registered watchers.
    watchers: [PressureWatcher; MAX_WATCHERS],
    /// Number of registered watchers.
    watcher_count: usize,
    /// Current pressure level.
    current_level: PressureLevel,
    /// Total events emitted.
    total_events: u64,
    /// Current timestamp.
    timestamp: u64,
    /// Custom thresholds (low, medium, critical) as percent.
    thresholds: [u64; 3],
}

impl PressureMonitor {
    /// Create a new monitor with default thresholds.
    pub const fn new() -> Self {
        Self {
            watchers: [const { PressureWatcher::new(0, PressureLevel::Low) }; MAX_WATCHERS],
            watcher_count: 0,
            current_level: PressureLevel::None,
            total_events: 0,
            timestamp: 0,
            thresholds: [
                LOW_THRESHOLD_PCT,
                MEDIUM_THRESHOLD_PCT,
                CRITICAL_THRESHOLD_PCT,
            ],
        }
    }

    /// Return the current pressure level.
    pub const fn level(&self) -> PressureLevel {
        self.current_level
    }

    /// Return total events emitted.
    pub const fn total_events(&self) -> u64 {
        self.total_events
    }

    /// Return the number of registered watchers.
    pub const fn watcher_count(&self) -> usize {
        self.watcher_count
    }

    /// Register a new watcher.
    pub fn register(&mut self, watcher_id: u32, min_level: PressureLevel) -> Result<()> {
        if self.watcher_count >= MAX_WATCHERS {
            return Err(Error::OutOfMemory);
        }
        self.watchers[self.watcher_count] = PressureWatcher::new(watcher_id, min_level);
        self.watcher_count += 1;
        Ok(())
    }

    /// Unregister a watcher by ID.
    pub fn unregister(&mut self, watcher_id: u32) -> Result<()> {
        for idx in 0..self.watcher_count {
            if self.watchers[idx].watcher_id() == watcher_id {
                self.watchers[idx].deactivate();
                return Ok(());
            }
        }
        Err(Error::NotFound)
    }

    /// Compute the pressure level from free/total pages.
    fn compute_level(&self, free: u64, total: u64) -> PressureLevel {
        if total == 0 {
            return PressureLevel::Critical;
        }
        let free_pct = free * 100 / total;
        if free_pct <= self.thresholds[2] {
            PressureLevel::Critical
        } else if free_pct <= self.thresholds[1] {
            PressureLevel::Medium
        } else if free_pct <= self.thresholds[0] {
            PressureLevel::Low
        } else {
            PressureLevel::None
        }
    }

    /// Update with current memory state. Returns an event if level changed.
    pub fn update(&mut self, free_pages: u64, total_pages: u64) -> Option<PressureEvent> {
        self.timestamp += 1;
        let new_level = self.compute_level(free_pages, total_pages);

        if new_level == self.current_level {
            return None;
        }

        let event = PressureEvent::new(
            self.current_level,
            new_level,
            free_pages,
            total_pages,
            self.timestamp,
        );
        self.current_level = new_level;
        self.total_events += 1;

        // Notify watchers.
        for idx in 0..self.watcher_count {
            self.watchers[idx].maybe_notify(new_level);
        }

        Some(event)
    }

    /// Set custom thresholds.
    pub fn set_thresholds(
        &mut self,
        low_pct: u64,
        medium_pct: u64,
        critical_pct: u64,
    ) -> Result<()> {
        if low_pct <= medium_pct || medium_pct <= critical_pct {
            return Err(Error::InvalidArgument);
        }
        self.thresholds = [low_pct, medium_pct, critical_pct];
        Ok(())
    }
}

impl Default for PressureMonitor {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// Public helpers
// -------------------------------------------------------------------

/// Check the current pressure level for given memory state.
pub fn check_pressure(free_pages: u64, total_pages: u64) -> PressureLevel {
    let monitor = PressureMonitor::new();
    monitor.compute_level(free_pages, total_pages)
}

/// Return whether emergency reclaim should be triggered.
pub fn needs_emergency_reclaim(free_pages: u64, total_pages: u64) -> bool {
    check_pressure(free_pages, total_pages) == PressureLevel::Critical
}

/// Format pressure level as a status string.
pub fn pressure_status(level: PressureLevel) -> &'static str {
    match level {
        PressureLevel::None => "memory pressure: none (healthy)",
        PressureLevel::Low => "memory pressure: low (reclaim advised)",
        PressureLevel::Medium => "memory pressure: medium (active reclaim)",
        PressureLevel::Critical => "memory pressure: critical (emergency)",
    }
}
