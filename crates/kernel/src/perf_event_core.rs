// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Performance event core — hardware and software event monitoring.
//!
//! Manages perf_event instances that monitor CPU performance counters
//! (cycles, instructions, cache misses) and software events (context
//! switches, page faults, task migrations).
//!
//! # Architecture
//!
//! ```text
//! PerfEventManager
//!  ├── events[MAX_PERF_EVENTS]
//!  │    ├── event_id, event_type, config
//!  │    ├── count, enabled, running
//!  │    └── target_pid, target_cpu
//!  └── stats: PerfGlobalStats
//! ```
//!
//! # Reference
//!
//! Linux `kernel/events/core.c`.

use oncrix_lib::{Error, Result};

// ══════════════════════════════════════════════════════════════
// Constants
// ══════════════════════════════════════════════════════════════

/// Maximum active perf events.
const MAX_PERF_EVENTS: usize = 256;

// ══════════════════════════════════════════════════════════════
// PerfEventType
// ══════════════════════════════════════════════════════════════

/// Type of performance event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PerfEventType {
    /// Hardware counter (cycles, instructions, etc.).
    Hardware = 0,
    /// Software event (context switch, page fault, etc.).
    Software = 1,
    /// Tracepoint event.
    Tracepoint = 2,
    /// Hardware cache event.
    HwCache = 3,
    /// Raw PMU event.
    Raw = 4,
    /// Hardware breakpoint.
    Breakpoint = 5,
}

// ══════════════════════════════════════════════════════════════
// PerfEventState
// ══════════════════════════════════════════════════════════════

/// State of a perf event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PerfEventState {
    /// Slot is free.
    Free = 0,
    /// Event is created but inactive.
    Off = 1,
    /// Event is active (counting or sampling).
    Active = 2,
    /// Event encountered an error.
    Error = 3,
}

// ══════════════════════════════════════════════════════════════
// PerfEventEntry
// ══════════════════════════════════════════════════════════════

/// A single performance event.
#[derive(Debug, Clone, Copy)]
pub struct PerfEventEntry {
    /// Event identifier (unique).
    pub event_id: u64,
    /// Event type.
    pub event_type: PerfEventType,
    /// Hardware/software config selector.
    pub config: u64,
    /// Accumulated count.
    pub count: u64,
    /// Time the event has been enabled (ns).
    pub time_enabled: u64,
    /// Time the event has been running on a PMC (ns).
    pub time_running: u64,
    /// Target process (-1 = all).
    pub target_pid: i64,
    /// Target CPU (-1 = all).
    pub target_cpu: i32,
    /// Sample period (0 = counting mode).
    pub sample_period: u64,
    /// Number of overflows / samples generated.
    pub nr_samples: u64,
    /// Current state.
    pub state: PerfEventState,
    /// Whether this is an inherited event (follows fork).
    pub inherit: bool,
    /// Whether this event excludes kernel space.
    pub exclude_kernel: bool,
    /// Whether this event excludes user space.
    pub exclude_user: bool,
}

impl PerfEventEntry {
    /// Create a free entry.
    const fn empty() -> Self {
        Self {
            event_id: 0,
            event_type: PerfEventType::Hardware,
            config: 0,
            count: 0,
            time_enabled: 0,
            time_running: 0,
            target_pid: -1,
            target_cpu: -1,
            sample_period: 0,
            nr_samples: 0,
            state: PerfEventState::Free,
            inherit: false,
            exclude_kernel: false,
            exclude_user: false,
        }
    }
}

// ══════════════════════════════════════════════════════════════
// PerfGlobalStats
// ══════════════════════════════════════════════════════════════

/// Global perf subsystem statistics.
#[derive(Debug, Clone, Copy)]
pub struct PerfGlobalStats {
    /// Total events created.
    pub total_created: u64,
    /// Total events destroyed.
    pub total_destroyed: u64,
    /// Total events enabled.
    pub total_enabled: u64,
    /// Total samples generated.
    pub total_samples: u64,
}

impl PerfGlobalStats {
    /// Create zeroed stats.
    const fn new() -> Self {
        Self {
            total_created: 0,
            total_destroyed: 0,
            total_enabled: 0,
            total_samples: 0,
        }
    }
}

// ══════════════════════════════════════════════════════════════
// PerfEventManager
// ══════════════════════════════════════════════════════════════

/// Manages performance monitoring events.
pub struct PerfEventManager {
    /// Event table.
    events: [PerfEventEntry; MAX_PERF_EVENTS],
    /// Next event ID.
    next_id: u64,
    /// Statistics.
    stats: PerfGlobalStats,
}

impl PerfEventManager {
    /// Create a new perf event manager.
    pub const fn new() -> Self {
        Self {
            events: [const { PerfEventEntry::empty() }; MAX_PERF_EVENTS],
            next_id: 1,
            stats: PerfGlobalStats::new(),
        }
    }

    /// Create a new perf event.
    ///
    /// # Errors
    ///
    /// - `OutOfMemory` if no free slots.
    pub fn create_event(
        &mut self,
        event_type: PerfEventType,
        config: u64,
        target_pid: i64,
        target_cpu: i32,
        sample_period: u64,
    ) -> Result<u64> {
        let slot = self
            .events
            .iter()
            .position(|e| matches!(e.state, PerfEventState::Free))
            .ok_or(Error::OutOfMemory)?;
        let id = self.next_id;
        self.next_id += 1;
        self.events[slot] = PerfEventEntry {
            event_id: id,
            event_type,
            config,
            target_pid,
            target_cpu,
            sample_period,
            state: PerfEventState::Off,
            ..PerfEventEntry::empty()
        };
        self.stats.total_created += 1;
        Ok(id)
    }

    /// Enable a perf event.
    pub fn enable(&mut self, event_id: u64) -> Result<()> {
        let slot = self.find_event(event_id)?;
        self.events[slot].state = PerfEventState::Active;
        self.stats.total_enabled += 1;
        Ok(())
    }

    /// Disable a perf event.
    pub fn disable(&mut self, event_id: u64) -> Result<()> {
        let slot = self.find_event(event_id)?;
        self.events[slot].state = PerfEventState::Off;
        Ok(())
    }

    /// Read the current count of a perf event.
    pub fn read(&self, event_id: u64) -> Result<u64> {
        let slot = self.find_event(event_id)?;
        Ok(self.events[slot].count)
    }

    /// Increment the count (called from PMU overflow or sw event).
    pub fn increment(&mut self, event_id: u64, delta: u64) -> Result<()> {
        let slot = self.find_event(event_id)?;
        if !matches!(self.events[slot].state, PerfEventState::Active) {
            return Ok(());
        }
        self.events[slot].count += delta;
        if self.events[slot].sample_period > 0
            && self.events[slot].count >= self.events[slot].sample_period
        {
            self.events[slot].nr_samples += 1;
            self.stats.total_samples += 1;
            self.events[slot].count -= self.events[slot].sample_period;
        }
        Ok(())
    }

    /// Destroy a perf event.
    pub fn destroy(&mut self, event_id: u64) -> Result<()> {
        let slot = self.find_event(event_id)?;
        self.events[slot] = PerfEventEntry::empty();
        self.stats.total_destroyed += 1;
        Ok(())
    }

    /// Return event info.
    pub fn get(&self, event_id: u64) -> Result<&PerfEventEntry> {
        let slot = self.find_event(event_id)?;
        Ok(&self.events[slot])
    }

    /// Return statistics.
    pub fn stats(&self) -> PerfGlobalStats {
        self.stats
    }

    // ── Internal ─────────────────────────────────────────────

    fn find_event(&self, event_id: u64) -> Result<usize> {
        self.events
            .iter()
            .position(|e| !matches!(e.state, PerfEventState::Free) && e.event_id == event_id)
            .ok_or(Error::NotFound)
    }
}
