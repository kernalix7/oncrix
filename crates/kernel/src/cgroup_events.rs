// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Cgroup event notifications.
//!
//! Provides an event notification mechanism for cgroup controllers.
//! User-space applications can register interest in specific cgroup
//! events (e.g., memory threshold crossings, PID limit hits) and
//! receive notifications via eventfd or poll.
//!
//! # Supported Events
//!
//! - **MemoryThreshold** — memory usage crossed a configured limit.
//! - **MemoryOom** — OOM killer was invoked in the cgroup.
//! - **PidMax** — PID count reached the configured maximum.
//! - **Frozen** — cgroup was frozen/thawed.
//! - **Populated** — cgroup became populated or empty.
//!
//! # Architecture
//!
//! ```text
//! CgroupEventManager
//!  ├── registrations: [EventRegistration; MAX_REGS]
//!  ├── events: [CgroupEvent; MAX_EVENTS] (ring buffer)
//!  └── stats: EventStats
//! ```

use oncrix_lib::{Error, Result};

// ======================================================================
// Constants
// ======================================================================

/// Maximum event registrations.
const MAX_REGISTRATIONS: usize = 256;

/// Maximum buffered events.
const MAX_EVENTS: usize = 512;

// ======================================================================
// Types
// ======================================================================

/// Type of cgroup event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CgroupEventType {
    /// Memory usage crossed a threshold.
    MemoryThreshold,
    /// OOM killer invoked.
    MemoryOom,
    /// PID count reached maximum.
    PidMax,
    /// Cgroup was frozen.
    Frozen,
    /// Cgroup was thawed.
    Thawed,
    /// Cgroup became populated (has tasks).
    Populated,
    /// Cgroup became empty (no tasks).
    Empty,
    /// IO latency threshold exceeded.
    IoLatency,
}

impl Default for CgroupEventType {
    fn default() -> Self {
        Self::Populated
    }
}

/// An event registration by user space.
#[derive(Debug, Clone, Copy)]
pub struct EventRegistration {
    /// Registration identifier.
    pub reg_id: u64,
    /// Cgroup identifier being watched.
    pub cgroup_id: u64,
    /// Event type to watch for.
    pub event_type: CgroupEventType,
    /// Eventfd file descriptor number for notification.
    pub eventfd: u32,
    /// Threshold value (for threshold-type events).
    pub threshold: u64,
    /// PID of the registering process.
    pub owner_pid: u64,
    /// Whether this registration is active.
    pub active: bool,
}

impl EventRegistration {
    /// Creates an empty registration.
    pub const fn new() -> Self {
        Self {
            reg_id: 0,
            cgroup_id: 0,
            event_type: CgroupEventType::Populated,
            eventfd: 0,
            threshold: 0,
            owner_pid: 0,
            active: false,
        }
    }
}

impl Default for EventRegistration {
    fn default() -> Self {
        Self::new()
    }
}

/// A buffered cgroup event.
#[derive(Debug, Clone, Copy)]
pub struct CgroupEvent {
    /// Cgroup identifier.
    pub cgroup_id: u64,
    /// Event type.
    pub event_type: CgroupEventType,
    /// Associated value (usage, count, etc.).
    pub value: u64,
    /// Timestamp (tick).
    pub timestamp: u64,
    /// Whether this slot is occupied.
    pub active: bool,
}

impl CgroupEvent {
    /// Creates an empty event.
    pub const fn new() -> Self {
        Self {
            cgroup_id: 0,
            event_type: CgroupEventType::Populated,
            value: 0,
            timestamp: 0,
            active: false,
        }
    }
}

impl Default for CgroupEvent {
    fn default() -> Self {
        Self::new()
    }
}

/// Event notification statistics.
#[derive(Debug, Clone, Copy)]
pub struct EventStats {
    /// Total events generated.
    pub events_generated: u64,
    /// Events delivered (matched a registration).
    pub events_delivered: u64,
    /// Events dropped (buffer full).
    pub events_dropped: u64,
    /// Active registrations.
    pub active_registrations: u32,
}

impl EventStats {
    /// Creates zeroed statistics.
    pub const fn new() -> Self {
        Self {
            events_generated: 0,
            events_delivered: 0,
            events_dropped: 0,
            active_registrations: 0,
        }
    }
}

impl Default for EventStats {
    fn default() -> Self {
        Self::new()
    }
}

/// Manages cgroup event registrations and delivery.
pub struct CgroupEventManager {
    /// Event registrations.
    registrations: [EventRegistration; MAX_REGISTRATIONS],
    /// Number of active registrations.
    nr_registrations: usize,
    /// Next registration ID.
    next_reg_id: u64,
    /// Event ring buffer.
    events: [CgroupEvent; MAX_EVENTS],
    /// Write position in the ring buffer.
    write_pos: usize,
    /// Number of buffered events.
    nr_events: usize,
    /// Statistics.
    stats: EventStats,
}

impl CgroupEventManager {
    /// Creates a new cgroup event manager.
    pub const fn new() -> Self {
        Self {
            registrations: [EventRegistration::new(); MAX_REGISTRATIONS],
            nr_registrations: 0,
            next_reg_id: 1,
            events: [CgroupEvent::new(); MAX_EVENTS],
            write_pos: 0,
            nr_events: 0,
            stats: EventStats::new(),
        }
    }

    /// Registers interest in a cgroup event.
    pub fn register(
        &mut self,
        cgroup_id: u64,
        event_type: CgroupEventType,
        eventfd: u32,
        threshold: u64,
        owner_pid: u64,
    ) -> Result<u64> {
        if self.nr_registrations >= MAX_REGISTRATIONS {
            return Err(Error::OutOfMemory);
        }
        let reg_id = self.next_reg_id;
        self.next_reg_id += 1;

        for reg in &mut self.registrations {
            if !reg.active {
                *reg = EventRegistration {
                    reg_id,
                    cgroup_id,
                    event_type,
                    eventfd,
                    threshold,
                    owner_pid,
                    active: true,
                };
                self.nr_registrations += 1;
                self.stats.active_registrations = self.nr_registrations as u32;
                return Ok(reg_id);
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Unregisters an event notification.
    pub fn unregister(&mut self, reg_id: u64) -> Result<()> {
        let idx = self
            .registrations
            .iter()
            .position(|r| r.active && r.reg_id == reg_id)
            .ok_or(Error::NotFound)?;
        self.registrations[idx].active = false;
        self.nr_registrations = self.nr_registrations.saturating_sub(1);
        self.stats.active_registrations = self.nr_registrations as u32;
        Ok(())
    }

    /// Generates a cgroup event.
    ///
    /// Returns the number of registrations that match (and would
    /// be notified).
    pub fn generate_event(
        &mut self,
        cgroup_id: u64,
        event_type: CgroupEventType,
        value: u64,
        timestamp: u64,
    ) -> u32 {
        self.stats.events_generated += 1;

        // Buffer the event.
        if self.nr_events < MAX_EVENTS {
            self.events[self.write_pos] = CgroupEvent {
                cgroup_id,
                event_type,
                value,
                timestamp,
                active: true,
            };
            self.write_pos = (self.write_pos + 1) % MAX_EVENTS;
            self.nr_events += 1;
        } else {
            self.stats.events_dropped += 1;
        }

        // Count matching registrations.
        let mut matches = 0u32;
        for reg in &self.registrations {
            if !reg.active {
                continue;
            }
            if reg.cgroup_id != cgroup_id {
                continue;
            }
            if reg.event_type != event_type {
                continue;
            }
            // For threshold events, check the value.
            if reg.threshold > 0 && value < reg.threshold {
                continue;
            }
            matches += 1;
            self.stats.events_delivered += 1;
        }
        matches
    }

    /// Drains all events for a specific cgroup.
    pub fn drain_events(&mut self, cgroup_id: u64) -> u32 {
        let mut drained = 0u32;
        for event in &mut self.events {
            if event.active && event.cgroup_id == cgroup_id {
                event.active = false;
                self.nr_events = self.nr_events.saturating_sub(1);
                drained += 1;
            }
        }
        drained
    }

    /// Returns the number of buffered events.
    pub fn nr_events(&self) -> usize {
        self.nr_events
    }

    /// Returns the number of active registrations.
    pub fn nr_registrations(&self) -> usize {
        self.nr_registrations
    }

    /// Returns statistics.
    pub fn stats(&self) -> &EventStats {
        &self.stats
    }
}

impl Default for CgroupEventManager {
    fn default() -> Self {
        Self::new()
    }
}
