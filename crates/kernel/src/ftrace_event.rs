// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Ftrace event subsystem — structured trace event management.
//!
//! Manages the registration, enabling, and filtering of kernel trace
//! events. Events are categorised into systems (e.g., `sched`, `irq`,
//! `syscall`) and each event has a format descriptor and enable flag.
//!
//! # Architecture
//!
//! ```text
//! FtraceEventManager
//!  ├── events[MAX_EVENTS]
//!  │    ├── name, system, id
//!  │    ├── enabled, filter_active
//!  │    └── trigger_count
//!  ├── systems[MAX_SYSTEMS]
//!  └── stats: EventStats
//! ```
//!
//! # Reference
//!
//! Linux `kernel/trace/trace_events.c`.

use oncrix_lib::{Error, Result};

// ══════════════════════════════════════════════════════════════
// Constants
// ══════════════════════════════════════════════════════════════

/// Maximum registered trace events.
const MAX_EVENTS: usize = 512;

/// Maximum event systems (categories).
const MAX_SYSTEMS: usize = 32;

/// Maximum name length for events and systems.
const MAX_NAME_LEN: usize = 48;

// ══════════════════════════════════════════════════════════════
// EventSystem — trace event category
// ══════════════════════════════════════════════════════════════

/// A trace event system (category like "sched", "irq", etc.).
#[derive(Clone, Copy)]
pub struct EventSystem {
    /// System name (zero-padded).
    pub name: [u8; MAX_NAME_LEN],
    /// Name length.
    pub name_len: usize,
    /// Number of events in this system.
    pub event_count: u32,
    /// Whether all events in this system are enabled.
    pub all_enabled: bool,
    /// Whether this entry is active.
    pub active: bool,
}

impl EventSystem {
    /// Create an inactive system entry.
    const fn empty() -> Self {
        Self {
            name: [0u8; MAX_NAME_LEN],
            name_len: 0,
            event_count: 0,
            all_enabled: false,
            active: false,
        }
    }
}

// ══════════════════════════════════════════════════════════════
// TraceEvent — single event descriptor
// ══════════════════════════════════════════════════════════════

/// A single registered trace event.
#[derive(Clone, Copy)]
pub struct TraceEvent {
    /// Event name (zero-padded).
    pub name: [u8; MAX_NAME_LEN],
    /// Name length.
    pub name_len: usize,
    /// Unique event ID.
    pub id: u32,
    /// System index this event belongs to.
    pub system_idx: usize,
    /// Whether this event is enabled.
    pub enabled: bool,
    /// Whether a filter is active on this event.
    pub filter_active: bool,
    /// Number of times this event has been triggered.
    pub trigger_count: u64,
    /// Whether this entry is active.
    pub active: bool,
}

impl TraceEvent {
    /// Create an inactive event entry.
    const fn empty() -> Self {
        Self {
            name: [0u8; MAX_NAME_LEN],
            name_len: 0,
            id: 0,
            system_idx: 0,
            enabled: false,
            filter_active: false,
            trigger_count: 0,
            active: false,
        }
    }
}

// ══════════════════════════════════════════════════════════════
// EventStats
// ══════════════════════════════════════════════════════════════

/// Ftrace event subsystem statistics.
#[derive(Debug, Clone, Copy)]
pub struct EventStats {
    /// Total events registered.
    pub total_registered: u64,
    /// Total events enabled.
    pub total_enabled: u64,
    /// Total event triggers.
    pub total_triggers: u64,
    /// Total filter activations.
    pub total_filters: u64,
}

impl EventStats {
    /// Create zeroed stats.
    const fn new() -> Self {
        Self {
            total_registered: 0,
            total_enabled: 0,
            total_triggers: 0,
            total_filters: 0,
        }
    }
}

// ══════════════════════════════════════════════════════════════
// FtraceEventManager
// ══════════════════════════════════════════════════════════════

/// Manages kernel trace events.
pub struct FtraceEventManager {
    /// Registered events.
    events: [TraceEvent; MAX_EVENTS],
    /// Event systems (categories).
    systems: [EventSystem; MAX_SYSTEMS],
    /// Next event ID.
    next_id: u32,
    /// Statistics.
    stats: EventStats,
}

impl FtraceEventManager {
    /// Create a new ftrace event manager.
    pub const fn new() -> Self {
        Self {
            events: [const { TraceEvent::empty() }; MAX_EVENTS],
            systems: [const { EventSystem::empty() }; MAX_SYSTEMS],
            next_id: 1,
            stats: EventStats::new(),
        }
    }

    /// Register an event system (category).
    pub fn register_system(&mut self, name: &[u8]) -> Result<usize> {
        if name.is_empty() || name.len() > MAX_NAME_LEN {
            return Err(Error::InvalidArgument);
        }
        let slot = self
            .systems
            .iter()
            .position(|s| !s.active)
            .ok_or(Error::OutOfMemory)?;
        self.systems[slot].name[..name.len()].copy_from_slice(name);
        self.systems[slot].name_len = name.len();
        self.systems[slot].active = true;
        Ok(slot)
    }

    /// Register a trace event within a system.
    pub fn register_event(&mut self, name: &[u8], system_idx: usize) -> Result<u32> {
        if name.is_empty() || name.len() > MAX_NAME_LEN {
            return Err(Error::InvalidArgument);
        }
        if system_idx >= MAX_SYSTEMS || !self.systems[system_idx].active {
            return Err(Error::InvalidArgument);
        }
        let slot = self
            .events
            .iter()
            .position(|e| !e.active)
            .ok_or(Error::OutOfMemory)?;
        let id = self.next_id;
        self.next_id += 1;
        self.events[slot].name[..name.len()].copy_from_slice(name);
        self.events[slot].name_len = name.len();
        self.events[slot].id = id;
        self.events[slot].system_idx = system_idx;
        self.events[slot].active = true;
        self.systems[system_idx].event_count += 1;
        self.stats.total_registered += 1;
        Ok(id)
    }

    /// Enable a trace event by ID.
    pub fn enable_event(&mut self, event_id: u32) -> Result<()> {
        let slot = self.find_event(event_id)?;
        if !self.events[slot].enabled {
            self.events[slot].enabled = true;
            self.stats.total_enabled += 1;
        }
        Ok(())
    }

    /// Disable a trace event by ID.
    pub fn disable_event(&mut self, event_id: u32) -> Result<()> {
        let slot = self.find_event(event_id)?;
        self.events[slot].enabled = false;
        Ok(())
    }

    /// Enable all events in a system.
    pub fn enable_system(&mut self, system_idx: usize) -> Result<()> {
        if system_idx >= MAX_SYSTEMS || !self.systems[system_idx].active {
            return Err(Error::InvalidArgument);
        }
        for event in &mut self.events {
            if event.active && event.system_idx == system_idx && !event.enabled {
                event.enabled = true;
                self.stats.total_enabled += 1;
            }
        }
        self.systems[system_idx].all_enabled = true;
        Ok(())
    }

    /// Record a trigger for an event. Returns `true` if event is enabled.
    pub fn trigger(&mut self, event_id: u32) -> Result<bool> {
        let slot = self.find_event(event_id)?;
        if self.events[slot].enabled {
            self.events[slot].trigger_count += 1;
            self.stats.total_triggers += 1;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Set a filter on an event.
    pub fn set_filter(&mut self, event_id: u32, active: bool) -> Result<()> {
        let slot = self.find_event(event_id)?;
        self.events[slot].filter_active = active;
        if active {
            self.stats.total_filters += 1;
        }
        Ok(())
    }

    /// Return event info by ID.
    pub fn get_event(&self, event_id: u32) -> Result<&TraceEvent> {
        let slot = self.find_event(event_id)?;
        Ok(&self.events[slot])
    }

    /// Return statistics.
    pub fn stats(&self) -> EventStats {
        self.stats
    }

    // ── Internal ─────────────────────────────────────────────

    fn find_event(&self, event_id: u32) -> Result<usize> {
        self.events
            .iter()
            .position(|e| e.active && e.id == event_id)
            .ok_or(Error::NotFound)
    }
}
