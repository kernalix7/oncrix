// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Memory cgroup event notification.
//!
//! Provides an event mechanism for memory cgroups. Watchers can register
//! to be notified when a cgroup's memory usage crosses a threshold, when
//! OOM is triggered, or when pressure state changes. This powers the
//! `memory.events` and `cgroup.events` cgroupfs files.
//!
//! # Design
//!
//! ```text
//!  memcg state change (charge, uncharge, OOM)
//!       │
//!       ▼
//!  MemcgEventEmitter::emit(cgroup_id, event_type)
//!       │
//!       ├─ for each registered listener:
//!       │     if matches cgroup + type → deliver
//!       │
//!       └─ update event counters
//! ```
//!
//! # Key Types
//!
//! - [`MemcgEventType`] — types of cgroup memory events
//! - [`MemcgEventListener`] — a registered event listener
//! - [`MemcgEventEmitter`] — the event dispatch system
//! - [`MemcgEventCounters`] — per-cgroup event counters
//!
//! Reference: Linux `mm/memcontrol.c` (`memory.events`).

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Maximum listeners.
const MAX_LISTENERS: usize = 128;

/// Maximum cgroups tracked for event counters.
const MAX_CGROUPS: usize = 256;

/// Number of event types.
const NUM_EVENT_TYPES: usize = 8;

// -------------------------------------------------------------------
// MemcgEventType
// -------------------------------------------------------------------

/// Types of memory cgroup events.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(usize)]
pub enum MemcgEventType {
    /// Usage crossed the low watermark.
    Low = 0,
    /// Usage crossed the high watermark.
    High = 1,
    /// Usage hit the max limit.
    Max = 2,
    /// OOM was triggered.
    Oom = 3,
    /// OOM kill occurred.
    OomKill = 4,
    /// OOM group kill occurred.
    OomGroupKill = 5,
    /// Swap max limit reached.
    SwapMax = 6,
    /// Swap high limit reached.
    SwapHigh = 7,
}

impl MemcgEventType {
    /// Return the event name.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::High => "high",
            Self::Max => "max",
            Self::Oom => "oom",
            Self::OomKill => "oom_kill",
            Self::OomGroupKill => "oom_group_kill",
            Self::SwapMax => "swap_max",
            Self::SwapHigh => "swap_high",
        }
    }

    /// Return the index.
    pub const fn index(&self) -> usize {
        *self as usize
    }
}

// -------------------------------------------------------------------
// MemcgEventRecord
// -------------------------------------------------------------------

/// A single event occurrence.
#[derive(Debug, Clone, Copy)]
pub struct MemcgEventRecord {
    /// Cgroup that generated the event.
    pub cgroup_id: u32,
    /// Event type.
    pub event_type: MemcgEventType,
    /// Timestamp (monotonic tick).
    pub timestamp: u64,
    /// Additional data (e.g., PID killed for OOM).
    pub data: u64,
}

impl MemcgEventRecord {
    /// Create a new record.
    pub const fn new(cgroup_id: u32, event_type: MemcgEventType, timestamp: u64) -> Self {
        Self {
            cgroup_id,
            event_type,
            timestamp,
            data: 0,
        }
    }

    /// Create a record with additional data.
    pub const fn with_data(
        cgroup_id: u32,
        event_type: MemcgEventType,
        timestamp: u64,
        data: u64,
    ) -> Self {
        Self {
            cgroup_id,
            event_type,
            timestamp,
            data,
        }
    }
}

// -------------------------------------------------------------------
// MemcgEventListener
// -------------------------------------------------------------------

/// A registered event listener.
#[derive(Debug, Clone, Copy)]
pub struct MemcgEventListener {
    /// Listener identifier.
    listener_id: u32,
    /// Cgroup to watch (0 = all cgroups).
    cgroup_filter: u32,
    /// Event type filter (bitmask of event type indices).
    type_filter: u32,
    /// Whether this listener is active.
    active: bool,
    /// Events delivered to this listener.
    delivered: u64,
}

impl MemcgEventListener {
    /// Create a new listener for all events on a cgroup.
    pub const fn new(listener_id: u32, cgroup_filter: u32) -> Self {
        Self {
            listener_id,
            cgroup_filter,
            type_filter: u32::MAX, // all types
            active: true,
            delivered: 0,
        }
    }

    /// Create a listener with a type filter.
    pub const fn with_filter(listener_id: u32, cgroup_filter: u32, type_filter: u32) -> Self {
        Self {
            listener_id,
            cgroup_filter,
            type_filter,
            active: true,
            delivered: 0,
        }
    }

    /// Return the listener ID.
    pub const fn listener_id(&self) -> u32 {
        self.listener_id
    }

    /// Return the cgroup filter.
    pub const fn cgroup_filter(&self) -> u32 {
        self.cgroup_filter
    }

    /// Check whether this listener matches an event.
    pub fn matches(&self, cgroup_id: u32, event_type: MemcgEventType) -> bool {
        if !self.active {
            return false;
        }
        let cgroup_match = self.cgroup_filter == 0 || self.cgroup_filter == cgroup_id;
        let type_match = (self.type_filter & (1 << event_type.index())) != 0;
        cgroup_match && type_match
    }

    /// Record event delivery.
    pub fn record_delivery(&mut self) {
        self.delivered += 1;
    }

    /// Return delivered count.
    pub const fn delivered(&self) -> u64 {
        self.delivered
    }

    /// Deactivate.
    pub fn deactivate(&mut self) {
        self.active = false;
    }

    /// Check whether active.
    pub const fn is_active(&self) -> bool {
        self.active
    }
}

impl Default for MemcgEventListener {
    fn default() -> Self {
        Self::new(0, 0)
    }
}

// -------------------------------------------------------------------
// MemcgEventCounters
// -------------------------------------------------------------------

/// Per-cgroup cumulative event counters.
#[derive(Debug, Clone, Copy)]
pub struct MemcgEventCounters {
    /// Cgroup identifier.
    cgroup_id: u32,
    /// Per-type event counts.
    counts: [u64; NUM_EVENT_TYPES],
    /// Whether active.
    active: bool,
}

impl MemcgEventCounters {
    /// Create new counters.
    pub const fn new(cgroup_id: u32) -> Self {
        Self {
            cgroup_id,
            counts: [0u64; NUM_EVENT_TYPES],
            active: true,
        }
    }

    /// Return the cgroup ID.
    pub const fn cgroup_id(&self) -> u32 {
        self.cgroup_id
    }

    /// Read a counter.
    pub fn read(&self, event_type: MemcgEventType) -> u64 {
        self.counts[event_type.index()]
    }

    /// Increment a counter.
    pub fn increment(&mut self, event_type: MemcgEventType) {
        self.counts[event_type.index()] += 1;
    }

    /// Return the total OOM kills.
    pub fn oom_kills(&self) -> u64 {
        self.counts[MemcgEventType::OomKill.index()]
    }

    /// Whether active.
    pub const fn is_active(&self) -> bool {
        self.active
    }

    /// Deactivate.
    pub fn deactivate(&mut self) {
        self.active = false;
    }
}

impl Default for MemcgEventCounters {
    fn default() -> Self {
        Self::new(0)
    }
}

// -------------------------------------------------------------------
// MemcgEventEmitter
// -------------------------------------------------------------------

/// Event dispatch system for memory cgroups.
pub struct MemcgEventEmitter {
    /// Registered listeners.
    listeners: [MemcgEventListener; MAX_LISTENERS],
    /// Number of registered listeners.
    listener_count: usize,
    /// Per-cgroup event counters.
    counters: [MemcgEventCounters; MAX_CGROUPS],
    /// Number of cgroups tracked.
    cgroup_count: usize,
    /// Global timestamp counter.
    timestamp: u64,
    /// Total events emitted.
    total_emitted: u64,
}

impl MemcgEventEmitter {
    /// Create a new emitter.
    pub const fn new() -> Self {
        Self {
            listeners: [const { MemcgEventListener::new(0, 0) }; MAX_LISTENERS],
            listener_count: 0,
            counters: [const { MemcgEventCounters::new(0) }; MAX_CGROUPS],
            cgroup_count: 0,
            timestamp: 0,
            total_emitted: 0,
        }
    }

    /// Register a cgroup for event counting.
    pub fn register_cgroup(&mut self, cgroup_id: u32) -> Result<()> {
        if self.cgroup_count >= MAX_CGROUPS {
            return Err(Error::OutOfMemory);
        }
        self.counters[self.cgroup_count] = MemcgEventCounters::new(cgroup_id);
        self.cgroup_count += 1;
        Ok(())
    }

    /// Register a listener.
    pub fn register_listener(&mut self, listener: MemcgEventListener) -> Result<()> {
        if self.listener_count >= MAX_LISTENERS {
            return Err(Error::OutOfMemory);
        }
        self.listeners[self.listener_count] = listener;
        self.listener_count += 1;
        Ok(())
    }

    /// Unregister a listener by ID.
    pub fn unregister_listener(&mut self, listener_id: u32) -> Result<()> {
        for idx in 0..self.listener_count {
            if self.listeners[idx].listener_id() == listener_id {
                self.listeners[idx].deactivate();
                return Ok(());
            }
        }
        Err(Error::NotFound)
    }

    /// Emit an event.
    pub fn emit(&mut self, cgroup_id: u32, event_type: MemcgEventType) -> usize {
        self.timestamp += 1;
        self.total_emitted += 1;

        // Update per-cgroup counters.
        for idx in 0..self.cgroup_count {
            if self.counters[idx].cgroup_id() == cgroup_id && self.counters[idx].is_active() {
                self.counters[idx].increment(event_type);
                break;
            }
        }

        // Notify listeners.
        let mut notified = 0usize;
        for idx in 0..self.listener_count {
            if self.listeners[idx].matches(cgroup_id, event_type) {
                self.listeners[idx].record_delivery();
                notified += 1;
            }
        }
        notified
    }

    /// Read event counters for a cgroup.
    pub fn read_counters(&self, cgroup_id: u32) -> Option<&MemcgEventCounters> {
        for idx in 0..self.cgroup_count {
            if self.counters[idx].cgroup_id() == cgroup_id && self.counters[idx].is_active() {
                return Some(&self.counters[idx]);
            }
        }
        None
    }

    /// Return total events emitted.
    pub const fn total_emitted(&self) -> u64 {
        self.total_emitted
    }

    /// Return listener count.
    pub const fn listener_count(&self) -> usize {
        self.listener_count
    }
}

impl Default for MemcgEventEmitter {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// Public helpers
// -------------------------------------------------------------------

/// Emit an OOM kill event for a cgroup.
pub fn emit_oom_kill(emitter: &mut MemcgEventEmitter, cgroup_id: u32) -> usize {
    emitter.emit(cgroup_id, MemcgEventType::OomKill)
}

/// Emit a high watermark event.
pub fn emit_high(emitter: &mut MemcgEventEmitter, cgroup_id: u32) -> usize {
    emitter.emit(cgroup_id, MemcgEventType::High)
}

/// Return a summary of emitter state.
pub fn emitter_summary(emitter: &MemcgEventEmitter) -> &'static str {
    if emitter.total_emitted() == 0 {
        "memcg events: idle"
    } else {
        "memcg events: active"
    }
}
