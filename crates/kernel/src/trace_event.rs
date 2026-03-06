// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Trace event infrastructure.
//!
//! Provides the core infrastructure for defining, registering, and
//! emitting trace events. Trace events are lightweight instrumentation
//! points that can be enabled/disabled at runtime with minimal overhead
//! when disabled. Used by ftrace, perf, and BPF subsystems.

use oncrix_lib::{Error, Result};

// ── Constants ────────────────────────────────────────────────────────

/// Maximum number of registered trace events.
const MAX_TRACE_EVENTS: usize = 512;

/// Maximum number of trace event subsystems.
const MAX_SUBSYSTEMS: usize = 32;

/// Maximum event data fields.
const MAX_FIELDS: usize = 16;

/// Maximum event name length.
const MAX_NAME_LEN: usize = 48;

/// Trace ring buffer size (number of entries).
const RING_BUFFER_SIZE: usize = 1024;

// ── Types ────────────────────────────────────────────────────────────

/// Identifies a trace event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TraceEventId(u32);

impl TraceEventId {
    /// Creates a new trace event identifier.
    pub const fn new(id: u32) -> Self {
        Self(id)
    }

    /// Returns the raw identifier.
    pub const fn as_u32(self) -> u32 {
        self.0
    }
}

/// Identifies a trace subsystem.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SubsystemId(u16);

impl SubsystemId {
    /// Creates a new subsystem identifier.
    pub const fn new(id: u16) -> Self {
        Self(id)
    }

    /// Returns the raw identifier.
    pub const fn as_u16(self) -> u16 {
        self.0
    }
}

/// Field type in a trace event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FieldType {
    /// Unsigned 8-bit integer.
    U8,
    /// Unsigned 16-bit integer.
    U16,
    /// Unsigned 32-bit integer.
    U32,
    /// Unsigned 64-bit integer.
    U64,
    /// Signed 32-bit integer.
    I32,
    /// Signed 64-bit integer.
    I64,
    /// Fixed-size string.
    String,
}

/// A field definition within a trace event.
#[derive(Debug, Clone)]
pub struct TraceEventField {
    /// Field name.
    name: [u8; 32],
    /// Name length.
    name_len: usize,
    /// Field type.
    field_type: FieldType,
    /// Offset within the event data.
    offset: u16,
    /// Size of this field.
    size: u16,
}

impl TraceEventField {
    /// Creates a new field definition.
    pub const fn new(field_type: FieldType, offset: u16, size: u16) -> Self {
        Self {
            name: [0u8; 32],
            name_len: 0,
            field_type,
            offset,
            size,
        }
    }

    /// Returns the field type.
    pub const fn field_type(&self) -> FieldType {
        self.field_type
    }

    /// Returns the field offset.
    pub const fn offset(&self) -> u16 {
        self.offset
    }
}

/// A registered trace event definition.
#[derive(Debug)]
pub struct TraceEventDef {
    /// Event identifier.
    id: TraceEventId,
    /// Subsystem this event belongs to.
    subsystem_id: SubsystemId,
    /// Event name.
    name: [u8; MAX_NAME_LEN],
    /// Name length.
    name_len: usize,
    /// Field definitions.
    fields: [Option<TraceEventField>; MAX_FIELDS],
    /// Number of fields.
    field_count: usize,
    /// Whether this event is enabled.
    enabled: bool,
    /// Total emissions.
    emission_count: u64,
    /// Number of times this event was filtered out.
    filtered_count: u64,
}

impl TraceEventDef {
    /// Creates a new trace event definition.
    pub const fn new(id: TraceEventId, subsystem_id: SubsystemId) -> Self {
        Self {
            id,
            subsystem_id,
            name: [0u8; MAX_NAME_LEN],
            name_len: 0,
            fields: [const { None }; MAX_FIELDS],
            field_count: 0,
            enabled: false,
            emission_count: 0,
            filtered_count: 0,
        }
    }

    /// Returns the event identifier.
    pub const fn id(&self) -> TraceEventId {
        self.id
    }

    /// Returns whether the event is enabled.
    pub const fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Returns the emission count.
    pub const fn emission_count(&self) -> u64 {
        self.emission_count
    }
}

/// A trace subsystem grouping related events.
#[derive(Debug)]
pub struct TraceSubsystem {
    /// Subsystem identifier.
    id: SubsystemId,
    /// Subsystem name.
    name: [u8; 32],
    /// Name length.
    name_len: usize,
    /// Number of events in this subsystem.
    event_count: u32,
    /// Whether the subsystem is enabled.
    enabled: bool,
}

impl TraceSubsystem {
    /// Creates a new trace subsystem.
    pub const fn new(id: SubsystemId) -> Self {
        Self {
            id,
            name: [0u8; 32],
            name_len: 0,
            event_count: 0,
            enabled: true,
        }
    }

    /// Returns whether the subsystem is enabled.
    pub const fn is_enabled(&self) -> bool {
        self.enabled
    }
}

/// An emitted trace event entry in the ring buffer.
#[derive(Debug, Clone)]
pub struct TraceEntry {
    /// Event identifier.
    event_id: TraceEventId,
    /// Timestamp in nanoseconds.
    timestamp_ns: u64,
    /// CPU that emitted the event.
    cpu: u32,
    /// PID of the emitting task.
    pid: u64,
    /// Event-specific data (first 64 bytes).
    data: [u8; 64],
    /// Data length.
    data_len: usize,
}

impl TraceEntry {
    /// Creates a new trace entry.
    pub const fn new(event_id: TraceEventId, cpu: u32, pid: u64, timestamp_ns: u64) -> Self {
        Self {
            event_id,
            timestamp_ns,
            cpu,
            pid,
            data: [0u8; 64],
            data_len: 0,
        }
    }

    /// Returns the event identifier.
    pub const fn event_id(&self) -> TraceEventId {
        self.event_id
    }

    /// Returns the timestamp.
    pub const fn timestamp_ns(&self) -> u64 {
        self.timestamp_ns
    }
}

/// Trace event subsystem statistics.
#[derive(Debug, Clone)]
pub struct TraceEventStats {
    /// Total registered events.
    pub total_events: u32,
    /// Enabled events.
    pub enabled_events: u32,
    /// Total emissions across all events.
    pub total_emissions: u64,
    /// Total filtered emissions.
    pub total_filtered: u64,
    /// Number of subsystems.
    pub subsystem_count: u32,
    /// Ring buffer entries used.
    pub ring_buffer_used: u32,
}

impl Default for TraceEventStats {
    fn default() -> Self {
        Self::new()
    }
}

impl TraceEventStats {
    /// Creates zeroed statistics.
    pub const fn new() -> Self {
        Self {
            total_events: 0,
            enabled_events: 0,
            total_emissions: 0,
            total_filtered: 0,
            subsystem_count: 0,
            ring_buffer_used: 0,
        }
    }
}

/// Central trace event manager.
#[derive(Debug)]
pub struct TraceEventManager {
    /// Registered event definitions.
    events: [Option<TraceEventDef>; MAX_TRACE_EVENTS],
    /// Subsystems.
    subsystems: [Option<TraceSubsystem>; MAX_SUBSYSTEMS],
    /// Ring buffer of emitted events.
    ring_buffer: [Option<TraceEntry>; RING_BUFFER_SIZE],
    /// Ring buffer write position.
    ring_pos: usize,
    /// Number of registered events.
    event_count: usize,
    /// Number of subsystems.
    subsystem_count: usize,
    /// Next event identifier.
    next_event_id: u32,
    /// Next subsystem identifier.
    next_subsystem_id: u16,
    /// Ring buffer entries used.
    ring_used: usize,
}

impl Default for TraceEventManager {
    fn default() -> Self {
        Self::new()
    }
}

impl TraceEventManager {
    /// Creates a new trace event manager.
    pub const fn new() -> Self {
        Self {
            events: [const { None }; MAX_TRACE_EVENTS],
            subsystems: [const { None }; MAX_SUBSYSTEMS],
            ring_buffer: [const { None }; RING_BUFFER_SIZE],
            ring_pos: 0,
            event_count: 0,
            subsystem_count: 0,
            next_event_id: 1,
            next_subsystem_id: 1,
            ring_used: 0,
        }
    }

    /// Registers a new trace subsystem.
    pub fn register_subsystem(&mut self) -> Result<SubsystemId> {
        if self.subsystem_count >= MAX_SUBSYSTEMS {
            return Err(Error::OutOfMemory);
        }
        let id = SubsystemId::new(self.next_subsystem_id);
        self.next_subsystem_id += 1;
        let subsystem = TraceSubsystem::new(id);
        if let Some(slot) = self.subsystems.iter_mut().find(|s| s.is_none()) {
            *slot = Some(subsystem);
            self.subsystem_count += 1;
            Ok(id)
        } else {
            Err(Error::OutOfMemory)
        }
    }

    /// Registers a new trace event.
    pub fn register_event(&mut self, subsystem_id: SubsystemId) -> Result<TraceEventId> {
        if self.event_count >= MAX_TRACE_EVENTS {
            return Err(Error::OutOfMemory);
        }
        let id = TraceEventId::new(self.next_event_id);
        self.next_event_id += 1;
        let event = TraceEventDef::new(id, subsystem_id);
        if let Some(slot) = self.events.iter_mut().find(|s| s.is_none()) {
            *slot = Some(event);
            self.event_count += 1;
            // Increment subsystem event count.
            if let Some(sub) = self
                .subsystems
                .iter_mut()
                .flatten()
                .find(|s| s.id == subsystem_id)
            {
                sub.event_count += 1;
            }
            Ok(id)
        } else {
            Err(Error::OutOfMemory)
        }
    }

    /// Enables a trace event.
    pub fn enable_event(&mut self, event_id: TraceEventId) -> Result<()> {
        let event = self
            .events
            .iter_mut()
            .flatten()
            .find(|e| e.id == event_id)
            .ok_or(Error::NotFound)?;
        event.enabled = true;
        Ok(())
    }

    /// Disables a trace event.
    pub fn disable_event(&mut self, event_id: TraceEventId) -> Result<()> {
        let event = self
            .events
            .iter_mut()
            .flatten()
            .find(|e| e.id == event_id)
            .ok_or(Error::NotFound)?;
        event.enabled = false;
        Ok(())
    }

    /// Emits a trace event.
    pub fn emit(
        &mut self,
        event_id: TraceEventId,
        cpu: u32,
        pid: u64,
        timestamp_ns: u64,
        data: &[u8],
    ) -> Result<()> {
        let event = self
            .events
            .iter_mut()
            .flatten()
            .find(|e| e.id == event_id)
            .ok_or(Error::NotFound)?;
        if !event.enabled {
            event.filtered_count += 1;
            return Ok(());
        }
        event.emission_count += 1;
        let mut entry = TraceEntry::new(event_id, cpu, pid, timestamp_ns);
        let copy_len = data.len().min(64);
        entry.data[..copy_len].copy_from_slice(&data[..copy_len]);
        entry.data_len = copy_len;
        self.ring_buffer[self.ring_pos] = Some(entry);
        self.ring_pos = (self.ring_pos + 1) % RING_BUFFER_SIZE;
        if self.ring_used < RING_BUFFER_SIZE {
            self.ring_used += 1;
        }
        Ok(())
    }

    /// Clears the trace ring buffer.
    pub fn clear_ring_buffer(&mut self) {
        for slot in self.ring_buffer.iter_mut() {
            *slot = None;
        }
        self.ring_pos = 0;
        self.ring_used = 0;
    }

    /// Returns statistics.
    pub fn stats(&self) -> TraceEventStats {
        let mut s = TraceEventStats::new();
        s.total_events = self.event_count as u32;
        s.subsystem_count = self.subsystem_count as u32;
        s.ring_buffer_used = self.ring_used as u32;
        for event in self.events.iter().flatten() {
            if event.enabled {
                s.enabled_events += 1;
            }
            s.total_emissions += event.emission_count;
            s.total_filtered += event.filtered_count;
        }
        s
    }

    /// Returns the number of registered events.
    pub const fn event_count(&self) -> usize {
        self.event_count
    }
}
