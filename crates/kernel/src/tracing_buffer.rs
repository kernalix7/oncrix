// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Tracing buffer — high-level trace data management.
//!
//! Provides the trace buffer infrastructure that sits above the ring
//! buffer. Manages trace instances, buffer sizing, snapshot buffers,
//! and trace output formatting (binary/text).
//!
//! # Architecture
//!
//! ```text
//! TracingBufferManager
//!  ├── instances[MAX_INSTANCES]
//!  │    ├── id, name
//!  │    ├── buffer_size_kb, entries_written
//!  │    ├── format: TraceFormat
//!  │    └── state: InstanceState
//!  └── stats: TracingStats
//! ```
//!
//! # Reference
//!
//! Linux `kernel/trace/trace.c`.

use oncrix_lib::{Error, Result};

// ══════════════════════════════════════════════════════════════
// Constants
// ══════════════════════════════════════════════════════════════

/// Maximum trace instances.
const MAX_INSTANCES: usize = 16;

/// Maximum instance name length.
const MAX_NAME_LEN: usize = 32;

/// Default buffer size in KB per CPU.
const DEFAULT_BUFFER_SIZE_KB: u32 = 1408;

/// Minimum buffer size in KB.
const MIN_BUFFER_SIZE_KB: u32 = 4;

// ══════════════════════════════════════════════════════════════
// TraceFormat
// ══════════════════════════════════════════════════════════════

/// Output format for trace data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum TraceFormat {
    /// Human-readable text format.
    Text = 0,
    /// Binary format (for perf/trace-cmd).
    Binary = 1,
    /// Raw format (minimal processing).
    Raw = 2,
}

// ══════════════════════════════════════════════════════════════
// InstanceState
// ══════════════════════════════════════════════════════════════

/// State of a trace instance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum InstanceState {
    /// Slot is free.
    Free = 0,
    /// Instance is created but tracing is off.
    Inactive = 1,
    /// Tracing is active.
    Active = 2,
    /// Instance is being torn down.
    Destroying = 3,
}

// ══════════════════════════════════════════════════════════════
// TraceInstance
// ══════════════════════════════════════════════════════════════

/// A trace buffer instance.
#[derive(Clone, Copy)]
pub struct TraceInstance {
    /// Instance identifier.
    pub id: u32,
    /// Instance name.
    pub name: [u8; MAX_NAME_LEN],
    /// Name length.
    pub name_len: usize,
    /// Per-CPU buffer size in KB.
    pub buffer_size_kb: u32,
    /// Total entries written.
    pub entries_written: u64,
    /// Entries overwritten (ring buffer wrap).
    pub entries_overwritten: u64,
    /// Output format.
    pub format: TraceFormat,
    /// Current state.
    pub state: InstanceState,
    /// Whether a snapshot buffer exists.
    pub has_snapshot: bool,
    /// Snapshot entries count.
    pub snapshot_entries: u64,
    /// Whether timestamps are absolute or relative.
    pub absolute_timestamps: bool,
}

impl TraceInstance {
    /// Create a free instance slot.
    const fn empty() -> Self {
        Self {
            id: 0,
            name: [0u8; MAX_NAME_LEN],
            name_len: 0,
            buffer_size_kb: DEFAULT_BUFFER_SIZE_KB,
            entries_written: 0,
            entries_overwritten: 0,
            format: TraceFormat::Text,
            state: InstanceState::Free,
            has_snapshot: false,
            snapshot_entries: 0,
            absolute_timestamps: false,
        }
    }

    /// Returns `true` if the instance is usable.
    pub const fn is_live(&self) -> bool {
        matches!(self.state, InstanceState::Inactive | InstanceState::Active)
    }
}

// ══════════════════════════════════════════════════════════════
// TracingStats
// ══════════════════════════════════════════════════════════════

/// Global tracing statistics.
#[derive(Debug, Clone, Copy)]
pub struct TracingStats {
    /// Total instances created.
    pub instances_created: u64,
    /// Total instances destroyed.
    pub instances_destroyed: u64,
    /// Total entries across all instances.
    pub total_entries: u64,
    /// Total snapshots taken.
    pub total_snapshots: u64,
}

impl TracingStats {
    /// Create zeroed stats.
    const fn new() -> Self {
        Self {
            instances_created: 0,
            instances_destroyed: 0,
            total_entries: 0,
            total_snapshots: 0,
        }
    }
}

// ══════════════════════════════════════════════════════════════
// TracingBufferManager
// ══════════════════════════════════════════════════════════════

/// Manages trace buffer instances.
pub struct TracingBufferManager {
    /// Trace instances.
    instances: [TraceInstance; MAX_INSTANCES],
    /// Next instance ID.
    next_id: u32,
    /// Statistics.
    stats: TracingStats,
}

impl TracingBufferManager {
    /// Create a new tracing buffer manager.
    pub const fn new() -> Self {
        Self {
            instances: [const { TraceInstance::empty() }; MAX_INSTANCES],
            next_id: 1,
            stats: TracingStats::new(),
        }
    }

    /// Create a new trace instance.
    pub fn create_instance(&mut self, name: &[u8], buffer_size_kb: u32) -> Result<u32> {
        if name.is_empty() || name.len() > MAX_NAME_LEN {
            return Err(Error::InvalidArgument);
        }
        if buffer_size_kb < MIN_BUFFER_SIZE_KB {
            return Err(Error::InvalidArgument);
        }
        let slot = self
            .instances
            .iter()
            .position(|i| matches!(i.state, InstanceState::Free))
            .ok_or(Error::OutOfMemory)?;
        let id = self.next_id;
        self.next_id += 1;
        let inst = &mut self.instances[slot];
        inst.id = id;
        inst.name[..name.len()].copy_from_slice(name);
        inst.name_len = name.len();
        inst.buffer_size_kb = buffer_size_kb;
        inst.state = InstanceState::Inactive;
        self.stats.instances_created += 1;
        Ok(id)
    }

    /// Start tracing on an instance.
    pub fn start(&mut self, id: u32) -> Result<()> {
        let slot = self.find_instance(id)?;
        self.instances[slot].state = InstanceState::Active;
        Ok(())
    }

    /// Stop tracing on an instance.
    pub fn stop(&mut self, id: u32) -> Result<()> {
        let slot = self.find_instance(id)?;
        self.instances[slot].state = InstanceState::Inactive;
        Ok(())
    }

    /// Record a trace entry.
    pub fn record_entry(&mut self, id: u32) -> Result<()> {
        let slot = self.find_instance(id)?;
        if !matches!(self.instances[slot].state, InstanceState::Active) {
            return Err(Error::InvalidArgument);
        }
        self.instances[slot].entries_written += 1;
        self.stats.total_entries += 1;
        Ok(())
    }

    /// Take a snapshot of the current buffer contents.
    pub fn take_snapshot(&mut self, id: u32) -> Result<()> {
        let slot = self.find_instance(id)?;
        self.instances[slot].has_snapshot = true;
        self.instances[slot].snapshot_entries = self.instances[slot].entries_written;
        self.stats.total_snapshots += 1;
        Ok(())
    }

    /// Set the output format for an instance.
    pub fn set_format(&mut self, id: u32, format: TraceFormat) -> Result<()> {
        let slot = self.find_instance(id)?;
        self.instances[slot].format = format;
        Ok(())
    }

    /// Resize the per-CPU buffer.
    pub fn resize_buffer(&mut self, id: u32, size_kb: u32) -> Result<()> {
        if size_kb < MIN_BUFFER_SIZE_KB {
            return Err(Error::InvalidArgument);
        }
        let slot = self.find_instance(id)?;
        self.instances[slot].buffer_size_kb = size_kb;
        Ok(())
    }

    /// Destroy a trace instance.
    pub fn destroy(&mut self, id: u32) -> Result<()> {
        let slot = self.find_instance(id)?;
        self.instances[slot] = TraceInstance::empty();
        self.stats.instances_destroyed += 1;
        Ok(())
    }

    /// Return instance info.
    pub fn get(&self, id: u32) -> Result<&TraceInstance> {
        let slot = self.find_instance(id)?;
        Ok(&self.instances[slot])
    }

    /// Return statistics.
    pub fn stats(&self) -> TracingStats {
        self.stats
    }

    // ── Internal ─────────────────────────────────────────────

    fn find_instance(&self, id: u32) -> Result<usize> {
        self.instances
            .iter()
            .position(|i| i.is_live() && i.id == id)
            .ok_or(Error::NotFound)
    }
}
