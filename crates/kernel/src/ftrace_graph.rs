// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Function graph tracer — tracing function entry and exit with timing.
//!
//! The function graph tracer hooks function prologues and epilogues to
//! record call graphs with precise timing information.  This enables
//! performance analysis of code paths and identification of latency
//! sources.
//!
//! # Architecture
//!
//! ```text
//! ┌──────────────────────────────────────────────────────────────┐
//! │                   FtraceGraphTracer                           │
//! │                                                              │
//! │  GraphEntry[0..MAX_ENTRIES]  (trace ring buffer)             │
//! │  ┌────────────────────────────────────────────────────────┐  │
//! │  │  func_addr: u64                                        │  │
//! │  │  call_time: u64                                        │  │
//! │  │  ret_time: u64                                         │  │
//! │  │  depth: u8                                             │  │
//! │  │  cpu: u16                                              │  │
//! │  └────────────────────────────────────────────────────────┘  │
//! │                                                              │
//! │  PerCpuGraph[0..MAX_CPUS]  (per-CPU state)                   │
//! └──────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Reference
//!
//! Linux `kernel/trace/trace_functions_graph.c`.

use oncrix_lib::{Error, Result};

// ══════════════════════════════════════════════════════════════
// Constants
// ══════════════════════════════════════════════════════════════

/// Maximum trace entries in the ring buffer.
const MAX_ENTRIES: usize = 4096;

/// Maximum CPUs.
const MAX_CPUS: usize = 64;

/// Maximum call depth tracked per CPU.
const MAX_DEPTH: usize = 32;

/// Maximum function filters.
const MAX_FILTERS: usize = 64;

// ══════════════════════════════════════════════════════════════
// EntryType
// ══════════════════════════════════════════════════════════════

/// Type of graph trace entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum EntryType {
    /// Function entry (call).
    Entry = 0,
    /// Function return.
    Return = 1,
    /// Leaf function (entry + return, no child calls).
    Leaf = 2,
}

// ══════════════════════════════════════════════════════════════
// GraphEntry
// ══════════════════════════════════════════════════════════════

/// A single function graph trace entry.
#[derive(Debug, Clone, Copy)]
pub struct GraphEntry {
    /// Function address.
    pub func_addr: u64,
    /// Timestamp at function entry.
    pub call_time: u64,
    /// Timestamp at function return (0 if not yet returned).
    pub ret_time: u64,
    /// Call depth when this function was entered.
    pub depth: u8,
    /// CPU on which the call occurred.
    pub cpu: u16,
    /// PID of the executing task.
    pub pid: u64,
    /// Entry type.
    pub entry_type: EntryType,
    /// Whether this entry is valid.
    pub valid: bool,
}

impl GraphEntry {
    const fn empty() -> Self {
        Self {
            func_addr: 0,
            call_time: 0,
            ret_time: 0,
            depth: 0,
            cpu: 0,
            pid: 0,
            entry_type: EntryType::Entry,
            valid: false,
        }
    }

    /// Return the duration of the function call (ret_time - call_time).
    pub const fn duration(&self) -> u64 {
        if self.ret_time > self.call_time {
            self.ret_time - self.call_time
        } else {
            0
        }
    }
}

// ══════════════════════════════════════════════════════════════
// PerCpuGraph — per-CPU call stack
// ══════════════════════════════════════════════════════════════

/// Per-CPU function graph state.
#[derive(Debug, Clone, Copy)]
pub struct PerCpuGraph {
    /// Call stack (function addresses at each depth).
    pub stack: [u64; MAX_DEPTH],
    /// Entry timestamps at each depth.
    pub timestamps: [u64; MAX_DEPTH],
    /// Current call depth.
    pub depth: usize,
    /// Whether tracing is active on this CPU.
    pub tracing: bool,
    /// Total entries recorded on this CPU.
    pub entry_count: u64,
}

impl PerCpuGraph {
    const fn new() -> Self {
        Self {
            stack: [0u64; MAX_DEPTH],
            timestamps: [0u64; MAX_DEPTH],
            depth: 0,
            tracing: false,
            entry_count: 0,
        }
    }
}

// ══════════════════════════════════════════════════════════════
// FtraceGraphStats
// ══════════════════════════════════════════════════════════════

/// Statistics for the function graph tracer.
#[derive(Debug, Clone, Copy)]
pub struct FtraceGraphStats {
    /// Total function entries recorded.
    pub total_entries: u64,
    /// Total function returns recorded.
    pub total_returns: u64,
    /// Total dropped entries (buffer full).
    pub total_dropped: u64,
    /// Maximum call depth observed.
    pub max_depth: u8,
    /// Maximum function duration observed (ticks).
    pub max_duration: u64,
}

impl FtraceGraphStats {
    const fn new() -> Self {
        Self {
            total_entries: 0,
            total_returns: 0,
            total_dropped: 0,
            max_depth: 0,
            max_duration: 0,
        }
    }
}

// ══════════════════════════════════════════════════════════════
// FunctionFilter
// ══════════════════════════════════════════════════════════════

/// A function filter for selective tracing.
#[derive(Debug, Clone, Copy)]
pub struct FunctionFilter {
    /// Function address to filter.
    pub func_addr: u64,
    /// Whether this filter is active.
    pub active: bool,
}

impl FunctionFilter {
    const fn empty() -> Self {
        Self {
            func_addr: 0,
            active: false,
        }
    }
}

// ══════════════════════════════════════════════════════════════
// FtraceGraphTracer
// ══════════════════════════════════════════════════════════════

/// Top-level function graph tracer.
pub struct FtraceGraphTracer {
    /// Trace ring buffer.
    entries: [GraphEntry; MAX_ENTRIES],
    /// Per-CPU state.
    per_cpu: [PerCpuGraph; MAX_CPUS],
    /// Function filters (empty = trace all).
    filters: [FunctionFilter; MAX_FILTERS],
    /// Statistics.
    stats: FtraceGraphStats,
    /// Write cursor.
    write_cursor: usize,
    /// Whether the tracer is enabled.
    enabled: bool,
    /// Whether the subsystem is initialised.
    initialised: bool,
    /// Maximum depth to trace (0 = unlimited).
    max_trace_depth: u8,
}

impl Default for FtraceGraphTracer {
    fn default() -> Self {
        Self::new()
    }
}

impl FtraceGraphTracer {
    /// Create a new function graph tracer.
    pub const fn new() -> Self {
        Self {
            entries: [const { GraphEntry::empty() }; MAX_ENTRIES],
            per_cpu: [const { PerCpuGraph::new() }; MAX_CPUS],
            filters: [const { FunctionFilter::empty() }; MAX_FILTERS],
            stats: FtraceGraphStats::new(),
            write_cursor: 0,
            enabled: false,
            initialised: false,
            max_trace_depth: 0,
        }
    }

    /// Initialise the tracer.
    pub fn init(&mut self) -> Result<()> {
        if self.initialised {
            return Err(Error::AlreadyExists);
        }
        self.initialised = true;
        Ok(())
    }

    /// Enable or disable the tracer.
    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }

    /// Set the maximum trace depth (0 = unlimited).
    pub fn set_max_depth(&mut self, depth: u8) {
        self.max_trace_depth = depth;
    }

    // ── Filter management ────────────────────────────────────

    /// Add a function filter.
    pub fn add_filter(&mut self, func_addr: u64) -> Result<()> {
        let slot = self
            .filters
            .iter()
            .position(|f| !f.active)
            .ok_or(Error::OutOfMemory)?;
        self.filters[slot] = FunctionFilter {
            func_addr,
            active: true,
        };
        Ok(())
    }

    /// Clear all filters.
    pub fn clear_filters(&mut self) {
        for filter in &mut self.filters {
            *filter = FunctionFilter::empty();
        }
    }

    // ── Tracing ──────────────────────────────────────────────

    /// Record a function entry.
    pub fn trace_entry(
        &mut self,
        cpu: usize,
        func_addr: u64,
        pid: u64,
        timestamp: u64,
    ) -> Result<()> {
        if !self.enabled || cpu >= MAX_CPUS {
            return Ok(());
        }

        // Check depth limit.
        let depth = self.per_cpu[cpu].depth;
        if self.max_trace_depth > 0 && (depth as u8) >= self.max_trace_depth {
            return Ok(());
        }

        // Push onto per-CPU stack.
        if depth < MAX_DEPTH {
            self.per_cpu[cpu].stack[depth] = func_addr;
            self.per_cpu[cpu].timestamps[depth] = timestamp;
            self.per_cpu[cpu].depth += 1;
        }

        // Record entry.
        let slot = self.write_cursor;
        self.write_cursor = (self.write_cursor + 1) % MAX_ENTRIES;

        self.entries[slot] = GraphEntry {
            func_addr,
            call_time: timestamp,
            ret_time: 0,
            depth: depth as u8,
            cpu: cpu as u16,
            pid,
            entry_type: EntryType::Entry,
            valid: true,
        };

        self.stats.total_entries += 1;
        self.per_cpu[cpu].entry_count += 1;

        if (depth as u8) > self.stats.max_depth {
            self.stats.max_depth = depth as u8;
        }

        Ok(())
    }

    /// Record a function return.
    pub fn trace_return(&mut self, cpu: usize, pid: u64, timestamp: u64) -> Result<()> {
        if !self.enabled || cpu >= MAX_CPUS {
            return Ok(());
        }

        let depth = self.per_cpu[cpu].depth;
        if depth == 0 {
            return Ok(());
        }

        let new_depth = depth - 1;
        let func_addr = self.per_cpu[cpu].stack[new_depth];
        let call_time = self.per_cpu[cpu].timestamps[new_depth];
        self.per_cpu[cpu].depth = new_depth;

        let slot = self.write_cursor;
        self.write_cursor = (self.write_cursor + 1) % MAX_ENTRIES;

        self.entries[slot] = GraphEntry {
            func_addr,
            call_time,
            ret_time: timestamp,
            depth: new_depth as u8,
            cpu: cpu as u16,
            pid,
            entry_type: EntryType::Return,
            valid: true,
        };

        let duration = timestamp.wrapping_sub(call_time);
        if duration > self.stats.max_duration {
            self.stats.max_duration = duration;
        }

        self.stats.total_returns += 1;
        Ok(())
    }

    /// Clear the trace buffer.
    pub fn clear(&mut self) {
        for entry in &mut self.entries {
            *entry = GraphEntry::empty();
        }
        for cpu in &mut self.per_cpu {
            cpu.depth = 0;
            cpu.entry_count = 0;
        }
        self.write_cursor = 0;
    }

    // ── Query ────────────────────────────────────────────────

    /// Return statistics.
    pub fn stats(&self) -> FtraceGraphStats {
        self.stats
    }

    /// Return the number of valid entries.
    pub fn entry_count(&self) -> usize {
        self.entries.iter().filter(|e| e.valid).count()
    }

    /// Return per-CPU state.
    pub fn cpu_state(&self, cpu: usize) -> Result<&PerCpuGraph> {
        if cpu >= MAX_CPUS {
            return Err(Error::InvalidArgument);
        }
        Ok(&self.per_cpu[cpu])
    }
}
