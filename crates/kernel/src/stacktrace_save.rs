// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Stack trace save — capturing and storing kernel stack traces.
//!
//! Provides mechanisms for capturing stack traces from arbitrary
//! kernel contexts (interrupt, process, panic) and storing them
//! for later analysis via /proc/stacktrace or crash dumps.
//!
//! # Architecture
//!
//! ```text
//! ┌──────────────────────────────────────────────────────────────┐
//! │                 StacktraceSaver                               │
//! │                                                              │
//! │  SavedTrace[0..MAX_SAVED_TRACES]  (stored traces)            │
//! │  ┌────────────────────────────────────────────────────────┐  │
//! │  │  pid: u64                                              │  │
//! │  │  cpu: u16                                              │  │
//! │  │  frames: [u64; MAX_FRAMES]                             │  │
//! │  │  frame_count: usize                                    │  │
//! │  │  context: TraceContext                                  │  │
//! │  └────────────────────────────────────────────────────────┘  │
//! └──────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Reference
//!
//! Linux `kernel/stacktrace.c`, `include/linux/stacktrace.h`.

use oncrix_lib::{Error, Result};

// ══════════════════════════════════════════════════════════════
// Constants
// ══════════════════════════════════════════════════════════════

/// Maximum stored traces.
const MAX_SAVED_TRACES: usize = 256;

/// Maximum frames per trace.
const MAX_FRAMES: usize = 32;

// ══════════════════════════════════════════════════════════════
// TraceContext
// ══════════════════════════════════════════════════════════════

/// Context in which a stack trace was captured.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum TraceContext {
    /// Normal process context.
    Process = 0,
    /// Interrupt context.
    Interrupt = 1,
    /// Softirq context.
    Softirq = 2,
    /// NMI context.
    Nmi = 3,
    /// Panic handler.
    Panic = 4,
    /// Oops/bug handler.
    Oops = 5,
}

impl TraceContext {
    /// Display name.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Process => "process",
            Self::Interrupt => "interrupt",
            Self::Softirq => "softirq",
            Self::Nmi => "nmi",
            Self::Panic => "panic",
            Self::Oops => "oops",
        }
    }
}

// ══════════════════════════════════════════════════════════════
// SavedTrace
// ══════════════════════════════════════════════════════════════

/// A saved stack trace.
#[derive(Debug, Clone, Copy)]
pub struct SavedTrace {
    /// PID of the task (0 for kernel / interrupt context).
    pub pid: u64,
    /// CPU on which the trace was captured.
    pub cpu: u16,
    /// Trace identifier.
    pub trace_id: u64,
    /// Frame addresses (instruction pointers).
    pub frames: [u64; MAX_FRAMES],
    /// Number of valid frames.
    pub frame_count: usize,
    /// Context of capture.
    pub context: TraceContext,
    /// Timestamp of capture (tick).
    pub timestamp: u64,
    /// Whether this slot is occupied.
    pub active: bool,
    /// Whether the trace was truncated (more frames existed).
    pub truncated: bool,
}

impl SavedTrace {
    /// Create an empty trace slot.
    const fn empty() -> Self {
        Self {
            pid: 0,
            cpu: 0,
            trace_id: 0,
            frames: [0u64; MAX_FRAMES],
            frame_count: 0,
            context: TraceContext::Process,
            timestamp: 0,
            active: false,
            truncated: false,
        }
    }
}

// ══════════════════════════════════════════════════════════════
// StacktraceStats
// ══════════════════════════════════════════════════════════════

/// Statistics for stack trace capture.
#[derive(Debug, Clone, Copy)]
pub struct StacktraceStats {
    /// Total traces captured.
    pub total_captured: u64,
    /// Total traces saved to storage.
    pub total_saved: u64,
    /// Total traces dropped (storage full).
    pub total_dropped: u64,
    /// Total truncated traces.
    pub total_truncated: u64,
    /// Total frames captured.
    pub total_frames: u64,
}

impl StacktraceStats {
    const fn new() -> Self {
        Self {
            total_captured: 0,
            total_saved: 0,
            total_dropped: 0,
            total_truncated: 0,
            total_frames: 0,
        }
    }
}

// ══════════════════════════════════════════════════════════════
// StacktraceSaver
// ══════════════════════════════════════════════════════════════

/// Top-level stack trace save subsystem.
pub struct StacktraceSaver {
    /// Stored traces.
    traces: [SavedTrace; MAX_SAVED_TRACES],
    /// Statistics.
    stats: StacktraceStats,
    /// Next trace ID.
    next_trace_id: u64,
    /// Write cursor (ring buffer index).
    write_cursor: usize,
    /// Whether the subsystem is initialised.
    initialised: bool,
    /// Whether to overwrite old traces when full.
    overwrite_on_full: bool,
}

impl Default for StacktraceSaver {
    fn default() -> Self {
        Self::new()
    }
}

impl StacktraceSaver {
    /// Create a new stacktrace saver.
    pub const fn new() -> Self {
        Self {
            traces: [const { SavedTrace::empty() }; MAX_SAVED_TRACES],
            stats: StacktraceStats::new(),
            next_trace_id: 1,
            write_cursor: 0,
            initialised: false,
            overwrite_on_full: true,
        }
    }

    /// Initialise the subsystem.
    pub fn init(&mut self) -> Result<()> {
        if self.initialised {
            return Err(Error::AlreadyExists);
        }
        self.initialised = true;
        Ok(())
    }

    /// Set whether to overwrite old traces when the buffer is full.
    pub fn set_overwrite(&mut self, overwrite: bool) {
        self.overwrite_on_full = overwrite;
    }

    // ── Capture ──────────────────────────────────────────────

    /// Save a stack trace.
    ///
    /// Returns the trace ID.
    pub fn save(
        &mut self,
        pid: u64,
        cpu: u16,
        frames: &[u64],
        context: TraceContext,
        timestamp: u64,
    ) -> Result<u64> {
        self.stats.total_captured += 1;

        let slot = if self.overwrite_on_full {
            let s = self.write_cursor;
            self.write_cursor = (self.write_cursor + 1) % MAX_SAVED_TRACES;
            s
        } else {
            match self.traces.iter().position(|t| !t.active) {
                Some(s) => s,
                None => {
                    self.stats.total_dropped += 1;
                    return Err(Error::OutOfMemory);
                }
            }
        };

        let trace_id = self.next_trace_id;
        self.next_trace_id += 1;

        let copy_count = frames.len().min(MAX_FRAMES);
        let truncated = frames.len() > MAX_FRAMES;

        self.traces[slot] = SavedTrace::empty();
        self.traces[slot].pid = pid;
        self.traces[slot].cpu = cpu;
        self.traces[slot].trace_id = trace_id;
        self.traces[slot].frames[..copy_count].copy_from_slice(&frames[..copy_count]);
        self.traces[slot].frame_count = copy_count;
        self.traces[slot].context = context;
        self.traces[slot].timestamp = timestamp;
        self.traces[slot].active = true;
        self.traces[slot].truncated = truncated;

        self.stats.total_saved += 1;
        self.stats.total_frames += copy_count as u64;
        if truncated {
            self.stats.total_truncated += 1;
        }

        Ok(trace_id)
    }

    // ── Lookup ───────────────────────────────────────────────

    /// Find a trace by ID.
    pub fn find(&self, trace_id: u64) -> Option<&SavedTrace> {
        self.traces
            .iter()
            .find(|t| t.active && t.trace_id == trace_id)
    }

    /// Return all traces for a given PID.
    pub fn count_by_pid(&self, pid: u64) -> usize {
        self.traces
            .iter()
            .filter(|t| t.active && t.pid == pid)
            .count()
    }

    /// Clear a specific trace.
    pub fn clear(&mut self, trace_id: u64) -> Result<()> {
        let slot = self
            .traces
            .iter()
            .position(|t| t.active && t.trace_id == trace_id)
            .ok_or(Error::NotFound)?;
        self.traces[slot] = SavedTrace::empty();
        Ok(())
    }

    /// Clear all saved traces.
    pub fn clear_all(&mut self) {
        for trace in &mut self.traces {
            *trace = SavedTrace::empty();
        }
        self.write_cursor = 0;
    }

    // ── Query ────────────────────────────────────────────────

    /// Return statistics.
    pub fn stats(&self) -> StacktraceStats {
        self.stats
    }

    /// Return the number of active saved traces.
    pub fn active_count(&self) -> usize {
        self.traces.iter().filter(|t| t.active).count()
    }

    /// Return the most recent trace.
    pub fn most_recent(&self) -> Option<&SavedTrace> {
        self.traces
            .iter()
            .filter(|t| t.active)
            .max_by_key(|t| t.timestamp)
    }
}
