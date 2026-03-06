// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Kernel tracing infrastructure (ftrace-style).
//!
//! Provides lightweight, low-overhead tracing for performance analysis
//! and debugging. Events are recorded into a fixed-size ring buffer
//! and can be filtered by event type, PID, or CPU.
//!
//! # Architecture
//!
//! ```text
//!  trace_syscall_entry()──┐
//!  trace_sched_switch()───┤  TraceFilter   TraceBuffer
//!  trace_irq()────────────┼──► should_trace? ──► record()
//!  trace_page_fault()─────┤     (bitmask)      (ring buffer)
//!  trace_custom()─────────┘
//! ```
//!
//! Reference: Linux `kernel/trace/trace.c`,
//! `include/linux/trace_events.h`.

/// Trace ring buffer capacity (power of two for fast modulo).
const TRACE_BUFFER_SIZE: usize = 4096;

/// Maximum length of a trace event name.
const MAX_NAME_LEN: usize = 32;

// -----------------------------------------------------------------------
// TraceEventType
// -----------------------------------------------------------------------

/// Kinds of kernel trace events.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum TraceEventType {
    /// System call entry.
    SyscallEntry = 0,
    /// System call exit.
    SyscallExit = 1,
    /// Scheduler context switch.
    SchedSwitch = 2,
    /// Task wakeup.
    SchedWakeup = 3,
    /// Interrupt handler entry.
    IrqEntry = 4,
    /// Interrupt handler exit.
    IrqExit = 5,
    /// Page fault.
    PageFault = 6,
    /// Memory mapping allocation.
    MmapAlloc = 7,
    /// Memory mapping free.
    MmapFree = 8,
    /// IPC message send.
    IpcSend = 9,
    /// IPC message receive.
    IpcReceive = 10,
    /// User-defined custom event.
    Custom = 11,
}

impl TraceEventType {
    /// Convert to a bitmask position.
    const fn bit(self) -> u32 {
        1u32 << (self as u8)
    }
}

// -----------------------------------------------------------------------
// TraceEvent
// -----------------------------------------------------------------------

/// A single trace event recorded by the kernel.
#[derive(Debug, Clone, Copy)]
pub struct TraceEvent {
    /// Kernel tick at the time the event was recorded.
    pub timestamp: u64,
    /// Logical CPU that generated the event.
    pub cpu_id: u8,
    /// Kind of event.
    pub event_type: TraceEventType,
    /// PID of the process associated with this event.
    pub pid: u64,
    /// First event-specific argument.
    pub arg0: u64,
    /// Second event-specific argument.
    pub arg1: u64,
    /// Event name (fixed-size byte array).
    name: [u8; MAX_NAME_LEN],
    /// Length of the valid portion of `name`.
    name_len: usize,
}

impl TraceEvent {
    /// Create a new trace event.
    pub fn new(
        timestamp: u64,
        cpu_id: u8,
        event_type: TraceEventType,
        pid: u64,
        arg0: u64,
        arg1: u64,
        name: &[u8],
    ) -> Self {
        let mut ev = Self {
            timestamp,
            cpu_id,
            event_type,
            pid,
            arg0,
            arg1,
            name: [0; MAX_NAME_LEN],
            name_len: 0,
        };
        let len = name.len().min(MAX_NAME_LEN);
        ev.name[..len].copy_from_slice(&name[..len]);
        ev.name_len = len;
        ev
    }

    /// Event name as a byte slice.
    pub fn name(&self) -> &[u8] {
        &self.name[..self.name_len]
    }
}

/// Default trace event (used for buffer initialization).
const EMPTY_EVENT: TraceEvent = TraceEvent {
    timestamp: 0,
    cpu_id: 0,
    event_type: TraceEventType::Custom,
    pid: 0,
    arg0: 0,
    arg1: 0,
    name: [0; MAX_NAME_LEN],
    name_len: 0,
};

// -----------------------------------------------------------------------
// TraceBuffer
// -----------------------------------------------------------------------

/// Fixed-size ring buffer for trace events.
///
/// Stores up to [`TRACE_BUFFER_SIZE`] events. When full, new events
/// overwrite the oldest entries.
pub struct TraceBuffer {
    /// Event storage.
    events: [TraceEvent; TRACE_BUFFER_SIZE],
    /// Next write position (monotonically increasing).
    write_idx: usize,
    /// Total events ever written (including overwritten).
    total: u64,
}

impl Default for TraceBuffer {
    fn default() -> Self {
        Self::new()
    }
}

impl TraceBuffer {
    /// Create an empty trace buffer.
    pub const fn new() -> Self {
        Self {
            events: [EMPTY_EVENT; TRACE_BUFFER_SIZE],
            write_idx: 0,
            total: 0,
        }
    }

    /// Append an event to the ring buffer.
    ///
    /// When the buffer is full the oldest event is overwritten.
    /// Returns `true` if an older event was overwritten.
    pub fn record(&mut self, event: TraceEvent) -> bool {
        let wrapped = self.write_idx >= TRACE_BUFFER_SIZE;
        let idx = self.write_idx % TRACE_BUFFER_SIZE;
        self.events[idx] = event;
        self.write_idx += 1;
        self.total += 1;
        wrapped
    }

    /// Read the event at the given logical index (0 = oldest).
    ///
    /// Returns `None` if the index is out of range.
    pub fn read(&self, index: usize) -> Option<&TraceEvent> {
        let count = self.count();
        if index >= count {
            return None;
        }
        let start = self.write_idx.saturating_sub(count);
        let physical = (start + index) % TRACE_BUFFER_SIZE;
        Some(&self.events[physical])
    }

    /// Number of events currently stored (up to buffer capacity).
    pub fn count(&self) -> usize {
        self.write_idx.min(TRACE_BUFFER_SIZE)
    }

    /// Remove all events from the buffer.
    pub fn clear(&mut self) {
        self.write_idx = 0;
        self.total = 0;
    }

    /// Check whether the buffer has wrapped at least once.
    pub fn is_full(&self) -> bool {
        self.write_idx >= TRACE_BUFFER_SIZE
    }

    /// Total events ever written (including overwritten ones).
    pub fn total_written(&self) -> u64 {
        self.total
    }
}

impl core::fmt::Debug for TraceBuffer {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("TraceBuffer")
            .field("entries", &self.count())
            .field("capacity", &TRACE_BUFFER_SIZE)
            .field("total_written", &self.total)
            .finish()
    }
}

// -----------------------------------------------------------------------
// TraceFilter
// -----------------------------------------------------------------------

/// Filter configuration for the kernel tracer.
///
/// Controls which events are actually recorded. Each event type can
/// be individually enabled/disabled via a bitmask, and optional PID
/// and CPU filters provide further narrowing.
#[derive(Debug, Clone)]
pub struct TraceFilter {
    /// Bitmask of enabled [`TraceEventType`] variants.
    enabled_types: u32,
    /// When `Some(pid)`, only events for that PID are recorded.
    pub filter_pid: Option<u64>,
    /// When `Some(cpu)`, only events from that CPU are recorded.
    pub filter_cpu: Option<u8>,
}

impl Default for TraceFilter {
    fn default() -> Self {
        Self::new()
    }
}

impl TraceFilter {
    /// Create a new filter with all event types enabled and no
    /// PID/CPU restriction.
    pub const fn new() -> Self {
        Self {
            enabled_types: u32::MAX,
            filter_pid: None,
            filter_cpu: None,
        }
    }

    /// Check whether a specific event type is enabled.
    pub fn is_enabled(&self, event_type: TraceEventType) -> bool {
        self.enabled_types & event_type.bit() != 0
    }

    /// Evaluate all filter criteria for a potential trace event.
    pub fn should_trace(&self, event_type: TraceEventType, pid: u64, cpu: u8) -> bool {
        if !self.is_enabled(event_type) {
            return false;
        }
        if let Some(fp) = self.filter_pid {
            if fp != pid {
                return false;
            }
        }
        if let Some(fc) = self.filter_cpu {
            if fc != cpu {
                return false;
            }
        }
        true
    }

    /// Enable tracing for a specific event type.
    pub fn enable_type(&mut self, t: TraceEventType) {
        self.enabled_types |= t.bit();
    }

    /// Disable tracing for a specific event type.
    pub fn disable_type(&mut self, t: TraceEventType) {
        self.enabled_types &= !t.bit();
    }

    /// Enable all event types.
    pub fn enable_all(&mut self) {
        self.enabled_types = u32::MAX;
    }

    /// Disable all event types.
    pub fn disable_all(&mut self) {
        self.enabled_types = 0;
    }
}

// -----------------------------------------------------------------------
// TraceStats
// -----------------------------------------------------------------------

/// Cumulative statistics for the kernel tracer.
#[derive(Debug, Clone, Copy, Default)]
pub struct TraceStats {
    /// Total events successfully recorded.
    pub events_recorded: u64,
    /// Events dropped because the tracer was inactive or filtered.
    pub events_dropped: u64,
    /// Number of times the ring buffer has wrapped around.
    pub buffer_wraps: u64,
}

// -----------------------------------------------------------------------
// Tracer
// -----------------------------------------------------------------------

/// Top-level kernel tracer.
///
/// Combines a [`TraceBuffer`], a [`TraceFilter`], and runtime
/// statistics. Provides convenience methods for common event types
/// (syscall, scheduler, IRQ, page fault, custom).
pub struct Tracer {
    /// Ring buffer holding recorded events.
    pub buffer: TraceBuffer,
    /// Active filter configuration.
    pub filter: TraceFilter,
    /// Whether the tracer is currently recording.
    active: bool,
    /// Cumulative statistics.
    stats: TraceStats,
}

impl Default for Tracer {
    fn default() -> Self {
        Self::new()
    }
}

impl Tracer {
    /// Create a new inactive tracer.
    pub const fn new() -> Self {
        Self {
            buffer: TraceBuffer::new(),
            filter: TraceFilter::new(),
            active: false,
            stats: TraceStats {
                events_recorded: 0,
                events_dropped: 0,
                buffer_wraps: 0,
            },
        }
    }

    /// Start recording trace events.
    pub fn start(&mut self) {
        self.active = true;
    }

    /// Stop recording trace events.
    pub fn stop(&mut self) {
        self.active = false;
    }

    /// Check whether the tracer is currently active.
    pub fn is_active(&self) -> bool {
        self.active
    }

    /// Get a snapshot of the current statistics.
    pub fn stats(&self) -> &TraceStats {
        &self.stats
    }

    // ---------------------------------------------------------------
    // Internal helper
    // ---------------------------------------------------------------

    /// Record an event if the tracer is active and the filter allows
    /// it. Returns `true` if the event was recorded.
    #[allow(clippy::too_many_arguments)]
    fn try_record(
        &mut self,
        event_type: TraceEventType,
        pid: u64,
        cpu: u8,
        arg0: u64,
        arg1: u64,
        name: &[u8],
        timestamp: u64,
    ) -> bool {
        if !self.active {
            self.stats.events_dropped += 1;
            return false;
        }
        if !self.filter.should_trace(event_type, pid, cpu) {
            self.stats.events_dropped += 1;
            return false;
        }
        let event = TraceEvent::new(timestamp, cpu, event_type, pid, arg0, arg1, name);
        let wrapped = self.buffer.record(event);
        self.stats.events_recorded += 1;
        if wrapped {
            self.stats.buffer_wraps += 1;
        }
        true
    }

    // ---------------------------------------------------------------
    // Convenience trace points
    // ---------------------------------------------------------------

    /// Record a system call entry event.
    ///
    /// - `pid`: calling process ID
    /// - `syscall_nr`: system call number (`arg0`)
    /// - `arg0`: first user-space argument (`arg1`)
    pub fn trace_syscall_entry(&mut self, pid: u64, syscall_nr: u64, arg0: u64) {
        self.try_record(
            TraceEventType::SyscallEntry,
            pid,
            0,
            syscall_nr,
            arg0,
            b"sys_enter",
            0,
        );
    }

    /// Record a system call exit event.
    ///
    /// - `pid`: calling process ID
    /// - `syscall_nr`: system call number (`arg0`)
    /// - `ret_val`: return value (`arg1`)
    pub fn trace_syscall_exit(&mut self, pid: u64, syscall_nr: u64, ret_val: u64) {
        self.try_record(
            TraceEventType::SyscallExit,
            pid,
            0,
            syscall_nr,
            ret_val,
            b"sys_exit",
            0,
        );
    }

    /// Record a scheduler context switch event.
    ///
    /// - `prev_pid`: PID being switched out (`arg0`)
    /// - `next_pid`: PID being switched in (`arg1`)
    pub fn trace_sched_switch(&mut self, prev_pid: u64, next_pid: u64) {
        self.try_record(
            TraceEventType::SchedSwitch,
            prev_pid,
            0,
            prev_pid,
            next_pid,
            b"sched_switch",
            0,
        );
    }

    /// Record an IRQ entry or exit event.
    ///
    /// - `irq_nr`: interrupt number (`arg0`)
    /// - `is_entry`: `true` for entry, `false` for exit
    pub fn trace_irq(&mut self, irq_nr: u64, is_entry: bool) {
        let event_type = if is_entry {
            TraceEventType::IrqEntry
        } else {
            TraceEventType::IrqExit
        };
        let name: &[u8] = if is_entry { b"irq_enter" } else { b"irq_exit" };
        self.try_record(event_type, 0, 0, irq_nr, 0, name, 0);
    }

    /// Record a page fault event.
    ///
    /// - `pid`: faulting process ID
    /// - `addr`: faulting virtual address (`arg0`)
    /// - `is_write`: `true` for write fault (`arg1` = 1)
    pub fn trace_page_fault(&mut self, pid: u64, addr: u64, is_write: bool) {
        self.try_record(
            TraceEventType::PageFault,
            pid,
            0,
            addr,
            if is_write { 1 } else { 0 },
            b"page_fault",
            0,
        );
    }

    /// Record a user-defined custom trace event.
    ///
    /// - `pid`: associated process ID
    /// - `cpu`: CPU number
    /// - `name`: event name (up to 32 bytes)
    /// - `arg0`: first argument
    /// - `arg1`: second argument
    pub fn trace_custom(&mut self, pid: u64, cpu: u8, name: &[u8], arg0: u64, arg1: u64) {
        self.try_record(TraceEventType::Custom, pid, cpu, arg0, arg1, name, 0);
    }
}

impl core::fmt::Debug for Tracer {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Tracer")
            .field("active", &self.active)
            .field("buffer", &self.buffer)
            .field("stats", &self.stats)
            .finish()
    }
}
