// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Tracefs virtual filesystem (`/sys/kernel/tracing/`).
//!
//! Provides the kernel tracing control interface as a filesystem. User space
//! enables/disables trace events, reads the trace pipe, and controls global
//! tracing by reading and writing special files under the mount point.
//!
//! # Design
//!
//! - [`TracefsEntry`] — a node in the tracefs tree (dir, control file, event).
//! - [`TracePipe`] — ring buffer exposing the kernel trace log as a stream.
//! - [`TraceEvent`] — a subsystem event that can be individually toggled.
//! - [`TraceFilter`] — per-event filter expression controlling which hits record.
//! - [`TriggerAction`] — action fired when a tracepoint is hit.
//! - [`TraceRingBuffer`] — per-CPU ring buffer storing structured trace records.
//! - [`FtraceFilter`] — function-level filter for function tracing.
//! - [`TraceInstance`] — isolated tracing context with independent buffers.
//! - [`TracefsSuperblock`] — filesystem root; owns all nodes and the pipe.
//!
//! # Standard layout
//!
//! ```text
//! /sys/kernel/tracing/
//! ├── tracing_on          (read/write: "1" enable, "0" disable)
//! ├── trace               (read: current trace buffer snapshot)
//! ├── trace_pipe          (blocking read: streaming trace output)
//! ├── trace_clock         (read/write: trace clock source)
//! ├── buffer_size_kb      (read/write: per-CPU buffer size in KiB)
//! ├── current_tracer      (read/write: active tracer name)
//! ├── trace_options       (read: space-separated trace option flags)
//! ├── set_ftrace_filter   (read/write: function names to trace)
//! ├── set_ftrace_notrace  (read/write: function names to exclude)
//! ├── events/
//! │   └── <subsystem>/
//! │       ├── enable      (read/write: enable all events in subsystem)
//! │       └── <event>/
//! │           ├── enable  (read/write: individual event toggle)
//! │           ├── format  (read: event field format)
//! │           ├── filter  (read/write: event filter expression)
//! │           └── trigger (read/write: trigger actions)
//! └── instances/
//!     └── <name>/         (mkdir/rmdir: create/remove trace instances)
//! ```
//!
//! Reference: Linux `fs/tracefs/`, `kernel/trace/`, `Documentation/trace/`.

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum number of nodes in the tracefs tree.
pub const MAX_TRACEFS_ENTRIES: usize = 256;

/// Maximum name length for a tracefs entry.
pub const MAX_NAME_LEN: usize = 64;

/// Capacity of the trace ring buffer in bytes.
pub const TRACE_BUF_SIZE: usize = 65536;

/// Maximum number of individually registerable trace events.
pub const MAX_TRACE_EVENTS: usize = 128;

/// Maximum length of a tracer name (e.g. `"nop"`, `"function"`, `"blk"`).
pub const TRACER_NAME_LEN: usize = 32;

/// Maximum subsystem name length.
pub const SUBSYS_NAME_LEN: usize = 32;

/// Default per-CPU ring buffer size in KiB.
pub const DEFAULT_BUFFER_SIZE_KB: u32 = 1408;

/// Maximum number of per-CPU trace ring buffers.
const MAX_CPUS: usize = 16;

/// Maximum number of records per CPU ring buffer.
const RING_BUFFER_RECORDS: usize = 64;

/// Maximum length of a filter expression.
const MAX_FILTER_LEN: usize = 128;

/// Maximum number of function trace filter entries.
const MAX_FTRACE_FILTERS: usize = 64;

/// Maximum length of a function name in ftrace filter.
const MAX_FUNC_NAME_LEN: usize = 64;

/// Maximum number of trigger actions per event.
const MAX_TRIGGERS_PER_EVENT: usize = 4;

/// Maximum number of named trace instances.
const MAX_INSTANCES: usize = 8;

// ---------------------------------------------------------------------------
// TracefsEntryKind
// ---------------------------------------------------------------------------

/// The kind of a tracefs tree node.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TracefsEntryKind {
    /// A directory node.
    Dir,
    /// `tracing_on` — global enable/disable toggle.
    TracingOn,
    /// `trace` — snapshot of the trace buffer (read-only).
    Trace,
    /// `trace_pipe` — streaming, consuming read of the ring buffer.
    TracePipe,
    /// `trace_clock` — clock source selector.
    TraceClock,
    /// `buffer_size_kb` — per-CPU ring buffer size.
    BufferSizeKb,
    /// `current_tracer` — name of the active tracer.
    CurrentTracer,
    /// `trace_options` — space-separated trace option flags.
    TraceOptions,
    /// `set_ftrace_filter` — function names to trace.
    SetFtraceFilter,
    /// `set_ftrace_notrace` — function names to exclude.
    SetFtraceNotrace,
    /// An `events/<subsystem>/<event>/enable` file.
    EventEnable,
    /// An `events/<subsystem>/enable` file (aggregate).
    SubsysEnable,
    /// An `events/<subsystem>/<event>/format` file.
    EventFormat,
    /// An `events/<subsystem>/<event>/filter` file.
    EventFilter,
    /// An `events/<subsystem>/<event>/trigger` file.
    EventTrigger,
}

// ---------------------------------------------------------------------------
// TracefsEntry
// ---------------------------------------------------------------------------

/// A single node in the tracefs tree.
#[derive(Debug, Clone, Copy)]
pub struct TracefsEntry {
    /// Node kind.
    pub kind: TracefsEntryKind,
    /// Node name (null-padded).
    name: [u8; MAX_NAME_LEN],
    /// Name length in bytes.
    name_len: usize,
    /// Handle of the parent node (index in `TracefsSuperblock::entries`).
    /// `usize::MAX` for the root.
    pub parent: usize,
    /// Optional opaque payload index (e.g. event index for `EventEnable`).
    pub payload_idx: usize,
    /// Whether this slot is occupied.
    pub active: bool,
}

impl TracefsEntry {
    const fn empty() -> Self {
        Self {
            kind: TracefsEntryKind::Dir,
            name: [0u8; MAX_NAME_LEN],
            name_len: 0,
            parent: usize::MAX,
            payload_idx: 0,
            active: false,
        }
    }

    /// Return the name as a byte slice.
    pub fn name_bytes(&self) -> &[u8] {
        &self.name[..self.name_len]
    }
}

// ---------------------------------------------------------------------------
// TracePipe
// ---------------------------------------------------------------------------

/// A ring-buffer exposing the kernel trace log as a byte stream.
///
/// Producers call [`TracePipe::write`]; consumers call [`TracePipe::read`].
/// Once consumed, bytes are discarded (no re-read without seeking to `trace`).
pub struct TracePipe {
    buf: [u8; TRACE_BUF_SIZE],
    /// Write position (next byte to write).
    write_pos: usize,
    /// Read position (next byte to read / consume).
    read_pos: usize,
    /// Number of bytes currently in the buffer.
    available: usize,
    /// Count of bytes dropped due to buffer overflow.
    pub dropped: u64,
}

impl TracePipe {
    /// Create an empty trace pipe.
    pub const fn new() -> Self {
        Self {
            buf: [0u8; TRACE_BUF_SIZE],
            write_pos: 0,
            read_pos: 0,
            available: 0,
            dropped: 0,
        }
    }

    /// Write `data` into the ring buffer.
    ///
    /// If the buffer is full, the oldest bytes are overwritten and the
    /// `dropped` counter is incremented for each byte lost.
    pub fn write(&mut self, data: &[u8]) {
        for &b in data {
            if self.available == TRACE_BUF_SIZE {
                // Overwrite oldest byte.
                self.read_pos = (self.read_pos + 1) % TRACE_BUF_SIZE;
                self.available -= 1;
                self.dropped += 1;
            }
            self.buf[self.write_pos] = b;
            self.write_pos = (self.write_pos + 1) % TRACE_BUF_SIZE;
            self.available += 1;
        }
    }

    /// Consume up to `buf.len()` bytes from the pipe into `buf`.
    ///
    /// Returns the number of bytes read. Returns `0` if the pipe is empty.
    pub fn read(&mut self, buf: &mut [u8]) -> usize {
        let to_read = buf.len().min(self.available);
        for byte in buf[..to_read].iter_mut() {
            *byte = self.buf[self.read_pos];
            self.read_pos = (self.read_pos + 1) % TRACE_BUF_SIZE;
        }
        self.available -= to_read;
        to_read
    }

    /// Peek at the ring buffer without consuming bytes (for `trace` snapshot).
    ///
    /// Copies up to `buf.len()` bytes in order from the oldest to newest.
    pub fn peek(&self, buf: &mut [u8]) -> usize {
        let to_copy = buf.len().min(self.available);
        let mut pos = self.read_pos;
        for byte in buf[..to_copy].iter_mut() {
            *byte = self.buf[pos];
            pos = (pos + 1) % TRACE_BUF_SIZE;
        }
        to_copy
    }

    /// Number of bytes available to read.
    pub fn available(&self) -> usize {
        self.available
    }

    /// Reset the ring buffer (discard all data).
    pub fn clear(&mut self) {
        self.write_pos = 0;
        self.read_pos = 0;
        self.available = 0;
    }
}

impl Default for TracePipe {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// TraceClockSource
// ---------------------------------------------------------------------------

/// Available clock sources for timestamping trace events.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TraceClockSource {
    /// Local CPU counter — fast but not synchronised between CPUs.
    Local,
    /// Global monotonic clock.
    Global,
    /// Counter incremented at each trace event (no time semantics).
    Counter,
    /// Absolute time from the platform RTC.
    Tai,
}

impl TraceClockSource {
    /// Parse from bytes (e.g. `b"global"` → `Global`).
    pub fn from_bytes(b: &[u8]) -> Result<Self> {
        match b {
            b"local" => Ok(Self::Local),
            b"global" => Ok(Self::Global),
            b"counter" => Ok(Self::Counter),
            b"tai" => Ok(Self::Tai),
            _ => Err(Error::InvalidArgument),
        }
    }

    /// Return the canonical name bytes.
    pub fn name_bytes(self) -> &'static [u8] {
        match self {
            Self::Local => b"local",
            Self::Global => b"global",
            Self::Counter => b"counter",
            Self::Tai => b"tai",
        }
    }

    /// Return the canonical name as a static string.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Local => "local",
            Self::Global => "global",
            Self::Counter => "counter",
            Self::Tai => "tai",
        }
    }
}

// ---------------------------------------------------------------------------
// TriggerAction
// ---------------------------------------------------------------------------

/// Action triggered when a tracepoint fires.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TriggerAction {
    /// Take a snapshot of the trace buffer.
    Snapshot,
    /// Record a stack trace at the tracepoint.
    Stacktrace,
    /// Enable global tracing.
    Traceon,
    /// Disable global tracing.
    Traceoff,
}

impl TriggerAction {
    /// Return the trigger name as a static string.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Snapshot => "snapshot",
            Self::Stacktrace => "stacktrace",
            Self::Traceon => "traceon",
            Self::Traceoff => "traceoff",
        }
    }

    /// Parse a trigger name from bytes.
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        match data {
            b"snapshot" => Ok(Self::Snapshot),
            b"stacktrace" => Ok(Self::Stacktrace),
            b"traceon" => Ok(Self::Traceon),
            b"traceoff" => Ok(Self::Traceoff),
            _ => Err(Error::InvalidArgument),
        }
    }
}

// ---------------------------------------------------------------------------
// TraceFilter
// ---------------------------------------------------------------------------

/// Per-event filter expression controlling which event hits are recorded.
///
/// Example: `pid == 42`, `comm == "bash"`. An empty filter matches all hits.
#[derive(Debug, Clone, Copy)]
pub struct TraceFilter {
    /// Filter expression bytes.
    expr: [u8; MAX_FILTER_LEN],
    /// Length of the expression.
    len: usize,
}

impl TraceFilter {
    /// Create an empty (match-all) filter.
    const fn empty() -> Self {
        Self {
            expr: [0u8; MAX_FILTER_LEN],
            len: 0,
        }
    }

    /// Return the filter expression as a byte slice.
    pub fn expr_bytes(&self) -> &[u8] {
        &self.expr[..self.len]
    }

    /// Set the filter expression. Empty data clears the filter.
    pub fn set(&mut self, data: &[u8]) -> Result<()> {
        let trimmed = trim_newline(data);
        if trimmed.len() > MAX_FILTER_LEN {
            return Err(Error::InvalidArgument);
        }
        self.expr[..trimmed.len()].copy_from_slice(trimmed);
        self.len = trimmed.len();
        Ok(())
    }

    /// Return `true` if the filter is empty (match-all).
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Clear the filter expression.
    pub fn clear(&mut self) {
        self.len = 0;
    }
}

// ---------------------------------------------------------------------------
// TraceEvent
// ---------------------------------------------------------------------------

/// A single trace event that can be individually enabled or disabled.
#[derive(Debug, Clone, Copy)]
pub struct TraceEvent {
    /// Subsystem name.
    pub subsystem: [u8; SUBSYS_NAME_LEN],
    /// Subsystem name length.
    pub subsys_len: u8,
    /// Event name.
    pub name: [u8; MAX_NAME_LEN],
    /// Event name length.
    pub name_len: u8,
    /// Whether the event is enabled.
    pub enabled: bool,
    /// Format string describing event fields (optional, null-padded).
    pub format: [u8; 256],
    /// Format length.
    pub format_len: u16,
    /// Per-event filter expression.
    pub filter: TraceFilter,
    /// Trigger actions attached to this event.
    pub triggers: [Option<TriggerAction>; MAX_TRIGGERS_PER_EVENT],
    /// Number of active triggers.
    pub trigger_count: u8,
    /// Whether this slot is occupied.
    pub active: bool,
}

impl TraceEvent {
    const fn empty() -> Self {
        Self {
            subsystem: [0u8; SUBSYS_NAME_LEN],
            subsys_len: 0,
            name: [0u8; MAX_NAME_LEN],
            name_len: 0,
            enabled: false,
            format: [0u8; 256],
            format_len: 0,
            filter: TraceFilter::empty(),
            triggers: [None; MAX_TRIGGERS_PER_EVENT],
            trigger_count: 0,
            active: false,
        }
    }

    /// Create a new trace event.
    fn new(subsystem: &[u8], name: &[u8]) -> Result<Self> {
        if subsystem.is_empty()
            || subsystem.len() > SUBSYS_NAME_LEN
            || name.is_empty()
            || name.len() > MAX_NAME_LEN
        {
            return Err(Error::InvalidArgument);
        }
        let mut event = Self::empty();
        event.subsystem[..subsystem.len()].copy_from_slice(subsystem);
        event.subsys_len = subsystem.len() as u8;
        event.name[..name.len()].copy_from_slice(name);
        event.name_len = name.len() as u8;
        event.active = true;
        Ok(event)
    }

    /// Return the subsystem name as a byte slice.
    pub fn subsystem_bytes(&self) -> &[u8] {
        &self.subsystem[..self.subsys_len as usize]
    }

    /// Return the event name as a byte slice.
    pub fn name_bytes(&self) -> &[u8] {
        &self.name[..self.name_len as usize]
    }

    /// Return the format string as a byte slice.
    pub fn format_bytes(&self) -> &[u8] {
        &self.format[..self.format_len as usize]
    }

    /// Set the event format string.
    pub fn set_format(&mut self, fmt: &[u8]) -> Result<()> {
        if fmt.len() > 256 {
            return Err(Error::InvalidArgument);
        }
        self.format[..fmt.len()].copy_from_slice(fmt);
        self.format_len = fmt.len() as u16;
        Ok(())
    }

    /// Add a trigger action. Returns error if trigger table is full.
    pub fn add_trigger(&mut self, action: TriggerAction) -> Result<()> {
        if self.trigger_count as usize >= MAX_TRIGGERS_PER_EVENT {
            return Err(Error::OutOfMemory);
        }
        self.triggers[self.trigger_count as usize] = Some(action);
        self.trigger_count += 1;
        Ok(())
    }

    /// Clear all trigger actions.
    pub fn clear_triggers(&mut self) {
        self.triggers = [None; MAX_TRIGGERS_PER_EVENT];
        self.trigger_count = 0;
    }
}

// ---------------------------------------------------------------------------
// TraceRecord — per-CPU ring buffer record
// ---------------------------------------------------------------------------

/// A single trace record stored in a per-CPU ring buffer.
#[derive(Debug, Clone, Copy)]
pub struct TraceRecord {
    /// Timestamp (interpretation depends on [`TraceClockSource`]).
    pub timestamp: u64,
    /// Index of the event that generated this record.
    pub event_idx: u16,
    /// CPU that recorded this event.
    pub cpu: u8,
    /// PID of the task that triggered the event.
    pub pid: u32,
    /// Payload bytes.
    payload: [u8; 64],
    /// Length of valid payload data.
    payload_len: u8,
    /// Whether this slot is occupied.
    occupied: bool,
}

impl TraceRecord {
    /// Create an empty (unoccupied) record.
    const fn empty() -> Self {
        Self {
            timestamp: 0,
            event_idx: 0,
            cpu: 0,
            pid: 0,
            payload: [0u8; 64],
            payload_len: 0,
            occupied: false,
        }
    }

    /// Create a new trace record with the given fields.
    pub fn new(timestamp: u64, event_idx: u16, cpu: u8, pid: u32, payload: &[u8]) -> Self {
        let len = payload.len().min(64);
        let mut data = [0u8; 64];
        data[..len].copy_from_slice(&payload[..len]);
        Self {
            timestamp,
            event_idx,
            cpu,
            pid,
            payload: data,
            payload_len: len as u8,
            occupied: true,
        }
    }

    /// Return the payload as a byte slice.
    pub fn payload(&self) -> &[u8] {
        &self.payload[..self.payload_len as usize]
    }

    /// Format this record as a human-readable line into `buf`.
    ///
    /// Format: `<timestamp> cpu=<cpu> pid=<pid> event=<idx> <payload>\n`
    /// Returns the number of bytes written.
    pub fn format_into(&self, buf: &mut [u8]) -> usize {
        let mut pos = 0;
        pos += fmt_u64(&mut buf[pos..], self.timestamp);
        pos += copy_bytes(&mut buf[pos..], b" cpu=");
        pos += fmt_u64(&mut buf[pos..], self.cpu as u64);
        pos += copy_bytes(&mut buf[pos..], b" pid=");
        pos += fmt_u64(&mut buf[pos..], self.pid as u64);
        pos += copy_bytes(&mut buf[pos..], b" event=");
        pos += fmt_u64(&mut buf[pos..], self.event_idx as u64);
        if self.payload_len > 0 {
            pos += copy_bytes(&mut buf[pos..], b" ");
            let plen = (self.payload_len as usize).min(buf.len().saturating_sub(pos));
            if plen > 0 {
                buf[pos..pos + plen].copy_from_slice(&self.payload[..plen]);
                pos += plen;
            }
        }
        pos += copy_bytes(&mut buf[pos..], b"\n");
        pos
    }
}

// ---------------------------------------------------------------------------
// TraceRingBuffer — per-CPU
// ---------------------------------------------------------------------------

/// Per-CPU ring buffer storing structured [`TraceRecord`] entries.
///
/// Fixed-size circular buffer. When full, oldest entries are overwritten
/// (overwrite mode) or new entries are dropped (no-overwrite mode).
pub struct TraceRingBuffer {
    /// Record storage.
    records: [TraceRecord; RING_BUFFER_RECORDS],
    /// Write head (next slot to write).
    head: usize,
    /// Read tail (next slot to consume for trace_pipe).
    tail: usize,
    /// Number of records currently stored.
    count: usize,
    /// Total records written since creation.
    pub total_written: u64,
    /// Records dropped due to buffer full (no-overwrite mode).
    pub dropped: u64,
    /// Whether overwrite mode is enabled.
    pub overwrite: bool,
}

impl TraceRingBuffer {
    /// Create a new empty ring buffer in overwrite mode.
    pub const fn new() -> Self {
        Self {
            records: [TraceRecord::empty(); RING_BUFFER_RECORDS],
            head: 0,
            tail: 0,
            count: 0,
            total_written: 0,
            dropped: 0,
            overwrite: true,
        }
    }

    /// Push a record into the ring buffer.
    pub fn push(&mut self, record: TraceRecord) {
        if self.count == RING_BUFFER_RECORDS {
            if !self.overwrite {
                self.dropped += 1;
                return;
            }
            // Overwrite oldest: advance tail.
            self.tail = (self.tail + 1) % RING_BUFFER_RECORDS;
            self.count -= 1;
        }
        self.records[self.head] = record;
        self.head = (self.head + 1) % RING_BUFFER_RECORDS;
        self.count += 1;
        self.total_written += 1;
    }

    /// Pop the oldest record (destructive read for trace_pipe).
    pub fn pop(&mut self) -> Option<TraceRecord> {
        if self.count == 0 {
            return None;
        }
        let record = self.records[self.tail];
        if !record.occupied {
            return None;
        }
        self.tail = (self.tail + 1) % RING_BUFFER_RECORDS;
        self.count -= 1;
        Some(record)
    }

    /// Peek at a record by index from tail (non-destructive).
    pub fn peek(&self, index: usize) -> Option<&TraceRecord> {
        if index >= self.count {
            return None;
        }
        let actual = (self.tail + index) % RING_BUFFER_RECORDS;
        let rec = &self.records[actual];
        if rec.occupied { Some(rec) } else { None }
    }

    /// Return the number of records currently stored.
    pub fn record_count(&self) -> usize {
        self.count
    }

    /// Clear all records.
    pub fn clear(&mut self) {
        self.records = [TraceRecord::empty(); RING_BUFFER_RECORDS];
        self.head = 0;
        self.tail = 0;
        self.count = 0;
    }
}

impl Default for TraceRingBuffer {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// FtraceFilter — function tracing filter
// ---------------------------------------------------------------------------

/// An entry in the ftrace function filter list.
#[derive(Debug, Clone, Copy)]
struct FtraceFilterEntry {
    /// Function name pattern.
    name: [u8; MAX_FUNC_NAME_LEN],
    /// Length of the name.
    name_len: usize,
    /// Whether this is a notrace (exclusion) entry.
    is_notrace: bool,
    /// Whether this slot is occupied.
    active: bool,
}

impl FtraceFilterEntry {
    const fn empty() -> Self {
        Self {
            name: [0u8; MAX_FUNC_NAME_LEN],
            name_len: 0,
            is_notrace: false,
            active: false,
        }
    }
}

/// Function-level trace filter managing `set_ftrace_filter` and
/// `set_ftrace_notrace` lists.
pub struct FtraceFilter {
    /// Filter entries.
    entries: [FtraceFilterEntry; MAX_FTRACE_FILTERS],
    /// Number of active entries.
    count: usize,
}

impl FtraceFilter {
    /// Create an empty filter table.
    const fn new() -> Self {
        Self {
            entries: [FtraceFilterEntry::empty(); MAX_FTRACE_FILTERS],
            count: 0,
        }
    }

    /// Add a function name to the filter or notrace list.
    pub fn add(&mut self, name: &[u8], is_notrace: bool) -> Result<()> {
        let trimmed = trim_newline(name);
        if trimmed.is_empty() || trimmed.len() > MAX_FUNC_NAME_LEN {
            return Err(Error::InvalidArgument);
        }
        if self.count >= MAX_FTRACE_FILTERS {
            return Err(Error::OutOfMemory);
        }
        for entry in &mut self.entries {
            if !entry.active {
                entry.name[..trimmed.len()].copy_from_slice(trimmed);
                entry.name_len = trimmed.len();
                entry.is_notrace = is_notrace;
                entry.active = true;
                self.count += 1;
                return Ok(());
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Clear all entries, optionally filtering by notrace flag.
    pub fn clear(&mut self, notrace_only: Option<bool>) {
        match notrace_only {
            None => {
                self.entries = [FtraceFilterEntry::empty(); MAX_FTRACE_FILTERS];
                self.count = 0;
            }
            Some(is_notrace) => {
                for entry in &mut self.entries {
                    if entry.active && entry.is_notrace == is_notrace {
                        *entry = FtraceFilterEntry::empty();
                        self.count = self.count.saturating_sub(1);
                    }
                }
            }
        }
    }

    /// Format the filter or notrace list into `buf`. Returns bytes written.
    pub fn format_list(&self, buf: &mut [u8], is_notrace: bool) -> usize {
        let mut pos = 0;
        for entry in &self.entries {
            if entry.active && entry.is_notrace == is_notrace {
                let name = &entry.name[..entry.name_len];
                let n = name.len().min(buf.len().saturating_sub(pos));
                if n > 0 {
                    buf[pos..pos + n].copy_from_slice(&name[..n]);
                    pos += n;
                }
                pos += copy_bytes(&mut buf[pos..], b"\n");
            }
        }
        pos
    }

    /// Check if a function name is in the filter list (and not excluded).
    pub fn is_traced(&self, func_name: &[u8]) -> bool {
        let has_filter = self.entries.iter().any(|e| e.active && !e.is_notrace);
        if !has_filter {
            // No positive filters: trace everything except notrace.
            let is_excluded = self
                .entries
                .iter()
                .any(|e| e.active && e.is_notrace && &e.name[..e.name_len] == func_name);
            return !is_excluded;
        }
        // Explicit filter: must be in filter and not in notrace.
        let in_filter = self
            .entries
            .iter()
            .any(|e| e.active && !e.is_notrace && &e.name[..e.name_len] == func_name);
        let is_excluded = self
            .entries
            .iter()
            .any(|e| e.active && e.is_notrace && &e.name[..e.name_len] == func_name);
        in_filter && !is_excluded
    }
}

impl Default for FtraceFilter {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// TraceInstance — isolated tracing context
// ---------------------------------------------------------------------------

/// A named trace instance with independent buffers and configuration.
///
/// Instances provide isolated tracing contexts — each has its own
/// per-CPU ring buffers, event enable overrides, and tracer selection.
/// Created by `mkdir` in the `instances/` directory.
pub struct TraceInstance {
    /// Instance name (null-padded).
    name: [u8; MAX_NAME_LEN],
    /// Name length.
    name_len: usize,
    /// Whether tracing is enabled for this instance.
    pub tracing_on: bool,
    /// Active tracer name for this instance.
    current_tracer: [u8; TRACER_NAME_LEN],
    /// Active tracer name length.
    current_tracer_len: usize,
    /// Per-CPU ring buffers for this instance.
    pub ring_buffers: [TraceRingBuffer; MAX_CPUS],
    /// Buffer size in KiB for this instance.
    pub buffer_size_kb: u32,
    /// Byte-level trace pipe for this instance.
    pub pipe: TracePipe,
    /// Per-event enable overrides (event index → enabled override).
    event_overrides: [Option<bool>; MAX_TRACE_EVENTS],
    /// Whether this slot is occupied.
    pub active: bool,
}

impl TraceInstance {
    /// Create an empty (inactive) instance.
    const fn empty() -> Self {
        Self {
            name: [0u8; MAX_NAME_LEN],
            name_len: 0,
            tracing_on: false,
            current_tracer: [0u8; TRACER_NAME_LEN],
            current_tracer_len: 0,
            ring_buffers: [const { TraceRingBuffer::new() }; MAX_CPUS],
            buffer_size_kb: DEFAULT_BUFFER_SIZE_KB,
            pipe: TracePipe::new(),
            event_overrides: [None; MAX_TRACE_EVENTS],
            active: false,
        }
    }

    /// Create a new active instance with the given name.
    fn new(name: &[u8]) -> Result<Self> {
        if name.is_empty() || name.len() > MAX_NAME_LEN {
            return Err(Error::InvalidArgument);
        }
        let mut inst = Self::empty();
        inst.name[..name.len()].copy_from_slice(name);
        inst.name_len = name.len();
        inst.active = true;
        inst.current_tracer[..3].copy_from_slice(b"nop");
        inst.current_tracer_len = 3;
        Ok(inst)
    }

    /// Return the instance name as a byte slice.
    pub fn name_bytes(&self) -> &[u8] {
        &self.name[..self.name_len]
    }

    /// Return the current tracer name as a byte slice.
    pub fn tracer_bytes(&self) -> &[u8] {
        &self.current_tracer[..self.current_tracer_len]
    }

    /// Set an event enable override for this instance.
    pub fn set_event_override(&mut self, event_idx: usize, enabled: bool) -> Result<()> {
        if event_idx >= MAX_TRACE_EVENTS {
            return Err(Error::InvalidArgument);
        }
        self.event_overrides[event_idx] = Some(enabled);
        Ok(())
    }

    /// Check if an event is enabled in this instance.
    ///
    /// Instance overrides take precedence over global event state.
    pub fn is_event_enabled(&self, event_idx: usize, global_enabled: bool) -> bool {
        if event_idx < MAX_TRACE_EVENTS {
            self.event_overrides[event_idx].unwrap_or(global_enabled)
        } else {
            global_enabled
        }
    }

    /// Clear all ring buffers in this instance.
    pub fn clear_buffers(&mut self) {
        for rb in &mut self.ring_buffers {
            rb.clear();
        }
        self.pipe.clear();
    }
}

impl Default for TraceInstance {
    fn default() -> Self {
        Self::empty()
    }
}

// ---------------------------------------------------------------------------
// TracefsSuperblock
// ---------------------------------------------------------------------------

/// Tracefs filesystem superblock.
///
/// Owns the tree of [`TracefsEntry`] nodes, the [`TracePipe`] ring buffer,
/// the registered trace events, per-CPU ring buffers, function trace
/// filters, trace instances, and the global tracing-on flag.
pub struct TracefsSuperblock {
    /// Flat node table; index 0 is the root `/sys/kernel/tracing/`.
    entries: [TracefsEntry; MAX_TRACEFS_ENTRIES],
    /// Number of occupied slots (high-water mark).
    entry_count: usize,
    /// Index of the `events/` directory entry.
    events_dir_idx: usize,
    /// Index of the `instances/` directory entry.
    instances_dir_idx: usize,
    /// Registered trace events.
    events: [TraceEvent; MAX_TRACE_EVENTS],
    /// Number of registered events.
    event_count: usize,
    /// Trace ring buffer / pipe (byte-level).
    pub pipe: TracePipe,
    /// Per-CPU structured ring buffers.
    pub ring_buffers: [TraceRingBuffer; MAX_CPUS],
    /// Number of active CPUs.
    num_cpus: usize,
    /// Global tracing enabled flag.
    pub tracing_on: bool,
    /// Selected clock source.
    pub clock: TraceClockSource,
    /// Per-CPU ring buffer size in KiB.
    pub buffer_size_kb: u32,
    /// Active tracer name (e.g. `"nop"`, `"function"`).
    current_tracer: [u8; TRACER_NAME_LEN],
    /// Active tracer name length.
    current_tracer_len: usize,
    /// Function trace filter.
    pub ftrace_filter: FtraceFilter,
    /// Named trace instances.
    instances: [TraceInstance; MAX_INSTANCES],
    /// Number of active instances.
    instance_count: usize,
    /// Whether the filesystem is mounted.
    pub mounted: bool,
}

impl TracefsSuperblock {
    /// Create a new unmounted tracefs superblock and build the standard tree.
    pub fn new() -> Self {
        const EMPTY_ENTRY: TracefsEntry = TracefsEntry::empty();
        const EMPTY_EVENT: TraceEvent = TraceEvent::empty();
        let mut sb = Self {
            entries: [EMPTY_ENTRY; MAX_TRACEFS_ENTRIES],
            entry_count: 0,
            events_dir_idx: 0,
            instances_dir_idx: 0,
            events: [EMPTY_EVENT; MAX_TRACE_EVENTS],
            event_count: 0,
            pipe: TracePipe::new(),
            ring_buffers: [const { TraceRingBuffer::new() }; MAX_CPUS],
            num_cpus: 1,
            tracing_on: false,
            clock: TraceClockSource::Local,
            buffer_size_kb: DEFAULT_BUFFER_SIZE_KB,
            current_tracer: [0u8; TRACER_NAME_LEN],
            current_tracer_len: 0,
            ftrace_filter: FtraceFilter::new(),
            instances: [const { TraceInstance::empty() }; MAX_INSTANCES],
            instance_count: 0,
            mounted: false,
        };
        // Pre-populate the standard tree (best-effort; errors are silent).
        let _ = sb.build_standard_tree();
        sb
    }

    // --- Tree construction --------------------------------------------------

    fn build_standard_tree(&mut self) -> Result<()> {
        // Slot 0: root directory.
        let root_name = b"/";
        let mut name_buf = [0u8; MAX_NAME_LEN];
        name_buf[..root_name.len()].copy_from_slice(root_name);
        self.entries[0] = TracefsEntry {
            kind: TracefsEntryKind::Dir,
            name: name_buf,
            name_len: root_name.len(),
            parent: usize::MAX,
            payload_idx: 0,
            active: true,
        };
        self.entry_count = 1;

        // Standard control files under root (slot 0).
        self.add_control_file(b"tracing_on", TracefsEntryKind::TracingOn, 0)?;
        self.add_control_file(b"trace", TracefsEntryKind::Trace, 0)?;
        self.add_control_file(b"trace_pipe", TracefsEntryKind::TracePipe, 0)?;
        self.add_control_file(b"trace_clock", TracefsEntryKind::TraceClock, 0)?;
        self.add_control_file(b"buffer_size_kb", TracefsEntryKind::BufferSizeKb, 0)?;
        self.add_control_file(b"current_tracer", TracefsEntryKind::CurrentTracer, 0)?;
        self.add_control_file(b"trace_options", TracefsEntryKind::TraceOptions, 0)?;
        self.add_control_file(b"set_ftrace_filter", TracefsEntryKind::SetFtraceFilter, 0)?;
        self.add_control_file(b"set_ftrace_notrace", TracefsEntryKind::SetFtraceNotrace, 0)?;

        // `events/` directory.
        let ev_idx = self.alloc_entry()?;
        let mut ev_name = [0u8; MAX_NAME_LEN];
        ev_name[..6].copy_from_slice(b"events");
        self.entries[ev_idx] = TracefsEntry {
            kind: TracefsEntryKind::Dir,
            name: ev_name,
            name_len: 6,
            parent: 0,
            payload_idx: 0,
            active: true,
        };
        self.events_dir_idx = ev_idx;

        // `instances/` directory.
        let inst_idx = self.alloc_entry()?;
        let mut inst_name = [0u8; MAX_NAME_LEN];
        inst_name[..9].copy_from_slice(b"instances");
        self.entries[inst_idx] = TracefsEntry {
            kind: TracefsEntryKind::Dir,
            name: inst_name,
            name_len: 9,
            parent: 0,
            payload_idx: 0,
            active: true,
        };
        self.instances_dir_idx = inst_idx;

        // Set default tracer to "nop".
        let nop = b"nop";
        self.current_tracer[..nop.len()].copy_from_slice(nop);
        self.current_tracer_len = nop.len();
        Ok(())
    }

    fn add_control_file(
        &mut self,
        name: &[u8],
        kind: TracefsEntryKind,
        parent: usize,
    ) -> Result<usize> {
        let idx = self.alloc_entry()?;
        let copy_len = name.len().min(MAX_NAME_LEN);
        let mut name_buf = [0u8; MAX_NAME_LEN];
        name_buf[..copy_len].copy_from_slice(&name[..copy_len]);
        self.entries[idx] = TracefsEntry {
            kind,
            name: name_buf,
            name_len: copy_len,
            parent,
            payload_idx: 0,
            active: true,
        };
        Ok(idx)
    }

    fn alloc_entry(&mut self) -> Result<usize> {
        if self.entry_count < MAX_TRACEFS_ENTRIES {
            let idx = self.entry_count;
            self.entry_count += 1;
            return Ok(idx);
        }
        // Search for a freed slot.
        for (i, e) in self.entries.iter().enumerate() {
            if !e.active {
                return Ok(i);
            }
        }
        Err(Error::OutOfMemory)
    }

    // --- Lifecycle ----------------------------------------------------------

    /// Mount the tracefs filesystem.
    pub fn mount(&mut self) -> Result<()> {
        if self.mounted {
            return Err(Error::Busy);
        }
        self.mounted = true;
        Ok(())
    }

    /// Unmount tracefs and disable tracing.
    pub fn umount(&mut self) -> Result<()> {
        if !self.mounted {
            return Err(Error::InvalidArgument);
        }
        self.tracing_on = false;
        self.mounted = false;
        Ok(())
    }

    // --- CPU management -----------------------------------------------------

    /// Set the number of active CPUs.
    pub fn set_num_cpus(&mut self, n: usize) {
        self.num_cpus = n.min(MAX_CPUS);
    }

    /// Return the number of active CPUs.
    pub fn num_cpus(&self) -> usize {
        self.num_cpus
    }

    // --- Event registration -------------------------------------------------

    /// Register a new trace event under `subsystem/name`.
    ///
    /// Creates the necessary tree nodes (`events/<subsystem>/<event>/enable`,
    /// `events/<subsystem>/<event>/format`, `events/<subsystem>/<event>/filter`,
    /// and `events/<subsystem>/<event>/trigger`) and returns the event index.
    pub fn register_event(&mut self, subsystem: &[u8], name: &[u8]) -> Result<usize> {
        if self.event_count >= MAX_TRACE_EVENTS {
            return Err(Error::OutOfMemory);
        }
        // Deduplicate.
        for ev in &self.events[..self.event_count] {
            if ev.active && ev.subsystem_bytes() == subsystem && ev.name_bytes() == name {
                return Err(Error::AlreadyExists);
            }
        }
        let event_idx = self.event_count;
        let event = TraceEvent::new(subsystem, name)?;
        self.events[event_idx] = event;
        self.event_count += 1;

        // Ensure the subsystem directory exists under `events/`.
        let subsys_dir = self.ensure_subsystem_dir(subsystem)?;

        // Create the event directory under the subsystem directory.
        let ev_dir_idx = self.alloc_entry()?;
        {
            let copy_len = name.len().min(MAX_NAME_LEN);
            let mut name_buf = [0u8; MAX_NAME_LEN];
            name_buf[..copy_len].copy_from_slice(&name[..copy_len]);
            self.entries[ev_dir_idx] = TracefsEntry {
                kind: TracefsEntryKind::Dir,
                name: name_buf,
                name_len: copy_len,
                parent: subsys_dir,
                payload_idx: event_idx,
                active: true,
            };
        }

        // `enable` file.
        self.add_event_file(
            ev_dir_idx,
            b"enable",
            TracefsEntryKind::EventEnable,
            event_idx,
        )?;

        // `format` file.
        self.add_event_file(
            ev_dir_idx,
            b"format",
            TracefsEntryKind::EventFormat,
            event_idx,
        )?;

        // `filter` file.
        self.add_event_file(
            ev_dir_idx,
            b"filter",
            TracefsEntryKind::EventFilter,
            event_idx,
        )?;

        // `trigger` file.
        self.add_event_file(
            ev_dir_idx,
            b"trigger",
            TracefsEntryKind::EventTrigger,
            event_idx,
        )?;

        Ok(event_idx)
    }

    /// Helper to add an event-related file entry.
    fn add_event_file(
        &mut self,
        parent: usize,
        name: &[u8],
        kind: TracefsEntryKind,
        event_idx: usize,
    ) -> Result<usize> {
        let idx = self.alloc_entry()?;
        let copy_len = name.len().min(MAX_NAME_LEN);
        let mut name_buf = [0u8; MAX_NAME_LEN];
        name_buf[..copy_len].copy_from_slice(&name[..copy_len]);
        self.entries[idx] = TracefsEntry {
            kind,
            name: name_buf,
            name_len: copy_len,
            parent,
            payload_idx: event_idx,
            active: true,
        };
        Ok(idx)
    }

    /// Ensure a subsystem directory exists under `events/` and return its index.
    fn ensure_subsystem_dir(&mut self, subsystem: &[u8]) -> Result<usize> {
        let ev_dir = self.events_dir_idx;
        // Search existing subsystem dirs.
        for i in 0..self.entry_count {
            if self.entries[i].active
                && self.entries[i].kind == TracefsEntryKind::Dir
                && self.entries[i].parent == ev_dir
                && self.entries[i].name_bytes() == subsystem
            {
                return Ok(i);
            }
        }
        // Create it.
        let idx = self.alloc_entry()?;
        let copy_len = subsystem.len().min(MAX_NAME_LEN);
        let mut name_buf = [0u8; MAX_NAME_LEN];
        name_buf[..copy_len].copy_from_slice(&subsystem[..copy_len]);
        self.entries[idx] = TracefsEntry {
            kind: TracefsEntryKind::Dir,
            name: name_buf,
            name_len: copy_len,
            parent: ev_dir,
            payload_idx: 0,
            active: true,
        };
        // Add a subsystem-level `enable` file.
        let en_idx = self.alloc_entry()?;
        {
            let mut name_buf2 = [0u8; MAX_NAME_LEN];
            name_buf2[..6].copy_from_slice(b"enable");
            self.entries[en_idx] = TracefsEntry {
                kind: TracefsEntryKind::SubsysEnable,
                name: name_buf2,
                name_len: 6,
                parent: idx,
                payload_idx: 0,
                active: true,
            };
        }
        Ok(idx)
    }

    // --- Per-CPU ring buffer operations -------------------------------------

    /// Record a trace event into the per-CPU structured ring buffer.
    ///
    /// Only records if global tracing is on, the event is enabled,
    /// and the current tracer supports event recording.
    pub fn record_event(
        &mut self,
        cpu: usize,
        timestamp: u64,
        event_idx: usize,
        pid: u32,
        payload: &[u8],
    ) -> Result<()> {
        if !self.tracing_on {
            return Ok(());
        }
        if cpu >= self.num_cpus {
            return Err(Error::InvalidArgument);
        }
        if event_idx >= self.event_count || !self.events[event_idx].active {
            return Err(Error::NotFound);
        }
        if !self.events[event_idx].enabled {
            return Ok(());
        }

        let record = TraceRecord::new(timestamp, event_idx as u16, cpu as u8, pid, payload);
        self.ring_buffers[cpu].push(record);

        // Also write a formatted line to the byte-level pipe.
        let mut line_buf = [0u8; 256];
        let line_len = record.format_into(&mut line_buf);
        self.pipe.write(&line_buf[..line_len]);

        Ok(())
    }

    /// Read structured trace records from all CPUs (non-destructive).
    ///
    /// Formats records into `buf` and returns bytes written.
    pub fn read_ring_buffers(&self, offset: u64, buf: &mut [u8]) -> usize {
        let mut tmp = [0u8; 4096];
        let mut pos = 0usize;

        for cpu_idx in 0..self.num_cpus {
            let ring = &self.ring_buffers[cpu_idx];
            let count = ring.record_count();
            for i in 0..count {
                if let Some(record) = ring.peek(i) {
                    if pos + 128 > tmp.len() {
                        break;
                    }
                    let written = record.format_into(&mut tmp[pos..]);
                    pos += written;
                }
            }
        }

        let off = offset as usize;
        if off >= pos {
            return 0;
        }
        let available = pos - off;
        let to_copy = buf.len().min(available);
        buf[..to_copy].copy_from_slice(&tmp[off..off + to_copy]);
        to_copy
    }

    /// Consume structured trace records from all CPUs (destructive).
    ///
    /// Returns bytes written.
    pub fn consume_ring_buffers(&mut self, buf: &mut [u8]) -> usize {
        let mut pos = 0usize;

        for cpu_idx in 0..self.num_cpus {
            let ring = &mut self.ring_buffers[cpu_idx];
            while let Some(record) = ring.pop() {
                let remaining = buf.len().saturating_sub(pos);
                if remaining < 32 {
                    break;
                }
                let written = record.format_into(&mut buf[pos..]);
                pos += written;
            }
        }
        pos
    }

    /// Clear all per-CPU ring buffers.
    pub fn clear_ring_buffers(&mut self) {
        for rb in &mut self.ring_buffers {
            rb.clear();
        }
    }

    // --- Instance management ------------------------------------------------

    /// Create a named trace instance.
    ///
    /// Returns the instance index. Fails if the name already exists or
    /// the instance table is full.
    pub fn create_instance(&mut self, name: &[u8]) -> Result<usize> {
        // Check for duplicate.
        for inst in &self.instances {
            if inst.active && inst.name_bytes() == name {
                return Err(Error::AlreadyExists);
            }
        }
        if self.instance_count >= MAX_INSTANCES {
            return Err(Error::OutOfMemory);
        }

        let instance = TraceInstance::new(name)?;

        // Create directory under instances/.
        let idx = self.alloc_entry()?;
        let copy_len = name.len().min(MAX_NAME_LEN);
        let mut name_buf = [0u8; MAX_NAME_LEN];
        name_buf[..copy_len].copy_from_slice(&name[..copy_len]);
        self.entries[idx] = TracefsEntry {
            kind: TracefsEntryKind::Dir,
            name: name_buf,
            name_len: copy_len,
            parent: self.instances_dir_idx,
            payload_idx: 0,
            active: true,
        };

        for (i, slot) in self.instances.iter_mut().enumerate() {
            if !slot.active {
                *slot = instance;
                self.instance_count += 1;
                return Ok(i);
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Remove a named trace instance.
    pub fn remove_instance(&mut self, name: &[u8]) -> Result<()> {
        for inst in &mut self.instances {
            if inst.active && inst.name_bytes() == name {
                *inst = TraceInstance::empty();
                self.instance_count = self.instance_count.saturating_sub(1);

                // Remove the directory entry.
                for entry in &mut self.entries {
                    if entry.active
                        && entry.parent == self.instances_dir_idx
                        && entry.name_bytes() == name
                    {
                        entry.active = false;
                        break;
                    }
                }
                return Ok(());
            }
        }
        Err(Error::NotFound)
    }

    /// Find a trace instance by name.
    pub fn find_instance(&self, name: &[u8]) -> Option<&TraceInstance> {
        self.instances
            .iter()
            .find(|i| i.active && i.name_bytes() == name)
    }

    /// Find a mutable trace instance by name.
    pub fn find_instance_mut(&mut self, name: &[u8]) -> Option<&mut TraceInstance> {
        self.instances
            .iter_mut()
            .find(|i| i.active && i.name_bytes() == name)
    }

    /// Return the number of active instances.
    pub fn instance_count(&self) -> usize {
        self.instance_count
    }

    // --- File read/write ----------------------------------------------------

    /// Read the content of the file at tree index `entry_idx` into `buf`.
    ///
    /// Returns the number of bytes written.
    pub fn read_entry(&self, entry_idx: usize, buf: &mut [u8]) -> Result<usize> {
        if entry_idx >= self.entry_count || !self.entries[entry_idx].active {
            return Err(Error::NotFound);
        }
        let entry = &self.entries[entry_idx];
        match entry.kind {
            TracefsEntryKind::TracingOn => {
                let s: &[u8] = if self.tracing_on { b"1\n" } else { b"0\n" };
                let len = s.len().min(buf.len());
                buf[..len].copy_from_slice(&s[..len]);
                Ok(len)
            }
            TracefsEntryKind::Trace => {
                let pipe_n = self.pipe.peek(buf);
                if pipe_n > 0 {
                    return Ok(pipe_n);
                }
                Ok(self.read_ring_buffers(0, buf))
            }
            TracefsEntryKind::TracePipe => {
                let n = self.pipe.peek(buf);
                Ok(n)
            }
            TracefsEntryKind::TraceClock => {
                let n = self.format_trace_clock(buf);
                Ok(n)
            }
            TracefsEntryKind::BufferSizeKb => {
                let n = fmt_u32(buf, self.buffer_size_kb);
                Ok(n)
            }
            TracefsEntryKind::CurrentTracer => {
                let len = self.current_tracer_len.min(buf.len());
                buf[..len].copy_from_slice(&self.current_tracer[..len]);
                Ok(len)
            }
            TracefsEntryKind::TraceOptions => {
                let n = self.format_trace_options(buf);
                Ok(n)
            }
            TracefsEntryKind::SetFtraceFilter => {
                let n = self.ftrace_filter.format_list(buf, false);
                Ok(n)
            }
            TracefsEntryKind::SetFtraceNotrace => {
                let n = self.ftrace_filter.format_list(buf, true);
                Ok(n)
            }
            TracefsEntryKind::EventEnable | TracefsEntryKind::SubsysEnable => {
                let enabled = if entry.kind == TracefsEntryKind::EventEnable {
                    self.events
                        .get(entry.payload_idx)
                        .map_or(false, |e| e.enabled)
                } else {
                    let parent_name = self.entries[entry.parent].name_bytes();
                    self.events[..self.event_count]
                        .iter()
                        .any(|e| e.active && e.subsystem_bytes() == parent_name && e.enabled)
                };
                let s: &[u8] = if enabled { b"1\n" } else { b"0\n" };
                let len = s.len().min(buf.len());
                buf[..len].copy_from_slice(&s[..len]);
                Ok(len)
            }
            TracefsEntryKind::EventFormat => {
                let ev = self
                    .events
                    .get(entry.payload_idx)
                    .filter(|e| e.active)
                    .ok_or(Error::NotFound)?;
                let fmt = ev.format_bytes();
                let len = fmt.len().min(buf.len());
                buf[..len].copy_from_slice(&fmt[..len]);
                Ok(len)
            }
            TracefsEntryKind::EventFilter => {
                let ev = self
                    .events
                    .get(entry.payload_idx)
                    .filter(|e| e.active)
                    .ok_or(Error::NotFound)?;
                let filter = ev.filter.expr_bytes();
                if filter.is_empty() {
                    let msg = b"none\n";
                    let len = msg.len().min(buf.len());
                    buf[..len].copy_from_slice(&msg[..len]);
                    Ok(len)
                } else {
                    let len = filter.len().min(buf.len());
                    buf[..len].copy_from_slice(&filter[..len]);
                    let nl = copy_bytes(&mut buf[len..], b"\n");
                    Ok(len + nl)
                }
            }
            TracefsEntryKind::EventTrigger => {
                let ev = self
                    .events
                    .get(entry.payload_idx)
                    .filter(|e| e.active)
                    .ok_or(Error::NotFound)?;
                let n = self.format_triggers(ev, buf);
                Ok(n)
            }
            TracefsEntryKind::Dir => Err(Error::InvalidArgument),
        }
    }

    /// Write to the file at tree index `entry_idx`.
    ///
    /// Returns the number of bytes consumed.
    pub fn write_entry(&mut self, entry_idx: usize, data: &[u8]) -> Result<usize> {
        if entry_idx >= self.entry_count || !self.entries[entry_idx].active {
            return Err(Error::NotFound);
        }
        let kind = self.entries[entry_idx].kind;
        let payload_idx = self.entries[entry_idx].payload_idx;
        let parent = self.entries[entry_idx].parent;

        match kind {
            TracefsEntryKind::TracingOn => {
                let trimmed = trim_newline(data);
                match trimmed {
                    b"1" => self.tracing_on = true,
                    b"0" => self.tracing_on = false,
                    _ => return Err(Error::InvalidArgument),
                }
                Ok(data.len())
            }
            TracefsEntryKind::Trace => {
                self.pipe.clear();
                self.clear_ring_buffers();
                Ok(data.len())
            }
            TracefsEntryKind::TracePipe => Err(Error::PermissionDenied),
            TracefsEntryKind::TraceClock => {
                let trimmed = trim_newline(data);
                self.clock = TraceClockSource::from_bytes(trimmed)?;
                Ok(data.len())
            }
            TracefsEntryKind::BufferSizeKb => {
                let trimmed = trim_newline(data);
                let kb = parse_u32(trimmed)?;
                self.buffer_size_kb = kb;
                Ok(data.len())
            }
            TracefsEntryKind::CurrentTracer => {
                let trimmed = trim_newline(data);
                if trimmed.len() > TRACER_NAME_LEN {
                    return Err(Error::InvalidArgument);
                }
                self.current_tracer[..trimmed.len()].copy_from_slice(trimmed);
                self.current_tracer_len = trimmed.len();
                Ok(data.len())
            }
            TracefsEntryKind::TraceOptions => Err(Error::PermissionDenied),
            TracefsEntryKind::SetFtraceFilter => {
                self.ftrace_filter.add(data, false)?;
                Ok(data.len())
            }
            TracefsEntryKind::SetFtraceNotrace => {
                self.ftrace_filter.add(data, true)?;
                Ok(data.len())
            }
            TracefsEntryKind::EventEnable => {
                let trimmed = trim_newline(data);
                let enable = match trimmed {
                    b"1" => true,
                    b"0" => false,
                    _ => return Err(Error::InvalidArgument),
                };
                if payload_idx >= self.event_count || !self.events[payload_idx].active {
                    return Err(Error::NotFound);
                }
                self.events[payload_idx].enabled = enable;
                Ok(data.len())
            }
            TracefsEntryKind::SubsysEnable => {
                let trimmed = trim_newline(data);
                let enable = match trimmed {
                    b"1" => true,
                    b"0" => false,
                    _ => return Err(Error::InvalidArgument),
                };
                let subsys_name_buf = self.entries[parent].name;
                let subsys_name_len = self.entries[parent].name_len;
                let subsys_name = &subsys_name_buf[..subsys_name_len];
                for ev in self.events[..self.event_count].iter_mut() {
                    if ev.active && ev.subsystem_bytes() == subsys_name {
                        ev.enabled = enable;
                    }
                }
                Ok(data.len())
            }
            TracefsEntryKind::EventFormat => Err(Error::PermissionDenied),
            TracefsEntryKind::EventFilter => {
                if payload_idx >= self.event_count || !self.events[payload_idx].active {
                    return Err(Error::NotFound);
                }
                self.events[payload_idx].filter.set(data)?;
                Ok(data.len())
            }
            TracefsEntryKind::EventTrigger => {
                if payload_idx >= self.event_count || !self.events[payload_idx].active {
                    return Err(Error::NotFound);
                }
                let trimmed = trim_newline(data);
                if trimmed.first() == Some(&b'!') {
                    self.events[payload_idx].clear_triggers();
                } else {
                    let action = TriggerAction::from_bytes(trimmed)?;
                    self.events[payload_idx].add_trigger(action)?;
                }
                Ok(data.len())
            }
            TracefsEntryKind::Dir => Err(Error::InvalidArgument),
        }
    }

    /// Consume bytes from the trace pipe into `buf` (destructive read).
    pub fn consume_trace_pipe(&mut self, buf: &mut [u8]) -> usize {
        self.pipe.read(buf)
    }

    /// Append `msg` to the trace pipe (called by the tracing subsystem).
    ///
    /// Silently discards data if tracing is disabled.
    pub fn trace_write(&mut self, msg: &[u8]) {
        if self.tracing_on {
            self.pipe.write(msg);
        }
    }

    // --- Formatting helpers -------------------------------------------------

    /// Format the `trace_clock` content showing available clocks with the
    /// active one in brackets.
    fn format_trace_clock(&self, buf: &mut [u8]) -> usize {
        let clocks = [
            TraceClockSource::Local,
            TraceClockSource::Global,
            TraceClockSource::Counter,
            TraceClockSource::Tai,
        ];
        let mut pos = 0;
        for (i, clock) in clocks.iter().enumerate() {
            if i > 0 {
                pos += copy_bytes(&mut buf[pos..], b" ");
            }
            if *clock == self.clock {
                pos += copy_bytes(&mut buf[pos..], b"[");
                pos += copy_bytes(&mut buf[pos..], clock.name_bytes());
                pos += copy_bytes(&mut buf[pos..], b"]");
            } else {
                pos += copy_bytes(&mut buf[pos..], clock.name_bytes());
            }
        }
        pos += copy_bytes(&mut buf[pos..], b"\n");
        pos
    }

    /// Format the `trace_options` content.
    fn format_trace_options(&self, buf: &mut [u8]) -> usize {
        let options = b"print-parent nosym-offset nosym-addr noverbose \
noraw nohex nobin noblock trace_printk annotate \
nouserstacktrace nosym-userobj noprintk-msg-only \
context-info nolatency-format record-cmd overwrite\n";
        let len = options.len().min(buf.len());
        buf[..len].copy_from_slice(&options[..len]);
        len
    }

    /// Format trigger list for an event into `buf`. Returns bytes written.
    fn format_triggers(&self, event: &TraceEvent, buf: &mut [u8]) -> usize {
        let mut pos = 0;
        let count = event.trigger_count as usize;
        if count == 0 {
            return copy_bytes(buf, b"# none\n");
        }
        for trigger in &event.triggers[..count] {
            if let Some(action) = trigger {
                pos += copy_bytes(&mut buf[pos..], action.as_str().as_bytes());
                pos += copy_bytes(&mut buf[pos..], b"\n");
            }
        }
        pos
    }

    // --- Lookup -------------------------------------------------------------

    /// Find the tree index of the entry with `name` under `parent_idx`.
    pub fn find_child(&self, parent_idx: usize, name: &[u8]) -> Option<usize> {
        self.entries[..self.entry_count]
            .iter()
            .position(|e| e.active && e.parent == parent_idx && e.name_bytes() == name)
    }

    /// Find entry index by absolute path (e.g. `b"tracing_on"`).
    ///
    /// Supports single-component (root-relative) and multi-component paths
    /// separated by `b'/'`.
    pub fn lookup_path(&self, path: &[u8]) -> Option<usize> {
        let path = if path.first() == Some(&b'/') {
            &path[1..]
        } else {
            path
        };
        if path.is_empty() {
            return Some(0);
        }
        let mut current = 0usize;
        for component in path.split(|&b| b == b'/') {
            if component.is_empty() {
                continue;
            }
            current = self.find_child(current, component)?;
        }
        Some(current)
    }

    /// Enable or disable a named event.
    pub fn set_event_enabled(&mut self, subsystem: &[u8], name: &[u8], enable: bool) -> Result<()> {
        for ev in self.events[..self.event_count].iter_mut() {
            if ev.active && ev.subsystem_bytes() == subsystem && ev.name_bytes() == name {
                ev.enabled = enable;
                return Ok(());
            }
        }
        Err(Error::NotFound)
    }

    /// Return whether a named event is currently enabled.
    pub fn is_event_enabled(&self, subsystem: &[u8], name: &[u8]) -> bool {
        self.events[..self.event_count].iter().any(|e| {
            e.active && e.subsystem_bytes() == subsystem && e.name_bytes() == name && e.enabled
        })
    }

    /// Total registered events.
    pub fn event_count(&self) -> usize {
        self.event_count
    }

    /// Total tree entries (including freed slots up to high-water mark).
    pub fn entry_count(&self) -> usize {
        self.entry_count
    }

    /// Return the current tracer name as a byte slice.
    pub fn current_tracer_bytes(&self) -> &[u8] {
        &self.current_tracer[..self.current_tracer_len]
    }
}

impl Default for TracefsSuperblock {
    fn default() -> Self {
        Self::new()
    }
}

impl core::fmt::Debug for TracefsSuperblock {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("TracefsSuperblock")
            .field("mounted", &self.mounted)
            .field("tracing_on", &self.tracing_on)
            .field("event_count", &self.event_count)
            .field("instance_count", &self.instance_count)
            .field("pipe_available", &self.pipe.available())
            .field("num_cpus", &self.num_cpus)
            .finish()
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Trim a single trailing newline from a byte slice.
fn trim_newline(data: &[u8]) -> &[u8] {
    if data.last() == Some(&b'\n') {
        &data[..data.len() - 1]
    } else {
        data
    }
}

/// Copy bytes from `src` into `buf`. Returns bytes written.
fn copy_bytes(buf: &mut [u8], src: &[u8]) -> usize {
    let len = src.len().min(buf.len());
    buf[..len].copy_from_slice(&src[..len]);
    len
}

/// Format a `u64` as decimal ASCII into `buf`. Returns bytes written.
fn fmt_u64(buf: &mut [u8], value: u64) -> usize {
    if buf.is_empty() {
        return 0;
    }
    if value == 0 {
        buf[0] = b'0';
        return 1;
    }
    let mut tmp = [0u8; 20];
    let mut pos = tmp.len();
    let mut v = value;
    while v > 0 {
        pos -= 1;
        tmp[pos] = b'0' + (v % 10) as u8;
        v /= 10;
    }
    let digits = &tmp[pos..];
    let len = digits.len().min(buf.len());
    buf[..len].copy_from_slice(&digits[..len]);
    len
}

/// Format a `u32` as decimal ASCII into `buf`, appending `\n`.
/// Returns bytes written.
fn fmt_u32(buf: &mut [u8], value: u32) -> usize {
    let mut tmp = [0u8; 11];
    let mut pos = tmp.len();
    let mut v = value;
    if v == 0 {
        if buf.is_empty() {
            return 0;
        }
        buf[0] = b'0';
        if buf.len() > 1 {
            buf[1] = b'\n';
            return 2;
        }
        return 1;
    }
    while v > 0 {
        pos -= 1;
        tmp[pos] = b'0' + (v % 10) as u8;
        v /= 10;
    }
    let digits = &tmp[pos..];
    let need = digits.len() + 1;
    let write_len = need.min(buf.len());
    let copy_d = write_len.min(digits.len());
    buf[..copy_d].copy_from_slice(&digits[..copy_d]);
    if write_len > digits.len() {
        buf[digits.len()] = b'\n';
    }
    write_len
}

/// Parse a `u32` from decimal ASCII bytes (optional trailing newline).
fn parse_u32(data: &[u8]) -> Result<u32> {
    let mut result: u32 = 0;
    for &b in data {
        if !b.is_ascii_digit() {
            return Err(Error::InvalidArgument);
        }
        result = result
            .checked_mul(10)
            .and_then(|r| r.checked_add((b - b'0') as u32))
            .ok_or(Error::InvalidArgument)?;
    }
    Ok(result)
}

// ---------------------------------------------------------------------------
// Global singleton
// ---------------------------------------------------------------------------

/// Global tracefs superblock.
static mut TRACEFS_SB: Option<TracefsSuperblock> = None;

/// Initialise the global tracefs superblock.
///
/// # Safety
///
/// Must be called exactly once during single-threaded kernel initialisation.
pub unsafe fn tracefs_init() {
    // SAFETY: Single-threaded init; no concurrent access.
    unsafe {
        *core::ptr::addr_of_mut!(TRACEFS_SB) = Some(TracefsSuperblock::new());
    }
}

/// Obtain a shared reference to the global tracefs superblock.
pub fn tracefs_get() -> Option<&'static TracefsSuperblock> {
    // SAFETY: Read-only after init; never moved.
    unsafe { (*core::ptr::addr_of!(TRACEFS_SB)).as_ref() }
}

/// Obtain a mutable reference to the global tracefs superblock.
///
/// # Safety
///
/// The caller must ensure no other reference is live.
pub unsafe fn tracefs_get_mut() -> Option<&'static mut TracefsSuperblock> {
    // SAFETY: Caller guarantees exclusive access.
    unsafe { (*core::ptr::addr_of_mut!(TRACEFS_SB)).as_mut() }
}
