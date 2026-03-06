// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Kernel audit subsystem.
//!
//! Provides a security-oriented event logging facility for tracking
//! system calls, file access, process lifecycle, capability usage,
//! and security violations. Events are stored in a fixed-size
//! circular ring buffer with sequence numbering, filtering, and
//! rate limiting.
//!
//! # Architecture
//!
//! ```text
//!  audit_log()───► AuditConfig ──► AuditFilter ──► AuditLog
//!                  (enabled?       (type/pid/uid    (ring buffer,
//!                   rate limit?)    severity?)       seq numbers)
//! ```
//!
//! Reference: Linux `kernel/audit.c`, `include/linux/audit.h`.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Maximum message length stored in a single audit event (bytes).
const MAX_MSG_LEN: usize = 128;

/// Number of entries in the audit ring buffer (power of two).
const AUDIT_LOG_SIZE: usize = 512;

/// Maximum formatted audit record line length.
///
/// Layout: `audit[<20 seq>]: ts=<20> type=<18> pid=<20>
/// uid=<20> res=<4> msg=<128>`
const MAX_RECORD_LEN: usize = 280;

// -------------------------------------------------------------------
// AuditEventType
// -------------------------------------------------------------------

/// Kinds of auditable kernel events.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum AuditEventType {
    /// System call invocation.
    Syscall = 0,
    /// File or directory access.
    FileAccess = 1,
    /// Process execution (exec family).
    ProcessExec = 2,
    /// Process termination.
    ProcessExit = 3,
    /// Use of a kernel capability.
    CapabilityUse = 4,
    /// Outbound network connection.
    NetworkConnect = 5,
    /// User login.
    Login = 6,
    /// User logout.
    Logout = 7,
    /// System configuration change.
    ConfigChange = 8,
    /// Security policy violation.
    SecurityViolation = 9,
}

impl AuditEventType {
    /// Convert to a bitmask bit position.
    const fn bit(self) -> u16 {
        1u16 << (self as u16)
    }

    /// Short label for formatted output.
    pub const fn label(self) -> &'static str {
        match self {
            Self::Syscall => "SYSCALL",
            Self::FileAccess => "FILE_ACCESS",
            Self::ProcessExec => "PROC_EXEC",
            Self::ProcessExit => "PROC_EXIT",
            Self::CapabilityUse => "CAP_USE",
            Self::NetworkConnect => "NET_CONN",
            Self::Login => "LOGIN",
            Self::Logout => "LOGOUT",
            Self::ConfigChange => "CONFIG_CHG",
            Self::SecurityViolation => "SEC_VIOLAT",
        }
    }
}

// -------------------------------------------------------------------
// AuditSeverity
// -------------------------------------------------------------------

/// Severity level of an audit event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
#[repr(u8)]
pub enum AuditSeverity {
    /// Informational event (routine operations).
    #[default]
    Info = 0,
    /// Warning (potential issue, not yet critical).
    Warning = 1,
    /// Error (operation failed or policy violated).
    Error = 2,
    /// Critical (immediate attention required).
    Critical = 3,
}

impl AuditSeverity {
    /// Short label for formatted output.
    pub const fn label(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Warning => "warn",
            Self::Error => "err",
            Self::Critical => "crit",
        }
    }
}

impl core::fmt::Display for AuditSeverity {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.label())
    }
}

// -------------------------------------------------------------------
// AuditEvent
// -------------------------------------------------------------------

/// A single audit event record.
#[derive(Debug, Clone, Copy)]
pub struct AuditEvent {
    /// Monotonically increasing sequence number.
    pub sequence: u64,
    /// Kernel tick at the time the event was recorded.
    pub timestamp: u64,
    /// Kind of auditable event.
    pub event_type: AuditEventType,
    /// Process ID associated with this event.
    pub pid: u64,
    /// User ID associated with this event.
    pub uid: u64,
    /// Whether the audited operation succeeded.
    pub success: bool,
    /// Severity classification.
    pub severity: AuditSeverity,
    /// Message bytes (fixed-size buffer).
    msg: [u8; MAX_MSG_LEN],
    /// Valid length of `msg`.
    msg_len: u8,
}

/// Default (empty) audit event for buffer initialization.
const EMPTY_EVENT: AuditEvent = AuditEvent {
    sequence: 0,
    timestamp: 0,
    event_type: AuditEventType::Syscall,
    pid: 0,
    uid: 0,
    success: true,
    severity: AuditSeverity::Info,
    msg: [0; MAX_MSG_LEN],
    msg_len: 0,
};

impl AuditEvent {
    /// Create a new audit event.
    ///
    /// The message is truncated to [`MAX_MSG_LEN`] bytes if longer.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        sequence: u64,
        timestamp: u64,
        event_type: AuditEventType,
        pid: u64,
        uid: u64,
        success: bool,
        severity: AuditSeverity,
        msg: &[u8],
    ) -> Self {
        let mut ev = EMPTY_EVENT;
        ev.sequence = sequence;
        ev.timestamp = timestamp;
        ev.event_type = event_type;
        ev.pid = pid;
        ev.uid = uid;
        ev.success = success;
        ev.severity = severity;
        let len = msg.len().min(MAX_MSG_LEN);
        ev.msg[..len].copy_from_slice(&msg[..len]);
        ev.msg_len = len as u8;
        ev
    }

    /// Message as a byte slice.
    pub fn msg(&self) -> &[u8] {
        &self.msg[..self.msg_len as usize]
    }
}

// -------------------------------------------------------------------
// AuditFilter
// -------------------------------------------------------------------

/// Filter configuration for the audit subsystem.
///
/// Controls which events are recorded. Events must pass all
/// active filter criteria (type bitmask, optional PID, optional
/// UID, minimum severity).
#[derive(Debug, Clone)]
pub struct AuditFilter {
    /// Bitmask of enabled [`AuditEventType`] variants.
    enabled_types: u16,
    /// When `Some(pid)`, only events for that PID pass.
    pub filter_pid: Option<u64>,
    /// When `Some(uid)`, only events for that UID pass.
    pub filter_uid: Option<u64>,
    /// Minimum severity level to pass the filter.
    pub min_severity: AuditSeverity,
}

impl Default for AuditFilter {
    fn default() -> Self {
        Self::new()
    }
}

impl AuditFilter {
    /// Create a new filter with all event types enabled, no
    /// PID/UID restriction, and minimum severity [`AuditSeverity::Info`].
    pub const fn new() -> Self {
        Self {
            enabled_types: u16::MAX,
            filter_pid: None,
            filter_uid: None,
            min_severity: AuditSeverity::Info,
        }
    }

    /// Check whether a specific event type is enabled.
    pub fn is_type_enabled(&self, event_type: AuditEventType) -> bool {
        self.enabled_types & event_type.bit() != 0
    }

    /// Evaluate all filter criteria for a potential audit event.
    pub fn should_audit(
        &self,
        event_type: AuditEventType,
        pid: u64,
        uid: u64,
        severity: AuditSeverity,
    ) -> bool {
        if !self.is_type_enabled(event_type) {
            return false;
        }
        if severity < self.min_severity {
            return false;
        }
        if let Some(fp) = self.filter_pid {
            if fp != pid {
                return false;
            }
        }
        if let Some(fu) = self.filter_uid {
            if fu != uid {
                return false;
            }
        }
        true
    }

    /// Enable auditing for a specific event type.
    pub fn enable_type(&mut self, t: AuditEventType) {
        self.enabled_types |= t.bit();
    }

    /// Disable auditing for a specific event type.
    pub fn disable_type(&mut self, t: AuditEventType) {
        self.enabled_types &= !t.bit();
    }

    /// Enable all event types.
    pub fn enable_all_types(&mut self) {
        self.enabled_types = u16::MAX;
    }

    /// Disable all event types.
    pub fn disable_all_types(&mut self) {
        self.enabled_types = 0;
    }
}

// -------------------------------------------------------------------
// AuditConfig
// -------------------------------------------------------------------

/// Runtime configuration for the audit subsystem.
#[derive(Debug, Clone)]
pub struct AuditConfig {
    /// Whether the audit subsystem is active.
    pub enabled: bool,
    /// Filter settings controlling which events are recorded.
    pub filter: AuditFilter,
    /// Maximum events per second (0 = unlimited).
    pub rate_limit: u32,
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self::new()
    }
}

impl AuditConfig {
    /// Create a default configuration (enabled, all types, no
    /// rate limit).
    pub const fn new() -> Self {
        Self {
            enabled: true,
            filter: AuditFilter::new(),
            rate_limit: 0,
        }
    }
}

// -------------------------------------------------------------------
// AuditStats
// -------------------------------------------------------------------

/// Cumulative statistics for the audit subsystem.
#[derive(Debug, Clone, Copy, Default)]
pub struct AuditStats {
    /// Total events successfully recorded.
    pub total_events: u64,
    /// Events rejected by the filter.
    pub filtered_events: u64,
    /// Events dropped due to rate limiting.
    pub dropped_events: u64,
}

// -------------------------------------------------------------------
// AuditLog
// -------------------------------------------------------------------

/// Circular ring buffer for audit events with sequence numbering.
///
/// Stores up to [`AUDIT_LOG_SIZE`] events. When full, new events
/// overwrite the oldest entries. A monotonically increasing
/// sequence number provides stable cursors for readers.
pub struct AuditLog {
    /// Event storage.
    events: [AuditEvent; AUDIT_LOG_SIZE],
    /// Next write position (monotonically increasing).
    write_pos: usize,
    /// Next sequence number to assign.
    next_seq: u64,
    /// Audit configuration.
    config: AuditConfig,
    /// Cumulative statistics.
    stats: AuditStats,
    /// Events recorded in the current rate-limit window.
    window_count: u32,
    /// Timestamp of the current rate-limit window start.
    window_start: u64,
}

impl Default for AuditLog {
    fn default() -> Self {
        Self::new()
    }
}

impl AuditLog {
    /// Create an empty audit log with default configuration.
    pub const fn new() -> Self {
        Self {
            events: [EMPTY_EVENT; AUDIT_LOG_SIZE],
            write_pos: 0,
            next_seq: 1,
            config: AuditConfig::new(),
            stats: AuditStats {
                total_events: 0,
                filtered_events: 0,
                dropped_events: 0,
            },
            window_count: 0,
            window_start: 0,
        }
    }

    /// Get a reference to the current configuration.
    pub fn config(&self) -> &AuditConfig {
        &self.config
    }

    /// Get a mutable reference to the current configuration.
    pub fn config_mut(&mut self) -> &mut AuditConfig {
        &mut self.config
    }

    /// Get a snapshot of the current statistics.
    pub fn stats(&self) -> &AuditStats {
        &self.stats
    }

    /// Number of events currently stored (up to buffer capacity).
    pub fn count(&self) -> usize {
        self.write_pos.min(AUDIT_LOG_SIZE)
    }

    /// Check if the buffer is empty.
    pub fn is_empty(&self) -> bool {
        self.write_pos == 0
    }

    /// Total events ever written (including overwritten ones).
    pub fn total_written(&self) -> u64 {
        self.stats.total_events
    }

    /// Next sequence number that will be assigned.
    pub fn next_sequence(&self) -> u64 {
        self.next_seq
    }

    /// Clear all events and reset the log.
    ///
    /// Configuration and statistics are preserved.
    pub fn clear(&mut self) {
        self.write_pos = 0;
        self.next_seq = 1;
    }

    /// Record an event into the ring buffer (internal).
    ///
    /// Assigns a sequence number and stores the event. Returns
    /// `true` if an older event was overwritten.
    fn push(&mut self, event: AuditEvent) -> bool {
        let wrapped = self.write_pos >= AUDIT_LOG_SIZE;
        let idx = self.write_pos % AUDIT_LOG_SIZE;
        self.events[idx] = event;
        self.write_pos += 1;
        self.stats.total_events += 1;
        wrapped
    }

    /// Check and update rate limiting for the given timestamp.
    ///
    /// Returns `true` if the event is allowed under the rate
    /// limit.
    fn check_rate_limit(&mut self, timestamp: u64) -> bool {
        if self.config.rate_limit == 0 {
            return true;
        }
        // Simple per-second window: if the timestamp has moved to
        // a new second, reset the window.
        if timestamp != self.window_start {
            self.window_start = timestamp;
            self.window_count = 0;
        }
        if self.window_count >= self.config.rate_limit {
            return false;
        }
        self.window_count += 1;
        true
    }

    /// Read events starting from sequence number `start_seq`.
    ///
    /// Copies up to `buf.len()` matching events into `buf` and
    /// returns the number of entries actually copied. If
    /// `start_seq` refers to an event that has been overwritten,
    /// reading starts from the oldest available event.
    pub fn read_events(&self, start_seq: u64, buf: &mut [AuditEvent]) -> usize {
        if buf.is_empty() || self.write_pos == 0 {
            return 0;
        }
        let oldest_seq = self.next_seq.saturating_sub(self.count() as u64);
        let effective_start = if start_seq < oldest_seq {
            oldest_seq
        } else {
            start_seq
        };
        if effective_start >= self.next_seq {
            return 0;
        }
        let available = (self.next_seq - effective_start) as usize;
        let to_copy = available.min(buf.len());
        for (i, slot) in buf.iter_mut().enumerate().take(to_copy) {
            let seq = effective_start + i as u64;
            // Sequence numbers start at 1; map to physical index.
            let phys = (seq.saturating_sub(1) as usize) % AUDIT_LOG_SIZE;
            *slot = self.events[phys];
        }
        to_copy
    }
}

impl core::fmt::Debug for AuditLog {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("AuditLog")
            .field("entries", &self.count())
            .field("capacity", &AUDIT_LOG_SIZE)
            .field("next_seq", &self.next_seq)
            .field("stats", &self.stats)
            .finish()
    }
}

// -------------------------------------------------------------------
// Public API
// -------------------------------------------------------------------

/// Record an audit event if the subsystem is enabled, the filter
/// passes, and the rate limit allows it.
///
/// # Arguments
///
/// - `log`: the audit log instance
/// - `event_type`: kind of event
/// - `pid`: process ID
/// - `uid`: user ID
/// - `success`: whether the operation succeeded
/// - `msg`: human-readable description (truncated to 128 bytes)
/// - `timestamp`: kernel tick counter
/// - `severity`: event severity level
///
/// # Returns
///
/// The assigned sequence number on success, or an error if the
/// subsystem is disabled, the event is filtered, or rate-limited.
#[allow(clippy::too_many_arguments)]
pub fn audit_log(
    log: &mut AuditLog,
    event_type: AuditEventType,
    pid: u64,
    uid: u64,
    success: bool,
    msg: &[u8],
    timestamp: u64,
    severity: AuditSeverity,
) -> Result<u64> {
    if !log.config.enabled {
        return Err(Error::PermissionDenied);
    }
    if !log
        .config
        .filter
        .should_audit(event_type, pid, uid, severity)
    {
        log.stats.filtered_events += 1;
        return Err(Error::InvalidArgument);
    }
    if !log.check_rate_limit(timestamp) {
        log.stats.dropped_events += 1;
        return Err(Error::Busy);
    }
    let seq = log.next_seq;
    let event = AuditEvent::new(seq, timestamp, event_type, pid, uid, success, severity, msg);
    log.push(event);
    log.next_seq += 1;
    Ok(seq)
}

/// Read audit events starting from a given sequence number.
///
/// Copies up to `buf.len()` events into `buf`. Returns the number
/// of events actually copied.
pub fn audit_read(log: &AuditLog, start_seq: u64, buf: &mut [AuditEvent]) -> usize {
    log.read_events(start_seq, buf)
}

/// Format a single audit event into a human-readable record.
///
/// Output format:
/// `audit[<seq>]: ts=<timestamp> type=<TYPE> pid=<pid>
/// uid=<uid> res=<ok|fail> sev=<severity> msg=<message>`
///
/// Returns the number of bytes written to `buf`, or
/// `Err(InvalidArgument)` if `buf` is too small.
pub fn format_audit_record(event: &AuditEvent, buf: &mut [u8]) -> Result<usize> {
    if buf.len() < 32 {
        return Err(Error::InvalidArgument);
    }
    let cap = buf.len().min(MAX_RECORD_LEN);
    let mut pos = 0;

    // "audit["
    pos = write_bytes(b"audit[", buf, pos, cap);

    // sequence number
    pos = write_u64_decimal(event.sequence, buf, pos, cap);

    // "]: ts="
    pos = write_bytes(b"]: ts=", buf, pos, cap);

    // timestamp
    pos = write_u64_decimal(event.timestamp, buf, pos, cap);

    // " type="
    pos = write_bytes(b" type=", buf, pos, cap);

    // event type label
    pos = write_bytes(event.event_type.label().as_bytes(), buf, pos, cap);

    // " pid="
    pos = write_bytes(b" pid=", buf, pos, cap);
    pos = write_u64_decimal(event.pid, buf, pos, cap);

    // " uid="
    pos = write_bytes(b" uid=", buf, pos, cap);
    pos = write_u64_decimal(event.uid, buf, pos, cap);

    // " res="
    pos = write_bytes(b" res=", buf, pos, cap);
    let res_label: &[u8] = if event.success { b"ok" } else { b"fail" };
    pos = write_bytes(res_label, buf, pos, cap);

    // " sev="
    pos = write_bytes(b" sev=", buf, pos, cap);
    pos = write_bytes(event.severity.label().as_bytes(), buf, pos, cap);

    // " msg="
    pos = write_bytes(b" msg=", buf, pos, cap);
    pos = write_bytes(event.msg(), buf, pos, cap);

    Ok(pos)
}

// -------------------------------------------------------------------
// Helpers
// -------------------------------------------------------------------

/// Copy `src` bytes into `buf` starting at `pos`, respecting `cap`.
/// Returns the new position.
fn write_bytes(src: &[u8], buf: &mut [u8], pos: usize, cap: usize) -> usize {
    let avail = cap.saturating_sub(pos);
    let len = src.len().min(avail);
    buf[pos..pos + len].copy_from_slice(&src[..len]);
    pos + len
}

/// Write a `u64` as decimal ASCII into `buf` starting at `pos`.
/// Returns the new position.
fn write_u64_decimal(val: u64, buf: &mut [u8], pos: usize, cap: usize) -> usize {
    if val == 0 {
        if pos < cap {
            buf[pos] = b'0';
            return pos + 1;
        }
        return pos;
    }
    let mut digits = [0u8; 20];
    let mut n = val;
    let mut count = 0usize;
    while n > 0 {
        digits[count] = b'0' + (n % 10) as u8;
        n /= 10;
        count += 1;
    }
    let mut p = pos;
    let mut i = count;
    while i > 0 && p < cap {
        i -= 1;
        buf[p] = digits[i];
        p += 1;
    }
    p
}
