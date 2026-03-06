// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Audit subsystem core.
//!
//! Provides structured audit logging for security-relevant kernel events.
//! Implements the core record format, filtering, and ring buffer used by
//! the higher-level audit rules layer (`audit_rules.rs`).
//!
//! # Architecture
//!
//! | Component           | Purpose                                            |
//! |---------------------|----------------------------------------------------|
//! | [`AuditEventType`]  | Numeric event type identifiers (SYSCALL, PATH, …)  |
//! | [`AuditRecord`]     | A single audit record with fields                  |
//! | [`AuditField`]      | A key=value pair within a record                   |
//! | [`AuditFilter`]     | Simple filter matching event type and UID ranges   |
//! | [`AuditRingBuffer`] | Fixed-size circular buffer of audit records        |
//! | [`AuditCore`]       | Top-level audit subsystem state                    |
//!
//! # Record Lifecycle
//!
//! ```text
//! Kernel event → audit_core::emit() → filter check → AuditRingBuffer
//!                                                         ↓
//!                                             userspace audit daemon reads
//! ```

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum number of fields per audit record.
pub const MAX_FIELDS_PER_RECORD: usize = 32;

/// Maximum field name length (bytes).
pub const MAX_FIELD_NAME_LEN: usize = 32;

/// Maximum field value length (bytes).
pub const MAX_FIELD_VALUE_LEN: usize = 128;

/// Ring buffer capacity (number of records).
pub const RING_BUFFER_CAPACITY: usize = 512;

/// Maximum number of audit filters.
pub const MAX_FILTERS: usize = 64;

// ---------------------------------------------------------------------------
// Event types
// ---------------------------------------------------------------------------

/// Audit event type codes (subset of Linux audit_type values).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum AuditEventType {
    /// Syscall entry/exit record.
    Syscall = 1300,
    /// File path associated with a syscall.
    Path = 1302,
    /// IPC record.
    Ipc = 1303,
    /// Socket record.
    Socket = 1304,
    /// Audit configuration change.
    Config = 1305,
    /// User-space audit message.
    User = 1309,
    /// Login event.
    Login = 1006,
    /// User start event.
    UserStart = 1103,
    /// User end event.
    UserEnd = 1104,
    /// Process credential change.
    CredAcq = 1403,
    /// Security module event.
    Selinux = 1400,
    /// Integrity check event.
    Integrity = 1800,
    /// Kernel module load/unload.
    KernModule = 1315,
    /// Capability use.
    CapUse = 1123,
    /// Unknown / generic event.
    Unknown = 0,
}

impl Default for AuditEventType {
    fn default() -> Self {
        Self::Unknown
    }
}

// ---------------------------------------------------------------------------
// Audit field
// ---------------------------------------------------------------------------

/// A single key=value field within an audit record.
#[derive(Debug, Clone, Copy)]
pub struct AuditField {
    /// Field name (NUL-terminated).
    pub name: [u8; MAX_FIELD_NAME_LEN],
    /// Field value (NUL-terminated).
    pub value: [u8; MAX_FIELD_VALUE_LEN],
    /// Length of the name string.
    pub name_len: u8,
    /// Length of the value string.
    pub value_len: u8,
}

impl AuditField {
    /// Create an empty audit field.
    pub const fn empty() -> Self {
        Self {
            name: [0u8; MAX_FIELD_NAME_LEN],
            value: [0u8; MAX_FIELD_VALUE_LEN],
            name_len: 0,
            value_len: 0,
        }
    }

    /// Set the field name from a byte slice (truncated to fit).
    pub fn set_name(&mut self, s: &[u8]) {
        let len = s.len().min(MAX_FIELD_NAME_LEN);
        self.name[..len].copy_from_slice(&s[..len]);
        self.name_len = len as u8;
    }

    /// Set the field value from a byte slice (truncated to fit).
    pub fn set_value(&mut self, s: &[u8]) {
        let len = s.len().min(MAX_FIELD_VALUE_LEN);
        self.value[..len].copy_from_slice(&s[..len]);
        self.value_len = len as u8;
    }

    /// Return the name as a byte slice.
    pub fn name_bytes(&self) -> &[u8] {
        &self.name[..self.name_len as usize]
    }

    /// Return the value as a byte slice.
    pub fn value_bytes(&self) -> &[u8] {
        &self.value[..self.value_len as usize]
    }
}

impl Default for AuditField {
    fn default() -> Self {
        Self::empty()
    }
}

// ---------------------------------------------------------------------------
// Audit record
// ---------------------------------------------------------------------------

/// A single audit record.
#[derive(Debug, Clone, Copy)]
pub struct AuditRecord {
    /// Monotonic timestamp in nanoseconds.
    pub timestamp_ns: u64,
    /// Unique sequential record serial number.
    pub serial: u64,
    /// Event type.
    pub event_type: AuditEventType,
    /// UID of the process that triggered this event.
    pub uid: u32,
    /// GID of the process that triggered this event.
    pub gid: u32,
    /// PID of the process that triggered this event.
    pub pid: u32,
    /// Syscall number (for Syscall records), else 0.
    pub syscall_nr: u32,
    /// Return value / result code.
    pub result: i32,
    /// Fields attached to this record.
    pub fields: [AuditField; MAX_FIELDS_PER_RECORD],
    /// Number of populated fields.
    pub field_count: u8,
}

impl AuditRecord {
    /// Create a blank audit record.
    pub const fn new(event_type: AuditEventType) -> Self {
        Self {
            timestamp_ns: 0,
            serial: 0,
            event_type,
            uid: 0,
            gid: 0,
            pid: 0,
            syscall_nr: 0,
            result: 0,
            fields: [AuditField {
                name: [0u8; MAX_FIELD_NAME_LEN],
                value: [0u8; MAX_FIELD_VALUE_LEN],
                name_len: 0,
                value_len: 0,
            }; MAX_FIELDS_PER_RECORD],
            field_count: 0,
        }
    }

    /// Add a field to the record.
    pub fn add_field(&mut self, name: &[u8], value: &[u8]) -> Result<()> {
        if self.field_count as usize >= MAX_FIELDS_PER_RECORD {
            return Err(Error::OutOfMemory);
        }
        let idx = self.field_count as usize;
        self.fields[idx].set_name(name);
        self.fields[idx].set_value(value);
        self.field_count += 1;
        Ok(())
    }

    /// Iterate over populated fields.
    pub fn fields(&self) -> &[AuditField] {
        &self.fields[..self.field_count as usize]
    }
}

impl Default for AuditRecord {
    fn default() -> Self {
        Self::new(AuditEventType::Unknown)
    }
}

// ---------------------------------------------------------------------------
// Audit filter
// ---------------------------------------------------------------------------

/// Filter action: whether matching records should be logged.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum FilterAction {
    /// Log the record (default).
    #[default]
    Log,
    /// Suppress the record.
    Suppress,
}

/// A simple audit filter matching on event type and UID range.
#[derive(Debug, Clone, Copy)]
pub struct AuditFilter {
    /// Event type to match (None = match all).
    pub event_type: Option<AuditEventType>,
    /// Minimum UID (inclusive). u32::MIN = no lower bound.
    pub uid_min: u32,
    /// Maximum UID (inclusive). u32::MAX = no upper bound.
    pub uid_max: u32,
    /// Action for matching records.
    pub action: FilterAction,
    /// Whether this filter slot is active.
    pub active: bool,
}

impl AuditFilter {
    /// Create a new catch-all log filter.
    pub const fn new_log_all() -> Self {
        Self {
            event_type: None,
            uid_min: 0,
            uid_max: u32::MAX,
            action: FilterAction::Log,
            active: true,
        }
    }

    /// Returns true if this filter matches the given record.
    pub fn matches(&self, record: &AuditRecord) -> bool {
        if !self.active {
            return false;
        }
        if let Some(et) = self.event_type {
            if et != record.event_type {
                return false;
            }
        }
        record.uid >= self.uid_min && record.uid <= self.uid_max
    }
}

impl Default for AuditFilter {
    fn default() -> Self {
        Self::new_log_all()
    }
}

// ---------------------------------------------------------------------------
// Ring buffer
// ---------------------------------------------------------------------------

/// Fixed-size circular buffer of audit records.
pub struct AuditRingBuffer {
    records: [AuditRecord; RING_BUFFER_CAPACITY],
    head: usize,
    tail: usize,
    count: usize,
    dropped: u64,
}

impl AuditRingBuffer {
    /// Create a new empty ring buffer.
    pub const fn new() -> Self {
        Self {
            records: [AuditRecord {
                timestamp_ns: 0,
                serial: 0,
                event_type: AuditEventType::Unknown,
                uid: 0,
                gid: 0,
                pid: 0,
                syscall_nr: 0,
                result: 0,
                fields: [AuditField {
                    name: [0u8; MAX_FIELD_NAME_LEN],
                    value: [0u8; MAX_FIELD_VALUE_LEN],
                    name_len: 0,
                    value_len: 0,
                }; MAX_FIELDS_PER_RECORD],
                field_count: 0,
            }; RING_BUFFER_CAPACITY],
            head: 0,
            tail: 0,
            count: 0,
            dropped: 0,
        }
    }

    /// Returns true if the buffer is full.
    pub fn is_full(&self) -> bool {
        self.count == RING_BUFFER_CAPACITY
    }

    /// Returns true if the buffer is empty.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Push a record. If full, the oldest record is overwritten and `dropped`
    /// is incremented.
    pub fn push(&mut self, record: AuditRecord) {
        if self.is_full() {
            // Overwrite oldest.
            self.head = (self.head + 1) % RING_BUFFER_CAPACITY;
            self.dropped = self.dropped.saturating_add(1);
        } else {
            self.count += 1;
        }
        self.records[self.tail] = record;
        self.tail = (self.tail + 1) % RING_BUFFER_CAPACITY;
    }

    /// Pop the oldest record.
    pub fn pop(&mut self) -> Option<AuditRecord> {
        if self.is_empty() {
            return None;
        }
        let record = self.records[self.head];
        self.head = (self.head + 1) % RING_BUFFER_CAPACITY;
        self.count -= 1;
        Some(record)
    }

    /// Number of records in the buffer.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Number of records dropped due to buffer overflow.
    pub fn dropped(&self) -> u64 {
        self.dropped
    }
}

impl Default for AuditRingBuffer {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Audit core
// ---------------------------------------------------------------------------

/// Top-level audit subsystem state.
pub struct AuditCore {
    /// Record ring buffer.
    buffer: AuditRingBuffer,
    /// Active filters.
    filters: [AuditFilter; MAX_FILTERS],
    /// Number of active filters.
    filter_count: usize,
    /// Next serial number to assign.
    next_serial: u64,
    /// Whether auditing is globally enabled.
    enabled: bool,
    /// Total records emitted.
    total_emitted: u64,
    /// Total records suppressed by filters.
    total_suppressed: u64,
}

impl AuditCore {
    /// Create a new audit core (disabled by default).
    pub const fn new() -> Self {
        Self {
            buffer: AuditRingBuffer {
                records: [AuditRecord {
                    timestamp_ns: 0,
                    serial: 0,
                    event_type: AuditEventType::Unknown,
                    uid: 0,
                    gid: 0,
                    pid: 0,
                    syscall_nr: 0,
                    result: 0,
                    fields: [AuditField {
                        name: [0u8; MAX_FIELD_NAME_LEN],
                        value: [0u8; MAX_FIELD_VALUE_LEN],
                        name_len: 0,
                        value_len: 0,
                    }; MAX_FIELDS_PER_RECORD],
                    field_count: 0,
                }; RING_BUFFER_CAPACITY],
                head: 0,
                tail: 0,
                count: 0,
                dropped: 0,
            },
            filters: [AuditFilter {
                event_type: None,
                uid_min: 0,
                uid_max: u32::MAX,
                action: FilterAction::Log,
                active: false,
            }; MAX_FILTERS],
            filter_count: 0,
            next_serial: 1,
            enabled: false,
            total_emitted: 0,
            total_suppressed: 0,
        }
    }

    /// Enable or disable the audit subsystem.
    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }

    /// Returns true if auditing is enabled.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Add a filter. Returns error if filter table is full.
    pub fn add_filter(&mut self, filter: AuditFilter) -> Result<()> {
        if self.filter_count >= MAX_FILTERS {
            return Err(Error::OutOfMemory);
        }
        self.filters[self.filter_count] = filter;
        self.filter_count += 1;
        Ok(())
    }

    /// Remove all filters.
    pub fn clear_filters(&mut self) {
        for f in self.filters.iter_mut() {
            f.active = false;
        }
        self.filter_count = 0;
    }

    /// Emit a record, applying filters.
    ///
    /// `timestamp_ns` is a monotonic clock reading provided by the caller.
    pub fn emit(&mut self, mut record: AuditRecord, timestamp_ns: u64) {
        if !self.enabled {
            return;
        }
        record.timestamp_ns = timestamp_ns;
        record.serial = self.next_serial;
        self.next_serial = self.next_serial.wrapping_add(1);

        // Apply filters — first matching filter wins.
        let mut action = FilterAction::Log;
        for i in 0..self.filter_count {
            if self.filters[i].matches(&record) {
                action = self.filters[i].action;
                break;
            }
        }

        match action {
            FilterAction::Log => {
                self.buffer.push(record);
                self.total_emitted = self.total_emitted.saturating_add(1);
            }
            FilterAction::Suppress => {
                self.total_suppressed = self.total_suppressed.saturating_add(1);
            }
        }
    }

    /// Drain one record from the buffer.
    pub fn drain_one(&mut self) -> Option<AuditRecord> {
        self.buffer.pop()
    }

    /// Number of records currently buffered.
    pub fn buffered(&self) -> usize {
        self.buffer.len()
    }

    /// Records dropped due to ring buffer overflow.
    pub fn dropped(&self) -> u64 {
        self.buffer.dropped()
    }

    /// Total records emitted (passed filters).
    pub fn total_emitted(&self) -> u64 {
        self.total_emitted
    }

    /// Total records suppressed by filters.
    pub fn total_suppressed(&self) -> u64 {
        self.total_suppressed
    }
}

impl Default for AuditCore {
    fn default() -> Self {
        Self::new()
    }
}
