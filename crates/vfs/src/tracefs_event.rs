// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! tracefs event file management.
//!
//! Implements tracefs event infrastructure: each trace event is exposed
//! as a directory under `/sys/kernel/debug/tracing/events/<system>/<event>/`
//! with files for enable/disable, format, id, and filter.
//!
//! # Components
//!
//! - [`TraceEvent`] — event descriptor with name, id, enabled flag, format
//! - `tracefs_create_event_file` — register a new event in tracefs
//! - Event enable/disable via write to the `enable` file
//! - Format file generation describing the event's field layout
//!
//! # Reference
//!
//! Linux `kernel/trace/trace_events.c`, `kernel/trace/trace.c`.

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum number of trace events.
const MAX_TRACE_EVENTS: usize = 128;

/// Maximum event name length.
const MAX_EVENT_NAME: usize = 64;

/// Maximum system name length.
const MAX_SYSTEM_NAME: usize = 32;

/// Maximum format string length.
const MAX_FORMAT_LEN: usize = 512;

/// Maximum filter expression length.
const MAX_FILTER_LEN: usize = 256;

/// Maximum number of fields per event.
const MAX_FIELDS: usize = 16;

/// Maximum field name length.
const MAX_FIELD_NAME: usize = 32;

// ---------------------------------------------------------------------------
// Event field type
// ---------------------------------------------------------------------------

/// Type of a trace event field.
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
    /// String (fixed length).
    String,
    /// Pointer.
    Ptr,
}

impl FieldType {
    /// Returns the C type name for format output.
    pub fn c_type_name(&self) -> &'static [u8] {
        match self {
            Self::U8 => b"u8",
            Self::U16 => b"u16",
            Self::U32 => b"u32",
            Self::U64 => b"u64",
            Self::I32 => b"int",
            Self::I64 => b"long long",
            Self::String => b"char[]",
            Self::Ptr => b"void *",
        }
    }

    /// Returns the size in bytes.
    pub fn size_bytes(&self) -> usize {
        match self {
            Self::U8 => 1,
            Self::U16 => 2,
            Self::U32 | Self::I32 => 4,
            Self::U64 | Self::I64 | Self::Ptr => 8,
            Self::String => 0, // Variable.
        }
    }
}

// ---------------------------------------------------------------------------
// Event field descriptor
// ---------------------------------------------------------------------------

/// A single field in a trace event.
#[derive(Debug, Clone)]
pub struct TraceField {
    /// Field name.
    pub name: [u8; MAX_FIELD_NAME],
    /// Valid bytes in `name`.
    pub name_len: usize,
    /// Field type.
    pub field_type: FieldType,
    /// Byte offset within the event record.
    pub offset: u16,
    /// Field size.
    pub size: u16,
    /// Whether the field is signed.
    pub is_signed: bool,
}

impl TraceField {
    /// Creates a new trace field.
    pub fn new(name: &[u8], field_type: FieldType, offset: u16) -> Result<Self> {
        if name.is_empty() || name.len() > MAX_FIELD_NAME {
            return Err(Error::InvalidArgument);
        }
        let mut n_buf = [0u8; MAX_FIELD_NAME];
        n_buf[..name.len()].copy_from_slice(name);
        let size = field_type.size_bytes() as u16;
        let is_signed = matches!(field_type, FieldType::I32 | FieldType::I64);
        Ok(Self {
            name: n_buf,
            name_len: name.len(),
            field_type,
            offset,
            size,
            is_signed,
        })
    }

    /// Returns the field name as bytes.
    pub fn name_bytes(&self) -> &[u8] {
        &self.name[..self.name_len]
    }
}

// ---------------------------------------------------------------------------
// Trace event
// ---------------------------------------------------------------------------

/// A single tracefs event entry.
pub struct TraceEvent {
    /// Event name (e.g., "sys_enter_read").
    pub name: [u8; MAX_EVENT_NAME],
    /// Valid bytes in `name`.
    pub name_len: usize,
    /// System name (e.g., "syscalls").
    pub system: [u8; MAX_SYSTEM_NAME],
    /// Valid bytes in `system`.
    pub system_len: usize,
    /// Unique event ID.
    pub id: u32,
    /// Whether tracing is enabled for this event.
    pub enabled: bool,
    /// Format string for this event.
    pub format: [u8; MAX_FORMAT_LEN],
    /// Valid bytes in `format`.
    pub format_len: usize,
    /// Current filter expression.
    pub filter: [u8; MAX_FILTER_LEN],
    /// Valid bytes in `filter`.
    pub filter_len: usize,
    /// Fields of this event.
    pub fields: [Option<TraceField>; MAX_FIELDS],
    /// Number of fields.
    pub field_count: usize,
    /// Number of times this event was triggered.
    pub hit_count: u64,
    /// Whether this event entry is active.
    pub active: bool,
}

impl TraceEvent {
    /// Creates a new trace event.
    pub fn new(name: &[u8], system: &[u8], id: u32) -> Result<Self> {
        if name.is_empty() || name.len() > MAX_EVENT_NAME {
            return Err(Error::InvalidArgument);
        }
        if system.len() > MAX_SYSTEM_NAME {
            return Err(Error::InvalidArgument);
        }
        let mut n_buf = [0u8; MAX_EVENT_NAME];
        n_buf[..name.len()].copy_from_slice(name);
        let mut s_buf = [0u8; MAX_SYSTEM_NAME];
        if !system.is_empty() {
            s_buf[..system.len()].copy_from_slice(system);
        }
        let mut event = Self {
            name: n_buf,
            name_len: name.len(),
            system: s_buf,
            system_len: system.len(),
            id,
            enabled: false,
            format: [0u8; MAX_FORMAT_LEN],
            format_len: 0,
            filter: [0u8; MAX_FILTER_LEN],
            filter_len: 0,
            fields: core::array::from_fn(|_| None),
            field_count: 0,
            hit_count: 0,
            active: true,
        };
        // Generate default format.
        event.regen_format();
        Ok(event)
    }

    /// Returns the event name as bytes.
    pub fn name_bytes(&self) -> &[u8] {
        &self.name[..self.name_len]
    }

    /// Returns the system name as bytes.
    pub fn system_bytes(&self) -> &[u8] {
        &self.system[..self.system_len]
    }

    /// Adds a field to this event.
    pub fn add_field(&mut self, field: TraceField) -> Result<()> {
        if self.field_count >= MAX_FIELDS {
            return Err(Error::OutOfMemory);
        }
        for slot in &mut self.fields {
            if slot.is_none() {
                *slot = Some(field);
                self.field_count += 1;
                self.regen_format();
                return Ok(());
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Enables the event.
    pub fn enable(&mut self) {
        self.enabled = true;
    }

    /// Disables the event.
    pub fn disable(&mut self) {
        self.enabled = false;
    }

    /// Sets the filter expression.
    pub fn set_filter(&mut self, filter: &[u8]) -> Result<()> {
        if filter.len() > MAX_FILTER_LEN {
            return Err(Error::InvalidArgument);
        }
        self.filter[..filter.len()].copy_from_slice(filter);
        self.filter_len = filter.len();
        Ok(())
    }

    /// Regenerates the format string from the current field list.
    fn regen_format(&mut self) {
        // Simple format: "name: <event>\nfield: <type> <name>; ...\n"
        let mut pos = 0usize;
        let out = &mut self.format;

        // Write "name: <event_name>\n"
        let prefix = b"name: ";
        if pos + prefix.len() + self.name_len + 1 <= MAX_FORMAT_LEN {
            out[pos..pos + prefix.len()].copy_from_slice(prefix);
            pos += prefix.len();
            out[pos..pos + self.name_len].copy_from_slice(&self.name[..self.name_len]);
            pos += self.name_len;
            out[pos] = b'\n';
            pos += 1;
        }

        // Write "ID: <id>\n"
        let id_prefix = b"ID: ";
        if pos + id_prefix.len() + 12 <= MAX_FORMAT_LEN {
            out[pos..pos + id_prefix.len()].copy_from_slice(id_prefix);
            pos += id_prefix.len();
            pos += write_u32_to(self.id, &mut out[pos..]);
            if pos < MAX_FORMAT_LEN {
                out[pos] = b'\n';
                pos += 1;
            }
        }

        // Write "format:\n" header.
        let fmt_hdr = b"format:\n";
        if pos + fmt_hdr.len() <= MAX_FORMAT_LEN {
            out[pos..pos + fmt_hdr.len()].copy_from_slice(fmt_hdr);
            pos += fmt_hdr.len();
        }

        // Write each field.
        for field_slot in self.fields[..self.field_count].iter().flatten() {
            let type_name = field_slot.field_type.c_type_name();
            let line_len = 7 + type_name.len() + 1 + field_slot.name_len + 2;
            if pos + line_len > MAX_FORMAT_LEN {
                break;
            }
            let field_prefix = b"\tfield:";
            out[pos..pos + field_prefix.len()].copy_from_slice(field_prefix);
            pos += field_prefix.len();
            out[pos..pos + type_name.len()].copy_from_slice(type_name);
            pos += type_name.len();
            out[pos] = b' ';
            pos += 1;
            out[pos..pos + field_field_name_len(field_slot)]
                .copy_from_slice(&field_slot.name[..field_slot.name_len]);
            pos += field_slot.name_len;
            out[pos] = b';';
            pos += 1;
            out[pos] = b'\n';
            pos += 1;
        }

        self.format_len = pos;
    }
}

fn field_field_name_len(f: &TraceField) -> usize {
    f.name_len
}

fn write_u32_to(mut v: u32, out: &mut [u8]) -> usize {
    if out.is_empty() {
        return 0;
    }
    if v == 0 {
        out[0] = b'0';
        return 1;
    }
    let mut buf = [0u8; 10];
    let mut i = 10usize;
    while v > 0 {
        i -= 1;
        buf[i] = b'0' + (v % 10) as u8;
        v /= 10;
    }
    let digits = &buf[i..];
    let n = digits.len().min(out.len());
    out[..n].copy_from_slice(&digits[..n]);
    n
}

// ---------------------------------------------------------------------------
// Event registry
// ---------------------------------------------------------------------------

/// Registry of all tracefs events.
pub struct TraceEventRegistry {
    /// Events.
    events: [Option<TraceEvent>; MAX_TRACE_EVENTS],
    /// Number of events.
    count: usize,
    /// Next event ID.
    next_id: u32,
}

impl TraceEventRegistry {
    /// Creates an empty registry.
    pub fn new() -> Self {
        Self {
            events: core::array::from_fn(|_| None),
            count: 0,
            next_id: 1,
        }
    }

    /// Returns the number of registered events.
    pub fn count(&self) -> usize {
        self.count
    }

    /// Finds an event by name.
    pub fn find(&self, name: &[u8]) -> Option<&TraceEvent> {
        self.events
            .iter()
            .flatten()
            .find(|e| e.name_bytes() == name && e.active)
    }

    /// Finds a mutable event by name.
    pub fn find_mut(&mut self, name: &[u8]) -> Option<&mut TraceEvent> {
        self.events
            .iter_mut()
            .flatten()
            .find(|e| e.name_bytes() == name && e.active)
    }
}

impl Default for TraceEventRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Operations
// ---------------------------------------------------------------------------

/// Creates and registers a new trace event file.
///
/// The event is initially disabled. Its format is auto-generated from the
/// supplied fields.
pub fn tracefs_create_event_file(
    registry: &mut TraceEventRegistry,
    name: &[u8],
    system: &[u8],
) -> Result<u32> {
    if registry.count >= MAX_TRACE_EVENTS {
        return Err(Error::OutOfMemory);
    }
    if registry.find(name).is_some() {
        return Err(Error::AlreadyExists);
    }
    let id = registry.next_id;
    registry.next_id += 1;
    let event = TraceEvent::new(name, system, id)?;
    for slot in &mut registry.events {
        if slot.is_none() {
            *slot = Some(event);
            registry.count += 1;
            return Ok(id);
        }
    }
    Err(Error::OutOfMemory)
}

/// Enables a trace event (write "1" to the enable file).
pub fn event_enable(registry: &mut TraceEventRegistry, name: &[u8], data: &[u8]) -> Result<()> {
    let event = registry.find_mut(name).ok_or(Error::NotFound)?;
    match data {
        b"1" | b"1\n" => event.enable(),
        b"0" | b"0\n" => event.disable(),
        _ => return Err(Error::InvalidArgument),
    }
    Ok(())
}

/// Returns the format file content for an event.
pub fn event_read_format(
    registry: &TraceEventRegistry,
    name: &[u8],
    out: &mut [u8],
) -> Result<usize> {
    let event = registry.find(name).ok_or(Error::NotFound)?;
    let len = event.format_len.min(out.len());
    out[..len].copy_from_slice(&event.format[..len]);
    Ok(len)
}

/// Returns whether an event is enabled.
pub fn event_is_enabled(registry: &TraceEventRegistry, name: &[u8]) -> bool {
    registry.find(name).map(|e| e.enabled).unwrap_or(false)
}
