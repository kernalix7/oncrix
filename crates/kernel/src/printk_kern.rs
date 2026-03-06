// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Printk ring buffer and console output.
//!
//! Implements the kernel's central logging facility: a circular
//! ring buffer of [`LogRecord`] entries and a set of registered
//! console output callbacks. Messages are tagged with a log level,
//! timestamp, CPU ID, and optional facility name.
//!
//! # Log Levels
//!
//! | Level | Name | Description |
//! |-------|------|-------------|
//! | 0 | EMERG | System is unusable |
//! | 1 | ALERT | Action must be taken immediately |
//! | 2 | CRIT | Critical conditions |
//! | 3 | ERR | Error conditions |
//! | 4 | WARNING | Warning conditions |
//! | 5 | NOTICE | Normal but significant |
//! | 6 | INFO | Informational |
//! | 7 | DEBUG | Debug-level messages |
//!
//! # Architecture
//!
//! ```text
//! PrintkSubsystem
//! ├── ring_buffer: RingBuffer
//! │   └── records: [LogRecord; RING_SIZE]
//! ├── consoles: [ConsoleDriver; MAX_CONSOLES]
//! └── stats: PrintkStats
//! ```
//!
//! # Reference
//!
//! Linux `kernel/printk/printk.c`,
//! `include/linux/printk.h`,
//! `include/linux/kern_levels.h`.

use oncrix_lib::{Error, Result};

// ── Constants ────────────────────────────────────────────────

/// Ring buffer capacity (number of records).
const RING_SIZE: usize = 1024;

/// Maximum message length per record.
const MAX_MSG_LEN: usize = 256;

/// Maximum number of console drivers.
const MAX_CONSOLES: usize = 8;

/// Maximum facility name length.
const MAX_FACILITY_LEN: usize = 32;

/// Maximum console name length.
const MAX_CONSOLE_NAME_LEN: usize = 16;

/// Default console log level (messages at or below this are shown).
const DEFAULT_CONSOLE_LOGLEVEL: u8 = 7;

// ── LogLevel ────────────────────────────────────────────────

/// Kernel log levels (syslog-compatible).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum LogLevel {
    /// System is unusable.
    Emerg = 0,
    /// Action must be taken immediately.
    Alert = 1,
    /// Critical conditions.
    Crit = 2,
    /// Error conditions.
    Err = 3,
    /// Warning conditions.
    Warning = 4,
    /// Normal but significant condition.
    Notice = 5,
    /// Informational.
    Info = 6,
    /// Debug-level messages.
    Debug = 7,
}

impl LogLevel {
    /// Create from numeric level.
    pub fn from_u8(level: u8) -> Self {
        match level {
            0 => Self::Emerg,
            1 => Self::Alert,
            2 => Self::Crit,
            3 => Self::Err,
            4 => Self::Warning,
            5 => Self::Notice,
            6 => Self::Info,
            _ => Self::Debug,
        }
    }

    /// Human-readable name.
    pub fn name(self) -> &'static str {
        match self {
            Self::Emerg => "emerg",
            Self::Alert => "alert",
            Self::Crit => "crit",
            Self::Err => "err",
            Self::Warning => "warning",
            Self::Notice => "notice",
            Self::Info => "info",
            Self::Debug => "debug",
        }
    }

    /// Numeric value.
    pub fn as_u8(self) -> u8 {
        self as u8
    }
}

impl Default for LogLevel {
    fn default() -> Self {
        Self::Info
    }
}

// ── LogRecord ───────────────────────────────────────────────

/// A single log record in the ring buffer.
#[derive(Clone, Copy)]
pub struct LogRecord {
    /// Sequence number.
    seq: u64,
    /// Timestamp in nanoseconds since boot.
    timestamp_ns: u64,
    /// Log level.
    level: LogLevel,
    /// CPU that generated the message.
    cpu: u32,
    /// Facility name.
    facility: [u8; MAX_FACILITY_LEN],
    /// Facility name length.
    facility_len: usize,
    /// Message text.
    msg: [u8; MAX_MSG_LEN],
    /// Message length.
    msg_len: usize,
    /// Whether this slot contains a valid record.
    valid: bool,
}

impl LogRecord {
    /// Create an empty record.
    const fn empty() -> Self {
        Self {
            seq: 0,
            timestamp_ns: 0,
            level: LogLevel::Info,
            cpu: 0,
            facility: [0u8; MAX_FACILITY_LEN],
            facility_len: 0,
            msg: [0u8; MAX_MSG_LEN],
            msg_len: 0,
            valid: false,
        }
    }

    /// Sequence number.
    pub fn seq(&self) -> u64 {
        self.seq
    }

    /// Timestamp.
    pub fn timestamp_ns(&self) -> u64 {
        self.timestamp_ns
    }

    /// Log level.
    pub fn level(&self) -> LogLevel {
        self.level
    }

    /// CPU ID.
    pub fn cpu(&self) -> u32 {
        self.cpu
    }

    /// Facility name.
    pub fn facility_str(&self) -> &str {
        let len = self.facility_len.min(MAX_FACILITY_LEN);
        core::str::from_utf8(&self.facility[..len]).unwrap_or("<unknown>")
    }

    /// Message text.
    pub fn msg_str(&self) -> &str {
        let len = self.msg_len.min(MAX_MSG_LEN);
        core::str::from_utf8(&self.msg[..len]).unwrap_or("<invalid>")
    }

    /// Whether this record is valid.
    pub fn is_valid(&self) -> bool {
        self.valid
    }
}

impl core::fmt::Debug for LogRecord {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("LogRecord")
            .field("seq", &self.seq)
            .field("level", &self.level)
            .field("cpu", &self.cpu)
            .field("msg", &self.msg_str())
            .finish()
    }
}

// ── RingBuffer ──────────────────────────────────────────────

/// Circular ring buffer for log records.
struct RingBuffer {
    /// Records.
    records: [LogRecord; RING_SIZE],
    /// Write position (next slot to write).
    head: usize,
    /// Total records written (wraps around).
    total_written: u64,
    /// Next sequence number.
    next_seq: u64,
}

impl RingBuffer {
    /// Create an empty ring buffer.
    const fn new() -> Self {
        Self {
            records: [const { LogRecord::empty() }; RING_SIZE],
            head: 0,
            total_written: 0,
            next_seq: 1,
        }
    }

    /// Write a record. Overwrites the oldest if full.
    fn write(
        &mut self,
        level: LogLevel,
        cpu: u32,
        facility: &str,
        msg: &str,
        timestamp_ns: u64,
    ) -> u64 {
        let seq = self.next_seq;
        self.next_seq += 1;

        let mut record = LogRecord::empty();
        record.seq = seq;
        record.timestamp_ns = timestamp_ns;
        record.level = level;
        record.cpu = cpu;
        record.valid = true;

        let fac_len = facility.len().min(MAX_FACILITY_LEN);
        record.facility[..fac_len].copy_from_slice(&facility.as_bytes()[..fac_len]);
        record.facility_len = fac_len;

        let msg_len = msg.len().min(MAX_MSG_LEN);
        record.msg[..msg_len].copy_from_slice(&msg.as_bytes()[..msg_len]);
        record.msg_len = msg_len;

        self.records[self.head] = record;
        self.head = (self.head + 1) % RING_SIZE;
        self.total_written += 1;
        seq
    }

    /// Read a record by sequence number.
    fn read_by_seq(&self, seq: u64) -> Option<&LogRecord> {
        self.records.iter().find(|r| r.valid && r.seq == seq)
    }

    /// Read the most recent record.
    fn read_latest(&self) -> Option<&LogRecord> {
        if self.total_written == 0 {
            return None;
        }
        let idx = if self.head > 0 {
            self.head - 1
        } else {
            RING_SIZE - 1
        };
        if self.records[idx].valid {
            Some(&self.records[idx])
        } else {
            None
        }
    }

    /// Clear the entire buffer.
    fn clear(&mut self) {
        for record in &mut self.records {
            record.valid = false;
        }
        self.head = 0;
    }

    /// Count valid records.
    fn count(&self) -> usize {
        self.records.iter().filter(|r| r.valid).count()
    }
}

// ── ConsoleWriteFn ──────────────────────────────────────────

/// Console write callback.
///
/// Parameters: (level, message_str_ptr, message_len)
pub type ConsoleWriteFn = fn(LogLevel, &str);

// ── ConsoleDriver ───────────────────────────────────────────

/// A registered console driver.
#[derive(Clone, Copy)]
struct ConsoleDriver {
    /// Console name.
    name: [u8; MAX_CONSOLE_NAME_LEN],
    /// Name length.
    name_len: usize,
    /// Write callback.
    write: Option<ConsoleWriteFn>,
    /// Minimum log level to display.
    loglevel: u8,
    /// Whether active.
    active: bool,
    /// Total messages written.
    write_count: u64,
}

impl ConsoleDriver {
    /// Create an empty console.
    const fn empty() -> Self {
        Self {
            name: [0u8; MAX_CONSOLE_NAME_LEN],
            name_len: 0,
            write: None,
            loglevel: DEFAULT_CONSOLE_LOGLEVEL,
            active: false,
            write_count: 0,
        }
    }
}

// ── PrintkStats ─────────────────────────────────────────────

/// Printk statistics.
#[derive(Debug, Clone, Copy, Default)]
pub struct PrintkStats {
    /// Total messages logged.
    pub total_messages: u64,
    /// Messages per level.
    pub per_level: [u64; 8],
    /// Total messages written to consoles.
    pub console_writes: u64,
    /// Messages dropped (ring buffer overflow).
    pub dropped: u64,
    /// Number of registered consoles.
    pub console_count: u32,
}

// ── PrintkSubsystem ────────────────────────────────────────

/// Kernel printk logging subsystem.
pub struct PrintkSubsystem {
    /// Ring buffer.
    ring: RingBuffer,
    /// Console drivers.
    consoles: [ConsoleDriver; MAX_CONSOLES],
    /// Number of active consoles.
    console_count: u32,
    /// Global default log level.
    default_loglevel: LogLevel,
    /// Console log level (messages <= this level go to console).
    console_loglevel: u8,
    /// Statistics.
    stats: PrintkStats,
    /// Whether initialized.
    initialized: bool,
}

impl PrintkSubsystem {
    /// Create a new printk subsystem.
    pub const fn new() -> Self {
        Self {
            ring: RingBuffer::new(),
            consoles: [ConsoleDriver::empty(); MAX_CONSOLES],
            console_count: 0,
            default_loglevel: LogLevel::Info,
            console_loglevel: DEFAULT_CONSOLE_LOGLEVEL,
            stats: PrintkStats {
                total_messages: 0,
                per_level: [0; 8],
                console_writes: 0,
                dropped: 0,
                console_count: 0,
            },
            initialized: false,
        }
    }

    /// Initialize.
    pub fn init(&mut self) -> Result<()> {
        if self.initialized {
            return Err(Error::AlreadyExists);
        }
        self.initialized = true;
        Ok(())
    }

    /// Log a message (the main printk entry point).
    pub fn printk(
        &mut self,
        level: LogLevel,
        cpu: u32,
        facility: &str,
        msg: &str,
        timestamp_ns: u64,
    ) -> u64 {
        let seq = self.ring.write(level, cpu, facility, msg, timestamp_ns);
        self.stats.total_messages += 1;
        let lvl_idx = level.as_u8() as usize;
        if lvl_idx < 8 {
            self.stats.per_level[lvl_idx] += 1;
        }

        // Emit to consoles.
        if level.as_u8() <= self.console_loglevel {
            self.emit_to_consoles(level, msg);
        }

        seq
    }

    /// Convenience: log at INFO level.
    pub fn pr_info(&mut self, cpu: u32, facility: &str, msg: &str, timestamp_ns: u64) -> u64 {
        self.printk(LogLevel::Info, cpu, facility, msg, timestamp_ns)
    }

    /// Convenience: log at ERR level.
    pub fn pr_err(&mut self, cpu: u32, facility: &str, msg: &str, timestamp_ns: u64) -> u64 {
        self.printk(LogLevel::Err, cpu, facility, msg, timestamp_ns)
    }

    /// Convenience: log at WARNING level.
    pub fn pr_warn(&mut self, cpu: u32, facility: &str, msg: &str, timestamp_ns: u64) -> u64 {
        self.printk(LogLevel::Warning, cpu, facility, msg, timestamp_ns)
    }

    /// Convenience: log at DEBUG level.
    pub fn pr_debug(&mut self, cpu: u32, facility: &str, msg: &str, timestamp_ns: u64) -> u64 {
        self.printk(LogLevel::Debug, cpu, facility, msg, timestamp_ns)
    }

    /// Register a console driver.
    pub fn register_console(&mut self, name: &str, write_fn: ConsoleWriteFn) -> Result<()> {
        let slot = self
            .consoles
            .iter()
            .position(|c| !c.active)
            .ok_or(Error::OutOfMemory)?;

        self.consoles[slot] = ConsoleDriver::empty();
        self.consoles[slot].write = Some(write_fn);
        self.consoles[slot].loglevel = self.console_loglevel;
        self.consoles[slot].active = true;

        let name_len = name.len().min(MAX_CONSOLE_NAME_LEN);
        self.consoles[slot].name[..name_len].copy_from_slice(&name.as_bytes()[..name_len]);
        self.consoles[slot].name_len = name_len;

        self.console_count += 1;
        self.stats.console_count = self.console_count;
        Ok(())
    }

    /// Unregister a console driver by name.
    pub fn unregister_console(&mut self, name: &str) -> Result<()> {
        let slot = self
            .consoles
            .iter()
            .position(|c| {
                c.active && {
                    let len = c.name_len.min(MAX_CONSOLE_NAME_LEN);
                    core::str::from_utf8(&c.name[..len]).unwrap_or("") == name
                }
            })
            .ok_or(Error::NotFound)?;

        self.consoles[slot].active = false;
        self.console_count = self.console_count.saturating_sub(1);
        self.stats.console_count = self.console_count;
        Ok(())
    }

    /// Set the console log level.
    pub fn set_console_loglevel(&mut self, level: u8) {
        self.console_loglevel = level.min(7);
    }

    /// Get the console log level.
    pub fn console_loglevel(&self) -> u8 {
        self.console_loglevel
    }

    /// Read a record by sequence number.
    pub fn read_record(&self, seq: u64) -> Option<&LogRecord> {
        self.ring.read_by_seq(seq)
    }

    /// Number of records in the ring buffer.
    pub fn record_count(&self) -> usize {
        self.ring.count()
    }

    /// Clear the ring buffer.
    pub fn clear(&mut self) {
        self.ring.clear();
    }

    /// Statistics.
    pub fn stats(&self) -> &PrintkStats {
        &self.stats
    }

    // ── Internal ────────────────────────────────────────────

    /// Emit a message to all active consoles.
    fn emit_to_consoles(&mut self, level: LogLevel, msg: &str) {
        for console in &mut self.consoles {
            if !console.active {
                continue;
            }
            if level.as_u8() > console.loglevel {
                continue;
            }
            if let Some(write) = console.write {
                write(level, msg);
                console.write_count += 1;
                self.stats.console_writes += 1;
            }
        }
    }
}

impl Default for PrintkSubsystem {
    fn default() -> Self {
        Self::new()
    }
}
