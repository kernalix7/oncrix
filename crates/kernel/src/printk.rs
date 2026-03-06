// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Kernel logging subsystem (printk).
//!
//! Provides the primary kernel message logging facility, modeled after
//! Linux's `printk`. Messages are stored in a fixed-size ring buffer
//! with sequence numbering and can be read back via `dmesg` or the
//! `syslog_action` interface (klogctl).
//!
//! # Architecture
//!
//! ```text
//!  printk(level, facility, msg)
//!    └──► PrintkState
//!           ├── RingBuffer (512 entries, seq-numbered)
//!           ├── ConsoleConfig (serial/framebuffer/network)
//!           └── level filtering (suppress_below)
//! ```
//!
//! Reference: Linux `kernel/printk/printk.c`,
//! `include/linux/printk.h`.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Maximum message length in a single log entry (bytes).
const MAX_MSG_LEN: usize = 256;

/// Maximum facility name length (bytes).
const MAX_FACILITY_LEN: usize = 32;

/// Number of entries in the printk ring buffer.
const RING_BUFFER_SIZE: usize = 512;

// -------------------------------------------------------------------
// LogFlags
// -------------------------------------------------------------------

/// Append a newline after the message.
pub const LOG_NEWLINE: u32 = 1;

/// Continuation of a previous log line.
pub const LOG_CONT: u32 = 2;

/// Include the log level prefix in output.
pub const LOG_PREFIX: u32 = 4;

// -------------------------------------------------------------------
// LogLevel
// -------------------------------------------------------------------

/// Kernel log severity levels (syslog-compatible).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
#[repr(u8)]
pub enum LogLevel {
    /// System is unusable.
    Emergency = 0,
    /// Action must be taken immediately.
    Alert = 1,
    /// Critical conditions.
    Critical = 2,
    /// Error conditions.
    Error = 3,
    /// Warning conditions.
    Warning = 4,
    /// Normal but significant condition.
    Notice = 5,
    /// Informational.
    #[default]
    Info = 6,
    /// Debug-level messages.
    Debug = 7,
}

impl LogLevel {
    /// Convert to the underlying `u8` value.
    pub const fn as_u8(self) -> u8 {
        self as u8
    }

    /// Convert from a `u8` value, returning `None` for invalid values.
    pub const fn from_u8(val: u8) -> Option<Self> {
        match val {
            0 => Some(Self::Emergency),
            1 => Some(Self::Alert),
            2 => Some(Self::Critical),
            3 => Some(Self::Error),
            4 => Some(Self::Warning),
            5 => Some(Self::Notice),
            6 => Some(Self::Info),
            7 => Some(Self::Debug),
            _ => None,
        }
    }

    /// Human-readable label for formatted output.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Emergency => "emerg",
            Self::Alert => "alert",
            Self::Critical => "crit",
            Self::Error => "err",
            Self::Warning => "warn",
            Self::Notice => "notice",
            Self::Info => "info",
            Self::Debug => "debug",
        }
    }
}

impl core::fmt::Display for LogLevel {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

// -------------------------------------------------------------------
// LogEntry
// -------------------------------------------------------------------

/// A single kernel log entry stored in the ring buffer.
#[derive(Debug, Clone, Copy)]
pub struct LogEntry {
    /// Severity level.
    pub level: LogLevel,
    /// Timestamp in nanoseconds since boot.
    pub timestamp_ns: u64,
    /// Message bytes (fixed-size buffer).
    message: [u8; MAX_MSG_LEN],
    /// Valid length of `message`.
    msg_len: usize,
    /// Facility name bytes (e.g., "kernel", "mm", "net").
    facility: [u8; MAX_FACILITY_LEN],
    /// Valid length of `facility`.
    facility_len: usize,
    /// Monotonically increasing sequence number.
    pub seq: u64,
    /// Log flags (combination of `LOG_NEWLINE`, `LOG_CONT`, `LOG_PREFIX`).
    pub flags: u32,
    /// Whether this slot contains a valid entry.
    pub in_use: bool,
}

/// Default (empty) log entry for buffer initialization.
const EMPTY_ENTRY: LogEntry = LogEntry {
    level: LogLevel::Info,
    timestamp_ns: 0,
    message: [0; MAX_MSG_LEN],
    msg_len: 0,
    facility: [0; MAX_FACILITY_LEN],
    facility_len: 0,
    seq: 0,
    flags: 0,
    in_use: false,
};

impl LogEntry {
    /// Create a new log entry.
    ///
    /// Message and facility are truncated to their respective maximum
    /// lengths if longer.
    pub fn new(
        level: LogLevel,
        timestamp_ns: u64,
        msg: &[u8],
        facility: &[u8],
        seq: u64,
        flags: u32,
    ) -> Self {
        let mut entry = EMPTY_ENTRY;
        entry.level = level;
        entry.timestamp_ns = timestamp_ns;
        entry.seq = seq;
        entry.flags = flags;
        entry.in_use = true;

        let mlen = msg.len().min(MAX_MSG_LEN);
        entry.message[..mlen].copy_from_slice(&msg[..mlen]);
        entry.msg_len = mlen;

        let flen = facility.len().min(MAX_FACILITY_LEN);
        entry.facility[..flen].copy_from_slice(&facility[..flen]);
        entry.facility_len = flen;

        entry
    }

    /// Message as a byte slice.
    pub fn message(&self) -> &[u8] {
        &self.message[..self.msg_len]
    }

    /// Facility name as a byte slice.
    pub fn facility(&self) -> &[u8] {
        &self.facility[..self.facility_len]
    }
}

// -------------------------------------------------------------------
// RingBuffer
// -------------------------------------------------------------------

/// Fixed-size ring buffer for kernel log entries with sequence numbering.
///
/// Stores up to [`RING_BUFFER_SIZE`] entries. When full, new entries
/// overwrite the oldest ones. A monotonic sequence counter provides
/// stable cursors for readers.
pub struct RingBuffer {
    /// Entry storage.
    entries: [LogEntry; RING_BUFFER_SIZE],
    /// Index of the oldest valid entry.
    head: usize,
    /// Next write position.
    tail: usize,
    /// Number of entries currently stored.
    count: usize,
    /// Next sequence number to assign.
    total_seq: u64,
    /// Number of entries that were overwritten before being read.
    dropped: u64,
}

impl Default for RingBuffer {
    fn default() -> Self {
        Self::new()
    }
}

impl RingBuffer {
    /// Create an empty ring buffer.
    pub const fn new() -> Self {
        Self {
            entries: [EMPTY_ENTRY; RING_BUFFER_SIZE],
            head: 0,
            tail: 0,
            count: 0,
            total_seq: 1,
            dropped: 0,
        }
    }

    /// Write an entry into the ring buffer.
    ///
    /// Returns the assigned sequence number on success.
    pub fn write(&mut self, mut entry: LogEntry) -> Result<u64> {
        let seq = self.total_seq;
        entry.seq = seq;
        self.total_seq += 1;

        if self.count == RING_BUFFER_SIZE {
            // Overwrite oldest entry.
            self.head = (self.head + 1) % RING_BUFFER_SIZE;
            self.dropped += 1;
        } else {
            self.count += 1;
        }

        self.entries[self.tail] = entry;
        self.tail = (self.tail + 1) % RING_BUFFER_SIZE;
        Ok(seq)
    }

    /// Read the next entry with a sequence number strictly greater
    /// than `after_seq`.
    ///
    /// Returns `None` if no such entry exists.
    pub fn read_next(&self, after_seq: u64) -> Option<&LogEntry> {
        if self.count == 0 {
            return None;
        }
        // Scan from oldest to newest for the first entry with seq > after_seq.
        for i in 0..self.count {
            let idx = (self.head + i) % RING_BUFFER_SIZE;
            let entry = &self.entries[idx];
            if entry.in_use && entry.seq > after_seq {
                return Some(entry);
            }
        }
        None
    }

    /// Remove all entries from the buffer.
    pub fn clear(&mut self) {
        self.head = 0;
        self.tail = 0;
        self.count = 0;
        // Sequence and dropped counters are preserved.
    }

    /// Number of entries available for reading.
    pub fn pending(&self) -> usize {
        self.count
    }

    /// Sequence number of the oldest entry, or 0 if empty.
    pub fn oldest_seq(&self) -> u64 {
        if self.count == 0 {
            return 0;
        }
        self.entries[self.head].seq
    }

    /// Sequence number of the newest entry, or 0 if empty.
    pub fn newest_seq(&self) -> u64 {
        if self.count == 0 {
            return 0;
        }
        let idx = if self.tail == 0 {
            RING_BUFFER_SIZE - 1
        } else {
            self.tail - 1
        };
        self.entries[idx].seq
    }
}

impl core::fmt::Debug for RingBuffer {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RingBuffer")
            .field("count", &self.count)
            .field("capacity", &RING_BUFFER_SIZE)
            .field("total_seq", &self.total_seq)
            .field("dropped", &self.dropped)
            .finish()
    }
}

// -------------------------------------------------------------------
// ConsoleTarget
// -------------------------------------------------------------------

/// Output target for kernel console messages.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ConsoleTarget {
    /// Serial port (UART).
    #[default]
    Serial,
    /// Framebuffer text console.
    Framebuffer,
    /// Network console (netconsole).
    Network,
    /// No output.
    None,
}

// -------------------------------------------------------------------
// ConsoleConfig
// -------------------------------------------------------------------

/// Configuration for the kernel console output.
#[derive(Debug, Clone, Copy)]
pub struct ConsoleConfig {
    /// Where console output is directed.
    pub target: ConsoleTarget,
    /// Minimum log level to emit on the console.
    pub log_level: LogLevel,
    /// Whether console output is enabled.
    pub enabled: bool,
}

impl Default for ConsoleConfig {
    fn default() -> Self {
        Self::new()
    }
}

impl ConsoleConfig {
    /// Create a default console configuration (serial, info level, enabled).
    pub const fn new() -> Self {
        Self {
            target: ConsoleTarget::Serial,
            log_level: LogLevel::Info,
            enabled: true,
        }
    }
}

// -------------------------------------------------------------------
// PrintkState
// -------------------------------------------------------------------

/// Top-level printk subsystem state.
///
/// Combines the ring buffer, console configuration, and level
/// filtering into a single management structure.
pub struct PrintkState {
    /// Ring buffer holding log entries.
    pub buffer: RingBuffer,
    /// Console output configuration.
    pub console: ConsoleConfig,
    /// Default log level for messages that do not specify one.
    pub default_level: LogLevel,
    /// Messages below this level are silently dropped.
    pub suppress_below: LogLevel,
}

impl Default for PrintkState {
    fn default() -> Self {
        Self::new()
    }
}

impl PrintkState {
    /// Create a new printk state with default settings.
    pub const fn new() -> Self {
        Self {
            buffer: RingBuffer::new(),
            console: ConsoleConfig::new(),
            default_level: LogLevel::Info,
            suppress_below: LogLevel::Debug,
        }
    }

    /// Log a kernel message.
    ///
    /// Messages with a level numerically greater than `suppress_below`
    /// are silently dropped. Returns the assigned sequence number on
    /// success.
    pub fn printk(&mut self, level: LogLevel, facility: &[u8], msg: &[u8]) -> Result<u64> {
        // Suppress messages below the configured threshold.
        // Lower numeric value = higher severity, so suppress if
        // the message level is *greater* than suppress_below.
        if level > self.suppress_below {
            return Err(Error::InvalidArgument);
        }

        let entry = LogEntry::new(level, 0, msg, facility, 0, LOG_NEWLINE | LOG_PREFIX);
        self.buffer.write(entry)
    }

    /// Read log entries into a caller-provided buffer (dmesg).
    ///
    /// Copies entries with sequence numbers greater than `from_seq`
    /// into `buf`. Returns `(count, last_seq)` where `count` is the
    /// number of entries copied and `last_seq` is the sequence number
    /// of the last entry copied (or `from_seq` if none were copied).
    pub fn dmesg(&self, from_seq: u64, buf: &mut [LogEntry]) -> Result<(usize, u64)> {
        if buf.is_empty() {
            return Ok((0, from_seq));
        }

        let mut copied = 0usize;
        let mut current_seq = from_seq;

        while copied < buf.len() {
            match self.buffer.read_next(current_seq) {
                Some(entry) => {
                    buf[copied] = *entry;
                    current_seq = entry.seq;
                    copied += 1;
                }
                None => break,
            }
        }

        Ok((copied, current_seq))
    }

    /// Set the minimum log level for console output.
    pub fn set_console_level(&mut self, level: LogLevel) {
        self.console.log_level = level;
    }

    /// Set the default log level for messages without an explicit level.
    pub fn set_default_level(&mut self, level: LogLevel) {
        self.default_level = level;
    }

    /// Enable console output.
    pub fn enable_console(&mut self) {
        self.console.enabled = true;
    }

    /// Disable console output.
    pub fn disable_console(&mut self) {
        self.console.enabled = false;
    }

    /// Perform a syslog action (klogctl-style).
    ///
    /// Actions:
    /// - `0`: Close log (no-op, returns 0).
    /// - `1`: Open log (no-op, returns 0).
    /// - `2`: Read entries starting from `from_seq` (returns newest seq).
    /// - `3`: Read and clear (returns newest seq).
    /// - `4`: Clear ring buffer (returns 0).
    /// - `5`: Disable console output (returns 0).
    /// - `6`: Enable console output (returns 0).
    /// - `7`: Set console level to `from_seq` as u8 (returns 0).
    /// - `8`: Return number of pending entries as u64.
    /// - `9`: Return total buffer capacity as u64.
    /// - `10`: Return number of dropped entries as u64.
    ///
    /// Returns `Err(InvalidArgument)` for unknown actions.
    pub fn syslog_action(&mut self, action: u32, from_seq: u64) -> Result<u64> {
        match action {
            // Close / Open log (no-op).
            0 | 1 => Ok(0),
            // Read from sequence.
            2 => Ok(self.buffer.newest_seq()),
            // Read all and clear.
            3 => {
                let newest = self.buffer.newest_seq();
                self.buffer.clear();
                Ok(newest)
            }
            // Clear ring buffer.
            4 => {
                self.buffer.clear();
                Ok(0)
            }
            // Disable console.
            5 => {
                self.disable_console();
                Ok(0)
            }
            // Enable console.
            6 => {
                self.enable_console();
                Ok(0)
            }
            // Set console level.
            7 => {
                let level_val = from_seq as u8;
                match LogLevel::from_u8(level_val) {
                    Some(level) => {
                        self.set_console_level(level);
                        Ok(0)
                    }
                    None => Err(Error::InvalidArgument),
                }
            }
            // Pending entries.
            8 => Ok(self.buffer.pending() as u64),
            // Buffer capacity.
            9 => Ok(RING_BUFFER_SIZE as u64),
            // Dropped entries.
            10 => Ok(self.buffer.dropped),
            _ => Err(Error::InvalidArgument),
        }
    }

    /// Return summary statistics: `(total_seq, dropped, pending)`.
    pub fn stats(&self) -> (u64, u64, usize) {
        (
            self.buffer.total_seq.saturating_sub(1),
            self.buffer.dropped,
            self.buffer.pending(),
        )
    }
}

impl core::fmt::Debug for PrintkState {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PrintkState")
            .field("buffer", &self.buffer)
            .field("console", &self.console)
            .field("default_level", &self.default_level)
            .field("suppress_below", &self.suppress_below)
            .finish()
    }
}
