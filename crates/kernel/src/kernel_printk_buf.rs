// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Kernel printk ring buffer internals.
//!
//! Implements the internal ring buffer for kernel log messages,
//! providing lock-free single-producer, multiple-consumer access
//! for high-performance logging. Supports log levels, sequence
//! numbering, timestamps, and structured metadata for each
//! message record.

use oncrix_lib::{Error, Result};

/// Ring buffer size in bytes.
const RING_BUFFER_SIZE: usize = 65536;

/// Maximum single message size in bytes.
const MAX_MSG_SIZE: usize = 1024;

/// Maximum number of message records.
const MAX_RECORDS: usize = 2048;

/// Log level for kernel messages.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
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
    Info = 6,
    /// Debug-level messages.
    Debug = 7,
}

impl LogLevel {
    /// Returns the string prefix for this log level.
    pub const fn prefix(&self) -> &'static str {
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

/// Log message record metadata.
#[derive(Clone, Copy)]
pub struct LogRecord {
    /// Monotonically increasing sequence number.
    seq: u64,
    /// Timestamp in nanoseconds since boot.
    timestamp_ns: u64,
    /// Log level.
    level: LogLevel,
    /// Offset into the ring buffer for message text.
    text_offset: usize,
    /// Length of the message text.
    text_len: usize,
    /// CPU that generated this message.
    cpu_id: u32,
    /// Task ID that generated this message.
    task_id: u64,
    /// Facility code (for syslog compatibility).
    facility: u16,
    /// Whether this record is valid.
    valid: bool,
}

impl LogRecord {
    /// Creates a new empty log record.
    pub const fn new() -> Self {
        Self {
            seq: 0,
            timestamp_ns: 0,
            level: LogLevel::Info,
            text_offset: 0,
            text_len: 0,
            cpu_id: 0,
            task_id: 0,
            facility: 0,
            valid: false,
        }
    }

    /// Returns the sequence number.
    pub const fn seq(&self) -> u64 {
        self.seq
    }

    /// Returns the timestamp in nanoseconds.
    pub const fn timestamp_ns(&self) -> u64 {
        self.timestamp_ns
    }

    /// Returns the log level.
    pub const fn level(&self) -> LogLevel {
        self.level
    }

    /// Returns the message text length.
    pub const fn text_len(&self) -> usize {
        self.text_len
    }

    /// Returns the CPU that generated this message.
    pub const fn cpu_id(&self) -> u32 {
        self.cpu_id
    }

    /// Returns whether this record is valid.
    pub const fn is_valid(&self) -> bool {
        self.valid
    }
}

impl Default for LogRecord {
    fn default() -> Self {
        Self::new()
    }
}

/// Ring buffer consumer state.
#[derive(Clone, Copy)]
pub struct ConsumerState {
    /// Consumer identifier.
    id: u32,
    /// Next sequence number to read.
    read_seq: u64,
    /// Whether this consumer is active.
    active: bool,
    /// Number of messages read by this consumer.
    messages_read: u64,
    /// Number of messages dropped (overwritten before read).
    messages_dropped: u64,
}

impl ConsumerState {
    /// Creates a new consumer state.
    pub const fn new() -> Self {
        Self {
            id: 0,
            read_seq: 0,
            active: false,
            messages_read: 0,
            messages_dropped: 0,
        }
    }

    /// Returns the consumer identifier.
    pub const fn id(&self) -> u32 {
        self.id
    }

    /// Returns the next sequence to read.
    pub const fn read_seq(&self) -> u64 {
        self.read_seq
    }

    /// Returns the number of messages read.
    pub const fn messages_read(&self) -> u64 {
        self.messages_read
    }

    /// Returns the number of dropped messages.
    pub const fn messages_dropped(&self) -> u64 {
        self.messages_dropped
    }
}

impl Default for ConsumerState {
    fn default() -> Self {
        Self::new()
    }
}

/// Maximum number of consumers.
const MAX_CONSUMERS: usize = 16;

/// Kernel printk ring buffer.
pub struct PrintkRingBuffer {
    /// Raw ring buffer storage.
    buffer: [u8; RING_BUFFER_SIZE],
    /// Write position in the ring buffer.
    write_pos: usize,
    /// Message record metadata.
    records: [LogRecord; MAX_RECORDS],
    /// Number of records written (may wrap).
    record_count: usize,
    /// Next sequence number to assign.
    next_seq: u64,
    /// First valid sequence number.
    first_seq: u64,
    /// Consumer states.
    consumers: [ConsumerState; MAX_CONSUMERS],
    /// Number of registered consumers.
    consumer_count: usize,
    /// Current minimum log level for output.
    console_loglevel: LogLevel,
    /// Total bytes written to the ring buffer.
    total_bytes_written: u64,
}

impl PrintkRingBuffer {
    /// Creates a new printk ring buffer.
    pub const fn new() -> Self {
        Self {
            buffer: [0u8; RING_BUFFER_SIZE],
            write_pos: 0,
            records: [const { LogRecord::new() }; MAX_RECORDS],
            record_count: 0,
            next_seq: 1,
            first_seq: 1,
            consumers: [const { ConsumerState::new() }; MAX_CONSUMERS],
            consumer_count: 0,
            console_loglevel: LogLevel::Warning,
            total_bytes_written: 0,
        }
    }

    /// Writes a message to the ring buffer.
    pub fn write_msg(
        &mut self,
        level: LogLevel,
        msg: &[u8],
        timestamp_ns: u64,
        cpu_id: u32,
        task_id: u64,
    ) -> Result<u64> {
        if msg.is_empty() {
            return Err(Error::InvalidArgument);
        }
        let len = if msg.len() > MAX_MSG_SIZE {
            MAX_MSG_SIZE
        } else {
            msg.len()
        };

        // Write to ring buffer (wrapping)
        let text_offset = self.write_pos;
        for i in 0..len {
            let pos = (self.write_pos + i) % RING_BUFFER_SIZE;
            self.buffer[pos] = msg[i];
        }
        self.write_pos = (self.write_pos + len) % RING_BUFFER_SIZE;

        // Create record
        let record_idx = self.record_count % MAX_RECORDS;
        let seq = self.next_seq;
        self.records[record_idx] = LogRecord {
            seq,
            timestamp_ns,
            level,
            text_offset,
            text_len: len,
            cpu_id,
            task_id,
            facility: 0,
            valid: true,
        };
        self.next_seq += 1;
        self.record_count += 1;
        self.total_bytes_written += len as u64;

        // Update first_seq if we've wrapped
        if self.record_count > MAX_RECORDS {
            self.first_seq = self.next_seq - MAX_RECORDS as u64;
        }

        Ok(seq)
    }

    /// Registers a consumer.
    pub fn register_consumer(&mut self) -> Result<u32> {
        if self.consumer_count >= MAX_CONSUMERS {
            return Err(Error::OutOfMemory);
        }
        let id = self.consumer_count as u32;
        self.consumers[self.consumer_count] = ConsumerState {
            id,
            read_seq: self.first_seq,
            active: true,
            messages_read: 0,
            messages_dropped: 0,
        };
        self.consumer_count += 1;
        Ok(id)
    }

    /// Reads the next available record for a consumer.
    pub fn read_next(&mut self, consumer_id: u32) -> Result<&LogRecord> {
        let cidx = consumer_id as usize;
        if cidx >= self.consumer_count {
            return Err(Error::NotFound);
        }
        let read_seq = self.consumers[cidx].read_seq;
        if read_seq >= self.next_seq {
            return Err(Error::WouldBlock);
        }

        // Check if the record was overwritten
        if read_seq < self.first_seq {
            let dropped = self.first_seq - read_seq;
            self.consumers[cidx].messages_dropped += dropped;
            self.consumers[cidx].read_seq = self.first_seq;
        }

        let cur_seq = self.consumers[cidx].read_seq;
        let record_idx = (cur_seq % MAX_RECORDS as u64) as usize;
        self.consumers[cidx].read_seq += 1;
        self.consumers[cidx].messages_read += 1;

        Ok(&self.records[record_idx])
    }

    /// Sets the console log level.
    pub fn set_console_loglevel(&mut self, level: LogLevel) {
        self.console_loglevel = level;
    }

    /// Returns the console log level.
    pub const fn console_loglevel(&self) -> LogLevel {
        self.console_loglevel
    }

    /// Returns the next sequence number.
    pub const fn next_seq(&self) -> u64 {
        self.next_seq
    }

    /// Returns the number of records stored.
    pub const fn record_count(&self) -> usize {
        self.record_count
    }

    /// Returns the total bytes written.
    pub const fn total_bytes_written(&self) -> u64 {
        self.total_bytes_written
    }

    /// Clears the ring buffer.
    pub fn clear(&mut self) {
        self.write_pos = 0;
        self.record_count = 0;
        self.first_seq = self.next_seq;
    }
}

impl Default for PrintkRingBuffer {
    fn default() -> Self {
        Self::new()
    }
}
