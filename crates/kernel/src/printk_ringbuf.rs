// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Kernel printk ring buffer for log message storage.
//!
//! Provides a fixed-size circular ring buffer that stores kernel log
//! messages produced by `printk()`. Each entry carries a sequence
//! number, timestamp, log level, and message text. Producer and
//! consumer indices track the write and read positions; when the
//! buffer is full the oldest entries are silently overwritten
//! (overflow mode).
//!
//! # Architecture
//!
//! ```text
//! PrintkRingBuffer
//!  ├── entries[RING_SIZE]        (fixed-size log entry slots)
//!  ├── write_seq / read_seq      (producer / consumer counters)
//!  ├── overflow_count            (dropped messages on wrap)
//!  ├── level_filter              (suppress below threshold)
//!  └── stats: RingBufStats
//! ```
//!
//! # Overflow Policy
//!
//! When the write cursor catches the read cursor the oldest unread
//! entry is overwritten and `overflow_count` is incremented. Readers
//! can detect lost messages by comparing sequence numbers.
//!
//! Reference: Linux `kernel/printk/printk_ringbuffer.c`,
//! `include/linux/printk.h`.

use oncrix_lib::{Error, Result};

// ══════════════════════════════════════════════════════════════
// Constants
// ══════════════════════════════════════════════════════════════

/// Number of entries in the printk ring buffer (power of two).
const RING_SIZE: usize = 1024;

/// Mask for fast modulo on power-of-two ring size.
const RING_MASK: usize = RING_SIZE - 1;

/// Maximum message payload per entry (bytes).
const MAX_MSG_LEN: usize = 248;

/// Maximum facility tag length (bytes).
const MAX_FACILITY_LEN: usize = 24;

/// Maximum caller function name length (bytes).
const MAX_CALLER_LEN: usize = 32;

// ══════════════════════════════════════════════════════════════
// LogLevel
// ══════════════════════════════════════════════════════════════

/// Kernel log severity levels (syslog-compatible 0..7).
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
    /// Convert from raw u8, returns `None` if out of range.
    pub const fn from_u8(v: u8) -> Option<Self> {
        match v {
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

    /// Return the numeric severity value.
    pub const fn as_u8(self) -> u8 {
        self as u8
    }
}

// ══════════════════════════════════════════════════════════════
// RingEntry — one log record
// ══════════════════════════════════════════════════════════════

/// A single log entry stored in the ring buffer.
#[derive(Debug, Clone)]
pub struct RingEntry {
    /// Monotonically increasing sequence number.
    pub seq: u64,
    /// Timestamp in nanoseconds since boot.
    pub timestamp_ns: u64,
    /// Log severity level.
    pub level: LogLevel,
    /// Facility tag (e.g. "sched", "mm", "net").
    facility: [u8; MAX_FACILITY_LEN],
    /// Facility tag length.
    facility_len: usize,
    /// Caller function name (optional).
    caller: [u8; MAX_CALLER_LEN],
    /// Caller name length.
    caller_len: usize,
    /// Log message text.
    message: [u8; MAX_MSG_LEN],
    /// Message text length.
    message_len: usize,
    /// CPU that produced this entry.
    pub cpu: u32,
    /// Whether this slot is occupied.
    occupied: bool,
}

impl RingEntry {
    /// Create an empty entry.
    const fn empty() -> Self {
        Self {
            seq: 0,
            timestamp_ns: 0,
            level: LogLevel::Info,
            facility: [0u8; MAX_FACILITY_LEN],
            facility_len: 0,
            caller: [0u8; MAX_CALLER_LEN],
            caller_len: 0,
            message: [0u8; MAX_MSG_LEN],
            message_len: 0,
            cpu: 0,
            occupied: false,
        }
    }

    /// Return the facility tag as a byte slice.
    pub fn facility(&self) -> &[u8] {
        &self.facility[..self.facility_len]
    }

    /// Return the caller name as a byte slice.
    pub fn caller(&self) -> &[u8] {
        &self.caller[..self.caller_len]
    }

    /// Return the message text as a byte slice.
    pub fn message(&self) -> &[u8] {
        &self.message[..self.message_len]
    }
}

// ══════════════════════════════════════════════════════════════
// RingBufStats
// ══════════════════════════════════════════════════════════════

/// Statistics for the printk ring buffer.
#[derive(Debug, Clone, Copy)]
pub struct RingBufStats {
    /// Total messages written since boot.
    pub total_written: u64,
    /// Total messages read / consumed.
    pub total_read: u64,
    /// Messages dropped due to overflow (reader too slow).
    pub overflow_count: u64,
    /// Messages suppressed by level filter.
    pub filtered_count: u64,
}

impl Default for RingBufStats {
    fn default() -> Self {
        Self::new()
    }
}

impl RingBufStats {
    /// Create zeroed statistics.
    const fn new() -> Self {
        Self {
            total_written: 0,
            total_read: 0,
            overflow_count: 0,
            filtered_count: 0,
        }
    }
}

// ══════════════════════════════════════════════════════════════
// DrainIterState
// ══════════════════════════════════════════════════════════════

/// Snapshot state for draining the ring buffer.
///
/// Returned by [`PrintkRingBuffer::start_drain`] and consumed
/// by successive [`PrintkRingBuffer::drain_next`] calls.
#[derive(Debug, Clone, Copy)]
pub struct DrainIterState {
    /// Next sequence number to read.
    next_seq: u64,
    /// Sequence number at which draining stops.
    end_seq: u64,
}

// ══════════════════════════════════════════════════════════════
// PrintkRingBuffer — the core data structure
// ══════════════════════════════════════════════════════════════

/// Fixed-size circular ring buffer for kernel log messages.
///
/// The buffer stores up to [`RING_SIZE`] entries. A monotonic
/// write sequence counter is used as the logical write position;
/// modular arithmetic maps it to physical slot indices. When
/// the buffer wraps, the oldest unread entries are overwritten
/// and `overflow_count` is incremented.
pub struct PrintkRingBuffer {
    /// Ring buffer storage.
    entries: [RingEntry; RING_SIZE],
    /// Next sequence number to assign to a new entry.
    write_seq: u64,
    /// Next sequence number to be consumed by a reader.
    read_seq: u64,
    /// Minimum log level to accept (messages below are dropped).
    level_filter: LogLevel,
    /// Accumulated statistics.
    stats: RingBufStats,
    /// Whether the buffer is enabled (accepting writes).
    enabled: bool,
}

impl Default for PrintkRingBuffer {
    fn default() -> Self {
        Self::new()
    }
}

impl PrintkRingBuffer {
    /// Create a new, empty ring buffer with default level filter.
    pub const fn new() -> Self {
        Self {
            entries: [const { RingEntry::empty() }; RING_SIZE],
            write_seq: 0,
            read_seq: 0,
            level_filter: LogLevel::Debug,
            stats: RingBufStats::new(),
            enabled: true,
        }
    }

    /// Set the minimum log level. Messages with a severity
    /// numerically greater than `level` are suppressed.
    pub fn set_level_filter(&mut self, level: LogLevel) {
        self.level_filter = level;
    }

    /// Return the current level filter.
    pub fn level_filter(&self) -> LogLevel {
        self.level_filter
    }

    /// Enable or disable writes to the ring buffer.
    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }

    /// Return whether the buffer is enabled.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Write a log entry into the ring buffer.
    ///
    /// If the message level is below the filter threshold, the
    /// entry is silently discarded. Returns the assigned sequence
    /// number on success.
    pub fn write(
        &mut self,
        level: LogLevel,
        facility: &[u8],
        caller: &[u8],
        message: &[u8],
        timestamp_ns: u64,
        cpu: u32,
    ) -> Result<u64> {
        if !self.enabled {
            return Err(Error::WouldBlock);
        }

        // Filter by severity: higher numeric value = lower
        // severity, so suppress if level > filter.
        if level > self.level_filter {
            self.stats.filtered_count += 1;
            return Err(Error::InvalidArgument);
        }

        let seq = self.write_seq;
        let idx = (seq as usize) & RING_MASK;

        // Detect overflow: the slot we are about to overwrite
        // is still unread.
        if self.write_seq >= self.read_seq + RING_SIZE as u64 {
            self.stats.overflow_count += 1;
            // Advance read_seq past the overwritten entry.
            self.read_seq = self.write_seq - (RING_SIZE as u64 - 1);
        }

        let entry = &mut self.entries[idx];
        entry.seq = seq;
        entry.timestamp_ns = timestamp_ns;
        entry.level = level;
        entry.cpu = cpu;
        entry.occupied = true;

        let flen = facility.len().min(MAX_FACILITY_LEN);
        entry.facility[..flen].copy_from_slice(&facility[..flen]);
        entry.facility_len = flen;

        let clen = caller.len().min(MAX_CALLER_LEN);
        entry.caller[..clen].copy_from_slice(&caller[..clen]);
        entry.caller_len = clen;

        let mlen = message.len().min(MAX_MSG_LEN);
        entry.message[..mlen].copy_from_slice(&message[..mlen]);
        entry.message_len = mlen;

        self.write_seq += 1;
        self.stats.total_written += 1;

        Ok(seq)
    }

    /// Read the next unread entry from the ring buffer.
    ///
    /// Returns the entry and advances the read cursor, or
    /// `WouldBlock` if no unread entries remain.
    pub fn read_next(&mut self) -> Result<RingEntry> {
        if self.read_seq >= self.write_seq {
            return Err(Error::WouldBlock);
        }

        let idx = (self.read_seq as usize) & RING_MASK;
        let entry = self.entries[idx].clone();

        if !entry.occupied {
            return Err(Error::NotFound);
        }

        self.read_seq += 1;
        self.stats.total_read += 1;

        Ok(entry)
    }

    /// Peek at a specific entry by sequence number without
    /// advancing the read cursor.
    pub fn peek_seq(&self, seq: u64) -> Result<&RingEntry> {
        // Check the sequence is still in the buffer.
        if seq < self.read_seq || seq >= self.write_seq {
            return Err(Error::NotFound);
        }

        let idx = (seq as usize) & RING_MASK;
        let entry = &self.entries[idx];

        if !entry.occupied || entry.seq != seq {
            return Err(Error::NotFound);
        }

        Ok(entry)
    }

    /// Return the number of unread entries.
    pub fn pending_count(&self) -> u64 {
        self.write_seq.saturating_sub(self.read_seq)
    }

    /// Return the total number of entries ever written.
    pub fn total_written(&self) -> u64 {
        self.stats.total_written
    }

    /// Return the next sequence number that will be assigned.
    pub fn next_seq(&self) -> u64 {
        self.write_seq
    }

    /// Return accumulated statistics.
    pub fn stats(&self) -> &RingBufStats {
        &self.stats
    }

    /// Begin a drain operation. Returns a state object that can
    /// be fed to [`drain_next`] to iterate through all unread
    /// entries without modifying the buffer read pointer.
    pub fn start_drain(&self) -> DrainIterState {
        DrainIterState {
            next_seq: self.read_seq,
            end_seq: self.write_seq,
        }
    }

    /// Fetch the next entry in a drain operation.
    ///
    /// Returns the entry and advances the drain state, or
    /// `WouldBlock` when the drain is complete.
    pub fn drain_next(&self, state: &mut DrainIterState) -> Result<&RingEntry> {
        if state.next_seq >= state.end_seq {
            return Err(Error::WouldBlock);
        }

        let idx = (state.next_seq as usize) & RING_MASK;
        let entry = &self.entries[idx];

        if !entry.occupied || entry.seq != state.next_seq {
            // Entry was overwritten; skip to a valid one.
            state.next_seq += 1;
            return Err(Error::NotFound);
        }

        state.next_seq += 1;
        Ok(entry)
    }

    /// Drain all unread entries and advance the read cursor to
    /// the write cursor. Returns the number of entries consumed.
    pub fn drain_all(&mut self) -> u64 {
        let count = self.pending_count();
        self.stats.total_read += count;
        self.read_seq = self.write_seq;
        count
    }

    /// Clear the ring buffer, resetting all state.
    pub fn clear(&mut self) {
        for entry in &mut self.entries {
            entry.occupied = false;
            entry.seq = 0;
        }
        self.write_seq = 0;
        self.read_seq = 0;
        self.stats = RingBufStats::new();
    }

    /// Search for entries matching a log level within the
    /// current readable range. Returns up to `max_results`
    /// sequence numbers.
    pub fn find_by_level(&self, level: LogLevel, results: &mut [u64], max_results: usize) -> usize {
        let mut found = 0;
        let limit = max_results.min(results.len());
        let mut seq = self.read_seq;

        while seq < self.write_seq && found < limit {
            let idx = (seq as usize) & RING_MASK;
            let entry = &self.entries[idx];
            if entry.occupied && entry.seq == seq && entry.level == level {
                results[found] = seq;
                found += 1;
            }
            seq += 1;
        }

        found
    }

    /// Search for entries whose message contains the given byte
    /// pattern. Returns up to `max_results` sequence numbers.
    pub fn find_by_pattern(
        &self,
        pattern: &[u8],
        results: &mut [u64],
        max_results: usize,
    ) -> usize {
        if pattern.is_empty() {
            return 0;
        }

        let mut found = 0;
        let limit = max_results.min(results.len());
        let mut seq = self.read_seq;

        while seq < self.write_seq && found < limit {
            let idx = (seq as usize) & RING_MASK;
            let entry = &self.entries[idx];
            if entry.occupied && entry.seq == seq {
                let msg = entry.message();
                if contains_subslice(msg, pattern) {
                    results[found] = seq;
                    found += 1;
                }
            }
            seq += 1;
        }

        found
    }
}

// ══════════════════════════════════════════════════════════════
// Helpers
// ══════════════════════════════════════════════════════════════

/// Naive byte-level substring search (no heap allocation).
fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.len() > haystack.len() {
        return false;
    }
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}
