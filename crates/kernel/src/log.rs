// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Kernel logging framework (printk-style).
//!
//! Provides structured logging with severity levels, a ring buffer
//! for early-boot buffering, and a subsystem tag for filtering.
//! Log output is routed to the serial console and optionally to
//! a `/proc/kmsg`-style interface for user-space log readers.
//!
//! # Log Levels
//!
//! | Level | Name    | Use |
//! |-------|---------|-----|
//! | 0     | Error   | Critical failures |
//! | 1     | Warn    | Non-fatal issues |
//! | 2     | Info    | Key state changes |
//! | 3     | Debug   | Development details |
//! | 4     | Trace   | Verbose tracing |
//!
//! Reference: Linux `kernel/printk/printk.c`, `include/linux/kern_levels.h`.

use core::fmt;
use core::sync::atomic::{AtomicU8, Ordering};

// ---------------------------------------------------------------------------
// Log levels
// ---------------------------------------------------------------------------

/// Log severity levels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum Level {
    /// Critical errors.
    Error = 0,
    /// Non-fatal warnings.
    Warn = 1,
    /// Informational messages.
    Info = 2,
    /// Debug messages.
    Debug = 3,
    /// Verbose trace output.
    Trace = 4,
}

impl Level {
    /// Short prefix string for log output.
    pub const fn prefix(self) -> &'static str {
        match self {
            Level::Error => "ERR",
            Level::Warn => "WRN",
            Level::Info => "INF",
            Level::Debug => "DBG",
            Level::Trace => "TRC",
        }
    }

    /// From a numeric level (clamped to 0..=4).
    pub const fn from_u8(val: u8) -> Self {
        match val {
            0 => Level::Error,
            1 => Level::Warn,
            2 => Level::Info,
            3 => Level::Debug,
            _ => Level::Trace,
        }
    }
}

impl fmt::Display for Level {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.prefix())
    }
}

// ---------------------------------------------------------------------------
// Global log level filter
// ---------------------------------------------------------------------------

/// Current minimum log level (messages below this are suppressed).
static MIN_LEVEL: AtomicU8 = AtomicU8::new(Level::Info as u8);

/// Set the minimum log level.
pub fn set_level(level: Level) {
    MIN_LEVEL.store(level as u8, Ordering::Relaxed);
}

/// Get the current minimum log level.
pub fn current_level() -> Level {
    Level::from_u8(MIN_LEVEL.load(Ordering::Relaxed))
}

/// Check if a message at `level` would be logged.
pub fn is_enabled(level: Level) -> bool {
    (level as u8) <= MIN_LEVEL.load(Ordering::Relaxed)
}

// ---------------------------------------------------------------------------
// Log record
// ---------------------------------------------------------------------------

/// Maximum message length in a log record.
const MAX_MSG_LEN: usize = 200;

/// Maximum subsystem tag length.
const MAX_TAG_LEN: usize = 16;

/// A single log record.
#[derive(Debug, Clone, Copy)]
pub struct LogRecord {
    /// Severity level.
    pub level: Level,
    /// Subsystem tag (e.g., "sched", "mm", "ipc").
    tag: [u8; MAX_TAG_LEN],
    /// Tag length.
    tag_len: u8,
    /// Message text.
    msg: [u8; MAX_MSG_LEN],
    /// Message length.
    msg_len: u8,
    /// Kernel tick at log time.
    pub tick: u64,
}

impl LogRecord {
    /// Create a new log record.
    pub fn new(level: Level, tag: &[u8], msg: &[u8], tick: u64) -> Self {
        let mut rec = Self {
            level,
            tag: [0; MAX_TAG_LEN],
            tag_len: 0,
            msg: [0; MAX_MSG_LEN],
            msg_len: 0,
            tick,
        };
        let tl = tag.len().min(MAX_TAG_LEN);
        rec.tag[..tl].copy_from_slice(&tag[..tl]);
        rec.tag_len = tl as u8;
        let ml = msg.len().min(MAX_MSG_LEN);
        rec.msg[..ml].copy_from_slice(&msg[..ml]);
        rec.msg_len = ml as u8;
        rec
    }

    /// Subsystem tag as a byte slice.
    pub fn tag(&self) -> &[u8] {
        &self.tag[..self.tag_len as usize]
    }

    /// Message as a byte slice.
    pub fn msg(&self) -> &[u8] {
        &self.msg[..self.msg_len as usize]
    }
}

// ---------------------------------------------------------------------------
// Ring buffer
// ---------------------------------------------------------------------------

/// Ring buffer size (power of two for fast modulo).
const RING_SIZE: usize = 256;

/// Kernel log ring buffer.
///
/// Stores the most recent `RING_SIZE` log records. Older entries
/// are overwritten when the buffer is full (circular behavior).
pub struct LogRing {
    /// Record storage.
    records: [LogRecord; RING_SIZE],
    /// Write index (monotonically increasing).
    write_idx: usize,
    /// Total records ever written.
    total: u64,
}

impl Default for LogRing {
    fn default() -> Self {
        Self::new()
    }
}

impl LogRing {
    /// Create an empty log ring.
    pub const fn new() -> Self {
        Self {
            records: [LogRecord {
                level: Level::Info,
                tag: [0; MAX_TAG_LEN],
                tag_len: 0,
                msg: [0; MAX_MSG_LEN],
                msg_len: 0,
                tick: 0,
            }; RING_SIZE],
            write_idx: 0,
            total: 0,
        }
    }

    /// Append a log record to the ring.
    pub fn push(&mut self, record: LogRecord) {
        let idx = self.write_idx % RING_SIZE;
        self.records[idx] = record;
        self.write_idx += 1;
        self.total += 1;
    }

    /// Get the most recent record (if any).
    pub fn last(&self) -> Option<&LogRecord> {
        if self.write_idx == 0 {
            return None;
        }
        Some(&self.records[(self.write_idx - 1) % RING_SIZE])
    }

    /// Number of records currently in the buffer (up to `RING_SIZE`).
    pub fn len(&self) -> usize {
        self.write_idx.min(RING_SIZE)
    }

    /// Check if the ring is empty.
    pub fn is_empty(&self) -> bool {
        self.write_idx == 0
    }

    /// Total records ever written (including overwritten ones).
    pub fn total_written(&self) -> u64 {
        self.total
    }

    /// Iterate over records from oldest to newest.
    pub fn iter(&self) -> LogRingIter<'_> {
        let count = self.len();
        let start = self.write_idx.saturating_sub(RING_SIZE);
        LogRingIter {
            ring: self,
            pos: start,
            remaining: count,
        }
    }
}

impl core::fmt::Debug for LogRing {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("LogRing")
            .field("entries", &self.len())
            .field("capacity", &RING_SIZE)
            .field("total_written", &self.total)
            .finish()
    }
}

/// Iterator over log ring records.
pub struct LogRingIter<'a> {
    ring: &'a LogRing,
    pos: usize,
    remaining: usize,
}

impl<'a> Iterator for LogRingIter<'a> {
    type Item = &'a LogRecord;

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 {
            return None;
        }
        let idx = self.pos % RING_SIZE;
        self.pos += 1;
        self.remaining -= 1;
        Some(&self.ring.records[idx])
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.remaining, Some(self.remaining))
    }
}

impl ExactSizeIterator for LogRingIter<'_> {}

// ---------------------------------------------------------------------------
// Format helper
// ---------------------------------------------------------------------------

/// A small fixed-size buffer for formatting log messages via `core::fmt`.
pub struct FmtBuf {
    /// Buffer storage.
    buf: [u8; MAX_MSG_LEN],
    /// Current write position.
    pos: usize,
}

impl Default for FmtBuf {
    fn default() -> Self {
        Self::new()
    }
}

impl FmtBuf {
    /// Create a new empty format buffer.
    pub const fn new() -> Self {
        Self {
            buf: [0; MAX_MSG_LEN],
            pos: 0,
        }
    }

    /// Get the written bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.buf[..self.pos]
    }

    /// Reset the buffer.
    pub fn clear(&mut self) {
        self.pos = 0;
    }
}

impl fmt::Write for FmtBuf {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        let bytes = s.as_bytes();
        let remaining = MAX_MSG_LEN - self.pos;
        let to_copy = bytes.len().min(remaining);
        self.buf[self.pos..self.pos + to_copy].copy_from_slice(&bytes[..to_copy]);
        self.pos += to_copy;
        Ok(())
    }
}
