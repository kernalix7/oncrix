// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Kernel syslog / dmesg ring buffer.
//!
//! Provides a circular buffer for kernel log messages compatible with
//! the Linux `syslog(2)` / `dmesg` interface. Messages are tagged
//! with a timestamp (kernel ticks), a syslog facility, and a log
//! level.
//!
//! # Buffer Layout
//!
//! The ring buffer holds up to [`DMESG_BUFFER_SIZE`] entries. When
//! full, new entries overwrite the oldest ones. A monotonically
//! increasing sequence number (`total_written`) provides stable
//! cursors for readers even after wrap-around.
//!
//! # Syslog Actions
//!
//! [`do_syslog`] implements the semantics of Linux `syslog(2)`,
//! supporting read, read-all, read-clear, clear, and size queries.
//!
//! Reference: Linux `kernel/printk/printk.c`,
//! `include/linux/syslog.h`.

use crate::log::Level;
use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Maximum message length stored in a single dmesg entry (bytes).
const MAX_MSG_LEN: usize = 128;

/// Number of entries in the dmesg ring buffer (power of two).
const DMESG_BUFFER_SIZE: usize = 256;

/// Maximum formatted line length for [`format_dmesg_line`].
///
/// Layout: `[<20 digits timestamp>] <8 facility>.<5 level>: <128 msg>\n`
const MAX_LINE_LEN: usize = 180;

// -------------------------------------------------------------------
// DmesgFacility
// -------------------------------------------------------------------

/// Syslog-compatible message facility codes.
///
/// These mirror the standard POSIX/BSD syslog facility values
/// defined in `<syslog.h>`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum DmesgFacility {
    /// Kernel messages.
    Kern = 0,
    /// User-level messages.
    User = 1,
    /// System daemons.
    Daemon = 3,
    /// Security/authorization messages.
    Auth = 4,
    /// Syslog internal messages.
    Syslog = 5,
    /// Line printer subsystem.
    Lpr = 6,
    /// Network news subsystem.
    News = 7,
}

impl DmesgFacility {
    /// Short label for formatted output.
    pub const fn label(self) -> &'static str {
        match self {
            Self::Kern => "kern",
            Self::User => "user",
            Self::Daemon => "daemon",
            Self::Auth => "auth",
            Self::Syslog => "syslog",
            Self::Lpr => "lpr",
            Self::News => "news",
        }
    }

    /// Convert a raw `u8` to a facility, returning `None` for
    /// unknown codes.
    pub const fn from_u8(val: u8) -> Option<Self> {
        match val {
            0 => Some(Self::Kern),
            1 => Some(Self::User),
            3 => Some(Self::Daemon),
            4 => Some(Self::Auth),
            5 => Some(Self::Syslog),
            6 => Some(Self::Lpr),
            7 => Some(Self::News),
            _ => None,
        }
    }
}

impl core::fmt::Display for DmesgFacility {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.label())
    }
}

// -------------------------------------------------------------------
// DmesgEntry
// -------------------------------------------------------------------

/// A single kernel log entry stored in the dmesg ring buffer.
#[derive(Debug, Clone, Copy)]
pub struct DmesgEntry {
    /// Kernel tick at log time.
    pub timestamp: u64,
    /// Log severity level.
    pub level: Level,
    /// Syslog facility.
    pub facility: DmesgFacility,
    /// Message bytes.
    msg: [u8; MAX_MSG_LEN],
    /// Valid length of `msg`.
    msg_len: u8,
}

/// Default (empty) entry used for buffer initialization.
const EMPTY_ENTRY: DmesgEntry = DmesgEntry {
    timestamp: 0,
    level: Level::Info,
    facility: DmesgFacility::Kern,
    msg: [0; MAX_MSG_LEN],
    msg_len: 0,
};

impl DmesgEntry {
    /// Create a new dmesg entry.
    ///
    /// The message is truncated to [`MAX_MSG_LEN`] bytes if longer.
    pub fn new(timestamp: u64, level: Level, facility: DmesgFacility, msg: &[u8]) -> Self {
        let mut entry = EMPTY_ENTRY;
        entry.timestamp = timestamp;
        entry.level = level;
        entry.facility = facility;
        let len = msg.len().min(MAX_MSG_LEN);
        entry.msg[..len].copy_from_slice(&msg[..len]);
        entry.msg_len = len as u8;
        entry
    }

    /// Message as a byte slice.
    pub fn msg(&self) -> &[u8] {
        &self.msg[..self.msg_len as usize]
    }
}

// -------------------------------------------------------------------
// DmesgBuffer
// -------------------------------------------------------------------

/// Circular ring buffer holding the most recent kernel log messages.
///
/// Stores up to [`DMESG_BUFFER_SIZE`] entries. When full, new
/// entries silently overwrite the oldest ones. The `total_written`
/// counter serves as a sequence number for stable read cursors.
pub struct DmesgBuffer {
    /// Entry storage.
    entries: [DmesgEntry; DMESG_BUFFER_SIZE],
    /// Next write position (monotonically increasing).
    write_pos: usize,
    /// Next read position (used by sequential readers).
    read_pos: usize,
    /// Total entries ever written (sequence counter).
    total_written: u64,
}

impl Default for DmesgBuffer {
    fn default() -> Self {
        Self::new()
    }
}

impl DmesgBuffer {
    /// Create an empty dmesg buffer.
    pub const fn new() -> Self {
        Self {
            entries: [EMPTY_ENTRY; DMESG_BUFFER_SIZE],
            write_pos: 0,
            read_pos: 0,
            total_written: 0,
        }
    }

    /// Append an entry to the ring buffer.
    ///
    /// Returns `true` if an older entry was overwritten.
    pub fn push(&mut self, entry: DmesgEntry) -> bool {
        let wrapped = self.write_pos >= DMESG_BUFFER_SIZE;
        let idx = self.write_pos % DMESG_BUFFER_SIZE;
        self.entries[idx] = entry;
        self.write_pos += 1;
        self.total_written += 1;
        // Advance read_pos if it fell behind the oldest retained
        // entry (i.e., the buffer wrapped past it).
        let oldest_pos = self.write_pos.saturating_sub(DMESG_BUFFER_SIZE);
        if self.read_pos < oldest_pos {
            self.read_pos = oldest_pos;
        }
        wrapped
    }

    /// Number of entries currently stored (up to buffer capacity).
    pub fn count(&self) -> usize {
        self.write_pos.min(DMESG_BUFFER_SIZE)
    }

    /// Check if the buffer is empty.
    pub fn is_empty(&self) -> bool {
        self.write_pos == 0
    }

    /// Total entries ever written (including overwritten ones).
    pub fn total_written(&self) -> u64 {
        self.total_written
    }

    /// Number of unread entries (between `read_pos` and
    /// `write_pos`).
    pub fn unread_count(&self) -> usize {
        self.write_pos.saturating_sub(self.read_pos)
    }

    /// Clear all entries and reset positions.
    pub fn clear(&mut self) {
        self.write_pos = 0;
        self.read_pos = 0;
        self.total_written = 0;
    }

    /// Read entries starting from sequence number `start_seq`.
    ///
    /// Copies up to `buf.len()` matching entries into `buf` and
    /// returns the number of entries actually copied. If
    /// `start_seq` refers to an entry that has already been
    /// overwritten, reading starts from the oldest available entry.
    pub fn read_entries(&self, start_seq: u64, buf: &mut [DmesgEntry]) -> usize {
        if buf.is_empty() || self.write_pos == 0 {
            return 0;
        }
        // Determine the oldest still-available sequence number.
        let oldest_seq = self.total_written.saturating_sub(self.count() as u64);
        let effective_start = if start_seq < oldest_seq {
            oldest_seq
        } else {
            start_seq
        };
        if effective_start >= self.total_written {
            return 0;
        }
        let available = (self.total_written - effective_start) as usize;
        let to_copy = available.min(buf.len());
        for (i, slot) in buf.iter_mut().enumerate().take(to_copy) {
            let seq = effective_start + i as u64;
            let phys = (seq as usize) % DMESG_BUFFER_SIZE;
            *slot = self.entries[phys];
        }
        to_copy
    }
}

impl core::fmt::Debug for DmesgBuffer {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("DmesgBuffer")
            .field("entries", &self.count())
            .field("capacity", &DMESG_BUFFER_SIZE)
            .field("total_written", &self.total_written)
            .finish()
    }
}

// -------------------------------------------------------------------
// SyslogAction
// -------------------------------------------------------------------

/// Actions for the `syslog(2)` system call.
///
/// These mirror the Linux `SYSLOG_ACTION_*` constants from
/// `<linux/syslog.h>`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum SyslogAction {
    /// Read up to `len` bytes of new messages from the log.
    Read = 2,
    /// Read and return all messages in the ring buffer.
    ReadAll = 3,
    /// Read and return all messages, then clear the ring buffer.
    ReadClear = 4,
    /// Clear the ring buffer.
    Clear = 5,
    /// Return number of bytes in unread messages.
    SizeUnread = 9,
    /// Return total size of the ring buffer.
    SizeBuffer = 10,
}

impl SyslogAction {
    /// Convert a raw `u32` to a `SyslogAction`.
    ///
    /// Returns `Err(InvalidArgument)` for unknown action codes.
    pub fn from_u32(val: u32) -> Result<Self> {
        match val {
            2 => Ok(Self::Read),
            3 => Ok(Self::ReadAll),
            4 => Ok(Self::ReadClear),
            5 => Ok(Self::Clear),
            9 => Ok(Self::SizeUnread),
            10 => Ok(Self::SizeBuffer),
            _ => Err(Error::InvalidArgument),
        }
    }
}

// -------------------------------------------------------------------
// Public API
// -------------------------------------------------------------------

/// Add a message to the dmesg ring buffer with the current
/// timestamp.
///
/// `tick` should be the current kernel tick counter value.
/// The message is silently truncated to [`MAX_MSG_LEN`] bytes.
pub fn log_message(
    buffer: &mut DmesgBuffer,
    level: Level,
    facility: DmesgFacility,
    msg: &[u8],
    tick: u64,
) {
    let entry = DmesgEntry::new(tick, level, facility, msg);
    buffer.push(entry);
}

/// Read entries from the ring buffer starting at `start_seq`.
///
/// This is a convenience wrapper around
/// [`DmesgBuffer::read_entries`].
pub fn read_entries(buffer: &DmesgBuffer, start_seq: u64, buf: &mut [DmesgEntry]) -> usize {
    buffer.read_entries(start_seq, buf)
}

/// Clear all entries from the dmesg ring buffer.
pub fn clear(buffer: &mut DmesgBuffer) {
    buffer.clear();
}

/// Execute a `syslog(2)` action on the dmesg buffer.
///
/// # Arguments
///
/// - `action`: the syslog command to execute
/// - `buf`: output buffer for read operations (unused for
///   `Clear`, `SizeUnread`, `SizeBuffer`)
///
/// # Returns
///
/// - `Read` / `ReadAll` / `ReadClear`: number of entries copied
///   into `buf`
/// - `Clear`: 0
/// - `SizeUnread`: number of unread entries
/// - `SizeBuffer`: total buffer capacity
pub fn do_syslog(
    buffer: &mut DmesgBuffer,
    action: SyslogAction,
    buf: &mut [DmesgEntry],
) -> Result<usize> {
    match action {
        SyslogAction::Read => {
            let n = buffer.read_entries(
                buffer
                    .total_written()
                    .saturating_sub(buffer.unread_count() as u64),
                buf,
            );
            // Advance the read position past what was returned.
            let new_read = buffer.read_pos.saturating_add(n);
            buffer.read_pos = new_read.min(buffer.write_pos);
            Ok(n)
        }
        SyslogAction::ReadAll => {
            let oldest_seq = buffer.total_written().saturating_sub(buffer.count() as u64);
            let n = buffer.read_entries(oldest_seq, buf);
            Ok(n)
        }
        SyslogAction::ReadClear => {
            let oldest_seq = buffer.total_written().saturating_sub(buffer.count() as u64);
            let n = buffer.read_entries(oldest_seq, buf);
            buffer.clear();
            Ok(n)
        }
        SyslogAction::Clear => {
            buffer.clear();
            Ok(0)
        }
        SyslogAction::SizeUnread => Ok(buffer.unread_count()),
        SyslogAction::SizeBuffer => Ok(DMESG_BUFFER_SIZE),
    }
}

/// Format a single dmesg entry into a human-readable line.
///
/// Output format: `[<timestamp>] <facility>.<level>: <message>`
///
/// Returns the number of bytes written to `buf`, or
/// `Err(InvalidArgument)` if `buf` is too small.
pub fn format_dmesg_line(entry: &DmesgEntry, buf: &mut [u8]) -> Result<usize> {
    if buf.len() < MAX_LINE_LEN {
        // Allow smaller buffers, but we need at least some space
        // for the prefix.
        if buf.len() < 16 {
            return Err(Error::InvalidArgument);
        }
    }
    let mut pos = 0;

    // "[" prefix
    if pos < buf.len() {
        buf[pos] = b'[';
        pos += 1;
    }

    // Timestamp — simple decimal formatting without allocator.
    pos = write_u64_decimal(entry.timestamp, buf, pos);

    // "] "
    let suffix = b"] ";
    let end = (pos + suffix.len()).min(buf.len());
    let copy_len = end - pos;
    buf[pos..pos + copy_len].copy_from_slice(&suffix[..copy_len]);
    pos += copy_len;

    // facility.level
    let fac = entry.facility.label().as_bytes();
    let fac_len = fac.len().min(buf.len().saturating_sub(pos));
    buf[pos..pos + fac_len].copy_from_slice(&fac[..fac_len]);
    pos += fac_len;

    if pos < buf.len() {
        buf[pos] = b'.';
        pos += 1;
    }

    let lvl = entry.level.prefix().as_bytes();
    let lvl_len = lvl.len().min(buf.len().saturating_sub(pos));
    buf[pos..pos + lvl_len].copy_from_slice(&lvl[..lvl_len]);
    pos += lvl_len;

    // ": "
    let sep = b": ";
    let sep_len = sep.len().min(buf.len().saturating_sub(pos));
    buf[pos..pos + sep_len].copy_from_slice(&sep[..sep_len]);
    pos += sep_len;

    // message
    let msg = entry.msg();
    let msg_len = msg.len().min(buf.len().saturating_sub(pos));
    buf[pos..pos + msg_len].copy_from_slice(&msg[..msg_len]);
    pos += msg_len;

    Ok(pos)
}

// -------------------------------------------------------------------
// Helpers
// -------------------------------------------------------------------

/// Write a `u64` as decimal ASCII into `buf` starting at `pos`.
/// Returns the new position after the digits.
fn write_u64_decimal(val: u64, buf: &mut [u8], pos: usize) -> usize {
    if val == 0 {
        if pos < buf.len() {
            buf[pos] = b'0';
            return pos + 1;
        }
        return pos;
    }
    // Stack-buffer for up to 20 decimal digits.
    let mut digits = [0u8; 20];
    let mut n = val;
    let mut count = 0usize;
    while n > 0 {
        digits[count] = b'0' + (n % 10) as u8;
        n /= 10;
        count += 1;
    }
    // Write digits in correct (reversed) order.
    let mut p = pos;
    let mut i = count;
    while i > 0 && p < buf.len() {
        i -= 1;
        buf[p] = digits[i];
        p += 1;
    }
    p
}
