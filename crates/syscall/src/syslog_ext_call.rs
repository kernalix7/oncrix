// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `syslog(2)` / `klogctl(3)` extended implementation.
//!
//! Provides the full set of `syslog` actions, a circular kernel log buffer,
//! and log level filtering.  The basic `syslog_call.rs` provides the entry
//! shim; this module provides the in-kernel ring buffer and action dispatch.
//!
//! # Syscall signature
//!
//! ```text
//! int syslog(int type, char *bufp, int len);
//! ```
//!
//! # POSIX reference
//!
//! `syslog(2)` (kernel interface) is not part of POSIX; the POSIX facility
//! is the user-space `<syslog.h>` API.
//!
//! # References
//!
//! - Linux: `kernel/printk/printk.c`
//! - `syslog(2)` man page

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Action constants
// ---------------------------------------------------------------------------

/// Close the kernel log.
pub const SYSLOG_ACTION_CLOSE: i32 = 0;
/// Open the kernel log.
pub const SYSLOG_ACTION_OPEN: i32 = 1;
/// Read from the kernel log.
pub const SYSLOG_ACTION_READ: i32 = 2;
/// Read all messages from the ring buffer.
pub const SYSLOG_ACTION_READ_ALL: i32 = 3;
/// Read and clear all messages.
pub const SYSLOG_ACTION_READ_CLEAR: i32 = 4;
/// Clear the ring buffer.
pub const SYSLOG_ACTION_CLEAR: i32 = 5;
/// Disable printing to console.
pub const SYSLOG_ACTION_CONSOLE_OFF: i32 = 6;
/// Enable printing to console.
pub const SYSLOG_ACTION_CONSOLE_ON: i32 = 7;
/// Set console log level.
pub const SYSLOG_ACTION_CONSOLE_LEVEL: i32 = 8;
/// Return size of unread messages.
pub const SYSLOG_ACTION_SIZE_UNREAD: i32 = 9;
/// Return size of the ring buffer.
pub const SYSLOG_ACTION_SIZE_BUFFER: i32 = 10;

// ---------------------------------------------------------------------------
// Log level constants
// ---------------------------------------------------------------------------

/// Emergency (system is unusable).
pub const LOG_EMERG: u8 = 0;
/// Alert (action must be taken immediately).
pub const LOG_ALERT: u8 = 1;
/// Critical conditions.
pub const LOG_CRIT: u8 = 2;
/// Error conditions.
pub const LOG_ERR: u8 = 3;
/// Warning conditions.
pub const LOG_WARNING: u8 = 4;
/// Normal but significant condition.
pub const LOG_NOTICE: u8 = 5;
/// Informational.
pub const LOG_INFO: u8 = 6;
/// Debug-level messages.
pub const LOG_DEBUG: u8 = 7;

/// Default console log level.
pub const DEFAULT_CONSOLE_LOGLEVEL: u8 = LOG_WARNING;
/// Maximum log level value.
pub const LOG_LEVEL_MAX: u8 = LOG_DEBUG;

// ---------------------------------------------------------------------------
// LogEntry — single ring buffer entry
// ---------------------------------------------------------------------------

/// Maximum length of one log line.
const LOG_LINE_MAX: usize = 256;

/// A single kernel log entry.
#[derive(Clone, Copy)]
pub struct LogEntry {
    /// Log level.
    pub level: u8,
    /// Message bytes (NUL-terminated).
    pub msg: [u8; LOG_LINE_MAX],
    /// Length of message (not counting NUL).
    pub len: usize,
    /// Sequence number.
    pub seq: u64,
    /// Whether this entry has been read.
    pub read: bool,
}

impl LogEntry {
    const fn empty() -> Self {
        Self {
            level: LOG_INFO,
            msg: [0; LOG_LINE_MAX],
            len: 0,
            seq: 0,
            read: true,
        }
    }
}

// ---------------------------------------------------------------------------
// KernelLogBuffer — circular ring buffer
// ---------------------------------------------------------------------------

/// Ring buffer capacity.
const RING_SIZE: usize = 512;

/// Kernel log ring buffer.
pub struct KernelLogBuffer {
    entries: [LogEntry; RING_SIZE],
    head: usize,
    tail: usize,
    count: usize,
    next_seq: u64,
    /// Console log level (messages >= this are not printed to console).
    pub console_loglevel: u8,
    /// Whether the console is enabled.
    pub console_enabled: bool,
}

impl KernelLogBuffer {
    /// Create an empty ring buffer.
    pub const fn new() -> Self {
        Self {
            entries: [const { LogEntry::empty() }; RING_SIZE],
            head: 0,
            tail: 0,
            count: 0,
            next_seq: 1,
            console_loglevel: DEFAULT_CONSOLE_LOGLEVEL,
            console_enabled: true,
        }
    }

    /// Append a log message.
    ///
    /// If the buffer is full, the oldest entry is overwritten.
    pub fn write(&mut self, level: u8, msg: &[u8]) {
        let len = msg.len().min(LOG_LINE_MAX - 1);
        let slot = self.head;
        self.entries[slot].level = level;
        self.entries[slot].msg[..len].copy_from_slice(&msg[..len]);
        self.entries[slot].msg[len] = 0;
        self.entries[slot].len = len;
        self.entries[slot].seq = self.next_seq;
        self.entries[slot].read = false;
        self.next_seq += 1;

        self.head = (self.head + 1) % RING_SIZE;
        if self.count < RING_SIZE {
            self.count += 1;
        } else {
            // Overwrite: advance tail too.
            self.tail = (self.tail + 1) % RING_SIZE;
        }
    }

    /// Count unread bytes.
    pub fn unread_bytes(&self) -> usize {
        self.entries
            .iter()
            .filter(|e| !e.read && e.seq > 0)
            .map(|e| e.len + 1)
            .sum()
    }

    /// Mark all entries as read.
    pub fn clear_read_flag(&mut self) {
        for e in &mut self.entries {
            e.read = true;
        }
    }

    /// Total ring buffer capacity.
    pub const fn buffer_size(&self) -> usize {
        RING_SIZE * LOG_LINE_MAX
    }

    /// Return `true` if `level` should be printed to the console.
    pub fn should_print(&self, level: u8) -> bool {
        self.console_enabled && level < self.console_loglevel
    }
}

impl Default for KernelLogBuffer {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Validation helpers
// ---------------------------------------------------------------------------

/// Validate and parse a `syslog` action.
fn validate_action(action: i32) -> Result<()> {
    if !(SYSLOG_ACTION_CLOSE..=SYSLOG_ACTION_SIZE_BUFFER).contains(&action) {
        return Err(Error::InvalidArgument);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// sys_syslog — entry point
// ---------------------------------------------------------------------------

/// Handler for `syslog(2)`.
///
/// Dispatches the action and returns the appropriate result.
///
/// # Arguments
///
/// * `buf`        — Kernel log ring buffer.
/// * `action`     — `SYSLOG_ACTION_*` constant.
/// * `len`        — Length argument (for `READ*` actions).
/// * `has_cap`    — Whether the caller has `CAP_SYS_ADMIN` or `CAP_SYSLOG`.
///
/// # Returns
///
/// `Ok(n)` where `n` is action-dependent:
/// - For size queries: the byte count.
/// - For enable/disable: 0.
/// - For read operations: 0 (actual data copy is handled by the caller).
///
/// # Errors
///
/// * [`Error::InvalidArgument`]  — unknown action or invalid level.
/// * [`Error::PermissionDenied`] — caller lacks required capability.
pub fn sys_syslog(
    buf: &mut KernelLogBuffer,
    action: i32,
    len: i32,
    has_cap: bool,
) -> Result<usize> {
    validate_action(action)?;

    // Most actions require CAP_SYS_ADMIN / CAP_SYSLOG.
    if action != SYSLOG_ACTION_OPEN && action != SYSLOG_ACTION_CLOSE && !has_cap {
        return Err(Error::PermissionDenied);
    }

    match action {
        SYSLOG_ACTION_CLOSE | SYSLOG_ACTION_OPEN => Ok(0),

        SYSLOG_ACTION_READ => {
            if len < 0 {
                return Err(Error::InvalidArgument);
            }
            Ok(buf.unread_bytes().min(len as usize))
        }

        SYSLOG_ACTION_READ_ALL => {
            if len < 0 {
                return Err(Error::InvalidArgument);
            }
            let unread = buf.unread_bytes();
            Ok(unread.min(len as usize))
        }

        SYSLOG_ACTION_READ_CLEAR => {
            let unread = buf.unread_bytes();
            buf.clear_read_flag();
            Ok(unread)
        }

        SYSLOG_ACTION_CLEAR => {
            buf.clear_read_flag();
            Ok(0)
        }

        SYSLOG_ACTION_CONSOLE_OFF => {
            buf.console_enabled = false;
            Ok(0)
        }

        SYSLOG_ACTION_CONSOLE_ON => {
            buf.console_enabled = true;
            Ok(0)
        }

        SYSLOG_ACTION_CONSOLE_LEVEL => {
            if len < 0 || len > LOG_LEVEL_MAX as i32 {
                return Err(Error::InvalidArgument);
            }
            buf.console_loglevel = len as u8;
            Ok(0)
        }

        SYSLOG_ACTION_SIZE_UNREAD => Ok(buf.unread_bytes()),

        SYSLOG_ACTION_SIZE_BUFFER => Ok(buf.buffer_size()),

        _ => Err(Error::InvalidArgument),
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn buffer_size_query() {
        let mut buf = KernelLogBuffer::new();
        let size = sys_syslog(&mut buf, SYSLOG_ACTION_SIZE_BUFFER, 0, true).unwrap();
        assert!(size > 0);
    }

    #[test]
    fn write_and_unread() {
        let mut buf = KernelLogBuffer::new();
        buf.write(LOG_INFO, b"hello world");
        let n = sys_syslog(&mut buf, SYSLOG_ACTION_SIZE_UNREAD, 0, true).unwrap();
        assert!(n > 0);
    }

    #[test]
    fn clear_removes_unread() {
        let mut buf = KernelLogBuffer::new();
        buf.write(LOG_ERR, b"error msg");
        sys_syslog(&mut buf, SYSLOG_ACTION_CLEAR, 0, true).unwrap();
        let n = sys_syslog(&mut buf, SYSLOG_ACTION_SIZE_UNREAD, 0, true).unwrap();
        assert_eq!(n, 0);
    }

    #[test]
    fn console_level_set() {
        let mut buf = KernelLogBuffer::new();
        sys_syslog(&mut buf, SYSLOG_ACTION_CONSOLE_LEVEL, 3, true).unwrap();
        assert_eq!(buf.console_loglevel, 3);
    }

    #[test]
    fn invalid_console_level() {
        let mut buf = KernelLogBuffer::new();
        assert_eq!(
            sys_syslog(&mut buf, SYSLOG_ACTION_CONSOLE_LEVEL, 99, true),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn unprivileged_read_denied() {
        let mut buf = KernelLogBuffer::new();
        assert_eq!(
            sys_syslog(&mut buf, SYSLOG_ACTION_READ, 256, false),
            Err(Error::PermissionDenied)
        );
    }

    #[test]
    fn console_toggle() {
        let mut buf = KernelLogBuffer::new();
        sys_syslog(&mut buf, SYSLOG_ACTION_CONSOLE_OFF, 0, true).unwrap();
        assert!(!buf.console_enabled);
        sys_syslog(&mut buf, SYSLOG_ACTION_CONSOLE_ON, 0, true).unwrap();
        assert!(buf.console_enabled);
    }

    #[test]
    fn should_print_filters() {
        let buf = KernelLogBuffer::new();
        assert!(buf.should_print(LOG_EMERG));
        assert!(buf.should_print(LOG_ERR));
        assert!(!buf.should_print(LOG_INFO));
    }
}
