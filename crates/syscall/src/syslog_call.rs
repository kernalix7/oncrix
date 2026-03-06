// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `syslog` syscall handler — printk ring-buffer access.
//!
//! Implements `syslog(2)` (also known as `klogctl(3)`) which allows
//! user-space to read, clear, and control the kernel message ring
//! buffer, and to toggle/set the console log level.
//!
//! # Actions
//!
//! | Value | Name           | Description                            |
//! |-------|----------------|----------------------------------------|
//! |   0   | Close          | Close the log (no-op in this impl)     |
//! |   1   | Open           | Open the log (no-op in this impl)      |
//! |   2   | Read           | Read unread messages                   |
//! |   3   | ReadAll        | Read all messages                      |
//! |   4   | ReadClear      | Read all messages and clear the buffer |
//! |   5   | Clear          | Clear the ring buffer                  |
//! |   6   | ConsoleOff     | Disable console output                 |
//! |   7   | ConsoleOn      | Enable console output                  |
//! |   8   | ConsoleLevel   | Set console log level                  |
//! |   9   | SizeUnread     | Return number of unread bytes          |
//! |  10   | SizeBuffer     | Return total ring-buffer size          |
//!
//! # Permissions
//!
//! Actions 2, 3, 4, 5, and 9 require `CAP_SYSLOG` or
//! `dmesg_restrict == false`.  Actions 6, 7, and 8 require
//! `CAP_SYS_ADMIN`.
//!
//! # POSIX Reference
//!
//! `syslog(2)` is a Linux extension; no POSIX equivalent exists.

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Capacity of the in-kernel log ring buffer (bytes).
pub const SYSLOG_RING_BUFFER_SIZE: usize = 4096;

/// Maximum console log level (highest verbosity).
pub const SYSLOG_MAX_LEVEL: u8 = 8;

/// Default console log level (WARNING and above are printed).
pub const SYSLOG_DEFAULT_LEVEL: u8 = 7;

/// Default minimum log level that can be set via `ConsoleLevel`.
pub const SYSLOG_MIN_LOGLEVEL: u8 = 1;

// ---------------------------------------------------------------------------
// SyslogAction
// ---------------------------------------------------------------------------

/// Discriminant for the `type` argument of the `syslog(2)` syscall.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum SyslogAction {
    /// Close the log (no-op).
    Close = 0,
    /// Open the log (no-op).
    Open = 1,
    /// Read unread messages from the ring buffer.
    Read = 2,
    /// Read all messages from the ring buffer.
    ReadAll = 3,
    /// Read all messages and then clear the buffer.
    ReadClear = 4,
    /// Clear the ring buffer.
    Clear = 5,
    /// Disable kernel console output (set level to 0).
    ConsoleOff = 6,
    /// Enable kernel console output (restore default level).
    ConsoleOn = 7,
    /// Set console log level to `len` (0..=8).
    ConsoleLevel = 8,
    /// Return number of unread bytes in the ring buffer.
    SizeUnread = 9,
    /// Return total ring-buffer capacity in bytes.
    SizeBuffer = 10,
}

impl SyslogAction {
    /// Convert a raw `u32` into a [`SyslogAction`].
    ///
    /// Returns `None` for unrecognised values.
    pub fn from_raw(raw: u32) -> Option<Self> {
        match raw {
            0 => Some(Self::Close),
            1 => Some(Self::Open),
            2 => Some(Self::Read),
            3 => Some(Self::ReadAll),
            4 => Some(Self::ReadClear),
            5 => Some(Self::Clear),
            6 => Some(Self::ConsoleOff),
            7 => Some(Self::ConsoleOn),
            8 => Some(Self::ConsoleLevel),
            9 => Some(Self::SizeUnread),
            10 => Some(Self::SizeBuffer),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// SyslogConfig
// ---------------------------------------------------------------------------

/// Global configuration for the syslog subsystem.
#[derive(Debug, Clone, Copy)]
pub struct SyslogConfig {
    /// When `true`, reading the ring buffer requires `CAP_SYSLOG`.
    pub dmesg_restrict: bool,
    /// Default console log level restored by `ConsoleOn`.
    pub default_console_loglevel: u8,
    /// Minimum log level that can be set by `ConsoleLevel`.
    pub min_loglevel: u8,
}

impl SyslogConfig {
    /// Create a default configuration.
    pub const fn new() -> Self {
        Self {
            dmesg_restrict: false,
            default_console_loglevel: SYSLOG_DEFAULT_LEVEL,
            min_loglevel: SYSLOG_MIN_LOGLEVEL,
        }
    }
}

impl Default for SyslogConfig {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// SyslogState
// ---------------------------------------------------------------------------

/// Mutable runtime state of the syslog subsystem.
#[derive(Debug)]
pub struct SyslogState {
    /// Current console log level (messages <= this level are shown).
    pub console_level: u8,
    /// Whether console output is currently enabled.
    pub console_enabled: bool,
    /// Ring buffer holding kernel log messages.
    buffer: [u8; SYSLOG_RING_BUFFER_SIZE],
    /// Write cursor (next byte to be written).
    write_pos: usize,
    /// Total bytes ever written (used to compute unread count).
    total_written: usize,
    /// Total bytes already read by the last `Read` operation.
    read_pos: usize,
}

impl SyslogState {
    /// Create a new, empty state.
    pub const fn new() -> Self {
        Self {
            console_level: SYSLOG_DEFAULT_LEVEL,
            console_enabled: true,
            buffer: [0u8; SYSLOG_RING_BUFFER_SIZE],
            write_pos: 0,
            total_written: 0,
            read_pos: 0,
        }
    }

    /// Append `data` to the ring buffer (wraps around on overflow).
    pub fn write(&mut self, data: &[u8]) {
        for &b in data {
            self.buffer[self.write_pos % SYSLOG_RING_BUFFER_SIZE] = b;
            self.write_pos = (self.write_pos + 1) % SYSLOG_RING_BUFFER_SIZE;
            self.total_written = self.total_written.saturating_add(1);
        }
    }

    /// Number of bytes not yet consumed by a `Read` action.
    pub fn unread_bytes(&self) -> usize {
        self.total_written.saturating_sub(self.read_pos)
    }

    /// Copy unread bytes into `buf`, returning the number copied.
    fn read_unread(&mut self, buf: &mut [u8]) -> usize {
        let available = self.unread_bytes().min(buf.len());
        for i in 0..available {
            let pos = (self.read_pos + i) % SYSLOG_RING_BUFFER_SIZE;
            buf[i] = self.buffer[pos];
        }
        self.read_pos = self.read_pos.saturating_add(available);
        available
    }

    /// Copy all buffered bytes into `buf`, returning the number copied.
    fn read_all(&self, buf: &mut [u8]) -> usize {
        let available = self
            .total_written
            .min(SYSLOG_RING_BUFFER_SIZE)
            .min(buf.len());
        // The most recent `available` bytes start at:
        // write_pos - available (modular).
        let start = self
            .write_pos
            .wrapping_sub(available)
            .wrapping_add(SYSLOG_RING_BUFFER_SIZE)
            % SYSLOG_RING_BUFFER_SIZE;
        for i in 0..available {
            buf[i] = self.buffer[(start + i) % SYSLOG_RING_BUFFER_SIZE];
        }
        available
    }

    /// Clear the ring buffer and reset the read cursor.
    fn clear_buffer(&mut self) {
        self.buffer = [0u8; SYSLOG_RING_BUFFER_SIZE];
        self.write_pos = 0;
        self.total_written = 0;
        self.read_pos = 0;
    }
}

impl Default for SyslogState {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// SyslogStats
// ---------------------------------------------------------------------------

/// Cumulative statistics for the syslog subsystem.
#[derive(Debug, Clone, Copy, Default)]
pub struct SyslogStats {
    /// Number of read operations performed.
    pub reads: u64,
    /// Number of clear operations performed.
    pub clears: u64,
    /// Number of console on/off toggles.
    pub console_toggles: u64,
    /// Number of calls rejected due to insufficient privilege.
    pub permission_denied: u64,
}

// ---------------------------------------------------------------------------
// SyslogSubsystem
// ---------------------------------------------------------------------------

/// Top-level syslog subsystem bundling config, state, and statistics.
pub struct SyslogSubsystem {
    /// Static configuration.
    pub config: SyslogConfig,
    /// Mutable runtime state.
    pub state: SyslogState,
    /// Cumulative statistics.
    pub stats: SyslogStats,
}

impl SyslogSubsystem {
    /// Create a new subsystem with default configuration.
    pub const fn new() -> Self {
        Self {
            config: SyslogConfig::new(),
            state: SyslogState::new(),
            stats: SyslogStats {
                reads: 0,
                clears: 0,
                console_toggles: 0,
                permission_denied: 0,
            },
        }
    }

    // -- capability helpers ------------------------------------------------

    /// Check read/clear permission (requires `CAP_SYSLOG` when restricted).
    fn check_read_permission(&mut self, has_cap_syslog: bool) -> Result<()> {
        if self.config.dmesg_restrict && !has_cap_syslog {
            self.stats.permission_denied = self.stats.permission_denied.saturating_add(1);
            return Err(Error::PermissionDenied);
        }
        Ok(())
    }

    /// Check admin permission (requires `CAP_SYS_ADMIN`).
    fn check_admin_permission(&mut self, has_cap_sys_admin: bool) -> Result<()> {
        if !has_cap_sys_admin {
            self.stats.permission_denied = self.stats.permission_denied.saturating_add(1);
            return Err(Error::PermissionDenied);
        }
        Ok(())
    }

    // -- action dispatcher -------------------------------------------------

    /// Dispatch the `syslog` action.
    ///
    /// `has_cap_syslog` and `has_cap_sys_admin` represent the
    /// capability set of the calling process.
    ///
    /// `buf` is the user-supplied buffer for `Read*` actions.
    /// `len` is the user-supplied length; also the new level for
    /// `ConsoleLevel`.
    ///
    /// Returns the number of bytes copied for `Read*` actions,
    /// or the buffer/unread size for `Size*` actions, or 0 otherwise.
    pub fn handle_action(
        &mut self,
        action: SyslogAction,
        buf: &mut [u8],
        len: usize,
        has_cap_syslog: bool,
        has_cap_sys_admin: bool,
    ) -> Result<usize> {
        match action {
            SyslogAction::Close | SyslogAction::Open => {
                // No-ops.
                Ok(0)
            }

            SyslogAction::Read => {
                self.check_read_permission(has_cap_syslog)?;
                let buf_len = buf.len();
                let n = self.state.read_unread(&mut buf[..len.min(buf_len)]);
                self.stats.reads = self.stats.reads.saturating_add(1);
                Ok(n)
            }

            SyslogAction::ReadAll => {
                self.check_read_permission(has_cap_syslog)?;
                let buf_len = buf.len();
                let n = self.state.read_all(&mut buf[..len.min(buf_len)]);
                self.stats.reads = self.stats.reads.saturating_add(1);
                Ok(n)
            }

            SyslogAction::ReadClear => {
                self.check_read_permission(has_cap_syslog)?;
                let buf_len = buf.len();
                let n = self.state.read_all(&mut buf[..len.min(buf_len)]);
                self.state.clear_buffer();
                self.stats.reads = self.stats.reads.saturating_add(1);
                self.stats.clears = self.stats.clears.saturating_add(1);
                Ok(n)
            }

            SyslogAction::Clear => {
                self.check_read_permission(has_cap_syslog)?;
                self.state.clear_buffer();
                self.stats.clears = self.stats.clears.saturating_add(1);
                Ok(0)
            }

            SyslogAction::ConsoleOff => {
                self.check_admin_permission(has_cap_sys_admin)?;
                self.state.console_enabled = false;
                self.state.console_level = 0;
                self.stats.console_toggles = self.stats.console_toggles.saturating_add(1);
                Ok(0)
            }

            SyslogAction::ConsoleOn => {
                self.check_admin_permission(has_cap_sys_admin)?;
                self.state.console_enabled = true;
                self.state.console_level = self.config.default_console_loglevel;
                self.stats.console_toggles = self.stats.console_toggles.saturating_add(1);
                Ok(0)
            }

            SyslogAction::ConsoleLevel => {
                self.check_admin_permission(has_cap_sys_admin)?;
                // `len` carries the desired level.
                let level = len as u8;
                if level < self.config.min_loglevel || level > SYSLOG_MAX_LEVEL {
                    return Err(Error::InvalidArgument);
                }
                self.state.console_level = level;
                Ok(0)
            }

            SyslogAction::SizeUnread => {
                self.check_read_permission(has_cap_syslog)?;
                Ok(self.state.unread_bytes())
            }

            SyslogAction::SizeBuffer => {
                // SizeBuffer does not require any capability.
                Ok(SYSLOG_RING_BUFFER_SIZE)
            }
        }
    }
}

impl Default for SyslogSubsystem {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Syscall entry point
// ---------------------------------------------------------------------------

/// Main `syslog` syscall handler.
///
/// Translates raw syscall arguments to typed values and dispatches
/// to [`SyslogSubsystem::handle_action`].
///
/// # Arguments
///
/// - `subsystem`       — The global syslog subsystem.
/// - `action_type`     — The `type` argument (0..=10).
/// - `buf`             — User-space buffer for `Read*` actions.
/// - `len`             — Buffer length or new console level.
/// - `has_cap_syslog`  — Whether the caller holds `CAP_SYSLOG`.
/// - `has_cap_sys_admin` — Whether the caller holds `CAP_SYS_ADMIN`.
///
/// # Returns
///
/// The number of bytes copied, the queue length, or 0.
///
/// # Errors
///
/// - `InvalidArgument`  — Unrecognised `action_type` or bad level.
/// - `PermissionDenied` — Caller lacks the required capability.
pub fn do_syslog(
    subsystem: &mut SyslogSubsystem,
    action_type: u32,
    buf: &mut [u8],
    len: usize,
    has_cap_syslog: bool,
    has_cap_sys_admin: bool,
) -> Result<usize> {
    let action = SyslogAction::from_raw(action_type).ok_or(Error::InvalidArgument)?;

    subsystem.handle_action(action, buf, len, has_cap_syslog, has_cap_sys_admin)
}
