// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Hardware watchdog timer driver.
//!
//! Provides a watchdog timer subsystem that monitors system health and
//! triggers a configurable action (reset, poweroff, panic) if the system
//! fails to ping the watchdog within a configured timeout period.
//!
//! # Architecture
//!
//! - **WatchdogDevice** — represents a single hardware watchdog timer
//!   with configurable timeout, nowayout mode, and magic close support.
//! - **WatchdogRegistry** — manages up to [`MAX_WATCHDOGS`] devices,
//!   providing registration, lookup, and periodic tick checking.
//!
//! # Magic Close
//!
//! Following the Linux watchdog convention, a watchdog that has
//! `nowayout` set cannot be stopped unless the userspace process
//! writes the magic character `'V'` before closing the device.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Default watchdog timeout in seconds.
const _DEFAULT_TIMEOUT_SECS: u32 = 30;

/// Minimum allowed timeout in seconds.
const _MIN_TIMEOUT: u32 = 1;

/// Maximum allowed timeout in seconds.
const _MAX_TIMEOUT: u32 = 3600;

/// Maximum number of watchdog devices supported.
const MAX_WATCHDOGS: usize = 4;

/// Watchdog option flag: timeout is settable.
const _WDIOF_SETTIMEOUT: u32 = 0x80;

/// Watchdog option flag: supports magic close.
const _WDIOF_MAGICCLOSE: u32 = 0x100;

/// Watchdog option flag: supports keepalive ping.
const _WDIOF_KEEPALIVEPING: u32 = 0x8000;

/// Magic close character (`'V'`).
const MAGIC_CLOSE_CHAR: u8 = b'V';

/// Nanoseconds per second.
const NANOS_PER_SEC: u64 = 1_000_000_000;

// -------------------------------------------------------------------
// WatchdogState
// -------------------------------------------------------------------

/// Current state of a watchdog timer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum WatchdogState {
    /// Watchdog is stopped and not counting.
    #[default]
    Stopped,
    /// Watchdog is running and counting down.
    Running,
    /// Watchdog has expired (timeout reached without ping).
    Expired,
}

// -------------------------------------------------------------------
// WatchdogAction
// -------------------------------------------------------------------

/// Action to take when the watchdog timer expires.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum WatchdogAction {
    /// Reset the system (default).
    #[default]
    Reset,
    /// Power off the system.
    Poweroff,
    /// Trigger a kernel panic.
    Panic,
    /// Take no action.
    None,
}

// -------------------------------------------------------------------
// WatchdogInfo
// -------------------------------------------------------------------

/// Descriptive information about a watchdog device.
#[derive(Debug, Clone, Default)]
pub struct WatchdogInfo {
    /// Current timeout in seconds.
    pub timeout_secs: u32,
    /// Minimum supported timeout in seconds.
    pub min_timeout: u32,
    /// Maximum supported timeout in seconds.
    pub max_timeout: u32,
    /// Option flags (`WDIOF_*`).
    pub options: u32,
    /// Firmware/hardware version.
    pub firmware_version: u32,
    /// Identity string stored as raw bytes.
    pub identity: [u8; 32],
    /// Number of valid bytes in [`identity`](Self::identity).
    pub identity_len: usize,
}

// -------------------------------------------------------------------
// WatchdogDevice
// -------------------------------------------------------------------

/// A single hardware watchdog timer device.
#[derive(Debug, Clone)]
pub struct WatchdogDevice {
    /// Unique device identifier.
    pub id: u32,
    /// Descriptive information about the device.
    pub info: WatchdogInfo,
    /// Current state of the watchdog.
    pub state: WatchdogState,
    /// Action to take on expiry.
    pub action: WatchdogAction,
    /// Timestamp (ns) of the last successful ping.
    pub last_ping_ns: u64,
    /// Timestamp (ns) when the watchdog was started.
    pub start_time_ns: u64,
    /// Timestamp (ns) when the watchdog will expire.
    pub expires_ns: u64,
    /// If true, the watchdog cannot be stopped once started.
    pub nowayout: bool,
    /// Set when the magic close character has been received.
    pub magic_close: bool,
    /// Total number of pings received.
    pub ping_count: u64,
    /// Whether the device is active and registered.
    pub active: bool,
}

impl WatchdogDevice {
    /// Creates a new watchdog device with the given `id` and
    /// `timeout` in seconds.
    ///
    /// The timeout is clamped to
    /// [`_MIN_TIMEOUT`]..=[`_MAX_TIMEOUT`].
    pub fn new(id: u32, timeout: u32) -> Self {
        let clamped = timeout.clamp(_MIN_TIMEOUT, _MAX_TIMEOUT);
        Self {
            id,
            info: WatchdogInfo {
                timeout_secs: clamped,
                min_timeout: _MIN_TIMEOUT,
                max_timeout: _MAX_TIMEOUT,
                options: _WDIOF_SETTIMEOUT | _WDIOF_MAGICCLOSE | _WDIOF_KEEPALIVEPING,
                firmware_version: 0,
                identity: [0u8; 32],
                identity_len: 0,
            },
            state: WatchdogState::Stopped,
            action: WatchdogAction::Reset,
            last_ping_ns: 0,
            start_time_ns: 0,
            expires_ns: 0,
            nowayout: false,
            magic_close: false,
            ping_count: 0,
            active: true,
        }
    }

    /// Starts the watchdog timer.
    ///
    /// Sets the state to [`WatchdogState::Running`] and computes
    /// the expiry timestamp based on the configured timeout and
    /// the provided current time `now_ns` (in nanoseconds).
    ///
    /// Returns [`Error::Busy`] if the watchdog is already running.
    pub fn start(&mut self, now_ns: u64) -> Result<()> {
        if self.state == WatchdogState::Running {
            return Err(Error::Busy);
        }
        self.state = WatchdogState::Running;
        self.start_time_ns = now_ns;
        self.last_ping_ns = now_ns;
        self.expires_ns = now_ns + u64::from(self.info.timeout_secs) * NANOS_PER_SEC;
        self.magic_close = false;
        Ok(())
    }

    /// Stops the watchdog timer.
    ///
    /// If [`nowayout`](Self::nowayout) is set, the watchdog can
    /// only be stopped after the magic close character has been
    /// received via [`write_magic`](Self::write_magic).
    ///
    /// Returns [`Error::PermissionDenied`] when `nowayout` is set
    /// and the magic close handshake has not been performed.
    /// Returns [`Error::InvalidArgument`] when the watchdog is not
    /// currently running.
    pub fn stop(&mut self) -> Result<()> {
        if self.state != WatchdogState::Running {
            return Err(Error::InvalidArgument);
        }
        if self.nowayout && !self.magic_close {
            return Err(Error::PermissionDenied);
        }
        self.state = WatchdogState::Stopped;
        self.magic_close = false;
        Ok(())
    }

    /// Pings (kicks) the watchdog to reset the expiry timer.
    ///
    /// This should be called periodically by the monitoring process
    /// to indicate that the system is still healthy.
    pub fn ping(&mut self, now_ns: u64) {
        if self.state == WatchdogState::Running {
            self.last_ping_ns = now_ns;
            self.expires_ns = now_ns + u64::from(self.info.timeout_secs) * NANOS_PER_SEC;
            self.ping_count += 1;
        }
    }

    /// Sets the watchdog timeout in seconds.
    ///
    /// The value must be within the range
    /// [`min_timeout`](WatchdogInfo::min_timeout)..=
    /// [`max_timeout`](WatchdogInfo::max_timeout).
    ///
    /// Returns [`Error::InvalidArgument`] if out of range.
    pub fn set_timeout(&mut self, secs: u32) -> Result<()> {
        if secs < self.info.min_timeout || secs > self.info.max_timeout {
            return Err(Error::InvalidArgument);
        }
        self.info.timeout_secs = secs;
        Ok(())
    }

    /// Checks whether the watchdog has expired.
    ///
    /// If the current time `now_ns` is at or past the expiry
    /// timestamp and the watchdog is running, the state transitions
    /// to [`WatchdogState::Expired`] and the configured
    /// [`WatchdogAction`] is returned.
    pub fn check_expiry(&mut self, now_ns: u64) -> Option<WatchdogAction> {
        if self.state != WatchdogState::Running {
            return None;
        }
        if now_ns >= self.expires_ns {
            self.state = WatchdogState::Expired;
            Some(self.action)
        } else {
            None
        }
    }

    /// Returns the number of seconds remaining before expiry.
    ///
    /// Returns `0` if the watchdog is not running or has already
    /// expired.
    pub fn time_left(&self, now_ns: u64) -> u64 {
        if self.state != WatchdogState::Running {
            return 0;
        }
        if now_ns >= self.expires_ns {
            return 0;
        }
        (self.expires_ns - now_ns) / NANOS_PER_SEC
    }

    /// Enables or disables the `nowayout` mode.
    ///
    /// When enabled, the watchdog cannot be stopped unless the
    /// magic close character is written first.
    pub fn set_nowayout(&mut self, nowayout: bool) {
        self.nowayout = nowayout;
    }

    /// Scans the given data for the magic close character (`'V'`).
    ///
    /// If found, the internal `magic_close` flag is set, allowing
    /// a subsequent [`stop`](Self::stop) call to succeed even when
    /// `nowayout` is enabled.
    pub fn write_magic(&mut self, data: &[u8]) {
        if data.contains(&MAGIC_CLOSE_CHAR) {
            self.magic_close = true;
        }
    }
}

// -------------------------------------------------------------------
// WatchdogRegistry
// -------------------------------------------------------------------

/// Registry that manages multiple [`WatchdogDevice`] instances.
///
/// Supports up to [`MAX_WATCHDOGS`] concurrently registered devices.
pub struct WatchdogRegistry {
    /// Registered watchdog devices.
    devices: [Option<WatchdogDevice>; MAX_WATCHDOGS],
    /// Number of currently registered devices.
    count: usize,
}

impl Default for WatchdogRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl WatchdogRegistry {
    /// Creates a new, empty watchdog registry.
    pub const fn new() -> Self {
        Self {
            devices: [const { None }; MAX_WATCHDOGS],
            count: 0,
        }
    }

    /// Registers a watchdog device.
    ///
    /// Returns [`Error::OutOfMemory`] if the registry is full, or
    /// [`Error::AlreadyExists`] if a device with the same id is
    /// already registered.
    pub fn register(&mut self, device: WatchdogDevice) -> Result<()> {
        // Check for duplicate id.
        for slot in &self.devices {
            if let Some(ref d) = *slot {
                if d.id == device.id {
                    return Err(Error::AlreadyExists);
                }
            }
        }
        // Find a free slot.
        for slot in &mut self.devices {
            if slot.is_none() {
                *slot = Some(device);
                self.count += 1;
                return Ok(());
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Returns a shared reference to the device with the given
    /// `id`, or [`None`] if not found.
    pub fn get(&self, id: u32) -> Option<&WatchdogDevice> {
        self.devices.iter().flatten().find(|d| d.id == id)
    }

    /// Returns a mutable reference to the device with the given
    /// `id`, or [`None`] if not found.
    pub fn get_mut(&mut self, id: u32) -> Option<&mut WatchdogDevice> {
        self.devices.iter_mut().flatten().find(|d| d.id == id)
    }

    /// Ticks all registered watchdog devices, checking for expiry.
    ///
    /// For each expired watchdog, the configured
    /// [`WatchdogAction`] is collected and returned. The caller is
    /// responsible for executing the appropriate response.
    pub fn tick(&mut self, now_ns: u64) -> [Option<(u32, WatchdogAction)>; MAX_WATCHDOGS] {
        let mut results = [const { None }; MAX_WATCHDOGS];
        for (i, slot) in self.devices.iter_mut().enumerate() {
            if let Some(ref mut dev) = *slot {
                if let Some(action) = dev.check_expiry(now_ns) {
                    results[i] = Some((dev.id, action));
                }
            }
        }
        results
    }

    /// Returns the number of registered watchdog devices.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Returns `true` if no watchdog devices are registered.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
}
