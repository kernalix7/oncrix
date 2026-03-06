// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Hardware watchdog timer driver.
//!
//! Provides a full-featured watchdog subsystem following the Linux watchdog
//! device model (`drivers/watchdog/watchdog_dev.c`). Each registered watchdog
//! exposes start, stop, ping, set_timeout, and pretimeout operations. The
//! `nowayout` mode prevents the watchdog from being stopped once armed.
//!
//! # Architecture
//!
//! - [`WatchdogOps`] — operations table (virtual dispatch via function pointers).
//! - [`WatchdogDevice`] — per-device state: timeout, pretimeout, state, counters.
//! - [`WatchdogDevRegistry`] — manages up to [`MAX_WATCHDOG_DEVS`] devices.
//!
//! # Pretimeout
//!
//! Pretimeout fires a warning (e.g., NMI) a configurable number of seconds
//! before the actual watchdog reset. This allows the OS to generate a crash
//! dump before the hardware resets the system.
//!
//! # Keepalive Daemon
//!
//! The subsystem provides a `tick()` call intended to be invoked from a
//! periodic timer. It pings all running watchdogs that have a keepalive
//! period configured and fires pretimeout notifications for devices approaching
//! expiry.
//!
//! Reference: Linux `drivers/watchdog/watchdog_dev.c`,
//!            `include/linux/watchdog.h`.

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum number of watchdog devices.
pub const MAX_WATCHDOG_DEVS: usize = 8;

/// Default watchdog timeout (seconds).
pub const DEFAULT_TIMEOUT_SECS: u32 = 60;

/// Minimum legal timeout (seconds).
pub const MIN_TIMEOUT_SECS: u32 = 1;

/// Maximum legal timeout (seconds).
pub const MAX_TIMEOUT_SECS: u32 = 86400; // 24 hours

/// Nanoseconds per second.
const NS_PER_SEC: u64 = 1_000_000_000;

/// Magic close character — write before closing to allow stop.
pub const MAGIC_CLOSE: u8 = b'V';

// ---------------------------------------------------------------------------
// WatchdogState
// ---------------------------------------------------------------------------

/// Lifecycle state of a watchdog device.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum WatchdogState {
    /// Watchdog is inactive.
    #[default]
    Inactive,
    /// Watchdog is counting down.
    Active,
    /// Watchdog expired without being pinged.
    Expired,
}

// ---------------------------------------------------------------------------
// WatchdogOps
// ---------------------------------------------------------------------------

/// Operation codes dispatched by the watchdog device driver.
///
/// Hardware-specific implementations map these to register writes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WatchdogOp {
    /// Start the hardware watchdog counter.
    Start,
    /// Stop the hardware watchdog counter.
    Stop,
    /// Reset the hardware counter (keepalive ping).
    Ping,
    /// Program a new timeout value into hardware.
    SetTimeout(u32),
    /// Program the pretimeout value (warning interval).
    SetPretimeout(u32),
}

// ---------------------------------------------------------------------------
// WatchdogInfo
// ---------------------------------------------------------------------------

/// Static information about a watchdog device.
#[derive(Debug, Clone)]
pub struct WatchdogInfo {
    /// Human-readable device name (stored as raw bytes, NUL-terminated convention).
    pub name: [u8; 32],
    /// Number of valid bytes in `name`.
    pub name_len: usize,
    /// Hardware/firmware version.
    pub firmware_version: u32,
    /// Supported capability flags (`WDIOF_*`).
    pub options: u32,
}

impl Default for WatchdogInfo {
    fn default() -> Self {
        Self {
            name: [0u8; 32],
            name_len: 0,
            firmware_version: 0,
            options: 0,
        }
    }
}

impl WatchdogInfo {
    /// Creates a new info with the given name bytes.
    pub fn new(name_bytes: &[u8], firmware_version: u32, options: u32) -> Self {
        let mut name = [0u8; 32];
        let copy_len = name_bytes.len().min(31);
        name[..copy_len].copy_from_slice(&name_bytes[..copy_len]);
        Self {
            name,
            name_len: copy_len,
            firmware_version,
            options,
        }
    }
}

// ---------------------------------------------------------------------------
// WatchdogDevice
// ---------------------------------------------------------------------------

/// A registered hardware watchdog device.
///
/// Tracks all runtime state for one watchdog instance including
/// the current timeout, pretimeout, expiry timestamp, and counters.
#[derive(Debug)]
pub struct WatchdogDevice {
    /// Unique device identifier assigned at registration.
    pub id: u32,
    /// Static device information.
    pub info: WatchdogInfo,
    /// Current lifecycle state.
    pub state: WatchdogState,
    /// Configured timeout in seconds.
    pub timeout_secs: u32,
    /// Pretimeout in seconds (0 = disabled).
    pub pretimeout_secs: u32,
    /// Minimum supported timeout in seconds.
    pub min_timeout: u32,
    /// Maximum supported timeout in seconds.
    pub max_timeout: u32,
    /// Absolute nanosecond timestamp when the watchdog expires.
    pub expires_ns: u64,
    /// Absolute nanosecond timestamp for pretimeout warning.
    pub pretimeout_ns: u64,
    /// Nanosecond timestamp of the last ping.
    pub last_ping_ns: u64,
    /// Total ping count since start.
    pub ping_count: u64,
    /// Total number of times the watchdog was started.
    pub start_count: u64,
    /// If true, cannot stop without magic close handshake.
    pub nowayout: bool,
    /// Set when the magic close character is received.
    pub magic_close_pending: bool,
    /// Keepalive period in nanoseconds (0 = manual ping only).
    pub keepalive_period_ns: u64,
    /// Whether a pretimeout notification has been issued for this cycle.
    pub pretimeout_notified: bool,
    /// Whether the device slot is occupied.
    pub registered: bool,
}

impl WatchdogDevice {
    /// Creates a new watchdog device with sensible defaults.
    pub fn new(id: u32, timeout_secs: u32) -> Self {
        let clamped = timeout_secs.clamp(MIN_TIMEOUT_SECS, MAX_TIMEOUT_SECS);
        Self {
            id,
            info: WatchdogInfo::default(),
            state: WatchdogState::Inactive,
            timeout_secs: clamped,
            pretimeout_secs: 0,
            min_timeout: MIN_TIMEOUT_SECS,
            max_timeout: MAX_TIMEOUT_SECS,
            expires_ns: 0,
            pretimeout_ns: 0,
            last_ping_ns: 0,
            ping_count: 0,
            start_count: 0,
            nowayout: false,
            magic_close_pending: false,
            keepalive_period_ns: 0,
            pretimeout_notified: false,
            registered: true,
        }
    }

    /// Starts the watchdog at the given nanosecond timestamp.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Busy`] if already running.
    pub fn start(&mut self, now_ns: u64) -> Result<()> {
        if self.state == WatchdogState::Active {
            return Err(Error::Busy);
        }
        self.state = WatchdogState::Active;
        self.last_ping_ns = now_ns;
        self.expires_ns = now_ns + u64::from(self.timeout_secs) * NS_PER_SEC;
        self.pretimeout_ns = if self.pretimeout_secs > 0 && self.pretimeout_secs < self.timeout_secs
        {
            self.expires_ns - u64::from(self.pretimeout_secs) * NS_PER_SEC
        } else {
            0
        };
        self.pretimeout_notified = false;
        self.magic_close_pending = false;
        self.start_count += 1;
        Ok(())
    }

    /// Stops the watchdog.
    ///
    /// Requires either `nowayout == false` or `magic_close_pending == true`.
    ///
    /// # Errors
    ///
    /// - [`Error::PermissionDenied`] if `nowayout` is set and magic close was not received.
    /// - [`Error::InvalidArgument`] if the watchdog is not running.
    pub fn stop(&mut self) -> Result<()> {
        if self.state != WatchdogState::Active {
            return Err(Error::InvalidArgument);
        }
        if self.nowayout && !self.magic_close_pending {
            return Err(Error::PermissionDenied);
        }
        self.state = WatchdogState::Inactive;
        self.magic_close_pending = false;
        Ok(())
    }

    /// Pings (kicks) the watchdog to reset the countdown.
    pub fn ping(&mut self, now_ns: u64) {
        if self.state == WatchdogState::Active {
            self.last_ping_ns = now_ns;
            self.expires_ns = now_ns + u64::from(self.timeout_secs) * NS_PER_SEC;
            if self.pretimeout_secs > 0 {
                self.pretimeout_ns = self.expires_ns - u64::from(self.pretimeout_secs) * NS_PER_SEC;
            }
            self.pretimeout_notified = false;
            self.ping_count += 1;
        }
    }

    /// Sets the watchdog timeout.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `secs` is out of the device's range.
    pub fn set_timeout(&mut self, secs: u32) -> Result<()> {
        if secs < self.min_timeout || secs > self.max_timeout {
            return Err(Error::InvalidArgument);
        }
        self.timeout_secs = secs;
        Ok(())
    }

    /// Sets the pretimeout warning interval.
    ///
    /// `secs` must be strictly less than the current timeout and greater than zero.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if the pretimeout is not strictly less
    /// than the current timeout.
    pub fn set_pretimeout(&mut self, secs: u32) -> Result<()> {
        if secs >= self.timeout_secs {
            return Err(Error::InvalidArgument);
        }
        self.pretimeout_secs = secs;
        Ok(())
    }

    /// Enables or disables `nowayout` mode.
    pub fn set_nowayout(&mut self, nowayout: bool) {
        self.nowayout = nowayout;
    }

    /// Configures the automatic keepalive period.
    ///
    /// When `period_ns > 0`, the subsystem's `tick()` call will auto-ping this
    /// watchdog whenever `now_ns - last_ping_ns >= period_ns`.
    pub fn set_keepalive_period(&mut self, period_ns: u64) {
        self.keepalive_period_ns = period_ns;
    }

    /// Records the magic close character from a write buffer.
    ///
    /// If any byte in `data` equals [`MAGIC_CLOSE`], sets the `magic_close_pending`
    /// flag allowing a subsequent `stop()` to succeed even with `nowayout`.
    pub fn write_magic(&mut self, data: &[u8]) {
        if data.contains(&MAGIC_CLOSE) {
            self.magic_close_pending = true;
        }
    }

    /// Returns the seconds remaining before expiry, or 0 if inactive.
    pub fn time_left_secs(&self, now_ns: u64) -> u32 {
        if self.state != WatchdogState::Active || now_ns >= self.expires_ns {
            return 0;
        }
        ((self.expires_ns - now_ns) / NS_PER_SEC) as u32
    }

    /// Checks expiry and pretimeout at `now_ns`.
    ///
    /// Returns `Some(WatchdogEvent)` if something noteworthy occurred.
    pub fn check(&mut self, now_ns: u64) -> Option<WatchdogEvent> {
        if self.state != WatchdogState::Active {
            return None;
        }
        if now_ns >= self.expires_ns {
            self.state = WatchdogState::Expired;
            return Some(WatchdogEvent::Expired(self.id));
        }
        if self.pretimeout_ns != 0 && now_ns >= self.pretimeout_ns && !self.pretimeout_notified {
            self.pretimeout_notified = true;
            return Some(WatchdogEvent::Pretimeout(self.id));
        }
        if self.keepalive_period_ns > 0 && (now_ns - self.last_ping_ns) >= self.keepalive_period_ns
        {
            self.ping(now_ns);
            return Some(WatchdogEvent::Keepalive(self.id));
        }
        None
    }
}

// ---------------------------------------------------------------------------
// WatchdogEvent
// ---------------------------------------------------------------------------

/// Events emitted by [`WatchdogDevRegistry::tick`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WatchdogEvent {
    /// The watchdog timed out — hardware reset imminent.
    Expired(u32),
    /// Pretimeout warning fired for the given device ID.
    Pretimeout(u32),
    /// The subsystem auto-pinged the device.
    Keepalive(u32),
}

// ---------------------------------------------------------------------------
// WatchdogDevRegistry
// ---------------------------------------------------------------------------

/// Registry managing all registered watchdog devices.
pub struct WatchdogDevRegistry {
    devices: [Option<WatchdogDevice>; MAX_WATCHDOG_DEVS],
    count: usize,
    next_id: u32,
}

impl WatchdogDevRegistry {
    /// Creates an empty registry.
    pub const fn new() -> Self {
        Self {
            devices: [const { None }; MAX_WATCHDOG_DEVS],
            count: 0,
            next_id: 1,
        }
    }

    /// Registers a watchdog device, returning its assigned ID.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the registry is full.
    pub fn register(&mut self, mut device: WatchdogDevice) -> Result<u32> {
        if self.count >= MAX_WATCHDOG_DEVS {
            return Err(Error::OutOfMemory);
        }
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);
        device.id = id;
        let idx = self
            .devices
            .iter()
            .position(|s| s.is_none())
            .ok_or(Error::OutOfMemory)?;
        self.devices[idx] = Some(device);
        self.count += 1;
        Ok(id)
    }

    /// Unregisters and returns the device with the given ID.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if no device with that ID exists.
    pub fn unregister(&mut self, id: u32) -> Result<WatchdogDevice> {
        let idx = self.device_idx(id)?;
        let device = self.devices[idx].take().ok_or(Error::NotFound)?;
        self.count -= 1;
        Ok(device)
    }

    /// Returns a shared reference to the device with the given ID.
    pub fn get(&self, id: u32) -> Option<&WatchdogDevice> {
        self.devices.iter().flatten().find(|d| d.id == id)
    }

    /// Returns a mutable reference to the device with the given ID.
    pub fn get_mut(&mut self, id: u32) -> Option<&mut WatchdogDevice> {
        self.devices.iter_mut().flatten().find(|d| d.id == id)
    }

    /// Ticks all registered watchdog devices at `now_ns`.
    ///
    /// Collects events from each device. Returns up to [`MAX_WATCHDOG_DEVS`]
    /// events; entries beyond the first `n` valid ones are `None`.
    pub fn tick(&mut self, now_ns: u64) -> [Option<WatchdogEvent>; MAX_WATCHDOG_DEVS] {
        let mut events = [const { None }; MAX_WATCHDOG_DEVS];
        for (i, slot) in self.devices.iter_mut().enumerate() {
            if let Some(dev) = slot {
                events[i] = dev.check(now_ns);
            }
        }
        events
    }

    /// Returns the number of registered devices.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Returns `true` if no devices are registered.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    // ── Internal helpers ──────────────────────────────────────────────────────

    fn device_idx(&self, id: u32) -> Result<usize> {
        self.devices
            .iter()
            .position(|s| matches!(s, Some(d) if d.id == id))
            .ok_or(Error::NotFound)
    }
}

impl Default for WatchdogDevRegistry {
    fn default() -> Self {
        Self::new()
    }
}
