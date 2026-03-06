// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! timerfd timer notification subsystem.
//!
//! Provides a file-descriptor-based timer mechanism compatible with
//! the Linux `timerfd` API. A [`TimerFd`] delivers timer expiration
//! notifications via a readable file descriptor, allowing timers to
//! be monitored with `poll`, `select`, or `epoll`.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────┐
//! │              TimerFdRegistry                 │
//! │  (up to MAX_TIMERFDS timerfd instances)      │
//! │  ┌────────┐ ┌────────┐       ┌────────┐    │
//! │  │ tfd 0  │ │ tfd 1  │  ...  │ tfd N  │    │
//! │  └────────┘ └────────┘       └────────┘    │
//! └─────────────────────────────────────────────┘
//! ```
//!
//! # Tick-based operation
//!
//! Timer expirations are driven by [`TimerFd::tick`], which must
//! be called on each hardware timer tick. When the current tick
//! reaches the expiration tick, the timer's `expired_count` is
//! incremented. If an interval is set, the timer is automatically
//! re-armed for the next period.
//!
//! # POSIX Reference
//!
//! While timerfd is a Linux extension (not POSIX), ONCRIX provides
//! it for compatibility with event-loop frameworks (libuv, libev,
//! systemd, tokio, etc.) that rely on timer file descriptors.

use oncrix_lib::{Error, Result};

// ── Constants ────────────────────────────────────────────────────

/// Non-blocking mode: `read` returns `WouldBlock` (`EAGAIN`)
/// instead of blocking when no timer expirations have occurred.
pub const TFD_NONBLOCK: u32 = 0x800;

/// Close-on-exec flag: the file descriptor is automatically
/// closed across `execve`.
pub const TFD_CLOEXEC: u32 = 0x80000;

/// Bitmask of all valid timerfd creation flags.
const TFD_VALID_FLAGS: u32 = TFD_NONBLOCK | TFD_CLOEXEC;

/// Interpret `new_value.it_value` as an absolute time on the
/// timer's clock rather than a relative duration.
pub const TFD_TIMER_ABSTIME: u32 = 1;

/// Number of nanoseconds per tick.
///
/// Assumes a 1 kHz tick rate (1 ms per tick). This must match
/// the `TimerWheel::ns_per_tick` configuration.
const NS_PER_TICK: u64 = 1_000_000;

// ── Timespec / ItimerSpec ────────────────────────────────────────

/// POSIX `struct timespec` for timerfd intervals and values.
///
/// Compatible with the `Timespec` in `crate::timer`, but defined
/// locally so this module is self-contained for the timerfd ABI.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct Timespec {
    /// Seconds.
    pub tv_sec: i64,
    /// Nanoseconds (0..999_999_999).
    pub tv_nsec: i64,
}

impl Timespec {
    /// A zero timespec (disarmed / no time remaining).
    pub const ZERO: Self = Self {
        tv_sec: 0,
        tv_nsec: 0,
    };

    /// Convert to total nanoseconds.
    ///
    /// Returns `None` if the values are negative or if
    /// `tv_nsec` is out of range.
    pub fn to_ns(&self) -> Option<u64> {
        if self.tv_sec < 0 || self.tv_nsec < 0 || self.tv_nsec >= 1_000_000_000 {
            return None;
        }
        let secs_ns = (self.tv_sec as u64).checked_mul(1_000_000_000)?;
        secs_ns.checked_add(self.tv_nsec as u64)
    }

    /// Create a `Timespec` from a nanosecond count.
    pub const fn from_ns(ns: u64) -> Self {
        Self {
            tv_sec: (ns / 1_000_000_000) as i64,
            tv_nsec: (ns % 1_000_000_000) as i64,
        }
    }
}

/// Interval timer specification, equivalent to `struct itimerspec`.
///
/// Used by [`TimerFd::settime`] and [`TimerFd::gettime`] to
/// configure and query timer parameters.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct ItimerSpec {
    /// Interval for periodic timers. If both fields are zero the
    /// timer fires only once (one-shot mode).
    pub it_interval: Timespec,
    /// Initial expiration time. If both fields are zero the timer
    /// is disarmed.
    pub it_value: Timespec,
}

impl ItimerSpec {
    /// A zeroed itimerspec (disarmed timer, no interval).
    pub const ZERO: Self = Self {
        it_interval: Timespec::ZERO,
        it_value: Timespec::ZERO,
    };
}

// ── TimerFd ─────────────────────────────────────────────────────

/// A timerfd instance that delivers timer expirations via a
/// readable file descriptor.
///
/// Created via [`TimerFd::new`] with a clock ID and flags.
/// The timer is armed/disarmed via [`settime`](TimerFd::settime)
/// and expiration info is consumed via [`read`](TimerFd::read).
pub struct TimerFd {
    /// POSIX clock ID (`CLOCK_REALTIME` = 0,
    /// `CLOCK_MONOTONIC` = 1).
    clock_id: u32,
    /// Creation flags (combination of `TFD_*` constants).
    flags: u32,
    /// Absolute tick at which the timer next expires.
    expiration_tick: u64,
    /// Interval in ticks for periodic re-arming (0 = one-shot).
    interval_tick: u64,
    /// Number of expirations since the last `read`.
    expired_count: u64,
    /// Whether the timer is currently armed.
    armed: bool,
    /// Whether this slot is in use in the registry.
    in_use: bool,
}

impl TimerFd {
    /// Create a new timerfd with the given clock ID and flags.
    ///
    /// The timer is created in the disarmed state. Call
    /// [`settime`](TimerFd::settime) to arm it.
    pub const fn new(clock_id: u32, flags: u32) -> Self {
        Self {
            clock_id,
            flags,
            expiration_tick: 0,
            interval_tick: 0,
            expired_count: 0,
            armed: false,
            in_use: false,
        }
    }

    /// Return the clock ID.
    pub const fn clock_id(&self) -> u32 {
        self.clock_id
    }

    /// Return the current flags.
    pub const fn flags(&self) -> u32 {
        self.flags
    }

    /// Whether this timerfd is in non-blocking mode.
    const fn is_nonblock(&self) -> bool {
        self.flags & TFD_NONBLOCK != 0
    }

    /// Whether the timer is currently armed.
    pub const fn is_armed(&self) -> bool {
        self.armed
    }

    /// Return the number of unread expirations.
    pub const fn expired_count(&self) -> u64 {
        self.expired_count
    }

    /// Arm or disarm the timer.
    ///
    /// If `new_value.it_value` is non-zero the timer is armed:
    /// - With `TFD_TIMER_ABSTIME` in `flags`, `it_value` is
    ///   treated as an absolute tick on the timer's clock.
    /// - Otherwise, `it_value` is a relative duration in
    ///   nanoseconds from the current tick.
    ///
    /// If `new_value.it_value` is zero the timer is disarmed.
    ///
    /// Returns the previous timer setting.
    pub fn settime(
        &mut self,
        flags: u32,
        new_value: &ItimerSpec,
        current_tick: u64,
    ) -> Result<ItimerSpec> {
        // Capture the old value before modifying.
        let old = self.gettime(current_tick);

        // Compute the new interval in ticks.
        let interval_ns = new_value
            .it_interval
            .to_ns()
            .ok_or(Error::InvalidArgument)?;
        self.interval_tick = ns_to_ticks(interval_ns);

        // Compute the new expiration.
        let value_ns = new_value.it_value.to_ns().ok_or(Error::InvalidArgument)?;

        if value_ns == 0 {
            // Disarm the timer.
            self.armed = false;
            self.expiration_tick = 0;
            self.expired_count = 0;
        } else if flags & TFD_TIMER_ABSTIME != 0 {
            // Absolute time: convert ns to ticks directly.
            self.expiration_tick = ns_to_ticks(value_ns);
            self.armed = true;
            self.expired_count = 0;
        } else {
            // Relative time: add to current tick.
            let delta_ticks = ns_to_ticks(value_ns);
            self.expiration_tick = current_tick.saturating_add(delta_ticks);
            self.armed = true;
            self.expired_count = 0;
        }

        Ok(old)
    }

    /// Return the current timer setting.
    ///
    /// The returned `it_value` contains the remaining time until
    /// the next expiration (as a relative duration), or zero if
    /// the timer is disarmed. The returned `it_interval` contains
    /// the interval setting.
    pub fn gettime(&self, current_tick: u64) -> ItimerSpec {
        if !self.armed {
            return ItimerSpec::ZERO;
        }

        let remaining_ticks = self.expiration_tick.saturating_sub(current_tick);
        let remaining_ns = ticks_to_ns(remaining_ticks);
        let interval_ns = ticks_to_ns(self.interval_tick);

        ItimerSpec {
            it_interval: Timespec::from_ns(interval_ns),
            it_value: Timespec::from_ns(remaining_ns),
        }
    }

    /// Consume the expiration count.
    ///
    /// Returns the number of timer expirations since the last
    /// `read` (or since the timer was armed). Resets the counter
    /// to zero.
    ///
    /// If no expirations have occurred and the timerfd is in
    /// non-blocking mode, returns `Err(WouldBlock)`. In blocking
    /// mode, the caller should block until an expiration occurs
    /// (not handled here -- requires scheduler integration).
    pub fn read(&mut self) -> Result<u64> {
        if self.expired_count == 0 {
            return Err(if self.is_nonblock() {
                Error::WouldBlock
            } else {
                // Blocking mode: caller must block and retry.
                Error::WouldBlock
            });
        }

        let count = self.expired_count;
        self.expired_count = 0;
        Ok(count)
    }

    /// Advance the timer by one tick.
    ///
    /// Must be called on every hardware timer tick. If the
    /// current tick has reached or passed the expiration tick,
    /// the `expired_count` is incremented. For periodic timers
    /// the expiration is automatically advanced by the interval.
    pub fn tick(&mut self, current_tick: u64) {
        if !self.armed {
            return;
        }

        if current_tick < self.expiration_tick {
            return;
        }

        // Timer has expired at least once.
        if self.interval_tick == 0 {
            // One-shot: fire once, disarm.
            self.expired_count = self.expired_count.saturating_add(1);
            self.armed = false;
        } else {
            // Periodic: count how many intervals have elapsed
            // and re-arm for the next one.
            let elapsed = current_tick.saturating_sub(self.expiration_tick);
            let missed = elapsed.checked_div(self.interval_tick).unwrap_or(0);
            let fires = missed.saturating_add(1);
            self.expired_count = self.expired_count.saturating_add(fires);
            self.expiration_tick = self
                .expiration_tick
                .saturating_add(fires.saturating_mul(self.interval_tick));
        }
    }
}

// ── TimerFdRegistry ──────────────────────────────────────────────

/// Maximum number of concurrent timerfd instances system-wide.
const MAX_TIMERFDS: usize = 64;

/// Global registry of timerfd instances.
///
/// Manages the creation, lookup, and destruction of [`TimerFd`]
/// objects. Each instance is identified by a numeric ID returned
/// by [`create`](TimerFdRegistry::create).
pub struct TimerFdRegistry {
    /// Fixed array of timerfd slots.
    fds: [TimerFd; MAX_TIMERFDS],
}

impl Default for TimerFdRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl TimerFdRegistry {
    /// Create an empty registry with no active timerfds.
    pub const fn new() -> Self {
        Self {
            fds: [const { TimerFd::new(0, 0) }; MAX_TIMERFDS],
        }
    }

    /// Allocate a new timerfd instance.
    ///
    /// Returns the instance ID on success, or `Err(OutOfMemory)`
    /// if all slots are occupied. Returns `Err(InvalidArgument)`
    /// if `flags` contains unknown bits or `clock_id` is invalid.
    pub fn create(&mut self, clock_id: u32, flags: u32) -> Result<usize> {
        if flags & !TFD_VALID_FLAGS != 0 {
            return Err(Error::InvalidArgument);
        }
        // Only CLOCK_REALTIME (0) and CLOCK_MONOTONIC (1).
        if clock_id > 1 {
            return Err(Error::InvalidArgument);
        }
        for (id, tfd) in self.fds.iter_mut().enumerate() {
            if !tfd.in_use {
                *tfd = TimerFd::new(clock_id, flags);
                tfd.in_use = true;
                return Ok(id);
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Get a shared reference to a timerfd by ID.
    ///
    /// Returns `Err(InvalidArgument)` if the ID is out of range,
    /// or `Err(NotFound)` if the slot is not in use.
    pub fn get(&self, id: usize) -> Result<&TimerFd> {
        let tfd = self.fds.get(id).ok_or(Error::InvalidArgument)?;
        if !tfd.in_use {
            return Err(Error::NotFound);
        }
        Ok(tfd)
    }

    /// Get a mutable reference to a timerfd by ID.
    ///
    /// Returns `Err(InvalidArgument)` if the ID is out of range,
    /// or `Err(NotFound)` if the slot is not in use.
    pub fn get_mut(&mut self, id: usize) -> Result<&mut TimerFd> {
        let tfd = self.fds.get_mut(id).ok_or(Error::InvalidArgument)?;
        if !tfd.in_use {
            return Err(Error::NotFound);
        }
        Ok(tfd)
    }

    /// Destroy a timerfd instance, freeing its slot.
    ///
    /// Returns `Err(InvalidArgument)` if the ID is out of range,
    /// or `Err(NotFound)` if the slot is not in use.
    pub fn close(&mut self, id: usize) -> Result<()> {
        let tfd = self.fds.get_mut(id).ok_or(Error::InvalidArgument)?;
        if !tfd.in_use {
            return Err(Error::NotFound);
        }
        *tfd = TimerFd::new(0, 0);
        Ok(())
    }

    /// Advance all active timerfds by one tick.
    ///
    /// Must be called on every hardware timer tick so that armed
    /// timers can detect their expirations.
    pub fn tick_all(&mut self, current_tick: u64) {
        for tfd in &mut self.fds {
            if tfd.in_use {
                tfd.tick(current_tick);
            }
        }
    }
}

// ── Helper functions ─────────────────────────────────────────────

/// Convert nanoseconds to ticks, rounding up.
const fn ns_to_ticks(ns: u64) -> u64 {
    // Ceiling division: (ns + NS_PER_TICK - 1) / NS_PER_TICK
    ns.saturating_add(NS_PER_TICK - 1) / NS_PER_TICK
}

/// Convert ticks to nanoseconds.
const fn ticks_to_ns(ticks: u64) -> u64 {
    ticks.saturating_mul(NS_PER_TICK)
}
