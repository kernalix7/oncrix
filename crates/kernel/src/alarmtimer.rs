// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Alarm timer — RTC-backed wakeup timers.
//!
//! Implements the alarm timer subsystem which provides POSIX CLOCK_REALTIME_ALARM
//! and CLOCK_BOOTTIME_ALARM timer semantics. Alarm timers are backed by the
//! RTC (Real-Time Clock) device and can wake the system from suspend states.
//!
//! Alarm timers sit above the generic `hrtimer` infrastructure and add the
//! suspend-wakeup capability. The `AlarmBase` manages a sorted queue of
//! `Alarm` entries; on expiry, callbacks are invoked and — if the system
//! was suspended — it is resumed.

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use oncrix_lib::{Error, Result};

extern crate alloc;

/// Clock IDs supported by the alarm timer subsystem.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlarmClock {
    /// CLOCK_REALTIME_ALARM — wall-clock time, wakes from suspend.
    RealtimeAlarm,
    /// CLOCK_BOOTTIME_ALARM — time since boot, wakes from suspend.
    BoottimeAlarm,
}

impl AlarmClock {
    /// Returns true if this clock ticks during suspend.
    pub fn ticks_during_suspend(self) -> bool {
        match self {
            AlarmClock::BoottimeAlarm => true,
            AlarmClock::RealtimeAlarm => true,
        }
    }
}

/// Nanosecond-resolution timestamp used by alarm timers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
pub struct Ktime(pub i64);

impl Ktime {
    /// Creates a Ktime from a nanoseconds value.
    pub const fn from_ns(ns: i64) -> Self {
        Self(ns)
    }

    /// Returns the raw nanosecond value.
    pub fn as_ns(self) -> i64 {
        self.0
    }

    /// Adds a duration in nanoseconds.
    pub fn add_ns(self, ns: i64) -> Self {
        Self(self.0.saturating_add(ns))
    }

    /// Checks whether this time has passed relative to `now`.
    pub fn has_expired(self, now: Ktime) -> bool {
        self.0 <= now.0
    }
}

/// State of an alarm timer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlarmState {
    /// Timer is inactive (not scheduled).
    Inactive,
    /// Timer is scheduled and pending.
    Enqueued,
    /// Timer callback is currently executing.
    Firing,
    /// Timer has fired and is awaiting restart.
    Fired,
}

/// Callback function type for alarm timers.
///
/// Returns a `Ktime` for rearming (0 = one-shot, positive = rearm interval).
pub type AlarmFn = fn(alarm: &Alarm) -> Ktime;

/// A single alarm timer instance.
pub struct Alarm {
    /// Which clock backs this alarm.
    pub clock: AlarmClock,
    /// Absolute expiry time.
    pub node: Ktime,
    /// Softirq expiry time (set when the underlying hrtimer fires).
    pub softexpires: Ktime,
    /// Current state of this alarm.
    pub state: AlarmState,
    /// The callback to invoke on expiry.
    pub function: AlarmFn,
    /// Whether this alarm can wake the system from suspend.
    pub wake_on_expire: bool,
}

impl Alarm {
    /// Creates a new, inactive alarm timer.
    pub fn new(clock: AlarmClock, function: AlarmFn) -> Self {
        Self {
            clock,
            node: Ktime(0),
            softexpires: Ktime(0),
            state: AlarmState::Inactive,
            function,
            wake_on_expire: true,
        }
    }

    /// Returns true if the alarm is currently scheduled.
    pub fn is_active(&self) -> bool {
        self.state == AlarmState::Enqueued || self.state == AlarmState::Firing
    }

    /// Arms the alarm to fire at `expiry` (absolute clock time).
    ///
    /// The `softexpires` may be earlier than `expiry`; the alarm fires
    /// anywhere in [softexpires, expiry].
    pub fn start(&mut self, expiry: Ktime, softexpires: Ktime) -> Result<()> {
        if expiry.0 < softexpires.0 {
            return Err(Error::InvalidArgument);
        }
        self.node = expiry;
        self.softexpires = softexpires;
        self.state = AlarmState::Enqueued;
        Ok(())
    }

    /// Arms the alarm for a one-shot expiry (softexpires = expiry).
    pub fn start_oneshot(&mut self, expiry: Ktime) -> Result<()> {
        self.start(expiry, expiry)
    }

    /// Cancels the alarm if it is pending.
    ///
    /// Returns true if the alarm was successfully cancelled before it fired.
    pub fn cancel(&mut self) -> bool {
        match self.state {
            AlarmState::Enqueued => {
                self.state = AlarmState::Inactive;
                true
            }
            _ => false,
        }
    }

    /// Returns the expiry time.
    pub fn expires(&self) -> Ktime {
        self.node
    }

    /// Returns the soft expiry time.
    pub fn soft_expires(&self) -> Ktime {
        self.softexpires
    }

    /// Runs the callback, returning the rearm interval.
    pub fn fire(&mut self) -> Ktime {
        self.state = AlarmState::Firing;
        let rearm = (self.function)(self);
        self.state = if rearm.0 > 0 {
            AlarmState::Enqueued
        } else {
            AlarmState::Fired
        };
        rearm
    }
}

/// RTC wakeup source descriptor.
///
/// Describes the hardware RTC that backs the alarm timer subsystem.
pub struct RtcWakeup {
    /// Name of the RTC device (e.g., "rtc0").
    pub name: &'static str,
    /// Whether the RTC supports wakeup from suspend.
    pub supports_wakeup: bool,
    /// Whether the RTC is currently armed as a wakeup source.
    armed: AtomicBool,
    /// The absolute real-time second at which the RTC will fire.
    wakeup_time_secs: AtomicU64,
}

impl RtcWakeup {
    /// Creates a new RTC wakeup source descriptor.
    pub const fn new(name: &'static str, supports_wakeup: bool) -> Self {
        Self {
            name,
            supports_wakeup,
            armed: AtomicBool::new(false),
            wakeup_time_secs: AtomicU64::new(0),
        }
    }

    /// Returns true if the RTC is currently armed as a wakeup source.
    pub fn is_armed(&self) -> bool {
        self.armed.load(Ordering::Acquire)
    }

    /// Arms the RTC to wake up at `secs` (Unix epoch seconds).
    pub fn arm(&self, secs: u64) -> Result<()> {
        if !self.supports_wakeup {
            return Err(Error::NotImplemented);
        }
        self.wakeup_time_secs.store(secs, Ordering::Release);
        self.armed.store(true, Ordering::Release);
        Ok(())
    }

    /// Disarms the RTC wakeup source.
    pub fn disarm(&self) {
        self.armed.store(false, Ordering::Release);
        self.wakeup_time_secs.store(0, Ordering::Release);
    }

    /// Returns the programmed wakeup time in seconds, or 0 if disarmed.
    pub fn wakeup_time(&self) -> u64 {
        self.wakeup_time_secs.load(Ordering::Acquire)
    }
}

impl Default for RtcWakeup {
    fn default() -> Self {
        Self::new("rtc0", false)
    }
}

/// Configuration for the alarm timer subsystem.
#[derive(Debug, Clone, Copy)]
pub struct AlarmTimerConfig {
    /// Nanoseconds of slack allowed when grouping alarm timers.
    pub slack_ns: u64,
    /// Whether to use the RTC for suspend wakeup.
    pub use_rtc_wakeup: bool,
}

impl AlarmTimerConfig {
    /// Creates the default alarm timer configuration.
    pub const fn new() -> Self {
        Self {
            slack_ns: 1_000_000, // 1 ms slack
            use_rtc_wakeup: true,
        }
    }
}

impl Default for AlarmTimerConfig {
    fn default() -> Self {
        Self::new()
    }
}

/// Alarm base — per-CPU state for the alarm timer subsystem.
///
/// In a full implementation this would hold a timerqueue (sorted rb-tree)
/// of pending alarms and the hrtimer used to drive them. Here we track
/// counts and the nearest expiry.
pub struct AlarmBase {
    /// Which clock this base manages.
    pub clock: AlarmClock,
    /// Nanoseconds of the earliest alarm in this base.
    pub next_expires_ns: i64,
    /// Number of alarms currently queued.
    pub pending_count: u32,
    /// Total alarms that have fired from this base.
    pub fired_count: u64,
    /// Total alarms cancelled from this base.
    pub cancelled_count: u64,
}

impl AlarmBase {
    /// Creates a new alarm base for the given clock.
    pub const fn new(clock: AlarmClock) -> Self {
        Self {
            clock,
            next_expires_ns: i64::MAX,
            pending_count: 0,
            fired_count: 0,
            cancelled_count: 0,
        }
    }

    /// Updates the nearest expiry after inserting an alarm.
    pub fn update_next_expires(&mut self, alarm_expires_ns: i64) {
        if alarm_expires_ns < self.next_expires_ns {
            self.next_expires_ns = alarm_expires_ns;
        }
    }

    /// Records an alarm being added.
    pub fn on_enqueue(&mut self, expires_ns: i64) {
        self.pending_count += 1;
        self.update_next_expires(expires_ns);
    }

    /// Records an alarm firing.
    pub fn on_fire(&mut self) {
        if self.pending_count > 0 {
            self.pending_count -= 1;
        }
        self.fired_count += 1;
    }

    /// Records an alarm being cancelled.
    pub fn on_cancel(&mut self) {
        if self.pending_count > 0 {
            self.pending_count -= 1;
        }
        self.cancelled_count += 1;
    }

    /// Returns true if there are pending alarms in this base.
    pub fn has_pending(&self) -> bool {
        self.pending_count > 0
    }

    /// Returns the nanosecond timestamp of the nearest alarm (i64::MAX if none).
    pub fn next_expires(&self) -> Ktime {
        Ktime(self.next_expires_ns)
    }
}

impl Default for AlarmBase {
    fn default() -> Self {
        Self::new(AlarmClock::RealtimeAlarm)
    }
}

/// Suspend state passed to alarm timer callbacks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SuspendState {
    /// System is resuming from suspend.
    Resuming,
    /// System is about to enter suspend.
    Suspending,
}

/// Alarm timer event used for suspend/resume notifications.
#[derive(Debug, Clone, Copy)]
pub struct AlarmTimerEvent {
    /// The suspend state transition.
    pub state: SuspendState,
    /// The current boottime in nanoseconds.
    pub boottime_ns: i64,
    /// The current realtime in nanoseconds.
    pub realtime_ns: i64,
}

impl AlarmTimerEvent {
    /// Creates a new alarm timer event.
    pub const fn new(state: SuspendState, boottime_ns: i64, realtime_ns: i64) -> Self {
        Self {
            state,
            boottime_ns,
            realtime_ns,
        }
    }
}

/// Returns true if `clock` is an alarm-capable (wakeup) clock.
pub fn is_alarm_clock(clock_id: u32) -> bool {
    // POSIX CLOCK_REALTIME_ALARM = 8, CLOCK_BOOTTIME_ALARM = 9
    clock_id == 8 || clock_id == 9
}

/// Maps a POSIX clock ID to the `AlarmClock` variant.
pub fn clock_id_to_alarm_clock(clock_id: u32) -> Result<AlarmClock> {
    match clock_id {
        8 => Ok(AlarmClock::RealtimeAlarm),
        9 => Ok(AlarmClock::BoottimeAlarm),
        _ => Err(Error::InvalidArgument),
    }
}
