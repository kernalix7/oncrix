// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! POSIX per-process interval timers.
//!
//! Implements `timer_create`, `timer_settime`, `timer_gettime`,
//! `timer_delete`, and `timer_getoverrun` as specified by
//! POSIX.1-2024 (IEEE Std 1003.1-2024).
//!
//! # Architecture
//!
//! ```text
//! ┌──────────────────────────────────────────────┐
//! │           PosixTimerRegistry                  │
//! │  (up to MAX_TOTAL_TIMERS timer instances)     │
//! │  ┌────────┐ ┌────────┐       ┌────────┐     │
//! │  │ tmr 0  │ │ tmr 1  │  ...  │ tmr N  │     │
//! │  └────────┘ └────────┘       └────────┘     │
//! └──────────────────────────────────────────────┘
//! ```
//!
//! Each timer is owned by a process (identified by PID) and can
//! deliver expiration notifications via signals or thread
//! callbacks. The [`PosixTimerRegistry::tick`] method must be
//! called on each hardware timer tick to check for expirations.

use oncrix_lib::{Error, Result};

// ── Constants ────────────────────────────────────────────────

/// Maximum number of POSIX timers a single process may create.
pub const MAX_TIMERS_PER_PROCESS: usize = 32;

/// Maximum number of POSIX timers system-wide.
pub const MAX_TOTAL_TIMERS: usize = 256;

/// Signal event notification: no notification on expiration.
pub const _SIGEV_NONE: i32 = 0;

/// Signal event notification: deliver a signal on expiration.
pub const _SIGEV_SIGNAL: i32 = 1;

/// Signal event notification: invoke a function in a new
/// thread on expiration.
pub const _SIGEV_THREAD: i32 = 2;

/// Signal event notification: deliver a signal to a specific
/// thread on expiration.
pub const _SIGEV_THREAD_ID: i32 = 3;

/// Flag for `timer_settime`: interpret the new timer value as
/// an absolute time on the timer's clock.
pub const TIMER_ABSTIME: i32 = 1;

/// Number of nanoseconds in one second.
const _NANOS_PER_SEC: u64 = 1_000_000_000;

// ── Timespec ─────────────────────────────────────────────────

/// POSIX `struct timespec` for timer intervals and values.
///
/// Represents a point in time or a duration with nanosecond
/// precision. Fields follow the C ABI layout.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[repr(C)]
pub struct Timespec {
    /// Seconds component.
    pub tv_sec: i64,
    /// Nanoseconds component (0..999_999_999).
    pub tv_nsec: i64,
}

impl Timespec {
    /// Create a new `Timespec` with the given seconds and
    /// nanoseconds.
    pub const fn new(tv_sec: i64, tv_nsec: i64) -> Self {
        Self { tv_sec, tv_nsec }
    }

    /// Returns `true` if the timespec is valid.
    ///
    /// A timespec is valid when both fields are non-negative
    /// and `tv_nsec` is less than 1 billion.
    pub const fn is_valid(&self) -> bool {
        self.tv_sec >= 0 && self.tv_nsec >= 0 && self.tv_nsec < 1_000_000_000
    }

    /// Convert to total nanoseconds.
    ///
    /// Returns `None` if the timespec is invalid or on
    /// arithmetic overflow.
    pub fn to_nanos(&self) -> Option<u64> {
        if !self.is_valid() {
            return None;
        }
        let secs_ns = (self.tv_sec as u64).checked_mul(1_000_000_000)?;
        secs_ns.checked_add(self.tv_nsec as u64)
    }

    /// Create a `Timespec` from a nanosecond count.
    pub const fn from_nanos(ns: u64) -> Self {
        Self {
            tv_sec: (ns / 1_000_000_000) as i64,
            tv_nsec: (ns % 1_000_000_000) as i64,
        }
    }

    /// Returns `true` if both fields are zero.
    const fn is_zero(&self) -> bool {
        self.tv_sec == 0 && self.tv_nsec == 0
    }
}

// ── Itimerspec ───────────────────────────────────────────────

/// Interval timer specification (`struct itimerspec`).
///
/// Used by [`PosixTimerRegistry::timer_settime`] and
/// [`PosixTimerRegistry::timer_gettime`] to configure and
/// query timer parameters.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[repr(C)]
pub struct Itimerspec {
    /// Interval for periodic timers. Zero means one-shot.
    pub it_interval: Timespec,
    /// Initial expiration time. Zero means disarmed.
    pub it_value: Timespec,
}

// ── SigEvent ─────────────────────────────────────────────────

/// Signal event specification for timer expiration
/// notification.
///
/// Determines how the process is notified when its timer
/// expires: via a signal, a thread callback, or not at all.
#[derive(Debug, Clone, Copy, Default)]
pub struct SigEvent {
    /// Notification method (`SIGEV_*` constant).
    pub notify: i32,
    /// Signal number (for `SIGEV_SIGNAL` / `SIGEV_THREAD_ID`).
    pub signo: i32,
    /// User-defined value passed with the notification.
    pub value: u64,
    /// Target thread ID (for `SIGEV_THREAD_ID`).
    pub tid: u64,
}

impl SigEvent {
    /// Returns `true` if this event specification is valid.
    ///
    /// The `notify` field must be one of the four standard
    /// `SIGEV_*` values (0..=3).
    pub const fn is_valid(&self) -> bool {
        self.notify >= 0 && self.notify <= 3
    }
}

// ── TimerState ───────────────────────────────────────────────

/// State of a POSIX timer.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum TimerState {
    /// Timer is not armed.
    #[default]
    Disarmed,
    /// Timer is armed and counting down.
    Armed,
    /// Timer has expired.
    Expired,
}

// ── PosixTimer ───────────────────────────────────────────────

/// A single POSIX per-process interval timer.
///
/// Each timer is associated with a clock, owned by a process,
/// and can be armed to expire at a given time. When expired,
/// the timer generates a notification described by its
/// [`SigEvent`].
pub struct PosixTimer {
    /// Unique timer identifier.
    pub id: u32,
    /// POSIX clock ID (e.g. `CLOCK_REALTIME` = 0).
    pub clock_id: i32,
    /// PID of the owning process.
    pub owner_pid: u64,
    /// Notification specification.
    pub sigevent: SigEvent,
    /// Repeating interval (zero for one-shot timers).
    pub interval: Timespec,
    /// Absolute expiry time in nanoseconds.
    pub expires_ns: u64,
    /// Current timer state.
    pub state: TimerState,
    /// Number of overrun expirations.
    pub overrun_count: u32,
    /// Whether this timer slot is active (allocated).
    pub active: bool,
}

impl PosixTimer {
    /// Create an inactive timer with default values.
    const fn empty() -> Self {
        Self {
            id: 0,
            clock_id: 0,
            owner_pid: 0,
            sigevent: SigEvent {
                notify: 0,
                signo: 0,
                value: 0,
                tid: 0,
            },
            interval: Timespec {
                tv_sec: 0,
                tv_nsec: 0,
            },
            expires_ns: 0,
            state: TimerState::Disarmed,
            overrun_count: 0,
            active: false,
        }
    }
}

// ── TimerTickResult ──────────────────────────────────────────

/// Maximum number of signals reported per tick.
const MAX_SIGNALS_PER_TICK: usize = 16;

/// Result of a timer tick operation.
///
/// Contains information about timers that expired during the
/// tick and the signals that should be delivered.
#[derive(Debug)]
pub struct TimerTickResult {
    /// Number of timers that expired during this tick.
    pub expired_count: usize,
    /// Pending signals: (timer_id, signo, value).
    pub signals: [(u32, i32, u64); MAX_SIGNALS_PER_TICK],
    /// Number of valid entries in `signals`.
    pub signal_count: usize,
}

impl Default for TimerTickResult {
    fn default() -> Self {
        Self {
            expired_count: 0,
            signals: [(0, 0, 0); MAX_SIGNALS_PER_TICK],
            signal_count: 0,
        }
    }
}

// ── PosixTimerRegistry ───────────────────────────────────────

/// Global registry of POSIX per-process interval timers.
///
/// Manages the lifecycle of [`PosixTimer`] instances: creation,
/// arming/disarming, querying, and deletion. The [`tick`]
/// method drives expiration checking.
///
/// [`tick`]: PosixTimerRegistry::tick
pub struct PosixTimerRegistry {
    /// Fixed array of timer slots.
    timers: [PosixTimer; MAX_TOTAL_TIMERS],
    /// Next timer ID to allocate.
    next_id: u32,
    /// Number of active timers.
    count: usize,
}

impl Default for PosixTimerRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl PosixTimerRegistry {
    /// Create an empty registry with no active timers.
    pub const fn new() -> Self {
        Self {
            timers: [const { PosixTimer::empty() }; MAX_TOTAL_TIMERS],
            next_id: 1,
            count: 0,
        }
    }

    /// Create a new POSIX timer for the given process.
    ///
    /// Returns the timer ID on success. Fails with
    /// `OutOfMemory` if the system-wide or per-process limit
    /// is reached, or `InvalidArgument` if the event
    /// specification is invalid.
    pub fn timer_create(&mut self, clock_id: i32, event: SigEvent, pid: u64) -> Result<u32> {
        if !event.is_valid() {
            return Err(Error::InvalidArgument);
        }
        // Check per-process limit.
        if self.timers_for_pid(pid) >= MAX_TIMERS_PER_PROCESS {
            return Err(Error::OutOfMemory);
        }
        // Find a free slot.
        let slot = self
            .timers
            .iter_mut()
            .find(|t| !t.active)
            .ok_or(Error::OutOfMemory)?;

        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);

        slot.id = id;
        slot.clock_id = clock_id;
        slot.owner_pid = pid;
        slot.sigevent = event;
        slot.interval = Timespec::default();
        slot.expires_ns = 0;
        slot.state = TimerState::Disarmed;
        slot.overrun_count = 0;
        slot.active = true;

        self.count += 1;
        Ok(id)
    }

    /// Delete a POSIX timer by ID.
    ///
    /// Returns `NotFound` if no active timer with the given ID
    /// exists.
    pub fn timer_delete(&mut self, id: u32) -> Result<()> {
        let slot = self
            .timers
            .iter_mut()
            .find(|t| t.active && t.id == id)
            .ok_or(Error::NotFound)?;

        *slot = PosixTimer::empty();
        self.count = self.count.saturating_sub(1);
        Ok(())
    }

    /// Arm or disarm a POSIX timer.
    ///
    /// If `new_value.it_value` is non-zero the timer is armed.
    /// When `flags` contains [`TIMER_ABSTIME`], the value is
    /// treated as an absolute time in nanoseconds; otherwise it
    /// is relative to `now_ns`.
    ///
    /// Returns the previous timer setting.
    pub fn timer_settime(
        &mut self,
        id: u32,
        flags: i32,
        new_value: &Itimerspec,
        now_ns: u64,
    ) -> Result<Itimerspec> {
        let timer = self
            .timers
            .iter_mut()
            .find(|t| t.active && t.id == id)
            .ok_or(Error::NotFound)?;

        // Validate the new value.
        if !new_value.it_value.is_valid() || !new_value.it_interval.is_valid() {
            return Err(Error::InvalidArgument);
        }

        // Capture old value.
        let old = get_itimerspec(timer, now_ns);

        // Set the interval.
        timer.interval = new_value.it_interval;

        if new_value.it_value.is_zero() {
            // Disarm.
            timer.state = TimerState::Disarmed;
            timer.expires_ns = 0;
            timer.overrun_count = 0;
        } else {
            let value_ns = new_value
                .it_value
                .to_nanos()
                .ok_or(Error::InvalidArgument)?;

            if flags & TIMER_ABSTIME != 0 {
                timer.expires_ns = value_ns;
            } else {
                timer.expires_ns = now_ns.saturating_add(value_ns);
            }
            timer.state = TimerState::Armed;
            timer.overrun_count = 0;
        }

        Ok(old)
    }

    /// Query the current setting of a POSIX timer.
    ///
    /// Returns the remaining time until expiration and the
    /// interval. If the timer is disarmed both fields are zero.
    pub fn timer_gettime(&self, id: u32, now_ns: u64) -> Result<Itimerspec> {
        let timer = self
            .timers
            .iter()
            .find(|t| t.active && t.id == id)
            .ok_or(Error::NotFound)?;

        Ok(get_itimerspec(timer, now_ns))
    }

    /// Return the overrun count for a POSIX timer.
    ///
    /// The overrun count indicates how many additional
    /// expirations occurred between the initial expiration and
    /// the delivery of the notification signal.
    pub fn timer_getoverrun(&self, id: u32) -> Result<u32> {
        let timer = self
            .timers
            .iter()
            .find(|t| t.active && t.id == id)
            .ok_or(Error::NotFound)?;

        Ok(timer.overrun_count)
    }

    /// Check all armed timers for expiration.
    ///
    /// Must be called on every hardware timer tick. Timers that
    /// have passed their deadline are moved to the `Expired`
    /// state. Repeating timers are automatically re-armed with
    /// their interval. Overrun counts are updated for repeating
    /// timers that missed multiple intervals.
    pub fn tick(&mut self, now_ns: u64) -> TimerTickResult {
        let mut result = TimerTickResult::default();

        for timer in &mut self.timers {
            if !timer.active || timer.state != TimerState::Armed {
                continue;
            }
            if now_ns < timer.expires_ns {
                continue;
            }

            // Timer has expired.
            result.expired_count += 1;

            // Record signal if there is room.
            if result.signal_count < MAX_SIGNALS_PER_TICK {
                result.signals[result.signal_count] =
                    (timer.id, timer.sigevent.signo, timer.sigevent.value);
                result.signal_count += 1;
            }

            // Check for repeating timer.
            let interval_ns = timer.interval.to_nanos();
            match interval_ns {
                Some(ns) if ns > 0 => {
                    // Count overruns and re-arm.
                    let elapsed = now_ns.saturating_sub(timer.expires_ns);
                    let overruns = elapsed / ns;
                    timer.overrun_count = timer.overrun_count.saturating_add(overruns as u32);
                    let total = overruns.saturating_add(1);
                    timer.expires_ns = timer.expires_ns.saturating_add(total.saturating_mul(ns));
                    // Stays Armed.
                }
                _ => {
                    // One-shot: mark expired and disarm.
                    timer.state = TimerState::Expired;
                }
            }
        }

        result
    }

    /// Count the number of active timers owned by a process.
    pub fn timers_for_pid(&self, pid: u64) -> usize {
        self.timers
            .iter()
            .filter(|t| t.active && t.owner_pid == pid)
            .count()
    }

    /// Delete all timers owned by a process.
    ///
    /// Called during process exit to release timer resources.
    pub fn delete_all_for_pid(&mut self, pid: u64) {
        for timer in &mut self.timers {
            if timer.active && timer.owner_pid == pid {
                *timer = PosixTimer::empty();
                self.count = self.count.saturating_sub(1);
            }
        }
    }

    /// Return the number of active timers in the registry.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Returns `true` if no timers are active.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
}

// ── Helpers ──────────────────────────────────────────────────

/// Build an `Itimerspec` from a timer's current state.
fn get_itimerspec(timer: &PosixTimer, now_ns: u64) -> Itimerspec {
    if timer.state == TimerState::Disarmed {
        return Itimerspec::default();
    }

    let remaining = timer.expires_ns.saturating_sub(now_ns);
    Itimerspec {
        it_interval: timer.interval,
        it_value: Timespec::from_nanos(remaining),
    }
}
