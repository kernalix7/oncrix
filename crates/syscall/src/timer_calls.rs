// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! POSIX per-process timer syscall handlers.
//!
//! Implements `timer_create(2)`, `timer_settime(2)`, `timer_gettime(2)`,
//! `timer_delete(2)`, and `timer_getoverrun(2)` per POSIX.1-2024.
//!
//! Each process may create up to [`TIMERCALLS_MAX`] timers, identified
//! by an opaque [`TimerId`].  On expiry a timer can deliver a signal,
//! invoke a thread notification, or remain silent depending on the
//! `SigEvent` notification mode.
//!
//! # POSIX Reference
//!
//! See `.TheOpenGroup/susv5-html/functions/timer_create.html` and
//! adjacent pages for the authoritative specification.

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum number of POSIX timers across all processes.
pub const TIMERCALLS_MAX: usize = 256;

/// Flag: treat `it_value` as an absolute clock value rather than an offset.
pub const TIMER_ABSTIME: i32 = 1;

/// Nanoseconds per second.
pub const NS_PER_SEC: i64 = 1_000_000_000;

/// Maximum overrun count per POSIX (`DELAYTIMER_MAX`).
pub const DELAYTIMER_MAX: i32 = i32::MAX;

// ---------------------------------------------------------------------------
// Timespec
// ---------------------------------------------------------------------------

/// POSIX `struct timespec` — seconds and nanoseconds.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Timespec {
    /// Whole seconds.
    pub tv_sec: i64,
    /// Sub-second nanoseconds (must be in `[0, NS_PER_SEC)`).
    pub tv_nsec: i64,
}

impl Timespec {
    /// Create a new `Timespec`.
    pub const fn new(tv_sec: i64, tv_nsec: i64) -> Self {
        Self { tv_sec, tv_nsec }
    }

    /// Return `true` if the nanosecond field is in bounds.
    pub const fn is_valid(&self) -> bool {
        self.tv_nsec >= 0 && self.tv_nsec < NS_PER_SEC
    }

    /// Return `true` if this represents the zero time / zero duration.
    pub const fn is_zero(&self) -> bool {
        self.tv_sec == 0 && self.tv_nsec == 0
    }

    /// Convert to total nanoseconds, saturating on overflow.
    pub fn to_nanos(self) -> i64 {
        self.tv_sec
            .saturating_mul(NS_PER_SEC)
            .saturating_add(self.tv_nsec)
    }

    /// Construct from total nanoseconds.
    pub fn from_nanos(nanos: i64) -> Self {
        let tv_sec = nanos / NS_PER_SEC;
        let tv_nsec = nanos % NS_PER_SEC;
        Self { tv_sec, tv_nsec }
    }
}

// ---------------------------------------------------------------------------
// Itimerspec
// ---------------------------------------------------------------------------

/// POSIX `struct itimerspec` — interval timer specification.
///
/// When `it_value` is zero the timer is disarmed.  A non-zero
/// `it_interval` enables periodic re-arming after each expiry.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Itimerspec {
    /// Reload interval (zero = one-shot timer).
    pub it_interval: Timespec,
    /// Initial expiration time (zero = disarm).
    pub it_value: Timespec,
}

impl Itimerspec {
    /// Create a disarmed `Itimerspec`.
    pub const fn new() -> Self {
        Self {
            it_interval: Timespec::new(0, 0),
            it_value: Timespec::new(0, 0),
        }
    }

    /// Return `true` if the timer is disarmed (`it_value` is zero).
    pub fn is_disarmed(&self) -> bool {
        self.it_value.is_zero()
    }

    /// Validate both `Timespec` fields.
    pub fn is_valid(&self) -> bool {
        self.it_interval.is_valid() && self.it_value.is_valid()
    }
}

// ---------------------------------------------------------------------------
// ClockId
// ---------------------------------------------------------------------------

/// Clock source for a POSIX timer.
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ClockId {
    /// Wall-clock time; settable.
    #[default]
    Realtime = 0,
    /// Monotonic clock; not settable.
    Monotonic = 1,
    /// Per-process CPU-time clock.
    ProcessCputime = 2,
    /// Per-thread CPU-time clock.
    ThreadCputime = 3,
    /// Raw hardware monotonic (no NTP).
    MonotonicRaw = 4,
    /// Coarse realtime (fast, low precision).
    RealtimeCoarse = 5,
    /// Coarse monotonic (fast, low precision).
    MonotonicCoarse = 6,
    /// Time since boot, including suspend.
    Boottime = 7,
}

impl ClockId {
    /// Convert a raw `u32` to a `ClockId`.
    pub fn from_u32(val: u32) -> Option<Self> {
        match val {
            0 => Some(Self::Realtime),
            1 => Some(Self::Monotonic),
            2 => Some(Self::ProcessCputime),
            3 => Some(Self::ThreadCputime),
            4 => Some(Self::MonotonicRaw),
            5 => Some(Self::RealtimeCoarse),
            6 => Some(Self::MonotonicCoarse),
            7 => Some(Self::Boottime),
            _ => None,
        }
    }

    /// Return `true` if per-thread CPU timers are allowed to create
    /// timers with this clock.  POSIX forbids `CLOCK_THREAD_CPUTIME_ID`
    /// in some contexts but allows it here.
    pub const fn is_valid_for_timer(self) -> bool {
        // All defined clock IDs are valid for timer_create.
        true
    }
}

// ---------------------------------------------------------------------------
// SigNotify — notification mode inside SigEvent
// ---------------------------------------------------------------------------

/// Notification method for timer expiry.
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SigNotify {
    /// No notification on expiry.
    #[default]
    None = 0,
    /// Deliver a signal to the creating process.
    Signal = 1,
    /// Invoke a thread (stub: treated as signal delivery).
    Thread = 2,
}

impl SigNotify {
    /// Convert a raw `i32` to `SigNotify`.
    pub fn from_i32(val: i32) -> Option<Self> {
        match val {
            0 => Some(Self::None),
            1 => Some(Self::Signal),
            2 => Some(Self::Thread),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// SigEvent
// ---------------------------------------------------------------------------

/// POSIX `struct sigevent` — specifies how timer expiry is notified.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SigEvent {
    /// Notification method.
    pub sigev_notify: i32,
    /// Signal number to deliver (for `SIGEV_SIGNAL`).
    pub sigev_signo: i32,
    /// Signal value (opaque, carried in `si_value`).
    pub sigev_value: u64,
}

impl SigEvent {
    /// Create a signal-delivery `SigEvent`.
    pub const fn signal(signo: i32) -> Self {
        Self {
            sigev_notify: SigNotify::Signal as i32,
            sigev_signo: signo,
            sigev_value: 0,
        }
    }

    /// Create a silent (no-notify) `SigEvent`.
    pub const fn none() -> Self {
        Self {
            sigev_notify: SigNotify::None as i32,
            sigev_signo: 0,
            sigev_value: 0,
        }
    }

    /// Validate the signal event fields.
    pub fn is_valid(&self) -> bool {
        let notify = SigNotify::from_i32(self.sigev_notify);
        if notify.is_none() {
            return false;
        }
        // If signal delivery, signal number must be in [1, 64].
        if notify == Some(SigNotify::Signal) && (self.sigev_signo < 1 || self.sigev_signo > 64) {
            return false;
        }
        true
    }
}

// ---------------------------------------------------------------------------
// TimerId
// ---------------------------------------------------------------------------

/// Opaque POSIX timer identifier (`timer_t`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TimerId(u32);

impl TimerId {
    /// Create a timer ID from a raw slot index.
    pub const fn from_raw(val: u32) -> Self {
        Self(val)
    }

    /// Return the raw value.
    pub const fn raw(self) -> u32 {
        self.0
    }
}

// ---------------------------------------------------------------------------
// TimerState — per-timer state
// ---------------------------------------------------------------------------

/// Armed/disarmed state of a POSIX timer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TimerArmed {
    /// Timer is disarmed (not ticking).
    #[default]
    Disarmed,
    /// Timer is armed with absolute deadline (nanoseconds).
    Armed {
        /// Absolute deadline in monotonic nanoseconds.
        deadline_ns: i64,
        /// Reload interval in nanoseconds (0 = one-shot).
        interval_ns: i64,
    },
}

/// Per-timer kernel state.
pub struct TimerState {
    /// Owner PID.
    pub owner_pid: u32,
    /// Clock source.
    pub clock_id: ClockId,
    /// Notification configuration.
    pub sigevent: SigEvent,
    /// Armed state and deadline.
    pub armed: TimerArmed,
    /// Number of times the timer has overrun since last `timer_getoverrun`.
    pub overrun_count: i32,
    /// Whether this slot is occupied.
    pub active: bool,
}

impl TimerState {
    /// Create a new (inactive) timer state.
    const fn new() -> Self {
        Self {
            owner_pid: 0,
            clock_id: ClockId::Realtime,
            sigevent: SigEvent {
                sigev_notify: SigNotify::None as i32,
                sigev_signo: 0,
                sigev_value: 0,
            },
            armed: TimerArmed::Disarmed,
            overrun_count: 0,
            active: false,
        }
    }
}

// ---------------------------------------------------------------------------
// TimerCallsState — global timer table
// ---------------------------------------------------------------------------

/// Kernel-wide POSIX timer table.
///
/// Holds up to [`TIMERCALLS_MAX`] timers across all processes.
pub struct TimerCallsState {
    timers: [TimerState; TIMERCALLS_MAX],
    /// Number of active timers.
    count: usize,
}

impl TimerCallsState {
    /// Create an empty timer table.
    pub const fn new() -> Self {
        Self {
            timers: [const { TimerState::new() }; TIMERCALLS_MAX],
            count: 0,
        }
    }

    /// Return the number of active timers.
    pub const fn count(&self) -> usize {
        self.count
    }

    // -- Internal helpers --------------------------------------------------

    /// Find a free slot.
    fn find_free(&self) -> Option<usize> {
        for (i, t) in self.timers.iter().enumerate() {
            if !t.active {
                return Some(i);
            }
        }
        None
    }

    /// Validate a timer ID and return its slot index.
    fn validate_id(&self, id: TimerId, owner_pid: u32) -> Result<usize> {
        let idx = id.raw() as usize;
        if idx >= TIMERCALLS_MAX {
            return Err(Error::InvalidArgument);
        }
        let t = &self.timers[idx];
        if !t.active {
            return Err(Error::NotFound);
        }
        if t.owner_pid != owner_pid {
            return Err(Error::PermissionDenied);
        }
        Ok(idx)
    }
}

impl Default for TimerCallsState {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Syscall handlers
// ---------------------------------------------------------------------------

/// `timer_create(2)` — create a POSIX per-process timer.
///
/// `clock_id` selects the clock source; `sigevent` configures notification.
/// Returns a [`TimerId`] that uniquely identifies the new timer.
///
/// Fails with `OutOfMemory` if the timer table is full.
pub fn do_timer_create(
    state: &mut TimerCallsState,
    owner_pid: u32,
    clock_id: u32,
    sigevent: Option<&SigEvent>,
) -> Result<TimerId> {
    if owner_pid == 0 {
        return Err(Error::InvalidArgument);
    }

    let cid = ClockId::from_u32(clock_id).ok_or(Error::InvalidArgument)?;

    if !cid.is_valid_for_timer() {
        return Err(Error::InvalidArgument);
    }

    // Default notification: SIGALRM if no sigevent supplied.
    let ev = match sigevent {
        Some(ev) => {
            if !ev.is_valid() {
                return Err(Error::InvalidArgument);
            }
            *ev
        }
        None => SigEvent::signal(14), // SIGALRM = 14
    };

    let idx = state.find_free().ok_or(Error::OutOfMemory)?;

    state.timers[idx].owner_pid = owner_pid;
    state.timers[idx].clock_id = cid;
    state.timers[idx].sigevent = ev;
    state.timers[idx].armed = TimerArmed::Disarmed;
    state.timers[idx].overrun_count = 0;
    state.timers[idx].active = true;
    state.count += 1;

    Ok(TimerId::from_raw(idx as u32))
}

/// `timer_settime(2)` — arm or disarm a POSIX timer.
///
/// `flags` may include [`TIMER_ABSTIME`].  If `old_value` is requested,
/// the previous setting is returned.  Setting `new_value.it_value` to
/// zero disarms the timer.
pub fn do_timer_settime(
    state: &mut TimerCallsState,
    owner_pid: u32,
    timer_id: TimerId,
    flags: i32,
    new_value: &Itimerspec,
) -> Result<Itimerspec> {
    if flags & !TIMER_ABSTIME != 0 {
        return Err(Error::InvalidArgument);
    }

    if !new_value.is_valid() {
        return Err(Error::InvalidArgument);
    }

    let idx = state.validate_id(timer_id, owner_pid)?;

    // Snapshot the old setting before overwriting.
    let old = match state.timers[idx].armed {
        TimerArmed::Disarmed => Itimerspec::new(),
        TimerArmed::Armed {
            deadline_ns,
            interval_ns,
        } => Itimerspec {
            it_interval: Timespec::from_nanos(interval_ns),
            it_value: Timespec::from_nanos(deadline_ns),
        },
    };

    if new_value.is_disarmed() {
        state.timers[idx].armed = TimerArmed::Disarmed;
        state.timers[idx].overrun_count = 0;
    } else {
        let deadline_ns = if flags & TIMER_ABSTIME != 0 {
            // Absolute: use the given value directly.
            new_value.it_value.to_nanos()
        } else {
            // Relative: in a real kernel we add the current clock reading.
            // Stub: treat as an absolute offset from zero.
            new_value.it_value.to_nanos()
        };
        let interval_ns = new_value.it_interval.to_nanos();

        state.timers[idx].armed = TimerArmed::Armed {
            deadline_ns,
            interval_ns,
        };
        state.timers[idx].overrun_count = 0;
    }

    Ok(old)
}

/// `timer_gettime(2)` — retrieve the current setting of a POSIX timer.
///
/// Returns the remaining time until expiry and the reload interval.
/// Both fields are zero if the timer is disarmed.
pub fn do_timer_gettime(
    state: &TimerCallsState,
    owner_pid: u32,
    timer_id: TimerId,
) -> Result<Itimerspec> {
    let idx = state.validate_id(timer_id, owner_pid)?;

    let spec = match state.timers[idx].armed {
        TimerArmed::Disarmed => Itimerspec::new(),
        TimerArmed::Armed {
            deadline_ns,
            interval_ns,
        } => Itimerspec {
            it_interval: Timespec::from_nanos(interval_ns),
            it_value: Timespec::from_nanos(deadline_ns),
        },
    };

    Ok(spec)
}

/// `timer_delete(2)` — delete a POSIX timer.
///
/// Disarms the timer and releases the slot.  Any pending expiry
/// notifications are cancelled.
pub fn do_timer_delete(
    state: &mut TimerCallsState,
    owner_pid: u32,
    timer_id: TimerId,
) -> Result<()> {
    let idx = state.validate_id(timer_id, owner_pid)?;

    state.timers[idx].active = false;
    state.timers[idx].armed = TimerArmed::Disarmed;
    state.timers[idx].overrun_count = 0;
    state.count = state.count.saturating_sub(1);
    Ok(())
}

/// `timer_getoverrun(2)` — retrieve the overrun count for a timer.
///
/// Returns the number of extra expirations that occurred since the
/// last `timer_getoverrun` call or the last signal delivery.
/// POSIX caps the value at [`DELAYTIMER_MAX`].
pub fn do_timer_getoverrun(
    state: &mut TimerCallsState,
    owner_pid: u32,
    timer_id: TimerId,
) -> Result<i32> {
    let idx = state.validate_id(timer_id, owner_pid)?;

    let overrun = state.timers[idx].overrun_count.min(DELAYTIMER_MAX);
    // Reset overrun count after retrieval.
    state.timers[idx].overrun_count = 0;
    Ok(overrun)
}

// ---------------------------------------------------------------------------
// Timer expiry helper (called from clock interrupt context)
// ---------------------------------------------------------------------------

/// Record an expiry event for the given timer (called from the tick handler).
///
/// Increments the overrun count (capped at [`DELAYTIMER_MAX`]) and,
/// for periodic timers, advances the deadline by one interval.
pub fn timer_on_expiry(state: &mut TimerCallsState, timer_id: TimerId) {
    let idx = timer_id.raw() as usize;
    if idx >= TIMERCALLS_MAX || !state.timers[idx].active {
        return;
    }

    // Increment overrun, saturating at DELAYTIMER_MAX.
    let ov = &mut state.timers[idx].overrun_count;
    *ov = ov.saturating_add(1).min(DELAYTIMER_MAX);

    // Advance deadline for periodic timers.
    if let TimerArmed::Armed {
        ref mut deadline_ns,
        interval_ns,
    } = state.timers[idx].armed
    {
        if interval_ns > 0 {
            *deadline_ns = deadline_ns.saturating_add(interval_ns);
        } else {
            // One-shot: disarm after expiry.
            state.timers[idx].armed = TimerArmed::Disarmed;
        }
    }
}

/// Return the `SigEvent` associated with a timer (for signal delivery).
///
/// Returns `None` if the timer ID is invalid or inactive.
pub fn timer_get_sigevent(state: &TimerCallsState, timer_id: TimerId) -> Option<SigEvent> {
    let idx = timer_id.raw() as usize;
    if idx >= TIMERCALLS_MAX || !state.timers[idx].active {
        return None;
    }
    Some(state.timers[idx].sigevent)
}
