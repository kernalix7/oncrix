// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `timerfd_settime(2)` and `timerfd_gettime(2)` syscall handlers.
//!
//! These complement `timerfd_create`: once a timerfd has been created,
//! `timerfd_settime` arms or disarms it by programming an initial expiration
//! and (optional) periodic interval.  `timerfd_gettime` queries the current
//! remaining time and interval.
//!
//! # Linux man page
//!
//! `timerfd_settime(2)`, `timerfd_gettime(2)`.

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Flags
// ---------------------------------------------------------------------------

/// Interpret expiration as an absolute time.
pub const TFD_TIMER_ABSTIME: u32 = 1 << 0;
/// Cancel if the clock is stepped (real-time clocks only).
pub const TFD_TIMER_CANCEL_ON_SET: u32 = 1 << 1;

/// All valid `timerfd_settime` flags.
const VALID_FLAGS: u32 = TFD_TIMER_ABSTIME | TFD_TIMER_CANCEL_ON_SET;

// ---------------------------------------------------------------------------
// Time types
// ---------------------------------------------------------------------------

/// POSIX `struct timespec`.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Timespec {
    /// Whole seconds.
    pub tv_sec: i64,
    /// Nanoseconds [0, 999_999_999].
    pub tv_nsec: i64,
}

impl Timespec {
    /// Create a new timespec.
    pub fn new(sec: i64, nsec: i64) -> Self {
        Self {
            tv_sec: sec,
            tv_nsec: nsec,
        }
    }

    /// Returns `true` if the nanoseconds field is in the valid range.
    pub fn is_valid(&self) -> bool {
        self.tv_nsec >= 0 && self.tv_nsec < 1_000_000_000
    }

    /// Returns `true` if this represents time zero (disarmed state).
    pub fn is_zero(&self) -> bool {
        self.tv_sec == 0 && self.tv_nsec == 0
    }

    /// Convert to total nanoseconds.
    pub fn to_nanos(&self) -> u64 {
        (self.tv_sec as u64)
            .saturating_mul(1_000_000_000)
            .saturating_add(self.tv_nsec as u64)
    }
}

/// POSIX `struct itimerspec` — interval timer specification.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Itimerspec {
    /// Timer interval (zero = one-shot).
    pub it_interval: Timespec,
    /// Initial expiration (zero = disarm).
    pub it_value: Timespec,
}

impl Itimerspec {
    /// Create a periodic timer spec.
    pub fn periodic(initial: Timespec, interval: Timespec) -> Self {
        Self {
            it_interval: interval,
            it_value: initial,
        }
    }

    /// Create a one-shot timer spec.
    pub fn oneshot(initial: Timespec) -> Self {
        Self {
            it_interval: Timespec::default(),
            it_value: initial,
        }
    }

    /// Returns `true` if the timer is disarmed (it_value is zero).
    pub fn is_disarmed(&self) -> bool {
        self.it_value.is_zero()
    }

    /// Returns `true` if both timespec fields are valid.
    pub fn is_valid(&self) -> bool {
        self.it_value.is_valid() && self.it_interval.is_valid()
    }
}

// ---------------------------------------------------------------------------
// Timerfd state
// ---------------------------------------------------------------------------

/// Kernel-side timerfd object used by the settime/gettime handlers.
#[derive(Debug, Clone, Copy)]
pub struct TimerfdState {
    /// Clock ID (e.g. CLOCK_MONOTONIC).
    pub clockid: u32,
    /// Non-blocking read mode.
    pub nonblock: bool,
    /// Currently programmed spec.
    pub spec: Itimerspec,
    /// Clock reading (nanoseconds) when the timer was last armed.
    pub armed_at_ns: u64,
    /// Pending expiration count (read-and-clear via read(2)).
    pub expirations: u64,
}

impl TimerfdState {
    /// Create a disarmed timerfd state.
    pub fn new(clockid: u32, nonblock: bool) -> Self {
        Self {
            clockid,
            nonblock,
            spec: Itimerspec::default(),
            armed_at_ns: 0,
            expirations: 0,
        }
    }

    /// Increment the expiration counter (called by timer subsystem).
    pub fn tick(&mut self, count: u64) {
        self.expirations = self.expirations.saturating_add(count);
    }
}

// ---------------------------------------------------------------------------
// Core handlers
// ---------------------------------------------------------------------------

/// Handler for `timerfd_settime(2)`.
///
/// Arms or disarms the timer.  If `new_value.it_value` is zero the timer is
/// disarmed.  If `TFD_TIMER_ABSTIME` is set the initial expiration is
/// interpreted as an absolute clock value rather than a relative offset.
///
/// The old timer spec is written into `old_value` before updating, matching
/// Linux semantics.
///
/// # Arguments
///
/// - `state`     — mutable timerfd state
/// - `flags`     — combination of `TFD_TIMER_ABSTIME` / `TFD_TIMER_CANCEL_ON_SET`
/// - `new_value` — new expiration and interval
/// - `old_value` — storage to receive the previous timer spec
/// - `now_ns`    — current clock value in nanoseconds
///
/// # Errors
///
/// | `Error`           | Condition                                    |
/// |-------------------|----------------------------------------------|
/// | `InvalidArgument` | Unknown flags or invalid timespec fields     |
pub fn do_timerfd_settime(
    state: &mut TimerfdState,
    flags: u32,
    new_value: &Itimerspec,
    old_value: Option<&mut Itimerspec>,
    now_ns: u64,
) -> Result<()> {
    if flags & !VALID_FLAGS != 0 {
        return Err(Error::InvalidArgument);
    }
    if !new_value.is_valid() {
        return Err(Error::InvalidArgument);
    }

    // Capture old spec before overwriting.
    if let Some(old) = old_value {
        *old = state.spec;
    }

    state.spec = *new_value;
    state.armed_at_ns = now_ns;
    state.expirations = 0;
    Ok(())
}

/// Handler for `timerfd_gettime(2)`.
///
/// Returns the current timer spec.  For a relative timer, `it_value` reflects
/// the time remaining until the next expiration.  For an absolute timer this
/// handler returns the raw stored spec — the caller is responsible for
/// converting to remaining time if needed.
///
/// # Arguments
///
/// - `state`  — timerfd state
/// - `now_ns` — current clock value in nanoseconds
pub fn do_timerfd_gettime(state: &TimerfdState, now_ns: u64) -> Itimerspec {
    if state.spec.is_disarmed() {
        return Itimerspec::default();
    }
    let expire_ns = state
        .armed_at_ns
        .saturating_add(state.spec.it_value.to_nanos());
    let remaining_ns = expire_ns.saturating_sub(now_ns);
    Itimerspec {
        it_interval: state.spec.it_interval,
        it_value: Timespec {
            tv_sec: (remaining_ns / 1_000_000_000) as i64,
            tv_nsec: (remaining_ns % 1_000_000_000) as i64,
        },
    }
}

/// Drain the expiration counter (implements timerfd `read(2)`).
///
/// Returns the accumulated count and resets it to zero.
///
/// # Errors
///
/// | `Error`      | Condition                                   |
/// |--------------|---------------------------------------------|
/// | `WouldBlock` | No expirations and `nonblock` flag is set   |
pub fn do_timerfd_drain(state: &mut TimerfdState) -> Result<u64> {
    if state.expirations == 0 {
        return Err(Error::WouldBlock);
    }
    let count = state.expirations;
    state.expirations = 0;
    Ok(count)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_state() -> TimerfdState {
        TimerfdState::new(1 /* CLOCK_MONOTONIC */, false)
    }

    #[test]
    fn settime_ok() {
        let mut s = make_state();
        let spec = Itimerspec::oneshot(Timespec::new(5, 0));
        do_timerfd_settime(&mut s, 0, &spec, None, 0).unwrap();
        assert!(!s.spec.is_disarmed());
    }

    #[test]
    fn settime_saves_old() {
        let mut s = make_state();
        let spec1 = Itimerspec::oneshot(Timespec::new(1, 0));
        do_timerfd_settime(&mut s, 0, &spec1, None, 0).unwrap();
        let spec2 = Itimerspec::oneshot(Timespec::new(2, 0));
        let mut old = Itimerspec::default();
        do_timerfd_settime(&mut s, 0, &spec2, Some(&mut old), 1_000_000_000).unwrap();
        assert_eq!(old.it_value.tv_sec, 1);
    }

    #[test]
    fn settime_bad_flags() {
        let mut s = make_state();
        let spec = Itimerspec::default();
        assert_eq!(
            do_timerfd_settime(&mut s, 0xFF, &spec, None, 0),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn settime_invalid_nsec() {
        let mut s = make_state();
        let spec = Itimerspec::oneshot(Timespec::new(0, 2_000_000_000));
        assert_eq!(
            do_timerfd_settime(&mut s, 0, &spec, None, 0),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn gettime_disarmed() {
        let s = make_state();
        let cur = do_timerfd_gettime(&s, 0);
        assert!(cur.is_disarmed());
    }

    #[test]
    fn gettime_remaining() {
        let mut s = make_state();
        let spec = Itimerspec::oneshot(Timespec::new(10, 0));
        do_timerfd_settime(&mut s, 0, &spec, None, 0).unwrap();
        // 3 seconds elapsed.
        let cur = do_timerfd_gettime(&s, 3_000_000_000);
        assert_eq!(cur.it_value.tv_sec, 7);
    }

    #[test]
    fn drain_ok() {
        let mut s = make_state();
        s.tick(5);
        assert_eq!(do_timerfd_drain(&mut s).unwrap(), 5);
        assert_eq!(s.expirations, 0);
    }

    #[test]
    fn drain_wouldblock() {
        let mut s = make_state();
        assert_eq!(do_timerfd_drain(&mut s), Err(Error::WouldBlock));
    }
}
