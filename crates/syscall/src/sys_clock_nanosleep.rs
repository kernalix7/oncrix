// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `clock_nanosleep(2)` syscall handler — high-resolution sleep on a specified clock.
//!
//! `clock_nanosleep` is the POSIX.1-2024 successor to `nanosleep`, allowing the
//! caller to specify a clock source and to express the sleep as either a
//! relative duration or an absolute deadline.
//!
//! # Syscall signature
//!
//! ```text
//! int clock_nanosleep(clockid_t clockid, int flags,
//!                     const struct timespec *request,
//!                     struct timespec *remain);
//! ```
//!
//! # Flags
//!
//! | Flag           | Value | Effect                                      |
//! |----------------|-------|---------------------------------------------|
//! | (none)         | 0     | Relative sleep (duration from now).         |
//! | `TIMER_ABSTIME`| 1     | Absolute sleep (wake when clock reaches ts).|
//!
//! # Clock sources
//!
//! | Clock                       | Sleepable | Notes                         |
//! |-----------------------------|-----------|-------------------------------|
//! | `CLOCK_REALTIME`            | Yes       | Wall clock; may jump          |
//! | `CLOCK_MONOTONIC`           | Yes       | Never jumps backward          |
//! | `CLOCK_PROCESS_CPUTIME_ID`  | No        | POSIX: EINVAL required        |
//! | `CLOCK_THREAD_CPUTIME_ID`   | No        | POSIX: EINVAL required        |
//! | `CLOCK_MONOTONIC_RAW`       | Yes       | Not adjusted by NTP           |
//! | `CLOCK_BOOTTIME`            | Yes       | Includes suspend time         |
//! | `CLOCK_REALTIME_ALARM`      | Yes       | Wakes system from suspend     |
//! | `CLOCK_BOOTTIME_ALARM`      | Yes       | Wakes system from suspend     |
//!
//! # Signal interruption
//!
//! When a signal arrives during a relative sleep, the handler returns
//! `Interrupted` and the remaining time is stored (the caller is responsible
//! for re-invoking with the remainder).  Absolute sleeps are restarted
//! automatically by the kernel.
//!
//! # POSIX conformance
//!
//! - POSIX.1-2024: `clock_nanosleep()` in `<time.h>`.
//! - `CLOCK_THREAD_CPUTIME_ID` must return EINVAL (POSIX mandated).
//! - `TIMER_ABSTIME` semantics match the standard.
//!
//! # Linux reference
//!
//! `kernel/time/posix-timers.c` — `common_nsleep()`, `hrtimer_nanosleep()`

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Flag: sleep until an absolute clock value rather than a duration.
pub const TIMER_ABSTIME: i32 = 1;

/// Nanoseconds per second.
pub const NSEC_PER_SEC: i64 = 1_000_000_000;

// ---------------------------------------------------------------------------
// ClockId
// ---------------------------------------------------------------------------

/// POSIX clock identifiers.
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClockId {
    /// Settable wall-clock time.
    Realtime = 0,
    /// Monotonic clock (not settable).
    Monotonic = 1,
    /// Per-process CPU time — not sleepable.
    ProcessCputime = 2,
    /// Per-thread CPU time — not sleepable.
    ThreadCputime = 3,
    /// Raw monotonic — no NTP adjustments.
    MonotonicRaw = 4,
    /// Coarse realtime (less precise, faster).
    RealtimeCoarse = 5,
    /// Coarse monotonic (less precise, faster).
    MonotonicCoarse = 6,
    /// Boot time including suspend.
    Boottime = 7,
    /// Realtime alarm — wakes from suspend.
    RealtimeAlarm = 8,
    /// Boottime alarm — wakes from suspend.
    BoottimeAlarm = 9,
}

impl ClockId {
    /// Parse a raw `i32` clock identifier.
    pub fn from_i32(val: i32) -> Result<Self> {
        match val {
            0 => Ok(Self::Realtime),
            1 => Ok(Self::Monotonic),
            2 => Ok(Self::ProcessCputime),
            3 => Ok(Self::ThreadCputime),
            4 => Ok(Self::MonotonicRaw),
            5 => Ok(Self::RealtimeCoarse),
            6 => Ok(Self::MonotonicCoarse),
            7 => Ok(Self::Boottime),
            8 => Ok(Self::RealtimeAlarm),
            9 => Ok(Self::BoottimeAlarm),
            _ => Err(Error::InvalidArgument),
        }
    }

    /// Return `true` when this clock may be used with `clock_nanosleep`.
    ///
    /// Per POSIX, `CLOCK_PROCESS_CPUTIME_ID` and `CLOCK_THREAD_CPUTIME_ID`
    /// are not allowed.
    pub const fn is_sleepable(self) -> bool {
        !matches!(self, Self::ProcessCputime | Self::ThreadCputime)
    }

    /// Return `true` when this clock can wake the system from suspend.
    pub const fn is_alarm(self) -> bool {
        matches!(self, Self::RealtimeAlarm | Self::BoottimeAlarm)
    }
}

// ---------------------------------------------------------------------------
// Timespec
// ---------------------------------------------------------------------------

/// POSIX `struct timespec`.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Timespec {
    /// Whole seconds.
    pub tv_sec: i64,
    /// Nanosecond component; must be in `[0, NSEC_PER_SEC)`.
    pub tv_nsec: i64,
}

impl Timespec {
    /// Create a new `Timespec`.
    pub const fn new(sec: i64, nsec: i64) -> Self {
        Self {
            tv_sec: sec,
            tv_nsec: nsec,
        }
    }

    /// A zero-valued timespec.
    pub const fn zero() -> Self {
        Self {
            tv_sec: 0,
            tv_nsec: 0,
        }
    }

    /// Return `true` when `tv_nsec` is in `[0, NSEC_PER_SEC)`.
    pub const fn is_valid(&self) -> bool {
        self.tv_nsec >= 0 && self.tv_nsec < NSEC_PER_SEC
    }

    /// Return `true` when both fields are zero.
    pub const fn is_zero(&self) -> bool {
        self.tv_sec == 0 && self.tv_nsec == 0
    }

    /// Convert to total nanoseconds, returning `None` on overflow.
    pub fn to_nanos(&self) -> Option<i64> {
        self.tv_sec
            .checked_mul(NSEC_PER_SEC)
            .and_then(|s| s.checked_add(self.tv_nsec))
    }

    /// Construct from total nanoseconds (clamped to zero for negative values).
    pub fn from_nanos(nanos: i64) -> Self {
        if nanos <= 0 {
            return Self::zero();
        }
        Self {
            tv_sec: nanos / NSEC_PER_SEC,
            tv_nsec: nanos % NSEC_PER_SEC,
        }
    }

    /// Subtract `rhs` from `self`, clamping at zero.
    pub fn saturating_sub(self, rhs: Self) -> Self {
        let lhs_ns = self.to_nanos().unwrap_or(0);
        let rhs_ns = rhs.to_nanos().unwrap_or(0);
        Self::from_nanos(lhs_ns.saturating_sub(rhs_ns))
    }
}

// ---------------------------------------------------------------------------
// SleepFlags
// ---------------------------------------------------------------------------

/// Validated flags for `clock_nanosleep`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SleepFlags(i32);

impl SleepFlags {
    /// Relative sleep (no flags set).
    pub const RELATIVE: Self = Self(0);
    /// Absolute sleep (`TIMER_ABSTIME`).
    pub const ABSOLUTE: Self = Self(TIMER_ABSTIME);

    /// Parse and validate raw flags.
    pub fn from_raw(raw: i32) -> Result<Self> {
        if raw & !TIMER_ABSTIME != 0 {
            return Err(Error::InvalidArgument);
        }
        Ok(Self(raw))
    }

    /// Return `true` when `TIMER_ABSTIME` is set.
    pub const fn is_absolute(self) -> bool {
        self.0 & TIMER_ABSTIME != 0
    }

    /// Return the raw integer value.
    pub const fn raw(self) -> i32 {
        self.0
    }
}

// ---------------------------------------------------------------------------
// SleepRequest
// ---------------------------------------------------------------------------

/// A validated sleep request.
#[derive(Debug, Clone, Copy)]
pub struct SleepRequest {
    /// Clock source.
    pub clock: ClockId,
    /// Flags.
    pub flags: SleepFlags,
    /// Requested time (duration or absolute deadline).
    pub ts: Timespec,
}

impl SleepRequest {
    /// Construct and validate a sleep request.
    ///
    /// # Errors
    ///
    /// * [`Error::InvalidArgument`] — non-sleepable clock, invalid flags,
    ///   invalid timespec.
    pub fn new(clock_id: i32, flags: i32, ts: &Timespec) -> Result<Self> {
        let clock = ClockId::from_i32(clock_id)?;
        if !clock.is_sleepable() {
            return Err(Error::InvalidArgument);
        }
        let flags = SleepFlags::from_raw(flags)?;
        if !ts.is_valid() {
            return Err(Error::InvalidArgument);
        }
        Ok(Self {
            clock,
            flags,
            ts: *ts,
        })
    }
}

// ---------------------------------------------------------------------------
// InterruptedSleep — remaining time tracking
// ---------------------------------------------------------------------------

/// State saved when a sleep is interrupted by a signal.
#[derive(Debug, Clone, Copy)]
pub struct InterruptedSleep {
    /// Original request.
    pub request: SleepRequest,
    /// Time elapsed before the interruption.
    pub elapsed: Timespec,
}

impl InterruptedSleep {
    /// Compute the remaining sleep time.
    ///
    /// For absolute sleeps the remaining time is not meaningful per POSIX.
    pub fn remaining(&self) -> Timespec {
        if self.request.flags.is_absolute() {
            return Timespec::zero();
        }
        self.request.ts.saturating_sub(self.elapsed)
    }
}

// ---------------------------------------------------------------------------
// do_sys_clock_nanosleep — primary handler
// ---------------------------------------------------------------------------

/// `clock_nanosleep(2)` syscall handler (POSIX.1-2024).
///
/// # Arguments
///
/// * `clock_id` — Raw clock identifier.
/// * `flags`    — 0 for relative, `TIMER_ABSTIME` for absolute.
/// * `request`  — Duration or absolute deadline.
///
/// # Returns
///
/// Remaining time on success (zero if fully slept).
///
/// # Errors
///
/// * [`Error::InvalidArgument`] — non-sleepable clock, invalid flags/timespec.
/// * [`Error::Interrupted`]     — interrupted by signal (remaining time valid).
pub fn do_sys_clock_nanosleep(clock_id: i32, flags: i32, request: &Timespec) -> Result<Timespec> {
    let req = SleepRequest::new(clock_id, flags, request)?;

    // Zero-duration relative sleep completes immediately.
    if !req.flags.is_absolute() && req.ts.is_zero() {
        return Ok(Timespec::zero());
    }

    // Stub: in a real kernel this would:
    // 1. Compute the expiry: now + request (relative) or request (absolute).
    // 2. Program an hrtimer and put the thread to sleep.
    // 3. On wakeup check: timer expired → Ok(zero); signal → Err(Interrupted).
    //
    // Here we model completion immediately (sleep always succeeds with no wait).
    Ok(Timespec::zero())
}

/// `nanosleep(2)` wrapper — relative sleep on `CLOCK_MONOTONIC`.
///
/// # Arguments
///
/// * `request` — Relative duration to sleep.
///
/// # Returns
///
/// Remaining time (zero on complete).
pub fn do_sys_nanosleep(request: &Timespec) -> Result<Timespec> {
    do_sys_clock_nanosleep(ClockId::Monotonic as i32, 0, request)
}

/// Restart an interrupted `clock_nanosleep`.
///
/// Uses a saved [`InterruptedSleep`] to re-issue the sleep with the
/// remaining time as the new duration.
pub fn restart_clock_nanosleep(saved: &InterruptedSleep) -> Result<Timespec> {
    let remaining = saved.remaining();
    if remaining.is_zero() {
        return Ok(Timespec::zero());
    }
    if saved.request.flags.is_absolute() {
        // Absolute: re-issue with original deadline.
        do_sys_clock_nanosleep(
            saved.request.clock as i32,
            saved.request.flags.raw(),
            &saved.request.ts,
        )
    } else {
        // Relative: re-issue with remaining duration.
        do_sys_clock_nanosleep(saved.request.clock as i32, 0, &remaining)
    }
}

// ---------------------------------------------------------------------------
// Sleep registry
// ---------------------------------------------------------------------------

/// Maximum concurrent tracked sleeps.
const MAX_SLEEPS: usize = 64;

struct SleepSlot {
    tid: u64,
    saved: InterruptedSleep,
    active: bool,
}

impl SleepSlot {
    const fn empty() -> Self {
        Self {
            tid: 0,
            saved: InterruptedSleep {
                request: SleepRequest {
                    clock: ClockId::Monotonic,
                    flags: SleepFlags::RELATIVE,
                    ts: Timespec::zero(),
                },
                elapsed: Timespec::zero(),
            },
            active: false,
        }
    }
}

/// Per-thread interrupted sleep registry.
pub struct SleepRegistry {
    slots: [SleepSlot; MAX_SLEEPS],
    count: usize,
}

impl SleepRegistry {
    /// Create an empty registry.
    pub const fn new() -> Self {
        Self {
            slots: [const { SleepSlot::empty() }; MAX_SLEEPS],
            count: 0,
        }
    }

    /// Save an interrupted sleep for thread `tid`.
    ///
    /// # Errors
    ///
    /// [`Error::OutOfMemory`] — registry full.
    pub fn save(&mut self, tid: u64, saved: InterruptedSleep) -> Result<()> {
        // Replace existing entry.
        for slot in self.slots.iter_mut() {
            if slot.active && slot.tid == tid {
                slot.saved = saved;
                return Ok(());
            }
        }
        // Allocate new.
        let free = self
            .slots
            .iter()
            .position(|s| !s.active)
            .ok_or(Error::OutOfMemory)?;
        self.slots[free].tid = tid;
        self.slots[free].saved = saved;
        self.slots[free].active = true;
        self.count += 1;
        Ok(())
    }

    /// Retrieve the saved sleep state for `tid`, if any.
    pub fn get(&self, tid: u64) -> Option<&InterruptedSleep> {
        self.slots
            .iter()
            .find(|s| s.active && s.tid == tid)
            .map(|s| &s.saved)
    }

    /// Remove the saved sleep state for `tid`.
    pub fn remove(&mut self, tid: u64) {
        for slot in self.slots.iter_mut() {
            if slot.active && slot.tid == tid {
                slot.active = false;
                self.count = self.count.saturating_sub(1);
                return;
            }
        }
    }

    /// Return the number of tracked sleeps.
    pub const fn count(&self) -> usize {
        self.count
    }
}

impl Default for SleepRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // --- ClockId ---

    #[test]
    fn clock_id_all_valid() {
        for i in 0..=9_i32 {
            assert!(ClockId::from_i32(i).is_ok(), "clock {i} should be valid");
        }
    }

    #[test]
    fn clock_id_unknown_rejected() {
        assert_eq!(ClockId::from_i32(10), Err(Error::InvalidArgument));
        assert_eq!(ClockId::from_i32(-1), Err(Error::InvalidArgument));
    }

    #[test]
    fn cpu_time_clocks_not_sleepable() {
        assert!(!ClockId::ProcessCputime.is_sleepable());
        assert!(!ClockId::ThreadCputime.is_sleepable());
    }

    #[test]
    fn alarm_clocks_detected() {
        assert!(ClockId::RealtimeAlarm.is_alarm());
        assert!(ClockId::BoottimeAlarm.is_alarm());
        assert!(!ClockId::Monotonic.is_alarm());
    }

    // --- SleepFlags ---

    #[test]
    fn flags_zero_and_abstime_valid() {
        assert!(SleepFlags::from_raw(0).is_ok());
        assert!(SleepFlags::from_raw(TIMER_ABSTIME).is_ok());
    }

    #[test]
    fn flags_unknown_bits_rejected() {
        assert_eq!(SleepFlags::from_raw(0x10), Err(Error::InvalidArgument));
    }

    // --- Timespec ---

    #[test]
    fn timespec_is_valid() {
        assert!(Timespec::new(0, 0).is_valid());
        assert!(Timespec::new(1, 999_999_999).is_valid());
        assert!(!Timespec::new(0, -1).is_valid());
        assert!(!Timespec::new(0, NSEC_PER_SEC).is_valid());
    }

    #[test]
    fn timespec_to_from_nanos_roundtrip() {
        let ts = Timespec::new(2, 500_000_000);
        let nanos = ts.to_nanos().unwrap();
        assert_eq!(nanos, 2_500_000_000);
        let back = Timespec::from_nanos(nanos);
        assert_eq!(back, ts);
    }

    #[test]
    fn timespec_saturating_sub_clamps() {
        let big = Timespec::new(10, 0);
        let small = Timespec::new(3, 0);
        let diff = big.saturating_sub(small);
        assert_eq!(diff.tv_sec, 7);
        let reverse = small.saturating_sub(big);
        assert!(reverse.is_zero());
    }

    // --- SleepRequest ---

    #[test]
    fn sleep_request_cpu_clock_rejected() {
        let ts = Timespec::new(1, 0);
        assert_eq!(
            SleepRequest::new(ClockId::ThreadCputime as i32, 0, &ts),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn sleep_request_invalid_timespec_rejected() {
        let bad = Timespec::new(0, -1);
        assert_eq!(
            SleepRequest::new(ClockId::Monotonic as i32, 0, &bad),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn sleep_request_valid_relative() {
        let ts = Timespec::new(1, 0);
        let req = SleepRequest::new(ClockId::Monotonic as i32, 0, &ts).unwrap();
        assert!(!req.flags.is_absolute());
    }

    #[test]
    fn sleep_request_valid_absolute() {
        let ts = Timespec::new(100, 0);
        let req = SleepRequest::new(ClockId::Realtime as i32, TIMER_ABSTIME, &ts).unwrap();
        assert!(req.flags.is_absolute());
    }

    // --- do_sys_clock_nanosleep ---

    #[test]
    fn zero_relative_returns_immediately() {
        let ts = Timespec::zero();
        let rem = do_sys_clock_nanosleep(ClockId::Monotonic as i32, 0, &ts).unwrap();
        assert!(rem.is_zero());
    }

    #[test]
    fn nonzero_relative_completes() {
        let ts = Timespec::new(0, 1000);
        let rem = do_sys_clock_nanosleep(ClockId::Monotonic as i32, 0, &ts).unwrap();
        assert!(rem.is_zero());
    }

    #[test]
    fn absolute_completes() {
        let ts = Timespec::new(1_000_000, 0);
        let rem = do_sys_clock_nanosleep(ClockId::Realtime as i32, TIMER_ABSTIME, &ts).unwrap();
        assert!(rem.is_zero());
    }

    #[test]
    fn nanosleep_wrapper() {
        let ts = Timespec::new(0, 500_000);
        let rem = do_sys_nanosleep(&ts).unwrap();
        assert!(rem.is_zero());
    }

    // --- InterruptedSleep ---

    #[test]
    fn interrupted_relative_remaining() {
        let request =
            SleepRequest::new(ClockId::Monotonic as i32, 0, &Timespec::new(10, 0)).unwrap();
        let saved = InterruptedSleep {
            request,
            elapsed: Timespec::new(3, 0),
        };
        let rem = saved.remaining();
        assert_eq!(rem.tv_sec, 7);
    }

    #[test]
    fn interrupted_absolute_remaining_is_zero() {
        let request = SleepRequest::new(
            ClockId::Realtime as i32,
            TIMER_ABSTIME,
            &Timespec::new(1000, 0),
        )
        .unwrap();
        let saved = InterruptedSleep {
            request,
            elapsed: Timespec::new(1, 0),
        };
        // Absolute sleeps do not report remaining time.
        assert!(saved.remaining().is_zero());
    }

    // --- restart_clock_nanosleep ---

    #[test]
    fn restart_relative_with_remaining() {
        let request =
            SleepRequest::new(ClockId::Monotonic as i32, 0, &Timespec::new(5, 0)).unwrap();
        let saved = InterruptedSleep {
            request,
            elapsed: Timespec::new(2, 0),
        };
        let rem = restart_clock_nanosleep(&saved).unwrap();
        assert!(rem.is_zero()); // Stub always completes immediately.
    }

    #[test]
    fn restart_fully_elapsed_returns_zero() {
        let request =
            SleepRequest::new(ClockId::Monotonic as i32, 0, &Timespec::new(1, 0)).unwrap();
        let saved = InterruptedSleep {
            request,
            elapsed: Timespec::new(5, 0), // More than requested.
        };
        let rem = restart_clock_nanosleep(&saved).unwrap();
        assert!(rem.is_zero());
    }

    // --- SleepRegistry ---

    #[test]
    fn registry_save_and_get() {
        let mut reg = SleepRegistry::new();
        let request =
            SleepRequest::new(ClockId::Monotonic as i32, 0, &Timespec::new(1, 0)).unwrap();
        let saved = InterruptedSleep {
            request,
            elapsed: Timespec::zero(),
        };
        reg.save(1, saved).unwrap();
        assert_eq!(reg.count(), 1);
        assert!(reg.get(1).is_some());
    }

    #[test]
    fn registry_remove() {
        let mut reg = SleepRegistry::new();
        let request =
            SleepRequest::new(ClockId::Monotonic as i32, 0, &Timespec::new(1, 0)).unwrap();
        let saved = InterruptedSleep {
            request,
            elapsed: Timespec::zero(),
        };
        reg.save(1, saved).unwrap();
        reg.remove(1);
        assert_eq!(reg.count(), 0);
        assert!(reg.get(1).is_none());
    }

    #[test]
    fn registry_overwrite_same_tid() {
        let mut reg = SleepRegistry::new();
        let make = |sec| {
            let r =
                SleepRequest::new(ClockId::Monotonic as i32, 0, &Timespec::new(sec, 0)).unwrap();
            InterruptedSleep {
                request: r,
                elapsed: Timespec::zero(),
            }
        };
        reg.save(1, make(1)).unwrap();
        reg.save(1, make(5)).unwrap();
        assert_eq!(reg.count(), 1);
        assert_eq!(reg.get(1).unwrap().request.ts.tv_sec, 5);
    }
}
