// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `clock_nanosleep(2)` — high-resolution sleep with specifiable clock.
//!
//! Implements the POSIX.1-2024 `clock_nanosleep` interface with support for
//! multiple clock sources, both absolute and relative sleep modes, and signal
//! interruption with remaining time reporting.
//!
//! # Operations
//!
//! | Syscall            | Handler                  | Purpose                       |
//! |--------------------|--------------------------|-------------------------------|
//! | `clock_nanosleep`  | [`sys_clock_nanosleep`]  | Sleep on a specific clock     |
//! | `nanosleep`        | [`do_nanosleep`]         | Monotonic relative sleep      |
//! | restart            | [`restart_nanosleep`]    | Resume interrupted sleep      |
//!
//! # Clock IDs
//!
//! | Clock                 | ID  | Sleepable | Description                     |
//! |-----------------------|-----|-----------|--------------------------------|
//! | `CLOCK_REALTIME`      | 0   | Yes       | Wall-clock time; settable       |
//! | `CLOCK_MONOTONIC`     | 1   | Yes       | Monotonic; not settable         |
//! | `CLOCK_PROCESS_CPUTIME_ID` | 2 | No  | Per-process CPU time            |
//! | `CLOCK_THREAD_CPUTIME_ID`  | 3 | No  | Per-thread CPU time (POSIX ban) |
//! | `CLOCK_MONOTONIC_RAW` | 4   | Yes       | Raw monotonic (no NTP)          |
//! | `CLOCK_REALTIME_COARSE` | 5 | Yes       | Coarse realtime                 |
//! | `CLOCK_MONOTONIC_COARSE` | 6 | Yes      | Coarse monotonic                |
//! | `CLOCK_BOOTTIME`      | 7   | Yes       | Including suspend time          |
//!
//! # POSIX conformance
//!
//! - POSIX.1-2024: `clock_nanosleep()`
//! - TIMER_ABSTIME flag for absolute deadlines
//! - EINVAL for CPU-time clocks (POSIX requirement)
//! - EINTR when interrupted by signal, remaining time in rmtp
//!
//! # References
//!
//! - POSIX.1-2024: `clock_nanosleep()`
//! - Linux: `kernel/time/hrtimer.c`, `kernel/time/posix-timers.c`

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Flag for absolute time in `clock_nanosleep`.
pub const TIMER_ABSTIME: i32 = 1;

/// Nanoseconds per second.
pub const NANOS_PER_SEC: i64 = 1_000_000_000;

/// Nanoseconds per millisecond.
pub const NANOS_PER_MSEC: i64 = 1_000_000;

/// Nanoseconds per microsecond.
pub const NANOS_PER_USEC: i64 = 1_000;

// ---------------------------------------------------------------------------
// ClockId — clock source identifier
// ---------------------------------------------------------------------------

/// POSIX clock identifiers supported by `clock_nanosleep`.
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClockId {
    /// Wall-clock time; settable.
    Realtime = 0,
    /// Monotonic clock; not settable.
    Monotonic = 1,
    /// Per-process CPU-time clock.
    ProcessCputime = 2,
    /// Per-thread CPU-time clock.
    ThreadCputime = 3,
    /// Raw monotonic (no NTP adjustment).
    MonotonicRaw = 4,
    /// Coarse realtime (faster, less precise).
    RealtimeCoarse = 5,
    /// Coarse monotonic (faster, less precise).
    MonotonicCoarse = 6,
    /// Time since boot, including suspend.
    Boottime = 7,
}

impl ClockId {
    /// Convert a raw `i32` to a `ClockId`, if valid.
    ///
    /// Returns `Err(Error::InvalidArgument)` for unknown values.
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
            _ => Err(Error::InvalidArgument),
        }
    }

    /// Return `true` if this clock supports `clock_nanosleep`.
    ///
    /// Per POSIX, `CLOCK_THREAD_CPUTIME_ID` is not allowed.
    /// We also disallow `CLOCK_PROCESS_CPUTIME_ID` per Linux convention.
    pub const fn is_sleepable(self) -> bool {
        !matches!(self, Self::ProcessCputime | Self::ThreadCputime)
    }
}

// ---------------------------------------------------------------------------
// SleepFlags — validated sleep flags
// ---------------------------------------------------------------------------

/// Validated sleep flags for `clock_nanosleep`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SleepFlags(i32);

impl SleepFlags {
    /// No flags set (relative sleep).
    pub const NONE: Self = Self(0);
    /// Absolute time flag.
    pub const ABSTIME: Self = Self(TIMER_ABSTIME);

    /// Create validated sleep flags from a raw `i32`.
    ///
    /// Returns `Err(Error::InvalidArgument)` if unknown bits are set.
    pub fn from_raw(flags: i32) -> Result<Self> {
        if flags & !TIMER_ABSTIME != 0 {
            return Err(Error::InvalidArgument);
        }
        Ok(Self(flags))
    }

    /// Return `true` if `TIMER_ABSTIME` is set.
    pub const fn is_absolute(self) -> bool {
        self.0 & TIMER_ABSTIME != 0
    }

    /// Return the raw flags value.
    pub const fn raw(self) -> i32 {
        self.0
    }
}

// ---------------------------------------------------------------------------
// Timespec — time representation
// ---------------------------------------------------------------------------

/// POSIX `struct timespec` — represents a point in time or a duration.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Timespec {
    /// Whole seconds.
    pub tv_sec: i64,
    /// Nanoseconds (must be in `0..NANOS_PER_SEC`).
    pub tv_nsec: i64,
}

impl Timespec {
    /// Create a new `Timespec` from seconds and nanoseconds.
    pub const fn new(tv_sec: i64, tv_nsec: i64) -> Self {
        Self { tv_sec, tv_nsec }
    }

    /// A zero-valued timespec.
    pub const fn zero() -> Self {
        Self {
            tv_sec: 0,
            tv_nsec: 0,
        }
    }

    /// Returns `true` if the nanosecond field is in `[0, 999_999_999]`.
    pub const fn is_valid(&self) -> bool {
        self.tv_nsec >= 0 && self.tv_nsec < NANOS_PER_SEC
    }

    /// Returns `true` if this timespec represents zero duration.
    pub const fn is_zero(&self) -> bool {
        self.tv_sec == 0 && self.tv_nsec == 0
    }

    /// Convert to total nanoseconds.  Returns `None` on overflow.
    pub fn to_nanos(&self) -> Option<i64> {
        self.tv_sec
            .checked_mul(NANOS_PER_SEC)
            .and_then(|s| s.checked_add(self.tv_nsec))
    }

    /// Construct a `Timespec` from total nanoseconds.
    pub fn from_nanos(nanos: i64) -> Self {
        if nanos <= 0 {
            return Self::zero();
        }
        let tv_sec = nanos / NANOS_PER_SEC;
        let tv_nsec = nanos % NANOS_PER_SEC;
        Self { tv_sec, tv_nsec }
    }

    /// Subtract `other` from `self`, clamping to zero.
    ///
    /// Returns the remaining duration after subtracting elapsed time.
    pub fn saturating_sub(&self, other: &Timespec) -> Self {
        let self_ns = self.to_nanos().unwrap_or(0);
        let other_ns = other.to_nanos().unwrap_or(0);
        let diff = self_ns.saturating_sub(other_ns);
        if diff <= 0 {
            Self::zero()
        } else {
            Self::from_nanos(diff)
        }
    }

    /// Add two timespecs, saturating on overflow.
    pub fn saturating_add(&self, other: &Timespec) -> Self {
        let self_ns = self.to_nanos().unwrap_or(i64::MAX);
        let other_ns = other.to_nanos().unwrap_or(i64::MAX);
        let sum = self_ns.saturating_add(other_ns);
        Self::from_nanos(sum)
    }

    /// Compare two timespecs.  Returns negative if `self < other`,
    /// zero if equal, positive if `self > other`.
    pub fn cmp_ts(&self, other: &Timespec) -> i64 {
        let self_ns = self.to_nanos().unwrap_or(0);
        let other_ns = other.to_nanos().unwrap_or(0);
        self_ns.saturating_sub(other_ns)
    }
}

// ---------------------------------------------------------------------------
// SleepState — kernel-internal sleep state tracker
// ---------------------------------------------------------------------------

/// Kernel-internal state for an in-progress `clock_nanosleep`.
///
/// Tracks the original request parameters so that an interrupted sleep
/// can be restarted with the correct remaining time.
#[derive(Debug, Clone, Copy)]
pub struct SleepState {
    /// Clock source for the sleep.
    pub clock_id: ClockId,
    /// Original flags (absolute vs relative).
    pub flags: SleepFlags,
    /// Original requested time (absolute deadline or duration).
    pub request: Timespec,
    /// Time at which the sleep was started (for relative sleeps).
    pub start_time: Timespec,
    /// Elapsed time so far (accumulated across restarts).
    pub elapsed: Timespec,
    /// Whether the sleep was interrupted by a signal.
    pub interrupted: bool,
    /// Whether the sleep has completed.
    pub completed: bool,
}

impl SleepState {
    /// Create a new sleep state for a `clock_nanosleep` request.
    pub const fn new(
        clock_id: ClockId,
        flags: SleepFlags,
        request: Timespec,
        start_time: Timespec,
    ) -> Self {
        Self {
            clock_id,
            flags,
            request,
            start_time,
            elapsed: Timespec::zero(),
            interrupted: false,
            completed: false,
        }
    }

    /// Compute the remaining time for an interrupted relative sleep.
    ///
    /// For absolute sleeps, the remaining time is not meaningful (POSIX
    /// does not update `rmtp` for absolute sleeps).
    pub fn remaining(&self) -> Timespec {
        if self.flags.is_absolute() {
            // Per POSIX: absolute sleeps do not update rmtp.
            return Timespec::zero();
        }
        self.request.saturating_sub(&self.elapsed)
    }

    /// Mark the sleep as complete.
    pub fn complete(&mut self) {
        self.completed = true;
    }

    /// Mark the sleep as interrupted.
    pub fn interrupt(&mut self, elapsed: Timespec) {
        self.interrupted = true;
        self.elapsed = elapsed;
    }
}

// ---------------------------------------------------------------------------
// SleepEntry — per-thread sleep tracking
// ---------------------------------------------------------------------------

/// Maximum concurrent sleep entries.
const MAX_SLEEP_ENTRIES: usize = 64;

/// Per-thread sleep tracking entry.
struct SleepEntry {
    /// Thread ID.
    tid: u64,
    /// Sleep state.
    state: SleepState,
    /// Whether this entry is in use.
    in_use: bool,
}

impl SleepEntry {
    /// Create an inactive entry.
    const fn new() -> Self {
        Self {
            tid: 0,
            state: SleepState {
                clock_id: ClockId::Monotonic,
                flags: SleepFlags::NONE,
                request: Timespec::zero(),
                start_time: Timespec::zero(),
                elapsed: Timespec::zero(),
                interrupted: false,
                completed: false,
            },
            in_use: false,
        }
    }
}

/// Registry tracking active sleep operations per thread.
pub struct SleepRegistry {
    entries: [SleepEntry; MAX_SLEEP_ENTRIES],
    count: usize,
}

impl SleepRegistry {
    /// Create an empty registry.
    pub const fn new() -> Self {
        Self {
            entries: [const { SleepEntry::new() }; MAX_SLEEP_ENTRIES],
            count: 0,
        }
    }

    /// Return the number of active sleep entries.
    pub const fn count(&self) -> usize {
        self.count
    }

    /// Return `true` if there are no active sleep entries.
    pub const fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Register a sleep for a thread.
    ///
    /// # Errors
    ///
    /// [`Error::OutOfMemory`] if the registry is full.
    pub fn register(&mut self, tid: u64, state: SleepState) -> Result<()> {
        // Replace existing entry for this tid.
        for entry in self.entries.iter_mut() {
            if entry.in_use && entry.tid == tid {
                entry.state = state;
                return Ok(());
            }
        }
        // Allocate new entry.
        for entry in self.entries.iter_mut() {
            if !entry.in_use {
                entry.tid = tid;
                entry.state = state;
                entry.in_use = true;
                self.count += 1;
                return Ok(());
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Remove the sleep entry for a thread.
    pub fn remove(&mut self, tid: u64) {
        for entry in self.entries.iter_mut() {
            if entry.in_use && entry.tid == tid {
                entry.in_use = false;
                entry.tid = 0;
                self.count = self.count.saturating_sub(1);
                return;
            }
        }
    }

    /// Get the sleep state for a thread, if any.
    pub fn get(&self, tid: u64) -> Option<&SleepState> {
        self.entries
            .iter()
            .find(|e| e.in_use && e.tid == tid)
            .map(|e| &e.state)
    }
}

impl Default for SleepRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// sys_clock_nanosleep — main syscall handler
// ---------------------------------------------------------------------------

/// `clock_nanosleep` syscall handler (POSIX.1-2024).
///
/// Suspends the calling thread until the specified time interval has
/// elapsed on the given clock, or a signal is delivered.
///
/// # Arguments
///
/// * `clock_id` — Raw clock identifier.
/// * `flags`    — 0 for relative sleep, `TIMER_ABSTIME` for absolute.
/// * `request`  — Requested sleep time (duration or absolute deadline).
///
/// # Returns
///
/// The remaining time on success (zero if the sleep completed).
///
/// # Errors
///
/// * [`Error::InvalidArgument`]  — invalid clock ID, flags, or timespec.
/// * [`Error::Interrupted`]      — interrupted by signal (remaining time
///                                  is in the return value's remaining field).
///
/// # POSIX conformance
///
/// - `CLOCK_THREAD_CPUTIME_ID` returns EINVAL per POSIX requirement.
/// - For relative sleeps, the remaining time is computed; for absolute
///   sleeps, no remaining time is reported.
pub fn sys_clock_nanosleep(clock_id: i32, flags: i32, request: &Timespec) -> Result<Timespec> {
    let id = ClockId::from_i32(clock_id)?;

    // POSIX: clock_nanosleep shall fail for CPU-time clocks.
    if !id.is_sleepable() {
        return Err(Error::InvalidArgument);
    }

    let sleep_flags = SleepFlags::from_raw(flags)?;

    // Validate the timespec.
    if !request.is_valid() {
        return Err(Error::InvalidArgument);
    }

    // For relative sleep with zero duration, return immediately.
    if !sleep_flags.is_absolute() && request.is_zero() {
        return Ok(Timespec::zero());
    }

    // Stub: in a real kernel, we would:
    // 1. Compute the deadline (for relative: now + request; for absolute: request)
    // 2. Add the thread to a timer wait queue
    // 3. Context-switch to the next runnable thread
    // 4. On wakeup, check if deadline expired or signal arrived
    //
    // For now, the sleep completes immediately.
    Ok(Timespec::zero())
}

// ---------------------------------------------------------------------------
// do_nanosleep — POSIX nanosleep wrapper
// ---------------------------------------------------------------------------

/// `nanosleep` syscall handler.
///
/// Equivalent to `clock_nanosleep(CLOCK_MONOTONIC, 0, request, rmtp)`.
///
/// # Arguments
///
/// * `request` — Duration to sleep.
///
/// # Returns
///
/// Remaining time (zero if complete).
///
/// # Errors
///
/// Same as [`sys_clock_nanosleep`].
pub fn do_nanosleep(request: &Timespec) -> Result<Timespec> {
    sys_clock_nanosleep(ClockId::Monotonic as i32, 0, request)
}

// ---------------------------------------------------------------------------
// restart_nanosleep — restart an interrupted sleep
// ---------------------------------------------------------------------------

/// Restart an interrupted `clock_nanosleep`.
///
/// Uses the saved sleep state to compute the remaining time and
/// re-issue the sleep with the correct parameters.
///
/// # Arguments
///
/// * `state` — The saved sleep state from the interrupted call.
///
/// # Returns
///
/// The remaining time (zero if complete).
///
/// # Errors
///
/// Same as [`sys_clock_nanosleep`].
pub fn restart_nanosleep(state: &SleepState) -> Result<Timespec> {
    if state.completed {
        return Ok(Timespec::zero());
    }

    if state.flags.is_absolute() {
        // For absolute sleeps, just re-issue with the same deadline.
        sys_clock_nanosleep(state.clock_id as i32, state.flags.raw(), &state.request)
    } else {
        // For relative sleeps, compute the remaining duration.
        let remaining = state.remaining();
        if remaining.is_zero() {
            return Ok(Timespec::zero());
        }
        sys_clock_nanosleep(state.clock_id as i32, 0, &remaining)
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // --- ClockId ---

    #[test]
    fn clock_id_valid_conversions() {
        for i in 0..=7 {
            assert!(ClockId::from_i32(i).is_ok());
        }
    }

    #[test]
    fn clock_id_invalid() {
        assert_eq!(ClockId::from_i32(8), Err(Error::InvalidArgument));
        assert_eq!(ClockId::from_i32(-1), Err(Error::InvalidArgument));
    }

    #[test]
    fn clock_id_sleepable() {
        assert!(ClockId::Realtime.is_sleepable());
        assert!(ClockId::Monotonic.is_sleepable());
        assert!(ClockId::MonotonicRaw.is_sleepable());
        assert!(ClockId::Boottime.is_sleepable());
        assert!(!ClockId::ThreadCputime.is_sleepable());
        assert!(!ClockId::ProcessCputime.is_sleepable());
    }

    // --- SleepFlags ---

    #[test]
    fn sleep_flags_valid() {
        assert!(SleepFlags::from_raw(0).is_ok());
        assert!(SleepFlags::from_raw(TIMER_ABSTIME).is_ok());
    }

    #[test]
    fn sleep_flags_invalid() {
        assert_eq!(SleepFlags::from_raw(0x10), Err(Error::InvalidArgument));
    }

    #[test]
    fn sleep_flags_is_absolute() {
        assert!(!SleepFlags::NONE.is_absolute());
        assert!(SleepFlags::ABSTIME.is_absolute());
    }

    // --- Timespec ---

    #[test]
    fn timespec_valid() {
        assert!(Timespec::new(0, 0).is_valid());
        assert!(Timespec::new(1, 999_999_999).is_valid());
        assert!(!Timespec::new(0, -1).is_valid());
        assert!(!Timespec::new(0, NANOS_PER_SEC).is_valid());
    }

    #[test]
    fn timespec_is_zero() {
        assert!(Timespec::zero().is_zero());
        assert!(!Timespec::new(1, 0).is_zero());
    }

    #[test]
    fn timespec_to_nanos() {
        assert_eq!(
            Timespec::new(1, 500_000_000).to_nanos(),
            Some(1_500_000_000)
        );
    }

    #[test]
    fn timespec_from_nanos() {
        let ts = Timespec::from_nanos(1_500_000_000);
        assert_eq!(ts.tv_sec, 1);
        assert_eq!(ts.tv_nsec, 500_000_000);
    }

    #[test]
    fn timespec_saturating_sub() {
        let a = Timespec::new(5, 0);
        let b = Timespec::new(3, 0);
        let c = a.saturating_sub(&b);
        assert_eq!(c.tv_sec, 2);
        assert_eq!(c.tv_nsec, 0);
    }

    #[test]
    fn timespec_saturating_sub_clamp() {
        let a = Timespec::new(1, 0);
        let b = Timespec::new(5, 0);
        let c = a.saturating_sub(&b);
        assert!(c.is_zero());
    }

    #[test]
    fn timespec_saturating_add() {
        let a = Timespec::new(1, 500_000_000);
        let b = Timespec::new(2, 600_000_000);
        let c = a.saturating_add(&b);
        assert_eq!(c.tv_sec, 4);
        assert_eq!(c.tv_nsec, 100_000_000);
    }

    #[test]
    fn timespec_cmp() {
        let a = Timespec::new(5, 0);
        let b = Timespec::new(3, 0);
        assert!(a.cmp_ts(&b) > 0);
        assert!(b.cmp_ts(&a) < 0);
        assert_eq!(a.cmp_ts(&a), 0);
    }

    // --- sys_clock_nanosleep ---

    #[test]
    fn nanosleep_cpu_time_clock_rejected() {
        let req = Timespec::new(1, 0);
        assert_eq!(
            sys_clock_nanosleep(ClockId::ThreadCputime as i32, 0, &req,),
            Err(Error::InvalidArgument)
        );
        assert_eq!(
            sys_clock_nanosleep(ClockId::ProcessCputime as i32, 0, &req,),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn nanosleep_invalid_timespec() {
        let req = Timespec::new(0, -1);
        assert_eq!(
            sys_clock_nanosleep(ClockId::Monotonic as i32, 0, &req,),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn nanosleep_invalid_flags() {
        let req = Timespec::new(1, 0);
        assert_eq!(
            sys_clock_nanosleep(ClockId::Monotonic as i32, 0x10, &req,),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn nanosleep_zero_duration_returns_immediately() {
        let req = Timespec::zero();
        let rem = sys_clock_nanosleep(ClockId::Monotonic as i32, 0, &req).unwrap();
        assert!(rem.is_zero());
    }

    #[test]
    fn nanosleep_relative_completes() {
        let req = Timespec::new(0, 100_000);
        let rem = sys_clock_nanosleep(ClockId::Monotonic as i32, 0, &req).unwrap();
        assert!(rem.is_zero());
    }

    #[test]
    fn nanosleep_absolute_completes() {
        let req = Timespec::new(0, 100_000);
        let rem = sys_clock_nanosleep(ClockId::Monotonic as i32, TIMER_ABSTIME, &req).unwrap();
        assert!(rem.is_zero());
    }

    // --- do_nanosleep ---

    #[test]
    fn do_nanosleep_completes() {
        let req = Timespec::new(0, 1_000);
        let rem = do_nanosleep(&req).unwrap();
        assert!(rem.is_zero());
    }

    // --- restart_nanosleep ---

    #[test]
    fn restart_completed_returns_zero() {
        let mut state = SleepState::new(
            ClockId::Monotonic,
            SleepFlags::NONE,
            Timespec::new(1, 0),
            Timespec::zero(),
        );
        state.complete();
        let rem = restart_nanosleep(&state).unwrap();
        assert!(rem.is_zero());
    }

    #[test]
    fn restart_absolute_reissues() {
        let state = SleepState::new(
            ClockId::Monotonic,
            SleepFlags::ABSTIME,
            Timespec::new(100, 0),
            Timespec::zero(),
        );
        let rem = restart_nanosleep(&state).unwrap();
        assert!(rem.is_zero());
    }

    #[test]
    fn restart_relative_with_remaining() {
        let mut state = SleepState::new(
            ClockId::Monotonic,
            SleepFlags::NONE,
            Timespec::new(5, 0),
            Timespec::zero(),
        );
        state.interrupt(Timespec::new(2, 0));
        let remaining = state.remaining();
        assert_eq!(remaining.tv_sec, 3);
        let rem = restart_nanosleep(&state).unwrap();
        assert!(rem.is_zero());
    }

    // --- SleepState ---

    #[test]
    fn sleep_state_remaining_absolute() {
        let state = SleepState::new(
            ClockId::Monotonic,
            SleepFlags::ABSTIME,
            Timespec::new(100, 0),
            Timespec::zero(),
        );
        // Absolute sleeps do not report remaining time.
        assert!(state.remaining().is_zero());
    }

    #[test]
    fn sleep_state_remaining_relative() {
        let mut state = SleepState::new(
            ClockId::Monotonic,
            SleepFlags::NONE,
            Timespec::new(10, 0),
            Timespec::zero(),
        );
        state.interrupt(Timespec::new(3, 0));
        let rem = state.remaining();
        assert_eq!(rem.tv_sec, 7);
        assert_eq!(rem.tv_nsec, 0);
    }

    // --- SleepRegistry ---

    #[test]
    fn registry_register_and_get() {
        let mut reg = SleepRegistry::new();
        let state = SleepState::new(
            ClockId::Monotonic,
            SleepFlags::NONE,
            Timespec::new(1, 0),
            Timespec::zero(),
        );
        reg.register(1, state).unwrap();
        assert!(reg.get(1).is_some());
        assert_eq!(reg.count(), 1);
    }

    #[test]
    fn registry_remove() {
        let mut reg = SleepRegistry::new();
        let state = SleepState::new(
            ClockId::Monotonic,
            SleepFlags::NONE,
            Timespec::new(1, 0),
            Timespec::zero(),
        );
        reg.register(1, state).unwrap();
        reg.remove(1);
        assert!(reg.get(1).is_none());
        assert_eq!(reg.count(), 0);
    }

    #[test]
    fn registry_overwrite_existing() {
        let mut reg = SleepRegistry::new();
        let state1 = SleepState::new(
            ClockId::Monotonic,
            SleepFlags::NONE,
            Timespec::new(1, 0),
            Timespec::zero(),
        );
        let state2 = SleepState::new(
            ClockId::Realtime,
            SleepFlags::ABSTIME,
            Timespec::new(5, 0),
            Timespec::zero(),
        );
        reg.register(1, state1).unwrap();
        reg.register(1, state2).unwrap();
        assert_eq!(reg.count(), 1);
        let got = reg.get(1).unwrap();
        assert_eq!(got.clock_id, ClockId::Realtime);
    }
}
