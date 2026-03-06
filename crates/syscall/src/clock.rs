// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! POSIX clock, timer, and memory locking syscall handlers.
//!
//! Implements `clock_gettime`, `clock_settime`, `clock_getres`,
//! `clock_nanosleep`, `nanosleep`, `mlock`, `munlock`, `mlockall`,
//! `munlockall`, and `mlock2` per POSIX.1-2024.

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Flag for absolute time in `clock_nanosleep`.
pub const TIMER_ABSTIME: i32 = 1;

/// Nanoseconds per second.
pub const NANOS_PER_SEC: i64 = 1_000_000_000;

/// Page size used for alignment validation (4 KiB).
const PAGE_SIZE: u64 = 4096;

// ---------------------------------------------------------------------------
// Timespec
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
    pub fn new(tv_sec: i64, tv_nsec: i64) -> Self {
        Self { tv_sec, tv_nsec }
    }

    /// Returns `true` if the nanosecond field is in `[0, 999_999_999]`.
    pub fn is_valid(&self) -> bool {
        self.tv_nsec >= 0 && self.tv_nsec < NANOS_PER_SEC
    }

    /// Convert to total nanoseconds.
    ///
    /// Returns `None` on overflow.
    pub fn to_nanos(&self) -> Option<i64> {
        self.tv_sec
            .checked_mul(NANOS_PER_SEC)
            .and_then(|s| s.checked_add(self.tv_nsec))
    }

    /// Construct a `Timespec` from total nanoseconds.
    pub fn from_nanos(nanos: i64) -> Self {
        let tv_sec = nanos / NANOS_PER_SEC;
        let tv_nsec = nanos % NANOS_PER_SEC;
        Self { tv_sec, tv_nsec }
    }

    /// A zero-valued timespec.
    pub fn zero() -> Self {
        Self {
            tv_sec: 0,
            tv_nsec: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// Itimerspec
// ---------------------------------------------------------------------------

/// POSIX `struct itimerspec` — interval timer specification.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Itimerspec {
    /// Timer period (zero = one-shot).
    pub it_interval: Timespec,
    /// Initial expiration.
    pub it_value: Timespec,
}

// ---------------------------------------------------------------------------
// ClockId
// ---------------------------------------------------------------------------

/// POSIX clock identifiers.
#[repr(i32)]
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
    pub fn from_i32(val: i32) -> Option<Self> {
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
}

// ---------------------------------------------------------------------------
// ClockState
// ---------------------------------------------------------------------------

/// Kernel-internal clock state tracker.
///
/// Tracks monotonic ticks, realtime offset, and boot time for use
/// by the clock syscall handlers.
#[derive(Default)]
pub struct ClockState {
    /// Cumulative monotonic nanoseconds since boot.
    monotonic_ticks: u64,
    /// Signed offset applied to monotonic to yield realtime.
    realtime_offset_ns: i64,
    /// Boot-time nanosecond snapshot.
    boot_time_ns: u64,
}

impl ClockState {
    /// Create a new `ClockState` with all counters at zero.
    pub fn new() -> Self {
        Self {
            monotonic_ticks: 0,
            realtime_offset_ns: 0,
            boot_time_ns: 0,
        }
    }

    /// Advance the monotonic counter by `elapsed_ns` nanoseconds.
    pub fn tick(&mut self, elapsed_ns: u64) {
        self.monotonic_ticks = self.monotonic_ticks.saturating_add(elapsed_ns);
    }

    /// Current monotonic time in nanoseconds.
    pub fn get_monotonic_ns(&self) -> u64 {
        self.monotonic_ticks
    }

    /// Current realtime in nanoseconds (monotonic + offset).
    pub fn get_realtime_ns(&self) -> i64 {
        (self.monotonic_ticks as i64).saturating_add(self.realtime_offset_ns)
    }

    /// Set the realtime clock by adjusting the offset.
    pub fn set_realtime_ns(&mut self, ns: i64) {
        self.realtime_offset_ns = ns.saturating_sub(self.monotonic_ticks as i64);
    }

    /// Time since boot in nanoseconds.
    pub fn get_boottime_ns(&self) -> u64 {
        self.monotonic_ticks.saturating_add(self.boot_time_ns)
    }
}

// ---------------------------------------------------------------------------
// MlockFlags
// ---------------------------------------------------------------------------

/// Flags for `mlockall` / `mlock2`.
pub struct MlockFlags;

impl MlockFlags {
    /// Lock all currently mapped pages.
    pub const MCL_CURRENT: i32 = 1;
    /// Lock pages mapped in the future.
    pub const MCL_FUTURE: i32 = 2;
    /// Lock pages when they are faulted in.
    pub const MCL_ONFAULT: i32 = 4;
}

/// All valid `mlockall` flag bits.
const MLOCKALL_VALID: i32 =
    MlockFlags::MCL_CURRENT | MlockFlags::MCL_FUTURE | MlockFlags::MCL_ONFAULT;

/// All valid `mlock2` flag bits.
const MLOCK2_VALID: i32 = MlockFlags::MCL_ONFAULT;

// ---------------------------------------------------------------------------
// Clock syscall handlers
// ---------------------------------------------------------------------------

/// `clock_gettime` — retrieve the time of the specified clock.
///
/// Returns a stub time derived from a conceptual tick counter.
/// Real implementations will read hardware timers via the HAL.
pub fn do_clock_gettime(clock_id: i32) -> Result<Timespec> {
    let id = ClockId::from_i32(clock_id).ok_or(Error::InvalidArgument)?;

    // Stub: return a deterministic value per clock type.
    let ns: i64 = match id {
        ClockId::Realtime | ClockId::RealtimeCoarse => {
            // Epoch-based stub: 2026-01-01T00:00:00Z
            1_767_225_600_i64.saturating_mul(NANOS_PER_SEC)
        }
        ClockId::Monotonic | ClockId::MonotonicRaw | ClockId::MonotonicCoarse => 0,
        ClockId::ProcessCputime | ClockId::ThreadCputime => 0,
        ClockId::Boottime => 0,
    };

    Ok(Timespec::from_nanos(ns))
}

/// `clock_getres` — get the resolution of the specified clock.
pub fn do_clock_getres(clock_id: i32) -> Result<Timespec> {
    let id = ClockId::from_i32(clock_id).ok_or(Error::InvalidArgument)?;

    let res_ns: i64 = match id {
        ClockId::Monotonic | ClockId::MonotonicRaw | ClockId::Realtime => 1, // 1 ns
        ClockId::RealtimeCoarse | ClockId::MonotonicCoarse => 4_000_000,     // 4 ms
        ClockId::ProcessCputime | ClockId::ThreadCputime => 1,
        ClockId::Boottime => 1,
    };

    Ok(Timespec::new(0, res_ns))
}

/// `clock_settime` — set the specified clock.
///
/// Only `CLOCK_REALTIME` is settable per POSIX.
pub fn do_clock_settime(clock_id: i32, ts: &Timespec) -> Result<()> {
    let id = ClockId::from_i32(clock_id).ok_or(Error::InvalidArgument)?;

    if !ts.is_valid() {
        return Err(Error::InvalidArgument);
    }

    match id {
        ClockId::Realtime => {
            // Stub: in a real kernel we would update the
            // realtime offset in the global ClockState.
            Ok(())
        }
        _ => Err(Error::PermissionDenied),
    }
}

/// `clock_nanosleep` — high-resolution sleep on a specific clock.
///
/// `flags` may include [`TIMER_ABSTIME`] for absolute deadlines.
/// Returns the remaining time; a zero timespec means the sleep
/// completed (stub behaviour).
pub fn do_clock_nanosleep(clock_id: i32, flags: i32, request: &Timespec) -> Result<Timespec> {
    let id = ClockId::from_i32(clock_id).ok_or(Error::InvalidArgument)?;

    // POSIX: CLOCK_THREAD_CPUTIME_ID not allowed.
    if id == ClockId::ThreadCputime {
        return Err(Error::InvalidArgument);
    }

    if !request.is_valid() {
        return Err(Error::InvalidArgument);
    }

    // Validate flags: only TIMER_ABSTIME is defined.
    if flags & !TIMER_ABSTIME != 0 {
        return Err(Error::InvalidArgument);
    }

    // Stub: sleep completes immediately.
    Ok(Timespec::zero())
}

// ---------------------------------------------------------------------------
// Sleep handler
// ---------------------------------------------------------------------------

/// `nanosleep` — suspend execution for a specified duration.
///
/// Wrapper around [`do_clock_nanosleep`] using `CLOCK_MONOTONIC`.
pub fn do_nanosleep(request: &Timespec) -> Result<Timespec> {
    do_clock_nanosleep(ClockId::Monotonic as i32, 0, request)
}

// ---------------------------------------------------------------------------
// Memory locking handlers
// ---------------------------------------------------------------------------

/// Validate that `addr` is page-aligned and the range is non-empty.
fn validate_mlock_range(addr: u64, len: u64) -> Result<()> {
    if addr % PAGE_SIZE != 0 {
        return Err(Error::InvalidArgument);
    }
    if len == 0 {
        return Err(Error::InvalidArgument);
    }
    Ok(())
}

/// `mlock` — lock pages in memory.
///
/// Prevents the specified address range from being paged out.
pub fn do_mlock(addr: u64, len: u64) -> Result<()> {
    validate_mlock_range(addr, len)?;
    // Stub: record lock in MM subsystem.
    Ok(())
}

/// `munlock` — unlock pages.
pub fn do_munlock(addr: u64, len: u64) -> Result<()> {
    validate_mlock_range(addr, len)?;
    // Stub: remove lock from MM subsystem.
    Ok(())
}

/// `mlockall` — lock all current and/or future mappings.
pub fn do_mlockall(flags: i32) -> Result<()> {
    if flags == 0 || (flags & !MLOCKALL_VALID) != 0 {
        return Err(Error::InvalidArgument);
    }
    // Stub: apply flags to process memory policy.
    Ok(())
}

/// `munlockall` — unlock all pages of the calling process.
pub fn do_munlockall() -> Result<()> {
    // Always succeeds.
    Ok(())
}

/// `mlock2` — lock pages with additional flags.
///
/// Supports `MLOCK_ONFAULT` to defer locking until page fault.
pub fn do_mlock2(addr: u64, len: u64, flags: i32) -> Result<()> {
    validate_mlock_range(addr, len)?;
    if (flags & !MLOCK2_VALID) != 0 {
        return Err(Error::InvalidArgument);
    }
    // Stub: record lock with flags in MM subsystem.
    Ok(())
}
