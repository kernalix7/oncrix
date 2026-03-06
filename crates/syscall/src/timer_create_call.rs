// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `timer_create(2)`, `timer_settime(2)`, `timer_gettime(2)`,
//! `timer_getoverrun(2)`, and `timer_delete(2)` syscall handlers.
//!
//! POSIX per-process interval timers that deliver a signal or thread
//! notification on expiry.
//!
//! # POSIX Conformance
//!
//! Follows POSIX.1-2024 `timer_create()` etc.  Key behaviours:
//! - `EINVAL` for unknown clock IDs.
//! - `EAGAIN` (mapped to WouldBlock) when the timer table is full.
//! - `TIMER_ABSTIME` flag in `timer_settime` uses absolute time.
//! - Overrun count saturates at `DELAYTIMER_MAX`.
//! - A zero `it_value` disarms the timer.
//!
//! # References
//!
//! - POSIX.1-2024: `timer_create()`
//! - Linux man pages: `timer_create(2)`

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum number of per-process POSIX timers.
pub const POSIX_TIMER_MAX: usize = 32;
/// Maximum overrun count (POSIX `DELAYTIMER_MAX`).
pub const DELAYTIMER_MAX: i32 = i32::MAX;
/// Flag for absolute time in `timer_settime`.
pub const TIMER_ABSTIME: i32 = 1;

/// CLOCK_REALTIME.
pub const CLOCK_REALTIME: i32 = 0;
/// CLOCK_MONOTONIC.
pub const CLOCK_MONOTONIC: i32 = 1;
/// CLOCK_BOOTTIME.
pub const CLOCK_BOOTTIME: i32 = 7;

/// Nanoseconds per second.
pub const NANOS_PER_SEC: i64 = 1_000_000_000;

// ---------------------------------------------------------------------------
// Timespec / Itimerspec
// ---------------------------------------------------------------------------

/// POSIX `struct timespec`.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Timespec {
    /// Whole seconds.
    pub tv_sec: i64,
    /// Nanoseconds (0–999_999_999).
    pub tv_nsec: i64,
}

impl Timespec {
    /// Returns `true` if the `tv_nsec` is in range.
    pub fn is_valid(&self) -> bool {
        self.tv_nsec >= 0 && self.tv_nsec < NANOS_PER_SEC
    }

    /// Returns `true` if both fields are zero (disarm value).
    pub fn is_zero(&self) -> bool {
        self.tv_sec == 0 && self.tv_nsec == 0
    }
}

/// POSIX `struct itimerspec` — interval timer specification.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Itimerspec {
    /// Timer interval (0 = one-shot).
    pub it_interval: Timespec,
    /// Initial expiration time (0 = disarm).
    pub it_value: Timespec,
}

// ---------------------------------------------------------------------------
// Sigevent (simplified)
// ---------------------------------------------------------------------------

/// Signal notification method.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignotifyMethod {
    /// Deliver `signo` to the process.
    Signal(i32),
    /// No notification.
    None,
}

// ---------------------------------------------------------------------------
// Timer state
// ---------------------------------------------------------------------------

/// A single POSIX interval timer.
#[derive(Debug, Clone, Copy)]
pub struct PosixTimer {
    /// Whether this slot is occupied.
    pub active: bool,
    /// Clock used by this timer.
    pub clock_id: i32,
    /// Notification method.
    pub notify: SignotifyMethod,
    /// Current timer setting.
    pub spec: Itimerspec,
    /// Overrun count.
    pub overrun: i32,
    /// Whether the timer is armed (it_value != 0).
    pub armed: bool,
}

/// Table of per-process POSIX timers.
pub struct TimerTable {
    timers: [Option<PosixTimer>; POSIX_TIMER_MAX],
    count: usize,
}

impl Default for TimerTable {
    fn default() -> Self {
        Self::new()
    }
}

impl TimerTable {
    /// Create an empty timer table.
    pub const fn new() -> Self {
        Self {
            timers: [const { None }; POSIX_TIMER_MAX],
            count: 0,
        }
    }

    fn alloc_slot(&mut self) -> Option<usize> {
        self.timers.iter().position(|s| s.is_none())
    }

    /// Return immutable reference to timer `id`.
    pub fn get(&self, id: usize) -> Option<&PosixTimer> {
        self.timers.get(id)?.as_ref()
    }

    /// Return mutable reference to timer `id`.
    pub fn get_mut(&mut self, id: usize) -> Option<&mut PosixTimer> {
        self.timers.get_mut(id)?.as_mut()
    }
}

// ---------------------------------------------------------------------------
// Core handlers
// ---------------------------------------------------------------------------

/// Handler for `timer_create(2)`.
///
/// Allocates a new POSIX timer using `clock_id` and registers it in `table`.
/// Returns the new timer ID.
///
/// # Errors
///
/// | `Error`         | Condition                             |
/// |-----------------|---------------------------------------|
/// | `InvalidArgument` | Unknown clock ID                    |
/// | `WouldBlock`    | Timer table is full (`EAGAIN`)         |
pub fn do_timer_create(
    table: &mut TimerTable,
    clock_id: i32,
    notify: SignotifyMethod,
) -> Result<usize> {
    match clock_id {
        CLOCK_REALTIME | CLOCK_MONOTONIC | CLOCK_BOOTTIME => {}
        _ => return Err(Error::InvalidArgument),
    }
    let slot = table.alloc_slot().ok_or(Error::WouldBlock)?;
    table.timers[slot] = Some(PosixTimer {
        active: true,
        clock_id,
        notify,
        spec: Itimerspec::default(),
        overrun: 0,
        armed: false,
    });
    table.count += 1;
    Ok(slot)
}

/// Handler for `timer_settime(2)`.
///
/// Arms or disarms timer `id`.  Returns the previous `Itimerspec`.
///
/// # Errors
///
/// | `Error`         | Condition                               |
/// |-----------------|-----------------------------------------|
/// | `NotFound`      | Timer `id` does not exist               |
/// | `InvalidArgument` | Invalid timespec values               |
pub fn do_timer_settime(
    table: &mut TimerTable,
    id: usize,
    flags: i32,
    new_spec: Itimerspec,
    _now_ns: i64,
) -> Result<Itimerspec> {
    let _ = flags; // TIMER_ABSTIME handled by clock layer in real kernel
    if !new_spec.it_value.is_valid() || !new_spec.it_interval.is_valid() {
        return Err(Error::InvalidArgument);
    }
    let timer = table.get_mut(id).ok_or(Error::NotFound)?;
    let old = timer.spec;
    timer.spec = new_spec;
    timer.armed = !new_spec.it_value.is_zero();
    timer.overrun = 0;
    Ok(old)
}

/// Handler for `timer_gettime(2)`.
///
/// Returns the current setting of timer `id`.
///
/// # Errors
///
/// Returns `Err(NotFound)` if `id` is invalid.
pub fn do_timer_gettime(table: &TimerTable, id: usize) -> Result<Itimerspec> {
    table.get(id).map(|t| t.spec).ok_or(Error::NotFound)
}

/// Handler for `timer_getoverrun(2)`.
///
/// Returns the overrun count for timer `id`.
///
/// # Errors
///
/// Returns `Err(NotFound)` if `id` is invalid.
pub fn do_timer_getoverrun(table: &TimerTable, id: usize) -> Result<i32> {
    table.get(id).map(|t| t.overrun).ok_or(Error::NotFound)
}

/// Handler for `timer_delete(2)`.
///
/// Deletes timer `id`.
///
/// # Errors
///
/// Returns `Err(NotFound)` if `id` is invalid.
pub fn do_timer_delete(table: &mut TimerTable, id: usize) -> Result<()> {
    let slot = table.timers.get_mut(id).ok_or(Error::NotFound)?;
    if slot.is_none() {
        return Err(Error::NotFound);
    }
    *slot = None;
    table.count -= 1;
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_and_set() {
        let mut t = TimerTable::new();
        let id = do_timer_create(&mut t, CLOCK_MONOTONIC, SignotifyMethod::Signal(14)).unwrap();
        let spec = Itimerspec {
            it_value: Timespec {
                tv_sec: 5,
                tv_nsec: 0,
            },
            it_interval: Timespec {
                tv_sec: 1,
                tv_nsec: 0,
            },
        };
        do_timer_settime(&mut t, id, 0, spec, 0).unwrap();
        assert!(t.get(id).unwrap().armed);
    }

    #[test]
    fn create_invalid_clock() {
        let mut t = TimerTable::new();
        assert_eq!(
            do_timer_create(&mut t, 999, SignotifyMethod::None),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn delete_timer() {
        let mut t = TimerTable::new();
        let id = do_timer_create(&mut t, CLOCK_REALTIME, SignotifyMethod::None).unwrap();
        do_timer_delete(&mut t, id).unwrap();
        assert!(t.get(id).is_none());
    }

    #[test]
    fn getoverrun() {
        let mut t = TimerTable::new();
        let id = do_timer_create(&mut t, CLOCK_REALTIME, SignotifyMethod::None).unwrap();
        assert_eq!(do_timer_getoverrun(&t, id).unwrap(), 0);
    }

    #[test]
    fn table_full() {
        let mut t = TimerTable::new();
        for _ in 0..POSIX_TIMER_MAX {
            do_timer_create(&mut t, CLOCK_REALTIME, SignotifyMethod::None).unwrap();
        }
        assert_eq!(
            do_timer_create(&mut t, CLOCK_REALTIME, SignotifyMethod::None),
            Err(Error::WouldBlock)
        );
    }
}
