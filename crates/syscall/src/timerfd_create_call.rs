// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `timerfd_create(2)`, `timerfd_settime(2)`, and `timerfd_gettime(2)`
//! syscall handlers.
//!
//! Timer notification via file descriptor.
//!
//! # Key behaviours
//!
//! - A `timerfd` delivers timer expiration counts via `read(2)` as a u64.
//! - Supported clocks: `CLOCK_REALTIME`, `CLOCK_MONOTONIC`,
//!   `CLOCK_BOOTTIME`, `CLOCK_REALTIME_ALARM`, `CLOCK_BOOTTIME_ALARM`.
//! - `TFD_NONBLOCK` and `TFD_CLOEXEC` are creation flags.
//! - `TFD_TIMER_ABSTIME` in `timerfd_settime` sets an absolute expiration.
//! - `timerfd_gettime` returns the time until next expiration and interval.
//!
//! # References
//!
//! - Linux man pages: `timerfd_create(2)`, `timerfd_settime(2)`,
//!   `timerfd_gettime(2)`

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Clock IDs
// ---------------------------------------------------------------------------

/// System-wide realtime clock.
pub const CLOCK_REALTIME: u32 = 0;
/// Monotonic clock (cannot be set).
pub const CLOCK_MONOTONIC: u32 = 1;
/// Boot time clock (includes suspend).
pub const CLOCK_BOOTTIME: u32 = 7;
/// Realtime alarm clock.
pub const CLOCK_REALTIME_ALARM: u32 = 8;
/// Boot time alarm clock.
pub const CLOCK_BOOTTIME_ALARM: u32 = 9;

// ---------------------------------------------------------------------------
// Flags
// ---------------------------------------------------------------------------

/// Non-blocking I/O.
pub const TFD_NONBLOCK: u32 = 0x0000_0800;
/// Close-on-exec.
pub const TFD_CLOEXEC: u32 = 0x0002_0000;
/// Absolute time in `timerfd_settime`.
pub const TFD_TIMER_ABSTIME: u32 = 1 << 0;
/// Cancel-on-set flag for `timerfd_settime`.
pub const TFD_TIMER_CANCEL_ON_SET: u32 = 1 << 1;

// ---------------------------------------------------------------------------
// Timespec / Itimerspec
// ---------------------------------------------------------------------------

/// A POSIX `struct timespec`.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Timespec {
    /// Seconds.
    pub tv_sec: i64,
    /// Nanoseconds [0, 999_999_999].
    pub tv_nsec: i64,
}

impl Timespec {
    /// Returns `true` if this is a valid timespec.
    pub fn is_valid(&self) -> bool {
        self.tv_nsec >= 0 && self.tv_nsec < 1_000_000_000
    }

    /// Convert to nanoseconds.
    pub fn to_nanos(&self) -> u64 {
        (self.tv_sec as u64)
            .saturating_mul(1_000_000_000)
            .saturating_add(self.tv_nsec as u64)
    }
}

/// POSIX `struct itimerspec` — initial expiration and interval.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Itimerspec {
    /// Timer interval (0 = one-shot).
    pub it_interval: Timespec,
    /// Initial expiration.
    pub it_value: Timespec,
}

// ---------------------------------------------------------------------------
// Timerfd instance
// ---------------------------------------------------------------------------

/// Kernel-side timerfd object.
#[derive(Debug, Clone, Copy)]
pub struct Timerfd {
    /// Clock ID used for this timer.
    pub clockid: u32,
    /// Non-blocking flag.
    pub nonblock: bool,
    /// Armed timer spec (zero = disarmed).
    pub spec: Itimerspec,
    /// Accumulated expirations (readable via read(2)).
    pub expirations: u64,
    /// Current clock value when timer was set (nanoseconds).
    pub set_at_ns: u64,
}

impl Timerfd {
    fn new(clockid: u32, flags: u32) -> Self {
        Self {
            clockid,
            nonblock: flags & TFD_NONBLOCK != 0,
            spec: Itimerspec::default(),
            expirations: 0,
            set_at_ns: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// Core handlers
// ---------------------------------------------------------------------------

/// Handler for `timerfd_create(2)`.
///
/// # Errors
///
/// | `Error`           | Condition                                      |
/// |-------------------|------------------------------------------------|
/// | `InvalidArgument` | Unsupported clock or unknown flags             |
pub fn do_timerfd_create(clockid: u32, flags: u32) -> Result<Timerfd> {
    match clockid {
        CLOCK_REALTIME | CLOCK_MONOTONIC | CLOCK_BOOTTIME | CLOCK_REALTIME_ALARM
        | CLOCK_BOOTTIME_ALARM => {}
        _ => return Err(Error::InvalidArgument),
    }
    let known = TFD_NONBLOCK | TFD_CLOEXEC;
    if flags & !known != 0 {
        return Err(Error::InvalidArgument);
    }
    Ok(Timerfd::new(clockid, flags))
}

/// Handler for `timerfd_settime(2)`.
///
/// Arms or disarms the timer.  `now_ns` is the current clock reading in
/// nanoseconds.  Pass 0 to disarm (by providing a zero `new_value`).
///
/// # Errors
///
/// | `Error`           | Condition                                      |
/// |-------------------|------------------------------------------------|
/// | `InvalidArgument` | Invalid `new_value` or unknown flags           |
pub fn do_timerfd_settime(
    tfd: &mut Timerfd,
    flags: u32,
    new_value: &Itimerspec,
    old_value: Option<&mut Itimerspec>,
    now_ns: u64,
) -> Result<()> {
    let known = TFD_TIMER_ABSTIME | TFD_TIMER_CANCEL_ON_SET;
    if flags & !known != 0 {
        return Err(Error::InvalidArgument);
    }
    if !new_value.it_value.is_valid() || !new_value.it_interval.is_valid() {
        return Err(Error::InvalidArgument);
    }

    // Return old setting.
    if let Some(old) = old_value {
        *old = tfd.spec;
    }

    tfd.spec = *new_value;
    tfd.set_at_ns = now_ns;
    tfd.expirations = 0;
    Ok(())
}

/// Handler for `timerfd_gettime(2)`.
///
/// Returns the current timer spec (time until next expiration and interval).
/// `now_ns` is the current clock reading.
pub fn do_timerfd_gettime(tfd: &Timerfd, now_ns: u64) -> Itimerspec {
    if tfd.spec.it_value.to_nanos() == 0 {
        // Disarmed.
        return Itimerspec::default();
    }
    let expire_ns = tfd.set_at_ns.saturating_add(tfd.spec.it_value.to_nanos());
    let remaining_ns = expire_ns.saturating_sub(now_ns);
    Itimerspec {
        it_interval: tfd.spec.it_interval,
        it_value: Timespec {
            tv_sec: (remaining_ns / 1_000_000_000) as i64,
            tv_nsec: (remaining_ns % 1_000_000_000) as i64,
        },
    }
}

/// Handler for timerfd `read(2)`.
///
/// Returns the number of timer expirations since last read.  Resets the
/// counter to 0.
///
/// # Errors
///
/// | `Error`      | Condition                                     |
/// |--------------|-----------------------------------------------|
/// | `WouldBlock` | No expirations pending and `TFD_NONBLOCK` set |
pub fn do_timerfd_read(tfd: &mut Timerfd) -> Result<u64> {
    if tfd.expirations == 0 {
        return Err(Error::WouldBlock);
    }
    let n = tfd.expirations;
    tfd.expirations = 0;
    Ok(n)
}

/// Simulate timer tick: record `count` expirations (called by timer subsystem).
pub fn timerfd_tick(tfd: &mut Timerfd, count: u64) {
    tfd.expirations = tfd.expirations.saturating_add(count);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_ok() {
        let tfd = do_timerfd_create(CLOCK_MONOTONIC, 0).unwrap();
        assert_eq!(tfd.clockid, CLOCK_MONOTONIC);
        assert!(!tfd.nonblock);
    }

    #[test]
    fn create_unknown_clock_fails() {
        assert_eq!(do_timerfd_create(99, 0), Err(Error::InvalidArgument));
    }

    #[test]
    fn settime_and_gettime() {
        let mut tfd = do_timerfd_create(CLOCK_MONOTONIC, 0).unwrap();
        let spec = Itimerspec {
            it_interval: Timespec {
                tv_sec: 1,
                tv_nsec: 0,
            },
            it_value: Timespec {
                tv_sec: 2,
                tv_nsec: 0,
            },
        };
        do_timerfd_settime(&mut tfd, 0, &spec, None, 1_000_000_000).unwrap();
        // 1s has elapsed since setting.
        let cur = do_timerfd_gettime(&tfd, 2_000_000_000);
        // Expected remaining: 1s.
        assert_eq!(cur.it_value.tv_sec, 1);
    }

    #[test]
    fn read_expirations() {
        let mut tfd = do_timerfd_create(CLOCK_MONOTONIC, 0).unwrap();
        timerfd_tick(&mut tfd, 3);
        assert_eq!(do_timerfd_read(&mut tfd).unwrap(), 3);
        assert_eq!(tfd.expirations, 0);
    }

    #[test]
    fn read_no_expirations_wouldblock() {
        let mut tfd = do_timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK).unwrap();
        assert_eq!(do_timerfd_read(&mut tfd), Err(Error::WouldBlock));
    }
}
