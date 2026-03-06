// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! timerfd file implementation.
//!
//! Implements the timerfd(2) interface:
//! - [`Timerfd`] — kernel object (clockid, interval, expiry, ticks, flags)
//! - [`timerfd_create`] — allocate a timerfd with a given clock source
//! - [`timerfd_settime`] — arm/disarm the timer (absolute or relative)
//! - [`timerfd_gettime`] — query current setting and time-to-expiry
//! - [`timerfd_read`] — return accumulated tick count (blocks if 0)
//! - Flags: `TFD_NONBLOCK`, `TFD_CLOEXEC`, `TFD_TIMER_ABSTIME`
//!
//! # Time Model
//!
//! This implementation uses monotonic tick counts (u64 nanoseconds) rather
//! than wall-clock time, so it is independent of system time sources.
//!
//! # References
//! - Linux `fs/timerfd.c`
//! - POSIX.1-2024 timerfd_create(2)

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Clock IDs (matching Linux POSIX clock constants)
// ---------------------------------------------------------------------------

/// Monotonic clock (CLOCK_MONOTONIC).
pub const CLOCK_MONOTONIC: u32 = 1;
/// Real-time clock (CLOCK_REALTIME).
pub const CLOCK_REALTIME: u32 = 0;
/// Boottime clock (CLOCK_BOOTTIME).
pub const CLOCK_BOOTTIME: u32 = 7;
/// Real-time alarm clock.
pub const CLOCK_REALTIME_ALARM: u32 = 8;
/// Boottime alarm clock.
pub const CLOCK_BOOTTIME_ALARM: u32 = 9;

// ---------------------------------------------------------------------------
// TFD flags
// ---------------------------------------------------------------------------

/// Non-blocking I/O.
pub const TFD_NONBLOCK: u32 = 1 << 11;
/// Close-on-exec.
pub const TFD_CLOEXEC: u32 = 1 << 19;
/// Absolute expiry time for timerfd_settime.
pub const TFD_TIMER_ABSTIME: u32 = 1 << 0;
/// Cancel-on-set: fire if wall clock changes.
pub const TFD_TIMER_CANCEL_ON_SET: u32 = 1 << 1;

/// Maximum timerfd objects.
const MAX_TIMERFDS: usize = 256;

// ---------------------------------------------------------------------------
// Timespec (ns-resolution)
// ---------------------------------------------------------------------------

/// A timespec value in nanoseconds.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Timespec {
    /// Seconds.
    pub tv_sec: i64,
    /// Nanoseconds.
    pub tv_nsec: i64,
}

impl Timespec {
    /// Create a new Timespec.
    pub fn new(tv_sec: i64, tv_nsec: i64) -> Result<Self> {
        if tv_nsec < 0 || tv_nsec >= 1_000_000_000 {
            return Err(Error::InvalidArgument);
        }
        Ok(Self { tv_sec, tv_nsec })
    }

    /// Convert to total nanoseconds (for simulation arithmetic).
    pub fn to_nanos(&self) -> i128 {
        self.tv_sec as i128 * 1_000_000_000 + self.tv_nsec as i128
    }

    /// Create a Timespec from nanoseconds.
    pub fn from_nanos(ns: u64) -> Self {
        Self {
            tv_sec: (ns / 1_000_000_000) as i64,
            tv_nsec: (ns % 1_000_000_000) as i64,
        }
    }
}

// ---------------------------------------------------------------------------
// ItimerSpec
// ---------------------------------------------------------------------------

/// Timer specification: initial expiry and optional interval.
#[derive(Debug, Clone, Copy, Default)]
pub struct ItimerSpec {
    /// Repeat interval (0 = one-shot).
    pub it_interval: Timespec,
    /// Time until next expiry (0 = disarmed).
    pub it_value: Timespec,
}

// ---------------------------------------------------------------------------
// Timerfd
// ---------------------------------------------------------------------------

/// Kernel object backing a timerfd file descriptor.
#[derive(Debug)]
pub struct Timerfd {
    /// Clock source (`CLOCK_MONOTONIC`, `CLOCK_REALTIME`, etc.).
    pub clockid: u32,
    /// Repeat interval in nanoseconds (0 = one-shot).
    pub interval_ns: u64,
    /// Absolute expiry time in simulated nanoseconds.
    pub expiry_ns: u64,
    /// Accumulated unexpired tick count.
    pub ticks: u64,
    /// Creation flags (`TFD_NONBLOCK`, `TFD_CLOEXEC`).
    pub flags: u32,
    /// Unique identifier.
    pub id: u32,
    /// True if the timer is currently armed.
    pub armed: bool,
}

impl Timerfd {
    /// Return true if non-blocking mode is set.
    pub fn is_nonblock(&self) -> bool {
        self.flags & TFD_NONBLOCK != 0
    }
}

// ---------------------------------------------------------------------------
// TimerfdTable
// ---------------------------------------------------------------------------

/// Registry of timerfd objects.
pub struct TimerfdTable {
    fds: [Option<Timerfd>; MAX_TIMERFDS],
    count: usize,
    next_id: u32,
    /// Simulated current time in nanoseconds.
    pub now_ns: u64,
}

impl TimerfdTable {
    /// Create an empty table.
    pub fn new() -> Self {
        Self {
            fds: core::array::from_fn(|_| None),
            count: 0,
            next_id: 1,
            now_ns: 0,
        }
    }

    fn find(&self, id: u32) -> Option<usize> {
        for (i, slot) in self.fds[..self.count].iter().enumerate() {
            if let Some(fd) = slot {
                if fd.id == id {
                    return Some(i);
                }
            }
        }
        None
    }

    /// Advance simulated time by `delta_ns` nanoseconds, accumulating ticks
    /// for all armed timers that have expired.
    pub fn advance_time(&mut self, delta_ns: u64) {
        self.now_ns = self.now_ns.saturating_add(delta_ns);
        for slot in self.fds[..self.count].iter_mut().flatten() {
            if !slot.armed || slot.expiry_ns == 0 {
                continue;
            }
            if self.now_ns >= slot.expiry_ns {
                if slot.interval_ns > 0 {
                    // Periodic: compute how many intervals have elapsed.
                    let elapsed = self.now_ns - slot.expiry_ns;
                    let extra_ticks = elapsed / slot.interval_ns;
                    slot.ticks = slot.ticks.saturating_add(1 + extra_ticks);
                    slot.expiry_ns += (1 + extra_ticks) * slot.interval_ns;
                } else {
                    // One-shot.
                    slot.ticks = slot.ticks.saturating_add(1);
                    slot.armed = false;
                    slot.expiry_ns = 0;
                }
            }
        }
    }
}

impl Default for TimerfdTable {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// timerfd_create
// ---------------------------------------------------------------------------

/// Create a new timerfd with the given clock source and flags.
///
/// Returns the timerfd id.
pub fn timerfd_create(table: &mut TimerfdTable, clockid: u32, flags: u32) -> Result<u32> {
    match clockid {
        CLOCK_MONOTONIC | CLOCK_REALTIME | CLOCK_BOOTTIME | CLOCK_REALTIME_ALARM
        | CLOCK_BOOTTIME_ALARM => {}
        _ => return Err(Error::InvalidArgument),
    }
    if table.count >= MAX_TIMERFDS {
        return Err(Error::OutOfMemory);
    }
    let id = table.next_id;
    table.next_id += 1;
    table.fds[table.count] = Some(Timerfd {
        clockid,
        interval_ns: 0,
        expiry_ns: 0,
        ticks: 0,
        flags,
        id,
        armed: false,
    });
    table.count += 1;
    Ok(id)
}

// ---------------------------------------------------------------------------
// timerfd_settime
// ---------------------------------------------------------------------------

/// Arm or disarm a timerfd.
///
/// `flags` may include `TFD_TIMER_ABSTIME` to interpret `new_value.it_value`
/// as an absolute time (relative to `table.now_ns`).
///
/// Returns the previous timer setting via `old_value` (optional).
pub fn timerfd_settime(
    table: &mut TimerfdTable,
    id: u32,
    flags: u32,
    new_value: &ItimerSpec,
    old_value: Option<&mut ItimerSpec>,
) -> Result<()> {
    let now = table.now_ns;
    let idx = table.find(id).ok_or(Error::NotFound)?;
    let fd = table.fds[idx].as_mut().ok_or(Error::NotFound)?;

    // Return old setting.
    if let Some(old) = old_value {
        if fd.armed {
            let remaining_ns = fd.expiry_ns.saturating_sub(now);
            old.it_value = Timespec::from_nanos(remaining_ns);
        } else {
            old.it_value = Timespec::default();
        }
        old.it_interval = Timespec::from_nanos(fd.interval_ns);
    }

    let val_ns = new_value.it_value.to_nanos();
    let int_ns = new_value.it_interval.to_nanos();

    if val_ns <= 0 {
        // Disarm.
        fd.armed = false;
        fd.expiry_ns = 0;
        fd.interval_ns = 0;
        fd.ticks = 0;
        return Ok(());
    }

    let expiry = if flags & TFD_TIMER_ABSTIME != 0 {
        // Absolute: expiry is the given value.
        val_ns.max(0) as u64
    } else {
        // Relative: add to current time.
        now.saturating_add(val_ns.max(0) as u64)
    };

    fd.expiry_ns = expiry;
    fd.interval_ns = int_ns.max(0) as u64;
    fd.ticks = 0;
    fd.armed = true;
    Ok(())
}

// ---------------------------------------------------------------------------
// timerfd_gettime
// ---------------------------------------------------------------------------

/// Query the current timer settings.
///
/// Returns the remaining time until expiry and the interval.
pub fn timerfd_gettime(table: &TimerfdTable, id: u32) -> Result<ItimerSpec> {
    let now = table.now_ns;
    let idx = table.find(id).ok_or(Error::NotFound)?;
    let fd = table.fds[idx].as_ref().ok_or(Error::NotFound)?;

    let it_value = if fd.armed && fd.expiry_ns > now {
        Timespec::from_nanos(fd.expiry_ns - now)
    } else {
        Timespec::default()
    };
    let it_interval = Timespec::from_nanos(fd.interval_ns);

    Ok(ItimerSpec {
        it_interval,
        it_value,
    })
}

// ---------------------------------------------------------------------------
// timerfd_read
// ---------------------------------------------------------------------------

/// Read the accumulated tick count from a timerfd.
///
/// Returns the number of expirations since the last read and resets the
/// counter. Returns `Err(WouldBlock)` if no ticks have accumulated and the
/// fd is non-blocking.
pub fn timerfd_read(table: &mut TimerfdTable, id: u32) -> Result<u64> {
    let idx = table.find(id).ok_or(Error::NotFound)?;
    let fd = table.fds[idx].as_mut().ok_or(Error::NotFound)?;

    if fd.ticks == 0 {
        return Err(Error::WouldBlock);
    }

    let ticks = fd.ticks;
    fd.ticks = 0;
    Ok(ticks)
}

// ---------------------------------------------------------------------------
// timerfd_close
// ---------------------------------------------------------------------------

/// Close a timerfd.
pub fn timerfd_close(table: &mut TimerfdTable, id: u32) -> Result<()> {
    let idx = table.find(id).ok_or(Error::NotFound)?;
    if idx < table.count - 1 {
        table.fds.swap(idx, table.count - 1);
    }
    table.fds[table.count - 1] = None;
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
    fn test_oneshot() {
        let mut table = TimerfdTable::new();
        let id = timerfd_create(&mut table, CLOCK_MONOTONIC, TFD_NONBLOCK).unwrap();
        let spec = ItimerSpec {
            it_interval: Timespec::default(),
            it_value: Timespec::new(0, 100_000_000).unwrap(), // 100ms
        };
        timerfd_settime(&mut table, id, 0, &spec, None).unwrap();
        // Not expired yet.
        assert!(matches!(
            timerfd_read(&mut table, id),
            Err(Error::WouldBlock)
        ));
        // Advance past expiry.
        table.advance_time(200_000_000);
        assert_eq!(timerfd_read(&mut table, id).unwrap(), 1);
    }

    #[test]
    fn test_periodic() {
        let mut table = TimerfdTable::new();
        let id = timerfd_create(&mut table, CLOCK_MONOTONIC, TFD_NONBLOCK).unwrap();
        let spec = ItimerSpec {
            it_interval: Timespec::new(0, 100_000_000).unwrap(),
            it_value: Timespec::new(0, 100_000_000).unwrap(),
        };
        timerfd_settime(&mut table, id, 0, &spec, None).unwrap();
        table.advance_time(350_000_000); // 3.5 intervals
        let ticks = timerfd_read(&mut table, id).unwrap();
        assert_eq!(ticks, 3);
    }

    #[test]
    fn test_gettime() {
        let mut table = TimerfdTable::new();
        let id = timerfd_create(&mut table, CLOCK_MONOTONIC, 0).unwrap();
        let spec = ItimerSpec {
            it_interval: Timespec::default(),
            it_value: Timespec::new(1, 0).unwrap(),
        };
        timerfd_settime(&mut table, id, 0, &spec, None).unwrap();
        let remaining = timerfd_gettime(&table, id).unwrap();
        assert!(remaining.it_value.tv_sec > 0 || remaining.it_value.tv_nsec > 0);
    }
}
