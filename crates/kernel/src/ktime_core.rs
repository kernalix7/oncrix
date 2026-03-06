// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Kernel time core — nanosecond-precision timekeeping.
//!
//! Provides the central ktime type and time conversion utilities
//! used throughout the kernel. ktime values are stored as signed
//! 64-bit nanoseconds (supports ~292 years from epoch).
//!
//! # Architecture
//!
//! ```text
//! Timekeeper
//!  ├── wall_time: Ktime        (real/wall clock)
//!  ├── mono_time: Ktime        (monotonic, never goes back)
//!  ├── boot_time: Ktime        (monotonic + suspend time)
//!  ├── raw_time: Ktime         (raw hardware counter)
//!  └── stats: TimekeeperStats
//! ```
//!
//! # Reference
//!
//! Linux `kernel/time/timekeeping.c`, `include/linux/ktime.h`.

use oncrix_lib::{Error, Result};

// ══════════════════════════════════════════════════════════════
// Constants
// ══════════════════════════════════════════════════════════════

/// Nanoseconds per second.
const NSEC_PER_SEC: i64 = 1_000_000_000;

/// Nanoseconds per millisecond.
const NSEC_PER_MSEC: i64 = 1_000_000;

/// Nanoseconds per microsecond.
const NSEC_PER_USEC: i64 = 1_000;

// ══════════════════════════════════════════════════════════════
// Ktime — nanosecond timestamp
// ══════════════════════════════════════════════════════════════

/// Kernel time value in nanoseconds (signed 64-bit).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Ktime(pub i64);

impl Ktime {
    /// Zero time.
    pub const ZERO: Self = Self(0);

    /// Maximum representable time.
    pub const MAX: Self = Self(i64::MAX);

    /// Create a ktime from nanoseconds.
    pub const fn from_ns(ns: i64) -> Self {
        Self(ns)
    }

    /// Create a ktime from microseconds.
    pub const fn from_us(us: i64) -> Self {
        Self(us * NSEC_PER_USEC)
    }

    /// Create a ktime from milliseconds.
    pub const fn from_ms(ms: i64) -> Self {
        Self(ms * NSEC_PER_MSEC)
    }

    /// Create a ktime from seconds.
    pub const fn from_secs(secs: i64) -> Self {
        Self(secs * NSEC_PER_SEC)
    }

    /// Convert to nanoseconds.
    pub const fn to_ns(self) -> i64 {
        self.0
    }

    /// Convert to microseconds.
    pub const fn to_us(self) -> i64 {
        self.0 / NSEC_PER_USEC
    }

    /// Convert to milliseconds.
    pub const fn to_ms(self) -> i64 {
        self.0 / NSEC_PER_MSEC
    }

    /// Convert to seconds.
    pub const fn to_secs(self) -> i64 {
        self.0 / NSEC_PER_SEC
    }

    /// Add two ktime values.
    pub const fn add(self, other: Self) -> Self {
        Self(self.0.saturating_add(other.0))
    }

    /// Subtract two ktime values.
    pub const fn sub(self, other: Self) -> Self {
        Self(self.0.saturating_sub(other.0))
    }

    /// Returns `true` if this time is zero.
    pub const fn is_zero(self) -> bool {
        self.0 == 0
    }

    /// Returns `true` if this time is positive.
    pub const fn is_positive(self) -> bool {
        self.0 > 0
    }
}

// ══════════════════════════════════════════════════════════════
// Timespec — seconds + nanoseconds pair
// ══════════════════════════════════════════════════════════════

/// POSIX-compatible timespec (seconds + nanoseconds).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Timespec {
    /// Seconds.
    pub tv_sec: i64,
    /// Nanoseconds (0 to 999_999_999).
    pub tv_nsec: i64,
}

impl Timespec {
    /// Create a timespec from seconds and nanoseconds.
    pub const fn new(sec: i64, nsec: i64) -> Self {
        Self {
            tv_sec: sec,
            tv_nsec: nsec,
        }
    }

    /// Convert to Ktime.
    pub const fn to_ktime(self) -> Ktime {
        Ktime(self.tv_sec * NSEC_PER_SEC + self.tv_nsec)
    }

    /// Convert from Ktime.
    pub const fn from_ktime(kt: Ktime) -> Self {
        Self {
            tv_sec: kt.0 / NSEC_PER_SEC,
            tv_nsec: kt.0 % NSEC_PER_SEC,
        }
    }
}

// ══════════════════════════════════════════════════════════════
// TimekeeperStats
// ══════════════════════════════════════════════════════════════

/// Timekeeper statistics.
#[derive(Debug, Clone, Copy)]
pub struct TimekeeperStats {
    /// Total time updates.
    pub updates: u64,
    /// Total NTP adjustments applied.
    pub ntp_adjustments: u64,
    /// Total suspend cycles.
    pub suspend_count: u64,
    /// Total suspend time in ns.
    pub total_suspend_ns: i64,
}

impl TimekeeperStats {
    /// Create zeroed stats.
    const fn new() -> Self {
        Self {
            updates: 0,
            ntp_adjustments: 0,
            suspend_count: 0,
            total_suspend_ns: 0,
        }
    }
}

// ══════════════════════════════════════════════════════════════
// Timekeeper
// ══════════════════════════════════════════════════════════════

/// Central kernel timekeeping state.
pub struct Timekeeper {
    /// Wall-clock (real) time.
    pub wall_time: Ktime,
    /// Monotonic time (never goes backwards).
    pub mono_time: Ktime,
    /// Boot time (monotonic + suspend duration).
    pub boot_time: Ktime,
    /// Raw hardware time.
    pub raw_time: Ktime,
    /// Accumulated suspend time.
    pub suspend_time: Ktime,
    /// NTP error accumulator.
    pub ntp_error_ns: i64,
    /// Statistics.
    pub stats: TimekeeperStats,
    /// Whether the timekeeper is initialised.
    initialised: bool,
}

impl Timekeeper {
    /// Create an uninitialised timekeeper.
    pub const fn new() -> Self {
        Self {
            wall_time: Ktime::ZERO,
            mono_time: Ktime::ZERO,
            boot_time: Ktime::ZERO,
            raw_time: Ktime::ZERO,
            suspend_time: Ktime::ZERO,
            ntp_error_ns: 0,
            stats: TimekeeperStats::new(),
            initialised: false,
        }
    }

    /// Initialise the timekeeper with the given wall-clock time.
    pub fn init(&mut self, wall_ns: i64) -> Result<()> {
        if self.initialised {
            return Err(Error::AlreadyExists);
        }
        self.wall_time = Ktime::from_ns(wall_ns);
        self.initialised = true;
        Ok(())
    }

    /// Advance all clocks by the given delta (from clocksource).
    pub fn update(&mut self, delta_ns: i64) -> Result<()> {
        if !self.initialised {
            return Err(Error::InvalidArgument);
        }
        let delta = Ktime::from_ns(delta_ns);
        self.wall_time = self.wall_time.add(delta);
        self.mono_time = self.mono_time.add(delta);
        self.boot_time = self.boot_time.add(delta);
        self.raw_time = self.raw_time.add(delta);
        self.stats.updates += 1;
        Ok(())
    }

    /// Record entering suspend.
    pub fn suspend_enter(&mut self) -> Result<()> {
        if !self.initialised {
            return Err(Error::InvalidArgument);
        }
        self.stats.suspend_count += 1;
        Ok(())
    }

    /// Record exiting suspend, adding suspend duration.
    pub fn suspend_exit(&mut self, suspend_ns: i64) -> Result<()> {
        if !self.initialised {
            return Err(Error::InvalidArgument);
        }
        let dur = Ktime::from_ns(suspend_ns);
        self.suspend_time = self.suspend_time.add(dur);
        self.boot_time = self.boot_time.add(dur);
        self.stats.total_suspend_ns += suspend_ns;
        Ok(())
    }

    /// Apply an NTP adjustment to wall-clock time.
    pub fn ntp_adjust(&mut self, adjust_ns: i64) -> Result<()> {
        if !self.initialised {
            return Err(Error::InvalidArgument);
        }
        self.wall_time = self.wall_time.add(Ktime::from_ns(adjust_ns));
        self.ntp_error_ns += adjust_ns;
        self.stats.ntp_adjustments += 1;
        Ok(())
    }

    /// Return the current wall-clock as a Timespec.
    pub fn get_realtime(&self) -> Timespec {
        Timespec::from_ktime(self.wall_time)
    }

    /// Return the current monotonic time as a Timespec.
    pub fn get_monotonic(&self) -> Timespec {
        Timespec::from_ktime(self.mono_time)
    }
}
