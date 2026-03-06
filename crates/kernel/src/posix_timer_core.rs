// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! POSIX interval timer core — `timer_create`, `timer_settime`,
//! `timer_gettime`, `timer_delete`, and overrun counting.
//!
//! Implements the kernel-side state for POSIX per-process interval
//! timers as defined by POSIX.1-2024 (IEEE Std 1003.1-2024). Each
//! timer is bound to a clock source (`CLOCK_REALTIME`,
//! `CLOCK_MONOTONIC`, etc.) and delivers expiration notifications
//! via signals or thread callbacks.
//!
//! # Architecture
//!
//! ```text
//! PosixTimerTable
//!  ├── timers[MAX_TIMERS]
//!  │    ├── TimerEntry
//!  │    │    ├── clock_id, it_value, it_interval
//!  │    │    ├── overrun_count, armed, signal_config
//!  │    │    └── owner_pid, timer_id
//!  │    └── ...
//!  └── stats: TimerTableStats
//! ```
//!
//! # Timer Lifecycle
//!
//! 1. `timer_create(clock_id, sigevent)` → allocates a TimerEntry
//! 2. `timer_settime(timer_id, flags, value, interval)` → arms it
//! 3. Hardware tick → `tick()` checks armed timers for expiration
//! 4. On expiry: increment overrun if still pending, else mark
//!    pending and record signal delivery request
//! 5. `timer_gettime(timer_id)` → reads remaining time
//! 6. `timer_getoverrun(timer_id)` → reads and clears overrun
//! 7. `timer_delete(timer_id)` → frees the slot
//!
//! Reference: Linux `kernel/time/posix-timers.c`,
//! `include/linux/posix-timers.h`.

use oncrix_lib::{Error, Result};

// ══════════════════════════════════════════════════════════════
// Constants
// ══════════════════════════════════════════════════════════════

/// Maximum timers per process.
const MAX_TIMERS_PER_PROCESS: usize = 32;

/// Maximum timers system-wide.
const MAX_TIMERS: usize = 512;

/// Nanoseconds per second.
const NANOS_PER_SEC: u64 = 1_000_000_000;

// ── Clock IDs ───────────────────────────────────────────────

/// `CLOCK_REALTIME` — wall clock, settable.
pub const CLOCK_REALTIME: u32 = 0;

/// `CLOCK_MONOTONIC` — non-settable monotonic clock.
pub const CLOCK_MONOTONIC: u32 = 1;

/// `CLOCK_PROCESS_CPUTIME_ID` — per-process CPU time.
pub const CLOCK_PROCESS_CPUTIME_ID: u32 = 2;

/// `CLOCK_THREAD_CPUTIME_ID` — per-thread CPU time.
pub const CLOCK_THREAD_CPUTIME_ID: u32 = 3;

/// `CLOCK_MONOTONIC_RAW` — hardware-raw monotonic.
pub const CLOCK_MONOTONIC_RAW: u32 = 4;

/// `CLOCK_REALTIME_COARSE` — low-resolution wall clock.
pub const CLOCK_REALTIME_COARSE: u32 = 5;

/// `CLOCK_MONOTONIC_COARSE` — low-resolution monotonic.
pub const CLOCK_MONOTONIC_COARSE: u32 = 6;

/// `CLOCK_BOOTTIME` — monotonic including suspend.
pub const CLOCK_BOOTTIME: u32 = 7;

// ── Sigevent notification types ─────────────────────────────

/// No notification on timer expiration.
pub const SIGEV_NONE: u32 = 0;

/// Deliver a signal on timer expiration.
pub const SIGEV_SIGNAL: u32 = 1;

/// Invoke a function in a new thread on expiration.
pub const SIGEV_THREAD: u32 = 2;

/// Deliver a signal to a specific thread.
pub const SIGEV_THREAD_ID: u32 = 3;

// ── timer_settime flags ─────────────────────────────────────

/// Interpret the timer value as an absolute time.
pub const TIMER_ABSTIME: u32 = 1;

// ══════════════════════════════════════════════════════════════
// Timespec
// ══════════════════════════════════════════════════════════════

/// POSIX `struct timespec` equivalent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(C)]
pub struct Timespec {
    /// Seconds.
    pub tv_sec: i64,
    /// Nanoseconds (0..999_999_999).
    pub tv_nsec: i64,
}

impl Timespec {
    /// Create a zero timespec.
    pub const fn zero() -> Self {
        Self {
            tv_sec: 0,
            tv_nsec: 0,
        }
    }

    /// Create from seconds and nanoseconds.
    pub const fn new(sec: i64, nsec: i64) -> Self {
        Self {
            tv_sec: sec,
            tv_nsec: nsec,
        }
    }

    /// Return true if this timespec represents zero duration.
    pub const fn is_zero(&self) -> bool {
        self.tv_sec == 0 && self.tv_nsec == 0
    }

    /// Convert to total nanoseconds.
    pub fn to_nanos(&self) -> i64 {
        self.tv_sec
            .saturating_mul(NANOS_PER_SEC as i64)
            .saturating_add(self.tv_nsec)
    }

    /// Create from total nanoseconds.
    pub fn from_nanos(ns: i64) -> Self {
        if ns <= 0 {
            return Self::zero();
        }
        Self {
            tv_sec: ns / NANOS_PER_SEC as i64,
            tv_nsec: ns % NANOS_PER_SEC as i64,
        }
    }

    /// Validate that `tv_nsec` is in range.
    pub fn validate(&self) -> Result<()> {
        if self.tv_nsec < 0 || self.tv_nsec >= NANOS_PER_SEC as i64 {
            return Err(Error::InvalidArgument);
        }
        Ok(())
    }
}

// ══════════════════════════════════════════════════════════════
// Itimerspec
// ══════════════════════════════════════════════════════════════

/// POSIX `struct itimerspec` — timer interval and initial value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(C)]
pub struct Itimerspec {
    /// Reload interval (zero = one-shot).
    pub it_interval: Timespec,
    /// Initial expiration value.
    pub it_value: Timespec,
}

impl Itimerspec {
    /// Create a zeroed itimerspec (disarmed).
    pub const fn zero() -> Self {
        Self {
            it_interval: Timespec::zero(),
            it_value: Timespec::zero(),
        }
    }

    /// Validate both fields.
    pub fn validate(&self) -> Result<()> {
        self.it_interval.validate()?;
        self.it_value.validate()
    }
}

// ══════════════════════════════════════════════════════════════
// SigEventConfig — signal delivery configuration
// ══════════════════════════════════════════════════════════════

/// Configuration for how a timer notifies the owning process.
#[derive(Debug, Clone, Copy)]
pub struct SigEventConfig {
    /// Notification type (SIGEV_NONE, SIGEV_SIGNAL, etc.).
    pub notify: u32,
    /// Signal number to deliver (for SIGEV_SIGNAL / SIGEV_THREAD_ID).
    pub signo: u32,
    /// Target thread ID (for SIGEV_THREAD_ID).
    pub thread_id: u64,
    /// User-provided value passed in si_value.
    pub value: u64,
}

impl Default for SigEventConfig {
    fn default() -> Self {
        Self::new()
    }
}

impl SigEventConfig {
    /// Create a default config (SIGEV_SIGNAL, SIGALRM).
    pub const fn new() -> Self {
        Self {
            notify: SIGEV_SIGNAL,
            signo: 14, // SIGALRM
            thread_id: 0,
            value: 0,
        }
    }

    /// Validate notification type.
    pub fn validate(&self) -> Result<()> {
        if self.notify > SIGEV_THREAD_ID {
            return Err(Error::InvalidArgument);
        }
        if self.signo == 0 || self.signo > 64 {
            return Err(Error::InvalidArgument);
        }
        Ok(())
    }
}

// ══════════════════════════════════════════════════════════════
// TimerEntry — one POSIX timer instance
// ══════════════════════════════════════════════════════════════

/// A single POSIX timer.
pub struct TimerEntry {
    /// Unique timer ID assigned at creation.
    pub timer_id: u32,
    /// Owning process PID.
    pub owner_pid: u64,
    /// Clock source.
    pub clock_id: u32,
    /// Whether the timer is armed.
    pub armed: bool,
    /// Absolute expiration time (in clock_id time base, nanos).
    pub expiry_ns: i64,
    /// Reload interval (nanos). Zero = one-shot.
    pub interval_ns: i64,
    /// Overrun count since last signal delivery.
    pub overrun_count: u32,
    /// Whether a signal delivery is pending (not yet acknowledged).
    pub signal_pending: bool,
    /// Signal delivery configuration.
    pub sig_event: SigEventConfig,
    /// Whether this slot is in use.
    active: bool,
}

impl TimerEntry {
    /// Create an empty timer entry.
    const fn empty() -> Self {
        Self {
            timer_id: 0,
            owner_pid: 0,
            clock_id: 0,
            armed: false,
            expiry_ns: 0,
            interval_ns: 0,
            overrun_count: 0,
            signal_pending: false,
            sig_event: SigEventConfig::new(),
            active: false,
        }
    }

    /// Compute the remaining time until expiration, relative
    /// to `now_ns`. Returns Timespec::zero() if already expired.
    pub fn remaining(&self, now_ns: i64) -> Timespec {
        if !self.armed {
            return Timespec::zero();
        }
        let diff = self.expiry_ns.saturating_sub(now_ns);
        if diff <= 0 {
            Timespec::zero()
        } else {
            Timespec::from_nanos(diff)
        }
    }
}

// ══════════════════════════════════════════════════════════════
// TimerTableStats
// ══════════════════════════════════════════════════════════════

/// Statistics for the POSIX timer table.
#[derive(Debug, Clone, Copy, Default)]
pub struct TimerTableStats {
    /// Total timers created.
    pub created: u64,
    /// Total timers deleted.
    pub deleted: u64,
    /// Total timer expirations.
    pub expirations: u64,
    /// Total overruns.
    pub overruns: u64,
    /// Currently active (allocated) timers.
    pub active: u32,
}

// ══════════════════════════════════════════════════════════════
// PosixTimerTable
// ══════════════════════════════════════════════════════════════

/// System-wide POSIX interval timer table.
///
/// Manages creation, arming, expiration checking, and deletion
/// of POSIX per-process timers.
pub struct PosixTimerTable {
    /// Timer entries.
    timers: [TimerEntry; MAX_TIMERS],
    /// Next timer ID to assign.
    next_id: u32,
    /// Accumulated statistics.
    stats: TimerTableStats,
}

impl Default for PosixTimerTable {
    fn default() -> Self {
        Self::new()
    }
}

impl PosixTimerTable {
    /// Create a new empty timer table.
    pub const fn new() -> Self {
        Self {
            timers: [const { TimerEntry::empty() }; MAX_TIMERS],
            next_id: 1,
            stats: TimerTableStats {
                created: 0,
                deleted: 0,
                expirations: 0,
                overruns: 0,
                active: 0,
            },
        }
    }

    /// Return accumulated statistics.
    pub fn stats(&self) -> &TimerTableStats {
        &self.stats
    }

    /// Count timers owned by a specific process.
    fn count_for_pid(&self, pid: u64) -> usize {
        self.timers
            .iter()
            .filter(|t| t.active && t.owner_pid == pid)
            .count()
    }

    /// Validate a clock ID.
    fn validate_clock(clock_id: u32) -> Result<()> {
        match clock_id {
            CLOCK_REALTIME
            | CLOCK_MONOTONIC
            | CLOCK_PROCESS_CPUTIME_ID
            | CLOCK_THREAD_CPUTIME_ID
            | CLOCK_MONOTONIC_RAW
            | CLOCK_REALTIME_COARSE
            | CLOCK_MONOTONIC_COARSE
            | CLOCK_BOOTTIME => Ok(()),
            _ => Err(Error::InvalidArgument),
        }
    }

    // ── timer_create ────────────────────────────────────────

    /// Create a new POSIX timer for the given process.
    ///
    /// Returns the assigned timer ID.
    pub fn timer_create(
        &mut self,
        owner_pid: u64,
        clock_id: u32,
        sig_event: &SigEventConfig,
    ) -> Result<u32> {
        Self::validate_clock(clock_id)?;
        sig_event.validate()?;

        if self.count_for_pid(owner_pid) >= MAX_TIMERS_PER_PROCESS {
            return Err(Error::OutOfMemory);
        }

        let pos = self
            .timers
            .iter()
            .position(|t| !t.active)
            .ok_or(Error::OutOfMemory)?;

        let tid = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);

        let entry = &mut self.timers[pos];
        entry.timer_id = tid;
        entry.owner_pid = owner_pid;
        entry.clock_id = clock_id;
        entry.sig_event = *sig_event;
        entry.armed = false;
        entry.expiry_ns = 0;
        entry.interval_ns = 0;
        entry.overrun_count = 0;
        entry.signal_pending = false;
        entry.active = true;

        self.stats.created += 1;
        self.stats.active += 1;

        Ok(tid)
    }

    // ── timer_settime ───────────────────────────────────────

    /// Arm or disarm a timer. If `flags` includes `TIMER_ABSTIME`
    /// the value is treated as an absolute time; otherwise it is
    /// relative to `now_ns`.
    ///
    /// Returns the previous timer value.
    pub fn timer_settime(
        &mut self,
        owner_pid: u64,
        timer_id: u32,
        flags: u32,
        new_value: &Itimerspec,
        now_ns: i64,
    ) -> Result<Itimerspec> {
        new_value.validate()?;

        let pos = self
            .timers
            .iter()
            .position(|t| t.active && t.timer_id == timer_id && t.owner_pid == owner_pid)
            .ok_or(Error::NotFound)?;

        let entry = &mut self.timers[pos];

        // Capture old value.
        let old = Itimerspec {
            it_value: entry.remaining(now_ns),
            it_interval: Timespec::from_nanos(entry.interval_ns),
        };

        if new_value.it_value.is_zero() {
            // Disarm.
            entry.armed = false;
            entry.expiry_ns = 0;
            entry.interval_ns = 0;
            entry.overrun_count = 0;
            entry.signal_pending = false;
        } else {
            let value_ns = new_value.it_value.to_nanos();
            let abs = (flags & TIMER_ABSTIME) != 0;
            entry.expiry_ns = if abs {
                value_ns
            } else {
                now_ns.saturating_add(value_ns)
            };
            entry.interval_ns = new_value.it_interval.to_nanos();
            entry.armed = true;
            entry.overrun_count = 0;
            entry.signal_pending = false;
        }

        Ok(old)
    }

    // ── timer_gettime ───────────────────────────────────────

    /// Return the current timer value (remaining time and interval).
    pub fn timer_gettime(&self, owner_pid: u64, timer_id: u32, now_ns: i64) -> Result<Itimerspec> {
        let entry = self
            .timers
            .iter()
            .find(|t| t.active && t.timer_id == timer_id && t.owner_pid == owner_pid)
            .ok_or(Error::NotFound)?;

        Ok(Itimerspec {
            it_value: entry.remaining(now_ns),
            it_interval: Timespec::from_nanos(entry.interval_ns),
        })
    }

    // ── timer_getoverrun ────────────────────────────────────

    /// Return the overrun count and reset it to zero.
    pub fn timer_getoverrun(&mut self, owner_pid: u64, timer_id: u32) -> Result<u32> {
        let pos = self
            .timers
            .iter()
            .position(|t| t.active && t.timer_id == timer_id && t.owner_pid == owner_pid)
            .ok_or(Error::NotFound)?;

        let entry = &mut self.timers[pos];
        let overrun = entry.overrun_count;
        entry.overrun_count = 0;
        Ok(overrun)
    }

    // ── timer_delete ────────────────────────────────────────

    /// Delete a POSIX timer, freeing the slot.
    pub fn timer_delete(&mut self, owner_pid: u64, timer_id: u32) -> Result<()> {
        let pos = self
            .timers
            .iter()
            .position(|t| t.active && t.timer_id == timer_id && t.owner_pid == owner_pid)
            .ok_or(Error::NotFound)?;

        self.timers[pos] = TimerEntry::empty();
        self.stats.deleted += 1;
        self.stats.active = self.stats.active.saturating_sub(1);
        Ok(())
    }

    // ── tick ────────────────────────────────────────────────

    /// Called on each hardware timer tick. Checks all armed timers
    /// for expiration and handles overrun counting.
    ///
    /// Returns the number of timers that expired in this tick.
    /// For each expired timer, the caller should deliver the
    /// configured signal to the owning process.
    pub fn tick(
        &mut self,
        now_ns: i64,
        expired_out: &mut [TimerExpiry],
        max_expired: usize,
    ) -> usize {
        let mut count = 0;
        let limit = max_expired.min(expired_out.len());

        for timer in &mut self.timers {
            if !timer.active || !timer.armed {
                continue;
            }
            if now_ns < timer.expiry_ns {
                continue;
            }

            // Timer expired.
            if timer.signal_pending {
                // Signal from previous expiry not yet consumed.
                timer.overrun_count = timer.overrun_count.saturating_add(1);
                self.stats.overruns += 1;
            } else {
                timer.signal_pending = true;
            }

            self.stats.expirations += 1;

            if count < limit {
                expired_out[count] = TimerExpiry {
                    timer_id: timer.timer_id,
                    owner_pid: timer.owner_pid,
                    signo: timer.sig_event.signo,
                    notify: timer.sig_event.notify,
                    value: timer.sig_event.value,
                    overrun: timer.overrun_count,
                };
                count += 1;
            }

            // Re-arm or disarm.
            if timer.interval_ns > 0 {
                // Re-arm: advance expiry by one interval, handling
                // the case where multiple intervals have elapsed.
                let elapsed = now_ns - timer.expiry_ns;
                let periods = (elapsed / timer.interval_ns) + 1;
                timer.expiry_ns += periods * timer.interval_ns;
            } else {
                // One-shot: disarm.
                timer.armed = false;
            }
        }

        count
    }

    // ── cleanup ─────────────────────────────────────────────

    /// Delete all timers belonging to a process (on exit).
    pub fn delete_all_for_pid(&mut self, pid: u64) -> u32 {
        let mut count = 0u32;
        for timer in &mut self.timers {
            if timer.active && timer.owner_pid == pid {
                *timer = TimerEntry::empty();
                count += 1;
                self.stats.deleted += 1;
                self.stats.active = self.stats.active.saturating_sub(1);
            }
        }
        count
    }

    /// Acknowledge signal delivery for a timer (clear pending).
    pub fn ack_signal(&mut self, owner_pid: u64, timer_id: u32) -> Result<()> {
        let pos = self
            .timers
            .iter()
            .position(|t| t.active && t.timer_id == timer_id && t.owner_pid == owner_pid)
            .ok_or(Error::NotFound)?;

        self.timers[pos].signal_pending = false;
        Ok(())
    }
}

// ══════════════════════════════════════════════════════════════
// TimerExpiry — output from tick()
// ══════════════════════════════════════════════════════════════

/// Describes a timer that expired during a `tick()` call.
#[derive(Debug, Clone, Copy, Default)]
pub struct TimerExpiry {
    /// Timer ID.
    pub timer_id: u32,
    /// Owning process PID.
    pub owner_pid: u64,
    /// Signal number to deliver.
    pub signo: u32,
    /// Notification type.
    pub notify: u32,
    /// User value for si_value.
    pub value: u64,
    /// Current overrun count.
    pub overrun: u32,
}
