// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Kernel timer subsystem — software timers and sleep support.
//!
//! Provides high-resolution timer (hrtimer) infrastructure for:
//! - `nanosleep` / `clock_nanosleep` syscalls
//! - Kernel-internal timeouts (e.g., IPC with timeout)
//! - Periodic callbacks (watchdogs, statistics)
//!
//! Timers are stored in a sorted array and checked on each tick.
//! When a timer expires, its callback action is executed (typically
//! waking a sleeping thread).
//!
//! Reference: Linux `kernel/time/hrtimer.c`, POSIX.1-2024 §clock_nanosleep.

use oncrix_lib::{Error, Result};
use oncrix_process::pid::Pid;

/// Maximum number of pending timers system-wide.
const MAX_TIMERS: usize = 256;

/// Time representation in nanoseconds since boot.
pub type Nanoseconds = u64;

/// What to do when a timer expires.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimerAction {
    /// Wake a sleeping thread.
    WakeThread {
        /// Process owning the thread.
        pid: Pid,
        /// Thread ID to wake.
        tid: u64,
    },
    /// No action (timer slot is a placeholder).
    None,
}

/// A single kernel timer.
#[derive(Debug, Clone, Copy)]
pub struct KernelTimer {
    /// Absolute expiry time in nanoseconds since boot.
    pub expires: Nanoseconds,
    /// Action to perform on expiry.
    pub action: TimerAction,
    /// Whether this timer is active.
    pub active: bool,
}

/// Timer wheel — manages all pending kernel timers.
///
/// Uses a flat sorted array. On each tick, the kernel calls
/// `process_expired()` to handle all timers that have elapsed.
pub struct TimerWheel {
    /// Timer slots.
    timers: [Option<KernelTimer>; MAX_TIMERS],
    /// Number of active timers.
    count: usize,
    /// Current monotonic time in nanoseconds since boot.
    now_ns: Nanoseconds,
    /// Nanoseconds per hardware tick (set during calibration).
    ns_per_tick: u64,
    /// Total hardware ticks since boot.
    tick_count: u64,
}

impl Default for TimerWheel {
    fn default() -> Self {
        Self::new()
    }
}

impl TimerWheel {
    /// Create a new timer wheel.
    pub const fn new() -> Self {
        const NONE: Option<KernelTimer> = None;
        Self {
            timers: [NONE; MAX_TIMERS],
            count: 0,
            now_ns: 0,
            ns_per_tick: 0,
            tick_count: 0,
        }
    }

    /// Set the nanoseconds per hardware tick.
    ///
    /// Must be called during boot after timer calibration.
    /// For example, if the APIC timer fires at 1000 Hz,
    /// `ns_per_tick` = 1_000_000.
    pub fn set_tick_rate(&mut self, ns_per_tick: u64) {
        self.ns_per_tick = ns_per_tick;
    }

    /// Called on each hardware timer tick.
    ///
    /// Updates the monotonic clock and returns the current time.
    pub fn tick(&mut self) -> Nanoseconds {
        self.tick_count += 1;
        self.now_ns = self.tick_count.saturating_mul(self.ns_per_tick);
        self.now_ns
    }

    /// Return the current monotonic time in nanoseconds.
    pub fn now(&self) -> Nanoseconds {
        self.now_ns
    }

    /// Return total ticks since boot.
    pub fn ticks(&self) -> u64 {
        self.tick_count
    }

    /// Schedule a timer to expire at an absolute time.
    ///
    /// Returns a timer ID (slot index) for cancellation.
    pub fn schedule(&mut self, expires: Nanoseconds, action: TimerAction) -> Result<usize> {
        if self.count >= MAX_TIMERS {
            return Err(Error::OutOfMemory);
        }

        for (idx, slot) in self.timers.iter_mut().enumerate() {
            if slot.is_none() {
                *slot = Some(KernelTimer {
                    expires,
                    action,
                    active: true,
                });
                self.count += 1;
                return Ok(idx);
            }
        }

        Err(Error::OutOfMemory)
    }

    /// Schedule a timer relative to now.
    ///
    /// `delay_ns` is the duration from now until expiry.
    pub fn schedule_relative(
        &mut self,
        delay_ns: Nanoseconds,
        action: TimerAction,
    ) -> Result<usize> {
        let expires = self.now_ns.saturating_add(delay_ns);
        self.schedule(expires, action)
    }

    /// Cancel a timer by slot index.
    pub fn cancel(&mut self, timer_id: usize) -> bool {
        if timer_id < MAX_TIMERS {
            if let Some(timer) = &mut self.timers[timer_id] {
                timer.active = false;
                self.timers[timer_id] = None;
                self.count = self.count.saturating_sub(1);
                return true;
            }
        }
        false
    }

    /// Process all expired timers.
    ///
    /// Returns the expired timer actions. The caller is responsible
    /// for executing them (e.g., waking threads via the scheduler).
    pub fn process_expired(&mut self) -> ExpiredTimers {
        let mut expired = ExpiredTimers::new();
        let now = self.now_ns;

        for slot in self.timers.iter_mut() {
            if let Some(timer) = slot {
                if timer.active && timer.expires <= now {
                    if expired.count < MAX_EXPIRED {
                        expired.actions[expired.count] = timer.action;
                        expired.count += 1;
                    }
                    *slot = None;
                    self.count = self.count.saturating_sub(1);
                }
            }
        }

        expired
    }

    /// Remove all timers for a given process.
    pub fn remove_process(&mut self, pid: Pid) {
        for slot in self.timers.iter_mut() {
            if let Some(timer) = slot {
                if let TimerAction::WakeThread { pid: p, .. } = timer.action {
                    if p == pid {
                        *slot = None;
                        self.count = self.count.saturating_sub(1);
                    }
                }
            }
        }
    }

    /// Return the number of active timers.
    pub fn active_count(&self) -> usize {
        self.count
    }
}

/// Maximum number of expired timers returned per tick.
const MAX_EXPIRED: usize = 32;

/// Batch of expired timer actions.
#[derive(Debug)]
pub struct ExpiredTimers {
    /// Expired actions.
    pub actions: [TimerAction; MAX_EXPIRED],
    /// Number of valid entries.
    pub count: usize,
}

impl ExpiredTimers {
    const fn new() -> Self {
        Self {
            actions: [TimerAction::None; MAX_EXPIRED],
            count: 0,
        }
    }

    /// Iterate over expired actions.
    pub fn iter(&self) -> impl Iterator<Item = &TimerAction> {
        self.actions[..self.count].iter()
    }
}

/// POSIX timespec structure for nanosleep.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct Timespec {
    /// Seconds.
    pub tv_sec: i64,
    /// Nanoseconds (0-999_999_999).
    pub tv_nsec: i64,
}

impl Timespec {
    /// Convert to total nanoseconds.
    pub fn to_ns(&self) -> Option<u64> {
        if self.tv_sec < 0 || self.tv_nsec < 0 || self.tv_nsec >= 1_000_000_000 {
            return None;
        }
        let secs_ns = (self.tv_sec as u64).checked_mul(1_000_000_000)?;
        secs_ns.checked_add(self.tv_nsec as u64)
    }
}

/// POSIX clock IDs.
pub mod clock {
    /// Monotonic clock (cannot be set, not affected by NTP).
    pub const CLOCK_MONOTONIC: u32 = 1;
    /// Real-time clock (wall clock, can be set).
    pub const CLOCK_REALTIME: u32 = 0;
}

impl core::fmt::Debug for TimerWheel {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("TimerWheel")
            .field("active_timers", &self.count)
            .field("now_ns", &self.now_ns)
            .field("ticks", &self.tick_count)
            .finish()
    }
}
