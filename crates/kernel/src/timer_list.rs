// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Timer list — legacy low-resolution kernel timers.
//!
//! Implements the classic Linux-style timer wheel for low-resolution,
//! coarse-grained kernel timers. These timers fire at HZ-granularity
//! (jiffies resolution) and are used for timeouts, periodic polling,
//! and other non-latency-sensitive timer needs.
//!
//! The timer wheel uses a hierarchical bucket scheme: five cascading
//! arrays of 64, 64, 64, 64, and 64 slots respectively (TVR/TVN arrays).

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use oncrix_lib::Result;

extern crate alloc;

/// Number of slots in the root (finest) level of the timer wheel.
pub const TVR_SIZE: usize = 64;

/// Number of slots in each cascading level.
pub const TVN_SIZE: usize = 64;

/// Bits used by the root level.
const TVR_BITS: u32 = 6;

/// Bits used by each cascading level.
const TVN_BITS: u32 = 6;

/// Mask for the root level.
const TVR_MASK: u64 = (TVR_SIZE as u64) - 1;

/// Mask for cascading levels.
const TVN_MASK: u64 = (TVN_SIZE as u64) - 1;

/// Maximum timer expiry expressible in the wheel (5 cascading levels).
pub const MAX_TVAL: u64 = (1u64 << (TVR_BITS + TVN_BITS * 4)) - 1;

/// Jiffies-based absolute expiry timestamp.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Jiffies(pub u64);

impl Jiffies {
    /// Creates a Jiffies value from a raw count.
    pub const fn new(val: u64) -> Self {
        Self(val)
    }

    /// Returns the raw u64 value.
    pub fn as_u64(self) -> u64 {
        self.0
    }

    /// Computes the difference between two jiffies values (wrapping).
    pub fn wrapping_sub(self, other: Jiffies) -> u64 {
        self.0.wrapping_sub(other.0)
    }
}

/// Function pointer type for timer callbacks.
pub type TimerFn = fn(data: u64);

/// A single kernel timer entry.
pub struct Timer {
    /// Expiry time in jiffies.
    pub expires: Jiffies,
    /// Callback function invoked on expiry.
    pub function: TimerFn,
    /// Opaque data passed to the callback.
    pub data: u64,
    /// Flags for this timer (see `TIMER_*` constants).
    pub flags: u32,
    /// Whether this timer is currently pending in the wheel.
    pub pending: AtomicBool,
}

/// Timer flag: timer is deferrable (may fire late to save wakeups).
pub const TIMER_DEFERRABLE: u32 = 1 << 0;
/// Timer flag: pinned to the current CPU.
pub const TIMER_PINNED: u32 = 1 << 1;
/// Timer flag: irqsafe — callback may run in interrupt context.
pub const TIMER_IRQSAFE: u32 = 1 << 2;

impl Timer {
    /// Creates a new timer with the given callback and data.
    pub const fn new(function: TimerFn, data: u64) -> Self {
        Self {
            expires: Jiffies(0),
            function,
            data,
            flags: 0,
            pending: AtomicBool::new(false),
        }
    }

    /// Returns true if the timer is currently scheduled.
    pub fn is_pending(&self) -> bool {
        self.pending.load(Ordering::Acquire)
    }

    /// Sets the expiry time (does not schedule the timer).
    pub fn set_expires(&mut self, expires: Jiffies) {
        self.expires = expires;
    }
}

impl Default for Timer {
    fn default() -> Self {
        Self::new(|_| {}, 0)
    }
}

/// Calculates the cascade level and index for a given timer delta.
///
/// Returns `(level, index)` where level 0 is the root (finest) wheel.
pub fn timer_wheel_index(jiffies_now: Jiffies, expires: Jiffies) -> (usize, usize) {
    let delta = expires.wrapping_sub(jiffies_now);

    if delta < TVR_SIZE as u64 {
        let idx = expires.as_u64() & TVR_MASK;
        return (0, idx as usize);
    }

    for level in 1usize..=4 {
        let shift = TVR_BITS + TVN_BITS * (level as u32 - 1);
        if delta < (1u64 << (shift + TVN_BITS)) {
            let idx = (expires.as_u64() >> shift) & TVN_MASK;
            return (level, idx as usize);
        }
    }

    // Timer is far in the future — cap at the last level's last slot.
    (4, TVN_SIZE - 1)
}

/// Statistics for the timer wheel.
#[derive(Debug, Default)]
pub struct TimerStats {
    /// Total timers added to the wheel.
    pub added: u64,
    /// Total timers cancelled before firing.
    pub cancelled: u64,
    /// Total timers that fired (callback invoked).
    pub fired: u64,
    /// Total times the wheel was cascaded (level 1+ advanced).
    pub cascades: u64,
}

/// A per-CPU timer wheel state.
pub struct TimerWheel {
    /// Current jiffies value (advanced by the timer interrupt).
    jiffies: AtomicU64,
    /// Statistics.
    stats: TimerStats,
    /// Number of pending timers currently in the wheel.
    pending_count: u64,
}

impl TimerWheel {
    /// Creates a new timer wheel starting at jiffies = 0.
    pub const fn new() -> Self {
        Self {
            jiffies: AtomicU64::new(0),
            stats: TimerStats {
                added: 0,
                cancelled: 0,
                fired: 0,
                cascades: 0,
            },
            pending_count: 0,
        }
    }

    /// Returns the current jiffies count.
    pub fn jiffies(&self) -> Jiffies {
        Jiffies(self.jiffies.load(Ordering::Relaxed))
    }

    /// Advances jiffies by one tick (called from the timer interrupt).
    pub fn tick(&mut self) {
        self.jiffies.fetch_add(1, Ordering::Relaxed);
    }

    /// Advances jiffies by `n` ticks.
    pub fn advance(&mut self, n: u64) {
        self.jiffies.fetch_add(n, Ordering::Relaxed);
    }

    /// Records that a timer was added.
    pub fn on_add(&mut self) {
        self.stats.added += 1;
        self.pending_count += 1;
    }

    /// Records that a timer was cancelled.
    pub fn on_cancel(&mut self) {
        if self.pending_count > 0 {
            self.pending_count -= 1;
        }
        self.stats.cancelled += 1;
    }

    /// Records that a timer fired.
    pub fn on_fire(&mut self) {
        if self.pending_count > 0 {
            self.pending_count -= 1;
        }
        self.stats.fired += 1;
    }

    /// Records a cascade event.
    pub fn on_cascade(&mut self) {
        self.stats.cascades += 1;
    }

    /// Returns the number of pending timers.
    pub fn pending_count(&self) -> u64 {
        self.pending_count
    }

    /// Returns a reference to the wheel statistics.
    pub fn stats(&self) -> &TimerStats {
        &self.stats
    }
}

impl Default for TimerWheel {
    fn default() -> Self {
        Self::new()
    }
}

/// Validates and clamps a timer expiry relative to now.
///
/// Returns `Err(InvalidArgument)` if the timeout is unreasonably large
/// (overflows the 5-level wheel).
pub fn check_timer_expiry(now: Jiffies, expires: Jiffies) -> Result<Jiffies> {
    let delta = expires.wrapping_sub(now);
    if delta > MAX_TVAL {
        // Clamp to MAX_TVAL from now.
        return Ok(Jiffies(now.0.wrapping_add(MAX_TVAL)));
    }
    Ok(expires)
}

/// Computes the number of jiffies until a timer fires.
///
/// Returns 0 if the timer has already expired.
pub fn timer_remaining(now: Jiffies, expires: Jiffies) -> u64 {
    let delta = expires.wrapping_sub(now);
    // A delta larger than MAX_TVAL means the timer already expired (jiffies
    // wrapped or expiry is in the past).
    if delta > MAX_TVAL { 0 } else { delta }
}

/// Low-resolution timer configuration for the system.
#[derive(Debug, Clone, Copy)]
pub struct TimerConfig {
    /// Nominal HZ value (ticks per second).
    pub hz: u32,
    /// Whether deferred timers are allowed to batch.
    pub allow_deferral: bool,
    /// Maximum deferral in jiffies.
    pub max_deferral_jiffies: u32,
}

impl TimerConfig {
    /// Creates a default 250 Hz configuration.
    pub const fn new() -> Self {
        Self {
            hz: 250,
            allow_deferral: true,
            max_deferral_jiffies: 10,
        }
    }
}

impl Default for TimerConfig {
    fn default() -> Self {
        Self::new()
    }
}

/// Global timer configuration.
static TIMER_CONFIG: TimerConfig = TimerConfig::new();

/// Returns the global timer configuration.
pub fn timer_config() -> &'static TimerConfig {
    &TIMER_CONFIG
}

/// Converts milliseconds to jiffies using the configured HZ.
pub fn msecs_to_jiffies(ms: u64) -> u64 {
    ms * TIMER_CONFIG.hz as u64 / 1000
}

/// Converts jiffies to milliseconds using the configured HZ.
pub fn jiffies_to_msecs(j: u64) -> u64 {
    j * 1000 / TIMER_CONFIG.hz as u64
}

/// Represents a timer wheel bucket slot (intrusive list node anchor).
///
/// In a real implementation this would be an intrusive linked list of
/// `Timer` nodes. Here we track the count of timers in the slot.
#[derive(Debug, Default)]
pub struct TimerBucket {
    /// Number of timers in this bucket.
    pub count: u32,
}

impl TimerBucket {
    /// Creates an empty bucket.
    pub const fn new() -> Self {
        Self { count: 0 }
    }

    /// Adds a timer count to this bucket.
    pub fn add(&mut self) {
        self.count += 1;
    }

    /// Removes a timer count from this bucket.
    pub fn remove(&mut self) {
        if self.count > 0 {
            self.count -= 1;
        }
    }

    /// Returns true if the bucket contains no timers.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
}
