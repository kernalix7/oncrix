// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Printk rate limiting — prevents log flooding from repeated messages.
//!
//! Tracks per-caller rate limits to prevent a single source from
//! overwhelming the kernel log buffer. Each caller is identified by
//! a `caller_id` and is allowed at most `burst` messages per
//! `interval` ticks. Messages beyond the burst limit are silently
//! dropped, and a count of missed messages is maintained for
//! later reporting.
//!
//! # Architecture
//!
//! ```text
//!  PrintkRatelimit (global wrapper)
//!    └──► RatelimitTable (64 callers)
//!           └──► RatelimitCaller
//!                  ├── caller_id (u64)
//!                  ├── RatelimitState
//!                  │     ├── interval (ticks)
//!                  │     ├── burst (max prints per interval)
//!                  │     ├── printed / missed counters
//!                  │     └── begin_tick
//!                  └── last_check (tick)
//! ```
//!
//! Reference: Linux `kernel/printk/printk_ratelimit.c`,
//! `include/linux/ratelimit.h`.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Maximum number of tracked callers.
const MAX_CALLERS: usize = 64;

/// Default interval between rate limit resets (ticks).
const DEFAULT_INTERVAL: u64 = 100;

/// Default burst limit (messages per interval).
const DEFAULT_BURST: u32 = 10;

// -------------------------------------------------------------------
// RatelimitState
// -------------------------------------------------------------------

/// Rate limiting state for a single source.
///
/// Tracks how many messages have been printed during the current
/// interval and how many were suppressed. When the interval
/// elapses, counters are reset.
#[derive(Debug, Clone, Copy)]
pub struct RatelimitState {
    /// Interval duration in ticks. After this many ticks since
    /// `begin_tick`, the counters are reset.
    pub interval: u64,
    /// Maximum number of messages allowed per interval.
    pub burst: u32,
    /// Number of messages printed during the current interval.
    pub printed: u32,
    /// Number of messages suppressed during the current interval.
    pub missed: u64,
    /// Tick at which the current interval began.
    pub begin_tick: u64,
}

/// Default (inactive) ratelimit state.
const EMPTY_RATELIMIT_STATE: RatelimitState = RatelimitState {
    interval: DEFAULT_INTERVAL,
    burst: DEFAULT_BURST,
    printed: 0,
    missed: 0,
    begin_tick: 0,
};

impl RatelimitState {
    /// Create a new ratelimit state with the given interval and burst.
    pub const fn new(interval: u64, burst: u32) -> Self {
        Self {
            interval,
            burst,
            printed: 0,
            missed: 0,
            begin_tick: 0,
        }
    }

    /// Create a ratelimit state with default parameters.
    pub const fn with_defaults() -> Self {
        EMPTY_RATELIMIT_STATE
    }

    /// Check whether a message should be allowed at the given tick.
    ///
    /// Returns `true` if the message is within the burst limit for
    /// the current interval. If the interval has elapsed, counters
    /// are reset first.
    pub fn check(&mut self, current_tick: u64) -> bool {
        // If the interval has elapsed, reset counters.
        if current_tick.saturating_sub(self.begin_tick) >= self.interval {
            self.begin_tick = current_tick;
            self.printed = 0;
            // `missed` is accumulated across intervals for reporting.
        }

        if self.printed < self.burst {
            self.printed += 1;
            true
        } else {
            self.missed += 1;
            false
        }
    }

    /// Reset the state, clearing all counters.
    pub fn reset(&mut self) {
        self.printed = 0;
        self.missed = 0;
        self.begin_tick = 0;
    }
}

impl Default for RatelimitState {
    fn default() -> Self {
        Self::with_defaults()
    }
}

// -------------------------------------------------------------------
// RatelimitCaller
// -------------------------------------------------------------------

/// Per-caller rate limiting entry.
///
/// Associates a `caller_id` with a [`RatelimitState`] and tracks
/// the last tick at which the caller was checked.
#[derive(Debug, Clone, Copy)]
pub struct RatelimitCaller {
    /// Opaque caller identifier (e.g., hash of file:line).
    pub caller_id: u64,
    /// Rate limiting state for this caller.
    pub state: RatelimitState,
    /// Tick of the last rate limit check.
    pub last_check: u64,
    /// Whether this slot is occupied.
    in_use: bool,
}

/// An empty caller entry for array initialization.
const EMPTY_CALLER: RatelimitCaller = RatelimitCaller {
    caller_id: 0,
    state: EMPTY_RATELIMIT_STATE,
    last_check: 0,
    in_use: false,
};

impl RatelimitCaller {
    /// Create a new caller entry with custom interval and burst.
    pub const fn new(caller_id: u64, interval: u64, burst: u32) -> Self {
        Self {
            caller_id,
            state: RatelimitState::new(interval, burst),
            last_check: 0,
            in_use: true,
        }
    }

    /// Create a new caller entry with default rate limits.
    pub const fn with_defaults(caller_id: u64) -> Self {
        Self {
            caller_id,
            state: EMPTY_RATELIMIT_STATE,
            last_check: 0,
            in_use: true,
        }
    }
}

// -------------------------------------------------------------------
// RatelimitTable
// -------------------------------------------------------------------

/// Table of per-caller rate limiters.
///
/// Supports up to 64 distinct callers. Each caller is identified
/// by a `caller_id` and has its own rate limiting state.
pub struct RatelimitTable {
    /// Caller entries.
    callers: [RatelimitCaller; MAX_CALLERS],
    /// Number of registered callers.
    count: usize,
}

impl Default for RatelimitTable {
    fn default() -> Self {
        Self::new()
    }
}

impl RatelimitTable {
    /// Create an empty ratelimit table.
    pub const fn new() -> Self {
        Self {
            callers: [EMPTY_CALLER; MAX_CALLERS],
            count: 0,
        }
    }

    /// Register a caller with custom interval and burst.
    ///
    /// Returns the slot index on success.
    pub fn register(&mut self, caller_id: u64, interval: u64, burst: u32) -> Result<usize> {
        if self.count >= MAX_CALLERS {
            return Err(Error::OutOfMemory);
        }

        // Check for duplicate.
        for c in &self.callers {
            if c.in_use && c.caller_id == caller_id {
                return Err(Error::AlreadyExists);
            }
        }

        // Find a free slot.
        for (idx, slot) in self.callers.iter_mut().enumerate() {
            if !slot.in_use {
                *slot = RatelimitCaller::new(caller_id, interval, burst);
                self.count += 1;
                return Ok(idx);
            }
        }

        Err(Error::OutOfMemory)
    }

    /// Register a caller with default rate limits.
    pub fn register_default(&mut self, caller_id: u64) -> Result<usize> {
        self.register(caller_id, DEFAULT_INTERVAL, DEFAULT_BURST)
    }

    /// Check whether a message from the given caller should be
    /// allowed at the given tick.
    ///
    /// Returns `true` if the message is within the caller's rate
    /// limit. Returns `Err(NotFound)` if the caller is not
    /// registered.
    pub fn check(&mut self, caller_id: u64, current_tick: u64) -> Result<bool> {
        for caller in self.callers.iter_mut() {
            if caller.in_use && caller.caller_id == caller_id {
                caller.last_check = current_tick;
                return Ok(caller.state.check(current_tick));
            }
        }
        Err(Error::NotFound)
    }

    /// Get the number of missed (suppressed) messages for a caller.
    pub fn get_missed(&self, caller_id: u64) -> Result<u64> {
        for caller in &self.callers {
            if caller.in_use && caller.caller_id == caller_id {
                return Ok(caller.state.missed);
            }
        }
        Err(Error::NotFound)
    }

    /// Unregister a caller.
    pub fn unregister(&mut self, caller_id: u64) -> Result<()> {
        for slot in self.callers.iter_mut() {
            if slot.in_use && slot.caller_id == caller_id {
                *slot = EMPTY_CALLER;
                self.count = self.count.saturating_sub(1);
                return Ok(());
            }
        }
        Err(Error::NotFound)
    }

    /// Return the number of registered callers.
    pub fn count(&self) -> usize {
        self.count
    }
}

impl core::fmt::Debug for RatelimitTable {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RatelimitTable")
            .field("count", &self.count)
            .field("capacity", &MAX_CALLERS)
            .finish()
    }
}

// -------------------------------------------------------------------
// PrintkRatelimit
// -------------------------------------------------------------------

/// Global printk rate limiter.
///
/// Wraps a [`RatelimitTable`] and provides the top-level
/// `printk_ratelimited` interface. Kernel subsystems call this
/// before emitting a log message to check whether they are within
/// their rate limit.
pub struct PrintkRatelimit {
    /// The backing ratelimit table.
    pub table: RatelimitTable,
}

impl Default for PrintkRatelimit {
    fn default() -> Self {
        Self::new()
    }
}

impl PrintkRatelimit {
    /// Create a new, empty printk ratelimiter.
    pub const fn new() -> Self {
        Self {
            table: RatelimitTable::new(),
        }
    }

    /// Register a caller with default rate limits.
    pub fn register(&mut self, caller_id: u64) -> Result<usize> {
        self.table.register_default(caller_id)
    }

    /// Register a caller with custom interval and burst.
    pub fn register_custom(&mut self, caller_id: u64, interval: u64, burst: u32) -> Result<usize> {
        self.table.register(caller_id, interval, burst)
    }

    /// Check whether a rate-limited printk from the given caller
    /// should be emitted at the given tick.
    ///
    /// Returns `true` if the message is allowed, `false` if it
    /// should be suppressed. Returns `Err(NotFound)` if the caller
    /// is not registered.
    pub fn printk_ratelimited(&mut self, caller_id: u64, current_tick: u64) -> Result<bool> {
        self.table.check(caller_id, current_tick)
    }

    /// Get the number of suppressed messages for a caller.
    pub fn get_missed(&self, caller_id: u64) -> Result<u64> {
        self.table.get_missed(caller_id)
    }

    /// Unregister a caller.
    pub fn unregister(&mut self, caller_id: u64) -> Result<()> {
        self.table.unregister(caller_id)
    }

    /// Return the number of registered callers.
    pub fn count(&self) -> usize {
        self.table.count()
    }
}

impl core::fmt::Debug for PrintkRatelimit {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PrintkRatelimit")
            .field("table", &self.table)
            .finish()
    }
}
