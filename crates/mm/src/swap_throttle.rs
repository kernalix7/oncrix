// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Swap throttling under memory pressure.
//!
//! When swap I/O is saturated, allowing all processes to generate swap
//! requests leads to thrashing. This module implements throttling:
//! processes that trigger swap I/O may be forced to sleep, giving the
//! swap device time to drain pending writes and avoiding latency spikes
//! for the entire system.
//!
//! # Design
//!
//! ```text
//!  Process triggers swap-out
//!       │
//!       ▼
//!  SwapThrottle::should_throttle(io_pending, bandwidth)
//!       │
//!       ├─ below threshold → allow
//!       └─ above threshold → sleep for calculated duration
//! ```
//!
//! # Key Types
//!
//! - [`ThrottlePolicy`] — configuration for throttle behaviour
//! - [`SwapThrottle`] — the throttle controller
//! - [`ThrottleDecision`] — outcome of a throttle check
//!
//! Reference: Linux `mm/swap_state.c`, `mm/vmscan.c` (swap throttling).

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Maximum tracked processes for throttling.
const MAX_TRACKED: usize = 512;

/// Default I/O pending threshold (pages).
const DEFAULT_IO_THRESHOLD: u64 = 256;

/// Minimum sleep time in microseconds.
const MIN_SLEEP_US: u64 = 100;

/// Maximum sleep time in microseconds.
const MAX_SLEEP_US: u64 = 100_000;

/// Exponential backoff factor (numerator/denominator = 1.5).
const BACKOFF_NUM: u64 = 3;
const BACKOFF_DEN: u64 = 2;

// -------------------------------------------------------------------
// ThrottlePolicy
// -------------------------------------------------------------------

/// Configuration for swap throttling.
#[derive(Debug, Clone, Copy)]
pub struct ThrottlePolicy {
    /// Number of pending I/O pages above which throttling begins.
    pub io_threshold: u64,
    /// Minimum sleep time (microseconds).
    pub min_sleep_us: u64,
    /// Maximum sleep time (microseconds).
    pub max_sleep_us: u64,
    /// Whether throttling is enabled.
    pub enabled: bool,
}

impl ThrottlePolicy {
    /// Create a default policy.
    pub const fn new() -> Self {
        Self {
            io_threshold: DEFAULT_IO_THRESHOLD,
            min_sleep_us: MIN_SLEEP_US,
            max_sleep_us: MAX_SLEEP_US,
            enabled: true,
        }
    }

    /// Create a disabled policy.
    pub const fn disabled() -> Self {
        Self {
            io_threshold: u64::MAX,
            min_sleep_us: 0,
            max_sleep_us: 0,
            enabled: false,
        }
    }

    /// Validate the policy.
    pub fn validate(&self) -> Result<()> {
        if self.enabled && self.min_sleep_us > self.max_sleep_us {
            return Err(Error::InvalidArgument);
        }
        Ok(())
    }
}

impl Default for ThrottlePolicy {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// ThrottleDecision
// -------------------------------------------------------------------

/// Outcome of a throttle check.
#[derive(Debug, Clone, Copy)]
pub struct ThrottleDecision {
    /// Whether the caller should be throttled.
    pub throttle: bool,
    /// Suggested sleep time in microseconds (0 if not throttled).
    pub sleep_us: u64,
    /// Current I/O pressure ratio (0-100).
    pub pressure_pct: u64,
}

impl ThrottleDecision {
    /// Create an allow decision.
    pub const fn allow() -> Self {
        Self {
            throttle: false,
            sleep_us: 0,
            pressure_pct: 0,
        }
    }

    /// Create a throttle decision.
    pub const fn throttle(sleep_us: u64, pressure_pct: u64) -> Self {
        Self {
            throttle: true,
            sleep_us,
            pressure_pct,
        }
    }
}

// -------------------------------------------------------------------
// ProcessThrottleState
// -------------------------------------------------------------------

/// Per-process throttle state.
#[derive(Debug, Clone, Copy)]
struct ProcessThrottleState {
    /// Process ID.
    pid: u32,
    /// Number of consecutive throttles.
    consecutive: u32,
    /// Last sleep time in microseconds.
    last_sleep_us: u64,
    /// Total time spent sleeping (microseconds).
    total_sleep_us: u64,
    /// Whether this slot is in use.
    active: bool,
}

impl ProcessThrottleState {
    const fn empty() -> Self {
        Self {
            pid: 0,
            consecutive: 0,
            last_sleep_us: 0,
            total_sleep_us: 0,
            active: false,
        }
    }
}

// -------------------------------------------------------------------
// SwapThrottle
// -------------------------------------------------------------------

/// Swap I/O throttle controller.
pub struct SwapThrottle {
    /// Policy configuration.
    policy: ThrottlePolicy,
    /// Per-process state.
    processes: [ProcessThrottleState; MAX_TRACKED],
    /// Number of active entries.
    active_count: usize,
    /// Total throttle events.
    total_throttles: u64,
    /// Total sleep time across all processes.
    total_sleep_us: u64,
}

impl SwapThrottle {
    /// Create a new throttle controller with default policy.
    pub const fn new() -> Self {
        Self {
            policy: ThrottlePolicy::new(),
            processes: [const { ProcessThrottleState::empty() }; MAX_TRACKED],
            active_count: 0,
            total_throttles: 0,
            total_sleep_us: 0,
        }
    }

    /// Create with a custom policy.
    pub const fn with_policy(policy: ThrottlePolicy) -> Self {
        Self {
            policy,
            processes: [const { ProcessThrottleState::empty() }; MAX_TRACKED],
            active_count: 0,
            total_throttles: 0,
            total_sleep_us: 0,
        }
    }

    /// Return the policy.
    pub const fn policy(&self) -> &ThrottlePolicy {
        &self.policy
    }

    /// Update the policy.
    pub fn set_policy(&mut self, policy: ThrottlePolicy) -> Result<()> {
        policy.validate()?;
        self.policy = policy;
        Ok(())
    }

    /// Return total throttle events.
    pub const fn total_throttles(&self) -> u64 {
        self.total_throttles
    }

    /// Return total accumulated sleep time.
    pub const fn total_sleep_us(&self) -> u64 {
        self.total_sleep_us
    }

    /// Find or create a process entry.
    fn find_or_create(&mut self, pid: u32) -> Option<usize> {
        // Look for existing.
        for idx in 0..self.active_count {
            if self.processes[idx].active && self.processes[idx].pid == pid {
                return Some(idx);
            }
        }
        // Create new.
        if self.active_count >= MAX_TRACKED {
            return None;
        }
        let idx = self.active_count;
        self.processes[idx] = ProcessThrottleState {
            pid,
            consecutive: 0,
            last_sleep_us: 0,
            total_sleep_us: 0,
            active: true,
        };
        self.active_count += 1;
        Some(idx)
    }

    /// Check whether a process should be throttled.
    pub fn check(&mut self, pid: u32, io_pending: u64) -> ThrottleDecision {
        if !self.policy.enabled || io_pending < self.policy.io_threshold {
            // Reset consecutive count for this process.
            for idx in 0..self.active_count {
                if self.processes[idx].pid == pid && self.processes[idx].active {
                    self.processes[idx].consecutive = 0;
                }
            }
            return ThrottleDecision::allow();
        }

        let pressure_pct = if self.policy.io_threshold > 0 {
            (io_pending * 100 / self.policy.io_threshold).min(100)
        } else {
            100
        };

        let idx = match self.find_or_create(pid) {
            Some(i) => i,
            None => {
                return ThrottleDecision::throttle(self.policy.min_sleep_us, pressure_pct);
            }
        };

        // Exponential backoff.
        let base_sleep = if self.processes[idx].last_sleep_us == 0 {
            self.policy.min_sleep_us
        } else {
            (self.processes[idx].last_sleep_us * BACKOFF_NUM / BACKOFF_DEN)
                .min(self.policy.max_sleep_us)
        };

        self.processes[idx].consecutive += 1;
        self.processes[idx].last_sleep_us = base_sleep;
        self.processes[idx].total_sleep_us += base_sleep;

        self.total_throttles += 1;
        self.total_sleep_us += base_sleep;

        ThrottleDecision::throttle(base_sleep, pressure_pct)
    }

    /// Clear throttle state for a process.
    pub fn clear_process(&mut self, pid: u32) {
        for idx in 0..self.active_count {
            if self.processes[idx].pid == pid {
                self.processes[idx].active = false;
            }
        }
    }
}

impl Default for SwapThrottle {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// Public helpers
// -------------------------------------------------------------------

/// Check whether a process should be swap-throttled.
pub fn should_throttle(throttle: &mut SwapThrottle, pid: u32, io_pending: u64) -> ThrottleDecision {
    throttle.check(pid, io_pending)
}

/// Return a summary of throttle state.
pub fn throttle_summary(throttle: &SwapThrottle) -> &'static str {
    if !throttle.policy().enabled {
        "swap throttle: disabled"
    } else if throttle.total_throttles() == 0 {
        "swap throttle: enabled (no events)"
    } else {
        "swap throttle: enabled (active)"
    }
}

/// Create a throttle controller with custom I/O threshold.
pub fn create_throttle(io_threshold: u64) -> SwapThrottle {
    let policy = ThrottlePolicy {
        io_threshold,
        ..ThrottlePolicy::new()
    };
    SwapThrottle::with_policy(policy)
}
