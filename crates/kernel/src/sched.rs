// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Timer-based preemptive scheduling.
//!
//! The timer IRQ handler calls `timer_tick()` on every tick. This
//! module tracks the remaining time slice for the current thread
//! and forces a context switch when the slice expires.
//!
//! Time slices are priority-dependent: higher-priority threads get
//! longer slices to reduce context-switch overhead, while lower-
//! priority threads get shorter slices for responsiveness.

use oncrix_process::thread::Priority;

/// Default time slice in timer ticks (~100 Hz → 10ms per tick).
const DEFAULT_SLICE_TICKS: u32 = 10; // 100ms at 100 Hz

/// Minimum time slice (even idle threads get at least 1 tick).
const MIN_SLICE_TICKS: u32 = 1;

/// Maximum time slice for the highest-priority threads.
const MAX_SLICE_TICKS: u32 = 50; // 500ms at 100 Hz

/// Per-CPU preemption state.
///
/// Tracks the remaining time slice for the currently running thread
/// and the system-wide tick count.
pub struct PreemptionState {
    /// Remaining ticks in the current thread's time slice.
    remaining: u32,
    /// Total system ticks since boot.
    total_ticks: u64,
    /// Whether preemption is currently enabled.
    preempt_enabled: bool,
    /// Preemption disable nesting count.
    preempt_count: u32,
    /// Number of forced context switches.
    forced_switches: u64,
    /// Number of voluntary yields.
    voluntary_yields: u64,
}

impl PreemptionState {
    /// Create a new preemption state.
    pub const fn new() -> Self {
        Self {
            remaining: DEFAULT_SLICE_TICKS,
            total_ticks: 0,
            preempt_enabled: true,
            preempt_count: 0,
            forced_switches: 0,
            voluntary_yields: 0,
        }
    }

    /// Called on every timer tick.
    ///
    /// Returns `true` if the current thread's time slice has expired
    /// and a context switch should be performed.
    pub fn timer_tick(&mut self) -> bool {
        self.total_ticks = self.total_ticks.wrapping_add(1);

        if !self.preempt_enabled || self.preempt_count > 0 {
            return false;
        }

        if self.remaining > 0 {
            self.remaining -= 1;
        }

        if self.remaining == 0 {
            self.forced_switches += 1;
            true
        } else {
            false
        }
    }

    /// Reset the time slice for a newly scheduled thread.
    pub fn reset_slice(&mut self, priority: Priority) {
        self.remaining = priority_to_slice(priority);
    }

    /// Reset the time slice to the default.
    pub fn reset_default_slice(&mut self) {
        self.remaining = DEFAULT_SLICE_TICKS;
    }

    /// Record a voluntary yield.
    pub fn voluntary_yield(&mut self) {
        self.voluntary_yields += 1;
        self.remaining = 0;
    }

    /// Disable preemption (nestable).
    ///
    /// While preemption is disabled, `timer_tick()` will not request
    /// a context switch. Used in critical sections.
    pub fn disable(&mut self) {
        self.preempt_count = self.preempt_count.saturating_add(1);
        self.preempt_enabled = false;
    }

    /// Re-enable preemption (nestable).
    ///
    /// Returns `true` if preemption is now fully enabled (count == 0)
    /// and the time slice has expired (a deferred switch is needed).
    pub fn enable(&mut self) -> bool {
        if self.preempt_count > 0 {
            self.preempt_count -= 1;
        }
        if self.preempt_count == 0 {
            self.preempt_enabled = true;
            // Check if we missed a switch while disabled.
            return self.remaining == 0;
        }
        false
    }

    /// Return the total system tick count.
    pub fn total_ticks(&self) -> u64 {
        self.total_ticks
    }

    /// Return the remaining ticks in the current slice.
    pub fn remaining_ticks(&self) -> u32 {
        self.remaining
    }

    /// Return whether preemption is currently enabled.
    pub fn is_preempt_enabled(&self) -> bool {
        self.preempt_enabled && self.preempt_count == 0
    }

    /// Return scheduling statistics.
    pub fn stats(&self) -> SchedStats {
        SchedStats {
            total_ticks: self.total_ticks,
            forced_switches: self.forced_switches,
            voluntary_yields: self.voluntary_yields,
        }
    }
}

impl Default for PreemptionState {
    fn default() -> Self {
        Self::new()
    }
}

/// Scheduling statistics.
#[derive(Debug, Clone, Copy)]
pub struct SchedStats {
    /// Total timer ticks since boot.
    pub total_ticks: u64,
    /// Number of forced (preemptive) context switches.
    pub forced_switches: u64,
    /// Number of voluntary yields.
    pub voluntary_yields: u64,
}

/// Map a thread priority to a time slice (in timer ticks).
///
/// Higher priority (lower value) → longer time slice.
/// Lower priority (higher value) → shorter time slice.
fn priority_to_slice(priority: Priority) -> u32 {
    let p = priority.as_u8() as u32;
    // Linear interpolation: priority 0 → MAX_SLICE, priority 255 → MIN_SLICE.
    let range = MAX_SLICE_TICKS - MIN_SLICE_TICKS;
    let slice = MAX_SLICE_TICKS - (p * range) / 255;
    slice.max(MIN_SLICE_TICKS)
}
