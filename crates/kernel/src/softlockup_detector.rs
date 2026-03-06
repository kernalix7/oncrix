// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Soft lockup detection watchdog.
//!
//! Monitors CPUs for soft lockups where a CPU is stuck in kernel
//! mode without scheduling for an extended period. Uses per-CPU
//! watchdog timestamps updated by the scheduler. If a CPU fails
//! to update its timestamp within the threshold, a soft lockup
//! warning is generated.

use oncrix_lib::{Error, Result};

/// Maximum number of monitored CPUs.
const MAX_CPUS: usize = 256;

/// Default soft lockup threshold in seconds.
const DEFAULT_THRESHOLD_SECS: u64 = 20;

/// Maximum allowed threshold in seconds.
const MAX_THRESHOLD_SECS: u64 = 120;

/// Maximum number of lockup events to record.
const MAX_LOCKUP_EVENTS: usize = 64;

/// Watchdog state for a CPU.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum WatchdogState {
    /// Watchdog is not running on this CPU.
    Inactive,
    /// Watchdog is running and CPU is healthy.
    Healthy,
    /// CPU has not reported in time — warning issued.
    Warning,
    /// CPU is confirmed in soft lockup state.
    Lockup,
    /// CPU has been marked as recovered after a lockup.
    Recovered,
}

/// Per-CPU watchdog status.
#[derive(Clone, Copy)]
pub struct CpuWatchdog {
    /// CPU identifier.
    cpu_id: u32,
    /// Current watchdog state.
    state: WatchdogState,
    /// Last timestamp when the scheduler ran (nanoseconds).
    last_touch_ns: u64,
    /// Timestamp when soft lockup was first detected.
    lockup_detected_ns: u64,
    /// Number of soft lockup events on this CPU.
    lockup_count: u32,
    /// Whether the watchdog is enabled for this CPU.
    enabled: bool,
    /// Whether a backtrace was captured for the current lockup.
    backtrace_captured: bool,
    /// Duration of the current or last lockup in nanoseconds.
    lockup_duration_ns: u64,
}

impl CpuWatchdog {
    /// Creates a new CPU watchdog entry.
    pub const fn new() -> Self {
        Self {
            cpu_id: 0,
            state: WatchdogState::Inactive,
            last_touch_ns: 0,
            lockup_detected_ns: 0,
            lockup_count: 0,
            enabled: false,
            backtrace_captured: false,
            lockup_duration_ns: 0,
        }
    }

    /// Returns the CPU identifier.
    pub const fn cpu_id(&self) -> u32 {
        self.cpu_id
    }

    /// Returns the current watchdog state.
    pub const fn state(&self) -> WatchdogState {
        self.state
    }

    /// Returns the last touch timestamp.
    pub const fn last_touch_ns(&self) -> u64 {
        self.last_touch_ns
    }

    /// Returns the number of lockup events.
    pub const fn lockup_count(&self) -> u32 {
        self.lockup_count
    }

    /// Returns whether the watchdog is enabled.
    pub const fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Updates the watchdog timestamp (called by scheduler).
    pub fn touch(&mut self, now_ns: u64) {
        self.last_touch_ns = now_ns;
        if self.state == WatchdogState::Lockup || self.state == WatchdogState::Warning {
            self.state = WatchdogState::Recovered;
            self.lockup_duration_ns = now_ns.saturating_sub(self.lockup_detected_ns);
        } else {
            self.state = WatchdogState::Healthy;
        }
    }
}

impl Default for CpuWatchdog {
    fn default() -> Self {
        Self::new()
    }
}

/// Recorded soft lockup event.
#[derive(Clone, Copy)]
pub struct LockupEvent {
    /// CPU where the lockup occurred.
    cpu_id: u32,
    /// Timestamp when lockup was detected.
    detected_ns: u64,
    /// Duration of the lockup in nanoseconds.
    duration_ns: u64,
    /// Task ID that was running during the lockup.
    task_id: u64,
    /// Instruction pointer at detection time.
    ip_at_detection: u64,
    /// Whether this triggered a panic.
    triggered_panic: bool,
}

impl LockupEvent {
    /// Creates a new empty lockup event.
    pub const fn new() -> Self {
        Self {
            cpu_id: 0,
            detected_ns: 0,
            duration_ns: 0,
            task_id: 0,
            ip_at_detection: 0,
            triggered_panic: false,
        }
    }

    /// Returns the CPU where the lockup occurred.
    pub const fn cpu_id(&self) -> u32 {
        self.cpu_id
    }

    /// Returns the detection timestamp.
    pub const fn detected_ns(&self) -> u64 {
        self.detected_ns
    }

    /// Returns the lockup duration.
    pub const fn duration_ns(&self) -> u64 {
        self.duration_ns
    }

    /// Returns the task ID involved.
    pub const fn task_id(&self) -> u64 {
        self.task_id
    }
}

impl Default for LockupEvent {
    fn default() -> Self {
        Self::new()
    }
}

/// Soft lockup detection watchdog manager.
pub struct SoftlockupDetector {
    /// Per-CPU watchdog state.
    watchdogs: [CpuWatchdog; MAX_CPUS],
    /// Number of monitored CPUs.
    cpu_count: usize,
    /// Soft lockup threshold in nanoseconds.
    threshold_ns: u64,
    /// Whether the detector is globally enabled.
    enabled: bool,
    /// Whether to panic on soft lockup.
    panic_on_lockup: bool,
    /// Recorded lockup events.
    events: [LockupEvent; MAX_LOCKUP_EVENTS],
    /// Number of recorded events.
    event_count: usize,
    /// Total number of soft lockups detected system-wide.
    total_lockups: u64,
}

impl SoftlockupDetector {
    /// Creates a new soft lockup detector.
    pub const fn new() -> Self {
        Self {
            watchdogs: [const { CpuWatchdog::new() }; MAX_CPUS],
            cpu_count: 0,
            threshold_ns: DEFAULT_THRESHOLD_SECS * 1_000_000_000,
            enabled: false,
            panic_on_lockup: false,
            events: [const { LockupEvent::new() }; MAX_LOCKUP_EVENTS],
            event_count: 0,
            total_lockups: 0,
        }
    }

    /// Enables the soft lockup detector.
    pub fn enable(&mut self) {
        self.enabled = true;
        for i in 0..self.cpu_count {
            self.watchdogs[i].enabled = true;
            self.watchdogs[i].state = WatchdogState::Healthy;
        }
    }

    /// Disables the soft lockup detector.
    pub fn disable(&mut self) {
        self.enabled = false;
        for i in 0..self.cpu_count {
            self.watchdogs[i].enabled = false;
            self.watchdogs[i].state = WatchdogState::Inactive;
        }
    }

    /// Sets the lockup threshold in seconds.
    pub fn set_threshold_secs(&mut self, secs: u64) -> Result<()> {
        if secs == 0 || secs > MAX_THRESHOLD_SECS {
            return Err(Error::InvalidArgument);
        }
        self.threshold_ns = secs * 1_000_000_000;
        Ok(())
    }

    /// Sets whether to panic on soft lockup detection.
    pub fn set_panic_on_lockup(&mut self, panic: bool) {
        self.panic_on_lockup = panic;
    }

    /// Registers a CPU for monitoring.
    pub fn register_cpu(&mut self, cpu_id: u32, now_ns: u64) -> Result<()> {
        if self.cpu_count >= MAX_CPUS {
            return Err(Error::OutOfMemory);
        }
        self.watchdogs[self.cpu_count].cpu_id = cpu_id;
        self.watchdogs[self.cpu_count].last_touch_ns = now_ns;
        self.watchdogs[self.cpu_count].enabled = self.enabled;
        self.watchdogs[self.cpu_count].state = if self.enabled {
            WatchdogState::Healthy
        } else {
            WatchdogState::Inactive
        };
        self.cpu_count += 1;
        Ok(())
    }

    /// Checks all CPUs for soft lockups.
    pub fn check_all(&mut self, now_ns: u64) -> usize {
        if !self.enabled {
            return 0;
        }
        let mut lockups = 0usize;

        for i in 0..self.cpu_count {
            if !self.watchdogs[i].enabled {
                continue;
            }
            let elapsed = now_ns.saturating_sub(self.watchdogs[i].last_touch_ns);
            if elapsed > self.threshold_ns {
                if self.watchdogs[i].state != WatchdogState::Lockup {
                    self.watchdogs[i].state = WatchdogState::Lockup;
                    self.watchdogs[i].lockup_detected_ns = now_ns;
                    self.watchdogs[i].lockup_count += 1;
                    self.total_lockups += 1;
                    lockups += 1;

                    // Record the event
                    if self.event_count < MAX_LOCKUP_EVENTS {
                        self.events[self.event_count] = LockupEvent {
                            cpu_id: self.watchdogs[i].cpu_id,
                            detected_ns: now_ns,
                            duration_ns: elapsed,
                            task_id: 0,
                            ip_at_detection: 0,
                            triggered_panic: self.panic_on_lockup,
                        };
                        self.event_count += 1;
                    }
                }
            } else if elapsed > self.threshold_ns / 2 {
                if self.watchdogs[i].state == WatchdogState::Healthy {
                    self.watchdogs[i].state = WatchdogState::Warning;
                }
            }
        }
        lockups
    }

    /// Returns the total number of detected lockups.
    pub const fn total_lockups(&self) -> u64 {
        self.total_lockups
    }

    /// Returns the number of monitored CPUs.
    pub const fn cpu_count(&self) -> usize {
        self.cpu_count
    }

    /// Returns whether the detector is enabled.
    pub const fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Returns the number of recorded events.
    pub const fn event_count(&self) -> usize {
        self.event_count
    }
}

impl Default for SoftlockupDetector {
    fn default() -> Self {
        Self::new()
    }
}
