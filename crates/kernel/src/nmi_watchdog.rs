// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! NMI watchdog — non-maskable interrupt watchdog for detecting hard lockups.
//!
//! The NMI watchdog uses the performance monitoring unit (PMU) to
//! generate periodic non-maskable interrupts.  If a CPU does not
//! service the interrupt within the expected window, a hard lockup
//! is detected and the system can take corrective action.
//!
//! # Architecture
//!
//! ```text
//! ┌──────────────────────────────────────────────────────────────┐
//! │                    NmiWatchdog                                │
//! │                                                              │
//! │  CpuWatchdogState[0..MAX_CPUS]  (per-CPU watchdog state)     │
//! │  ┌────────────────────────────────────────────────────────┐  │
//! │  │  last_timestamp: u64                                   │  │
//! │  │  touch_count: u64                                      │  │
//! │  │  lockup_detected: bool                                 │  │
//! │  └────────────────────────────────────────────────────────┘  │
//! │                                                              │
//! │  WatchdogConfig                                              │
//! │  - threshold_ticks, enabled, panic_on_lockup                 │
//! └──────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Reference
//!
//! Linux `kernel/watchdog.c`, `kernel/watchdog_hld.c`.

use oncrix_lib::{Error, Result};

// ══════════════════════════════════════════════════════════════
// Constants
// ══════════════════════════════════════════════════════════════

/// Maximum CPUs supported.
const MAX_CPUS: usize = 64;

/// Default watchdog threshold in ticks (approximately 10 seconds).
const DEFAULT_THRESHOLD_TICKS: u64 = 10_000;

/// Maximum allowed threshold.
const MAX_THRESHOLD_TICKS: u64 = 60_000;

// ══════════════════════════════════════════════════════════════
// LockupType
// ══════════════════════════════════════════════════════════════

/// Type of lockup detected by the watchdog.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum LockupType {
    /// Hard lockup: CPU stuck in kernel with interrupts disabled.
    Hard = 0,
    /// Soft lockup: CPU stuck in kernel with interrupts enabled
    /// but not scheduling.
    Soft = 1,
}

impl LockupType {
    /// Display name.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Hard => "hard_lockup",
            Self::Soft => "soft_lockup",
        }
    }
}

// ══════════════════════════════════════════════════════════════
// WatchdogAction
// ══════════════════════════════════════════════════════════════

/// Action to take when a lockup is detected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum WatchdogAction {
    /// Log the lockup but take no further action.
    Log = 0,
    /// Generate a kernel panic.
    Panic = 1,
    /// Generate a backtrace for the stuck CPU.
    Backtrace = 2,
}

// ══════════════════════════════════════════════════════════════
// CpuWatchdogState
// ══════════════════════════════════════════════════════════════

/// Per-CPU watchdog state.
#[derive(Debug, Clone, Copy)]
pub struct CpuWatchdogState {
    /// Last timestamp when the watchdog was touched (pet).
    pub last_timestamp: u64,
    /// Number of times the watchdog has been touched.
    pub touch_count: u64,
    /// Whether the CPU is currently enabled for watchdog monitoring.
    pub enabled: bool,
    /// Whether a hard lockup has been detected on this CPU.
    pub hard_lockup_detected: bool,
    /// Whether a soft lockup has been detected on this CPU.
    pub soft_lockup_detected: bool,
    /// Number of hard lockups detected.
    pub hard_lockup_count: u64,
    /// Number of soft lockups detected.
    pub soft_lockup_count: u64,
}

impl CpuWatchdogState {
    /// Create a fresh per-CPU state.
    const fn new() -> Self {
        Self {
            last_timestamp: 0,
            touch_count: 0,
            enabled: false,
            hard_lockup_detected: false,
            soft_lockup_detected: false,
            hard_lockup_count: 0,
            soft_lockup_count: 0,
        }
    }
}

// ══════════════════════════════════════════════════════════════
// WatchdogConfig
// ══════════════════════════════════════════════════════════════

/// Global watchdog configuration.
#[derive(Debug, Clone, Copy)]
pub struct WatchdogConfig {
    /// Threshold in ticks before declaring a lockup.
    pub threshold_ticks: u64,
    /// Whether the NMI watchdog is globally enabled.
    pub enabled: bool,
    /// Action on hard lockup.
    pub hard_lockup_action: WatchdogAction,
    /// Action on soft lockup.
    pub soft_lockup_action: WatchdogAction,
}

impl WatchdogConfig {
    /// Create the default configuration.
    const fn new() -> Self {
        Self {
            threshold_ticks: DEFAULT_THRESHOLD_TICKS,
            enabled: true,
            hard_lockup_action: WatchdogAction::Panic,
            soft_lockup_action: WatchdogAction::Log,
        }
    }
}

// ══════════════════════════════════════════════════════════════
// NmiWatchdogStats
// ══════════════════════════════════════════════════════════════

/// Aggregated NMI watchdog statistics.
#[derive(Debug, Clone, Copy)]
pub struct NmiWatchdogStats {
    /// Total NMI interrupts handled.
    pub total_nmi_handled: u64,
    /// Total hard lockups detected.
    pub total_hard_lockups: u64,
    /// Total soft lockups detected.
    pub total_soft_lockups: u64,
    /// Total watchdog touches (pets).
    pub total_touches: u64,
}

impl NmiWatchdogStats {
    const fn new() -> Self {
        Self {
            total_nmi_handled: 0,
            total_hard_lockups: 0,
            total_soft_lockups: 0,
            total_touches: 0,
        }
    }
}

// ══════════════════════════════════════════════════════════════
// NmiWatchdog
// ══════════════════════════════════════════════════════════════

/// Top-level NMI watchdog subsystem.
pub struct NmiWatchdog {
    /// Per-CPU watchdog state.
    per_cpu: [CpuWatchdogState; MAX_CPUS],
    /// Configuration.
    config: WatchdogConfig,
    /// Statistics.
    stats: NmiWatchdogStats,
    /// Whether the subsystem is initialised.
    initialised: bool,
}

impl Default for NmiWatchdog {
    fn default() -> Self {
        Self::new()
    }
}

impl NmiWatchdog {
    /// Create a new NMI watchdog subsystem.
    pub const fn new() -> Self {
        Self {
            per_cpu: [const { CpuWatchdogState::new() }; MAX_CPUS],
            config: WatchdogConfig::new(),
            stats: NmiWatchdogStats::new(),
            initialised: false,
        }
    }

    /// Initialise the NMI watchdog.
    pub fn init(&mut self) -> Result<()> {
        if self.initialised {
            return Err(Error::AlreadyExists);
        }
        self.initialised = true;
        Ok(())
    }

    // ── Configuration ────────────────────────────────────────

    /// Set the watchdog threshold.
    pub fn set_threshold(&mut self, ticks: u64) -> Result<()> {
        if ticks == 0 || ticks > MAX_THRESHOLD_TICKS {
            return Err(Error::InvalidArgument);
        }
        self.config.threshold_ticks = ticks;
        Ok(())
    }

    /// Enable or disable the watchdog globally.
    pub fn set_enabled(&mut self, enabled: bool) {
        self.config.enabled = enabled;
    }

    /// Set the action for hard lockups.
    pub fn set_hard_lockup_action(&mut self, action: WatchdogAction) {
        self.config.hard_lockup_action = action;
    }

    /// Set the action for soft lockups.
    pub fn set_soft_lockup_action(&mut self, action: WatchdogAction) {
        self.config.soft_lockup_action = action;
    }

    // ── Per-CPU control ──────────────────────────────────────

    /// Enable the watchdog on a specific CPU.
    pub fn enable_cpu(&mut self, cpu: usize, current_tick: u64) -> Result<()> {
        if cpu >= MAX_CPUS {
            return Err(Error::InvalidArgument);
        }
        self.per_cpu[cpu].enabled = true;
        self.per_cpu[cpu].last_timestamp = current_tick;
        self.per_cpu[cpu].hard_lockup_detected = false;
        self.per_cpu[cpu].soft_lockup_detected = false;
        Ok(())
    }

    /// Disable the watchdog on a specific CPU.
    pub fn disable_cpu(&mut self, cpu: usize) -> Result<()> {
        if cpu >= MAX_CPUS {
            return Err(Error::InvalidArgument);
        }
        self.per_cpu[cpu].enabled = false;
        Ok(())
    }

    // ── Watchdog operations ──────────────────────────────────

    /// Touch (pet) the watchdog on the given CPU.
    ///
    /// Must be called periodically to prevent lockup detection.
    pub fn touch(&mut self, cpu: usize, current_tick: u64) -> Result<()> {
        if cpu >= MAX_CPUS {
            return Err(Error::InvalidArgument);
        }
        self.per_cpu[cpu].last_timestamp = current_tick;
        self.per_cpu[cpu].touch_count += 1;
        self.stats.total_touches += 1;
        Ok(())
    }

    /// Handle an NMI on the given CPU.
    ///
    /// Checks whether the CPU has exceeded the threshold since
    /// the last touch.  Returns the lockup type if detected.
    pub fn handle_nmi(&mut self, cpu: usize, current_tick: u64) -> Result<Option<LockupType>> {
        if cpu >= MAX_CPUS {
            return Err(Error::InvalidArgument);
        }
        if !self.config.enabled || !self.per_cpu[cpu].enabled {
            return Ok(None);
        }

        self.stats.total_nmi_handled += 1;

        let elapsed = current_tick.wrapping_sub(self.per_cpu[cpu].last_timestamp);

        if elapsed > self.config.threshold_ticks {
            self.per_cpu[cpu].hard_lockup_detected = true;
            self.per_cpu[cpu].hard_lockup_count += 1;
            self.stats.total_hard_lockups += 1;
            return Ok(Some(LockupType::Hard));
        }

        Ok(None)
    }

    /// Check for soft lockup on the given CPU (called from timer).
    pub fn check_soft_lockup(
        &mut self,
        cpu: usize,
        current_tick: u64,
    ) -> Result<Option<LockupType>> {
        if cpu >= MAX_CPUS {
            return Err(Error::InvalidArgument);
        }
        if !self.config.enabled || !self.per_cpu[cpu].enabled {
            return Ok(None);
        }

        let elapsed = current_tick.wrapping_sub(self.per_cpu[cpu].last_timestamp);
        let soft_threshold = self.config.threshold_ticks / 2;

        if elapsed > soft_threshold && !self.per_cpu[cpu].soft_lockup_detected {
            self.per_cpu[cpu].soft_lockup_detected = true;
            self.per_cpu[cpu].soft_lockup_count += 1;
            self.stats.total_soft_lockups += 1;
            return Ok(Some(LockupType::Soft));
        }

        Ok(None)
    }

    // ── Query ────────────────────────────────────────────────

    /// Return statistics.
    pub fn stats(&self) -> NmiWatchdogStats {
        self.stats
    }

    /// Return the configuration.
    pub fn config(&self) -> WatchdogConfig {
        self.config
    }

    /// Return per-CPU state.
    pub fn cpu_state(&self, cpu: usize) -> Result<&CpuWatchdogState> {
        if cpu >= MAX_CPUS {
            return Err(Error::InvalidArgument);
        }
        Ok(&self.per_cpu[cpu])
    }

    /// Return the number of CPUs with the watchdog enabled.
    pub fn enabled_cpu_count(&self) -> usize {
        self.per_cpu.iter().filter(|c| c.enabled).count()
    }
}
