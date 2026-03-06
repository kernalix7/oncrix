// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Software watchdog and NMI watchdog subsystem.
//!
//! Provides two complementary watchdog mechanisms:
//!
//! - **Soft watchdog** (`softdog`): A high-resolution timer that fires when the
//!   watchdog pet interval expires, indicating CPU lock-up or task starvation.
//! - **Hard watchdog** (NMI-based): Uses performance-counter NMIs to detect CPUs
//!   stuck with interrupts disabled.
//!
//! # Architecture
//!
//! | Component             | Purpose                                          |
//! |-----------------------|--------------------------------------------------|
//! | [`WatchdogConfig`]    | System-wide watchdog configuration               |
//! | [`CpuWatchdog`]       | Per-CPU soft + hard watchdog state               |
//! | [`WatchdogRegistry`]  | Global registry managing all per-CPU watchdogs   |
//! | [`WatchdogAction`]    | Action taken when a lockup is detected           |
//!
//! # Pet Protocol
//!
//! Each CPU must call [`CpuWatchdog::pet`] at least once per `thresh_ns`
//! interval. The watchdog timer checks the timestamp on every NMI (hard) or
//! hrtimer callback (soft). If the last pet timestamp is stale, a lockup is
//! declared and the configured action is triggered.

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum number of CPUs supported.
pub const MAX_CPUS: usize = 256;

/// Default soft-lockup threshold in nanoseconds (20 seconds).
pub const DEFAULT_THRESH_NS: u64 = 20_000_000_000;

/// Default hard-lockup threshold in nanoseconds (10 seconds).
pub const DEFAULT_HARD_THRESH_NS: u64 = 10_000_000_000;

/// Default watchdog check interval in nanoseconds (4 seconds).
pub const DEFAULT_CHECK_INTERVAL_NS: u64 = 4_000_000_000;

// ---------------------------------------------------------------------------
// Watchdog action
// ---------------------------------------------------------------------------

/// Action taken when a lockup is detected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WatchdogAction {
    /// Log a warning message only.
    Warn,
    /// Trigger a kernel panic.
    Panic,
    /// Trigger a kernel dump then panic.
    PanicDump,
}

impl Default for WatchdogAction {
    fn default() -> Self {
        Self::Warn
    }
}

// ---------------------------------------------------------------------------
// Watchdog configuration
// ---------------------------------------------------------------------------

/// System-wide watchdog configuration.
#[derive(Debug, Clone, Copy)]
pub struct WatchdogConfig {
    /// Soft-lockup threshold in nanoseconds.
    pub soft_thresh_ns: u64,
    /// Hard-lockup (NMI) threshold in nanoseconds.
    pub hard_thresh_ns: u64,
    /// Check interval in nanoseconds.
    pub check_interval_ns: u64,
    /// Action on soft lockup.
    pub soft_action: WatchdogAction,
    /// Action on hard lockup.
    pub hard_action: WatchdogAction,
    /// Whether the soft watchdog is enabled.
    pub soft_enabled: bool,
    /// Whether the hard watchdog (NMI) is enabled.
    pub hard_enabled: bool,
}

impl WatchdogConfig {
    /// Create a default watchdog configuration.
    pub const fn new() -> Self {
        Self {
            soft_thresh_ns: DEFAULT_THRESH_NS,
            hard_thresh_ns: DEFAULT_HARD_THRESH_NS,
            check_interval_ns: DEFAULT_CHECK_INTERVAL_NS,
            soft_action: WatchdogAction::Warn,
            hard_action: WatchdogAction::Panic,
            soft_enabled: true,
            hard_enabled: true,
        }
    }

    /// Validate configuration parameters.
    pub fn validate(&self) -> Result<()> {
        if self.soft_thresh_ns == 0 || self.hard_thresh_ns == 0 {
            return Err(Error::InvalidArgument);
        }
        if self.check_interval_ns == 0 || self.check_interval_ns > self.soft_thresh_ns {
            return Err(Error::InvalidArgument);
        }
        Ok(())
    }
}

impl Default for WatchdogConfig {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Lockup report
// ---------------------------------------------------------------------------

/// Type of detected lockup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockupKind {
    /// CPU was not scheduled / soft lockup.
    SoftLockup,
    /// CPU stuck with IRQs disabled / hard lockup.
    HardLockup,
}

/// A lockup detection report.
#[derive(Debug, Clone, Copy)]
pub struct LockupReport {
    /// CPU where lockup was detected.
    pub cpu: u16,
    /// Kind of lockup.
    pub kind: LockupKind,
    /// Timestamp when the lockup was detected, in nanoseconds.
    pub detected_at_ns: u64,
    /// Elapsed time since last pet, in nanoseconds.
    pub stall_ns: u64,
}

// ---------------------------------------------------------------------------
// Per-CPU watchdog
// ---------------------------------------------------------------------------

/// Per-CPU watchdog state.
#[derive(Debug, Clone, Copy)]
pub struct CpuWatchdog {
    /// CPU index this watchdog belongs to.
    pub cpu: u16,
    /// Last soft-watchdog pet timestamp in nanoseconds.
    pub last_soft_pet_ns: u64,
    /// Last hard-watchdog pet timestamp in nanoseconds.
    pub last_hard_pet_ns: u64,
    /// Number of soft lockups detected on this CPU.
    pub soft_lockups: u32,
    /// Number of hard lockups detected on this CPU.
    pub hard_lockups: u32,
    /// Whether this CPU's watchdog is enabled.
    pub enabled: bool,
}

impl CpuWatchdog {
    /// Create a new per-CPU watchdog state.
    pub const fn new(cpu: u16) -> Self {
        Self {
            cpu,
            last_soft_pet_ns: 0,
            last_hard_pet_ns: 0,
            soft_lockups: 0,
            hard_lockups: 0,
            enabled: false,
        }
    }

    /// Pet the soft watchdog (call from scheduler tick).
    pub fn pet_soft(&mut self, now_ns: u64) {
        self.last_soft_pet_ns = now_ns;
    }

    /// Pet the hard watchdog (call from NMI handler).
    pub fn pet_hard(&mut self, now_ns: u64) {
        self.last_hard_pet_ns = now_ns;
    }

    /// Check whether a soft lockup has occurred.
    ///
    /// Returns a `LockupReport` if the soft threshold has been exceeded.
    pub fn check_soft(&mut self, now_ns: u64, thresh_ns: u64) -> Option<LockupReport> {
        if !self.enabled {
            return None;
        }
        let stall = now_ns.saturating_sub(self.last_soft_pet_ns);
        if stall >= thresh_ns {
            self.soft_lockups = self.soft_lockups.saturating_add(1);
            Some(LockupReport {
                cpu: self.cpu,
                kind: LockupKind::SoftLockup,
                detected_at_ns: now_ns,
                stall_ns: stall,
            })
        } else {
            None
        }
    }

    /// Check whether a hard lockup has occurred.
    ///
    /// Returns a `LockupReport` if the hard threshold has been exceeded.
    pub fn check_hard(&mut self, now_ns: u64, thresh_ns: u64) -> Option<LockupReport> {
        if !self.enabled {
            return None;
        }
        let stall = now_ns.saturating_sub(self.last_hard_pet_ns);
        if stall >= thresh_ns {
            self.hard_lockups = self.hard_lockups.saturating_add(1);
            Some(LockupReport {
                cpu: self.cpu,
                kind: LockupKind::HardLockup,
                detected_at_ns: now_ns,
                stall_ns: stall,
            })
        } else {
            None
        }
    }
}

impl Default for CpuWatchdog {
    fn default() -> Self {
        Self::new(0)
    }
}

// ---------------------------------------------------------------------------
// Global watchdog registry
// ---------------------------------------------------------------------------

/// Global watchdog registry managing all per-CPU watchdogs.
pub struct WatchdogRegistry {
    /// Per-CPU watchdog state.
    cpus: [CpuWatchdog; MAX_CPUS],
    /// Number of online CPUs.
    cpu_count: usize,
    /// System-wide configuration.
    config: WatchdogConfig,
    /// Total lockup events recorded.
    total_events: u64,
}

impl WatchdogRegistry {
    /// Create a new watchdog registry.
    pub const fn new() -> Self {
        Self {
            cpus: [CpuWatchdog {
                cpu: 0,
                last_soft_pet_ns: 0,
                last_hard_pet_ns: 0,
                soft_lockups: 0,
                hard_lockups: 0,
                enabled: false,
            }; MAX_CPUS],
            cpu_count: 0,
            config: WatchdogConfig {
                soft_thresh_ns: DEFAULT_THRESH_NS,
                hard_thresh_ns: DEFAULT_HARD_THRESH_NS,
                check_interval_ns: DEFAULT_CHECK_INTERVAL_NS,
                soft_action: WatchdogAction::Warn,
                hard_action: WatchdogAction::Panic,
                soft_enabled: true,
                hard_enabled: true,
            },
            total_events: 0,
        }
    }

    /// Apply a new configuration.
    pub fn configure(&mut self, config: WatchdogConfig) -> Result<()> {
        config.validate()?;
        self.config = config;
        Ok(())
    }

    /// Register a CPU and enable its watchdog.
    pub fn register_cpu(&mut self, cpu: u16, now_ns: u64) -> Result<()> {
        let idx = cpu as usize;
        if idx >= MAX_CPUS {
            return Err(Error::InvalidArgument);
        }
        self.cpus[idx] = CpuWatchdog::new(cpu);
        self.cpus[idx].last_soft_pet_ns = now_ns;
        self.cpus[idx].last_hard_pet_ns = now_ns;
        self.cpus[idx].enabled = true;
        self.cpu_count = self.cpu_count.max(idx + 1);
        Ok(())
    }

    /// Unregister a CPU.
    pub fn unregister_cpu(&mut self, cpu: u16) {
        let idx = cpu as usize;
        if idx < MAX_CPUS {
            self.cpus[idx].enabled = false;
        }
    }

    /// Pet the soft watchdog for `cpu`.
    pub fn pet_soft(&mut self, cpu: u16, now_ns: u64) -> Result<()> {
        let idx = cpu as usize;
        if idx >= MAX_CPUS {
            return Err(Error::InvalidArgument);
        }
        self.cpus[idx].pet_soft(now_ns);
        Ok(())
    }

    /// Pet the hard watchdog for `cpu`.
    pub fn pet_hard(&mut self, cpu: u16, now_ns: u64) -> Result<()> {
        let idx = cpu as usize;
        if idx >= MAX_CPUS {
            return Err(Error::InvalidArgument);
        }
        self.cpus[idx].pet_hard(now_ns);
        Ok(())
    }

    /// Run a full lockup check for all CPUs.
    ///
    /// Calls `on_lockup` for each lockup detected. The callback receives the
    /// report and the configured action, and returns whether to stop scanning.
    pub fn check_all<F>(&mut self, now_ns: u64, mut on_lockup: F)
    where
        F: FnMut(LockupReport, WatchdogAction),
    {
        for i in 0..self.cpu_count {
            if self.config.soft_enabled {
                if let Some(report) = self.cpus[i].check_soft(now_ns, self.config.soft_thresh_ns) {
                    self.total_events = self.total_events.saturating_add(1);
                    on_lockup(report, self.config.soft_action);
                }
            }
            if self.config.hard_enabled {
                if let Some(report) = self.cpus[i].check_hard(now_ns, self.config.hard_thresh_ns) {
                    self.total_events = self.total_events.saturating_add(1);
                    on_lockup(report, self.config.hard_action);
                }
            }
        }
    }

    /// Return the current configuration.
    pub fn config(&self) -> &WatchdogConfig {
        &self.config
    }

    /// Return total lockup events recorded.
    pub fn total_events(&self) -> u64 {
        self.total_events
    }

    /// Return per-CPU watchdog state.
    pub fn cpu_state(&self, cpu: u16) -> Option<&CpuWatchdog> {
        let idx = cpu as usize;
        if idx < MAX_CPUS && self.cpus[idx].enabled {
            Some(&self.cpus[idx])
        } else {
            None
        }
    }
}

impl Default for WatchdogRegistry {
    fn default() -> Self {
        Self::new()
    }
}
