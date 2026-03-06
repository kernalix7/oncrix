// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! RCU stall detection.
//!
//! Detects and reports RCU (Read-Copy-Update) stalls where a CPU
//! fails to pass through a quiescent state within the expected
//! grace period. RCU stalls indicate a CPU stuck in a critical
//! section, which can lead to memory exhaustion and system hangs.

use oncrix_lib::{Error, Result};

// ── Constants ────────────────────────────────────────────────────────

/// Maximum CPUs to monitor.
const MAX_CPUS: usize = 64;

/// Default stall timeout in seconds.
const DEFAULT_STALL_TIMEOUT_SECS: u64 = 21;

/// Default stall warning interval in seconds.
const STALL_WARNING_INTERVAL_SECS: u64 = 60;

/// Maximum stall events in the log.
const MAX_STALL_LOG: usize = 128;

/// Nanoseconds per second.
const NS_PER_SEC: u64 = 1_000_000_000;

// ── Types ────────────────────────────────────────────────────────────

/// Type of RCU stall detected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StallType {
    /// CPU did not report a quiescent state.
    CpuStall,
    /// Grace period is taking too long overall.
    GracePeriodStall,
    /// Callback processing stall.
    CallbackStall,
    /// Task holding RCU read lock too long.
    TaskStall,
}

impl Default for StallType {
    fn default() -> Self {
        Self::CpuStall
    }
}

/// Per-CPU RCU monitoring state.
#[derive(Debug, Clone)]
pub struct CpuRcuState {
    /// CPU identifier.
    cpu_id: u32,
    /// Last quiescent state timestamp (nanoseconds).
    last_qs_ns: u64,
    /// Current grace period sequence number.
    grace_period_seq: u64,
    /// Whether this CPU has passed through a QS in the current GP.
    qs_passed: bool,
    /// Number of stalls detected on this CPU.
    stall_count: u64,
    /// Whether the CPU is online.
    online: bool,
    /// Number of callbacks pending.
    pending_callbacks: u32,
}

impl CpuRcuState {
    /// Creates a new per-CPU RCU state.
    pub const fn new(cpu_id: u32) -> Self {
        Self {
            cpu_id,
            last_qs_ns: 0,
            grace_period_seq: 0,
            qs_passed: false,
            stall_count: 0,
            online: true,
            pending_callbacks: 0,
        }
    }

    /// Returns whether this CPU has passed a quiescent state.
    pub const fn qs_passed(&self) -> bool {
        self.qs_passed
    }

    /// Returns the stall count for this CPU.
    pub const fn stall_count(&self) -> u64 {
        self.stall_count
    }
}

/// A stall event record.
#[derive(Debug, Clone)]
pub struct StallEvent {
    /// Type of stall.
    stall_type: StallType,
    /// CPU that stalled (or 0xFFFF for system-wide).
    cpu_id: u32,
    /// Grace period sequence number.
    grace_period_seq: u64,
    /// Duration of the stall in nanoseconds.
    duration_ns: u64,
    /// Timestamp when detected.
    detected_at_ns: u64,
    /// Number of pending callbacks at detection time.
    pending_callbacks: u32,
}

impl StallEvent {
    /// Creates a new stall event.
    pub const fn new(
        stall_type: StallType,
        cpu_id: u32,
        grace_period_seq: u64,
        duration_ns: u64,
    ) -> Self {
        Self {
            stall_type,
            cpu_id,
            grace_period_seq,
            duration_ns,
            detected_at_ns: 0,
            pending_callbacks: 0,
        }
    }

    /// Returns the stall type.
    pub const fn stall_type(&self) -> StallType {
        self.stall_type
    }

    /// Returns the duration in nanoseconds.
    pub const fn duration_ns(&self) -> u64 {
        self.duration_ns
    }
}

/// RCU stall detection configuration.
#[derive(Debug, Clone)]
pub struct StallConfig {
    /// Timeout before declaring a CPU stall (seconds).
    pub cpu_stall_timeout_secs: u64,
    /// Timeout for grace period stalls (seconds).
    pub gp_stall_timeout_secs: u64,
    /// Warning interval for repeated stalls (seconds).
    pub warning_interval_secs: u64,
    /// Whether to panic on stall detection.
    pub panic_on_stall: bool,
    /// Whether to suppress warnings after the first.
    pub suppress_after_first: bool,
}

impl Default for StallConfig {
    fn default() -> Self {
        Self::new()
    }
}

impl StallConfig {
    /// Creates a default stall configuration.
    pub const fn new() -> Self {
        Self {
            cpu_stall_timeout_secs: DEFAULT_STALL_TIMEOUT_SECS,
            gp_stall_timeout_secs: DEFAULT_STALL_TIMEOUT_SECS * 2,
            warning_interval_secs: STALL_WARNING_INTERVAL_SECS,
            panic_on_stall: false,
            suppress_after_first: false,
        }
    }
}

/// RCU stall detection statistics.
#[derive(Debug, Clone)]
pub struct RcuStallStats {
    /// Total check cycles.
    pub total_checks: u64,
    /// Total CPU stalls detected.
    pub cpu_stalls: u64,
    /// Total grace period stalls detected.
    pub gp_stalls: u64,
    /// Total warnings emitted.
    pub warnings: u64,
    /// CPUs currently stalled.
    pub currently_stalled: u32,
}

impl Default for RcuStallStats {
    fn default() -> Self {
        Self::new()
    }
}

impl RcuStallStats {
    /// Creates zeroed statistics.
    pub const fn new() -> Self {
        Self {
            total_checks: 0,
            cpu_stalls: 0,
            gp_stalls: 0,
            warnings: 0,
            currently_stalled: 0,
        }
    }
}

/// Central RCU stall detector.
#[derive(Debug)]
pub struct RcuStallDetector {
    /// Per-CPU states.
    cpu_states: [Option<CpuRcuState>; MAX_CPUS],
    /// Stall event log.
    stall_log: [Option<StallEvent>; MAX_STALL_LOG],
    /// Log write position.
    log_pos: usize,
    /// Configuration.
    config: StallConfig,
    /// Number of monitored CPUs.
    cpu_count: usize,
    /// Current grace period sequence.
    current_gp_seq: u64,
    /// Grace period start timestamp (nanoseconds).
    gp_start_ns: u64,
    /// Statistics counters.
    total_checks: u64,
    cpu_stalls: u64,
    gp_stalls: u64,
    warnings: u64,
}

impl Default for RcuStallDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl RcuStallDetector {
    /// Creates a new RCU stall detector.
    pub const fn new() -> Self {
        Self {
            cpu_states: [const { None }; MAX_CPUS],
            stall_log: [const { None }; MAX_STALL_LOG],
            log_pos: 0,
            config: StallConfig::new(),
            cpu_count: 0,
            current_gp_seq: 0,
            gp_start_ns: 0,
            total_checks: 0,
            cpu_stalls: 0,
            gp_stalls: 0,
            warnings: 0,
        }
    }

    /// Registers a CPU for stall monitoring.
    pub fn register_cpu(&mut self, cpu_id: u32) -> Result<()> {
        let idx = cpu_id as usize;
        if idx >= MAX_CPUS {
            return Err(Error::InvalidArgument);
        }
        if self.cpu_states[idx].is_some() {
            return Err(Error::AlreadyExists);
        }
        self.cpu_states[idx] = Some(CpuRcuState::new(cpu_id));
        self.cpu_count += 1;
        Ok(())
    }

    /// Reports a quiescent state for a CPU.
    pub fn report_qs(&mut self, cpu_id: u32, timestamp_ns: u64) -> Result<()> {
        let idx = cpu_id as usize;
        if idx >= MAX_CPUS {
            return Err(Error::InvalidArgument);
        }
        let state = self.cpu_states[idx].as_mut().ok_or(Error::NotFound)?;
        state.last_qs_ns = timestamp_ns;
        state.qs_passed = true;
        Ok(())
    }

    /// Starts a new grace period.
    pub fn start_grace_period(&mut self, timestamp_ns: u64) -> Result<u64> {
        self.current_gp_seq += 1;
        self.gp_start_ns = timestamp_ns;
        for state in self.cpu_states.iter_mut().flatten() {
            state.qs_passed = false;
            state.grace_period_seq = self.current_gp_seq;
        }
        Ok(self.current_gp_seq)
    }

    /// Checks for stalls at the given timestamp.
    pub fn check_stalls(&mut self, current_ns: u64) -> Result<u32> {
        self.total_checks += 1;
        let timeout_ns = self.config.cpu_stall_timeout_secs * NS_PER_SEC;
        let mut stall_count = 0u32;
        for idx in 0..MAX_CPUS {
            let stalled = if let Some(state) = &self.cpu_states[idx] {
                state.online
                    && !state.qs_passed
                    && current_ns.saturating_sub(state.last_qs_ns) > timeout_ns
            } else {
                false
            };
            if stalled {
                let duration = current_ns
                    .saturating_sub(self.cpu_states[idx].as_ref().map_or(0, |s| s.last_qs_ns));
                if let Some(state) = &mut self.cpu_states[idx] {
                    state.stall_count += 1;
                }
                let event = StallEvent::new(
                    StallType::CpuStall,
                    idx as u32,
                    self.current_gp_seq,
                    duration,
                );
                self.stall_log[self.log_pos] = Some(event);
                self.log_pos = (self.log_pos + 1) % MAX_STALL_LOG;
                self.cpu_stalls += 1;
                self.warnings += 1;
                stall_count += 1;
            }
        }
        // Check grace period stall.
        let gp_timeout_ns = self.config.gp_stall_timeout_secs * NS_PER_SEC;
        if current_ns.saturating_sub(self.gp_start_ns) > gp_timeout_ns {
            self.gp_stalls += 1;
        }
        Ok(stall_count)
    }

    /// Updates the configuration.
    pub fn set_config(&mut self, config: StallConfig) {
        self.config = config;
    }

    /// Returns statistics.
    pub fn stats(&self) -> RcuStallStats {
        let currently_stalled = self
            .cpu_states
            .iter()
            .flatten()
            .filter(|s| s.online && !s.qs_passed)
            .count() as u32;
        RcuStallStats {
            total_checks: self.total_checks,
            cpu_stalls: self.cpu_stalls,
            gp_stalls: self.gp_stalls,
            warnings: self.warnings,
            currently_stalled,
        }
    }

    /// Returns the number of monitored CPUs.
    pub const fn cpu_count(&self) -> usize {
        self.cpu_count
    }
}
