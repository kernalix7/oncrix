// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! CPU idle poll state — managing CPU idle polling behaviour.
//!
//! Controls whether idle CPUs enter low-power C-states or remain
//! in a polling loop for minimal wake-up latency.  Polling mode
//! trades power consumption for lower interrupt response time.
//!
//! # Reference
//!
//! Linux `kernel/sched/idle.c`, `drivers/cpuidle/`.

use oncrix_lib::{Error, Result};

const MAX_CPUS: usize = 64;

/// Idle mode for a CPU.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum IdleMode {
    /// Enter low-power C-states when idle.
    CState = 0,
    /// Poll (busy-wait) when idle for minimum latency.
    Poll = 1,
    /// Halt instruction (lightweight idle).
    Halt = 2,
    /// Monitor/mwait instruction.
    Mwait = 3,
}

impl IdleMode {
    /// Display name.
    pub const fn name(self) -> &'static str {
        match self {
            Self::CState => "cstate",
            Self::Poll => "poll",
            Self::Halt => "halt",
            Self::Mwait => "mwait",
        }
    }
}

/// Per-CPU idle state.
#[derive(Debug, Clone, Copy)]
pub struct CpuIdleState {
    /// Current idle mode.
    pub mode: IdleMode,
    /// Whether the CPU is currently idle.
    pub idle: bool,
    /// Total time spent idle (ticks).
    pub idle_ticks: u64,
    /// Total time spent polling (ticks).
    pub poll_ticks: u64,
    /// Number of idle entries.
    pub idle_count: u64,
    /// Number of poll loops completed.
    pub poll_loops: u64,
    /// Last idle entry timestamp.
    pub last_idle_tick: u64,
    /// Whether forced poll mode is active.
    pub force_poll: bool,
}

impl CpuIdleState {
    const fn new() -> Self {
        Self {
            mode: IdleMode::CState,
            idle: false,
            idle_ticks: 0,
            poll_ticks: 0,
            idle_count: 0,
            poll_loops: 0,
            last_idle_tick: 0,
            force_poll: false,
        }
    }
}

/// Statistics for the idle poll subsystem.
#[derive(Debug, Clone, Copy)]
pub struct CpuIdlePollStats {
    /// Total idle entries across all CPUs.
    pub total_idle_entries: u64,
    /// Total poll loop iterations.
    pub total_poll_loops: u64,
    /// Total ticks in idle state.
    pub total_idle_ticks: u64,
    /// Total ticks in poll state.
    pub total_poll_ticks: u64,
    /// Total mode switches.
    pub total_mode_switches: u64,
}

impl CpuIdlePollStats {
    const fn new() -> Self {
        Self {
            total_idle_entries: 0,
            total_poll_loops: 0,
            total_idle_ticks: 0,
            total_poll_ticks: 0,
            total_mode_switches: 0,
        }
    }
}

/// Top-level CPU idle poll subsystem.
pub struct CpuIdlePoll {
    /// Per-CPU state.
    per_cpu: [CpuIdleState; MAX_CPUS],
    /// Statistics.
    stats: CpuIdlePollStats,
    /// Global default idle mode.
    default_mode: IdleMode,
    /// Whether the subsystem is initialised.
    initialised: bool,
    /// Global poll duration limit (ticks, 0 = unlimited).
    poll_limit_ticks: u64,
}

impl Default for CpuIdlePoll {
    fn default() -> Self {
        Self::new()
    }
}

impl CpuIdlePoll {
    /// Create a new CPU idle poll subsystem.
    pub const fn new() -> Self {
        Self {
            per_cpu: [const { CpuIdleState::new() }; MAX_CPUS],
            stats: CpuIdlePollStats::new(),
            default_mode: IdleMode::CState,
            initialised: false,
            poll_limit_ticks: 0,
        }
    }

    /// Initialise the subsystem.
    pub fn init(&mut self) -> Result<()> {
        if self.initialised {
            return Err(Error::AlreadyExists);
        }
        self.initialised = true;
        Ok(())
    }

    /// Set the global default idle mode.
    pub fn set_default_mode(&mut self, mode: IdleMode) {
        self.default_mode = mode;
    }

    /// Set the poll duration limit.
    pub fn set_poll_limit(&mut self, ticks: u64) {
        self.poll_limit_ticks = ticks;
    }

    /// Set the idle mode for a specific CPU.
    pub fn set_cpu_mode(&mut self, cpu: usize, mode: IdleMode) -> Result<()> {
        if cpu >= MAX_CPUS {
            return Err(Error::InvalidArgument);
        }
        self.per_cpu[cpu].mode = mode;
        self.stats.total_mode_switches += 1;
        Ok(())
    }

    /// Force poll mode on a CPU (e.g., for latency-sensitive workloads).
    pub fn force_poll(&mut self, cpu: usize, force: bool) -> Result<()> {
        if cpu >= MAX_CPUS {
            return Err(Error::InvalidArgument);
        }
        self.per_cpu[cpu].force_poll = force;
        if force {
            self.per_cpu[cpu].mode = IdleMode::Poll;
        }
        Ok(())
    }

    /// Enter idle state on a CPU.
    pub fn enter_idle(&mut self, cpu: usize, timestamp: u64) -> Result<IdleMode> {
        if cpu >= MAX_CPUS {
            return Err(Error::InvalidArgument);
        }

        self.per_cpu[cpu].idle = true;
        self.per_cpu[cpu].last_idle_tick = timestamp;
        self.per_cpu[cpu].idle_count += 1;
        self.stats.total_idle_entries += 1;

        Ok(self.per_cpu[cpu].mode)
    }

    /// Exit idle state on a CPU.
    pub fn exit_idle(&mut self, cpu: usize, timestamp: u64) -> Result<()> {
        if cpu >= MAX_CPUS {
            return Err(Error::InvalidArgument);
        }

        let elapsed = timestamp.wrapping_sub(self.per_cpu[cpu].last_idle_tick);
        self.per_cpu[cpu].idle = false;
        self.per_cpu[cpu].idle_ticks += elapsed;
        self.stats.total_idle_ticks += elapsed;

        if matches!(self.per_cpu[cpu].mode, IdleMode::Poll) {
            self.per_cpu[cpu].poll_ticks += elapsed;
            self.stats.total_poll_ticks += elapsed;
        }

        Ok(())
    }

    /// Record a poll loop iteration.
    pub fn record_poll_loop(&mut self, cpu: usize) -> Result<()> {
        if cpu >= MAX_CPUS {
            return Err(Error::InvalidArgument);
        }
        self.per_cpu[cpu].poll_loops += 1;
        self.stats.total_poll_loops += 1;
        Ok(())
    }

    /// Return per-CPU state.
    pub fn cpu_state(&self, cpu: usize) -> Result<&CpuIdleState> {
        if cpu >= MAX_CPUS {
            return Err(Error::InvalidArgument);
        }
        Ok(&self.per_cpu[cpu])
    }

    /// Return statistics.
    pub fn stats(&self) -> CpuIdlePollStats {
        self.stats
    }

    /// Return the number of currently idle CPUs.
    pub fn idle_cpu_count(&self) -> usize {
        self.per_cpu.iter().filter(|c| c.idle).count()
    }

    /// Return the number of CPUs in poll mode.
    pub fn poll_cpu_count(&self) -> usize {
        self.per_cpu
            .iter()
            .filter(|c| matches!(c.mode, IdleMode::Poll))
            .count()
    }

    /// Return the global default mode.
    pub fn default_mode(&self) -> IdleMode {
        self.default_mode
    }
}
