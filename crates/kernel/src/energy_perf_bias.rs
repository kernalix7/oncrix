// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Energy performance bias — CPU energy vs. performance preference.
//!
//! Controls the hardware energy-performance bias hint (EPB) on each
//! CPU, allowing the kernel to influence whether the processor favors
//! lower power consumption or higher performance.
//!
//! # Architecture
//!
//! ```text
//! ┌──────────────────────────────────────────────────────────────┐
//! │                  EnergyPerfBiasSubsystem                     │
//! │                                                              │
//! │  CpuEpbState[0..MAX_CPUS]  (per-CPU EPB state)              │
//! │  ┌────────────────────────────────────────────────────────┐  │
//! │  │  bias: EpbHint                                         │  │
//! │  │  raw_value: u8                                         │  │
//! │  │  locked: bool                                          │  │
//! │  └────────────────────────────────────────────────────────┘  │
//! │                                                              │
//! │  EpbPolicy (global policy)                                   │
//! └──────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Reference
//!
//! Linux `arch/x86/kernel/cpu/intel_epb.c`,
//! Intel SDM Vol. 3B, Section 14.4.4.

use oncrix_lib::{Error, Result};

const MAX_CPUS: usize = 64;

/// Energy performance bias hint value.
///
/// Maps to the IA32_ENERGY_PERF_BIAS MSR (0x1B0) on x86.
/// Values range from 0 (maximum performance) to 15 (maximum power saving).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum EpbHint {
    /// Maximum performance (EPB = 0).
    Performance = 0,
    /// Balance performance (EPB = 4).
    BalancePerformance = 4,
    /// Normal / balanced (EPB = 6).
    Normal = 6,
    /// Balance power saving (EPB = 8).
    BalancePowerSave = 8,
    /// Maximum power saving (EPB = 15).
    PowerSave = 15,
}

impl EpbHint {
    /// Display name.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Performance => "performance",
            Self::BalancePerformance => "balance-performance",
            Self::Normal => "normal",
            Self::BalancePowerSave => "balance-power-save",
            Self::PowerSave => "power-save",
        }
    }

    /// Convert a raw EPB value (0-15) to the nearest hint.
    pub const fn from_raw(val: u8) -> Self {
        match val {
            0..=2 => Self::Performance,
            3..=5 => Self::BalancePerformance,
            6..=7 => Self::Normal,
            8..=11 => Self::BalancePowerSave,
            _ => Self::PowerSave,
        }
    }

    /// Return the raw EPB register value.
    pub const fn raw(self) -> u8 {
        self as u8
    }
}

/// Per-CPU EPB state.
#[derive(Debug, Clone, Copy)]
pub struct CpuEpbState {
    /// Current EPB hint.
    pub bias: EpbHint,
    /// Raw MSR value.
    pub raw_value: u8,
    /// Whether the EPB is locked (cannot be changed).
    pub locked: bool,
    /// Whether the CPU supports EPB.
    pub supported: bool,
    /// Number of times EPB was changed.
    pub change_count: u64,
    /// Whether the CPU is online.
    pub online: bool,
}

impl CpuEpbState {
    const fn new() -> Self {
        Self {
            bias: EpbHint::Normal,
            raw_value: EpbHint::Normal as u8,
            locked: false,
            supported: false,
            change_count: 0,
            online: false,
        }
    }
}

/// Global EPB policy.
#[derive(Debug, Clone, Copy)]
pub struct EpbPolicy {
    /// Default bias for all CPUs.
    pub default_bias: EpbHint,
    /// Whether to override per-CPU settings.
    pub force_global: bool,
    /// Whether to restore EPB after CPU hotplug.
    pub restore_on_hotplug: bool,
}

impl EpbPolicy {
    const fn new() -> Self {
        Self {
            default_bias: EpbHint::Normal,
            force_global: false,
            restore_on_hotplug: true,
        }
    }
}

/// Statistics for the EPB subsystem.
#[derive(Debug, Clone, Copy)]
pub struct EpbStats {
    /// Total EPB writes.
    pub total_writes: u64,
    /// Total EPB reads.
    pub total_reads: u64,
    /// Total write failures (locked or unsupported).
    pub total_failures: u64,
    /// Total hotplug restores.
    pub total_restores: u64,
}

impl EpbStats {
    const fn new() -> Self {
        Self {
            total_writes: 0,
            total_reads: 0,
            total_failures: 0,
            total_restores: 0,
        }
    }
}

/// Top-level energy performance bias subsystem.
pub struct EnergyPerfBiasSubsystem {
    /// Per-CPU EPB state.
    per_cpu: [CpuEpbState; MAX_CPUS],
    /// Global policy.
    policy: EpbPolicy,
    /// Statistics.
    stats: EpbStats,
    /// Whether the subsystem is initialised.
    initialised: bool,
}

impl Default for EnergyPerfBiasSubsystem {
    fn default() -> Self {
        Self::new()
    }
}

impl EnergyPerfBiasSubsystem {
    /// Create a new EPB subsystem.
    pub const fn new() -> Self {
        Self {
            per_cpu: [const { CpuEpbState::new() }; MAX_CPUS],
            policy: EpbPolicy::new(),
            stats: EpbStats::new(),
            initialised: false,
        }
    }

    /// Initialise the subsystem.
    pub fn init(&mut self, nr_cpus: usize) -> Result<()> {
        if self.initialised {
            return Err(Error::AlreadyExists);
        }
        if nr_cpus > MAX_CPUS {
            return Err(Error::InvalidArgument);
        }

        for cpu in 0..nr_cpus {
            self.per_cpu[cpu].supported = true;
            self.per_cpu[cpu].online = true;
        }
        self.initialised = true;
        Ok(())
    }

    // ── Policy ───────────────────────────────────────────────

    /// Set the global default bias.
    pub fn set_default_bias(&mut self, bias: EpbHint) {
        self.policy.default_bias = bias;
    }

    /// Set whether to force the global bias on all CPUs.
    pub fn set_force_global(&mut self, force: bool) {
        self.policy.force_global = force;
    }

    /// Return the current policy.
    pub fn policy(&self) -> EpbPolicy {
        self.policy
    }

    // ── Per-CPU control ──────────────────────────────────────

    /// Set the EPB bias for a specific CPU.
    pub fn set_cpu_bias(&mut self, cpu: usize, bias: EpbHint) -> Result<()> {
        if cpu >= MAX_CPUS {
            return Err(Error::InvalidArgument);
        }
        if !self.per_cpu[cpu].supported {
            self.stats.total_failures += 1;
            return Err(Error::NotImplemented);
        }
        if self.per_cpu[cpu].locked {
            self.stats.total_failures += 1;
            return Err(Error::PermissionDenied);
        }

        self.per_cpu[cpu].bias = bias;
        self.per_cpu[cpu].raw_value = bias.raw();
        self.per_cpu[cpu].change_count += 1;
        self.stats.total_writes += 1;
        Ok(())
    }

    /// Read the EPB bias for a CPU.
    pub fn get_cpu_bias(&mut self, cpu: usize) -> Result<EpbHint> {
        if cpu >= MAX_CPUS {
            return Err(Error::InvalidArgument);
        }
        self.stats.total_reads += 1;
        Ok(self.per_cpu[cpu].bias)
    }

    /// Set all CPUs to the global default bias.
    pub fn apply_global(&mut self) -> Result<usize> {
        let bias = self.policy.default_bias;
        let mut applied = 0usize;
        for cpu in 0..MAX_CPUS {
            if self.per_cpu[cpu].supported && self.per_cpu[cpu].online && !self.per_cpu[cpu].locked
            {
                self.per_cpu[cpu].bias = bias;
                self.per_cpu[cpu].raw_value = bias.raw();
                self.per_cpu[cpu].change_count += 1;
                self.stats.total_writes += 1;
                applied += 1;
            }
        }
        Ok(applied)
    }

    /// Handle a CPU coming online (restore EPB).
    pub fn cpu_online(&mut self, cpu: usize) -> Result<()> {
        if cpu >= MAX_CPUS {
            return Err(Error::InvalidArgument);
        }
        self.per_cpu[cpu].online = true;

        if self.policy.restore_on_hotplug {
            let bias = if self.policy.force_global {
                self.policy.default_bias
            } else {
                self.per_cpu[cpu].bias
            };
            self.per_cpu[cpu].bias = bias;
            self.per_cpu[cpu].raw_value = bias.raw();
            self.stats.total_restores += 1;
        }
        Ok(())
    }

    /// Handle a CPU going offline.
    pub fn cpu_offline(&mut self, cpu: usize) -> Result<()> {
        if cpu >= MAX_CPUS {
            return Err(Error::InvalidArgument);
        }
        self.per_cpu[cpu].online = false;
        Ok(())
    }

    // ── Query ────────────────────────────────────────────────

    /// Return per-CPU state.
    pub fn cpu_state(&self, cpu: usize) -> Result<&CpuEpbState> {
        if cpu >= MAX_CPUS {
            return Err(Error::InvalidArgument);
        }
        Ok(&self.per_cpu[cpu])
    }

    /// Return statistics.
    pub fn stats(&self) -> EpbStats {
        self.stats
    }

    /// Return the number of supported CPUs.
    pub fn supported_count(&self) -> usize {
        self.per_cpu.iter().filter(|c| c.supported).count()
    }

    /// Return the number of online CPUs.
    pub fn online_count(&self) -> usize {
        self.per_cpu.iter().filter(|c| c.online).count()
    }
}
