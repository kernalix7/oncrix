// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! CPU frequency scaling driver.
//!
//! Provides the cpufreq abstraction for controlling processor operating
//! frequency and voltage via ACPI P-states (Enhanced SpeedStep on Intel,
//! Cool'n'Quiet on AMD) or MSR-based frequency control.

use oncrix_lib::{Error, Result};

/// Maximum number of P-states per CPU.
const MAX_PSTATES: usize = 32;

/// Maximum number of CPUs tracked.
const MAX_CPUS: usize = 64;

/// Intel SpeedStep MSR addresses.
const MSR_PLATFORM_INFO: u32 = 0xCE;
const MSR_IA32_PERF_CTL: u32 = 0x199;
const MSR_IA32_PERF_STATUS: u32 = 0x198;
const MSR_IA32_MPERF: u32 = 0xE7; // Actual performance counter
const MSR_IA32_APERF: u32 = 0xE8; // Reference cycles

/// AMD PState MSRs.
const MSR_AMD_PSTATE_DEF_0: u32 = 0xC001_0064;
const MSR_AMD_PSTATE_CTL: u32 = 0xC001_0062;
const MSR_AMD_PSTATE_STATUS: u32 = 0xC001_0063;

/// CPU frequency governor type.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Governor {
    /// Always use the highest frequency (performance).
    Performance,
    /// Always use the lowest frequency (power saving).
    PowerSave,
    /// Scale frequency to demand (userspace / ondemand).
    OnDemand,
    /// Schedule-driven frequency scaling.
    Schedutil,
    /// Fixed frequency set by userspace.
    Userspace,
}

/// A single P-state (frequency/voltage operating point).
#[derive(Clone, Copy, Debug, Default)]
pub struct PState {
    /// CPU frequency in kHz.
    pub freq_khz: u32,
    /// Core voltage in millivolts.
    pub voltage_mv: u16,
    /// Hardware P-state ratio (FID/DID encoding, platform-specific).
    pub hw_value: u16,
    /// Power consumption in milliwatts (estimated).
    pub power_mw: u32,
    /// Transition latency in microseconds.
    pub latency_us: u16,
}

/// Per-CPU frequency state.
#[derive(Clone, Copy, Debug)]
pub struct CpuFreqState {
    /// Current P-state index (0 = highest frequency).
    pub cur_pstate: usize,
    /// Minimum allowed P-state index.
    pub min_pstate: usize,
    /// Maximum allowed P-state index.
    pub max_pstate: usize,
    /// Number of P-states available.
    pub num_pstates: usize,
    /// Active governor.
    pub governor: Governor,
    /// Boost (turbo) is enabled.
    pub boost_enabled: bool,
}

impl Default for CpuFreqState {
    fn default() -> Self {
        Self {
            cur_pstate: 0,
            min_pstate: 0,
            max_pstate: 0,
            num_pstates: 0,
            governor: Governor::OnDemand,
            boost_enabled: true,
        }
    }
}

/// cpufreq driver (manages all CPUs in the system).
pub struct CpuFreq {
    /// Available P-states (shared across all CPUs on this platform).
    pstates: [PState; MAX_PSTATES],
    /// Number of available P-states.
    num_pstates: usize,
    /// Per-CPU frequency state.
    cpu_state: [CpuFreqState; MAX_CPUS],
    /// Number of CPUs.
    num_cpus: usize,
    /// Platform is Intel SpeedStep-compatible.
    is_intel: bool,
}

impl CpuFreq {
    /// Create a new cpufreq driver for `num_cpus` processors.
    pub fn new(num_cpus: usize, is_intel: bool) -> Self {
        Self {
            pstates: [const {
                PState {
                    freq_khz: 0,
                    voltage_mv: 0,
                    hw_value: 0,
                    power_mw: 0,
                    latency_us: 0,
                }
            }; MAX_PSTATES],
            num_pstates: 0,
            cpu_state: [const {
                CpuFreqState {
                    cur_pstate: 0,
                    min_pstate: 0,
                    max_pstate: 0,
                    num_pstates: 0,
                    governor: Governor::OnDemand,
                    boost_enabled: true,
                }
            }; MAX_CPUS],
            num_cpus: num_cpus.min(MAX_CPUS),
            is_intel,
        }
    }

    /// Register an available P-state.
    pub fn add_pstate(&mut self, pstate: PState) -> Result<()> {
        if self.num_pstates >= MAX_PSTATES {
            return Err(Error::OutOfMemory);
        }
        self.pstates[self.num_pstates] = pstate;
        self.num_pstates += 1;
        // Update per-CPU max P-state index.
        for state in self.cpu_state[..self.num_cpus].iter_mut() {
            state.num_pstates = self.num_pstates;
            state.max_pstate = self.num_pstates - 1;
        }
        Ok(())
    }

    /// Set the governor for a specific CPU.
    pub fn set_governor(&mut self, cpu: usize, gov: Governor) -> Result<()> {
        if cpu >= self.num_cpus {
            return Err(Error::InvalidArgument);
        }
        self.cpu_state[cpu].governor = gov;
        Ok(())
    }

    /// Request a frequency transition for a CPU to the target P-state.
    pub fn set_pstate(&mut self, cpu: usize, pstate_idx: usize) -> Result<()> {
        if cpu >= self.num_cpus {
            return Err(Error::InvalidArgument);
        }
        let state = &self.cpu_state[cpu];
        if pstate_idx < state.min_pstate || pstate_idx > state.max_pstate {
            return Err(Error::InvalidArgument);
        }
        let hw_val = self.pstates[pstate_idx].hw_value;
        self.write_perf_ctl(cpu, hw_val)?;
        self.cpu_state[cpu].cur_pstate = pstate_idx;
        Ok(())
    }

    /// Read the current hardware P-state for a CPU.
    pub fn read_current_pstate(&self, cpu: usize) -> Result<usize> {
        if cpu >= self.num_cpus {
            return Err(Error::InvalidArgument);
        }
        let hw_val = self.read_perf_status(cpu)?;
        // Find the matching P-state.
        for (i, ps) in self.pstates[..self.num_pstates].iter().enumerate() {
            if ps.hw_value == hw_val {
                return Ok(i);
            }
        }
        // Return current cached value if no exact match.
        Ok(self.cpu_state[cpu].cur_pstate)
    }

    /// Set the minimum and maximum allowed frequency (in kHz) for a CPU.
    pub fn set_freq_range(&mut self, cpu: usize, min_khz: u32, max_khz: u32) -> Result<()> {
        if cpu >= self.num_cpus || min_khz > max_khz {
            return Err(Error::InvalidArgument);
        }
        // Map kHz to P-state indices.
        let min_idx = self.pstates[..self.num_pstates]
            .iter()
            .position(|ps| ps.freq_khz >= min_khz)
            .unwrap_or(self.num_pstates - 1);
        let max_idx = self.pstates[..self.num_pstates]
            .iter()
            .rposition(|ps| ps.freq_khz <= max_khz)
            .unwrap_or(0);
        self.cpu_state[cpu].min_pstate = min_idx;
        self.cpu_state[cpu].max_pstate = max_idx;
        Ok(())
    }

    /// Enable or disable turbo/boost for a CPU.
    pub fn set_boost(&mut self, cpu: usize, enable: bool) -> Result<()> {
        if cpu >= self.num_cpus {
            return Err(Error::InvalidArgument);
        }
        self.cpu_state[cpu].boost_enabled = enable;
        Ok(())
    }

    /// Return the P-state table entry for the given index.
    pub fn pstate_info(&self, idx: usize) -> Option<&PState> {
        if idx < self.num_pstates {
            Some(&self.pstates[idx])
        } else {
            None
        }
    }

    /// Return a reference to the per-CPU state.
    pub fn cpu_state(&self, cpu: usize) -> Option<&CpuFreqState> {
        if cpu < self.num_cpus {
            Some(&self.cpu_state[cpu])
        } else {
            None
        }
    }

    /// Write the IA32_PERF_CTL MSR for a CPU.
    fn write_perf_ctl(&self, _cpu: usize, hw_val: u16) -> Result<()> {
        let msr = if self.is_intel {
            MSR_IA32_PERF_CTL
        } else {
            MSR_AMD_PSTATE_CTL
        };
        #[cfg(target_arch = "x86_64")]
        // SAFETY: IA32_PERF_CTL / AMD_PSTATE_CTL MSRs control CPU P-state;
        // hw_val is a validated hardware ratio from the P-state table.
        unsafe {
            core::arch::asm!(
                "wrmsr",
                in("ecx") msr,
                in("eax") (hw_val as u32) << 8,
                in("edx") 0u32,
                options(nomem, nostack)
            );
        }
        Ok(())
    }

    /// Read IA32_PERF_STATUS to get the current hardware frequency ratio.
    fn read_perf_status(&self, _cpu: usize) -> Result<u16> {
        let msr = if self.is_intel {
            MSR_IA32_PERF_STATUS
        } else {
            MSR_AMD_PSTATE_STATUS
        };
        #[cfg(target_arch = "x86_64")]
        {
            let lo: u32;
            let hi: u32;
            // SAFETY: IA32_PERF_STATUS is a read-only MSR reporting current frequency.
            unsafe {
                core::arch::asm!(
                    "rdmsr",
                    in("ecx") msr,
                    out("eax") lo,
                    out("edx") hi,
                    options(nomem, nostack)
                );
            }
            let _ = hi;
            return Ok(((lo >> 8) & 0xFF) as u16);
        }
        #[allow(unreachable_code)]
        Ok(0)
    }
}
