// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! CPU idle state management (cpuidle) driver.
//!
//! Manages processor idle states (C-states) for power efficiency. Supports
//! ACPI-defined C-states and Intel-native C-states accessed via MWAIT/MONITOR
//! instructions or I/O port reads. Provides the idle governor interface for
//! selecting the deepest safe idle state.

use oncrix_lib::{Error, Result};

/// Maximum number of idle states per CPU.
pub const MAX_CSTATES: usize = 10;
/// Maximum number of CPUs managed.
pub const MAX_CPUS: usize = 64;

/// ACPI processor power state type.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CstateType {
    /// C0 — actively running.
    C0,
    /// C1 — halted (HALT instruction).
    C1,
    /// C1E — enhanced halt (on Intel).
    C1E,
    /// C2 — stop clock (requires I/O port read or MWAIT hint 0x10).
    C2,
    /// C3 — sleep (requires bus mastering disabled).
    C3,
    /// C6 — power gate (Intel Nehalem+).
    C6,
    /// C7 — deep power gate.
    C7,
    /// C8/C9/C10 — platform-specific deeper states.
    CDeep,
}

/// An individual CPU idle C-state.
#[derive(Clone, Copy, Debug)]
pub struct CstateDesc {
    /// State type.
    pub cstate: CstateType,
    /// State name (e.g., "POLL", "C1", "C1E", "C3-HSW").
    pub name: [u8; 16],
    /// Entry latency in microseconds.
    pub latency_us: u32,
    /// Exit latency in microseconds.
    pub exit_latency_us: u32,
    /// Target residency in microseconds (min useful sleep time).
    pub target_residency_us: u32,
    /// Power consumed in this state in milliwatts.
    pub power_mw: u32,
    /// State is enabled.
    pub enabled: bool,
}

impl CstateDesc {
    /// Create a C1 (HALT) state descriptor.
    pub const fn c1() -> Self {
        let mut name = [0u8; 16];
        name[0] = b'C';
        name[1] = b'1';
        Self {
            cstate: CstateType::C1,
            name,
            latency_us: 2,
            exit_latency_us: 2,
            target_residency_us: 4,
            power_mw: 1000,
            enabled: true,
        }
    }

    /// Create a C3 state descriptor.
    pub const fn c3(latency_us: u32) -> Self {
        let mut name = [0u8; 16];
        name[0] = b'C';
        name[1] = b'3';
        Self {
            cstate: CstateType::C3,
            name,
            latency_us,
            exit_latency_us: latency_us,
            target_residency_us: latency_us * 2,
            power_mw: 50,
            enabled: true,
        }
    }
}

/// Idle governor type.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IdleGovernor {
    /// Always use the deepest available state (maximum power savings).
    Deepest,
    /// Use ladder algorithm (from Linux menu governor).
    Ladder,
    /// Use the menu governor (predicted residency-based).
    Menu,
    /// Ticket-based scheduler-integrated governor.
    Teo,
}

/// Per-CPU idle statistics.
#[derive(Clone, Copy, Debug, Default)]
pub struct CpuIdleStats {
    /// Times this C-state was entered.
    pub usage: u64,
    /// Total time spent in this state (microseconds).
    pub time_us: u64,
    /// Number of times this state was rejected by the governor.
    pub above: u64,
    /// Number of times the actual sleep was shorter than predicted.
    pub below: u64,
}

/// cpuidle driver state.
pub struct CpuIdle {
    /// Available C-states (shared across CPUs on this platform).
    cstates: [Option<CstateDesc>; MAX_CSTATES],
    /// Number of registered C-states.
    num_cstates: usize,
    /// Per-CPU, per-state statistics.
    stats: [[CpuIdleStats; MAX_CSTATES]; MAX_CPUS],
    /// Active governor.
    governor: IdleGovernor,
    /// Number of CPUs.
    num_cpus: usize,
}

impl CpuIdle {
    /// Create a new cpuidle driver for `num_cpus` CPUs.
    pub fn new(num_cpus: usize) -> Self {
        Self {
            cstates: [const { None }; MAX_CSTATES],
            num_cstates: 0,
            stats: [[const {
                CpuIdleStats {
                    usage: 0,
                    time_us: 0,
                    above: 0,
                    below: 0,
                }
            }; MAX_CSTATES]; MAX_CPUS],
            governor: IdleGovernor::Menu,
            num_cpus: num_cpus.min(MAX_CPUS),
        }
    }

    /// Register an available C-state.
    pub fn add_cstate(&mut self, desc: CstateDesc) -> Result<()> {
        if self.num_cstates >= MAX_CSTATES {
            return Err(Error::OutOfMemory);
        }
        self.cstates[self.num_cstates] = Some(desc);
        self.num_cstates += 1;
        Ok(())
    }

    /// Set the idle governor.
    pub fn set_governor(&mut self, gov: IdleGovernor) {
        self.governor = gov;
    }

    /// Select the best C-state for the given expected idle duration.
    ///
    /// Returns the index of the selected C-state.
    pub fn select_cstate(&self, predicted_us: u32) -> usize {
        match self.governor {
            IdleGovernor::Deepest => {
                // Pick deepest enabled state.
                for i in (0..self.num_cstates).rev() {
                    if let Some(ref cs) = self.cstates[i] {
                        if cs.enabled {
                            return i;
                        }
                    }
                }
                0
            }
            IdleGovernor::Menu | IdleGovernor::Ladder | IdleGovernor::Teo => {
                // Select deepest state whose target residency <= predicted_us.
                let mut best = 0;
                for i in 0..self.num_cstates {
                    if let Some(ref cs) = self.cstates[i] {
                        if cs.enabled && cs.target_residency_us <= predicted_us {
                            best = i;
                        }
                    }
                }
                best
            }
        }
    }

    /// Enter the selected C-state on the current CPU.
    pub fn enter_idle(&mut self, cpu: usize, cstate_idx: usize) -> Result<()> {
        if cpu >= self.num_cpus || cstate_idx >= self.num_cstates {
            return Err(Error::InvalidArgument);
        }
        let desc = self.cstates[cstate_idx].as_ref().ok_or(Error::NotFound)?;
        if !desc.enabled {
            return Err(Error::InvalidArgument);
        }
        match desc.cstate {
            CstateType::C0 => {}
            CstateType::C1 | CstateType::C1E => {
                #[cfg(target_arch = "x86_64")]
                // SAFETY: HLT is a valid processor instruction that halts the CPU
                // until the next interrupt. It is safe to execute in ring 0.
                unsafe {
                    core::arch::asm!("hlt", options(nomem, nostack));
                }
            }
            CstateType::C2
            | CstateType::C3
            | CstateType::C6
            | CstateType::C7
            | CstateType::CDeep => {
                #[cfg(target_arch = "x86_64")]
                // SAFETY: MWAIT with hint 0 enters the deepest C-state supported
                // by the current MWAIT hint encoding. The CPU resumes on interrupt.
                unsafe {
                    core::arch::asm!(
                        "xor eax, eax",
                        "xor ecx, ecx",
                        "monitor",
                        "mwait",
                        options(nomem, nostack)
                    );
                }
            }
        }
        self.stats[cpu][cstate_idx].usage += 1;
        Ok(())
    }

    /// Update idle statistics for a CPU after waking from idle.
    pub fn record_idle_time(&mut self, cpu: usize, cstate_idx: usize, duration_us: u64) {
        if cpu < self.num_cpus && cstate_idx < self.num_cstates {
            self.stats[cpu][cstate_idx].time_us = self.stats[cpu][cstate_idx]
                .time_us
                .saturating_add(duration_us);
        }
    }

    /// Enable or disable a C-state globally.
    pub fn set_cstate_enabled(&mut self, cstate_idx: usize, enabled: bool) -> Result<()> {
        let desc = self
            .cstates
            .get_mut(cstate_idx)
            .and_then(Option::as_mut)
            .ok_or(Error::NotFound)?;
        desc.enabled = enabled;
        Ok(())
    }

    /// Return an immutable reference to a C-state descriptor.
    pub fn cstate(&self, idx: usize) -> Option<&CstateDesc> {
        self.cstates.get(idx).and_then(Option::as_ref)
    }

    /// Return the number of registered C-states.
    pub fn num_cstates(&self) -> usize {
        self.num_cstates
    }

    /// Return a reference to per-CPU per-state statistics.
    pub fn stats(&self, cpu: usize, cstate_idx: usize) -> Option<&CpuIdleStats> {
        if cpu < self.num_cpus && cstate_idx < self.num_cstates {
            Some(&self.stats[cpu][cstate_idx])
        } else {
            None
        }
    }
}
