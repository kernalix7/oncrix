// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! CPU frequency governor framework.
//!
//! Implements the governor abstraction that decides which CPU
//! frequency to request based on current load. Includes built-in
//! governors: performance, powersave, ondemand, and conservative.
//!
//! # Architecture
//!
//! ```text
//! FreqGovernorManager
//!  ├── governors[MAX_GOVERNORS]     (registered governor policies)
//!  ├── cpu_state[MAX_CPUS]          (per-CPU frequency state)
//!  └── stats: GovernorStats
//! ```
//!
//! # Reference
//!
//! Linux `drivers/cpufreq/cpufreq_governor.c`.

use oncrix_lib::{Error, Result};

// ══════════════════════════════════════════════════════════════
// Constants
// ══════════════════════════════════════════════════════════════

/// Maximum registered governors.
const MAX_GOVERNORS: usize = 8;

/// Maximum CPUs.
const MAX_CPUS: usize = 64;

/// Default sampling interval in microseconds.
const DEFAULT_SAMPLING_US: u64 = 50_000;

/// Ondemand up-threshold (percentage).
const ONDEMAND_UP_THRESHOLD: u32 = 80;

/// Conservative step (percentage per sample).
const CONSERVATIVE_STEP: u32 = 5;

// ══════════════════════════════════════════════════════════════
// GovernorType — built-in governor identifiers
// ══════════════════════════════════════════════════════════════

/// Identifies a CPU frequency governor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum GovernorType {
    /// Always request maximum frequency.
    Performance = 0,
    /// Always request minimum frequency.
    Powersave = 1,
    /// Scale frequency based on load (jump to max above threshold).
    Ondemand = 2,
    /// Scale frequency incrementally based on load.
    Conservative = 3,
    /// Let the hardware/firmware decide.
    Schedutil = 4,
}

// ══════════════════════════════════════════════════════════════
// GovernorEntry — registered governor
// ══════════════════════════════════════════════════════════════

/// A registered frequency governor.
#[derive(Debug, Clone, Copy)]
pub struct GovernorEntry {
    /// Governor type.
    pub gov_type: GovernorType,
    /// Sampling interval in microseconds.
    pub sampling_us: u64,
    /// Up threshold (percentage, for ondemand/conservative).
    pub up_threshold: u32,
    /// Down threshold (percentage, for conservative).
    pub down_threshold: u32,
    /// Step size (percentage, for conservative).
    pub step: u32,
    /// Whether this governor is registered.
    pub registered: bool,
}

impl GovernorEntry {
    /// Create an unregistered entry.
    const fn empty() -> Self {
        Self {
            gov_type: GovernorType::Performance,
            sampling_us: DEFAULT_SAMPLING_US,
            up_threshold: ONDEMAND_UP_THRESHOLD,
            down_threshold: 20,
            step: CONSERVATIVE_STEP,
            registered: false,
        }
    }
}

// ══════════════════════════════════════════════════════════════
// CpuFreqState — per-CPU state
// ══════════════════════════════════════════════════════════════

/// Per-CPU frequency state managed by the active governor.
#[derive(Debug, Clone, Copy)]
pub struct CpuFreqState {
    /// Current frequency in kHz.
    pub current_freq_khz: u32,
    /// Minimum allowed frequency in kHz.
    pub min_freq_khz: u32,
    /// Maximum allowed frequency in kHz.
    pub max_freq_khz: u32,
    /// Current CPU load (0-100 percentage).
    pub load_pct: u32,
    /// Active governor type for this CPU.
    pub governor: GovernorType,
    /// Whether this CPU is online for freq scaling.
    pub online: bool,
    /// Total frequency transitions.
    pub transitions: u64,
}

impl CpuFreqState {
    /// Create an offline CPU state.
    const fn empty() -> Self {
        Self {
            current_freq_khz: 0,
            min_freq_khz: 0,
            max_freq_khz: 0,
            load_pct: 0,
            governor: GovernorType::Performance,
            online: false,
            transitions: 0,
        }
    }
}

// ══════════════════════════════════════════════════════════════
// GovernorStats
// ══════════════════════════════════════════════════════════════

/// Global governor statistics.
#[derive(Debug, Clone, Copy)]
pub struct GovernorStats {
    /// Total governor evaluations.
    pub evaluations: u64,
    /// Total frequency transitions requested.
    pub transitions: u64,
    /// Total governor switches.
    pub governor_switches: u64,
}

impl GovernorStats {
    /// Create zeroed stats.
    const fn new() -> Self {
        Self {
            evaluations: 0,
            transitions: 0,
            governor_switches: 0,
        }
    }
}

// ══════════════════════════════════════════════════════════════
// FreqGovernorManager
// ══════════════════════════════════════════════════════════════

/// CPU frequency governor manager.
pub struct FreqGovernorManager {
    /// Registered governors.
    governors: [GovernorEntry; MAX_GOVERNORS],
    /// Per-CPU frequency state.
    cpus: [CpuFreqState; MAX_CPUS],
    /// Statistics.
    stats: GovernorStats,
}

impl FreqGovernorManager {
    /// Create a new governor manager.
    pub const fn new() -> Self {
        Self {
            governors: [const { GovernorEntry::empty() }; MAX_GOVERNORS],
            cpus: [const { CpuFreqState::empty() }; MAX_CPUS],
            stats: GovernorStats::new(),
        }
    }

    /// Register a governor.
    pub fn register_governor(&mut self, gov_type: GovernorType) -> Result<usize> {
        // Check for duplicate.
        if self
            .governors
            .iter()
            .any(|g| g.registered && g.gov_type == gov_type)
        {
            return Err(Error::AlreadyExists);
        }
        let slot = self
            .governors
            .iter()
            .position(|g| !g.registered)
            .ok_or(Error::OutOfMemory)?;
        self.governors[slot].gov_type = gov_type;
        self.governors[slot].registered = true;
        Ok(slot)
    }

    /// Bring a CPU online for frequency scaling.
    pub fn cpu_online(
        &mut self,
        cpu: u32,
        min_khz: u32,
        max_khz: u32,
        governor: GovernorType,
    ) -> Result<()> {
        let c = cpu as usize;
        if c >= MAX_CPUS {
            return Err(Error::InvalidArgument);
        }
        self.cpus[c].min_freq_khz = min_khz;
        self.cpus[c].max_freq_khz = max_khz;
        self.cpus[c].current_freq_khz = min_khz;
        self.cpus[c].governor = governor;
        self.cpus[c].online = true;
        Ok(())
    }

    /// Evaluate the governor for a CPU and return the new frequency.
    ///
    /// This is the core governor decision logic.
    pub fn evaluate(&mut self, cpu: u32, load_pct: u32) -> Result<u32> {
        let c = cpu as usize;
        if c >= MAX_CPUS || !self.cpus[c].online {
            return Err(Error::InvalidArgument);
        }
        self.cpus[c].load_pct = load_pct;
        self.stats.evaluations += 1;

        let new_freq = match self.cpus[c].governor {
            GovernorType::Performance => self.cpus[c].max_freq_khz,
            GovernorType::Powersave => self.cpus[c].min_freq_khz,
            GovernorType::Ondemand => {
                if load_pct >= ONDEMAND_UP_THRESHOLD {
                    self.cpus[c].max_freq_khz
                } else {
                    let range = self.cpus[c].max_freq_khz - self.cpus[c].min_freq_khz;
                    let scaled = (range as u64 * load_pct as u64 / 100) as u32;
                    self.cpus[c].min_freq_khz + scaled
                }
            }
            GovernorType::Conservative => {
                let cur = self.cpus[c].current_freq_khz;
                let range = self.cpus[c].max_freq_khz - self.cpus[c].min_freq_khz;
                let step = range * CONSERVATIVE_STEP / 100;
                if load_pct >= ONDEMAND_UP_THRESHOLD {
                    (cur + step).min(self.cpus[c].max_freq_khz)
                } else if load_pct < 20 {
                    cur.saturating_sub(step).max(self.cpus[c].min_freq_khz)
                } else {
                    cur
                }
            }
            GovernorType::Schedutil => {
                let range = self.cpus[c].max_freq_khz - self.cpus[c].min_freq_khz;
                let scaled = (range as u64 * load_pct as u64 / 100) as u32;
                self.cpus[c].min_freq_khz + scaled
            }
        };

        if new_freq != self.cpus[c].current_freq_khz {
            self.cpus[c].current_freq_khz = new_freq;
            self.cpus[c].transitions += 1;
            self.stats.transitions += 1;
        }
        Ok(new_freq)
    }

    /// Switch governor for a CPU.
    pub fn set_governor(&mut self, cpu: u32, governor: GovernorType) -> Result<()> {
        let c = cpu as usize;
        if c >= MAX_CPUS || !self.cpus[c].online {
            return Err(Error::InvalidArgument);
        }
        self.cpus[c].governor = governor;
        self.stats.governor_switches += 1;
        Ok(())
    }

    /// Return per-CPU state.
    pub fn cpu_state(&self, cpu: u32) -> Result<&CpuFreqState> {
        let c = cpu as usize;
        if c >= MAX_CPUS {
            return Err(Error::InvalidArgument);
        }
        Ok(&self.cpus[c])
    }

    /// Return statistics.
    pub fn stats(&self) -> GovernorStats {
        self.stats
    }
}
