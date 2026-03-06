// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! CPU frequency governor framework.
//!
//! Provides the infrastructure for dynamic CPU frequency scaling
//! (DVFS). Governors observe system load and request frequency
//! changes from the underlying `cpufreq` driver.
//!
//! # Built-in Governors
//!
//! - **Performance** — always request maximum frequency.
//! - **Powersave** — always request minimum frequency.
//! - **OnDemand** — scale frequency proportional to CPU load.
//! - **Conservative** — step frequency up/down gradually.
//! - **Schedutil** — integrate scheduler utilisation signals.
//!
//! # Architecture
//!
//! ```text
//! GovernorManager
//!  ├── governors: [Governor; MAX_GOVERNORS]
//!  ├── policies:  [FreqPolicy; MAX_CPUS]
//!  └── active_governor: GovernorId
//! ```

use oncrix_lib::{Error, Result};

// ======================================================================
// Constants
// ======================================================================

/// Maximum registered governors.
const MAX_GOVERNORS: usize = 8;

/// Maximum CPUs.
const MAX_CPUS: usize = 64;

/// Maximum governor name length.
const MAX_NAME_LEN: usize = 32;

/// Default sampling interval in microseconds.
const _DEFAULT_SAMPLING_US: u64 = 10_000;

// ======================================================================
// Types
// ======================================================================

/// Identifier for a registered governor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GovernorId(pub u8);

impl GovernorId {
    /// Creates a new governor identifier.
    pub const fn new(id: u8) -> Self {
        Self(id)
    }
}

impl Default for GovernorId {
    fn default() -> Self {
        Self(0)
    }
}

/// Governor type enumeration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GovernorType {
    /// Always request maximum frequency.
    Performance,
    /// Always request minimum frequency.
    Powersave,
    /// Scale proportionally to load.
    OnDemand,
    /// Step up/down gradually.
    Conservative,
    /// Scheduler-utilisation driven.
    Schedutil,
    /// User-defined / custom governor.
    Custom,
}

impl Default for GovernorType {
    fn default() -> Self {
        Self::Performance
    }
}

/// A registered frequency governor.
#[derive(Debug, Clone, Copy)]
pub struct Governor {
    /// Governor name (null-padded).
    pub name: [u8; MAX_NAME_LEN],
    /// Governor type.
    pub gov_type: GovernorType,
    /// Whether this governor is enabled.
    pub enabled: bool,
    /// Sampling interval in microseconds.
    pub sampling_us: u64,
    /// Up-threshold percentage (0-100) for on-demand style.
    pub up_threshold: u8,
    /// Down-threshold percentage (0-100) for conservative style.
    pub down_threshold: u8,
}

impl Governor {
    /// Creates a new governor with default settings.
    pub const fn new() -> Self {
        Self {
            name: [0u8; MAX_NAME_LEN],
            gov_type: GovernorType::Performance,
            enabled: false,
            sampling_us: 10_000,
            up_threshold: 80,
            down_threshold: 20,
        }
    }
}

impl Default for Governor {
    fn default() -> Self {
        Self::new()
    }
}

/// Per-CPU frequency policy.
#[derive(Debug, Clone, Copy)]
pub struct FreqPolicy {
    /// CPU identifier.
    pub cpu_id: u32,
    /// Minimum allowed frequency in kHz.
    pub min_khz: u32,
    /// Maximum allowed frequency in kHz.
    pub max_khz: u32,
    /// Current frequency in kHz.
    pub cur_khz: u32,
    /// Governor assigned to this CPU.
    pub governor_id: GovernorId,
    /// CPU utilisation (0-1024 fixed-point).
    pub util: u32,
    /// Whether this policy is active.
    pub active: bool,
}

impl FreqPolicy {
    /// Creates a new default frequency policy.
    pub const fn new() -> Self {
        Self {
            cpu_id: 0,
            min_khz: 0,
            max_khz: 0,
            cur_khz: 0,
            governor_id: GovernorId::new(0),
            util: 0,
            active: false,
        }
    }

    /// Creates a policy for a specific CPU with frequency bounds.
    pub fn with_range(cpu_id: u32, min_khz: u32, max_khz: u32) -> Result<Self> {
        if min_khz > max_khz {
            return Err(Error::InvalidArgument);
        }
        Ok(Self {
            cpu_id,
            min_khz,
            max_khz,
            cur_khz: min_khz,
            governor_id: GovernorId::new(0),
            util: 0,
            active: true,
        })
    }
}

impl Default for FreqPolicy {
    fn default() -> Self {
        Self::new()
    }
}

/// Manages governors and per-CPU frequency policies.
pub struct GovernorManager {
    /// Registered governors.
    governors: [Governor; MAX_GOVERNORS],
    /// Number of registered governors.
    nr_governors: usize,
    /// Per-CPU frequency policies.
    policies: [FreqPolicy; MAX_CPUS],
    /// Number of active policies.
    nr_policies: usize,
    /// System-wide active governor index.
    active_governor: GovernorId,
}

impl GovernorManager {
    /// Creates a new governor manager.
    pub const fn new() -> Self {
        Self {
            governors: [Governor::new(); MAX_GOVERNORS],
            nr_governors: 0,
            policies: [FreqPolicy::new(); MAX_CPUS],
            nr_policies: 0,
            active_governor: GovernorId::new(0),
        }
    }

    /// Registers a new governor.
    pub fn register_governor(&mut self, gov_type: GovernorType, name: &[u8]) -> Result<GovernorId> {
        if self.nr_governors >= MAX_GOVERNORS {
            return Err(Error::OutOfMemory);
        }
        if name.len() > MAX_NAME_LEN {
            return Err(Error::InvalidArgument);
        }
        let mut gov = Governor::new();
        gov.gov_type = gov_type;
        gov.enabled = true;
        let copy_len = name.len().min(MAX_NAME_LEN);
        gov.name[..copy_len].copy_from_slice(&name[..copy_len]);

        let id = self.nr_governors;
        self.governors[id] = gov;
        self.nr_governors += 1;
        Ok(GovernorId::new(id as u8))
    }

    /// Sets the system-wide active governor.
    pub fn set_active_governor(&mut self, id: GovernorId) -> Result<()> {
        if (id.0 as usize) >= self.nr_governors {
            return Err(Error::NotFound);
        }
        self.active_governor = id;
        Ok(())
    }

    /// Adds a per-CPU frequency policy.
    pub fn add_policy(&mut self, cpu_id: u32, min_khz: u32, max_khz: u32) -> Result<()> {
        if self.nr_policies >= MAX_CPUS {
            return Err(Error::OutOfMemory);
        }
        let policy = FreqPolicy::with_range(cpu_id, min_khz, max_khz)?;
        self.policies[self.nr_policies] = policy;
        self.policies[self.nr_policies].governor_id = self.active_governor;
        self.nr_policies += 1;
        Ok(())
    }

    /// Evaluates the governor for a CPU and returns the target freq.
    pub fn evaluate(&self, cpu_id: u32, util: u32) -> Result<u32> {
        let policy = self.policies[..self.nr_policies]
            .iter()
            .find(|p| p.cpu_id == cpu_id && p.active)
            .ok_or(Error::NotFound)?;

        let gov_idx = policy.governor_id.0 as usize;
        if gov_idx >= self.nr_governors {
            return Err(Error::NotFound);
        }
        let gov = &self.governors[gov_idx];

        let target = match gov.gov_type {
            GovernorType::Performance => policy.max_khz,
            GovernorType::Powersave => policy.min_khz,
            GovernorType::OnDemand | GovernorType::Schedutil => {
                let range = policy.max_khz - policy.min_khz;
                let scaled = (range as u64 * util as u64) / 1024;
                policy.min_khz + scaled as u32
            }
            GovernorType::Conservative => {
                if util > gov.up_threshold as u32 * 1024 / 100 {
                    policy
                        .cur_khz
                        .saturating_add((policy.max_khz - policy.min_khz) / 10)
                        .min(policy.max_khz)
                } else if util < gov.down_threshold as u32 * 1024 / 100 {
                    policy
                        .cur_khz
                        .saturating_sub((policy.max_khz - policy.min_khz) / 10)
                        .max(policy.min_khz)
                } else {
                    policy.cur_khz
                }
            }
            GovernorType::Custom => policy.cur_khz,
        };
        Ok(target)
    }

    /// Returns the number of registered governors.
    pub fn nr_governors(&self) -> usize {
        self.nr_governors
    }

    /// Returns the number of active policies.
    pub fn nr_policies(&self) -> usize {
        self.nr_policies
    }
}

impl Default for GovernorManager {
    fn default() -> Self {
        Self::new()
    }
}
