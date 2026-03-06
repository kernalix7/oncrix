// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Energy model for power-aware scheduling.
//!
//! Describes the energy characteristics of every CPU in the system,
//! organised into performance domains (PDs). Each PD groups CPUs
//! that share the same DVFS (Dynamic Voltage and Frequency Scaling)
//! domain — they always run at the same frequency and voltage.
//!
//! The scheduler uses this model to compute the marginal energy cost
//! of placing a task on each candidate CPU, selecting the option
//! that minimises total system energy.
//!
//! # Energy Estimation
//!
//! ```text
//! For a task with utilization u_task and a CPU with utilization u_cpu:
//!
//!   new_util = u_cpu + u_task
//!   opp      = smallest OPP where capacity >= new_util
//!   energy   = power(opp) * new_util / capacity(opp)
//! ```
//!
//! The energy model is populated from firmware (ACPI _CPC, device
//! tree `energy-model` nodes) or from hardware performance counters.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────┐
//! │                   EnergyModel                    │
//! │                                                  │
//! │  ┌──────────────┐  ┌──────────────┐             │
//! │  │  PerfDomain 0 │  │  PerfDomain 1 │  ...      │
//! │  │  CPUs: 0-3    │  │  CPUs: 4-7    │           │
//! │  │  OPPs:        │  │  OPPs:        │           │
//! │  │   500MHz 100mW│  │   800MHz 200mW│           │
//! │  │  1000MHz 300mW│  │  1600MHz 500mW│           │
//! │  │  1500MHz 600mW│  │  2400MHz 900mW│           │
//! │  └──────────────┘  └──────────────┘             │
//! └─────────────────────────────────────────────────┘
//! ```
//!
//! # Reference
//!
//! Linux `include/linux/energy_model.h`, `kernel/power/energy_model.c`.

use oncrix_lib::{Error, Result};

// ======================================================================
// Constants
// ======================================================================

/// Maximum number of performance domains.
const MAX_PERF_DOMAINS: usize = 16;

/// Maximum number of capacity states (OPPs) per domain.
const MAX_CAPACITY_STATES: usize = 32;

/// Maximum number of CPUs per performance domain.
const MAX_CPUS_PER_DOMAIN: usize = 32;

/// Maximum number of CPUs system-wide.
const MAX_CPUS: usize = 256;

/// Maximum name length for a performance domain.
const MAX_NAME_LEN: usize = 64;

/// Capacity scale factor (1024 = 100% of max compute capacity).
const CAPACITY_SCALE: u32 = 1024;

/// Maximum power cost value (milliwatts).
const _MAX_POWER_MW: u32 = 100_000;

// ======================================================================
// CapacityState — a single OPP in a performance domain
// ======================================================================

/// A single Operating Performance Point (OPP) / capacity state.
///
/// Represents a supported (frequency, power, capacity) triple
/// within a performance domain.
#[derive(Debug, Clone, Copy)]
pub struct CapacityState {
    /// CPU frequency in kHz.
    pub freq_khz: u32,
    /// Dynamic power consumption in milliwatts at this frequency.
    pub power_mw: u32,
    /// Normalised compute capacity (0 .. [`CAPACITY_SCALE`]).
    pub capacity: u32,
    /// Energy cost metric: power_mw * CAPACITY_SCALE / capacity.
    ///
    /// Pre-computed for fast lookup during scheduling. Lower is
    /// more efficient.
    pub cost: u64,
    /// Whether this state is active (can be selected by DVFS).
    pub active: bool,
}

impl CapacityState {
    /// Create an empty (unused) capacity state.
    const fn empty() -> Self {
        Self {
            freq_khz: 0,
            power_mw: 0,
            capacity: 0,
            cost: 0,
            active: false,
        }
    }

    /// Create a new capacity state and pre-compute the cost metric.
    pub const fn new(freq_khz: u32, power_mw: u32, capacity: u32) -> Self {
        let cost = if capacity > 0 {
            (power_mw as u64) * (CAPACITY_SCALE as u64) / (capacity as u64)
        } else {
            u64::MAX
        };
        Self {
            freq_khz,
            power_mw,
            capacity,
            cost,
            active: true,
        }
    }
}

// ======================================================================
// PowerCost — result of an energy estimate
// ======================================================================

/// Result of an energy cost estimation for a particular placement.
#[derive(Debug, Clone, Copy)]
pub struct PowerCost {
    /// The CPU on which the task would be placed.
    pub cpu_id: u32,
    /// The performance domain index.
    pub domain_idx: u32,
    /// The capacity state (OPP index) that would be selected.
    pub opp_idx: u32,
    /// Estimated energy cost (arbitrary units — lower is better).
    pub energy: u64,
    /// Frequency at the selected OPP (kHz).
    pub freq_khz: u32,
    /// Power at the selected OPP (mW).
    pub power_mw: u32,
}

impl PowerCost {
    /// Create an empty power cost.
    const fn empty() -> Self {
        Self {
            cpu_id: 0,
            domain_idx: 0,
            opp_idx: 0,
            energy: u64::MAX,
            freq_khz: 0,
            power_mw: 0,
        }
    }
}

// ======================================================================
// PerfDomain — a group of CPUs sharing a DVFS domain
// ======================================================================

/// A performance domain grouping CPUs with shared DVFS control.
#[derive(Debug, Clone, Copy)]
pub struct PerfDomain {
    /// Human-readable domain name.
    pub name: [u8; MAX_NAME_LEN],
    /// Name length in bytes.
    pub name_len: usize,
    /// Domain index.
    pub index: u32,
    /// Capacity states (OPPs), sorted by increasing frequency.
    pub states: [CapacityState; MAX_CAPACITY_STATES],
    /// Number of active capacity states.
    pub num_states: usize,
    /// CPU IDs belonging to this domain.
    pub cpus: [u32; MAX_CPUS_PER_DOMAIN],
    /// Number of CPUs in this domain.
    pub num_cpus: usize,
    /// Current utilization per CPU (0 .. CAPACITY_SCALE).
    pub cpu_util: [u32; MAX_CPUS_PER_DOMAIN],
    /// Maximum capacity across all OPPs.
    pub max_capacity: u32,
    /// Whether this domain has been registered.
    pub active: bool,
}

impl PerfDomain {
    /// Create an empty (inactive) performance domain.
    const fn empty() -> Self {
        Self {
            name: [0u8; MAX_NAME_LEN],
            name_len: 0,
            index: 0,
            states: [const { CapacityState::empty() }; MAX_CAPACITY_STATES],
            num_states: 0,
            cpus: [0u32; MAX_CPUS_PER_DOMAIN],
            num_cpus: 0,
            cpu_util: [0u32; MAX_CPUS_PER_DOMAIN],
            max_capacity: 0,
            active: false,
        }
    }

    /// Add a capacity state to this domain.
    ///
    /// States must be added in order of increasing frequency.
    fn add_state(&mut self, freq_khz: u32, power_mw: u32, capacity: u32) -> Result<()> {
        if self.num_states >= MAX_CAPACITY_STATES {
            return Err(Error::OutOfMemory);
        }
        if self.num_states > 0 {
            let prev = &self.states[self.num_states - 1];
            if freq_khz <= prev.freq_khz {
                return Err(Error::InvalidArgument);
            }
        }
        self.states[self.num_states] = CapacityState::new(freq_khz, power_mw, capacity);
        self.num_states += 1;
        if capacity > self.max_capacity {
            self.max_capacity = capacity;
        }
        Ok(())
    }

    /// Add a CPU to this domain.
    fn add_cpu(&mut self, cpu_id: u32) -> Result<()> {
        if self.num_cpus >= MAX_CPUS_PER_DOMAIN {
            return Err(Error::OutOfMemory);
        }
        // Check for duplicates.
        for i in 0..self.num_cpus {
            if self.cpus[i] == cpu_id {
                return Err(Error::AlreadyExists);
            }
        }
        self.cpus[self.num_cpus] = cpu_id;
        self.num_cpus += 1;
        Ok(())
    }

    /// Find the smallest OPP whose capacity >= `required_capacity`.
    fn find_opp(&self, required_capacity: u32) -> Option<usize> {
        for i in 0..self.num_states {
            if self.states[i].active && self.states[i].capacity >= required_capacity {
                return Some(i);
            }
        }
        // If no OPP is large enough, use the highest.
        if self.num_states > 0 {
            Some(self.num_states - 1)
        } else {
            None
        }
    }

    /// Compute energy cost for running additional `task_util` on
    /// the CPU at local index `cpu_local_idx`.
    fn compute_energy(&self, cpu_local_idx: usize, task_util: u32) -> Option<(u64, usize)> {
        if cpu_local_idx >= self.num_cpus || self.num_states == 0 {
            return None;
        }

        let current_util = self.cpu_util[cpu_local_idx];
        let new_util = current_util.saturating_add(task_util);
        let opp_idx = self.find_opp(new_util)?;
        let opp = &self.states[opp_idx];

        // energy = power * new_util / capacity (avoid division by 0).
        let energy = if opp.capacity > 0 {
            (opp.power_mw as u64) * (new_util as u64) / (opp.capacity as u64)
        } else {
            u64::MAX
        };

        Some((energy, opp_idx))
    }

    /// Update utilization for a CPU (by local index within domain).
    fn update_util(&mut self, cpu_local_idx: usize, util: u32) -> Result<()> {
        if cpu_local_idx >= self.num_cpus {
            return Err(Error::InvalidArgument);
        }
        self.cpu_util[cpu_local_idx] = util.min(CAPACITY_SCALE);
        Ok(())
    }

    /// Get the sum of utilization across all CPUs in this domain.
    fn total_util(&self) -> u64 {
        let mut sum = 0u64;
        for i in 0..self.num_cpus {
            sum += self.cpu_util[i] as u64;
        }
        sum
    }
}

// ======================================================================
// EnergyModel — system-wide energy model
// ======================================================================

/// System-wide energy model containing all performance domains.
pub struct EnergyModel {
    /// Performance domains.
    domains: [PerfDomain; MAX_PERF_DOMAINS],
    /// Number of registered domains.
    num_domains: usize,
    /// Reverse map: cpu_id -> (domain_index, local_cpu_index).
    cpu_to_domain: [(u32, u32); MAX_CPUS],
    /// Whether the model has been fully initialised.
    ready: bool,
}

impl EnergyModel {
    /// Create an empty energy model.
    pub const fn new() -> Self {
        Self {
            domains: [const { PerfDomain::empty() }; MAX_PERF_DOMAINS],
            num_domains: 0,
            cpu_to_domain: [(u32::MAX, u32::MAX); MAX_CPUS],
            ready: false,
        }
    }

    /// Register a new performance domain.
    ///
    /// Returns the domain index on success.
    pub fn register_domain(
        &mut self,
        name: &[u8],
        cpu_ids: &[u32],
        states: &[(u32, u32, u32)], // (freq_khz, power_mw, capacity)
    ) -> Result<u32> {
        if self.num_domains >= MAX_PERF_DOMAINS {
            return Err(Error::OutOfMemory);
        }
        if cpu_ids.is_empty() || states.is_empty() {
            return Err(Error::InvalidArgument);
        }

        let idx = self.num_domains;
        let domain = &mut self.domains[idx];
        let len = name.len().min(MAX_NAME_LEN);
        domain.name[..len].copy_from_slice(&name[..len]);
        domain.name_len = len;
        domain.index = idx as u32;
        domain.active = true;

        // Add capacity states (must be in ascending frequency order).
        for &(freq, power, cap) in states {
            domain.add_state(freq, power, cap)?;
        }

        // Add CPUs.
        for &cpu_id in cpu_ids {
            let cid = cpu_id as usize;
            if cid >= MAX_CPUS {
                return Err(Error::InvalidArgument);
            }
            if self.cpu_to_domain[cid].0 != u32::MAX {
                return Err(Error::AlreadyExists);
            }
            let local_idx = domain.num_cpus as u32;
            domain.add_cpu(cpu_id)?;
            self.cpu_to_domain[cid] = (idx as u32, local_idx);
        }

        self.num_domains += 1;
        Ok(idx as u32)
    }

    /// Mark the energy model as ready for use.
    pub fn finalize(&mut self) -> Result<()> {
        if self.num_domains == 0 {
            return Err(Error::InvalidArgument);
        }
        self.ready = true;
        Ok(())
    }

    /// Get the energy cost for placing a task on a specific CPU.
    pub fn get_cost(&self, cpu_id: u32, task_util: u32) -> Result<PowerCost> {
        if !self.ready {
            return Err(Error::NotImplemented);
        }
        let cid = cpu_id as usize;
        if cid >= MAX_CPUS {
            return Err(Error::InvalidArgument);
        }
        let (domain_idx, local_idx) = self.cpu_to_domain[cid];
        if domain_idx == u32::MAX {
            return Err(Error::NotFound);
        }

        let domain = &self.domains[domain_idx as usize];
        let (energy, opp_idx) = domain
            .compute_energy(local_idx as usize, task_util)
            .ok_or(Error::NotFound)?;

        let opp = &domain.states[opp_idx];
        Ok(PowerCost {
            cpu_id,
            domain_idx,
            opp_idx: opp_idx as u32,
            energy,
            freq_khz: opp.freq_khz,
            power_mw: opp.power_mw,
        })
    }

    /// Find the most energy-efficient CPU for a task.
    ///
    /// Evaluates every online CPU across all domains and returns the
    /// CPU ID with the lowest marginal energy cost.
    pub fn find_efficient_cpu(&self, task_util: u32, online_mask: &[bool]) -> Result<PowerCost> {
        if !self.ready {
            return Err(Error::NotImplemented);
        }

        let mut best = PowerCost::empty();
        let mask_len = online_mask.len();

        for d in 0..self.num_domains {
            let domain = &self.domains[d];
            if !domain.active {
                continue;
            }

            for c in 0..domain.num_cpus {
                let cpu_id = domain.cpus[c] as usize;
                if cpu_id >= mask_len || !online_mask[cpu_id] {
                    continue;
                }

                if let Some((energy, opp_idx)) = domain.compute_energy(c, task_util) {
                    if energy < best.energy {
                        let opp = &domain.states[opp_idx];
                        best = PowerCost {
                            cpu_id: cpu_id as u32,
                            domain_idx: d as u32,
                            opp_idx: opp_idx as u32,
                            energy,
                            freq_khz: opp.freq_khz,
                            power_mw: opp.power_mw,
                        };
                    }
                }
            }
        }

        if best.energy == u64::MAX {
            Err(Error::NotFound)
        } else {
            Ok(best)
        }
    }

    /// Update the utilization of a CPU.
    pub fn update_capacity(&mut self, cpu_id: u32, util: u32) -> Result<()> {
        let cid = cpu_id as usize;
        if cid >= MAX_CPUS {
            return Err(Error::InvalidArgument);
        }
        let (domain_idx, local_idx) = self.cpu_to_domain[cid];
        if domain_idx == u32::MAX {
            return Err(Error::NotFound);
        }
        self.domains[domain_idx as usize].update_util(local_idx as usize, util)
    }

    /// Get the performance domain for a CPU.
    pub fn get_domain_for_cpu(&self, cpu_id: u32) -> Result<&PerfDomain> {
        let cid = cpu_id as usize;
        if cid >= MAX_CPUS {
            return Err(Error::InvalidArgument);
        }
        let (domain_idx, _) = self.cpu_to_domain[cid];
        if domain_idx == u32::MAX {
            return Err(Error::NotFound);
        }
        Ok(&self.domains[domain_idx as usize])
    }

    /// Get a performance domain by index.
    pub fn get_domain(&self, idx: usize) -> Result<&PerfDomain> {
        if idx >= self.num_domains {
            return Err(Error::NotFound);
        }
        Ok(&self.domains[idx])
    }

    /// Get the number of registered domains.
    pub fn num_domains(&self) -> usize {
        self.num_domains
    }

    /// Check whether the energy model is ready.
    pub fn is_ready(&self) -> bool {
        self.ready
    }

    /// Compute the total energy for the entire system given current
    /// utilization values.
    pub fn total_system_energy(&self) -> Result<u64> {
        if !self.ready {
            return Err(Error::NotImplemented);
        }

        let mut total = 0u64;
        for d in 0..self.num_domains {
            let domain = &self.domains[d];
            if !domain.active {
                continue;
            }

            for c in 0..domain.num_cpus {
                let util = domain.cpu_util[c];
                if util == 0 {
                    continue;
                }
                if let Some(opp_idx) = domain.find_opp(util) {
                    let opp = &domain.states[opp_idx];
                    if opp.capacity > 0 {
                        total += (opp.power_mw as u64) * (util as u64) / (opp.capacity as u64);
                    }
                }
            }
        }

        Ok(total)
    }

    /// Disable a capacity state in a domain (e.g., thermal throttle).
    pub fn disable_state(&mut self, domain_idx: usize, opp_idx: usize) -> Result<()> {
        if domain_idx >= self.num_domains {
            return Err(Error::NotFound);
        }
        let domain = &mut self.domains[domain_idx];
        if opp_idx >= domain.num_states {
            return Err(Error::NotFound);
        }
        domain.states[opp_idx].active = false;
        Ok(())
    }

    /// Re-enable a previously disabled capacity state.
    pub fn enable_state(&mut self, domain_idx: usize, opp_idx: usize) -> Result<()> {
        if domain_idx >= self.num_domains {
            return Err(Error::NotFound);
        }
        let domain = &mut self.domains[domain_idx];
        if opp_idx >= domain.num_states {
            return Err(Error::NotFound);
        }
        domain.states[opp_idx].active = true;
        Ok(())
    }

    /// Get the maximum capacity across all domains.
    pub fn max_system_capacity(&self) -> u32 {
        let mut max = 0u32;
        for d in 0..self.num_domains {
            if self.domains[d].active && self.domains[d].max_capacity > max {
                max = self.domains[d].max_capacity;
            }
        }
        max
    }

    /// Get total utilization across the entire system.
    pub fn total_system_util(&self) -> u64 {
        let mut total = 0u64;
        for d in 0..self.num_domains {
            if self.domains[d].active {
                total += self.domains[d].total_util();
            }
        }
        total
    }
}
