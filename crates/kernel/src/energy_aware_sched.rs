// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Energy-Aware Scheduling (EAS).
//!
//! Selects the most energy-efficient CPU for task placement by
//! combining an energy model (per-cluster OPP tables) with
//! utilization estimates.
//!
//! # Architecture
//!
//! | Component              | Purpose                                    |
//! |------------------------|--------------------------------------------|
//! | [`OppEntry`]           | Operating Performance Point (freq + power) |
//! | [`PerformanceDomain`]  | CPU cluster with shared OPP table          |
//! | [`EnergyModel`]        | System-wide collection of perf domains     |
//! | [`EasRegistry`]        | Scheduling interface: find best CPU        |
//!
//! # Energy Estimation
//!
//! For each candidate CPU the scheduler estimates the energy cost
//! of running a task at that CPU's current OPP:
//!
//! ```text
//! energy = power(opp) * (util_cpu + util_task) / capacity(opp)
//! ```
//!
//! The CPU (and OPP) that minimises total domain energy wins.

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum number of performance domains (CPU clusters).
const MAX_PERF_DOMAINS: usize = 8;

/// Maximum number of OPPs per performance domain.
const MAX_OPPS: usize = 16;

/// Maximum number of CPUs per performance domain.
const MAX_CPUS_PER_DOMAIN: usize = 16;

/// Maximum number of CPUs system-wide.
const MAX_CPUS: usize = 128;

/// Maximum name length for a performance domain.
const MAX_NAME_LEN: usize = 32;

// ---------------------------------------------------------------------------
// OppEntry — Operating Performance Point
// ---------------------------------------------------------------------------

/// An Operating Performance Point in a CPU's DVFS table.
///
/// Each entry represents a supported (frequency, power) pair.
/// The `capacity` field is the normalised compute capacity at
/// this frequency (0..1024, where 1024 = max system capacity).
#[derive(Debug, Clone, Copy)]
pub struct OppEntry {
    /// Frequency in kHz.
    pub freq_khz: u32,
    /// Power consumption in milliwatts at this frequency.
    pub power_mw: u32,
    /// Normalised capacity (0..1024).
    pub capacity: u32,
}

impl OppEntry {
    /// Create a new OPP entry.
    pub const fn new(freq_khz: u32, power_mw: u32, capacity: u32) -> Self {
        Self {
            freq_khz,
            power_mw,
            capacity,
        }
    }

    /// Empty (unused) OPP entry.
    const fn empty() -> Self {
        Self {
            freq_khz: 0,
            power_mw: 0,
            capacity: 0,
        }
    }
}

impl Default for OppEntry {
    fn default() -> Self {
        Self::empty()
    }
}

// ---------------------------------------------------------------------------
// PerformanceDomain — CPU cluster
// ---------------------------------------------------------------------------

/// A performance domain groups CPUs that share the same voltage
/// and frequency domain (e.g. a big.LITTLE cluster).
///
/// Each domain has an OPP table sorted by frequency (ascending).
#[derive(Debug, Clone, Copy)]
pub struct PerformanceDomain {
    /// Domain identifier.
    pub id: u32,
    /// Human-readable name (e.g. "little", "big", "prime").
    pub name: [u8; MAX_NAME_LEN],
    /// Name length in bytes.
    name_len: usize,
    /// OPP table sorted by ascending frequency.
    pub opps: [OppEntry; MAX_OPPS],
    /// Number of valid entries in `opps`.
    pub opp_count: usize,
    /// CPU IDs belonging to this domain.
    pub cpus: [u32; MAX_CPUS_PER_DOMAIN],
    /// Number of CPUs in this domain.
    pub cpu_count: usize,
    /// Index of the currently active OPP.
    pub active_opp: usize,
    /// Whether this domain slot is in use.
    pub in_use: bool,
}

impl PerformanceDomain {
    /// Creates an empty (inactive) domain.
    const fn empty() -> Self {
        Self {
            id: 0,
            name: [0u8; MAX_NAME_LEN],
            name_len: 0,
            opps: [OppEntry::empty(); MAX_OPPS],
            opp_count: 0,
            cpus: [0u32; MAX_CPUS_PER_DOMAIN],
            cpu_count: 0,
            active_opp: 0,
            in_use: false,
        }
    }

    /// Maximum capacity of this domain (highest OPP).
    pub fn max_capacity(&self) -> u32 {
        if self.opp_count == 0 {
            return 0;
        }
        self.opps[self.opp_count - 1].capacity
    }

    /// Current capacity at the active OPP.
    pub fn current_capacity(&self) -> u32 {
        if self.active_opp < self.opp_count {
            self.opps[self.active_opp].capacity
        } else {
            0
        }
    }

    /// Current power draw at the active OPP (mW).
    pub fn current_power(&self) -> u32 {
        if self.active_opp < self.opp_count {
            self.opps[self.active_opp].power_mw
        } else {
            0
        }
    }

    /// Whether a CPU belongs to this domain.
    pub fn contains_cpu(&self, cpu_id: u32) -> bool {
        self.cpus[..self.cpu_count].contains(&cpu_id)
    }

    /// Set the active OPP index.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `opp_idx` is out of
    /// range.
    pub fn set_active_opp(&mut self, opp_idx: usize) -> Result<()> {
        if opp_idx >= self.opp_count {
            return Err(Error::InvalidArgument);
        }
        self.active_opp = opp_idx;
        Ok(())
    }

    /// Find the lowest OPP that satisfies a utilization level.
    ///
    /// `util` is in the range 0..1024. Returns the index of the
    /// cheapest OPP whose capacity >= `util`, or the highest OPP
    /// if none is sufficient.
    pub fn find_opp_for_util(&self, util: u32) -> usize {
        for (i, opp) in self.opps[..self.opp_count].iter().enumerate() {
            if opp.capacity >= util {
                return i;
            }
        }
        // Fall back to highest OPP.
        if self.opp_count > 0 {
            self.opp_count - 1
        } else {
            0
        }
    }

    /// Estimate energy for running `util` units of work at a
    /// given OPP.
    ///
    /// ```text
    /// energy = power(opp) * util / capacity(opp)
    /// ```
    ///
    /// Returns energy in arbitrary units (proportional to mW * utilization).
    pub fn estimate_energy(&self, opp_idx: usize, util: u32) -> u64 {
        if opp_idx >= self.opp_count {
            return u64::MAX;
        }
        let opp = &self.opps[opp_idx];
        if opp.capacity == 0 {
            return u64::MAX;
        }
        (opp.power_mw as u64) * (util as u64) / (opp.capacity as u64)
    }
}

// ---------------------------------------------------------------------------
// EnergyModel — system-wide model
// ---------------------------------------------------------------------------

/// System-wide energy model containing all performance domains.
pub struct EnergyModel {
    /// Performance domains.
    domains: [PerformanceDomain; MAX_PERF_DOMAINS],
    /// Next domain ID.
    next_id: u32,
    /// Number of active domains.
    domain_count: usize,
}

impl EnergyModel {
    /// Create an empty energy model.
    pub const fn new() -> Self {
        const EMPTY: PerformanceDomain = PerformanceDomain::empty();
        Self {
            domains: [EMPTY; MAX_PERF_DOMAINS],
            next_id: 1,
            domain_count: 0,
        }
    }

    /// Number of active performance domains.
    pub fn domain_count(&self) -> usize {
        self.domain_count
    }

    /// Register a new performance domain.
    ///
    /// Returns the domain ID.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidArgument`] — name is empty or too long,
    ///   or no OPPs / CPUs provided.
    /// - [`Error::OutOfMemory`] — no free domain slots.
    pub fn register_domain(&mut self, name: &[u8], opps: &[OppEntry], cpus: &[u32]) -> Result<u32> {
        if name.is_empty() || name.len() > MAX_NAME_LEN {
            return Err(Error::InvalidArgument);
        }
        if opps.is_empty() || opps.len() > MAX_OPPS {
            return Err(Error::InvalidArgument);
        }
        if cpus.is_empty() || cpus.len() > MAX_CPUS_PER_DOMAIN {
            return Err(Error::InvalidArgument);
        }

        let slot = self
            .domains
            .iter()
            .position(|d| !d.in_use)
            .ok_or(Error::OutOfMemory)?;

        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);

        let domain = &mut self.domains[slot];
        *domain = PerformanceDomain::empty();
        domain.id = id;
        domain.in_use = true;
        domain.name_len = name.len();
        domain.name[..name.len()].copy_from_slice(name);
        domain.opps[..opps.len()].copy_from_slice(opps);
        domain.opp_count = opps.len();
        domain.cpus[..cpus.len()].copy_from_slice(cpus);
        domain.cpu_count = cpus.len();
        // Start at the lowest OPP.
        domain.active_opp = 0;

        self.domain_count += 1;
        Ok(id)
    }

    /// Unregister a performance domain.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the domain does not exist.
    pub fn unregister_domain(&mut self, id: u32) -> Result<()> {
        let idx = self.domain_index(id)?;
        self.domains[idx].in_use = false;
        self.domain_count = self.domain_count.saturating_sub(1);
        Ok(())
    }

    /// Get a reference to a domain by ID.
    pub fn get_domain(&self, id: u32) -> Option<&PerformanceDomain> {
        self.domains.iter().find(|d| d.in_use && d.id == id)
    }

    /// Get a mutable reference to a domain by ID.
    pub fn get_domain_mut(&mut self, id: u32) -> Option<&mut PerformanceDomain> {
        self.domains.iter_mut().find(|d| d.in_use && d.id == id)
    }

    /// Find which domain a CPU belongs to.
    pub fn domain_of_cpu(&self, cpu_id: u32) -> Option<&PerformanceDomain> {
        self.domains
            .iter()
            .find(|d| d.in_use && d.contains_cpu(cpu_id))
    }

    /// Iterate over all active domains.
    pub fn active_domains(&self) -> impl Iterator<Item = &PerformanceDomain> {
        self.domains.iter().filter(|d| d.in_use)
    }

    /// Internal: find domain index by ID.
    fn domain_index(&self, id: u32) -> Result<usize> {
        self.domains
            .iter()
            .position(|d| d.in_use && d.id == id)
            .ok_or(Error::NotFound)
    }
}

impl Default for EnergyModel {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Per-CPU utilization tracking
// ---------------------------------------------------------------------------

/// Per-CPU utilization state.
#[derive(Debug, Clone, Copy, Default)]
pub struct CpuUtil {
    /// CPU identifier.
    pub cpu_id: u32,
    /// Current utilization (0..1024).
    pub util: u32,
    /// Whether this CPU is online.
    pub online: bool,
}

// ---------------------------------------------------------------------------
// EasRegistry — main scheduling interface
// ---------------------------------------------------------------------------

/// Energy-Aware Scheduling registry.
///
/// Combines the energy model with per-CPU utilization tracking to
/// find the most energy-efficient CPU for a new task placement.
pub struct EasRegistry {
    /// The system energy model.
    pub model: EnergyModel,
    /// Per-CPU utilization tracking.
    cpu_utils: [CpuUtil; MAX_CPUS],
    /// Number of online CPUs.
    online_count: usize,
}

impl EasRegistry {
    /// Create an empty EAS registry.
    pub const fn new() -> Self {
        const EMPTY_UTIL: CpuUtil = CpuUtil {
            cpu_id: 0,
            util: 0,
            online: false,
        };
        Self {
            model: EnergyModel::new(),
            cpu_utils: [EMPTY_UTIL; MAX_CPUS],
            online_count: 0,
        }
    }

    /// Register a CPU as online.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `cpu_id` exceeds
    /// `MAX_CPUS`.
    pub fn cpu_online(&mut self, cpu_id: u32) -> Result<()> {
        let idx = cpu_id as usize;
        if idx >= MAX_CPUS {
            return Err(Error::InvalidArgument);
        }
        if !self.cpu_utils[idx].online {
            self.cpu_utils[idx].cpu_id = cpu_id;
            self.cpu_utils[idx].online = true;
            self.online_count += 1;
        }
        Ok(())
    }

    /// Mark a CPU as offline.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `cpu_id` exceeds
    /// `MAX_CPUS`.
    pub fn cpu_offline(&mut self, cpu_id: u32) -> Result<()> {
        let idx = cpu_id as usize;
        if idx >= MAX_CPUS {
            return Err(Error::InvalidArgument);
        }
        if self.cpu_utils[idx].online {
            self.cpu_utils[idx].online = false;
            self.cpu_utils[idx].util = 0;
            self.online_count = self.online_count.saturating_sub(1);
        }
        Ok(())
    }

    /// Update the utilization of a CPU.
    ///
    /// `util` is in the range 0..1024 (fraction of capacity).
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `cpu_id` exceeds
    /// `MAX_CPUS` or `util` exceeds 1024.
    pub fn update_util(&mut self, cpu_id: u32, util: u32) -> Result<()> {
        let idx = cpu_id as usize;
        if idx >= MAX_CPUS {
            return Err(Error::InvalidArgument);
        }
        if util > 1024 {
            return Err(Error::InvalidArgument);
        }
        self.cpu_utils[idx].util = util;
        Ok(())
    }

    /// Get the current utilization of a CPU.
    pub fn get_util(&self, cpu_id: u32) -> u32 {
        let idx = cpu_id as usize;
        if idx >= MAX_CPUS {
            return 0;
        }
        self.cpu_utils[idx].util
    }

    /// Number of online CPUs.
    pub fn online_count(&self) -> usize {
        self.online_count
    }

    /// Find the most energy-efficient CPU for a task with the
    /// given utilization demand.
    ///
    /// Iterates over all performance domains and their CPUs,
    /// estimates the marginal energy cost of placing the task on
    /// each online CPU, and returns the CPU with the lowest cost.
    ///
    /// Returns `None` if no online CPU is available.
    pub fn find_energy_efficient_cpu(&self, task_util: u32) -> Option<u32> {
        let mut best_cpu: Option<u32> = None;
        let mut best_energy = u64::MAX;

        for domain in self.model.active_domains() {
            for &cpu_id in &domain.cpus[..domain.cpu_count] {
                let idx = cpu_id as usize;
                if idx >= MAX_CPUS || !self.cpu_utils[idx].online {
                    continue;
                }

                let current_util = self.cpu_utils[idx].util;
                let combined_util = current_util.saturating_add(task_util).min(1024);

                // Find the cheapest OPP that satisfies the
                // combined utilization.
                let opp_idx = domain.find_opp_for_util(combined_util);
                let energy = domain.estimate_energy(opp_idx, combined_util);

                if energy < best_energy {
                    best_energy = energy;
                    best_cpu = Some(cpu_id);
                }
            }
        }

        best_cpu
    }

    /// Estimate the total system energy across all domains at
    /// their current OPPs and utilizations.
    ///
    /// Returns energy in arbitrary units (sum of per-domain costs).
    pub fn estimate_total_energy(&self) -> u64 {
        let mut total: u64 = 0;

        for domain in self.model.active_domains() {
            let mut domain_util: u32 = 0;
            for &cpu_id in &domain.cpus[..domain.cpu_count] {
                let idx = cpu_id as usize;
                if idx < MAX_CPUS && self.cpu_utils[idx].online {
                    domain_util = domain_util.saturating_add(self.cpu_utils[idx].util);
                }
            }

            let energy = domain.estimate_energy(domain.active_opp, domain_util);
            if energy != u64::MAX {
                total = total.saturating_add(energy);
            }
        }

        total
    }
}

impl Default for EasRegistry {
    fn default() -> Self {
        Self::new()
    }
}
