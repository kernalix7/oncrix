// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Scheduler energy-aware task placement.
//!
//! Implements energy-aware scheduling (EAS) decisions that consider
//! CPU power consumption alongside performance. Tasks are placed on
//! CPUs to minimize total energy consumption while meeting performance
//! requirements. Uses an energy model describing the power/performance
//! characteristics of each CPU frequency operating point.

use oncrix_lib::{Error, Result};

// ── Constants ────────────────────────────────────────────────────────

/// Maximum CPUs in the energy model.
const MAX_CPUS: usize = 64;

/// Maximum performance domains.
const MAX_PERF_DOMAINS: usize = 16;

/// Maximum operating points per domain.
const MAX_OPP_COUNT: usize = 32;

/// Energy computation log size.
const MAX_ENERGY_LOG: usize = 128;

// ── Types ────────────────────────────────────────────────────────────

/// Identifies a performance domain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PerfDomainId(u16);

impl PerfDomainId {
    /// Creates a new performance domain identifier.
    pub const fn new(id: u16) -> Self {
        Self(id)
    }

    /// Returns the raw identifier.
    pub const fn as_u16(self) -> u16 {
        self.0
    }
}

/// An operating performance point (OPP).
#[derive(Debug, Clone, Copy)]
pub struct OperatingPoint {
    /// Frequency in kHz.
    freq_khz: u32,
    /// Power consumption in milliwatts.
    power_mw: u32,
    /// Compute capacity at this OPP (0-1024 scale).
    capacity: u32,
}

impl OperatingPoint {
    /// Creates a new operating point.
    pub const fn new(freq_khz: u32, power_mw: u32, capacity: u32) -> Self {
        Self {
            freq_khz,
            power_mw,
            capacity,
        }
    }

    /// Returns the frequency in kHz.
    pub const fn freq_khz(&self) -> u32 {
        self.freq_khz
    }

    /// Returns the power in milliwatts.
    pub const fn power_mw(&self) -> u32 {
        self.power_mw
    }
}

/// A performance domain grouping CPUs with shared frequency.
#[derive(Debug)]
pub struct PerfDomain {
    /// Domain identifier.
    id: PerfDomainId,
    /// CPUs in this domain.
    cpus: [bool; MAX_CPUS],
    /// Number of CPUs.
    cpu_count: u32,
    /// Operating points.
    opps: [Option<OperatingPoint>; MAX_OPP_COUNT],
    /// Number of operating points.
    opp_count: usize,
    /// Current OPP index.
    current_opp: usize,
    /// Total energy consumed (milliwatt-milliseconds).
    total_energy_mwms: u64,
}

impl PerfDomain {
    /// Creates a new performance domain.
    pub const fn new(id: PerfDomainId) -> Self {
        Self {
            id,
            cpus: [false; MAX_CPUS],
            cpu_count: 0,
            opps: [None; MAX_OPP_COUNT],
            opp_count: 0,
            current_opp: 0,
            total_energy_mwms: 0,
        }
    }

    /// Returns the domain identifier.
    pub const fn id(&self) -> PerfDomainId {
        self.id
    }

    /// Returns the number of CPUs.
    pub const fn cpu_count(&self) -> u32 {
        self.cpu_count
    }
}

/// Result of an energy-aware placement computation.
#[derive(Debug, Clone)]
pub struct PlacementResult {
    /// Recommended CPU for task placement.
    pub target_cpu: u32,
    /// Estimated energy delta (positive = more energy).
    pub energy_delta_mwms: i64,
    /// Whether EAS found a better placement than default.
    pub overrides_default: bool,
    /// Performance domain of the target CPU.
    pub target_domain: PerfDomainId,
}

/// Energy-aware scheduling statistics.
#[derive(Debug, Clone)]
pub struct SchedEnergyStats {
    /// Total placement computations.
    pub total_computations: u64,
    /// Placements that overrode the default.
    pub overrides: u64,
    /// Total energy saved (milliwatt-milliseconds).
    pub total_energy_saved: u64,
    /// Number of performance domains.
    pub domain_count: u32,
    /// Average energy delta per placement.
    pub avg_energy_delta: i64,
}

impl Default for SchedEnergyStats {
    fn default() -> Self {
        Self::new()
    }
}

impl SchedEnergyStats {
    /// Creates zeroed statistics.
    pub const fn new() -> Self {
        Self {
            total_computations: 0,
            overrides: 0,
            total_energy_saved: 0,
            domain_count: 0,
            avg_energy_delta: 0,
        }
    }
}

/// Energy computation log entry.
#[derive(Debug, Clone)]
pub struct EnergyLogEntry {
    /// Task PID.
    pid: u64,
    /// Default CPU.
    default_cpu: u32,
    /// Selected CPU.
    selected_cpu: u32,
    /// Energy delta.
    energy_delta: i64,
    /// Timestamp.
    timestamp_ns: u64,
}

impl EnergyLogEntry {
    /// Creates a new log entry.
    pub const fn new(pid: u64, default_cpu: u32, selected_cpu: u32, energy_delta: i64) -> Self {
        Self {
            pid,
            default_cpu,
            selected_cpu,
            energy_delta,
            timestamp_ns: 0,
        }
    }
}

/// Central energy-aware scheduler.
#[derive(Debug)]
pub struct SchedEnergyManager {
    /// Performance domains.
    domains: [Option<PerfDomain>; MAX_PERF_DOMAINS],
    /// Energy computation log.
    energy_log: [Option<EnergyLogEntry>; MAX_ENERGY_LOG],
    /// Log write position.
    log_pos: usize,
    /// Number of domains.
    domain_count: usize,
    /// Next domain identifier.
    next_id: u16,
    /// Total computations.
    total_computations: u64,
    /// Total overrides.
    total_overrides: u64,
    /// Total energy saved.
    total_saved: u64,
    /// Whether EAS is enabled.
    enabled: bool,
}

impl Default for SchedEnergyManager {
    fn default() -> Self {
        Self::new()
    }
}

impl SchedEnergyManager {
    /// Creates a new energy manager.
    pub const fn new() -> Self {
        Self {
            domains: [const { None }; MAX_PERF_DOMAINS],
            energy_log: [const { None }; MAX_ENERGY_LOG],
            log_pos: 0,
            domain_count: 0,
            next_id: 1,
            total_computations: 0,
            total_overrides: 0,
            total_saved: 0,
            enabled: false,
        }
    }

    /// Enables EAS.
    pub fn enable(&mut self) {
        self.enabled = true;
    }

    /// Disables EAS.
    pub fn disable(&mut self) {
        self.enabled = false;
    }

    /// Creates a new performance domain.
    pub fn create_domain(&mut self) -> Result<PerfDomainId> {
        if self.domain_count >= MAX_PERF_DOMAINS {
            return Err(Error::OutOfMemory);
        }
        let id = PerfDomainId::new(self.next_id);
        self.next_id += 1;
        let domain = PerfDomain::new(id);
        if let Some(slot) = self.domains.iter_mut().find(|s| s.is_none()) {
            *slot = Some(domain);
            self.domain_count += 1;
            Ok(id)
        } else {
            Err(Error::OutOfMemory)
        }
    }

    /// Adds a CPU to a performance domain.
    pub fn add_cpu_to_domain(&mut self, domain_id: PerfDomainId, cpu: u32) -> Result<()> {
        if (cpu as usize) >= MAX_CPUS {
            return Err(Error::InvalidArgument);
        }
        let domain = self
            .domains
            .iter_mut()
            .flatten()
            .find(|d| d.id == domain_id)
            .ok_or(Error::NotFound)?;
        domain.cpus[cpu as usize] = true;
        domain.cpu_count += 1;
        Ok(())
    }

    /// Adds an operating point to a domain.
    pub fn add_opp(
        &mut self,
        domain_id: PerfDomainId,
        freq_khz: u32,
        power_mw: u32,
        capacity: u32,
    ) -> Result<()> {
        let domain = self
            .domains
            .iter_mut()
            .flatten()
            .find(|d| d.id == domain_id)
            .ok_or(Error::NotFound)?;
        if domain.opp_count >= MAX_OPP_COUNT {
            return Err(Error::OutOfMemory);
        }
        let opp = OperatingPoint::new(freq_khz, power_mw, capacity);
        domain.opps[domain.opp_count] = Some(opp);
        domain.opp_count += 1;
        Ok(())
    }

    /// Computes the energy-aware placement for a task.
    pub fn compute_placement(
        &mut self,
        pid: u64,
        default_cpu: u32,
        task_util: u32,
    ) -> Result<PlacementResult> {
        if !self.enabled {
            return Err(Error::NotImplemented);
        }
        self.total_computations += 1;
        // Find the domain with the best energy efficiency.
        let mut best_cpu = default_cpu;
        let mut best_energy = i64::MAX;
        for domain in self.domains.iter().flatten() {
            if let Some(opp) = domain.opps.get(domain.current_opp).and_then(|o| o.as_ref()) {
                let energy =
                    (opp.power_mw as i64) * (task_util as i64) / (opp.capacity.max(1) as i64);
                if energy < best_energy {
                    best_energy = energy;
                    // Pick first CPU in this domain.
                    for (i, &in_domain) in domain.cpus.iter().enumerate() {
                        if in_domain {
                            best_cpu = i as u32;
                            break;
                        }
                    }
                }
            }
        }
        let overrides = best_cpu != default_cpu;
        if overrides {
            self.total_overrides += 1;
        }
        // Find the domain of the target CPU.
        let target_domain = self
            .domains
            .iter()
            .flatten()
            .find(|d| (best_cpu as usize) < MAX_CPUS && d.cpus[best_cpu as usize])
            .map(|d| d.id)
            .unwrap_or(PerfDomainId::new(0));
        let entry = EnergyLogEntry::new(pid, default_cpu, best_cpu, best_energy);
        self.energy_log[self.log_pos] = Some(entry);
        self.log_pos = (self.log_pos + 1) % MAX_ENERGY_LOG;
        Ok(PlacementResult {
            target_cpu: best_cpu,
            energy_delta_mwms: best_energy,
            overrides_default: overrides,
            target_domain,
        })
    }

    /// Returns statistics.
    pub fn stats(&self) -> SchedEnergyStats {
        SchedEnergyStats {
            total_computations: self.total_computations,
            overrides: self.total_overrides,
            total_energy_saved: self.total_saved,
            domain_count: self.domain_count as u32,
            avg_energy_delta: 0,
        }
    }

    /// Returns whether EAS is enabled.
    pub const fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Returns the number of performance domains.
    pub const fn domain_count(&self) -> usize {
        self.domain_count
    }
}
