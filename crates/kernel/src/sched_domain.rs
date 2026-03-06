// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Scheduling domain hierarchy.
//!
//! Represents the hierarchical topology of scheduling domains used
//! by the scheduler for load balancing decisions. Domains represent
//! levels of the CPU topology (SMT, core, die, NUMA node, system)
//! and control how aggressively tasks are migrated between CPUs.

use oncrix_lib::{Error, Result};

// ── Constants ────────────────────────────────────────────────────────

/// Maximum scheduling domains.
const MAX_DOMAINS: usize = 64;

/// Maximum domain levels (SMT -> core -> die -> NUMA -> system).
const MAX_LEVELS: usize = 8;

/// Maximum CPUs per domain span.
const MAX_SPAN_CPUS: usize = 128;

/// CPU mask word count.
const CPU_MASK_WORDS: usize = (MAX_SPAN_CPUS + 63) / 64;

/// Default balance interval in milliseconds.
const _DEFAULT_BALANCE_INTERVAL_MS: u64 = 8;

// ── Types ────────────────────────────────────────────────────────────

/// Level of the scheduling domain in the topology.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum DomainLevel {
    /// Simultaneous Multi-Threading (hyperthreads).
    Smt,
    /// Physical core.
    Core,
    /// Die within a package.
    Die,
    /// NUMA node.
    Numa,
    /// System-wide.
    System,
}

impl Default for DomainLevel {
    fn default() -> Self {
        Self::System
    }
}

/// Identifies a scheduling domain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DomainId(u32);

impl DomainId {
    /// Creates a new domain identifier.
    pub const fn new(id: u32) -> Self {
        Self(id)
    }

    /// Returns the raw identifier.
    pub const fn as_u32(self) -> u32 {
        self.0
    }
}

/// CPU span mask for a scheduling domain.
#[derive(Debug, Clone)]
pub struct DomainSpan {
    /// Bitmask of CPUs in this domain.
    bits: [u64; CPU_MASK_WORDS],
    /// Number of CPUs in the span.
    cpu_count: u32,
}

impl DomainSpan {
    /// Creates an empty domain span.
    pub const fn new() -> Self {
        Self {
            bits: [0u64; CPU_MASK_WORDS],
            cpu_count: 0,
        }
    }

    /// Adds a CPU to the span.
    pub fn add_cpu(&mut self, cpu: u32) -> Result<()> {
        let idx = (cpu as usize) / 64;
        let bit = (cpu as usize) % 64;
        if idx >= CPU_MASK_WORDS {
            return Err(Error::InvalidArgument);
        }
        if self.bits[idx] & (1u64 << bit) == 0 {
            self.bits[idx] |= 1u64 << bit;
            self.cpu_count += 1;
        }
        Ok(())
    }

    /// Tests whether a CPU is in the span.
    pub fn contains(&self, cpu: u32) -> bool {
        let idx = (cpu as usize) / 64;
        let bit = (cpu as usize) % 64;
        if idx >= CPU_MASK_WORDS {
            return false;
        }
        self.bits[idx] & (1u64 << bit) != 0
    }

    /// Returns the number of CPUs.
    pub const fn cpu_count(&self) -> u32 {
        self.cpu_count
    }
}

impl Default for DomainSpan {
    fn default() -> Self {
        Self::new()
    }
}

/// Domain flags controlling load balancing behavior.
#[derive(Debug, Clone)]
pub struct DomainFlags {
    /// Allow load balancing within this domain.
    pub balance: bool,
    /// Allow task wakeup migration.
    pub wake_affine: bool,
    /// Share power state among CPUs.
    pub share_power: bool,
    /// Share package-level caches.
    pub share_pkg: bool,
    /// Prefer to keep tasks on the same NUMA node.
    pub numa_affine: bool,
}

impl Default for DomainFlags {
    fn default() -> Self {
        Self::new()
    }
}

impl DomainFlags {
    /// Creates default domain flags.
    pub const fn new() -> Self {
        Self {
            balance: true,
            wake_affine: true,
            share_power: false,
            share_pkg: false,
            numa_affine: false,
        }
    }
}

/// A scheduling domain.
#[derive(Debug)]
pub struct SchedDomain {
    /// Domain identifier.
    id: DomainId,
    /// Topology level.
    level: DomainLevel,
    /// Parent domain identifier (None for top-level).
    parent_id: Option<DomainId>,
    /// CPU span.
    span: DomainSpan,
    /// Domain flags.
    flags: DomainFlags,
    /// Load balance interval in milliseconds.
    balance_interval_ms: u64,
    /// Imbalance threshold percentage.
    imbalance_pct: u32,
    /// Number of child domains.
    child_count: u32,
    /// Total load balance attempts.
    balance_count: u64,
    /// Successful load balance moves.
    balance_moves: u64,
    /// Failed balance attempts (no suitable task).
    balance_failures: u64,
}

impl SchedDomain {
    /// Creates a new scheduling domain.
    pub const fn new(id: DomainId, level: DomainLevel) -> Self {
        Self {
            id,
            level,
            parent_id: None,
            span: DomainSpan::new(),
            flags: DomainFlags::new(),
            balance_interval_ms: 8,
            imbalance_pct: 125,
            child_count: 0,
            balance_count: 0,
            balance_moves: 0,
            balance_failures: 0,
        }
    }

    /// Returns the domain level.
    pub const fn level(&self) -> DomainLevel {
        self.level
    }

    /// Returns the domain identifier.
    pub const fn id(&self) -> DomainId {
        self.id
    }

    /// Returns the number of CPUs in this domain.
    pub const fn cpu_count(&self) -> u32 {
        self.span.cpu_count
    }
}

/// Scheduling domain statistics.
#[derive(Debug, Clone)]
pub struct SchedDomainStats {
    /// Total domains.
    pub total_domains: u32,
    /// Domains per level.
    pub smt_domains: u32,
    /// Core-level domains.
    pub core_domains: u32,
    /// NUMA-level domains.
    pub numa_domains: u32,
    /// System-level domains.
    pub system_domains: u32,
    /// Total balance operations.
    pub total_balance_ops: u64,
    /// Total successful moves.
    pub total_moves: u64,
}

impl Default for SchedDomainStats {
    fn default() -> Self {
        Self::new()
    }
}

impl SchedDomainStats {
    /// Creates zeroed statistics.
    pub const fn new() -> Self {
        Self {
            total_domains: 0,
            smt_domains: 0,
            core_domains: 0,
            numa_domains: 0,
            system_domains: 0,
            total_balance_ops: 0,
            total_moves: 0,
        }
    }
}

/// Central scheduling domain manager.
#[derive(Debug)]
pub struct SchedDomainManager {
    /// Domains.
    domains: [Option<SchedDomain>; MAX_DOMAINS],
    /// Number of domains.
    domain_count: usize,
    /// Next domain identifier.
    next_id: u32,
    /// Whether the topology has been built.
    built: bool,
}

impl Default for SchedDomainManager {
    fn default() -> Self {
        Self::new()
    }
}

impl SchedDomainManager {
    /// Creates a new scheduling domain manager.
    pub const fn new() -> Self {
        Self {
            domains: [const { None }; MAX_DOMAINS],
            domain_count: 0,
            next_id: 1,
            built: false,
        }
    }

    /// Creates a new scheduling domain.
    pub fn create_domain(
        &mut self,
        level: DomainLevel,
        parent_id: Option<DomainId>,
    ) -> Result<DomainId> {
        if self.domain_count >= MAX_DOMAINS {
            return Err(Error::OutOfMemory);
        }
        let id = DomainId::new(self.next_id);
        self.next_id += 1;
        let mut domain = SchedDomain::new(id, level);
        domain.parent_id = parent_id;
        if let Some(pid) = parent_id {
            if let Some(p) = self.domains.iter_mut().flatten().find(|d| d.id == pid) {
                p.child_count += 1;
            }
        }
        if let Some(slot) = self.domains.iter_mut().find(|s| s.is_none()) {
            *slot = Some(domain);
            self.domain_count += 1;
            Ok(id)
        } else {
            Err(Error::OutOfMemory)
        }
    }

    /// Adds CPUs to a domain's span.
    pub fn add_domain_cpus(&mut self, domain_id: DomainId, cpus: &[u32]) -> Result<()> {
        let domain = self
            .domains
            .iter_mut()
            .flatten()
            .find(|d| d.id == domain_id)
            .ok_or(Error::NotFound)?;
        for &cpu in cpus {
            domain.span.add_cpu(cpu)?;
        }
        Ok(())
    }

    /// Sets domain flags.
    pub fn set_domain_flags(&mut self, domain_id: DomainId, flags: DomainFlags) -> Result<()> {
        let domain = self
            .domains
            .iter_mut()
            .flatten()
            .find(|d| d.id == domain_id)
            .ok_or(Error::NotFound)?;
        domain.flags = flags;
        Ok(())
    }

    /// Records a load balance attempt for a domain.
    pub fn record_balance(&mut self, domain_id: DomainId, moved: bool) -> Result<()> {
        let domain = self
            .domains
            .iter_mut()
            .flatten()
            .find(|d| d.id == domain_id)
            .ok_or(Error::NotFound)?;
        domain.balance_count += 1;
        if moved {
            domain.balance_moves += 1;
        } else {
            domain.balance_failures += 1;
        }
        Ok(())
    }

    /// Marks the topology as built.
    pub fn finalize_topology(&mut self) {
        self.built = true;
    }

    /// Returns whether the topology has been built.
    pub const fn is_built(&self) -> bool {
        self.built
    }

    /// Removes a domain.
    pub fn remove_domain(&mut self, domain_id: DomainId) -> Result<()> {
        let slot = self
            .domains
            .iter_mut()
            .find(|s| s.as_ref().map_or(false, |d| d.id == domain_id))
            .ok_or(Error::NotFound)?;
        *slot = None;
        self.domain_count -= 1;
        Ok(())
    }

    /// Returns domain statistics.
    pub fn stats(&self) -> SchedDomainStats {
        let mut s = SchedDomainStats::new();
        for d in self.domains.iter().flatten() {
            s.total_domains += 1;
            match d.level {
                DomainLevel::Smt => s.smt_domains += 1,
                DomainLevel::Core => s.core_domains += 1,
                DomainLevel::Numa => s.numa_domains += 1,
                DomainLevel::System => s.system_domains += 1,
                _ => {}
            }
            s.total_balance_ops += d.balance_count;
            s.total_moves += d.balance_moves;
        }
        s
    }

    /// Returns the number of domains.
    pub const fn domain_count(&self) -> usize {
        self.domain_count
    }
}
