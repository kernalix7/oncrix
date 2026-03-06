// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! IRQ domain — hardware-to-Linux IRQ number mapping.
//!
//! An IRQ domain provides a mapping between hardware interrupt numbers
//! (hwirq) and Linux virtual IRQ numbers (virq). This abstraction
//! supports interrupt controllers that manage their own numbering
//! space (e.g., GIC, IOAPIC, MSI).
//!
//! # Architecture
//!
//! ```text
//! IrqDomainManager
//!  ├── domains[MAX_DOMAINS]
//!  │    ├── id, name
//!  │    ├── mappings[MAX_MAPPINGS] (hwirq → virq)
//!  │    └── parent_id, flags
//!  └── stats: IrqDomainStats
//! ```
//!
//! # Reference
//!
//! Linux `kernel/irq/irqdomain.c`.

use oncrix_lib::{Error, Result};

// ══════════════════════════════════════════════════════════════
// Constants
// ══════════════════════════════════════════════════════════════

/// Maximum IRQ domains.
const MAX_DOMAINS: usize = 16;

/// Maximum mappings per domain.
const MAX_MAPPINGS: usize = 128;

/// Maximum name length.
const MAX_NAME_LEN: usize = 32;

// ══════════════════════════════════════════════════════════════
// IrqMapping
// ══════════════════════════════════════════════════════════════

/// A single hwirq-to-virq mapping.
#[derive(Debug, Clone, Copy)]
pub struct IrqMapping {
    /// Hardware interrupt number.
    pub hwirq: u32,
    /// Virtual (Linux) interrupt number.
    pub virq: u32,
    /// Whether this mapping is active.
    pub active: bool,
}

impl IrqMapping {
    /// Create an inactive mapping.
    const fn empty() -> Self {
        Self {
            hwirq: 0,
            virq: 0,
            active: false,
        }
    }
}

// ══════════════════════════════════════════════════════════════
// DomainFlags
// ══════════════════════════════════════════════════════════════

/// Flags for an IRQ domain.
#[derive(Debug, Clone, Copy)]
pub struct DomainFlags {
    /// Domain provides hierarchical IRQ dispatch.
    pub hierarchy: bool,
    /// Domain supports MSI (Message Signaled Interrupts).
    pub msi: bool,
    /// Domain maps IRQs lazily on first use.
    pub lazy_map: bool,
}

impl DomainFlags {
    /// Default flags.
    const fn default_flags() -> Self {
        Self {
            hierarchy: false,
            msi: false,
            lazy_map: false,
        }
    }
}

// ══════════════════════════════════════════════════════════════
// IrqDomain
// ══════════════════════════════════════════════════════════════

/// A single IRQ domain.
#[derive(Clone, Copy)]
pub struct IrqDomain {
    /// Domain identifier.
    pub id: u32,
    /// Name (zero-padded).
    pub name: [u8; MAX_NAME_LEN],
    /// Name length.
    pub name_len: usize,
    /// Parent domain ID (0 = root / no parent).
    pub parent_id: u32,
    /// Configuration flags.
    pub flags: DomainFlags,
    /// hwirq → virq mappings.
    pub mappings: [IrqMapping; MAX_MAPPINGS],
    /// Number of active mappings.
    pub nr_mappings: u32,
    /// Whether this domain is active.
    pub active: bool,
}

impl IrqDomain {
    /// Create an inactive domain.
    const fn empty() -> Self {
        Self {
            id: 0,
            name: [0u8; MAX_NAME_LEN],
            name_len: 0,
            parent_id: 0,
            flags: DomainFlags::default_flags(),
            mappings: [const { IrqMapping::empty() }; MAX_MAPPINGS],
            nr_mappings: 0,
            active: false,
        }
    }
}

// ══════════════════════════════════════════════════════════════
// IrqDomainStats
// ══════════════════════════════════════════════════════════════

/// IRQ domain subsystem statistics.
#[derive(Debug, Clone, Copy)]
pub struct IrqDomainStats {
    /// Total domains created.
    pub domains_created: u64,
    /// Total mappings created.
    pub mappings_created: u64,
    /// Total lookups.
    pub lookups: u64,
    /// Total lookup misses.
    pub misses: u64,
}

impl IrqDomainStats {
    /// Create zeroed stats.
    const fn new() -> Self {
        Self {
            domains_created: 0,
            mappings_created: 0,
            lookups: 0,
            misses: 0,
        }
    }
}

// ══════════════════════════════════════════════════════════════
// IrqDomainManager
// ══════════════════════════════════════════════════════════════

/// Manages IRQ domains and their hwirq→virq mappings.
pub struct IrqDomainManager {
    /// Domain table.
    domains: [IrqDomain; MAX_DOMAINS],
    /// Next domain ID.
    next_id: u32,
    /// Next virtual IRQ number.
    next_virq: u32,
    /// Statistics.
    stats: IrqDomainStats,
}

impl IrqDomainManager {
    /// Create a new IRQ domain manager.
    pub const fn new() -> Self {
        Self {
            domains: [const { IrqDomain::empty() }; MAX_DOMAINS],
            next_id: 1,
            next_virq: 32, // Reserve low IRQs for legacy.
            stats: IrqDomainStats::new(),
        }
    }

    /// Create a new IRQ domain.
    pub fn create_domain(
        &mut self,
        name: &[u8],
        parent_id: u32,
        flags: DomainFlags,
    ) -> Result<u32> {
        if name.is_empty() || name.len() > MAX_NAME_LEN {
            return Err(Error::InvalidArgument);
        }
        let slot = self
            .domains
            .iter()
            .position(|d| !d.active)
            .ok_or(Error::OutOfMemory)?;
        let id = self.next_id;
        self.next_id += 1;
        let dom = &mut self.domains[slot];
        dom.id = id;
        dom.name[..name.len()].copy_from_slice(name);
        dom.name_len = name.len();
        dom.parent_id = parent_id;
        dom.flags = flags;
        dom.active = true;
        self.stats.domains_created += 1;
        Ok(id)
    }

    /// Create a hwirq→virq mapping in a domain.
    ///
    /// Allocates a new virtual IRQ number automatically.
    pub fn create_mapping(&mut self, domain_id: u32, hwirq: u32) -> Result<u32> {
        let slot = self.find_domain(domain_id)?;
        // Check for existing mapping.
        for m in &self.domains[slot].mappings {
            if m.active && m.hwirq == hwirq {
                return Ok(m.virq);
            }
        }
        let map_slot = self.domains[slot]
            .mappings
            .iter()
            .position(|m| !m.active)
            .ok_or(Error::OutOfMemory)?;
        let virq = self.next_virq;
        self.next_virq += 1;
        self.domains[slot].mappings[map_slot] = IrqMapping {
            hwirq,
            virq,
            active: true,
        };
        self.domains[slot].nr_mappings += 1;
        self.stats.mappings_created += 1;
        Ok(virq)
    }

    /// Look up a virtual IRQ by domain and hwirq.
    pub fn find_mapping(&mut self, domain_id: u32, hwirq: u32) -> Result<u32> {
        let slot = self.find_domain(domain_id)?;
        self.stats.lookups += 1;
        self.domains[slot]
            .mappings
            .iter()
            .find(|m| m.active && m.hwirq == hwirq)
            .map(|m| m.virq)
            .ok_or_else(|| {
                self.stats.misses += 1;
                Error::NotFound
            })
    }

    /// Remove a mapping.
    pub fn remove_mapping(&mut self, domain_id: u32, hwirq: u32) -> Result<()> {
        let slot = self.find_domain(domain_id)?;
        let map_slot = self.domains[slot]
            .mappings
            .iter()
            .position(|m| m.active && m.hwirq == hwirq)
            .ok_or(Error::NotFound)?;
        self.domains[slot].mappings[map_slot] = IrqMapping::empty();
        self.domains[slot].nr_mappings = self.domains[slot].nr_mappings.saturating_sub(1);
        Ok(())
    }

    /// Return domain info.
    pub fn get_domain(&self, domain_id: u32) -> Result<&IrqDomain> {
        let slot = self.find_domain(domain_id)?;
        Ok(&self.domains[slot])
    }

    /// Return statistics.
    pub fn stats(&self) -> IrqDomainStats {
        self.stats
    }

    // ── Internal ─────────────────────────────────────────────

    fn find_domain(&self, id: u32) -> Result<usize> {
        self.domains
            .iter()
            .position(|d| d.active && d.id == id)
            .ok_or(Error::NotFound)
    }
}
