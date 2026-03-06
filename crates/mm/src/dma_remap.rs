// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! DMA remapping (IOMMU) support.
//!
//! Provides an abstraction for IOMMU-based DMA remapping. When an
//! IOMMU is present, DMA addresses seen by devices are different from
//! physical addresses — the IOMMU translates them. This module manages
//! the DMA address space, mapping/unmapping, and domain isolation.
//!
//! # Design
//!
//! ```text
//!  Device DMA request
//!       │
//!       ▼
//!  IOMMU page table (DMA addr → phys addr)
//!       │
//!       ├─ mapping exists → translate to physical
//!       └─ no mapping     → DMA fault
//!
//!  DmaRemapDomain::map(dma_addr, phys_addr, size)
//!  DmaRemapDomain::unmap(dma_addr, size)
//! ```
//!
//! # Key Types
//!
//! - [`DmaRemapEntry`] — a single DMA mapping
//! - [`DmaRemapDomain`] — an IOMMU domain (isolation boundary)
//! - [`DmaRemapManager`] — manages all domains
//!
//! Reference: Linux `drivers/iommu/`, `include/linux/iommu.h`.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Maximum mappings per domain.
const MAX_MAPPINGS: usize = 512;

/// Maximum domains.
const MAX_DOMAINS: usize = 64;

/// DMA address space start.
const DMA_ADDR_START: u64 = 0x0000_0000_1000_0000;

/// Page size for DMA mappings.
const PAGE_SIZE: u64 = 4096;

// -------------------------------------------------------------------
// DmaDirection
// -------------------------------------------------------------------

/// Direction of a DMA transfer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DmaDirection {
    /// Device reads from memory.
    ToDevice,
    /// Device writes to memory.
    FromDevice,
    /// Bidirectional.
    Bidirectional,
    /// No DMA transfer (buffer management only).
    None,
}

impl DmaDirection {
    /// Return a human-readable name.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::ToDevice => "to_device",
            Self::FromDevice => "from_device",
            Self::Bidirectional => "bidirectional",
            Self::None => "none",
        }
    }
}

impl Default for DmaDirection {
    fn default() -> Self {
        Self::Bidirectional
    }
}

// -------------------------------------------------------------------
// DmaRemapEntry
// -------------------------------------------------------------------

/// A single DMA address mapping.
#[derive(Debug, Clone, Copy)]
pub struct DmaRemapEntry {
    /// DMA (I/O virtual) address.
    dma_addr: u64,
    /// Physical address.
    phys_addr: u64,
    /// Size in bytes.
    size: u64,
    /// Transfer direction.
    direction: DmaDirection,
    /// Whether this entry is active.
    active: bool,
}

impl DmaRemapEntry {
    /// Create a new mapping entry.
    pub const fn new(dma_addr: u64, phys_addr: u64, size: u64, direction: DmaDirection) -> Self {
        Self {
            dma_addr,
            phys_addr,
            size,
            direction,
            active: true,
        }
    }

    /// Return the DMA address.
    pub const fn dma_addr(&self) -> u64 {
        self.dma_addr
    }

    /// Return the physical address.
    pub const fn phys_addr(&self) -> u64 {
        self.phys_addr
    }

    /// Return the size.
    pub const fn size(&self) -> u64 {
        self.size
    }

    /// Return the direction.
    pub const fn direction(&self) -> DmaDirection {
        self.direction
    }

    /// Check whether this entry is active.
    pub const fn is_active(&self) -> bool {
        self.active
    }

    /// Translate a DMA address to physical.
    pub const fn translate(&self, dma: u64) -> Option<u64> {
        if dma >= self.dma_addr && dma < self.dma_addr + self.size && self.active {
            Some(self.phys_addr + (dma - self.dma_addr))
        } else {
            None
        }
    }

    /// Deactivate this entry.
    pub fn deactivate(&mut self) {
        self.active = false;
    }
}

impl Default for DmaRemapEntry {
    fn default() -> Self {
        Self {
            dma_addr: 0,
            phys_addr: 0,
            size: 0,
            direction: DmaDirection::None,
            active: false,
        }
    }
}

// -------------------------------------------------------------------
// DmaRemapDomain
// -------------------------------------------------------------------

/// An IOMMU domain — an isolated DMA address space.
#[derive(Clone)]
pub struct DmaRemapDomain {
    /// Domain identifier.
    domain_id: u32,
    /// Mappings in this domain.
    mappings: [DmaRemapEntry; MAX_MAPPINGS],
    /// Number of active mappings.
    count: usize,
    /// Next DMA address to allocate.
    next_dma_addr: u64,
    /// Whether this domain is active.
    active: bool,
}

impl DmaRemapDomain {
    /// Create a new domain.
    pub const fn new(domain_id: u32) -> Self {
        Self {
            domain_id,
            mappings: [const {
                DmaRemapEntry {
                    dma_addr: 0,
                    phys_addr: 0,
                    size: 0,
                    direction: DmaDirection::None,
                    active: false,
                }
            }; MAX_MAPPINGS],
            count: 0,
            next_dma_addr: DMA_ADDR_START,
            active: true,
        }
    }

    /// Return the domain ID.
    pub const fn domain_id(&self) -> u32 {
        self.domain_id
    }

    /// Return the number of active mappings.
    pub const fn mapping_count(&self) -> usize {
        self.count
    }

    /// Check whether this domain is active.
    pub const fn is_active(&self) -> bool {
        self.active
    }

    /// Map a physical address into DMA space.
    pub fn map(&mut self, phys_addr: u64, size: u64, direction: DmaDirection) -> Result<u64> {
        if size == 0 || !self.active {
            return Err(Error::InvalidArgument);
        }
        if self.count >= MAX_MAPPINGS {
            return Err(Error::OutOfMemory);
        }

        let aligned_size = (size + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
        let dma_addr = self.next_dma_addr;
        self.next_dma_addr += aligned_size;

        self.mappings[self.count] =
            DmaRemapEntry::new(dma_addr, phys_addr, aligned_size, direction);
        self.count += 1;

        Ok(dma_addr)
    }

    /// Unmap a DMA address.
    pub fn unmap(&mut self, dma_addr: u64) -> Result<u64> {
        for idx in 0..self.count {
            if self.mappings[idx].dma_addr() == dma_addr && self.mappings[idx].is_active() {
                let size = self.mappings[idx].size();
                self.mappings[idx].deactivate();
                return Ok(size);
            }
        }
        Err(Error::NotFound)
    }

    /// Translate a DMA address to physical.
    pub fn translate(&self, dma_addr: u64) -> Option<u64> {
        for idx in 0..self.count {
            if let Some(phys) = self.mappings[idx].translate(dma_addr) {
                return Some(phys);
            }
        }
        None
    }

    /// Deactivate the domain.
    pub fn deactivate(&mut self) {
        self.active = false;
    }
}

impl Default for DmaRemapDomain {
    fn default() -> Self {
        Self::new(0)
    }
}

// -------------------------------------------------------------------
// DmaRemapManager
// -------------------------------------------------------------------

/// Manages all IOMMU domains.
pub struct DmaRemapManager {
    /// Domains.
    domains: [DmaRemapDomain; MAX_DOMAINS],
    /// Number of active domains.
    count: usize,
    /// Next domain ID to assign.
    next_id: u32,
    /// Total mappings across all domains.
    total_mappings: u64,
}

impl DmaRemapManager {
    /// Create a new manager.
    pub const fn new() -> Self {
        Self {
            domains: [const { DmaRemapDomain::new(0) }; MAX_DOMAINS],
            count: 0,
            next_id: 1,
            total_mappings: 0,
        }
    }

    /// Create a new domain.
    pub fn create_domain(&mut self) -> Result<u32> {
        if self.count >= MAX_DOMAINS {
            return Err(Error::OutOfMemory);
        }
        let id = self.next_id;
        self.domains[self.count] = DmaRemapDomain::new(id);
        self.count += 1;
        self.next_id += 1;
        Ok(id)
    }

    /// Find a domain by ID (mutable).
    pub fn find_domain_mut(&mut self, domain_id: u32) -> Option<&mut DmaRemapDomain> {
        for idx in 0..self.count {
            if self.domains[idx].domain_id() == domain_id && self.domains[idx].is_active() {
                return Some(&mut self.domains[idx]);
            }
        }
        None
    }

    /// Map in a domain and return the DMA address.
    pub fn map_in_domain(
        &mut self,
        domain_id: u32,
        phys_addr: u64,
        size: u64,
        direction: DmaDirection,
    ) -> Result<u64> {
        let domain = self.find_domain_mut(domain_id).ok_or(Error::NotFound)?;
        let dma = domain.map(phys_addr, size, direction)?;
        self.total_mappings += 1;
        Ok(dma)
    }

    /// Return the number of active domains.
    pub const fn domain_count(&self) -> usize {
        self.count
    }

    /// Return total mappings created.
    pub const fn total_mappings(&self) -> u64 {
        self.total_mappings
    }
}

impl Default for DmaRemapManager {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// Public helpers
// -------------------------------------------------------------------

/// Create a domain and map a single region.
pub fn quick_map(manager: &mut DmaRemapManager, phys_addr: u64, size: u64) -> Result<(u32, u64)> {
    let domain_id = manager.create_domain()?;
    let dma = manager.map_in_domain(domain_id, phys_addr, size, DmaDirection::Bidirectional)?;
    Ok((domain_id, dma))
}

/// Translate a DMA address within a specific domain.
pub fn translate_dma(manager: &mut DmaRemapManager, domain_id: u32, dma_addr: u64) -> Option<u64> {
    manager
        .find_domain_mut(domain_id)
        .and_then(|d| d.translate(dma_addr))
}

/// Return a summary of DMA remap state.
pub fn remap_summary(manager: &DmaRemapManager) -> &'static str {
    if manager.domain_count() == 0 {
        "DMA remap: no domains"
    } else {
        "DMA remap: active"
    }
}
