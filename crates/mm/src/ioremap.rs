// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! I/O memory remapping (ioremap).
//!
//! Maps device physical addresses (MMIO regions) into kernel virtual
//! address space. Unlike regular memory, MMIO regions require special
//! caching attributes (uncacheable, write-combining) and must not be
//! prefetched by the CPU.
//!
//! # Design
//!
//! ```text
//!  Driver requests MMIO access
//!       │
//!       ▼
//!  ioremap(phys, size, cache_type)
//!       │
//!       ├─ allocate virtual range from ioremap space
//!       ├─ set up page table entries with UC/WC caching
//!       └─ return virtual address
//! ```
//!
//! # Key Types
//!
//! - [`IoMemType`] — caching policy for I/O memory
//! - [`IoMapping`] — a single I/O memory mapping
//! - [`IoRemapAllocator`] — manages the ioremap virtual address space
//!
//! Reference: Linux `arch/x86/mm/ioremap.c`, `lib/ioremap.c`.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Maximum number of concurrent ioremap mappings.
const MAX_IO_MAPPINGS: usize = 256;

/// Start of ioremap virtual address space.
const IOREMAP_BASE: u64 = 0xFFFF_C900_0000_0000;

/// Size of ioremap virtual address space (1 GiB).
const IOREMAP_SIZE: u64 = 1 << 30;

/// Page size.
const PAGE_SIZE: u64 = 4096;

// -------------------------------------------------------------------
// IoMemType
// -------------------------------------------------------------------

/// Caching policy for I/O memory regions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IoMemType {
    /// Uncacheable — every access goes to the device.
    Uncacheable,
    /// Write-combining — writes are combined, reads uncached.
    WriteCombining,
    /// Write-through — reads may be cached, writes go through.
    WriteThrough,
    /// Write-back (normal caching, usually inappropriate for MMIO).
    WriteBack,
}

impl IoMemType {
    /// Return PTE cache-attribute bits for this type.
    pub const fn pte_bits(&self) -> u64 {
        match self {
            Self::Uncacheable => (1 << 4) | (1 << 3), // PCD + PWT
            Self::WriteCombining => 1 << 4,           // PCD
            Self::WriteThrough => 1 << 3,             // PWT
            Self::WriteBack => 0,
        }
    }

    /// Return a human-readable name.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Uncacheable => "UC",
            Self::WriteCombining => "WC",
            Self::WriteThrough => "WT",
            Self::WriteBack => "WB",
        }
    }
}

impl Default for IoMemType {
    fn default() -> Self {
        Self::Uncacheable
    }
}

// -------------------------------------------------------------------
// IoMapping
// -------------------------------------------------------------------

/// A single I/O memory mapping.
#[derive(Debug, Clone, Copy)]
pub struct IoMapping {
    /// Physical base address.
    phys_base: u64,
    /// Virtual base address in ioremap space.
    virt_base: u64,
    /// Size in bytes (page-aligned).
    size: u64,
    /// Caching policy.
    mem_type: IoMemType,
    /// Whether this mapping is active.
    active: bool,
}

impl IoMapping {
    /// Create a new I/O mapping.
    pub const fn new(phys_base: u64, virt_base: u64, size: u64, mem_type: IoMemType) -> Self {
        Self {
            phys_base,
            virt_base,
            size,
            mem_type,
            active: true,
        }
    }

    /// Return the physical base address.
    pub const fn phys_base(&self) -> u64 {
        self.phys_base
    }

    /// Return the virtual base address.
    pub const fn virt_base(&self) -> u64 {
        self.virt_base
    }

    /// Return the mapping size.
    pub const fn size(&self) -> u64 {
        self.size
    }

    /// Return the number of pages.
    pub const fn page_count(&self) -> u64 {
        self.size / PAGE_SIZE
    }

    /// Return the caching policy.
    pub const fn mem_type(&self) -> IoMemType {
        self.mem_type
    }

    /// Check whether this mapping is active.
    pub const fn is_active(&self) -> bool {
        self.active
    }

    /// Translate a virtual address to physical.
    pub const fn translate(&self, virt: u64) -> Option<u64> {
        if virt >= self.virt_base && virt < self.virt_base + self.size && self.active {
            Some(self.phys_base + (virt - self.virt_base))
        } else {
            None
        }
    }

    /// Deactivate the mapping.
    pub fn deactivate(&mut self) {
        self.active = false;
    }
}

impl Default for IoMapping {
    fn default() -> Self {
        Self {
            phys_base: 0,
            virt_base: 0,
            size: 0,
            mem_type: IoMemType::Uncacheable,
            active: false,
        }
    }
}

// -------------------------------------------------------------------
// IoRemapAllocator
// -------------------------------------------------------------------

/// Manages the ioremap virtual address space.
pub struct IoRemapAllocator {
    /// Active mappings.
    mappings: [IoMapping; MAX_IO_MAPPINGS],
    /// Number of active mappings.
    count: usize,
    /// Next virtual address to allocate from.
    next_virt: u64,
}

impl IoRemapAllocator {
    /// Create a new ioremap allocator.
    pub const fn new() -> Self {
        Self {
            mappings: [const {
                IoMapping {
                    phys_base: 0,
                    virt_base: 0,
                    size: 0,
                    mem_type: IoMemType::Uncacheable,
                    active: false,
                }
            }; MAX_IO_MAPPINGS],
            count: 0,
            next_virt: IOREMAP_BASE,
        }
    }

    /// Return the number of active mappings.
    pub const fn mapping_count(&self) -> usize {
        self.count
    }

    /// Return the amount of virtual space consumed.
    pub const fn used_space(&self) -> u64 {
        self.next_virt - IOREMAP_BASE
    }

    /// Align a size up to page boundary.
    const fn align_up(size: u64) -> u64 {
        (size + PAGE_SIZE - 1) & !(PAGE_SIZE - 1)
    }

    /// Map a physical MMIO region into virtual space.
    pub fn ioremap(&mut self, phys: u64, size: u64, mem_type: IoMemType) -> Result<u64> {
        if size == 0 {
            return Err(Error::InvalidArgument);
        }
        if self.count >= MAX_IO_MAPPINGS {
            return Err(Error::OutOfMemory);
        }

        let aligned_size = Self::align_up(size);
        let remaining = IOREMAP_BASE + IOREMAP_SIZE - self.next_virt;
        if aligned_size > remaining {
            return Err(Error::OutOfMemory);
        }

        let virt = self.next_virt;
        self.mappings[self.count] = IoMapping::new(phys, virt, aligned_size, mem_type);
        self.count += 1;
        self.next_virt += aligned_size;

        Ok(virt)
    }

    /// Unmap a previously mapped region.
    pub fn iounmap(&mut self, virt: u64) -> Result<()> {
        for idx in 0..self.count {
            if self.mappings[idx].virt_base() == virt && self.mappings[idx].is_active() {
                self.mappings[idx].deactivate();
                return Ok(());
            }
        }
        Err(Error::NotFound)
    }

    /// Look up a mapping by virtual address.
    pub fn find_mapping(&self, virt: u64) -> Option<&IoMapping> {
        for idx in 0..self.count {
            let m = &self.mappings[idx];
            if m.is_active() && virt >= m.virt_base() && virt < m.virt_base() + m.size() {
                return Some(m);
            }
        }
        None
    }
}

impl Default for IoRemapAllocator {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// Public helpers
// -------------------------------------------------------------------

/// Map an MMIO region as uncacheable.
pub fn ioremap_uc(alloc: &mut IoRemapAllocator, phys: u64, size: u64) -> Result<u64> {
    alloc.ioremap(phys, size, IoMemType::Uncacheable)
}

/// Map an MMIO region as write-combining.
pub fn ioremap_wc(alloc: &mut IoRemapAllocator, phys: u64, size: u64) -> Result<u64> {
    alloc.ioremap(phys, size, IoMemType::WriteCombining)
}

/// Translate a virtual ioremap address to physical.
pub fn ioremap_translate(alloc: &IoRemapAllocator, virt: u64) -> Option<u64> {
    alloc.find_mapping(virt).and_then(|m| m.translate(virt))
}
