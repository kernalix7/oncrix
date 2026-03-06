// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! DMA remapping helper (IOMMU DMA mapping layer).
//!
//! Provides a software mapping table that tracks device DMA buffers:
//! their I/O virtual addresses (IOVAs), physical addresses, sizes, and
//! direction. This sits above the hardware IOMMU and provides the
//! "streaming DMA" interface used by device drivers.
//!
//! # Usage
//!
//! 1. Call [`DmaRemapTable::map`] to create a mapping for a DMA buffer.
//! 2. Pass the returned IOVA to the device.
//! 3. After the transfer, call [`DmaRemapTable::unmap`] to release it.
//!
//! Reference: Linux `include/linux/dma-mapping.h`, kernel DMA API.

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum number of concurrent DMA mappings tracked.
pub const MAX_DMA_MAPPINGS: usize = 256;

/// Page size for IOVA alignment (4 KiB).
pub const DMA_PAGE_SIZE: u64 = 4096;

// ---------------------------------------------------------------------------
// DMA direction
// ---------------------------------------------------------------------------

/// DMA transfer direction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DmaDirection {
    /// CPU writes, device reads (host → device).
    ToDevice,
    /// Device writes, CPU reads (device → host).
    FromDevice,
    /// Bidirectional transfer.
    Bidirectional,
    /// No data transfer (address-only).
    None,
}

// ---------------------------------------------------------------------------
// DmaMapping
// ---------------------------------------------------------------------------

/// A single active DMA mapping entry.
#[derive(Debug, Clone, Copy)]
pub struct DmaMapping {
    /// Physical address of the mapped buffer.
    pub phys_addr: u64,
    /// I/O virtual address (device-visible DMA address).
    pub iova: u64,
    /// Size of the mapped region in bytes.
    pub size: u64,
    /// Transfer direction.
    pub direction: DmaDirection,
    /// PCI Bus:Device.Function of the device that owns this mapping.
    pub bdf: u16,
    /// Whether this slot is in use.
    pub active: bool,
}

impl DmaMapping {
    const fn empty() -> Self {
        Self {
            phys_addr: 0,
            iova: 0,
            size: 0,
            direction: DmaDirection::None,
            bdf: 0,
            active: false,
        }
    }
}

// ---------------------------------------------------------------------------
// DmaStats
// ---------------------------------------------------------------------------

/// DMA mapping statistics.
#[derive(Debug, Clone, Copy, Default)]
pub struct DmaStats {
    /// Total mappings created.
    pub maps: u64,
    /// Total mappings released.
    pub unmaps: u64,
    /// Total bytes mapped.
    pub bytes_mapped: u64,
}

// ---------------------------------------------------------------------------
// DmaRemapTable
// ---------------------------------------------------------------------------

/// Tracks all active DMA mappings across all devices.
pub struct DmaRemapTable {
    mappings: [DmaMapping; MAX_DMA_MAPPINGS],
    /// Next IOVA to allocate (simple bump allocator starting at 4 MiB).
    next_iova: u64,
    stats: DmaStats,
}

impl Default for DmaRemapTable {
    fn default() -> Self {
        Self::new()
    }
}

impl DmaRemapTable {
    /// Creates an empty DMA remap table.
    pub fn new() -> Self {
        Self {
            mappings: [DmaMapping::empty(); MAX_DMA_MAPPINGS],
            // Start IOVA allocations at 4 MiB to avoid low-address conflicts.
            next_iova: 0x0040_0000,
            stats: DmaStats::default(),
        }
    }

    /// Allocates an IOVA range aligned to `DMA_PAGE_SIZE`.
    fn alloc_iova(&mut self, size: u64) -> u64 {
        let aligned_size = size.next_multiple_of(DMA_PAGE_SIZE);
        let iova = self.next_iova;
        self.next_iova = self.next_iova.saturating_add(aligned_size);
        iova
    }

    /// Creates a DMA mapping for a physical buffer.
    ///
    /// Returns the IOVA that should be programmed into the device.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the mapping table is full or the
    /// IOVA space is exhausted.
    /// Returns [`Error::InvalidArgument`] if `size` is zero.
    pub fn map(
        &mut self,
        phys_addr: u64,
        size: u64,
        direction: DmaDirection,
        bdf: u16,
    ) -> Result<u64> {
        if size == 0 {
            return Err(Error::InvalidArgument);
        }
        // Find a free slot.
        let slot = self
            .mappings
            .iter()
            .position(|m| !m.active)
            .ok_or(Error::OutOfMemory)?;

        let iova = self.alloc_iova(size);
        self.mappings[slot] = DmaMapping {
            phys_addr,
            iova,
            size,
            direction,
            bdf,
            active: true,
        };
        self.stats.maps += 1;
        self.stats.bytes_mapped = self.stats.bytes_mapped.saturating_add(size);
        Ok(iova)
    }

    /// Releases a DMA mapping by its IOVA.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if no mapping for `iova` exists.
    pub fn unmap(&mut self, iova: u64) -> Result<()> {
        let slot = self
            .mappings
            .iter()
            .position(|m| m.active && m.iova == iova)
            .ok_or(Error::NotFound)?;
        self.mappings[slot].active = false;
        self.stats.unmaps += 1;
        Ok(())
    }

    /// Looks up the physical address for an IOVA.
    pub fn lookup_phys(&self, iova: u64) -> Option<u64> {
        self.mappings
            .iter()
            .find(|m| m.active && iova >= m.iova && iova < m.iova + m.size)
            .map(|m| m.phys_addr + (iova - m.iova))
    }

    /// Returns a reference to a mapping by IOVA.
    pub fn find(&self, iova: u64) -> Option<&DmaMapping> {
        self.mappings.iter().find(|m| m.active && m.iova == iova)
    }

    /// Releases all mappings owned by `bdf`.
    pub fn unmap_all_for_device(&mut self, bdf: u16) -> usize {
        let mut count = 0;
        for m in self.mappings.iter_mut() {
            if m.active && m.bdf == bdf {
                m.active = false;
                self.stats.unmaps += 1;
                count += 1;
            }
        }
        count
    }

    /// Returns the number of active mappings.
    pub fn active_count(&self) -> usize {
        self.mappings.iter().filter(|m| m.active).count()
    }

    /// Returns DMA statistics.
    pub fn stats(&self) -> &DmaStats {
        &self.stats
    }
}
