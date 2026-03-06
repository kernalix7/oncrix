// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! PCIe DMA engine and bus-master DMA coordination.
//!
//! Provides high-level abstractions for PCIe device DMA operations:
//!
//! - [`DmaDirection`] — transfer direction for cache coherency hints
//! - [`DmaRegion`] — a pinned, mapped DMA buffer descriptor
//! - [`PcieDmaEngine`] — coordinator for device DMA transactions
//! - [`ScatterGatherList`] — multi-segment DMA scatter/gather table
//!
//! # DMA Addressing
//!
//! PCIe devices use 32-bit or 64-bit DMA addresses (bus addresses).
//! This module abstracts the translation between physical addresses
//! and bus addresses via an optional IOMMU offset.
//!
//! Reference: PCI Express Base Specification Rev. 6.0, Section 2.2.

use oncrix_lib::{Error, Result};

/// Maximum segments in a scatter-gather list.
const MAX_SG_SEGMENTS: usize = 128;
/// Maximum DMA regions tracked per engine.
const MAX_DMA_REGIONS: usize = 64;

// ── DMA Direction ──────────────────────────────────────────────────────────

/// The direction of a DMA transfer.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum DmaDirection {
    /// Device reads from memory (e.g., NIC transmit).
    ToDevice,
    /// Device writes to memory (e.g., NIC receive).
    FromDevice,
    /// Bidirectional (e.g., some storage commands).
    Bidirectional,
}

// ── DMA Region ─────────────────────────────────────────────────────────────

/// A contiguous DMA-mappable memory region.
#[derive(Clone, Copy)]
pub struct DmaRegion {
    /// Physical (host) address of the buffer.
    pub phys_addr: u64,
    /// Bus (device-visible) DMA address.
    pub dma_addr: u64,
    /// Length of the buffer in bytes.
    pub len: usize,
    /// Transfer direction.
    pub direction: DmaDirection,
    /// True if the mapping is 64-bit capable.
    pub addr64: bool,
}

impl DmaRegion {
    /// Create a new DMA region with identity mapping (phys == dma).
    pub fn identity(phys_addr: u64, len: usize, direction: DmaDirection) -> Self {
        Self {
            phys_addr,
            dma_addr: phys_addr,
            len,
            direction,
            addr64: phys_addr > 0xFFFF_FFFF,
        }
    }

    /// Create a DMA region with an IOMMU-translated bus address.
    pub fn translated(phys_addr: u64, dma_addr: u64, len: usize, direction: DmaDirection) -> Self {
        Self {
            phys_addr,
            dma_addr,
            len,
            direction,
            addr64: dma_addr > 0xFFFF_FFFF,
        }
    }

    /// Return the high 32 bits of the DMA address (for 64-bit BARs).
    pub fn dma_addr_hi(&self) -> u32 {
        (self.dma_addr >> 32) as u32
    }

    /// Return the low 32 bits of the DMA address.
    pub fn dma_addr_lo(&self) -> u32 {
        self.dma_addr as u32
    }
}

// ── Scatter-Gather List ─────────────────────────────────────────────────────

/// A scatter-gather list for multi-segment DMA transfers.
pub struct ScatterGatherList {
    segments: [DmaRegion; MAX_SG_SEGMENTS],
    count: usize,
    /// Total bytes across all segments.
    total_bytes: usize,
}

impl ScatterGatherList {
    /// Create an empty scatter-gather list.
    pub fn new() -> Self {
        Self {
            segments: [const {
                DmaRegion {
                    phys_addr: 0,
                    dma_addr: 0,
                    len: 0,
                    direction: DmaDirection::Bidirectional,
                    addr64: false,
                }
            }; MAX_SG_SEGMENTS],
            count: 0,
            total_bytes: 0,
        }
    }

    /// Append a segment.
    pub fn push(&mut self, region: DmaRegion) -> Result<()> {
        if self.count >= MAX_SG_SEGMENTS {
            return Err(Error::OutOfMemory);
        }
        self.total_bytes += region.len;
        self.segments[self.count] = region;
        self.count += 1;
        Ok(())
    }

    /// Return the number of segments.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Return true if no segments are present.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Return total byte count across all segments.
    pub fn total_len(&self) -> usize {
        self.total_bytes
    }

    /// Iterate over segments as a slice.
    pub fn segments(&self) -> &[DmaRegion] {
        &self.segments[..self.count]
    }

    /// Clear all segments.
    pub fn clear(&mut self) {
        self.count = 0;
        self.total_bytes = 0;
    }
}

impl Default for ScatterGatherList {
    fn default() -> Self {
        Self::new()
    }
}

// ── DMA Capability ─────────────────────────────────────────────────────────

/// DMA capabilities reported by the device or platform.
#[derive(Clone, Copy)]
pub struct DmaCapability {
    /// Maximum DMA address bits supported by the device.
    pub dma_mask_bits: u8,
    /// Whether the device supports 64-bit DMA.
    pub supports_64bit: bool,
    /// Whether the device supports scatter-gather DMA.
    pub supports_sg: bool,
    /// Maximum scatter-gather segments in a single transfer.
    pub max_sg_segments: u32,
    /// Maximum single DMA transfer size in bytes.
    pub max_transfer_size: u64,
}

impl DmaCapability {
    /// Standard 32-bit DMA capability.
    pub const DMA_32BIT: Self = Self {
        dma_mask_bits: 32,
        supports_64bit: false,
        supports_sg: true,
        max_sg_segments: 32,
        max_transfer_size: u64::MAX,
    };

    /// Standard 64-bit DMA capability.
    pub const DMA_64BIT: Self = Self {
        dma_mask_bits: 64,
        supports_64bit: true,
        supports_sg: true,
        max_sg_segments: MAX_SG_SEGMENTS as u32,
        max_transfer_size: u64::MAX,
    };

    /// Check if a given physical address is reachable.
    pub fn can_reach(&self, addr: u64) -> bool {
        if self.dma_mask_bits >= 64 {
            return true;
        }
        addr < (1u64 << self.dma_mask_bits)
    }
}

// ── PCIe DMA Engine ────────────────────────────────────────────────────────

/// PCIe DMA engine coordinating device DMA transactions.
pub struct PcieDmaEngine {
    /// IOMMU offset applied to physical addresses (0 = identity mapping).
    iommu_offset: u64,
    /// Active DMA regions.
    regions: [Option<DmaRegion>; MAX_DMA_REGIONS],
    /// Number of active regions.
    region_count: usize,
    /// Device DMA capability.
    capability: DmaCapability,
    /// Total bytes currently mapped.
    mapped_bytes: u64,
}

impl PcieDmaEngine {
    /// Create a new DMA engine with identity mapping.
    pub fn new(capability: DmaCapability) -> Self {
        Self {
            iommu_offset: 0,
            regions: [const { None }; MAX_DMA_REGIONS],
            region_count: 0,
            capability,
            mapped_bytes: 0,
        }
    }

    /// Set an IOMMU address offset (physical → bus address translation).
    pub fn set_iommu_offset(&mut self, offset: u64) {
        self.iommu_offset = offset;
    }

    /// Map a physical buffer for DMA.
    pub fn map(
        &mut self,
        phys_addr: u64,
        len: usize,
        direction: DmaDirection,
    ) -> Result<DmaRegion> {
        if self.region_count >= MAX_DMA_REGIONS {
            return Err(Error::OutOfMemory);
        }
        let dma_addr = phys_addr.wrapping_add(self.iommu_offset);
        if !self.capability.can_reach(dma_addr) {
            return Err(Error::InvalidArgument);
        }
        let region = DmaRegion::translated(phys_addr, dma_addr, len, direction);
        self.regions[self.region_count] = Some(region);
        self.region_count += 1;
        self.mapped_bytes += len as u64;
        Ok(region)
    }

    /// Unmap a previously mapped DMA region.
    pub fn unmap(&mut self, dma_addr: u64) -> Result<()> {
        for slot in self.regions.iter_mut() {
            if let Some(r) = slot {
                if r.dma_addr == dma_addr {
                    self.mapped_bytes -= r.len as u64;
                    *slot = None;
                    self.region_count -= 1;
                    return Ok(());
                }
            }
        }
        Err(Error::NotFound)
    }

    /// Build a scatter-gather list from a series of physical buffers.
    pub fn map_sg(
        &mut self,
        buffers: &[(u64, usize)],
        direction: DmaDirection,
    ) -> Result<ScatterGatherList> {
        if buffers.len() > MAX_SG_SEGMENTS {
            return Err(Error::InvalidArgument);
        }
        if !self.capability.supports_sg {
            return Err(Error::NotImplemented);
        }
        let mut sg = ScatterGatherList::new();
        for &(phys, len) in buffers {
            let region = self.map(phys, len, direction)?;
            sg.push(region)?;
        }
        Ok(sg)
    }

    /// Sync a DMA region for CPU access (cache invalidation hint).
    ///
    /// On non-coherent systems, callers must invoke this before reading
    /// DMA buffers written by the device.
    pub fn sync_for_cpu(&self, region: &DmaRegion) -> Result<()> {
        if region.direction == DmaDirection::ToDevice {
            return Err(Error::InvalidArgument);
        }
        // On x86_64, MESI coherency protocol makes explicit sync unnecessary.
        // On non-coherent ARM/RISC-V, the HAL platform layer handles cache ops.
        let _ = region;
        Ok(())
    }

    /// Returns total bytes currently mapped.
    pub fn mapped_bytes(&self) -> u64 {
        self.mapped_bytes
    }

    /// Returns the device DMA capability.
    pub fn capability(&self) -> &DmaCapability {
        &self.capability
    }
}
