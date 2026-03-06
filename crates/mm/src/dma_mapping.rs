// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! DMA address mapping.
//!
//! DMA devices access memory through bus addresses that may differ
//! from CPU physical addresses due to IOMMUs and address translation.
//! This module manages DMA address mappings: translating between CPU
//! physical addresses and DMA bus addresses, tracking mapping
//! lifetimes, and handling bounce buffers for devices with limited
//! address ranges.
//!
//! # Design
//!
//! ```text
//!  dma_map_single(dev, cpu_addr, size, direction)
//!     │
//!     ├─ IOMMU present? → create IOMMU mapping
//!     ├─ device can address cpu_addr? → identity map
//!     └─ otherwise → allocate bounce buffer, copy data
//!
//!  dma_unmap_single(dev, dma_addr, size, direction)
//!     │
//!     ├─ bounce buffer? → sync back, free buffer
//!     └─ IOMMU? → remove mapping
//! ```
//!
//! # Key Types
//!
//! - [`DmaDirection`] — data transfer direction
//! - [`DmaMapping`] — a single DMA mapping
//! - [`DmaMappingTable`] — tracks all active mappings
//! - [`DmaMappingStats`] — mapping statistics
//!
//! Reference: Linux `kernel/dma/mapping.c`, `include/linux/dma-mapping.h`.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Maximum active mappings.
const MAX_MAPPINGS: usize = 4096;

/// Page size.
const PAGE_SIZE: u64 = 4096;

/// DMA address limit for 32-bit devices.
const DMA32_LIMIT: u64 = 0xFFFF_FFFF;

// -------------------------------------------------------------------
// DmaDirection
// -------------------------------------------------------------------

/// Data transfer direction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DmaDirection {
    /// Device reads from memory.
    ToDevice,
    /// Device writes to memory.
    FromDevice,
    /// Bidirectional.
    Bidirectional,
    /// No data transfer (for mapping only).
    None,
}

impl DmaDirection {
    /// Return a label string.
    pub const fn label(&self) -> &'static str {
        match self {
            Self::ToDevice => "to-device",
            Self::FromDevice => "from-device",
            Self::Bidirectional => "bidirectional",
            Self::None => "none",
        }
    }

    /// Check whether a sync-back is needed on unmap.
    pub const fn needs_sync_back(&self) -> bool {
        matches!(self, Self::FromDevice | Self::Bidirectional)
    }
}

// -------------------------------------------------------------------
// DmaMapping
// -------------------------------------------------------------------

/// A single DMA mapping.
#[derive(Debug, Clone, Copy)]
pub struct DmaMapping {
    /// Mapping ID.
    mapping_id: u64,
    /// CPU physical address.
    cpu_addr: u64,
    /// DMA bus address.
    dma_addr: u64,
    /// Size in bytes.
    size: u64,
    /// Direction.
    direction: DmaDirection,
    /// Whether this uses a bounce buffer.
    bounce: bool,
    /// Device ID.
    device_id: u64,
    /// Whether the mapping is active.
    active: bool,
    /// Timestamp.
    timestamp: u64,
}

impl DmaMapping {
    /// Create a new mapping.
    pub const fn new(
        mapping_id: u64,
        cpu_addr: u64,
        dma_addr: u64,
        size: u64,
        direction: DmaDirection,
        device_id: u64,
        timestamp: u64,
    ) -> Self {
        Self {
            mapping_id,
            cpu_addr,
            dma_addr,
            size,
            direction,
            bounce: false,
            device_id,
            active: true,
            timestamp,
        }
    }

    /// Return the mapping ID.
    pub const fn mapping_id(&self) -> u64 {
        self.mapping_id
    }

    /// Return the CPU address.
    pub const fn cpu_addr(&self) -> u64 {
        self.cpu_addr
    }

    /// Return the DMA address.
    pub const fn dma_addr(&self) -> u64 {
        self.dma_addr
    }

    /// Return the size.
    pub const fn size(&self) -> u64 {
        self.size
    }

    /// Return the direction.
    pub const fn direction(&self) -> DmaDirection {
        self.direction
    }

    /// Check whether a bounce buffer is used.
    pub const fn bounce(&self) -> bool {
        self.bounce
    }

    /// Return the device ID.
    pub const fn device_id(&self) -> u64 {
        self.device_id
    }

    /// Check whether the mapping is active.
    pub const fn active(&self) -> bool {
        self.active
    }

    /// Set bounce buffer flag.
    pub fn set_bounce(&mut self, val: bool) {
        self.bounce = val;
    }

    /// Unmap (deactivate).
    pub fn unmap(&mut self) {
        self.active = false;
    }

    /// Page count.
    pub const fn page_count(&self) -> u64 {
        (self.size + PAGE_SIZE - 1) / PAGE_SIZE
    }
}

impl Default for DmaMapping {
    fn default() -> Self {
        Self {
            mapping_id: 0,
            cpu_addr: 0,
            dma_addr: 0,
            size: 0,
            direction: DmaDirection::None,
            bounce: false,
            device_id: 0,
            active: false,
            timestamp: 0,
        }
    }
}

// -------------------------------------------------------------------
// DmaMappingStats
// -------------------------------------------------------------------

/// Mapping statistics.
#[derive(Debug, Clone, Copy)]
pub struct DmaMappingStats {
    /// Total mappings created.
    pub total_maps: u64,
    /// Total mappings removed.
    pub total_unmaps: u64,
    /// Bounce buffer allocations.
    pub bounce_allocs: u64,
    /// Total bytes mapped.
    pub total_bytes: u64,
    /// Mapping failures.
    pub map_failures: u64,
}

impl DmaMappingStats {
    /// Create zero stats.
    pub const fn new() -> Self {
        Self {
            total_maps: 0,
            total_unmaps: 0,
            bounce_allocs: 0,
            total_bytes: 0,
            map_failures: 0,
        }
    }

    /// Active mappings.
    pub const fn active_count(&self) -> u64 {
        self.total_maps - self.total_unmaps
    }

    /// Bounce rate as percent.
    pub const fn bounce_rate_pct(&self) -> u64 {
        if self.total_maps == 0 {
            return 0;
        }
        self.bounce_allocs * 100 / self.total_maps
    }
}

impl Default for DmaMappingStats {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// DmaMappingTable
// -------------------------------------------------------------------

/// Tracks all active DMA mappings.
pub struct DmaMappingTable {
    /// Mappings.
    mappings: [DmaMapping; MAX_MAPPINGS],
    /// Number of mappings.
    count: usize,
    /// Next mapping ID.
    next_id: u64,
    /// Statistics.
    stats: DmaMappingStats,
}

impl DmaMappingTable {
    /// Create a new table.
    pub const fn new() -> Self {
        Self {
            mappings: [const {
                DmaMapping {
                    mapping_id: 0,
                    cpu_addr: 0,
                    dma_addr: 0,
                    size: 0,
                    direction: DmaDirection::None,
                    bounce: false,
                    device_id: 0,
                    active: false,
                    timestamp: 0,
                }
            }; MAX_MAPPINGS],
            count: 0,
            next_id: 1,
            stats: DmaMappingStats::new(),
        }
    }

    /// Return the statistics.
    pub const fn stats(&self) -> &DmaMappingStats {
        &self.stats
    }

    /// Return the number of mappings.
    pub const fn count(&self) -> usize {
        self.count
    }

    /// Create a DMA mapping.
    pub fn map(
        &mut self,
        cpu_addr: u64,
        size: u64,
        direction: DmaDirection,
        device_id: u64,
        dma_limit: u64,
        timestamp: u64,
    ) -> Result<u64> {
        if size == 0 {
            return Err(Error::InvalidArgument);
        }
        if self.count >= MAX_MAPPINGS {
            self.stats.map_failures += 1;
            return Err(Error::OutOfMemory);
        }

        let mid = self.next_id;
        let bounce = cpu_addr + size > dma_limit;
        let dma_addr = if bounce { 0 } else { cpu_addr };

        let mut mapping = DmaMapping::new(
            mid, cpu_addr, dma_addr, size, direction, device_id, timestamp,
        );
        if bounce {
            mapping.set_bounce(true);
            self.stats.bounce_allocs += 1;
        }

        self.mappings[self.count] = mapping;
        self.count += 1;
        self.next_id += 1;
        self.stats.total_maps += 1;
        self.stats.total_bytes += size;
        Ok(mid)
    }

    /// Remove a DMA mapping.
    pub fn unmap(&mut self, mapping_id: u64) -> Result<()> {
        for idx in 0..self.count {
            if self.mappings[idx].mapping_id() == mapping_id && self.mappings[idx].active() {
                self.mappings[idx].unmap();
                self.stats.total_unmaps += 1;
                return Ok(());
            }
        }
        Err(Error::NotFound)
    }

    /// Find a mapping by ID.
    pub fn find(&self, mapping_id: u64) -> Option<&DmaMapping> {
        for idx in 0..self.count {
            if self.mappings[idx].mapping_id() == mapping_id {
                return Some(&self.mappings[idx]);
            }
        }
        None
    }

    /// Translate DMA address to CPU address.
    pub fn dma_to_cpu(&self, dma_addr: u64) -> Option<u64> {
        for idx in 0..self.count {
            let m = &self.mappings[idx];
            if m.active() && dma_addr >= m.dma_addr() && dma_addr < m.dma_addr() + m.size() {
                let offset = dma_addr - m.dma_addr();
                return Some(m.cpu_addr() + offset);
            }
        }
        None
    }
}

impl Default for DmaMappingTable {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// Public helpers
// -------------------------------------------------------------------

/// Return the maximum mappings.
pub const fn max_mappings() -> usize {
    MAX_MAPPINGS
}

/// Return the DMA32 address limit.
pub const fn dma32_limit() -> u64 {
    DMA32_LIMIT
}
