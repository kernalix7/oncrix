// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! DMA address space mapping subsystem.
//!
//! Provides a hardware-agnostic interface for mapping kernel/physical memory
//! regions into the DMA address space that devices see. This is the Rust
//! equivalent of the Linux DMA-mapping API (`include/linux/dma-mapping.h`).
//!
//! # Concepts
//!
//! - **DMA address (dma_addr_t)** — the address a device uses when performing
//!   DMA. May differ from the CPU physical address when an IOMMU is present.
//! - **Coherent mapping** — CPU and device see the same data without explicit
//!   cache management. Typically implemented as uncached/write-combining memory.
//! - **Streaming mapping** — DMA of existing kernel buffers. Requires explicit
//!   sync operations (`sync_for_device` / `sync_for_cpu`) to handle caches.
//! - **DMA direction** — controls which caches are flushed/invalidated.
//! - **DMA mask** — the maximum DMA address the device can generate
//!   (e.g. 32-bit DMA: 0xFFFF_FFFF).
//!
//! # Address Translation
//!
//! Without an IOMMU: `dma_addr = phys_addr + dma_offset`.
//! With an IOMMU: the IOMMU translates an IOVA → physical address.
//!
//! # Usage
//!
//! ```ignore
//! let mut ctx = DmaContext::new(DmaMask::BITS32);
//! ctx.init()?;
//! let region = ctx.alloc_coherent(4096)?;
//! // use region.dma_addr for DMA descriptors
//! ctx.free_coherent(region);
//! ```
//!
//! Reference: Linux `Documentation/core-api/dma-api.rst`,
//! `Documentation/core-api/dma-api-howto.rst`.

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum number of active DMA mappings tracked per context.
pub const MAX_DMA_MAPPINGS: usize = 256;

/// Maximum number of DMA contexts (one per device typically).
pub const MAX_DMA_CONTEXTS: usize = 32;

/// Alignment required for coherent DMA allocations (cache-line size = 64 B).
pub const DMA_COHERENT_ALIGN: usize = 64;

/// Scatter-gather list maximum entries.
pub const MAX_SG_ENTRIES: usize = 64;

// ---------------------------------------------------------------------------
// DMA Mask
// ---------------------------------------------------------------------------

/// DMA address mask defining the maximum address a device can reach.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct DmaMask(pub u64);

impl DmaMask {
    /// 24-bit DMA mask (ISA devices).
    pub const BITS24: Self = Self(0x00FF_FFFF);
    /// 32-bit DMA mask (most legacy PCI devices).
    pub const BITS32: Self = Self(0xFFFF_FFFF);
    /// 40-bit DMA mask.
    pub const BITS40: Self = Self(0xFF_FFFF_FFFF);
    /// 48-bit DMA mask.
    pub const BITS48: Self = Self(0xFFFF_FFFF_FFFF);
    /// 64-bit DMA mask (modern PCIe devices).
    pub const BITS64: Self = Self(0xFFFF_FFFF_FFFF_FFFF);

    /// Returns `true` if the given physical address is within this mask.
    pub fn covers(&self, phys: u64) -> bool {
        phys <= self.0
    }
}

impl Default for DmaMask {
    fn default() -> Self {
        Self::BITS32
    }
}

// ---------------------------------------------------------------------------
// DMA direction
// ---------------------------------------------------------------------------

/// Specifies the direction of a DMA transfer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DmaDirection {
    /// Data moves from device to CPU memory (e.g., DMA read / network RX).
    ToDevice,
    /// Data moves from CPU memory to device (e.g., DMA write / network TX).
    FromDevice,
    /// Data flows in both directions.
    Bidirectional,
    /// No data movement (for status/flag buffers).
    None,
}

// ---------------------------------------------------------------------------
// DMA region (coherent)
// ---------------------------------------------------------------------------

/// A coherently-mapped DMA region.
///
/// Returned by [`DmaContext::alloc_coherent`] and must be freed with
/// [`DmaContext::free_coherent`].
#[derive(Debug, Clone, Copy)]
pub struct DmaRegion {
    /// CPU-visible virtual address of the region.
    pub virt_addr: u64,
    /// Physical address of the region.
    pub phys_addr: u64,
    /// DMA address that the device uses.
    pub dma_addr: u64,
    /// Size of the region in bytes.
    pub size: usize,
    /// Index into the context's mapping table.
    pub(crate) slot: usize,
}

// ---------------------------------------------------------------------------
// Streaming DMA mapping
// ---------------------------------------------------------------------------

/// A single streaming DMA mapping entry.
#[derive(Debug, Clone, Copy)]
pub struct DmaMapping {
    /// Physical address of the mapped buffer.
    pub phys_addr: u64,
    /// DMA address given to the device.
    pub dma_addr: u64,
    /// Length of the buffer in bytes.
    pub size: usize,
    /// Transfer direction.
    pub direction: DmaDirection,
    /// Whether this slot is in use.
    pub(crate) active: bool,
}

impl DmaMapping {
    /// An inactive (empty) mapping slot.
    pub const EMPTY: Self = Self {
        phys_addr: 0,
        dma_addr: 0,
        size: 0,
        direction: DmaDirection::None,
        active: false,
    };
}

// ---------------------------------------------------------------------------
// Scatter-Gather
// ---------------------------------------------------------------------------

/// A single scatter-gather list entry.
#[derive(Debug, Clone, Copy, Default)]
pub struct SgEntry {
    /// Physical address of this chunk.
    pub phys_addr: u64,
    /// DMA address for this chunk (filled by `map_sg`).
    pub dma_addr: u64,
    /// Length of this chunk in bytes.
    pub len: u32,
    /// Offset within the original buffer.
    pub offset: u32,
}

/// A scatter-gather list for multi-region DMA transfers.
pub struct SgList {
    entries: [SgEntry; MAX_SG_ENTRIES],
    count: usize,
}

impl SgList {
    /// Creates an empty scatter-gather list.
    pub const fn new() -> Self {
        Self {
            entries: [SgEntry {
                phys_addr: 0,
                dma_addr: 0,
                len: 0,
                offset: 0,
            }; MAX_SG_ENTRIES],
            count: 0,
        }
    }

    /// Appends an entry to the list.
    pub fn push(&mut self, entry: SgEntry) -> Result<()> {
        if self.count >= MAX_SG_ENTRIES {
            return Err(Error::OutOfMemory);
        }
        self.entries[self.count] = entry;
        self.count += 1;
        Ok(())
    }

    /// Returns the entry at `index`.
    pub fn get(&self, index: usize) -> Option<&SgEntry> {
        if index < self.count {
            Some(&self.entries[index])
        } else {
            None
        }
    }

    /// Returns a mutable reference to the entry at `index`.
    pub fn get_mut(&mut self, index: usize) -> Option<&mut SgEntry> {
        if index < self.count {
            Some(&mut self.entries[index])
        } else {
            None
        }
    }

    /// Returns the number of entries.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Returns `true` if the list is empty.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Clears all entries.
    pub fn clear(&mut self) {
        self.count = 0;
    }
}

impl Default for SgList {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// DMA pool (simple fixed-size allocator for coherent memory)
// ---------------------------------------------------------------------------

/// Fixed-size pool for coherent DMA allocations.
///
/// Each slot tracks a fixed-stride coherent region. In a real system the
/// backing memory would be allocated from a DMA-safe physical range; here
/// we model the accounting only.
pub struct DmaPool {
    /// Physical base address of the pool backing memory.
    phys_base: u64,
    /// DMA base address (may differ if an IOMMU is present).
    dma_base: u64,
    /// Size of each allocation slot in bytes.
    slot_size: usize,
    /// Maximum number of slots.
    capacity: usize,
    /// Bitmap of allocated slots (true = in use).
    allocated: [bool; MAX_DMA_MAPPINGS],
}

impl DmaPool {
    /// Creates a new DMA pool.
    ///
    /// `phys_base` — physical address of the pool backing memory.
    /// `dma_offset` — added to physical addresses to get DMA addresses.
    /// `slot_size` — bytes per allocation (must be ≥ 1).
    /// `capacity` — number of slots (capped at `MAX_DMA_MAPPINGS`).
    pub const fn new(phys_base: u64, dma_offset: i64, slot_size: usize, capacity: usize) -> Self {
        let dma_base = phys_base.wrapping_add_signed(dma_offset);
        let cap = if capacity > MAX_DMA_MAPPINGS {
            MAX_DMA_MAPPINGS
        } else {
            capacity
        };
        Self {
            phys_base,
            dma_base,
            slot_size,
            capacity: cap,
            allocated: [false; MAX_DMA_MAPPINGS],
        }
    }

    /// Allocates a slot from the pool.
    ///
    /// Returns a [`DmaRegion`] on success, or `Err(OutOfMemory)` if the pool
    /// is exhausted.
    pub fn alloc(&mut self) -> Result<DmaRegion> {
        for slot in 0..self.capacity {
            if !self.allocated[slot] {
                self.allocated[slot] = true;
                let offset = (slot * self.slot_size) as u64;
                let phys = self.phys_base + offset;
                let dma = self.dma_base + offset;
                return Ok(DmaRegion {
                    virt_addr: phys, // identity-mapped in simple model
                    phys_addr: phys,
                    dma_addr: dma,
                    size: self.slot_size,
                    slot,
                });
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Frees a previously allocated slot.
    pub fn free(&mut self, region: DmaRegion) {
        if region.slot < self.capacity {
            self.allocated[region.slot] = false;
        }
    }

    /// Returns the number of allocated slots.
    pub fn allocated_count(&self) -> usize {
        self.allocated[..self.capacity]
            .iter()
            .filter(|&&x| x)
            .count()
    }

    /// Returns `true` if the pool is exhausted.
    pub fn is_full(&self) -> bool {
        self.allocated_count() == self.capacity
    }
}

// ---------------------------------------------------------------------------
// DmaContext
// ---------------------------------------------------------------------------

/// DMA context for a single device.
///
/// Tracks the device's DMA mask, streaming mappings, and provides access to
/// a DMA pool for coherent allocations.
pub struct DmaContext {
    /// Device DMA mask.
    pub mask: DmaMask,
    /// DMA offset added to physical addresses (0 if no IOMMU, no offset).
    pub dma_offset: i64,
    /// Streaming DMA mappings table.
    mappings: [DmaMapping; MAX_DMA_MAPPINGS],
    /// Number of active streaming mappings.
    mapping_count: usize,
    /// Whether the context has been initialised.
    initialized: bool,
}

impl DmaContext {
    /// Creates a new DMA context with the given mask.
    pub const fn new(mask: DmaMask) -> Self {
        Self {
            mask,
            dma_offset: 0,
            mappings: [DmaMapping::EMPTY; MAX_DMA_MAPPINGS],
            mapping_count: 0,
            initialized: false,
        }
    }

    /// Initialises the context.
    pub fn init(&mut self) -> Result<()> {
        self.initialized = true;
        Ok(())
    }

    /// Maps a physical buffer for DMA streaming access.
    ///
    /// Returns the DMA address to program into the device descriptor.
    /// Call [`sync_for_device`](Self::sync_for_device) before starting DMA
    /// and [`sync_for_cpu`](Self::sync_for_cpu) after the device completes.
    pub fn map_single(
        &mut self,
        phys_addr: u64,
        size: usize,
        direction: DmaDirection,
    ) -> Result<u64> {
        if !self.initialized {
            return Err(Error::IoError);
        }
        let dma_addr = self.phys_to_dma(phys_addr);
        if !self.mask.covers(dma_addr) {
            return Err(Error::InvalidArgument);
        }
        let slot = self.alloc_mapping_slot()?;
        self.mappings[slot] = DmaMapping {
            phys_addr,
            dma_addr,
            size,
            direction,
            active: true,
        };
        self.mapping_count += 1;
        Ok(dma_addr)
    }

    /// Unmaps a streaming DMA mapping by DMA address.
    ///
    /// The caller must have completed the DMA transfer and called
    /// `sync_for_cpu` before unmapping.
    pub fn unmap_single(&mut self, dma_addr: u64) {
        for i in 0..MAX_DMA_MAPPINGS {
            if self.mappings[i].active && self.mappings[i].dma_addr == dma_addr {
                self.mappings[i].active = false;
                if self.mapping_count > 0 {
                    self.mapping_count -= 1;
                }
                return;
            }
        }
    }

    /// Maps a scatter-gather list for DMA.
    ///
    /// Fills in the `dma_addr` field of each `SgEntry`. Returns the number
    /// of entries successfully mapped.
    pub fn map_sg(&mut self, sg: &mut SgList, direction: DmaDirection) -> Result<usize> {
        if !self.initialized {
            return Err(Error::IoError);
        }
        let n = sg.len();
        for i in 0..n {
            let entry = sg.get_mut(i).ok_or(Error::InvalidArgument)?;
            let dma = self.phys_to_dma(entry.phys_addr);
            if !self.mask.covers(dma) {
                // Unmap already-mapped entries.
                for j in 0..i {
                    if let Some(e) = sg.get_mut(j) {
                        self.unmap_single(e.dma_addr);
                        e.dma_addr = 0;
                    }
                }
                return Err(Error::InvalidArgument);
            }
            let slot = self.alloc_mapping_slot()?;
            self.mappings[slot] = DmaMapping {
                phys_addr: entry.phys_addr,
                dma_addr: dma,
                size: entry.len as usize,
                direction,
                active: true,
            };
            self.mapping_count += 1;
            entry.dma_addr = dma;
        }
        Ok(n)
    }

    /// Unmaps all entries in a scatter-gather list.
    pub fn unmap_sg(&mut self, sg: &mut SgList) {
        for i in 0..sg.len() {
            if let Some(e) = sg.get_mut(i) {
                self.unmap_single(e.dma_addr);
                e.dma_addr = 0;
            }
        }
    }

    /// Prepares a streaming mapping for device access (flush CPU caches).
    ///
    /// Must be called before starting a DMA transfer from the device's
    /// perspective.
    pub fn sync_for_device(&self, dma_addr: u64, size: usize, direction: DmaDirection) {
        // On x86_64 with coherent caches this is a no-op; on architectures
        // with non-coherent caches this would flush the relevant cache lines.
        let _ = (dma_addr, size, direction);
        #[cfg(target_arch = "x86_64")]
        {
            // x86_64 has a fully-coherent cache model for DMA; no flush needed.
        }
    }

    /// Prepares a streaming mapping for CPU access (invalidate caches).
    ///
    /// Must be called after a device finishes writing, before the CPU reads.
    pub fn sync_for_cpu(&self, dma_addr: u64, size: usize, direction: DmaDirection) {
        let _ = (dma_addr, size, direction);
        #[cfg(target_arch = "x86_64")]
        {
            // Same rationale as `sync_for_device`.
        }
    }

    /// Returns the number of active streaming mappings.
    pub fn mapping_count(&self) -> usize {
        self.mapping_count
    }

    /// Returns `true` if the context has been initialised.
    pub fn is_initialized(&self) -> bool {
        self.initialized
    }

    /// Converts a physical address to a DMA address using the context offset.
    pub fn phys_to_dma(&self, phys: u64) -> u64 {
        phys.wrapping_add_signed(self.dma_offset)
    }

    /// Converts a DMA address back to a physical address.
    pub fn dma_to_phys(&self, dma: u64) -> u64 {
        dma.wrapping_add_signed(-self.dma_offset)
    }

    // -----------------------------------------------------------------------
    // Private
    // -----------------------------------------------------------------------

    fn alloc_mapping_slot(&self) -> Result<usize> {
        for i in 0..MAX_DMA_MAPPINGS {
            if !self.mappings[i].active {
                return Ok(i);
            }
        }
        Err(Error::OutOfMemory)
    }
}

// ---------------------------------------------------------------------------
// Global DMA context registry
// ---------------------------------------------------------------------------

/// Global registry of DMA contexts (one per device).
pub struct DmaContextRegistry {
    contexts: [DmaContext; MAX_DMA_CONTEXTS],
    count: usize,
}

impl DmaContextRegistry {
    /// Creates an empty registry.
    pub const fn new() -> Self {
        Self {
            contexts: [const { DmaContext::new(DmaMask::BITS32) }; MAX_DMA_CONTEXTS],
            count: 0,
        }
    }

    /// Registers a DMA context for a device and returns its index.
    pub fn register(&mut self, mask: DmaMask) -> Result<usize> {
        if self.count >= MAX_DMA_CONTEXTS {
            return Err(Error::OutOfMemory);
        }
        let mut ctx = DmaContext::new(mask);
        ctx.init()?;
        let idx = self.count;
        self.contexts[idx] = ctx;
        self.count += 1;
        Ok(idx)
    }

    /// Returns an immutable reference to the context at `index`.
    pub fn get(&self, index: usize) -> Option<&DmaContext> {
        if index < self.count {
            Some(&self.contexts[index])
        } else {
            None
        }
    }

    /// Returns a mutable reference to the context at `index`.
    pub fn get_mut(&mut self, index: usize) -> Option<&mut DmaContext> {
        if index < self.count {
            Some(&mut self.contexts[index])
        } else {
            None
        }
    }

    /// Returns the number of registered contexts.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Returns `true` if no contexts are registered.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
}

impl Default for DmaContextRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dma_mask_coverage() {
        assert!(DmaMask::BITS32.covers(0xFFFF_FFFF));
        assert!(!DmaMask::BITS32.covers(0x1_0000_0000));
        assert!(DmaMask::BITS64.covers(u64::MAX));
    }

    #[test]
    fn dma_context_map_unmap() {
        let mut ctx = DmaContext::new(DmaMask::BITS64);
        ctx.init().unwrap();
        let dma = ctx.map_single(0x1000, 512, DmaDirection::ToDevice).unwrap();
        assert_eq!(dma, 0x1000);
        assert_eq!(ctx.mapping_count(), 1);
        ctx.unmap_single(dma);
        assert_eq!(ctx.mapping_count(), 0);
    }

    #[test]
    fn dma_context_mask_violation() {
        let mut ctx = DmaContext::new(DmaMask::BITS32);
        ctx.init().unwrap();
        // Physical address beyond 32-bit mask.
        let result = ctx.map_single(0x1_0000_0000, 4096, DmaDirection::Bidirectional);
        assert!(result.is_err());
    }

    #[test]
    fn dma_pool_alloc_free() {
        let mut pool = DmaPool::new(0x8000_0000, 0, 4096, 4);
        let r1 = pool.alloc().unwrap();
        assert_eq!(r1.phys_addr, 0x8000_0000);
        let r2 = pool.alloc().unwrap();
        assert_eq!(r2.phys_addr, 0x8000_1000);
        pool.free(r1);
        assert_eq!(pool.allocated_count(), 1);
        let r3 = pool.alloc().unwrap();
        assert_eq!(r3.slot, 0); // reused slot 0
    }

    #[test]
    fn dma_pool_exhaustion() {
        let mut pool = DmaPool::new(0, 0, 64, 2);
        pool.alloc().unwrap();
        pool.alloc().unwrap();
        assert!(pool.is_full());
        assert!(pool.alloc().is_err());
    }

    #[test]
    fn sg_list_operations() {
        let mut sg = SgList::new();
        assert!(sg.is_empty());
        sg.push(SgEntry {
            phys_addr: 0x1000,
            dma_addr: 0,
            len: 512,
            offset: 0,
        })
        .unwrap();
        assert_eq!(sg.len(), 1);
        sg.clear();
        assert!(sg.is_empty());
    }

    #[test]
    fn dma_registry_empty() {
        let reg = DmaContextRegistry::new();
        assert!(reg.is_empty());
    }

    #[test]
    fn phys_dma_round_trip() {
        let mut ctx = DmaContext::new(DmaMask::BITS64);
        ctx.dma_offset = 0x1000;
        assert_eq!(ctx.phys_to_dma(0x5000), 0x6000);
        assert_eq!(ctx.dma_to_phys(0x6000), 0x5000);
    }
}
