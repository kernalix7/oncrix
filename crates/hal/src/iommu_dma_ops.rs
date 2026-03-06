// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! IOMMU DMA operations layer.
//!
//! Provides a unified interface for DMA mapping and unmapping, with
//! IOMMU-backed address translation when available and a direct
//! (identity) fallback for non-IOMMU or bounce-buffer paths.
//!
//! # Overview
//!
//! - [`DmaDomain`] — an IOMMU protection domain for a set of devices.
//! - [`DmaOps`] — map/unmap single buffers and scatter-gather lists.
//! - [`IovaAllocator`] — bump allocator for I/O virtual addresses.
//! - [`BounceBuffer`] — fallback buffer for devices incapable of
//!   accessing the full physical address space.
//!
//! # DMA Directions
//!
//! [`DmaDirection`] mirrors the Linux `enum dma_data_direction`:
//! - `ToDevice` — CPU writes, device reads (TX).
//! - `FromDevice` — device writes, CPU reads (RX).
//! - `Bidirectional` — both directions (shared memory).
//!
//! Reference: Linux `drivers/iommu/dma-iommu.c`, `include/linux/dma-mapping.h`.

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Page size used by the IOMMU (4 KiB).
const IOMMU_PAGE_SIZE: u64 = 4096;

/// Page size mask — bits below this must be zero for aligned addresses.
const IOMMU_PAGE_MASK: u64 = IOMMU_PAGE_SIZE - 1;

/// Maximum scatter-gather segments per transfer.
const MAX_SG_SEGMENTS: usize = 32;

/// Maximum active DMA mappings per domain.
const MAX_DMA_MAPPINGS: usize = 128;

/// Bounce buffer size (1 MiB) for non-IOMMU fallback paths.
const BOUNCE_BUFFER_SIZE: usize = 1024 * 1024;

/// IOVA allocator base address (start of the IOVA space).
const IOVA_BASE: u64 = 0x0001_0000_0000; // 4 GiB — above 32-bit space

/// IOVA allocator limit (256 GiB).
const IOVA_LIMIT: u64 = 0x0040_0000_0000;

/// Maximum number of DMA domains.
const MAX_DOMAINS: usize = 8;

// ---------------------------------------------------------------------------
// DMA Direction
// ---------------------------------------------------------------------------

/// Data transfer direction for a DMA operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DmaDirection {
    /// CPU writes data to memory; device reads from it (TX path).
    ToDevice,
    /// Device writes data to memory; CPU reads from it (RX path).
    FromDevice,
    /// Both CPU and device may read and write the buffer.
    Bidirectional,
}

impl DmaDirection {
    /// Return whether device read access is required.
    pub fn device_reads(&self) -> bool {
        matches!(self, Self::ToDevice | Self::Bidirectional)
    }

    /// Return whether device write access is required.
    pub fn device_writes(&self) -> bool {
        matches!(self, Self::FromDevice | Self::Bidirectional)
    }
}

// ---------------------------------------------------------------------------
// Scatter-gather segment
// ---------------------------------------------------------------------------

/// A single contiguous memory segment in a scatter-gather list.
#[derive(Debug, Clone, Copy, Default)]
pub struct SgSegment {
    /// Physical address of this segment.
    pub phys: u64,
    /// Length of this segment in bytes.
    pub len: u64,
    /// I/O virtual address assigned during mapping (0 = unmapped).
    pub iova: u64,
}

impl SgSegment {
    /// Create a new segment for the given physical address and length.
    pub const fn new(phys: u64, len: u64) -> Self {
        Self { phys, len, iova: 0 }
    }
}

/// A scatter-gather list of up to [`MAX_SG_SEGMENTS`] segments.
#[derive(Debug)]
pub struct ScatterList {
    /// Segment entries.
    segments: [SgSegment; MAX_SG_SEGMENTS],
    /// Number of valid entries.
    count: usize,
}

impl Default for ScatterList {
    fn default() -> Self {
        Self::new()
    }
}

impl ScatterList {
    /// Create an empty scatter-gather list.
    pub fn new() -> Self {
        Self {
            segments: [SgSegment::default(); MAX_SG_SEGMENTS],
            count: 0,
        }
    }

    /// Append a segment to the list.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the list is full.
    pub fn push(&mut self, seg: SgSegment) -> Result<()> {
        if self.count >= MAX_SG_SEGMENTS {
            return Err(Error::OutOfMemory);
        }
        self.segments[self.count] = seg;
        self.count += 1;
        Ok(())
    }

    /// Return a slice over the valid segments.
    pub fn segments(&self) -> &[SgSegment] {
        &self.segments[..self.count]
    }

    /// Return a mutable slice over the valid segments.
    pub fn segments_mut(&mut self) -> &mut [SgSegment] {
        &mut self.segments[..self.count]
    }

    /// Number of segments in the list.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Whether the list has no segments.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
}

// ---------------------------------------------------------------------------
// IOVA Allocator
// ---------------------------------------------------------------------------

/// Bump allocator for I/O Virtual Addresses.
///
/// Allocates IOVA ranges from a linear range starting at [`IOVA_BASE`].
/// This is a simplified allocator; a production implementation would
/// use a red-black tree to track free ranges and support deallocation.
#[derive(Debug)]
pub struct IovaAllocator {
    /// Next free IOVA to hand out.
    next: u64,
    /// Upper limit (exclusive).
    limit: u64,
}

impl Default for IovaAllocator {
    fn default() -> Self {
        Self::new()
    }
}

impl IovaAllocator {
    /// Create a new IOVA allocator with default base/limit.
    pub const fn new() -> Self {
        Self {
            next: IOVA_BASE,
            limit: IOVA_LIMIT,
        }
    }

    /// Allocate an IOVA range of `size` bytes, page-aligned.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the IOVA space is exhausted.
    pub fn alloc(&mut self, size: u64) -> Result<u64> {
        if size == 0 {
            return Err(Error::InvalidArgument);
        }
        let aligned_size = (size + IOMMU_PAGE_MASK) & !IOMMU_PAGE_MASK;
        let iova = self.next;
        let next = iova.checked_add(aligned_size).ok_or(Error::OutOfMemory)?;
        if next > self.limit {
            return Err(Error::OutOfMemory);
        }
        self.next = next;
        Ok(iova)
    }

    /// Free a previously allocated IOVA range.
    ///
    /// The bump allocator does not reclaim ranges; this is a no-op
    /// in this implementation. A real allocator would update free-list
    /// data structures here.
    pub fn free(&mut self, _iova: u64, _size: u64) {
        // Bump allocator: deallocation is a no-op.
    }

    /// Return the current allocation frontier.
    pub fn next_free(&self) -> u64 {
        self.next
    }
}

// ---------------------------------------------------------------------------
// Bounce Buffer
// ---------------------------------------------------------------------------

/// Fixed-size bounce buffer for devices that cannot access the full
/// physical address space (e.g., 32-bit DMA mask devices).
///
/// When IOMMU-remapping is unavailable or the physical address lies
/// above the device's DMA mask, data is staged through this buffer.
pub struct BounceBuffer {
    /// The backing storage region (static, identity-mapped).
    data: [u8; BOUNCE_BUFFER_SIZE],
    /// Physical base address of the `data` array.
    phys_base: u64,
    /// Amount of the buffer currently in use.
    used: usize,
}

impl BounceBuffer {
    /// Create a new bounce buffer with the given physical base.
    pub const fn new(phys_base: u64) -> Self {
        Self {
            data: [0u8; BOUNCE_BUFFER_SIZE],
            phys_base,
            used: 0,
        }
    }

    /// Copy `src` into the bounce buffer and return the physical
    /// address that the device should read from.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the buffer cannot hold `src`.
    pub fn stage_for_device(&mut self, src: &[u8]) -> Result<u64> {
        if self.used + src.len() > BOUNCE_BUFFER_SIZE {
            return Err(Error::OutOfMemory);
        }
        let offset = self.used;
        self.data[offset..offset + src.len()].copy_from_slice(src);
        self.used += src.len();
        Ok(self.phys_base + offset as u64)
    }

    /// Copy from the bounce buffer into `dst` (after device DMA).
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `offset + dst.len()` is
    /// out of bounds.
    pub fn retrieve_from_device(&self, offset: usize, dst: &mut [u8]) -> Result<()> {
        let end = offset
            .checked_add(dst.len())
            .ok_or(Error::InvalidArgument)?;
        if end > self.used {
            return Err(Error::InvalidArgument);
        }
        dst.copy_from_slice(&self.data[offset..end]);
        Ok(())
    }

    /// Reset the bounce buffer (reclaim all staged data).
    pub fn reset(&mut self) {
        self.used = 0;
    }

    /// Return the physical base address of the bounce buffer.
    pub fn phys_base(&self) -> u64 {
        self.phys_base
    }

    /// Return the number of bytes currently staged.
    pub fn used(&self) -> usize {
        self.used
    }
}

// ---------------------------------------------------------------------------
// DMA Mapping Record
// ---------------------------------------------------------------------------

/// Tracks a single active DMA mapping within a domain.
#[derive(Debug, Clone, Copy, Default)]
pub struct DmaMappingRecord {
    /// I/O virtual address.
    pub iova: u64,
    /// Physical address.
    pub phys: u64,
    /// Size of the mapping in bytes.
    pub size: u64,
    /// Transfer direction.
    pub direction: u8,
    /// Whether this slot is occupied.
    pub active: bool,
}

impl DmaMappingRecord {
    /// Create an empty, inactive record.
    pub const fn new() -> Self {
        Self {
            iova: 0,
            phys: 0,
            size: 0,
            direction: 0,
            active: false,
        }
    }
}

// ---------------------------------------------------------------------------
// DMA Domain
// ---------------------------------------------------------------------------

/// An IOMMU protection domain grouping one or more PCI devices.
///
/// Each domain has its own IOVA address space managed by an
/// [`IovaAllocator`] and tracks all active mappings for tear-down.
pub struct DmaDomain {
    /// Unique domain identifier.
    id: u32,
    /// IOVA allocator for this domain.
    iova_alloc: IovaAllocator,
    /// Active DMA mappings.
    mappings: [DmaMappingRecord; MAX_DMA_MAPPINGS],
    /// Number of active mappings.
    mapping_count: usize,
    /// Whether the domain is attached to a physical IOMMU unit.
    iommu_backed: bool,
}

impl DmaDomain {
    /// Create a new DMA domain with the given ID.
    ///
    /// If `iommu_backed` is `false`, all map operations use
    /// identity mapping (IOVA == physical address).
    pub fn new(id: u32, iommu_backed: bool) -> Self {
        Self {
            id,
            iova_alloc: IovaAllocator::new(),
            mappings: [DmaMappingRecord::new(); MAX_DMA_MAPPINGS],
            mapping_count: 0,
            iommu_backed,
        }
    }

    /// Map a single contiguous buffer for DMA.
    ///
    /// Returns the IOVA that the device should use to access the buffer.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidArgument`] if `phys` or `size` is zero, or
    ///   if `phys` is not page-aligned.
    /// - [`Error::OutOfMemory`] if the IOVA space or mapping table is
    ///   exhausted.
    pub fn map_single(&mut self, phys: u64, size: u64, direction: DmaDirection) -> Result<u64> {
        if phys == 0 || size == 0 || phys & IOMMU_PAGE_MASK != 0 {
            return Err(Error::InvalidArgument);
        }
        let iova = if self.iommu_backed {
            self.iova_alloc.alloc(size)?
        } else {
            phys // identity mapping
        };
        let slot = self
            .mappings
            .iter()
            .position(|m| !m.active)
            .ok_or(Error::OutOfMemory)?;
        self.mappings[slot] = DmaMappingRecord {
            iova,
            phys,
            size,
            direction: direction as u8,
            active: true,
        };
        if slot >= self.mapping_count {
            self.mapping_count = slot + 1;
        }
        Ok(iova)
    }

    /// Unmap a previously mapped single buffer.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if no mapping for `iova` exists.
    pub fn unmap_single(&mut self, iova: u64) -> Result<()> {
        let slot = self.mappings[..self.mapping_count]
            .iter()
            .position(|m| m.active && m.iova == iova)
            .ok_or(Error::NotFound)?;
        let size = self.mappings[slot].size;
        self.mappings[slot].active = false;
        if self.iommu_backed {
            self.iova_alloc.free(iova, size);
        }
        while self.mapping_count > 0 && !self.mappings[self.mapping_count - 1].active {
            self.mapping_count -= 1;
        }
        Ok(())
    }

    /// Map all segments in a scatter-gather list.
    ///
    /// Assigns an IOVA to each segment in-place. On error, already-mapped
    /// segments are left mapped; the caller must call [`Self::unmap_sg`].
    ///
    /// # Errors
    ///
    /// Returns an error from [`Self::map_single`] if any segment fails.
    pub fn map_sg(&mut self, sg: &mut ScatterList, direction: DmaDirection) -> Result<()> {
        for seg in sg.segments_mut() {
            let aligned_phys = seg.phys & !IOMMU_PAGE_MASK;
            seg.iova = self.map_single(aligned_phys, seg.len, direction)?;
        }
        Ok(())
    }

    /// Unmap all segments in a scatter-gather list.
    pub fn unmap_sg(&mut self, sg: &mut ScatterList) {
        for seg in sg.segments_mut() {
            if seg.iova != 0 {
                let _ = self.unmap_single(seg.iova);
                seg.iova = 0;
            }
        }
    }

    /// Return the domain identifier.
    pub fn id(&self) -> u32 {
        self.id
    }

    /// Return whether the domain is backed by a physical IOMMU.
    pub fn is_iommu_backed(&self) -> bool {
        self.iommu_backed
    }

    /// Return the number of active mappings.
    pub fn mapping_count(&self) -> usize {
        self.mapping_count
    }
}

// ---------------------------------------------------------------------------
// DMA Ops Registry
// ---------------------------------------------------------------------------

/// Registry of DMA domains for all buses in the system.
pub struct DmaOpsRegistry {
    /// Allocated domains.
    domains: [Option<DmaDomain>; MAX_DOMAINS],
    /// Number of allocated domains.
    count: usize,
    /// Next domain ID to assign.
    next_id: u32,
}

impl Default for DmaOpsRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl DmaOpsRegistry {
    /// Create an empty DMA ops registry.
    pub const fn new() -> Self {
        Self {
            domains: [const { None }; MAX_DOMAINS],
            count: 0,
            next_id: 1,
        }
    }

    /// Allocate a new DMA domain.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the registry is full.
    pub fn alloc_domain(&mut self, iommu_backed: bool) -> Result<u32> {
        if self.count >= MAX_DOMAINS {
            return Err(Error::OutOfMemory);
        }
        let id = self.next_id;
        self.next_id += 1;
        let idx = self.count;
        self.domains[idx] = Some(DmaDomain::new(id, iommu_backed));
        self.count += 1;
        Ok(id)
    }

    /// Retrieve a mutable reference to a domain by ID.
    pub fn get_mut(&mut self, id: u32) -> Option<&mut DmaDomain> {
        self.domains[..self.count]
            .iter_mut()
            .filter_map(|d| d.as_mut())
            .find(|d| d.id() == id)
    }

    /// Return the number of allocated domains.
    pub fn count(&self) -> usize {
        self.count
    }
}
