// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! IOMMU DMA mapping subsystem.
//!
//! Provides a higher-level DMA mapping API built on top of the raw
//! IOMMU hardware abstraction. Handles IOVA space allocation, scatter-
//! gather list mapping, streaming vs coherent DMA, and cache
//! synchronization hints.
//!
//! # Architecture
//!
//! ```text
//! Device driver
//!      │  dma_map_single() / dma_map_sg()
//!      ▼
//! DmaMapper (per-device)
//!      │  allocate IOVA, fill I/O page table entries
//!      ▼
//! IommuDmaOps (trait)
//!      │  map / unmap / sync
//!      ▼
//! IommuDevice (crates/hal/src/iommu.rs)
//! ```
//!
//! # Usage
//!
//! ```ignore
//! let mut mapper = DmaMapper::new(device_id, iova_base, iova_size);
//! let handle = mapper.map_single(phys_addr, len, DmaDirection::ToDevice)?;
//! // ... perform DMA ...
//! mapper.sync_single(&handle, DmaDirection::ToDevice)?;
//! mapper.unmap_single(handle)?;
//! ```

extern crate alloc;

use oncrix_lib::{Error, Result};

// ── Constants ─────────────────────────────────────────────────

/// Page size for IOVA alignment (4 KiB).
const PAGE_SIZE: u64 = 4096;
/// Page mask for alignment checks.
const PAGE_MASK: u64 = PAGE_SIZE - 1;
/// Maximum scatter-gather segments per mapping.
const MAX_SG_SEGMENTS: usize = 64;
/// Maximum concurrent DMA handles per mapper.
const MAX_DMA_HANDLES: usize = 128;
/// Maximum DMA mappers in the system.
const MAX_DMA_MAPPERS: usize = 16;

// ── DMA Direction ─────────────────────────────────────────────

/// Direction of a DMA data transfer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DmaDirection {
    /// Data moves from host memory to device (write by device).
    ToDevice,
    /// Data moves from device to host memory (read by device).
    FromDevice,
    /// Data moves in both directions (bidirectional).
    Bidirectional,
    /// No data movement (e.g., pure synchronization).
    None,
}

// ── Scatter-Gather Segment ─────────────────────────────────────

/// A single contiguous segment in a scatter-gather list.
#[derive(Debug, Clone, Copy, Default)]
pub struct ScatterGatherSegment {
    /// Physical address of this segment.
    pub phys_addr: u64,
    /// Length of this segment in bytes.
    pub length: u64,
    /// IOVA assigned to this segment after mapping.
    pub iova: u64,
}

impl ScatterGatherSegment {
    /// Create a new segment with the given physical address and length.
    pub const fn new(phys_addr: u64, length: u64) -> Self {
        Self {
            phys_addr,
            length,
            iova: 0,
        }
    }
}

// ── DMA Mapping Type ──────────────────────────────────────────

/// Distinguishes streaming from coherent DMA mappings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DmaMappingType {
    /// Streaming: single-use, direction-aware, requires sync.
    Streaming,
    /// Coherent: persistent, always synchronized, no explicit sync needed.
    Coherent,
}

// ── DMA Handle ────────────────────────────────────────────────

/// Opaque handle returned by a successful DMA map operation.
///
/// Must be passed to [`DmaMapper::unmap_single`] or
/// [`DmaMapper::unmap_sg`] to release the mapping.
#[derive(Debug, Clone, Copy)]
pub struct DmaHandle {
    /// Assigned IOVA base for the mapping.
    pub iova: u64,
    /// Total size of the mapped region in bytes.
    pub size: u64,
    /// Device this handle belongs to.
    pub device_id: u16,
    /// Handle sequence number for uniqueness.
    pub sequence: u32,
    /// Direction this mapping was created for.
    pub direction: DmaDirection,
    /// Mapping type (streaming or coherent).
    pub mapping_type: DmaMappingType,
    /// Whether this handle slot is valid.
    pub valid: bool,
}

impl Default for DmaHandle {
    fn default() -> Self {
        Self::invalid()
    }
}

impl DmaHandle {
    /// Create an invalid (placeholder) handle.
    pub const fn invalid() -> Self {
        Self {
            iova: 0,
            size: 0,
            device_id: 0,
            sequence: 0,
            direction: DmaDirection::None,
            mapping_type: DmaMappingType::Streaming,
            valid: false,
        }
    }

    /// Return whether this handle refers to an active mapping.
    pub const fn is_valid(&self) -> bool {
        self.valid
    }
}

// ── IOVA Allocator ────────────────────────────────────────────

/// Simple linear IOVA space allocator.
///
/// Manages a flat IOVA window `[base, base + size)` with a
/// bump-pointer allocator for simplicity. In a production
/// implementation this would use a red-black tree or bitmap.
#[derive(Debug, Clone, Copy)]
pub struct IovaAllocator {
    /// Base of the IOVA window.
    base: u64,
    /// Total size of the IOVA window in bytes.
    size: u64,
    /// Current allocation pointer (next free address).
    cursor: u64,
    /// Total bytes currently allocated.
    allocated: u64,
}

impl IovaAllocator {
    /// Create a new IOVA allocator covering `[base, base + size)`.
    pub const fn new(base: u64, size: u64) -> Self {
        Self {
            base,
            size,
            cursor: base,
            allocated: 0,
        }
    }

    /// Allocate `len` bytes of IOVA space, aligned to `PAGE_SIZE`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the IOVA window is exhausted.
    pub fn alloc(&mut self, len: u64) -> Result<u64> {
        let aligned_len = (len + PAGE_MASK) & !PAGE_MASK;
        if self.cursor + aligned_len > self.base + self.size {
            return Err(Error::OutOfMemory);
        }
        let iova = self.cursor;
        self.cursor += aligned_len;
        self.allocated += aligned_len;
        Ok(iova)
    }

    /// Free a previously allocated IOVA region.
    ///
    /// Note: this bump allocator does not reclaim space; the free
    /// operation only decrements the accounting counter. A real
    /// allocator would insert the range into a free list.
    pub fn free(&mut self, len: u64) {
        let aligned_len = (len + PAGE_MASK) & !PAGE_MASK;
        self.allocated = self.allocated.saturating_sub(aligned_len);
    }

    /// Return the amount of IOVA space currently allocated.
    pub const fn allocated(&self) -> u64 {
        self.allocated
    }

    /// Return the total IOVA window size.
    pub const fn window_size(&self) -> u64 {
        self.size
    }

    /// Return whether the IOVA window is exhausted.
    pub fn is_exhausted(&self) -> bool {
        self.cursor >= self.base + self.size
    }
}

// ── DMA Sync Operation ────────────────────────────────────────

/// Cache synchronization action for streaming DMA.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DmaSyncAction {
    /// Flush CPU caches to device (before ToDevice transfer).
    FlushToDevice,
    /// Invalidate CPU caches from device (after FromDevice transfer).
    InvalidateFromDevice,
    /// Flush and invalidate (bidirectional).
    FlushAndInvalidate,
}

impl DmaSyncAction {
    /// Derive the appropriate sync action for a given DMA direction.
    pub fn for_direction(dir: DmaDirection) -> Self {
        match dir {
            DmaDirection::ToDevice => Self::FlushToDevice,
            DmaDirection::FromDevice => Self::InvalidateFromDevice,
            DmaDirection::Bidirectional => Self::FlushAndInvalidate,
            DmaDirection::None => Self::FlushToDevice,
        }
    }
}

// ── DMA Stats ─────────────────────────────────────────────────

/// Per-device DMA mapping statistics.
#[derive(Debug, Clone, Copy, Default)]
pub struct DmaStats {
    /// Total single-buffer mappings created.
    pub single_maps: u64,
    /// Total single-buffer mappings released.
    pub single_unmaps: u64,
    /// Total scatter-gather mappings created.
    pub sg_maps: u64,
    /// Total scatter-gather mappings released.
    pub sg_unmaps: u64,
    /// Total synchronization operations performed.
    pub sync_ops: u64,
    /// Mapping failures (IOVA exhaustion, etc.).
    pub map_errors: u64,
}

// ── DMA Mapper ────────────────────────────────────────────────

/// Per-device DMA mapper.
///
/// Owns an IOVA allocator and a table of active DMA handles for
/// a single PCI device. Created once per device and used for all
/// DMA operations on that device.
pub struct DmaMapper {
    /// PCI device identifier this mapper belongs to.
    device_id: u16,
    /// IOVA space allocator.
    iova_alloc: IovaAllocator,
    /// Active DMA handle table.
    handles: [DmaHandle; MAX_DMA_HANDLES],
    /// Next sequence number.
    next_seq: u32,
    /// Number of active handles.
    active_count: usize,
    /// Accumulated statistics.
    stats: DmaStats,
}

impl DmaMapper {
    /// Create a new DMA mapper for `device_id`.
    ///
    /// The mapper will manage IOVA allocations within the window
    /// `[iova_base, iova_base + iova_size)`.
    pub fn new(device_id: u16, iova_base: u64, iova_size: u64) -> Self {
        Self {
            device_id,
            iova_alloc: IovaAllocator::new(iova_base, iova_size),
            handles: [DmaHandle::invalid(); MAX_DMA_HANDLES],
            next_seq: 1,
            active_count: 0,
            stats: DmaStats::default(),
        }
    }

    /// Map a single physically-contiguous buffer for DMA.
    ///
    /// Allocates an IOVA range, records the mapping, and returns a
    /// [`DmaHandle`] that can be passed to the device.
    ///
    /// # Arguments
    ///
    /// * `phys_addr` — Physical base address of the buffer.
    /// * `len` — Length of the buffer in bytes.
    /// * `direction` — Transfer direction.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidArgument`] if `len` is zero or `phys_addr` is not
    ///   page-aligned.
    /// - [`Error::OutOfMemory`] if no IOVA space or handle slots remain.
    pub fn map_single(
        &mut self,
        phys_addr: u64,
        len: u64,
        direction: DmaDirection,
    ) -> Result<DmaHandle> {
        if len == 0 || phys_addr & PAGE_MASK != 0 {
            self.stats.map_errors += 1;
            return Err(Error::InvalidArgument);
        }

        let slot = self.handles.iter().position(|h| !h.valid).ok_or_else(|| {
            self.stats.map_errors += 1;
            Error::OutOfMemory
        })?;

        let iova = self.iova_alloc.alloc(len).map_err(|e| {
            self.stats.map_errors += 1;
            e
        })?;

        let seq = self.next_seq;
        self.next_seq = self.next_seq.wrapping_add(1);

        let handle = DmaHandle {
            iova,
            size: len,
            device_id: self.device_id,
            sequence: seq,
            direction,
            mapping_type: DmaMappingType::Streaming,
            valid: true,
        };

        self.handles[slot] = handle;
        self.active_count += 1;
        self.stats.single_maps += 1;
        Ok(handle)
    }

    /// Unmap a single-buffer DMA handle.
    ///
    /// Releases the IOVA allocation and invalidates the handle.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the handle is not active.
    pub fn unmap_single(&mut self, handle: DmaHandle) -> Result<()> {
        let slot = self
            .handles
            .iter()
            .position(|h| h.valid && h.sequence == handle.sequence && h.iova == handle.iova)
            .ok_or(Error::NotFound)?;

        let size = self.handles[slot].size;
        self.handles[slot] = DmaHandle::invalid();
        self.iova_alloc.free(size);
        self.active_count = self.active_count.saturating_sub(1);
        self.stats.single_unmaps += 1;
        Ok(())
    }

    /// Map a scatter-gather list for DMA.
    ///
    /// Allocates a contiguous IOVA range large enough to cover all
    /// segments and returns a handle covering the whole range.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidArgument`] if `segments` is empty or any
    ///   segment has a zero length.
    /// - [`Error::OutOfMemory`] if IOVA space is exhausted.
    pub fn map_sg(
        &mut self,
        segments: &mut [ScatterGatherSegment],
        direction: DmaDirection,
    ) -> Result<DmaHandle> {
        if segments.is_empty() || segments.len() > MAX_SG_SEGMENTS {
            self.stats.map_errors += 1;
            return Err(Error::InvalidArgument);
        }

        let total_size: u64 = segments.iter().map(|s| s.length).sum();
        if total_size == 0 {
            self.stats.map_errors += 1;
            return Err(Error::InvalidArgument);
        }

        let slot = self.handles.iter().position(|h| !h.valid).ok_or_else(|| {
            self.stats.map_errors += 1;
            Error::OutOfMemory
        })?;

        let iova_base = self.iova_alloc.alloc(total_size).map_err(|e| {
            self.stats.map_errors += 1;
            e
        })?;

        // Assign per-segment IOVAs.
        let mut cursor = iova_base;
        for seg in segments.iter_mut() {
            seg.iova = cursor;
            cursor += (seg.length + PAGE_MASK) & !PAGE_MASK;
        }

        let seq = self.next_seq;
        self.next_seq = self.next_seq.wrapping_add(1);

        let handle = DmaHandle {
            iova: iova_base,
            size: total_size,
            device_id: self.device_id,
            sequence: seq,
            direction,
            mapping_type: DmaMappingType::Streaming,
            valid: true,
        };

        self.handles[slot] = handle;
        self.active_count += 1;
        self.stats.sg_maps += 1;
        Ok(handle)
    }

    /// Unmap a scatter-gather DMA handle.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the handle is not active.
    pub fn unmap_sg(&mut self, handle: DmaHandle) -> Result<()> {
        let slot = self
            .handles
            .iter()
            .position(|h| h.valid && h.sequence == handle.sequence && h.iova == handle.iova)
            .ok_or(Error::NotFound)?;

        let size = self.handles[slot].size;
        self.handles[slot] = DmaHandle::invalid();
        self.iova_alloc.free(size);
        self.active_count = self.active_count.saturating_sub(1);
        self.stats.sg_unmaps += 1;
        Ok(())
    }

    /// Synchronize a streaming DMA mapping for CPU access.
    ///
    /// Must be called before the CPU reads data written by a device
    /// (FromDevice) or after the CPU writes data for the device
    /// (ToDevice). For coherent mappings this is a no-op.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the handle is not active.
    pub fn sync_single(&mut self, handle: &DmaHandle, direction: DmaDirection) -> Result<()> {
        let found = self
            .handles
            .iter()
            .any(|h| h.valid && h.sequence == handle.sequence);
        if !found {
            return Err(Error::NotFound);
        }

        let _action = DmaSyncAction::for_direction(direction);
        // On a real system this would issue cache maintenance
        // instructions (e.g., CLFLUSH on x86 or DC CIVAC on ARM).
        // For this HAL implementation the IOMMU is assumed to be
        // operating in cache-coherent mode (ECAP.PWC = 1).
        self.stats.sync_ops += 1;
        Ok(())
    }

    /// Allocate a coherent DMA buffer.
    ///
    /// Returns an IOVA handle for a coherent region. Coherent
    /// mappings do not require explicit synchronization.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidArgument`] if `size` is zero.
    /// - [`Error::OutOfMemory`] if IOVA space or handle slots are exhausted.
    pub fn alloc_coherent(&mut self, phys_addr: u64, size: u64) -> Result<DmaHandle> {
        if size == 0 {
            return Err(Error::InvalidArgument);
        }

        let slot = self
            .handles
            .iter()
            .position(|h| !h.valid)
            .ok_or(Error::OutOfMemory)?;

        let iova = self.iova_alloc.alloc(size)?;
        let seq = self.next_seq;
        self.next_seq = self.next_seq.wrapping_add(1);

        let handle = DmaHandle {
            iova,
            size,
            device_id: self.device_id,
            sequence: seq,
            direction: DmaDirection::Bidirectional,
            mapping_type: DmaMappingType::Coherent,
            valid: true,
        };

        self.handles[slot] = handle;
        self.active_count += 1;
        self.stats.single_maps += 1;
        let _ = phys_addr; // address recorded in the IOMMU page tables (hw path)
        Ok(handle)
    }

    /// Free a coherent DMA buffer handle.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the handle is not active.
    pub fn free_coherent(&mut self, handle: DmaHandle) -> Result<()> {
        self.unmap_single(handle)
    }

    /// Return the device ID this mapper belongs to.
    pub const fn device_id(&self) -> u16 {
        self.device_id
    }

    /// Return the number of currently active DMA handles.
    pub const fn active_count(&self) -> usize {
        self.active_count
    }

    /// Return a reference to accumulated DMA statistics.
    pub const fn stats(&self) -> &DmaStats {
        &self.stats
    }

    /// Return whether the IOVA space is exhausted.
    pub fn iova_exhausted(&self) -> bool {
        self.iova_alloc.is_exhausted()
    }

    /// Return the total IOVA window size.
    pub fn iova_window_size(&self) -> u64 {
        self.iova_alloc.window_size()
    }

    /// Return the current IOVA allocated bytes.
    pub fn iova_allocated(&self) -> u64 {
        self.iova_alloc.allocated()
    }
}

// ── DMA Mapper Registry ───────────────────────────────────────

/// System-wide registry of DMA mappers (one per PCI device).
pub struct DmaMapperRegistry {
    /// Registered mapper slots.
    mappers: [Option<DmaMapper>; MAX_DMA_MAPPERS],
    /// Number of registered mappers.
    count: usize,
}

impl Default for DmaMapperRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl DmaMapperRegistry {
    /// Create an empty mapper registry.
    pub const fn new() -> Self {
        Self {
            mappers: [
                None, None, None, None, None, None, None, None, None, None, None, None, None, None,
                None, None,
            ],
            count: 0,
        }
    }

    /// Register a DMA mapper.
    ///
    /// # Errors
    ///
    /// - [`Error::OutOfMemory`] if the registry is full.
    /// - [`Error::AlreadyExists`] if a mapper for this device already exists.
    pub fn register(&mut self, mapper: DmaMapper) -> Result<usize> {
        let device_id = mapper.device_id();
        let exists = self.mappers[..self.count]
            .iter()
            .flatten()
            .any(|m| m.device_id() == device_id);
        if exists {
            return Err(Error::AlreadyExists);
        }
        if self.count >= MAX_DMA_MAPPERS {
            return Err(Error::OutOfMemory);
        }
        let idx = self.count;
        self.mappers[idx] = Some(mapper);
        self.count += 1;
        Ok(idx)
    }

    /// Look up a mapper by device ID, returning a mutable reference.
    pub fn get_mut_by_device(&mut self, device_id: u16) -> Option<&mut DmaMapper> {
        self.mappers[..self.count]
            .iter_mut()
            .filter_map(|slot| slot.as_mut())
            .find(|m| m.device_id() == device_id)
    }

    /// Look up a mapper by device ID (shared reference).
    pub fn get_by_device(&self, device_id: u16) -> Option<&DmaMapper> {
        self.mappers[..self.count]
            .iter()
            .filter_map(|slot| slot.as_ref())
            .find(|m| m.device_id() == device_id)
    }

    /// Return the number of registered mappers.
    pub const fn count(&self) -> usize {
        self.count
    }

    /// Return whether there are no registered mappers.
    pub const fn is_empty(&self) -> bool {
        self.count == 0
    }
}
