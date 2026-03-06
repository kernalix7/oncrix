// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! DMA coherent buffer allocation and mapping.
//!
//! Provides coherent (non-cacheable) DMA buffer management for
//! device drivers that need CPU-accessible buffers visible to
//! DMA-capable hardware without explicit cache maintenance. This
//! is the standard allocation path for descriptor rings, command
//! queues, and small data buffers shared between CPU and devices.
//!
//! # Architecture
//!
//! - [`DmaCoherentPool`] — pre-allocated pool of coherent pages
//! - [`CoherentBuffer`] — handle to an allocated coherent region
//! - [`DmaMapping`] — a single CPU↔device address mapping
//! - [`DmaDirection`] — transfer direction for streaming mappings
//!
//! # Usage
//!
//! ```ignore
//! let mut pool = DmaCoherentPool::new();
//! pool.init(base_phys, base_virt, pool_size)?;
//! let buf = pool.alloc_coherent(4096, 4096)?;
//! // ... use buf.virt_addr() for CPU access ...
//! // ... pass buf.phys_addr() to device ...
//! pool.free_coherent(buf)?;
//! ```
//!
//! Reference: Linux `dma-mapping.h`, Intel VT-d specification.

use oncrix_lib::{Error, Result};

// ── Constants ───────────────────────────────────────────────────

/// Default page size for coherent allocations.
const PAGE_SIZE: usize = 4096;

/// Maximum number of concurrent coherent buffer allocations.
const MAX_COHERENT_BUFFERS: usize = 256;

/// Maximum number of streaming DMA mappings.
const MAX_STREAMING_MAPPINGS: usize = 512;

/// Maximum coherent pools in the system.
const MAX_POOLS: usize = 4;

/// Alignment mask for page-aligned addresses.
const PAGE_MASK: u64 = !(PAGE_SIZE as u64 - 1);

// ── DMA Direction ───────────────────────────────────────────────

/// Direction of a DMA transfer for streaming mappings.
///
/// Determines cache maintenance operations needed to ensure
/// coherence between CPU and device views of memory.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DmaDirection {
    /// Bidirectional — both CPU and device may read/write.
    #[default]
    Bidirectional,
    /// Host to device (CPU writes, device reads).
    ToDevice,
    /// Device to host (device writes, CPU reads).
    FromDevice,
    /// No data transfer direction specified.
    None,
}

// ── Buffer State ────────────────────────────────────────────────

/// State of a coherent buffer allocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum BufferState {
    /// Buffer slot is free.
    #[default]
    Free,
    /// Buffer is allocated and in use.
    Allocated,
    /// Buffer is mapped for device DMA.
    Mapped,
}

// ── Coherent Buffer ─────────────────────────────────────────────

/// A coherent DMA buffer allocation.
///
/// Represents a contiguous region of memory that is accessible
/// by both the CPU (via `virt_addr`) and a DMA-capable device
/// (via `phys_addr`) without explicit cache flushes.
#[derive(Debug, Clone, Copy)]
pub struct CoherentBuffer {
    /// CPU virtual address of the buffer.
    virt_addr: u64,
    /// Device-visible physical address.
    phys_addr: u64,
    /// Size of the allocation in bytes.
    size: usize,
    /// Alignment of the allocation.
    alignment: usize,
    /// Current state.
    state: BufferState,
    /// Pool index this buffer was allocated from.
    pool_index: u8,
    /// Allocation handle (index in the pool's buffer table).
    handle: u16,
}

impl CoherentBuffer {
    /// Create an empty buffer descriptor.
    const fn empty() -> Self {
        Self {
            virt_addr: 0,
            phys_addr: 0,
            size: 0,
            alignment: 0,
            state: BufferState::Free,
            pool_index: 0,
            handle: 0,
        }
    }

    /// Return the CPU virtual address.
    pub fn virt_addr(&self) -> u64 {
        self.virt_addr
    }

    /// Return the device-visible physical address.
    pub fn phys_addr(&self) -> u64 {
        self.phys_addr
    }

    /// Return the buffer size in bytes.
    pub fn size(&self) -> usize {
        self.size
    }

    /// Return the alignment.
    pub fn alignment(&self) -> usize {
        self.alignment
    }

    /// Return the current state.
    pub fn state(&self) -> BufferState {
        self.state
    }

    /// Return the allocation handle.
    pub fn handle(&self) -> u16 {
        self.handle
    }

    /// Return whether the buffer is currently allocated.
    pub fn is_allocated(&self) -> bool {
        self.state != BufferState::Free
    }
}

// ── DMA Mapping ─────────────────────────────────────────────────

/// A streaming DMA mapping for a single buffer region.
///
/// Unlike coherent allocations, streaming mappings are established
/// for existing buffers and require explicit sync operations before
/// and after device access.
#[derive(Debug, Clone, Copy)]
pub struct DmaMapping {
    /// CPU virtual address of the mapped region.
    virt_addr: u64,
    /// Device-visible (bus) address.
    bus_addr: u64,
    /// Size of the mapped region.
    size: usize,
    /// Direction of the mapping.
    direction: DmaDirection,
    /// Whether this mapping is currently active.
    active: bool,
    /// Mapping handle.
    handle: u16,
}

impl DmaMapping {
    /// Create an empty mapping descriptor.
    const fn empty() -> Self {
        Self {
            virt_addr: 0,
            bus_addr: 0,
            size: 0,
            direction: DmaDirection::None,
            active: false,
            handle: 0,
        }
    }

    /// Return the CPU virtual address.
    pub fn virt_addr(&self) -> u64 {
        self.virt_addr
    }

    /// Return the device bus address.
    pub fn bus_addr(&self) -> u64 {
        self.bus_addr
    }

    /// Return the mapping size.
    pub fn size(&self) -> usize {
        self.size
    }

    /// Return the DMA direction.
    pub fn direction(&self) -> DmaDirection {
        self.direction
    }

    /// Return whether the mapping is active.
    pub fn is_active(&self) -> bool {
        self.active
    }
}

// ── Pool Region ─────────────────────────────────────────────────

/// Tracks a contiguous region of coherent memory in the pool.
#[derive(Debug, Clone, Copy)]
struct PoolRegion {
    /// Physical base address of the region.
    phys_base: u64,
    /// Virtual base address of the region.
    virt_base: u64,
    /// Total size of the region in bytes.
    total_size: usize,
    /// Bitmap tracking allocated pages (1 bit per page).
    /// Supports up to 64 pages (256 KiB with 4K pages).
    alloc_bitmap: u64,
    /// Number of pages in this region.
    page_count: usize,
}

impl PoolRegion {
    /// Create an uninitialised pool region.
    const fn empty() -> Self {
        Self {
            phys_base: 0,
            virt_base: 0,
            total_size: 0,
            alloc_bitmap: 0,
            page_count: 0,
        }
    }

    /// Find N contiguous free pages starting from the bitmap.
    ///
    /// Returns the starting page index, or `None` if no space.
    fn find_free_pages(&self, count: usize) -> Option<usize> {
        if count == 0 || count > self.page_count {
            return None;
        }

        let mut start = 0usize;
        while start + count <= self.page_count {
            let mut found = true;
            for offset in 0..count {
                if self.alloc_bitmap & (1u64 << (start + offset)) != 0 {
                    start = start + offset + 1;
                    found = false;
                    break;
                }
            }
            if found {
                return Some(start);
            }
        }
        None
    }

    /// Mark pages as allocated in the bitmap.
    fn mark_allocated(&mut self, start: usize, count: usize) {
        for i in 0..count {
            self.alloc_bitmap |= 1u64 << (start + i);
        }
    }

    /// Mark pages as free in the bitmap.
    fn mark_free(&mut self, start: usize, count: usize) {
        for i in 0..count {
            self.alloc_bitmap &= !(1u64 << (start + i));
        }
    }
}

// ── DMA Coherent Pool ───────────────────────────────────────────

/// Coherent DMA buffer allocator.
///
/// Manages a pool of physically-contiguous, non-cacheable memory
/// that is accessible to both the CPU and DMA-capable devices.
/// Allocations are page-granularity.
pub struct DmaCoherentPool {
    /// Pool memory regions.
    regions: [PoolRegion; MAX_POOLS],
    /// Number of active regions.
    region_count: usize,
    /// Allocated buffer descriptors.
    buffers: [CoherentBuffer; MAX_COHERENT_BUFFERS],
    /// Number of allocated buffers.
    buffer_count: usize,
    /// Streaming DMA mappings.
    mappings: [DmaMapping; MAX_STREAMING_MAPPINGS],
    /// Number of active mappings.
    mapping_count: usize,
    /// Next allocation handle.
    next_handle: u16,
    /// Whether the pool has been initialised.
    initialised: bool,
}

impl DmaCoherentPool {
    /// Create an uninitialised coherent pool.
    pub const fn new() -> Self {
        Self {
            regions: [const { PoolRegion::empty() }; MAX_POOLS],
            region_count: 0,
            buffers: [const { CoherentBuffer::empty() }; MAX_COHERENT_BUFFERS],
            buffer_count: 0,
            mappings: [const { DmaMapping::empty() }; MAX_STREAMING_MAPPINGS],
            mapping_count: 0,
            next_handle: 1,
            initialised: false,
        }
    }

    /// Initialise the pool with a coherent memory region.
    ///
    /// The region at `phys_base` / `virt_base` of `size` bytes
    /// must be mapped as non-cacheable (write-combining or
    /// uncacheable) for coherent operation.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if parameters are invalid.
    /// Returns [`Error::OutOfMemory`] if the maximum number of
    /// regions has been reached.
    pub fn init(&mut self, phys_base: u64, virt_base: u64, size: usize) -> Result<()> {
        if phys_base == 0 || virt_base == 0 || size == 0 {
            return Err(Error::InvalidArgument);
        }

        if phys_base & !PAGE_MASK != 0 || virt_base & !PAGE_MASK != 0 {
            return Err(Error::InvalidArgument);
        }

        if self.region_count >= MAX_POOLS {
            return Err(Error::OutOfMemory);
        }

        let page_count = size / PAGE_SIZE;
        if page_count == 0 || page_count > 64 {
            return Err(Error::InvalidArgument);
        }

        self.regions[self.region_count] = PoolRegion {
            phys_base,
            virt_base,
            total_size: size,
            alloc_bitmap: 0,
            page_count,
        };
        self.region_count += 1;
        self.initialised = true;

        Ok(())
    }

    /// Allocate a coherent DMA buffer.
    ///
    /// Returns a [`CoherentBuffer`] with both physical and virtual
    /// addresses. The buffer is zero-initialised.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `size` is zero.
    /// Returns [`Error::OutOfMemory`] if there is insufficient
    /// contiguous space in the pool.
    pub fn alloc_coherent(&mut self, size: usize, alignment: usize) -> Result<CoherentBuffer> {
        if size == 0 {
            return Err(Error::InvalidArgument);
        }

        if self.buffer_count >= MAX_COHERENT_BUFFERS {
            return Err(Error::OutOfMemory);
        }

        let pages_needed = (size + PAGE_SIZE - 1) / PAGE_SIZE;
        let align = if alignment < PAGE_SIZE {
            PAGE_SIZE
        } else {
            alignment
        };

        // Search regions for contiguous free pages.
        for region_idx in 0..self.region_count {
            let region = &self.regions[region_idx];
            if let Some(start_page) = region.find_free_pages(pages_needed) {
                let phys = region.phys_base + (start_page * PAGE_SIZE) as u64;
                let virt = region.virt_base + (start_page * PAGE_SIZE) as u64;

                // Check alignment.
                if phys % align as u64 != 0 {
                    continue;
                }

                // Mark pages as allocated.
                self.regions[region_idx].mark_allocated(start_page, pages_needed);

                let handle = self.next_handle;
                self.next_handle = self.next_handle.wrapping_add(1);

                let buf = CoherentBuffer {
                    virt_addr: virt,
                    phys_addr: phys,
                    size: pages_needed * PAGE_SIZE,
                    alignment: align,
                    state: BufferState::Allocated,
                    pool_index: region_idx as u8,
                    handle,
                };

                self.buffers[self.buffer_count] = buf;
                self.buffer_count += 1;

                // Zero-initialise the buffer via volatile writes.
                // SAFETY: The virtual address range is valid and
                // mapped to our coherent pool. We write zeros to
                // ensure the buffer starts in a known state.
                unsafe {
                    let ptr = virt as *mut u8;
                    let total_bytes = pages_needed * PAGE_SIZE;
                    for offset in 0..total_bytes {
                        core::ptr::write_volatile(ptr.add(offset), 0);
                    }
                }

                return Ok(buf);
            }
        }

        Err(Error::OutOfMemory)
    }

    /// Free a previously allocated coherent buffer.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the buffer handle is not
    /// recognised.
    pub fn free_coherent(&mut self, buffer: CoherentBuffer) -> Result<()> {
        // Find the buffer in our table.
        let mut found_idx = None;
        for i in 0..self.buffer_count {
            if self.buffers[i].handle == buffer.handle && self.buffers[i].state != BufferState::Free
            {
                found_idx = Some(i);
                break;
            }
        }

        let idx = found_idx.ok_or(Error::NotFound)?;
        let buf = &self.buffers[idx];
        let region_idx = buf.pool_index as usize;

        if region_idx >= self.region_count {
            return Err(Error::InvalidArgument);
        }

        let region = &self.regions[region_idx];
        let offset = buf.phys_addr.saturating_sub(region.phys_base) as usize;
        let start_page = offset / PAGE_SIZE;
        let pages = buf.size / PAGE_SIZE;

        self.regions[region_idx].mark_free(start_page, pages);

        // Remove from buffer table by swapping with last entry.
        self.buffers[idx] = self.buffers[self.buffer_count - 1];
        self.buffers[self.buffer_count - 1] = CoherentBuffer::empty();
        self.buffer_count -= 1;

        Ok(())
    }

    /// Create a streaming DMA mapping for an existing buffer.
    ///
    /// The buffer at `virt_addr` with `size` bytes is made
    /// accessible to a device at the returned bus address. For
    /// identity-mapped systems, bus_addr equals phys_addr.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if parameters are invalid.
    /// Returns [`Error::OutOfMemory`] if the mapping table is full.
    pub fn map_single(
        &mut self,
        virt_addr: u64,
        phys_addr: u64,
        size: usize,
        direction: DmaDirection,
    ) -> Result<DmaMapping> {
        if virt_addr == 0 || phys_addr == 0 || size == 0 {
            return Err(Error::InvalidArgument);
        }

        if self.mapping_count >= MAX_STREAMING_MAPPINGS {
            return Err(Error::OutOfMemory);
        }

        let handle = self.next_handle;
        self.next_handle = self.next_handle.wrapping_add(1);

        let mapping = DmaMapping {
            virt_addr,
            bus_addr: phys_addr,
            size,
            direction,
            active: true,
            handle,
        };

        self.mappings[self.mapping_count] = mapping;
        self.mapping_count += 1;

        Ok(mapping)
    }

    /// Remove a streaming DMA mapping.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the mapping handle is not found.
    pub fn unmap_single(&mut self, mapping: DmaMapping) -> Result<()> {
        let mut found_idx = None;
        for i in 0..self.mapping_count {
            if self.mappings[i].handle == mapping.handle && self.mappings[i].active {
                found_idx = Some(i);
                break;
            }
        }

        let idx = found_idx.ok_or(Error::NotFound)?;

        // Swap-remove.
        self.mappings[idx] = self.mappings[self.mapping_count - 1];
        self.mappings[self.mapping_count - 1] = DmaMapping::empty();
        self.mapping_count -= 1;

        Ok(())
    }

    /// Synchronise a streaming mapping for device access.
    ///
    /// Call before the device accesses the buffer to ensure
    /// CPU writes are visible to the device.
    ///
    /// On x86_64 with coherent memory this is typically a no-op,
    /// but the interface exists for architectures with non-coherent
    /// DMA (e.g., ARM).
    pub fn sync_for_device(&self, mapping: &DmaMapping) -> Result<()> {
        if !mapping.active {
            return Err(Error::InvalidArgument);
        }

        // SAFETY: x86_64 is cache-coherent for DMA. We issue
        // an SFENCE to ensure all preceding stores are globally
        // visible, which is sufficient for device synchronisation.
        #[cfg(target_arch = "x86_64")]
        unsafe {
            core::arch::asm!("sfence", options(nostack, preserves_flags));
        }

        Ok(())
    }

    /// Synchronise a streaming mapping for CPU access.
    ///
    /// Call after the device has written data and before the CPU
    /// reads it, to ensure device writes are visible to the CPU.
    pub fn sync_for_cpu(&self, mapping: &DmaMapping) -> Result<()> {
        if !mapping.active {
            return Err(Error::InvalidArgument);
        }

        // SAFETY: x86_64 is cache-coherent. LFENCE ensures all
        // preceding loads are complete before subsequent reads.
        #[cfg(target_arch = "x86_64")]
        unsafe {
            core::arch::asm!("lfence", options(nostack, preserves_flags));
        }

        Ok(())
    }

    // ── Status queries ──────────────────────────────────────

    /// Return the number of allocated buffers.
    pub fn allocated_buffers(&self) -> usize {
        self.buffer_count
    }

    /// Return the number of active streaming mappings.
    pub fn active_mappings(&self) -> usize {
        self.mapping_count
    }

    /// Return the number of configured regions.
    pub fn region_count(&self) -> usize {
        self.region_count
    }

    /// Return whether the pool has been initialised.
    pub fn is_initialised(&self) -> bool {
        self.initialised
    }

    /// Return the total free pages across all regions.
    pub fn free_pages(&self) -> usize {
        let mut count = 0;
        for i in 0..self.region_count {
            let region = &self.regions[i];
            for page in 0..region.page_count {
                if region.alloc_bitmap & (1u64 << page) == 0 {
                    count += 1;
                }
            }
        }
        count
    }

    /// Return a reference to an allocated buffer by handle.
    pub fn find_buffer(&self, handle: u16) -> Option<&CoherentBuffer> {
        for i in 0..self.buffer_count {
            if self.buffers[i].handle == handle {
                return Some(&self.buffers[i]);
            }
        }
        None
    }
}

impl Default for DmaCoherentPool {
    fn default() -> Self {
        Self::new()
    }
}
