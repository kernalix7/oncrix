// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Software I/O TLB (SWIOTLB) bounce buffer pool.
//!
//! On systems where DMA-capable devices cannot address all of physical memory
//! (e.g., 32-bit DMA masks on a machine with >4 GB RAM), the SWIOTLB provides
//! a pool of bounce buffers located in DMA-addressable memory. Inbound DMA
//! is copied from the bounce buffer into the real destination; outbound DMA
//! is copied from the real source into the bounce buffer before transfer.
//!
//! # Architecture
//!
//! - [`SwiotlbSlot`] — a single fixed-size bounce buffer slot with tracking state.
//! - [`SwiotlbPool`] — the global pool managing a contiguous DMA-capable slab.
//!
//! # Slot lifecycle
//!
//! 1. `alloc_slot(size)` — finds a free slot large enough, marks it busy.
//! 2. `sync_for_device(slot_idx, src)` — copies real-memory data into the bounce buf.
//! 3. Device performs DMA using the slot's `dma_addr`.
//! 4. `sync_for_cpu(slot_idx, dst)` — copies bounce buf data back to real memory.
//! 5. `free_slot(slot_idx)` — returns the slot to the free pool.
//!
//! Reference: Linux `kernel/dma/swiotlb.c`.

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum number of bounce buffer slots in the pool.
pub const MAX_SWIOTLB_SLOTS: usize = 64;

/// Default size of each bounce buffer slot (2 KiB).
pub const DEFAULT_SLOT_SIZE: usize = 2048;

/// Maximum size of a single bounce buffer allocation.
pub const MAX_BOUNCE_SIZE: usize = DEFAULT_SLOT_SIZE;

/// Alignment required for bounce buffer slots (64-byte cache line).
pub const SLOT_ALIGNMENT: usize = 64;

// ---------------------------------------------------------------------------
// SwiotlbSlot
// ---------------------------------------------------------------------------

/// Metadata for a single SWIOTLB bounce buffer slot.
///
/// The actual buffer data lives in the pool's contiguous slab; this struct
/// carries only the tracking information (addresses, size, state).
#[derive(Debug, Clone, Copy)]
pub struct SwiotlbSlot {
    /// Physical address of the bounce buffer (DMA-safe region).
    pub phys_addr: u64,
    /// DMA address seen by the device (may equal `phys_addr` without IOMMU).
    pub dma_addr: u64,
    /// Virtual (CPU) address for copy operations.
    pub virt_addr: usize,
    /// Capacity of this slot in bytes.
    pub capacity: usize,
    /// Actual size of the current allocation (≤ capacity).
    pub alloc_size: usize,
    /// Whether this slot is currently in use.
    pub in_use: bool,
}

impl SwiotlbSlot {
    /// Creates an empty, free slot.
    pub const fn new() -> Self {
        Self {
            phys_addr: 0,
            dma_addr: 0,
            virt_addr: 0,
            capacity: 0,
            alloc_size: 0,
            in_use: false,
        }
    }

    /// Initialises a slot for a given position in the pool slab.
    ///
    /// `slot_index` is used to compute the offset within the slab.
    pub fn init(&mut self, phys_base: u64, virt_base: usize, slot_index: usize, slot_size: usize) {
        let offset = slot_index * slot_size;
        self.phys_addr = phys_base + offset as u64;
        self.dma_addr = self.phys_addr; // Identity mapping without IOMMU.
        self.virt_addr = virt_base + offset;
        self.capacity = slot_size;
        self.alloc_size = 0;
        self.in_use = false;
    }

    /// Returns `true` if this slot can satisfy an allocation of `size` bytes.
    pub fn can_fit(&self, size: usize) -> bool {
        !self.in_use && size <= self.capacity && size > 0
    }
}

impl Default for SwiotlbSlot {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// SwiotlbStats
// ---------------------------------------------------------------------------

/// Diagnostic counters for the SWIOTLB pool.
#[derive(Debug, Default, Clone, Copy)]
pub struct SwiotlbStats {
    /// Number of successful slot allocations.
    pub allocs: u64,
    /// Number of slot frees.
    pub frees: u64,
    /// Number of allocation failures (no free slot large enough).
    pub alloc_failures: u64,
    /// Bytes copied into bounce buffers (sync_for_device).
    pub bytes_to_device: u64,
    /// Bytes copied from bounce buffers (sync_for_cpu).
    pub bytes_from_device: u64,
}

impl SwiotlbStats {
    /// Creates a zeroed stats struct.
    pub const fn new() -> Self {
        Self {
            allocs: 0,
            frees: 0,
            alloc_failures: 0,
            bytes_to_device: 0,
            bytes_from_device: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// SwiotlbPool
// ---------------------------------------------------------------------------

/// The global SWIOTLB bounce buffer pool.
///
/// Manages a fixed array of [`SwiotlbSlot`]s backed by a contiguous
/// DMA-addressable memory slab provided at initialization time.
pub struct SwiotlbPool {
    /// Slot metadata array.
    slots: [SwiotlbSlot; MAX_SWIOTLB_SLOTS],
    /// Physical base address of the slab.
    phys_base: u64,
    /// Virtual base address of the slab (for CPU access).
    virt_base: usize,
    /// Size of each slot in bytes.
    slot_size: usize,
    /// Total number of configured slots.
    num_slots: usize,
    /// Whether the pool has been initialized.
    initialized: bool,
    /// Diagnostic counters.
    stats: SwiotlbStats,
}

impl SwiotlbPool {
    /// Creates an uninitialized pool.
    pub const fn new() -> Self {
        Self {
            slots: [const { SwiotlbSlot::new() }; MAX_SWIOTLB_SLOTS],
            phys_base: 0,
            virt_base: 0,
            slot_size: DEFAULT_SLOT_SIZE,
            num_slots: 0,
            initialized: false,
            stats: SwiotlbStats::new(),
        }
    }

    /// Initializes the pool from a contiguous DMA-addressable slab.
    ///
    /// # Arguments
    ///
    /// - `phys_base` — Physical address of the slab (must be DMA-addressable).
    /// - `virt_base` — Virtual address of the slab (for CPU copy operations).
    /// - `num_slots` — Number of slots to configure (≤ `MAX_SWIOTLB_SLOTS`).
    /// - `slot_size` — Size of each slot in bytes (≤ `MAX_BOUNCE_SIZE`).
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] for out-of-range parameters.
    pub fn init(
        &mut self,
        phys_base: u64,
        virt_base: usize,
        num_slots: usize,
        slot_size: usize,
    ) -> Result<()> {
        if num_slots == 0 || num_slots > MAX_SWIOTLB_SLOTS {
            return Err(Error::InvalidArgument);
        }
        if slot_size == 0 || slot_size > MAX_BOUNCE_SIZE {
            return Err(Error::InvalidArgument);
        }
        if virt_base == 0 || phys_base == 0 {
            return Err(Error::InvalidArgument);
        }
        self.phys_base = phys_base;
        self.virt_base = virt_base;
        self.slot_size = slot_size;
        self.num_slots = num_slots;
        for i in 0..num_slots {
            self.slots[i].init(phys_base, virt_base, i, slot_size);
        }
        self.initialized = true;
        Ok(())
    }

    /// Allocates a bounce buffer slot for a transfer of `size` bytes.
    ///
    /// Returns the slot index.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidArgument`] if pool not initialized or `size` is zero.
    /// - [`Error::OutOfMemory`] if no slot is free and large enough.
    pub fn alloc_slot(&mut self, size: usize) -> Result<usize> {
        if !self.initialized {
            return Err(Error::InvalidArgument);
        }
        if size == 0 || size > self.slot_size {
            return Err(Error::InvalidArgument);
        }
        let idx = (0..self.num_slots)
            .find(|&i| self.slots[i].can_fit(size))
            .ok_or_else(|| {
                self.stats.alloc_failures += 1;
                Error::OutOfMemory
            })?;
        self.slots[idx].in_use = true;
        self.slots[idx].alloc_size = size;
        self.stats.allocs += 1;
        Ok(idx)
    }

    /// Frees a previously allocated slot.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `slot_idx` is out of range or
    /// the slot is not currently in use.
    pub fn free_slot(&mut self, slot_idx: usize) -> Result<()> {
        if slot_idx >= self.num_slots {
            return Err(Error::InvalidArgument);
        }
        if !self.slots[slot_idx].in_use {
            return Err(Error::InvalidArgument);
        }
        self.slots[slot_idx].in_use = false;
        self.slots[slot_idx].alloc_size = 0;
        self.stats.frees += 1;
        Ok(())
    }

    /// Returns the DMA address of a slot.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `slot_idx` is out of range or
    /// the slot is not in use.
    pub fn dma_addr(&self, slot_idx: usize) -> Result<u64> {
        if slot_idx >= self.num_slots || !self.slots[slot_idx].in_use {
            return Err(Error::InvalidArgument);
        }
        Ok(self.slots[slot_idx].dma_addr)
    }

    /// Copies `size` bytes from `src` into the bounce buffer (sync for device).
    ///
    /// Call this before a device-write (outbound) DMA transfer so the device
    /// sees the correct data in the bounce buffer.
    ///
    /// # Safety
    ///
    /// `src` must be a valid pointer to at least `size` readable bytes.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if parameters are invalid.
    pub fn sync_for_device(&mut self, slot_idx: usize, src: *const u8, size: usize) -> Result<()> {
        if slot_idx >= self.num_slots || !self.slots[slot_idx].in_use {
            return Err(Error::InvalidArgument);
        }
        if size == 0 || size > self.slots[slot_idx].capacity {
            return Err(Error::InvalidArgument);
        }
        if src.is_null() {
            return Err(Error::InvalidArgument);
        }
        let dst_virt = self.slots[slot_idx].virt_addr as *mut u8;
        // SAFETY: `dst_virt` is within the initialized SWIOTLB slab (valid for `size` bytes).
        // `src` validity is the caller's responsibility per the safety contract above.
        unsafe {
            core::ptr::copy_nonoverlapping(src, dst_virt, size);
        }
        self.stats.bytes_to_device += size as u64;
        Ok(())
    }

    /// Copies `size` bytes from the bounce buffer into `dst` (sync for CPU).
    ///
    /// Call this after a device-read (inbound) DMA transfer so the CPU sees
    /// the data the device wrote into the bounce buffer.
    ///
    /// # Safety
    ///
    /// `dst` must be a valid pointer to at least `size` writable bytes.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if parameters are invalid.
    pub fn sync_for_cpu(&mut self, slot_idx: usize, dst: *mut u8, size: usize) -> Result<()> {
        if slot_idx >= self.num_slots || !self.slots[slot_idx].in_use {
            return Err(Error::InvalidArgument);
        }
        if size == 0 || size > self.slots[slot_idx].capacity {
            return Err(Error::InvalidArgument);
        }
        if dst.is_null() {
            return Err(Error::InvalidArgument);
        }
        let src_virt = self.slots[slot_idx].virt_addr as *const u8;
        // SAFETY: `src_virt` is within the initialized SWIOTLB slab (valid for `size` bytes).
        // `dst` validity is the caller's responsibility per the safety contract above.
        unsafe {
            core::ptr::copy_nonoverlapping(src_virt, dst, size);
        }
        self.stats.bytes_from_device += size as u64;
        Ok(())
    }

    /// Returns the current diagnostic statistics snapshot.
    pub fn stats(&self) -> SwiotlbStats {
        self.stats
    }

    /// Returns the number of free (not in-use) slots.
    pub fn free_slot_count(&self) -> usize {
        (0..self.num_slots)
            .filter(|&i| !self.slots[i].in_use)
            .count()
    }

    /// Returns the total number of configured slots.
    pub fn total_slots(&self) -> usize {
        self.num_slots
    }

    /// Returns `true` if the pool has been initialized.
    pub fn is_initialized(&self) -> bool {
        self.initialized
    }

    /// Returns a reference to a slot's metadata.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `slot_idx` is out of range.
    pub fn slot_info(&self, slot_idx: usize) -> Result<&SwiotlbSlot> {
        if slot_idx >= self.num_slots {
            return Err(Error::InvalidArgument);
        }
        Ok(&self.slots[slot_idx])
    }
}

impl Default for SwiotlbPool {
    fn default() -> Self {
        Self::new()
    }
}
