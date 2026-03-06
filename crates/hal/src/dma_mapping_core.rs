// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! DMA mapping core infrastructure.
//!
//! Provides IOVA (I/O Virtual Address) allocation, coherent DMA memory
//! management, streaming DMA mappings, and bounce buffer support for
//! devices that cannot reach all physical memory.
//!
//! # Concepts
//!
//! - **IOVA** — the address a device places on the bus during DMA. With a
//!   plain physical mapping it equals the physical address; with an IOMMU
//!   the IOMMU translates the IOVA to a physical address.
//! - **Coherent DMA** — CPU and device share a view of the buffer with no
//!   explicit cache management (typically uncached or write-combining memory).
//! - **Streaming DMA** — the caller owns the buffer; the DMA subsystem maps
//!   it temporarily and requires explicit `sync_for_device` / `sync_for_cpu`
//!   fence operations.
//! - **Bounce buffer** — an intermediary buffer allocated within a device's
//!   reachable DMA window when the original buffer is outside that window.
//!
//! # Usage
//!
//! ```ignore
//! let mut iova = IovaAllocator::new(0x1000_0000, 0x1_0000_0000);
//! let addr = iova.alloc(4096, 12)?;  // 4 KiB, 4 KiB aligned
//!
//! let mut pool = CoherentPool::new(0x8000_0000, 0, 64);
//! pool.init()?;
//! let region = pool.alloc()?;
//! ```
//!
//! Reference: Linux `Documentation/core-api/dma-api.rst`;
//! Linux `kernel/dma/mapping.c`.

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum IOVA regions tracked by the allocator.
pub const MAX_IOVA_REGIONS: usize = 128;

/// Maximum coherent pool slots.
pub const MAX_COHERENT_SLOTS: usize = 64;

/// Maximum streaming DMA mappings.
pub const MAX_STREAMING_MAPS: usize = 256;

/// Maximum bounce buffers.
pub const MAX_BOUNCE_BUFFERS: usize = 32;

/// Default IOVA alignment (4 KiB page).
pub const DEFAULT_IOVA_ALIGN_SHIFT: u32 = 12;

// ---------------------------------------------------------------------------
// DMA direction
// ---------------------------------------------------------------------------

/// Direction of a DMA transfer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DmaDir {
    /// Device reads from the buffer (host-to-device).
    ToDevice,
    /// Device writes to the buffer (device-to-host).
    FromDevice,
    /// Both directions (read-modify-write).
    Bidirectional,
    /// No data movement (flag / descriptor buffers).
    None,
}

// ---------------------------------------------------------------------------
// IOVA allocator
// ---------------------------------------------------------------------------

/// A single allocated IOVA region record.
#[derive(Debug, Clone, Copy)]
struct IovaRegion {
    /// Start IOVA address.
    start: u64,
    /// Size in bytes (page-rounded).
    size: u64,
    /// Whether this slot is in use.
    active: bool,
}

impl IovaRegion {
    const EMPTY: Self = Self {
        start: 0,
        size: 0,
        active: false,
    };
}

/// Bump-pointer IOVA address space allocator.
///
/// Manages a window of I/O virtual addresses, providing `alloc` / `free`
/// operations. In this implementation free only tracks the slot; a full
/// implementation would coalesce free regions.
pub struct IovaAllocator {
    /// Inclusive start of the IOVA window.
    window_start: u64,
    /// Exclusive end of the IOVA window.
    window_end: u64,
    /// Next IOVA to try (bump pointer).
    cursor: u64,
    /// Allocation records.
    regions: [IovaRegion; MAX_IOVA_REGIONS],
    /// Number of active allocations.
    count: usize,
}

impl IovaAllocator {
    /// Create a new IOVA allocator covering `[start, end)`.
    pub const fn new(start: u64, end: u64) -> Self {
        Self {
            window_start: start,
            window_end: end,
            cursor: start,
            regions: [IovaRegion::EMPTY; MAX_IOVA_REGIONS],
            count: 0,
        }
    }

    /// Allocate an IOVA region of `size` bytes aligned to `2^align_shift`.
    ///
    /// Returns the allocated IOVA base address.
    ///
    /// # Errors
    ///
    /// - `InvalidArgument` if `size == 0` or `align_shift > 30`.
    /// - `OutOfMemory` if the IOVA window is exhausted or the table is full.
    pub fn alloc(&mut self, size: u64, align_shift: u32) -> Result<u64> {
        if size == 0 || align_shift > 30 {
            return Err(Error::InvalidArgument);
        }
        let align = 1u64 << align_shift;
        let aligned_start = (self.cursor + align - 1) & !(align - 1);
        let end = aligned_start.checked_add(size).ok_or(Error::OutOfMemory)?;
        if end > self.window_end {
            return Err(Error::OutOfMemory);
        }
        if self.count >= MAX_IOVA_REGIONS {
            return Err(Error::OutOfMemory);
        }

        // Find a free slot.
        let slot = self
            .regions
            .iter()
            .position(|r| !r.active)
            .ok_or(Error::OutOfMemory)?;

        self.regions[slot] = IovaRegion {
            start: aligned_start,
            size,
            active: true,
        };
        self.cursor = end;
        self.count += 1;
        Ok(aligned_start)
    }

    /// Free a previously allocated IOVA region by its base address.
    ///
    /// Silently ignores addresses not found in the table.
    pub fn free(&mut self, iova: u64) {
        let pos = self
            .regions
            .iter()
            .position(|r| r.active && r.start == iova);
        if let Some(idx) = pos {
            self.regions[idx].active = false;
            if self.count > 0 {
                self.count -= 1;
            }
        }
    }

    /// Return the number of active allocations.
    pub fn active_count(&self) -> usize {
        self.count
    }

    /// Return `true` if the IOVA window has no active allocations.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Return the window bounds `(start, end)`.
    pub fn window(&self) -> (u64, u64) {
        (self.window_start, self.window_end)
    }
}

// ---------------------------------------------------------------------------
// Coherent DMA pool
// ---------------------------------------------------------------------------

/// A single coherent DMA slot.
#[derive(Debug, Clone, Copy)]
pub struct CoherentSlot {
    /// CPU-visible virtual address (identity-mapped in simple model).
    pub virt_addr: u64,
    /// Physical address.
    pub phys_addr: u64,
    /// DMA (IOVA) address seen by the device.
    pub dma_addr: u64,
    /// Slot size in bytes.
    pub size: usize,
    /// Index within the pool.
    pub(crate) index: usize,
}

/// Fixed-stride coherent DMA memory pool.
///
/// All slots are the same size. Suitable for descriptor rings and
/// similar fixed-size DMA structures.
pub struct CoherentPool {
    /// Physical base address.
    phys_base: u64,
    /// DMA offset added to physical addresses.
    dma_offset: i64,
    /// Size of each slot in bytes.
    slot_size: usize,
    /// Allocation bitmap.
    used: [bool; MAX_COHERENT_SLOTS],
    /// Number of occupied slots.
    count: usize,
    /// Whether the pool has been initialized.
    initialized: bool,
}

impl CoherentPool {
    /// Create a new coherent pool.
    ///
    /// `phys_base` — physical start address of the backing memory.
    /// `dma_offset` — signed offset: `dma_addr = phys + dma_offset`.
    /// `slot_size` — bytes per slot.
    pub const fn new(phys_base: u64, dma_offset: i64, slot_size: usize) -> Self {
        Self {
            phys_base,
            dma_offset,
            slot_size,
            used: [false; MAX_COHERENT_SLOTS],
            count: 0,
            initialized: false,
        }
    }

    /// Initialize the pool (must be called before `alloc`).
    pub fn init(&mut self) -> Result<()> {
        if self.slot_size == 0 {
            return Err(Error::InvalidArgument);
        }
        self.initialized = true;
        Ok(())
    }

    /// Allocate one slot from the pool.
    ///
    /// # Errors
    ///
    /// - `IoError` if `init` has not been called.
    /// - `OutOfMemory` if all slots are exhausted.
    pub fn alloc(&mut self) -> Result<CoherentSlot> {
        if !self.initialized {
            return Err(Error::IoError);
        }
        let idx = self
            .used
            .iter()
            .position(|&u| !u)
            .ok_or(Error::OutOfMemory)?;

        self.used[idx] = true;
        self.count += 1;
        let offset = (idx * self.slot_size) as u64;
        let phys = self.phys_base + offset;
        let dma = phys.wrapping_add_signed(self.dma_offset);
        Ok(CoherentSlot {
            virt_addr: phys,
            phys_addr: phys,
            dma_addr: dma,
            size: self.slot_size,
            index: idx,
        })
    }

    /// Free a previously allocated slot.
    pub fn free(&mut self, slot: CoherentSlot) {
        if slot.index < MAX_COHERENT_SLOTS {
            self.used[slot.index] = false;
            if self.count > 0 {
                self.count -= 1;
            }
        }
    }

    /// Return the number of occupied slots.
    pub fn used_count(&self) -> usize {
        self.count
    }

    /// Return `true` if no slots are in use.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
}

// ---------------------------------------------------------------------------
// Streaming DMA map table
// ---------------------------------------------------------------------------

/// An active streaming DMA mapping entry.
#[derive(Debug, Clone, Copy)]
pub struct StreamingMap {
    /// Original physical address.
    pub phys_addr: u64,
    /// DMA address programmed into the device.
    pub dma_addr: u64,
    /// Length in bytes.
    pub size: usize,
    /// Transfer direction.
    pub direction: DmaDir,
    /// Whether this slot is live.
    pub(crate) active: bool,
}

impl StreamingMap {
    const EMPTY: Self = Self {
        phys_addr: 0,
        dma_addr: 0,
        size: 0,
        direction: DmaDir::None,
        active: false,
    };
}

/// Registry of all active streaming DMA mappings.
pub struct StreamingMapTable {
    entries: [StreamingMap; MAX_STREAMING_MAPS],
    count: usize,
    /// Signed offset: `dma_addr = phys + dma_offset`.
    dma_offset: i64,
}

impl StreamingMapTable {
    /// Create an empty table.
    pub const fn new(dma_offset: i64) -> Self {
        Self {
            entries: [StreamingMap::EMPTY; MAX_STREAMING_MAPS],
            count: 0,
            dma_offset,
        }
    }

    /// Map a physical buffer for streaming DMA.
    ///
    /// Returns the DMA address to write into a device descriptor.
    ///
    /// # Errors
    ///
    /// Returns `OutOfMemory` if the table is full.
    pub fn map(&mut self, phys: u64, size: usize, dir: DmaDir) -> Result<u64> {
        if size == 0 {
            return Err(Error::InvalidArgument);
        }
        let dma = phys.wrapping_add_signed(self.dma_offset);
        let slot = self
            .entries
            .iter()
            .position(|e| !e.active)
            .ok_or(Error::OutOfMemory)?;

        self.entries[slot] = StreamingMap {
            phys_addr: phys,
            dma_addr: dma,
            size,
            direction: dir,
            active: true,
        };
        self.count += 1;
        Ok(dma)
    }

    /// Unmap a streaming DMA mapping by DMA address.
    pub fn unmap(&mut self, dma: u64) {
        let pos = self
            .entries
            .iter()
            .position(|e| e.active && e.dma_addr == dma);
        if let Some(idx) = pos {
            self.entries[idx].active = false;
            if self.count > 0 {
                self.count -= 1;
            }
        }
    }

    /// Synchronize the buffer for device access (flush CPU caches).
    ///
    /// On x86_64 with coherent caches this is a no-op. Non-coherent
    /// architectures must flush the relevant cache lines here.
    pub fn sync_for_device(&self, dma: u64) {
        let _ = dma;
        // x86_64: cache-coherent DMA; no operation required.
    }

    /// Synchronize the buffer for CPU access (invalidate caches).
    pub fn sync_for_cpu(&self, dma: u64) {
        let _ = dma;
        // x86_64: cache-coherent DMA; no operation required.
    }

    /// Return the number of active mappings.
    pub fn active_count(&self) -> usize {
        self.count
    }
}

// ---------------------------------------------------------------------------
// Bounce buffer
// ---------------------------------------------------------------------------

/// A bounce buffer slot for devices with limited DMA reach.
#[derive(Debug, Clone, Copy)]
pub struct BounceBuffer {
    /// Physical address of the bounce buffer (within device DMA window).
    pub bounce_phys: u64,
    /// DMA address of the bounce buffer.
    pub bounce_dma: u64,
    /// Original physical address of the caller's buffer.
    pub orig_phys: u64,
    /// Buffer size in bytes.
    pub size: usize,
    /// Transfer direction.
    pub direction: DmaDir,
    /// Whether this slot is in use.
    pub(crate) active: bool,
}

impl BounceBuffer {
    const EMPTY: Self = Self {
        bounce_phys: 0,
        bounce_dma: 0,
        orig_phys: 0,
        size: 0,
        direction: DmaDir::None,
        active: false,
    };
}

/// Bounce buffer pool for DMA-constrained devices.
///
/// When a device cannot reach a buffer (e.g., 32-bit DMA mask but buffer
/// at high physical address), the subsystem copies data through a bounce
/// buffer that lies within the device's reachable window.
pub struct BouncePool {
    /// Physical base of the bounce region.
    phys_base: u64,
    /// DMA offset.
    dma_offset: i64,
    /// Size of each bounce slot in bytes.
    slot_size: usize,
    /// Slot usage bitmap.
    used: [bool; MAX_BOUNCE_BUFFERS],
    /// Active slot records.
    slots: [BounceBuffer; MAX_BOUNCE_BUFFERS],
    /// Count of active bounce buffers.
    count: usize,
}

impl BouncePool {
    /// Create a new bounce buffer pool.
    pub const fn new(phys_base: u64, dma_offset: i64, slot_size: usize) -> Self {
        Self {
            phys_base,
            dma_offset,
            slot_size,
            used: [false; MAX_BOUNCE_BUFFERS],
            slots: [BounceBuffer::EMPTY; MAX_BOUNCE_BUFFERS],
            count: 0,
        }
    }

    /// Allocate a bounce buffer for `orig_phys` with the given `size` and
    /// transfer `direction`.
    ///
    /// The caller is responsible for copying data between the original buffer
    /// and `bounce_phys` before/after DMA. Returns a `BounceBuffer` with the
    /// device-visible DMA address.
    ///
    /// # Errors
    ///
    /// Returns `OutOfMemory` if no slots remain or `size > slot_size`.
    pub fn alloc(
        &mut self,
        orig_phys: u64,
        size: usize,
        direction: DmaDir,
    ) -> Result<BounceBuffer> {
        if size > self.slot_size || size == 0 {
            return Err(Error::InvalidArgument);
        }
        let idx = self
            .used
            .iter()
            .position(|&u| !u)
            .ok_or(Error::OutOfMemory)?;

        let offset = (idx * self.slot_size) as u64;
        let bounce_phys = self.phys_base + offset;
        let bounce_dma = bounce_phys.wrapping_add_signed(self.dma_offset);

        let buf = BounceBuffer {
            bounce_phys,
            bounce_dma,
            orig_phys,
            size,
            direction,
            active: true,
        };
        self.used[idx] = true;
        self.slots[idx] = buf;
        self.count += 1;
        Ok(buf)
    }

    /// Free a bounce buffer by its `bounce_dma` address.
    pub fn free(&mut self, bounce_dma: u64) {
        let pos = self
            .slots
            .iter()
            .position(|s| s.active && s.bounce_dma == bounce_dma);
        if let Some(idx) = pos {
            self.slots[idx].active = false;
            self.used[idx] = false;
            if self.count > 0 {
                self.count -= 1;
            }
        }
    }

    /// Return the number of active bounce buffers.
    pub fn active_count(&self) -> usize {
        self.count
    }

    /// Return `true` if no bounce buffers are allocated.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn iova_alloc_free() {
        let mut iova = IovaAllocator::new(0x1000_0000, 0x2000_0000);
        let a = iova.alloc(4096, 12).unwrap();
        assert_eq!(a, 0x1000_0000);
        assert_eq!(iova.active_count(), 1);
        iova.free(a);
        assert!(iova.is_empty());
    }

    #[test]
    fn iova_alignment() {
        let mut iova = IovaAllocator::new(0x1000, 0x1_0000_0000);
        // First alloc at 0x1000 (already aligned to 4 KiB).
        let a = iova.alloc(1, 12).unwrap();
        assert_eq!(a & 0xFFF, 0);
        // Second alloc should align up.
        let b = iova.alloc(4096, 12).unwrap();
        assert_eq!(b & 0xFFF, 0);
        assert!(b > a);
    }

    #[test]
    fn iova_window_exhausted() {
        let mut iova = IovaAllocator::new(0, 4096);
        iova.alloc(4096, 12).unwrap();
        assert!(iova.alloc(1, 0).is_err());
    }

    #[test]
    fn coherent_pool_alloc_free() {
        let mut pool = CoherentPool::new(0x8000_0000, 0, 4096);
        pool.init().unwrap();
        let s0 = pool.alloc().unwrap();
        assert_eq!(s0.phys_addr, 0x8000_0000);
        assert_eq!(s0.dma_addr, 0x8000_0000);
        let s1 = pool.alloc().unwrap();
        assert_eq!(s1.phys_addr, 0x8000_1000);
        pool.free(s0);
        assert_eq!(pool.used_count(), 1);
    }

    #[test]
    fn coherent_pool_uninit_error() {
        let mut pool = CoherentPool::new(0, 0, 64);
        assert!(pool.alloc().is_err());
    }

    #[test]
    fn streaming_map_unmap() {
        let mut table = StreamingMapTable::new(0);
        let dma = table.map(0x4000, 512, DmaDir::ToDevice).unwrap();
        assert_eq!(dma, 0x4000);
        assert_eq!(table.active_count(), 1);
        table.unmap(dma);
        assert_eq!(table.active_count(), 0);
    }

    #[test]
    fn bounce_pool_alloc_free() {
        let mut pool = BouncePool::new(0x0100_0000, 0, 4096);
        let buf = pool.alloc(0xFFFF_0000, 512, DmaDir::FromDevice).unwrap();
        assert_eq!(buf.bounce_phys, 0x0100_0000);
        assert_eq!(buf.orig_phys, 0xFFFF_0000);
        assert_eq!(pool.active_count(), 1);
        pool.free(buf.bounce_dma);
        assert!(pool.is_empty());
    }

    #[test]
    fn bounce_pool_size_check() {
        let mut pool = BouncePool::new(0, 0, 512);
        assert!(pool.alloc(0, 513, DmaDir::None).is_err());
    }
}
