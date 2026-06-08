// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! PCI MSI/MSI-X interrupt management for device drivers.
//!
//! Provides the driver-facing interface for allocating, configuring,
//! and masking MSI (Message Signaled Interrupts) and MSI-X interrupts.
//! Abstracts over PCI configuration-space capability reads and the
//! vector allocation table.
//!
//! # MSI vs MSI-X
//!
//! | Feature     | MSI             | MSI-X             |
//! |-------------|-----------------|-------------------|
//! | Vectors     | Up to 32        | Up to 2048        |
//! | Table        | Config space    | Separate BAR MMIO |
//! | Per-vector mask | No (global) | Yes               |
//!
//! Reference: PCI Express Base Specification 5.0, §6.1.4 (MSI), §6.1.5 (MSI-X).

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum MSI vectors that can be allocated for a single device.
pub const MAX_MSI_VECTORS: usize = 32;

/// Maximum MSI-X vectors tracked in this table.
pub const MAX_MSIX_VECTORS: usize = 256;

/// MSI capability: Message Control register offset within capability.
pub const MSI_CTRL_OFFSET: u8 = 2;

/// MSI capability: Message Address register offset.
pub const MSI_ADDR_OFFSET: u8 = 4;

/// MSI capability: Message Data register offset (32-bit addressing).
pub const MSI_DATA_OFFSET_32: u8 = 8;

/// MSI capability: Message Data register offset (64-bit addressing).
pub const MSI_DATA_OFFSET_64: u8 = 12;

/// MSI Control: MSI Enable bit.
pub const MSI_CTRL_ENABLE: u16 = 1 << 0;

/// MSI Control: Multiple Message Capable field shift.
pub const MSI_CTRL_MMC_SHIFT: u16 = 1;

/// MSI Control: Multiple Message Capable mask (3 bits).
pub const MSI_CTRL_MMC_MASK: u16 = 0x7 << 1;

/// MSI Control: Multiple Message Enable field shift.
pub const MSI_CTRL_MME_SHIFT: u16 = 4;

/// MSI Control: 64-bit address capable.
pub const MSI_CTRL_64BIT: u16 = 1 << 7;

/// MSI-X Control: MSI-X Enable bit.
pub const MSIX_CTRL_ENABLE: u16 = 1 << 15;

/// MSI-X Control: Global Mask bit.
pub const MSIX_CTRL_FMASK: u16 = 1 << 14;

/// MSI-X Control: Table Size mask (bits 10:0).
pub const MSIX_CTRL_TSIZE_MASK: u16 = 0x7FF;

/// MSI-X table entry: Vector Control word offset (mask bit = bit 0).
pub const MSIX_ENTRY_VECTOR_CTRL: u32 = 12;

/// MSI-X table entry size in bytes.
pub const MSIX_ENTRY_SIZE: u32 = 16;

// ---------------------------------------------------------------------------
// MsiVector
// ---------------------------------------------------------------------------

/// A single allocated MSI interrupt vector.
#[derive(Debug, Clone, Copy)]
pub struct MsiVector {
    /// PCI Bus:Device.Function that owns this vector.
    pub bdf: u16,
    /// IRQ vector number assigned by the interrupt controller.
    pub vector: u8,
    /// MSI message address (LAPIC destination).
    pub msg_addr: u64,
    /// MSI message data (vector + delivery mode).
    pub msg_data: u32,
    /// Whether this slot is in use.
    pub active: bool,
}

impl MsiVector {
    const fn empty() -> Self {
        Self {
            bdf: 0,
            vector: 0,
            msg_addr: 0,
            msg_data: 0,
            active: false,
        }
    }
}

// ---------------------------------------------------------------------------
// MsixEntry
// ---------------------------------------------------------------------------

/// MSI-X table entry (16 bytes, stored in BAR-mapped MMIO).
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct MsixEntry {
    /// Message address lower 32 bits.
    pub msg_addr_lo: u32,
    /// Message address upper 32 bits.
    pub msg_addr_hi: u32,
    /// Message data.
    pub msg_data: u32,
    /// Vector control (bit 0 = mask).
    pub vector_ctrl: u32,
}

// ---------------------------------------------------------------------------
// MsiAllocator
// ---------------------------------------------------------------------------

/// Tracks MSI vector allocations across all PCI devices.
pub struct MsiAllocator {
    vectors: [MsiVector; MAX_MSI_VECTORS],
    count: usize,
}

impl Default for MsiAllocator {
    fn default() -> Self {
        Self::new()
    }
}

impl MsiAllocator {
    /// Creates an empty MSI allocator.
    pub const fn new() -> Self {
        Self {
            vectors: [MsiVector::empty(); MAX_MSI_VECTORS],
            count: 0,
        }
    }

    /// Allocates a vector slot for `bdf` with IRQ `vector`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the table is full.
    /// Returns [`Error::AlreadyExists`] if `bdf` already has a vector.
    pub fn alloc(&mut self, bdf: u16, vector: u8, msg_addr: u64, msg_data: u32) -> Result<()> {
        for v in &self.vectors {
            if v.active && v.bdf == bdf {
                return Err(Error::AlreadyExists);
            }
        }
        let slot = self
            .vectors
            .iter()
            .position(|v| !v.active)
            .ok_or(Error::OutOfMemory)?;
        self.vectors[slot] = MsiVector {
            bdf,
            vector,
            msg_addr,
            msg_data,
            active: true,
        };
        self.count += 1;
        Ok(())
    }

    /// Frees the MSI vector allocation for `bdf`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if no allocation exists for `bdf`.
    pub fn free(&mut self, bdf: u16) -> Result<()> {
        let slot = self
            .vectors
            .iter()
            .position(|v| v.active && v.bdf == bdf)
            .ok_or(Error::NotFound)?;
        self.vectors[slot].active = false;
        self.count -= 1;
        Ok(())
    }

    /// Returns the MSI vector record for `bdf`.
    pub fn get(&self, bdf: u16) -> Option<&MsiVector> {
        self.vectors.iter().find(|v| v.active && v.bdf == bdf)
    }

    /// Returns the number of active allocations.
    pub fn count(&self) -> usize {
        self.count
    }
}

// ---------------------------------------------------------------------------
// MsixController
// ---------------------------------------------------------------------------

/// MSI-X table controller for a single PCI device.
///
/// Manages the 16-byte per-vector entries in the device's MSI-X table,
/// which is mapped through a BAR specified in the MSI-X capability.
pub struct MsixController {
    /// Virtual address of the MSI-X table (mapped from BAR).
    pub table_virt: u64,
    /// Number of vectors in the table (from capability Table Size + 1).
    pub table_size: usize,
    /// Whether MSI-X is globally enabled for this device.
    pub enabled: bool,
}

impl MsixController {
    /// Creates a new MSI-X controller for the given table mapping.
    ///
    /// `table_virt` must be the virtual address of the MSI-X table mapped
    /// from the device's BAR. `table_size` is the number of entries.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `table_size` is zero or exceeds
    /// [`MAX_MSIX_VECTORS`] — rejects a device-supplied MSI-X Table Size that
    /// would allow out-of-bounds MMIO access via [`entry_addr`](Self::entry_addr).
    ///
    /// # Security
    ///
    /// `table_size` is read from device config space and is therefore
    /// attacker-controlled.  An unbounded table_size would allow
    /// [`entry_addr`] to compute a pointer far outside the mapped BAR region.
    pub fn new(table_virt: u64, table_size: usize) -> Result<Self> {
        // SECURITY: Reject a device-reported table size of zero (nonsensical)
        // or larger than MAX_MSIX_VECTORS (256) — the PCIe spec allows up to
        // 2048 but our backing array is bounded by this constant.  A malicious
        // device could otherwise cause entry_addr to walk off the end of the
        // mapped BAR region.
        if table_size == 0 || table_size > MAX_MSIX_VECTORS {
            return Err(Error::InvalidArgument);
        }
        Ok(Self {
            table_virt,
            table_size,
            enabled: false,
        })
    }

    /// Returns the virtual address of entry `index` in the MSI-X table.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `index >= table_size` or if the
    /// address arithmetic overflows.
    fn entry_addr(&self, index: usize) -> Result<u64> {
        // SECURITY: index is bounds-checked against the already-validated
        // table_size (capped at MAX_MSIX_VECTORS in new()), preventing
        // out-of-bounds MMIO access.
        if index >= self.table_size {
            return Err(Error::InvalidArgument);
        }
        // SECURITY: Use checked arithmetic for the MMIO address calculation.
        // A malicious device could supply a table_virt near u64::MAX; overflow
        // here would produce a wrapped address pointing outside the BAR.
        let offset = (index as u64)
            .checked_mul(MSIX_ENTRY_SIZE as u64)
            .ok_or(Error::InvalidArgument)?;
        self.table_virt
            .checked_add(offset)
            .ok_or(Error::InvalidArgument)
    }

    /// Programs entry `index` with the given message address and data.
    ///
    /// Leaves the vector unmasked (vector_ctrl = 0).
    ///
    /// # Safety
    ///
    /// `table_virt` must be a valid MMIO mapping of the MSI-X table.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `index >= table_size`.
    pub unsafe fn write_entry(&self, index: usize, msg_addr: u64, msg_data: u32) -> Result<()> {
        let base = self.entry_addr(index)?;
        // SAFETY: Caller guarantees valid MMIO; volatile writes required.
        unsafe {
            core::ptr::write_volatile(base as *mut u32, msg_addr as u32);
            core::ptr::write_volatile((base + 4) as *mut u32, (msg_addr >> 32) as u32);
            core::ptr::write_volatile((base + 8) as *mut u32, msg_data);
            // Unmask: vector_ctrl bit 0 = 0.
            core::ptr::write_volatile((base + 12) as *mut u32, 0);
        }
        Ok(())
    }

    /// Masks entry `index` (sets vector_ctrl bit 0).
    ///
    /// # Safety
    ///
    /// `table_virt` must be a valid MMIO mapping.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `index >= table_size`.
    pub unsafe fn mask_entry(&self, index: usize) -> Result<()> {
        let base = self.entry_addr(index)?;
        let ctrl_addr = (base + 12) as *mut u32;
        // SAFETY: Caller guarantees valid MMIO.
        let ctrl = unsafe { core::ptr::read_volatile(ctrl_addr) };
        // SAFETY: Same.
        unsafe { core::ptr::write_volatile(ctrl_addr, ctrl | 1) };
        Ok(())
    }

    /// Unmasks entry `index` (clears vector_ctrl bit 0).
    ///
    /// # Safety
    ///
    /// `table_virt` must be a valid MMIO mapping.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `index >= table_size`.
    pub unsafe fn unmask_entry(&self, index: usize) -> Result<()> {
        let base = self.entry_addr(index)?;
        let ctrl_addr = (base + 12) as *mut u32;
        // SAFETY: Caller guarantees valid MMIO.
        let ctrl = unsafe { core::ptr::read_volatile(ctrl_addr) };
        // SAFETY: Same.
        unsafe { core::ptr::write_volatile(ctrl_addr, ctrl & !1) };
        Ok(())
    }
}
