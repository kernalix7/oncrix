// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! PCIe MSI (Message Signaled Interrupt) and MSI-X configuration.
//!
//! Manages MSI and MSI-X capability structures in PCIe configuration space,
//! enabling devices to signal interrupts via memory writes rather than
//! dedicated interrupt pins.
//!
//! # MSI vs MSI-X
//!
//! - **MSI**: Up to 32 vectors per device, configured via a single capability
//! - **MSI-X**: Up to 2048 vectors per device, table-based, flexible masking
//!
//! # References
//!
//! - PCI Local Bus Specification Revision 3.0, Section 6.8
//! - PCI Express Base Specification, Section 7.7

#![allow(dead_code)]

use oncrix_lib::{Error, Result};

/// MSI capability structure offsets (from capability base).
const MSI_CTRL_OFFSET: u8 = 0x02;
const MSI_ADDR_LO_OFFSET: u8 = 0x04;
const MSI_ADDR_HI_OFFSET: u8 = 0x08;
const MSI_DATA_OFFSET_32: u8 = 0x08;
const MSI_DATA_OFFSET_64: u8 = 0x0C;
const MSI_MASK_OFFSET_32: u8 = 0x0C;
const MSI_MASK_OFFSET_64: u8 = 0x10;

/// MSI-X capability structure offsets.
const MSIX_CTRL_OFFSET: u8 = 0x02;
const MSIX_TABLE_OFFSET: u8 = 0x04;
const MSIX_PBA_OFFSET: u8 = 0x08;

/// MSI-X table entry size in bytes.
const MSIX_ENTRY_SIZE: usize = 16;

/// MSI-X table entry field offsets.
const MSIX_ENTRY_ADDR_LO: usize = 0;
const MSIX_ENTRY_ADDR_HI: usize = 4;
const MSIX_ENTRY_DATA: usize = 8;
const MSIX_ENTRY_CTRL: usize = 12;

/// MSI message address for x86 (directed to specific LAPIC).
///
/// Format: 0xFEE[dest][rh][dm]XX
pub const MSI_ADDR_BASE: u32 = 0xFEE0_0000;

/// MSI message data format bits.
pub mod msi_data {
    /// Vector number (bits 7:0).
    pub const VECTOR_MASK: u32 = 0xFF;
    /// Delivery mode: Fixed (0b000).
    pub const DELIVERY_FIXED: u32 = 0 << 8;
    /// Level: deassert (0) or assert (1).
    pub const LEVEL_ASSERT: u32 = 1 << 14;
    /// Trigger mode: edge (0) or level (1).
    pub const TRIGGER_LEVEL: u32 = 1 << 15;
}

/// MSI message configuration.
#[derive(Debug, Clone, Copy)]
pub struct MsiMessage {
    /// Lower 32 bits of the message address.
    pub address_lo: u32,
    /// Upper 32 bits of the message address (for 64-bit addressing).
    pub address_hi: u32,
    /// Message data (interrupt vector and delivery mode).
    pub data: u32,
}

impl MsiMessage {
    /// Creates an MSI message targeting a specific LAPIC and vector.
    ///
    /// # Arguments
    ///
    /// * `apic_id` - Destination APIC ID
    /// * `vector` - Interrupt vector number (32–255)
    pub const fn new(apic_id: u8, vector: u8) -> Self {
        let address_lo = MSI_ADDR_BASE | ((apic_id as u32) << 12);
        let data = msi_data::DELIVERY_FIXED | (vector as u32 & msi_data::VECTOR_MASK);
        Self {
            address_lo,
            address_hi: 0,
            data,
        }
    }
}

/// MSI capability descriptor, parsed from PCI configuration space.
#[derive(Debug, Clone, Copy)]
pub struct MsiCapability {
    /// Offset of MSI capability in PCI config space.
    pub cap_offset: u8,
    /// Whether 64-bit addressing is supported.
    pub is_64bit: bool,
    /// Whether per-vector masking is supported.
    pub has_masking: bool,
    /// Number of requested message vectors (log2 encoded).
    pub multiple_msg_capable: u8,
}

impl MsiCapability {
    /// Parses an MSI capability from the raw control register value.
    pub fn from_ctrl(cap_offset: u8, ctrl: u16) -> Self {
        Self {
            cap_offset,
            is_64bit: ctrl & (1 << 7) != 0,
            has_masking: ctrl & (1 << 8) != 0,
            multiple_msg_capable: ((ctrl >> 1) & 0x7) as u8,
        }
    }

    /// Returns the offset to the data register.
    pub fn data_offset(&self) -> u8 {
        if self.is_64bit {
            self.cap_offset + MSI_DATA_OFFSET_64
        } else {
            self.cap_offset + MSI_DATA_OFFSET_32
        }
    }

    /// Returns the offset to the mask register (if masking is supported).
    pub fn mask_offset(&self) -> Option<u8> {
        if !self.has_masking {
            return None;
        }
        Some(if self.is_64bit {
            self.cap_offset + MSI_MASK_OFFSET_64
        } else {
            self.cap_offset + MSI_MASK_OFFSET_32
        })
    }
}

/// MSI-X capability descriptor.
#[derive(Debug, Clone, Copy)]
pub struct MsixCapability {
    /// Offset of MSI-X capability in PCI config space.
    pub cap_offset: u8,
    /// Table size (number of vectors, 0-indexed value + 1).
    pub table_size: u16,
    /// BAR index containing the MSI-X table.
    pub table_bar: u8,
    /// Offset of MSI-X table within the BAR (in bytes, 8-byte aligned).
    pub table_offset: u32,
    /// BAR index containing the pending bit array (PBA).
    pub pba_bar: u8,
    /// Offset of PBA within the BAR.
    pub pba_offset: u32,
}

impl MsixCapability {
    /// Parses an MSI-X capability from control and table/PBA registers.
    pub fn parse(cap_offset: u8, ctrl: u16, table_reg: u32, pba_reg: u32) -> Result<Self> {
        let table_size = (ctrl & 0x7FF) + 1;
        if table_size as usize > 2048 {
            return Err(Error::InvalidArgument);
        }
        Ok(Self {
            cap_offset,
            table_size,
            table_bar: (table_reg & 0x7) as u8,
            table_offset: table_reg & !0x7,
            pba_bar: (pba_reg & 0x7) as u8,
            pba_offset: pba_reg & !0x7,
        })
    }

    /// Returns the MMIO address of a specific MSI-X table entry.
    ///
    /// # Arguments
    ///
    /// * `table_base_va` - Virtual address of the MSI-X table (BAR mapped)
    /// * `index` - Entry index (0 to table_size - 1)
    pub fn entry_addr(&self, table_base_va: usize, index: u16) -> Result<usize> {
        if index >= self.table_size {
            return Err(Error::InvalidArgument);
        }
        Ok(table_base_va + (index as usize) * MSIX_ENTRY_SIZE)
    }
}

/// MSI-X table entry accessor using MMIO.
pub struct MsixEntry {
    /// Virtual address of this entry in the MSI-X table.
    base: usize,
}

impl MsixEntry {
    /// Creates an accessor for an MSI-X entry at the given MMIO address.
    pub const fn new(base: usize) -> Self {
        Self { base }
    }

    /// Programs this MSI-X entry with the given message and unmasked state.
    pub fn program(&self, msg: &MsiMessage) {
        self.write32(MSIX_ENTRY_ADDR_LO, msg.address_lo);
        self.write32(MSIX_ENTRY_ADDR_HI, msg.address_hi);
        self.write32(MSIX_ENTRY_DATA, msg.data);
        self.write32(MSIX_ENTRY_CTRL, 0); // Unmask
    }

    /// Masks this MSI-X entry (sets bit 0 of the control field).
    pub fn mask(&self) {
        let ctrl = self.read32(MSIX_ENTRY_CTRL);
        self.write32(MSIX_ENTRY_CTRL, ctrl | 1);
    }

    /// Unmasks this MSI-X entry.
    pub fn unmask(&self) {
        let ctrl = self.read32(MSIX_ENTRY_CTRL);
        self.write32(MSIX_ENTRY_CTRL, ctrl & !1);
    }

    /// Returns whether this entry is masked.
    pub fn is_masked(&self) -> bool {
        self.read32(MSIX_ENTRY_CTRL) & 1 != 0
    }

    fn read32(&self, offset: usize) -> u32 {
        let addr = (self.base + offset) as *const u32;
        // SAFETY: base is a valid MSI-X table MMIO region. offset is within
        // the 16-byte MSI-X entry structure. Volatile read is required for MMIO.
        unsafe { addr.read_volatile() }
    }

    fn write32(&self, offset: usize, val: u32) {
        let addr = (self.base + offset) as *mut u32;
        // SAFETY: base is a valid MSI-X table MMIO region mapped from a BAR.
        // Volatile write ensures the interrupt controller receives the update.
        unsafe { addr.write_volatile(val) }
    }
}

/// Enables MSI-X in the device's MSI-X capability control register.
///
/// # Arguments
///
/// * `cap_va` - Virtual address of the MSI-X capability structure in PCI config space
pub fn msix_enable(cap_va: usize) {
    let ctrl_addr = (cap_va + MSIX_CTRL_OFFSET as usize) as *mut u16;
    // SAFETY: cap_va is the start of an MSI-X capability structure in PCI config space.
    // Setting bit 15 (MSI-X Enable) activates MSI-X mode for the device.
    unsafe {
        let ctrl = ctrl_addr.read_volatile();
        ctrl_addr.write_volatile(ctrl | (1 << 15));
    }
}

/// Disables MSI-X in the device capability.
pub fn msix_disable(cap_va: usize) {
    let ctrl_addr = (cap_va + MSIX_CTRL_OFFSET as usize) as *mut u16;
    // SAFETY: Clearing bit 15 of the MSI-X control register disables MSI-X mode.
    unsafe {
        let ctrl = ctrl_addr.read_volatile();
        ctrl_addr.write_volatile(ctrl & !(1 << 15));
    }
}
