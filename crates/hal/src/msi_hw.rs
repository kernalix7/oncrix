// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! MSI/MSI-X interrupt hardware interface.
//!
//! This module provides the low-level hardware routines for programming
//! MSI (Message Signaled Interrupts) and MSI-X capability registers
//! directly in PCI configuration space.
//!
//! Unlike `msi.rs` which defines data structures and the registry,
//! `msi_hw.rs` provides the MMIO/port-I/O operations that write the
//! message address and data into the device's config space registers.
//!
//! # MSI programming sequence
//! 1. Find the MSI capability in config space (cap ID 0x05).
//! 2. Compute the message address and data for the target vector/APIC.
//! 3. Write address lo, address hi (64-bit cap), and data registers.
//! 4. Set the enable bit in Message Control.
//!
//! # MSI-X programming sequence
//! 1. Find MSI-X capability (cap ID 0x11).
//! 2. Map the MSI-X Table BAR region.
//! 3. Write address lo/hi, data, and vector-control per table entry.
//! 4. Set MSI-X Enable in Message Control.
//!
//! Reference: PCI Local Bus Specification 3.0 §6.8, PCI Express Base 5.0 §7.7.

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// PCI capability ID for MSI.
pub const CAP_ID_MSI: u8 = 0x05;

/// PCI capability ID for MSI-X.
pub const CAP_ID_MSIX: u8 = 0x11;

/// MSI Message Control offset from capability base.
pub const MSI_MSG_CTRL_OFFSET: u8 = 0x02;

/// MSI Message Address offset from capability base.
pub const MSI_MSG_ADDR_OFFSET: u8 = 0x04;

/// MSI Message Upper Address offset (64-bit only).
pub const MSI_MSG_UPPER_ADDR_OFFSET: u8 = 0x08;

/// MSI Message Data offset (32-bit capable device).
pub const MSI_MSG_DATA_OFFSET_32: u8 = 0x08;

/// MSI Message Data offset (64-bit capable device).
pub const MSI_MSG_DATA_OFFSET_64: u8 = 0x0C;

/// MSI Message Control: Enable bit (bit 0).
pub const MSI_CTRL_ENABLE: u16 = 1 << 0;

/// MSI Message Control: 64-bit capable bit (bit 7).
pub const MSI_CTRL_64BIT: u16 = 1 << 7;

/// MSI Message Control: Per-vector masking capable (bit 8).
pub const MSI_CTRL_PER_VEC_MASK: u16 = 1 << 8;

/// MSI Message Control: Multiple Message Capable field mask (bits 3:1).
pub const MSI_CTRL_MMC_MASK: u16 = 0x000E;

/// MSI Message Control: Multiple Message Enable field mask (bits 6:4).
pub const MSI_CTRL_MME_MASK: u16 = 0x0070;

/// MSI-X Message Control: Table Size field mask (bits 10:0).
pub const MSIX_CTRL_TABLE_SIZE_MASK: u16 = 0x07FF;

/// MSI-X Message Control: Function Mask bit (bit 14).
pub const MSIX_CTRL_FUNC_MASK: u16 = 1 << 14;

/// MSI-X Message Control: Enable bit (bit 15).
pub const MSIX_CTRL_ENABLE: u16 = 1 << 15;

/// MSI-X table entry size in bytes (16 bytes: addr_lo, addr_hi, data, ctrl).
pub const MSIX_ENTRY_SIZE: usize = 16;

/// MSI-X vector control: Mask bit (bit 0).
pub const MSIX_VEC_CTRL_MASKED: u32 = 1 << 0;

/// x86 MSI address base (Local APIC message delivery).
pub const MSI_ADDR_BASE: u32 = 0xFEE0_0000;

/// MSI address: destination APIC ID field shift (bits 19:12).
pub const MSI_ADDR_DEST_ID_SHIFT: u32 = 12;

/// MSI address: Redirection Hint (bit 3).
pub const MSI_ADDR_RH: u32 = 1 << 3;

/// MSI address: Destination Mode logical (bit 2).
pub const MSI_ADDR_DM_LOGICAL: u32 = 1 << 2;

/// MSI data: delivery mode field shift (bits 10:8).
pub const MSI_DATA_DELIVERY_SHIFT: u32 = 8;

/// MSI data: delivery mode Fixed (0b000).
pub const MSI_DATA_DELIVERY_FIXED: u32 = 0x0 << 8;

/// MSI data: trigger mode Level (bit 15).
pub const MSI_DATA_TRIGGER_LEVEL: u32 = 1 << 15;

/// MSI data: level assert (bit 14).
pub const MSI_DATA_LEVEL_ASSERT: u32 = 1 << 14;

// ---------------------------------------------------------------------------
// MsiAddress / MsiData helpers
// ---------------------------------------------------------------------------

/// Builds the 32-bit MSI message address for x86_64.
///
/// `dest_apic_id` is the physical APIC ID of the target CPU.
/// `logical` selects logical (true) vs physical (false) destination mode.
#[inline]
pub const fn msi_build_address(dest_apic_id: u8, logical: bool) -> u32 {
    let mut addr = MSI_ADDR_BASE | ((dest_apic_id as u32) << MSI_ADDR_DEST_ID_SHIFT);
    if logical {
        addr |= MSI_ADDR_DM_LOGICAL;
    }
    addr
}

/// Builds the 32-bit MSI message data word.
///
/// `vector` is the interrupt vector (32–255).
/// `delivery` is the delivery mode (use `MSI_DATA_DELIVERY_FIXED` etc.).
#[inline]
pub const fn msi_build_data(vector: u8, delivery: u32) -> u32 {
    (vector as u32) | delivery
}

// ---------------------------------------------------------------------------
// MsiConfig — tracks capability register state
// ---------------------------------------------------------------------------

/// Raw MSI capability configuration parsed from PCI config space.
#[derive(Debug, Clone, Copy)]
pub struct MsiConfig {
    /// Byte offset of the MSI capability in config space.
    pub cap_offset: u8,
    /// Raw Message Control register value.
    pub msg_ctrl: u16,
    /// Message address (lower 32 bits).
    pub msg_addr_lo: u32,
    /// Message address (upper 32 bits, 0 for 32-bit devices).
    pub msg_addr_hi: u32,
    /// Message data register value.
    pub msg_data: u16,
    /// Whether 64-bit addressing is supported.
    pub is_64bit: bool,
    /// Whether per-vector masking is supported.
    pub per_vector_mask: bool,
}

impl MsiConfig {
    /// Parse an `MsiConfig` from raw config space bytes.
    ///
    /// `data` must be at least 24 bytes starting at the MSI capability.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `data` is too short.
    pub fn parse(cap_offset: u8, data: &[u8]) -> Result<Self> {
        if data.len() < 14 {
            return Err(Error::InvalidArgument);
        }
        let ctrl = u16::from_le_bytes([data[2], data[3]]);
        let is_64bit = ctrl & MSI_CTRL_64BIT != 0;
        let per_vector_mask = ctrl & MSI_CTRL_PER_VEC_MASK != 0;

        let addr_lo = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
        let (addr_hi, data_off) = if is_64bit {
            let hi = u32::from_le_bytes([data[8], data[9], data[10], data[11]]);
            (hi, 12usize)
        } else {
            (0u32, 8usize)
        };
        if data.len() < data_off + 2 {
            return Err(Error::InvalidArgument);
        }
        let msg_data = u16::from_le_bytes([data[data_off], data[data_off + 1]]);

        Ok(Self {
            cap_offset,
            msg_ctrl: ctrl,
            msg_addr_lo: addr_lo,
            msg_addr_hi: addr_hi,
            msg_data,
            is_64bit,
            per_vector_mask,
        })
    }

    /// Return whether MSI is currently enabled.
    pub const fn is_enabled(&self) -> bool {
        self.msg_ctrl & MSI_CTRL_ENABLE != 0
    }

    /// Return the number of vectors the device requests (log2 in bits 3:1).
    pub const fn multi_msg_capable(&self) -> u8 {
        ((self.msg_ctrl & MSI_CTRL_MMC_MASK) >> 1) as u8
    }

    /// Return the number of currently enabled vectors (log2 in bits 6:4).
    pub const fn multi_msg_enabled(&self) -> u8 {
        ((self.msg_ctrl & MSI_CTRL_MME_MASK) >> 4) as u8
    }

    /// Return max vectors the device can use.
    pub const fn max_vectors(&self) -> usize {
        1usize << self.multi_msg_capable()
    }
}

// ---------------------------------------------------------------------------
// MsixConfig
// ---------------------------------------------------------------------------

/// Raw MSI-X capability configuration.
#[derive(Debug, Clone, Copy)]
pub struct MsixConfig {
    /// Byte offset of the MSI-X capability in config space.
    pub cap_offset: u8,
    /// Raw Message Control register value.
    pub msg_ctrl: u16,
    /// Table BIR (BAR Index Register, bits 2:0 of Table Offset/BIR).
    pub table_bir: u8,
    /// Table offset within the BAR (bits 31:3, 8-byte aligned).
    pub table_offset: u32,
    /// PBA BIR (bits 2:0 of PBA Offset/BIR).
    pub pba_bir: u8,
    /// PBA offset within the BAR (bits 31:3).
    pub pba_offset: u32,
}

impl MsixConfig {
    /// Parse an `MsixConfig` from raw config-space bytes at the capability.
    ///
    /// `data` must be at least 12 bytes starting at the MSI-X capability.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `data` is too short.
    pub fn parse(cap_offset: u8, data: &[u8]) -> Result<Self> {
        if data.len() < 12 {
            return Err(Error::InvalidArgument);
        }
        let ctrl = u16::from_le_bytes([data[2], data[3]]);
        let table_reg = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
        let pba_reg = u32::from_le_bytes([data[8], data[9], data[10], data[11]]);

        Ok(Self {
            cap_offset,
            msg_ctrl: ctrl,
            table_bir: (table_reg & 0x7) as u8,
            table_offset: table_reg & !0x7,
            pba_bir: (pba_reg & 0x7) as u8,
            pba_offset: pba_reg & !0x7,
        })
    }

    /// Return the number of MSI-X vectors (table size + 1).
    pub const fn num_vectors(&self) -> usize {
        ((self.msg_ctrl & MSIX_CTRL_TABLE_SIZE_MASK) as usize) + 1
    }

    /// Return whether MSI-X is enabled.
    pub const fn is_enabled(&self) -> bool {
        self.msg_ctrl & MSIX_CTRL_ENABLE != 0
    }

    /// Return whether the function mask is active.
    pub const fn is_function_masked(&self) -> bool {
        self.msg_ctrl & MSIX_CTRL_FUNC_MASK != 0
    }
}

// ---------------------------------------------------------------------------
// MSI-X table entry MMIO helpers
// ---------------------------------------------------------------------------

/// Reads a 32-bit value from an MSI-X table entry field via MMIO.
///
/// # Safety
///
/// `table_base` must be the virtual address of the mapped MSI-X table.
/// `entry` must be < `num_vectors`. `field_offset` must be 0, 4, 8, or 12.
#[inline]
pub unsafe fn msix_read_entry_field(table_base: u64, entry: usize, field_offset: usize) -> u32 {
    let addr = table_base + (entry * MSIX_ENTRY_SIZE + field_offset) as u64;
    // SAFETY: Caller guarantees valid MMIO table mapping and bounds.
    unsafe { core::ptr::read_volatile(addr as *const u32) }
}

/// Writes a 32-bit value to an MSI-X table entry field via MMIO.
///
/// # Safety
///
/// Same as [`msix_read_entry_field`].
#[inline]
pub unsafe fn msix_write_entry_field(table_base: u64, entry: usize, field_offset: usize, val: u32) {
    let addr = table_base + (entry * MSIX_ENTRY_SIZE + field_offset) as u64;
    // SAFETY: Caller guarantees valid MMIO table mapping and bounds.
    unsafe { core::ptr::write_volatile(addr as *mut u32, val) }
}

/// Programs a single MSI-X table entry.
///
/// # Parameters
/// - `table_base`: virtual address of the mapped MSI-X table.
/// - `entry`: zero-based vector index.
/// - `addr_lo` / `addr_hi`: 64-bit message address split into halves.
/// - `data`: message data word.
/// - `masked`: whether to mask this vector.
///
/// # Safety
///
/// `table_base` must be the virtual address of a properly mapped MSI-X table.
/// `entry` must be within `MsixConfig::num_vectors()`.
pub unsafe fn msix_program_entry(
    table_base: u64,
    entry: usize,
    addr_lo: u32,
    addr_hi: u32,
    data: u32,
    masked: bool,
) {
    // SAFETY: Caller guarantees table_base and entry are valid.
    unsafe {
        msix_write_entry_field(table_base, entry, 0, addr_lo);
        msix_write_entry_field(table_base, entry, 4, addr_hi);
        msix_write_entry_field(table_base, entry, 8, data);
        let ctrl = if masked { MSIX_VEC_CTRL_MASKED } else { 0 };
        msix_write_entry_field(table_base, entry, 12, ctrl);
    }
}

/// Masks or unmasks a single MSI-X table entry.
///
/// # Safety
///
/// Same as [`msix_program_entry`].
pub unsafe fn msix_set_vector_mask(table_base: u64, entry: usize, masked: bool) {
    // SAFETY: Reading then writing the vector control field.
    unsafe {
        let ctrl = msix_read_entry_field(table_base, entry, 12);
        let new_ctrl = if masked {
            ctrl | MSIX_VEC_CTRL_MASKED
        } else {
            ctrl & !MSIX_VEC_CTRL_MASKED
        };
        msix_write_entry_field(table_base, entry, 12, new_ctrl);
    }
}

// ---------------------------------------------------------------------------
// Capability chain search
// ---------------------------------------------------------------------------

/// Searches PCI configuration space for a capability with the given ID.
///
/// `config` must be a slice of at least 256 bytes (standard PCI config space).
/// Returns the byte offset of the matching capability, or `None`.
///
/// # Errors
///
/// Returns [`Error::InvalidArgument`] if `config` is too short.
pub fn find_pci_capability(config: &[u8], cap_id: u8) -> Result<Option<u8>> {
    if config.len() < 256 {
        return Err(Error::InvalidArgument);
    }
    // Status register bit 4: capabilities list present.
    let status = u16::from_le_bytes([config[0x06], config[0x07]]);
    if status & (1 << 4) == 0 {
        return Ok(None);
    }
    // Capabilities pointer at offset 0x34.
    let mut ptr = config[0x34] & 0xFC;
    let mut hops = 0u8;
    while ptr >= 0x40 && hops < 48 {
        let id = config[ptr as usize];
        if id == cap_id {
            return Ok(Some(ptr));
        }
        ptr = config[ptr as usize + 1] & 0xFC;
        hops += 1;
    }
    Ok(None)
}

// ---------------------------------------------------------------------------
// MsiHwManager
// ---------------------------------------------------------------------------

/// Maximum number of MSI-capable devices tracked.
const MAX_MSI_HW_DEVICES: usize = 32;

/// Hardware MSI/MSI-X device record.
#[derive(Debug, Clone, Copy)]
pub struct MsiHwDevice {
    /// PCI BDF (bus << 8 | device << 3 | function).
    pub bdf: u16,
    /// MSI config (if the device has MSI).
    pub msi: Option<MsiConfig>,
    /// MSI-X config (if the device has MSI-X).
    pub msix: Option<MsixConfig>,
    /// Virtual address of the MSI-X table (0 if not mapped).
    pub msix_table_vaddr: u64,
}

/// Manager for MSI/MSI-X hardware state across PCI devices.
pub struct MsiHwManager {
    devices: [Option<MsiHwDevice>; MAX_MSI_HW_DEVICES],
    count: usize,
}

impl MsiHwManager {
    /// Create an empty manager.
    pub const fn new() -> Self {
        const NONE: Option<MsiHwDevice> = None;
        Self {
            devices: [NONE; MAX_MSI_HW_DEVICES],
            count: 0,
        }
    }

    /// Register a device and its MSI/MSI-X capabilities.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] when the manager is full.
    pub fn register(
        &mut self,
        bdf: u16,
        msi: Option<MsiConfig>,
        msix: Option<MsixConfig>,
    ) -> Result<usize> {
        let slot = self
            .devices
            .iter()
            .position(|d| d.is_none())
            .ok_or(Error::OutOfMemory)?;
        self.devices[slot] = Some(MsiHwDevice {
            bdf,
            msi,
            msix,
            msix_table_vaddr: 0,
        });
        self.count += 1;
        Ok(slot)
    }

    /// Set the virtual address for the MSI-X table of a device.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the device index is invalid.
    pub fn set_msix_table_vaddr(&mut self, idx: usize, vaddr: u64) -> Result<()> {
        let dev = self
            .devices
            .get_mut(idx)
            .and_then(|d| d.as_mut())
            .ok_or(Error::NotFound)?;
        dev.msix_table_vaddr = vaddr;
        Ok(())
    }

    /// Look up a device by BDF.
    pub fn find_by_bdf(&self, bdf: u16) -> Option<&MsiHwDevice> {
        self.devices.iter().flatten().find(|d| d.bdf == bdf)
    }

    /// Look up a device by BDF (mutable).
    pub fn find_by_bdf_mut(&mut self, bdf: u16) -> Option<&mut MsiHwDevice> {
        self.devices.iter_mut().flatten().find(|d| d.bdf == bdf)
    }

    /// Return the number of registered devices.
    pub const fn len(&self) -> usize {
        self.count
    }

    /// Return `true` if no devices are registered.
    pub const fn is_empty(&self) -> bool {
        self.count == 0
    }
}

impl Default for MsiHwManager {
    fn default() -> Self {
        Self::new()
    }
}
