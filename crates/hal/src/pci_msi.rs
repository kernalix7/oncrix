// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! PCI MSI/MSI-X capability setup.
//!
//! This module provides the high-level routines for enabling MSI and MSI-X
//! on PCI/PCIe devices. It bridges the raw hardware access in `msi_hw.rs`
//! with the PCI config-space read/write interface.
//!
//! # Flow
//!
//! ```text
//! pci_msi_enable()
//!   ├── find_pci_capability() to locate cap
//!   ├── MsiConfig::parse() to read current state
//!   ├── build message address + data
//!   └── write address/data/control registers
//!
//! pci_msix_enable()
//!   ├── MsixConfig::parse() to find table BIR/offset
//!   ├── map BAR memory for the MSI-X table
//!   ├── program each table entry via MMIO
//!   └── set MSI-X enable in Message Control
//! ```
//!
//! Reference: PCI Local Bus Spec 3.0 §6.8; PCIe Base Spec 5.0 §7.7.

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum MSI vectors per device (2^5 = 32).
pub const MSI_MAX_VECTORS: usize = 32;

/// Maximum MSI-X vectors we track per device.
pub const MSIX_MAX_TRACKED: usize = 64;

/// MSI capability ID.
pub const PCI_CAP_ID_MSI: u8 = 0x05;

/// MSI-X capability ID.
pub const PCI_CAP_ID_MSIX: u8 = 0x11;

/// MSI message control: enable bit.
pub const MSI_CTRL_ENABLE: u16 = 1 << 0;

/// MSI message control: 64-bit address capable.
pub const MSI_CTRL_64BIT: u16 = 1 << 7;

/// MSI-X message control: enable bit.
pub const MSIX_CTRL_ENABLE: u16 = 1 << 15;

/// MSI-X message control: function mask.
pub const MSIX_CTRL_FUNC_MASK: u16 = 1 << 14;

/// MSI-X message control: table size mask (bits 10:0).
pub const MSIX_CTRL_TABLE_SIZE: u16 = 0x07FF;

/// MSI-X table entry size (bytes).
pub const MSIX_ENTRY_SIZE: usize = 16;

/// MSI-X vector control: mask bit.
pub const MSIX_VEC_MASKED: u32 = 1 << 0;

/// x86 MSI message address base.
pub const MSI_ADDR_BASE: u32 = 0xFEE0_0000;

/// Destination ID shift in MSI address (bits 19:12).
pub const MSI_DEST_ID_SHIFT: u32 = 12;

// ---------------------------------------------------------------------------
// PciConfigAccess trait
// ---------------------------------------------------------------------------

/// Abstraction over PCI configuration space access.
///
/// Implementations may use port I/O (type 1) or MMIO (ECAM).
pub trait PciConfigAccess {
    /// Read a 16-bit word from PCI config space.
    fn read_u16(&self, bdf: u16, offset: u8) -> u16;
    /// Write a 16-bit word to PCI config space.
    fn write_u16(&self, bdf: u16, offset: u8, val: u16);
    /// Read a 32-bit dword from PCI config space.
    fn read_u32(&self, bdf: u16, offset: u8) -> u32;
    /// Write a 32-bit dword to PCI config space.
    fn write_u32(&self, bdf: u16, offset: u8, val: u32);
}

// ---------------------------------------------------------------------------
// Capability-chain scan
// ---------------------------------------------------------------------------

/// Find the offset of a capability in PCI configuration space.
///
/// Uses the standard capability linked list starting at offset 0x34.
///
/// Returns the capability offset or `None` if not found.
pub fn find_capability<C: PciConfigAccess>(cfg: &C, bdf: u16, cap_id: u8) -> Option<u8> {
    // Status register bit 4: capabilities list present.
    let status = cfg.read_u16(bdf, 0x06);
    if status & (1 << 4) == 0 {
        return None;
    }
    let mut ptr = (cfg.read_u16(bdf, 0x34) & 0xFC) as u8;
    let mut hops = 0u8;
    while ptr >= 0x40 && hops < 48 {
        let id = (cfg.read_u16(bdf, ptr) & 0xFF) as u8;
        if id == cap_id {
            return Some(ptr);
        }
        ptr = ((cfg.read_u16(bdf, ptr) >> 8) & 0xFC) as u8;
        hops += 1;
    }
    None
}

// ---------------------------------------------------------------------------
// MsiSetup
// ---------------------------------------------------------------------------

/// Parameters for programming MSI on a device.
#[derive(Debug, Clone, Copy)]
pub struct MsiSetup {
    /// Destination APIC ID.
    pub dest_apic_id: u8,
    /// Interrupt vector.
    pub vector: u8,
    /// Use logical destination mode (true) or physical (false).
    pub logical: bool,
}

impl MsiSetup {
    /// Build the 32-bit message address.
    pub const fn message_address(&self) -> u32 {
        let mut addr = MSI_ADDR_BASE | ((self.dest_apic_id as u32) << MSI_DEST_ID_SHIFT);
        if self.logical {
            addr |= 1 << 2; // Destination Mode = logical
        }
        addr
    }

    /// Build the 16-bit message data.
    pub const fn message_data(&self) -> u16 {
        self.vector as u16 // Delivery mode Fixed (0)
    }
}

// ---------------------------------------------------------------------------
// pci_msi_enable
// ---------------------------------------------------------------------------

/// Enable MSI on a PCI device.
///
/// Programs the MSI Message Address and Data registers, then sets the
/// enable bit in Message Control.
///
/// # Errors
///
/// Returns [`Error::NotFound`] if the device has no MSI capability.
pub fn pci_msi_enable<C: PciConfigAccess>(cfg: &C, bdf: u16, setup: &MsiSetup) -> Result<()> {
    let cap = find_capability(cfg, bdf, PCI_CAP_ID_MSI).ok_or(Error::NotFound)?;

    // Read Message Control.
    let ctrl = cfg.read_u16(bdf, cap + 2);
    let is_64bit = ctrl & MSI_CTRL_64BIT != 0;

    let addr_lo = setup.message_address();
    let data = setup.message_data();

    // Write address and data.
    cfg.write_u32(bdf, cap + 4, addr_lo);
    if is_64bit {
        cfg.write_u32(bdf, cap + 8, 0); // addr_hi = 0 (below 4 GiB)
        cfg.write_u16(bdf, cap + 12, data);
    } else {
        cfg.write_u16(bdf, cap + 8, data);
    }

    // Enable MSI (clear multi-message enable to 1 vector, set enable bit).
    let new_ctrl = (ctrl & !0x0070) | MSI_CTRL_ENABLE;
    cfg.write_u16(bdf, cap + 2, new_ctrl);
    Ok(())
}

/// Disable MSI on a PCI device.
///
/// Clears the enable bit in Message Control.
pub fn pci_msi_disable<C: PciConfigAccess>(cfg: &C, bdf: u16) {
    if let Some(cap) = find_capability(cfg, bdf, PCI_CAP_ID_MSI) {
        let ctrl = cfg.read_u16(bdf, cap + 2);
        cfg.write_u16(bdf, cap + 2, ctrl & !MSI_CTRL_ENABLE);
    }
}

// ---------------------------------------------------------------------------
// MsixVectorSetup
// ---------------------------------------------------------------------------

/// Per-vector setup for MSI-X.
#[derive(Debug, Clone, Copy, Default)]
pub struct MsixVectorSetup {
    /// Destination APIC ID.
    pub dest_apic_id: u8,
    /// Interrupt vector.
    pub vector: u8,
    /// Use logical destination mode.
    pub logical: bool,
    /// Mask this vector initially.
    pub masked: bool,
}

impl MsixVectorSetup {
    fn addr_lo(&self) -> u32 {
        let mut addr = MSI_ADDR_BASE | ((self.dest_apic_id as u32) << MSI_DEST_ID_SHIFT);
        if self.logical {
            addr |= 1 << 2;
        }
        addr
    }

    const fn data(&self) -> u32 {
        self.vector as u32
    }
}

// ---------------------------------------------------------------------------
// pci_msix_enable
// ---------------------------------------------------------------------------

/// Enable MSI-X on a PCI device.
///
/// Programs each table entry via MMIO and sets the MSI-X enable bit.
///
/// # Parameters
/// - `cfg`: PCI config-space accessor.
/// - `bdf`: Bus/Device/Function.
/// - `table_vaddr`: Virtual address of the mapped MSI-X table.
/// - `vectors`: Slice of per-vector setup parameters.
///
/// # Errors
///
/// Returns [`Error::NotFound`] if the device has no MSI-X capability.
/// Returns [`Error::InvalidArgument`] if `vectors` is empty or exceeds table size.
pub fn pci_msix_enable<C: PciConfigAccess>(
    cfg: &C,
    bdf: u16,
    table_vaddr: u64,
    vectors: &[MsixVectorSetup],
) -> Result<()> {
    if vectors.is_empty() {
        return Err(Error::InvalidArgument);
    }
    let cap = find_capability(cfg, bdf, PCI_CAP_ID_MSIX).ok_or(Error::NotFound)?;

    let ctrl = cfg.read_u16(bdf, cap + 2);
    let table_size = (ctrl & MSIX_CTRL_TABLE_SIZE) as usize + 1;
    if vectors.len() > table_size || vectors.len() > MSIX_MAX_TRACKED {
        return Err(Error::InvalidArgument);
    }

    // Set Function Mask to avoid spurious interrupts during programming.
    cfg.write_u16(bdf, cap + 2, ctrl | MSIX_CTRL_FUNC_MASK);

    for (i, v) in vectors.iter().enumerate() {
        let base = table_vaddr + (i * MSIX_ENTRY_SIZE) as u64;
        // SAFETY: table_vaddr is a caller-mapped MMIO region of the MSI-X table.
        unsafe {
            core::ptr::write_volatile(base as *mut u32, v.addr_lo());
            core::ptr::write_volatile((base + 4) as *mut u32, 0u32);
            core::ptr::write_volatile((base + 8) as *mut u32, v.data());
            let vc: u32 = if v.masked { MSIX_VEC_MASKED } else { 0 };
            core::ptr::write_volatile((base + 12) as *mut u32, vc);
        }
    }

    // Clear Function Mask, set MSI-X Enable.
    let new_ctrl = (ctrl & !MSIX_CTRL_FUNC_MASK) | MSIX_CTRL_ENABLE;
    cfg.write_u16(bdf, cap + 2, new_ctrl);
    Ok(())
}

/// Disable MSI-X on a PCI device.
pub fn pci_msix_disable<C: PciConfigAccess>(cfg: &C, bdf: u16) {
    if let Some(cap) = find_capability(cfg, bdf, PCI_CAP_ID_MSIX) {
        let ctrl = cfg.read_u16(bdf, cap + 2);
        cfg.write_u16(bdf, cap + 2, ctrl & !MSIX_CTRL_ENABLE);
    }
}

/// Mask a single MSI-X vector.
///
/// # Safety
///
/// `table_vaddr` must be the virtual address of the mapped MSI-X table.
/// `entry` must be < the table size.
pub unsafe fn pci_msix_mask_vector(table_vaddr: u64, entry: usize) {
    let ctrl_addr = table_vaddr + (entry * MSIX_ENTRY_SIZE + 12) as u64;
    // SAFETY: Caller guarantees valid MMIO table address and entry bounds.
    unsafe {
        let v = core::ptr::read_volatile(ctrl_addr as *const u32);
        core::ptr::write_volatile(ctrl_addr as *mut u32, v | MSIX_VEC_MASKED);
    }
}

/// Unmask a single MSI-X vector.
///
/// # Safety
///
/// Same as [`pci_msix_mask_vector`].
pub unsafe fn pci_msix_unmask_vector(table_vaddr: u64, entry: usize) {
    let ctrl_addr = table_vaddr + (entry * MSIX_ENTRY_SIZE + 12) as u64;
    // SAFETY: Caller guarantees valid MMIO table address and entry bounds.
    unsafe {
        let v = core::ptr::read_volatile(ctrl_addr as *const u32);
        core::ptr::write_volatile(ctrl_addr as *mut u32, v & !MSIX_VEC_MASKED);
    }
}

// ---------------------------------------------------------------------------
// PciMsiState — device state tracker
// ---------------------------------------------------------------------------

/// Maximum devices with MSI/MSI-X tracked by `PciMsiState`.
const MAX_MSI_STATE_DEVICES: usize = 64;

/// MSI mode enabled on a device.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum MsiMode {
    /// No MSI active.
    #[default]
    None,
    /// Legacy MSI active.
    Msi,
    /// MSI-X active.
    Msix,
}

/// Per-device MSI state record.
#[derive(Debug, Clone, Copy)]
pub struct PciMsiEntry {
    /// PCI BDF.
    pub bdf: u16,
    /// Active MSI mode.
    pub mode: MsiMode,
    /// MSI capability offset in config space (if mode == Msi).
    pub msi_cap_offset: u8,
    /// MSI-X capability offset in config space (if mode == Msix).
    pub msix_cap_offset: u8,
    /// Number of vectors in use.
    pub vector_count: usize,
}

/// Tracker for MSI/MSI-X state across PCI devices.
pub struct PciMsiState {
    entries: [Option<PciMsiEntry>; MAX_MSI_STATE_DEVICES],
    count: usize,
}

impl PciMsiState {
    /// Create an empty state tracker.
    pub const fn new() -> Self {
        const NONE: Option<PciMsiEntry> = None;
        Self {
            entries: [NONE; MAX_MSI_STATE_DEVICES],
            count: 0,
        }
    }

    /// Register a device's MSI state.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the tracker is full.
    pub fn register(&mut self, entry: PciMsiEntry) -> Result<usize> {
        let slot = self
            .entries
            .iter()
            .position(|e| e.is_none())
            .ok_or(Error::OutOfMemory)?;
        self.entries[slot] = Some(entry);
        self.count += 1;
        Ok(slot)
    }

    /// Look up a device by BDF.
    pub fn find(&self, bdf: u16) -> Option<&PciMsiEntry> {
        self.entries.iter().flatten().find(|e| e.bdf == bdf)
    }

    /// Return the number of tracked devices.
    pub const fn len(&self) -> usize {
        self.count
    }

    /// Return `true` if no devices are tracked.
    pub const fn is_empty(&self) -> bool {
        self.count == 0
    }
}

impl Default for PciMsiState {
    fn default() -> Self {
        Self::new()
    }
}
