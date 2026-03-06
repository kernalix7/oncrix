// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! MSI (Message Signaled Interrupts) and MSI-X support.
//!
//! Modern PCI/PCIe devices use MSI/MSI-X instead of legacy pin-based
//! interrupts. This module provides structures and helpers for
//! configuring MSI and MSI-X capabilities on PCI devices.
//!
//! # MSI vs MSI-X
//!
//! | Feature    | MSI            | MSI-X          |
//! |------------|----------------|----------------|
//! | Vectors    | 1–32           | 1–2048         |
//! | Table      | In config space| BAR-based      |
//! | Masking    | Per-vector opt.| Per-vector     |
//! | Steering   | Limited        | Full per-vector|
//!
//! Reference: PCI Local Bus Specification 3.0, PCI Express 5.0.

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// PCI capability ID for MSI.
pub const PCI_CAP_MSI: u8 = 0x05;

/// PCI capability ID for MSI-X.
pub const PCI_CAP_MSIX: u8 = 0x11;

/// MSI message address base for x86 (0xFEE00000).
const MSI_ADDR_BASE: u32 = 0xFEE0_0000;

/// MSI address: destination APIC ID shift.
const MSI_ADDR_DEST_SHIFT: u32 = 12;

/// MSI address: redirection hint bit.
const MSI_ADDR_REDIRECT_HINT: u32 = 1 << 3;

/// MSI address: destination mode (0=physical, 1=logical).
const MSI_ADDR_DEST_MODE_LOGICAL: u32 = 1 << 2;

/// MSI data: delivery mode shift.
const MSI_DATA_DELIVERY_SHIFT: u32 = 8;

/// MSI data: trigger mode (0=edge, 1=level).
const _MSI_DATA_TRIGGER_LEVEL: u32 = 1 << 15;

/// MSI data: level assert.
const _MSI_DATA_LEVEL_ASSERT: u32 = 1 << 14;

/// Maximum MSI vectors per device.
pub const MSI_MAX_VECTORS: usize = 32;

/// Maximum MSI-X table entries.
pub const MSIX_MAX_VECTORS: usize = 2048;

/// Maximum MSI-X entries we track per device.
const MSIX_TRACKED_MAX: usize = 64;

/// Maximum devices with MSI/MSI-X.
const MAX_MSI_DEVICES: usize = 32;

// ---------------------------------------------------------------------------
// MSI Delivery Mode
// ---------------------------------------------------------------------------

/// MSI/MSI-X delivery mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
#[derive(Default)]
pub enum DeliveryMode {
    /// Fixed delivery to specified APIC(s).
    #[default]
    Fixed = 0,
    /// Lowest priority delivery.
    LowestPriority = 1,
    /// System Management Interrupt.
    Smi = 2,
    /// Non-Maskable Interrupt.
    Nmi = 4,
    /// INIT signal.
    Init = 5,
    /// External interrupt (ExtINT).
    ExtInt = 7,
}

// ---------------------------------------------------------------------------
// MSI Address/Data
// ---------------------------------------------------------------------------

/// MSI message (address + data pair).
///
/// On x86_64, the address encodes the destination APIC ID and
/// the data encodes the vector and delivery mode.
#[derive(Debug, Clone, Copy, Default)]
pub struct MsiMessage {
    /// Message address (written to MSI address register).
    pub address: u64,
    /// Message data (written to MSI data register).
    pub data: u32,
}

impl MsiMessage {
    /// Build an MSI message for x86_64.
    ///
    /// `dest_apic_id` is the target Local APIC ID.
    /// `vector` is the interrupt vector number (32–255).
    /// `delivery` is the delivery mode.
    /// `logical` selects logical (true) vs physical (false) dest mode.
    pub fn new(dest_apic_id: u8, vector: u8, delivery: DeliveryMode, logical: bool) -> Self {
        let mut addr = MSI_ADDR_BASE;
        addr |= (dest_apic_id as u32) << MSI_ADDR_DEST_SHIFT;
        if logical {
            addr |= MSI_ADDR_DEST_MODE_LOGICAL;
        }

        let data = (vector as u32) | ((delivery as u32) << MSI_DATA_DELIVERY_SHIFT);

        Self {
            address: addr as u64,
            data,
        }
    }

    /// Build an MSI message with lowest-priority delivery and
    /// redirection hint (for load balancing across CPUs).
    pub fn lowest_priority(vector: u8) -> Self {
        let addr = MSI_ADDR_BASE | MSI_ADDR_REDIRECT_HINT | MSI_ADDR_DEST_MODE_LOGICAL;

        let data =
            (vector as u32) | ((DeliveryMode::LowestPriority as u32) << MSI_DATA_DELIVERY_SHIFT);

        Self {
            address: addr as u64,
            data,
        }
    }
}

// ---------------------------------------------------------------------------
// MSI Capability
// ---------------------------------------------------------------------------

/// MSI capability state for a PCI device.
#[derive(Debug, Clone, Copy)]
pub struct MsiCapability {
    /// Capability offset in PCI config space.
    pub cap_offset: u8,
    /// Message Control register value.
    pub msg_control: u16,
    /// Number of requested vectors (log2).
    pub multi_msg_capable: u8,
    /// Number of enabled vectors (log2).
    pub multi_msg_enable: u8,
    /// Whether 64-bit addressing is supported.
    pub is_64bit: bool,
    /// Whether per-vector masking is supported.
    pub per_vector_mask: bool,
    /// Whether MSI is enabled.
    pub enabled: bool,
    /// Configured message.
    pub message: MsiMessage,
}

impl MsiCapability {
    /// Parse MSI capability from message control register.
    pub fn from_msg_control(cap_offset: u8, msg_control: u16) -> Self {
        Self {
            cap_offset,
            msg_control,
            multi_msg_capable: ((msg_control >> 1) & 0x7) as u8,
            multi_msg_enable: ((msg_control >> 4) & 0x7) as u8,
            is_64bit: (msg_control & (1 << 7)) != 0,
            per_vector_mask: (msg_control & (1 << 8)) != 0,
            enabled: (msg_control & 1) != 0,
            message: MsiMessage::default(),
        }
    }

    /// Returns the maximum number of vectors this device supports.
    pub fn max_vectors(&self) -> usize {
        1 << self.multi_msg_capable
    }

    /// Returns the number of currently enabled vectors.
    pub fn enabled_vectors(&self) -> usize {
        1 << self.multi_msg_enable
    }
}

// ---------------------------------------------------------------------------
// MSI-X Table Entry
// ---------------------------------------------------------------------------

/// A single MSI-X table entry (16 bytes in BAR memory).
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct MsixTableEntry {
    /// Message address (lower 32 bits).
    pub addr_lo: u32,
    /// Message address (upper 32 bits).
    pub addr_hi: u32,
    /// Message data.
    pub data: u32,
    /// Vector control (bit 0 = masked).
    pub vector_control: u32,
}

impl MsixTableEntry {
    /// Returns `true` if this vector is masked.
    pub fn is_masked(&self) -> bool {
        self.vector_control & 1 != 0
    }

    /// Set the mask bit.
    pub fn set_masked(&mut self, masked: bool) {
        if masked {
            self.vector_control |= 1;
        } else {
            self.vector_control &= !1;
        }
    }

    /// Set the message from an [`MsiMessage`].
    pub fn set_message(&mut self, msg: &MsiMessage) {
        self.addr_lo = msg.address as u32;
        self.addr_hi = (msg.address >> 32) as u32;
        self.data = msg.data;
    }

    /// Get the full 64-bit message address.
    pub fn address(&self) -> u64 {
        (self.addr_hi as u64) << 32 | self.addr_lo as u64
    }
}

// ---------------------------------------------------------------------------
// MSI-X Capability
// ---------------------------------------------------------------------------

/// MSI-X capability state for a PCI device.
#[derive(Debug, Clone, Copy)]
pub struct MsixCapability {
    /// Capability offset in PCI config space.
    pub cap_offset: u8,
    /// Table size (number of entries - 1, from Message Control).
    pub table_size: u16,
    /// BAR index for the MSI-X table.
    pub table_bir: u8,
    /// Offset within the BAR for the table.
    pub table_offset: u32,
    /// BAR index for the PBA (Pending Bit Array).
    pub pba_bir: u8,
    /// Offset within the BAR for the PBA.
    pub pba_offset: u32,
    /// Whether MSI-X is enabled.
    pub enabled: bool,
    /// Whether function mask is active.
    pub function_mask: bool,
    /// Configured table entries (tracked subset).
    pub entries: [MsixTableEntry; MSIX_TRACKED_MAX],
    /// Number of configured entries.
    pub configured_count: usize,
}

impl MsixCapability {
    /// Parse MSI-X capability from config space values.
    pub fn from_config(cap_offset: u8, msg_control: u16, table_reg: u32, pba_reg: u32) -> Self {
        Self {
            cap_offset,
            table_size: msg_control & 0x7FF,
            table_bir: (table_reg & 0x7) as u8,
            table_offset: table_reg & !0x7,
            pba_bir: (pba_reg & 0x7) as u8,
            pba_offset: pba_reg & !0x7,
            enabled: (msg_control & (1 << 15)) != 0,
            function_mask: (msg_control & (1 << 14)) != 0,
            entries: [MsixTableEntry::default(); MSIX_TRACKED_MAX],
            configured_count: 0,
        }
    }

    /// Returns the total number of MSI-X vectors (table_size + 1).
    pub fn max_vectors(&self) -> usize {
        (self.table_size as usize) + 1
    }

    /// Configure a vector entry.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `index` is out of range.
    pub fn configure_vector(&mut self, index: usize, msg: &MsiMessage) -> Result<()> {
        if index >= self.max_vectors() || index >= MSIX_TRACKED_MAX {
            return Err(Error::InvalidArgument);
        }
        self.entries[index].set_message(msg);
        self.entries[index].set_masked(false);
        if index >= self.configured_count {
            self.configured_count = index + 1;
        }
        Ok(())
    }

    /// Mask a specific vector.
    pub fn mask_vector(&mut self, index: usize) -> Result<()> {
        if index >= MSIX_TRACKED_MAX {
            return Err(Error::InvalidArgument);
        }
        self.entries[index].set_masked(true);
        Ok(())
    }

    /// Unmask a specific vector.
    pub fn unmask_vector(&mut self, index: usize) -> Result<()> {
        if index >= MSIX_TRACKED_MAX {
            return Err(Error::InvalidArgument);
        }
        self.entries[index].set_masked(false);
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// MSI Device Registry
// ---------------------------------------------------------------------------

/// Tracks PCI devices with MSI/MSI-X capabilities.
pub struct MsiDeviceRegistry {
    /// Registered devices.
    entries: [Option<MsiDeviceEntry>; MAX_MSI_DEVICES],
    /// Number of registered devices.
    count: usize,
}

/// A device with MSI or MSI-X capability.
#[derive(Debug, Clone, Copy)]
pub struct MsiDeviceEntry {
    /// PCI bus/device/function.
    pub bdf: u16,
    /// MSI capability (if present).
    pub msi: Option<MsiCapability>,
    /// MSI-X capability (if present).
    pub msix: Option<MsixCapability>,
}

impl MsiDeviceRegistry {
    /// Create an empty registry.
    pub const fn new() -> Self {
        const NONE: Option<MsiDeviceEntry> = None;
        Self {
            entries: [NONE; MAX_MSI_DEVICES],
            count: 0,
        }
    }

    /// Register a device with MSI capability.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the registry is full.
    pub fn register(
        &mut self,
        bdf: u16,
        msi: Option<MsiCapability>,
        msix: Option<MsixCapability>,
    ) -> Result<usize> {
        let idx = self
            .entries
            .iter()
            .position(|e| e.is_none())
            .ok_or(Error::OutOfMemory)?;
        self.entries[idx] = Some(MsiDeviceEntry { bdf, msi, msix });
        self.count += 1;
        Ok(idx)
    }

    /// Look up a device by BDF.
    pub fn lookup(&self, bdf: u16) -> Option<&MsiDeviceEntry> {
        self.entries.iter().flatten().find(|e| e.bdf == bdf)
    }

    /// Returns the number of registered devices.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Returns `true` if no devices are registered.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
}

impl Default for MsiDeviceRegistry {
    fn default() -> Self {
        Self::new()
    }
}
