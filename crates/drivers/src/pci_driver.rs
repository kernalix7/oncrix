// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! PCI device driver matching and probe framework.
//!
//! This module provides the infrastructure for registering PCI drivers and
//! matching them against enumerated PCI devices. The model follows the Linux
//! kernel's `pci_driver` pattern:
//!
//! 1. A driver registers an ID table of `(vendor, device)` pairs it handles.
//! 2. During PCI enumeration, each discovered device is matched against all
//!    registered drivers.
//! 3. The matching driver's `probe()` function is called.
//! 4. On device removal, `remove()` is called.
//!
//! Reference: PCI Local Bus Specification 3.0, §6 — Configuration Space.

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// PCI Device Identity
// ---------------------------------------------------------------------------

/// Wildcard Vendor/Device ID (matches any value when used in an ID table).
pub const PCI_ANY_ID: u16 = 0xFFFF;

/// PCI device identifier.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PciId {
    /// Vendor ID (0xFFFF = wildcard).
    pub vendor: u16,
    /// Device ID (0xFFFF = wildcard).
    pub device: u16,
    /// Subsystem Vendor ID (0xFFFF = don't care).
    pub subvendor: u16,
    /// Subsystem Device ID (0xFFFF = don't care).
    pub subdevice: u16,
    /// PCI class code (bits 23:8 = class/subclass; 0 = don't care).
    pub class: u32,
    /// Class mask (bits that must match in `class`; 0 = ignore all).
    pub class_mask: u32,
}

impl PciId {
    /// Creates a PCI ID matching a specific vendor and device.
    pub const fn vid_did(vendor: u16, device: u16) -> Self {
        Self {
            vendor,
            device,
            subvendor: PCI_ANY_ID,
            subdevice: PCI_ANY_ID,
            class: 0,
            class_mask: 0,
        }
    }

    /// Creates a PCI ID matching any device of a specific class.
    pub const fn class(class: u32, class_mask: u32) -> Self {
        Self {
            vendor: PCI_ANY_ID,
            device: PCI_ANY_ID,
            subvendor: PCI_ANY_ID,
            subdevice: PCI_ANY_ID,
            class,
            class_mask,
        }
    }

    /// Returns `true` if this ID matches the given device attributes.
    pub const fn matches(
        &self,
        vendor: u16,
        device: u16,
        subvendor: u16,
        subdevice: u16,
        class: u32,
    ) -> bool {
        (self.vendor == PCI_ANY_ID || self.vendor == vendor)
            && (self.device == PCI_ANY_ID || self.device == device)
            && (self.subvendor == PCI_ANY_ID || self.subvendor == subvendor)
            && (self.subdevice == PCI_ANY_ID || self.subdevice == subdevice)
            && (self.class_mask == 0 || (class & self.class_mask) == (self.class & self.class_mask))
    }
}

// ---------------------------------------------------------------------------
// PCI Device Info
// ---------------------------------------------------------------------------

/// Snapshot of a PCI device's configuration as discovered during enumeration.
#[derive(Clone, Copy, Debug, Default)]
pub struct PciDeviceInfo {
    /// Bus number.
    pub bus: u8,
    /// Device number.
    pub device: u8,
    /// Function number.
    pub function: u8,
    /// Vendor ID.
    pub vendor: u16,
    /// Device ID.
    pub device_id: u16,
    /// Subsystem Vendor ID.
    pub subvendor: u16,
    /// Subsystem Device ID.
    pub subdevice: u16,
    /// Class code (24-bit).
    pub class: u32,
    /// Revision ID.
    pub revision: u8,
    /// Interrupt line.
    pub irq: u8,
    /// ECAM/MMIO base for BAR0.
    pub bar0: u64,
    /// BAR0 size.
    pub bar0_size: u64,
    /// BAR1 base address.
    pub bar1: u64,
    /// BAR1 size.
    pub bar1_size: u64,
    /// Virtual base used to access config space (ECAM).
    pub config_base: u64,
}

impl PciDeviceInfo {
    /// Returns a BDF string representation.
    pub fn bdf_str(&self) -> [u8; 8] {
        let mut s = [b'?'; 8];
        let hex = b"0123456789ABCDEF";
        s[0] = hex[(self.bus >> 4) as usize];
        s[1] = hex[(self.bus & 0xF) as usize];
        s[2] = b':';
        s[3] = hex[(self.device >> 4) as usize];
        s[4] = hex[(self.device & 0xF) as usize];
        s[5] = b'.';
        s[6] = hex[(self.function & 0xF) as usize];
        s[7] = 0;
        s
    }
}

// ---------------------------------------------------------------------------
// Driver Descriptor
// ---------------------------------------------------------------------------

/// Maximum number of PCI IDs a single driver can match.
pub const MAX_ID_TABLE: usize = 32;

/// A PCI driver descriptor.
///
/// Drivers fill in the `id_table` and provide a `probe` callback.
/// Registration via [`PciDriverRegistry`] is then used to match devices.
pub struct PciDriver {
    /// Human-readable name (null-terminated ASCII, max 63 chars).
    pub name: &'static [u8],
    /// ID table (entries with `vendor == 0` terminate the list).
    pub id_table: &'static [PciId],
    /// Probe callback: called when a matching device is found.
    ///
    /// # Parameters
    /// - `dev`: Device information.
    /// - `id`: The matching PCI ID entry.
    ///
    /// # Returns
    /// `Ok(())` on success; `Err` causes the driver to be unloaded.
    pub probe: fn(dev: &PciDeviceInfo, id: &PciId) -> Result<()>,
    /// Remove callback: called when the device is removed.
    pub remove: fn(dev: &PciDeviceInfo),
}

// ---------------------------------------------------------------------------
// PCI Driver Registry
// ---------------------------------------------------------------------------

/// Maximum number of registered PCI drivers.
pub const MAX_PCI_DRIVERS: usize = 64;

/// Central registry of all PCI drivers.
pub struct PciDriverRegistry {
    drivers: [Option<&'static PciDriver>; MAX_PCI_DRIVERS],
    count: usize,
}

impl PciDriverRegistry {
    /// Creates an empty driver registry.
    pub const fn new() -> Self {
        Self {
            drivers: [const { None }; MAX_PCI_DRIVERS],
            count: 0,
        }
    }

    /// Registers a PCI driver.
    ///
    /// # Errors
    /// Returns `Error::InvalidArgument` if the registry is full.
    pub fn register(&mut self, driver: &'static PciDriver) -> Result<()> {
        if self.count >= MAX_PCI_DRIVERS {
            return Err(Error::InvalidArgument);
        }
        self.drivers[self.count] = Some(driver);
        self.count += 1;
        Ok(())
    }

    /// Probes a device against all registered drivers.
    ///
    /// Iterates all drivers and all ID table entries. Calls `probe` on the
    /// first matching driver. Only one driver is loaded per device.
    ///
    /// # Returns
    /// `Ok(true)` if a driver was matched and probed successfully.
    /// `Ok(false)` if no driver matched.
    /// `Err` if a matching driver's `probe()` returned an error.
    pub fn probe_device(&self, dev: &PciDeviceInfo) -> Result<bool> {
        for i in 0..self.count {
            let drv = match &self.drivers[i] {
                Some(d) => *d,
                None => continue,
            };
            for id in drv.id_table {
                if id.matches(
                    dev.vendor,
                    dev.device_id,
                    dev.subvendor,
                    dev.subdevice,
                    dev.class,
                ) {
                    (drv.probe)(dev, id)?;
                    return Ok(true);
                }
            }
        }
        Ok(false)
    }

    /// Notifies drivers that a device has been removed.
    ///
    /// Calls `remove()` on any driver that previously matched `dev`.
    pub fn remove_device(&self, dev: &PciDeviceInfo) {
        for i in 0..self.count {
            let drv = match &self.drivers[i] {
                Some(d) => *d,
                None => continue,
            };
            for id in drv.id_table {
                if id.matches(
                    dev.vendor,
                    dev.device_id,
                    dev.subvendor,
                    dev.subdevice,
                    dev.class,
                ) {
                    (drv.remove)(dev);
                    return;
                }
            }
        }
    }

    /// Returns the number of registered drivers.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Returns `true` if no drivers are registered.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
}

impl Default for PciDriverRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// PCI Command / Status Register Helpers
// ---------------------------------------------------------------------------

/// PCI Command register bit: I/O Space enable.
pub const PCI_CMD_IO_SPACE: u16 = 1 << 0;
/// PCI Command register bit: Memory Space enable.
pub const PCI_CMD_MEM_SPACE: u16 = 1 << 1;
/// PCI Command register bit: Bus Master enable.
pub const PCI_CMD_BUS_MASTER: u16 = 1 << 2;
/// PCI Command register bit: Interrupt Disable.
pub const PCI_CMD_INTX_DISABLE: u16 = 1 << 10;

/// PCI Config Space offsets.
pub mod cfg_offset {
    /// Vendor ID.
    pub const VENDOR_ID: u16 = 0x00;
    /// Device ID.
    pub const DEVICE_ID: u16 = 0x02;
    /// Command register.
    pub const COMMAND: u16 = 0x04;
    /// Status register.
    pub const STATUS: u16 = 0x06;
    /// Revision ID.
    pub const REVISION: u16 = 0x08;
    /// Class code (24-bit, read as u32 at offset 0x08, bits 31:8).
    pub const CLASS_CODE: u16 = 0x09;
    /// Cache Line Size.
    pub const CACHE_LINE: u16 = 0x0C;
    /// Header Type.
    pub const HEADER_TYPE: u16 = 0x0E;
    /// BAR0.
    pub const BAR0: u16 = 0x10;
    /// BAR1.
    pub const BAR1: u16 = 0x14;
    /// BAR2.
    pub const BAR2: u16 = 0x18;
    /// BAR3.
    pub const BAR3: u16 = 0x1C;
    /// BAR4.
    pub const BAR4: u16 = 0x20;
    /// BAR5.
    pub const BAR5: u16 = 0x24;
    /// Subsystem Vendor ID.
    pub const SUBSYSTEM_VENDOR: u16 = 0x2C;
    /// Subsystem Device ID.
    pub const SUBSYSTEM_ID: u16 = 0x2E;
    /// Capabilities Pointer.
    pub const CAP_PTR: u16 = 0x34;
    /// Interrupt Line.
    pub const IRQ_LINE: u16 = 0x3C;
    /// Interrupt Pin.
    pub const IRQ_PIN: u16 = 0x3D;
}

/// PCI class codes (upper byte of the 24-bit class code).
pub mod pci_class {
    /// Mass storage controller.
    pub const STORAGE: u32 = 0x01;
    /// Network controller.
    pub const NETWORK: u32 = 0x02;
    /// Display controller.
    pub const DISPLAY: u32 = 0x03;
    /// Multimedia controller.
    pub const MULTIMEDIA: u32 = 0x04;
    /// Memory controller.
    pub const MEMORY: u32 = 0x05;
    /// Bridge device.
    pub const BRIDGE: u32 = 0x06;
    /// Serial bus controller.
    pub const SERIAL: u32 = 0x0C;
}

/// PCI storage subclass codes.
pub mod pci_subclass_storage {
    /// NVM Express.
    pub const NVME: u32 = 0x08;
    /// SATA AHCI.
    pub const SATA: u32 = 0x06;
    /// ATA.
    pub const ATA: u32 = 0x01;
}

/// PCI serial bus subclass codes.
pub mod pci_subclass_serial {
    /// USB XHCI.
    pub const USB_XHCI: u32 = 0x30;
    /// USB EHCI.
    pub const USB_EHCI: u32 = 0x20;
    /// USB OHCI.
    pub const USB_OHCI: u32 = 0x10;
}

/// Reads a BAR and determines if it is 64-bit MMIO.
///
/// Returns `(base_address, is_64bit, is_io_space)`.
pub fn decode_bar(bar_value: u32, bar_high: u32) -> (u64, bool, bool) {
    let is_io = bar_value & 1 != 0;
    if is_io {
        return ((bar_value & !3) as u64, false, true);
    }
    let bar_type = (bar_value >> 1) & 3;
    let is_64bit = bar_type == 2;
    let base = if is_64bit {
        ((bar_high as u64) << 32) | (bar_value & !0xF) as u64
    } else {
        (bar_value & !0xF) as u64
    };
    (base, is_64bit, false)
}
