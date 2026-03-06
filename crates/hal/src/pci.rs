// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! PCI bus enumeration using Configuration Mechanism 1.
//!
//! Provides brute-force scanning of all 256 buses, 32 devices per
//! bus, and 8 functions per device. Configuration space is accessed
//! through I/O ports `0xCF8` (address) and `0xCFC` (data).

use oncrix_lib::{Error, Result};

use crate::power::{inl, outl};

// ── PCI I/O ports ─────────────────────────────────────────────

/// PCI configuration address port (CONFIG_ADDRESS).
const PCI_CONFIG_ADDR: u16 = 0x0CF8;

/// PCI configuration data port (CONFIG_DATA).
const PCI_CONFIG_DATA: u16 = 0x0CFC;

/// Enable bit (bit 31) for PCI configuration address.
const PCI_ENABLE_BIT: u32 = 1 << 31;

/// Invalid PCI vendor ID indicating no device present.
const PCI_VENDOR_INVALID: u16 = 0xFFFF;

/// Maximum number of devices stored by [`PciDeviceList`].
const PCI_MAX_DEVICES: usize = 64;

// ── PCI Address ───────────────────────────────────────────────

/// A PCI bus/device/function address triple.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PciAddress {
    /// Bus number (0–255).
    pub bus: u8,
    /// Device number (0–31).
    pub device: u8,
    /// Function number (0–7).
    pub function: u8,
}

impl PciAddress {
    /// Create a new PCI address.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `device > 31` or
    /// `function > 7`.
    pub fn new(bus: u8, device: u8, function: u8) -> Result<Self> {
        if device > 31 || function > 7 {
            return Err(Error::InvalidArgument);
        }
        Ok(Self {
            bus,
            device,
            function,
        })
    }

    /// Build the 32-bit CONFIG_ADDRESS value for a given register
    /// offset (must be 4-byte aligned).
    fn config_address(self, offset: u8) -> u32 {
        PCI_ENABLE_BIT
            | (u32::from(self.bus) << 16)
            | (u32::from(self.device & 0x1F) << 11)
            | (u32::from(self.function & 0x07) << 8)
            | u32::from(offset & 0xFC)
    }
}

// ── Config-space read / write ─────────────────────────────────

/// Read a 32-bit doubleword from PCI configuration space.
///
/// Uses Mechanism 1 (I/O ports `0xCF8` / `0xCFC`). The `offset`
/// must be 4-byte aligned (bits 1:0 are masked to zero).
///
/// # Errors
///
/// Returns [`Error::InvalidArgument`] if the address components
/// are out of range.
#[cfg(target_arch = "x86_64")]
pub fn pci_config_read_u32(addr: PciAddress, offset: u8) -> u32 {
    outl(PCI_CONFIG_ADDR, addr.config_address(offset));
    inl(PCI_CONFIG_DATA)
}

/// Write a 32-bit doubleword to PCI configuration space.
///
/// Uses Mechanism 1 (I/O ports `0xCF8` / `0xCFC`). The `offset`
/// must be 4-byte aligned (bits 1:0 are masked to zero).
#[cfg(target_arch = "x86_64")]
pub fn pci_config_write_u32(addr: PciAddress, offset: u8, value: u32) {
    outl(PCI_CONFIG_ADDR, addr.config_address(offset));
    outl(PCI_CONFIG_DATA, value);
}

// ── Convenience readers ───────────────────────────────────────

/// Read a 16-bit word from PCI configuration space.
#[cfg(target_arch = "x86_64")]
fn pci_config_read_u16(addr: PciAddress, offset: u8) -> u16 {
    let dword = pci_config_read_u32(addr, offset & 0xFC);
    let shift = ((offset & 2) as u32) * 8;
    (dword >> shift) as u16
}

/// Read an 8-bit byte from PCI configuration space.
#[cfg(target_arch = "x86_64")]
fn pci_config_read_u8(addr: PciAddress, offset: u8) -> u8 {
    let dword = pci_config_read_u32(addr, offset & 0xFC);
    let shift = ((offset & 3) as u32) * 8;
    (dword >> shift) as u8
}

// ── PCI Class ─────────────────────────────────────────────────

/// PCI device class codes (base class).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PciClass {
    /// Pre-PCI 2.0 device (class 0x00).
    Unclassified,
    /// Mass storage controller (class 0x01).
    Storage,
    /// Network controller (class 0x02).
    Network,
    /// Display controller (class 0x03).
    Display,
    /// Multimedia controller (class 0x04).
    Multimedia,
    /// Memory controller (class 0x05).
    Memory,
    /// Bridge device (class 0x06).
    Bridge,
    /// Simple communication controller (class 0x07).
    Serial,
    /// Base system peripheral (class 0x08).
    BaseSystemPeripheral,
    /// Input device controller (class 0x09).
    Input,
    /// Docking station (class 0x0A).
    DockingStation,
    /// Processor (class 0x0B).
    Processor,
    /// Serial bus controller (class 0x0C).
    SerialBus,
    /// Wireless controller (class 0x0D).
    Wireless,
    /// Unknown or unrecognised class code.
    Unknown(u8),
}

impl PciClass {
    /// Convert a raw base-class byte to a [`PciClass`] variant.
    pub fn from_code(code: u8) -> Self {
        match code {
            0x00 => Self::Unclassified,
            0x01 => Self::Storage,
            0x02 => Self::Network,
            0x03 => Self::Display,
            0x04 => Self::Multimedia,
            0x05 => Self::Memory,
            0x06 => Self::Bridge,
            0x07 => Self::Serial,
            0x08 => Self::BaseSystemPeripheral,
            0x09 => Self::Input,
            0x0A => Self::DockingStation,
            0x0B => Self::Processor,
            0x0C => Self::SerialBus,
            0x0D => Self::Wireless,
            other => Self::Unknown(other),
        }
    }
}

// ── PCI BAR ───────────────────────────────────────────────────

/// A PCI Base Address Register (BAR) value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PciBar {
    /// Memory-mapped BAR.
    Memory {
        /// Physical base address.
        base: u64,
        /// Region size in bytes (0 if not yet probed).
        size: u64,
        /// Whether the region is prefetchable.
        prefetchable: bool,
    },
    /// I/O port BAR.
    Io {
        /// I/O port base address.
        port: u32,
        /// Region size in bytes (0 if not yet probed).
        size: u32,
    },
    /// BAR is not present or disabled.
    #[default]
    None,
}

// ── PCI Device ────────────────────────────────────────────────

/// Number of BARs in a standard PCI Type 0 header.
const BAR_COUNT: usize = 6;

/// Describes a discovered PCI device.
#[derive(Debug, Clone, Copy)]
pub struct PciDevice {
    /// Bus/device/function address.
    pub address: PciAddress,
    /// Vendor ID.
    pub vendor_id: u16,
    /// Device ID.
    pub device_id: u16,
    /// Base class code.
    pub class_code: u8,
    /// Sub-class code.
    pub subclass: u8,
    /// Programming interface byte.
    pub prog_if: u8,
    /// Revision ID.
    pub revision: u8,
    /// Header type (bits 6:0), bit 7 = multi-function flag.
    pub header_type: u8,
    /// Base Address Registers (6 for Type 0 headers).
    pub bars: [PciBar; BAR_COUNT],
    /// Interrupt line (from config offset 0x3C).
    pub interrupt_line: u8,
    /// Interrupt pin (from config offset 0x3D).
    pub interrupt_pin: u8,
}

impl PciDevice {
    /// Return the parsed [`PciClass`] for this device.
    pub fn class(&self) -> PciClass {
        PciClass::from_code(self.class_code)
    }

    /// Return `true` if this is a PCI-to-PCI bridge (class 0x06,
    /// subclass 0x04).
    pub fn is_pci_bridge(&self) -> bool {
        self.class_code == 0x06 && self.subclass == 0x04
    }

    /// Return the secondary bus number if this device is a
    /// PCI-to-PCI bridge.
    #[cfg(target_arch = "x86_64")]
    pub fn secondary_bus(&self) -> Option<u8> {
        if self.is_pci_bridge() {
            // Secondary bus number is at config offset 0x19.
            Some(pci_config_read_u8(self.address, 0x19))
        } else {
            None
        }
    }
}

// ── BAR decoding ──────────────────────────────────────────────

/// Offset of the first BAR in the PCI configuration header.
const BAR_OFFSET: u8 = 0x10;

/// Decode all 6 BARs for a Type 0 device.
///
/// For each BAR the function reads the original value, writes
/// all-ones to determine the size, then restores the original.
#[cfg(target_arch = "x86_64")]
fn decode_bars(addr: PciAddress) -> [PciBar; BAR_COUNT] {
    let mut bars = [PciBar::None; BAR_COUNT];
    let mut i = 0usize;
    while i < BAR_COUNT {
        let offset = BAR_OFFSET.wrapping_add((i as u8) << 2);
        let original = pci_config_read_u32(addr, offset);

        if original == 0 {
            i += 1;
            continue;
        }

        let is_io = original & 1 != 0;

        if is_io {
            // I/O BAR
            pci_config_write_u32(addr, offset, 0xFFFF_FFFF);
            let sizing = pci_config_read_u32(addr, offset);
            pci_config_write_u32(addr, offset, original);

            let mask = sizing | 0x03;
            let size = (!mask).wrapping_add(1);
            bars[i] = PciBar::Io {
                port: original & 0xFFFF_FFFC,
                size,
            };
        } else {
            // Memory BAR
            let prefetchable = original & 0x08 != 0;
            let bar_type = (original >> 1) & 0x03;

            pci_config_write_u32(addr, offset, 0xFFFF_FFFF);
            let sizing_lo = pci_config_read_u32(addr, offset);
            pci_config_write_u32(addr, offset, original);

            if bar_type == 0x02 && i + 1 < BAR_COUNT {
                // 64-bit BAR: spans two consecutive BAR slots.
                let next_offset = BAR_OFFSET.wrapping_add(((i + 1) as u8) << 2);
                let original_hi = pci_config_read_u32(addr, next_offset);

                pci_config_write_u32(addr, next_offset, 0xFFFF_FFFF);
                let sizing_hi = pci_config_read_u32(addr, next_offset);
                pci_config_write_u32(addr, next_offset, original_hi);

                let base = (u64::from(original_hi) << 32) | u64::from(original & 0xFFFF_FFF0);
                let sizing_full = (u64::from(sizing_hi) << 32) | u64::from(sizing_lo & 0xFFFF_FFF0);
                let size = (!sizing_full).wrapping_add(1);

                bars[i] = PciBar::Memory {
                    base,
                    size,
                    prefetchable,
                };
                // Next BAR slot is consumed by the upper 32 bits.
                i += 2;
                continue;
            }

            // 32-bit memory BAR.
            let mask = sizing_lo & 0xFFFF_FFF0;
            let size = u64::from((!mask).wrapping_add(1));
            bars[i] = PciBar::Memory {
                base: u64::from(original & 0xFFFF_FFF0),
                size,
                prefetchable,
            };
        }

        i += 1;
    }
    bars
}

// ── Bus scanning ──────────────────────────────────────────────

/// Read a device from a given PCI address, returning `None` if
/// no device is present (vendor ID == `0xFFFF`).
#[cfg(target_arch = "x86_64")]
fn read_device(addr: PciAddress) -> Option<PciDevice> {
    let vendor_id = pci_config_read_u16(addr, 0x00);
    if vendor_id == PCI_VENDOR_INVALID {
        return None;
    }

    let device_id = pci_config_read_u16(addr, 0x02);
    let revision = pci_config_read_u8(addr, 0x08);
    let prog_if = pci_config_read_u8(addr, 0x09);
    let subclass = pci_config_read_u8(addr, 0x0A);
    let class_code = pci_config_read_u8(addr, 0x0B);
    let header_type = pci_config_read_u8(addr, 0x0E);
    let interrupt_line = pci_config_read_u8(addr, 0x3C);
    let interrupt_pin = pci_config_read_u8(addr, 0x3D);

    let bars = if header_type & 0x7F == 0x00 {
        decode_bars(addr)
    } else {
        [PciBar::None; BAR_COUNT]
    };

    Some(PciDevice {
        address: addr,
        vendor_id,
        device_id,
        class_code,
        subclass,
        prog_if,
        revision,
        header_type,
        bars,
        interrupt_line,
        interrupt_pin,
    })
}

/// Enumerate all PCI devices across all 256 buses.
///
/// Performs a brute-force scan of 256 buses x 32 devices x 8
/// functions. Multi-function devices are detected via header
/// type bit 7. Discovered devices are collected into a
/// [`PciDeviceList`].
///
/// # Errors
///
/// Returns [`Error::OutOfMemory`] if more than
/// [`PCI_MAX_DEVICES`] devices are found (the excess devices
/// are silently dropped; the list is still usable).
#[cfg(target_arch = "x86_64")]
pub fn scan_bus() -> Result<PciDeviceList> {
    let mut list = PciDeviceList::new();

    let mut bus: u16 = 0;
    while bus < 256 {
        let mut dev: u8 = 0;
        while dev < 32 {
            scan_device(&mut list, bus as u8, dev);
            dev += 1;
        }
        bus += 1;
    }

    Ok(list)
}

/// Scan a single device slot, checking all functions if
/// multi-function.
#[cfg(target_arch = "x86_64")]
fn scan_device(list: &mut PciDeviceList, bus: u8, device: u8) {
    // SAFETY: device <= 31 and function == 0, so new() cannot
    // fail. We avoid unwrap by constructing directly.
    let addr = PciAddress {
        bus,
        device,
        function: 0,
    };

    let Some(dev) = read_device(addr) else {
        return;
    };

    let multifunction = dev.header_type & 0x80 != 0;
    let _ = list.push(dev);

    if multifunction {
        let mut func: u8 = 1;
        while func < 8 {
            let faddr = PciAddress {
                bus,
                device,
                function: func,
            };
            if let Some(fdev) = read_device(faddr) {
                let _ = list.push(fdev);
            }
            func += 1;
        }
    }
}

// ── PCI Device List ───────────────────────────────────────────

/// A fixed-capacity list of discovered PCI devices.
///
/// Stores up to [`PCI_MAX_DEVICES`] (64) entries with no heap
/// allocation. Provides lookup by class code and vendor/device
/// ID pair.
pub struct PciDeviceList {
    /// Backing storage for device entries.
    devices: [Option<PciDevice>; PCI_MAX_DEVICES],
    /// Number of devices currently stored.
    count: usize,
}

impl Default for PciDeviceList {
    fn default() -> Self {
        Self::new()
    }
}

impl PciDeviceList {
    /// Create an empty device list.
    pub const fn new() -> Self {
        // const-compatible initialisation: None is a ZST variant,
        // so an array of None is valid at compile time.
        const NONE: Option<PciDevice> = None;
        Self {
            devices: [NONE; PCI_MAX_DEVICES],
            count: 0,
        }
    }

    /// Return the number of stored devices.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Return `true` if the list contains no devices.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Add a device to the list.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the list is full.
    pub fn push(&mut self, dev: PciDevice) -> Result<()> {
        if self.count >= PCI_MAX_DEVICES {
            return Err(Error::OutOfMemory);
        }
        self.devices[self.count] = Some(dev);
        self.count += 1;
        Ok(())
    }

    /// Return a reference to the device at `index`, if present.
    pub fn get(&self, index: usize) -> Option<&PciDevice> {
        if index < self.count {
            self.devices[index].as_ref()
        } else {
            None
        }
    }

    /// Find the first device matching a given [`PciClass`].
    pub fn find_by_class(&self, class: PciClass) -> Option<&PciDevice> {
        let mut i = 0;
        while i < self.count {
            if let Some(ref dev) = self.devices[i] {
                if dev.class() == class {
                    return Some(dev);
                }
            }
            i += 1;
        }
        None
    }

    /// Find the first device matching a vendor/device ID pair.
    pub fn find_by_vendor_device(&self, vendor_id: u16, device_id: u16) -> Option<&PciDevice> {
        let mut i = 0;
        while i < self.count {
            if let Some(ref dev) = self.devices[i] {
                if dev.vendor_id == vendor_id && dev.device_id == device_id {
                    return Some(dev);
                }
            }
            i += 1;
        }
        None
    }

    /// Return an iterator over all stored devices.
    pub fn iter(&self) -> PciDeviceIter<'_> {
        PciDeviceIter {
            list: self,
            index: 0,
        }
    }
}

/// Iterator over [`PciDeviceList`] entries.
pub struct PciDeviceIter<'a> {
    /// Reference to the backing list.
    list: &'a PciDeviceList,
    /// Current index.
    index: usize,
}

impl<'a> Iterator for PciDeviceIter<'a> {
    type Item = &'a PciDevice;

    fn next(&mut self) -> Option<Self::Item> {
        while self.index < self.list.count {
            let i = self.index;
            self.index += 1;
            if let Some(ref dev) = self.list.devices[i] {
                return Some(dev);
            }
        }
        None
    }
}
