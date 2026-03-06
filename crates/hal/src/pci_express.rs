// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! PCIe Enhanced Configuration Access Mechanism (ECAM).
//!
//! PCIe ECAM provides direct MMIO access to the full 4 KiB configuration
//! space of each PCIe function, enabling access to extended capabilities
//! beyond the 256-byte legacy PCI space.
//!
//! # Layout
//!
//! The ECAM region base address is segment/bus/device/function encoded:
//! ```text
//! offset = ((bus - start_bus) << 20) | (device << 15) | (function << 12) | register
//! ```
//!
//! # Extended Capabilities
//!
//! PCIe extended capabilities start at config offset 0x100 and use a
//! linked-list structure (DVSEC, AER, SR-IOV, etc.).
//!
//! Reference: PCI Express Base Specification 5.0, Section 7.2 (ECAM)

use oncrix_lib::{Error, Result};

// ── Constants ────────────────────────────────────────────────────────────────

/// Size of the configuration space for a single PCIe function (4 KiB).
const ECAM_FUNC_SIZE: usize = 4096;

/// Starting offset of PCIe extended capabilities.
pub const PCIE_EXT_CAP_OFFSET: u16 = 0x100;

/// Extended capability ID: AER (Advanced Error Reporting).
pub const PCIE_ECAP_ID_AER: u16 = 0x0001;
/// Extended capability ID: Virtual Channel.
pub const PCIE_ECAP_ID_VC: u16 = 0x0002;
/// Extended capability ID: Serial Number.
pub const PCIE_ECAP_ID_SN: u16 = 0x0003;
/// Extended capability ID: Power Budgeting.
pub const PCIE_ECAP_ID_PB: u16 = 0x0004;
/// Extended capability ID: SR-IOV.
pub const PCIE_ECAP_ID_SRIOV: u16 = 0x0010;
/// Extended capability ID: DVSEC.
pub const PCIE_ECAP_ID_DVSEC: u16 = 0x0023;
/// Extended capability ID: Data Link Feature.
pub const PCIE_ECAP_ID_DLF: u16 = 0x0025;
/// Extended capability ID: Physical Layer 16.0 GT/s.
pub const PCIE_ECAP_ID_PL16: u16 = 0x0026;

/// Standard PCIe capability ID: PCIe Capability.
pub const PCI_CAP_ID_PCIE: u8 = 0x10;
/// Standard PCIe capability ID: MSI.
pub const PCI_CAP_ID_MSI: u8 = 0x05;
/// Standard PCIe capability ID: MSI-X.
pub const PCI_CAP_ID_MSIX: u8 = 0x11;

/// PCI config space Vendor ID register offset.
pub const PCI_VENDOR_ID: u16 = 0x00;
/// PCI config space Device ID register offset.
pub const PCI_DEVICE_ID: u16 = 0x02;
/// PCI config space Command register offset.
pub const PCI_COMMAND: u16 = 0x04;
/// PCI config space Status register offset.
pub const PCI_STATUS: u16 = 0x06;
/// PCI config space class/subclass/prog-if.
pub const PCI_CLASS_CODE: u16 = 0x0A;
/// PCI config space Header Type.
pub const PCI_HEADER_TYPE: u16 = 0x0E;
/// PCI config space first capability pointer.
pub const PCI_CAP_PTR: u16 = 0x34;

/// PCI Status: Capabilities List present.
const PCI_STATUS_CAP_LIST: u16 = 1 << 4;

/// Maximum number of ECAM bus segments tracked.
const MAX_ECAM_REGIONS: usize = 8;

// ── EcamRegion ───────────────────────────────────────────────────────────────

/// A single ECAM configuration region covering a contiguous bus range
/// within one PCI segment.
#[derive(Debug, Clone, Copy)]
pub struct EcamRegion {
    /// MMIO base virtual address of the ECAM window.
    pub base: u64,
    /// PCI segment (domain) number.
    pub segment: u16,
    /// First bus number in this region.
    pub start_bus: u8,
    /// Last bus number in this region (inclusive).
    pub end_bus: u8,
    /// Whether this slot is occupied.
    pub valid: bool,
}

impl EcamRegion {
    /// Create a new ECAM region descriptor.
    pub const fn new(base: u64, segment: u16, start_bus: u8, end_bus: u8) -> Self {
        Self {
            base,
            segment,
            start_bus,
            end_bus,
            valid: true,
        }
    }

    /// Compute the byte offset within the ECAM window for the given BDF + register.
    ///
    /// `register` must be 4-byte aligned for 32-bit access.
    pub fn config_offset(&self, bus: u8, device: u8, function: u8, register: u16) -> Option<usize> {
        if bus < self.start_bus || bus > self.end_bus {
            return None;
        }
        if device >= 32 || function >= 8 {
            return None;
        }
        let bus_offset = (bus - self.start_bus) as usize;
        let offset = (bus_offset << 20)
            | ((device as usize) << 15)
            | ((function as usize) << 12)
            | (register as usize & 0xFFF);
        Some(offset)
    }

    /// Compute the virtual address for the given BDF + register.
    fn config_addr(&self, bus: u8, device: u8, function: u8, register: u16) -> Option<u64> {
        self.config_offset(bus, device, function, register)
            .map(|off| self.base + off as u64)
    }

    /// Read a 32-bit configuration register.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if BDF or register is out of range.
    pub fn read32(&self, bus: u8, device: u8, function: u8, register: u16) -> Result<u32> {
        let addr = self
            .config_addr(bus, device, function, register)
            .ok_or(Error::InvalidArgument)?;
        // SAFETY: ECAM MMIO region is mapped and register offset is valid.
        Ok(unsafe { core::ptr::read_volatile(addr as *const u32) })
    }

    /// Write a 32-bit configuration register.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if BDF or register is out of range.
    pub fn write32(
        &self,
        bus: u8,
        device: u8,
        function: u8,
        register: u16,
        value: u32,
    ) -> Result<()> {
        let addr = self
            .config_addr(bus, device, function, register)
            .ok_or(Error::InvalidArgument)?;
        // SAFETY: ECAM MMIO region is mapped and register offset is valid.
        unsafe { core::ptr::write_volatile(addr as *mut u32, value) };
        Ok(())
    }

    /// Read a 16-bit configuration register.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if BDF or register is out of range.
    pub fn read16(&self, bus: u8, device: u8, function: u8, register: u16) -> Result<u16> {
        let base_reg = register & !1;
        let shift = (register & 1) * 8;
        let val32 = self.read32(bus, device, function, base_reg)?;
        Ok((val32 >> shift) as u16)
    }

    /// Write a 16-bit configuration register (read-modify-write).
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if BDF or register is out of range.
    pub fn write16(
        &self,
        bus: u8,
        device: u8,
        function: u8,
        register: u16,
        value: u16,
    ) -> Result<()> {
        let base_reg = register & !1;
        let shift = (register & 1) * 8;
        let old = self.read32(bus, device, function, base_reg)?;
        let mask = !(0xFFFFu32 << shift);
        let new = (old & mask) | ((value as u32) << shift);
        self.write32(bus, device, function, base_reg, new)
    }

    /// Read an 8-bit configuration register.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if BDF or register is out of range.
    pub fn read8(&self, bus: u8, device: u8, function: u8, register: u16) -> Result<u8> {
        let base_reg = register & !3;
        let shift = (register & 3) * 8;
        let val32 = self.read32(bus, device, function, base_reg)?;
        Ok((val32 >> shift) as u8)
    }

    /// Write an 8-bit configuration register (read-modify-write).
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if BDF or register is out of range.
    pub fn write8(
        &self,
        bus: u8,
        device: u8,
        function: u8,
        register: u16,
        value: u8,
    ) -> Result<()> {
        let base_reg = register & !3;
        let shift = (register & 3) * 8;
        let old = self.read32(bus, device, function, base_reg)?;
        let mask = !(0xFFu32 << shift);
        let new = (old & mask) | ((value as u32) << shift);
        self.write32(bus, device, function, base_reg, new)
    }
}

// ── PcieExtCap ───────────────────────────────────────────────────────────────

/// PCIe extended capability header (at each capability in the linked list).
#[derive(Debug, Clone, Copy)]
pub struct PcieExtCap {
    /// Extended capability ID.
    pub cap_id: u16,
    /// Capability version (4 bits).
    pub version: u8,
    /// Offset of the next capability in the linked list (12 bits), or 0.
    pub next_offset: u16,
    /// Byte offset of this capability in config space.
    pub offset: u16,
}

impl PcieExtCap {
    /// Parse an extended capability header from its raw 32-bit DWORD.
    pub fn from_raw(raw: u32, offset: u16) -> Self {
        Self {
            cap_id: (raw & 0xFFFF) as u16,
            version: ((raw >> 16) & 0xF) as u8,
            next_offset: ((raw >> 20) & 0xFFF) as u16,
            offset,
        }
    }

    /// Return whether this is the null terminator (ID=0, version=0).
    pub fn is_null(&self) -> bool {
        self.cap_id == 0 && self.version == 0 && self.next_offset == 0
    }
}

// ── PcieCapIter ──────────────────────────────────────────────────────────────

/// Iterator over PCIe extended capabilities for a single function.
pub struct PcieExtCapIter<'a> {
    region: &'a EcamRegion,
    bus: u8,
    device: u8,
    function: u8,
    /// Current offset in config space.
    offset: u16,
    /// Iteration guard: stop after visiting too many capabilities.
    remaining: u8,
}

impl<'a> PcieExtCapIter<'a> {
    /// Create a new extended capability iterator starting at offset 0x100.
    pub fn new(region: &'a EcamRegion, bus: u8, device: u8, function: u8) -> Self {
        Self {
            region,
            bus,
            device,
            function,
            offset: PCIE_EXT_CAP_OFFSET,
            remaining: 64,
        }
    }
}

impl<'a> Iterator for PcieExtCapIter<'a> {
    type Item = PcieExtCap;

    fn next(&mut self) -> Option<Self::Item> {
        if self.offset < PCIE_EXT_CAP_OFFSET || self.remaining == 0 {
            return None;
        }
        self.remaining -= 1;

        let raw = self
            .region
            .read32(self.bus, self.device, self.function, self.offset)
            .ok()?;
        let cap = PcieExtCap::from_raw(raw, self.offset);

        if cap.is_null() {
            return None;
        }

        // Advance to the next capability.
        self.offset = if cap.next_offset >= PCIE_EXT_CAP_OFFSET {
            cap.next_offset
        } else {
            0
        };

        Some(cap)
    }
}

// ── PcieCapIter (standard capability list) ────────────────────────────────

/// Iterator over the standard PCI capability list (offsets 0x34+).
pub struct PcieCapIter<'a> {
    region: &'a EcamRegion,
    bus: u8,
    device: u8,
    function: u8,
    /// Current pointer offset.
    offset: u8,
    /// Guard against corrupt capability lists.
    remaining: u8,
}

impl<'a> PcieCapIter<'a> {
    /// Create a new standard capability iterator.
    ///
    /// Returns `None` if the device's Status register does not indicate
    /// capability list support.
    pub fn new(region: &'a EcamRegion, bus: u8, device: u8, function: u8) -> Option<Self> {
        let status = region.read16(bus, device, function, PCI_STATUS).ok()?;
        if status & PCI_STATUS_CAP_LIST == 0 {
            return None;
        }
        let ptr = region.read8(bus, device, function, PCI_CAP_PTR).ok()?;
        Some(Self {
            region,
            bus,
            device,
            function,
            offset: ptr & !3,
            remaining: 48,
        })
    }
}

/// A standard PCI capability entry.
#[derive(Debug, Clone, Copy)]
pub struct PcieCap {
    /// Capability ID (e.g., PCI_CAP_ID_PCIE = 0x10).
    pub cap_id: u8,
    /// Pointer to next capability (0 = end of list).
    pub next_ptr: u8,
    /// Offset of this capability header in config space.
    pub offset: u8,
}

impl<'a> Iterator for PcieCapIter<'a> {
    type Item = PcieCap;

    fn next(&mut self) -> Option<Self::Item> {
        if self.offset < 0x40 || self.remaining == 0 {
            return None;
        }
        self.remaining -= 1;

        let raw = self
            .region
            .read16(self.bus, self.device, self.function, self.offset as u16)
            .ok()?;
        let cap_id = (raw & 0xFF) as u8;
        let next_ptr = ((raw >> 8) & 0xFC) as u8;

        let cap = PcieCap {
            cap_id,
            next_ptr,
            offset: self.offset,
        };
        self.offset = if next_ptr >= 0x40 { next_ptr } else { 0 };
        Some(cap)
    }
}

// ── EcamManager ─────────────────────────────────────────────────────────────

/// Global PCIe ECAM region manager.
///
/// Stores up to [`MAX_ECAM_REGIONS`] ECAM windows and provides a unified
/// read/write interface for configuration space access by BDF address.
pub struct EcamManager {
    /// Registered ECAM regions.
    regions: [EcamRegion; MAX_ECAM_REGIONS],
    /// Number of registered regions.
    count: usize,
}

impl EcamManager {
    /// Create an empty ECAM manager.
    pub const fn new() -> Self {
        Self {
            regions: [EcamRegion {
                base: 0,
                segment: 0,
                start_bus: 0,
                end_bus: 0,
                valid: false,
            }; MAX_ECAM_REGIONS],
            count: 0,
        }
    }

    /// Register a new ECAM region.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the registry is full, or
    /// [`Error::InvalidArgument`] if `start_bus > end_bus` or `base` is 0.
    pub fn register(&mut self, base: u64, segment: u16, start_bus: u8, end_bus: u8) -> Result<()> {
        if base == 0 || start_bus > end_bus {
            return Err(Error::InvalidArgument);
        }
        if self.count >= MAX_ECAM_REGIONS {
            return Err(Error::OutOfMemory);
        }
        self.regions[self.count] = EcamRegion::new(base, segment, start_bus, end_bus);
        self.count += 1;
        Ok(())
    }

    /// Find the ECAM region covering the given segment/bus.
    fn find_region(&self, segment: u16, bus: u8) -> Option<&EcamRegion> {
        self.regions[..self.count]
            .iter()
            .find(|r| r.valid && r.segment == segment && bus >= r.start_bus && bus <= r.end_bus)
    }

    /// Read a 32-bit PCIe config space register.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if no ECAM region covers the given address.
    pub fn read32(&self, segment: u16, bus: u8, device: u8, function: u8, reg: u16) -> Result<u32> {
        let region = self.find_region(segment, bus).ok_or(Error::NotFound)?;
        region.read32(bus, device, function, reg)
    }

    /// Write a 32-bit PCIe config space register.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if no ECAM region covers the given address.
    pub fn write32(
        &self,
        segment: u16,
        bus: u8,
        device: u8,
        function: u8,
        reg: u16,
        value: u32,
    ) -> Result<()> {
        let region = self.find_region(segment, bus).ok_or(Error::NotFound)?;
        region.write32(bus, device, function, reg, value)
    }

    /// Read a 16-bit PCIe config space register.
    pub fn read16(&self, segment: u16, bus: u8, device: u8, function: u8, reg: u16) -> Result<u16> {
        let region = self.find_region(segment, bus).ok_or(Error::NotFound)?;
        region.read16(bus, device, function, reg)
    }

    /// Write a 16-bit PCIe config space register.
    pub fn write16(
        &self,
        segment: u16,
        bus: u8,
        device: u8,
        function: u8,
        reg: u16,
        value: u16,
    ) -> Result<()> {
        let region = self.find_region(segment, bus).ok_or(Error::NotFound)?;
        region.write16(bus, device, function, reg, value)
    }

    /// Read an 8-bit PCIe config space register.
    pub fn read8(&self, segment: u16, bus: u8, device: u8, function: u8, reg: u16) -> Result<u8> {
        let region = self.find_region(segment, bus).ok_or(Error::NotFound)?;
        region.read8(bus, device, function, reg)
    }

    /// Write an 8-bit PCIe config space register.
    pub fn write8(
        &self,
        segment: u16,
        bus: u8,
        device: u8,
        function: u8,
        reg: u16,
        value: u8,
    ) -> Result<()> {
        let region = self.find_region(segment, bus).ok_or(Error::NotFound)?;
        region.write8(bus, device, function, reg, value)
    }

    /// Return an iterator over extended capabilities for a PCIe function.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if no ECAM region covers the address.
    pub fn ext_caps(
        &self,
        segment: u16,
        bus: u8,
        device: u8,
        function: u8,
    ) -> Result<PcieExtCapIter<'_>> {
        let region = self.find_region(segment, bus).ok_or(Error::NotFound)?;
        Ok(PcieExtCapIter::new(region, bus, device, function))
    }

    /// Find a specific extended capability by ID.
    ///
    /// Returns the capability descriptor if found, or [`Error::NotFound`].
    pub fn find_ext_cap(
        &self,
        segment: u16,
        bus: u8,
        device: u8,
        function: u8,
        cap_id: u16,
    ) -> Result<PcieExtCap> {
        self.ext_caps(segment, bus, device, function)?
            .find(|c| c.cap_id == cap_id)
            .ok_or(Error::NotFound)
    }

    /// Find a standard PCI capability by ID.
    ///
    /// Returns the capability offset, or [`Error::NotFound`].
    pub fn find_cap(
        &self,
        segment: u16,
        bus: u8,
        device: u8,
        function: u8,
        cap_id: u8,
    ) -> Result<PcieCap> {
        let region = self.find_region(segment, bus).ok_or(Error::NotFound)?;
        PcieCapIter::new(region, bus, device, function)
            .ok_or(Error::NotFound)?
            .find(|c| c.cap_id == cap_id)
            .ok_or(Error::NotFound)
    }

    /// Check whether a PCIe function is present (Vendor ID != 0xFFFF).
    pub fn function_present(&self, segment: u16, bus: u8, device: u8, function: u8) -> bool {
        self.read16(segment, bus, device, function, PCI_VENDOR_ID)
            .map(|vid| vid != 0xFFFF)
            .unwrap_or(false)
    }

    /// Read the class code (24 bits: class/subclass/prog-if).
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the device is not present.
    pub fn class_code(&self, segment: u16, bus: u8, device: u8, function: u8) -> Result<u32> {
        if !self.function_present(segment, bus, device, function) {
            return Err(Error::NotFound);
        }
        let raw = self.read32(segment, bus, device, function, PCI_CLASS_CODE & !3)?;
        Ok((raw >> 8) & 0xFF_FFFF)
    }

    /// Return the size of the ECAM region for a given segment.
    ///
    /// Computed as `(end_bus - start_bus + 1) * 256 * 4096`.
    pub fn region_size(&self, segment: u16) -> usize {
        self.regions[..self.count]
            .iter()
            .filter(|r| r.valid && r.segment == segment)
            .map(|r| (r.end_bus - r.start_bus + 1) as usize * 256 * ECAM_FUNC_SIZE)
            .sum()
    }

    /// Return the number of registered ECAM regions.
    pub fn region_count(&self) -> usize {
        self.count
    }
}

impl Default for EcamManager {
    fn default() -> Self {
        Self::new()
    }
}
