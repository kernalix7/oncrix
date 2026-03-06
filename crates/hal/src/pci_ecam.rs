// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! PCIe ECAM (Enhanced Configuration Access Mechanism).
//!
//! ECAM maps PCI Express configuration space into physical memory. Each
//! bus/device/function (BDF) gets a 4 KiB window at:
//!
//! ```text
//! base_addr + ((bus << 20) | (device << 15) | (function << 12))
//! ```
//!
//! This allows MMIO access to the full 4096-byte PCIe extended config space,
//! compared to legacy PIO which only reaches the 256-byte traditional space.
//!
//! Reference: PCI Express Base Specification 3.0, §7.2.2 — Enhanced
//! Configuration Access Mechanism (ECAM).

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// ECAM Constants
// ---------------------------------------------------------------------------

/// Size of each BDF configuration window (4 KiB).
pub const ECAM_WINDOW_SIZE: u64 = 4096;

/// Maximum buses per ECAM segment (0–255).
pub const ECAM_MAX_BUS: u8 = 255;
/// Maximum devices per bus (0–31).
pub const ECAM_MAX_DEV: u8 = 31;
/// Maximum functions per device (0–7).
pub const ECAM_MAX_FUNC: u8 = 7;

/// PCI standard config space size (256 bytes).
pub const PCI_CFG_SPACE_SIZE: usize = 256;
/// PCIe extended config space size (4096 bytes).
pub const PCIE_ECAM_SPACE_SIZE: usize = 4096;

// ---------------------------------------------------------------------------
// BDF
// ---------------------------------------------------------------------------

/// PCI Bus/Device/Function identifier.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Bdf {
    /// Bus number (0–255).
    pub bus: u8,
    /// Device number (0–31).
    pub device: u8,
    /// Function number (0–7).
    pub function: u8,
}

impl Bdf {
    /// Creates a new BDF.
    ///
    /// # Errors
    /// Returns `Error::InvalidArgument` if device > 31 or function > 7.
    pub fn new(bus: u8, device: u8, function: u8) -> Result<Self> {
        if device > ECAM_MAX_DEV || function > ECAM_MAX_FUNC {
            return Err(Error::InvalidArgument);
        }
        Ok(Self {
            bus,
            device,
            function,
        })
    }

    /// Creates a BDF without bounds checking.
    pub const fn new_unchecked(bus: u8, device: u8, function: u8) -> Self {
        Self {
            bus,
            device,
            function,
        }
    }

    /// Returns the ECAM segment offset for this BDF.
    pub const fn offset(self) -> u64 {
        ((self.bus as u64) << 20) | ((self.device as u64) << 15) | ((self.function as u64) << 12)
    }

    /// Returns a packed 16-bit BDF value (bus:8, dev:5, func:3).
    pub const fn as_u16(self) -> u16 {
        ((self.bus as u16) << 8) | ((self.device as u16) << 3) | (self.function as u16)
    }
}

impl core::fmt::Display for Bdf {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "{:04x}:{:02x}:{:01x}",
            self.bus, self.device, self.function
        )
    }
}

// ---------------------------------------------------------------------------
// ECAM Region
// ---------------------------------------------------------------------------

/// A single ECAM segment covering a contiguous range of bus numbers.
#[derive(Clone, Copy, Debug)]
pub struct EcamRegion {
    /// Physical base address of the ECAM mapping.
    phys_base: u64,
    /// Virtual base address (after MMIO mapping).
    virt_base: u64,
    /// PCI segment number (typically 0 for systems with one PCIe root complex).
    segment: u16,
    /// First bus covered by this region.
    bus_start: u8,
    /// Last bus covered by this region (inclusive).
    bus_end: u8,
}

impl EcamRegion {
    /// Creates a new ECAM region.
    ///
    /// # Parameters
    /// - `phys_base`: Physical base address from the MCFG ACPI table.
    /// - `virt_base`: Virtual base address after MMIO mapping.
    /// - `segment`: PCI segment/domain number.
    /// - `bus_start`: First bus number.
    /// - `bus_end`: Last bus number (inclusive).
    ///
    /// # Errors
    /// Returns `Error::InvalidArgument` if `bus_end < bus_start`.
    pub fn new(
        phys_base: u64,
        virt_base: u64,
        segment: u16,
        bus_start: u8,
        bus_end: u8,
    ) -> Result<Self> {
        if bus_end < bus_start {
            return Err(Error::InvalidArgument);
        }
        Ok(Self {
            phys_base,
            virt_base,
            segment,
            bus_start,
            bus_end,
        })
    }

    /// Returns the physical base address.
    pub const fn phys_base(&self) -> u64 {
        self.phys_base
    }

    /// Returns the virtual base address.
    pub const fn virt_base(&self) -> u64 {
        self.virt_base
    }

    /// Returns the segment number.
    pub const fn segment(&self) -> u16 {
        self.segment
    }

    /// Returns `true` if the given bus is in this segment's range.
    pub const fn contains_bus(&self, bus: u8) -> bool {
        bus >= self.bus_start && bus <= self.bus_end
    }

    /// Computes the virtual address of the start of a BDF's config window.
    ///
    /// # Errors
    /// Returns `Error::InvalidArgument` if the BDF's bus is outside this region.
    pub fn bdf_virt_addr(&self, bdf: Bdf) -> Result<u64> {
        if !self.contains_bus(bdf.bus) {
            return Err(Error::InvalidArgument);
        }
        Ok(self.virt_base + bdf.offset())
    }
}

// ---------------------------------------------------------------------------
// ECAM Read/Write
// ---------------------------------------------------------------------------

/// Reads an 8-bit value from PCIe extended config space.
///
/// # Safety
/// - `base_virt` must be the correctly mapped ECAM window virtual address.
/// - `offset` must be `< PCIE_ECAM_SPACE_SIZE`.
#[inline]
pub unsafe fn ecam_read8(base_virt: u64, offset: u16) -> u8 {
    let ptr = (base_virt + offset as u64) as *const u8;
    // SAFETY: Caller guarantees a valid ECAM MMIO mapping.
    unsafe { core::ptr::read_volatile(ptr) }
}

/// Reads a 16-bit value from PCIe extended config space.
///
/// # Safety
/// Same as `ecam_read8`. `offset` must be 2-byte aligned.
#[inline]
pub unsafe fn ecam_read16(base_virt: u64, offset: u16) -> u16 {
    let ptr = (base_virt + offset as u64) as *const u16;
    // SAFETY: Caller guarantees aligned ECAM MMIO.
    unsafe { core::ptr::read_volatile(ptr) }
}

/// Reads a 32-bit value from PCIe extended config space.
///
/// # Safety
/// Same as `ecam_read8`. `offset` must be 4-byte aligned.
#[inline]
pub unsafe fn ecam_read32(base_virt: u64, offset: u16) -> u32 {
    let ptr = (base_virt + offset as u64) as *const u32;
    // SAFETY: Caller guarantees aligned ECAM MMIO.
    unsafe { core::ptr::read_volatile(ptr) }
}

/// Writes an 8-bit value to PCIe extended config space.
///
/// # Safety
/// Same as `ecam_read8`.
#[inline]
pub unsafe fn ecam_write8(base_virt: u64, offset: u16, val: u8) {
    let ptr = (base_virt + offset as u64) as *mut u8;
    // SAFETY: Caller guarantees valid ECAM MMIO.
    unsafe { core::ptr::write_volatile(ptr, val) }
}

/// Writes a 16-bit value to PCIe extended config space.
///
/// # Safety
/// Same as `ecam_read16`.
#[inline]
pub unsafe fn ecam_write16(base_virt: u64, offset: u16, val: u16) {
    let ptr = (base_virt + offset as u64) as *mut u16;
    // SAFETY: Caller guarantees aligned ECAM MMIO.
    unsafe { core::ptr::write_volatile(ptr, val) }
}

/// Writes a 32-bit value to PCIe extended config space.
///
/// # Safety
/// Same as `ecam_read32`.
#[inline]
pub unsafe fn ecam_write32(base_virt: u64, offset: u16, val: u32) {
    let ptr = (base_virt + offset as u64) as *mut u32;
    // SAFETY: Caller guarantees aligned ECAM MMIO.
    unsafe { core::ptr::write_volatile(ptr, val) }
}

// ---------------------------------------------------------------------------
// PCI Config Accessor
// ---------------------------------------------------------------------------

/// High-level PCI configuration space accessor for a single BDF.
pub struct PciEcamAccess {
    bdf_virt: u64,
}

impl PciEcamAccess {
    /// Creates an accessor for `bdf` within an ECAM region.
    ///
    /// # Errors
    /// Returns `Error::InvalidArgument` if the BDF is outside the region.
    pub fn new(region: &EcamRegion, bdf: Bdf) -> Result<Self> {
        Ok(Self {
            bdf_virt: region.bdf_virt_addr(bdf)?,
        })
    }

    /// Reads an 8-bit config register.
    ///
    /// # Safety
    /// `offset` must be within the 4 KiB config window.
    pub unsafe fn read8(&self, offset: u16) -> u8 {
        // SAFETY: bdf_virt is a valid ECAM window; offset in range is caller's responsibility.
        unsafe { ecam_read8(self.bdf_virt, offset) }
    }

    /// Reads a 16-bit config register.
    ///
    /// # Safety
    /// `offset` must be 2-byte aligned and within the 4 KiB config window.
    pub unsafe fn read16(&self, offset: u16) -> u16 {
        // SAFETY: Same as read8.
        unsafe { ecam_read16(self.bdf_virt, offset) }
    }

    /// Reads a 32-bit config register.
    ///
    /// # Safety
    /// `offset` must be 4-byte aligned and within the 4 KiB config window.
    pub unsafe fn read32(&self, offset: u16) -> u32 {
        // SAFETY: Same as read8.
        unsafe { ecam_read32(self.bdf_virt, offset) }
    }

    /// Writes an 8-bit config register.
    ///
    /// # Safety
    /// `offset` must be within the 4 KiB config window.
    pub unsafe fn write8(&self, offset: u16, val: u8) {
        // SAFETY: bdf_virt is a valid ECAM window.
        unsafe { ecam_write8(self.bdf_virt, offset, val) }
    }

    /// Writes a 16-bit config register.
    ///
    /// # Safety
    /// `offset` must be 2-byte aligned and within the 4 KiB config window.
    pub unsafe fn write16(&self, offset: u16, val: u16) {
        // SAFETY: Same as write8.
        unsafe { ecam_write16(self.bdf_virt, offset, val) }
    }

    /// Writes a 32-bit config register.
    ///
    /// # Safety
    /// `offset` must be 4-byte aligned and within the 4 KiB config window.
    pub unsafe fn write32(&self, offset: u16, val: u32) {
        // SAFETY: Same as write8.
        unsafe { ecam_write32(self.bdf_virt, offset, val) }
    }

    /// Reads the Vendor ID (offset 0x00).
    ///
    /// # Safety
    /// `bdf_virt` must be a valid ECAM mapping.
    pub unsafe fn vendor_id(&self) -> u16 {
        // SAFETY: Offset 0x00 is always valid and aligned.
        unsafe { self.read16(0x00) }
    }

    /// Reads the Device ID (offset 0x02).
    ///
    /// # Safety
    /// Same as `vendor_id`.
    pub unsafe fn device_id(&self) -> u16 {
        // SAFETY: Offset 0x02 is always valid and aligned.
        unsafe { self.read16(0x02) }
    }

    /// Returns `true` if the device is present (Vendor ID != 0xFFFF).
    ///
    /// # Safety
    /// Same as `vendor_id`.
    pub unsafe fn is_present(&self) -> bool {
        // SAFETY: Reading vendor ID is safe.
        unsafe { self.vendor_id() != 0xFFFF }
    }

    /// Reads the Command register (offset 0x04).
    ///
    /// # Safety
    /// Same as `vendor_id`.
    pub unsafe fn command(&self) -> u16 {
        // SAFETY: Offset 0x04 is always valid.
        unsafe { self.read16(0x04) }
    }

    /// Writes the Command register (offset 0x04).
    ///
    /// # Safety
    /// Same as `vendor_id`.
    pub unsafe fn set_command(&self, val: u16) {
        // SAFETY: Offset 0x04 is always valid.
        unsafe { self.write16(0x04, val) }
    }

    /// Reads the Status register (offset 0x06).
    ///
    /// # Safety
    /// Same as `vendor_id`.
    pub unsafe fn status(&self) -> u16 {
        // SAFETY: Offset 0x06 is always valid.
        unsafe { self.read16(0x06) }
    }
}

// ---------------------------------------------------------------------------
// ECAM Region Registry
// ---------------------------------------------------------------------------

/// Maximum number of ECAM regions (segments).
pub const ECAM_MAX_REGIONS: usize = 8;

/// Registry of known ECAM regions (from ACPI MCFG table).
pub struct EcamRegistry {
    regions: [Option<EcamRegion>; ECAM_MAX_REGIONS],
    count: usize,
}

impl EcamRegistry {
    /// Creates an empty registry.
    pub const fn new() -> Self {
        Self {
            regions: [const { None }; ECAM_MAX_REGIONS],
            count: 0,
        }
    }

    /// Registers an ECAM region.
    ///
    /// # Errors
    /// Returns `Error::InvalidArgument` if the registry is full.
    pub fn register(&mut self, region: EcamRegion) -> Result<()> {
        if self.count >= ECAM_MAX_REGIONS {
            return Err(Error::InvalidArgument);
        }
        self.regions[self.count] = Some(region);
        self.count += 1;
        Ok(())
    }

    /// Looks up the ECAM region for a given segment and bus.
    pub fn find(&self, segment: u16, bus: u8) -> Option<&EcamRegion> {
        for i in 0..self.count {
            if let Some(ref r) = self.regions[i] {
                if r.segment == segment && r.contains_bus(bus) {
                    return Some(r);
                }
            }
        }
        None
    }

    /// Returns the number of registered regions.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Returns `true` if no regions are registered.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
}

impl Default for EcamRegistry {
    fn default() -> Self {
        Self::new()
    }
}
