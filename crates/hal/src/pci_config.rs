// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! PCI configuration space access via CAM and ECAM.
//!
//! Provides low-level read/write access to PCI configuration space
//! using both the legacy Configuration Access Mechanism (CAM, I/O
//! ports `0xCF8`/`0xCFC`) and the PCIe Enhanced Configuration
//! Access Mechanism (ECAM, memory-mapped). Also includes:
//!
//! - **Capability enumeration** — walking the PCI capability linked
//!   list to find MSI, MSI-X, PCIe, power management, etc.
//! - **BAR decoding** — determining BAR type, base address, and size
//! - **MSI/MSI-X configuration** — enabling message signaled
//!   interrupts on a device
//!
//! # Usage
//!
//! ```ignore
//! let space = PciConfigSpace::new_cam();
//! let vendor = space.read_config_u16(0, 0, 0, 0x00)?;
//! let caps = space.find_capability(0, 0, 0, PCI_CAP_MSI)?;
//! ```
//!
//! Reference: PCI Local Bus Specification 3.0, PCI Express Base
//! Specification 5.0 (Section 7 — Configuration Space).

use oncrix_lib::{Error, Result};

// ── Constants ───────────────────────────────────────────────────

/// PCI Configuration Address port.
const CAM_ADDR_PORT: u16 = 0x0CF8;

/// PCI Configuration Data port.
const CAM_DATA_PORT: u16 = 0x0CFC;

/// Enable bit (bit 31) for CAM address.
const CAM_ENABLE: u32 = 1 << 31;

/// Invalid vendor ID value indicating no device.
pub const VENDOR_INVALID: u16 = 0xFFFF;

/// Maximum number of capabilities we track per device.
const MAX_CAPABILITIES: usize = 16;

/// Maximum number of BAR entries per device.
const MAX_BARS: usize = 6;

/// Maximum number of devices for which we cache config info.
const MAX_CACHED_DEVICES: usize = 64;

// ── Well-known capability IDs ───────────────────────────────────

/// PCI Power Management capability.
pub const PCI_CAP_PM: u8 = 0x01;

/// AGP capability.
pub const PCI_CAP_AGP: u8 = 0x02;

/// Vital Product Data capability.
pub const PCI_CAP_VPD: u8 = 0x03;

/// Slot Identification capability.
pub const PCI_CAP_SLOT_ID: u8 = 0x04;

/// Message Signaled Interrupts capability.
pub const PCI_CAP_MSI: u8 = 0x05;

/// CompactPCI Hot Swap capability.
pub const PCI_CAP_HOT_SWAP: u8 = 0x06;

/// PCI-X capability.
pub const PCI_CAP_PCIX: u8 = 0x07;

/// HyperTransport capability.
pub const PCI_CAP_HT: u8 = 0x08;

/// Vendor Specific capability.
pub const PCI_CAP_VENDOR: u8 = 0x09;

/// Debug Port capability.
pub const PCI_CAP_DEBUG: u8 = 0x0A;

/// PCI Express capability.
pub const PCI_CAP_PCIE: u8 = 0x10;

/// MSI-X capability.
pub const PCI_CAP_MSIX: u8 = 0x11;

/// SATA Data/Index Configuration capability.
pub const PCI_CAP_SATA: u8 = 0x12;

/// Advanced Features capability.
pub const PCI_CAP_AF: u8 = 0x13;

// ── Standard config register offsets ────────────────────────────

/// Vendor ID register (16-bit, offset 0x00).
pub const CFG_VENDOR_ID: u8 = 0x00;

/// Device ID register (16-bit, offset 0x02).
pub const CFG_DEVICE_ID: u8 = 0x02;

/// Command register (16-bit, offset 0x04).
pub const CFG_COMMAND: u8 = 0x04;

/// Status register (16-bit, offset 0x06).
pub const CFG_STATUS: u8 = 0x06;

/// Revision ID (8-bit, offset 0x08).
pub const CFG_REVISION: u8 = 0x08;

/// Class code — programming interface (offset 0x09).
pub const CFG_PROG_IF: u8 = 0x09;

/// Class code — subclass (offset 0x0A).
pub const CFG_SUBCLASS: u8 = 0x0A;

/// Class code — base class (offset 0x0B).
pub const CFG_CLASS: u8 = 0x0B;

/// Cache line size (offset 0x0C).
pub const CFG_CACHE_LINE: u8 = 0x0C;

/// Header type (offset 0x0E).
pub const CFG_HEADER_TYPE: u8 = 0x0E;

/// First BAR (offset 0x10).
pub const CFG_BAR0: u8 = 0x10;

/// Capabilities pointer (offset 0x34).
pub const CFG_CAP_PTR: u8 = 0x34;

/// Interrupt line (offset 0x3C).
pub const CFG_INT_LINE: u8 = 0x3C;

/// Interrupt pin (offset 0x3D).
pub const CFG_INT_PIN: u8 = 0x3D;

// ── Command register bits ───────────────────────────────────────

/// I/O Space Enable.
pub const CMD_IO_ENABLE: u16 = 1 << 0;

/// Memory Space Enable.
pub const CMD_MEM_ENABLE: u16 = 1 << 1;

/// Bus Master Enable.
pub const CMD_BUS_MASTER: u16 = 1 << 2;

/// Interrupt Disable.
pub const CMD_INT_DISABLE: u16 = 1 << 10;

// ── Status register bits ────────────────────────────────────────

/// Capabilities List — indicates capability pointer at 0x34 is valid.
const STATUS_CAP_LIST: u16 = 1 << 4;

// ── Config Access Mode ──────────────────────────────────────────

/// Configuration space access mechanism.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ConfigAccess {
    /// Legacy CAM via I/O ports 0xCF8/0xCFC.
    #[default]
    Cam,
    /// PCIe ECAM via memory-mapped configuration space.
    Ecam {
        /// Physical base address of the ECAM region.
        base_phys: u64,
        /// Virtual base address (mapped).
        base_virt: u64,
        /// First bus number covered.
        start_bus: u8,
        /// Last bus number covered (inclusive).
        end_bus: u8,
    },
}

// ── PCI Capability ──────────────────────────────────────────────

/// A PCI capability found in the configuration space capability list.
#[derive(Debug, Clone, Copy)]
pub struct PciCapability {
    /// Capability ID.
    pub id: u8,
    /// Offset of this capability in configuration space.
    pub offset: u8,
    /// Raw first dword of the capability (ID + next + data).
    pub header: u32,
}

impl PciCapability {
    /// Create an empty capability entry.
    pub const fn empty() -> Self {
        Self {
            id: 0,
            offset: 0,
            header: 0,
        }
    }
}

// ── PCI BAR ─────────────────────────────────────────────────────

/// Type of a PCI Base Address Register.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PciBarType {
    /// Memory-mapped, 32-bit address.
    Memory32,
    /// Memory-mapped, 64-bit address (spans two BAR slots).
    Memory64,
    /// I/O port BAR.
    Io,
    /// BAR not present or disabled.
    #[default]
    None,
}

/// Decoded PCI Base Address Register.
#[derive(Debug, Clone, Copy)]
pub struct PciBar {
    /// BAR index (0-5).
    pub index: u8,
    /// BAR type.
    pub bar_type: PciBarType,
    /// Base address (physical for memory, port for I/O).
    pub base: u64,
    /// Size of the region in bytes.
    pub size: u64,
    /// Whether the memory region is prefetchable.
    pub prefetchable: bool,
}

impl PciBar {
    /// Create an empty BAR descriptor.
    pub const fn empty() -> Self {
        Self {
            index: 0,
            bar_type: PciBarType::None,
            base: 0,
            size: 0,
            prefetchable: false,
        }
    }
}

// ── PCI Config Space ────────────────────────────────────────────

/// PCI configuration space access interface.
///
/// Supports both legacy CAM (I/O port) and PCIe ECAM (MMIO)
/// access modes. Provides typed read/write operations and higher-
/// level capability enumeration and BAR decoding.
pub struct PciConfigSpace {
    /// Active access mechanism.
    access: ConfigAccess,
    /// Cached capability lists for devices.
    cap_cache: [CachedCaps; MAX_CACHED_DEVICES],
    /// Number of cached capability sets.
    cap_cache_count: usize,
}

/// Cached capability list for a single device.
#[derive(Clone, Copy)]
struct CachedCaps {
    /// BDF address encoded as (bus << 16) | (device << 8) | function.
    bdf: u32,
    /// Capabilities found.
    caps: [PciCapability; MAX_CAPABILITIES],
    /// Number of capabilities.
    count: usize,
}

impl CachedCaps {
    const fn empty() -> Self {
        Self {
            bdf: 0xFFFF_FFFF,
            caps: [const { PciCapability::empty() }; MAX_CAPABILITIES],
            count: 0,
        }
    }
}

impl PciConfigSpace {
    /// Create a PCI config space accessor using legacy CAM.
    pub const fn new_cam() -> Self {
        Self {
            access: ConfigAccess::Cam,
            cap_cache: [const { CachedCaps::empty() }; MAX_CACHED_DEVICES],
            cap_cache_count: 0,
        }
    }

    /// Create a PCI config space accessor using PCIe ECAM.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `base_virt` is zero or
    /// `start_bus > end_bus`.
    pub fn new_ecam(base_phys: u64, base_virt: u64, start_bus: u8, end_bus: u8) -> Result<Self> {
        if base_virt == 0 || start_bus > end_bus {
            return Err(Error::InvalidArgument);
        }
        Ok(Self {
            access: ConfigAccess::Ecam {
                base_phys,
                base_virt,
                start_bus,
                end_bus,
            },
            cap_cache: [const { CachedCaps::empty() }; MAX_CACHED_DEVICES],
            cap_cache_count: 0,
        })
    }

    /// Return the active access mechanism.
    pub fn access_mode(&self) -> ConfigAccess {
        self.access
    }

    // ── Raw configuration reads ─────────────────────────────

    /// Read a 32-bit dword from PCI configuration space.
    ///
    /// The `offset` must be 4-byte aligned.
    pub fn read_config(&self, bus: u8, device: u8, function: u8, offset: u8) -> u32 {
        match self.access {
            ConfigAccess::Cam => self.cam_read32(bus, device, function, offset),
            ConfigAccess::Ecam {
                base_virt,
                start_bus,
                ..
            } => self.ecam_read32(base_virt, start_bus, bus, device, function, offset),
        }
    }

    /// Write a 32-bit dword to PCI configuration space.
    pub fn write_config(&self, bus: u8, device: u8, function: u8, offset: u8, value: u32) {
        match self.access {
            ConfigAccess::Cam => {
                self.cam_write32(bus, device, function, offset, value);
            }
            ConfigAccess::Ecam {
                base_virt,
                start_bus,
                ..
            } => {
                self.ecam_write32(base_virt, start_bus, bus, device, function, offset, value);
            }
        }
    }

    /// Read a 16-bit word from configuration space.
    pub fn read_config_u16(&self, bus: u8, device: u8, function: u8, offset: u8) -> u16 {
        let dword = self.read_config(bus, device, function, offset & 0xFC);
        let shift = u32::from(offset & 2) * 8;
        (dword >> shift) as u16
    }

    /// Read an 8-bit byte from configuration space.
    pub fn read_config_u8(&self, bus: u8, device: u8, function: u8, offset: u8) -> u8 {
        let dword = self.read_config(bus, device, function, offset & 0xFC);
        let shift = u32::from(offset & 3) * 8;
        (dword >> shift) as u8
    }

    /// Write a 16-bit word to configuration space.
    pub fn write_config_u16(&self, bus: u8, device: u8, function: u8, offset: u8, value: u16) {
        let aligned = offset & 0xFC;
        let shift = u32::from(offset & 2) * 8;
        let mask = !(0xFFFFu32 << shift);
        let old = self.read_config(bus, device, function, aligned);
        let new = (old & mask) | (u32::from(value) << shift);
        self.write_config(bus, device, function, aligned, new);
    }

    // ── CAM (I/O port) access ───────────────────────────────

    /// Build a CAM address for the given BDF + offset.
    fn cam_address(bus: u8, device: u8, function: u8, offset: u8) -> u32 {
        CAM_ENABLE
            | (u32::from(bus) << 16)
            | (u32::from(device & 0x1F) << 11)
            | (u32::from(function & 0x07) << 8)
            | u32::from(offset & 0xFC)
    }

    /// CAM read 32-bit.
    #[cfg(target_arch = "x86_64")]
    fn cam_read32(&self, bus: u8, device: u8, function: u8, offset: u8) -> u32 {
        let addr = Self::cam_address(bus, device, function, offset);
        // SAFETY: PCI CAM I/O ports 0xCF8/0xCFC are standard x86
        // configuration mechanism 1 ports.
        unsafe {
            let mut _val: u32;
            core::arch::asm!(
                "out dx, eax",
                in("dx") CAM_ADDR_PORT,
                in("eax") addr,
                options(nostack, preserves_flags),
            );
            core::arch::asm!(
                "in eax, dx",
                in("dx") CAM_DATA_PORT,
                out("eax") _val,
                options(nostack, preserves_flags),
            );
            _val
        }
    }

    /// CAM write 32-bit.
    #[cfg(target_arch = "x86_64")]
    fn cam_write32(&self, bus: u8, device: u8, function: u8, offset: u8, value: u32) {
        let addr = Self::cam_address(bus, device, function, offset);
        // SAFETY: PCI CAM I/O ports 0xCF8/0xCFC are standard x86
        // configuration mechanism 1 ports.
        unsafe {
            core::arch::asm!(
                "out dx, eax",
                in("dx") CAM_ADDR_PORT,
                in("eax") addr,
                options(nostack, preserves_flags),
            );
            core::arch::asm!(
                "out dx, eax",
                in("dx") CAM_DATA_PORT,
                in("eax") value,
                options(nostack, preserves_flags),
            );
        }
    }

    #[cfg(not(target_arch = "x86_64"))]
    fn cam_read32(&self, _bus: u8, _device: u8, _function: u8, _offset: u8) -> u32 {
        0xFFFF_FFFF
    }

    #[cfg(not(target_arch = "x86_64"))]
    fn cam_write32(&self, _bus: u8, _device: u8, _function: u8, _offset: u8, _value: u32) {}

    // ── ECAM (MMIO) access ──────────────────────────────────

    /// Compute ECAM offset for a given BDF + register offset.
    fn ecam_offset(start_bus: u8, bus: u8, device: u8, function: u8, offset: u8) -> u64 {
        let relative_bus = bus.saturating_sub(start_bus) as u64;
        (relative_bus << 20)
            | (u64::from(device & 0x1F) << 15)
            | (u64::from(function & 0x07) << 12)
            | u64::from(offset & 0xFC)
    }

    /// ECAM read 32-bit.
    fn ecam_read32(
        &self,
        base_virt: u64,
        start_bus: u8,
        bus: u8,
        device: u8,
        function: u8,
        offset: u8,
    ) -> u32 {
        let addr = base_virt + Self::ecam_offset(start_bus, bus, device, function, offset);
        // SAFETY: ECAM memory region is mapped into kernel virtual
        // address space during ACPI MCFG processing. The computed
        // offset is within the valid configuration space range.
        unsafe { core::ptr::read_volatile(addr as *const u32) }
    }

    /// ECAM write 32-bit.
    fn ecam_write32(
        &self,
        base_virt: u64,
        start_bus: u8,
        bus: u8,
        device: u8,
        function: u8,
        offset: u8,
        value: u32,
    ) {
        let addr = base_virt + Self::ecam_offset(start_bus, bus, device, function, offset);
        // SAFETY: ECAM memory region is mapped into kernel virtual
        // address space during ACPI MCFG processing.
        unsafe { core::ptr::write_volatile(addr as *mut u32, value) }
    }

    // ── Capability enumeration ──────────────────────────────

    /// Find a PCI capability by ID in the device's capability list.
    ///
    /// Walks the capability linked list starting from the
    /// capabilities pointer at offset `0x34`. Returns the first
    /// capability matching `cap_id`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the capability is not present.
    /// Returns [`Error::InvalidArgument`] if the device has no
    /// capability list (status bit not set).
    pub fn find_capability(
        &self,
        bus: u8,
        device: u8,
        function: u8,
        cap_id: u8,
    ) -> Result<PciCapability> {
        // Check if capabilities list is present.
        let status = self.read_config_u16(bus, device, function, CFG_STATUS);
        if status & STATUS_CAP_LIST == 0 {
            return Err(Error::InvalidArgument);
        }

        let mut ptr = self.read_config_u8(bus, device, function, CFG_CAP_PTR);
        ptr &= 0xFC; // Align to dword.

        let mut iterations = 0u32;
        while ptr != 0 && iterations < 48 {
            let header = self.read_config(bus, device, function, ptr);
            let id = (header & 0xFF) as u8;
            let next = ((header >> 8) & 0xFF) as u8;

            if id == cap_id {
                return Ok(PciCapability {
                    id,
                    offset: ptr,
                    header,
                });
            }

            ptr = next & 0xFC;
            iterations += 1;
        }

        Err(Error::NotFound)
    }

    /// Enumerate all capabilities for a device.
    ///
    /// Returns the number of capabilities found and fills the
    /// output slice.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if the device has no
    /// capability list.
    pub fn enumerate_capabilities(
        &self,
        bus: u8,
        device: u8,
        function: u8,
        out: &mut [PciCapability],
    ) -> Result<usize> {
        let status = self.read_config_u16(bus, device, function, CFG_STATUS);
        if status & STATUS_CAP_LIST == 0 {
            return Err(Error::InvalidArgument);
        }

        let mut ptr = self.read_config_u8(bus, device, function, CFG_CAP_PTR);
        ptr &= 0xFC;

        let mut count = 0usize;
        let mut iterations = 0u32;
        while ptr != 0 && iterations < 48 && count < out.len() {
            let header = self.read_config(bus, device, function, ptr);
            let id = (header & 0xFF) as u8;
            let next = ((header >> 8) & 0xFF) as u8;

            out[count] = PciCapability {
                id,
                offset: ptr,
                header,
            };
            count += 1;

            ptr = next & 0xFC;
            iterations += 1;
        }

        Ok(count)
    }

    // ── BAR decoding ────────────────────────────────────────

    /// Decode a single BAR for a device.
    ///
    /// Reads the BAR, writes all-ones to determine size, then
    /// restores the original value.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `bar_index > 5`.
    pub fn decode_bar(&self, bus: u8, device: u8, function: u8, bar_index: u8) -> Result<PciBar> {
        if bar_index >= MAX_BARS as u8 {
            return Err(Error::InvalidArgument);
        }

        let offset = CFG_BAR0.wrapping_add(bar_index << 2);
        let original = self.read_config(bus, device, function, offset);

        if original == 0 {
            return Ok(PciBar {
                index: bar_index,
                bar_type: PciBarType::None,
                base: 0,
                size: 0,
                prefetchable: false,
            });
        }

        let is_io = original & 1 != 0;

        if is_io {
            // I/O BAR.
            self.write_config(bus, device, function, offset, 0xFFFF_FFFF);
            let sizing = self.read_config(bus, device, function, offset);
            self.write_config(bus, device, function, offset, original);

            let mask = sizing | 0x03;
            let size = (!mask).wrapping_add(1) as u64;

            return Ok(PciBar {
                index: bar_index,
                bar_type: PciBarType::Io,
                base: u64::from(original & 0xFFFF_FFFC),
                size,
                prefetchable: false,
            });
        }

        // Memory BAR.
        let prefetchable = original & 0x08 != 0;
        let mem_type = (original >> 1) & 0x03;

        self.write_config(bus, device, function, offset, 0xFFFF_FFFF);
        let sizing_lo = self.read_config(bus, device, function, offset);
        self.write_config(bus, device, function, offset, original);

        if mem_type == 0x02 && bar_index + 1 < MAX_BARS as u8 {
            // 64-bit BAR.
            let next_offset = CFG_BAR0.wrapping_add((bar_index + 1) << 2);
            let original_hi = self.read_config(bus, device, function, next_offset);

            self.write_config(bus, device, function, next_offset, 0xFFFF_FFFF);
            let sizing_hi = self.read_config(bus, device, function, next_offset);
            self.write_config(bus, device, function, next_offset, original_hi);

            let base = (u64::from(original_hi) << 32) | u64::from(original & 0xFFFF_FFF0);
            let sizing_full = (u64::from(sizing_hi) << 32) | u64::from(sizing_lo & 0xFFFF_FFF0);
            let size = (!sizing_full).wrapping_add(1);

            return Ok(PciBar {
                index: bar_index,
                bar_type: PciBarType::Memory64,
                base,
                size,
                prefetchable,
            });
        }

        // 32-bit memory BAR.
        let mask = sizing_lo & 0xFFFF_FFF0;
        let size = u64::from((!mask).wrapping_add(1));

        Ok(PciBar {
            index: bar_index,
            bar_type: PciBarType::Memory32,
            base: u64::from(original & 0xFFFF_FFF0),
            size,
            prefetchable,
        })
    }

    // ── MSI configuration ───────────────────────────────────

    /// Enable MSI for a device.
    ///
    /// Finds the MSI capability, programs the message address and
    /// data registers, and sets the MSI enable bit.
    ///
    /// # Arguments
    ///
    /// * `addr` — MSI message address (e.g., `0xFEExx000`).
    /// * `data` — MSI message data (vector + delivery mode).
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the device lacks MSI capability.
    pub fn enable_msi(
        &self,
        bus: u8,
        device: u8,
        function: u8,
        addr: u32,
        data: u16,
    ) -> Result<()> {
        let cap = self.find_capability(bus, device, function, PCI_CAP_MSI)?;
        let offset = cap.offset;

        // Read Message Control.
        let msg_ctrl = self.read_config_u16(bus, device, function, offset + 2);

        // Determine if 64-bit address capable (bit 7 of msg_ctrl).
        let is_64bit = msg_ctrl & (1 << 7) != 0;

        // Write message address.
        self.write_config(bus, device, function, offset + 4, addr);

        if is_64bit {
            // Upper 32 bits of address = 0.
            self.write_config(bus, device, function, offset + 8, 0);
            // Write message data.
            self.write_config_u16(bus, device, function, offset + 12, data);
        } else {
            // Write message data.
            self.write_config_u16(bus, device, function, offset + 8, data);
        }

        // Enable MSI (bit 0 of message control).
        // Set requested vectors to 1 (bits 6:4 = 000).
        let new_ctrl = (msg_ctrl & !(0x70)) | 0x01;
        self.write_config_u16(bus, device, function, offset + 2, new_ctrl);

        // Disable legacy interrupts.
        let cmd = self.read_config_u16(bus, device, function, CFG_COMMAND);
        self.write_config_u16(bus, device, function, CFG_COMMAND, cmd | CMD_INT_DISABLE);

        Ok(())
    }

    /// Enable bus mastering for a device.
    pub fn enable_bus_master(&self, bus: u8, device: u8, function: u8) {
        let cmd = self.read_config_u16(bus, device, function, CFG_COMMAND);
        self.write_config_u16(
            bus,
            device,
            function,
            CFG_COMMAND,
            cmd | CMD_BUS_MASTER | CMD_MEM_ENABLE,
        );
    }

    /// Cache capability list for a device.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the cache is full.
    pub fn cache_capabilities(&mut self, bus: u8, device: u8, function: u8) -> Result<()> {
        if self.cap_cache_count >= MAX_CACHED_DEVICES {
            return Err(Error::OutOfMemory);
        }

        let bdf = (u32::from(bus) << 16) | (u32::from(device) << 8) | u32::from(function);

        let mut entry = CachedCaps::empty();
        entry.bdf = bdf;

        let mut caps = [PciCapability::empty(); MAX_CAPABILITIES];
        let count = self
            .enumerate_capabilities(bus, device, function, &mut caps)
            .unwrap_or(0);

        entry.caps[..count].copy_from_slice(&caps[..count]);
        entry.count = count;

        self.cap_cache[self.cap_cache_count] = entry;
        self.cap_cache_count += 1;

        Ok(())
    }

    /// Look up a cached capability for a device.
    pub fn find_cached_capability(
        &self,
        bus: u8,
        device: u8,
        function: u8,
        cap_id: u8,
    ) -> Option<&PciCapability> {
        let bdf = (u32::from(bus) << 16) | (u32::from(device) << 8) | u32::from(function);

        for i in 0..self.cap_cache_count {
            if self.cap_cache[i].bdf == bdf {
                for j in 0..self.cap_cache[i].count {
                    if self.cap_cache[i].caps[j].id == cap_id {
                        return Some(&self.cap_cache[i].caps[j]);
                    }
                }
                return None;
            }
        }
        None
    }
}

impl Default for PciConfigSpace {
    fn default() -> Self {
        Self::new_cam()
    }
}
