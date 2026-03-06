// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! PCI configuration space access — type 0/1 headers, capability scanning,
//! and BAR programming.
//!
//! # PCI Configuration Space Overview
//!
//! Each PCI function exposes 256 bytes (or 4 KiB for PCIe) of configuration
//! space. The first 64 bytes form a standard header common to all functions.
//! The remaining space is split between device-specific registers and a
//! capability linked list.
//!
//! ## Header Types
//!
//! - **Type 0** — endpoint device. Contains up to 6 BARs (Base Address
//!   Registers) and the subsystem vendor/device IDs.
//! - **Type 1** — PCI-to-PCI bridge. Contains 2 BARs plus bridge-specific
//!   registers for subordinate bus management.
//!
//! ## Capability List
//!
//! Bit 4 of the Status register signals that a capability list is present.
//! The list begins at the offset stored in the Capabilities Pointer register
//! (offset 0x34 for type 0). Each capability has an 8-bit ID followed by a
//! pointer to the next capability (0x00 = end of list).
//!
//! ## BAR Programming
//!
//! Software determines BAR size by:
//! 1. Saving the original value.
//! 2. Writing all-ones (`0xFFFF_FFFF`).
//! 3. Reading back the masked value to determine size.
//! 4. Restoring the original value.
//! 5. Writing the assigned base address.
//!
//! Reference: PCI Local Bus Specification, Revision 3.0; PCI Express Base
//! Specification, Revision 5.0.

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Standard configuration space offsets
// ---------------------------------------------------------------------------

/// Vendor ID register offset.
pub const CFG_VENDOR_ID: u8 = 0x00;
/// Device ID register offset.
pub const CFG_DEVICE_ID: u8 = 0x02;
/// Command register offset.
pub const CFG_COMMAND: u8 = 0x04;
/// Status register offset.
pub const CFG_STATUS: u8 = 0x06;
/// Revision ID register offset.
pub const CFG_REVISION: u8 = 0x08;
/// Class code / subclass / prog-IF / revision (32-bit at 0x08).
pub const CFG_CLASS_CODE: u8 = 0x09;
/// Cache line size.
pub const CFG_CACHE_LINE: u8 = 0x0C;
/// Latency timer.
pub const CFG_LATENCY: u8 = 0x0D;
/// Header type register.
pub const CFG_HEADER_TYPE: u8 = 0x0E;
/// BIST register.
pub const CFG_BIST: u8 = 0x0F;
/// BAR 0 offset (type 0 header).
pub const CFG_BAR0: u8 = 0x10;
/// BAR 1 offset.
pub const CFG_BAR1: u8 = 0x14;
/// BAR 2 offset.
pub const CFG_BAR2: u8 = 0x18;
/// BAR 3 offset.
pub const CFG_BAR3: u8 = 0x1C;
/// BAR 4 offset.
pub const CFG_BAR4: u8 = 0x20;
/// BAR 5 offset.
pub const CFG_BAR5: u8 = 0x24;
/// Cardbus CIS pointer.
pub const CFG_CARDBUS_CIS: u8 = 0x28;
/// Subsystem vendor ID.
pub const CFG_SUBSYS_VENDOR: u8 = 0x2C;
/// Subsystem device ID.
pub const CFG_SUBSYS_DEVICE: u8 = 0x2E;
/// Expansion ROM base address.
pub const CFG_ROM_BASE: u8 = 0x30;
/// Capabilities pointer (bits 7:2 are valid).
pub const CFG_CAP_PTR: u8 = 0x34;
/// Interrupt line.
pub const CFG_INT_LINE: u8 = 0x3C;
/// Interrupt pin.
pub const CFG_INT_PIN: u8 = 0x3D;
/// Min grant.
pub const CFG_MIN_GRANT: u8 = 0x3E;
/// Max latency.
pub const CFG_MAX_LATENCY: u8 = 0x3F;

// Status register bits.
/// Status bit: capability list present.
pub const STATUS_CAP_LIST: u16 = 1 << 4;

// Command register bits.
/// Command bit: I/O space enable.
pub const CMD_IO_SPACE: u16 = 1 << 0;
/// Command bit: memory space enable.
pub const CMD_MEM_SPACE: u16 = 1 << 1;
/// Command bit: bus master enable.
pub const CMD_BUS_MASTER: u16 = 1 << 2;
/// Command bit: interrupt disable.
pub const CMD_INT_DISABLE: u16 = 1 << 10;

// Header type bits.
/// Header type mask (bits 6:0).
pub const HDR_TYPE_MASK: u8 = 0x7F;
/// Multi-function device flag (bit 7).
pub const HDR_MULTI_FUNC: u8 = 0x80;
/// Type 0: endpoint device.
pub const HDR_TYPE_ENDPOINT: u8 = 0x00;
/// Type 1: PCI-to-PCI bridge.
pub const HDR_TYPE_BRIDGE: u8 = 0x01;

// BAR flags.
/// BAR address space: I/O (bit 0 set).
pub const BAR_IO_SPACE: u32 = 1 << 0;
/// BAR memory type field mask (bits 2:1).
pub const BAR_MEM_TYPE_MASK: u32 = 0x6;
/// BAR memory type: 32-bit address.
pub const BAR_MEM_32BIT: u32 = 0x0;
/// BAR memory type: 64-bit address (spans two BARs).
pub const BAR_MEM_64BIT: u32 = 0x4;
/// BAR prefetchable flag (bit 3).
pub const BAR_PREFETCH: u32 = 1 << 3;

// Well-known capability IDs.
/// Capability ID: Power Management.
pub const CAP_ID_PM: u8 = 0x01;
/// Capability ID: AGP.
pub const CAP_ID_AGP: u8 = 0x02;
/// Capability ID: VPD.
pub const CAP_ID_VPD: u8 = 0x03;
/// Capability ID: MSI.
pub const CAP_ID_MSI: u8 = 0x05;
/// Capability ID: PCI-X.
pub const CAP_ID_PCIX: u8 = 0x07;
/// Capability ID: MSI-X.
pub const CAP_ID_MSIX: u8 = 0x11;
/// Capability ID: PCIe.
pub const CAP_ID_PCIE: u8 = 0x10;
/// End-of-list sentinel.
pub const CAP_END: u8 = 0x00;

/// Invalid vendor ID (no device present).
pub const VENDOR_INVALID: u16 = 0xFFFF;

/// Maximum number of capabilities scanned per function.
pub const MAX_CAPS: usize = 48;

// ---------------------------------------------------------------------------
// PCI address
// ---------------------------------------------------------------------------

/// PCI bus/device/function address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PciAddr {
    /// Bus number (0–255).
    pub bus: u8,
    /// Device slot (0–31).
    pub device: u8,
    /// Function number (0–7).
    pub function: u8,
}

impl PciAddr {
    /// Create a new PCI address, validating the field ranges.
    ///
    /// # Errors
    ///
    /// Returns `InvalidArgument` if `device > 31` or `function > 7`.
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
}

impl core::fmt::Display for PciAddr {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{:04x}:{:02x}.{}", self.bus, self.device, self.function)
    }
}

// ---------------------------------------------------------------------------
// BAR descriptor
// ---------------------------------------------------------------------------

/// Decoded PCI Base Address Register.
#[derive(Debug, Clone, Copy)]
pub struct BarInfo {
    /// BAR index (0–5).
    pub index: u8,
    /// Whether this BAR maps I/O space (else memory-mapped).
    pub is_io: bool,
    /// Whether the BAR is 64-bit wide (occupies two consecutive BAR indices).
    pub is_64bit: bool,
    /// Whether the memory range is prefetchable.
    pub prefetchable: bool,
    /// Base address (after masking type bits).
    pub base: u64,
    /// Size in bytes (zero if the BAR is unimplemented).
    pub size: u64,
}

impl BarInfo {
    const EMPTY: Self = Self {
        index: 0,
        is_io: false,
        is_64bit: false,
        prefetchable: false,
        base: 0,
        size: 0,
    };
}

// ---------------------------------------------------------------------------
// Capability entry
// ---------------------------------------------------------------------------

/// A single PCI capability record.
#[derive(Debug, Clone, Copy)]
pub struct CapEntry {
    /// Capability ID (e.g., [`CAP_ID_MSI`]).
    pub id: u8,
    /// Byte offset within configuration space.
    pub offset: u8,
    /// Whether this slot is populated.
    pub(crate) valid: bool,
}

impl CapEntry {
    const EMPTY: Self = Self {
        id: 0,
        offset: 0,
        valid: false,
    };
}

// ---------------------------------------------------------------------------
// PCI function info
// ---------------------------------------------------------------------------

/// Fully-decoded information for one PCI function.
#[derive(Debug, Clone, Copy)]
pub struct PciFunctionInfo {
    /// BDF address.
    pub addr: PciAddr,
    /// Vendor identifier.
    pub vendor_id: u16,
    /// Device identifier.
    pub device_id: u16,
    /// Class code (24-bit: class, subclass, prog-IF).
    pub class_code: u32,
    /// Revision ID.
    pub revision: u8,
    /// Header type (masked to bits 6:0).
    pub header_type: u8,
    /// Whether the function is a multi-function device root.
    pub multi_function: bool,
    /// Interrupt line.
    pub int_line: u8,
    /// Interrupt pin (0 = none, 1 = INTA#, …).
    pub int_pin: u8,
    /// Decoded BARs (up to 6).
    pub bars: [BarInfo; 6],
    /// Number of valid BARs.
    pub bar_count: u8,
    /// Decoded capabilities.
    pub caps: [CapEntry; MAX_CAPS],
    /// Number of valid capabilities.
    pub cap_count: u8,
}

impl PciFunctionInfo {
    const fn empty(addr: PciAddr) -> Self {
        Self {
            addr,
            vendor_id: VENDOR_INVALID,
            device_id: 0,
            class_code: 0,
            revision: 0,
            header_type: 0,
            multi_function: false,
            int_line: 0,
            int_pin: 0,
            bars: [BarInfo::EMPTY; 6],
            bar_count: 0,
            caps: [CapEntry::EMPTY; MAX_CAPS],
            cap_count: 0,
        }
    }

    /// Return `true` if the function slot is populated (vendor != 0xFFFF).
    pub fn is_present(&self) -> bool {
        self.vendor_id != VENDOR_INVALID
    }
}

// ---------------------------------------------------------------------------
// Configuration space accessor trait
// ---------------------------------------------------------------------------

/// Trait for reading/writing PCI configuration space DWORDs.
///
/// Implementations may use Mechanism 1 I/O ports (x86), PCIe ECAM
/// (memory-mapped extended configuration), or a firmware abstraction.
pub trait PciConfigAccess {
    /// Read a 32-bit DWORD at `offset` (must be DWORD-aligned).
    fn read_u32(&self, addr: PciAddr, offset: u8) -> u32;
    /// Write a 32-bit DWORD at `offset` (must be DWORD-aligned).
    fn write_u32(&self, addr: PciAddr, offset: u8, value: u32);

    /// Read a 16-bit word at `offset` (must be word-aligned).
    fn read_u16(&self, addr: PciAddr, offset: u8) -> u16 {
        let dword = self.read_u32(addr, offset & !3);
        let shift = (offset & 2) * 8;
        (dword >> shift) as u16
    }

    /// Read an 8-bit byte at `offset`.
    fn read_u8(&self, addr: PciAddr, offset: u8) -> u8 {
        let dword = self.read_u32(addr, offset & !3);
        let shift = (offset & 3) * 8;
        (dword >> shift) as u8
    }

    /// Write a 16-bit word at `offset` using a read-modify-write.
    fn write_u16(&self, addr: PciAddr, offset: u8, value: u16) {
        let dword = self.read_u32(addr, offset & !3);
        let shift = (offset & 2) * 8;
        let mask = 0xFFFFu32 << shift;
        let new_dword = (dword & !mask) | ((value as u32) << shift);
        self.write_u32(addr, offset & !3, new_dword);
    }
}

// ---------------------------------------------------------------------------
// PCI configuration space scanner
// ---------------------------------------------------------------------------

/// High-level configuration space scanner and BAR/capability decoder.
pub struct PciConfigScanner<A: PciConfigAccess> {
    access: A,
}

impl<A: PciConfigAccess> PciConfigScanner<A> {
    /// Create a new scanner backed by the given access implementation.
    pub fn new(access: A) -> Self {
        Self { access }
    }

    /// Read and decode the full function descriptor for `addr`.
    ///
    /// Returns `None` if no device is present (vendor == 0xFFFF).
    pub fn read_function(&self, addr: PciAddr) -> Option<PciFunctionInfo> {
        let vendor_id = self.access.read_u16(addr, CFG_VENDOR_ID);
        if vendor_id == VENDOR_INVALID {
            return None;
        }
        let device_id = self.access.read_u16(addr, CFG_DEVICE_ID);
        let class_dword = self.access.read_u32(addr, CFG_CLASS_CODE);
        let class_code = class_dword >> 8;
        let revision = (class_dword & 0xFF) as u8;
        let hdr_raw = self.access.read_u8(addr, CFG_HEADER_TYPE);
        let header_type = hdr_raw & HDR_TYPE_MASK;
        let multi_function = hdr_raw & HDR_MULTI_FUNC != 0;
        let int_line = self.access.read_u8(addr, CFG_INT_LINE);
        let int_pin = self.access.read_u8(addr, CFG_INT_PIN);

        let mut info = PciFunctionInfo::empty(addr);
        info.vendor_id = vendor_id;
        info.device_id = device_id;
        info.class_code = class_code;
        info.revision = revision;
        info.header_type = header_type;
        info.multi_function = multi_function;
        info.int_line = int_line;
        info.int_pin = int_pin;

        if header_type == HDR_TYPE_ENDPOINT {
            self.decode_bars(&mut info);
        }

        let status = self.access.read_u16(addr, CFG_STATUS);
        if status & STATUS_CAP_LIST != 0 {
            self.scan_capabilities(&mut info);
        }

        Some(info)
    }

    /// Decode all BARs for a type-0 endpoint function.
    fn decode_bars(&self, info: &mut PciFunctionInfo) {
        let mut bar_idx = 0u8;
        while bar_idx < 6 {
            let offset = CFG_BAR0 + bar_idx * 4;
            let raw = self.access.read_u32(info.addr, offset);
            if raw == 0 {
                bar_idx += 1;
                continue;
            }

            let is_io = raw & BAR_IO_SPACE != 0;
            let is_64bit = !is_io && (raw & BAR_MEM_TYPE_MASK) == BAR_MEM_64BIT;
            let prefetchable = !is_io && (raw & BAR_PREFETCH != 0);

            // Probe size by writing all-ones.
            self.access.write_u32(info.addr, offset, 0xFFFF_FFFF);
            let size_raw = self.access.read_u32(info.addr, offset);
            // Restore original value.
            self.access.write_u32(info.addr, offset, raw);

            let mask = if is_io { !0x3u32 } else { !0xFu32 };
            let size32 = !(size_raw & mask) + 1;

            let (base, size) = if is_64bit && bar_idx < 5 {
                let offset_hi = CFG_BAR0 + (bar_idx + 1) * 4;
                let raw_hi = self.access.read_u32(info.addr, offset_hi);

                self.access.write_u32(info.addr, offset_hi, 0xFFFF_FFFF);
                let size_hi = self.access.read_u32(info.addr, offset_hi);
                self.access.write_u32(info.addr, offset_hi, raw_hi);

                let base64 = ((raw & !0xF) as u64) | ((raw_hi as u64) << 32);
                let size64 = if size_hi == 0 {
                    size32 as u64
                } else {
                    let full = !((size32 as u64) | ((!(size_hi) as u64) << 32)) + 1;
                    full
                };
                (base64, size64)
            } else {
                ((raw & mask) as u64, size32 as u64)
            };

            let slot = info.bar_count as usize;
            if slot < 6 {
                info.bars[slot] = BarInfo {
                    index: bar_idx,
                    is_io,
                    is_64bit,
                    prefetchable,
                    base,
                    size,
                };
                info.bar_count += 1;
            }

            bar_idx += if is_64bit { 2 } else { 1 };
        }
    }

    /// Walk the capability linked list and populate `info.caps`.
    fn scan_capabilities(&self, info: &mut PciFunctionInfo) {
        let mut ptr = self.access.read_u8(info.addr, CFG_CAP_PTR) & !0x3;
        let mut depth = 0usize;

        while ptr != CAP_END && depth < MAX_CAPS {
            let cap_id = self.access.read_u8(info.addr, ptr);
            if cap_id == 0xFF {
                break;
            }
            let slot = info.cap_count as usize;
            if slot < MAX_CAPS {
                info.caps[slot] = CapEntry {
                    id: cap_id,
                    offset: ptr,
                    valid: true,
                };
                info.cap_count += 1;
            }
            ptr = self.access.read_u8(info.addr, ptr + 1) & !0x3;
            depth += 1;
        }
    }

    /// Find a capability by ID in the already-decoded function info.
    ///
    /// Returns the capability offset within config space, or `None`.
    pub fn find_cap(info: &PciFunctionInfo, cap_id: u8) -> Option<u8> {
        for i in 0..info.cap_count as usize {
            if info.caps[i].valid && info.caps[i].id == cap_id {
                return Some(info.caps[i].offset);
            }
        }
        None
    }

    /// Return a reference to the underlying access implementation.
    pub fn access(&self) -> &A {
        &self.access
    }
}

// ---------------------------------------------------------------------------
// Command register helpers
// ---------------------------------------------------------------------------

/// Enable bus mastering and memory space access for the given function.
pub fn enable_bus_master<A: PciConfigAccess>(access: &A, addr: PciAddr) {
    let cmd = access.read_u16(addr, CFG_COMMAND);
    access.write_u16(addr, CFG_COMMAND, cmd | CMD_BUS_MASTER | CMD_MEM_SPACE);
}

/// Disable INTx interrupts for the given function.
pub fn disable_intx<A: PciConfigAccess>(access: &A, addr: PciAddr) {
    let cmd = access.read_u16(addr, CFG_COMMAND);
    access.write_u16(addr, CFG_COMMAND, cmd | CMD_INT_DISABLE);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Minimal in-memory configuration space for testing.
    struct FakeCfg {
        space: [u8; 256],
    }

    impl FakeCfg {
        fn new() -> Self {
            let mut s = Self { space: [0u8; 256] };
            // Vendor 0x8086, Device 0x1234.
            s.write_u16_raw(CFG_VENDOR_ID, 0x8086);
            s.write_u16_raw(CFG_DEVICE_ID, 0x1234);
            // Header type 0.
            s.space[CFG_HEADER_TYPE as usize] = HDR_TYPE_ENDPOINT;
            // Status: cap list present.
            s.write_u16_raw(CFG_STATUS, STATUS_CAP_LIST);
            // Cap pointer → 0x40.
            s.space[CFG_CAP_PTR as usize] = 0x40;
            // Capability: MSI at 0x40, next = 0x00.
            s.space[0x40] = CAP_ID_MSI;
            s.space[0x41] = 0x00;
            // BAR0: 32-bit memory, base = 0xF000_0000, size probe returns 0xFFFF_F000.
            s.write_u32_raw(CFG_BAR0, 0xF000_0000);
            s
        }

        fn write_u16_raw(&mut self, off: u8, v: u16) {
            self.space[off as usize] = v as u8;
            self.space[off as usize + 1] = (v >> 8) as u8;
        }

        fn write_u32_raw(&mut self, off: u8, v: u32) {
            for i in 0..4 {
                self.space[off as usize + i] = (v >> (i * 8)) as u8;
            }
        }
    }

    impl PciConfigAccess for FakeCfg {
        fn read_u32(&self, _addr: PciAddr, offset: u8) -> u32 {
            let o = (offset & !3) as usize;
            u32::from_le_bytes([
                self.space[o],
                self.space[o + 1],
                self.space[o + 2],
                self.space[o + 3],
            ])
        }

        fn write_u32(&self, _addr: PciAddr, _offset: u8, _value: u32) {
            // Read-only fake for tests.
        }
    }

    #[test]
    fn pci_addr_validation() {
        assert!(PciAddr::new(0, 32, 0).is_err());
        assert!(PciAddr::new(0, 0, 8).is_err());
        assert!(PciAddr::new(255, 31, 7).is_ok());
    }

    #[test]
    fn pci_function_decode() {
        let addr = PciAddr::new(0, 0, 0).unwrap();
        let scanner = PciConfigScanner::new(FakeCfg::new());
        let info = scanner.read_function(addr).unwrap();
        assert_eq!(info.vendor_id, 0x8086);
        assert_eq!(info.device_id, 0x1234);
        assert!(info.is_present());
    }

    #[test]
    fn pci_capability_found() {
        let addr = PciAddr::new(0, 0, 0).unwrap();
        let scanner = PciConfigScanner::new(FakeCfg::new());
        let info = scanner.read_function(addr).unwrap();
        let msi_off = PciConfigScanner::<FakeCfg>::find_cap(&info, CAP_ID_MSI);
        assert_eq!(msi_off, Some(0x40));
    }

    #[test]
    fn pci_capability_missing() {
        let addr = PciAddr::new(0, 0, 0).unwrap();
        let scanner = PciConfigScanner::new(FakeCfg::new());
        let info = scanner.read_function(addr).unwrap();
        let pm_off = PciConfigScanner::<FakeCfg>::find_cap(&info, CAP_ID_PM);
        assert!(pm_off.is_none());
    }

    #[test]
    fn no_device_returns_none() {
        let addr = PciAddr::new(1, 0, 0).unwrap();
        let mut fake = FakeCfg::new();
        // Overwrite vendor ID with 0xFFFF to simulate absent device.
        fake.write_u16_raw(CFG_VENDOR_ID, VENDOR_INVALID);
        let scanner = PciConfigScanner::new(fake);
        assert!(scanner.read_function(addr).is_none());
    }
}
