// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! AHCI (Advanced Host Controller Interface) SATA driver.
//!
//! Implements an AHCI driver for SATA devices using memory-mapped I/O.
//! The AHCI specification defines a host bus adapter (HBA) that connects
//! to one or more SATA ports, each capable of hosting a SATA device.
//!
//! # Architecture
//!
//! - **HBA registers** — global host controller configuration
//! - **Port registers** — per-port command and status registers
//! - **Command list** — up to 32 command headers per port
//! - **Command table** — FIS + PRDT entries for each command
//! - **FIS area** — received FIS from devices
//!
//! Reference: Serial ATA AHCI 1.3.1 Specification.

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Standard sector size in bytes.
pub const SECTOR_SIZE: usize = 512;

/// Maximum number of ports an AHCI HBA can support.
pub const MAX_PORTS: usize = 32;

/// Maximum command slots per port.
pub const MAX_CMD_SLOTS: usize = 32;

/// Maximum PRDT entries per command table.
pub const MAX_PRDT_ENTRIES: usize = 8;

/// BSY/DRQ polling timeout (iterations).
const POLL_TIMEOUT: u32 = 1_000_000;

/// Spin-up timeout for COMRESET (iterations).
const COMRESET_TIMEOUT: u32 = 100_000;

/// FIS type: Register — Host to Device.
const FIS_TYPE_REG_H2D: u8 = 0x27;

/// ATA command: IDENTIFY DEVICE.
const ATA_CMD_IDENTIFY: u8 = 0xEC;

/// ATA command: READ DMA EXT (LBA48).
const ATA_CMD_READ_DMA_EXT: u8 = 0x25;

/// ATA command: WRITE DMA EXT (LBA48).
const ATA_CMD_WRITE_DMA_EXT: u8 = 0x35;

/// ATA command: FLUSH CACHE EXT.
const ATA_CMD_FLUSH_EXT: u8 = 0xEA;

// ---------------------------------------------------------------------------
// GHC register bits
// ---------------------------------------------------------------------------

/// GHC bit: AHCI Enable.
const GHC_AE: u32 = 1 << 31;

/// GHC bit: HBA Reset.
const GHC_HR: u32 = 1 << 0;

/// GHC bit: Interrupt Enable.
const GHC_IE: u32 = 1 << 1;

// ---------------------------------------------------------------------------
// Port CMD register bits
// ---------------------------------------------------------------------------

/// Port CMD: Start (process command list).
const PORT_CMD_ST: u32 = 1 << 0;

/// Port CMD: FIS Receive Enable.
const PORT_CMD_FRE: u32 = 1 << 4;

/// Port CMD: FIS Receive Running.
const PORT_CMD_FR: u32 = 1 << 14;

/// Port CMD: Command List Running.
const PORT_CMD_CR: u32 = 1 << 15;

// ---------------------------------------------------------------------------
// Port TFD (Task File Data) bits
// ---------------------------------------------------------------------------

/// TFD: BSY bit (device busy).
const TFD_BSY: u32 = 1 << 7;

/// TFD: DRQ bit (data request).
const TFD_DRQ: u32 = 1 << 3;

/// TFD: ERR bit (error).
const TFD_ERR: u32 = 1 << 0;

// ---------------------------------------------------------------------------
// SATA device signatures
// ---------------------------------------------------------------------------

/// Signature for a SATA disk drive.
const SATA_SIG_ATA: u32 = 0x0000_0101;

/// Signature for an ATAPI device (CD/DVD).
const SATA_SIG_ATAPI: u32 = 0xEB14_0101;

/// Signature for an enclosure management bridge.
const SATA_SIG_SEMB: u32 = 0xC33C_0101;

/// Signature for a port multiplier.
const SATA_SIG_PM: u32 = 0x9669_0101;

// ---------------------------------------------------------------------------
// BIOS/OS Handoff Control (BOHC) bits
// ---------------------------------------------------------------------------

/// BOHC: BIOS Owned Semaphore.
const BOHC_BOS: u32 = 1 << 0;

/// BOHC: OS Owned Semaphore.
const BOHC_OOS: u32 = 1 << 1;

// ---------------------------------------------------------------------------
// MMIO helpers
// ---------------------------------------------------------------------------

/// Read a 32-bit value from a memory-mapped register.
///
/// # Safety
///
/// `addr` must point to a valid, mapped MMIO register.
unsafe fn mmio_read32(addr: usize) -> u32 {
    // SAFETY: Caller guarantees `addr` is valid MMIO.
    unsafe { core::ptr::read_volatile(addr as *const u32) }
}

/// Write a 32-bit value to a memory-mapped register.
///
/// # Safety
///
/// `addr` must point to a valid, mapped MMIO register.
unsafe fn mmio_write32(addr: usize, val: u32) {
    // SAFETY: Caller guarantees `addr` is valid MMIO.
    unsafe { core::ptr::write_volatile(addr as *mut u32, val) }
}

// ---------------------------------------------------------------------------
// AhciDeviceType
// ---------------------------------------------------------------------------

/// Type of device connected to an AHCI port, determined by
/// the port signature register.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AhciDeviceType {
    /// No device detected.
    #[default]
    None,
    /// SATA hard disk drive.
    Sata,
    /// SATAPI device (CD/DVD drive).
    Satapi,
    /// Serial Enclosure Management Bridge.
    Semb,
    /// Port Multiplier.
    PortMultiplier,
}

impl AhciDeviceType {
    /// Determine device type from a port signature value.
    pub const fn from_signature(sig: u32) -> Self {
        match sig {
            SATA_SIG_ATA => Self::Sata,
            SATA_SIG_ATAPI => Self::Satapi,
            SATA_SIG_SEMB => Self::Semb,
            SATA_SIG_PM => Self::PortMultiplier,
            _ => Self::None,
        }
    }
}

// ---------------------------------------------------------------------------
// AhciHbaRegs — HBA global memory registers
// ---------------------------------------------------------------------------

/// Offsets for HBA global memory-mapped registers.
///
/// These registers are located at the base address obtained from
/// PCI BAR5 (ABAR). All offsets are relative to that base.
#[derive(Debug, Clone, Copy)]
pub struct AhciHbaRegs {
    /// Base virtual address of the HBA register space.
    base: usize,
}

impl AhciHbaRegs {
    /// Host Capabilities register offset.
    const CAP: usize = 0x00;
    /// Global HBA Control register offset.
    const GHC: usize = 0x04;
    /// Interrupt Status register offset.
    const IS: usize = 0x08;
    /// Ports Implemented register offset.
    const PI: usize = 0x0C;
    /// AHCI Version register offset.
    const VS: usize = 0x10;
    /// Command Completion Coalescing Control offset.
    const CCC_CTL: usize = 0x14;
    /// Command Completion Coalescing Ports offset.
    const CCC_PORTS: usize = 0x18;
    /// Enclosure Management Location offset.
    const EM_LOC: usize = 0x1C;
    /// Enclosure Management Control offset.
    const EM_CTL: usize = 0x20;
    /// Host Capabilities Extended offset.
    const CAP2: usize = 0x24;
    /// BIOS/OS Handoff Control and Status offset.
    const BOHC: usize = 0x28;

    /// Create an HBA register accessor from a base address.
    ///
    /// `base` is the virtual address mapping of PCI BAR5.
    pub const fn new(base: usize) -> Self {
        Self { base }
    }

    /// Read the Host Capabilities register (CAP).
    pub fn cap(&self) -> u32 {
        // SAFETY: Valid MMIO within HBA register space.
        unsafe { mmio_read32(self.base + Self::CAP) }
    }

    /// Read the Global HBA Control register (GHC).
    pub fn ghc(&self) -> u32 {
        // SAFETY: Valid MMIO within HBA register space.
        unsafe { mmio_read32(self.base + Self::GHC) }
    }

    /// Write the Global HBA Control register (GHC).
    pub fn set_ghc(&self, val: u32) {
        // SAFETY: Valid MMIO within HBA register space.
        unsafe { mmio_write32(self.base + Self::GHC, val) }
    }

    /// Read the Interrupt Status register (IS).
    pub fn interrupt_status(&self) -> u32 {
        // SAFETY: Valid MMIO within HBA register space.
        unsafe { mmio_read32(self.base + Self::IS) }
    }

    /// Write the Interrupt Status register (IS) to clear bits.
    pub fn clear_interrupt_status(&self, bits: u32) {
        // SAFETY: Valid MMIO within HBA register space (W1C).
        unsafe { mmio_write32(self.base + Self::IS, bits) }
    }

    /// Read the Ports Implemented register (PI).
    pub fn ports_implemented(&self) -> u32 {
        // SAFETY: Valid MMIO within HBA register space.
        unsafe { mmio_read32(self.base + Self::PI) }
    }

    /// Read the AHCI Version register (VS).
    pub fn version(&self) -> u32 {
        // SAFETY: Valid MMIO within HBA register space.
        unsafe { mmio_read32(self.base + Self::VS) }
    }

    /// Read the Command Completion Coalescing Control register.
    pub fn ccc_ctl(&self) -> u32 {
        // SAFETY: Valid MMIO within HBA register space.
        unsafe { mmio_read32(self.base + Self::CCC_CTL) }
    }

    /// Read the Command Completion Coalescing Ports register.
    pub fn ccc_ports(&self) -> u32 {
        // SAFETY: Valid MMIO within HBA register space.
        unsafe { mmio_read32(self.base + Self::CCC_PORTS) }
    }

    /// Read the Enclosure Management Location register.
    pub fn em_loc(&self) -> u32 {
        // SAFETY: Valid MMIO within HBA register space.
        unsafe { mmio_read32(self.base + Self::EM_LOC) }
    }

    /// Read the Enclosure Management Control register.
    pub fn em_ctl(&self) -> u32 {
        // SAFETY: Valid MMIO within HBA register space.
        unsafe { mmio_read32(self.base + Self::EM_CTL) }
    }

    /// Read the Host Capabilities Extended register (CAP2).
    pub fn cap2(&self) -> u32 {
        // SAFETY: Valid MMIO within HBA register space.
        unsafe { mmio_read32(self.base + Self::CAP2) }
    }

    /// Read the BIOS/OS Handoff Control register (BOHC).
    pub fn bohc(&self) -> u32 {
        // SAFETY: Valid MMIO within HBA register space.
        unsafe { mmio_read32(self.base + Self::BOHC) }
    }

    /// Write the BIOS/OS Handoff Control register (BOHC).
    pub fn set_bohc(&self, val: u32) {
        // SAFETY: Valid MMIO within HBA register space.
        unsafe { mmio_write32(self.base + Self::BOHC, val) }
    }

    /// Return the number of command slots supported (from CAP).
    pub fn num_cmd_slots(&self) -> u32 {
        ((self.cap() >> 8) & 0x1F) + 1
    }

    /// Return the number of ports supported (from CAP).
    pub fn num_ports(&self) -> u32 {
        (self.cap() & 0x1F) + 1
    }

    /// Check whether 64-bit addressing is supported (CAP.S64A).
    pub fn supports_64bit(&self) -> bool {
        self.cap() & (1 << 31) != 0
    }
}

impl Default for AhciHbaRegs {
    fn default() -> Self {
        Self::new(0)
    }
}

// ---------------------------------------------------------------------------
// AhciPortRegs — per-port registers
// ---------------------------------------------------------------------------

/// Per-port AHCI register accessor.
///
/// Each port occupies 0x80 bytes starting at HBA base + 0x100 +
/// (port_number * 0x80).
#[derive(Debug, Clone, Copy, Default)]
pub struct AhciPortRegs {
    /// Base virtual address of this port's register space.
    base: usize,
}

impl AhciPortRegs {
    /// Port register block size.
    const PORT_SIZE: usize = 0x80;
    /// Offset of port 0 from HBA base.
    const PORT_BASE_OFFSET: usize = 0x100;

    /// Command List Base Address (lower 32 bits).
    const CLB: usize = 0x00;
    /// Command List Base Address (upper 32 bits).
    const CLBU: usize = 0x04;
    /// FIS Base Address (lower 32 bits).
    const FB: usize = 0x08;
    /// FIS Base Address (upper 32 bits).
    const FBU: usize = 0x0C;
    /// Interrupt Status.
    const IS: usize = 0x10;
    /// Interrupt Enable.
    const IE: usize = 0x14;
    /// Command and Status.
    const CMD: usize = 0x18;
    /// Task File Data.
    const TFD: usize = 0x20;
    /// Signature.
    const SIG: usize = 0x24;
    /// Serial ATA Status (SCR0: SStatus).
    const SSTS: usize = 0x28;
    /// Serial ATA Control (SCR2: SControl).
    const SCTL: usize = 0x2C;
    /// Serial ATA Error (SCR1: SError).
    const SERR: usize = 0x30;
    /// Serial ATA Active (SCR3: SActive).
    const SACT: usize = 0x34;
    /// Command Issue.
    const CI: usize = 0x38;
    /// Serial ATA Notification (SCR4: SNotification).
    const SNTF: usize = 0x3C;

    /// Create a port register accessor for the given port number.
    ///
    /// `hba_base` is the virtual address of the HBA register space.
    /// `port` is the port index (0..31).
    pub const fn new(hba_base: usize, port: u32) -> Self {
        let base = hba_base + Self::PORT_BASE_OFFSET + (port as usize) * Self::PORT_SIZE;
        Self { base }
    }

    /// Read the Command List Base Address (64-bit combined).
    pub fn clb(&self) -> u64 {
        // SAFETY: Valid MMIO within port register space.
        let lo = unsafe { mmio_read32(self.base + Self::CLB) } as u64;
        let hi = unsafe { mmio_read32(self.base + Self::CLBU) } as u64;
        lo | (hi << 32)
    }

    /// Write the Command List Base Address (64-bit).
    pub fn set_clb(&self, addr: u64) {
        // SAFETY: Valid MMIO within port register space.
        unsafe {
            mmio_write32(self.base + Self::CLB, addr as u32);
            mmio_write32(self.base + Self::CLBU, (addr >> 32) as u32);
        }
    }

    /// Read the FIS Base Address (64-bit combined).
    pub fn fb(&self) -> u64 {
        // SAFETY: Valid MMIO within port register space.
        let lo = unsafe { mmio_read32(self.base + Self::FB) } as u64;
        let hi = unsafe { mmio_read32(self.base + Self::FBU) } as u64;
        lo | (hi << 32)
    }

    /// Write the FIS Base Address (64-bit).
    pub fn set_fb(&self, addr: u64) {
        // SAFETY: Valid MMIO within port register space.
        unsafe {
            mmio_write32(self.base + Self::FB, addr as u32);
            mmio_write32(self.base + Self::FBU, (addr >> 32) as u32);
        }
    }

    /// Read the port Interrupt Status register.
    pub fn interrupt_status(&self) -> u32 {
        // SAFETY: Valid MMIO within port register space.
        unsafe { mmio_read32(self.base + Self::IS) }
    }

    /// Clear port interrupt status bits (write-1-to-clear).
    pub fn clear_interrupt_status(&self, bits: u32) {
        // SAFETY: Valid MMIO within port register space (W1C).
        unsafe { mmio_write32(self.base + Self::IS, bits) }
    }

    /// Read the port Interrupt Enable register.
    pub fn interrupt_enable(&self) -> u32 {
        // SAFETY: Valid MMIO within port register space.
        unsafe { mmio_read32(self.base + Self::IE) }
    }

    /// Write the port Interrupt Enable register.
    pub fn set_interrupt_enable(&self, val: u32) {
        // SAFETY: Valid MMIO within port register space.
        unsafe { mmio_write32(self.base + Self::IE, val) }
    }

    /// Read the port Command and Status register.
    pub fn cmd(&self) -> u32 {
        // SAFETY: Valid MMIO within port register space.
        unsafe { mmio_read32(self.base + Self::CMD) }
    }

    /// Write the port Command and Status register.
    pub fn set_cmd(&self, val: u32) {
        // SAFETY: Valid MMIO within port register space.
        unsafe { mmio_write32(self.base + Self::CMD, val) }
    }

    /// Read the Task File Data register.
    pub fn tfd(&self) -> u32 {
        // SAFETY: Valid MMIO within port register space.
        unsafe { mmio_read32(self.base + Self::TFD) }
    }

    /// Read the port Signature register.
    pub fn sig(&self) -> u32 {
        // SAFETY: Valid MMIO within port register space.
        unsafe { mmio_read32(self.base + Self::SIG) }
    }

    /// Read the Serial ATA Status register (SStatus).
    pub fn ssts(&self) -> u32 {
        // SAFETY: Valid MMIO within port register space.
        unsafe { mmio_read32(self.base + Self::SSTS) }
    }

    /// Read the Serial ATA Control register (SControl).
    pub fn sctl(&self) -> u32 {
        // SAFETY: Valid MMIO within port register space.
        unsafe { mmio_read32(self.base + Self::SCTL) }
    }

    /// Write the Serial ATA Control register (SControl).
    pub fn set_sctl(&self, val: u32) {
        // SAFETY: Valid MMIO within port register space.
        unsafe { mmio_write32(self.base + Self::SCTL, val) }
    }

    /// Read the Serial ATA Error register (SError).
    pub fn serr(&self) -> u32 {
        // SAFETY: Valid MMIO within port register space.
        unsafe { mmio_read32(self.base + Self::SERR) }
    }

    /// Clear Serial ATA Error bits (write-1-to-clear).
    pub fn clear_serr(&self, bits: u32) {
        // SAFETY: Valid MMIO within port register space (W1C).
        unsafe { mmio_write32(self.base + Self::SERR, bits) }
    }

    /// Read the Serial ATA Active register (SActive).
    pub fn sact(&self) -> u32 {
        // SAFETY: Valid MMIO within port register space.
        unsafe { mmio_read32(self.base + Self::SACT) }
    }

    /// Write the Serial ATA Active register (SActive).
    pub fn set_sact(&self, val: u32) {
        // SAFETY: Valid MMIO within port register space.
        unsafe { mmio_write32(self.base + Self::SACT, val) }
    }

    /// Read the Command Issue register.
    pub fn ci(&self) -> u32 {
        // SAFETY: Valid MMIO within port register space.
        unsafe { mmio_read32(self.base + Self::CI) }
    }

    /// Write the Command Issue register.
    pub fn set_ci(&self, val: u32) {
        // SAFETY: Valid MMIO within port register space.
        unsafe { mmio_write32(self.base + Self::CI, val) }
    }

    /// Read the Serial ATA Notification register.
    pub fn sntf(&self) -> u32 {
        // SAFETY: Valid MMIO within port register space.
        unsafe { mmio_read32(self.base + Self::SNTF) }
    }

    /// Extract the device detection status from SStatus.
    ///
    /// Returns the DET field (bits 3:0):
    /// - 0: no device, no PHY
    /// - 1: device present but no communication
    /// - 3: device present and PHY established
    /// - 4: PHY offline mode
    pub fn det(&self) -> u32 {
        self.ssts() & 0x0F
    }

    /// Extract the interface power management from SStatus.
    ///
    /// Returns the IPM field (bits 11:8):
    /// - 0: not present
    /// - 1: active
    /// - 2: partial power
    /// - 6: slumber
    pub fn ipm(&self) -> u32 {
        (self.ssts() >> 8) & 0x0F
    }
}

// ---------------------------------------------------------------------------
// CommandHeader — command list entry (repr(C), 32 bytes)
// ---------------------------------------------------------------------------

/// AHCI command list entry (command header).
///
/// Each port has a command list containing up to 32 headers.
/// Each header is 32 bytes and describes one command to issue.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct CommandHeader {
    /// Command flags (CFL, ATAPI, Write, Prefetchable, etc.)
    /// and Physical Region Descriptor Table Length.
    ///
    /// Bits 4:0 — Command FIS Length in DWORDs (2..=16).
    /// Bit 5    — ATAPI (1 = ATAPI command).
    /// Bit 6    — Write (1 = host-to-device, 0 = device-to-host).
    /// Bit 7    — Prefetchable.
    /// Bit 8    — Reset.
    /// Bit 9    — BIST.
    /// Bit 10   — Clear Busy upon R_OK.
    /// Bits 15:0 of upper word — PRDTL.
    flags_prdtl: u32,
    /// Physical Region Descriptor Byte Count — set by HBA on
    /// completion to indicate bytes transferred.
    pub prdbc: u32,
    /// Command Table Descriptor Base Address (lower 32 bits).
    /// Must be 128-byte aligned.
    ctba_lo: u32,
    /// Command Table Descriptor Base Address (upper 32 bits).
    ctba_hi: u32,
    /// Reserved DWORDs (4 DWORDs = 16 bytes).
    _reserved: [u32; 4],
}

impl CommandHeader {
    /// Create a zeroed command header.
    pub const fn new() -> Self {
        Self {
            flags_prdtl: 0,
            prdbc: 0,
            ctba_lo: 0,
            ctba_hi: 0,
            _reserved: [0; 4],
        }
    }

    /// Set the command FIS length in DWORDs (bits 4:0).
    pub fn set_cfl(&mut self, dwords: u8) {
        self.flags_prdtl = (self.flags_prdtl & !0x1F) | (dwords as u32 & 0x1F);
    }

    /// Set the Write bit (bit 6): 1 = host-to-device direction.
    pub fn set_write(&mut self, write: bool) {
        if write {
            self.flags_prdtl |= 1 << 6;
        } else {
            self.flags_prdtl &= !(1 << 6);
        }
    }

    /// Set the ATAPI bit (bit 5).
    pub fn set_atapi(&mut self, atapi: bool) {
        if atapi {
            self.flags_prdtl |= 1 << 5;
        } else {
            self.flags_prdtl &= !(1 << 5);
        }
    }

    /// Set the PRDT length (number of PRDT entries, bits 31:16).
    pub fn set_prdtl(&mut self, count: u16) {
        self.flags_prdtl = (self.flags_prdtl & 0x0000_FFFF) | ((count as u32) << 16);
    }

    /// Return the PRDT length (number of entries).
    pub fn prdtl(&self) -> u16 {
        (self.flags_prdtl >> 16) as u16
    }

    /// Set the Command Table Base Address (64-bit, 128-byte
    /// aligned).
    pub fn set_ctba(&mut self, addr: u64) {
        self.ctba_lo = addr as u32;
        self.ctba_hi = (addr >> 32) as u32;
    }

    /// Return the Command Table Base Address (64-bit).
    pub fn ctba(&self) -> u64 {
        (self.ctba_lo as u64) | ((self.ctba_hi as u64) << 32)
    }
}

impl Default for CommandHeader {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// PrdtEntry — Physical Region Descriptor Table entry (16 bytes)
// ---------------------------------------------------------------------------

/// Physical Region Descriptor Table (PRDT) entry.
///
/// Each entry describes one contiguous physical memory region
/// for DMA transfer. A command table may contain multiple entries.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct PrdtEntry {
    /// Data Base Address (lower 32 bits, word-aligned).
    dba_lo: u32,
    /// Data Base Address (upper 32 bits).
    dba_hi: u32,
    /// Reserved.
    _reserved: u32,
    /// Byte count (bits 21:0) and interrupt-on-completion (bit 31).
    ///
    /// The byte count is zero-based: a value of 0 means 1 byte,
    /// a value of N means N+1 bytes. Maximum 4 MiB (0x3FFFFF).
    dbc_i: u32,
}

impl PrdtEntry {
    /// Create a zeroed PRDT entry.
    pub const fn new() -> Self {
        Self {
            dba_lo: 0,
            dba_hi: 0,
            _reserved: 0,
            dbc_i: 0,
        }
    }

    /// Set the data base address (64-bit, word-aligned).
    pub fn set_dba(&mut self, addr: u64) {
        self.dba_lo = addr as u32;
        self.dba_hi = (addr >> 32) as u32;
    }

    /// Return the data base address (64-bit).
    pub fn dba(&self) -> u64 {
        (self.dba_lo as u64) | ((self.dba_hi as u64) << 32)
    }

    /// Set the byte count (zero-based, max 0x3FFFFF = 4 MiB - 1).
    pub fn set_byte_count(&mut self, count: u32) {
        self.dbc_i = (self.dbc_i & (1 << 31)) | (count & 0x003F_FFFF);
    }

    /// Return the byte count (zero-based).
    pub fn byte_count(&self) -> u32 {
        self.dbc_i & 0x003F_FFFF
    }

    /// Set interrupt-on-completion (bit 31).
    pub fn set_interrupt(&mut self, enable: bool) {
        if enable {
            self.dbc_i |= 1 << 31;
        } else {
            self.dbc_i &= !(1 << 31);
        }
    }
}

impl Default for PrdtEntry {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// FisRegH2D — Host-to-Device Register FIS (20 bytes)
// ---------------------------------------------------------------------------

/// Host-to-Device Register FIS (Frame Information Structure).
///
/// This 20-byte structure is used to issue ATA commands to a
/// device. It corresponds to FIS type 0x27 in the SATA spec.
#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct FisRegH2D {
    /// FIS type (always 0x27 for Register H2D).
    pub fis_type: u8,
    /// Port multiplier + command/control bit.
    ///
    /// Bit 7: Command (1) vs Control (0).
    /// Bits 3:0: Port multiplier port.
    pub pm_cmd: u8,
    /// ATA command register.
    pub command: u8,
    /// ATA feature register (lower).
    pub feature_lo: u8,
    /// LBA bits 7:0.
    pub lba0: u8,
    /// LBA bits 15:8.
    pub lba1: u8,
    /// LBA bits 23:16.
    pub lba2: u8,
    /// Device register.
    pub device: u8,
    /// LBA bits 31:24.
    pub lba3: u8,
    /// LBA bits 39:32.
    pub lba4: u8,
    /// LBA bits 47:40.
    pub lba5: u8,
    /// ATA feature register (upper).
    pub feature_hi: u8,
    /// Sector count (lower).
    pub count_lo: u8,
    /// Sector count (upper).
    pub count_hi: u8,
    /// Isochronous command completion.
    pub icc: u8,
    /// ATA control register.
    pub control: u8,
    /// Reserved (must be zero).
    pub _reserved: [u8; 4],
}

impl FisRegH2D {
    /// Create a zeroed H2D Register FIS with the type byte set.
    pub const fn new() -> Self {
        Self {
            fis_type: FIS_TYPE_REG_H2D,
            pm_cmd: 0,
            command: 0,
            feature_lo: 0,
            lba0: 0,
            lba1: 0,
            lba2: 0,
            device: 0,
            lba3: 0,
            lba4: 0,
            lba5: 0,
            feature_hi: 0,
            count_lo: 0,
            count_hi: 0,
            icc: 0,
            control: 0,
            _reserved: [0; 4],
        }
    }

    /// Set the command bit (bit 7 of pm_cmd), indicating this FIS
    /// carries an ATA command (vs. a control register update).
    pub fn set_command_bit(&mut self) {
        self.pm_cmd |= 1 << 7;
    }

    /// Set the 48-bit LBA address across the six LBA fields.
    pub fn set_lba(&mut self, lba: u64) {
        self.lba0 = lba as u8;
        self.lba1 = (lba >> 8) as u8;
        self.lba2 = (lba >> 16) as u8;
        self.lba3 = (lba >> 24) as u8;
        self.lba4 = (lba >> 32) as u8;
        self.lba5 = (lba >> 40) as u8;
    }

    /// Set the 16-bit sector count across the two count fields.
    pub fn set_count(&mut self, count: u16) {
        self.count_lo = count as u8;
        self.count_hi = (count >> 8) as u8;
    }
}

impl Default for FisRegH2D {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// CommandTable — command FIS + PRDT entries
// ---------------------------------------------------------------------------

/// AHCI Command Table.
///
/// Contains the command FIS, optional ATAPI command, and PRDT
/// entries. Must be 128-byte aligned in physical memory.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct CommandTable {
    /// Command FIS area (up to 64 bytes; we embed the H2D FIS
    /// and pad the rest).
    pub cfis: [u8; 64],
    /// ATAPI Command area (16 bytes, zero for non-ATAPI).
    pub acmd: [u8; 16],
    /// Reserved (48 bytes).
    pub _reserved: [u8; 48],
    /// Physical Region Descriptor Table entries.
    pub prdt: [PrdtEntry; MAX_PRDT_ENTRIES],
}

impl CommandTable {
    /// Create a zeroed command table.
    pub const fn new() -> Self {
        Self {
            cfis: [0; 64],
            acmd: [0; 16],
            _reserved: [0; 48],
            prdt: [PrdtEntry::new(); MAX_PRDT_ENTRIES],
        }
    }

    /// Write an H2D Register FIS into the command FIS area.
    ///
    /// Copies the 20-byte FIS into the first 20 bytes of `cfis`.
    pub fn set_fis_h2d(&mut self, fis: &FisRegH2D) {
        // SAFETY: FisRegH2D is repr(C, packed) and exactly 20 bytes.
        // We copy its raw bytes into the cfis buffer.
        let src = fis as *const FisRegH2D as *const u8;
        let fis_size = core::mem::size_of::<FisRegH2D>();
        // Manual byte copy (no memcpy in no_std without alloc).
        for i in 0..fis_size {
            // SAFETY: Both src and self.cfis are valid for fis_size
            // bytes, and fis_size (20) < cfis.len() (64).
            self.cfis[i] = unsafe { core::ptr::read(src.add(i)) };
        }
    }
}

impl Default for CommandTable {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// AhciPort — per-port driver logic
// ---------------------------------------------------------------------------

/// AHCI port driver.
///
/// Manages one SATA port: device detection, command engine
/// start/stop, and command issuance via the command list.
pub struct AhciPort {
    /// Port register accessor.
    regs: AhciPortRegs,
    /// Port number (0..31).
    port_num: u32,
    /// Detected device type.
    device_type: AhciDeviceType,
    /// Physical address of the command list (1 KiB, 1 KiB-aligned).
    cmd_list_phys: u64,
    /// Physical address of the FIS receive area (256 bytes,
    /// 256-byte aligned).
    fis_phys: u64,
    /// Physical addresses of command tables (one per slot).
    cmd_table_phys: [u64; MAX_CMD_SLOTS],
    /// Number of command slots supported by the HBA.
    num_cmd_slots: u32,
}

impl AhciPort {
    /// Create a new port driver.
    ///
    /// - `hba_base` — virtual base address of HBA register space
    /// - `port_num` — port index (0..31)
    /// - `num_cmd_slots` — from HBA CAP register
    pub const fn new(hba_base: usize, port_num: u32, num_cmd_slots: u32) -> Self {
        Self {
            regs: AhciPortRegs::new(hba_base, port_num),
            port_num,
            device_type: AhciDeviceType::None,
            cmd_list_phys: 0,
            fis_phys: 0,
            cmd_table_phys: [0u64; MAX_CMD_SLOTS],
            num_cmd_slots,
        }
    }

    /// Return the port number.
    pub const fn port_num(&self) -> u32 {
        self.port_num
    }

    /// Return the detected device type.
    pub const fn device_type(&self) -> AhciDeviceType {
        self.device_type
    }

    /// Return a reference to the port registers.
    pub const fn regs(&self) -> &AhciPortRegs {
        &self.regs
    }

    /// Return the configured command list physical address.
    pub const fn cmd_list_phys(&self) -> u64 {
        self.cmd_list_phys
    }

    /// Return the configured FIS receive area physical address.
    pub const fn fis_phys(&self) -> u64 {
        self.fis_phys
    }

    /// Return the command table physical addresses.
    pub const fn cmd_table_phys(&self) -> &[u64; MAX_CMD_SLOTS] {
        &self.cmd_table_phys
    }

    /// Detect the device type on this port from the signature
    /// register.
    ///
    /// Checks SStatus for device presence and PHY communication
    /// before reading the signature.
    pub fn detect_device(&mut self) -> AhciDeviceType {
        let det = self.regs.det();
        let ipm = self.regs.ipm();

        // DET == 3: device present and PHY established.
        // IPM == 1: interface is active.
        if det != 3 || ipm != 1 {
            self.device_type = AhciDeviceType::None;
            return AhciDeviceType::None;
        }

        let sig = self.regs.sig();
        self.device_type = AhciDeviceType::from_signature(sig);
        self.device_type
    }

    /// Configure the port's command list and FIS receive area.
    ///
    /// - `cmd_list_phys` — physical address of 1 KiB command list
    /// - `fis_phys` — physical address of 256-byte FIS area
    /// - `cmd_table_phys` — physical addresses of command tables
    ///   (one per slot actually used)
    pub fn configure(&mut self, cmd_list_phys: u64, fis_phys: u64, cmd_table_phys: &[u64]) {
        self.cmd_list_phys = cmd_list_phys;
        self.fis_phys = fis_phys;

        let slots = core::cmp::min(cmd_table_phys.len(), self.num_cmd_slots as usize);
        self.cmd_table_phys[..slots].copy_from_slice(&cmd_table_phys[..slots]);

        // Program the port registers.
        self.regs.set_clb(cmd_list_phys);
        self.regs.set_fb(fis_phys);

        // Clear pending interrupts and errors.
        self.regs.clear_interrupt_status(0xFFFF_FFFF);
        self.regs.clear_serr(0xFFFF_FFFF);
    }

    /// Start the port command engine.
    ///
    /// Enables FIS receive and sets the Start bit so the HBA
    /// begins processing the command list.
    pub fn start_cmd_engine(&self) -> Result<()> {
        // Wait for CR (Command List Running) to clear.
        self.wait_cmd_idle()?;

        let mut cmd = self.regs.cmd();
        cmd |= PORT_CMD_FRE;
        self.regs.set_cmd(cmd);

        cmd = self.regs.cmd();
        cmd |= PORT_CMD_ST;
        self.regs.set_cmd(cmd);

        Ok(())
    }

    /// Stop the port command engine.
    ///
    /// Clears the Start bit and waits for both FR and CR to
    /// deassert before returning.
    pub fn stop_cmd_engine(&self) -> Result<()> {
        let mut cmd = self.regs.cmd();

        // Clear ST (stop command processing).
        cmd &= !PORT_CMD_ST;
        self.regs.set_cmd(cmd);

        // Clear FRE (stop FIS receive).
        cmd &= !PORT_CMD_FRE;
        self.regs.set_cmd(cmd);

        // Wait for FR and CR to clear.
        for _ in 0..POLL_TIMEOUT {
            let c = self.regs.cmd();
            if c & PORT_CMD_FR == 0 && c & PORT_CMD_CR == 0 {
                return Ok(());
            }
        }
        Err(Error::Busy)
    }

    /// Find a free command slot.
    ///
    /// Returns the slot index (0-based) or `Error::Busy` if all
    /// slots are occupied.
    pub fn find_free_slot(&self) -> Result<u32> {
        let ci = self.regs.ci();
        let sact = self.regs.sact();
        let occupied = ci | sact;

        for i in 0..self.num_cmd_slots {
            if occupied & (1 << i) == 0 {
                return Ok(i);
            }
        }
        Err(Error::Busy)
    }

    /// Issue a command in the given slot and wait for completion.
    ///
    /// Sets the CI bit for the slot and polls until the HBA clears
    /// it (command complete) or a timeout/error occurs.
    pub fn issue_command(&self, slot: u32) -> Result<()> {
        self.regs.set_ci(1 << slot);

        // Poll for completion.
        for _ in 0..POLL_TIMEOUT {
            let ci = self.regs.ci();
            if ci & (1 << slot) == 0 {
                // Check for errors.
                let is = self.regs.interrupt_status();
                if is & (1 << 30) != 0 {
                    // TFES — Task File Error Status.
                    return Err(Error::IoError);
                }
                return Ok(());
            }

            let tfd = self.regs.tfd();
            if tfd & TFD_ERR != 0 {
                return Err(Error::IoError);
            }
        }
        Err(Error::Busy)
    }

    /// Wait for the device on this port to become not-busy.
    pub fn wait_not_busy(&self) -> Result<()> {
        for _ in 0..POLL_TIMEOUT {
            let tfd = self.regs.tfd();
            if tfd & (TFD_BSY | TFD_DRQ) == 0 {
                return Ok(());
            }
        }
        Err(Error::Busy)
    }

    /// Wait for the command engine to go idle (CR clear).
    fn wait_cmd_idle(&self) -> Result<()> {
        for _ in 0..POLL_TIMEOUT {
            if self.regs.cmd() & PORT_CMD_CR == 0 {
                return Ok(());
            }
        }
        Err(Error::Busy)
    }
}

// ---------------------------------------------------------------------------
// AhciController — main HBA driver
// ---------------------------------------------------------------------------

/// Port slot in the controller.
struct PortSlot {
    /// Port driver instance.
    port: AhciPort,
    /// Whether this port is implemented and active.
    active: bool,
}

/// AHCI Host Bus Adapter controller driver.
///
/// Manages the HBA global registers and up to 32 SATA ports.
/// Initialization sequence:
/// 1. Perform BIOS/OS handoff (if supported).
/// 2. Enable AHCI mode via GHC.AE.
/// 3. Probe implemented ports and detect devices.
pub struct AhciController {
    /// HBA global register accessor.
    hba: AhciHbaRegs,
    /// Port slots.
    ports: [PortSlot; MAX_PORTS],
    /// Number of active (implemented + device-present) ports.
    active_count: usize,
    /// Number of command slots supported by the HBA.
    num_cmd_slots: u32,
}

impl AhciController {
    /// Create a new AHCI controller from the PCI BAR5 base address.
    ///
    /// `bar5_vaddr` is the virtual address mapping of PCI BAR5
    /// (AHCI Base Address Register).
    pub fn new(bar5_vaddr: usize) -> Self {
        let hba = AhciHbaRegs::new(bar5_vaddr);
        let num_cmd_slots = hba.num_cmd_slots();

        // Build port slots (all inactive initially).
        let mut ports: [PortSlot; MAX_PORTS] = core::array::from_fn(|i| PortSlot {
            port: AhciPort::new(bar5_vaddr, i as u32, num_cmd_slots),
            active: false,
        });

        // Mark implemented ports.
        let pi = hba.ports_implemented();
        for (i, port) in ports.iter_mut().enumerate().take(MAX_PORTS) {
            port.active = pi & (1 << i) != 0;
        }

        Self {
            hba,
            ports,
            active_count: 0,
            num_cmd_slots,
        }
    }

    /// Return the HBA register accessor.
    pub const fn hba(&self) -> &AhciHbaRegs {
        &self.hba
    }

    /// Return the number of active ports with detected devices.
    pub const fn active_count(&self) -> usize {
        self.active_count
    }

    /// Return the number of command slots supported.
    pub const fn num_cmd_slots(&self) -> u32 {
        self.num_cmd_slots
    }

    /// Perform the BIOS/OS ownership handoff.
    ///
    /// If the HBA supports BIOS/OS handoff (CAP2.BOH), this method
    /// sets the OS Owned Semaphore and waits for the BIOS Owned
    /// Semaphore to clear.
    pub fn bios_handoff(&self) -> Result<()> {
        let cap2 = self.hba.cap2();
        // CAP2 bit 0: BOH — BIOS/OS Handoff supported.
        if cap2 & 1 == 0 {
            return Ok(());
        }

        let mut bohc = self.hba.bohc();
        // Set OS Owned Semaphore.
        bohc |= BOHC_OOS;
        self.hba.set_bohc(bohc);

        // Wait for BIOS to release ownership.
        for _ in 0..COMRESET_TIMEOUT {
            let b = self.hba.bohc();
            if b & BOHC_BOS == 0 {
                return Ok(());
            }
        }
        // BIOS did not release; proceed anyway (best-effort).
        Ok(())
    }

    /// Enable AHCI mode by setting GHC.AE.
    pub fn enable_ahci(&self) {
        let ghc = self.hba.ghc();
        if ghc & GHC_AE == 0 {
            self.hba.set_ghc(ghc | GHC_AE);
        }
    }

    /// Perform an HBA reset via GHC.HR.
    ///
    /// After reset, re-enables AHCI mode. Returns `Error::Busy`
    /// if the reset does not complete within the timeout.
    pub fn reset(&self) -> Result<()> {
        self.hba.set_ghc(GHC_HR);

        // Wait for HR to self-clear.
        for _ in 0..POLL_TIMEOUT {
            if self.hba.ghc() & GHC_HR == 0 {
                self.enable_ahci();
                return Ok(());
            }
        }
        Err(Error::Busy)
    }

    /// Enable global HBA interrupts (GHC.IE).
    pub fn enable_interrupts(&self) {
        let ghc = self.hba.ghc();
        self.hba.set_ghc(ghc | GHC_IE);
    }

    /// Initialize the controller: handoff, enable, probe ports.
    ///
    /// This is the main entry point after creating the controller.
    /// Returns the number of ports with detected SATA devices.
    pub fn init(&mut self) -> Result<usize> {
        self.bios_handoff()?;
        self.enable_ahci();

        // Clear global interrupt status.
        self.hba.clear_interrupt_status(0xFFFF_FFFF);

        self.probe_ports();
        self.enable_interrupts();
        Ok(self.active_count)
    }

    /// Probe all implemented ports and detect devices.
    pub fn probe_ports(&mut self) {
        self.active_count = 0;
        for slot in &mut self.ports {
            if !slot.active {
                continue;
            }
            let dev_type = slot.port.detect_device();
            if dev_type != AhciDeviceType::None {
                self.active_count = self.active_count.saturating_add(1);
            } else {
                slot.active = false;
            }
        }
    }

    /// Get a reference to a port by index (0..31).
    ///
    /// Returns `None` if the port is not implemented or inactive.
    pub fn port(&self, index: usize) -> Option<&AhciPort> {
        if index >= MAX_PORTS {
            return None;
        }
        if self.ports[index].active {
            Some(&self.ports[index].port)
        } else {
            None
        }
    }

    /// Get a mutable reference to a port by index (0..31).
    ///
    /// Returns `None` if the port is not implemented or inactive.
    pub fn port_mut(&mut self, index: usize) -> Option<&mut AhciPort> {
        if index >= MAX_PORTS {
            return None;
        }
        if self.ports[index].active {
            Some(&mut self.ports[index].port)
        } else {
            None
        }
    }
}

impl Default for AhciController {
    fn default() -> Self {
        Self::new(0)
    }
}

// ---------------------------------------------------------------------------
// AhciDisk — high-level disk I/O
// ---------------------------------------------------------------------------

/// High-level AHCI disk interface.
///
/// Wraps an [`AhciPort`] and provides sector-level read/write
/// operations using DMA EXT commands (LBA48).
pub struct AhciDisk {
    /// Port register accessor.
    port_regs: AhciPortRegs,
    /// Port number.
    port_num: u32,
    /// Number of command slots.
    num_cmd_slots: u32,
    /// Physical address of the command list.
    cmd_list_phys: u64,
    /// Virtual address of the command list (for software access).
    cmd_list_virt: usize,
    /// Physical addresses of command tables.
    cmd_table_phys: [u64; MAX_CMD_SLOTS],
    /// Virtual addresses of command tables.
    cmd_table_virt: [usize; MAX_CMD_SLOTS],
    /// Total sectors on the disk (populated after identify).
    total_sectors: u64,
    /// Whether the disk has been identified.
    identified: bool,
}

impl AhciDisk {
    /// Create a new AHCI disk from pre-allocated memory regions.
    ///
    /// - `hba_base` — virtual base of HBA register space
    /// - `port_num` — port index
    /// - `num_cmd_slots` — from HBA CAP
    /// - `cmd_list_phys` / `cmd_list_virt` — command list memory
    /// - `cmd_table_phys` / `cmd_table_virt` — per-slot command
    ///   table memory
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        hba_base: usize,
        port_num: u32,
        num_cmd_slots: u32,
        cmd_list_phys: u64,
        cmd_list_virt: usize,
        cmd_table_phys: &[u64],
        cmd_table_virt: &[usize],
    ) -> Self {
        let mut ct_phys = [0u64; MAX_CMD_SLOTS];
        let mut ct_virt = [0usize; MAX_CMD_SLOTS];
        let n = core::cmp::min(
            core::cmp::min(cmd_table_phys.len(), cmd_table_virt.len()),
            num_cmd_slots as usize,
        );
        ct_phys[..n].copy_from_slice(&cmd_table_phys[..n]);
        ct_virt[..n].copy_from_slice(&cmd_table_virt[..n]);

        Self {
            port_regs: AhciPortRegs::new(hba_base, port_num),
            port_num,
            num_cmd_slots,
            cmd_list_phys,
            cmd_list_virt,
            cmd_table_phys: ct_phys,
            cmd_table_virt: ct_virt,
            total_sectors: 0,
            identified: false,
        }
    }

    /// Return the port number.
    pub const fn port_num(&self) -> u32 {
        self.port_num
    }

    /// Return the physical address of the command list.
    pub const fn cmd_list_phys(&self) -> u64 {
        self.cmd_list_phys
    }

    /// Return whether the disk has been identified.
    pub const fn is_identified(&self) -> bool {
        self.identified
    }

    /// Return total sectors (valid only after identify).
    pub const fn total_sectors(&self) -> u64 {
        self.total_sectors
    }

    /// Return the disk capacity in bytes.
    pub const fn capacity_bytes(&self) -> u64 {
        self.total_sectors * SECTOR_SIZE as u64
    }

    /// Identify the device by issuing the ATA IDENTIFY command.
    ///
    /// On success, populates `total_sectors` from the IDENTIFY
    /// response. The caller must provide a physical address to a
    /// 512-byte buffer for the IDENTIFY data, and a virtual
    /// address to read the result.
    ///
    /// # Errors
    ///
    /// - `Error::Busy` if no slot is free or timeout
    /// - `Error::IoError` on device error
    /// - `Error::InvalidArgument` if addresses are zero
    pub fn identify(&mut self, buf_phys: u64, buf_virt: usize) -> Result<()> {
        if buf_phys == 0 || buf_virt == 0 {
            return Err(Error::InvalidArgument);
        }

        let slot = self.find_free_slot()?;
        self.wait_not_busy()?;

        self.setup_command_header(slot, 1, false);

        let ct_virt = self.cmd_table_virt[slot as usize];
        if ct_virt == 0 {
            return Err(Error::InvalidArgument);
        }

        // Build FIS for IDENTIFY DEVICE.
        let mut fis = FisRegH2D::new();
        fis.set_command_bit();
        fis.command = ATA_CMD_IDENTIFY;
        fis.device = 0;
        self.write_fis_to_table(ct_virt, &fis);

        // Single PRDT entry for 512 bytes.
        self.setup_prdt_entry(ct_virt, 0, buf_phys, SECTOR_SIZE as u32);

        self.issue_and_wait(slot)?;

        // Parse the 256-word IDENTIFY buffer for LBA48 sector
        // count (words 100-103).
        let words = buf_virt as *const u16;
        let mut sectors: u64 = 0;
        for i in 0..4u64 {
            // SAFETY: buf_virt points to a 512-byte buffer, and
            // words 100..103 are within the 256-word range.
            let w = unsafe { core::ptr::read_volatile(words.add(100 + i as usize)) };
            sectors |= (w as u64) << (i * 16);
        }

        // Fallback to LBA28 count (words 60-61) if LBA48 is zero.
        if sectors == 0 {
            let lo = unsafe { core::ptr::read_volatile(words.add(60)) } as u64;
            let hi = unsafe { core::ptr::read_volatile(words.add(61)) } as u64;
            sectors = lo | (hi << 16);
        }

        self.total_sectors = sectors;
        self.identified = true;
        Ok(())
    }

    /// Read sectors from the disk via DMA EXT.
    ///
    /// - `lba` — starting logical block address (LBA48)
    /// - `count` — number of sectors to read (1..=65535)
    /// - `buf_phys` — physical address of the output buffer
    ///   (must be large enough for `count * 512` bytes)
    ///
    /// # Errors
    ///
    /// - `Error::NotFound` if the disk has not been identified
    /// - `Error::InvalidArgument` if parameters are invalid
    /// - `Error::Busy` if no command slot is free or timeout
    /// - `Error::IoError` on device error
    pub fn read_sectors(&mut self, lba: u64, count: u16, buf_phys: u64) -> Result<()> {
        self.validate_io(lba, count)?;
        self.issue_dma_command(ATA_CMD_READ_DMA_EXT, lba, count, buf_phys, false)
    }

    /// Write sectors to the disk via DMA EXT.
    ///
    /// - `lba` — starting logical block address (LBA48)
    /// - `count` — number of sectors to write (1..=65535)
    /// - `buf_phys` — physical address of the input buffer
    ///   (must contain `count * 512` bytes of data)
    ///
    /// # Errors
    ///
    /// Same as [`read_sectors`](Self::read_sectors).
    pub fn write_sectors(&mut self, lba: u64, count: u16, buf_phys: u64) -> Result<()> {
        self.validate_io(lba, count)?;
        self.issue_dma_command(ATA_CMD_WRITE_DMA_EXT, lba, count, buf_phys, true)?;
        self.flush()
    }

    /// Flush the disk's volatile write cache.
    pub fn flush(&self) -> Result<()> {
        let slot = self.find_free_slot()?;
        self.wait_not_busy()?;

        self.setup_command_header(slot, 0, false);

        let ct_virt = self.cmd_table_virt[slot as usize];
        if ct_virt == 0 {
            return Err(Error::InvalidArgument);
        }

        // Build FIS for FLUSH CACHE EXT.
        let mut fis = FisRegH2D::new();
        fis.set_command_bit();
        fis.command = ATA_CMD_FLUSH_EXT;
        self.write_fis_to_table(ct_virt, &fis);

        self.issue_and_wait(slot)
    }

    // -- private helpers ------------------------------------------------

    /// Validate I/O parameters.
    fn validate_io(&self, lba: u64, count: u16) -> Result<()> {
        if !self.identified {
            return Err(Error::NotFound);
        }
        if count == 0 {
            return Err(Error::InvalidArgument);
        }
        let end = lba
            .checked_add(count as u64)
            .ok_or(Error::InvalidArgument)?;
        if end > self.total_sectors {
            return Err(Error::InvalidArgument);
        }
        Ok(())
    }

    /// Issue a DMA EXT read or write command.
    fn issue_dma_command(
        &self,
        command: u8,
        lba: u64,
        count: u16,
        buf_phys: u64,
        is_write: bool,
    ) -> Result<()> {
        let slot = self.find_free_slot()?;
        self.wait_not_busy()?;

        let prdt_count: u16 = 1;
        self.setup_command_header(slot, prdt_count, is_write);

        let ct_virt = self.cmd_table_virt[slot as usize];
        if ct_virt == 0 {
            return Err(Error::InvalidArgument);
        }

        // Build the H2D FIS.
        let mut fis = FisRegH2D::new();
        fis.set_command_bit();
        fis.command = command;
        fis.device = 1 << 6; // LBA mode.
        fis.set_lba(lba);
        fis.set_count(count);
        self.write_fis_to_table(ct_virt, &fis);

        // Set up the single PRDT entry.
        let byte_count = (count as u32).saturating_mul(SECTOR_SIZE as u32);
        self.setup_prdt_entry(ct_virt, 0, buf_phys, byte_count);

        self.issue_and_wait(slot)
    }

    /// Write the command header for a given slot.
    fn setup_command_header(&self, slot: u32, prdt_count: u16, is_write: bool) {
        if self.cmd_list_virt == 0 {
            return;
        }
        let header_size = core::mem::size_of::<CommandHeader>();
        let header_addr = self.cmd_list_virt + (slot as usize) * header_size;

        let mut hdr = CommandHeader::new();
        // CFL = size of FisRegH2D in DWORDs (20 / 4 = 5).
        hdr.set_cfl((core::mem::size_of::<FisRegH2D>() / 4) as u8);
        hdr.set_write(is_write);
        hdr.set_prdtl(prdt_count);
        hdr.prdbc = 0;
        hdr.set_ctba(self.cmd_table_phys[slot as usize]);

        // SAFETY: header_addr points to our pre-allocated command
        // list memory, and CommandHeader is repr(C).
        unsafe {
            core::ptr::write_volatile(header_addr as *mut CommandHeader, hdr);
        }
    }

    /// Write the FIS into a command table at `ct_virt`.
    fn write_fis_to_table(&self, ct_virt: usize, fis: &FisRegH2D) {
        let src = fis as *const FisRegH2D as *const u8;
        let fis_size = core::mem::size_of::<FisRegH2D>();
        for i in 0..fis_size {
            // SAFETY: ct_virt points to allocated command table
            // memory; fis_size (20) fits within the 64-byte CFIS
            // area.
            unsafe {
                let byte = core::ptr::read(src.add(i));
                core::ptr::write_volatile((ct_virt + i) as *mut u8, byte);
            }
        }
        // Zero remaining CFIS bytes.
        for i in fis_size..64 {
            // SAFETY: Within the 64-byte CFIS area.
            unsafe {
                core::ptr::write_volatile((ct_virt + i) as *mut u8, 0);
            }
        }
    }

    /// Set up a PRDT entry in a command table.
    fn setup_prdt_entry(&self, ct_virt: usize, index: usize, buf_phys: u64, byte_count: u32) {
        // PRDT starts at offset 0x80 in the command table.
        let prdt_offset = 128;
        let entry_size = core::mem::size_of::<PrdtEntry>();
        let entry_addr = ct_virt + prdt_offset + index * entry_size;

        let mut entry = PrdtEntry::new();
        entry.set_dba(buf_phys);
        // Byte count is zero-based (N means N+1 bytes).
        entry.set_byte_count(byte_count.saturating_sub(1));
        entry.set_interrupt(true);

        // SAFETY: entry_addr is within our pre-allocated command
        // table memory, and PrdtEntry is repr(C).
        unsafe {
            core::ptr::write_volatile(entry_addr as *mut PrdtEntry, entry);
        }
    }

    /// Find a free command slot.
    fn find_free_slot(&self) -> Result<u32> {
        let ci = self.port_regs.ci();
        let sact = self.port_regs.sact();
        let occupied = ci | sact;

        for i in 0..self.num_cmd_slots {
            if occupied & (1 << i) == 0 {
                return Ok(i);
            }
        }
        Err(Error::Busy)
    }

    /// Issue a command and wait for completion.
    fn issue_and_wait(&self, slot: u32) -> Result<()> {
        self.port_regs.set_ci(1 << slot);

        for _ in 0..POLL_TIMEOUT {
            let ci = self.port_regs.ci();
            if ci & (1 << slot) == 0 {
                let is = self.port_regs.interrupt_status();
                // Bit 30: Task File Error Status.
                if is & (1 << 30) != 0 {
                    return Err(Error::IoError);
                }
                return Ok(());
            }

            let tfd = self.port_regs.tfd();
            if tfd & TFD_ERR != 0 {
                return Err(Error::IoError);
            }
        }
        Err(Error::Busy)
    }

    /// Wait for device to become not-busy.
    pub fn wait_not_busy(&self) -> Result<()> {
        for _ in 0..POLL_TIMEOUT {
            let tfd = self.port_regs.tfd();
            if tfd & (TFD_BSY | TFD_DRQ) == 0 {
                return Ok(());
            }
        }
        Err(Error::Busy)
    }
}
