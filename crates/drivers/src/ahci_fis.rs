// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! AHCI FIS (Frame Information Structure) encoding and decoding.
//!
//! AHCI uses FIS frames to communicate commands and status between the
//! AHCI Host Bus Adapter (HBA) and SATA devices. FIS types relevant to
//! an AHCI driver include:
//!
//! | FIS Type | Value | Description |
//! |----------|-------|-------------|
//! | Register H2D | 0x27 | Host sends ATA command register contents |
//! | Register D2H | 0x34 | Device sends ATA status/error registers |
//! | DMA Activate | 0x39 | Device ready to receive DMA data |
//! | DMA Setup    | 0x41 | Sets up DMA (bi-directional) |
//! | Data         | 0x46 | Carries data (PIO transfers) |
//! | BIST Activate| 0x58 | BIST mode |
//! | PIO Setup    | 0x5F | Device announces PIO transfer |
//! | Set Device Bits | 0xA1 | Device reports interrupt bits |
//!
//! Reference: AHCI 1.3.1, §10 — Serial ATA Frame Information Structures.

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// FIS Type Codes
// ---------------------------------------------------------------------------

/// FIS type: Register Host-to-Device (H2D).
pub const FIS_TYPE_REG_H2D: u8 = 0x27;
/// FIS type: Register Device-to-Host (D2H).
pub const FIS_TYPE_REG_D2H: u8 = 0x34;
/// FIS type: DMA Activate.
pub const FIS_TYPE_DMA_ACT: u8 = 0x39;
/// FIS type: DMA Setup.
pub const FIS_TYPE_DMA_SETUP: u8 = 0x41;
/// FIS type: Data FIS.
pub const FIS_TYPE_DATA: u8 = 0x46;
/// FIS type: BIST Activate.
pub const FIS_TYPE_BIST: u8 = 0x58;
/// FIS type: PIO Setup.
pub const FIS_TYPE_PIO_SETUP: u8 = 0x5F;
/// FIS type: Set Device Bits.
pub const FIS_TYPE_SET_DEV_BITS: u8 = 0xA1;

// ---------------------------------------------------------------------------
// ATA Commands
// ---------------------------------------------------------------------------

/// ATA command: Read DMA Extended (48-bit LBA).
pub const ATA_CMD_READ_DMA_EXT: u8 = 0x25;
/// ATA command: Write DMA Extended (48-bit LBA).
pub const ATA_CMD_WRITE_DMA_EXT: u8 = 0x35;
/// ATA command: Read DMA (28-bit LBA).
pub const ATA_CMD_READ_DMA: u8 = 0xC8;
/// ATA command: Write DMA (28-bit LBA).
pub const ATA_CMD_WRITE_DMA: u8 = 0xCA;
/// ATA command: Flush Cache Extended.
pub const ATA_CMD_FLUSH_CACHE_EXT: u8 = 0xEA;
/// ATA command: IDENTIFY DEVICE.
pub const ATA_CMD_IDENTIFY: u8 = 0xEC;
/// ATA command: SET FEATURES.
pub const ATA_CMD_SET_FEATURES: u8 = 0xEF;
/// ATA command: READ FPDMA QUEUED (NCQ).
pub const ATA_CMD_READ_FPDMA: u8 = 0x60;
/// ATA command: WRITE FPDMA QUEUED (NCQ).
pub const ATA_CMD_WRITE_FPDMA: u8 = 0x61;

// ---------------------------------------------------------------------------
// Register H2D FIS
// ---------------------------------------------------------------------------

/// Register Host-to-Device FIS (20 bytes).
///
/// Used to send ATA command register contents to the device.
///
/// `#[repr(C)]` is required for correct layout in the AHCI command table.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct FisRegH2d {
    /// FIS type: must be `FIS_TYPE_REG_H2D`.
    pub fis_type: u8,
    /// Bit 7: C (1 = command, 0 = control); bits 3:0: Port Multiplier port.
    pub pm_port_c: u8,
    /// ATA Command register.
    pub command: u8,
    /// ATA Feature register low byte.
    pub featurel: u8,

    /// LBA low (bits 7:0).
    pub lba0: u8,
    /// LBA mid (bits 15:8).
    pub lba1: u8,
    /// LBA high (bits 23:16).
    pub lba2: u8,
    /// ATA Device register (LBA mode, DEV bit, etc.).
    pub device: u8,

    /// LBA extended low (bits 31:24).
    pub lba3: u8,
    /// LBA extended mid (bits 39:32).
    pub lba4: u8,
    /// LBA extended high (bits 47:40).
    pub lba5: u8,
    /// ATA Feature register high byte (for 48-bit commands).
    pub featureh: u8,

    /// Sector count low byte.
    pub count_l: u8,
    /// Sector count high byte (for 48-bit commands).
    pub count_h: u8,
    /// Isochronous Command Completion (ICC).
    pub icc: u8,
    /// ATA Control register.
    pub control: u8,

    /// Reserved (must be zero).
    _reserved: [u8; 4],
}

impl FisRegH2d {
    /// Builds a Register H2D FIS for an ATA command.
    ///
    /// # Parameters
    /// - `command`: ATA command opcode.
    /// - `lba`: 48-bit LBA address.
    /// - `count`: Sector count (0 = 65536 for 28-bit, 65536 for 48-bit).
    /// - `is_48bit`: If `true`, send as a 48-bit LBA command.
    pub fn new_lba(command: u8, lba: u64, count: u16, is_48bit: bool) -> Self {
        let device: u8 = if is_48bit {
            0x40
        } else {
            0x40 | ((lba >> 24) & 0x0F) as u8
        };
        Self {
            fis_type: FIS_TYPE_REG_H2D,
            pm_port_c: 0x80, // C=1: command
            command,
            featurel: 0,
            lba0: (lba & 0xFF) as u8,
            lba1: ((lba >> 8) & 0xFF) as u8,
            lba2: ((lba >> 16) & 0xFF) as u8,
            device,
            lba3: ((lba >> 24) & 0xFF) as u8,
            lba4: ((lba >> 32) & 0xFF) as u8,
            lba5: ((lba >> 40) & 0xFF) as u8,
            featureh: 0,
            count_l: (count & 0xFF) as u8,
            count_h: (count >> 8) as u8,
            icc: 0,
            control: 0,
            _reserved: [0u8; 4],
        }
    }

    /// Builds a Read DMA Extended FIS.
    pub fn read_dma_ext(lba: u64, count: u16) -> Self {
        Self::new_lba(ATA_CMD_READ_DMA_EXT, lba, count, true)
    }

    /// Builds a Write DMA Extended FIS.
    pub fn write_dma_ext(lba: u64, count: u16) -> Self {
        Self::new_lba(ATA_CMD_WRITE_DMA_EXT, lba, count, true)
    }

    /// Builds a Flush Cache Extended FIS.
    pub fn flush_cache_ext() -> Self {
        Self::new_lba(ATA_CMD_FLUSH_CACHE_EXT, 0, 0, true)
    }

    /// Builds an IDENTIFY DEVICE FIS.
    pub fn identify() -> Self {
        Self {
            fis_type: FIS_TYPE_REG_H2D,
            pm_port_c: 0x80,
            command: ATA_CMD_IDENTIFY,
            ..Self::default()
        }
    }
}

// ---------------------------------------------------------------------------
// Register D2H FIS
// ---------------------------------------------------------------------------

/// Register Device-to-Host FIS (20 bytes).
///
/// The device sends this after a command completes, with status/error registers.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct FisRegD2h {
    /// FIS type: must be `FIS_TYPE_REG_D2H`.
    pub fis_type: u8,
    /// Bit 6: I (Interrupt); bits 3:0: PM port.
    pub pm_port_i: u8,
    /// ATA Status register.
    pub status: u8,
    /// ATA Error register.
    pub error: u8,

    pub lba0: u8,
    pub lba1: u8,
    pub lba2: u8,
    pub device: u8,

    pub lba3: u8,
    pub lba4: u8,
    pub lba5: u8,
    _reserved0: u8,

    pub count_l: u8,
    pub count_h: u8,
    _reserved1: [u8; 6],
}

impl FisRegD2h {
    /// Returns `true` if the BSY bit is set (device busy).
    pub const fn is_busy(&self) -> bool {
        self.status & 0x80 != 0
    }

    /// Returns `true` if the ERR bit is set.
    pub const fn has_error(&self) -> bool {
        self.status & 0x01 != 0
    }

    /// Returns `true` if DRQ (Data Request) is set.
    pub const fn is_drq(&self) -> bool {
        self.status & 0x08 != 0
    }

    /// Returns `true` if DRDY (Device Ready) is set.
    pub const fn is_drdy(&self) -> bool {
        self.status & 0x40 != 0
    }

    /// Returns the full 48-bit LBA from the FIS.
    pub const fn lba(&self) -> u64 {
        (self.lba0 as u64)
            | ((self.lba1 as u64) << 8)
            | ((self.lba2 as u64) << 16)
            | ((self.lba3 as u64) << 24)
            | ((self.lba4 as u64) << 32)
            | ((self.lba5 as u64) << 40)
    }
}

// ---------------------------------------------------------------------------
// PIO Setup FIS
// ---------------------------------------------------------------------------

/// PIO Setup FIS (20 bytes) — device announces a PIO transfer.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct FisPioSetup {
    pub fis_type: u8,
    /// Bit 5: D (Direction, 1=D2H), bit 2: I.
    pub pm_port_di: u8,
    pub status: u8,
    pub error: u8,
    pub lba0: u8,
    pub lba1: u8,
    pub lba2: u8,
    pub device: u8,
    pub lba3: u8,
    pub lba4: u8,
    pub lba5: u8,
    _reserved0: u8,
    pub count_l: u8,
    pub count_h: u8,
    _reserved1: u8,
    pub e_status: u8,
    /// Transfer count (bytes remaining in this PIO phase).
    pub tc: u16,
    _reserved2: [u8; 2],
}

impl FisPioSetup {
    /// Returns `true` if this is a device-to-host (read) PIO transfer.
    pub const fn is_d2h(&self) -> bool {
        self.pm_port_di & (1 << 5) != 0
    }
}

// ---------------------------------------------------------------------------
// DMA Setup FIS
// ---------------------------------------------------------------------------

/// DMA Setup FIS (28 bytes) — bi-directional DMA setup.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct FisDmaSetup {
    pub fis_type: u8,
    pub pm_port_di_a: u8,
    _reserved0: [u8; 2],
    /// DMA buffer identifier.
    pub dma_buf_id_lo: u32,
    pub dma_buf_id_hi: u32,
    _reserved1: u32,
    /// DMA buffer offset (bytes from DMA buf start).
    pub dma_buf_offset: u32,
    /// Transfer count (bytes).
    pub transfer_count: u32,
    _reserved2: u32,
}

// ---------------------------------------------------------------------------
// Received FIS Structure
// ---------------------------------------------------------------------------

/// Received FIS area (256 bytes) pointed to by the HBA port RX FIS base.
///
/// `#[repr(C, align(256))]` is required by the AHCI specification.
#[repr(C, align(256))]
#[derive(Clone, Copy, Debug)]
pub struct ReceivedFis {
    /// DMA Setup FIS (at offset 0x00).
    pub dma_setup: FisDmaSetup,
    _pad0: [u8; 4],
    /// PIO Setup FIS (at offset 0x20).
    pub pio_setup: FisPioSetup,
    _pad1: [u8; 12],
    /// Register D2H FIS (at offset 0x40).
    pub reg_d2h: FisRegD2h,
    _pad2: [u8; 4],
    /// Set Device Bits FIS (at offset 0x58, 8 bytes).
    pub set_dev_bits: [u8; 8],
    /// Unknown FIS area (offset 0x60, 64 bytes).
    pub unknown_fis: [u8; 64],
    /// Reserved (offset 0xA0, 96 bytes).
    _reserved: [u8; 96],
}

impl Default for ReceivedFis {
    fn default() -> Self {
        // SAFETY: ReceivedFis is repr(C) with no padding/uninit requirements beyond
        // being zero-initialised; all-zero is a valid state.
        unsafe { core::mem::zeroed() }
    }
}

// ---------------------------------------------------------------------------
// AHCI Physical Region Descriptor Table (PRDT) Entry
// ---------------------------------------------------------------------------

/// PRDT entry: describes one DMA buffer segment.
///
/// `#[repr(C)]` is required for DMA.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct PrdtEntry {
    /// Data base address (physical, must be word-aligned).
    pub dba: u32,
    /// Data base address upper 32 bits.
    pub dbau: u32,
    /// Reserved.
    _reserved: u32,
    /// Bit 31: Interrupt on Completion; bits 21:0: Data Byte Count minus 1.
    pub dbc: u32,
}

impl PrdtEntry {
    /// Creates a PRDT entry.
    ///
    /// # Parameters
    /// - `buf_phys`: Physical address of the data buffer.
    /// - `byte_count`: Number of bytes (1..=4 MiB; 0 is invalid).
    /// - `ioc`: If `true`, generate an interrupt when this entry completes.
    ///
    /// # Errors
    /// Returns `Error::InvalidArgument` if `byte_count` is 0 or > 4 MiB.
    pub fn new(buf_phys: u64, byte_count: u32, ioc: bool) -> Result<Self> {
        if byte_count == 0 || byte_count > 4 * 1024 * 1024 {
            return Err(Error::InvalidArgument);
        }
        let ioc_bit: u32 = if ioc { 1 << 31 } else { 0 };
        Ok(Self {
            dba: (buf_phys & 0xFFFF_FFFE) as u32,
            dbau: (buf_phys >> 32) as u32,
            _reserved: 0,
            dbc: ioc_bit | (byte_count - 1),
        })
    }
}

// ---------------------------------------------------------------------------
// AHCI Command Table
// ---------------------------------------------------------------------------

/// Maximum number of PRDT entries per command table.
pub const MAX_PRDT_ENTRIES: usize = 8;

/// AHCI Command Table (variable-length; fixed header + PRDT array).
///
/// `#[repr(C, align(128))]` as required by AHCI spec.
#[repr(C, align(128))]
pub struct CommandTable {
    /// Command FIS (64 bytes, but only the first 20 are used for H2D).
    pub cfis: [u8; 64],
    /// ATAPI Command (16 bytes, used only for ATAPI commands).
    pub acmd: [u8; 16],
    /// Reserved.
    _reserved: [u8; 48],
    /// Physical Region Descriptor Table.
    pub prdt: [PrdtEntry; MAX_PRDT_ENTRIES],
}

impl CommandTable {
    /// Creates an empty command table (all zeros).
    pub const fn new() -> Self {
        Self {
            cfis: [0u8; 64],
            acmd: [0u8; 16],
            _reserved: [0u8; 48],
            prdt: [PrdtEntry {
                dba: 0,
                dbau: 0,
                _reserved: 0,
                dbc: 0,
            }; MAX_PRDT_ENTRIES],
        }
    }

    /// Writes a Register H2D FIS into the command FIS area.
    pub fn set_h2d_fis(&mut self, fis: &FisRegH2d) {
        let bytes = core::mem::size_of::<FisRegH2d>();
        // SAFETY: FisRegH2d is repr(C) and cfis is large enough (64 bytes >= 20).
        unsafe {
            let src = fis as *const FisRegH2d as *const u8;
            core::ptr::copy_nonoverlapping(src, self.cfis.as_mut_ptr(), bytes);
        }
    }

    /// Sets a PRDT entry.
    ///
    /// # Errors
    /// Returns `Error::InvalidArgument` if `index >= MAX_PRDT_ENTRIES`.
    pub fn set_prdt(&mut self, index: usize, entry: PrdtEntry) -> Result<()> {
        if index >= MAX_PRDT_ENTRIES {
            return Err(Error::InvalidArgument);
        }
        self.prdt[index] = entry;
        Ok(())
    }
}

impl Default for CommandTable {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// AHCI Command Header
// ---------------------------------------------------------------------------

/// AHCI Command Header (32 bytes), one per slot in the command list.
///
/// `#[repr(C)]` required for DMA.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct CommandHeader {
    /// Bits 15:0: PRDTL (PRDT entry count); bits 31:16: flags.
    pub flags_prdtl: u32,
    /// Physical Region Descriptor Byte Count (updated by hardware after transfer).
    pub prdbc: u32,
    /// Command Table Descriptor Base Address (physical, 128-byte aligned).
    pub ctba: u32,
    /// Command Table Descriptor Base Address Upper 32 bits.
    pub ctbau: u32,
    /// Reserved.
    _reserved: [u32; 4],
}

/// Command Header flag: Write (1 = H2D data transfer direction).
pub const CMD_HDR_WRITE: u32 = 1 << 6;
/// Command Header flag: ATAPI.
pub const CMD_HDR_ATAPI: u32 = 1 << 5;
/// Command Header CFL shift (bits 4:0 = Command FIS Length in DWORDs).
pub const CMD_HDR_CFL_SHIFT: u32 = 0;

impl CommandHeader {
    /// Configures this command header for a DMA transfer.
    ///
    /// # Parameters
    /// - `ctba_phys`: Physical address of the command table.
    /// - `prdt_count`: Number of PRDT entries.
    /// - `write`: `true` for host-to-device (write), `false` for device-to-host (read).
    /// - `cfl`: Command FIS length in DWORDs (5 for 20-byte H2D FIS).
    pub fn configure_dma(&mut self, ctba_phys: u64, prdt_count: u16, write: bool, cfl: u8) {
        let write_bit: u32 = if write { CMD_HDR_WRITE } else { 0 };
        self.flags_prdtl =
            ((prdt_count as u32) << 16) | write_bit | ((cfl as u32 & 0x1F) << CMD_HDR_CFL_SHIFT);
        self.prdbc = 0;
        self.ctba = (ctba_phys & 0xFFFF_FF80) as u32; // 128-byte aligned
        self.ctbau = (ctba_phys >> 32) as u32;
        self._reserved = [0u32; 4];
    }
}
