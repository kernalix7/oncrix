// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! AHCI (Advanced Host Controller Interface) port operations.
//!
//! Each AHCI port has its own register set describing the command list,
//! received FIS buffer, and status/control. Commands are submitted via
//! Command Slots in the Command List Base Address (CLB).
//!
//! # Command issue flow
//! 1. Fill a `CommandTable` with the FIS and PRD table.
//! 2. Fill the `PortCmdSlot` header in the CLB with the table address and FIS length.
//! 3. Set the corresponding bit in `CI` (Command Issue).
//! 4. Poll `CI` until the bit clears (command completed).
//!
//! Reference: Serial ATA AHCI 1.3.1 Specification.

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// AHCI Port Register Offsets (from port base = HBA_BASE + 0x100 + port*0x80)
// ---------------------------------------------------------------------------

/// CLB: Command List Base Address (lower 32 bits).
pub const PORT_CLB: u32 = 0x00;
/// CLBU: Command List Base Address (upper 32 bits).
pub const PORT_CLBU: u32 = 0x04;
/// FB: FIS Base Address (lower 32 bits).
pub const PORT_FB: u32 = 0x08;
/// FBU: FIS Base Address (upper 32 bits).
pub const PORT_FBU: u32 = 0x0C;
/// IS: Interrupt Status.
pub const PORT_IS: u32 = 0x10;
/// IE: Interrupt Enable.
pub const PORT_IE: u32 = 0x14;
/// CMD: Command and Status.
pub const PORT_CMD: u32 = 0x18;
/// TFD: Task File Data.
pub const PORT_TFD: u32 = 0x20;
/// SIG: Signature.
pub const PORT_SIG: u32 = 0x24;
/// SSTS: Serial ATA Status.
pub const PORT_SSTS: u32 = 0x28;
/// SCTL: Serial ATA Control.
pub const PORT_SCTL: u32 = 0x2C;
/// SERR: Serial ATA Error.
pub const PORT_SERR: u32 = 0x30;
/// SACT: Serial ATA Active (NCQ).
pub const PORT_SACT: u32 = 0x34;
/// CI: Command Issue.
pub const PORT_CI: u32 = 0x38;

// ---------------------------------------------------------------------------
// Port CMD Register Bits
// ---------------------------------------------------------------------------

/// CMD: Start (bit 0) — set to start processing command list.
pub const PORT_CMD_ST: u32 = 1 << 0;
/// CMD: Spin-Up Device (bit 1).
pub const PORT_CMD_SUD: u32 = 1 << 1;
/// CMD: Power On Device (bit 2).
pub const PORT_CMD_POD: u32 = 1 << 2;
/// CMD: FIS Receive Enable (bit 4).
pub const PORT_CMD_FRE: u32 = 1 << 4;
/// CMD: FIS Receive Running (bit 14, read-only).
pub const PORT_CMD_FR: u32 = 1 << 14;
/// CMD: Command List Running (bit 15, read-only).
pub const PORT_CMD_CR: u32 = 1 << 15;

// ---------------------------------------------------------------------------
// Task File Data Bits
// ---------------------------------------------------------------------------

/// TFD: BSY — device is busy.
pub const TFD_BSY: u32 = 1 << 7;
/// TFD: DRQ — data transfer requested.
pub const TFD_DRQ: u32 = 1 << 3;

// ---------------------------------------------------------------------------
// SSTS Link Speed / Device Detection
// ---------------------------------------------------------------------------

/// SSTS DET field: device and phy link established.
pub const SSTS_DET_PRESENT: u8 = 3;
/// SSTS IPM field: active.
pub const SSTS_IPM_ACTIVE: u8 = 1;
/// SSTS DET mask.
pub const SSTS_DET_MASK: u32 = 0xF;
/// SSTS IPM shift.
pub const SSTS_IPM_SHIFT: u32 = 8;

// ---------------------------------------------------------------------------
// FIS Types
// ---------------------------------------------------------------------------

/// FIS type: Register Host-to-Device.
pub const FIS_TYPE_REG_H2D: u8 = 0x27;
/// FIS type: Register Device-to-Host.
pub const FIS_TYPE_REG_D2H: u8 = 0x34;
/// FIS type: DMA Setup.
pub const FIS_TYPE_DMA_SETUP: u8 = 0x41;
/// FIS type: PIO Setup.
pub const FIS_TYPE_PIO_SETUP: u8 = 0x5F;
/// FIS type: Data.
pub const FIS_TYPE_DATA: u8 = 0x46;
/// FIS type: BIST Activate.
pub const _FIS_TYPE_BIST: u8 = 0x58;
/// FIS type: Set Device Bits.
pub const _FIS_TYPE_SDB: u8 = 0xA1;

/// FIS H2D C bit (bit 7 of byte 1): indicates Command Register write.
pub const FIS_H2D_C_BIT: u8 = 0x80;

// ---------------------------------------------------------------------------
// ATA Commands
// ---------------------------------------------------------------------------

/// ATA command: READ DMA EXT (48-bit LBA).
pub const ATA_CMD_READ_DMA_EXT: u8 = 0x25;
/// ATA command: WRITE DMA EXT (48-bit LBA).
pub const ATA_CMD_WRITE_DMA_EXT: u8 = 0x35;
/// ATA command: FLUSH CACHE EXT.
pub const ATA_CMD_FLUSH_EXT: u8 = 0xEA;
/// ATA command: IDENTIFY DEVICE.
pub const ATA_CMD_IDENTIFY: u8 = 0xEC;

// ---------------------------------------------------------------------------
// FIS Structures
// ---------------------------------------------------------------------------

/// Register Host-to-Device FIS (sends ATA commands to device).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct FisRegH2D {
    /// FIS type (0x27).
    pub fis_type: u8,
    /// PM port (bits 3:0) and C bit (bit 7).
    pub pmport_c: u8,
    /// ATA command register.
    pub command: u8,
    /// Feature register (7:0).
    pub featurel: u8,
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
    /// Feature register (15:8).
    pub featureh: u8,
    /// Sector count (7:0).
    pub countl: u8,
    /// Sector count (15:8).
    pub counth: u8,
    /// ICC (isochronous command completion).
    pub icc: u8,
    /// Control register.
    pub control: u8,
    /// Reserved.
    _reserved: [u8; 4],
}

/// Register Device-to-Host FIS (carries ATA status and error back to host).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct FisRegD2H {
    /// FIS type (0x34).
    pub fis_type: u8,
    /// PM port (bits 3:0) and interrupt bit (bit 6).
    pub pmport_i: u8,
    /// Status register.
    pub status: u8,
    /// Error register.
    pub error: u8,
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
    /// Reserved.
    _reserved0: u8,
    /// Sector count (7:0).
    pub countl: u8,
    /// Sector count (15:8).
    pub counth: u8,
    /// Reserved.
    _reserved1: [u8; 6],
}

/// DMA Setup FIS.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct FisDmaSetup {
    /// FIS type (0x41).
    pub fis_type: u8,
    /// Flags.
    pub flags: u8,
    /// Reserved.
    _reserved0: [u8; 2],
    /// DMA buffer identifier (lower 32 bits).
    pub dma_buf_id_lo: u32,
    /// DMA buffer identifier (upper 32 bits).
    pub dma_buf_id_hi: u32,
    /// Reserved.
    _reserved1: u32,
    /// DMA buffer offset.
    pub dma_buf_offset: u32,
    /// Transfer count.
    pub transfer_count: u32,
    /// Reserved.
    _reserved2: u32,
}

// ---------------------------------------------------------------------------
// Command List Header (PRD entry count is in `prdtl`)
// ---------------------------------------------------------------------------

/// One entry in the AHCI Command List (32 bytes per slot, up to 32 slots).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct PortCmdSlot {
    /// DW0: FIS length (bits 4:0 in dwords), A/W/P/R/C flags in bits 15:5.
    pub dw0: u16,
    /// PRD Table Length (number of PRD entries).
    pub prdtl: u16,
    /// PRD Byte Count (written by hardware after command completion).
    pub prdbc: u32,
    /// Command Table Base Address (64-bit physical address).
    pub ctba: u64,
    /// Reserved.
    _reserved: [u32; 4],
}

/// One Physical Region Descriptor entry.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct PrdEntry {
    /// Data base address (lower 32 bits).
    pub dba: u32,
    /// Data base address (upper 32 bits).
    pub dbau: u32,
    /// Reserved.
    _reserved: u32,
    /// Byte count minus 1 (bits 21:0), interrupt on completion (bit 31).
    pub dbc_i: u32,
}

// ---------------------------------------------------------------------------
// AHCI Port Driver
// ---------------------------------------------------------------------------

/// MMIO read helper.
///
/// # Safety
/// `base + offset` must be a valid mapped MMIO address.
#[inline]
unsafe fn read_mmio32(base: u64, offset: u32) -> u32 {
    let ptr = (base + offset as u64) as *const u32;
    // SAFETY: Caller guarantees valid MMIO address.
    unsafe { core::ptr::read_volatile(ptr) }
}

/// MMIO write helper.
///
/// # Safety
/// See `read_mmio32`.
#[inline]
unsafe fn write_mmio32(base: u64, offset: u32, val: u32) {
    let ptr = (base + offset as u64) as *mut u32;
    // SAFETY: Caller guarantees valid MMIO address.
    unsafe { core::ptr::write_volatile(ptr, val) }
}

/// AHCI port controller.
pub struct AhciPort {
    /// Virtual base address of this port's register set.
    base: u64,
}

impl AhciPort {
    /// Creates a new `AhciPort` for the given MMIO base.
    pub const fn new(base: u64) -> Self {
        Self { base }
    }

    /// Returns `true` if a device is detected and the link is established.
    ///
    /// # Safety
    /// `base` must be a valid mapped AHCI port register region.
    pub unsafe fn is_device_present(&self) -> bool {
        // SAFETY: Reading SSTS to check device detection and power state.
        unsafe {
            let ssts = read_mmio32(self.base, PORT_SSTS);
            let det = (ssts & SSTS_DET_MASK) as u8;
            let ipm = ((ssts >> SSTS_IPM_SHIFT) & 0xF) as u8;
            det == SSTS_DET_PRESENT && ipm == SSTS_IPM_ACTIVE
        }
    }

    /// Starts the port (sets ST and FRE in CMD).
    ///
    /// # Safety
    /// CLB and FB must have been configured with valid physical addresses before
    /// starting the port. Must not be called if the port is already running.
    pub unsafe fn port_start(&self) -> Result<()> {
        // SAFETY: Starting the port enables command list and FIS receive processing.
        unsafe {
            // Wait for CR to clear
            let mut spin = 500_000u32;
            while read_mmio32(self.base, PORT_CMD) & PORT_CMD_CR != 0 {
                if spin == 0 {
                    return Err(Error::Busy);
                }
                spin -= 1;
                core::hint::spin_loop();
            }
            let cmd = read_mmio32(self.base, PORT_CMD);
            write_mmio32(self.base, PORT_CMD, cmd | PORT_CMD_FRE | PORT_CMD_ST);
        }
        Ok(())
    }

    /// Stops the port (clears ST, waits for CR; then clears FRE, waits for FR).
    ///
    /// # Safety
    /// No commands should be outstanding when stopping the port.
    pub unsafe fn port_stop(&self) -> Result<()> {
        // SAFETY: Stopping the port per AHCI spec §10.1.2.
        unsafe {
            let cmd = read_mmio32(self.base, PORT_CMD);
            write_mmio32(self.base, PORT_CMD, cmd & !(PORT_CMD_ST));
            // Wait for CR to clear
            let mut spin = 500_000u32;
            while read_mmio32(self.base, PORT_CMD) & PORT_CMD_CR != 0 {
                if spin == 0 {
                    return Err(Error::Busy);
                }
                spin -= 1;
                core::hint::spin_loop();
            }
            let cmd2 = read_mmio32(self.base, PORT_CMD);
            write_mmio32(self.base, PORT_CMD, cmd2 & !PORT_CMD_FRE);
            // Wait for FR to clear
            spin = 500_000;
            while read_mmio32(self.base, PORT_CMD) & PORT_CMD_FR != 0 {
                if spin == 0 {
                    return Err(Error::Busy);
                }
                spin -= 1;
                core::hint::spin_loop();
            }
        }
        Ok(())
    }

    /// Sets the Command List Base and FIS Base physical addresses.
    ///
    /// # Safety
    /// Both `clb_phys` and `fb_phys` must be valid DMA-accessible physical
    /// addresses aligned to 1 KiB and 256 bytes respectively.
    pub unsafe fn set_buffers(&self, clb_phys: u64, fb_phys: u64) {
        // SAFETY: Programming CLB/FB before starting the port.
        unsafe {
            write_mmio32(self.base, PORT_CLB, clb_phys as u32);
            write_mmio32(self.base, PORT_CLBU, (clb_phys >> 32) as u32);
            write_mmio32(self.base, PORT_FB, fb_phys as u32);
            write_mmio32(self.base, PORT_FBU, (fb_phys >> 32) as u32);
        }
    }

    /// Issues a command in slot `slot` by setting the corresponding bit in CI.
    ///
    /// # Safety
    /// The command slot must have been fully prepared (FIS, PRD, CLB header)
    /// before calling this.
    pub unsafe fn issue_command(&self, slot: u8) -> Result<()> {
        if slot >= 32 {
            return Err(Error::InvalidArgument);
        }
        // SAFETY: Writing CI bit triggers hardware DMA.
        unsafe {
            write_mmio32(self.base, PORT_CI, 1 << slot);
        }
        Ok(())
    }

    /// Polls until command slot `slot` completes or times out.
    ///
    /// # Safety
    /// Must be called after `issue_command`.
    pub unsafe fn poll_command(&self, slot: u8) -> Result<()> {
        if slot >= 32 {
            return Err(Error::InvalidArgument);
        }
        let slot_mask = 1u32 << slot;
        // SAFETY: Polling CI and TFD to detect command completion.
        unsafe {
            let mut spin = 1_000_000u32;
            loop {
                if read_mmio32(self.base, PORT_CI) & slot_mask == 0 {
                    break;
                }
                let is = read_mmio32(self.base, PORT_IS);
                if is & (1 << 30) != 0 {
                    // Task file error
                    return Err(Error::IoError);
                }
                if spin == 0 {
                    return Err(Error::Busy);
                }
                spin -= 1;
                core::hint::spin_loop();
            }
            // Verify no error in TFD
            let tfd = read_mmio32(self.base, PORT_TFD);
            if tfd & 0x01 != 0 {
                // ERR bit set in alternate status
                return Err(Error::IoError);
            }
        }
        Ok(())
    }

    /// Acknowledges all pending interrupt status bits.
    ///
    /// Should be called from the AHCI interrupt handler.
    ///
    /// # Safety
    /// Must be called from an interrupt handler context.
    pub unsafe fn ack_interrupts(&self) -> u32 {
        // SAFETY: Writing IS bits clears them (write-1-to-clear).
        unsafe {
            let is = read_mmio32(self.base, PORT_IS);
            write_mmio32(self.base, PORT_IS, is);
            is
        }
    }

    /// Reads the port signature to identify the connected device type.
    ///
    /// Common values: 0x00000101 = SATA HDD, 0xEB140101 = SATAPI.
    ///
    /// # Safety
    /// Port must have a device present.
    pub unsafe fn signature(&self) -> u32 {
        // SAFETY: Reading SIG register after device detection.
        unsafe { read_mmio32(self.base, PORT_SIG) }
    }

    /// Clears SATA errors.
    ///
    /// # Safety
    /// Must be called before issuing commands after a link error.
    pub unsafe fn clear_errors(&self) {
        // SAFETY: Writing 1s to SERR clears error bits (write-1-to-clear).
        unsafe {
            let serr = read_mmio32(self.base, PORT_SERR);
            write_mmio32(self.base, PORT_SERR, serr);
        }
    }
}
