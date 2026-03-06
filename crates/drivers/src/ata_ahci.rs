// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! AHCI (Advanced Host Controller Interface) SATA driver.
//!
//! Implements the AHCI port state machine for submitting commands to SATA
//! devices attached to an HBA (Host Bus Adapter). This module focuses on the
//! command list / FIS receive / command table structures and the port command
//! engine startup procedure.
//!
//! Reference: AHCI 1.3.1 specification (Intel).

use oncrix_lib::{Error, Result};

/// Maximum number of command slots per port (AHCI supports 1-32).
pub const AHCI_MAX_CMD_SLOTS: usize = 32;
/// Number of PRD entries per command table.
pub const AHCI_PRD_ENTRIES: usize = 8;

// AHCI Port register offsets (from port base).
const PORT_CLB: usize = 0x00; // Command List Base Address (low)
const PORT_CLBU: usize = 0x04; // Command List Base Address (high)
const PORT_FB: usize = 0x08; // FIS Base Address (low)
const PORT_FBU: usize = 0x0C; // FIS Base Address (high)
const PORT_IS: usize = 0x10; // Interrupt Status
const PORT_IE: usize = 0x14; // Interrupt Enable
const PORT_CMD: usize = 0x18; // Command and Status
const PORT_TFD: usize = 0x20; // Task File Data
const PORT_SIG: usize = 0x24; // Signature
const PORT_SSTS: usize = 0x28; // SATA Status
const PORT_CI: usize = 0x38; // Command Issue

// PORT_CMD bits
const PORT_CMD_ST: u32 = 1 << 0; // Start
const PORT_CMD_FRE: u32 = 1 << 4; // FIS Receive Enable
const PORT_CMD_FR: u32 = 1 << 14; // FIS Receive Running
const PORT_CMD_CR: u32 = 1 << 15; // Command List Running

// PORT_SSTS link detect
const SSTS_DET_MASK: u32 = 0xF;
const SSTS_DET_PRESENT: u32 = 0x3;

/// Physical Region Descriptor (PRD) entry — one scatter-gather element.
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct PrdEntry {
    /// Data base address (low).
    pub dba: u32,
    /// Data base address (high).
    pub dbau: u32,
    /// Reserved.
    pub _reserved: u32,
    /// Byte count (DBC) — bits [21:0], bit 31 = interrupt-on-completion.
    pub dbc: u32,
}

/// AHCI command table (one per slot).
#[derive(Debug, Clone, Copy)]
#[repr(C, align(128))]
pub struct CommandTable {
    /// Command FIS (up to 64 bytes).
    pub cfis: [u8; 64],
    /// ATAPI command (12 or 16 bytes).
    pub acmd: [u8; 16],
    /// Reserved.
    pub _reserved: [u8; 48],
    /// PRD table.
    pub prdt: [PrdEntry; AHCI_PRD_ENTRIES],
}

impl CommandTable {
    /// Creates a zeroed command table.
    pub const fn new() -> Self {
        Self {
            cfis: [0u8; 64],
            acmd: [0u8; 16],
            _reserved: [0u8; 48],
            prdt: [const {
                PrdEntry {
                    dba: 0,
                    dbau: 0,
                    _reserved: 0,
                    dbc: 0,
                }
            }; AHCI_PRD_ENTRIES],
        }
    }
}

impl Default for CommandTable {
    fn default() -> Self {
        Self::new()
    }
}

/// AHCI command header (one per slot in the command list).
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct CommandHeader {
    /// Flags: CFL[4:0], ATAPI, Write, Prefetch, Reset, BIST, Clear, PMP[3:0], PRDTL[15:0].
    pub flags_prdtl: u32,
    /// Physical Region Descriptor Byte Count (written by hardware).
    pub prdbc: u32,
    /// Command Table Base Address (low).
    pub ctba: u32,
    /// Command Table Base Address (high).
    pub ctbau: u32,
    /// Reserved.
    pub _reserved: [u32; 4],
}

/// AHCI port state.
pub struct AhciPort {
    /// MMIO base of this port's registers.
    port_base: usize,
    /// Slot availability bitmap (bit=1 means free).
    free_slots: u32,
    /// Number of command slots supported.
    num_slots: usize,
}

impl AhciPort {
    /// Creates an AHCI port handle.
    ///
    /// # Arguments
    ///
    /// * `port_base` — Physical MMIO address of this port's register block.
    /// * `num_slots` — Number of command slots (from CAP.NCS).
    pub const fn new(port_base: usize, num_slots: usize) -> Self {
        let free_slots = if num_slots >= 32 {
            u32::MAX
        } else {
            (1u32 << num_slots) - 1
        };
        Self {
            port_base,
            free_slots,
            num_slots,
        }
    }

    /// Checks whether a device is attached (SATA status DET == 0x3).
    pub fn device_present(&self) -> bool {
        let ssts = self.read32(PORT_SSTS);
        (ssts & SSTS_DET_MASK) == SSTS_DET_PRESENT
    }

    /// Starts the port command engine (ST + FRE).
    pub fn start(&mut self) -> Result<()> {
        // Wait for command list to be not running.
        for _ in 0..10_000u32 {
            if (self.read32(PORT_CMD) & PORT_CMD_CR) == 0 {
                break;
            }
        }
        let cmd = self.read32(PORT_CMD);
        self.write32(PORT_CMD, cmd | PORT_CMD_FRE | PORT_CMD_ST);
        Ok(())
    }

    /// Stops the port command engine.
    pub fn stop(&mut self) -> Result<()> {
        let mut cmd = self.read32(PORT_CMD);
        cmd &= !(PORT_CMD_ST);
        self.write32(PORT_CMD, cmd);
        for _ in 0..10_000u32 {
            if (self.read32(PORT_CMD) & PORT_CMD_CR) == 0 {
                break;
            }
        }
        cmd = self.read32(PORT_CMD);
        cmd &= !(PORT_CMD_FRE);
        self.write32(PORT_CMD, cmd);
        for _ in 0..10_000u32 {
            if (self.read32(PORT_CMD) & PORT_CMD_FR) == 0 {
                return Ok(());
            }
        }
        Err(Error::Busy)
    }

    /// Sets the command list base address (physical).
    pub fn set_cmd_list_base(&self, paddr: u64) {
        self.write32(PORT_CLB, paddr as u32);
        self.write32(PORT_CLBU, (paddr >> 32) as u32);
    }

    /// Sets the FIS receive base address (physical).
    pub fn set_fis_base(&self, paddr: u64) {
        self.write32(PORT_FB, paddr as u32);
        self.write32(PORT_FBU, (paddr >> 32) as u32);
    }

    /// Issues a command in the first free slot.
    ///
    /// `ctba_paddr` is the physical address of the command table.
    pub fn issue_command(&mut self, ctba_paddr: u64, write: bool, prd_count: u16) -> Result<u8> {
        let slot = self.alloc_slot()?;
        // In a real driver we'd write the command header at slot * sizeof(CommandHeader).
        // Here we model the CI register write.
        let _ = (ctba_paddr, write, prd_count); // consumed by caller-set CommandHeader
        self.write32(PORT_CI, 1 << slot);
        Ok(slot)
    }

    /// Polls for completion of command in `slot`.
    pub fn poll_slot(&self, slot: u8) -> Result<bool> {
        if (slot as usize) >= self.num_slots {
            return Err(Error::InvalidArgument);
        }
        let ci = self.read32(PORT_CI);
        Ok((ci & (1 << slot)) == 0)
    }

    /// Releases `slot` back to the free pool.
    pub fn free_slot(&mut self, slot: u8) {
        self.free_slots |= 1 << slot;
    }

    /// Returns the Task File Data register (BSY/DRQ bits).
    pub fn task_file_data(&self) -> u32 {
        self.read32(PORT_TFD)
    }

    /// Clears all port interrupt status bits.
    pub fn clear_interrupts(&self) {
        let is = self.read32(PORT_IS);
        self.write32(PORT_IS, is);
    }

    /// Returns the number of command slots.
    pub fn num_slots(&self) -> usize {
        self.num_slots
    }

    // ---- private helpers ----

    fn alloc_slot(&mut self) -> Result<u8> {
        if self.free_slots == 0 {
            return Err(Error::Busy);
        }
        let slot = self.free_slots.trailing_zeros() as u8;
        self.free_slots &= !(1u32 << slot);
        Ok(slot)
    }

    fn read32(&self, offset: usize) -> u32 {
        let ptr = (self.port_base + offset) as *const u32;
        // SAFETY: port_base is a valid mapped AHCI port register block.
        unsafe { core::ptr::read_volatile(ptr) }
    }

    fn write32(&self, offset: usize, val: u32) {
        let ptr = (self.port_base + offset) as *mut u32;
        // SAFETY: port_base is a valid mapped AHCI port register block.
        unsafe { core::ptr::write_volatile(ptr, val) }
    }
}

/// Returns the AHCI port MMIO base for port `n` given the HBA base.
pub fn port_base(hba_base: usize, port: usize) -> usize {
    hba_base + 0x100 + port * 0x80
}

/// Builds a Register H2D FIS for an ATA command.
pub fn build_reg_h2d_fis(buf: &mut [u8; 64], command: u8, lba48: u64, count: u16) {
    buf[0] = 0x27; // FIS type: Register H2D
    buf[1] = 0x80; // C=1 (command update)
    buf[2] = command;
    buf[3] = 0; // features
    buf[4] = (lba48 & 0xFF) as u8;
    buf[5] = ((lba48 >> 8) & 0xFF) as u8;
    buf[6] = ((lba48 >> 16) & 0xFF) as u8;
    buf[7] = 0xE0; // device: LBA mode
    buf[8] = ((lba48 >> 24) & 0xFF) as u8;
    buf[9] = ((lba48 >> 32) & 0xFF) as u8;
    buf[10] = ((lba48 >> 40) & 0xFF) as u8;
    buf[11] = 0; // features (ext)
    buf[12] = (count & 0xFF) as u8;
    buf[13] = ((count >> 8) & 0xFF) as u8;
}
