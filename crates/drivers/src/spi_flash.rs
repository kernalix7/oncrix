// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! SPI NOR flash driver.
//!
//! Implements a driver for industry-standard SPI NOR flash devices
//! (JEDEC-compatible: Winbond, Macronix, Micron, etc.), supporting:
//!
//! - JEDEC ID detection.
//! - Read, page-program, sector erase, block erase, chip erase.
//! - Status register polling (WIP bit).
//! - Write-enable / write-disable.
//!
//! # SPI commands
//!
//! | Command | Opcode | Description |
//! |---------|--------|-------------|
//! | READ    | 0x03   | Read data bytes |
//! | FAST_READ | 0x0B | Fast read with dummy byte |
//! | PP      | 0x02   | Page program |
//! | SE      | 0x20   | Sector erase (4 KiB) |
//! | BE      | 0xD8   | Block erase (64 KiB) |
//! | CE      | 0xC7   | Chip erase |
//! | RDSR    | 0x05   | Read Status Register |
//! | WRSR    | 0x01   | Write Status Register |
//! | WREN    | 0x06   | Write Enable |
//! | WRDI    | 0x04   | Write Disable |
//! | RDID    | 0x9F   | Read JEDEC ID |

extern crate alloc;
use alloc::vec::Vec;

use oncrix_lib::{Error, Result};

// ── SPI command opcodes ───────────────────────────────────────────────────────

/// Read data (up to 25 MHz).
pub const CMD_READ: u8 = 0x03;
/// Fast read with one dummy byte (up to 104 MHz).
pub const CMD_FAST_READ: u8 = 0x0B;
/// Page program (256 bytes max).
pub const CMD_PP: u8 = 0x02;
/// Sector erase (4 KiB).
pub const CMD_SE: u8 = 0x20;
/// Block erase (64 KiB).
pub const CMD_BE: u8 = 0xD8;
/// Chip erase.
pub const CMD_CE: u8 = 0xC7;
/// Read status register.
pub const CMD_RDSR: u8 = 0x05;
/// Write status register.
pub const CMD_WRSR: u8 = 0x01;
/// Write enable.
pub const CMD_WREN: u8 = 0x06;
/// Write disable.
pub const CMD_WRDI: u8 = 0x04;
/// Read JEDEC ID.
pub const CMD_RDID: u8 = 0x9F;

// ── Status register bits ─────────────────────────────────────────────────────

/// SR: Write In Progress — flash is erasing or programming.
pub const SR_WIP: u8 = 1 << 0;
/// SR: Write Enable Latch — write/erase is permitted.
pub const SR_WEL: u8 = 1 << 1;

// ── Size constants ───────────────────────────────────────────────────────────

/// Typical sector size: 4 KiB.
pub const SECTOR_SIZE: u32 = 4096;
/// Typical block size: 64 KiB.
pub const BLOCK_SIZE: u32 = 65536;
/// Typical page size: 256 bytes.
pub const PAGE_SIZE: u32 = 256;

/// Polling timeout for WIP bit clear.
const WIP_TIMEOUT: u32 = 10_000_000;

// ── SpiTransfer ──────────────────────────────────────────────────────────────

/// A SPI transfer: TX buffer and optional RX buffer.
#[derive(Debug)]
pub struct SpiTransfer<'a> {
    /// Data to transmit (must not be empty).
    pub tx: &'a [u8],
    /// Buffer to receive into (may be empty for write-only).
    pub rx: &'a mut [u8],
}

// ── SpiBusOps ────────────────────────────────────────────────────────────────

/// SPI bus operations trait.
///
/// Implementors provide a full-duplex SPI transfer and chip-select control.
pub trait SpiBusOps {
    /// Assert chip-select (active low).
    fn cs_assert(&mut self);
    /// De-assert chip-select.
    fn cs_deassert(&mut self);
    /// Perform a synchronous full-duplex transfer.
    ///
    /// `tx` bytes are transmitted; `rx` bytes are received in parallel.
    /// If `rx.len() < tx.len()` the extra received bytes are discarded.
    ///
    /// # Errors
    ///
    /// Return [`Error::IoError`] on bus error.
    fn transfer(&mut self, tx: &[u8], rx: &mut [u8]) -> Result<()>;
}

// ── JedecId ──────────────────────────────────────────────────────────────────

/// Parsed JEDEC flash ID.
#[derive(Debug, Clone, Copy, Default)]
pub struct JedecId {
    /// Manufacturer ID byte.
    pub manufacturer: u8,
    /// Memory type byte.
    pub mem_type: u8,
    /// Capacity code byte.
    pub capacity: u8,
}

impl JedecId {
    /// Return the flash capacity in bytes derived from the capacity code.
    ///
    /// Assumes JEDEC standard: capacity = 2^capacity_code bytes.
    /// Returns 0 for capacity codes outside 0x10–0x22.
    pub fn size_bytes(&self) -> u64 {
        let code = self.capacity;
        if (0x10..=0x22).contains(&code) {
            1u64 << code
        } else {
            0
        }
    }
}

// ── SpiFlashDevice ───────────────────────────────────────────────────────────

/// SPI NOR flash device.
pub struct SpiFlashDevice {
    /// JEDEC ID read at init time.
    pub jedec_id: JedecId,
    /// Total flash capacity in bytes.
    pub size: u64,
    /// Page size in bytes.
    pub page_size: u32,
    /// Sector (smallest erasable unit) size in bytes.
    pub sector_size: u32,
    /// Block (large erase unit) size in bytes.
    pub block_size: u32,
    /// Whether the device has been successfully initialised.
    pub initialised: bool,
}

impl SpiFlashDevice {
    /// Create an uninitialised SPI flash device.
    pub const fn new() -> Self {
        Self {
            jedec_id: JedecId {
                manufacturer: 0,
                mem_type: 0,
                capacity: 0,
            },
            size: 0,
            page_size: PAGE_SIZE,
            sector_size: SECTOR_SIZE,
            block_size: BLOCK_SIZE,
            initialised: false,
        }
    }

    /// Initialise the device by reading the JEDEC ID.
    ///
    /// # Errors
    ///
    /// Returns [`Error::IoError`] if the JEDEC ID is all zeros or 0xFF
    /// (no device detected).
    pub fn init(&mut self, spi: &mut dyn SpiBusOps) -> Result<()> {
        let id = self.read_jedec_id(spi)?;
        if id.manufacturer == 0x00 || id.manufacturer == 0xFF {
            return Err(Error::IoError);
        }
        self.jedec_id = id;
        self.size = id.size_bytes();
        self.initialised = true;
        Ok(())
    }

    /// Read the JEDEC ID from the flash.
    fn read_jedec_id(&self, spi: &mut dyn SpiBusOps) -> Result<JedecId> {
        let tx = [CMD_RDID];
        let mut rx = [0u8; 4]; // 1 cmd + 3 ID bytes
        spi.cs_assert();
        spi.transfer(&tx, &mut rx)?;
        spi.cs_deassert();
        Ok(JedecId {
            manufacturer: rx[1],
            mem_type: rx[2],
            capacity: rx[3],
        })
    }

    /// Send write-enable command.
    pub fn write_enable(&self, spi: &mut dyn SpiBusOps) -> Result<()> {
        self.cmd_no_data(spi, CMD_WREN)
    }

    /// Send write-disable command.
    pub fn write_disable(&self, spi: &mut dyn SpiBusOps) -> Result<()> {
        self.cmd_no_data(spi, CMD_WRDI)
    }

    /// Read the status register.
    pub fn read_status(&self, spi: &mut dyn SpiBusOps) -> Result<u8> {
        let tx = [CMD_RDSR, 0x00];
        let mut rx = [0u8; 2];
        spi.cs_assert();
        spi.transfer(&tx, &mut rx)?;
        spi.cs_deassert();
        Ok(rx[1])
    }

    /// Poll the WIP bit until the flash is idle.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Busy`] if the flash does not become ready within
    /// `WIP_TIMEOUT` iterations.
    pub fn wait_ready(&self, spi: &mut dyn SpiBusOps) -> Result<()> {
        for _ in 0..WIP_TIMEOUT {
            let sr = self.read_status(spi)?;
            if sr & SR_WIP == 0 {
                return Ok(());
            }
            core::hint::spin_loop();
        }
        Err(Error::Busy)
    }

    /// Read `len` bytes from `addr` into `buf`.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidArgument`] if the read would exceed the device size.
    /// - Propagates SPI bus errors.
    pub fn read(&self, spi: &mut dyn SpiBusOps, addr: u32, buf: &mut [u8]) -> Result<()> {
        self.check_bounds(addr, buf.len())?;
        // Build command: READ + 3-byte address.
        let tx = [CMD_READ, (addr >> 16) as u8, (addr >> 8) as u8, addr as u8];
        // We need to receive tx.len() + buf.len() bytes total.
        let mut full_rx = Vec::new();
        full_rx.resize(tx.len() + buf.len(), 0u8);
        spi.cs_assert();
        spi.transfer(&tx, &mut full_rx)?;
        spi.cs_deassert();
        buf.copy_from_slice(&full_rx[tx.len()..]);
        Ok(())
    }

    /// Program up to one page (256 bytes) at `addr`.
    ///
    /// `addr` must be page-aligned. `data` must not exceed `page_size`.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidArgument`] if misaligned or data too large.
    pub fn write_page(&self, spi: &mut dyn SpiBusOps, addr: u32, data: &[u8]) -> Result<()> {
        if addr % self.page_size != 0 {
            return Err(Error::InvalidArgument);
        }
        if data.len() > self.page_size as usize {
            return Err(Error::InvalidArgument);
        }
        self.write_enable(spi)?;
        let mut cmd = Vec::new();
        cmd.push(CMD_PP);
        cmd.push((addr >> 16) as u8);
        cmd.push((addr >> 8) as u8);
        cmd.push(addr as u8);
        cmd.extend_from_slice(data);

        let rx_len = cmd.len();
        let mut rx = Vec::new();
        rx.resize(rx_len, 0u8);
        spi.cs_assert();
        spi.transfer(&cmd, &mut rx)?;
        spi.cs_deassert();
        self.wait_ready(spi)
    }

    /// Erase a 4 KiB sector containing `addr`.
    ///
    /// `addr` must be sector-aligned.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if misaligned.
    pub fn erase_sector(&self, spi: &mut dyn SpiBusOps, addr: u32) -> Result<()> {
        if addr % self.sector_size != 0 {
            return Err(Error::InvalidArgument);
        }
        self.write_enable(spi)?;
        let tx = [CMD_SE, (addr >> 16) as u8, (addr >> 8) as u8, addr as u8];
        let mut rx = [0u8; 4];
        spi.cs_assert();
        spi.transfer(&tx, &mut rx)?;
        spi.cs_deassert();
        self.wait_ready(spi)
    }

    /// Erase a 64 KiB block at `addr`.
    ///
    /// `addr` must be block-aligned.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if misaligned.
    pub fn erase_block(&self, spi: &mut dyn SpiBusOps, addr: u32) -> Result<()> {
        if addr % self.block_size != 0 {
            return Err(Error::InvalidArgument);
        }
        self.write_enable(spi)?;
        let tx = [CMD_BE, (addr >> 16) as u8, (addr >> 8) as u8, addr as u8];
        let mut rx = [0u8; 4];
        spi.cs_assert();
        spi.transfer(&tx, &mut rx)?;
        spi.cs_deassert();
        self.wait_ready(spi)
    }

    /// Erase the entire chip.
    ///
    /// This may take several seconds on large flash devices.
    pub fn erase_chip(&self, spi: &mut dyn SpiBusOps) -> Result<()> {
        self.write_enable(spi)?;
        self.cmd_no_data(spi, CMD_CE)?;
        self.wait_ready(spi)
    }

    // ── Private helpers ──────────────────────────────────────────────────────

    /// Send a single-byte command with no additional data.
    fn cmd_no_data(&self, spi: &mut dyn SpiBusOps, cmd: u8) -> Result<()> {
        let tx = [cmd];
        let mut rx = [0u8; 1];
        spi.cs_assert();
        spi.transfer(&tx, &mut rx)?;
        spi.cs_deassert();
        Ok(())
    }

    /// Validate that `[addr, addr+len)` is within the device bounds.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if the range exceeds device size.
    fn check_bounds(&self, addr: u32, len: usize) -> Result<()> {
        let end = addr as u64 + len as u64;
        if self.size > 0 && end > self.size {
            return Err(Error::InvalidArgument);
        }
        Ok(())
    }
}

impl Default for SpiFlashDevice {
    fn default() -> Self {
        Self::new()
    }
}
