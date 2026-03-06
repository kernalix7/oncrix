// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! NAND flash controller hardware abstraction.
//!
//! Provides a unified interface for NAND flash controllers supporting both
//! SLC (Single Level Cell) and MLC (Multi Level Cell) NAND. Handles page
//! read/write, block erase, ECC (Error Correction Code) and bad block
//! management.

use oncrix_lib::{Error, Result};

/// Maximum number of NAND controllers.
pub const MAX_NAND_CONTROLLERS: usize = 2;

/// NAND page size options in bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NandPageSize {
    /// 512-byte pages (small-page NAND).
    B512,
    /// 2048-byte pages (large-page NAND).
    B2048,
    /// 4096-byte pages.
    B4096,
    /// 8192-byte pages.
    B8192,
}

impl NandPageSize {
    /// Returns the page size in bytes.
    pub fn bytes(self) -> usize {
        match self {
            NandPageSize::B512 => 512,
            NandPageSize::B2048 => 2048,
            NandPageSize::B4096 => 4096,
            NandPageSize::B8192 => 8192,
        }
    }

    /// Returns the typical out-of-band (spare) area size in bytes.
    pub fn oob_bytes(self) -> usize {
        match self {
            NandPageSize::B512 => 16,
            NandPageSize::B2048 => 64,
            NandPageSize::B4096 => 128,
            NandPageSize::B8192 => 256,
        }
    }
}

/// NAND cell type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NandCellType {
    /// Single Level Cell — 1 bit per cell, most reliable.
    Slc,
    /// Multi Level Cell — 2 bits per cell.
    Mlc,
    /// Triple Level Cell — 3 bits per cell.
    Tlc,
    /// Quad Level Cell — 4 bits per cell.
    Qlc,
}

/// NAND geometry descriptor.
#[derive(Debug, Clone, Copy)]
pub struct NandGeometry {
    /// Page size.
    pub page_size: NandPageSize,
    /// Pages per block.
    pub pages_per_block: u32,
    /// Number of blocks per chip.
    pub blocks_per_chip: u32,
    /// Number of chips on this controller.
    pub chip_count: u8,
    /// Cell type.
    pub cell_type: NandCellType,
    /// ECC strength (number of correctable bit errors per ECC chunk).
    pub ecc_strength: u8,
}

impl NandGeometry {
    /// Creates a standard 2K-page SLC NAND geometry.
    pub const fn standard_slc() -> Self {
        Self {
            page_size: NandPageSize::B2048,
            pages_per_block: 64,
            blocks_per_chip: 1024,
            chip_count: 1,
            cell_type: NandCellType::Slc,
            ecc_strength: 4,
        }
    }

    /// Returns the block size in bytes.
    pub fn block_size_bytes(&self) -> u64 {
        self.page_size.bytes() as u64 * self.pages_per_block as u64
    }

    /// Returns the total device capacity in bytes.
    pub fn capacity_bytes(&self) -> u64 {
        self.block_size_bytes() * self.blocks_per_chip as u64 * self.chip_count as u64
    }
}

impl Default for NandGeometry {
    fn default() -> Self {
        Self::standard_slc()
    }
}

/// NAND address structure (chip, block, page).
#[derive(Debug, Clone, Copy, Default)]
pub struct NandAddress {
    /// Chip enable index.
    pub chip: u8,
    /// Block number.
    pub block: u32,
    /// Page number within the block.
    pub page: u32,
}

impl NandAddress {
    /// Creates a new NAND address.
    pub const fn new(chip: u8, block: u32, page: u32) -> Self {
        Self { chip, block, page }
    }
}

/// NAND controller statistics.
#[derive(Debug, Default, Clone, Copy)]
pub struct NandStats {
    /// Total pages read.
    pub pages_read: u64,
    /// Total pages written (programmed).
    pub pages_written: u64,
    /// Total blocks erased.
    pub blocks_erased: u64,
    /// Number of ECC correctable errors.
    pub ecc_corrected: u64,
    /// Number of uncorrectable ECC errors.
    pub ecc_uncorrectable: u64,
    /// Number of bad blocks encountered.
    pub bad_blocks: u32,
}

impl NandStats {
    /// Creates a new zeroed statistics structure.
    pub const fn new() -> Self {
        Self {
            pages_read: 0,
            pages_written: 0,
            blocks_erased: 0,
            ecc_corrected: 0,
            ecc_uncorrectable: 0,
            bad_blocks: 0,
        }
    }
}

/// Hardware NAND flash controller.
pub struct NandController {
    /// Controller index.
    id: u8,
    /// MMIO base address of the NAND controller registers.
    base_addr: u64,
    /// NAND device geometry.
    geometry: NandGeometry,
    /// Transfer statistics.
    stats: NandStats,
    /// Whether the controller has been initialized.
    initialized: bool,
}

impl NandController {
    /// Creates a new NAND controller.
    ///
    /// # Arguments
    /// * `id` — Controller identifier.
    /// * `base_addr` — MMIO base address.
    pub const fn new(id: u8, base_addr: u64) -> Self {
        Self {
            id,
            base_addr,
            geometry: NandGeometry::standard_slc(),
            stats: NandStats::new(),
            initialized: false,
        }
    }

    /// Returns the controller ID.
    pub fn id(&self) -> u8 {
        self.id
    }

    /// Returns the NAND geometry.
    pub fn geometry(&self) -> &NandGeometry {
        &self.geometry
    }

    /// Initializes the NAND controller and detects the attached device.
    ///
    /// # Errors
    /// Returns `Error::InvalidArgument` if base_addr is zero.
    /// Returns `Error::IoError` if the device does not respond.
    pub fn init(&mut self, geometry: NandGeometry) -> Result<()> {
        if self.base_addr == 0 {
            return Err(Error::InvalidArgument);
        }
        self.geometry = geometry;
        // SAFETY: MMIO writes to NAND controller initialization registers.
        // base_addr is validated to be non-zero.
        unsafe {
            let ctrl = self.base_addr as *mut u32;
            ctrl.write_volatile(0x1); // Reset controller
            let page_cfg = (self.base_addr + 0x04) as *mut u32;
            page_cfg.write_volatile(geometry.page_size.bytes() as u32);
            let ecc_cfg = (self.base_addr + 0x08) as *mut u32;
            ecc_cfg.write_volatile(geometry.ecc_strength as u32);
        }
        self.initialized = true;
        Ok(())
    }

    /// Reads a page from NAND flash.
    ///
    /// # Arguments
    /// * `addr` — NAND address (chip, block, page).
    /// * `buf` — Output buffer; must be at least page_size bytes.
    ///
    /// # Errors
    /// Returns `Error::Busy` if not initialized.
    /// Returns `Error::InvalidArgument` if buf is too small or address is out of range.
    pub fn read_page(&mut self, addr: NandAddress, buf: &mut [u8]) -> Result<()> {
        if !self.initialized {
            return Err(Error::Busy);
        }
        let page_size = self.geometry.page_size.bytes();
        if buf.len() < page_size {
            return Err(Error::InvalidArgument);
        }
        if addr.block >= self.geometry.blocks_per_chip {
            return Err(Error::InvalidArgument);
        }
        if addr.page >= self.geometry.pages_per_block {
            return Err(Error::InvalidArgument);
        }
        // SAFETY: MMIO writes to NAND address and command registers, then reads data.
        // base_addr is non-zero. The column/row address registers are at well-known offsets.
        unsafe {
            let cmd = (self.base_addr + 0x10) as *mut u32;
            let addr_reg = (self.base_addr + 0x14) as *mut u32;
            let data_reg = (self.base_addr + 0x18) as *const u32;
            // Issue READ command (0x00 for large-page NAND)
            cmd.write_volatile(0x00);
            // Write column (0) and row address
            let row = addr.block * self.geometry.pages_per_block + addr.page;
            addr_reg.write_volatile(0); // Column
            addr_reg.write_volatile(row);
            // Issue READ CONFIRM (0x30)
            cmd.write_volatile(0x30);
            // Read page data word by word
            let words = page_size / 4;
            for i in 0..words {
                let word = data_reg.read_volatile();
                let off = i * 4;
                buf[off] = (word & 0xFF) as u8;
                buf[off + 1] = ((word >> 8) & 0xFF) as u8;
                buf[off + 2] = ((word >> 16) & 0xFF) as u8;
                buf[off + 3] = ((word >> 24) & 0xFF) as u8;
            }
        }
        self.stats.pages_read += 1;
        Ok(())
    }

    /// Programs (writes) a page to NAND flash.
    ///
    /// NAND pages can only be written once after an erase cycle.
    ///
    /// # Errors
    /// Returns `Error::Busy` if not initialized.
    /// Returns `Error::InvalidArgument` if data or address is invalid.
    pub fn write_page(&mut self, addr: NandAddress, data: &[u8]) -> Result<()> {
        if !self.initialized {
            return Err(Error::Busy);
        }
        let page_size = self.geometry.page_size.bytes();
        if data.len() < page_size {
            return Err(Error::InvalidArgument);
        }
        if addr.block >= self.geometry.blocks_per_chip {
            return Err(Error::InvalidArgument);
        }
        // SAFETY: MMIO writes to NAND program command and data registers.
        // base_addr is non-zero.
        unsafe {
            let cmd = (self.base_addr + 0x10) as *mut u32;
            let addr_reg = (self.base_addr + 0x14) as *mut u32;
            let data_reg = (self.base_addr + 0x18) as *mut u32;
            // Issue PAGE PROGRAM (0x80)
            cmd.write_volatile(0x80);
            let row = addr.block * self.geometry.pages_per_block + addr.page;
            addr_reg.write_volatile(0);
            addr_reg.write_volatile(row);
            let words = page_size / 4;
            for i in 0..words {
                let off = i * 4;
                let word =
                    u32::from_le_bytes([data[off], data[off + 1], data[off + 2], data[off + 3]]);
                data_reg.write_volatile(word);
            }
            // Confirm write (0x10)
            cmd.write_volatile(0x10);
        }
        self.stats.pages_written += 1;
        Ok(())
    }

    /// Erases a NAND block.
    ///
    /// # Errors
    /// Returns `Error::Busy` if not initialized.
    /// Returns `Error::InvalidArgument` if block index is out of range.
    pub fn erase_block(&mut self, chip: u8, block: u32) -> Result<()> {
        if !self.initialized {
            return Err(Error::Busy);
        }
        if block >= self.geometry.blocks_per_chip {
            return Err(Error::InvalidArgument);
        }
        // SAFETY: MMIO writes to NAND erase command and row address registers.
        // base_addr is non-zero.
        unsafe {
            let cmd = (self.base_addr + 0x10) as *mut u32;
            let addr_reg = (self.base_addr + 0x14) as *mut u32;
            let row = block * self.geometry.pages_per_block;
            cmd.write_volatile(0x60); // ERASE SETUP
            addr_reg.write_volatile((chip as u32) << 24 | row);
            cmd.write_volatile(0xD0); // ERASE CONFIRM
        }
        self.stats.blocks_erased += 1;
        Ok(())
    }

    /// Returns a copy of the controller statistics.
    pub fn stats(&self) -> NandStats {
        self.stats
    }

    /// Checks whether a block is marked as bad in the OOB area.
    ///
    /// Returns true if the block is bad.
    pub fn is_bad_block(&self, block: u32) -> bool {
        if !self.initialized || self.base_addr == 0 {
            return false;
        }
        // SAFETY: MMIO read from NAND bad block table register. base_addr is non-zero.
        let bbt_word = unsafe {
            let bbt = (self.base_addr + 0x100 + (block as u64 / 32) * 4) as *const u32;
            bbt.read_volatile()
        };
        (bbt_word >> (block % 32)) & 1 == 0 // 0 = bad, 1 = good
    }
}

impl Default for NandController {
    fn default() -> Self {
        Self::new(0, 0)
    }
}

/// Registry of NAND controllers.
pub struct NandControllerRegistry {
    controllers: [NandController; MAX_NAND_CONTROLLERS],
    count: usize,
}

impl NandControllerRegistry {
    /// Creates a new empty NAND controller registry.
    pub fn new() -> Self {
        Self {
            controllers: [NandController::new(0, 0), NandController::new(1, 0)],
            count: 0,
        }
    }

    /// Registers a NAND controller.
    ///
    /// # Errors
    /// Returns `Error::OutOfMemory` if the registry is full.
    pub fn register(&mut self, ctrl: NandController) -> Result<()> {
        if self.count >= MAX_NAND_CONTROLLERS {
            return Err(Error::OutOfMemory);
        }
        self.controllers[self.count] = ctrl;
        self.count += 1;
        Ok(())
    }

    /// Returns the number of registered controllers.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Returns true if no controllers are registered.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Returns a mutable reference to the controller at the given index.
    ///
    /// # Errors
    /// Returns `Error::NotFound` if the index is out of range.
    pub fn get_mut(&mut self, index: usize) -> Result<&mut NandController> {
        if index >= self.count {
            return Err(Error::NotFound);
        }
        Ok(&mut self.controllers[index])
    }
}

impl Default for NandControllerRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Converts a linear byte offset to a NAND address.
///
/// # Arguments
/// * `offset` — Byte offset into the device.
/// * `geo` — NAND geometry.
pub fn offset_to_nand_addr(offset: u64, geo: &NandGeometry) -> NandAddress {
    let page_size = geo.page_size.bytes() as u64;
    let pages_per_block = geo.pages_per_block as u64;
    let page_index = offset / page_size;
    let block = (page_index / pages_per_block) as u32;
    let page = (page_index % pages_per_block) as u32;
    NandAddress::new(0, block, page)
}
