// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Non-Volatile Memory (NVMEM) hardware abstraction.
//!
//! Provides a unified interface for accessing non-volatile storage such as
//! EEPROM, flash memory, and battery-backed SRAM. Used for storing calibration
//! data, MAC addresses, and device configuration.
//!
//! # Access Model
//!
//! NVMEM devices are byte-addressable with optional write protection.
//! Write operations may require unlock sequences and may be slow (µs to ms).

#![allow(dead_code)]

use oncrix_lib::{Error, Result};

/// NVMEM cell type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NvmemType {
    /// Electrically Erasable Programmable Read-Only Memory.
    Eeprom,
    /// NOR flash memory (byte-writable, sector-erasable).
    NorFlash,
    /// NAND flash memory (page-writable, block-erasable).
    NandFlash,
    /// Battery-backed SRAM.
    BbSram,
    /// One-Time Programmable (OTP) / eFuse.
    Otp,
}

/// NVMEM device descriptor.
#[derive(Debug, Clone, Copy)]
pub struct NvmemDevice {
    /// Device type.
    pub device_type: NvmemType,
    /// Total capacity in bytes.
    pub size: usize,
    /// Minimum write granularity in bytes.
    pub write_granularity: usize,
    /// Erase block size in bytes (for flash; 0 for byte-writable devices).
    pub erase_block_size: usize,
    /// Whether write protection is enabled.
    pub write_protected: bool,
}

impl NvmemDevice {
    /// Creates an EEPROM device descriptor.
    pub const fn eeprom(size: usize) -> Self {
        Self {
            device_type: NvmemType::Eeprom,
            size,
            write_granularity: 1,
            erase_block_size: 0,
            write_protected: false,
        }
    }

    /// Creates a NOR flash device descriptor.
    pub const fn nor_flash(size: usize, erase_block_size: usize) -> Self {
        Self {
            device_type: NvmemType::NorFlash,
            size,
            write_granularity: 1,
            erase_block_size,
            write_protected: false,
        }
    }

    /// Validates that a byte range is within bounds.
    pub fn validate_range(&self, offset: usize, len: usize) -> Result<()> {
        if len == 0 {
            return Err(Error::InvalidArgument);
        }
        offset.checked_add(len).ok_or(Error::InvalidArgument)?;
        if offset + len > self.size {
            return Err(Error::InvalidArgument);
        }
        Ok(())
    }

    /// Returns whether an offset is erase-block-aligned.
    pub fn is_block_aligned(&self, offset: usize) -> bool {
        if self.erase_block_size == 0 {
            return true;
        }
        offset % self.erase_block_size == 0
    }
}

/// A named NVMEM cell — a specific field within the NVMEM storage.
///
/// Cells allow drivers to access named sub-regions of NVMEM without
/// needing to know absolute offsets.
#[derive(Debug, Clone, Copy)]
pub struct NvmemCell {
    /// Human-readable cell name.
    pub name: &'static str,
    /// Byte offset within the NVMEM device.
    pub offset: usize,
    /// Cell size in bytes.
    pub size: usize,
    /// Bit offset within the first byte (for sub-byte cells).
    pub bit_offset: u8,
    /// Number of bits (for sub-byte cells; 0 means full bytes).
    pub nbits: u8,
}

impl NvmemCell {
    /// Creates a byte-aligned NVMEM cell.
    pub const fn byte_cell(name: &'static str, offset: usize, size: usize) -> Self {
        Self {
            name,
            offset,
            size,
            bit_offset: 0,
            nbits: 0,
        }
    }

    /// Creates a single-bit NVMEM cell.
    pub const fn bit_cell(name: &'static str, byte_offset: usize, bit: u8) -> Self {
        Self {
            name,
            offset: byte_offset,
            size: 1,
            bit_offset: bit,
            nbits: 1,
        }
    }

    /// Returns whether this is a sub-byte (bit-field) cell.
    pub const fn is_bit_cell(self) -> bool {
        self.nbits > 0
    }
}

/// Trait for reading and writing NVMEM devices.
pub trait NvmemOps {
    /// Returns the device descriptor.
    fn device(&self) -> &NvmemDevice;

    /// Reads bytes from the NVMEM at the given offset.
    fn read(&mut self, offset: usize, buf: &mut [u8]) -> Result<()>;

    /// Writes bytes to the NVMEM at the given offset.
    ///
    /// Returns `Err(PermissionDenied)` if the device is write-protected.
    fn write(&mut self, offset: usize, data: &[u8]) -> Result<()>;

    /// Erases a block of flash memory (required before re-writing).
    ///
    /// The offset must be block-aligned for flash devices.
    /// Returns `Err(NotImplemented)` for byte-writable devices (EEPROM, BSRAM).
    fn erase_block(&mut self, block_offset: usize) -> Result<()>;

    /// Reads a named NVMEM cell.
    fn read_cell(&mut self, cell: &NvmemCell, buf: &mut [u8]) -> Result<()> {
        if buf.len() < cell.size {
            return Err(Error::InvalidArgument);
        }
        self.read(cell.offset, &mut buf[..cell.size])
    }

    /// Writes a named NVMEM cell.
    fn write_cell(&mut self, cell: &NvmemCell, data: &[u8]) -> Result<()> {
        if data.len() != cell.size {
            return Err(Error::InvalidArgument);
        }
        self.write(cell.offset, data)
    }
}

/// NVMEM cell registry (static list of named cells for a device).
pub struct NvmemCellRegistry {
    cells: [Option<NvmemCell>; 32],
    count: usize,
}

impl NvmemCellRegistry {
    /// Creates an empty cell registry.
    pub const fn new() -> Self {
        Self {
            cells: [None; 32],
            count: 0,
        }
    }

    /// Registers a cell.
    pub fn register(&mut self, cell: NvmemCell) -> Result<()> {
        if self.count >= 32 {
            return Err(Error::OutOfMemory);
        }
        self.cells[self.count] = Some(cell);
        self.count += 1;
        Ok(())
    }

    /// Finds a cell by name.
    pub fn find(&self, name: &str) -> Option<&NvmemCell> {
        self.cells[..self.count].iter().find_map(|c| {
            let cell = c.as_ref()?;
            if cell.name == name { Some(cell) } else { None }
        })
    }

    /// Returns the number of registered cells.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Returns whether the registry is empty.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
}

impl Default for NvmemCellRegistry {
    fn default() -> Self {
        Self::new()
    }
}
