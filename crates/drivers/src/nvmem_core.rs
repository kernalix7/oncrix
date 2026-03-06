// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! NVMEM (Non-Volatile Memory) core framework.
//!
//! Provides a unified interface for accessing small non-volatile memory
//! devices such as EEPROMs, OTP (One-Time Programmable) fuses, battery-backed
//! SRAM, and on-chip efuses. Drivers register devices with this framework
//! and expose cells (named sub-regions) for consumer drivers.

use oncrix_lib::{Error, Result};

/// Maximum number of NVMEM devices registered.
const MAX_DEVICES: usize = 16;
/// Maximum number of cells per device.
const MAX_CELLS_PER_DEV: usize = 32;
/// Maximum length of a device/cell name.
const NAME_LEN: usize = 32;
/// Maximum data size for a single read/write (bytes).
const MAX_DATA_LEN: usize = 256;

/// NVMEM device type.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NvmemType {
    /// EEPROM (byte- or page-erasable).
    Eeprom,
    /// OTP fuses (write-once, read-many).
    Otp,
    /// Battery-backed SRAM.
    BbSram,
    /// On-chip efuses.
    Efuse,
}

/// Access permissions for an NVMEM device or cell.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AccessMode {
    /// Read-only.
    ReadOnly,
    /// Read-write.
    ReadWrite,
    /// Write-once (OTP).
    WriteOnce,
}

/// A named sub-region of an NVMEM device.
#[derive(Clone, Copy, Debug)]
pub struct NvmemCell {
    /// Cell name (e.g., "mac-address", "serial-number").
    pub name: [u8; NAME_LEN],
    /// Byte offset within the NVMEM device.
    pub offset: u32,
    /// Length of the cell in bytes.
    pub len: u16,
    /// Bit offset within the first byte.
    pub bit_offset: u8,
    /// Number of significant bits (0 = use len * 8).
    pub nbits: u16,
}

impl NvmemCell {
    /// Create a simple byte-aligned cell.
    pub fn new(name: &[u8], offset: u32, len: u16) -> Self {
        let mut buf = [0u8; NAME_LEN];
        let n = name.len().min(NAME_LEN - 1);
        buf[..n].copy_from_slice(&name[..n]);
        Self {
            name: buf,
            offset,
            len,
            bit_offset: 0,
            nbits: 0,
        }
    }
}

/// NVMEM read callback type.
pub type NvmemReadFn = fn(offset: u32, buf: &mut [u8]) -> Result<()>;
/// NVMEM write callback type.
pub type NvmemWriteFn = fn(offset: u32, buf: &[u8]) -> Result<()>;

/// A registered NVMEM device descriptor.
pub struct NvmemDevice {
    /// Device name.
    pub name: [u8; NAME_LEN],
    /// Device type.
    pub dev_type: NvmemType,
    /// Total size in bytes.
    pub size: u32,
    /// Access mode.
    pub access: AccessMode,
    /// Word/page size in bytes (for page-based EEPROM writes).
    pub word_size: u8,
    /// Stride (increment between consecutive reads, usually 1).
    pub stride: u8,
    /// Read callback.
    pub read_fn: Option<NvmemReadFn>,
    /// Write callback.
    pub write_fn: Option<NvmemWriteFn>,
    /// Named cells.
    pub cells: [Option<NvmemCell>; MAX_CELLS_PER_DEV],
    /// Number of registered cells.
    pub num_cells: usize,
}

impl NvmemDevice {
    /// Create a new NVMEM device descriptor.
    pub fn new(name: &[u8], dev_type: NvmemType, size: u32, access: AccessMode) -> Self {
        let mut n = [0u8; NAME_LEN];
        let len = name.len().min(NAME_LEN - 1);
        n[..len].copy_from_slice(&name[..len]);
        Self {
            name: n,
            dev_type,
            size,
            access,
            word_size: 1,
            stride: 1,
            read_fn: None,
            write_fn: None,
            cells: [const { None }; MAX_CELLS_PER_DEV],
            num_cells: 0,
        }
    }

    /// Register a named cell within this device.
    pub fn add_cell(&mut self, cell: NvmemCell) -> Result<()> {
        if self.num_cells >= MAX_CELLS_PER_DEV {
            return Err(Error::OutOfMemory);
        }
        if (cell.offset + cell.len as u32) > self.size {
            return Err(Error::InvalidArgument);
        }
        self.cells[self.num_cells] = Some(cell);
        self.num_cells += 1;
        Ok(())
    }

    /// Read data from the device at the given offset.
    pub fn read(&self, offset: u32, buf: &mut [u8]) -> Result<()> {
        if offset + buf.len() as u32 > self.size {
            return Err(Error::InvalidArgument);
        }
        if let Some(read_fn) = self.read_fn {
            read_fn(offset, buf)
        } else {
            Err(Error::NotImplemented)
        }
    }

    /// Write data to the device at the given offset.
    pub fn write(&self, offset: u32, buf: &[u8]) -> Result<()> {
        if self.access == AccessMode::ReadOnly {
            return Err(Error::PermissionDenied);
        }
        if offset + buf.len() as u32 > self.size {
            return Err(Error::InvalidArgument);
        }
        if let Some(write_fn) = self.write_fn {
            write_fn(offset, buf)
        } else {
            Err(Error::NotImplemented)
        }
    }

    /// Read a named cell by name prefix (first match).
    pub fn read_cell(&self, name: &[u8], buf: &mut [u8]) -> Result<usize> {
        for cell_opt in &self.cells[..self.num_cells] {
            if let Some(cell) = cell_opt {
                let cname = &cell.name[..name.len().min(NAME_LEN)];
                if cname.starts_with(name) {
                    let len = buf.len().min(cell.len as usize);
                    self.read(cell.offset, &mut buf[..len])?;
                    return Ok(len);
                }
            }
        }
        Err(Error::NotFound)
    }
}

/// NVMEM core registry.
pub struct NvmemCore {
    /// Registered device descriptors.
    devices: [Option<NvmemDevice>; MAX_DEVICES],
    /// Number of registered devices.
    count: usize,
}

impl NvmemCore {
    /// Create an empty NVMEM core registry.
    pub const fn new() -> Self {
        Self {
            devices: [
                const { None },
                const { None },
                const { None },
                const { None },
                const { None },
                const { None },
                const { None },
                const { None },
                const { None },
                const { None },
                const { None },
                const { None },
                const { None },
                const { None },
                const { None },
                const { None },
            ],
            count: 0,
        }
    }

    /// Register a new NVMEM device. Returns its device index.
    pub fn register(&mut self, device: NvmemDevice) -> Result<usize> {
        if self.count >= MAX_DEVICES {
            return Err(Error::OutOfMemory);
        }
        let idx = self.count;
        self.devices[idx] = Some(device);
        self.count += 1;
        Ok(idx)
    }

    /// Unregister a device by index.
    pub fn unregister(&mut self, idx: usize) -> Result<()> {
        if idx >= MAX_DEVICES || self.devices[idx].is_none() {
            return Err(Error::NotFound);
        }
        self.devices[idx] = None;
        Ok(())
    }

    /// Get an immutable reference to a device by index.
    pub fn get(&self, idx: usize) -> Option<&NvmemDevice> {
        self.devices.get(idx).and_then(Option::as_ref)
    }

    /// Get a mutable reference to a device by index.
    pub fn get_mut(&mut self, idx: usize) -> Option<&mut NvmemDevice> {
        self.devices.get_mut(idx).and_then(Option::as_mut)
    }

    /// Find a device by name prefix.
    pub fn find_by_name(&self, name: &[u8]) -> Option<(usize, &NvmemDevice)> {
        for (i, dev_opt) in self.devices[..self.count].iter().enumerate() {
            if let Some(dev) = dev_opt {
                if dev.name.starts_with(name) {
                    return Some((i, dev));
                }
            }
        }
        None
    }

    /// Return the number of registered devices.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Return true if no devices are registered.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
}

impl Default for NvmemCore {
    fn default() -> Self {
        Self::new()
    }
}
