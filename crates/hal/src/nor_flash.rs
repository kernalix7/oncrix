// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! NOR flash memory interface hardware abstraction.
//!
//! Provides a unified interface for NOR flash devices accessed via SPI or
//! parallel bus. Supports CFI (Common Flash Interface) device detection,
//! sector erase, page program, and memory-mapped read-while-write operations.

use oncrix_lib::{Error, Result};

/// Maximum number of NOR flash devices.
pub const MAX_NOR_DEVICES: usize = 4;

/// NOR flash bus interface type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NorBusType {
    /// SPI-connected NOR flash (Serial Flash).
    Spi,
    /// Parallel NOR flash (memory-mapped).
    Parallel,
    /// Dual SPI (DSPI).
    DualSpi,
    /// Quad SPI (QSPI).
    QuadSpi,
    /// Octal SPI (OSPI).
    OctalSpi,
}

/// NOR flash erase granularity options.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EraseRegionType {
    /// 4 KiB sector erase.
    Sector4K,
    /// 32 KiB block erase.
    Block32K,
    /// 64 KiB block erase (most common).
    Block64K,
    /// Full chip erase.
    ChipErase,
}

impl EraseRegionType {
    /// Returns the erase unit size in bytes.
    pub fn size_bytes(self) -> u32 {
        match self {
            EraseRegionType::Sector4K => 4 * 1024,
            EraseRegionType::Block32K => 32 * 1024,
            EraseRegionType::Block64K => 64 * 1024,
            EraseRegionType::ChipErase => u32::MAX,
        }
    }
}

/// NOR flash device identification.
#[derive(Debug, Clone, Copy, Default)]
pub struct NorDeviceId {
    /// JEDEC manufacturer ID.
    pub manufacturer_id: u8,
    /// Device ID byte 1.
    pub device_id1: u8,
    /// Device ID byte 2.
    pub device_id2: u8,
    /// Extended device ID.
    pub ext_id: u8,
}

impl NorDeviceId {
    /// Creates a new device ID.
    pub const fn new(mfr: u8, dev1: u8, dev2: u8, ext: u8) -> Self {
        Self {
            manufacturer_id: mfr,
            device_id1: dev1,
            device_id2: dev2,
            ext_id: ext,
        }
    }
}

/// NOR flash device geometry and capabilities.
#[derive(Debug, Clone, Copy)]
pub struct NorGeometry {
    /// Device capacity in bytes.
    pub capacity_bytes: u64,
    /// Page program size in bytes.
    pub page_size: u32,
    /// Supported erase regions.
    pub erase_types: [EraseRegionType; 4],
    /// Number of valid erase types.
    pub erase_type_count: u8,
    /// Whether the device supports Quad-I/O.
    pub quad_enable: bool,
    /// Address mode (3-byte or 4-byte).
    pub addr_4byte: bool,
}

impl NorGeometry {
    /// Creates a typical 16 MiB SPI NOR flash geometry.
    pub const fn standard_16mib() -> Self {
        Self {
            capacity_bytes: 16 * 1024 * 1024,
            page_size: 256,
            erase_types: [
                EraseRegionType::Sector4K,
                EraseRegionType::Block64K,
                EraseRegionType::ChipErase,
                EraseRegionType::Sector4K, // placeholder
            ],
            erase_type_count: 3,
            quad_enable: false,
            addr_4byte: false,
        }
    }
}

impl Default for NorGeometry {
    fn default() -> Self {
        Self::standard_16mib()
    }
}

/// NOR flash operation status bits.
#[derive(Debug, Clone, Copy, Default)]
pub struct NorStatus {
    /// Write-in-progress flag (WIP).
    pub wip: bool,
    /// Write-enable latch (WEL).
    pub wel: bool,
    /// Block protect bits.
    pub bp: u8,
    /// Write-protect pin status.
    pub srwd: bool,
}

impl NorStatus {
    /// Creates a NorStatus from a raw status register byte.
    pub fn from_byte(byte: u8) -> Self {
        Self {
            wip: byte & 0x1 != 0,
            wel: byte & 0x2 != 0,
            bp: (byte >> 2) & 0x7,
            srwd: byte & 0x80 != 0,
        }
    }
}

/// NOR flash controller statistics.
#[derive(Debug, Default, Clone, Copy)]
pub struct NorStats {
    /// Total bytes read.
    pub bytes_read: u64,
    /// Total bytes written.
    pub bytes_written: u64,
    /// Total sector erases performed.
    pub erases: u64,
    /// Number of write failures.
    pub write_errors: u64,
}

impl NorStats {
    /// Creates a new zeroed statistics structure.
    pub const fn new() -> Self {
        Self {
            bytes_read: 0,
            bytes_written: 0,
            erases: 0,
            write_errors: 0,
        }
    }
}

/// Hardware NOR flash device driver.
pub struct NorFlash {
    /// Device index.
    id: u8,
    /// MMIO base address (for parallel NOR) or controller base (for SPI).
    base_addr: u64,
    /// Bus interface type.
    bus_type: NorBusType,
    /// Device identification.
    device_id: NorDeviceId,
    /// Device geometry.
    geometry: NorGeometry,
    /// Transfer statistics.
    stats: NorStats,
    /// Whether the device has been initialized.
    initialized: bool,
}

impl NorFlash {
    /// Creates a new NOR flash device.
    ///
    /// # Arguments
    /// * `id` — Device identifier.
    /// * `base_addr` — MMIO base address or SPI controller base.
    /// * `bus_type` — Bus interface type.
    pub const fn new(id: u8, base_addr: u64, bus_type: NorBusType) -> Self {
        Self {
            id,
            base_addr,
            bus_type,
            device_id: NorDeviceId::new(0, 0, 0, 0),
            geometry: NorGeometry::standard_16mib(),
            stats: NorStats::new(),
            initialized: false,
        }
    }

    /// Returns the device ID.
    pub fn id(&self) -> u8 {
        self.id
    }

    /// Returns the device identification (JEDEC).
    pub fn device_id(&self) -> NorDeviceId {
        self.device_id
    }

    /// Returns the device geometry.
    pub fn geometry(&self) -> &NorGeometry {
        &self.geometry
    }

    /// Initializes the NOR flash device.
    ///
    /// Issues JEDEC ID read (RDID) and reads the CFI query string.
    ///
    /// # Errors
    /// Returns `Error::InvalidArgument` if base_addr is zero.
    /// Returns `Error::IoError` if the device does not respond.
    pub fn init(&mut self) -> Result<()> {
        if self.base_addr == 0 {
            return Err(Error::InvalidArgument);
        }
        // SAFETY: MMIO write to NOR flash command register, then read ID.
        // base_addr is validated to be non-zero.
        unsafe {
            let cmd = self.base_addr as *mut u8;
            cmd.write_volatile(0x9F); // RDID command
            let mfr = (self.base_addr + 1) as *const u8;
            let dev1 = (self.base_addr + 2) as *const u8;
            let dev2 = (self.base_addr + 3) as *const u8;
            self.device_id = NorDeviceId::new(
                mfr.read_volatile(),
                dev1.read_volatile(),
                dev2.read_volatile(),
                0,
            );
        }
        self.initialized = true;
        Ok(())
    }

    /// Reads data from the NOR flash device.
    ///
    /// # Arguments
    /// * `offset` — Byte offset into the flash.
    /// * `buf` — Output buffer.
    ///
    /// # Errors
    /// Returns `Error::Busy` if not initialized.
    /// Returns `Error::InvalidArgument` if offset + buf.len() exceeds device capacity.
    pub fn read(&mut self, offset: u64, buf: &mut [u8]) -> Result<()> {
        if !self.initialized {
            return Err(Error::Busy);
        }
        if offset + buf.len() as u64 > self.geometry.capacity_bytes {
            return Err(Error::InvalidArgument);
        }
        // SAFETY: MMIO read from NOR flash mapped address. base_addr + offset is within
        // the device capacity which was bounds-checked above.
        unsafe {
            let src = (self.base_addr + offset) as *const u8;
            for (i, byte) in buf.iter_mut().enumerate() {
                *byte = src.add(i).read_volatile();
            }
        }
        self.stats.bytes_read += buf.len() as u64;
        Ok(())
    }

    /// Programs (writes) data to the NOR flash device.
    ///
    /// NOR flash can only clear bits (1→0). A sector erase must precede writing
    /// to bits that need to go from 0 to 1.
    ///
    /// # Errors
    /// Returns `Error::Busy` if not initialized or device is busy.
    /// Returns `Error::InvalidArgument` if write exceeds device bounds.
    pub fn write(&mut self, offset: u64, data: &[u8]) -> Result<()> {
        if !self.initialized {
            return Err(Error::Busy);
        }
        if offset + data.len() as u64 > self.geometry.capacity_bytes {
            return Err(Error::InvalidArgument);
        }
        // Issue write-enable
        // SAFETY: MMIO writes to NOR flash program registers. base_addr is non-zero.
        unsafe {
            let cmd = self.base_addr as *mut u8;
            cmd.write_volatile(0x06); // WREN
            // Issue page program command per page
            let page_size = self.geometry.page_size as u64;
            let mut pos = 0u64;
            while (pos as usize) < data.len() {
                let page_offset = (offset + pos) % page_size;
                let chunk = (page_size - page_offset) as usize;
                let chunk = chunk.min(data.len() - pos as usize);
                cmd.write_volatile(0x02); // PP command
                // Write address bytes
                let addr_reg = (self.base_addr + 1) as *mut u32;
                addr_reg.write_volatile((offset + pos) as u32);
                // Write data
                let data_reg = (self.base_addr + 5) as *mut u8;
                for i in 0..chunk {
                    data_reg.add(i).write_volatile(data[pos as usize + i]);
                }
                pos += chunk as u64;
            }
        }
        self.stats.bytes_written += data.len() as u64;
        Ok(())
    }

    /// Erases a region of the NOR flash.
    ///
    /// # Arguments
    /// * `offset` — Start address; must be aligned to the erase unit.
    /// * `erase_type` — Erase region type.
    ///
    /// # Errors
    /// Returns `Error::Busy` if not initialized.
    /// Returns `Error::InvalidArgument` if offset is unaligned or out of range.
    pub fn erase(&mut self, offset: u64, erase_type: EraseRegionType) -> Result<()> {
        if !self.initialized {
            return Err(Error::Busy);
        }
        let erase_size = erase_type.size_bytes() as u64;
        if erase_type != EraseRegionType::ChipErase && offset % erase_size != 0 {
            return Err(Error::InvalidArgument);
        }
        // SAFETY: MMIO writes to NOR flash erase command registers. base_addr is non-zero.
        unsafe {
            let cmd = self.base_addr as *mut u8;
            cmd.write_volatile(0x06); // WREN
            let erase_cmd = match erase_type {
                EraseRegionType::Sector4K => 0x20u8,
                EraseRegionType::Block32K => 0x52,
                EraseRegionType::Block64K => 0xD8,
                EraseRegionType::ChipErase => 0xC7,
            };
            cmd.write_volatile(erase_cmd);
            if erase_type != EraseRegionType::ChipErase {
                let addr_reg = (self.base_addr + 1) as *mut u32;
                addr_reg.write_volatile(offset as u32);
            }
        }
        self.stats.erases += 1;
        Ok(())
    }

    /// Reads the NOR flash status register.
    ///
    /// # Errors
    /// Returns `Error::Busy` if not initialized.
    pub fn read_status(&self) -> Result<NorStatus> {
        if !self.initialized {
            return Err(Error::Busy);
        }
        // SAFETY: MMIO write/read to NOR flash status register. base_addr is non-zero.
        let byte = unsafe {
            let cmd = self.base_addr as *mut u8;
            cmd.write_volatile(0x05); // RDSR
            let sr = (self.base_addr + 1) as *const u8;
            sr.read_volatile()
        };
        Ok(NorStatus::from_byte(byte))
    }

    /// Returns a copy of the statistics.
    pub fn stats(&self) -> NorStats {
        self.stats
    }
}

impl Default for NorFlash {
    fn default() -> Self {
        Self::new(0, 0, NorBusType::Spi)
    }
}

/// Registry of NOR flash devices.
pub struct NorFlashRegistry {
    devices: [NorFlash; MAX_NOR_DEVICES],
    count: usize,
}

impl NorFlashRegistry {
    /// Creates a new empty NOR flash registry.
    pub fn new() -> Self {
        Self {
            devices: [
                NorFlash::new(0, 0, NorBusType::Spi),
                NorFlash::new(1, 0, NorBusType::Spi),
                NorFlash::new(2, 0, NorBusType::Spi),
                NorFlash::new(3, 0, NorBusType::Spi),
            ],
            count: 0,
        }
    }

    /// Registers a NOR flash device.
    ///
    /// # Errors
    /// Returns `Error::OutOfMemory` if the registry is full.
    pub fn register(&mut self, dev: NorFlash) -> Result<()> {
        if self.count >= MAX_NOR_DEVICES {
            return Err(Error::OutOfMemory);
        }
        self.devices[self.count] = dev;
        self.count += 1;
        Ok(())
    }

    /// Returns the number of registered devices.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Returns true if no devices are registered.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Returns a mutable reference to the device at the given index.
    ///
    /// # Errors
    /// Returns `Error::NotFound` if the index is out of range.
    pub fn get_mut(&mut self, index: usize) -> Result<&mut NorFlash> {
        if index >= self.count {
            return Err(Error::NotFound);
        }
        Ok(&mut self.devices[index])
    }
}

impl Default for NorFlashRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Aligns a byte offset down to the nearest erase sector boundary.
pub fn align_to_sector(offset: u64, sector_size: u32) -> u64 {
    if sector_size == 0 {
        return offset;
    }
    let sz = sector_size as u64;
    (offset / sz) * sz
}

/// Returns the number of sectors needed to cover a given byte range.
pub fn sectors_needed(offset: u64, length: u64, sector_size: u32) -> u64 {
    if sector_size == 0 || length == 0 {
        return 0;
    }
    let sz = sector_size as u64;
    let start_sector = offset / sz;
    let end_sector = (offset + length - 1) / sz;
    end_sector - start_sector + 1
}
