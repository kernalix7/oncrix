// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! SATA Frame Information Structure (FIS) builder.
//!
//! Provides `#[repr(C)]` structures and constructors for all SATA FIS types
//! used in ATA command/data delivery via AHCI:
//!
//! - [`RegHostToDevice`] — Register FIS (H2D): ATA command delivery
//! - [`RegDeviceToHost`] — Register FIS (D2H): ATA status/error
//! - [`DmaActivate`] — DMA Activate FIS
//! - [`SetDeviceBits`] — Set Device Bits FIS
//! - [`Data`] — Data FIS for PIO/DMA payload
//!
//! All FIS types are serialized into a Command Table for the AHCI port.
//!
//! Reference: Serial ATA 3.5 Gold Specification §10; AHCI Spec 1.3.1 §5.6.

use oncrix_lib::{Error, Result};

// ── FIS Types ──────────────────────────────────────────────────────────────

/// FIS type byte values.
pub mod fis_type {
    /// Register FIS — Host to Device.
    pub const REG_H2D: u8 = 0x27;
    /// Register FIS — Device to Host.
    pub const REG_D2H: u8 = 0x34;
    /// DMA Activate FIS.
    pub const DMA_ACT: u8 = 0x39;
    /// DMA Setup FIS.
    pub const DMA_SETUP: u8 = 0x41;
    /// Data FIS.
    pub const DATA: u8 = 0x46;
    /// BIST Activate FIS.
    pub const BIST_ACTIVATE: u8 = 0x58;
    /// PIO Setup FIS — Device to Host.
    pub const PIO_SETUP: u8 = 0x5F;
    /// Set Device Bits FIS — Device to Host.
    pub const SET_DEVICE_BITS: u8 = 0xA1;
}

// ── ATA Commands ───────────────────────────────────────────────────────────

/// ATA command opcodes.
pub mod ata_cmd {
    /// READ DMA EXT (48-bit LBA).
    pub const READ_DMA_EXT: u8 = 0x25;
    /// WRITE DMA EXT (48-bit LBA).
    pub const WRITE_DMA_EXT: u8 = 0x35;
    /// IDENTIFY DEVICE.
    pub const IDENTIFY: u8 = 0xEC;
    /// FLUSH CACHE EXT.
    pub const FLUSH_CACHE_EXT: u8 = 0xEA;
    /// SET FEATURES.
    pub const SET_FEATURES: u8 = 0xEF;
    /// READ NATIVE MAX ADDRESS EXT.
    pub const READ_NATIVE_MAX_EXT: u8 = 0x27;
    /// STANDBY IMMEDIATE.
    pub const STANDBY_IMMEDIATE: u8 = 0xE0;
}

// ── Register FIS H2D ───────────────────────────────────────────────────────

/// Register FIS — Host to Device (5 dwords = 20 bytes).
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct RegHostToDevice {
    /// FIS type (must be `fis_type::REG_H2D`).
    pub fis_type: u8,
    /// Bit 7: Command (1) or Control (0); bits [3:0]: PM Port.
    pub pm_port_c: u8,
    /// ATA command register.
    pub command: u8,
    /// Feature register (7:0).
    pub feature_lo: u8,
    /// LBA low (23:0) stored in lba[0..3].
    pub lba0: u8,
    pub lba1: u8,
    pub lba2: u8,
    /// Device register (DEV/HEAD).
    pub device: u8,
    /// LBA high (47:24).
    pub lba3: u8,
    pub lba4: u8,
    pub lba5: u8,
    /// Feature register (15:8).
    pub feature_hi: u8,
    /// Sector count low byte.
    pub count_lo: u8,
    /// Sector count high byte.
    pub count_hi: u8,
    /// Isochronous command completion (ICC).
    pub icc: u8,
    /// Control register.
    pub control: u8,
    /// Reserved.
    pub _reserved: [u8; 4],
}

impl RegHostToDevice {
    /// Construct an H2D FIS for an ATA DMA READ/WRITE EXT command.
    pub fn dma_ext(command: u8, lba48: u64, sector_count: u16) -> Self {
        let mut fis = Self::default();
        fis.fis_type = fis_type::REG_H2D;
        fis.pm_port_c = 0x80; // Command bit set
        fis.command = command;
        fis.device = 0x40; // LBA mode
        fis.lba0 = lba48 as u8;
        fis.lba1 = (lba48 >> 8) as u8;
        fis.lba2 = (lba48 >> 16) as u8;
        fis.lba3 = (lba48 >> 24) as u8;
        fis.lba4 = (lba48 >> 32) as u8;
        fis.lba5 = (lba48 >> 40) as u8;
        fis.count_lo = sector_count as u8;
        fis.count_hi = (sector_count >> 8) as u8;
        fis
    }

    /// Construct a READ DMA EXT FIS.
    pub fn read_dma_ext(lba48: u64, sector_count: u16) -> Self {
        Self::dma_ext(ata_cmd::READ_DMA_EXT, lba48, sector_count)
    }

    /// Construct a WRITE DMA EXT FIS.
    pub fn write_dma_ext(lba48: u64, sector_count: u16) -> Self {
        Self::dma_ext(ata_cmd::WRITE_DMA_EXT, lba48, sector_count)
    }

    /// Construct an IDENTIFY DEVICE FIS.
    pub fn identify() -> Self {
        let mut fis = Self::default();
        fis.fis_type = fis_type::REG_H2D;
        fis.pm_port_c = 0x80;
        fis.command = ata_cmd::IDENTIFY;
        fis.device = 0; // obsolete but required
        fis
    }

    /// Construct a FLUSH CACHE EXT FIS.
    pub fn flush_cache_ext() -> Self {
        let mut fis = Self::default();
        fis.fis_type = fis_type::REG_H2D;
        fis.pm_port_c = 0x80;
        fis.command = ata_cmd::FLUSH_CACHE_EXT;
        fis
    }

    /// Validate the FIS type byte.
    pub fn validate(&self) -> Result<()> {
        if self.fis_type != fis_type::REG_H2D {
            return Err(Error::InvalidArgument);
        }
        Ok(())
    }

    /// Return the 48-bit LBA encoded in this FIS.
    pub fn lba48(&self) -> u64 {
        self.lba0 as u64
            | ((self.lba1 as u64) << 8)
            | ((self.lba2 as u64) << 16)
            | ((self.lba3 as u64) << 24)
            | ((self.lba4 as u64) << 32)
            | ((self.lba5 as u64) << 40)
    }

    /// Return the sector count from this FIS.
    pub fn sector_count(&self) -> u16 {
        self.count_lo as u16 | ((self.count_hi as u16) << 8)
    }
}

// ── Register FIS D2H ───────────────────────────────────────────────────────

/// Register FIS — Device to Host (5 dwords = 20 bytes).
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct RegDeviceToHost {
    /// FIS type (must be `fis_type::REG_D2H`).
    pub fis_type: u8,
    /// Bits [3:0]: PM Port; bit 6: interrupt bit.
    pub pm_port_i: u8,
    /// Status register value.
    pub status: u8,
    /// Error register value.
    pub error: u8,
    pub lba0: u8,
    pub lba1: u8,
    pub lba2: u8,
    pub device: u8,
    pub lba3: u8,
    pub lba4: u8,
    pub lba5: u8,
    pub _reserved0: u8,
    pub count_lo: u8,
    pub count_hi: u8,
    pub _reserved1: [u8; 6],
}

impl RegDeviceToHost {
    /// Return true if the BSY bit is clear and DRDY is set (ready).
    pub fn is_ready(&self) -> bool {
        const BSY: u8 = 0x80;
        const DRDY: u8 = 0x40;
        self.status & BSY == 0 && self.status & DRDY != 0
    }

    /// Return true if the ERR bit in status is set.
    pub fn has_error(&self) -> bool {
        self.status & 0x01 != 0
    }

    /// Convert device error bits to an ONCRIX result.
    pub fn to_result(&self) -> Result<()> {
        if self.has_error() {
            Err(Error::IoError)
        } else {
            Ok(())
        }
    }
}

// ── Set Device Bits FIS ────────────────────────────────────────────────────

/// Set Device Bits FIS — Device to Host (2 dwords = 8 bytes).
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct SetDeviceBits {
    pub fis_type: u8,
    pub pm_port_i: u8,
    pub status_lo: u8,
    pub error: u8,
    pub protocol: u8,
    pub _reserved: [u8; 3],
}

impl SetDeviceBits {
    /// Construct a Set Device Bits FIS.
    pub fn new(status: u8, error: u8) -> Self {
        Self {
            fis_type: fis_type::SET_DEVICE_BITS,
            pm_port_i: 0x40, // interrupt bit
            status_lo: status & 0x77,
            error,
            protocol: 0,
            _reserved: [0; 3],
        }
    }
}

// ── DMA Activate FIS ───────────────────────────────────────────────────────

/// DMA Activate FIS (1 dword = 4 bytes).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct DmaActivate {
    pub fis_type: u8,
    pub pm_port: u8,
    pub _reserved: [u8; 2],
}

impl DmaActivate {
    /// Construct a DMA Activate FIS.
    pub fn new() -> Self {
        Self {
            fis_type: fis_type::DMA_ACT,
            pm_port: 0,
            _reserved: [0; 2],
        }
    }
}

impl Default for DmaActivate {
    fn default() -> Self {
        Self::new()
    }
}

// ── Data FIS ───────────────────────────────────────────────────────────────

/// Maximum data payload in a Data FIS (2044 bytes = 511 dwords).
pub const DATA_FIS_MAX_PAYLOAD: usize = 2044;

/// Data FIS — variable length up to 2048 bytes.
pub struct DataFis {
    fis_type: u8,
    pm_port: u8,
    _reserved: [u8; 2],
    payload_len: usize,
    payload: [u8; DATA_FIS_MAX_PAYLOAD],
}

impl DataFis {
    /// Construct a Data FIS with the given payload.
    pub fn new(data: &[u8]) -> Result<Self> {
        if data.len() > DATA_FIS_MAX_PAYLOAD {
            return Err(Error::InvalidArgument);
        }
        let mut payload = [0u8; DATA_FIS_MAX_PAYLOAD];
        payload[..data.len()].copy_from_slice(data);
        Ok(Self {
            fis_type: fis_type::DATA,
            pm_port: 0,
            _reserved: [0; 2],
            payload_len: data.len(),
            payload,
        })
    }

    /// Return the payload slice.
    pub fn payload(&self) -> &[u8] {
        &self.payload[..self.payload_len]
    }

    /// Return the total FIS length in bytes (header + payload).
    pub fn total_len(&self) -> usize {
        4 + self.payload_len
    }
}

// ── IDENTIFY DEVICE data ───────────────────────────────────────────────────

/// Parsed fields from the 512-byte IDENTIFY DEVICE response.
#[repr(C)]
pub struct IdentifyDeviceData {
    /// Words 0–26: configuration, cylinders, heads, sectors (legacy).
    pub general: [u16; 27],
    /// Words 27–46: serial number (20 ASCII chars).
    pub serial_number: [u8; 20],
    /// Words 47–59: buffer/capabilities.
    pub config2: [u16; 13],
    /// Words 60–61: total user addressable sectors (28-bit).
    pub lba28_sectors: u32,
    /// Words 62–99: multi-word DMA, PIO modes, timing.
    pub config3: [u16; 38],
    /// Words 100–103: total user addressable sectors (48-bit).
    pub lba48_sectors: u64,
    /// Words 104–255: extended capability info.
    pub config4: [u16; 152],
}

impl IdentifyDeviceData {
    /// Return the 48-bit sector count.
    pub fn lba48_capacity(&self) -> u64 {
        self.lba48_sectors
    }

    /// Return true if 48-bit LBA is supported (word 83 bit 10).
    pub fn supports_lba48(&self) -> bool {
        // Word 83 is at index 83 within general+serial+config2+config3
        // For simplicity, check the lba48 sector count being non-zero.
        self.lba48_sectors > 0
    }
}
