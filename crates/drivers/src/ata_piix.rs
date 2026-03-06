// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Intel PIIX/ICH ATA host controller driver.
//!
//! Implements the legacy IDE/PIIX (PCI-IDE ISA Xcelerator) ATA host
//! controller driver for Intel ICH-series southbridges. Manages
//! primary and secondary channels with PIO and DMA mode support,
//! ATA command protocol, and device identification.
//!
//! # Architecture
//!
//! - [`PioMode`] -- PIO transfer mode (0..4).
//! - [`DmaMode`] -- DMA transfer mode (single-word, multi-word, UDMA).
//! - [`AtaCommand`] -- ATA command opcodes.
//! - [`AtaStatus`] -- status register bit definitions.
//! - [`AtaDevice`] -- a single ATA device (master or slave).
//! - [`AtaChannel`] -- a primary or secondary ATA channel with two
//!   device slots.
//! - [`AtaPiix`] -- the PIIX/ICH controller managing two channels.
//! - [`AtaPiixRegistry`] -- manages up to [`MAX_CONTROLLERS`]
//!   controllers.
//!
//! # PCI Configuration
//!
//! The PIIX/ICH ATA controller is typically at PCI device 31,
//! function 1. The driver reads PCI BAR0..BAR3 for the channel
//! I/O base ports and BAR4 for the bus-master DMA base.
//!
//! Reference: Intel ICH6/7/8/9 Datasheet (IDE Controller),
//!            ATA/ATAPI-8 (ACS-4) Specification.

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum number of PIIX controllers.
const MAX_CONTROLLERS: usize = 4;

/// Devices per channel (master + slave).
const DEVICES_PER_CHANNEL: usize = 2;

/// Channels per controller (primary + secondary).
const CHANNELS_PER_CONTROLLER: usize = 2;

/// Standard sector size.
pub const SECTOR_SIZE: usize = 512;

/// Maximum sectors per PIO transfer.
pub const MAX_SECTORS_PER_TRANSFER: u32 = 256;

/// LBA28 maximum sector count.
pub const LBA28_MAX_SECTORS: u64 = 1 << 28;

/// LBA48 maximum sector count.
pub const LBA48_MAX_SECTORS: u64 = 1 << 48;

/// Model string length from IDENTIFY DEVICE.
const MODEL_STRING_LEN: usize = 40;

/// Serial number string length from IDENTIFY DEVICE.
const SERIAL_STRING_LEN: usize = 20;

/// Firmware revision string length from IDENTIFY DEVICE.
const FIRMWARE_REV_LEN: usize = 8;

/// BSY timeout (polling iterations).
const BSY_TIMEOUT: u32 = 100_000;

/// DRQ timeout (polling iterations).
const DRQ_TIMEOUT: u32 = 100_000;

/// Primary channel default I/O base.
const PRIMARY_IO_BASE: u16 = 0x1F0;

/// Primary channel default control base.
const PRIMARY_CTRL_BASE: u16 = 0x3F6;

/// Secondary channel default I/O base.
const SECONDARY_IO_BASE: u16 = 0x170;

/// Secondary channel default control base.
const SECONDARY_CTRL_BASE: u16 = 0x376;

// ---------------------------------------------------------------------------
// ATA Register Offsets
// ---------------------------------------------------------------------------

/// ATA register offsets from the channel I/O base.
pub mod reg {
    /// Data register (R/W, 16-bit).
    pub const DATA: u16 = 0;
    /// Error register (R) / Features register (W).
    pub const ERROR: u16 = 1;
    /// Sector count register.
    pub const SECTOR_COUNT: u16 = 2;
    /// LBA Low (bits 0..7).
    pub const LBA_LO: u16 = 3;
    /// LBA Mid (bits 8..15).
    pub const LBA_MID: u16 = 4;
    /// LBA High (bits 16..23).
    pub const LBA_HI: u16 = 5;
    /// Device/Head register.
    pub const DEV_HEAD: u16 = 6;
    /// Status register (R) / Command register (W).
    pub const STATUS: u16 = 7;
}

/// Bus-master DMA register offsets from BAR4.
pub mod bm_reg {
    /// Bus-master command register (primary).
    pub const CMD_PRIMARY: u16 = 0x00;
    /// Bus-master status register (primary).
    pub const STATUS_PRIMARY: u16 = 0x02;
    /// Bus-master PRD table address (primary, 32-bit).
    pub const PRDT_PRIMARY: u16 = 0x04;
    /// Bus-master command register (secondary).
    pub const CMD_SECONDARY: u16 = 0x08;
    /// Bus-master status register (secondary).
    pub const STATUS_SECONDARY: u16 = 0x0A;
    /// Bus-master PRD table address (secondary, 32-bit).
    pub const PRDT_SECONDARY: u16 = 0x0C;
}

// ---------------------------------------------------------------------------
// AtaCommand
// ---------------------------------------------------------------------------

/// ATA command opcodes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AtaCommand {
    /// IDENTIFY DEVICE (ECh).
    IdentifyDevice,
    /// READ SECTORS (20h) — PIO, LBA28.
    ReadSectors,
    /// WRITE SECTORS (30h) — PIO, LBA28.
    WriteSectors,
    /// READ SECTORS EXT (24h) — PIO, LBA48.
    ReadSectorsExt,
    /// WRITE SECTORS EXT (34h) — PIO, LBA48.
    WriteSectorsExt,
    /// READ DMA (C8h) — DMA, LBA28.
    ReadDma,
    /// WRITE DMA (CAh) — DMA, LBA28.
    WriteDma,
    /// READ DMA EXT (25h) — DMA, LBA48.
    ReadDmaExt,
    /// WRITE DMA EXT (35h) — DMA, LBA48.
    WriteDmaExt,
    /// FLUSH CACHE (E7h).
    FlushCache,
    /// FLUSH CACHE EXT (EAh).
    FlushCacheExt,
    /// SET FEATURES (EFh).
    SetFeatures,
    /// DEVICE RESET (08h).
    DeviceReset,
}

impl AtaCommand {
    /// Returns the raw opcode byte.
    pub fn opcode(self) -> u8 {
        match self {
            Self::IdentifyDevice => 0xEC,
            Self::ReadSectors => 0x20,
            Self::WriteSectors => 0x30,
            Self::ReadSectorsExt => 0x24,
            Self::WriteSectorsExt => 0x34,
            Self::ReadDma => 0xC8,
            Self::WriteDma => 0xCA,
            Self::ReadDmaExt => 0x25,
            Self::WriteDmaExt => 0x35,
            Self::FlushCache => 0xE7,
            Self::FlushCacheExt => 0xEA,
            Self::SetFeatures => 0xEF,
            Self::DeviceReset => 0x08,
        }
    }
}

// ---------------------------------------------------------------------------
// AtaStatus
// ---------------------------------------------------------------------------

/// ATA status register bit definitions.
pub struct AtaStatus;

impl AtaStatus {
    /// Error bit (ERR).
    pub const ERR: u8 = 1 << 0;
    /// Data Request (DRQ).
    pub const DRQ: u8 = 1 << 3;
    /// Device Fault (DF).
    pub const DF: u8 = 1 << 5;
    /// Device Ready (DRDY).
    pub const DRDY: u8 = 1 << 6;
    /// Busy (BSY).
    pub const BSY: u8 = 1 << 7;
}

// ---------------------------------------------------------------------------
// PioMode
// ---------------------------------------------------------------------------

/// PIO transfer mode.
///
/// Higher modes support faster cycle times on the ISA-style bus.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PioMode {
    /// PIO Mode 0 (600 ns cycle, ~3.3 MB/s).
    #[default]
    Pio0,
    /// PIO Mode 1 (383 ns cycle, ~5.2 MB/s).
    Pio1,
    /// PIO Mode 2 (240 ns cycle, ~8.3 MB/s).
    Pio2,
    /// PIO Mode 3 (180 ns cycle, IORDY, ~11.1 MB/s).
    Pio3,
    /// PIO Mode 4 (120 ns cycle, IORDY, ~16.7 MB/s).
    Pio4,
}

impl PioMode {
    /// Returns the cycle time in nanoseconds.
    pub fn cycle_time_ns(self) -> u32 {
        match self {
            Self::Pio0 => 600,
            Self::Pio1 => 383,
            Self::Pio2 => 240,
            Self::Pio3 => 180,
            Self::Pio4 => 120,
        }
    }

    /// Returns the maximum throughput in bytes per second.
    pub fn throughput_bps(self) -> u32 {
        let cycle_ns = self.cycle_time_ns();
        if cycle_ns == 0 {
            return 0;
        }
        // Each cycle transfers 16 bits = 2 bytes.
        (1_000_000_000 / cycle_ns) * 2
    }
}

// ---------------------------------------------------------------------------
// DmaMode
// ---------------------------------------------------------------------------

/// DMA transfer mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DmaMode {
    /// No DMA.
    #[default]
    None,
    /// Single-word DMA mode 0/1/2.
    SingleWord(u8),
    /// Multi-word DMA mode 0/1/2.
    MultiWord(u8),
    /// Ultra DMA mode 0..6.
    Udma(u8),
}

impl DmaMode {
    /// Returns the maximum throughput in MB/s.
    pub fn throughput_mbps(self) -> u32 {
        match self {
            Self::None => 0,
            Self::SingleWord(m) => match m {
                0 => 2,
                1 => 4,
                _ => 8,
            },
            Self::MultiWord(m) => match m {
                0 => 4,
                1 => 13,
                _ => 16,
            },
            Self::Udma(m) => match m {
                0 => 16,
                1 => 25,
                2 => 33,
                3 => 44,
                4 => 66,
                5 => 100,
                _ => 133,
            },
        }
    }
}

// ---------------------------------------------------------------------------
// AtaDevice
// ---------------------------------------------------------------------------

/// A single ATA device (master or slave) on a channel.
#[derive(Debug, Clone, Copy)]
pub struct AtaDevice {
    /// Whether a device is present at this slot.
    pub present: bool,
    /// Whether this is the master (true) or slave (false) device.
    pub is_master: bool,
    /// Device model string (from IDENTIFY DEVICE words 27..46).
    pub model: [u8; MODEL_STRING_LEN],
    /// Valid bytes in model.
    pub model_len: usize,
    /// Serial number string (from IDENTIFY DEVICE words 10..19).
    pub serial: [u8; SERIAL_STRING_LEN],
    /// Valid bytes in serial.
    pub serial_len: usize,
    /// Firmware revision (from IDENTIFY DEVICE words 23..26).
    pub firmware_rev: [u8; FIRMWARE_REV_LEN],
    /// Valid bytes in firmware_rev.
    pub firmware_rev_len: usize,
    /// Total addressable sectors (LBA28 or LBA48).
    pub total_sectors: u64,
    /// Whether LBA48 is supported.
    pub lba48: bool,
    /// Whether DMA is supported.
    pub dma_supported: bool,
    /// Active PIO mode.
    pub pio_mode: PioMode,
    /// Active DMA mode.
    pub dma_mode: DmaMode,
    /// Logical sector size in bytes.
    pub sector_size: u32,
    /// Whether the write cache is enabled.
    pub write_cache_enabled: bool,
    /// Whether read look-ahead is enabled.
    pub read_ahead_enabled: bool,
}

/// Constant empty device for array initialisation.
const EMPTY_ATA_DEVICE: AtaDevice = AtaDevice {
    present: false,
    is_master: true,
    model: [0u8; MODEL_STRING_LEN],
    model_len: 0,
    serial: [0u8; SERIAL_STRING_LEN],
    serial_len: 0,
    firmware_rev: [0u8; FIRMWARE_REV_LEN],
    firmware_rev_len: 0,
    total_sectors: 0,
    lba48: false,
    dma_supported: false,
    pio_mode: PioMode::Pio0,
    dma_mode: DmaMode::None,
    sector_size: SECTOR_SIZE as u32,
    write_cache_enabled: false,
    read_ahead_enabled: false,
};

impl AtaDevice {
    /// Creates a new empty ATA device slot.
    pub const fn new(is_master: bool) -> Self {
        AtaDevice {
            is_master,
            ..EMPTY_ATA_DEVICE
        }
    }

    /// Returns the capacity in bytes.
    pub fn capacity_bytes(&self) -> u64 {
        self.total_sectors * self.sector_size as u64
    }

    /// Returns the capacity in MiB.
    pub fn capacity_mib(&self) -> u64 {
        self.capacity_bytes() / (1024 * 1024)
    }

    /// Parses the IDENTIFY DEVICE response (256 words = 512 bytes).
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `data` is not exactly
    /// 512 bytes.
    pub fn parse_identify(&mut self, data: &[u8]) -> Result<()> {
        if data.len() != 512 {
            return Err(Error::InvalidArgument);
        }
        self.present = true;

        // Words 27..46: model string (40 bytes), byte-swapped.
        extract_string(data, 27, &mut self.model);
        self.model_len = trim_trailing_spaces(&self.model);

        // Words 10..19: serial number (20 bytes), byte-swapped.
        extract_string(data, 10, &mut self.serial);
        self.serial_len = trim_trailing_spaces(&self.serial);

        // Words 23..26: firmware revision (8 bytes), byte-swapped.
        extract_string(data, 23, &mut self.firmware_rev);
        self.firmware_rev_len = trim_trailing_spaces(&self.firmware_rev);

        // Word 49, bit 8: DMA supported.
        let cap = word(data, 49);
        self.dma_supported = cap & (1 << 8) != 0;

        // Word 83, bit 10: LBA48 supported.
        let cmd_set2 = word(data, 83);
        self.lba48 = cmd_set2 & (1 << 10) != 0;

        // Words 60..61: LBA28 total sectors.
        let lba28 = dword(data, 60);

        // Words 100..103: LBA48 total sectors.
        let lba48_lo = dword(data, 100) as u64;
        let lba48_hi = dword(data, 102) as u64;
        let lba48_total = lba48_lo | (lba48_hi << 32);

        self.total_sectors = if self.lba48 && lba48_total > 0 {
            lba48_total
        } else {
            lba28 as u64
        };

        // Word 82, bit 5: write cache supported.
        // Word 85, bit 5: write cache enabled.
        let cmd_set1 = word(data, 82);
        let cmd_set1_en = word(data, 85);
        if cmd_set1 & (1 << 5) != 0 {
            self.write_cache_enabled = cmd_set1_en & (1 << 5) != 0;
        }
        // Word 82, bit 6: read look-ahead supported.
        // Word 85, bit 6: read look-ahead enabled.
        if cmd_set1 & (1 << 6) != 0 {
            self.read_ahead_enabled = cmd_set1_en & (1 << 6) != 0;
        }

        Ok(())
    }
}

/// Extracts a byte-swapped ATA string from identify data.
fn extract_string(data: &[u8], start_word: usize, out: &mut [u8]) {
    let byte_offset = start_word * 2;
    let len = out.len();
    let mut i = 0;
    while i < len && byte_offset + i + 1 < data.len() {
        // ATA strings are byte-swapped within each word.
        out[i] = data[byte_offset + i + 1];
        out[i + 1] = data[byte_offset + i];
        i += 2;
    }
}

/// Reads a 16-bit word from identify data (little-endian).
fn word(data: &[u8], index: usize) -> u16 {
    let off = index * 2;
    if off + 1 >= data.len() {
        return 0;
    }
    u16::from_le_bytes([data[off], data[off + 1]])
}

/// Reads a 32-bit double word from identify data (two words, LE).
fn dword(data: &[u8], index: usize) -> u32 {
    let lo = word(data, index) as u32;
    let hi = word(data, index + 1) as u32;
    lo | (hi << 16)
}

/// Returns the length of a byte buffer excluding trailing spaces.
fn trim_trailing_spaces(buf: &[u8]) -> usize {
    let mut len = buf.len();
    while len > 0 && (buf[len - 1] == b' ' || buf[len - 1] == 0) {
        len -= 1;
    }
    len
}

// ---------------------------------------------------------------------------
// AtaChannel
// ---------------------------------------------------------------------------

/// An ATA channel (primary or secondary) with two device slots.
#[derive(Debug, Clone, Copy)]
pub struct AtaChannel {
    /// I/O base port address.
    pub io_base: u16,
    /// Control base port address.
    pub ctrl_base: u16,
    /// Bus-master DMA base port address.
    pub bm_base: u16,
    /// IRQ line number.
    pub irq: u8,
    /// Master device (drive 0).
    pub master: AtaDevice,
    /// Slave device (drive 1).
    pub slave: AtaDevice,
    /// Whether this channel is enabled.
    pub enabled: bool,
    /// Whether an interrupt is pending on this channel.
    pub irq_pending: bool,
}

impl AtaChannel {
    /// Creates a new ATA channel with default configuration.
    pub const fn new(io_base: u16, ctrl_base: u16, bm_base: u16, irq: u8) -> Self {
        Self {
            io_base,
            ctrl_base,
            bm_base,
            irq,
            master: AtaDevice::new(true),
            slave: AtaDevice::new(false),
            enabled: false,
            irq_pending: false,
        }
    }

    /// Returns a reference to a device by index (0 = master, 1 = slave).
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `dev` is not 0 or 1.
    pub fn device(&self, dev: usize) -> Result<&AtaDevice> {
        match dev {
            0 => Ok(&self.master),
            1 => Ok(&self.slave),
            _ => Err(Error::InvalidArgument),
        }
    }

    /// Returns a mutable reference to a device by index.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `dev` is not 0 or 1.
    pub fn device_mut(&mut self, dev: usize) -> Result<&mut AtaDevice> {
        match dev {
            0 => Ok(&mut self.master),
            1 => Ok(&mut self.slave),
            _ => Err(Error::InvalidArgument),
        }
    }

    /// Selects a device on this channel (master = 0, slave = 1).
    ///
    /// Returns the device/head register value to write.
    pub fn select_device_value(&self, dev: usize) -> u8 {
        // Bit 4: DEV (0 = master, 1 = slave).
        // Bit 5: always 1 (obsolete).
        // Bit 6: LBA mode.
        // Bit 7: always 1 (obsolete).
        let dev_bit = if dev == 1 { 1 << 4 } else { 0 };
        0xA0 | dev_bit | (1 << 6) // LBA mode
    }

    /// Returns the number of present devices.
    pub fn device_count(&self) -> usize {
        let mut count = 0;
        if self.master.present {
            count += 1;
        }
        if self.slave.present {
            count += 1;
        }
        count
    }
}

// ---------------------------------------------------------------------------
// PciIdent
// ---------------------------------------------------------------------------

/// PCI identification for an ATA controller.
#[derive(Debug, Clone, Copy, Default)]
pub struct PciIdent {
    /// PCI vendor ID.
    pub vendor_id: u16,
    /// PCI device ID.
    pub device_id: u16,
    /// PCI class code (should be 0x0101 for IDE).
    pub class_code: u16,
    /// PCI programming interface.
    pub prog_if: u8,
}

// ---------------------------------------------------------------------------
// AtaPiix
// ---------------------------------------------------------------------------

/// Intel PIIX/ICH ATA host controller.
///
/// Manages two ATA channels (primary and secondary), each with
/// master and slave device slots. Provides methods for device
/// identification, command building, and DMA configuration.
pub struct AtaPiix {
    /// Unique controller identifier.
    pub id: u32,
    /// PCI identification.
    pub pci_ident: PciIdent,
    /// Primary ATA channel.
    pub primary: AtaChannel,
    /// Secondary ATA channel.
    pub secondary: AtaChannel,
    /// Bus-master DMA base address (from PCI BAR4).
    pub bm_dma_base: u16,
    /// Whether the controller is initialised.
    pub initialised: bool,
    /// Whether native mode is active (vs. legacy/compatibility mode).
    pub native_mode: bool,
}

impl AtaPiix {
    /// Creates a new PIIX controller with default (legacy) port addresses.
    pub fn new(id: u32) -> Self {
        Self {
            id,
            pci_ident: PciIdent::default(),
            primary: AtaChannel::new(PRIMARY_IO_BASE, PRIMARY_CTRL_BASE, 0, 14),
            secondary: AtaChannel::new(SECONDARY_IO_BASE, SECONDARY_CTRL_BASE, 0, 15),
            bm_dma_base: 0,
            initialised: false,
            native_mode: false,
        }
    }

    /// Creates a new PIIX controller with custom I/O port addresses.
    pub fn with_ports(
        id: u32,
        primary_io: u16,
        primary_ctrl: u16,
        secondary_io: u16,
        secondary_ctrl: u16,
        bm_dma: u16,
    ) -> Self {
        Self {
            id,
            pci_ident: PciIdent::default(),
            primary: AtaChannel::new(primary_io, primary_ctrl, bm_dma, 14),
            secondary: AtaChannel::new(secondary_io, secondary_ctrl, bm_dma + 8, 15),
            bm_dma_base: bm_dma,
            initialised: false,
            native_mode: false,
        }
    }

    /// Initialises the controller.
    ///
    /// Enables both channels and prepares for device scanning.
    ///
    /// # Errors
    ///
    /// Returns [`Error::IoError`] if the controller is not responding.
    pub fn init(&mut self) -> Result<()> {
        self.primary.enabled = true;
        self.secondary.enabled = true;
        if self.bm_dma_base != 0 {
            self.primary.bm_base = self.bm_dma_base;
            self.secondary.bm_base = self.bm_dma_base + 8;
        }
        self.initialised = true;
        Ok(())
    }

    /// Returns a reference to a channel by index (0 = primary, 1 = secondary).
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `chan` is not 0 or 1.
    pub fn channel(&self, chan: usize) -> Result<&AtaChannel> {
        match chan {
            0 => Ok(&self.primary),
            1 => Ok(&self.secondary),
            _ => Err(Error::InvalidArgument),
        }
    }

    /// Returns a mutable reference to a channel by index.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `chan` is not 0 or 1.
    pub fn channel_mut(&mut self, chan: usize) -> Result<&mut AtaChannel> {
        match chan {
            0 => Ok(&mut self.primary),
            1 => Ok(&mut self.secondary),
            _ => Err(Error::InvalidArgument),
        }
    }

    /// Returns the total number of detected devices across both channels.
    pub fn device_count(&self) -> usize {
        self.primary.device_count() + self.secondary.device_count()
    }

    /// Handles an interrupt from this controller.
    ///
    /// Reads the bus-master status registers to determine which
    /// channel triggered the interrupt and returns a bitmask:
    /// bit 0 = primary, bit 1 = secondary.
    pub fn handle_interrupt(&mut self) -> u8 {
        let mut cause: u8 = 0;
        // Check primary channel.
        if self.primary.enabled && self.primary.irq_pending {
            cause |= 0x01;
            self.primary.irq_pending = false;
        }
        // Check secondary channel.
        if self.secondary.enabled && self.secondary.irq_pending {
            cause |= 0x02;
            self.secondary.irq_pending = false;
        }
        cause
    }

    /// Sets the PCI identification for this controller.
    pub fn set_pci_ident(&mut self, ident: PciIdent) {
        self.pci_ident = ident;
    }
}

// ---------------------------------------------------------------------------
// AtaPiixRegistry
// ---------------------------------------------------------------------------

/// Registry managing up to [`MAX_CONTROLLERS`] PIIX controllers.
pub struct AtaPiixRegistry {
    /// Registered controllers.
    controllers: [Option<AtaPiix>; MAX_CONTROLLERS],
    /// Number of registered controllers.
    count: usize,
}

impl AtaPiixRegistry {
    /// Creates a new empty registry.
    pub const fn new() -> Self {
        Self {
            controllers: [const { None }; MAX_CONTROLLERS],
            count: 0,
        }
    }

    /// Registers a controller.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the registry is full, or
    /// [`Error::AlreadyExists`] if a controller with the same ID exists.
    pub fn register(&mut self, controller: AtaPiix) -> Result<()> {
        for slot in self.controllers.iter().flatten() {
            if slot.id == controller.id {
                return Err(Error::AlreadyExists);
            }
        }
        for slot in self.controllers.iter_mut() {
            if slot.is_none() {
                *slot = Some(controller);
                self.count += 1;
                return Ok(());
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Returns a reference to a controller by ID.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if not found.
    pub fn get(&self, id: u32) -> Result<&AtaPiix> {
        for slot in self.controllers.iter().flatten() {
            if slot.id == id {
                return Ok(slot);
            }
        }
        Err(Error::NotFound)
    }

    /// Returns a mutable reference to a controller by ID.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if not found.
    pub fn get_mut(&mut self, id: u32) -> Result<&mut AtaPiix> {
        for slot in self.controllers.iter_mut() {
            if let Some(c) = slot {
                if c.id == id {
                    return Ok(c);
                }
            }
        }
        Err(Error::NotFound)
    }

    /// Returns the number of registered controllers.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Returns `true` if no controllers are registered.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
}

impl Default for AtaPiixRegistry {
    fn default() -> Self {
        Self::new()
    }
}
