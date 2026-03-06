// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! ATA/IDE disk driver (PIO mode, LBA28).
//!
//! Implements a basic ATA driver supporting primary and secondary
//! channels, master and slave drives, using Programmed I/O (PIO)
//! with LBA28 addressing (up to 128 GiB per drive).
//!
//! # Supported ATA commands
//!
//! - `IDENTIFY` (0xEC) — detect and identify a drive
//! - `READ_SECTORS` (0x20) — read sectors via PIO
//! - `WRITE_SECTORS` (0x30) — write sectors via PIO
//! - `FLUSH_CACHE` (0xE7) — flush drive write cache
//!
//! # Architecture
//!
//! Port I/O is x86_64-specific. This entire module is gated behind
//! `#[cfg(target_arch = "x86_64")]` at the module level (see
//! `lib.rs`).

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Port I/O helpers (16-bit, not provided by HAL)
// ---------------------------------------------------------------------------

/// Read a byte from an x86 I/O port.
///
/// # Safety
///
/// Caller must ensure `port` is a valid I/O port.
unsafe fn inb(port: u16) -> u8 {
    let val: u8;
    // SAFETY: Caller guarantees port validity.
    unsafe {
        core::arch::asm!(
            "in al, dx",
            out("al") val,
            in("dx") port,
            options(nomem, nostack, preserves_flags),
        );
    }
    val
}

/// Write a byte to an x86 I/O port.
///
/// # Safety
///
/// Caller must ensure `port` is a valid I/O port.
unsafe fn outb(port: u16, val: u8) {
    // SAFETY: Caller guarantees port validity.
    unsafe {
        core::arch::asm!(
            "out dx, al",
            in("dx") port,
            in("al") val,
            options(nomem, nostack, preserves_flags),
        );
    }
}

/// Read a 16-bit word from an x86 I/O port.
///
/// # Safety
///
/// Caller must ensure `port` is a valid I/O port.
unsafe fn inw(port: u16) -> u16 {
    let val: u16;
    // SAFETY: Caller guarantees port validity.
    unsafe {
        core::arch::asm!(
            "in ax, dx",
            out("ax") val,
            in("dx") port,
            options(nomem, nostack, preserves_flags),
        );
    }
    val
}

/// Write a 16-bit word to an x86 I/O port.
///
/// # Safety
///
/// Caller must ensure `port` is a valid I/O port.
unsafe fn outw(port: u16, val: u16) {
    // SAFETY: Caller guarantees port validity.
    unsafe {
        core::arch::asm!(
            "out dx, ax",
            in("dx") port,
            in("ax") val,
            options(nomem, nostack, preserves_flags),
        );
    }
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Sector size in bytes (standard ATA sector).
pub const SECTOR_SIZE: usize = 512;

/// Maximum sectors addressable with LBA28 (2^28).
pub const LBA28_MAX_SECTORS: u64 = 1 << 28;

/// Maximum sector count per single PIO transfer (256 means 0 in the
/// sector-count register, which the ATA spec interprets as 256).
pub const MAX_SECTORS_PER_TRANSFER: u32 = 256;

/// Maximum number of drives in the registry (2 channels x 2 drives).
pub const MAX_ATA_DRIVES: usize = 4;

/// Maximum model string length (from IDENTIFY, 40 ASCII bytes).
const MODEL_STRING_LEN: usize = 40;

/// BSY wait timeout — number of polling iterations before giving up.
const BSY_TIMEOUT: u32 = 100_000;

// ---------------------------------------------------------------------------
// ATA commands
// ---------------------------------------------------------------------------

/// ATA command constants.
pub mod cmd {
    /// IDENTIFY DEVICE — returns 256 words of drive information.
    pub const IDENTIFY: u8 = 0xEC;
    /// READ SECTORS — PIO read, LBA28.
    pub const READ_SECTORS: u8 = 0x20;
    /// WRITE SECTORS — PIO write, LBA28.
    pub const WRITE_SECTORS: u8 = 0x30;
    /// FLUSH CACHE — flush volatile write cache to media.
    pub const FLUSH_CACHE: u8 = 0xE7;
}

// ---------------------------------------------------------------------------
// ATA register offsets (relative to I/O base)
// ---------------------------------------------------------------------------

/// ATA register offsets from the channel I/O base port.
mod reg {
    /// Data register (R/W, 16-bit).
    pub const DATA: u16 = 0;
    /// Error register (R) / Features register (W).
    pub const ERROR: u16 = 1;
    /// Sector count register.
    pub const SECTOR_COUNT: u16 = 2;
    /// LBA low (bits 0-7).
    pub const LBA_LO: u16 = 3;
    /// LBA mid (bits 8-15).
    pub const LBA_MID: u16 = 4;
    /// LBA high (bits 16-23).
    pub const LBA_HI: u16 = 5;
    /// Drive/head register (LBA bits 24-27 + drive select).
    pub const DRIVE_HEAD: u16 = 6;
    /// Status register (R) / Command register (W).
    pub const STATUS: u16 = 7;
}

// ---------------------------------------------------------------------------
// AtaStatus — status register bit flags
// ---------------------------------------------------------------------------

/// ATA status register flags.
#[derive(Debug, Clone, Copy)]
pub struct AtaStatus(u8);

impl AtaStatus {
    /// Error occurred (check error register for details).
    pub const ERR: u8 = 1 << 0;
    /// Drive fault (does not set ERR).
    pub const DF: u8 = 1 << 5;
    /// Data request — drive is ready to transfer data.
    pub const DRQ: u8 = 1 << 3;
    /// Drive is ready to accept commands.
    pub const DRDY: u8 = 1 << 6;
    /// Drive is busy — all other bits are invalid.
    pub const BSY: u8 = 1 << 7;

    /// Create a status value from a raw register read.
    pub const fn from_raw(raw: u8) -> Self {
        Self(raw)
    }

    /// Return the raw status byte.
    pub const fn raw(self) -> u8 {
        self.0
    }

    /// Check if a specific flag is set.
    pub const fn has(self, flag: u8) -> bool {
        self.0 & flag != 0
    }

    /// Check if the drive is busy.
    pub const fn is_busy(self) -> bool {
        self.0 & Self::BSY != 0
    }

    /// Check if the drive has an error.
    pub const fn is_error(self) -> bool {
        self.0 & (Self::ERR | Self::DF) != 0
    }

    /// Check if data is ready for transfer.
    pub const fn is_drq(self) -> bool {
        self.0 & Self::DRQ != 0
    }
}

// ---------------------------------------------------------------------------
// AtaChannel — primary or secondary
// ---------------------------------------------------------------------------

/// ATA channel identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AtaChannel {
    /// Primary channel (I/O base 0x1F0, control 0x3F6).
    Primary,
    /// Secondary channel (I/O base 0x170, control 0x376).
    Secondary,
}

// ---------------------------------------------------------------------------
// AtaDriveSelect — master or slave
// ---------------------------------------------------------------------------

/// Drive selection on an ATA channel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AtaDriveSelect {
    /// Master drive (drive 0).
    Master,
    /// Slave drive (drive 1).
    Slave,
}

// ---------------------------------------------------------------------------
// AtaController — manages I/O ports for one channel
// ---------------------------------------------------------------------------

/// ATA channel controller.
///
/// Encapsulates the I/O port base addresses for one ATA channel and
/// provides register-level read/write operations.
#[derive(Debug, Clone, Copy)]
pub struct AtaController {
    /// I/O base port (0x1F0 for primary, 0x170 for secondary).
    io_base: u16,
    /// Control register port (0x3F6 for primary, 0x376 for secondary).
    ctrl_base: u16,
    /// Which channel this controller manages.
    channel: AtaChannel,
}

impl AtaController {
    /// I/O base port for the primary ATA channel.
    pub const PRIMARY_IO_BASE: u16 = 0x1F0;
    /// Control base port for the primary ATA channel.
    pub const PRIMARY_CTRL_BASE: u16 = 0x3F6;
    /// I/O base port for the secondary ATA channel.
    pub const SECONDARY_IO_BASE: u16 = 0x170;
    /// Control base port for the secondary ATA channel.
    pub const SECONDARY_CTRL_BASE: u16 = 0x376;

    /// Create a controller for the given channel.
    pub const fn new(channel: AtaChannel) -> Self {
        match channel {
            AtaChannel::Primary => Self {
                io_base: Self::PRIMARY_IO_BASE,
                ctrl_base: Self::PRIMARY_CTRL_BASE,
                channel,
            },
            AtaChannel::Secondary => Self {
                io_base: Self::SECONDARY_IO_BASE,
                ctrl_base: Self::SECONDARY_CTRL_BASE,
                channel,
            },
        }
    }

    /// Return the channel this controller manages.
    pub const fn channel(&self) -> AtaChannel {
        self.channel
    }

    /// Read the status register.
    pub fn read_status(&self) -> AtaStatus {
        // SAFETY: Reading from a standard ATA I/O port.
        AtaStatus::from_raw(unsafe { inb(self.io_base + reg::STATUS) })
    }

    /// Read the alternate status register (does not clear IRQ).
    pub fn read_alt_status(&self) -> AtaStatus {
        // SAFETY: Reading from the ATA control port.
        AtaStatus::from_raw(unsafe { inb(self.ctrl_base) })
    }

    /// Read the error register.
    pub fn read_error(&self) -> u8 {
        // SAFETY: Reading from a standard ATA I/O port.
        unsafe { inb(self.io_base + reg::ERROR) }
    }

    /// Write a command to the command register.
    fn write_command(&self, cmd: u8) {
        // SAFETY: Writing to a standard ATA I/O port.
        unsafe { outb(self.io_base + reg::STATUS, cmd) }
    }

    /// Write to the sector count register.
    fn write_sector_count(&self, count: u8) {
        // SAFETY: Writing to a standard ATA I/O port.
        unsafe { outb(self.io_base + reg::SECTOR_COUNT, count) }
    }

    /// Write LBA low byte (bits 0-7).
    fn write_lba_lo(&self, val: u8) {
        // SAFETY: Writing to a standard ATA I/O port.
        unsafe { outb(self.io_base + reg::LBA_LO, val) }
    }

    /// Write LBA mid byte (bits 8-15).
    fn write_lba_mid(&self, val: u8) {
        // SAFETY: Writing to a standard ATA I/O port.
        unsafe { outb(self.io_base + reg::LBA_MID, val) }
    }

    /// Write LBA high byte (bits 16-23).
    fn write_lba_hi(&self, val: u8) {
        // SAFETY: Writing to a standard ATA I/O port.
        unsafe { outb(self.io_base + reg::LBA_HI, val) }
    }

    /// Write drive/head register (LBA bits 24-27 + drive select).
    fn write_drive_head(&self, val: u8) {
        // SAFETY: Writing to a standard ATA I/O port.
        unsafe { outb(self.io_base + reg::DRIVE_HEAD, val) }
    }

    /// Read a 16-bit word from the data register.
    fn read_data(&self) -> u16 {
        // SAFETY: Reading from the ATA data port.
        unsafe { inw(self.io_base + reg::DATA) }
    }

    /// Write a 16-bit word to the data register.
    fn write_data(&self, val: u16) {
        // SAFETY: Writing to the ATA data port.
        unsafe { outw(self.io_base + reg::DATA, val) }
    }

    /// Select a drive (master or slave) and set LBA mode.
    ///
    /// The upper 4 bits of the drive/head register encode:
    /// - bit 6: LBA mode (1)
    /// - bit 5: always 1
    /// - bit 4: drive select (0 = master, 1 = slave)
    fn select_drive(&self, drive: AtaDriveSelect) {
        let drv_bit = match drive {
            AtaDriveSelect::Master => 0,
            AtaDriveSelect::Slave => 1,
        };
        // 0xE0 = bit7(1) | bit6(LBA) | bit5(1) | bits4..0
        self.write_drive_head(0xE0 | (drv_bit << 4));
    }

    /// Wait for BSY to clear with a timeout.
    ///
    /// Returns the final status, or `Error::Busy` on timeout.
    fn wait_not_busy(&self) -> Result<AtaStatus> {
        for _ in 0..BSY_TIMEOUT {
            let status = self.read_alt_status();
            if !status.is_busy() {
                return Ok(status);
            }
        }
        Err(Error::Busy)
    }

    /// Wait for DRQ (data request) to be set.
    ///
    /// Returns `Error::IoError` if ERR or DF is set before DRQ.
    /// Returns `Error::Busy` if BSY never clears.
    fn wait_drq(&self) -> Result<AtaStatus> {
        for _ in 0..BSY_TIMEOUT {
            let status = self.read_alt_status();
            if status.is_error() {
                return Err(Error::IoError);
            }
            if !status.is_busy() && status.is_drq() {
                return Ok(status);
            }
        }
        Err(Error::Busy)
    }

    /// Perform a 400ns delay by reading the alternate status 4 times.
    ///
    /// Each I/O port read takes approximately 100ns on ISA bus timing.
    fn delay_400ns(&self) {
        for _ in 0..4 {
            let _ = self.read_alt_status();
        }
    }

    /// Set up the LBA28 address and sector count registers.
    fn setup_lba28(&self, drive: AtaDriveSelect, lba: u64, count: u8) {
        let drv_bit: u8 = match drive {
            AtaDriveSelect::Master => 0,
            AtaDriveSelect::Slave => 1,
        };
        // Drive/head: LBA mode | drive select | LBA bits 24-27.
        let head = 0xE0 | (drv_bit << 4) | ((lba >> 24) as u8 & 0x0F);
        self.write_drive_head(head);
        self.write_sector_count(count);
        self.write_lba_lo(lba as u8);
        self.write_lba_mid((lba >> 8) as u8);
        self.write_lba_hi((lba >> 16) as u8);
    }
}

// ---------------------------------------------------------------------------
// AtaDriveInfo — IDENTIFY response data
// ---------------------------------------------------------------------------

/// Information about an ATA drive parsed from the IDENTIFY response.
#[derive(Clone, Copy)]
pub struct AtaDriveInfo {
    /// Model string (40 ASCII bytes, space-padded).
    pub model: [u8; MODEL_STRING_LEN],
    /// Length of the valid (non-trailing-space) portion of `model`.
    pub model_len: usize,
    /// Total number of LBA28 addressable sectors.
    pub total_sectors: u64,
    /// Device capabilities word (word 49 of IDENTIFY).
    pub capabilities: u16,
    /// Whether LBA is supported.
    pub lba_supported: bool,
    /// Whether DMA is supported.
    pub dma_supported: bool,
}

impl AtaDriveInfo {
    /// Create a zeroed drive info (used as placeholder).
    const fn zeroed() -> Self {
        Self {
            model: [0u8; MODEL_STRING_LEN],
            model_len: 0,
            total_sectors: 0,
            capabilities: 0,
            lba_supported: false,
            dma_supported: false,
        }
    }
}

impl core::fmt::Debug for AtaDriveInfo {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("AtaDriveInfo")
            .field("model_len", &self.model_len)
            .field("total_sectors", &self.total_sectors)
            .field("lba_supported", &self.lba_supported)
            .field("dma_supported", &self.dma_supported)
            .finish()
    }
}

// ---------------------------------------------------------------------------
// AtaDrive — a single ATA drive
// ---------------------------------------------------------------------------

/// Represents a single ATA drive on a channel.
///
/// Provides sector-level read/write using PIO mode with LBA28
/// addressing.
pub struct AtaDrive {
    /// The channel controller for this drive.
    controller: AtaController,
    /// Master or slave selection.
    drive_select: AtaDriveSelect,
    /// Parsed IDENTIFY data.
    info: AtaDriveInfo,
    /// Whether the drive has been identified and is present.
    present: bool,
}

impl AtaDrive {
    /// Create a new (unidentified) drive handle.
    pub const fn new(channel: AtaChannel, drive_select: AtaDriveSelect) -> Self {
        Self {
            controller: AtaController::new(channel),
            drive_select,
            info: AtaDriveInfo::zeroed(),
            present: false,
        }
    }

    /// Return whether this drive is present and identified.
    pub const fn is_present(&self) -> bool {
        self.present
    }

    /// Return the drive information (valid only if `is_present()`).
    pub const fn info(&self) -> &AtaDriveInfo {
        &self.info
    }

    /// Return the channel this drive is on.
    pub const fn channel(&self) -> AtaChannel {
        self.controller.channel()
    }

    /// Return whether this is the master or slave drive.
    pub const fn drive_select(&self) -> AtaDriveSelect {
        self.drive_select
    }

    /// Identify the drive by issuing the ATA IDENTIFY command.
    ///
    /// On success, populates `self.info` with model string, sector
    /// count, and capability flags. If the drive is not present,
    /// returns `Error::NotFound`.
    pub fn identify(&mut self) -> Result<()> {
        // Select the drive.
        self.controller.select_drive(self.drive_select);
        self.controller.delay_400ns();

        // Zero out sector count and LBA registers.
        self.controller.write_sector_count(0);
        self.controller.write_lba_lo(0);
        self.controller.write_lba_mid(0);
        self.controller.write_lba_hi(0);

        // Issue IDENTIFY command.
        self.controller.write_command(cmd::IDENTIFY);
        self.controller.delay_400ns();

        // Check if drive exists: if status is 0, no drive.
        let status = self.controller.read_status();
        if status.raw() == 0 {
            self.present = false;
            return Err(Error::NotFound);
        }

        // Wait for BSY to clear.
        self.controller.wait_not_busy()?;

        // Check for ATAPI/SATA signatures (LBA mid/hi non-zero
        // after IDENTIFY means this is not a plain ATA drive).
        // SAFETY: Reading standard ATA I/O ports.
        let lba_mid = unsafe { inb(self.controller.io_base + reg::LBA_MID) };
        let lba_hi = unsafe { inb(self.controller.io_base + reg::LBA_HI) };
        if lba_mid != 0 || lba_hi != 0 {
            self.present = false;
            return Err(Error::NotFound);
        }

        // Wait for DRQ or error.
        self.controller.wait_drq()?;

        // Read the 256-word IDENTIFY buffer.
        let mut identify_buf = [0u16; 256];
        for word in &mut identify_buf {
            *word = self.controller.read_data();
        }

        // Parse the response.
        self.parse_identify(&identify_buf);
        self.present = true;
        Ok(())
    }

    /// Read sectors from the drive using PIO mode, LBA28.
    ///
    /// - `lba`: starting logical block address
    /// - `count`: number of sectors to read (1..=256; 0 is invalid)
    /// - `buf`: output buffer, must be at least `count * 512` bytes
    ///
    /// # Errors
    ///
    /// - `Error::NotFound` if the drive is not present
    /// - `Error::InvalidArgument` if parameters are out of range
    /// - `Error::Busy` if the drive times out
    /// - `Error::IoError` if the drive reports an error
    pub fn read_sectors(&mut self, lba: u64, count: u32, buf: &mut [u8]) -> Result<()> {
        self.validate_transfer(lba, count, buf.len())?;

        // count=256 is sent as 0 per ATA spec.
        let hw_count = if count == MAX_SECTORS_PER_TRANSFER {
            0u8
        } else {
            count as u8
        };

        self.controller
            .setup_lba28(self.drive_select, lba, hw_count);
        self.controller.write_command(cmd::READ_SECTORS);

        // Read `count` sectors, one sector at a time.
        let mut offset = 0usize;
        for _ in 0..count {
            self.controller.delay_400ns();
            self.controller.wait_drq()?;

            // Read 256 words (512 bytes) per sector.
            for _ in 0..256 {
                let word = self.controller.read_data();
                let bytes = word.to_le_bytes();
                buf[offset] = bytes[0];
                buf[offset + 1] = bytes[1];
                offset += 2;
            }
        }
        Ok(())
    }

    /// Write sectors to the drive using PIO mode, LBA28.
    ///
    /// - `lba`: starting logical block address
    /// - `count`: number of sectors to write (1..=256; 0 is invalid)
    /// - `buf`: input buffer, must be at least `count * 512` bytes
    ///
    /// # Errors
    ///
    /// Same error conditions as [`read_sectors`](Self::read_sectors).
    pub fn write_sectors(&mut self, lba: u64, count: u32, buf: &[u8]) -> Result<()> {
        self.validate_transfer(lba, count, buf.len())?;

        let hw_count = if count == MAX_SECTORS_PER_TRANSFER {
            0u8
        } else {
            count as u8
        };

        self.controller
            .setup_lba28(self.drive_select, lba, hw_count);
        self.controller.write_command(cmd::WRITE_SECTORS);

        let mut offset = 0usize;
        for _ in 0..count {
            self.controller.delay_400ns();
            self.controller.wait_drq()?;

            // Write 256 words (512 bytes) per sector.
            for _ in 0..256 {
                let lo = buf[offset];
                let hi = buf[offset + 1];
                let word = u16::from_le_bytes([lo, hi]);
                self.controller.write_data(word);
                offset += 2;
            }
        }

        // Flush after write to ensure data reaches the media.
        self.flush()
    }

    /// Flush the drive's volatile write cache to stable storage.
    ///
    /// Issues the ATA FLUSH CACHE command and waits for completion.
    pub fn flush(&mut self) -> Result<()> {
        if !self.present {
            return Err(Error::NotFound);
        }
        self.controller.select_drive(self.drive_select);
        self.controller.write_command(cmd::FLUSH_CACHE);
        self.controller.delay_400ns();
        let status = self.controller.wait_not_busy()?;
        if status.is_error() {
            return Err(Error::IoError);
        }
        Ok(())
    }

    /// Return the total number of sectors on the drive.
    pub const fn total_sectors(&self) -> u64 {
        self.info.total_sectors
    }

    /// Return the drive capacity in bytes.
    pub const fn capacity_bytes(&self) -> u64 {
        self.info.total_sectors * SECTOR_SIZE as u64
    }

    // -- private helpers --------------------------------------------------

    /// Validate parameters for a read or write transfer.
    fn validate_transfer(&self, lba: u64, count: u32, buf_len: usize) -> Result<()> {
        if !self.present {
            return Err(Error::NotFound);
        }
        if count == 0 || count > MAX_SECTORS_PER_TRANSFER {
            return Err(Error::InvalidArgument);
        }
        let needed = (count as usize)
            .checked_mul(SECTOR_SIZE)
            .ok_or(Error::InvalidArgument)?;
        if buf_len < needed {
            return Err(Error::InvalidArgument);
        }
        if lba >= LBA28_MAX_SECTORS {
            return Err(Error::InvalidArgument);
        }
        let end = lba
            .checked_add(count as u64)
            .ok_or(Error::InvalidArgument)?;
        if end > self.info.total_sectors {
            return Err(Error::InvalidArgument);
        }
        Ok(())
    }

    /// Parse the 256-word IDENTIFY buffer.
    fn parse_identify(&mut self, buf: &[u16; 256]) {
        // Words 27-46: model string (40 ASCII chars, byte-swapped).
        let mut model = [b' '; MODEL_STRING_LEN];
        for i in 0..20 {
            let word = buf[27 + i];
            let hi = (word >> 8) as u8;
            let lo = (word & 0xFF) as u8;
            model[i * 2] = hi;
            model[i * 2 + 1] = lo;
        }
        self.info.model = model;
        self.info.model_len = trim_trailing_spaces(&model);

        // Word 49: capabilities.
        self.info.capabilities = buf[49];
        // Bit 9: LBA supported.
        self.info.lba_supported = buf[49] & (1 << 9) != 0;
        // Bit 8: DMA supported.
        self.info.dma_supported = buf[49] & (1 << 8) != 0;

        // Words 60-61: total user-addressable LBA28 sectors.
        let lo = buf[60] as u64;
        let hi = buf[61] as u64;
        self.info.total_sectors = lo | (hi << 16);
    }
}

// ---------------------------------------------------------------------------
// AtaRegistry — detect and register up to 4 drives
// ---------------------------------------------------------------------------

/// Slot in the ATA drive registry.
struct AtaRegistrySlot {
    /// The drive instance.
    drive: AtaDrive,
    /// Whether this slot is occupied by a detected drive.
    active: bool,
}

/// Registry of ATA drives (up to 4: 2 channels x 2 drives).
///
/// Provides detection and enumeration of all ATA drives on the
/// primary and secondary IDE channels.
pub struct AtaRegistry {
    /// Drive slots.
    slots: [AtaRegistrySlot; MAX_ATA_DRIVES],
    /// Number of detected drives.
    count: usize,
}

impl Default for AtaRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl AtaRegistry {
    /// Create a new, empty ATA registry.
    pub const fn new() -> Self {
        Self {
            slots: [
                AtaRegistrySlot {
                    drive: AtaDrive::new(AtaChannel::Primary, AtaDriveSelect::Master),
                    active: false,
                },
                AtaRegistrySlot {
                    drive: AtaDrive::new(AtaChannel::Primary, AtaDriveSelect::Slave),
                    active: false,
                },
                AtaRegistrySlot {
                    drive: AtaDrive::new(AtaChannel::Secondary, AtaDriveSelect::Master),
                    active: false,
                },
                AtaRegistrySlot {
                    drive: AtaDrive::new(AtaChannel::Secondary, AtaDriveSelect::Slave),
                    active: false,
                },
            ],
            count: 0,
        }
    }

    /// Probe all four possible ATA drives and register any that
    /// respond to IDENTIFY.
    ///
    /// Returns the number of drives detected.
    pub fn detect_all(&mut self) -> usize {
        self.count = 0;
        for slot in &mut self.slots {
            if slot.drive.identify().is_ok() {
                slot.active = true;
                self.count = self.count.saturating_add(1);
            } else {
                slot.active = false;
            }
        }
        self.count
    }

    /// Return the number of detected drives.
    pub const fn count(&self) -> usize {
        self.count
    }

    /// Get a reference to a drive by slot index (0..4).
    ///
    /// Returns `None` if the index is out of range or no drive is
    /// present at that slot.
    pub fn get(&self, index: usize) -> Option<&AtaDrive> {
        if index >= MAX_ATA_DRIVES {
            return None;
        }
        if self.slots[index].active {
            Some(&self.slots[index].drive)
        } else {
            None
        }
    }

    /// Get a mutable reference to a drive by slot index (0..4).
    ///
    /// Returns `None` if the index is out of range or no drive is
    /// present at that slot.
    pub fn get_mut(&mut self, index: usize) -> Option<&mut AtaDrive> {
        if index >= MAX_ATA_DRIVES {
            return None;
        }
        if self.slots[index].active {
            Some(&mut self.slots[index].drive)
        } else {
            None
        }
    }

    /// Return the slot index for the given channel/drive pair.
    ///
    /// Layout: 0=Primary/Master, 1=Primary/Slave,
    ///         2=Secondary/Master, 3=Secondary/Slave.
    pub const fn slot_index(channel: AtaChannel, drive: AtaDriveSelect) -> usize {
        let ch = match channel {
            AtaChannel::Primary => 0,
            AtaChannel::Secondary => 2,
        };
        let dr = match drive {
            AtaDriveSelect::Master => 0,
            AtaDriveSelect::Slave => 1,
        };
        ch + dr
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Return the length of `s` after trimming trailing ASCII spaces.
fn trim_trailing_spaces(s: &[u8]) -> usize {
    let mut len = s.len();
    while len > 0 && s[len - 1] == b' ' {
        len -= 1;
    }
    len
}
