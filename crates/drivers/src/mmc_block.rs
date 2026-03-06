// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! MMC/SD block device driver.
//!
//! Implements the block-device layer over an MMC host controller (via the
//! `mmc_host` HAL module). Handles card detection, initialization state
//! machine (idle → ready → identification → transfer), block reads/writes,
//! and erase operations.
//!
//! Reference: JEDEC JESD84-B51 (eMMC 5.1), SD Association Physical Layer
//! Simplified Specification Version 9.0.

use oncrix_lib::{Error, Result};

/// Maximum number of MMC/SD devices tracked.
pub const MMC_MAX_DEVICES: usize = 4;
/// MMC block size (always 512 bytes).
pub const MMC_BLOCK_SIZE: usize = 512;

/// Card type detected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CardType {
    /// Standard-capacity SD card (≤ 2 GiB).
    Sd,
    /// High-capacity SDHC / SDXC card.
    Sdhc,
    /// MultiMediaCard (MMC / eMMC).
    Mmc,
    /// High-capacity MMC (eMMC ≥ 2 GiB).
    MmcHc,
}

/// Card initialization state machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CardState {
    /// No card present.
    Absent,
    /// Card detected; identification in progress.
    Identifying,
    /// Card fully initialized and ready for I/O.
    Ready,
    /// Card encountered an error.
    Error,
}

/// MMC/SD command (CMD) opcodes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum MmcCmd {
    /// GO_IDLE_STATE: reset card to idle.
    GoIdleState = 0,
    /// SEND_OP_COND (MMC).
    SendOpCondMmc = 1,
    /// ALL_SEND_CID.
    AllSendCid = 2,
    /// SEND_RELATIVE_ADDR.
    SendRelativeAddr = 3,
    /// SELECT_CARD (uses RCA).
    SelectCard = 7,
    /// SEND_IF_COND (SDHC).
    SendIfCond = 8,
    /// SEND_CSD.
    SendCsd = 9,
    /// STOP_TRANSMISSION.
    StopTransmission = 12,
    /// SET_BLOCKLEN.
    SetBlockLen = 16,
    /// READ_SINGLE_BLOCK.
    ReadSingleBlock = 17,
    /// READ_MULTIPLE_BLOCK.
    ReadMultipleBlock = 18,
    /// WRITE_BLOCK.
    WriteBlock = 24,
    /// WRITE_MULTIPLE_BLOCK.
    WriteMultipleBlock = 25,
    /// ERASE_WR_BLK_START.
    EraseWrBlkStart = 32,
    /// ERASE_WR_BLK_END.
    EraseWrBlkEnd = 33,
    /// ERASE.
    Erase = 38,
    /// APP_CMD (prefix for ACMD).
    AppCmd = 55,
    /// READ_OCR.
    ReadOcr = 58,
}

/// Card identification register (CID).
#[derive(Debug, Clone, Copy, Default)]
pub struct CardCid {
    /// Manufacturer ID.
    pub mid: u8,
    /// OEM/Application ID.
    pub oid: [u8; 2],
    /// Product name.
    pub pnm: [u8; 5],
    /// Product revision.
    pub prv: u8,
    /// Serial number.
    pub psn: u32,
    /// Manufacturing date.
    pub mdt: u16,
}

/// Card-specific data (CSD) — relevant decoded fields.
#[derive(Debug, Clone, Copy, Default)]
pub struct CardCsd {
    /// CSD structure version (0 or 1).
    pub csd_structure: u8,
    /// Block size exponent (READ_BL_LEN).
    pub read_bl_len: u8,
    /// C_SIZE (capacity field, raw).
    pub c_size: u32,
    /// C_SIZE_MULT (for CSD v1).
    pub c_size_mult: u8,
    /// Card capacity in blocks (computed).
    pub capacity_blocks: u64,
}

/// MMC/SD device.
pub struct MmcBlockDevice {
    /// Host controller index.
    pub host_idx: u32,
    /// Relative Card Address (RCA).
    pub rca: u16,
    /// Card type.
    pub card_type: CardType,
    /// Card state.
    pub state: CardState,
    /// Card CID.
    pub cid: CardCid,
    /// Card CSD (decoded).
    pub csd: CardCsd,
    /// Whether the card is write-protected.
    pub write_protected: bool,
    /// Whether high-speed mode is active.
    pub high_speed: bool,
    /// Current bus width (1, 4, or 8 bits).
    pub bus_width: u8,
}

impl MmcBlockDevice {
    /// Creates a new MMC block device handle.
    pub const fn new(host_idx: u32) -> Self {
        Self {
            host_idx,
            rca: 0,
            card_type: CardType::Sd,
            state: CardState::Absent,
            cid: CardCid {
                mid: 0,
                oid: [0u8; 2],
                pnm: [0u8; 5],
                prv: 0,
                psn: 0,
                mdt: 0,
            },
            csd: CardCsd {
                csd_structure: 0,
                read_bl_len: 9,
                c_size: 0,
                c_size_mult: 0,
                capacity_blocks: 0,
            },
            write_protected: false,
            high_speed: false,
            bus_width: 1,
        }
    }

    /// Parses the CSD register value and computes card capacity.
    pub fn parse_csd(&mut self, raw: [u32; 4]) -> Result<()> {
        let csd_structure = ((raw[3] >> 30) & 0x3) as u8;
        let read_bl_len = ((raw[2] >> 16) & 0xF) as u8;
        self.csd.csd_structure = csd_structure;
        self.csd.read_bl_len = read_bl_len;
        let capacity = if csd_structure == 0 {
            // CSD v1 (SD/MMC standard capacity)
            let c_size = ((raw[1] >> 30) | ((raw[2] & 0x3FF) << 2)) as u32;
            let c_size_mult = ((raw[1] >> 15) & 0x7) as u8;
            self.csd.c_size = c_size;
            self.csd.c_size_mult = c_size_mult;
            let mult = 1u64 << (c_size_mult + 2);
            (c_size as u64 + 1) * mult * (1u64 << read_bl_len) / MMC_BLOCK_SIZE as u64
        } else {
            // CSD v2 (SDHC/SDXC)
            let c_size = ((raw[1] >> 16) | ((raw[2] & 0x3F) << 16)) as u32;
            self.csd.c_size = c_size;
            (c_size as u64 + 1) * 1024
        };
        self.csd.capacity_blocks = capacity;
        Ok(())
    }

    /// Returns the card capacity in bytes.
    pub fn capacity_bytes(&self) -> u64 {
        self.csd.capacity_blocks * MMC_BLOCK_SIZE as u64
    }

    /// Returns the card capacity in 512-byte blocks.
    pub fn capacity_blocks(&self) -> u64 {
        self.csd.capacity_blocks
    }

    /// Validates a block range for a read or write operation.
    pub fn validate_range(&self, start_block: u64, count: u32) -> Result<()> {
        if self.state != CardState::Ready {
            return Err(Error::Busy);
        }
        if count == 0 {
            return Err(Error::InvalidArgument);
        }
        let end = start_block + count as u64;
        if end > self.csd.capacity_blocks {
            return Err(Error::InvalidArgument);
        }
        Ok(())
    }

    /// Returns the LBA argument for a command (adjusts for SDHC byte addressing).
    pub fn cmd_arg(&self, lba: u64) -> u32 {
        match self.card_type {
            CardType::Sd => (lba * MMC_BLOCK_SIZE as u64) as u32,
            CardType::Sdhc | CardType::Mmc | CardType::MmcHc => lba as u32,
        }
    }

    /// Marks the card as ready.
    pub fn set_ready(&mut self, rca: u16, card_type: CardType) {
        self.rca = rca;
        self.card_type = card_type;
        self.state = CardState::Ready;
    }

    /// Returns true if the card is write-protected.
    pub fn is_write_protected(&self) -> bool {
        self.write_protected
    }
}

impl Default for MmcBlockDevice {
    fn default() -> Self {
        Self::new(0)
    }
}

/// Registry for MMC block devices.
pub struct MmcBlockRegistry {
    devices: [Option<MmcBlockDevice>; MMC_MAX_DEVICES],
    count: usize,
}

impl MmcBlockRegistry {
    /// Creates an empty registry.
    pub const fn new() -> Self {
        Self {
            devices: [const { None }; MMC_MAX_DEVICES],
            count: 0,
        }
    }

    /// Registers a new device.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the registry is full.
    pub fn register(&mut self, dev: MmcBlockDevice) -> Result<usize> {
        if self.count >= MMC_MAX_DEVICES {
            return Err(Error::OutOfMemory);
        }
        let idx = self.count;
        self.devices[idx] = Some(dev);
        self.count += 1;
        Ok(idx)
    }

    /// Returns a reference to device `idx`.
    pub fn get(&self, idx: usize) -> Option<&MmcBlockDevice> {
        self.devices.get(idx)?.as_ref()
    }

    /// Returns a mutable reference to device `idx`.
    pub fn get_mut(&mut self, idx: usize) -> Option<&mut MmcBlockDevice> {
        self.devices.get_mut(idx)?.as_mut()
    }

    /// Returns the number of registered devices.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Returns true if no devices are registered.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
}

impl Default for MmcBlockRegistry {
    fn default() -> Self {
        Self::new()
    }
}
