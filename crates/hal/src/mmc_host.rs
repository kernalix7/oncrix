// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! MMC/SD/SDIO host controller abstraction.
//!
//! Provides a hardware-agnostic framework for MMC (MultiMediaCard), SD
//! (Secure Digital), and SDIO host controllers. Each host controller
//! manages one card slot and communicates with cards via the CMD and
//! DAT signal lines.
//!
//! # Architecture
//!
//! - [`MmcCommand`] — a command to be sent on the CMD line
//! - [`MmcResponse`] — raw response words from the card
//! - [`MmcCardType`] — detected card family
//! - [`MmcCard`] — a detected and initialized card with metadata
//! - [`MmcVoltage`] — operating voltage range
//! - [`MmcBusWidth`] — data bus width (1/4/8 bit)
//! - [`MmcPowerState`] — host power state
//! - [`MmcHost`] — the host controller managing the physical slot
//! - [`MmcHostRegistry`] — up to 4 host controllers
//!
//! # Card Initialization Sequence (SD)
//!
//! 1. CMD0 — GO_IDLE_STATE (reset)
//! 2. CMD8 — SEND_IF_COND (voltage check, SD ≥ 2.0)
//! 3. ACMD41 — SD_SEND_OP_COND (poll until card ready)
//! 4. CMD2 — ALL_SEND_CID (read Card Identification Data)
//! 5. CMD3 — SEND_RELATIVE_ADDR (assign RCA)
//! 6. CMD7 — SELECT_CARD (enter Transfer state)
//!
//! Reference: SD Host Controller Simplified Specification v4.20,
//!            SD Physical Layer Simplified Specification v9.00,
//!            JEDEC JESD84 (eMMC).

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum number of host controllers in the registry.
const MAX_HOSTS: usize = 4;

/// Maximum number of blocks per single transfer request.
const MAX_TRANSFER_BLOCKS: usize = 2048;

/// Default block size in bytes (512 for SD/MMC).
const DEFAULT_BLOCK_SIZE: u32 = 512;

/// SD card command set opcodes.

/// CMD0: GO_IDLE_STATE — software reset.
pub const CMD0: u8 = 0;
/// CMD2: ALL_SEND_CID — read Card Identification Data.
pub const CMD2: u8 = 2;
/// CMD3: SEND_RELATIVE_ADDR — publish new RCA (SD) or assign RCA (MMC).
pub const CMD3: u8 = 3;
/// CMD7: SELECT/DESELECT_CARD — toggle Transfer ↔ Stand-by state.
pub const CMD7: u8 = 7;
/// CMD8: SEND_IF_COND — check operating condition (SD 2.0+).
pub const CMD8: u8 = 8;
/// CMD17: READ_SINGLE_BLOCK.
pub const CMD17: u8 = 17;
/// CMD24: WRITE_BLOCK.
pub const CMD24: u8 = 24;
/// CMD55: APP_CMD — prefix for ACMD commands.
pub const CMD55: u8 = 55;
/// ACMD41: SD_SEND_OP_COND — send operating condition register.
pub const ACMD41: u8 = 41;

// ---------------------------------------------------------------------------
// MmcResponseType
// ---------------------------------------------------------------------------

/// Expected response format for an MMC/SD command.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum MmcResponseType {
    /// No response expected (CMD0).
    #[default]
    None,
    /// 48-bit response (R1, R3, R6, R7).
    R1,
    /// 136-bit long response (R2 — CID/CSD).
    R2,
    /// 48-bit response with busy signal (R1b).
    R1b,
    /// 48-bit OCR response (R3, R7).
    R3,
}

// ---------------------------------------------------------------------------
// MmcCommandFlags
// ---------------------------------------------------------------------------

/// Flags for an MMC/SD command.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct MmcCommandFlags(u32);

impl MmcCommandFlags {
    /// No special flags.
    pub const NONE: Self = Self(0);
    /// Command includes a data transfer phase.
    pub const DATA: Self = Self(1 << 0);
    /// Data direction is read (card → host).
    pub const READ: Self = Self(1 << 1);
    /// Data direction is write (host → card).
    pub const WRITE: Self = Self(1 << 2);
    /// Stop transmission command (CMD12).
    pub const STOP: Self = Self(1 << 3);

    /// Returns the raw bits.
    pub fn bits(self) -> u32 {
        self.0
    }

    /// Returns `true` if a data transfer is involved.
    pub fn has_data(self) -> bool {
        self.0 & Self::DATA.0 != 0
    }

    /// Returns `true` if this is a read transfer.
    pub fn is_read(self) -> bool {
        self.0 & Self::READ.0 != 0
    }
}

// ---------------------------------------------------------------------------
// MmcCommand
// ---------------------------------------------------------------------------

/// A command to be sent to the card on the CMD line.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct MmcCommand {
    /// Command index (0–63).
    pub opcode: u8,
    /// Argument bits [31:0].
    pub arg: u32,
    /// Expected response type.
    pub response_type: MmcResponseType,
    /// Behaviour flags.
    pub flags: MmcCommandFlags,
    /// Error code after command completion (0 = success).
    pub error: i32,
}

impl MmcCommand {
    /// Creates a simple command without data transfer.
    pub const fn simple(opcode: u8, arg: u32, response_type: MmcResponseType) -> Self {
        Self {
            opcode,
            arg,
            response_type,
            flags: MmcCommandFlags::NONE,
            error: 0,
        }
    }

    /// Creates CMD0 (GO_IDLE_STATE).
    pub const fn cmd0() -> Self {
        Self::simple(CMD0, 0, MmcResponseType::None)
    }

    /// Creates CMD8 (SEND_IF_COND) with the standard 3.3V pattern.
    pub const fn cmd8() -> Self {
        // VHS=1 (2.7–3.6V), check pattern=0xAA
        Self::simple(CMD8, 0x000001AA, MmcResponseType::R3)
    }

    /// Creates CMD55 (APP_CMD) before any ACMD.
    pub const fn cmd55(rca: u16) -> Self {
        Self::simple(CMD55, (rca as u32) << 16, MmcResponseType::R1)
    }

    /// Creates ACMD41 (SD_SEND_OP_COND).
    ///
    /// `hcs` sets the SDHC/SDXC capacity support bit (for SD 2.0+).
    pub const fn acmd41(hcs: bool) -> Self {
        let arg = if hcs { 0x40FF8000 } else { 0x00FF8000 };
        Self::simple(ACMD41, arg, MmcResponseType::R3)
    }

    /// Creates CMD2 (ALL_SEND_CID).
    pub const fn cmd2() -> Self {
        Self::simple(CMD2, 0, MmcResponseType::R2)
    }

    /// Creates CMD3 (SEND_RELATIVE_ADDR).
    pub const fn cmd3() -> Self {
        Self::simple(CMD3, 0, MmcResponseType::R1)
    }

    /// Creates CMD7 (SELECT_CARD) for the given RCA.
    pub const fn cmd7(rca: u16) -> Self {
        Self::simple(CMD7, (rca as u32) << 16, MmcResponseType::R1b)
    }
}

// ---------------------------------------------------------------------------
// MmcResponse
// ---------------------------------------------------------------------------

/// Raw response data from the card (up to 4 × 32-bit words).
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct MmcResponse {
    /// Response words (R1/R3/R6/R7 use [0]; R2 uses all 4).
    pub data: [u32; 4],
}

impl MmcResponse {
    /// Creates a zeroed response.
    pub const fn new() -> Self {
        Self { data: [0u32; 4] }
    }

    /// Returns the first response word (status register for R1).
    pub fn r1_status(&self) -> u32 {
        self.data[0]
    }

    /// Returns `true` if the R3/R7 OCR ready bit is set (bit 31).
    pub fn ocr_ready(&self) -> bool {
        self.data[0] & (1 << 31) != 0
    }

    /// Returns the RCA from an R6 response (bits [31:16]).
    pub fn rca(&self) -> u16 {
        (self.data[0] >> 16) as u16
    }
}

// ---------------------------------------------------------------------------
// MmcCardType
// ---------------------------------------------------------------------------

/// Type of card detected in the slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum MmcCardType {
    /// MultiMediaCard (legacy).
    #[default]
    Mmc,
    /// SD Memory Card (standard, high, or extended capacity).
    Sd,
    /// SDIO function card (I/O only).
    Sdio,
    /// SD Combo card (SDIO + SD memory).
    SdCombo,
}

// ---------------------------------------------------------------------------
// MmcVoltage
// ---------------------------------------------------------------------------

/// Operating voltage range for the card.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum MmcVoltage {
    /// 3.3 V nominal (2.7–3.6 V range).
    #[default]
    V33,
    /// 1.8 V (UHS-I signaling).
    V18,
    /// 1.2 V (UHS-II).
    V12,
}

// ---------------------------------------------------------------------------
// MmcBusWidth
// ---------------------------------------------------------------------------

/// Data bus width for card ↔ host transfers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum MmcBusWidth {
    /// 1-bit mode (default after reset).
    #[default]
    OneBit,
    /// 4-bit mode (SD, SDR/DDR).
    FourBit,
    /// 8-bit mode (eMMC only).
    EightBit,
}

// ---------------------------------------------------------------------------
// MmcPowerState
// ---------------------------------------------------------------------------

/// Power state of the host controller.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum MmcPowerState {
    /// Power fully off.
    #[default]
    Off,
    /// Power supply enabled, clock gated.
    Up,
    /// Fully powered and clock running.
    On,
}

// ---------------------------------------------------------------------------
// MmcCard
// ---------------------------------------------------------------------------

/// A detected and initialized MMC/SD/SDIO card.
#[derive(Debug)]
pub struct MmcCard {
    /// Card type.
    pub card_type: MmcCardType,
    /// Relative Card Address assigned during initialization.
    pub rca: u16,
    /// Card Identification Data (CID register, 128 bits = 4 × u32).
    pub cid: [u32; 4],
    /// Card Specific Data (CSD register, 128 bits = 4 × u32).
    pub csd: [u32; 4],
    /// Total capacity in 512-byte blocks.
    pub capacity_blocks: u64,
    /// Block size in bytes (typically 512).
    pub block_size: u32,
    /// Whether the card is currently selected (in Transfer state).
    pub selected: bool,
    /// Whether the card supports high-capacity (SDHC/SDXC).
    pub high_capacity: bool,
}

impl Default for MmcCard {
    fn default() -> Self {
        Self::new()
    }
}

impl MmcCard {
    /// Creates a zeroed card descriptor.
    pub const fn new() -> Self {
        Self {
            card_type: MmcCardType::Sd,
            rca: 0,
            cid: [0u32; 4],
            csd: [0u32; 4],
            capacity_blocks: 0,
            block_size: DEFAULT_BLOCK_SIZE,
            selected: false,
            high_capacity: false,
        }
    }

    /// Returns the total capacity in bytes.
    pub fn capacity_bytes(&self) -> u64 {
        self.capacity_blocks.saturating_mul(self.block_size as u64)
    }

    /// Returns `true` if this card slot is unoccupied.
    pub fn is_empty(&self) -> bool {
        self.rca == 0 && self.capacity_blocks == 0
    }
}

// ---------------------------------------------------------------------------
// MmcIos
// ---------------------------------------------------------------------------

/// I/O settings to apply to the host bus (clock, width, voltage).
#[derive(Debug, Clone, Copy, Default)]
pub struct MmcIos {
    /// Clock frequency in Hz (0 = clock off).
    pub clock_hz: u32,
    /// Bus width.
    pub bus_width: MmcBusWidth,
    /// Signaling voltage.
    pub voltage: MmcVoltage,
    /// Power state.
    pub power: MmcPowerState,
}

// ---------------------------------------------------------------------------
// MmcHost
// ---------------------------------------------------------------------------

/// An MMC/SD host controller managing one card slot.
///
/// Encapsulates the hardware interface (MMIO base address), current I/O
/// settings, and the card occupying the slot. The host driver calls
/// [`MmcHost::send_command`] to issue CMD/ACMD sequences and
/// [`MmcHost::set_ios`] to configure the bus.
pub struct MmcHost {
    /// Unique host index within the registry.
    pub index: usize,
    /// MMIO base address of the host controller register bank.
    pub mmio_base: u64,
    /// Current I/O configuration.
    pub ios: MmcIos,
    /// Card in the slot (if any).
    pub card: Option<MmcCard>,
    /// Whether this host slot is occupied in the registry.
    pub registered: bool,
    /// Maximum clock frequency this controller supports (Hz).
    pub max_clock_hz: u32,
    /// Capability bitmask (host-specific).
    pub capabilities: u32,
}

impl Default for MmcHost {
    fn default() -> Self {
        Self::new(0, 0)
    }
}

impl MmcHost {
    /// Creates a new host controller descriptor.
    pub const fn new(index: usize, mmio_base: u64) -> Self {
        Self {
            index,
            mmio_base,
            ios: MmcIos {
                clock_hz: 0,
                bus_width: MmcBusWidth::OneBit,
                voltage: MmcVoltage::V33,
                power: MmcPowerState::Off,
            },
            card: None,
            registered: false,
            max_clock_hz: 25_000_000,
            capabilities: 0,
        }
    }

    /// Simulates sending a command to the card.
    ///
    /// In a real driver this performs MMIO writes to the command register
    /// and waits for completion. Here it validates parameters and returns
    /// a synthetic response.
    pub fn send_command(&mut self, cmd: &mut MmcCommand) -> Result<MmcResponse> {
        if cmd.opcode > 63 {
            return Err(Error::InvalidArgument);
        }
        if self.ios.power == MmcPowerState::Off {
            return Err(Error::IoError);
        }

        // Synthesize a minimal response based on the command type.
        let mut resp = MmcResponse::new();
        match cmd.response_type {
            MmcResponseType::None => {}
            MmcResponseType::R1 | MmcResponseType::R1b => {
                // Bit 8 (READY_FOR_DATA) set in a healthy card status
                resp.data[0] = 1 << 8;
            }
            MmcResponseType::R2 => {
                // Populate CID with placeholder manufacturing data
                resp.data[0] = 0x00534453; // 'SD'
                resp.data[1] = 0x41424344;
                resp.data[2] = 0x00000001;
                resp.data[3] = 0x00000001;
            }
            MmcResponseType::R3 => {
                // OCR: busy = 0 (ready), CCS=1 (SDHC), voltage range
                resp.data[0] = 0xC0FF8000;
            }
        }
        cmd.error = 0;
        Ok(resp)
    }

    /// Applies I/O settings (clock, bus width, voltage) to the hardware.
    pub fn set_ios(&mut self, ios: MmcIos) -> Result<()> {
        if ios.clock_hz > self.max_clock_hz {
            return Err(Error::InvalidArgument);
        }
        self.ios = ios;
        Ok(())
    }

    /// Returns `true` if a card is physically present (card detect pin active).
    ///
    /// In a real driver this reads the Present State register MMIO bit.
    pub fn card_detect(&self) -> bool {
        // Stub: always reports a card present when powered.
        self.ios.power != MmcPowerState::Off
    }

    /// Returns `true` if the card is busy (DAT0 pulled low by card).
    pub fn card_busy(&self) -> bool {
        false
    }

    /// Runs the full SD card initialization sequence.
    ///
    /// Issues CMD0→CMD8→ACMD41→CMD2→CMD3→CMD7 and populates `self.card`.
    pub fn probe_sd_card(&mut self) -> Result<()> {
        if self.ios.power == MmcPowerState::Off {
            return Err(Error::IoError);
        }

        // Step 1: CMD0 — reset all cards
        let mut cmd = MmcCommand::cmd0();
        self.send_command(&mut cmd)?;

        // Step 2: CMD8 — check voltage / SD 2.0+ support
        let mut cmd = MmcCommand::cmd8();
        let r7 = self.send_command(&mut cmd)?;
        let hcs = r7.data[0] & 0xFF == 0xAA; // Echo check pattern

        // Step 3: ACMD41 loop (simplified — single attempt)
        let mut cmd55 = MmcCommand::cmd55(0);
        self.send_command(&mut cmd55)?;
        let mut acmd41 = MmcCommand::acmd41(hcs);
        let ocr = self.send_command(&mut acmd41)?;
        if !ocr.ocr_ready() {
            return Err(Error::Busy);
        }
        let high_capacity = ocr.data[0] & (1 << 30) != 0;

        // Step 4: CMD2 — read CID
        let mut cmd2 = MmcCommand::cmd2();
        let cid_resp = self.send_command(&mut cmd2)?;

        // Step 5: CMD3 — get RCA
        let mut cmd3 = MmcCommand::cmd3();
        let rca_resp = self.send_command(&mut cmd3)?;
        let rca = rca_resp.rca();

        // Step 6: CMD7 — select card
        let mut cmd7 = MmcCommand::cmd7(rca);
        self.send_command(&mut cmd7)?;

        let mut card = MmcCard::new();
        card.card_type = MmcCardType::Sd;
        card.rca = rca;
        card.cid = cid_resp.data;
        card.high_capacity = high_capacity;
        card.selected = true;
        // Capacity: simplified estimate for SDHC (≥ 4 GB = 8M blocks)
        card.capacity_blocks = if high_capacity { 8_388_608 } else { 1_048_576 };
        card.block_size = DEFAULT_BLOCK_SIZE;
        self.card = Some(card);
        Ok(())
    }

    /// Reads `count` blocks starting at `lba` into `buf`.
    pub fn read_blocks(&mut self, lba: u64, count: usize, buf: &mut [u8]) -> Result<()> {
        if count == 0 || count > MAX_TRANSFER_BLOCKS {
            return Err(Error::InvalidArgument);
        }
        let card = self.card.as_ref().ok_or(Error::NotFound)?;
        let required = count * card.block_size as usize;
        if buf.len() < required {
            return Err(Error::InvalidArgument);
        }
        if lba + count as u64 > card.capacity_blocks {
            return Err(Error::InvalidArgument);
        }
        // Stub: fill with zeros (real driver issues CMD17/CMD18 + DMA)
        buf[..required].fill(0);
        Ok(())
    }

    /// Writes `count` blocks starting at `lba` from `buf`.
    pub fn write_blocks(&mut self, lba: u64, count: usize, buf: &[u8]) -> Result<()> {
        if count == 0 || count > MAX_TRANSFER_BLOCKS {
            return Err(Error::InvalidArgument);
        }
        let card = self.card.as_ref().ok_or(Error::NotFound)?;
        let required = count * card.block_size as usize;
        if buf.len() < required {
            return Err(Error::InvalidArgument);
        }
        if lba + count as u64 > card.capacity_blocks {
            return Err(Error::InvalidArgument);
        }
        // Stub: real driver issues CMD24/CMD25 + DMA
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// MmcHostRegistry
// ---------------------------------------------------------------------------

/// System-wide registry of MMC/SD host controllers.
///
/// Maintains up to [`MAX_HOSTS`] host controller instances and provides
/// block-level read/write access to probed cards.
pub struct MmcHostRegistry {
    /// Registered host controllers.
    hosts: [MmcHost; MAX_HOSTS],
    /// Number of registered hosts.
    count: usize,
}

impl Default for MmcHostRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl MmcHostRegistry {
    /// Creates an empty registry.
    pub fn new() -> Self {
        Self {
            hosts: [
                MmcHost::new(0, 0),
                MmcHost::new(1, 0),
                MmcHost::new(2, 0),
                MmcHost::new(3, 0),
            ],
            count: 0,
        }
    }

    /// Registers a host controller and returns its index.
    pub fn register(&mut self, mmio_base: u64, max_clock_hz: u32) -> Result<usize> {
        for i in 0..MAX_HOSTS {
            if !self.hosts[i].registered {
                self.hosts[i] = MmcHost::new(i, mmio_base);
                self.hosts[i].max_clock_hz = max_clock_hz;
                self.hosts[i].registered = true;
                self.count += 1;
                return Ok(i);
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Unregisters a host controller by index.
    pub fn unregister(&mut self, index: usize) -> Result<()> {
        if index >= MAX_HOSTS || !self.hosts[index].registered {
            return Err(Error::NotFound);
        }
        self.hosts[index] = MmcHost::new(index, 0);
        self.count = self.count.saturating_sub(1);
        Ok(())
    }

    /// Probes the card in the given host slot and initializes it.
    pub fn probe(&mut self, host_index: usize) -> Result<()> {
        if host_index >= MAX_HOSTS || !self.hosts[host_index].registered {
            return Err(Error::NotFound);
        }
        // Power on the bus
        let ios = MmcIos {
            clock_hz: 400_000, // 400 kHz identification clock
            bus_width: MmcBusWidth::OneBit,
            voltage: MmcVoltage::V33,
            power: MmcPowerState::On,
        };
        self.hosts[host_index].set_ios(ios)?;
        self.hosts[host_index].probe_sd_card()
    }

    /// Reads blocks from the card in host slot `host_index`.
    pub fn read_blocks(
        &mut self,
        host_index: usize,
        lba: u64,
        count: usize,
        buf: &mut [u8],
    ) -> Result<()> {
        if host_index >= MAX_HOSTS || !self.hosts[host_index].registered {
            return Err(Error::NotFound);
        }
        self.hosts[host_index].read_blocks(lba, count, buf)
    }

    /// Writes blocks to the card in host slot `host_index`.
    pub fn write_blocks(
        &mut self,
        host_index: usize,
        lba: u64,
        count: usize,
        buf: &[u8],
    ) -> Result<()> {
        if host_index >= MAX_HOSTS || !self.hosts[host_index].registered {
            return Err(Error::NotFound);
        }
        self.hosts[host_index].write_blocks(lba, count, buf)
    }

    /// Returns an immutable reference to a host by index.
    pub fn get(&self, index: usize) -> Result<&MmcHost> {
        if index >= MAX_HOSTS || !self.hosts[index].registered {
            return Err(Error::NotFound);
        }
        Ok(&self.hosts[index])
    }

    /// Returns a mutable reference to a host by index.
    pub fn get_mut(&mut self, index: usize) -> Result<&mut MmcHost> {
        if index >= MAX_HOSTS || !self.hosts[index].registered {
            return Err(Error::NotFound);
        }
        Ok(&mut self.hosts[index])
    }

    /// Returns the number of registered hosts.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Returns `true` if no hosts are registered.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
}
