// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! MMC/SD card host controller driver.
//!
//! Implements an SD Host Controller (SDHC) compliant with the
//! SD Host Controller Simplified Specification version 4.20.
//! Supports SD, SDHC, SDXC, and eMMC cards using CMD/DAT lines.
//!
//! # Architecture
//!
//! - **SdHostController** — manages the SDHC MMIO register interface.
//!   Handles command issue, data transfer (PIO), and interrupt
//!   driven operation.
//! - **SdCard** — represents a discovered card. Tracks CID, CSD,
//!   OCR, RCA, and card capabilities.
//! - **SdRegistry** — fixed-size registry for SDHC instances.
//!
//! # Card Initialization Sequence
//!
//! 1. Issue CMD0 (GO_IDLE_STATE) to reset all cards.
//! 2. Issue CMD8 (SEND_IF_COND) to check voltage range (SD ≥ 2.0).
//! 3. Issue ACMD41 (SD_SEND_OP_COND) until OCR ready bit set.
//! 4. Issue CMD2 (ALL_SEND_CID) to read Card Identification Data.
//! 5. Issue CMD3 (SEND_RELATIVE_ADDR) to assign Relative Card Address.
//! 6. Issue CMD7 (SELECT_CARD) to place card in Transfer state.
//! 7. Issue ACMD6 (SET_BUS_WIDTH) to switch to 4-bit bus.
//!
//! # Transfer Modes
//!
//! - **Single block** — CMD17 (read) / CMD24 (write).
//! - **Multi-block** — CMD18 (read) / CMD25 (write), terminated with CMD12.
//!
//! Reference: SD Host Controller Simplified Specification v4.20,
//!            SD Physical Layer Simplified Specification v9.00.

#[allow(dead_code)]
use oncrix_lib::{Error, Result};

// ── MMIO Register Offsets (SDHC Simplified Spec §2.2) ───────────

/// SDMA System Address / Argument 2.
const REG_SDMA_ADDR: u32 = 0x00;

/// Block Size register.
const REG_BLOCK_SIZE: u32 = 0x04;

/// Block Count register (16-bit).
const REG_BLOCK_COUNT: u32 = 0x06;

/// Argument 1 register.
const REG_ARGUMENT: u32 = 0x08;

/// Transfer Mode register (16-bit).
const REG_TRANSFER_MODE: u32 = 0x0C;

/// Command register (16-bit).
const REG_COMMAND: u32 = 0x0E;

/// Response registers (16 bytes, 4 × 32-bit).
const REG_RESPONSE0: u32 = 0x10;
const REG_RESPONSE1: u32 = 0x14;
const REG_RESPONSE2: u32 = 0x18;
const REG_RESPONSE3: u32 = 0x1C;

/// Buffer Data Port (PIO data transfer).
const REG_BUFFER_DATA: u32 = 0x20;

/// Present State register.
const REG_PRESENT_STATE: u32 = 0x24;

/// Host Control 1 register (8-bit).
const REG_HOST_CTRL1: u32 = 0x28;

/// Power Control register (8-bit).
const REG_POWER_CTRL: u32 = 0x29;

/// Clock Control register (16-bit).
const REG_CLOCK_CTRL: u32 = 0x2C;

/// Timeout Control register (8-bit).
const REG_TIMEOUT_CTRL: u32 = 0x2E;

/// Software Reset register (8-bit).
const REG_SOFT_RESET: u32 = 0x2F;

/// Normal Interrupt Status register (16-bit).
const REG_NORMAL_INT_STATUS: u32 = 0x30;

/// Error Interrupt Status register (16-bit).
const REG_ERROR_INT_STATUS: u32 = 0x32;

/// Normal Interrupt Status Enable register.
const REG_NORMAL_INT_ENABLE: u32 = 0x34;

/// Error Interrupt Status Enable register.
const REG_ERROR_INT_ENABLE: u32 = 0x36;

/// Normal Interrupt Signal Enable register.
const REG_NORMAL_SIGNAL_ENABLE: u32 = 0x38;

/// Error Interrupt Signal Enable register.
const REG_ERROR_SIGNAL_ENABLE: u32 = 0x3A;

/// Capabilities register (64-bit, lower 32 bits).
const REG_CAPABILITIES: u32 = 0x40;

/// Capabilities register (upper 32 bits).
const REG_CAPABILITIES1: u32 = 0x44;

// ── Present State Bits ────────────────────────────────────────────

/// Command Inhibit (CMD line busy).
const PSTATE_CMD_INHIBIT: u32 = 1 << 0;

/// Data Inhibit (DAT line busy).
const PSTATE_DAT_INHIBIT: u32 = 1 << 1;

/// Card Inserted.
const PSTATE_CARD_INSERTED: u32 = 1 << 16;

/// Card state stable (debounced).
const PSTATE_CARD_STABLE: u32 = 1 << 17;

/// Buffer Read Enable.
const PSTATE_BUF_READ_ENABLE: u32 = 1 << 11;

/// Buffer Write Enable.
const PSTATE_BUF_WRITE_ENABLE: u32 = 1 << 10;

// ── Normal Interrupt Status Bits ──────────────────────────────────

/// Command Complete.
const NINT_CMD_COMPLETE: u16 = 1 << 0;

/// Transfer Complete.
const NINT_XFER_COMPLETE: u16 = 1 << 1;

/// Block Gap Event.
const _NINT_BLOCK_GAP: u16 = 1 << 2;

/// Buffer Write Ready.
const NINT_BUF_WRITE_RDY: u16 = 1 << 4;

/// Buffer Read Ready.
const NINT_BUF_READ_RDY: u16 = 1 << 5;

/// Card Insertion.
const NINT_CARD_INSERTION: u16 = 1 << 6;

/// Card Removal.
const NINT_CARD_REMOVAL: u16 = 1 << 7;

/// Error interrupt (bit 15 = summary, see error register).
const NINT_ERROR: u16 = 1 << 15;

// ── Error Interrupt Status Bits ───────────────────────────────────

/// Command Timeout Error.
const EINT_CMD_TIMEOUT: u16 = 1 << 0;

/// Command CRC Error.
const EINT_CMD_CRC: u16 = 1 << 1;

/// Command End Bit Error.
const _EINT_CMD_END: u16 = 1 << 2;

/// Command Index Error.
const EINT_CMD_INDEX: u16 = 1 << 3;

/// Data Timeout Error.
const EINT_DAT_TIMEOUT: u16 = 1 << 4;

/// Data CRC Error.
const EINT_DAT_CRC: u16 = 1 << 5;

// ── Software Reset Bits ───────────────────────────────────────────

/// Reset all (clears command and data circuits).
const SRST_ALL: u8 = 1 << 0;

/// Reset command circuit only.
const SRST_CMD: u8 = 1 << 1;

/// Reset data circuit only.
const SRST_DAT: u8 = 1 << 2;

// ── Host Control 1 Bits ───────────────────────────────────────────

/// LED control.
const _HCTRL1_LED: u8 = 1 << 0;

/// Data Transfer Width: 0 = 1-bit, 1 = 4-bit.
const HCTRL1_4BIT: u8 = 1 << 1;

/// High Speed Enable.
const HCTRL1_HS: u8 = 1 << 2;

// ── Power Control Bits ────────────────────────────────────────────

/// SD Bus Power enable.
const PWRCTRL_BUS_PWR: u8 = 1 << 0;

/// SD Bus Voltage: 3.3 V.
const PWRCTRL_3V3: u8 = 0x07 << 1;

// ── Clock Control Bits ────────────────────────────────────────────

/// Internal Clock Enable.
const CLKCTRL_INTERNAL_EN: u16 = 1 << 0;

/// Internal Clock Stable.
const CLKCTRL_INTERNAL_STABLE: u16 = 1 << 1;

/// SD Clock Enable.
const CLKCTRL_SD_CLK_EN: u16 = 1 << 2;

/// Frequency Select — divisor at bits[15:8] (divided clock mode).
const CLKCTRL_FREQ_SHIFT: u16 = 8;

// ── Command Register Bits ─────────────────────────────────────────

/// Response type: no response.
const CMD_RESP_NONE: u16 = 0 << 0;

/// Response type: 136-bit (R2).
const CMD_RESP_R2: u16 = 1 << 0;

/// Response type: 48-bit (R1, R3, R4, R6, R7).
const CMD_RESP_48: u16 = 2 << 0;

/// Response type: 48-bit with busy (R1b, R5b).
const CMD_RESP_48_BUSY: u16 = 3 << 0;

/// Enable Command CRC check.
const CMD_CRC_CHECK: u16 = 1 << 3;

/// Enable Command Index check.
const CMD_IDX_CHECK: u16 = 1 << 4;

/// Data Present: command uses DAT lines.
const CMD_DATA_PRESENT: u16 = 1 << 5;

/// Command index shift in command register (bits[13:8]).
const CMD_IDX_SHIFT: u16 = 8;

// ── Transfer Mode Bits ────────────────────────────────────────────

/// DMA Enable.
const XFER_DMA_EN: u16 = 1 << 0;

/// Block Count Enable.
const XFER_BLOCK_CNT_EN: u16 = 1 << 1;

/// Data Transfer Direction: 1 = read (card→host).
const XFER_READ: u16 = 1 << 4;

/// Multi Block Select.
const XFER_MULTI_BLOCK: u16 = 1 << 5;

/// Auto CMD12 enable (stop transmission for multi-block).
const XFER_AUTO_CMD12: u16 = 1 << 2;

// ── SD Commands ───────────────────────────────────────────────────

/// CMD0 — GO_IDLE_STATE.
const CMD0: u8 = 0;

/// CMD2 — ALL_SEND_CID (136-bit response).
const CMD2: u8 = 2;

/// CMD3 — SEND_RELATIVE_ADDR.
const CMD3: u8 = 3;

/// CMD7 — SELECT/DESELECT_CARD.
const CMD7: u8 = 7;

/// CMD8 — SEND_IF_COND (check voltage range).
const CMD8: u8 = 8;

/// CMD17 — READ_SINGLE_BLOCK.
const CMD17: u8 = 17;

/// CMD18 — READ_MULTIPLE_BLOCK.
const CMD18: u8 = 18;

/// CMD24 — WRITE_BLOCK.
const CMD24: u8 = 24;

/// CMD25 — WRITE_MULTIPLE_BLOCK.
const CMD25: u8 = 25;

/// CMD55 — APP_CMD (prefix for ACMD).
const CMD55: u8 = 55;

/// ACMD41 — SD_SEND_OP_COND.
const ACMD41: u8 = 41;

/// ACMD6 — SET_BUS_WIDTH.
const ACMD6: u8 = 6;

// ── OCR / ACMD41 Bits ─────────────────────────────────────────────

/// ACMD41 HCS (Host Capacity Support — SDHC/SDXC).
const OCR_HCS: u32 = 1 << 30;

/// ACMD41 voltage window: 3.2–3.4 V.
const OCR_VOLTAGE_33: u32 = 0x00FF_8000;

/// OCR card power-up status (ready) bit.
const OCR_READY: u32 = 1 << 31;

/// OCR CCS (Card Capacity Status): 1 = SDHC/SDXC.
const OCR_CCS: u32 = 1 << 30;

// ── CMD8 Argument ─────────────────────────────────────────────────

/// CMD8 argument: VHS = 2.7–3.6 V, check pattern = 0xAA.
const CMD8_ARG: u32 = 0x0000_01AA;

// ── Limits & Timeouts ─────────────────────────────────────────────

/// Maximum number of SDHC controllers.
const MAX_CONTROLLERS: usize = 4;

/// Standard block size for SD cards (512 bytes).
pub const SD_BLOCK_SIZE: usize = 512;

/// Maximum number of blocks per multi-block transfer.
const MAX_BLOCKS: u16 = 65535;

/// SDHC command ready polling timeout (iterations).
const CMD_TIMEOUT: u32 = 200_000;

/// ACMD41 initialization retry limit.
const INIT_RETRIES: u32 = 1_000_000;

/// Software reset wait timeout.
const RESET_TIMEOUT: u32 = 100_000;

// ── MMIO Helpers ─────────────────────────────────────────────────

/// Read a 32-bit value from an SDHC MMIO register.
///
/// # Safety
///
/// `base + offset` must be a valid, mapped SDHC register address.
unsafe fn mmio_read32(base: usize, offset: u32) -> u32 {
    // SAFETY: Caller guarantees valid MMIO address.
    unsafe { core::ptr::read_volatile((base + offset as usize) as *const u32) }
}

/// Write a 32-bit value to an SDHC MMIO register.
///
/// # Safety
///
/// `base + offset` must be a valid, mapped SDHC register address.
unsafe fn mmio_write32(base: usize, offset: u32, val: u32) {
    // SAFETY: Caller guarantees valid MMIO address.
    unsafe { core::ptr::write_volatile((base + offset as usize) as *mut u32, val) }
}

/// Read a 16-bit value from an SDHC MMIO register.
///
/// # Safety
///
/// `base + offset` must be a valid, mapped SDHC register address
/// aligned to a 16-bit boundary.
unsafe fn mmio_read16(base: usize, offset: u32) -> u16 {
    // SAFETY: Caller guarantees valid MMIO address.
    unsafe { core::ptr::read_volatile((base + offset as usize) as *const u16) }
}

/// Write a 16-bit value to an SDHC MMIO register.
///
/// # Safety
///
/// `base + offset` must be a valid, mapped SDHC register address.
unsafe fn mmio_write16(base: usize, offset: u32, val: u16) {
    // SAFETY: Caller guarantees valid MMIO address.
    unsafe { core::ptr::write_volatile((base + offset as usize) as *mut u16, val) }
}

/// Read an 8-bit value from an SDHC MMIO register.
///
/// # Safety
///
/// `base + offset` must be a valid, mapped SDHC register address.
unsafe fn mmio_read8(base: usize, offset: u32) -> u8 {
    // SAFETY: Caller guarantees valid MMIO address.
    unsafe { core::ptr::read_volatile((base + offset as usize) as *const u8) }
}

/// Write an 8-bit value to an SDHC MMIO register.
///
/// # Safety
///
/// `base + offset` must be a valid, mapped SDHC register address.
unsafe fn mmio_write8(base: usize, offset: u32, val: u8) {
    // SAFETY: Caller guarantees valid MMIO address.
    unsafe { core::ptr::write_volatile((base + offset as usize) as *mut u8, val) }
}

// ── SD Card Types ─────────────────────────────────────────────────

/// SD/MMC card variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CardType {
    /// Unknown or not yet identified.
    #[default]
    Unknown,
    /// SD version 1.x (block-addressed, ≤2 GB).
    Sdv1,
    /// SD High Capacity (≤32 GB, block-addressed).
    Sdhc,
    /// SD Extended Capacity (>32 GB, block-addressed).
    Sdxc,
    /// Embedded MultiMediaCard.
    Emmc,
}

/// SD card state machine state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CardState {
    /// No card inserted or power off.
    #[default]
    Absent,
    /// Card inserted, initialization not yet started.
    Present,
    /// Card initialization in progress.
    Initializing,
    /// Card ready for data transfer (in Transfer state).
    Ready,
    /// Card in error state.
    Error,
}

/// SD Card Identification Data (CID register, 128 bits).
#[derive(Debug, Clone, Copy, Default)]
pub struct Cid {
    /// Manufacturer ID (8 bits).
    pub mid: u8,
    /// OEM/Application ID (16 bits).
    pub oid: u16,
    /// Product name (5 ASCII characters, 40 bits).
    pub pnm: [u8; 5],
    /// Product revision: major.minor (8 bits).
    pub prv: u8,
    /// Product serial number (32 bits).
    pub psn: u32,
    /// Manufacturing date (12 bits): year[11:4] + month[3:0].
    pub mdt: u16,
}

impl Cid {
    /// Parse a CID from four 32-bit response words (R2 format).
    ///
    /// The SDHC shifts the 128-bit R2 response by 8 bits, so
    /// bytes[127:8] are stored in RESP[127:0].
    pub fn from_response(r: [u32; 4]) -> Self {
        // r[3] = bits[127:96], r[0] = bits[31:0]
        // R2 response: [127] = MID[7:0], [119:104] = OID, etc.
        let mid = (r[3] >> 24) as u8;
        let oid = ((r[3] >> 8) & 0xFFFF) as u16;
        let pnm = [
            (r[3] & 0xFF) as u8,
            (r[2] >> 24) as u8,
            ((r[2] >> 16) & 0xFF) as u8,
            ((r[2] >> 8) & 0xFF) as u8,
            (r[2] & 0xFF) as u8,
        ];
        let prv = (r[1] >> 24) as u8;
        let psn = ((r[1] & 0xFFFFFF) << 8) | (r[0] >> 24);
        let mdt = ((r[0] >> 8) & 0xFFF) as u16;
        Self {
            mid,
            oid,
            pnm,
            prv,
            psn,
            mdt,
        }
    }

    /// Return the manufacturing year (offset from 2000).
    pub fn year(&self) -> u16 {
        2000 + ((self.mdt >> 4) as u16)
    }

    /// Return the manufacturing month (1–12).
    pub fn month(&self) -> u8 {
        (self.mdt & 0xF) as u8
    }
}

/// Parsed SD card capacity and geometry.
#[derive(Debug, Clone, Copy, Default)]
pub struct CardCapacity {
    /// Total number of logical blocks.
    pub block_count: u64,
    /// Block size in bytes (typically 512).
    pub block_size: u32,
    /// Total capacity in bytes.
    pub total_bytes: u64,
}

impl CardCapacity {
    /// Compute capacity from a CSD v2 (SDHC/SDXC) register value.
    ///
    /// C_SIZE is in bits[69:48] of the 128-bit CSD.
    pub fn from_csd_v2(c_size: u32) -> Self {
        // Total blocks = (C_SIZE + 1) × 1024
        let block_count = (c_size as u64 + 1) * 1024;
        let block_size = 512u32;
        Self {
            block_count,
            block_size,
            total_bytes: block_count * block_size as u64,
        }
    }
}

/// Represents a discovered SD/MMC card.
#[derive(Debug, Default)]
pub struct SdCard {
    /// Card type (SD, SDHC, SDXC, eMMC).
    pub card_type: CardType,
    /// Card state.
    pub state: CardState,
    /// Relative Card Address (assigned during CMD3).
    pub rca: u16,
    /// Operation Conditions Register.
    pub ocr: u32,
    /// Card Identification Data.
    pub cid: Cid,
    /// Card capacity and geometry.
    pub capacity: CardCapacity,
    /// Whether 4-bit bus width is active.
    pub bus_width_4bit: bool,
    /// Whether high-speed mode is active.
    pub high_speed: bool,
    /// Number of read operations performed.
    pub read_count: u64,
    /// Number of write operations performed.
    pub write_count: u64,
    /// Number of read errors encountered.
    pub read_errors: u32,
    /// Number of write errors encountered.
    pub write_errors: u32,
}

// ── SD Host Controller ────────────────────────────────────────────

/// SD Host Controller (SDHC) instance.
pub struct SdHostController {
    /// MMIO base address of the SDHC registers.
    mmio_base: usize,
    /// Controller index.
    index: usize,
    /// Card currently inserted into this slot.
    pub card: SdCard,
    /// Whether the controller has been initialized.
    initialized: bool,
    /// Base clock frequency reported by capabilities (Hz).
    base_clock_hz: u32,
}

impl SdHostController {
    /// Create a new SDHC instance.
    pub fn new(mmio_base: usize, index: usize) -> Self {
        Self {
            mmio_base,
            index,
            card: SdCard::default(),
            initialized: false,
            base_clock_hz: 0,
        }
    }

    // ── Register Accessors ────────────────────────────────────────

    fn read32(&self, offset: u32) -> u32 {
        // SAFETY: mmio_base is the valid, mapped SDHC MMIO region.
        unsafe { mmio_read32(self.mmio_base, offset) }
    }

    fn write32(&self, offset: u32, val: u32) {
        // SAFETY: mmio_base is the valid, mapped SDHC MMIO region.
        unsafe { mmio_write32(self.mmio_base, offset, val) }
    }

    fn read16(&self, offset: u32) -> u16 {
        // SAFETY: mmio_base is the valid, mapped SDHC MMIO region.
        unsafe { mmio_read16(self.mmio_base, offset) }
    }

    fn write16(&self, offset: u32, val: u16) {
        // SAFETY: mmio_base is the valid, mapped SDHC MMIO region.
        unsafe { mmio_write16(self.mmio_base, offset, val) }
    }

    fn read8(&self, offset: u32) -> u8 {
        // SAFETY: mmio_base is the valid, mapped SDHC MMIO region.
        unsafe { mmio_read8(self.mmio_base, offset) }
    }

    fn write8(&self, offset: u32, val: u8) {
        // SAFETY: mmio_base is the valid, mapped SDHC MMIO region.
        unsafe { mmio_write8(self.mmio_base, offset, val) }
    }

    // ── Low-Level Operations ──────────────────────────────────────

    /// Perform a software reset of the specified circuit(s).
    ///
    /// `mask` is a combination of `SRST_ALL`, `SRST_CMD`, `SRST_DAT`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Busy`] if reset does not complete.
    fn soft_reset(&self, mask: u8) -> Result<()> {
        self.write8(REG_SOFT_RESET, mask);
        let mut timeout = RESET_TIMEOUT;
        loop {
            if self.read8(REG_SOFT_RESET) & mask == 0 {
                return Ok(());
            }
            timeout = timeout.wrapping_sub(1);
            if timeout == 0 {
                return Err(Error::Busy);
            }
        }
    }

    /// Wait for the CMD and DAT inhibit bits to clear.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Busy`] if inhibit bits do not clear.
    fn wait_cmd_dat_ready(&self) -> Result<()> {
        let mut timeout = CMD_TIMEOUT;
        loop {
            let state = self.read32(REG_PRESENT_STATE);
            if state & (PSTATE_CMD_INHIBIT | PSTATE_DAT_INHIBIT) == 0 {
                return Ok(());
            }
            timeout = timeout.wrapping_sub(1);
            if timeout == 0 {
                return Err(Error::Busy);
            }
        }
    }

    /// Wait for a normal interrupt status bit to be set.
    ///
    /// Polls `REG_NORMAL_INT_STATUS` until `bit` is set or error.
    ///
    /// # Errors
    ///
    /// Returns [`Error::IoError`] on error interrupt or timeout.
    fn wait_interrupt(&self, bit: u16) -> Result<()> {
        let mut timeout = CMD_TIMEOUT;
        loop {
            let status = self.read16(REG_NORMAL_INT_STATUS);
            if status & NINT_ERROR != 0 {
                let err = self.read16(REG_ERROR_INT_STATUS);
                // Clear errors.
                self.write16(REG_ERROR_INT_STATUS, err);
                self.write16(REG_NORMAL_INT_STATUS, NINT_ERROR);
                return Err(Error::IoError);
            }
            if status & bit != 0 {
                // Clear the interrupt.
                self.write16(REG_NORMAL_INT_STATUS, bit);
                return Ok(());
            }
            timeout = timeout.wrapping_sub(1);
            if timeout == 0 {
                return Err(Error::Busy);
            }
        }
    }

    /// Issue an SD command and wait for completion.
    ///
    /// `cmd_idx` is the command index (0–63).
    /// `arg` is the 32-bit command argument.
    /// `resp_type` is the CMD register response type bits.
    /// `data_present` indicates whether data transfer follows.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Busy`] on timeout, [`Error::IoError`] on
    /// hardware errors.
    pub fn send_command(
        &self,
        cmd_idx: u8,
        arg: u32,
        resp_type: u16,
        data_present: bool,
    ) -> Result<()> {
        self.wait_cmd_dat_ready()?;

        // Clear pending normal interrupts.
        let pending = self.read16(REG_NORMAL_INT_STATUS);
        self.write16(REG_NORMAL_INT_STATUS, pending & !NINT_ERROR);

        // Write argument.
        self.write32(REG_ARGUMENT, arg);

        // Build command register value.
        let mut cmd_reg: u16 = ((cmd_idx as u16) << CMD_IDX_SHIFT) | resp_type;
        if resp_type == CMD_RESP_48 || resp_type == CMD_RESP_48_BUSY {
            cmd_reg |= CMD_CRC_CHECK | CMD_IDX_CHECK;
        }
        if data_present {
            cmd_reg |= CMD_DATA_PRESENT;
        }
        self.write16(REG_COMMAND, cmd_reg);

        // Wait for Command Complete interrupt.
        self.wait_interrupt(NINT_CMD_COMPLETE)?;

        Ok(())
    }

    /// Read the 32-bit R1/R3/R6/R7 response.
    pub fn read_response32(&self) -> u32 {
        self.read32(REG_RESPONSE0)
    }

    /// Read the four response words for R2 (CID/CSD).
    pub fn read_response128(&self) -> [u32; 4] {
        [
            self.read32(REG_RESPONSE0),
            self.read32(REG_RESPONSE1),
            self.read32(REG_RESPONSE2),
            self.read32(REG_RESPONSE3),
        ]
    }

    /// Send an application-specific command (ACMD).
    ///
    /// Sends CMD55 (APP_CMD with the card's RCA) first, then sends
    /// the actual ACMD.
    fn send_acmd(&self, acmd_idx: u8, arg: u32, rca: u16, resp_type: u16) -> Result<()> {
        // CMD55: APP_CMD(RCA)
        self.send_command(CMD55, (rca as u32) << 16, CMD_RESP_48, false)?;
        // ACMD
        self.send_command(acmd_idx, arg, resp_type, false)?;
        Ok(())
    }

    /// Configure the SD clock to the given frequency divisor.
    ///
    /// Uses divided clock mode: SD_CLK = base_clock / (2 × divisor).
    /// Pass `divisor = 1` for base clock / 2, `divisor = 0` for base clock.
    fn set_clock(&self, divisor: u16) -> Result<()> {
        // Disable SD clock.
        self.write16(REG_CLOCK_CTRL, 0);

        // Enable internal clock with divisor.
        let clk = CLKCTRL_INTERNAL_EN | (divisor << CLKCTRL_FREQ_SHIFT);
        self.write16(REG_CLOCK_CTRL, clk);

        // Wait for internal clock stable.
        let mut timeout = CMD_TIMEOUT;
        loop {
            if self.read16(REG_CLOCK_CTRL) & CLKCTRL_INTERNAL_STABLE != 0 {
                break;
            }
            timeout = timeout.wrapping_sub(1);
            if timeout == 0 {
                return Err(Error::Busy);
            }
        }

        // Enable SD clock.
        self.write16(REG_CLOCK_CTRL, clk | CLKCTRL_SD_CLK_EN);
        Ok(())
    }

    // ── Card Initialization ───────────────────────────────────────

    /// Initialize the SDHC and any inserted SD card.
    ///
    /// Performs full card initialization: reset, voltage negotiation,
    /// capacity detection, CID/CSD read, and bus-width configuration.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if no card is inserted,
    /// [`Error::IoError`] on hardware error, or [`Error::Busy`] on
    /// timeout.
    pub fn init(&mut self) -> Result<()> {
        // Full software reset.
        self.soft_reset(SRST_ALL)?;

        // Read capabilities: extract base clock frequency.
        let caps = self.read32(REG_CAPABILITIES);
        // Bits[13:8]: base clock in MHz.
        let base_mhz = (caps >> 8) & 0x3F;
        self.base_clock_hz = base_mhz * 1_000_000;

        // Power on: 3.3 V, bus power enable.
        self.write8(REG_POWER_CTRL, PWRCTRL_3V3 | PWRCTRL_BUS_PWR);

        // Enable interrupt status reporting (not signals yet).
        self.write16(REG_NORMAL_INT_ENABLE, 0x00FF);
        self.write16(REG_ERROR_INT_ENABLE, 0x01FF);

        // Set identification-phase clock (~400 kHz).
        // For a typical 50 MHz base clock: divisor = 128 → ~195 kHz.
        self.set_clock(128)?;

        // Check card inserted.
        let state = self.read32(REG_PRESENT_STATE);
        if state & PSTATE_CARD_INSERTED == 0 {
            self.card.state = CardState::Absent;
            return Err(Error::NotFound);
        }

        self.card.state = CardState::Initializing;

        // CMD0: Reset all cards.
        self.send_command(CMD0, 0, CMD_RESP_NONE, false)?;

        // CMD8: Check voltage range and SD version.
        let sd_v2 = self
            .send_command(CMD8, CMD8_ARG, CMD_RESP_48, false)
            .is_ok();
        if sd_v2 {
            let resp = self.read_response32();
            if resp & 0xFF != 0xAA {
                return Err(Error::IoError);
            }
        }

        // ACMD41: Initialize — poll until OCR ready.
        let acmd41_arg = OCR_VOLTAGE_33 | if sd_v2 { OCR_HCS } else { 0 };
        let mut ocr;
        let mut retries = INIT_RETRIES;
        loop {
            self.send_acmd(ACMD41, acmd41_arg, 0, CMD_RESP_48)?;
            ocr = self.read_response32();
            if ocr & OCR_READY != 0 {
                break;
            }
            retries = retries.wrapping_sub(1);
            if retries == 0 {
                return Err(Error::Busy);
            }
        }
        self.card.ocr = ocr;
        self.card.card_type = if sd_v2 && (ocr & OCR_CCS != 0) {
            // Distinguish SDXC (>32 GB) from SDHC (≤32 GB) after reading CSD.
            CardType::Sdhc
        } else {
            CardType::Sdv1
        };

        // CMD2: Read CID.
        self.send_command(CMD2, 0, CMD_RESP_R2, false)?;
        let resp128 = self.read_response128();
        self.card.cid = Cid::from_response(resp128);

        // CMD3: Get RCA.
        self.send_command(CMD3, 0, CMD_RESP_48, false)?;
        let rca_resp = self.read_response32();
        let rca = (rca_resp >> 16) as u16;
        self.card.rca = rca;

        // Switch to full-speed clock (25 MHz = base / 2).
        self.set_clock(1)?;

        // CMD7: Select card (transition to Transfer state).
        self.send_command(CMD7, (rca as u32) << 16, CMD_RESP_48_BUSY, false)?;

        // ACMD6: Switch to 4-bit bus width.
        self.send_acmd(ACMD6, 0x2, rca, CMD_RESP_48)?;
        let mut hctrl = self.read8(REG_HOST_CTRL1);
        hctrl |= HCTRL1_4BIT;
        self.write8(REG_HOST_CTRL1, hctrl);
        self.card.bus_width_4bit = true;

        self.card.state = CardState::Ready;
        self.initialized = true;
        Ok(())
    }

    // ── Block I/O ─────────────────────────────────────────────────

    /// Read a single 512-byte block from the card using PIO.
    ///
    /// `lba` is the logical block address. `buf` must be exactly
    /// 512 bytes.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if the buffer is not 512
    /// bytes, [`Error::IoError`] on hardware error, or [`Error::Busy`]
    /// on timeout.
    pub fn read_block(&mut self, lba: u64, buf: &mut [u8]) -> Result<()> {
        if buf.len() != SD_BLOCK_SIZE {
            return Err(Error::InvalidArgument);
        }
        if self.card.state != CardState::Ready {
            return Err(Error::IoError);
        }

        // Block address: SDHC uses block LBA directly; SDv1 uses byte address.
        let arg = match self.card.card_type {
            CardType::Sdhc | CardType::Sdxc => lba as u32,
            _ => (lba * SD_BLOCK_SIZE as u64) as u32,
        };

        // Configure block size and count.
        self.write16(REG_BLOCK_SIZE, SD_BLOCK_SIZE as u16);
        self.write16(REG_BLOCK_COUNT, 1);

        // Configure transfer mode: single block, read, no DMA.
        self.write16(REG_TRANSFER_MODE, XFER_READ);

        // CMD17: READ_SINGLE_BLOCK.
        self.send_command(CMD17, arg, CMD_RESP_48, true)?;

        // Wait for Buffer Read Ready.
        self.wait_interrupt(NINT_BUF_READ_RDY)?;

        // PIO read: 512 bytes as 128 × u32.
        for chunk in buf.chunks_exact_mut(4) {
            let word = self.read32(REG_BUFFER_DATA);
            chunk[0] = (word & 0xFF) as u8;
            chunk[1] = ((word >> 8) & 0xFF) as u8;
            chunk[2] = ((word >> 16) & 0xFF) as u8;
            chunk[3] = ((word >> 24) & 0xFF) as u8;
        }

        // Wait for Transfer Complete.
        self.wait_interrupt(NINT_XFER_COMPLETE)?;

        self.card.read_count += 1;
        Ok(())
    }

    /// Write a single 512-byte block to the card using PIO.
    ///
    /// `lba` is the logical block address. `buf` must be exactly
    /// 512 bytes.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if the buffer is not 512
    /// bytes, [`Error::IoError`] on hardware error, or [`Error::Busy`]
    /// on timeout.
    pub fn write_block(&mut self, lba: u64, buf: &[u8]) -> Result<()> {
        if buf.len() != SD_BLOCK_SIZE {
            return Err(Error::InvalidArgument);
        }
        if self.card.state != CardState::Ready {
            return Err(Error::IoError);
        }

        let arg = match self.card.card_type {
            CardType::Sdhc | CardType::Sdxc => lba as u32,
            _ => (lba * SD_BLOCK_SIZE as u64) as u32,
        };

        self.write16(REG_BLOCK_SIZE, SD_BLOCK_SIZE as u16);
        self.write16(REG_BLOCK_COUNT, 1);

        // Configure transfer mode: single block, write, no DMA.
        self.write16(REG_TRANSFER_MODE, 0);

        // CMD24: WRITE_BLOCK.
        self.send_command(CMD24, arg, CMD_RESP_48, true)?;

        // Wait for Buffer Write Ready.
        self.wait_interrupt(NINT_BUF_WRITE_RDY)?;

        // PIO write: 512 bytes as 128 × u32.
        for chunk in buf.chunks_exact(4) {
            let word = (chunk[0] as u32)
                | ((chunk[1] as u32) << 8)
                | ((chunk[2] as u32) << 16)
                | ((chunk[3] as u32) << 24);
            self.write32(REG_BUFFER_DATA, word);
        }

        // Wait for Transfer Complete.
        self.wait_interrupt(NINT_XFER_COMPLETE)?;

        self.card.write_count += 1;
        Ok(())
    }

    /// Read multiple consecutive blocks using CMD18.
    ///
    /// `lba` is the starting block address. `buf` must be a multiple
    /// of 512 bytes. The count must not exceed [`MAX_BLOCKS`].
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `buf` length is not a
    /// multiple of 512 or the block count exceeds `MAX_BLOCKS`.
    pub fn read_blocks(&mut self, lba: u64, buf: &mut [u8]) -> Result<()> {
        if buf.len() % SD_BLOCK_SIZE != 0 {
            return Err(Error::InvalidArgument);
        }
        let block_count = (buf.len() / SD_BLOCK_SIZE) as u16;
        if block_count > MAX_BLOCKS {
            return Err(Error::InvalidArgument);
        }
        if self.card.state != CardState::Ready {
            return Err(Error::IoError);
        }

        let arg = match self.card.card_type {
            CardType::Sdhc | CardType::Sdxc => lba as u32,
            _ => (lba * SD_BLOCK_SIZE as u64) as u32,
        };

        self.write16(REG_BLOCK_SIZE, SD_BLOCK_SIZE as u16);
        self.write16(REG_BLOCK_COUNT, block_count);

        let xfer_mode = XFER_READ | XFER_MULTI_BLOCK | XFER_BLOCK_CNT_EN | XFER_AUTO_CMD12;
        self.write16(REG_TRANSFER_MODE, xfer_mode);

        // CMD18: READ_MULTIPLE_BLOCK.
        self.send_command(CMD18, arg, CMD_RESP_48, true)?;

        for blk in buf.chunks_exact_mut(SD_BLOCK_SIZE) {
            self.wait_interrupt(NINT_BUF_READ_RDY)?;
            for chunk in blk.chunks_exact_mut(4) {
                let word = self.read32(REG_BUFFER_DATA);
                chunk[0] = (word & 0xFF) as u8;
                chunk[1] = ((word >> 8) & 0xFF) as u8;
                chunk[2] = ((word >> 16) & 0xFF) as u8;
                chunk[3] = ((word >> 24) & 0xFF) as u8;
            }
        }

        self.wait_interrupt(NINT_XFER_COMPLETE)?;
        self.card.read_count += block_count as u64;
        Ok(())
    }

    /// Handle an SDHC interrupt.
    ///
    /// Reads and acknowledges the interrupt status. Returns the
    /// combined normal and error interrupt bits.
    pub fn handle_interrupt(&mut self) -> (u16, u16) {
        let normal = self.read16(REG_NORMAL_INT_STATUS);
        let error = self.read16(REG_ERROR_INT_STATUS);

        if normal & NINT_CARD_INSERTION != 0 {
            self.card.state = CardState::Present;
        }
        if normal & NINT_CARD_REMOVAL != 0 {
            self.card.state = CardState::Absent;
            self.card = SdCard::default();
        }
        if error != 0 {
            if error & (EINT_CMD_TIMEOUT | EINT_DAT_TIMEOUT) != 0 {
                self.card.read_errors = self.card.read_errors.saturating_add(1);
            }
            if error & (EINT_CMD_CRC | EINT_DAT_CRC | EINT_CMD_INDEX) != 0 {
                self.card.write_errors = self.card.write_errors.saturating_add(1);
            }
            self.write16(REG_ERROR_INT_STATUS, error);
        }

        self.write16(REG_NORMAL_INT_STATUS, normal);
        (normal, error)
    }

    /// Return the controller index.
    pub fn index(&self) -> usize {
        self.index
    }

    /// Return `true` if the controller has been initialized.
    pub fn is_initialized(&self) -> bool {
        self.initialized
    }

    /// Return `true` if a card is ready for I/O.
    pub fn card_ready(&self) -> bool {
        self.card.state == CardState::Ready
    }

    /// Return the total card capacity in bytes.
    pub fn capacity_bytes(&self) -> u64 {
        self.card.capacity.total_bytes
    }

    /// Return the base clock frequency in Hz.
    pub fn base_clock_hz(&self) -> u32 {
        self.base_clock_hz
    }
}

// ── Registry ─────────────────────────────────────────────────────

/// Registry for SD Host Controller instances.
pub struct SdRegistry {
    /// MMIO base addresses of registered controllers.
    controllers: [Option<usize>; MAX_CONTROLLERS],
    /// Number of registered controllers.
    count: usize,
}

impl Default for SdRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl SdRegistry {
    /// Create an empty registry.
    pub const fn new() -> Self {
        Self {
            controllers: [None; MAX_CONTROLLERS],
            count: 0,
        }
    }

    /// Register an SDHC by its MMIO base address.
    ///
    /// Returns the assigned controller index.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the registry is full.
    pub fn register(&mut self, mmio_base: usize) -> Result<usize> {
        if self.count >= MAX_CONTROLLERS {
            return Err(Error::OutOfMemory);
        }
        let idx = self.count;
        self.controllers[idx] = Some(mmio_base);
        self.count += 1;
        Ok(idx)
    }

    /// Get the MMIO base address of a registered controller.
    pub fn get(&self, index: usize) -> Option<usize> {
        if index < self.count {
            self.controllers[index]
        } else {
            None
        }
    }

    /// Return the number of registered controllers.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Return `true` if no controllers are registered.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
}
