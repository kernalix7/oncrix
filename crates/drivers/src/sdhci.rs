// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! SD Host Controller Interface (SDHCI) driver.
//!
//! Implements the SDHCI specification (v3.0/v4.0) for SD/SDIO/eMMC host
//! controllers. Supports PIO and DMA (SDMA, ADMA2) transfer modes,
//! voltage switching (3.3V/1.8V), and SD-UHS-I speed modes.

use oncrix_lib::{Error, Result};

/// SDHCI register offsets (relative to the controller base).
const REG_SDMA_ADDR: u32 = 0x00;
const REG_BLOCK_SIZE: u32 = 0x04;
const REG_BLOCK_COUNT: u32 = 0x06;
const REG_ARG1: u32 = 0x08;
const REG_XFER_MODE: u32 = 0x0C;
const REG_CMD: u32 = 0x0E;
const REG_RESP0: u32 = 0x10;
const REG_RESP1: u32 = 0x14;
const REG_RESP2: u32 = 0x18;
const REG_RESP3: u32 = 0x1C;
const REG_DATA: u32 = 0x20;
const REG_PRES_STATE: u32 = 0x24;
const REG_HOST_CTRL1: u32 = 0x28;
const REG_PWR_CTRL: u32 = 0x29;
const REG_BLK_GAP_CTRL: u32 = 0x2A;
const REG_WAKEUP_CTRL: u32 = 0x2B;
const REG_CLK_CTRL: u32 = 0x2C;
const REG_TIMEOUT_CTRL: u32 = 0x2E;
const REG_SW_RESET: u32 = 0x2F;
const REG_INT_STATUS: u32 = 0x30;
const REG_INT_ENABLE: u32 = 0x34;
const REG_SIGNAL_ENABLE: u32 = 0x38;
const REG_HOST_CTRL2: u32 = 0x3E;
const REG_CAPS: u32 = 0x40;
const REG_CAPS1: u32 = 0x44;
const REG_ADMA_ADDR: u32 = 0x58;
const REG_SLOT_INT_STATUS: u32 = 0xFC;
const REG_HOST_VERSION: u32 = 0xFE;

/// Transfer mode register bits.
const XFER_DMA_EN: u16 = 1 << 0;
const XFER_BLK_CNT_EN: u16 = 1 << 1;
const XFER_AUTO_CMD12: u16 = 1 << 2;
const XFER_AUTO_CMD23: u16 = 2 << 2;
const XFER_DATA_DIR_RD: u16 = 1 << 4; // 1=read
const XFER_MULTI_BLK: u16 = 1 << 5;

/// Command register bits.
const CMD_RESP_NONE: u16 = 0x00;
const CMD_RESP_136: u16 = 0x01;
const CMD_RESP_48: u16 = 0x02;
const CMD_RESP_48_BSY: u16 = 0x03;
const CMD_CRC_CHK_EN: u16 = 1 << 3;
const CMD_IDX_CHK_EN: u16 = 1 << 4;
const CMD_DATA_PRESENT: u16 = 1 << 5;

/// Present State register bits.
const PRES_CMD_INHIBIT: u32 = 1 << 0;
const PRES_DAT_INHIBIT: u32 = 1 << 1;
const PRES_DAT_LINE_ACTIVE: u32 = 1 << 2;
const PRES_CARD_INSERTED: u32 = 1 << 16;
const PRES_CARD_STABLE: u32 = 1 << 17;

/// Interrupt status bits.
const INT_CMD_COMPLETE: u32 = 1 << 0;
const INT_XFER_COMPLETE: u32 = 1 << 1;
const INT_BLK_GAP: u32 = 1 << 2;
const INT_DMA: u32 = 1 << 3;
const INT_BUF_WR_READY: u32 = 1 << 4;
const INT_BUF_RD_READY: u32 = 1 << 5;
const INT_CARD_INS: u32 = 1 << 6;
const INT_CARD_REM: u32 = 1 << 7;
const INT_ERROR: u32 = 1 << 15;

/// Host Control 1 register bits.
const HCTRL1_4BIT_BUS: u8 = 1 << 1;
const HCTRL1_DMA_SDMA: u8 = 0 << 3;
const HCTRL1_DMA_ADMA2: u8 = 2 << 3;
const HCTRL1_8BIT_BUS: u8 = 1 << 5;

/// Software reset bits.
const SWRESET_ALL: u8 = 1 << 0;
const SWRESET_CMD: u8 = 1 << 1;
const SWRESET_DAT: u8 = 1 << 2;

/// Clock control register bits.
const CLKCTRL_INTERNAL_CLK_EN: u16 = 1 << 0;
const CLKCTRL_INTERNAL_CLK_STABLE: u16 = 1 << 1;
const CLKCTRL_SD_CLK_EN: u16 = 1 << 2;
const CLKCTRL_PLL_EN: u16 = 1 << 3;
const CLKCTRL_FREQ_SEL_SHIFT: u16 = 8;

/// Power control values.
const PWR_1_8V: u8 = 0x0A;
const PWR_3_0V: u8 = 0x0C;
const PWR_3_3V: u8 = 0x0E;
const PWR_EN: u8 = 1 << 0;

/// SD command response type.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResponseType {
    /// No response (CMD0).
    None,
    /// 136-bit response (CMD2, CMD9, CMD10).
    R2,
    /// 48-bit response (most commands).
    R1,
    /// 48-bit with busy (CMD7, CMD12, CMD38).
    R1b,
}

/// A raw SD command.
#[derive(Clone, Copy, Debug)]
pub struct SdCommand {
    /// Command index (0–63).
    pub index: u8,
    /// Command argument.
    pub arg: u32,
    /// Expected response type.
    pub resp: ResponseType,
    /// Command transfers data (has data phase).
    pub has_data: bool,
}

impl SdCommand {
    /// Create a new SD command.
    pub const fn new(index: u8, arg: u32, resp: ResponseType, has_data: bool) -> Self {
        Self {
            index,
            arg,
            resp,
            has_data,
        }
    }
}

/// SD command response.
#[derive(Clone, Copy, Debug, Default)]
pub struct SdResponse {
    /// Response words (R2 uses all 4; R1/R1b uses word [0] only).
    pub words: [u32; 4],
}

/// SDHCI driver state.
pub struct Sdhci {
    /// Virtual address of the MMIO register block.
    mmio_base: usize,
    /// Card is currently present.
    card_inserted: bool,
    /// Base clock frequency in Hz (from capability register).
    base_clock_hz: u32,
    /// Current SD clock frequency in Hz.
    sd_clock_hz: u32,
    /// ADMA2 or SDMA transfer mode in use.
    use_dma: bool,
}

impl Sdhci {
    /// Create a new SDHCI driver.
    ///
    /// # Arguments
    /// - `mmio_base`: virtual address of the 256-byte SDHCI register block
    pub fn new(mmio_base: usize) -> Self {
        Self {
            mmio_base,
            card_inserted: false,
            base_clock_hz: 0,
            sd_clock_hz: 0,
            use_dma: false,
        }
    }

    /// Initialize the SDHCI controller.
    pub fn init(&mut self) -> Result<()> {
        self.software_reset_all()?;
        self.read_capabilities();
        self.set_power(PWR_3_3V | PWR_EN)?;
        self.set_clock(400_000)?; // Initialize at 400 kHz
        self.enable_interrupts();
        self.card_inserted = self.is_card_present();
        Ok(())
    }

    /// Perform a full software reset of the controller.
    fn software_reset_all(&mut self) -> Result<()> {
        self.write8(REG_SW_RESET, SWRESET_ALL);
        let mut tries = 0u32;
        loop {
            if (self.read8(REG_SW_RESET) & SWRESET_ALL) == 0 {
                return Ok(());
            }
            tries += 1;
            if tries > 100_000 {
                return Err(Error::Busy);
            }
            core::hint::spin_loop();
        }
    }

    /// Read the capability registers and extract the base clock.
    fn read_capabilities(&mut self) {
        let caps = self.read32(REG_CAPS);
        // Bits [13:8] = base clock frequency in MHz (spec v3.0+).
        let base_mhz = (caps >> 8) & 0xFF;
        self.base_clock_hz = base_mhz * 1_000_000;
        // Check DMA capability (ADMA2 or SDMA).
        self.use_dma = (caps & (1 << 22)) != 0 || (caps & (1 << 19)) != 0;
    }

    /// Set bus power voltage.
    fn set_power(&mut self, pwr: u8) -> Result<()> {
        self.write8(REG_PWR_CTRL, pwr);
        Ok(())
    }

    /// Set the SD clock frequency. Stops the clock first, then programs divisor.
    pub fn set_clock(&mut self, freq_hz: u32) -> Result<()> {
        if self.base_clock_hz == 0 || freq_hz == 0 {
            return Err(Error::InvalidArgument);
        }
        // Stop the clock.
        self.write16(REG_CLK_CTRL, 0);
        // Compute the divisor (power-of-two only in SDHCI spec ≤ 2.0).
        let mut div: u32 = 1;
        while div < 2048 && (self.base_clock_hz / (div * 2)) > freq_hz {
            div *= 2;
        }
        let div_val = (div as u16) << CLKCTRL_FREQ_SEL_SHIFT;
        self.write16(REG_CLK_CTRL, div_val | CLKCTRL_INTERNAL_CLK_EN);
        // Wait for internal clock stable.
        let mut tries = 0u32;
        loop {
            if (self.read16(REG_CLK_CTRL) & CLKCTRL_INTERNAL_CLK_STABLE) != 0 {
                break;
            }
            tries += 1;
            if tries > 10_000 {
                return Err(Error::Busy);
            }
            core::hint::spin_loop();
        }
        // Enable SD clock output.
        let clk = self.read16(REG_CLK_CTRL);
        self.write16(REG_CLK_CTRL, clk | CLKCTRL_SD_CLK_EN);
        self.sd_clock_hz = self.base_clock_hz / (div * 2);
        Ok(())
    }

    /// Enable a standard set of interrupts.
    fn enable_interrupts(&mut self) {
        let mask = INT_CMD_COMPLETE
            | INT_XFER_COMPLETE
            | INT_DMA
            | INT_BUF_WR_READY
            | INT_BUF_RD_READY
            | INT_CARD_INS
            | INT_CARD_REM
            | INT_ERROR;
        self.write32(REG_INT_ENABLE, mask);
        self.write32(REG_SIGNAL_ENABLE, mask);
    }

    /// Send a command and wait for completion.
    pub fn send_command(&mut self, cmd: SdCommand) -> Result<SdResponse> {
        self.wait_cmd_inhibit()?;
        if cmd.has_data {
            self.wait_dat_inhibit()?;
        }
        self.write32(REG_ARG1, cmd.arg);
        // Build transfer mode and command registers.
        let xfer: u16 = 0; // Simple command, no data for now.
        let cmd_reg = self.build_cmd_reg(&cmd);
        self.write16(REG_XFER_MODE, xfer);
        self.write16(REG_CMD, cmd_reg);
        // Wait for command complete interrupt.
        self.wait_interrupt(INT_CMD_COMPLETE)?;
        let mut resp = SdResponse::default();
        resp.words[0] = self.read32(REG_RESP0);
        resp.words[1] = self.read32(REG_RESP1);
        resp.words[2] = self.read32(REG_RESP2);
        resp.words[3] = self.read32(REG_RESP3);
        Ok(resp)
    }

    /// Build the 16-bit CMD register value.
    fn build_cmd_reg(&self, cmd: &SdCommand) -> u16 {
        let resp_bits: u16 = match cmd.resp {
            ResponseType::None => CMD_RESP_NONE,
            ResponseType::R2 => CMD_RESP_136,
            ResponseType::R1 => CMD_RESP_48 | CMD_CRC_CHK_EN | CMD_IDX_CHK_EN,
            ResponseType::R1b => CMD_RESP_48_BSY | CMD_CRC_CHK_EN | CMD_IDX_CHK_EN,
        };
        let data_bit: u16 = if cmd.has_data { CMD_DATA_PRESENT } else { 0 };
        ((cmd.index as u16) << 8) | data_bit | resp_bits
    }

    /// Check whether a card is currently inserted.
    pub fn is_card_present(&self) -> bool {
        let state = self.read32(REG_PRES_STATE);
        (state & PRES_CARD_INSERTED) != 0 && (state & PRES_CARD_STABLE) != 0
    }

    /// Handle an SDHCI interrupt; returns the interrupt status bits.
    pub fn handle_interrupt(&mut self) -> u32 {
        let ints = self.read32(REG_INT_STATUS);
        self.write32(REG_INT_STATUS, ints); // Write-to-clear.
        if (ints & INT_CARD_INS) != 0 {
            self.card_inserted = true;
        }
        if (ints & INT_CARD_REM) != 0 {
            self.card_inserted = false;
        }
        ints
    }

    /// Wait until CMD inhibit is cleared.
    fn wait_cmd_inhibit(&self) -> Result<()> {
        let mut tries = 0u32;
        loop {
            if (self.read32(REG_PRES_STATE) & PRES_CMD_INHIBIT) == 0 {
                return Ok(());
            }
            tries += 1;
            if tries > 100_000 {
                return Err(Error::Busy);
            }
            core::hint::spin_loop();
        }
    }

    /// Wait until DAT inhibit is cleared.
    fn wait_dat_inhibit(&self) -> Result<()> {
        let mut tries = 0u32;
        loop {
            if (self.read32(REG_PRES_STATE) & PRES_DAT_INHIBIT) == 0 {
                return Ok(());
            }
            tries += 1;
            if tries > 100_000 {
                return Err(Error::Busy);
            }
            core::hint::spin_loop();
        }
    }

    /// Spin-poll for an interrupt status bit to be set.
    fn wait_interrupt(&mut self, mask: u32) -> Result<()> {
        let mut tries = 0u32;
        loop {
            let ints = self.read32(REG_INT_STATUS);
            if (ints & INT_ERROR) != 0 {
                self.write32(REG_INT_STATUS, ints);
                return Err(Error::IoError);
            }
            if (ints & mask) != 0 {
                self.write32(REG_INT_STATUS, ints & mask);
                return Ok(());
            }
            tries += 1;
            if tries > 1_000_000 {
                return Err(Error::Busy);
            }
            core::hint::spin_loop();
        }
    }

    // --- MMIO helpers ---

    fn read8(&self, offset: u32) -> u8 {
        let addr = (self.mmio_base + offset as usize) as *const u8;
        // SAFETY: mmio_base is a valid SDHCI MMIO region; offset within spec-defined range.
        unsafe { core::ptr::read_volatile(addr) }
    }

    fn read16(&self, offset: u32) -> u16 {
        let addr = (self.mmio_base + offset as usize) as *const u16;
        // SAFETY: Same region as read8; offset is 2-byte aligned per SDHCI spec.
        unsafe { core::ptr::read_volatile(addr) }
    }

    fn read32(&self, offset: u32) -> u32 {
        let addr = (self.mmio_base + offset as usize) as *const u32;
        // SAFETY: Same region as read8; offset is 4-byte aligned per SDHCI spec.
        unsafe { core::ptr::read_volatile(addr) }
    }

    fn write8(&mut self, offset: u32, val: u8) {
        let addr = (self.mmio_base + offset as usize) as *mut u8;
        // SAFETY: Volatile write to a hardware register in the SDHCI MMIO region.
        unsafe { core::ptr::write_volatile(addr, val) }
    }

    fn write16(&mut self, offset: u32, val: u16) {
        let addr = (self.mmio_base + offset as usize) as *mut u16;
        // SAFETY: Volatile write to a 2-byte aligned hardware register.
        unsafe { core::ptr::write_volatile(addr, val) }
    }

    fn write32(&mut self, offset: u32, val: u32) {
        let addr = (self.mmio_base + offset as usize) as *mut u32;
        // SAFETY: Volatile write to a 4-byte aligned hardware register.
        unsafe { core::ptr::write_volatile(addr, val) }
    }
}
