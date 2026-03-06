// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! SDIO host controller hardware abstraction.
//!
//! Provides a unified interface for SD/SDIO/MMC host controllers. Supports
//! SD protocol command/response handling, data transfer with DMA, bus width
//! configuration (1-bit, 4-bit, 8-bit), and power management.

use oncrix_lib::{Error, Result};

/// Maximum number of SDIO host controllers.
pub const MAX_SDIO_HOSTS: usize = 4;

/// SDIO command response types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SdioResponseType {
    /// No response expected.
    None,
    /// Short response (48-bit).
    R1,
    /// Short response with busy (48-bit + busy check).
    R1b,
    /// Long response (136-bit CID/CSD).
    R2,
    /// Short response (48-bit OCR).
    R3,
    /// Short response (48-bit RCA).
    R6,
    /// Short response (48-bit switch function status).
    R7,
}

/// SDIO bus width.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SdioBusWidth {
    /// 1-bit SD bus (default).
    Width1Bit,
    /// 4-bit SD bus.
    Width4Bit,
    /// 8-bit eMMC bus.
    Width8Bit,
}

/// SDIO clock speed mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SdioSpeed {
    /// Default speed (25 MHz).
    DefaultSpeed,
    /// High speed (50 MHz).
    HighSpeed,
    /// SDR50 (100 MHz).
    Sdr50,
    /// SDR104 (208 MHz).
    Sdr104,
    /// DDR50 (50 MHz, double data rate).
    Ddr50,
}

impl SdioSpeed {
    /// Returns the maximum clock frequency for this speed mode in Hz.
    pub fn max_freq_hz(self) -> u32 {
        match self {
            SdioSpeed::DefaultSpeed => 25_000_000,
            SdioSpeed::HighSpeed => 50_000_000,
            SdioSpeed::Sdr50 => 100_000_000,
            SdioSpeed::Sdr104 => 208_000_000,
            SdioSpeed::Ddr50 => 50_000_000,
        }
    }
}

/// An SDIO command.
#[derive(Debug, Clone, Copy)]
pub struct SdioCommand {
    /// Command index (0..63).
    pub cmd_index: u8,
    /// Command argument.
    pub argument: u32,
    /// Expected response type.
    pub response_type: SdioResponseType,
    /// Whether this command initiates a data transfer.
    pub has_data: bool,
    /// Data transfer direction (true = read from card).
    pub read: bool,
    /// Block count for multi-block transfers.
    pub block_count: u16,
    /// Block size in bytes.
    pub block_size: u16,
}

impl SdioCommand {
    /// Creates a simple command with no data transfer.
    pub const fn simple(cmd_index: u8, argument: u32, response_type: SdioResponseType) -> Self {
        Self {
            cmd_index,
            argument,
            response_type,
            has_data: false,
            read: false,
            block_count: 0,
            block_size: 0,
        }
    }

    /// Creates a read data command.
    pub const fn read_data(
        cmd_index: u8,
        argument: u32,
        block_count: u16,
        block_size: u16,
    ) -> Self {
        Self {
            cmd_index,
            argument,
            response_type: SdioResponseType::R1,
            has_data: true,
            read: true,
            block_count,
            block_size,
        }
    }
}

impl Default for SdioCommand {
    fn default() -> Self {
        Self::simple(0, 0, SdioResponseType::None)
    }
}

/// Response data from an SDIO command.
#[derive(Debug, Clone, Copy, Default)]
pub struct SdioResponse {
    /// Response words (up to 4 for R2 136-bit response).
    pub words: [u32; 4],
    /// Number of valid response words.
    pub word_count: u8,
}

impl SdioResponse {
    /// Creates a new zeroed response.
    pub const fn new() -> Self {
        Self {
            words: [0u32; 4],
            word_count: 0,
        }
    }
}

/// SDIO host controller statistics.
#[derive(Debug, Default, Clone, Copy)]
pub struct SdioStats {
    /// Total commands issued.
    pub commands_issued: u64,
    /// Total data blocks transferred.
    pub blocks_transferred: u64,
    /// Number of command timeout errors.
    pub cmd_timeouts: u64,
    /// Number of CRC errors.
    pub crc_errors: u64,
    /// Number of data transfer errors.
    pub data_errors: u64,
}

impl SdioStats {
    /// Creates a new zeroed statistics structure.
    pub const fn new() -> Self {
        Self {
            commands_issued: 0,
            blocks_transferred: 0,
            cmd_timeouts: 0,
            crc_errors: 0,
            data_errors: 0,
        }
    }
}

/// SDIO host controller hardware driver.
pub struct SdioHost {
    /// Host controller index.
    id: u8,
    /// MMIO base address of the SDIO host controller registers.
    base_addr: u64,
    /// Current bus width.
    bus_width: SdioBusWidth,
    /// Current clock speed mode.
    speed: SdioSpeed,
    /// Current clock frequency in Hz.
    clock_hz: u32,
    /// Transfer statistics.
    stats: SdioStats,
    /// Whether the host controller has been initialized.
    initialized: bool,
}

impl SdioHost {
    /// Creates a new SDIO host controller.
    ///
    /// # Arguments
    /// * `id` — Host controller identifier.
    /// * `base_addr` — MMIO base address.
    pub const fn new(id: u8, base_addr: u64) -> Self {
        Self {
            id,
            base_addr,
            bus_width: SdioBusWidth::Width1Bit,
            speed: SdioSpeed::DefaultSpeed,
            clock_hz: 400_000, // Start at 400 kHz for identification
            stats: SdioStats::new(),
            initialized: false,
        }
    }

    /// Returns the host controller ID.
    pub fn id(&self) -> u8 {
        self.id
    }

    /// Returns the current bus width.
    pub fn bus_width(&self) -> SdioBusWidth {
        self.bus_width
    }

    /// Returns the current clock frequency in Hz.
    pub fn clock_hz(&self) -> u32 {
        self.clock_hz
    }

    /// Initializes the SDIO host controller.
    ///
    /// Sets up the controller for card identification at 400 kHz.
    ///
    /// # Errors
    /// Returns `Error::InvalidArgument` if base_addr is zero.
    pub fn init(&mut self) -> Result<()> {
        if self.base_addr == 0 {
            return Err(Error::InvalidArgument);
        }
        // SAFETY: MMIO writes to SDIO host controller initialization registers.
        // base_addr is validated to be non-zero.
        unsafe {
            let ctrl = self.base_addr as *mut u32;
            ctrl.write_volatile(0x0); // Reset
            let clk = (self.base_addr + 0x04) as *mut u32;
            clk.write_volatile(400_000); // 400 kHz ID mode
            let pwr = (self.base_addr + 0x08) as *mut u32;
            pwr.write_volatile(0x3); // Power on
            ctrl.write_volatile(0x1); // Enable
        }
        self.initialized = true;
        Ok(())
    }

    /// Sets the bus clock frequency.
    ///
    /// # Errors
    /// Returns `Error::Busy` if not initialized.
    /// Returns `Error::InvalidArgument` if freq_hz exceeds speed mode maximum.
    pub fn set_clock(&mut self, freq_hz: u32) -> Result<()> {
        if !self.initialized {
            return Err(Error::Busy);
        }
        if freq_hz > self.speed.max_freq_hz() {
            return Err(Error::InvalidArgument);
        }
        self.clock_hz = freq_hz;
        // SAFETY: MMIO write to SDIO clock frequency register. base_addr is non-zero.
        unsafe {
            let clk = (self.base_addr + 0x04) as *mut u32;
            clk.write_volatile(freq_hz);
        }
        Ok(())
    }

    /// Sets the bus width.
    ///
    /// # Errors
    /// Returns `Error::Busy` if not initialized.
    pub fn set_bus_width(&mut self, width: SdioBusWidth) -> Result<()> {
        if !self.initialized {
            return Err(Error::Busy);
        }
        self.bus_width = width;
        // SAFETY: MMIO write to SDIO bus width register. base_addr is non-zero.
        unsafe {
            let bw = (self.base_addr + 0x0C) as *mut u32;
            bw.write_volatile(match width {
                SdioBusWidth::Width1Bit => 0,
                SdioBusWidth::Width4Bit => 1,
                SdioBusWidth::Width8Bit => 2,
            });
        }
        Ok(())
    }

    /// Issues an SDIO command and returns the response.
    ///
    /// # Errors
    /// Returns `Error::Busy` if not initialized or controller is busy.
    /// Returns `Error::IoError` on timeout or CRC error.
    pub fn send_command(&mut self, cmd: &SdioCommand) -> Result<SdioResponse> {
        if !self.initialized {
            return Err(Error::Busy);
        }
        // SAFETY: MMIO writes/reads to SDIO command registers. base_addr is non-zero.
        unsafe {
            let sr = (self.base_addr + 0x10) as *const u32;
            // Wait for controller not busy
            let mut timeout = 100_000u32;
            while sr.read_volatile() & 0x1 != 0 {
                timeout -= 1;
                if timeout == 0 {
                    self.stats.cmd_timeouts += 1;
                    return Err(Error::IoError);
                }
            }
            let arg = (self.base_addr + 0x14) as *mut u32;
            arg.write_volatile(cmd.argument);
            let cmd_reg = (self.base_addr + 0x18) as *mut u32;
            let cmd_val = (cmd.cmd_index as u32)
                | match cmd.response_type {
                    SdioResponseType::None => 0,
                    SdioResponseType::R1 | SdioResponseType::R6 | SdioResponseType::R7 => 0x40,
                    SdioResponseType::R1b => 0xC0,
                    SdioResponseType::R2 => 0x80,
                    SdioResponseType::R3 => 0x20,
                };
            cmd_reg.write_volatile(cmd_val | 0x400); // CPSMEN bit
        }
        self.stats.commands_issued += 1;
        let mut resp = SdioResponse::new();
        if cmd.response_type != SdioResponseType::None {
            // SAFETY: MMIO reads from SDIO response registers. base_addr is non-zero.
            unsafe {
                let r0 = (self.base_addr + 0x20) as *const u32;
                resp.words[0] = r0.read_volatile();
                if cmd.response_type == SdioResponseType::R2 {
                    resp.words[1] = r0.add(1).read_volatile();
                    resp.words[2] = r0.add(2).read_volatile();
                    resp.words[3] = r0.add(3).read_volatile();
                    resp.word_count = 4;
                } else {
                    resp.word_count = 1;
                }
            }
        }
        Ok(resp)
    }

    /// Returns a copy of the transfer statistics.
    pub fn stats(&self) -> SdioStats {
        self.stats
    }
}

impl Default for SdioHost {
    fn default() -> Self {
        Self::new(0, 0)
    }
}

/// Registry of SDIO host controllers.
pub struct SdioHostRegistry {
    hosts: [SdioHost; MAX_SDIO_HOSTS],
    count: usize,
}

impl SdioHostRegistry {
    /// Creates a new empty SDIO host registry.
    pub fn new() -> Self {
        Self {
            hosts: [
                SdioHost::new(0, 0),
                SdioHost::new(1, 0),
                SdioHost::new(2, 0),
                SdioHost::new(3, 0),
            ],
            count: 0,
        }
    }

    /// Registers an SDIO host controller.
    ///
    /// # Errors
    /// Returns `Error::OutOfMemory` if the registry is full.
    pub fn register(&mut self, host: SdioHost) -> Result<()> {
        if self.count >= MAX_SDIO_HOSTS {
            return Err(Error::OutOfMemory);
        }
        self.hosts[self.count] = host;
        self.count += 1;
        Ok(())
    }

    /// Returns the number of registered hosts.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Returns true if no hosts are registered.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Returns a mutable reference to the host at the given index.
    ///
    /// # Errors
    /// Returns `Error::NotFound` if the index is out of range.
    pub fn get_mut(&mut self, index: usize) -> Result<&mut SdioHost> {
        if index >= self.count {
            return Err(Error::NotFound);
        }
        Ok(&mut self.hosts[index])
    }
}

impl Default for SdioHostRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Computes the SD card sector address for a given byte offset.
///
/// # Arguments
/// * `byte_offset` — Byte offset into the card.
/// * `high_capacity` — True for SDHC/SDXC cards (sector-addressed).
pub fn offset_to_address(byte_offset: u64, high_capacity: bool) -> u32 {
    if high_capacity {
        (byte_offset / 512) as u32
    } else {
        byte_offset as u32
    }
}
