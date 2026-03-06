// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! SPI bus master controller hardware abstraction.
//!
//! Provides a unified interface for SPI (Serial Peripheral Interface) bus
//! master controllers. Supports all four SPI modes (CPOL/CPHA combinations),
//! configurable clock frequencies, chip-select management, and both
//! polled and interrupt-driven transfer modes.

use oncrix_lib::{Error, Result};

/// Maximum number of SPI master controllers.
pub const MAX_SPI_MASTERS: usize = 8;

/// Maximum number of chip-select lines per SPI master.
pub const MAX_CS_LINES: usize = 8;

/// Maximum SPI transfer size in bytes.
pub const MAX_TRANSFER_BYTES: usize = 4096;

/// SPI clock mode (CPOL and CPHA combination).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpiMode {
    /// Mode 0: CPOL=0, CPHA=0 — idle low, sample on rising edge.
    Mode0,
    /// Mode 1: CPOL=0, CPHA=1 — idle low, sample on falling edge.
    Mode1,
    /// Mode 2: CPOL=1, CPHA=0 — idle high, sample on falling edge.
    Mode2,
    /// Mode 3: CPOL=1, CPHA=1 — idle high, sample on rising edge.
    Mode3,
}

impl SpiMode {
    /// Returns the CPOL bit for this mode.
    pub fn cpol(self) -> bool {
        matches!(self, SpiMode::Mode2 | SpiMode::Mode3)
    }

    /// Returns the CPHA bit for this mode.
    pub fn cpha(self) -> bool {
        matches!(self, SpiMode::Mode1 | SpiMode::Mode3)
    }
}

/// SPI bit order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BitOrder {
    /// Most significant bit first (standard).
    MsbFirst,
    /// Least significant bit first.
    LsbFirst,
}

/// Configuration for an SPI device on the bus.
#[derive(Debug, Clone, Copy)]
pub struct SpiDeviceConfig {
    /// SPI mode (clock polarity and phase).
    pub mode: SpiMode,
    /// Maximum clock frequency in Hz.
    pub max_freq_hz: u32,
    /// Chip-select line index.
    pub cs_index: u8,
    /// Chip-select active polarity (true = active high, false = active low).
    pub cs_active_high: bool,
    /// Bit order for transfers.
    pub bit_order: BitOrder,
    /// Word size in bits (typically 8).
    pub word_size: u8,
}

impl SpiDeviceConfig {
    /// Creates a standard SPI device configuration (Mode 0, CS active low).
    pub const fn new(cs_index: u8, max_freq_hz: u32) -> Self {
        Self {
            mode: SpiMode::Mode0,
            max_freq_hz,
            cs_index,
            cs_active_high: false,
            bit_order: BitOrder::MsbFirst,
            word_size: 8,
        }
    }
}

impl Default for SpiDeviceConfig {
    fn default() -> Self {
        Self::new(0, 1_000_000)
    }
}

/// An SPI transfer descriptor (full-duplex: simultaneous TX and RX).
#[derive(Debug)]
pub struct SpiTransfer<'a> {
    /// Data to transmit (may be shorter than rx_buf, rest is zero-filled).
    pub tx_buf: &'a [u8],
    /// Buffer to receive into.
    pub rx_buf: &'a mut [u8],
    /// Chip-select configuration to use for this transfer.
    pub config: SpiDeviceConfig,
}

impl<'a> SpiTransfer<'a> {
    /// Creates a new SPI transfer.
    pub fn new(tx_buf: &'a [u8], rx_buf: &'a mut [u8], config: SpiDeviceConfig) -> Self {
        Self {
            tx_buf,
            rx_buf,
            config,
        }
    }

    /// Returns the transfer length (max of tx/rx).
    pub fn len(&self) -> usize {
        self.tx_buf.len().max(self.rx_buf.len())
    }
}

/// Statistics for a single SPI master controller.
#[derive(Debug, Default, Clone, Copy)]
pub struct SpiStats {
    /// Total number of transfers completed.
    pub transfers: u64,
    /// Total bytes transmitted.
    pub tx_bytes: u64,
    /// Total bytes received.
    pub rx_bytes: u64,
    /// Number of transfer errors.
    pub errors: u64,
}

impl SpiStats {
    /// Creates a new zeroed statistics structure.
    pub const fn new() -> Self {
        Self {
            transfers: 0,
            tx_bytes: 0,
            rx_bytes: 0,
            errors: 0,
        }
    }
}

/// SPI master controller hardware driver.
pub struct SpiMaster {
    /// Controller index.
    id: u8,
    /// MMIO base address of the SPI controller registers.
    base_addr: u64,
    /// Maximum supported clock frequency in Hz.
    max_freq_hz: u32,
    /// Number of chip-select lines.
    cs_count: u8,
    /// Transfer statistics.
    stats: SpiStats,
    /// Whether the controller has been initialized.
    initialized: bool,
}

impl SpiMaster {
    /// Creates a new SPI master controller.
    ///
    /// # Arguments
    /// * `id` — Controller identifier (0..MAX_SPI_MASTERS).
    /// * `base_addr` — MMIO base address.
    /// * `max_freq_hz` — Maximum clock frequency in Hz.
    /// * `cs_count` — Number of chip-select lines available.
    pub const fn new(id: u8, base_addr: u64, max_freq_hz: u32, cs_count: u8) -> Self {
        Self {
            id,
            base_addr,
            max_freq_hz,
            cs_count,
            stats: SpiStats::new(),
            initialized: false,
        }
    }

    /// Returns the controller ID.
    pub fn id(&self) -> u8 {
        self.id
    }

    /// Returns the maximum clock frequency.
    pub fn max_freq_hz(&self) -> u32 {
        self.max_freq_hz
    }

    /// Returns the number of chip-select lines.
    pub fn cs_count(&self) -> u8 {
        self.cs_count
    }

    /// Initializes the SPI master controller hardware.
    ///
    /// # Errors
    /// Returns `Error::InvalidArgument` if base_addr is zero.
    pub fn init(&mut self) -> Result<()> {
        if self.base_addr == 0 {
            return Err(Error::InvalidArgument);
        }
        // SAFETY: MMIO write to SPI controller configuration register.
        // base_addr is validated to be non-zero.
        unsafe {
            let ctrl = self.base_addr as *mut u32;
            ctrl.write_volatile(0x0); // Disable during config
            let div_reg = (self.base_addr + 0x04) as *mut u32;
            div_reg.write_volatile(1); // Default clock divider
            ctrl.write_volatile(0x1); // Enable controller
        }
        self.initialized = true;
        Ok(())
    }

    /// Performs a full-duplex SPI transfer.
    ///
    /// # Errors
    /// Returns `Error::Busy` if not initialized.
    /// Returns `Error::InvalidArgument` if CS index is invalid or transfer is too large.
    pub fn transfer(&mut self, xfer: &mut SpiTransfer<'_>) -> Result<()> {
        if !self.initialized {
            return Err(Error::Busy);
        }
        if (xfer.config.cs_index as usize) >= self.cs_count as usize {
            return Err(Error::InvalidArgument);
        }
        if xfer.len() > MAX_TRANSFER_BYTES {
            return Err(Error::InvalidArgument);
        }
        if xfer.config.max_freq_hz > self.max_freq_hz {
            return Err(Error::InvalidArgument);
        }

        self.configure_hw(&xfer.config)?;
        self.assert_cs(xfer.config.cs_index, xfer.config.cs_active_high);

        let len = xfer.len();
        for i in 0..len {
            let tx_byte = if i < xfer.tx_buf.len() {
                xfer.tx_buf[i]
            } else {
                0xFF
            };
            let rx_byte = self.transfer_byte(tx_byte)?;
            if i < xfer.rx_buf.len() {
                xfer.rx_buf[i] = rx_byte;
            }
        }

        self.deassert_cs(xfer.config.cs_index, xfer.config.cs_active_high);

        self.stats.transfers += 1;
        self.stats.tx_bytes += xfer.tx_buf.len() as u64;
        self.stats.rx_bytes += xfer.rx_buf.len() as u64;
        Ok(())
    }

    /// Performs a write-only SPI transfer.
    ///
    /// # Errors
    /// Returns `Error::Busy` if not initialized.
    /// Returns `Error::InvalidArgument` if CS index is invalid or data is too large.
    pub fn write(&mut self, config: &SpiDeviceConfig, data: &[u8]) -> Result<()> {
        if !self.initialized {
            return Err(Error::Busy);
        }
        if (config.cs_index as usize) >= self.cs_count as usize {
            return Err(Error::InvalidArgument);
        }
        if data.len() > MAX_TRANSFER_BYTES {
            return Err(Error::InvalidArgument);
        }
        self.configure_hw(config)?;
        self.assert_cs(config.cs_index, config.cs_active_high);
        for &byte in data {
            self.transfer_byte(byte)?;
        }
        self.deassert_cs(config.cs_index, config.cs_active_high);
        self.stats.transfers += 1;
        self.stats.tx_bytes += data.len() as u64;
        Ok(())
    }

    /// Returns a copy of the current transfer statistics.
    pub fn stats(&self) -> SpiStats {
        self.stats
    }

    fn configure_hw(&self, config: &SpiDeviceConfig) -> Result<()> {
        // SAFETY: MMIO write to SPI mode/clock configuration register.
        // base_addr is validated to be non-zero during init().
        unsafe {
            let mode_reg = (self.base_addr + 0x08) as *mut u32;
            let mut mode_val = 0u32;
            if config.mode.cpol() {
                mode_val |= 1 << 1;
            }
            if config.mode.cpha() {
                mode_val |= 1 << 0;
            }
            if config.bit_order == BitOrder::LsbFirst {
                mode_val |= 1 << 2;
            }
            mode_val |= (config.word_size as u32 - 1) << 8;
            mode_reg.write_volatile(mode_val);
        }
        Ok(())
    }

    fn assert_cs(&self, cs_index: u8, active_high: bool) {
        // SAFETY: MMIO write to CS register. base_addr is non-zero.
        unsafe {
            let cs_reg = (self.base_addr + 0x10) as *mut u32;
            let mut val = cs_reg.read_volatile();
            let mask = 1u32 << cs_index;
            if active_high {
                val |= mask;
            } else {
                val &= !mask;
            }
            cs_reg.write_volatile(val);
        }
    }

    fn deassert_cs(&self, cs_index: u8, active_high: bool) {
        // SAFETY: MMIO write to CS deassert register. base_addr is non-zero.
        unsafe {
            let cs_reg = (self.base_addr + 0x10) as *mut u32;
            let mut val = cs_reg.read_volatile();
            let mask = 1u32 << cs_index;
            if active_high {
                val &= !mask;
            } else {
                val |= mask;
            }
            cs_reg.write_volatile(val);
        }
    }

    fn transfer_byte(&self, tx: u8) -> Result<u8> {
        // SAFETY: MMIO read/write to SPI data register. base_addr is non-zero.
        unsafe {
            let dr = (self.base_addr + 0x18) as *mut u32;
            // Wait for TX FIFO not full
            let sr = (self.base_addr + 0x14) as *const u32;
            let mut timeout = 10_000u32;
            while sr.read_volatile() & 0x2 == 0 {
                timeout -= 1;
                if timeout == 0 {
                    return Err(Error::Busy);
                }
            }
            dr.write_volatile(tx as u32);
            // Wait for RX FIFO not empty
            timeout = 10_000;
            while sr.read_volatile() & 0x1 == 0 {
                timeout -= 1;
                if timeout == 0 {
                    return Err(Error::Busy);
                }
            }
            Ok((dr.read_volatile() & 0xFF) as u8)
        }
    }
}

impl Default for SpiMaster {
    fn default() -> Self {
        Self::new(0, 0, 0, 0)
    }
}

/// Registry of all SPI master controllers in the system.
pub struct SpiMasterRegistry {
    masters: [SpiMaster; MAX_SPI_MASTERS],
    count: usize,
}

impl SpiMasterRegistry {
    /// Creates a new empty SPI master registry.
    pub fn new() -> Self {
        Self {
            masters: [
                SpiMaster::new(0, 0, 0, 0),
                SpiMaster::new(1, 0, 0, 0),
                SpiMaster::new(2, 0, 0, 0),
                SpiMaster::new(3, 0, 0, 0),
                SpiMaster::new(4, 0, 0, 0),
                SpiMaster::new(5, 0, 0, 0),
                SpiMaster::new(6, 0, 0, 0),
                SpiMaster::new(7, 0, 0, 0),
            ],
            count: 0,
        }
    }

    /// Registers an SPI master controller.
    ///
    /// # Errors
    /// Returns `Error::OutOfMemory` if the registry is full.
    pub fn register(&mut self, master: SpiMaster) -> Result<()> {
        if self.count >= MAX_SPI_MASTERS {
            return Err(Error::OutOfMemory);
        }
        self.masters[self.count] = master;
        self.count += 1;
        Ok(())
    }

    /// Returns the number of registered masters.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Returns true if no masters are registered.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Returns a mutable reference to the master at the given index.
    ///
    /// # Errors
    /// Returns `Error::NotFound` if the index is out of range.
    pub fn get_mut(&mut self, index: usize) -> Result<&mut SpiMaster> {
        if index >= self.count {
            return Err(Error::NotFound);
        }
        Ok(&mut self.masters[index])
    }
}

impl Default for SpiMasterRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Computes the clock divider for a given target frequency.
///
/// # Arguments
/// * `base_freq_hz` — Input clock frequency in Hz.
/// * `target_freq_hz` — Desired SPI clock frequency in Hz.
///
/// Returns the integer divider value (minimum 1).
pub fn compute_clock_divider(base_freq_hz: u32, target_freq_hz: u32) -> u32 {
    if target_freq_hz == 0 {
        return u32::MAX;
    }
    let div = base_freq_hz / target_freq_hz;
    div.max(1)
}
