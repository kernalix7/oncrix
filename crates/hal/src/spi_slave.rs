// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! SPI slave device abstraction layer.
//!
//! Manages SPI (Serial Peripheral Interface) slave device descriptors and
//! provides a uniform interface for SPI transfers, chip-select management,
//! and mode configuration.
//!
//! # SPI Modes
//!
//! SPI mode is determined by clock polarity (CPOL) and clock phase (CPHA):
//!
//! | Mode | CPOL | CPHA | Description |
//! |------|------|------|-------------|
//! | 0    | 0    | 0    | Clock idle low, sample on rising |
//! | 1    | 0    | 1    | Clock idle low, sample on falling |
//! | 2    | 1    | 0    | Clock idle high, sample on falling |
//! | 3    | 1    | 1    | Clock idle high, sample on rising |
//!
//! # References
//!
//! - Motorola SPI Block Guide, Version 3.06

#![allow(dead_code)]

use oncrix_lib::{Error, Result};

/// SPI clock polarity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cpol {
    /// Clock idle state is low.
    IdleLow = 0,
    /// Clock idle state is high.
    IdleHigh = 1,
}

/// SPI clock phase.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cpha {
    /// Sample on first clock edge (leading edge).
    LeadingEdge = 0,
    /// Sample on second clock edge (trailing edge).
    TrailingEdge = 1,
}

/// SPI transfer mode (combination of CPOL and CPHA).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpiMode {
    /// Mode 0: CPOL=0, CPHA=0.
    Mode0,
    /// Mode 1: CPOL=0, CPHA=1.
    Mode1,
    /// Mode 2: CPOL=1, CPHA=0.
    Mode2,
    /// Mode 3: CPOL=1, CPHA=1.
    Mode3,
}

impl SpiMode {
    /// Returns the CPOL value for this mode.
    pub const fn cpol(self) -> Cpol {
        match self {
            Self::Mode0 | Self::Mode1 => Cpol::IdleLow,
            Self::Mode2 | Self::Mode3 => Cpol::IdleHigh,
        }
    }

    /// Returns the CPHA value for this mode.
    pub const fn cpha(self) -> Cpha {
        match self {
            Self::Mode0 | Self::Mode2 => Cpha::LeadingEdge,
            Self::Mode1 | Self::Mode3 => Cpha::TrailingEdge,
        }
    }
}

/// SPI bit order for data transfer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BitOrder {
    /// Most significant bit first (standard).
    MsbFirst,
    /// Least significant bit first.
    LsbFirst,
}

/// SPI chip-select polarity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CsPolarity {
    /// Chip select is active low (standard).
    ActiveLow,
    /// Chip select is active high.
    ActiveHigh,
}

/// Configuration for an SPI slave device.
#[derive(Debug, Clone, Copy)]
pub struct SpiSlaveConfig {
    /// SPI mode (CPOL + CPHA).
    pub mode: SpiMode,
    /// Maximum clock frequency in Hz.
    pub max_clock_hz: u32,
    /// Bits per word (typically 8).
    pub bits_per_word: u8,
    /// Bit order.
    pub bit_order: BitOrder,
    /// Chip select polarity.
    pub cs_polarity: CsPolarity,
    /// Chip select index on the controller.
    pub cs_index: u8,
}

impl SpiSlaveConfig {
    /// Creates a standard 8-bit, mode 0, active-low CS configuration.
    pub const fn standard(cs_index: u8, max_clock_hz: u32) -> Self {
        Self {
            mode: SpiMode::Mode0,
            max_clock_hz,
            bits_per_word: 8,
            bit_order: BitOrder::MsbFirst,
            cs_polarity: CsPolarity::ActiveLow,
            cs_index,
        }
    }
}

/// An SPI transfer descriptor (one segment of a compound transaction).
#[derive(Debug)]
pub struct SpiTransfer<'a> {
    /// Data to transmit (or `None` for receive-only, controller sends 0xFF).
    pub tx: Option<&'a [u8]>,
    /// Buffer to receive into (or `None` for transmit-only).
    pub rx: Option<&'a mut [u8]>,
    /// Whether to keep CS asserted after this transfer.
    pub keep_cs: bool,
}

impl<'a> SpiTransfer<'a> {
    /// Creates a write-only transfer.
    pub fn write(data: &'a [u8]) -> Self {
        Self {
            tx: Some(data),
            rx: None,
            keep_cs: false,
        }
    }

    /// Creates a read-only transfer of a given length.
    pub fn read(buf: &'a mut [u8]) -> Self {
        Self {
            tx: None,
            rx: Some(buf),
            keep_cs: false,
        }
    }

    /// Creates a full-duplex transfer.
    pub fn full_duplex(tx: &'a [u8], rx: &'a mut [u8]) -> Self {
        Self {
            tx: Some(tx),
            rx: Some(rx),
            keep_cs: false,
        }
    }

    /// Returns the transfer length (whichever buffer is longer).
    pub fn len(&self) -> usize {
        let tx_len = self.tx.map_or(0, |b| b.len());
        let rx_len = self.rx.as_deref().map_or(0, |b| b.len());
        tx_len.max(rx_len)
    }

    /// Returns whether the transfer has zero length.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Trait for SPI bus controllers that can drive slave transactions.
pub trait SpiBusOps {
    /// Configures the bus for a specific slave device.
    fn configure(&mut self, config: &SpiSlaveConfig) -> Result<()>;

    /// Asserts (selects) the chip select for the configured device.
    fn cs_assert(&mut self) -> Result<()>;

    /// Deasserts (releases) the chip select.
    fn cs_deassert(&mut self) -> Result<()>;

    /// Transfers a single byte full-duplex: sends `tx`, returns received byte.
    fn transfer_byte(&mut self, tx: u8) -> Result<u8>;

    /// Executes a list of transfer segments as a compound transaction.
    ///
    /// CS is asserted before the first transfer and deasserted after the last
    /// unless `keep_cs` is set on intermediate transfers.
    fn execute(&mut self, transfers: &mut [SpiTransfer<'_>]) -> Result<()> {
        if transfers.is_empty() {
            return Ok(());
        }
        self.cs_assert()?;
        let last = transfers.len() - 1;
        for (i, xfer) in transfers.iter_mut().enumerate() {
            let len = xfer.len();
            for j in 0..len {
                let tx_byte = xfer.tx.and_then(|b| b.get(j)).copied().unwrap_or(0xFF);
                let rx_byte = self.transfer_byte(tx_byte)?;
                if let Some(rx) = xfer.rx.as_deref_mut() {
                    if let Some(slot) = rx.get_mut(j) {
                        *slot = rx_byte;
                    }
                }
            }
            if i == last || !xfer.keep_cs {
                if i == last {
                    self.cs_deassert()?;
                }
            }
        }
        Ok(())
    }
}

/// Registry of SPI slave devices attached to a bus.
pub struct SpiSlaveRegistry {
    devices: [Option<SpiSlaveConfig>; 8],
    count: usize,
}

impl SpiSlaveRegistry {
    /// Creates an empty registry.
    pub const fn new() -> Self {
        Self {
            devices: [None; 8],
            count: 0,
        }
    }

    /// Registers a slave device.
    pub fn register(&mut self, config: SpiSlaveConfig) -> Result<usize> {
        if self.count >= 8 {
            return Err(Error::OutOfMemory);
        }
        if config.bits_per_word == 0 || config.bits_per_word > 32 {
            return Err(Error::InvalidArgument);
        }
        let idx = self.count;
        self.devices[idx] = Some(config);
        self.count += 1;
        Ok(idx)
    }

    /// Returns the device configuration at the given index.
    pub fn get(&self, index: usize) -> Option<&SpiSlaveConfig> {
        self.devices.get(index)?.as_ref()
    }

    /// Returns the number of registered devices.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Returns whether the registry is empty.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
}

impl Default for SpiSlaveRegistry {
    fn default() -> Self {
        Self::new()
    }
}
