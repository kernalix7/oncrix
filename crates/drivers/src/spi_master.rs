// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! SPI master controller driver.
//!
//! Provides a generic SPI master interface supporting all four SPI modes
//! (CPOL/CPHA combinations), chip-select management, and both full-duplex
//! and simplex transfers. Controllers expose a FIFO-based TX/RX model.
//!
//! # SPI Modes
//!
//! | Mode | CPOL | CPHA | Clock idle | Data sampled |
//! |------|------|------|------------|--------------|
//! |  0   |  0   |  0   | Low        | Rising edge  |
//! |  1   |  0   |  1   | Low        | Falling edge |
//! |  2   |  1   |  0   | High       | Falling edge |
//! |  3   |  1   |  1   | High       | Rising edge  |
//!
//! Reference: SPI Block Guide (Motorola/NXP), Wikipedia SPI article.

use oncrix_lib::{Error, Result};

// ── SPI mode ──────────────────────────────────────────────────────────────────

/// SPI clock polarity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Cpol {
    /// Clock idle low.
    Low = 0,
    /// Clock idle high.
    High = 1,
}

/// SPI clock phase.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Cpha {
    /// Data sampled on leading edge.
    LeadingEdge = 0,
    /// Data sampled on trailing edge.
    TrailingEdge = 1,
}

/// Combined SPI mode (CPOL + CPHA).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SpiMode {
    /// Clock polarity.
    pub cpol: Cpol,
    /// Clock phase.
    pub cpha: Cpha,
}

impl SpiMode {
    /// SPI Mode 0: CPOL=0, CPHA=0 (most common).
    pub const MODE_0: Self = Self {
        cpol: Cpol::Low,
        cpha: Cpha::LeadingEdge,
    };
    /// SPI Mode 1: CPOL=0, CPHA=1.
    pub const MODE_1: Self = Self {
        cpol: Cpol::Low,
        cpha: Cpha::TrailingEdge,
    };
    /// SPI Mode 2: CPOL=1, CPHA=0.
    pub const MODE_2: Self = Self {
        cpol: Cpol::High,
        cpha: Cpha::LeadingEdge,
    };
    /// SPI Mode 3: CPOL=1, CPHA=1.
    pub const MODE_3: Self = Self {
        cpol: Cpol::High,
        cpha: Cpha::TrailingEdge,
    };

    /// Encode mode as a 2-bit value (CPOL<<1 | CPHA).
    pub fn as_bits(self) -> u8 {
        ((self.cpol as u8) << 1) | (self.cpha as u8)
    }
}

// ── Chip select polarity ──────────────────────────────────────────────────────

/// Chip select active polarity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CsPolarity {
    /// CS active low (standard).
    ActiveLow,
    /// CS active high.
    ActiveHigh,
}

// ── SPI transfer ──────────────────────────────────────────────────────────────

/// Descriptor for a single SPI synchronous transfer.
///
/// Either `tx_buf` or `rx_buf` may be `None` for simplex transfers.
pub struct SpiTransfer<'a> {
    /// Bytes to transmit (or `None` to send zeros).
    pub tx_buf: Option<&'a [u8]>,
    /// Buffer to store received bytes (or `None` to discard).
    pub rx_buf: Option<&'a mut [u8]>,
    /// Transfer length in bytes (must match non-None buffer lengths).
    pub len: usize,
    /// Assert CS before this transfer.
    pub cs_assert: bool,
    /// De-assert CS after this transfer.
    pub cs_deassert: bool,
    /// Bits per word (typically 8).
    pub bits_per_word: u8,
}

// ── SPI device configuration ──────────────────────────────────────────────────

/// Per-device SPI configuration.
#[derive(Clone, Copy, Debug)]
pub struct SpiDeviceConfig {
    /// Chip select index (0-based).
    pub chip_select: u8,
    /// SPI mode (CPOL/CPHA).
    pub mode: SpiMode,
    /// Maximum clock frequency in Hz.
    pub max_speed_hz: u32,
    /// Bits per word.
    pub bits_per_word: u8,
    /// CS polarity.
    pub cs_polarity: CsPolarity,
}

// ── MMIO FIFO helpers ─────────────────────────────────────────────────────────

/// Maximum number of SPI devices on a bus.
pub const MAX_SPI_DEVICES: usize = 8;

/// FIFO depth (bytes). Must not be exceeded per burst.
pub const FIFO_DEPTH: usize = 64;

/// Transfer timeout in iterations.
const TX_TIMEOUT: u32 = 1_000_000;

// ── SpiController trait ───────────────────────────────────────────────────────

/// Hardware-specific SPI controller operations.
///
/// Implementors map these primitives to their specific MMIO registers.
pub trait SpiControllerHw {
    /// Configure clock rate to the closest achievable frequency ≤ `hz`.
    fn set_clock_hz(&mut self, hz: u32) -> Result<()>;

    /// Set SPI mode (CPOL/CPHA).
    fn set_mode(&mut self, mode: SpiMode);

    /// Assert or de-assert chip select `cs`.
    fn set_cs(&mut self, cs: u8, active: bool, polarity: CsPolarity);

    /// Write bytes to TX FIFO. Returns bytes written.
    fn fifo_write(&mut self, data: &[u8]) -> usize;

    /// Read bytes from RX FIFO into `buf`. Returns bytes read.
    fn fifo_read(&mut self, buf: &mut [u8]) -> usize;

    /// Returns true when TX FIFO is empty (transfer complete).
    fn tx_empty(&self) -> bool;

    /// Returns true when RX FIFO has data available.
    fn rx_available(&self) -> bool;

    /// Returns the number of bytes available in RX FIFO.
    fn rx_count(&self) -> usize;
}

// ── SpiMaster ─────────────────────────────────────────────────────────────────

/// Generic SPI master built on top of [`SpiControllerHw`].
pub struct SpiMaster<HW: SpiControllerHw> {
    hw: HW,
    devices: [Option<SpiDeviceConfig>; MAX_SPI_DEVICES],
    device_count: usize,
}

impl<HW: SpiControllerHw> SpiMaster<HW> {
    /// Create a new SPI master.
    pub fn new(hw: HW) -> Self {
        Self {
            hw,
            devices: [None; MAX_SPI_DEVICES],
            device_count: 0,
        }
    }

    /// Register a SPI device. Returns the device slot index.
    pub fn add_device(&mut self, config: SpiDeviceConfig) -> Result<usize> {
        if self.device_count >= MAX_SPI_DEVICES {
            return Err(Error::OutOfMemory);
        }
        let idx = self.device_count;
        self.devices[idx] = Some(config);
        self.device_count += 1;
        Ok(idx)
    }

    /// Execute a synchronous transfer for the device at `device_idx`.
    ///
    /// Applies device configuration (speed, mode, CS polarity), then
    /// performs a full-duplex FIFO-based transfer.
    pub fn sync_transfer(&mut self, device_idx: usize, xfer: &mut SpiTransfer<'_>) -> Result<()> {
        let dev = self
            .devices
            .get(device_idx)
            .and_then(|d| d.as_ref())
            .ok_or(Error::NotFound)?;

        let cs = dev.chip_select;
        let mode = dev.mode;
        let speed = dev.max_speed_hz;
        let polarity = dev.cs_polarity;

        // Apply configuration.
        self.hw.set_mode(mode);
        self.hw.set_clock_hz(speed)?;

        if xfer.cs_assert {
            self.hw.set_cs(cs, true, polarity);
        }

        // Perform transfer in FIFO-sized chunks.
        let len = xfer.len;
        let mut offset = 0usize;
        while offset < len {
            let chunk = (len - offset).min(FIFO_DEPTH);

            // Write TX data (or zeros).
            let tx_written = if let Some(tx) = xfer.tx_buf.as_ref() {
                self.hw.fifo_write(&tx[offset..offset + chunk])
            } else {
                // Write zeros for RX-only transfer.
                let zeros = [0u8; FIFO_DEPTH];
                self.hw.fifo_write(&zeros[..chunk])
            };
            if tx_written == 0 {
                return Err(Error::IoError);
            }

            // Wait for TX to complete.
            let mut timeout = TX_TIMEOUT;
            while !self.hw.tx_empty() {
                if timeout == 0 {
                    return Err(Error::Busy);
                }
                timeout -= 1;
            }

            // Read RX data.
            if let Some(rx) = xfer.rx_buf.as_mut() {
                let mut rx_offset = offset;
                while rx_offset < offset + chunk {
                    if self.hw.rx_available() {
                        let n = self.hw.fifo_read(&mut rx[rx_offset..offset + chunk]);
                        rx_offset += n;
                    }
                }
            }

            offset += chunk;
        }

        if xfer.cs_deassert {
            self.hw.set_cs(cs, false, polarity);
        }

        Ok(())
    }

    /// Perform a write-only transfer (TX only, discard RX).
    pub fn write(&mut self, device_idx: usize, data: &[u8]) -> Result<()> {
        let mut xfer = SpiTransfer {
            tx_buf: Some(data),
            rx_buf: None,
            len: data.len(),
            cs_assert: true,
            cs_deassert: true,
            bits_per_word: 8,
        };
        self.sync_transfer(device_idx, &mut xfer)
    }

    /// Perform a read-only transfer (RX only, send zeros).
    pub fn read(&mut self, device_idx: usize, buf: &mut [u8]) -> Result<()> {
        let len = buf.len();
        let mut xfer = SpiTransfer {
            tx_buf: None,
            rx_buf: Some(buf),
            len,
            cs_assert: true,
            cs_deassert: true,
            bits_per_word: 8,
        };
        self.sync_transfer(device_idx, &mut xfer)
    }

    /// Perform a full-duplex transfer.
    pub fn transfer(&mut self, device_idx: usize, tx: &[u8], rx: &mut [u8]) -> Result<()> {
        if tx.len() != rx.len() {
            return Err(Error::InvalidArgument);
        }
        let len = tx.len();
        let mut xfer = SpiTransfer {
            tx_buf: Some(tx),
            rx_buf: Some(rx),
            len,
            cs_assert: true,
            cs_deassert: true,
            bits_per_word: 8,
        };
        self.sync_transfer(device_idx, &mut xfer)
    }

    /// Write then read without de-asserting CS in between.
    pub fn write_then_read(
        &mut self,
        device_idx: usize,
        write_data: &[u8],
        read_buf: &mut [u8],
    ) -> Result<()> {
        let dev = self
            .devices
            .get(device_idx)
            .and_then(|d| d.as_ref())
            .ok_or(Error::NotFound)?;
        let cs = dev.chip_select;
        let polarity = dev.cs_polarity;

        // Write phase.
        let mut write_xfer = SpiTransfer {
            tx_buf: Some(write_data),
            rx_buf: None,
            len: write_data.len(),
            cs_assert: true,
            cs_deassert: false,
            bits_per_word: 8,
        };
        self.sync_transfer(device_idx, &mut write_xfer)?;

        // Read phase — CS stays asserted.
        let read_len = read_buf.len();
        let mut read_xfer = SpiTransfer {
            tx_buf: None,
            rx_buf: Some(read_buf),
            len: read_len,
            cs_assert: false,
            cs_deassert: true,
            bits_per_word: 8,
        };
        let _ = (cs, polarity); // used above via sync_transfer
        self.sync_transfer(device_idx, &mut read_xfer)
    }

    /// Number of registered devices.
    pub fn device_count(&self) -> usize {
        self.device_count
    }

    /// Borrow the underlying hardware controller.
    pub fn hw(&mut self) -> &mut HW {
        &mut self.hw
    }
}
