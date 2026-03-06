// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! SPI bus controller abstraction for the ONCRIX hardware abstraction layer.
//!
//! Provides a comprehensive SPI master controller subsystem with support for
//! chip-select management, full-duplex transfers, clock polarity/phase
//! configuration (SPI modes 0-3), configurable word size, and MMIO-based
//! register access.
//!
//! # Architecture
//!
//! - **SpiMode** — clock polarity and phase configuration (modes 0-3)
//! - **SpiBitOrder** — MSB-first or LSB-first bit ordering
//! - **SpiChipSelect** — chip-select line identifier
//! - **SpiTransfer** — a single full-duplex transfer descriptor
//! - **SpiDeviceConfig** — per-device configuration (speed, mode, CS, word size)
//! - **SpiBusConfig** — MMIO layout and controller parameters
//! - **SpiBusState** — runtime state of the controller
//! - **SpiBus** — a single SPI master controller
//! - **SpiBusRegistry** — manages up to [`MAX_SPI_BUSES`] controllers
//!
//! # MMIO Access
//!
//! All register access uses volatile reads/writes via `read_mmio32` /
//! `write_mmio32` helpers.
//!
//! # Reference
//!
//! Linux: `drivers/spi/`, `include/linux/spi/spi.h`

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum number of SPI bus controllers in the registry.
const MAX_SPI_BUSES: usize = 8;

/// Maximum number of chip-select lines per bus.
const MAX_CHIP_SELECTS: usize = 8;

/// Maximum transfer buffer size in bytes (inline).
const MAX_TRANSFER_BUF: usize = 64;

/// Maximum number of transfers in a single transaction.
const MAX_TRANSFERS: usize = 16;

/// Maximum number of registered SPI devices per bus.
const MAX_DEVICES_PER_BUS: usize = 8;

/// Default SPI clock speed: 1 MHz.
const DEFAULT_SPEED_HZ: u32 = 1_000_000;

/// Maximum SPI clock speed: 50 MHz.
const MAX_SPEED_HZ: u32 = 50_000_000;

// ---------------------------------------------------------------------------
// MMIO register offsets (generic SPI controller, DesignWare SSI style)
// ---------------------------------------------------------------------------

/// Control register 0 offset.
const SPI_CTRLR0_OFF: usize = 0x00;

/// Control register 1 offset (receive-only frame count).
const SPI_CTRLR1_OFF: usize = 0x04;

/// SSI enable register offset.
const SPI_SSIENR_OFF: usize = 0x08;

/// Slave enable register offset (chip-select mask).
const SPI_SER_OFF: usize = 0x10;

/// Baud rate divisor register offset.
const SPI_BAUDR_OFF: usize = 0x14;

/// TX FIFO threshold register offset.
const SPI_TXFTLR_OFF: usize = 0x18;

/// RX FIFO threshold register offset.
const SPI_RXFTLR_OFF: usize = 0x1C;

/// TX FIFO level register offset.
const SPI_TXFLR_OFF: usize = 0x20;

/// RX FIFO level register offset.
const SPI_RXFLR_OFF: usize = 0x24;

/// Status register offset.
const SPI_SR_OFF: usize = 0x28;

/// Interrupt mask register offset.
const SPI_IMR_OFF: usize = 0x2C;

/// Interrupt status register offset.
const SPI_ISR_OFF: usize = 0x30;

/// Raw interrupt status register offset.
const SPI_RISR_OFF: usize = 0x34;

/// Data register offset (TX/RX FIFO access).
const SPI_DR_OFF: usize = 0x60;

// ---------------------------------------------------------------------------
// Status register bits
// ---------------------------------------------------------------------------

/// SPI busy flag (bit 0).
const SPI_SR_BUSY: u32 = 1 << 0;

/// TX FIFO not full (bit 1).
const SPI_SR_TFNF: u32 = 1 << 1;

/// TX FIFO empty (bit 2).
const SPI_SR_TFE: u32 = 1 << 2;

/// RX FIFO not empty (bit 3).
const SPI_SR_RFNE: u32 = 1 << 3;

// ---------------------------------------------------------------------------
// SpiMode
// ---------------------------------------------------------------------------

/// SPI clock polarity (CPOL) and phase (CPHA) configuration.
///
/// The four standard SPI modes define when data is sampled and shifted
/// relative to the clock signal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SpiMode {
    /// Mode 0: CPOL=0, CPHA=0 (idle low, sample on leading edge).
    #[default]
    Mode0,
    /// Mode 1: CPOL=0, CPHA=1 (idle low, sample on trailing edge).
    Mode1,
    /// Mode 2: CPOL=1, CPHA=0 (idle high, sample on leading edge).
    Mode2,
    /// Mode 3: CPOL=1, CPHA=1 (idle high, sample on trailing edge).
    Mode3,
}

impl SpiMode {
    /// Returns the CPOL and CPHA bits for this mode.
    ///
    /// Returns `(cpol, cpha)` as `(u8, u8)`.
    pub fn bits(self) -> (u8, u8) {
        match self {
            SpiMode::Mode0 => (0, 0),
            SpiMode::Mode1 => (0, 1),
            SpiMode::Mode2 => (1, 0),
            SpiMode::Mode3 => (1, 1),
        }
    }

    /// Encodes the mode into control register bits (bits [7:6] = CPOL:CPHA).
    pub fn to_ctrl_bits(self) -> u32 {
        let (cpol, cpha) = self.bits();
        ((cpol as u32) << 7) | ((cpha as u32) << 6)
    }
}

// ---------------------------------------------------------------------------
// SpiBitOrder
// ---------------------------------------------------------------------------

/// SPI bit ordering within each word.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SpiBitOrder {
    /// Most significant bit transmitted first (standard).
    #[default]
    MsbFirst,
    /// Least significant bit transmitted first.
    LsbFirst,
}

// ---------------------------------------------------------------------------
// SpiChipSelect
// ---------------------------------------------------------------------------

/// Identifies a chip-select line on an SPI bus.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SpiChipSelect {
    /// Chip-select line number (0-based).
    pub line: u8,
    /// Whether the CS is active-low (standard) or active-high.
    pub active_low: bool,
}

impl SpiChipSelect {
    /// Creates a standard active-low chip-select.
    pub const fn active_low(line: u8) -> Self {
        Self {
            line,
            active_low: true,
        }
    }

    /// Creates an active-high chip-select.
    pub const fn active_high(line: u8) -> Self {
        Self {
            line,
            active_low: false,
        }
    }
}

// ---------------------------------------------------------------------------
// SpiTransfer
// ---------------------------------------------------------------------------

/// A single SPI full-duplex transfer descriptor.
///
/// Contains both transmit and receive buffers. In full-duplex mode,
/// data is simultaneously shifted out (TX) and shifted in (RX).
#[derive(Debug, Clone, Copy)]
pub struct SpiTransfer {
    /// Transmit buffer (data to send to the device).
    pub tx_buf: [u8; MAX_TRANSFER_BUF],
    /// Receive buffer (data received from the device).
    pub rx_buf: [u8; MAX_TRANSFER_BUF],
    /// Number of bytes in this transfer.
    pub len: usize,
    /// Speed override for this transfer (0 = use device default).
    pub speed_hz: u32,
    /// Delay in microseconds after this transfer completes.
    pub delay_us: u32,
    /// Word size in bits (8, 16, or 32).
    pub bits_per_word: u8,
    /// Whether to deassert CS after this transfer.
    pub cs_change: bool,
    /// Whether this is a TX-only transfer (discard RX data).
    pub tx_only: bool,
    /// Whether this is an RX-only transfer (send zeros on TX).
    pub rx_only: bool,
}

/// Constant empty transfer for array initialisation.
const EMPTY_TRANSFER: SpiTransfer = SpiTransfer {
    tx_buf: [0u8; MAX_TRANSFER_BUF],
    rx_buf: [0u8; MAX_TRANSFER_BUF],
    len: 0,
    speed_hz: 0,
    delay_us: 0,
    bits_per_word: 8,
    cs_change: false,
    tx_only: false,
    rx_only: false,
};

impl SpiTransfer {
    /// Creates a new full-duplex transfer with the given TX data.
    pub fn new(tx_data: &[u8]) -> Self {
        let copy_len = tx_data.len().min(MAX_TRANSFER_BUF);
        let mut tx_buf = [0u8; MAX_TRANSFER_BUF];
        tx_buf[..copy_len].copy_from_slice(&tx_data[..copy_len]);
        Self {
            tx_buf,
            len: copy_len,
            ..EMPTY_TRANSFER
        }
    }

    /// Creates a TX-only transfer.
    pub fn tx_only(tx_data: &[u8]) -> Self {
        let mut xfer = Self::new(tx_data);
        xfer.tx_only = true;
        xfer
    }

    /// Creates an RX-only transfer of the specified length.
    pub fn rx_only(len: usize) -> Self {
        let clamped = len.min(MAX_TRANSFER_BUF);
        Self {
            len: clamped,
            rx_only: true,
            ..EMPTY_TRANSFER
        }
    }
}

// ---------------------------------------------------------------------------
// SpiDeviceConfig
// ---------------------------------------------------------------------------

/// Per-device SPI configuration.
///
/// Each device on the bus may have its own speed, mode, word size, and
/// chip-select configuration.
#[derive(Debug, Clone, Copy)]
pub struct SpiDeviceConfig {
    /// Device identifier.
    pub id: u32,
    /// Human-readable label (UTF-8).
    pub label: [u8; 32],
    /// Number of valid bytes in [`label`](Self::label).
    pub label_len: usize,
    /// Chip-select line for this device.
    pub cs: SpiChipSelect,
    /// Maximum clock speed in Hz.
    pub max_speed_hz: u32,
    /// SPI mode (CPOL/CPHA).
    pub mode: SpiMode,
    /// Bit ordering.
    pub bit_order: SpiBitOrder,
    /// Bits per word (8, 16, or 32).
    pub bits_per_word: u8,
    /// Whether the device is currently selected (CS asserted).
    pub selected: bool,
}

/// Constant empty device config for array initialisation.
const EMPTY_DEV_CFG: SpiDeviceConfig = SpiDeviceConfig {
    id: 0,
    label: [0u8; 32],
    label_len: 0,
    cs: SpiChipSelect {
        line: 0,
        active_low: true,
    },
    max_speed_hz: DEFAULT_SPEED_HZ,
    mode: SpiMode::Mode0,
    bit_order: SpiBitOrder::MsbFirst,
    bits_per_word: 8,
    selected: false,
};

impl SpiDeviceConfig {
    /// Creates a new device configuration.
    pub fn new(id: u32, label: &[u8], cs: SpiChipSelect) -> Self {
        let copy_len = label.len().min(32);
        let mut buf = [0u8; 32];
        buf[..copy_len].copy_from_slice(&label[..copy_len]);
        Self {
            id,
            label: buf,
            label_len: copy_len,
            cs,
            ..EMPTY_DEV_CFG
        }
    }

    /// Sets the maximum speed and returns self (builder pattern).
    pub fn with_speed(mut self, speed_hz: u32) -> Self {
        self.max_speed_hz = speed_hz.min(MAX_SPEED_HZ);
        self
    }

    /// Sets the SPI mode and returns self (builder pattern).
    pub fn with_mode(mut self, mode: SpiMode) -> Self {
        self.mode = mode;
        self
    }
}

// ---------------------------------------------------------------------------
// SpiBusState
// ---------------------------------------------------------------------------

/// Runtime state of the SPI bus controller.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SpiBusState {
    /// Controller is uninitialised.
    #[default]
    Uninitialised,
    /// Controller is idle and ready for transfers.
    Idle,
    /// A transfer is currently in progress.
    Busy,
    /// Controller is in an error state.
    Error,
}

// ---------------------------------------------------------------------------
// SpiBusConfig
// ---------------------------------------------------------------------------

/// Hardware configuration for an SPI bus controller.
#[derive(Debug, Clone, Copy)]
pub struct SpiBusConfig {
    /// MMIO base address of the SPI controller registers.
    pub mmio_base: usize,
    /// MMIO region size in bytes.
    pub mmio_size: usize,
    /// Input clock frequency to the controller (Hz).
    pub input_clk_hz: u32,
    /// Number of available chip-select lines.
    pub num_cs: u8,
    /// TX FIFO depth (entries).
    pub tx_fifo_depth: u8,
    /// RX FIFO depth (entries).
    pub rx_fifo_depth: u8,
    /// Maximum supported speed (Hz).
    pub max_speed_hz: u32,
}

impl Default for SpiBusConfig {
    fn default() -> Self {
        Self {
            mmio_base: 0,
            mmio_size: 0x100,
            input_clk_hz: 100_000_000,
            num_cs: 4,
            tx_fifo_depth: 32,
            rx_fifo_depth: 32,
            max_speed_hz: MAX_SPEED_HZ,
        }
    }
}

// ---------------------------------------------------------------------------
// MMIO helpers
// ---------------------------------------------------------------------------

/// Reads a 32-bit value from MMIO at `base + offset`.
///
/// # Safety
///
/// The caller must ensure `base + offset` is a valid MMIO address, properly
/// mapped, and that volatile reads are safe for this hardware register.
#[inline]
unsafe fn read_mmio32(base: usize, offset: usize) -> u32 {
    // SAFETY: caller guarantees the address is valid mapped MMIO.
    unsafe { core::ptr::read_volatile((base + offset) as *const u32) }
}

/// Writes a 32-bit value to MMIO at `base + offset`.
///
/// # Safety
///
/// The caller must ensure `base + offset` is a valid MMIO address, properly
/// mapped, and that volatile writes are safe for this hardware register.
#[inline]
unsafe fn write_mmio32(base: usize, offset: usize, val: u32) {
    // SAFETY: caller guarantees the address is valid mapped MMIO.
    unsafe { core::ptr::write_volatile((base + offset) as *mut u32, val) }
}

// ---------------------------------------------------------------------------
// SpiBus
// ---------------------------------------------------------------------------

/// A single SPI master bus controller.
///
/// Wraps the hardware configuration and provides safe methods for
/// initialisation, chip-select management, and full-duplex transfers.
pub struct SpiBus {
    /// Unique bus identifier.
    pub id: u32,
    /// Human-readable label (UTF-8).
    pub label: [u8; 32],
    /// Number of valid bytes in [`label`](Self::label).
    pub label_len: usize,
    /// Hardware configuration.
    pub config: SpiBusConfig,
    /// Current bus state.
    pub state: SpiBusState,
    /// Registered devices on this bus.
    devices: [SpiDeviceConfig; MAX_DEVICES_PER_BUS],
    /// Number of registered devices.
    device_count: usize,
    /// Currently selected chip-select line (or None).
    active_cs: Option<u8>,
    /// Current baud rate divisor.
    baud_div: u16,
    /// Total bytes transferred (statistics).
    pub bytes_transferred: u64,
    /// Total number of completed transfers.
    pub transfer_count: u64,
    /// Total number of errors.
    pub error_count: u64,
    /// Whether the controller is registered and active.
    pub active: bool,
}

impl SpiBus {
    /// Creates a new SPI bus controller.
    pub fn new(id: u32, label: &[u8], config: SpiBusConfig) -> Self {
        let copy_len = label.len().min(32);
        let mut buf = [0u8; 32];
        buf[..copy_len].copy_from_slice(&label[..copy_len]);
        Self {
            id,
            label: buf,
            label_len: copy_len,
            config,
            state: SpiBusState::Uninitialised,
            devices: [EMPTY_DEV_CFG; MAX_DEVICES_PER_BUS],
            device_count: 0,
            active_cs: None,
            baud_div: 0,
            bytes_transferred: 0,
            transfer_count: 0,
            error_count: 0,
            active: false,
        }
    }

    /// Initialises the SPI controller hardware.
    ///
    /// Disables the controller, configures registers, and re-enables.
    ///
    /// # Errors
    ///
    /// Returns [`Error::IoError`] if the MMIO base is zero (unmapped).
    pub fn init(&mut self) -> Result<()> {
        if self.config.mmio_base == 0 {
            return Err(Error::IoError);
        }

        // Disable SSI.
        // SAFETY: mmio_base checked non-zero; SPI MMIO is a valid region.
        unsafe {
            write_mmio32(self.config.mmio_base, SPI_SSIENR_OFF, 0);
        }

        // Configure CTRLR0: frame size = 8 bits, SPI mode 0.
        let ctrl0 = (7u32 << 0)  // DFS = 8 bits (DFS field = n-1)
            | SpiMode::Mode0.to_ctrl_bits();
        // SAFETY: mmio_base valid; CTRLR0 is 32-bit RW.
        unsafe {
            write_mmio32(self.config.mmio_base, SPI_CTRLR0_OFF, ctrl0);
        }

        // Set default baud rate (input_clk / (2 * DEFAULT_SPEED)).
        self.set_speed(DEFAULT_SPEED_HZ)?;

        // Mask all interrupts.
        // SAFETY: mmio_base valid; IMR is 32-bit RW.
        unsafe {
            write_mmio32(self.config.mmio_base, SPI_IMR_OFF, 0);
        }

        // Set FIFO thresholds.
        // SAFETY: mmio_base valid; TXFTLR/RXFTLR are 32-bit RW.
        unsafe {
            write_mmio32(self.config.mmio_base, SPI_TXFTLR_OFF, 0);
            write_mmio32(
                self.config.mmio_base,
                SPI_RXFTLR_OFF,
                (self.config.rx_fifo_depth / 2) as u32,
            );
        }

        // Enable SSI.
        // SAFETY: mmio_base valid; SSIENR is 32-bit RW.
        unsafe {
            write_mmio32(self.config.mmio_base, SPI_SSIENR_OFF, 1);
        }

        self.state = SpiBusState::Idle;
        self.active = true;
        Ok(())
    }

    /// Sets the SPI clock speed.
    ///
    /// The baud rate divisor is computed as `input_clk / speed` rounded
    /// up to the nearest even number (hardware requirement).
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `speed_hz` is zero or exceeds
    /// the controller maximum.
    pub fn set_speed(&mut self, speed_hz: u32) -> Result<()> {
        if speed_hz == 0 || speed_hz > self.config.max_speed_hz {
            return Err(Error::InvalidArgument);
        }
        let div = self.config.input_clk_hz / speed_hz;
        // Round up to nearest even number.
        let div = ((div + 1) & !1).max(2);
        self.baud_div = div.min(u16::MAX as u32) as u16;

        if self.config.mmio_base != 0 {
            // Disable SSI to change baud rate.
            // SAFETY: mmio_base valid; SSIENR and BAUDR are 32-bit RW.
            unsafe {
                write_mmio32(self.config.mmio_base, SPI_SSIENR_OFF, 0);
                write_mmio32(self.config.mmio_base, SPI_BAUDR_OFF, self.baud_div as u32);
                write_mmio32(self.config.mmio_base, SPI_SSIENR_OFF, 1);
            }
        }
        Ok(())
    }

    /// Selects a chip-select line (asserts CS).
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `cs_line` exceeds the number
    /// of available chip-selects, or [`Error::Busy`] if another CS is
    /// already active.
    pub fn select_chip(&mut self, cs_line: u8) -> Result<()> {
        if cs_line >= self.config.num_cs {
            return Err(Error::InvalidArgument);
        }
        if self.active_cs.is_some() {
            return Err(Error::Busy);
        }
        self.check_ready()?;

        // Write the chip-select enable register.
        // SAFETY: mmio_base valid; SER is 32-bit RW.
        if self.config.mmio_base != 0 {
            unsafe {
                write_mmio32(self.config.mmio_base, SPI_SER_OFF, 1u32 << cs_line);
            }
        }
        self.active_cs = Some(cs_line);
        Ok(())
    }

    /// Deselects the currently active chip-select line (deasserts CS).
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if no CS is currently active.
    pub fn deselect_chip(&mut self) -> Result<()> {
        if self.active_cs.is_none() {
            return Err(Error::InvalidArgument);
        }

        // Clear all chip-select enables.
        // SAFETY: mmio_base valid; SER is 32-bit RW.
        if self.config.mmio_base != 0 {
            unsafe {
                write_mmio32(self.config.mmio_base, SPI_SER_OFF, 0);
            }
        }
        self.active_cs = None;
        Ok(())
    }

    /// Registers a device on this SPI bus.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the device table is full, or
    /// [`Error::AlreadyExists`] if a device with the same id exists.
    pub fn register_device(&mut self, dev: SpiDeviceConfig) -> Result<()> {
        for d in &self.devices[..self.device_count] {
            if d.id == dev.id {
                return Err(Error::AlreadyExists);
            }
        }
        if self.device_count >= MAX_DEVICES_PER_BUS {
            return Err(Error::OutOfMemory);
        }
        self.devices[self.device_count] = dev;
        self.device_count += 1;
        Ok(())
    }

    /// Performs a full-duplex transfer.
    ///
    /// Simultaneously transmits `xfer.tx_buf` and receives into `xfer.rx_buf`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::IoError`] on hardware failure, [`Error::Busy`] if
    /// the bus is occupied, or [`Error::InvalidArgument`] if the transfer
    /// length is zero or exceeds the buffer size.
    pub fn transfer(&mut self, xfer: &mut SpiTransfer) -> Result<()> {
        if xfer.len == 0 || xfer.len > MAX_TRANSFER_BUF {
            return Err(Error::InvalidArgument);
        }
        self.check_ready()?;
        self.state = SpiBusState::Busy;

        // Apply speed override if specified.
        if xfer.speed_hz > 0 {
            self.set_speed(xfer.speed_hz)?;
        }

        // Configure word size if different from default.
        if xfer.bits_per_word != 8 && self.config.mmio_base != 0 {
            let dfs = (xfer.bits_per_word as u32).saturating_sub(1);
            // SAFETY: mmio_base valid; SSIENR and CTRLR0 are 32-bit RW.
            unsafe {
                write_mmio32(self.config.mmio_base, SPI_SSIENR_OFF, 0);
                let ctrl = read_mmio32(self.config.mmio_base, SPI_CTRLR0_OFF);
                let new_ctrl = (ctrl & !0x0F) | (dfs & 0x0F);
                write_mmio32(self.config.mmio_base, SPI_CTRLR0_OFF, new_ctrl);
                write_mmio32(self.config.mmio_base, SPI_SSIENR_OFF, 1);
            }
        }

        if self.config.mmio_base != 0 {
            // Push TX data into the FIFO.
            for i in 0..xfer.len {
                self.wait_tx_space()?;
                let tx_byte = if xfer.rx_only {
                    0u32
                } else {
                    xfer.tx_buf[i] as u32
                };
                // SAFETY: mmio_base valid; DR is 32-bit RW (FIFO access).
                unsafe {
                    write_mmio32(self.config.mmio_base, SPI_DR_OFF, tx_byte);
                }
            }

            // Read RX data from the FIFO.
            for i in 0..xfer.len {
                self.wait_rx_ready()?;
                // SAFETY: mmio_base valid; DR returns received data.
                let rx_val = unsafe { read_mmio32(self.config.mmio_base, SPI_DR_OFF) };
                if !xfer.tx_only {
                    xfer.rx_buf[i] = (rx_val & 0xFF) as u8;
                }
            }
        }

        self.wait_not_busy()?;

        self.bytes_transferred += xfer.len as u64;
        self.transfer_count += 1;
        self.state = SpiBusState::Idle;
        Ok(())
    }

    /// Performs a batch of transfers as a single transaction.
    ///
    /// The chip-select remains asserted across all transfers unless
    /// `cs_change` is set on a transfer.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `xfers` is empty or exceeds
    /// [`MAX_TRANSFERS`].
    pub fn transfer_batch(&mut self, cs_line: u8, xfers: &mut [SpiTransfer]) -> Result<usize> {
        if xfers.is_empty() || xfers.len() > MAX_TRANSFERS {
            return Err(Error::InvalidArgument);
        }

        self.select_chip(cs_line)?;

        let mut total_bytes: usize = 0;
        let xfer_count = xfers.len();

        for (idx, xfer) in xfers.iter_mut().enumerate() {
            self.state = SpiBusState::Idle; // Reset for each sub-transfer
            self.transfer(xfer)?;
            total_bytes += xfer.len;

            // Handle CS changes between transfers.
            if xfer.cs_change && idx < xfer_count - 1 {
                self.deselect_chip()?;
                self.select_chip(cs_line)?;
            }
        }

        self.deselect_chip()?;
        Ok(total_bytes)
    }

    /// Returns the current interrupt status.
    pub fn interrupt_status(&self) -> u32 {
        if self.config.mmio_base == 0 {
            return 0;
        }
        // SAFETY: mmio_base checked; ISR is 32-bit RO.
        unsafe { read_mmio32(self.config.mmio_base, SPI_ISR_OFF) }
    }

    /// Acknowledges interrupts by reading the raw interrupt status.
    pub fn acknowledge_interrupts(&self) -> u32 {
        if self.config.mmio_base == 0 {
            return 0;
        }
        // SAFETY: mmio_base valid; RISR is 32-bit RO/clear-on-read.
        unsafe { read_mmio32(self.config.mmio_base, SPI_RISR_OFF) }
    }

    /// Resets the SPI controller.
    ///
    /// # Errors
    ///
    /// Returns [`Error::IoError`] if the MMIO base is unmapped.
    pub fn reset(&mut self) -> Result<()> {
        if self.config.mmio_base == 0 {
            return Err(Error::IoError);
        }

        // SAFETY: mmio_base valid; SSIENR is 32-bit RW.
        unsafe {
            write_mmio32(self.config.mmio_base, SPI_SSIENR_OFF, 0);
        }

        self.active_cs = None;
        self.state = SpiBusState::Uninitialised;
        self.init()
    }

    /// Returns the number of registered devices.
    pub fn device_count(&self) -> usize {
        self.device_count
    }

    /// Returns a reference to a registered device by index.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `index` is out of range.
    pub fn get_device(&self, index: usize) -> Result<&SpiDeviceConfig> {
        if index >= self.device_count {
            return Err(Error::InvalidArgument);
        }
        Ok(&self.devices[index])
    }

    /// Checks that the bus is ready for a transfer.
    fn check_ready(&self) -> Result<()> {
        match self.state {
            SpiBusState::Idle => Ok(()),
            SpiBusState::Busy => Err(Error::Busy),
            SpiBusState::Error => Err(Error::IoError),
            SpiBusState::Uninitialised => Err(Error::InvalidArgument),
        }
    }

    /// Waits for space in the TX FIFO.
    fn wait_tx_space(&self) -> Result<()> {
        let mut retries: u32 = 100_000;
        while retries > 0 {
            // SAFETY: mmio_base valid; SR is 32-bit RO.
            let sr = unsafe { read_mmio32(self.config.mmio_base, SPI_SR_OFF) };
            if sr & SPI_SR_TFNF != 0 {
                return Ok(());
            }
            retries -= 1;
            core::hint::spin_loop();
        }
        Err(Error::Busy)
    }

    /// Waits for data in the RX FIFO.
    fn wait_rx_ready(&self) -> Result<()> {
        let mut retries: u32 = 100_000;
        while retries > 0 {
            // SAFETY: mmio_base valid; SR is 32-bit RO.
            let sr = unsafe { read_mmio32(self.config.mmio_base, SPI_SR_OFF) };
            if sr & SPI_SR_RFNE != 0 {
                return Ok(());
            }
            retries -= 1;
            core::hint::spin_loop();
        }
        Err(Error::Busy)
    }

    /// Waits for the SPI controller to finish all activity.
    fn wait_not_busy(&self) -> Result<()> {
        let mut retries: u32 = 100_000;
        while retries > 0 {
            // SAFETY: mmio_base valid; SR is 32-bit RO.
            let sr = unsafe { read_mmio32(self.config.mmio_base, SPI_SR_OFF) };
            if sr & SPI_SR_BUSY == 0 {
                return Ok(());
            }
            retries -= 1;
            core::hint::spin_loop();
        }
        Err(Error::Busy)
    }
}

// ---------------------------------------------------------------------------
// SpiBusRegistry
// ---------------------------------------------------------------------------

/// Registry managing up to [`MAX_SPI_BUSES`] SPI bus controllers.
pub struct SpiBusRegistry {
    /// Registered SPI buses.
    buses: [Option<SpiBus>; MAX_SPI_BUSES],
    /// Number of registered buses.
    count: usize,
}

impl Default for SpiBusRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl SpiBusRegistry {
    /// Creates a new, empty SPI bus registry.
    pub const fn new() -> Self {
        Self {
            buses: [const { None }; MAX_SPI_BUSES],
            count: 0,
        }
    }

    /// Registers an SPI bus controller.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the registry is full, or
    /// [`Error::AlreadyExists`] if a bus with the same `id` exists.
    pub fn register(&mut self, bus: SpiBus) -> Result<()> {
        for slot in self.buses.iter().flatten() {
            if slot.id == bus.id {
                return Err(Error::AlreadyExists);
            }
        }
        for slot in self.buses.iter_mut() {
            if slot.is_none() {
                *slot = Some(bus);
                self.count += 1;
                return Ok(());
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Unregisters an SPI bus by `id`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if no bus with that id exists,
    /// or [`Error::Busy`] if the bus is currently transferring.
    pub fn unregister(&mut self, id: u32) -> Result<()> {
        for slot in self.buses.iter_mut() {
            let busy = slot
                .as_ref()
                .is_some_and(|b| b.id == id && b.state == SpiBusState::Busy);
            if busy {
                return Err(Error::Busy);
            }
            let matches = slot.as_ref().is_some_and(|b| b.id == id);
            if matches {
                *slot = None;
                self.count -= 1;
                return Ok(());
            }
        }
        Err(Error::NotFound)
    }

    /// Returns a reference to a bus by its `id`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if not registered.
    pub fn get(&self, id: u32) -> Result<&SpiBus> {
        self.buses
            .iter()
            .flatten()
            .find(|b| b.id == id)
            .ok_or(Error::NotFound)
    }

    /// Returns a mutable reference to a bus by its `id`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if not registered.
    pub fn get_mut(&mut self, id: u32) -> Result<&mut SpiBus> {
        self.buses
            .iter_mut()
            .flatten()
            .find(|b| b.id == id)
            .ok_or(Error::NotFound)
    }

    /// Returns the number of registered buses.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Returns `true` if no buses are registered.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
}
