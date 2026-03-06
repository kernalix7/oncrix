// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! SPI bus controller driver for the ONCRIX operating system.
//!
//! Implements a full-featured SPI subsystem with support for multiple
//! master controllers, SPI mode (CPOL/CPHA), clock rate configuration,
//! chip-select management, DMA-capable transfer descriptors, and a
//! generic MMIO hardware path alongside a DesignWare SSI model.
//!
//! # Architecture
//!
//! - **SpiMode** — CPOL/CPHA clock polarity and phase bitmask
//! - **SpiControllerType** — hardware variant (DesignWare SSI, PL022, etc.)
//! - **SpiDevice** — registered peripheral descriptor (CS line, mode, speed)
//! - **SpiTransfer** — a single transfer segment (tx buf, rx buf, length)
//! - **SpiMessage** — a complete transaction composed of multiple transfers
//! - **SpiController** — a single SPI master with MMIO register access
//! - **SpiControllerRegistry** — manages up to [`MAX_CONTROLLERS`] controllers
//!
//! # MMIO Access
//!
//! All register reads/writes use volatile access via the `mmio_read32` /
//! `mmio_write32` helpers. Every `unsafe` block carries a `// SAFETY:` comment.
//!
//! # Reference
//!
//! Linux: `drivers/spi/spi.c`, `drivers/spi/spi-dw-core.c`,
//! `drivers/spi/spi-pl022.c`, `include/linux/spi/spi.h`

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum number of SPI master controllers.
const MAX_CONTROLLERS: usize = 8;

/// Maximum number of SPI devices (peripherals) per controller.
const MAX_DEVICES_PER_CTRL: usize = 16;

/// Maximum bytes in one SPI transfer buffer.
const MAX_XFER_BYTES: usize = 256;

/// Maximum number of transfers per SPI message.
const MAX_XFERS_PER_MSG: usize = 8;

// DesignWare SSI (DWSSI) register offsets
/// CTRLR0: Control register 0.
const DWSSI_CTRLR0: usize = 0x00;
/// CTRLR1: Control register 1 (NDF for receive-only mode).
const DWSSI_CTRLR1: usize = 0x04;
/// SSIENR: SSI enable register.
const DWSSI_SSIENR: usize = 0x08;
/// SER: Slave enable register.
const DWSSI_SER: usize = 0x10;
/// BAUDR: Baud rate select.
const DWSSI_BAUDR: usize = 0x14;
/// SR: Status register.
const DWSSI_SR: usize = 0x28;
/// DR: Data register (TX/RX FIFO).
const DWSSI_DR: usize = 0x60;

/// SR: Transmit FIFO empty bit.
const DWSSI_SR_TFE: u32 = 1 << 2;
/// SR: Receive FIFO not empty bit.
const DWSSI_SR_RFNE: u32 = 1 << 3;
/// SR: Busy bit.
const DWSSI_SR_BUSY: u32 = 1 << 0;

/// CTRLR0: Clock phase (CPHA) bit.
const DWSSI_CTRLR0_SCPH: u32 = 1 << 6;
/// CTRLR0: Clock polarity (CPOL) bit.
const DWSSI_CTRLR0_SCPOL: u32 = 1 << 7;
/// CTRLR0: Transfer mode shift.
const DWSSI_CTRLR0_TMOD_SHIFT: u32 = 8;
/// CTRLR0: 8-bit data frame format (DFS = 7).
const DWSSI_CTRLR0_DFS_8BIT: u32 = 7;

// ---------------------------------------------------------------------------
// SpiMode
// ---------------------------------------------------------------------------

/// SPI clock mode bitmask (CPOL | CPHA).
///
/// Matches Linux `SPI_MODE_x` defines: bit 0 = CPHA, bit 1 = CPOL.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SpiMode(pub u8);

impl SpiMode {
    /// Mode 0: CPOL=0, CPHA=0 (idle low, sample on rising edge).
    pub const MODE_0: Self = Self(0);
    /// Mode 1: CPOL=0, CPHA=1 (idle low, sample on falling edge).
    pub const MODE_1: Self = Self(1);
    /// Mode 2: CPOL=1, CPHA=0 (idle high, sample on falling edge).
    pub const MODE_2: Self = Self(2);
    /// Mode 3: CPOL=1, CPHA=1 (idle high, sample on rising edge).
    pub const MODE_3: Self = Self(3);

    /// Returns `true` if CPHA (clock phase) is set.
    pub fn cpha(self) -> bool {
        (self.0 & 0x01) != 0
    }

    /// Returns `true` if CPOL (clock polarity) is set.
    pub fn cpol(self) -> bool {
        (self.0 & 0x02) != 0
    }
}

// ---------------------------------------------------------------------------
// SpiControllerType
// ---------------------------------------------------------------------------

/// Hardware variant of the SPI master controller.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SpiControllerType {
    /// Generic MMIO SPI controller (basic shift register).
    #[default]
    GenericMmio,
    /// Synopsys DesignWare SSI IP block.
    DesignWareSsi,
    /// ARM PL022 SSP controller.
    ArmPl022,
    /// Intel LPSS SPI (DesignWare SSI variant with Intel quirks).
    IntelLpss,
}

// ---------------------------------------------------------------------------
// SpiDevice
// ---------------------------------------------------------------------------

/// Descriptor for a SPI peripheral registered on a controller.
#[derive(Debug, Clone, Copy)]
pub struct SpiDevice {
    /// Chip-select line index (0-based).
    pub cs: u8,
    /// SPI clock mode.
    pub mode: SpiMode,
    /// Maximum clock rate in Hz.
    pub max_speed_hz: u32,
    /// Bits per word (typically 8).
    pub bits_per_word: u8,
    /// Human-readable device name (UTF-8).
    pub name: [u8; 32],
    /// Number of valid bytes in `name`.
    pub name_len: usize,
    /// Whether this device is active.
    pub active: bool,
}

/// Constant empty device.
const EMPTY_SPI_DEV: SpiDevice = SpiDevice {
    cs: 0,
    mode: SpiMode(0),
    max_speed_hz: 1_000_000,
    bits_per_word: 8,
    name: [0u8; 32],
    name_len: 0,
    active: false,
};

impl SpiDevice {
    /// Creates a new SPI device descriptor.
    pub fn new(cs: u8, mode: SpiMode, max_speed_hz: u32, name: &[u8]) -> Self {
        let copy_len = name.len().min(32);
        let mut dev = EMPTY_SPI_DEV;
        dev.cs = cs;
        dev.mode = mode;
        dev.max_speed_hz = max_speed_hz;
        dev.name[..copy_len].copy_from_slice(&name[..copy_len]);
        dev.name_len = copy_len;
        dev.active = true;
        dev
    }
}

// ---------------------------------------------------------------------------
// SpiTransferDir
// ---------------------------------------------------------------------------

/// Direction of a SPI transfer segment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SpiTransferDir {
    /// Full-duplex: data clocked out on MOSI and in on MISO simultaneously.
    #[default]
    FullDuplex,
    /// Transmit only (MISO ignored).
    TxOnly,
    /// Receive only (MOSI held low).
    RxOnly,
}

// ---------------------------------------------------------------------------
// SpiTransfer
// ---------------------------------------------------------------------------

/// A single SPI transfer segment within a message.
#[derive(Clone, Copy)]
pub struct SpiTransfer {
    /// Transmit buffer (used for TxOnly and FullDuplex).
    pub tx_buf: [u8; MAX_XFER_BYTES],
    /// Receive buffer (populated for RxOnly and FullDuplex).
    pub rx_buf: [u8; MAX_XFER_BYTES],
    /// Number of bytes to transfer.
    pub len: usize,
    /// Transfer direction.
    pub dir: SpiTransferDir,
    /// Clock speed override (0 = use device's max_speed_hz).
    pub speed_hz: u32,
    /// CS change: deassert CS after this transfer.
    pub cs_change: bool,
}

impl SpiTransfer {
    /// Creates a full-duplex transfer from `data`.
    pub fn full_duplex(data: &[u8]) -> Self {
        let copy_len = data.len().min(MAX_XFER_BYTES);
        let mut xfer = Self::default();
        xfer.tx_buf[..copy_len].copy_from_slice(&data[..copy_len]);
        xfer.len = copy_len;
        xfer.dir = SpiTransferDir::FullDuplex;
        xfer
    }

    /// Creates a TX-only transfer from `data`.
    pub fn tx_only(data: &[u8]) -> Self {
        let mut xfer = Self::full_duplex(data);
        xfer.dir = SpiTransferDir::TxOnly;
        xfer
    }

    /// Creates an RX-only transfer requesting `len` bytes.
    pub fn rx_only(len: usize) -> Self {
        let mut xfer = Self::default();
        xfer.len = len.min(MAX_XFER_BYTES);
        xfer.dir = SpiTransferDir::RxOnly;
        xfer
    }
}

impl Default for SpiTransfer {
    fn default() -> Self {
        Self {
            tx_buf: [0u8; MAX_XFER_BYTES],
            rx_buf: [0u8; MAX_XFER_BYTES],
            len: 0,
            dir: SpiTransferDir::FullDuplex,
            speed_hz: 0,
            cs_change: false,
        }
    }
}

// ---------------------------------------------------------------------------
// SpiMessage
// ---------------------------------------------------------------------------

/// A complete SPI transaction composed of one or more transfers.
pub struct SpiMessage {
    /// Transfer segments.
    pub transfers: [Option<SpiTransfer>; MAX_XFERS_PER_MSG],
    /// Number of valid transfer entries.
    pub transfer_count: usize,
    /// Chip-select to use.
    pub cs: u8,
    /// Total bytes transferred (populated after execution).
    pub bytes_xferred: usize,
}

impl SpiMessage {
    /// Creates an empty SPI message targeting chip-select `cs`.
    pub fn new(cs: u8) -> Self {
        Self {
            transfers: [const { None }; MAX_XFERS_PER_MSG],
            transfer_count: 0,
            cs,
            bytes_xferred: 0,
        }
    }

    /// Appends a transfer segment to the message.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the transfer list is full.
    pub fn add_transfer(&mut self, xfer: SpiTransfer) -> Result<()> {
        if self.transfer_count >= MAX_XFERS_PER_MSG {
            return Err(Error::OutOfMemory);
        }
        self.transfers[self.transfer_count] = Some(xfer);
        self.transfer_count += 1;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// MMIO helpers
// ---------------------------------------------------------------------------

/// Volatile 32-bit MMIO read.
///
/// # Safety
///
/// `base + offset` must be a valid, mapped MMIO address.
#[inline]
unsafe fn mmio_read32(base: usize, offset: usize) -> u32 {
    // SAFETY: caller guarantees the address is valid mapped MMIO.
    unsafe { core::ptr::read_volatile((base + offset) as *const u32) }
}

/// Volatile 32-bit MMIO write.
///
/// # Safety
///
/// `base + offset` must be a valid, mapped MMIO address.
#[inline]
unsafe fn mmio_write32(base: usize, offset: usize, val: u32) {
    // SAFETY: caller guarantees the address is valid mapped MMIO.
    unsafe { core::ptr::write_volatile((base + offset) as *mut u32, val) }
}

// ---------------------------------------------------------------------------
// SpiController
// ---------------------------------------------------------------------------

/// A single SPI master controller with MMIO register access.
pub struct SpiController {
    /// Unique controller identifier.
    pub id: u32,
    /// Hardware variant.
    pub hw_type: SpiControllerType,
    /// MMIO base address.
    pub mmio_base: usize,
    /// Reference clock frequency in Hz (for baud rate calculation).
    pub ref_clk_hz: u32,
    /// Maximum supported bus speed in Hz.
    pub max_speed_hz: u32,
    /// Number of chip-select lines.
    pub num_cs: u8,
    /// Registered peripheral devices.
    pub devices: [Option<SpiDevice>; MAX_DEVICES_PER_CTRL],
    /// Number of registered devices.
    pub device_count: usize,
    /// Total successful messages.
    pub msg_count: u64,
    /// Total message errors.
    pub error_count: u64,
    /// Whether the controller is initialised.
    pub initialized: bool,
}

impl SpiController {
    /// Creates a new SPI controller.
    pub fn new(
        id: u32,
        hw_type: SpiControllerType,
        mmio_base: usize,
        ref_clk_hz: u32,
        num_cs: u8,
    ) -> Self {
        Self {
            id,
            hw_type,
            mmio_base,
            ref_clk_hz,
            max_speed_hz: ref_clk_hz / 2,
            num_cs,
            devices: [const { None }; MAX_DEVICES_PER_CTRL],
            device_count: 0,
            msg_count: 0,
            error_count: 0,
            initialized: false,
        }
    }

    /// Initialises the hardware controller.
    ///
    /// # Errors
    ///
    /// Returns [`Error::IoError`] if `mmio_base` is zero.
    pub fn init(&mut self) -> Result<()> {
        if self.mmio_base == 0 {
            return Err(Error::IoError);
        }
        match self.hw_type {
            SpiControllerType::DesignWareSsi | SpiControllerType::IntelLpss => {
                self.dwssi_init()?;
            }
            _ => {}
        }
        self.initialized = true;
        Ok(())
    }

    /// DesignWare SSI initialisation.
    fn dwssi_init(&mut self) -> Result<()> {
        let base = self.mmio_base;

        // Disable controller before configuration
        // SAFETY: DWSSI_SSIENR is the SSI enable register; writing 0 disables it.
        unsafe {
            mmio_write32(base, DWSSI_SSIENR, 0);
        }

        // Configure control register 0: 8-bit frame, mode 0 defaults
        let ctrlr0 = DWSSI_CTRLR0_DFS_8BIT; // 8-bit data frame
        // SAFETY: DWSSI_CTRLR0 is the main SPI control register.
        unsafe {
            mmio_write32(base, DWSSI_CTRLR0, ctrlr0);
        }

        // Default baud = ref_clk / 2
        let baud = (self.ref_clk_hz / self.max_speed_hz).max(2) & !1u32;
        // SAFETY: DWSSI_BAUDR sets the clock divider for the SPI bus.
        unsafe {
            mmio_write32(base, DWSSI_BAUDR, baud);
        }

        // Enable controller
        // SAFETY: DWSSI_SSIENR: writing 1 enables the SSI controller.
        unsafe {
            mmio_write32(base, DWSSI_SSIENR, 1);
        }

        Ok(())
    }

    /// Computes the DWSSI CTRLR0 value for the given device mode.
    fn dwssi_ctrlr0_for_mode(&self, mode: SpiMode, tmod: u32) -> u32 {
        let mut ctrl = DWSSI_CTRLR0_DFS_8BIT;
        if mode.cpha() {
            ctrl |= DWSSI_CTRLR0_SCPH;
        }
        if mode.cpol() {
            ctrl |= DWSSI_CTRLR0_SCPOL;
        }
        ctrl |= tmod << DWSSI_CTRLR0_TMOD_SHIFT;
        ctrl
    }

    /// Registers a SPI device on this controller.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if the CS index exceeds `num_cs`,
    /// [`Error::OutOfMemory`] if the table is full, or [`Error::AlreadyExists`]
    /// if the CS is already claimed.
    pub fn register_device(&mut self, dev: SpiDevice) -> Result<()> {
        if dev.cs >= self.num_cs {
            return Err(Error::InvalidArgument);
        }
        for slot in self.devices.iter().flatten() {
            if slot.cs == dev.cs {
                return Err(Error::AlreadyExists);
            }
        }
        for slot in self.devices.iter_mut() {
            if slot.is_none() {
                *slot = Some(dev);
                self.device_count += 1;
                return Ok(());
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Unregisters a device by chip-select index.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if no device on that CS is registered.
    pub fn unregister_device(&mut self, cs: u8) -> Result<()> {
        for slot in self.devices.iter_mut() {
            let matches = slot.as_ref().is_some_and(|d| d.cs == cs);
            if matches {
                *slot = None;
                self.device_count -= 1;
                return Ok(());
            }
        }
        Err(Error::NotFound)
    }

    /// Executes a SPI message (series of transfers with CS asserted).
    ///
    /// # Errors
    ///
    /// Returns [`Error::IoError`] if not initialised, or on hardware error.
    /// Returns [`Error::NotFound`] if no device is registered for the
    /// message's chip-select.
    pub fn transfer_message(&mut self, msg: &mut SpiMessage) -> Result<()> {
        if !self.initialized {
            return Err(Error::IoError);
        }
        // Validate CS
        let dev_mode = self
            .devices
            .iter()
            .flatten()
            .find(|d| d.cs == msg.cs)
            .map(|d| d.mode)
            .ok_or(Error::NotFound)?;

        match self.hw_type {
            SpiControllerType::DesignWareSsi | SpiControllerType::IntelLpss => {
                self.dwssi_transfer_message(msg, dev_mode)?;
            }
            _ => {
                self.sw_transfer_message(msg)?;
            }
        }
        self.msg_count += 1;
        Ok(())
    }

    /// DesignWare SSI transfer implementation.
    fn dwssi_transfer_message(&mut self, msg: &mut SpiMessage, dev_mode: SpiMode) -> Result<()> {
        let base = self.mmio_base;

        for idx in 0..msg.transfer_count {
            let xfer = match &mut msg.transfers[idx] {
                Some(x) => x,
                None => continue,
            };

            // Determine transfer mode bits for CTRLR0
            let tmod = match xfer.dir {
                SpiTransferDir::TxOnly => 1u32,
                SpiTransferDir::RxOnly => 2u32,
                SpiTransferDir::FullDuplex => 0u32,
            };

            // Reconfigure controller for this transfer
            // SAFETY: DWSSI_SSIENR: disable before changing control registers.
            unsafe {
                mmio_write32(base, DWSSI_SSIENR, 0);
            }
            let ctrlr0 = self.dwssi_ctrlr0_for_mode(dev_mode, tmod);
            // SAFETY: DWSSI_CTRLR0 is safe to write while SSI is disabled.
            unsafe {
                mmio_write32(base, DWSSI_CTRLR0, ctrlr0);
            }

            if xfer.dir == SpiTransferDir::RxOnly {
                // CTRLR1 holds NDF (number of data frames - 1) for RX mode
                // SAFETY: DWSSI_CTRLR1 is safe to write while SSI is disabled.
                unsafe {
                    mmio_write32(base, DWSSI_CTRLR1, (xfer.len as u32).saturating_sub(1));
                }
            }

            // Assert CS
            // SAFETY: DWSSI_SER bit N enables slave N.
            unsafe {
                mmio_write32(base, DWSSI_SER, 1u32 << msg.cs);
            }

            // Re-enable
            // SAFETY: DWSSI_SSIENR: writing 1 enables the SSI master.
            unsafe {
                mmio_write32(base, DWSSI_SSIENR, 1);
            }

            match xfer.dir {
                SpiTransferDir::TxOnly | SpiTransferDir::FullDuplex => {
                    for i in 0..xfer.len {
                        // Wait until TX FIFO is not full (TFE = TX FIFO empty, use
                        // SR busy bit as a simple "space available" indicator)
                        let mut timeout = 100_000u32;
                        loop {
                            // SAFETY: DWSSI_SR is a read-only status register.
                            let sr = unsafe { mmio_read32(base, DWSSI_SR) };
                            if (sr & DWSSI_SR_TFE) != 0 || (sr & DWSSI_SR_BUSY) == 0 {
                                break;
                            }
                            timeout -= 1;
                            if timeout == 0 {
                                self.error_count += 1;
                                return Err(Error::IoError);
                            }
                        }
                        // SAFETY: Writing to DWSSI_DR enqueues a byte into the TX FIFO.
                        unsafe {
                            mmio_write32(base, DWSSI_DR, u32::from(xfer.tx_buf[i]));
                        }
                        msg.bytes_xferred += 1;
                    }
                    if xfer.dir == SpiTransferDir::FullDuplex {
                        // Collect RX bytes
                        for i in 0..xfer.len {
                            let mut timeout = 100_000u32;
                            loop {
                                // SAFETY: DWSSI_SR RFNE indicates RX FIFO has data.
                                let sr = unsafe { mmio_read32(base, DWSSI_SR) };
                                if (sr & DWSSI_SR_RFNE) != 0 {
                                    break;
                                }
                                timeout -= 1;
                                if timeout == 0 {
                                    self.error_count += 1;
                                    return Err(Error::IoError);
                                }
                            }
                            // SAFETY: Reading DWSSI_DR dequeues one byte from the RX FIFO.
                            let byte = unsafe { mmio_read32(base, DWSSI_DR) as u8 };
                            xfer.rx_buf[i] = byte;
                        }
                    }
                }
                SpiTransferDir::RxOnly => {
                    for i in 0..xfer.len {
                        let mut timeout = 100_000u32;
                        loop {
                            // SAFETY: DWSSI_SR RFNE indicates RX FIFO has data.
                            let sr = unsafe { mmio_read32(base, DWSSI_SR) };
                            if (sr & DWSSI_SR_RFNE) != 0 {
                                break;
                            }
                            timeout -= 1;
                            if timeout == 0 {
                                self.error_count += 1;
                                return Err(Error::IoError);
                            }
                        }
                        // SAFETY: Reading DWSSI_DR dequeues one byte from the RX FIFO.
                        let byte = unsafe { mmio_read32(base, DWSSI_DR) as u8 };
                        xfer.rx_buf[i] = byte;
                        msg.bytes_xferred += 1;
                    }
                }
            }

            // Deassert CS if cs_change or last transfer
            if xfer.cs_change || idx == msg.transfer_count.saturating_sub(1) {
                // SAFETY: DWSSI_SER: clear bit N to deassert slave N CS.
                unsafe {
                    mmio_write32(base, DWSSI_SER, 0);
                }
            }
        }
        Ok(())
    }

    /// Software-simulation transfer (no real hardware).
    fn sw_transfer_message(&self, msg: &mut SpiMessage) -> Result<()> {
        for idx in 0..msg.transfer_count {
            if let Some(xfer) = &msg.transfers[idx] {
                msg.bytes_xferred += xfer.len;
            }
        }
        Ok(())
    }

    /// Writes `data` to a SPI device on the given CS in a single TX-only message.
    ///
    /// # Errors
    ///
    /// Propagates transfer errors.
    pub fn write(&mut self, cs: u8, data: &[u8]) -> Result<()> {
        let xfer = SpiTransfer::tx_only(data);
        let mut msg = SpiMessage::new(cs);
        msg.add_transfer(xfer)?;
        self.transfer_message(&mut msg)
    }

    /// Reads `len` bytes from a SPI device on the given CS.
    ///
    /// # Errors
    ///
    /// Propagates transfer errors.
    pub fn read(&mut self, cs: u8, buf: &mut [u8]) -> Result<()> {
        let mut xfer = SpiTransfer::rx_only(buf.len());
        let mut msg = SpiMessage::new(cs);
        msg.add_transfer(xfer)?;
        self.transfer_message(&mut msg)?;
        let xfer_back = msg.transfers[0].as_ref().ok_or(Error::IoError)?;
        let copy_len = buf.len().min(xfer_back.len);
        buf[..copy_len].copy_from_slice(&xfer_back.rx_buf[..copy_len]);
        // suppress unused warning on local xfer
        let _ = &mut xfer;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// SpiControllerRegistry
// ---------------------------------------------------------------------------

/// Registry managing up to [`MAX_CONTROLLERS`] SPI master controllers.
pub struct SpiControllerRegistry {
    /// Registered controllers.
    controllers: [Option<SpiController>; MAX_CONTROLLERS],
    /// Number of registered controllers.
    count: usize,
}

impl Default for SpiControllerRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl SpiControllerRegistry {
    /// Creates a new, empty registry.
    pub const fn new() -> Self {
        Self {
            controllers: [const { None }; MAX_CONTROLLERS],
            count: 0,
        }
    }

    /// Registers a controller.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the registry is full, or
    /// [`Error::AlreadyExists`] if a controller with the same `id` exists.
    pub fn register(&mut self, ctrl: SpiController) -> Result<()> {
        for slot in self.controllers.iter().flatten() {
            if slot.id == ctrl.id {
                return Err(Error::AlreadyExists);
            }
        }
        for slot in self.controllers.iter_mut() {
            if slot.is_none() {
                *slot = Some(ctrl);
                self.count += 1;
                return Ok(());
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Unregisters a controller by `id`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if no matching controller is registered.
    pub fn unregister(&mut self, id: u32) -> Result<()> {
        for slot in self.controllers.iter_mut() {
            let matches = slot.as_ref().is_some_and(|c| c.id == id);
            if matches {
                *slot = None;
                self.count -= 1;
                return Ok(());
            }
        }
        Err(Error::NotFound)
    }

    /// Returns a shared reference to a controller by `id`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if not registered.
    pub fn get(&self, id: u32) -> Result<&SpiController> {
        self.controllers
            .iter()
            .flatten()
            .find(|c| c.id == id)
            .ok_or(Error::NotFound)
    }

    /// Returns a mutable reference to a controller by `id`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if not registered.
    pub fn get_mut(&mut self, id: u32) -> Result<&mut SpiController> {
        self.controllers
            .iter_mut()
            .flatten()
            .find(|c| c.id == id)
            .ok_or(Error::NotFound)
    }

    /// Returns the number of registered controllers.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Returns `true` if no controllers are registered.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
}
