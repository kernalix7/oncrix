// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! SPI bus controller driver.
//!
//! Provides an SPI subsystem supporting multiple buses with device
//! registration, chip-select management, and full-duplex transfer
//! operations.
//!
//! # Architecture
//!
//! - **SpiMode** — SPI clock phase and polarity modes (0–3).
//! - **SpiDevice** — a device descriptor registered on a bus with
//!   chip-select line, speed, and mode configuration.
//! - **SpiTransfer** — a single full-duplex SPI transfer with
//!   separate TX and RX buffers.
//! - **SpiBus** — a single SPI controller with device management
//!   and transfer operations.
//! - **SpiRegistry** — manages up to [`MAX_SPI_BUSES`]
//!   controllers.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Maximum number of SPI bus controllers.
const MAX_SPI_BUSES: usize = 4;

/// Maximum number of devices per SPI bus.
const _MAX_SPI_DEVICES: usize = 8;

/// Clock phase bit flag.
const _SPI_CPHA: u8 = 0x01;

/// Clock polarity bit flag.
const _SPI_CPOL: u8 = 0x02;

/// SPI mode 0: CPOL=0, CPHA=0.
const _SPI_MODE_0: u8 = 0x00;

/// SPI mode 1: CPOL=0, CPHA=1.
const _SPI_MODE_1: u8 = 0x01;

/// SPI mode 2: CPOL=1, CPHA=0.
const _SPI_MODE_2: u8 = 0x02;

/// SPI mode 3: CPOL=1, CPHA=1.
const _SPI_MODE_3: u8 = 0x03;

/// Maximum bytes per single SPI transfer.
const _MAX_SPI_TRANSFER: usize = 4096;

// -------------------------------------------------------------------
// SpiMode
// -------------------------------------------------------------------

/// SPI clock phase and polarity mode.
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
    /// Returns `true` when clock phase (CPHA) is set.
    pub fn cpha(&self) -> bool {
        matches!(self, Self::Mode1 | Self::Mode3)
    }

    /// Returns `true` when clock polarity (CPOL) is set.
    pub fn cpol(&self) -> bool {
        matches!(self, Self::Mode2 | Self::Mode3)
    }
}

// -------------------------------------------------------------------
// SpiDevice
// -------------------------------------------------------------------

/// Descriptor for a device registered on an SPI bus.
pub struct SpiDevice {
    /// Identifier of the bus this device belongs to.
    pub bus_id: u8,
    /// Chip-select line index.
    pub cs: u8,
    /// Maximum clock speed in Hz for this device.
    pub max_speed_hz: u32,
    /// SPI clock mode.
    pub mode: SpiMode,
    /// Word size in bits (typically 8).
    pub bits_per_word: u8,
    /// Whether the device is currently active.
    pub active: bool,
    /// Human-readable name (UTF-8, not NUL-terminated).
    pub name: [u8; 32],
    /// Number of valid bytes in [`name`](Self::name).
    pub name_len: usize,
}

// -------------------------------------------------------------------
// SpiTransfer
// -------------------------------------------------------------------

/// A single full-duplex SPI transfer.
///
/// Contains separate transmit and receive buffers. During a
/// transfer, data is simultaneously clocked out from `tx_buf` and
/// clocked in to `rx_buf`.
pub struct SpiTransfer {
    /// Transmit data buffer.
    pub tx_buf: [u8; 256],
    /// Receive data buffer.
    pub rx_buf: [u8; 256],
    /// Number of valid bytes to transfer.
    pub len: usize,
    /// Clock speed in Hz for this transfer (0 = use device default).
    pub speed_hz: u32,
    /// Word size in bits for this transfer (0 = use device default).
    pub bits_per_word: u8,
    /// When `true`, deassert chip-select between transfers.
    pub cs_change: bool,
}

// -------------------------------------------------------------------
// SpiBus
// -------------------------------------------------------------------

/// An SPI bus controller.
///
/// Manages a set of devices and provides full-duplex transfer
/// operations as well as a convenience `write_then_read` helper.
pub struct SpiBus {
    /// Bus identifier.
    id: u8,
    /// Base address for memory-mapped I/O registers.
    mmio_base: u64,
    /// Registered devices on this bus.
    devices: [SpiDevice; 8],
    /// Number of registered devices.
    device_count: usize,
    /// Maximum supported clock speed in Hz.
    max_speed: u32,
    /// Whether this bus is active (initialised).
    active: bool,
}

impl SpiBus {
    /// Creates a new SPI bus with the given identifier, MMIO base
    /// address, and maximum clock speed.
    pub fn new(id: u8, mmio_base: u64, max_speed: u32) -> Self {
        const EMPTY_DEV: SpiDevice = SpiDevice {
            bus_id: 0,
            cs: 0,
            max_speed_hz: 0,
            mode: SpiMode::Mode0,
            bits_per_word: 8,
            active: false,
            name: [0u8; 32],
            name_len: 0,
        };
        Self {
            id,
            mmio_base,
            devices: [EMPTY_DEV; 8],
            device_count: 0,
            max_speed,
            active: true,
        }
    }

    /// Returns the MMIO base address of this controller.
    pub fn mmio_base(&self) -> u64 {
        self.mmio_base
    }

    /// Returns the maximum supported clock speed in Hz.
    pub fn max_speed(&self) -> u32 {
        self.max_speed
    }

    /// Registers a device on this bus with the given chip-select
    /// line, name, speed, and mode.
    ///
    /// Returns [`Error::OutOfMemory`] when the device table is
    /// full, [`Error::AlreadyExists`] when the chip-select line
    /// is already in use, or [`Error::InvalidArgument`] when
    /// `name` is empty.
    pub fn add_device(
        &mut self,
        cs: u8,
        name: &[u8],
        max_speed_hz: u32,
        mode: SpiMode,
    ) -> Result<()> {
        if name.is_empty() {
            return Err(Error::InvalidArgument);
        }
        if self.device_count >= 8 {
            return Err(Error::OutOfMemory);
        }
        for dev in &self.devices[..self.device_count] {
            if dev.active && dev.cs == cs {
                return Err(Error::AlreadyExists);
            }
        }
        let copy_len = name.len().min(32);
        let mut dev_name = [0u8; 32];
        dev_name[..copy_len].copy_from_slice(&name[..copy_len]);
        self.devices[self.device_count] = SpiDevice {
            bus_id: self.id,
            cs,
            max_speed_hz,
            mode,
            bits_per_word: 8,
            active: true,
            name: dev_name,
            name_len: copy_len,
        };
        self.device_count += 1;
        Ok(())
    }

    /// Removes the device with chip-select `cs` from this bus.
    ///
    /// Returns [`Error::NotFound`] when no device with the given
    /// chip-select is registered.
    pub fn remove_device(&mut self, cs: u8) -> Result<()> {
        for dev in &mut self.devices[..self.device_count] {
            if dev.active && dev.cs == cs {
                dev.active = false;
                return Ok(());
            }
        }
        Err(Error::NotFound)
    }

    /// Executes a sequence of full-duplex SPI transfers on the
    /// device with chip-select `cs`.
    ///
    /// This is a stub implementation that validates transfers and
    /// zeroes receive buffers without touching real hardware.
    ///
    /// Returns [`Error::IoError`] when the bus is inactive,
    /// [`Error::NotFound`] when no device matches `cs`,
    /// [`Error::InvalidArgument`] when `transfers` is empty or a
    /// transfer length exceeds the buffer size.
    pub fn transfer(&mut self, cs: u8, transfers: &mut [SpiTransfer]) -> Result<()> {
        if !self.active {
            return Err(Error::IoError);
        }
        if transfers.is_empty() {
            return Err(Error::InvalidArgument);
        }
        // Verify device exists.
        let mut found = false;
        for dev in &self.devices[..self.device_count] {
            if dev.active && dev.cs == cs {
                found = true;
                break;
            }
        }
        if !found {
            return Err(Error::NotFound);
        }

        for xfer in transfers.iter_mut() {
            if xfer.len > 256 {
                return Err(Error::InvalidArgument);
            }
            // Stub: zero the receive buffer for the transfer length.
            for b in &mut xfer.rx_buf[..xfer.len] {
                *b = 0;
            }
        }
        Ok(())
    }

    /// Writes `tx` bytes then reads `rx.len()` bytes from the
    /// device with chip-select `cs`.
    ///
    /// This is a convenience wrapper around [`transfer`](Self::transfer)
    /// that performs a write transfer followed by a read transfer.
    pub fn write_then_read(&mut self, cs: u8, tx: &[u8], rx: &mut [u8]) -> Result<()> {
        if tx.len() > 256 || rx.len() > 256 {
            return Err(Error::InvalidArgument);
        }
        let mut tx_buf = [0u8; 256];
        let tx_len = tx.len().min(256);
        tx_buf[..tx_len].copy_from_slice(&tx[..tx_len]);

        let mut transfers = [
            SpiTransfer {
                tx_buf,
                rx_buf: [0u8; 256],
                len: tx_len,
                speed_hz: 0,
                bits_per_word: 0,
                cs_change: false,
            },
            SpiTransfer {
                tx_buf: [0u8; 256],
                rx_buf: [0u8; 256],
                len: rx.len(),
                speed_hz: 0,
                bits_per_word: 0,
                cs_change: false,
            },
        ];
        self.transfer(cs, &mut transfers)?;
        let rx_len = rx.len().min(256);
        rx[..rx_len].copy_from_slice(&transfers[1].rx_buf[..rx_len]);
        Ok(())
    }

    /// Returns the number of registered (active) devices.
    pub fn device_count(&self) -> usize {
        self.devices[..self.device_count]
            .iter()
            .filter(|d| d.active)
            .count()
    }
}

// -------------------------------------------------------------------
// SpiRegistry
// -------------------------------------------------------------------

/// Registry of SPI bus controllers.
///
/// Manages up to [`MAX_SPI_BUSES`] bus instances, providing
/// registration and lookup by bus identifier.
pub struct SpiRegistry {
    /// Registered bus controllers.
    buses: [Option<SpiBus>; MAX_SPI_BUSES],
    /// Number of registered buses.
    count: usize,
}

impl Default for SpiRegistry {
    fn default() -> Self {
        const NONE: Option<SpiBus> = None;
        Self {
            buses: [NONE; MAX_SPI_BUSES],
            count: 0,
        }
    }
}

impl SpiRegistry {
    /// Registers a bus in the first available slot.
    ///
    /// Returns [`Error::OutOfMemory`] when the registry is full or
    /// [`Error::AlreadyExists`] when a bus with the same id is
    /// already registered.
    pub fn register(&mut self, bus: SpiBus) -> Result<()> {
        for b in self.buses.iter().flatten() {
            if b.id == bus.id {
                return Err(Error::AlreadyExists);
            }
        }
        for slot in &mut self.buses {
            if slot.is_none() {
                *slot = Some(bus);
                self.count += 1;
                return Ok(());
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Returns an immutable reference to the bus with `id`.
    pub fn get(&self, id: u8) -> Result<&SpiBus> {
        for b in self.buses.iter().flatten() {
            if b.id == id {
                return Ok(b);
            }
        }
        Err(Error::NotFound)
    }

    /// Returns a mutable reference to the bus with `id`.
    pub fn get_mut(&mut self, id: u8) -> Result<&mut SpiBus> {
        for b in self.buses.iter_mut().flatten() {
            if b.id == id {
                return Ok(b);
            }
        }
        Err(Error::NotFound)
    }

    /// Returns the number of registered buses.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Returns `true` when no buses are registered.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
}
