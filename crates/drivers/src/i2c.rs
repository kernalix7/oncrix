// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! I2C bus controller driver.
//!
//! Provides an I2C subsystem supporting multiple buses with device
//! registration, bus scanning, and byte/block-level read/write
//! operations.
//!
//! # Architecture
//!
//! - **I2cSpeed** — supported I2C clock rates (Standard through
//!   High-speed mode).
//! - **I2cMessage** — a single I2C transfer message with address,
//!   flags, and an inline data buffer.
//! - **I2cDevice** — a device descriptor registered on a bus.
//! - **I2cBus** — a single I2C controller with device management
//!   and transfer operations.
//! - **I2cRegistry** — manages up to [`MAX_I2C_BUSES`] controllers.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Maximum number of I2C bus controllers.
const MAX_I2C_BUSES: usize = 8;

/// Maximum number of devices per I2C bus.
const _MAX_I2C_DEVICES_PER_BUS: usize = 16;

/// Standard mode clock frequency (100 kHz).
const _I2C_SPEED_STANDARD: u32 = 100_000;

/// Fast mode clock frequency (400 kHz).
const _I2C_SPEED_FAST: u32 = 400_000;

/// Fast mode plus clock frequency (1 MHz).
const _I2C_SPEED_FAST_PLUS: u32 = 1_000_000;

/// High-speed mode clock frequency (3.4 MHz).
const _I2C_SPEED_HIGH: u32 = 3_400_000;

/// Message flag: read transfer.
const _I2C_M_RD: u16 = 0x01;

/// Message flag: ten-bit addressing.
const _I2C_M_TEN: u16 = 0x10;

/// Message flag: omit (re)START condition.
const _I2C_M_NOSTART: u16 = 0x40;

// -------------------------------------------------------------------
// I2cSpeed
// -------------------------------------------------------------------

/// I2C bus clock speed mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum I2cSpeed {
    /// Standard mode — 100 kHz.
    #[default]
    Standard,
    /// Fast mode — 400 kHz.
    Fast,
    /// Fast mode plus — 1 MHz.
    FastPlus,
    /// High-speed mode — 3.4 MHz.
    High,
}

impl I2cSpeed {
    /// Returns the clock frequency in Hz for this speed mode.
    pub fn frequency(&self) -> u32 {
        match self {
            Self::Standard => 100_000,
            Self::Fast => 400_000,
            Self::FastPlus => 1_000_000,
            Self::High => 3_400_000,
        }
    }
}

// -------------------------------------------------------------------
// I2cMessage
// -------------------------------------------------------------------

/// A single I2C transfer message.
///
/// Each message targets a device address, carries flags describing
/// the transfer direction and addressing mode, and includes an
/// inline 64-byte data buffer.
#[derive(Clone)]
pub struct I2cMessage {
    /// Target device address (7-bit or 10-bit).
    pub addr: u16,
    /// Transfer flags (see `I2C_M_*` constants).
    pub flags: u16,
    /// Number of valid bytes in [`buf`](Self::buf).
    pub len: u16,
    /// Inline data buffer.
    pub buf: [u8; 64],
}

impl I2cMessage {
    /// Returns `true` when this message is a read transfer.
    pub fn is_read(&self) -> bool {
        self.flags & 0x01 != 0
    }

    /// Returns `true` when ten-bit addressing is in use.
    pub fn is_ten_bit(&self) -> bool {
        self.flags & 0x10 != 0
    }
}

// -------------------------------------------------------------------
// I2cDevice
// -------------------------------------------------------------------

/// Descriptor for a device registered on an I2C bus.
pub struct I2cDevice {
    /// Device address (7-bit or 10-bit).
    pub addr: u16,
    /// Human-readable name (UTF-8, not NUL-terminated).
    pub name: [u8; 32],
    /// Number of valid bytes in [`name`](Self::name).
    pub name_len: usize,
    /// Identifier of the bus this device belongs to.
    pub bus_id: u8,
    /// Whether the device is currently present.
    pub present: bool,
    /// Whether the device uses ten-bit addressing.
    pub ten_bit: bool,
}

// -------------------------------------------------------------------
// I2cBus
// -------------------------------------------------------------------

/// An I2C bus controller.
///
/// Manages a set of devices and provides byte-level and block-level
/// read/write helpers, as well as a raw `transfer` method for
/// multi-message transactions.
pub struct I2cBus {
    /// Bus identifier.
    id: u8,
    /// Current clock speed mode.
    speed: I2cSpeed,
    /// Base address for memory-mapped I/O registers.
    mmio_base: u64,
    /// Registered devices on this bus.
    devices: [I2cDevice; 16],
    /// Number of registered devices.
    device_count: usize,
    /// Whether this bus is active (initialised).
    active: bool,
    /// Whether a transfer is currently in progress.
    busy: bool,
    /// Total number of successful transfers.
    transfer_count: u64,
    /// Total number of failed transfers.
    error_count: u64,
}

impl I2cBus {
    /// Creates a new I2C bus with the given identifier, MMIO base
    /// address, and clock speed.
    pub fn new(id: u8, mmio_base: u64, speed: I2cSpeed) -> Self {
        const EMPTY_DEV: I2cDevice = I2cDevice {
            addr: 0,
            name: [0u8; 32],
            name_len: 0,
            bus_id: 0,
            present: false,
            ten_bit: false,
        };
        Self {
            id,
            speed,
            mmio_base,
            devices: [EMPTY_DEV; 16],
            device_count: 0,
            active: true,
            busy: false,
            transfer_count: 0,
            error_count: 0,
        }
    }

    /// Returns the current clock speed mode.
    pub fn speed(&self) -> I2cSpeed {
        self.speed
    }

    /// Returns the MMIO base address of this controller.
    pub fn mmio_base(&self) -> u64 {
        self.mmio_base
    }

    /// Registers a device at `addr` on this bus.
    ///
    /// Returns [`Error::OutOfMemory`] when the device table is full,
    /// [`Error::AlreadyExists`] when the address is already
    /// registered, or [`Error::InvalidArgument`] when `name` is
    /// empty.
    pub fn add_device(&mut self, addr: u16, name: &[u8]) -> Result<()> {
        if name.is_empty() {
            return Err(Error::InvalidArgument);
        }
        if self.device_count >= 16 {
            return Err(Error::OutOfMemory);
        }
        // Check for duplicate address.
        for dev in &self.devices[..self.device_count] {
            if dev.present && dev.addr == addr {
                return Err(Error::AlreadyExists);
            }
        }
        let copy_len = name.len().min(32);
        let mut dev_name = [0u8; 32];
        dev_name[..copy_len].copy_from_slice(&name[..copy_len]);
        self.devices[self.device_count] = I2cDevice {
            addr,
            name: dev_name,
            name_len: copy_len,
            bus_id: self.id,
            present: true,
            ten_bit: addr > 0x7F,
        };
        self.device_count += 1;
        Ok(())
    }

    /// Removes the device at `addr` from this bus.
    ///
    /// Returns [`Error::NotFound`] when no device with the given
    /// address is registered.
    pub fn remove_device(&mut self, addr: u16) -> Result<()> {
        for dev in &mut self.devices[..self.device_count] {
            if dev.present && dev.addr == addr {
                dev.present = false;
                return Ok(());
            }
        }
        Err(Error::NotFound)
    }

    /// Executes a multi-message I2C transfer.
    ///
    /// Returns the number of messages successfully processed. This
    /// is a stub implementation that validates messages and marks
    /// them as processed without touching real hardware.
    pub fn transfer(&mut self, msgs: &mut [I2cMessage]) -> Result<usize> {
        if !self.active {
            return Err(Error::IoError);
        }
        if self.busy {
            return Err(Error::Busy);
        }
        if msgs.is_empty() {
            return Err(Error::InvalidArgument);
        }

        self.busy = true;

        let mut processed: usize = 0;
        for msg in msgs.iter_mut() {
            if msg.len as usize > 64 {
                self.error_count += 1;
                self.busy = false;
                return Err(Error::InvalidArgument);
            }
            // Stub: for read messages, zero the buffer.
            if msg.is_read() {
                let end = (msg.len as usize).min(64);
                for b in &mut msg.buf[..end] {
                    *b = 0;
                }
            }
            processed += 1;
        }

        self.transfer_count += processed as u64;
        self.busy = false;
        Ok(processed)
    }

    /// Reads a single byte from `reg` on the device at `addr`.
    pub fn read_byte(&mut self, addr: u16, reg: u8) -> Result<u8> {
        let mut msgs = [
            I2cMessage {
                addr,
                flags: 0,
                len: 1,
                buf: {
                    let mut b = [0u8; 64];
                    b[0] = reg;
                    b
                },
            },
            I2cMessage {
                addr,
                flags: 0x01,
                len: 1,
                buf: [0u8; 64],
            },
        ];
        self.transfer(&mut msgs)?;
        Ok(msgs[1].buf[0])
    }

    /// Writes a single byte `val` to `reg` on the device at `addr`.
    pub fn write_byte(&mut self, addr: u16, reg: u8, val: u8) -> Result<()> {
        let mut msgs = [I2cMessage {
            addr,
            flags: 0,
            len: 2,
            buf: {
                let mut b = [0u8; 64];
                b[0] = reg;
                b[1] = val;
                b
            },
        }];
        self.transfer(&mut msgs)?;
        Ok(())
    }

    /// Reads a block of bytes from `reg` on the device at `addr`
    /// into `buf`.
    ///
    /// Returns the number of bytes read (capped at 63 and
    /// `buf.len()`).
    pub fn read_block(&mut self, addr: u16, reg: u8, buf: &mut [u8]) -> Result<usize> {
        let read_len = buf.len().min(63);
        let mut msgs = [
            I2cMessage {
                addr,
                flags: 0,
                len: 1,
                buf: {
                    let mut b = [0u8; 64];
                    b[0] = reg;
                    b
                },
            },
            I2cMessage {
                addr,
                flags: 0x01,
                len: read_len as u16,
                buf: [0u8; 64],
            },
        ];
        self.transfer(&mut msgs)?;
        buf[..read_len].copy_from_slice(&msgs[1].buf[..read_len]);
        Ok(read_len)
    }

    /// Writes a block of bytes to `reg` on the device at `addr`.
    ///
    /// The block size is capped at 63 bytes (register byte occupies
    /// the first position in the buffer).
    pub fn write_block(&mut self, addr: u16, reg: u8, data: &[u8]) -> Result<()> {
        let write_len = data.len().min(63);
        let mut b = [0u8; 64];
        b[0] = reg;
        b[1..1 + write_len].copy_from_slice(&data[..write_len]);
        let mut msgs = [I2cMessage {
            addr,
            flags: 0,
            len: (write_len + 1) as u16,
            buf: b,
        }];
        self.transfer(&mut msgs)?;
        Ok(())
    }

    /// Scans the bus and returns which 7-bit addresses respond.
    ///
    /// Index *i* of the returned array is `true` when a device is
    /// registered and present at address *i*. This is a stub that
    /// checks the internal device table rather than probing
    /// hardware.
    pub fn scan(&self) -> [bool; 128] {
        let mut result = [false; 128];
        for dev in &self.devices[..self.device_count] {
            if dev.present && (dev.addr as usize) < 128 {
                result[dev.addr as usize] = true;
            }
        }
        result
    }

    /// Returns the number of registered (present) devices.
    pub fn device_count(&self) -> usize {
        self.devices[..self.device_count]
            .iter()
            .filter(|d| d.present)
            .count()
    }
}

// -------------------------------------------------------------------
// I2cRegistry
// -------------------------------------------------------------------

/// Registry of I2C bus controllers.
///
/// Manages up to [`MAX_I2C_BUSES`] bus instances, providing
/// registration and lookup by bus identifier.
pub struct I2cRegistry {
    /// Registered bus controllers.
    buses: [Option<I2cBus>; MAX_I2C_BUSES],
    /// Number of registered buses.
    count: usize,
}

impl Default for I2cRegistry {
    fn default() -> Self {
        const NONE: Option<I2cBus> = None;
        Self {
            buses: [NONE; MAX_I2C_BUSES],
            count: 0,
        }
    }
}

impl I2cRegistry {
    /// Registers a bus in the first available slot.
    ///
    /// Returns [`Error::OutOfMemory`] when the registry is full or
    /// [`Error::AlreadyExists`] when a bus with the same id is
    /// already registered.
    pub fn register(&mut self, bus: I2cBus) -> Result<()> {
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
    pub fn get(&self, id: u8) -> Result<&I2cBus> {
        for b in self.buses.iter().flatten() {
            if b.id == id {
                return Ok(b);
            }
        }
        Err(Error::NotFound)
    }

    /// Returns a mutable reference to the bus with `id`.
    pub fn get_mut(&mut self, id: u8) -> Result<&mut I2cBus> {
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
