// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! I2C slave device abstraction layer.
//!
//! Provides the HAL-side representation of I2C slave devices attached to an I2C bus.
//! Manages slave device addressing, transaction framing, and register-level access
//! using the standard I2C protocol (7-bit and 10-bit addressing).
//!
//! # I2C Protocol
//!
//! - **Start condition**: SDA transitions high-to-low while SCL is high
//! - **Address frame**: 7 or 10 bits of device address + R/W bit
//! - **Data frames**: 8-bit bytes, each acknowledged by receiver
//! - **Stop condition**: SDA transitions low-to-high while SCL is high
//!
//! # References
//!
//! - NXP UM10204: I2C-bus specification and user manual, Rev 7.0

#![allow(dead_code)]

use oncrix_lib::{Error, Result};

/// Maximum I2C bus speed classes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum I2cSpeed {
    /// Standard mode: 100 kHz.
    Standard = 100_000,
    /// Fast mode: 400 kHz.
    Fast = 400_000,
    /// Fast-mode Plus: 1 MHz.
    FastPlus = 1_000_000,
    /// High-speed mode: 3.4 MHz.
    HighSpeed = 3_400_000,
    /// Ultra Fast-mode: 5 MHz (unidirectional).
    UltraFast = 5_000_000,
}

/// I2C address type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum I2cAddress {
    /// 7-bit address (0x00–0x7F).
    Bit7(u8),
    /// 10-bit address (0x000–0x3FF).
    Bit10(u16),
}

impl I2cAddress {
    /// Returns the raw address value.
    pub fn raw(self) -> u16 {
        match self {
            Self::Bit7(a) => a as u16,
            Self::Bit10(a) => a,
        }
    }

    /// Returns whether this is a 10-bit address.
    pub fn is_10bit(self) -> bool {
        matches!(self, Self::Bit10(_))
    }

    /// Validates the address value.
    pub fn validate(self) -> Result<()> {
        match self {
            Self::Bit7(a) if a > 0x7F => Err(Error::InvalidArgument),
            Self::Bit10(a) if a > 0x3FF => Err(Error::InvalidArgument),
            _ => Ok(()),
        }
    }
}

/// Direction of an I2C transfer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransferDir {
    /// Master writes to slave.
    Write,
    /// Master reads from slave.
    Read,
}

/// A single I2C message (one segment of a compound transaction).
#[derive(Debug)]
pub struct I2cMsg<'a> {
    /// Slave device address.
    pub addr: I2cAddress,
    /// Transfer direction.
    pub dir: TransferDir,
    /// Data buffer (source for writes, destination for reads).
    pub buf: &'a mut [u8],
    /// Whether to send a repeated START instead of STOP after this message.
    pub repeated_start: bool,
}

/// I2C slave device descriptor.
///
/// Describes a peripheral attached to an I2C bus at a specific address.
#[derive(Debug, Clone, Copy)]
pub struct I2cSlaveDevice {
    /// Device address on the bus.
    pub addr: I2cAddress,
    /// Maximum clock speed this device supports.
    pub max_speed: I2cSpeed,
    /// Whether the device requires clock stretching support.
    pub needs_clock_stretch: bool,
}

impl I2cSlaveDevice {
    /// Creates a new I2C slave device descriptor.
    pub const fn new(addr: u8, max_speed: I2cSpeed) -> Self {
        Self {
            addr: I2cAddress::Bit7(addr),
            max_speed,
            needs_clock_stretch: false,
        }
    }

    /// Creates a 10-bit addressed I2C slave device.
    pub const fn new_10bit(addr: u16, max_speed: I2cSpeed) -> Self {
        Self {
            addr: I2cAddress::Bit10(addr),
            max_speed,
            needs_clock_stretch: false,
        }
    }

    /// Returns the 7-bit address for use in the I2C address frame (R/W not included).
    pub fn frame_address(&self) -> u8 {
        match self.addr {
            I2cAddress::Bit7(a) => a,
            I2cAddress::Bit10(a) => 0x78 | ((a >> 8) as u8 & 0x3),
        }
    }
}

/// I2C register access helper for devices with 8-bit register addresses.
pub struct I2cRegAccess<'b, B: I2cBusOps> {
    bus: &'b mut B,
    device: I2cSlaveDevice,
}

impl<'b, B: I2cBusOps> I2cRegAccess<'b, B> {
    /// Creates a new register access helper.
    pub fn new(bus: &'b mut B, device: I2cSlaveDevice) -> Self {
        Self { bus, device }
    }

    /// Reads a single byte from an 8-bit register address.
    pub fn read_reg(&mut self, reg: u8) -> Result<u8> {
        let reg_buf = [reg];
        let mut data = [0u8];
        self.bus
            .write_then_read(self.device.addr, &reg_buf, &mut data)?;
        Ok(data[0])
    }

    /// Writes a single byte to an 8-bit register address.
    pub fn write_reg(&mut self, reg: u8, val: u8) -> Result<()> {
        let buf = [reg, val];
        self.bus.write(self.device.addr, &buf)
    }

    /// Reads multiple bytes starting from an 8-bit register address.
    pub fn read_regs(&mut self, reg: u8, buf: &mut [u8]) -> Result<()> {
        let reg_buf = [reg];
        self.bus.write_then_read(self.device.addr, &reg_buf, buf)
    }

    /// Performs a read-modify-write on an 8-bit register.
    pub fn modify_reg(&mut self, reg: u8, mask: u8, val: u8) -> Result<()> {
        let cur = self.read_reg(reg)?;
        let new_val = (cur & !mask) | (val & mask);
        self.write_reg(reg, new_val)
    }
}

/// Trait for I2C bus controllers that can drive slave transactions.
pub trait I2cBusOps {
    /// Performs a simple write transaction.
    fn write(&mut self, addr: I2cAddress, data: &[u8]) -> Result<()>;

    /// Performs a simple read transaction.
    fn read(&mut self, addr: I2cAddress, buf: &mut [u8]) -> Result<()>;

    /// Performs a write-then-read with repeated START (no STOP between).
    fn write_then_read(
        &mut self,
        addr: I2cAddress,
        write_data: &[u8],
        read_buf: &mut [u8],
    ) -> Result<()>;

    /// Checks whether a device ACKs at the given address (device presence check).
    fn probe(&mut self, addr: I2cAddress) -> bool {
        let mut dummy = [0u8; 1];
        self.read(addr, &mut dummy).is_ok()
    }
}

/// Registry of discovered I2C slave devices on a bus.
pub struct I2cSlaveRegistry {
    devices: [Option<I2cSlaveDevice>; 16],
    count: usize,
}

impl I2cSlaveRegistry {
    /// Creates an empty slave registry.
    pub const fn new() -> Self {
        Self {
            devices: [None; 16],
            count: 0,
        }
    }

    /// Registers a slave device.
    pub fn register(&mut self, dev: I2cSlaveDevice) -> Result<()> {
        if self.count >= 16 {
            return Err(Error::OutOfMemory);
        }
        dev.addr.validate()?;
        self.devices[self.count] = Some(dev);
        self.count += 1;
        Ok(())
    }

    /// Returns the device at the given index.
    pub fn get(&self, index: usize) -> Option<&I2cSlaveDevice> {
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

    /// Looks up a device by address.
    pub fn find_by_addr(&self, addr: I2cAddress) -> Option<&I2cSlaveDevice> {
        self.devices[..self.count].iter().find_map(|d| {
            let dev = d.as_ref()?;
            if dev.addr == addr { Some(dev) } else { None }
        })
    }
}

impl Default for I2cSlaveRegistry {
    fn default() -> Self {
        Self::new()
    }
}
