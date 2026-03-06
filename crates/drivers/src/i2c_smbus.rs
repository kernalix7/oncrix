// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! I2C/SMBus protocol driver.
//!
//! Implements the I2C and System Management Bus (SMBus) protocol layer,
//! providing a generic transaction interface suitable for use with any
//! I2C host controller. SMBus is a strict subset of I2C with additional
//! timing and protocol constraints.
//!
//! # Architecture
//!
//! ```text
//! Application
//!   │  I2cTransaction / SmBusTransaction
//!   ▼
//! I2cBus ──► I2cAdapter (controller-specific)
//!              │
//!              ├── read_byte / write_byte
//!              ├── read_block / write_block
//!              └── process_call
//! ```
//!
//! # I2C vs SMBus
//!
//! | Feature         | I2C              | SMBus              |
//! |-----------------|------------------|--------------------|
//! | Speed           | 100/400/1000 kHz | 10–100 kHz         |
//! | Address width   | 7 or 10 bit      | 7 bit only         |
//! | Clock stretch   | Yes              | Limited            |
//! | Max block size  | 256 bytes        | 32 bytes           |
//! | CRC             | Optional         | Optional (PEC)     |
//!
//! Reference: I2C-bus specification v7.0, NXP UM10204;
//!            SMBus Specification 3.2.

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum number of I2C buses registered.
pub const MAX_BUS_COUNT: usize = 8;

/// Maximum I2C/SMBus transfer size in bytes.
pub const MAX_TRANSFER_SIZE: usize = 256;

/// Maximum SMBus block transfer size (spec §5.5).
pub const SMBUS_MAX_BLOCK: usize = 32;

/// I2C read flag (bit 0 of address byte on wire).
pub const I2C_READ_FLAG: u8 = 0x01;

/// I2C write flag (bit 0 of address byte on wire).
pub const I2C_WRITE_FLAG: u8 = 0x00;

/// 10-bit address prefix for the first byte.
const I2C_10BIT_PREFIX: u8 = 0xF0;

/// I2C speed: standard mode (100 kHz).
pub const I2C_SPEED_STANDARD: u32 = 100_000;

/// I2C speed: fast mode (400 kHz).
pub const I2C_SPEED_FAST: u32 = 400_000;

/// I2C speed: fast-mode plus (1 MHz).
pub const I2C_SPEED_FAST_PLUS: u32 = 1_000_000;

/// I2C speed: high-speed mode (3.4 MHz).
pub const I2C_SPEED_HIGH: u32 = 3_400_000;

/// SMBus Process Call command code (§5.5.6).
pub const SMBUS_PROCESS_CALL: u8 = 0x04;

/// SMBus timeout in microseconds (35 ms).
pub const SMBUS_TIMEOUT_US: u32 = 35_000;

/// PEC (Packet Error Code) polynomial: CRC-8/SMBUS (x^8+x^2+x+1).
const PEC_POLY: u8 = 0x07;

// ---------------------------------------------------------------------------
// I2C address types
// ---------------------------------------------------------------------------

/// I2C device address (7-bit or 10-bit).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum I2cAddress {
    /// 7-bit address (0x00–0x7F).
    SevenBit(u8),
    /// 10-bit address (0x000–0x3FF).
    TenBit(u16),
}

impl I2cAddress {
    /// Validate the address range.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] for reserved or out-of-range
    /// addresses.
    pub fn validate(&self) -> Result<()> {
        match self {
            I2cAddress::SevenBit(addr) => {
                // Reserved addresses: 0x00–0x07 and 0x78–0x7F.
                if *addr > 0x7F {
                    return Err(Error::InvalidArgument);
                }
                Ok(())
            }
            I2cAddress::TenBit(addr) => {
                if *addr > 0x3FF {
                    return Err(Error::InvalidArgument);
                }
                Ok(())
            }
        }
    }

    /// Build the first address byte for a 7-bit address on the bus.
    pub fn first_byte(&self, read: bool) -> u8 {
        match self {
            I2cAddress::SevenBit(a) => (a << 1) | if read { I2C_READ_FLAG } else { I2C_WRITE_FLAG },
            I2cAddress::TenBit(a) => {
                let high = ((a >> 7) & 0x06) as u8;
                I2C_10BIT_PREFIX | high | if read { I2C_READ_FLAG } else { I2C_WRITE_FLAG }
            }
        }
    }

    /// Second address byte for a 10-bit address (lower 8 bits).
    pub fn second_byte(&self) -> Option<u8> {
        match self {
            I2cAddress::SevenBit(_) => None,
            I2cAddress::TenBit(a) => Some((*a & 0xFF) as u8),
        }
    }

    /// Whether this is a 10-bit address.
    pub fn is_ten_bit(&self) -> bool {
        matches!(self, I2cAddress::TenBit(_))
    }
}

// ---------------------------------------------------------------------------
// I2C transfer direction
// ---------------------------------------------------------------------------

/// I2C transfer direction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum I2cDirection {
    /// Driver writes to device.
    Write,
    /// Driver reads from device.
    Read,
}

// ---------------------------------------------------------------------------
// I2C message
// ---------------------------------------------------------------------------

/// A single I2C message (one segment of a combined transfer).
#[derive(Debug, Clone)]
pub struct I2cMsg {
    /// Target device address.
    pub addr: I2cAddress,
    /// Transfer direction.
    pub dir: I2cDirection,
    /// Whether to emit a repeated START instead of STOP+START.
    pub repeated_start: bool,
    /// Number of valid bytes in `buf`.
    pub len: usize,
    /// Data buffer (read: filled by device; write: sent to device).
    pub buf: [u8; MAX_TRANSFER_SIZE],
}

impl I2cMsg {
    /// Create a write message.
    pub fn write(addr: I2cAddress, data: &[u8]) -> Result<Self> {
        if data.len() > MAX_TRANSFER_SIZE {
            return Err(Error::InvalidArgument);
        }
        let mut msg = Self {
            addr,
            dir: I2cDirection::Write,
            repeated_start: false,
            len: data.len(),
            buf: [0u8; MAX_TRANSFER_SIZE],
        };
        msg.buf[..data.len()].copy_from_slice(data);
        Ok(msg)
    }

    /// Create a read message.
    pub fn read(addr: I2cAddress, len: usize) -> Result<Self> {
        if len > MAX_TRANSFER_SIZE {
            return Err(Error::InvalidArgument);
        }
        Ok(Self {
            addr,
            dir: I2cDirection::Read,
            repeated_start: false,
            len,
            buf: [0u8; MAX_TRANSFER_SIZE],
        })
    }

    /// Data slice for this message.
    pub fn data(&self) -> &[u8] {
        &self.buf[..self.len]
    }

    /// Mutable data slice for this message.
    pub fn data_mut(&mut self) -> &mut [u8] {
        &mut self.buf[..self.len]
    }
}

// ---------------------------------------------------------------------------
// SMBus transaction type
// ---------------------------------------------------------------------------

/// SMBus transaction variants.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SmBusTransactionKind {
    /// Quick command (address + R/W only, no data).
    Quick,
    /// Send/receive a single byte (no command byte).
    SendByte,
    /// Write one byte at a given command code.
    WriteByte,
    /// Read one byte from a given command code.
    ReadByte,
    /// Write two bytes (word) at a given command code.
    WriteWord,
    /// Read two bytes (word) from a given command code.
    ReadWord,
    /// Write a block of up to 32 bytes.
    WriteBlock,
    /// Read a block of up to 32 bytes.
    ReadBlock,
    /// Combined write+read (process call).
    ProcessCall,
    /// Block write + block read (block process call).
    BlockProcessCall,
}

/// An SMBus transaction descriptor.
#[derive(Debug, Clone)]
pub struct SmBusTransaction {
    /// Device address (7-bit only for SMBus).
    pub addr: u8,
    /// Transaction kind.
    pub kind: SmBusTransactionKind,
    /// Command byte (register address).
    pub command: u8,
    /// Whether to append/check a Packet Error Code byte.
    pub pec: bool,
    /// Data bytes (for write operations or block transfers).
    pub data: [u8; SMBUS_MAX_BLOCK + 1],
    /// Number of valid bytes in `data`.
    pub data_len: usize,
}

impl SmBusTransaction {
    /// Create a new SMBus transaction.
    pub const fn new(addr: u8, kind: SmBusTransactionKind) -> Self {
        Self {
            addr,
            kind,
            command: 0,
            pec: false,
            data: [0u8; SMBUS_MAX_BLOCK + 1],
            data_len: 0,
        }
    }

    /// Data slice.
    pub fn data(&self) -> &[u8] {
        &self.data[..self.data_len]
    }

    /// Set write data from a slice.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `src.len() > SMBUS_MAX_BLOCK`.
    pub fn set_data(&mut self, src: &[u8]) -> Result<()> {
        if src.len() > SMBUS_MAX_BLOCK {
            return Err(Error::InvalidArgument);
        }
        self.data[..src.len()].copy_from_slice(src);
        self.data_len = src.len();
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// PEC (Packet Error Code / CRC-8)
// ---------------------------------------------------------------------------

/// Compute the CRC-8/SMBus checksum over `data`.
///
/// Uses the polynomial 0x07 (x^8 + x^2 + x + 1) with an initial value
/// of 0x00 and no final XOR.
pub fn compute_pec(data: &[u8]) -> u8 {
    let mut crc: u8 = 0;
    for &byte in data {
        crc ^= byte;
        for _ in 0..8 {
            if crc & 0x80 != 0 {
                crc = (crc << 1) ^ PEC_POLY;
            } else {
                crc <<= 1;
            }
        }
    }
    crc
}

/// Verify a PEC byte appended to `data`.
///
/// The last byte in `data` is the received PEC. Returns `true` when
/// the CRC computed over all preceding bytes matches the PEC.
pub fn verify_pec(data: &[u8]) -> bool {
    if data.is_empty() {
        return false;
    }
    compute_pec(data) == 0
}

// ---------------------------------------------------------------------------
// I2cAdapter trait
// ---------------------------------------------------------------------------

/// Trait that a concrete I2C host controller must implement.
///
/// Each method corresponds to a primitive operation on the bus. The
/// `I2cBus` layer builds higher-level transactions on top of these.
pub trait I2cAdapter {
    /// Perform a series of I2C messages as a combined transfer.
    ///
    /// The controller issues a START before the first message and a STOP
    /// after the last. Between consecutive messages, it issues a repeated
    /// START if `msg.repeated_start` is set, or STOP+START otherwise.
    ///
    /// # Errors
    ///
    /// Returns [`Error::IoError`] on bus error (NACK, arbitration loss,
    /// timeout), or [`Error::InvalidArgument`] for malformed requests.
    fn transfer(&mut self, msgs: &mut [I2cMsg]) -> Result<usize>;

    /// Return the maximum I2C bus speed supported (Hz).
    fn max_speed_hz(&self) -> u32;

    /// Whether 10-bit addressing is supported.
    fn supports_ten_bit(&self) -> bool {
        false
    }

    /// Recover from a bus hang (release SDA/SCL via clock cycling).
    fn recover(&mut self) -> Result<()> {
        Err(Error::NotImplemented)
    }
}

// ---------------------------------------------------------------------------
// I2cBus
// ---------------------------------------------------------------------------

/// I2C bus high-level interface.
///
/// Wraps an [`I2cAdapter`] and adds SMBus helpers and combined-transfer
/// convenience methods.
pub struct I2cBus<A: I2cAdapter> {
    /// The underlying hardware adapter.
    pub adapter: A,
    /// Bus number (for identification).
    pub bus_id: u8,
    /// Current target speed in Hz.
    pub speed_hz: u32,
}

impl<A: I2cAdapter> I2cBus<A> {
    /// Create a new I2C bus wrapping `adapter`.
    pub fn new(bus_id: u8, adapter: A) -> Self {
        let speed = adapter.max_speed_hz().min(I2C_SPEED_FAST);
        Self {
            adapter,
            bus_id,
            speed_hz: speed,
        }
    }

    /// Write `data` to device `addr`.
    ///
    /// Issues a single I2C write transfer.
    pub fn write(&mut self, addr: I2cAddress, data: &[u8]) -> Result<()> {
        let mut msg = I2cMsg::write(addr, data)?;
        self.adapter.transfer(core::slice::from_mut(&mut msg))?;
        Ok(())
    }

    /// Read `len` bytes from device `addr` into `buf`.
    pub fn read(&mut self, addr: I2cAddress, buf: &mut [u8]) -> Result<()> {
        let mut msg = I2cMsg::read(addr, buf.len())?;
        self.adapter.transfer(core::slice::from_mut(&mut msg))?;
        buf.copy_from_slice(msg.data());
        Ok(())
    }

    /// Write `reg` byte then read `len` bytes (combined write+read).
    pub fn write_read(&mut self, addr: I2cAddress, reg: u8, buf: &mut [u8]) -> Result<()> {
        let mut write_msg = I2cMsg::write(addr, &[reg])?;
        let read_msg = I2cMsg::read(addr, buf.len())?;
        write_msg.repeated_start = true;
        let msgs = &mut [write_msg, read_msg];
        self.adapter.transfer(msgs)?;
        buf.copy_from_slice(msgs[1].data());
        Ok(())
    }

    // -----------------------------------------------------------------------
    // SMBus helpers
    // -----------------------------------------------------------------------

    /// SMBus: read a single byte from `command` register.
    pub fn smbus_read_byte(&mut self, addr: u8, command: u8) -> Result<u8> {
        let mut buf = [0u8; 1];
        self.write_read(I2cAddress::SevenBit(addr), command, &mut buf)?;
        Ok(buf[0])
    }

    /// SMBus: write a single byte to `command` register.
    pub fn smbus_write_byte(&mut self, addr: u8, command: u8, value: u8) -> Result<()> {
        self.write(I2cAddress::SevenBit(addr), &[command, value])
    }

    /// SMBus: read a 16-bit word (little-endian) from `command`.
    pub fn smbus_read_word(&mut self, addr: u8, command: u8) -> Result<u16> {
        let mut buf = [0u8; 2];
        self.write_read(I2cAddress::SevenBit(addr), command, &mut buf)?;
        Ok(u16::from_le_bytes([buf[0], buf[1]]))
    }

    /// SMBus: write a 16-bit word (little-endian) to `command`.
    pub fn smbus_write_word(&mut self, addr: u8, command: u8, value: u16) -> Result<()> {
        let bytes = value.to_le_bytes();
        self.write(I2cAddress::SevenBit(addr), &[command, bytes[0], bytes[1]])
    }

    /// SMBus: read a block of up to 32 bytes from `command`.
    ///
    /// The first byte returned by the device is the block length.
    pub fn smbus_read_block(&mut self, addr: u8, command: u8, buf: &mut [u8]) -> Result<usize> {
        let max = buf.len().min(SMBUS_MAX_BLOCK);
        let mut tmp = [0u8; SMBUS_MAX_BLOCK + 1];
        self.write_read(I2cAddress::SevenBit(addr), command, &mut tmp[..max + 1])?;
        let len = (tmp[0] as usize).min(max);
        buf[..len].copy_from_slice(&tmp[1..1 + len]);
        Ok(len)
    }

    /// SMBus: write a block of up to 32 bytes to `command`.
    ///
    /// Prefixes data with `command` and block length byte.
    pub fn smbus_write_block(&mut self, addr: u8, command: u8, data: &[u8]) -> Result<()> {
        if data.len() > SMBUS_MAX_BLOCK {
            return Err(Error::InvalidArgument);
        }
        let mut buf = [0u8; SMBUS_MAX_BLOCK + 2];
        buf[0] = command;
        buf[1] = data.len() as u8;
        buf[2..2 + data.len()].copy_from_slice(data);
        self.write(I2cAddress::SevenBit(addr), &buf[..2 + data.len()])
    }

    /// SMBus: process call — write 2-byte `value`, read 2-byte result.
    pub fn smbus_process_call(&mut self, addr: u8, command: u8, value: u16) -> Result<u16> {
        let vb = value.to_le_bytes();
        let mut write_msg = I2cMsg::write(I2cAddress::SevenBit(addr), &[command, vb[0], vb[1]])?;
        let read_msg = I2cMsg::read(I2cAddress::SevenBit(addr), 2)?;
        write_msg.repeated_start = true;
        let msgs = &mut [write_msg, read_msg];
        self.adapter.transfer(msgs)?;
        let rb = msgs[1].data();
        if rb.len() < 2 {
            return Err(Error::IoError);
        }
        Ok(u16::from_le_bytes([rb[0], rb[1]]))
    }

    /// Execute a raw [`SmBusTransaction`].
    ///
    /// Translates the transaction kind into the appropriate I2C messages.
    pub fn smbus_execute(&mut self, txn: &mut SmBusTransaction) -> Result<()> {
        match txn.kind {
            SmBusTransactionKind::WriteByte => {
                self.smbus_write_byte(txn.addr, txn.command, txn.data[0])
            }
            SmBusTransactionKind::ReadByte => {
                txn.data[0] = self.smbus_read_byte(txn.addr, txn.command)?;
                txn.data_len = 1;
                Ok(())
            }
            SmBusTransactionKind::WriteWord => {
                let w = u16::from_le_bytes([txn.data[0], txn.data[1]]);
                self.smbus_write_word(txn.addr, txn.command, w)
            }
            SmBusTransactionKind::ReadWord => {
                let w = self.smbus_read_word(txn.addr, txn.command)?;
                let bytes = w.to_le_bytes();
                txn.data[0] = bytes[0];
                txn.data[1] = bytes[1];
                txn.data_len = 2;
                Ok(())
            }
            SmBusTransactionKind::WriteBlock => {
                self.smbus_write_block(txn.addr, txn.command, txn.data())?;
                Ok(())
            }
            SmBusTransactionKind::ReadBlock => {
                let n = self.smbus_read_block(txn.addr, txn.command, &mut txn.data)?;
                txn.data_len = n;
                Ok(())
            }
            SmBusTransactionKind::ProcessCall => {
                let v = u16::from_le_bytes([txn.data[0], txn.data[1]]);
                let result = self.smbus_process_call(txn.addr, txn.command, v)?;
                let rb = result.to_le_bytes();
                txn.data[0] = rb[0];
                txn.data[1] = rb[1];
                txn.data_len = 2;
                Ok(())
            }
            SmBusTransactionKind::SendByte => {
                self.write(I2cAddress::SevenBit(txn.addr), &[txn.command])
            }
            SmBusTransactionKind::Quick | SmBusTransactionKind::BlockProcessCall => {
                Err(Error::NotImplemented)
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Stub adapter (for testing and no-hardware builds)
// ---------------------------------------------------------------------------

/// A no-operation I2C adapter that always NACKs.
///
/// Useful as a placeholder when the real controller driver is absent.
pub struct NullAdapter;

impl I2cAdapter for NullAdapter {
    fn transfer(&mut self, _msgs: &mut [I2cMsg]) -> Result<usize> {
        Err(Error::IoError)
    }

    fn max_speed_hz(&self) -> u32 {
        I2C_SPEED_STANDARD
    }
}

// ---------------------------------------------------------------------------
// I2cBusRegistry
// ---------------------------------------------------------------------------

/// Registry of I2C bus numbers to bus IDs.
///
/// Stores bus metadata without owning the adapter (adapters are stored
/// in driver-specific structures).
#[derive(Debug, Clone, Copy, Default)]
pub struct I2cBusInfo {
    /// Logical bus number.
    pub bus_id: u8,
    /// Current speed setting.
    pub speed_hz: u32,
    /// Whether 10-bit addressing is active.
    pub ten_bit: bool,
    /// Human-readable name (null-terminated, max 16 bytes).
    pub name: [u8; 16],
}

impl I2cBusInfo {
    /// Create new bus info.
    pub const fn new(bus_id: u8, speed_hz: u32) -> Self {
        Self {
            bus_id,
            speed_hz,
            ten_bit: false,
            name: [0u8; 16],
        }
    }
}

// ---------------------------------------------------------------------------
// I2C client flags
// ---------------------------------------------------------------------------

/// I2C client flag: use 10-bit addressing.
pub const I2C_CLIENT_TEN: u16 = 0x0001;

/// I2C client flag: device is a PEC-capable SMBus device.
pub const I2C_CLIENT_PEC: u16 = 0x0004;

/// I2C client flag: do not use SMBus PEC for this client.
pub const I2C_CLIENT_SCCB: u16 = 0x0008;

/// I2C client flag: device cannot be detected (manual instantiation only).
pub const I2C_CLIENT_NO_PROBE: u16 = 0x0010;

/// I2C client flag: device is wake-capable.
pub const I2C_CLIENT_WAKE: u16 = 0x0100;

// ---------------------------------------------------------------------------
// I2cClient
// ---------------------------------------------------------------------------

/// Maximum length of an I2C client driver name.
pub const I2C_CLIENT_NAME_LEN: usize = 20;

/// An I2C client device — a device attached to an I2C bus at a given address.
///
/// Corresponds to Linux `struct i2c_client`.
#[derive(Debug, Clone, Copy)]
pub struct I2cClient {
    /// 7-bit device address (or 10-bit if `I2C_CLIENT_TEN` is set).
    pub addr: u16,
    /// Client flags (see `I2C_CLIENT_*` constants).
    pub flags: u16,
    /// Bus ID this client is on.
    pub bus_id: u8,
    /// Human-readable driver/device name (null-padded ASCII).
    pub name: [u8; I2C_CLIENT_NAME_LEN],
    /// Whether this client has been successfully probed/bound.
    pub bound: bool,
    /// IRQ number assigned to this client (0 = none).
    pub irq: u32,
}

impl I2cClient {
    /// Creates a new I2C client.
    pub const fn new(addr: u16, bus_id: u8) -> Self {
        Self {
            addr,
            flags: 0,
            bus_id,
            name: [0u8; I2C_CLIENT_NAME_LEN],
            bound: false,
            irq: 0,
        }
    }

    /// Sets the client name from a byte slice (truncated to `I2C_CLIENT_NAME_LEN`).
    pub fn set_name(&mut self, name: &[u8]) {
        let len = name.len().min(I2C_CLIENT_NAME_LEN);
        self.name[..len].copy_from_slice(&name[..len]);
    }

    /// Returns whether this client uses 10-bit addressing.
    pub fn is_ten_bit(&self) -> bool {
        self.flags & I2C_CLIENT_TEN != 0
    }

    /// Returns whether PEC is enabled for this client.
    pub fn pec_enabled(&self) -> bool {
        self.flags & I2C_CLIENT_PEC != 0
    }

    /// Returns the I2C address as an `I2cAddress`.
    pub fn i2c_address(&self) -> I2cAddress {
        if self.is_ten_bit() {
            I2cAddress::TenBit(self.addr)
        } else {
            I2cAddress::SevenBit(self.addr as u8)
        }
    }
}

// ---------------------------------------------------------------------------
// I2cClientRegistry
// ---------------------------------------------------------------------------

/// Maximum number of I2C client devices registered per bus.
pub const MAX_CLIENTS_PER_BUS: usize = 32;

/// Maximum number of I2C client registries (one per bus).
pub const MAX_CLIENT_REGISTRIES: usize = MAX_BUS_COUNT;

/// Per-bus I2C client registry.
pub struct I2cClientRegistry {
    /// Bus ID this registry belongs to.
    pub bus_id: u8,
    clients: [Option<I2cClient>; MAX_CLIENTS_PER_BUS],
    count: usize,
}

impl I2cClientRegistry {
    /// Creates an empty registry for `bus_id`.
    pub const fn new(bus_id: u8) -> Self {
        const EMPTY: Option<I2cClient> = None;
        Self {
            bus_id,
            clients: [EMPTY; MAX_CLIENTS_PER_BUS],
            count: 0,
        }
    }

    /// Registers a client device.
    ///
    /// # Errors
    ///
    /// Returns [`Error::AlreadyExists`] if the address is already registered,
    /// or [`Error::OutOfMemory`] if the registry is full.
    pub fn register(&mut self, client: I2cClient) -> Result<usize> {
        for entry in self.clients[..self.count].iter() {
            if let Some(c) = entry {
                if c.addr == client.addr
                    && c.flags & I2C_CLIENT_TEN == client.flags & I2C_CLIENT_TEN
                {
                    return Err(Error::AlreadyExists);
                }
            }
        }
        if self.count >= MAX_CLIENTS_PER_BUS {
            return Err(Error::OutOfMemory);
        }
        let idx = self.count;
        self.clients[idx] = Some(client);
        self.count += 1;
        Ok(idx)
    }

    /// Unregisters the client at `addr`.
    pub fn unregister(&mut self, addr: u16) -> Result<()> {
        for i in 0..self.count {
            if self.clients[i].map_or(false, |c| c.addr == addr) {
                for j in i..self.count - 1 {
                    self.clients[j] = self.clients[j + 1];
                }
                self.clients[self.count - 1] = None;
                self.count -= 1;
                return Ok(());
            }
        }
        Err(Error::NotFound)
    }

    /// Returns a reference to the client at `addr`.
    pub fn find(&self, addr: u16) -> Option<&I2cClient> {
        self.clients[..self.count]
            .iter()
            .find_map(|e| e.as_ref().filter(|c| c.addr == addr))
    }

    /// Returns a mutable reference to the client at `addr`.
    pub fn find_mut(&mut self, addr: u16) -> Option<&mut I2cClient> {
        self.clients[..self.count]
            .iter_mut()
            .find_map(|e| e.as_mut().filter(|c| c.addr == addr))
    }

    /// Returns the number of registered clients.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Returns true if no clients are registered.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Iterates over registered clients.
    pub fn iter(&self) -> impl Iterator<Item = &I2cClient> {
        self.clients[..self.count].iter().filter_map(|e| e.as_ref())
    }
}

// ---------------------------------------------------------------------------
// Bus scan and device detection
// ---------------------------------------------------------------------------

/// Result of probing a single I2C address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeResult {
    /// Device responded (ACK).
    Ack,
    /// No device at this address (NACK or timeout).
    Nack,
    /// Address is in a reserved range and was not probed.
    Skipped,
}

/// Address ranges reserved by the I2C specification (not to be probed).
///
/// - 0x00: general call
/// - 0x01–0x07: reserved
/// - 0x78–0x7F: 10-bit address prefix
const RESERVED_LOW: u8 = 0x08;
const RESERVED_HIGH: u8 = 0x77;

/// Checks whether `addr` is in the probing-safe range.
pub fn is_probeable_address(addr: u8) -> bool {
    addr >= RESERVED_LOW && addr <= RESERVED_HIGH
}

/// Probes a single 7-bit address by sending an SMBus Quick Write.
///
/// Returns `ProbeResult::Ack` if the device responds, `Nack` if not,
/// or `Skipped` for reserved addresses.
pub fn probe_address<A: I2cAdapter>(adapter: &mut A, addr: u8) -> ProbeResult {
    if !is_probeable_address(addr) {
        return ProbeResult::Skipped;
    }
    // SMBus Quick Write: address byte only (write direction), no data.
    let data: &[u8] = &[];
    let msg = match I2cMsg::write(I2cAddress::SevenBit(addr), data) {
        Ok(m) => m,
        Err(_) => return ProbeResult::Nack,
    };
    let mut msgs = [msg];
    match adapter.transfer(&mut msgs) {
        Ok(_) => ProbeResult::Ack,
        Err(_) => ProbeResult::Nack,
    }
}

/// Scans all probeable 7-bit I2C addresses (0x08–0x77).
///
/// Fills `results` with one entry per address and returns the number
/// of addresses that responded with ACK.
///
/// `results` must have at least 120 entries (0x08..=0x77).
pub fn bus_scan<A: I2cAdapter>(adapter: &mut A, results: &mut [(u8, ProbeResult)]) -> usize {
    let mut ack_count = 0usize;
    let mut out_idx = 0usize;
    for addr in RESERVED_LOW..=RESERVED_HIGH {
        let result = probe_address(adapter, addr);
        if result == ProbeResult::Ack {
            ack_count += 1;
        }
        if out_idx < results.len() {
            results[out_idx] = (addr, result);
            out_idx += 1;
        }
    }
    ack_count
}

// ---------------------------------------------------------------------------
// SMBus Alert Response Address (ARA)
// ---------------------------------------------------------------------------

/// SMBus Alert Response Address.
///
/// When a device asserts SMBALERT#, the host sends a Quick Read to this
/// special broadcast address (0x0C). The alerting device ACKs and returns
/// its own address.
pub const SMBUS_ALERT_RESPONSE_ADDR: u8 = 0x0C;

/// Maximum number of alerting devices that can respond in one poll.
pub const SMBUS_MAX_ALERT_DEVICES: usize = 8;

/// Result of an SMBus alert response poll.
#[derive(Debug, Clone, Copy)]
pub struct AlertResponse {
    /// Address of the device that asserted SMBALERT#.
    pub device_addr: u8,
    /// Whether the device flagged an alert (bit 0 of the response byte).
    pub alert_flag: bool,
}

impl<A: I2cAdapter> I2cBus<A> {
    // -----------------------------------------------------------------------
    // SMBus Quick command
    // -----------------------------------------------------------------------

    /// SMBus Quick command: sends address + R/W bit only, no data.
    ///
    /// Used to detect device presence or to trigger a simple action
    /// (e.g., power toggle on some devices).
    pub fn smbus_quick(&mut self, addr: u8, read: bool) -> Result<()> {
        // A Quick command is an I2C START + address byte + STOP.
        // We model it as a zero-length write (or read).
        let empty: &[u8] = &[];
        if read {
            let mut msg = I2cMsg::read(I2cAddress::SevenBit(addr), 0)?;
            self.adapter.transfer(core::slice::from_mut(&mut msg))?;
        } else {
            let mut msg = I2cMsg::write(I2cAddress::SevenBit(addr), empty)?;
            self.adapter.transfer(core::slice::from_mut(&mut msg))?;
        }
        Ok(())
    }

    // -----------------------------------------------------------------------
    // SMBus Send/Receive Byte (no command register)
    // -----------------------------------------------------------------------

    /// SMBus Send Byte: sends a single byte to `addr` with no command byte.
    pub fn smbus_send_byte(&mut self, addr: u8, value: u8) -> Result<()> {
        self.write(I2cAddress::SevenBit(addr), &[value])
    }

    /// SMBus Receive Byte: reads a single byte from `addr` with no command byte.
    pub fn smbus_receive_byte(&mut self, addr: u8) -> Result<u8> {
        let mut buf = [0u8; 1];
        self.read(I2cAddress::SevenBit(addr), &mut buf)?;
        Ok(buf[0])
    }

    // -----------------------------------------------------------------------
    // I2C block data (raw I2C, not SMBus block — no length byte)
    // -----------------------------------------------------------------------

    /// I2C block write: writes `command` followed by `data` (no length byte).
    ///
    /// This differs from SMBus block write in that no count byte is prepended.
    pub fn i2c_block_write(&mut self, addr: u8, command: u8, data: &[u8]) -> Result<()> {
        if data.len() > MAX_TRANSFER_SIZE - 1 {
            return Err(Error::InvalidArgument);
        }
        let mut buf = [0u8; MAX_TRANSFER_SIZE];
        buf[0] = command;
        buf[1..1 + data.len()].copy_from_slice(data);
        self.write(I2cAddress::SevenBit(addr), &buf[..1 + data.len()])
    }

    /// I2C block read: writes `command`, then reads `len` bytes (no length byte).
    pub fn i2c_block_read(&mut self, addr: u8, command: u8, buf: &mut [u8]) -> Result<()> {
        self.write_read(I2cAddress::SevenBit(addr), command, buf)
    }

    // -----------------------------------------------------------------------
    // SMBus Block Process Call
    // -----------------------------------------------------------------------

    /// SMBus Block Process Call: write block, receive block in one transaction.
    ///
    /// Sends `command` + length + `write_data`, then reads a length-prefixed
    /// block from the device. Returns the number of bytes read.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if write data exceeds `SMBUS_MAX_BLOCK`.
    pub fn smbus_block_process_call(
        &mut self,
        addr: u8,
        command: u8,
        write_data: &[u8],
        read_buf: &mut [u8],
    ) -> Result<usize> {
        if write_data.len() > SMBUS_MAX_BLOCK {
            return Err(Error::InvalidArgument);
        }
        // Build write message: command + count + data.
        let mut wbuf = [0u8; SMBUS_MAX_BLOCK + 2];
        wbuf[0] = command;
        wbuf[1] = write_data.len() as u8;
        wbuf[2..2 + write_data.len()].copy_from_slice(write_data);
        let wlen = 2 + write_data.len();

        // Read back: length byte + up to SMBUS_MAX_BLOCK bytes.
        let rlen = read_buf.len().min(SMBUS_MAX_BLOCK) + 1;
        let _rbuf = [0u8; SMBUS_MAX_BLOCK + 1];

        let mut write_msg = I2cMsg::write(I2cAddress::SevenBit(addr), &wbuf[..wlen])?;
        let read_msg = I2cMsg::read(I2cAddress::SevenBit(addr), rlen)?;
        write_msg.repeated_start = true;
        let msgs = &mut [write_msg, read_msg];
        self.adapter.transfer(msgs)?;

        let resp = msgs[1].data();
        let count = if resp.is_empty() { 0 } else { resp[0] as usize };
        let actual = count.min(read_buf.len()).min(SMBUS_MAX_BLOCK);
        if actual > 0 && resp.len() > actual {
            read_buf[..actual].copy_from_slice(&resp[1..1 + actual]);
        }
        Ok(actual)
    }

    // -----------------------------------------------------------------------
    // SMBus Alert Response
    // -----------------------------------------------------------------------

    /// Polls the SMBus Alert Response Address (0x0C).
    ///
    /// Reads one byte from ARA. If a device is asserting SMBALERT#, it
    /// will ACK and return its address (bits [7:1]) and alert flag (bit 0).
    ///
    /// Returns `Ok(AlertResponse)` if a device responded, or
    /// `Err(IoError)` if no device is alerting.
    pub fn smbus_poll_alert(&mut self) -> Result<AlertResponse> {
        let mut buf = [0u8; 1];
        self.read(I2cAddress::SevenBit(SMBUS_ALERT_RESPONSE_ADDR), &mut buf)?;
        let device_addr = buf[0] >> 1;
        let alert_flag = buf[0] & 0x01 != 0;
        Ok(AlertResponse {
            device_addr,
            alert_flag,
        })
    }

    /// Polls the SMBus ARA up to `max_devices` times, collecting all alerting
    /// devices into `responses`. Returns the number of responses collected.
    pub fn smbus_poll_all_alerts(
        &mut self,
        responses: &mut [AlertResponse; SMBUS_MAX_ALERT_DEVICES],
    ) -> usize {
        let mut count = 0usize;
        while count < SMBUS_MAX_ALERT_DEVICES {
            match self.smbus_poll_alert() {
                Ok(resp) => {
                    responses[count] = resp;
                    count += 1;
                }
                Err(_) => break,
            }
        }
        count
    }

    // -----------------------------------------------------------------------
    // Extended smbus_execute (Quick + BlockProcessCall)
    // -----------------------------------------------------------------------

    /// Execute a raw [`SmBusTransaction`] including Quick and BlockProcessCall.
    ///
    /// Complements `smbus_execute`, handling the two previously unimplemented
    /// variants.
    pub fn smbus_execute_ext(
        &mut self,
        txn: &mut SmBusTransaction,
        read_buf: &mut [u8; SMBUS_MAX_BLOCK],
    ) -> Result<()> {
        match txn.kind {
            SmBusTransactionKind::Quick => {
                // value in data[0]: 0=write, 1=read
                self.smbus_quick(txn.addr, txn.data[0] != 0)
            }
            SmBusTransactionKind::BlockProcessCall => {
                let n =
                    self.smbus_block_process_call(txn.addr, txn.command, txn.data(), read_buf)?;
                txn.data[..n].copy_from_slice(&read_buf[..n]);
                txn.data_len = n;
                Ok(())
            }
            // All other variants are handled by smbus_execute.
            _ => self.smbus_execute(txn),
        }
    }

    // -----------------------------------------------------------------------
    // Bus scan
    // -----------------------------------------------------------------------

    /// Scans all probeable 7-bit addresses on this bus.
    ///
    /// Returns a bitmap of responding addresses (bit N set = address N ACKed).
    /// The returned array covers addresses 0x00–0x7F (8 bytes × 8 bits).
    pub fn scan(&mut self) -> [u8; 16] {
        let mut bitmap = [0u8; 16];
        for addr in RESERVED_LOW..=RESERVED_HIGH {
            let result = probe_address(&mut self.adapter, addr);
            if result == ProbeResult::Ack {
                let byte_idx = addr as usize / 8;
                let bit_idx = addr % 8;
                bitmap[byte_idx] |= 1 << bit_idx;
            }
        }
        bitmap
    }

    /// Scans the bus and registers all detected clients in `registry`.
    ///
    /// Skips addresses that are already registered.
    pub fn scan_and_register(&mut self, registry: &mut I2cClientRegistry) -> usize {
        let mut found = 0usize;
        for addr in RESERVED_LOW..=RESERVED_HIGH {
            if registry.find(addr as u16).is_some() {
                continue;
            }
            let result = probe_address(&mut self.adapter, addr);
            if result == ProbeResult::Ack {
                let client = I2cClient::new(addr as u16, self.bus_id);
                if registry.register(client).is_ok() {
                    found += 1;
                }
            }
        }
        found
    }
}

/// Global I2C bus registry.
pub struct I2cBusRegistry {
    buses: [Option<I2cBusInfo>; MAX_BUS_COUNT],
    len: usize,
}

impl I2cBusRegistry {
    /// Create an empty registry.
    pub const fn new() -> Self {
        Self {
            buses: [const { None }; MAX_BUS_COUNT],
            len: 0,
        }
    }

    /// Register a new bus.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the registry is full, or
    /// [`Error::AlreadyExists`] if the bus ID is already registered.
    pub fn register(&mut self, info: I2cBusInfo) -> Result<()> {
        if self.find(info.bus_id).is_some() {
            return Err(Error::AlreadyExists);
        }
        if self.len >= MAX_BUS_COUNT {
            return Err(Error::OutOfMemory);
        }
        self.buses[self.len] = Some(info);
        self.len += 1;
        Ok(())
    }

    /// Find a bus by its ID.
    pub fn find(&self, bus_id: u8) -> Option<&I2cBusInfo> {
        for i in 0..self.len {
            if let Some(ref b) = self.buses[i] {
                if b.bus_id == bus_id {
                    return Some(b);
                }
            }
        }
        None
    }

    /// Number of registered buses.
    pub fn len(&self) -> usize {
        self.len
    }

    /// Whether the registry is empty.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Iterate over registered buses.
    pub fn iter(&self) -> impl Iterator<Item = &I2cBusInfo> {
        self.buses[..self.len].iter().filter_map(|b| b.as_ref())
    }
}
