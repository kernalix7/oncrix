// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! I2C core subsystem base.
//!
//! Provides I2C adapter registration, client device binding, message
//! transfer, SMBus compatibility (byte/word/block), bus recovery, and
//! adapter locking. Modeled after Linux `drivers/i2c/i2c-core-base.c`.
//!
//! # Architecture
//!
//! - [`I2cAdapter`] — represents a physical I2C controller/bus.
//! - [`I2cClient`] — a slave device on an adapter at a 7-bit address.
//! - [`I2cMsg`] — a single read or write transaction.
//! - [`I2cAdapterRegistry`] — global table of registered adapters.
//!
//! SMBus operations are emulated via plain I2C messages when the adapter
//! does not declare native SMBus support.

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum number of registered I2C adapters.
const MAX_ADAPTERS: usize = 16;

/// Maximum number of client devices per adapter.
const MAX_CLIENTS: usize = 32;

/// Maximum length of an SMBus block data payload.
pub const SMBUS_BLOCK_MAX: usize = 32;

/// Maximum length of an I2C message data buffer.
pub const I2C_MSG_MAX_LEN: usize = 128;

/// I2C message flag: read direction (0 = write).
pub const I2C_M_RD: u16 = 0x0001;

/// I2C message flag: 10-bit address.
pub const I2C_M_TEN: u16 = 0x0010;

/// I2C message flag: no repeated start / STOP after this message.
pub const I2C_M_NOSTART: u16 = 0x4000;

// ---------------------------------------------------------------------------
// I2C Message
// ---------------------------------------------------------------------------

/// A single I2C transfer request.
#[derive(Debug, Clone, Copy)]
pub struct I2cMsg {
    /// 7-bit (or 10-bit with `I2C_M_TEN`) slave address.
    pub addr: u16,
    /// Transfer flags (combination of `I2C_M_*` constants).
    pub flags: u16,
    /// Number of data bytes to transfer.
    pub len: u16,
    /// Data buffer (valid bytes are `0..len`).
    pub buf: [u8; I2C_MSG_MAX_LEN],
}

impl I2cMsg {
    /// Create a write message.
    pub fn write(addr: u16, data: &[u8]) -> Result<Self> {
        if data.len() > I2C_MSG_MAX_LEN {
            return Err(Error::InvalidArgument);
        }
        let mut buf = [0u8; I2C_MSG_MAX_LEN];
        buf[..data.len()].copy_from_slice(data);
        Ok(Self {
            addr,
            flags: 0,
            len: data.len() as u16,
            buf,
        })
    }

    /// Create a read message (buffer filled by adapter).
    pub fn read(addr: u16, len: u16) -> Result<Self> {
        if len as usize > I2C_MSG_MAX_LEN {
            return Err(Error::InvalidArgument);
        }
        Ok(Self {
            addr,
            flags: I2C_M_RD,
            len,
            buf: [0u8; I2C_MSG_MAX_LEN],
        })
    }

    /// Returns `true` if this is a read message.
    pub fn is_read(&self) -> bool {
        self.flags & I2C_M_RD != 0
    }
}

// ---------------------------------------------------------------------------
// SMBus
// ---------------------------------------------------------------------------

/// SMBus transaction type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SmBusCmd {
    /// Read/write a single byte without a command byte.
    Quick,
    /// Read/write a single byte with a command byte.
    Byte,
    /// Read/write a 16-bit word.
    Word,
    /// Read/write up to 32 bytes.
    Block,
}

/// SMBus transaction descriptor.
#[derive(Debug, Clone, Copy)]
pub struct SmBusXfer {
    /// Slave address.
    pub addr: u16,
    /// Command byte (register address).
    pub command: u8,
    /// Transaction type.
    pub cmd: SmBusCmd,
    /// `true` for read, `false` for write.
    pub read_write: bool,
    /// Data (for write or filled on read).
    pub data: [u8; SMBUS_BLOCK_MAX + 1],
    /// Valid data length (for block transactions).
    pub len: u8,
}

impl SmBusXfer {
    /// Build an SMBus byte-read transaction.
    pub const fn byte_read(addr: u16, command: u8) -> Self {
        Self {
            addr,
            command,
            cmd: SmBusCmd::Byte,
            read_write: true,
            data: [0u8; SMBUS_BLOCK_MAX + 1],
            len: 1,
        }
    }

    /// Build an SMBus word-write transaction.
    pub fn word_write(addr: u16, command: u8, value: u16) -> Self {
        let mut data = [0u8; SMBUS_BLOCK_MAX + 1];
        data[0] = (value & 0xFF) as u8;
        data[1] = (value >> 8) as u8;
        Self {
            addr,
            command,
            cmd: SmBusCmd::Word,
            read_write: false,
            data,
            len: 2,
        }
    }
}

// ---------------------------------------------------------------------------
// Bus Recovery
// ---------------------------------------------------------------------------

/// Bus recovery information for an I2C adapter.
#[derive(Debug, Clone, Copy, Default)]
pub struct BusRecoveryInfo {
    /// Number of clock stretching cycles sent during recovery.
    pub clk_cycles_sent: u32,
    /// Number of recovery attempts performed.
    pub attempts: u32,
    /// Whether the last recovery succeeded.
    pub last_success: bool,
}

impl BusRecoveryInfo {
    /// Record a recovery attempt result.
    pub fn record(&mut self, clk_cycles: u32, success: bool) {
        self.clk_cycles_sent += clk_cycles;
        self.attempts += 1;
        self.last_success = success;
    }
}

// ---------------------------------------------------------------------------
// I2C Client
// ---------------------------------------------------------------------------

/// An I2C slave device registered on an adapter.
#[derive(Debug, Clone, Copy)]
pub struct I2cClient {
    /// 7-bit I2C address of this device.
    pub addr: u16,
    /// Adapter index this client is on.
    pub adapter_idx: usize,
    /// Device name / driver binding key (up to 15 chars + NUL).
    pub name: [u8; 16],
    /// Whether this client is currently active/bound.
    pub active: bool,
}

impl I2cClient {
    /// Create a new client entry.
    pub fn new(addr: u16, adapter_idx: usize, name: &[u8]) -> Result<Self> {
        if name.len() >= 16 {
            return Err(Error::InvalidArgument);
        }
        let mut buf = [0u8; 16];
        buf[..name.len()].copy_from_slice(name);
        Ok(Self {
            addr,
            adapter_idx,
            name: buf,
            active: true,
        })
    }
}

// ---------------------------------------------------------------------------
// I2C Adapter
// ---------------------------------------------------------------------------

/// Capabilities reported by an I2C adapter.
#[derive(Debug, Clone, Copy, Default)]
pub struct AdapterCaps {
    /// Adapter supports 10-bit addressing.
    pub ten_bit_addr: bool,
    /// Adapter supports native SMBus protocol.
    pub smbus_native: bool,
    /// Maximum transfer rate in kHz (e.g. 100, 400, 1000).
    pub max_khz: u32,
}

/// An I2C adapter (controller).
#[derive(Debug)]
pub struct I2cAdapter {
    /// Adapter index (assigned at registration).
    pub index: usize,
    /// Capabilities of this adapter.
    pub caps: AdapterCaps,
    /// Client devices registered on this bus.
    clients: [Option<I2cClient>; MAX_CLIENTS],
    /// Number of registered clients.
    client_count: usize,
    /// Bus recovery state.
    pub recovery: BusRecoveryInfo,
    /// Whether the adapter is locked for an exclusive transfer.
    locked: bool,
    /// Transfer count (for diagnostics).
    pub xfer_count: u64,
}

impl I2cAdapter {
    /// Create a new adapter at the given index.
    pub const fn new(index: usize, caps: AdapterCaps) -> Self {
        const NONE: Option<I2cClient> = None;
        Self {
            index,
            caps,
            clients: [NONE; MAX_CLIENTS],
            client_count: 0,
            recovery: BusRecoveryInfo {
                clk_cycles_sent: 0,
                attempts: 0,
                last_success: false,
            },
            locked: false,
            xfer_count: 0,
        }
    }

    /// Lock the adapter for exclusive access.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Busy`] if the adapter is already locked.
    pub fn lock(&mut self) -> Result<()> {
        if self.locked {
            return Err(Error::Busy);
        }
        self.locked = true;
        Ok(())
    }

    /// Unlock the adapter.
    pub fn unlock(&mut self) {
        self.locked = false;
    }

    /// Simulate an I2C transfer (validates messages and increments counter).
    ///
    /// In a real driver this would invoke the controller's hardware transfer
    /// routine. Here we validate arguments and track the call.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Busy`] if the adapter is not locked.
    /// Returns [`Error::InvalidArgument`] if `msgs` is empty or a message
    /// has zero length.
    pub fn transfer(&mut self, msgs: &mut [I2cMsg]) -> Result<()> {
        if !self.locked {
            return Err(Error::Busy);
        }
        if msgs.is_empty() {
            return Err(Error::InvalidArgument);
        }
        for msg in msgs.iter() {
            if msg.len == 0 {
                return Err(Error::InvalidArgument);
            }
        }
        self.xfer_count += msgs.len() as u64;
        Ok(())
    }

    /// Perform an SMBus transaction (emulated via plain I2C messages).
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotImplemented`] for unsupported SMBus commands.
    pub fn smbus_xfer(&mut self, xfer: &mut SmBusXfer) -> Result<()> {
        if !self.locked {
            return Err(Error::Busy);
        }
        match xfer.cmd {
            SmBusCmd::Quick => {
                // Just an address probe — one zero-length write.
                let _msg = I2cMsg::write(xfer.addr, &[])?;
                self.xfer_count += 1;
                Ok(())
            }
            SmBusCmd::Byte => {
                if xfer.read_write {
                    // Read: send command, receive 1 byte.
                    self.xfer_count += 2;
                    xfer.data[0] = 0; // placeholder; real hw fills this.
                } else {
                    self.xfer_count += 1;
                }
                Ok(())
            }
            SmBusCmd::Word => {
                self.xfer_count += 2;
                if xfer.read_write {
                    xfer.data[0] = 0;
                    xfer.data[1] = 0;
                }
                Ok(())
            }
            SmBusCmd::Block => {
                if xfer.len as usize > SMBUS_BLOCK_MAX {
                    return Err(Error::InvalidArgument);
                }
                self.xfer_count += 2;
                Ok(())
            }
        }
    }

    /// Register a client device on this adapter.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the client table is full.
    /// Returns [`Error::AlreadyExists`] if `addr` is already registered.
    pub fn register_client(&mut self, addr: u16, name: &[u8]) -> Result<usize> {
        for slot in self.clients.iter().flatten() {
            if slot.addr == addr {
                return Err(Error::AlreadyExists);
            }
        }
        let idx = self
            .clients
            .iter()
            .position(|s| s.is_none())
            .ok_or(Error::OutOfMemory)?;
        self.clients[idx] = Some(I2cClient::new(addr, self.index, name)?);
        self.client_count += 1;
        Ok(idx)
    }

    /// Unregister a client by address.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if no client with `addr` exists.
    pub fn unregister_client(&mut self, addr: u16) -> Result<()> {
        let idx = self
            .clients
            .iter()
            .position(|s| s.map_or(false, |c| c.addr == addr))
            .ok_or(Error::NotFound)?;
        self.clients[idx] = None;
        self.client_count -= 1;
        Ok(())
    }

    /// Perform bus recovery by sending up to 9 clock pulses.
    ///
    /// Returns `true` if the bus was recovered (SDA released).
    pub fn recover_bus(&mut self) -> bool {
        // Simulate: after 9 clocks the bus is assumed free.
        let cycles = 9u32;
        let success = true;
        self.recovery.record(cycles, success);
        success
    }

    /// Returns the number of registered clients.
    pub fn client_count(&self) -> usize {
        self.client_count
    }
}

// ---------------------------------------------------------------------------
// Adapter Registry
// ---------------------------------------------------------------------------

/// Global registry of I2C adapters.
pub struct I2cAdapterRegistry {
    adapters: [Option<I2cAdapter>; MAX_ADAPTERS],
    count: usize,
}

impl I2cAdapterRegistry {
    /// Create an empty registry.
    pub const fn new() -> Self {
        const NONE: Option<I2cAdapter> = None;
        Self {
            adapters: [NONE; MAX_ADAPTERS],
            count: 0,
        }
    }

    /// Register an adapter and return its assigned index.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the registry is full.
    pub fn register(&mut self, caps: AdapterCaps) -> Result<usize> {
        let idx = self
            .adapters
            .iter()
            .position(|s| s.is_none())
            .ok_or(Error::OutOfMemory)?;
        self.adapters[idx] = Some(I2cAdapter::new(idx, caps));
        self.count += 1;
        Ok(idx)
    }

    /// Get a mutable reference to an adapter by index.
    pub fn get_mut(&mut self, index: usize) -> Option<&mut I2cAdapter> {
        self.adapters.get_mut(index)?.as_mut()
    }

    /// Get an immutable reference to an adapter by index.
    pub fn get(&self, index: usize) -> Option<&I2cAdapter> {
        self.adapters.get(index)?.as_ref()
    }

    /// Returns the total number of registered adapters.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Returns `true` if no adapters are registered.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
}

impl Default for I2cAdapterRegistry {
    fn default() -> Self {
        Self::new()
    }
}
