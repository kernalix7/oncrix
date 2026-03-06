// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! ACPI Embedded Controller (EC) interface driver.
//!
//! Implements the ACPI Embedded Controller interface defined in the
//! ACPI Specification §12.3. The EC is a microcontroller embedded
//! in laptops and desktops that manages battery, thermal, lid,
//! keyboard backlight, and many other platform functions.
//!
//! # Architecture
//!
//! The host communicates with the EC via two I/O port pairs:
//! - **Command/Status port** (e.g. `0x66` / `0x62`): the host writes
//!   commands and reads status; the EC reads commands and writes status.
//! - **Data port** (e.g. `0x62`): used to exchange single bytes.
//!
//! Each transaction follows:
//! 1. Wait for IBF (Input Buffer Full, bit 1) to be clear.
//! 2. Write the command byte to the command port.
//! 3. For write transactions: wait for IBF clear, write the address;
//!    wait for IBF clear, write the data byte.
//! 4. For read transactions: wait for IBF clear, write the address;
//!    wait for OBF (Output Buffer Full, bit 0) to be set, read the
//!    data byte from the data port.
//!
//! # Burst Mode
//!
//! When burst mode is enabled, the EC holds off SCI events while
//! the host performs a multi-byte block transfer. The host issues
//! `BurstEnable`, performs reads/writes, then issues `BurstDisable`.
//!
//! Reference: ACPI Specification 6.5, §12.3.

use oncrix_lib::{Error, Result};

#[cfg(target_arch = "x86_64")]
use crate::power::{inb, outb};

// ── Status register bit positions ─────────────────────────────

/// OBF — Output Buffer Full (EC→host data available, bit 0).
pub const EC_STATUS_OBF: u8 = 1 << 0;

/// IBF — Input Buffer Full (host data pending, bit 1).
pub const EC_STATUS_IBF: u8 = 1 << 1;

/// CMD — Command/Data flag (1=command, 0=data, bit 3).
pub const EC_STATUS_CMD: u8 = 1 << 3;

/// BURST — EC is in burst mode (bit 4).
pub const EC_STATUS_BURST: u8 = 1 << 4;

/// SCI_EVT — EC event pending (bit 5).
pub const EC_STATUS_SCI_EVT: u8 = 1 << 5;

// ── EC commands ───────────────────────────────────────────────

/// EC command opcodes (ACPI spec §12.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EcCommand {
    /// Read a byte from EC address space (0x80).
    Read,
    /// Write a byte to EC address space (0x81).
    Write,
    /// Enter burst mode (0x82).
    BurstEnable,
    /// Exit burst mode (0x83).
    BurstDisable,
    /// Query current event code (0x84).
    Query,
}

impl EcCommand {
    /// Return the raw byte value for the command.
    pub fn opcode(self) -> u8 {
        match self {
            Self::Read => 0x80,
            Self::Write => 0x81,
            Self::BurstEnable => 0x82,
            Self::BurstDisable => 0x83,
            Self::Query => 0x84,
        }
    }
}

// ── EC register set ───────────────────────────────────────────

/// EC I/O port addresses and cached status.
#[derive(Debug, Clone, Copy)]
pub struct EcRegisters {
    /// Command/status port (write command, read status).
    pub command_port: u16,
    /// Data port (bidirectional data exchange).
    pub data_port: u16,
    /// Cached status byte from last poll.
    pub status_cache: u8,
}

impl Default for EcRegisters {
    fn default() -> Self {
        Self::new()
    }
}

impl EcRegisters {
    /// Create an EC register set with the standard ACPI ports
    /// (command=0x66, data=0x62).
    pub const fn new() -> Self {
        Self {
            command_port: 0x66,
            data_port: 0x62,
            status_cache: 0,
        }
    }

    /// Create an EC register set with custom port addresses.
    pub const fn with_ports(command_port: u16, data_port: u16) -> Self {
        Self {
            command_port,
            data_port,
            status_cache: 0,
        }
    }
}

// ── EC event handler ──────────────────────────────────────────

/// A registered EC event handler.
///
/// The EC reports events by returning a non-zero query value when
/// SCI_EVT is set. Each query value maps to a handler callback
/// index, which the platform uses to dispatch the event.
#[derive(Debug, Clone, Copy)]
pub struct EcEventHandler {
    /// EC query value that triggers this handler (1–255).
    pub query_value: u8,
    /// Handler callback index (platform-defined dispatch table).
    pub handler_idx: u8,
    /// Whether this handler slot is occupied.
    pub active: bool,
}

impl Default for EcEventHandler {
    fn default() -> Self {
        Self::new()
    }
}

impl EcEventHandler {
    /// Create an empty handler entry.
    pub const fn new() -> Self {
        Self {
            query_value: 0,
            handler_idx: 0,
            active: false,
        }
    }
}

// ── Poll timeout ──────────────────────────────────────────────

/// Maximum busy-wait iterations for EC status polling.
const EC_POLL_TIMEOUT: u32 = 100_000;

/// Maximum number of event handlers per EC.
const MAX_EC_HANDLERS: usize = 32;

// ── Single EC device ──────────────────────────────────────────

/// A single ACPI Embedded Controller device.
///
/// Manages register access, burst mode, event dispatch, and per-EC
/// statistics for one physical EC.
pub struct AcpiEc {
    /// I/O port configuration.
    pub registers: EcRegisters,
    /// Registered event handlers.
    handlers: [EcEventHandler; MAX_EC_HANDLERS],
    /// Number of registered handlers.
    handler_count: usize,
    /// Whether burst mode is currently active.
    pub burst_mode: bool,
    /// Transaction lock flag — prevents re-entrant transactions.
    transaction_active: bool,
    /// Total transactions completed.
    pub transactions: u64,
    /// Total query (SCI) events processed.
    pub query_events: u64,
    /// Total poll timeouts (IBF/OBF timeout errors).
    pub timeouts: u64,
    /// Number of burst-mode enters.
    pub burst_enters: u64,
    /// Whether this EC slot is in use.
    pub active: bool,
}

impl Default for AcpiEc {
    fn default() -> Self {
        Self::new()
    }
}

impl AcpiEc {
    /// Create an EC device using standard ACPI ports (0x66/0x62).
    pub fn new() -> Self {
        Self {
            registers: EcRegisters::new(),
            handlers: [const { EcEventHandler::new() }; MAX_EC_HANDLERS],
            handler_count: 0,
            burst_mode: false,
            transaction_active: false,
            transactions: 0,
            query_events: 0,
            timeouts: 0,
            burst_enters: 0,
            active: false,
        }
    }

    /// Create an EC device with custom I/O port addresses.
    pub fn with_ports(command_port: u16, data_port: u16) -> Self {
        let mut ec = Self::new();
        ec.registers = EcRegisters::with_ports(command_port, data_port);
        ec
    }

    // ── Low-level port I/O ───────────────────────────────────

    /// Read the EC status register.
    #[cfg(target_arch = "x86_64")]
    fn read_status(&mut self) -> u8 {
        let status = inb(self.registers.command_port);
        self.registers.status_cache = status;
        status
    }

    /// Write a command byte to the EC command port.
    #[cfg(target_arch = "x86_64")]
    fn write_command(&self, cmd: u8) {
        outb(self.registers.command_port, cmd);
    }

    /// Read a data byte from the EC data port.
    #[cfg(target_arch = "x86_64")]
    fn read_data(&self) -> u8 {
        inb(self.registers.data_port)
    }

    /// Write a data byte to the EC data port.
    #[cfg(target_arch = "x86_64")]
    fn write_data(&self, data: u8) {
        outb(self.registers.data_port, data);
    }

    // ── Status polling ───────────────────────────────────────

    /// Poll until the IBF (Input Buffer Full) bit clears.
    ///
    /// Returns `Ok(())` when IBF is clear, or [`Error::Busy`] on
    /// timeout.
    #[cfg(target_arch = "x86_64")]
    fn wait_ibf_clear(&mut self) -> Result<()> {
        let mut retries = EC_POLL_TIMEOUT;
        loop {
            if self.read_status() & EC_STATUS_IBF == 0 {
                return Ok(());
            }
            retries = retries.saturating_sub(1);
            if retries == 0 {
                self.timeouts += 1;
                return Err(Error::Busy);
            }
        }
    }

    /// Poll until the OBF (Output Buffer Full) bit is set.
    ///
    /// Returns the data byte once available, or [`Error::Busy`] on
    /// timeout.
    #[cfg(target_arch = "x86_64")]
    fn wait_obf_set(&mut self) -> Result<u8> {
        let mut retries = EC_POLL_TIMEOUT;
        loop {
            if self.read_status() & EC_STATUS_OBF != 0 {
                return Ok(self.read_data());
            }
            retries = retries.saturating_sub(1);
            if retries == 0 {
                self.timeouts += 1;
                return Err(Error::Busy);
            }
        }
    }

    // ── Public transaction API ───────────────────────────────

    /// Read a byte from EC address `addr`.
    ///
    /// Issues the `Read` command (0x80), sends the address byte,
    /// and waits for the data byte.
    ///
    /// # Errors
    ///
    /// - [`Error::Busy`] if the EC does not respond within the
    ///   timeout period or a transaction is already in progress.
    #[cfg(target_arch = "x86_64")]
    pub fn read_byte(&mut self, addr: u8) -> Result<u8> {
        if self.transaction_active {
            return Err(Error::Busy);
        }
        self.transaction_active = true;

        let result = self.do_read(addr);
        self.transaction_active = false;
        if result.is_ok() {
            self.transactions += 1;
        }
        result
    }

    #[cfg(target_arch = "x86_64")]
    fn do_read(&mut self, addr: u8) -> Result<u8> {
        self.wait_ibf_clear()?;
        self.write_command(EcCommand::Read.opcode());
        self.wait_ibf_clear()?;
        self.write_data(addr);
        let data = self.wait_obf_set()?;
        Ok(data)
    }

    /// Write `data` to EC address `addr`.
    ///
    /// Issues the `Write` command (0x81), sends the address byte,
    /// then sends the data byte.
    ///
    /// # Errors
    ///
    /// - [`Error::Busy`] if the EC does not respond within the
    ///   timeout period or a transaction is already in progress.
    #[cfg(target_arch = "x86_64")]
    pub fn write_byte(&mut self, addr: u8, data: u8) -> Result<()> {
        if self.transaction_active {
            return Err(Error::Busy);
        }
        self.transaction_active = true;

        let result = self.do_write(addr, data);
        self.transaction_active = false;
        if result.is_ok() {
            self.transactions += 1;
        }
        result
    }

    #[cfg(target_arch = "x86_64")]
    fn do_write(&mut self, addr: u8, data: u8) -> Result<()> {
        self.wait_ibf_clear()?;
        self.write_command(EcCommand::Write.opcode());
        self.wait_ibf_clear()?;
        self.write_data(addr);
        self.wait_ibf_clear()?;
        self.write_data(data);
        Ok(())
    }

    /// Query the EC for the current event code.
    ///
    /// Clears the SCI_EVT flag and returns the query byte. A return
    /// value of 0 means no event is pending.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Busy`] on timeout.
    #[cfg(target_arch = "x86_64")]
    pub fn query(&mut self) -> Result<u8> {
        if self.transaction_active {
            return Err(Error::Busy);
        }
        self.transaction_active = true;
        self.wait_ibf_clear()?;
        self.write_command(EcCommand::Query.opcode());
        let code = self.wait_obf_set()?;
        self.transaction_active = false;
        if code != 0 {
            self.query_events += 1;
        }
        Ok(code)
    }

    /// Enter burst mode.
    ///
    /// Sends `BurstEnable` and waits for the EC to acknowledge with
    /// OBF set. The returned byte is the burst acknowledgement (0x90
    /// per spec).
    ///
    /// # Errors
    ///
    /// Returns [`Error::Busy`] on timeout.
    #[cfg(target_arch = "x86_64")]
    pub fn burst_enable(&mut self) -> Result<u8> {
        self.wait_ibf_clear()?;
        self.write_command(EcCommand::BurstEnable.opcode());
        let ack = self.wait_obf_set()?;
        self.burst_mode = true;
        self.burst_enters += 1;
        Ok(ack)
    }

    /// Exit burst mode.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Busy`] on timeout.
    #[cfg(target_arch = "x86_64")]
    pub fn burst_disable(&mut self) -> Result<()> {
        self.wait_ibf_clear()?;
        self.write_command(EcCommand::BurstDisable.opcode());
        self.burst_mode = false;
        Ok(())
    }

    // ── Non-x86 stubs ────────────────────────────────────────

    /// Read a byte from EC address `addr` (stub for non-x86 targets).
    #[cfg(not(target_arch = "x86_64"))]
    pub fn read_byte(&mut self, _addr: u8) -> Result<u8> {
        Err(Error::NotImplemented)
    }

    /// Write a byte to EC address `addr` (stub for non-x86 targets).
    #[cfg(not(target_arch = "x86_64"))]
    pub fn write_byte(&mut self, _addr: u8, _data: u8) -> Result<()> {
        Err(Error::NotImplemented)
    }

    /// Query the EC for the current event code (stub).
    #[cfg(not(target_arch = "x86_64"))]
    pub fn query(&mut self) -> Result<u8> {
        Err(Error::NotImplemented)
    }

    // ── Event handler registration ───────────────────────────

    /// Register an event handler for a specific query value.
    ///
    /// # Errors
    ///
    /// - [`Error::OutOfMemory`] if the handler table is full.
    /// - [`Error::AlreadyExists`] if a handler for `query_value`
    ///   is already registered.
    pub fn register_handler(&mut self, query_value: u8, handler_idx: u8) -> Result<()> {
        if self.handlers[..self.handler_count]
            .iter()
            .any(|h| h.active && h.query_value == query_value)
        {
            return Err(Error::AlreadyExists);
        }
        if self.handler_count >= MAX_EC_HANDLERS {
            return Err(Error::OutOfMemory);
        }
        self.handlers[self.handler_count] = EcEventHandler {
            query_value,
            handler_idx,
            active: true,
        };
        self.handler_count += 1;
        Ok(())
    }

    /// Find the handler index for a given `query_value`.
    ///
    /// Returns `None` if no handler is registered for that value.
    pub fn find_handler(&self, query_value: u8) -> Option<u8> {
        self.handlers[..self.handler_count]
            .iter()
            .find(|h| h.active && h.query_value == query_value)
            .map(|h| h.handler_idx)
    }
}

// ── EC subsystem ──────────────────────────────────────────────

/// Maximum number of EC devices in the system.
const MAX_EC_DEVICES: usize = 2;

/// Aggregate statistics for the EC subsystem.
#[derive(Debug, Clone, Copy, Default)]
pub struct AcpiEcStats {
    /// Total EC transactions completed.
    pub transactions: u64,
    /// Total query (SCI) events processed.
    pub query_events: u64,
    /// Total poll timeouts.
    pub timeouts: u64,
    /// Total burst-mode enter operations.
    pub burst_enters: u64,
}

/// ACPI EC subsystem — manages up to [`MAX_EC_DEVICES`] (2) ECs.
pub struct AcpiEcSubsystem {
    /// Registered EC devices.
    devices: [AcpiEc; MAX_EC_DEVICES],
    /// Number of active EC devices.
    count: usize,
}

impl Default for AcpiEcSubsystem {
    fn default() -> Self {
        Self::new()
    }
}

impl AcpiEcSubsystem {
    /// Create an empty EC subsystem.
    pub fn new() -> Self {
        Self {
            devices: [AcpiEc::new(), AcpiEc::new()],
            count: 0,
        }
    }

    /// Register an EC device.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the device table is full.
    pub fn register(&mut self, mut ec: AcpiEc) -> Result<usize> {
        if self.count >= MAX_EC_DEVICES {
            return Err(Error::OutOfMemory);
        }
        let idx = self.count;
        ec.active = true;
        self.devices[idx] = ec;
        self.count += 1;
        Ok(idx)
    }

    /// Read a byte from EC `ec_idx` at `addr`.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] if `ec_idx` is out of range.
    /// - [`Error::Busy`] on timeout.
    pub fn read_byte(&mut self, ec_idx: usize, addr: u8) -> Result<u8> {
        if ec_idx >= self.count {
            return Err(Error::NotFound);
        }
        self.devices[ec_idx].read_byte(addr)
    }

    /// Write `data` to EC `ec_idx` at `addr`.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] if `ec_idx` is out of range.
    /// - [`Error::Busy`] on timeout.
    pub fn write_byte(&mut self, ec_idx: usize, addr: u8, data: u8) -> Result<()> {
        if ec_idx >= self.count {
            return Err(Error::NotFound);
        }
        self.devices[ec_idx].write_byte(addr, data)
    }

    /// Query EC `ec_idx` for the current event code.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] if `ec_idx` is out of range.
    /// - [`Error::Busy`] on timeout.
    pub fn query(&mut self, ec_idx: usize) -> Result<u8> {
        if ec_idx >= self.count {
            return Err(Error::NotFound);
        }
        self.devices[ec_idx].query()
    }

    /// Return aggregate statistics across all ECs.
    pub fn stats(&self) -> AcpiEcStats {
        let mut s = AcpiEcStats::default();
        let mut i = 0usize;
        while i < self.count {
            s.transactions += self.devices[i].transactions;
            s.query_events += self.devices[i].query_events;
            s.timeouts += self.devices[i].timeouts;
            s.burst_enters += self.devices[i].burst_enters;
            i += 1;
        }
        s
    }

    /// Return a reference to EC device at `index`.
    pub fn get(&self, index: usize) -> Option<&AcpiEc> {
        if index < self.count && self.devices[index].active {
            Some(&self.devices[index])
        } else {
            None
        }
    }

    /// Return the number of registered EC devices.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Return `true` if no EC devices are registered.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
}
