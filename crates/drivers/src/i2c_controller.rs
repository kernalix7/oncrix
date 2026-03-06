// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! I2C bus controller driver for the ONCRIX operating system.
//!
//! Implements a comprehensive I2C subsystem with support for multiple
//! host controllers, device registration, bus scanning, byte-level
//! and block-level read/write operations, combined START/STOP transfers,
//! and 7-bit / 10-bit device addressing.
//!
//! # Architecture
//!
//! - **I2cControllerType** — hardware variant (DesignWare, Synopsys, etc.)
//! - **I2cSpeed** — bus clock rate (Standard, Fast, FastPlus, HighSpeed)
//! - **I2cTransferFlags** — per-message flags (read, ten-bit, no-start, etc.)
//! - **I2cMsg** — a single I2C transfer segment with inline data buffer
//! - **I2cDevInfo** — device registration descriptor for one I2C address
//! - **I2cController** — a single host controller managing one I2C bus
//! - **I2cControllerRegistry** — manages up to [`MAX_CONTROLLERS`] controllers
//!
//! # MMIO Access
//!
//! Register access uses volatile reads/writes. All `unsafe` blocks carry
//! `// SAFETY:` annotations.
//!
//! # Reference
//!
//! Linux: `drivers/i2c/i2c-core.c`, `drivers/i2c/busses/i2c-designware-core.c`,
//! `include/linux/i2c.h`

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum number of I2C host controllers.
const MAX_CONTROLLERS: usize = 8;

/// Maximum number of registered devices per controller.
const MAX_DEVICES_PER_BUS: usize = 16;

/// Maximum bytes in a single I2C message data buffer.
const MAX_MSG_DATA: usize = 64;

/// Maximum number of messages in one transfer.
const MAX_MSGS_PER_XFER: usize = 8;

// DesignWare I2C register offsets
/// DW I2C Control register offset.
const DW_IC_CON: usize = 0x00;
/// DW I2C Target address register offset.
const DW_IC_TAR: usize = 0x04;
/// DW I2C FIFO transmit data register offset.
const DW_IC_DATA_CMD: usize = 0x10;
/// DW I2C Standard-speed SCL high count register offset.
const DW_IC_SS_SCL_HCNT: usize = 0x14;
/// DW I2C Standard-speed SCL low count register offset.
const DW_IC_SS_SCL_LCNT: usize = 0x18;
/// DW I2C Fast-speed SCL high count register offset.
const DW_IC_FS_SCL_HCNT: usize = 0x1C;
/// DW I2C Fast-speed SCL low count register offset.
const DW_IC_FS_SCL_LCNT: usize = 0x20;
/// DW I2C Interrupt status register offset.
const DW_IC_INTR_STAT: usize = 0x2C;
/// DW I2C Enable register offset.
const DW_IC_ENABLE: usize = 0x6C;
/// DW I2C Status register offset.
const DW_IC_STATUS: usize = 0x70;
/// DW I2C TX FIFO level register offset.
const DW_IC_TXFLR: usize = 0x74;
/// DW I2C RX FIFO level register offset.
const DW_IC_RXFLR: usize = 0x78;
/// DW I2C Clear all interrupts register offset.
const DW_IC_CLR_INTR: usize = 0x40;

/// DW_IC_CON: master mode enable.
const DW_IC_CON_MASTER: u32 = 1 << 0;
/// DW_IC_CON: speed mask shift.
const DW_IC_CON_SPEED_SHIFT: u32 = 1;
/// DW_IC_CON: restart enable.
const DW_IC_CON_RESTART_EN: u32 = 1 << 5;
/// DW_IC_CON: 7-bit addressing.
const DW_IC_CON_10BITADDR_MASTER: u32 = 1 << 4;

/// DW_IC_STATUS: activity bit.
const DW_IC_STATUS_ACTIVITY: u32 = 1 << 0;
/// DW_IC_STATUS: TFE (TX FIFO empty).
const DW_IC_STATUS_TFE: u32 = 1 << 2;

/// DW_IC_DATA_CMD: read command bit.
const DW_IC_DATA_CMD_READ: u32 = 1 << 8;
/// DW_IC_DATA_CMD: STOP after this byte.
const DW_IC_DATA_CMD_STOP: u32 = 1 << 9;

// ---------------------------------------------------------------------------
// I2cControllerType
// ---------------------------------------------------------------------------

/// Hardware variant of the I2C host controller.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum I2cControllerType {
    /// Generic MMIO I2C controller (simple byte-by-byte).
    #[default]
    GenericMmio,
    /// Synopsys DesignWare I2C master IP block.
    DesignWare,
    /// Intel LPSS I2C (DesignWare variant with Intel quirks).
    IntelLpss,
    /// Broadcom I2C (BSC) controller.
    Broadcom,
}

// ---------------------------------------------------------------------------
// I2cSpeed
// ---------------------------------------------------------------------------

/// I2C bus clock speed mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum I2cSpeed {
    /// Standard mode: 100 kHz.
    #[default]
    Standard,
    /// Fast mode: 400 kHz.
    Fast,
    /// Fast mode plus: 1 MHz.
    FastPlus,
    /// High-speed mode: 3.4 MHz.
    HighSpeed,
}

impl I2cSpeed {
    /// Returns the bus frequency in Hz.
    pub fn frequency_hz(&self) -> u32 {
        match self {
            Self::Standard => 100_000,
            Self::Fast => 400_000,
            Self::FastPlus => 1_000_000,
            Self::HighSpeed => 3_400_000,
        }
    }

    /// Returns the DW I2C CON speed field value (bits [2:1]).
    pub fn dw_speed_bits(&self) -> u32 {
        match self {
            Self::Standard => 1,
            Self::Fast | Self::FastPlus => 2,
            Self::HighSpeed => 3,
        }
    }
}

// ---------------------------------------------------------------------------
// I2cTransferFlags
// ---------------------------------------------------------------------------

/// Flags modifying an I2C transfer message.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct I2cTransferFlags(pub u16);

impl I2cTransferFlags {
    /// Read transfer (from device to host).
    pub const READ: Self = Self(0x01);
    /// Ten-bit device address.
    pub const TEN_BIT: Self = Self(0x10);
    /// Skip the (re)START condition before this message.
    pub const NO_START: Self = Self(0x40);
    /// Stop after this message regardless of batching.
    pub const STOP: Self = Self(0x80);

    /// Returns `true` if the given flag is set.
    pub fn has(self, flag: Self) -> bool {
        (self.0 & flag.0) != 0
    }
}

// ---------------------------------------------------------------------------
// I2cMsg
// ---------------------------------------------------------------------------

/// A single I2C transfer message.
///
/// Each message targets one device address and carries up to
/// [`MAX_MSG_DATA`] bytes. Multiple messages can be chained into a
/// combined transfer with repeated-START conditions.
#[derive(Debug, Clone, Copy)]
pub struct I2cMsg {
    /// 7-bit or 10-bit device address.
    pub addr: u16,
    /// Transfer flags.
    pub flags: I2cTransferFlags,
    /// Inline data buffer.
    pub data: [u8; MAX_MSG_DATA],
    /// Number of valid bytes in `data`.
    pub len: usize,
}

/// Constant empty message for array initialisation.
const EMPTY_MSG: I2cMsg = I2cMsg {
    addr: 0,
    flags: I2cTransferFlags(0),
    data: [0u8; MAX_MSG_DATA],
    len: 0,
};

impl I2cMsg {
    /// Creates a write message to `addr` with the given data slice.
    ///
    /// Data is truncated to [`MAX_MSG_DATA`].
    pub fn write(addr: u16, data: &[u8]) -> Self {
        let copy_len = data.len().min(MAX_MSG_DATA);
        let mut msg = EMPTY_MSG;
        msg.addr = addr;
        msg.data[..copy_len].copy_from_slice(&data[..copy_len]);
        msg.len = copy_len;
        msg
    }

    /// Creates a read message from `addr` requesting `len` bytes.
    ///
    /// `len` is clamped to [`MAX_MSG_DATA`].
    pub fn read(addr: u16, len: usize) -> Self {
        let mut msg = EMPTY_MSG;
        msg.addr = addr;
        msg.flags = I2cTransferFlags::READ;
        msg.len = len.min(MAX_MSG_DATA);
        msg
    }

    /// Returns `true` if this is a read transfer.
    pub fn is_read(&self) -> bool {
        self.flags.has(I2cTransferFlags::READ)
    }
}

// ---------------------------------------------------------------------------
// I2cDevInfo
// ---------------------------------------------------------------------------

/// Descriptor for an I2C device registered on a bus.
#[derive(Debug, Clone, Copy)]
pub struct I2cDevInfo {
    /// Device I2C address.
    pub addr: u16,
    /// Human-readable name (UTF-8).
    pub name: [u8; 32],
    /// Number of valid bytes in `name`.
    pub name_len: usize,
    /// Whether this device was found via bus scan (vs statically registered).
    pub from_scan: bool,
    /// Whether the device is active.
    pub active: bool,
}

/// Constant empty device info.
const EMPTY_DEV: I2cDevInfo = I2cDevInfo {
    addr: 0,
    name: [0u8; 32],
    name_len: 0,
    from_scan: false,
    active: false,
};

impl I2cDevInfo {
    /// Creates a new device descriptor.
    pub fn new(addr: u16, name: &[u8]) -> Self {
        let copy_len = name.len().min(32);
        let mut dev = EMPTY_DEV;
        dev.addr = addr;
        dev.name[..copy_len].copy_from_slice(&name[..copy_len]);
        dev.name_len = copy_len;
        dev.active = true;
        dev
    }
}

// ---------------------------------------------------------------------------
// I2cTransferResult
// ---------------------------------------------------------------------------

/// Result of a completed I2C transfer.
#[derive(Debug, Clone, Copy, Default)]
pub struct I2cTransferResult {
    /// Number of messages successfully processed.
    pub msgs_ok: usize,
    /// Total bytes written (write messages only).
    pub bytes_written: usize,
    /// Total bytes read (read messages only).
    pub bytes_read: usize,
}

// ---------------------------------------------------------------------------
// MMIO helpers (volatile, for MMIO registers)
// ---------------------------------------------------------------------------

/// Volatile 32-bit MMIO read from `base + offset`.
///
/// # Safety
///
/// `base + offset` must be a valid, mapped MMIO address.
#[inline]
unsafe fn mmio_read32(base: usize, offset: usize) -> u32 {
    // SAFETY: caller guarantees valid MMIO address.
    unsafe { core::ptr::read_volatile((base + offset) as *const u32) }
}

/// Volatile 32-bit MMIO write to `base + offset`.
///
/// # Safety
///
/// `base + offset` must be a valid, mapped MMIO address.
#[inline]
unsafe fn mmio_write32(base: usize, offset: usize, val: u32) {
    // SAFETY: caller guarantees valid MMIO address.
    unsafe { core::ptr::write_volatile((base + offset) as *mut u32, val) }
}

// ---------------------------------------------------------------------------
// I2cController
// ---------------------------------------------------------------------------

/// A single I2C host controller managing one bus.
///
/// Tracks registered devices, transfer statistics, bus speed, and provides
/// MMIO-level transfer primitives.
pub struct I2cController {
    /// Unique controller identifier.
    pub id: u32,
    /// Hardware variant.
    pub hw_type: I2cControllerType,
    /// MMIO base address.
    pub mmio_base: usize,
    /// Bus clock speed.
    pub speed: I2cSpeed,
    /// Registered devices on this bus.
    pub devices: [Option<I2cDevInfo>; MAX_DEVICES_PER_BUS],
    /// Number of registered devices.
    pub device_count: usize,
    /// Total successful transfers.
    pub transfer_count: u64,
    /// Total transfer errors.
    pub error_count: u64,
    /// Whether the controller is initialised.
    pub initialized: bool,
}

impl I2cController {
    /// Creates a new I2C controller with the given parameters.
    pub fn new(id: u32, hw_type: I2cControllerType, mmio_base: usize, speed: I2cSpeed) -> Self {
        Self {
            id,
            hw_type,
            mmio_base,
            speed,
            devices: [const { None }; MAX_DEVICES_PER_BUS],
            device_count: 0,
            transfer_count: 0,
            error_count: 0,
            initialized: false,
        }
    }

    /// Initialises the hardware controller.
    ///
    /// For DesignWare controllers, disables the master, sets speed and
    /// addressing mode, then re-enables. For generic controllers, a no-op.
    ///
    /// # Errors
    ///
    /// Returns [`Error::IoError`] if `mmio_base` is zero.
    pub fn init(&mut self) -> Result<()> {
        if self.mmio_base == 0 {
            return Err(Error::IoError);
        }
        match self.hw_type {
            I2cControllerType::DesignWare | I2cControllerType::IntelLpss => {
                self.dw_init()?;
            }
            _ => {}
        }
        self.initialized = true;
        Ok(())
    }

    /// DesignWare I2C initialisation sequence.
    fn dw_init(&mut self) -> Result<()> {
        let base = self.mmio_base;

        // 1. Disable the controller
        // SAFETY: mmio_base is checked non-zero in init(); DW_IC_ENABLE is the
        // enable/disable register of the DesignWare I2C IP block.
        unsafe {
            mmio_write32(base, DW_IC_ENABLE, 0);
        }

        // 2. Configure master mode + speed + restart enable
        let speed_bits = self.speed.dw_speed_bits() << DW_IC_CON_SPEED_SHIFT;
        let con = DW_IC_CON_MASTER | speed_bits | DW_IC_CON_RESTART_EN;
        // SAFETY: DW_IC_CON is the control register, safe to write while disabled.
        unsafe {
            mmio_write32(base, DW_IC_CON, con);
        }

        // 3. Set SCL timing for chosen speed
        match self.speed {
            I2cSpeed::Standard => {
                // SAFETY: SCL count registers are 16-bit RW registers in the DW block.
                unsafe {
                    mmio_write32(base, DW_IC_SS_SCL_HCNT, 0x190); // ~400ns high
                    mmio_write32(base, DW_IC_SS_SCL_LCNT, 0x1D4); // ~470ns low
                }
            }
            I2cSpeed::Fast | I2cSpeed::FastPlus => {
                // SAFETY: Fast-mode SCL count registers.
                unsafe {
                    mmio_write32(base, DW_IC_FS_SCL_HCNT, 0x3C); // ~60ns high
                    mmio_write32(base, DW_IC_FS_SCL_LCNT, 0x82); // ~130ns low
                }
            }
            I2cSpeed::HighSpeed => {
                // High-speed timing left at reset defaults
            }
        }

        // 4. Clear interrupt flags
        // SAFETY: DW_IC_CLR_INTR clears all pending interrupt status bits.
        unsafe {
            let _ = mmio_read32(base, DW_IC_CLR_INTR);
        }

        // 5. Re-enable
        // SAFETY: DW_IC_ENABLE: writing 1 enables the master controller.
        unsafe {
            mmio_write32(base, DW_IC_ENABLE, 1);
        }

        Ok(())
    }

    /// Registers a device on this bus.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the device table is full, or
    /// [`Error::AlreadyExists`] if the address is already registered.
    pub fn register_device(&mut self, dev: I2cDevInfo) -> Result<()> {
        for slot in self.devices.iter().flatten() {
            if slot.addr == dev.addr {
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

    /// Unregisters a device by address.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if no device with `addr` is registered.
    pub fn unregister_device(&mut self, addr: u16) -> Result<()> {
        for slot in self.devices.iter_mut() {
            let matches = slot.as_ref().is_some_and(|d| d.addr == addr);
            if matches {
                *slot = None;
                self.device_count -= 1;
                return Ok(());
            }
        }
        Err(Error::NotFound)
    }

    /// Performs a multi-message I2C transfer (write/read/combined).
    ///
    /// For DesignWare controllers, uses the FIFO-based transfer path.
    /// For generic controllers, falls back to a software simulation.
    ///
    /// # Errors
    ///
    /// Returns [`Error::IoError`] if the controller is not initialised, or
    /// if a hardware error occurs during the transfer.
    pub fn transfer(&mut self, msgs: &mut [I2cMsg]) -> Result<I2cTransferResult> {
        if !self.initialized {
            return Err(Error::IoError);
        }
        if msgs.is_empty() {
            return Ok(I2cTransferResult::default());
        }
        let count = msgs.len().min(MAX_MSGS_PER_XFER);
        let result = match self.hw_type {
            I2cControllerType::DesignWare | I2cControllerType::IntelLpss => {
                self.dw_transfer(msgs, count)?
            }
            _ => self.sw_transfer(msgs, count)?,
        };
        self.transfer_count += 1;
        Ok(result)
    }

    /// DesignWare FIFO-based transfer implementation.
    fn dw_transfer(&mut self, msgs: &mut [I2cMsg], count: usize) -> Result<I2cTransferResult> {
        let base = self.mmio_base;
        let mut result = I2cTransferResult::default();

        for msg in msgs.iter_mut().take(count) {
            // Set target address
            let tar = if msg.flags.has(I2cTransferFlags::TEN_BIT) {
                (u32::from(msg.addr)) | DW_IC_CON_10BITADDR_MASTER
            } else {
                u32::from(msg.addr)
            };
            // SAFETY: DW_IC_TAR sets the 7/10-bit target address for the next transfer.
            unsafe {
                mmio_write32(base, DW_IC_TAR, tar);
            }

            if msg.is_read() {
                // Issue READ commands
                for i in 0..msg.len {
                    let cmd = DW_IC_DATA_CMD_READ
                        | if i == msg.len.saturating_sub(1) {
                            DW_IC_DATA_CMD_STOP
                        } else {
                            0
                        };
                    // SAFETY: DW_IC_DATA_CMD enqueues a read or write byte into the TX FIFO.
                    unsafe {
                        mmio_write32(base, DW_IC_DATA_CMD, cmd);
                    }
                }
                // Poll RX FIFO for received bytes (simplified busy-poll)
                for i in 0..msg.len {
                    let mut timeout = 10_000u32;
                    loop {
                        // SAFETY: DW_IC_RXFLR gives the RX FIFO fill level.
                        let rxflr = unsafe { mmio_read32(base, DW_IC_RXFLR) };
                        if rxflr > 0 {
                            break;
                        }
                        timeout -= 1;
                        if timeout == 0 {
                            self.error_count += 1;
                            return Err(Error::IoError);
                        }
                    }
                    // SAFETY: Reading DW_IC_DATA_CMD dequeues one byte from the RX FIFO.
                    let byte = unsafe { mmio_read32(base, DW_IC_DATA_CMD) as u8 };
                    msg.data[i] = byte;
                    result.bytes_read += 1;
                }
            } else {
                // Issue WRITE commands
                for i in 0..msg.len {
                    let cmd = u32::from(msg.data[i])
                        | if i == msg.len.saturating_sub(1) {
                            DW_IC_DATA_CMD_STOP
                        } else {
                            0
                        };
                    // SAFETY: DW_IC_DATA_CMD enqueues the byte into the TX FIFO.
                    unsafe {
                        mmio_write32(base, DW_IC_DATA_CMD, cmd);
                    }
                    result.bytes_written += 1;
                }
                // Wait for TX FIFO to drain
                let mut timeout = 50_000u32;
                loop {
                    // SAFETY: DW_IC_STATUS_TFE indicates TX FIFO is empty.
                    let sts = unsafe { mmio_read32(base, DW_IC_STATUS) };
                    if (sts & DW_IC_STATUS_TFE) != 0 {
                        break;
                    }
                    timeout -= 1;
                    if timeout == 0 {
                        self.error_count += 1;
                        return Err(Error::IoError);
                    }
                }
            }
            result.msgs_ok += 1;
        }

        // Clear interrupt status
        // SAFETY: Reading DW_IC_CLR_INTR clears all non-masked interrupt bits.
        unsafe {
            let _ = mmio_read32(base, DW_IC_CLR_INTR);
            let _ = mmio_read32(base, DW_IC_INTR_STAT);
        }
        Ok(result)
    }

    /// Software-simulation transfer (no real hardware).
    fn sw_transfer(&self, msgs: &mut [I2cMsg], count: usize) -> Result<I2cTransferResult> {
        let mut result = I2cTransferResult::default();
        for msg in msgs.iter_mut().take(count) {
            if msg.is_read() {
                result.bytes_read += msg.len;
            } else {
                result.bytes_written += msg.len;
            }
            result.msgs_ok += 1;
        }
        Ok(result)
    }

    /// Writes a single byte register `reg` on device at `addr`.
    ///
    /// # Errors
    ///
    /// Returns the underlying transfer error on failure.
    pub fn write_byte(&mut self, addr: u16, reg: u8, value: u8) -> Result<()> {
        let mut msgs = [I2cMsg::write(addr, &[reg, value])];
        self.transfer(&mut msgs)?;
        Ok(())
    }

    /// Reads one byte from register `reg` on device at `addr`.
    ///
    /// # Errors
    ///
    /// Returns the underlying transfer error on failure.
    pub fn read_byte(&mut self, addr: u16, reg: u8) -> Result<u8> {
        let mut msgs = [I2cMsg::write(addr, &[reg]), I2cMsg::read(addr, 1)];
        self.transfer(&mut msgs)?;
        Ok(msgs[1].data[0])
    }

    /// Scans the bus for responsive devices in the 7-bit address range
    /// `0x08..=0x77` and registers discovered devices.
    ///
    /// Only probes the range; no actual read/write data is exchanged.
    ///
    /// # Errors
    ///
    /// Returns [`Error::IoError`] if not initialised.
    pub fn scan_bus(&mut self) -> Result<usize> {
        if !self.initialized {
            return Err(Error::IoError);
        }
        let mut found = 0usize;
        for addr in 0x08u16..=0x77 {
            // Issue a zero-length write; if the device ACKs, it is present.
            let mut probe = [I2cMsg::write(addr, &[])];
            if self.transfer(&mut probe).is_ok() {
                let dev = I2cDevInfo {
                    addr,
                    name: [0u8; 32],
                    name_len: 0,
                    from_scan: true,
                    active: true,
                };
                // Ignore error if already registered
                let _ = self.register_device(dev);
                found += 1;
            }
        }
        Ok(found)
    }

    /// Returns the device info for the given address, if registered.
    pub fn find_device(&self, addr: u16) -> Option<&I2cDevInfo> {
        self.devices.iter().flatten().find(|d| d.addr == addr)
    }
}

// ---------------------------------------------------------------------------
// I2cControllerRegistry
// ---------------------------------------------------------------------------

/// Registry managing up to [`MAX_CONTROLLERS`] I2C host controllers.
pub struct I2cControllerRegistry {
    /// Registered controllers.
    controllers: [Option<I2cController>; MAX_CONTROLLERS],
    /// Number of registered controllers.
    count: usize,
}

impl Default for I2cControllerRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl I2cControllerRegistry {
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
    pub fn register(&mut self, ctrl: I2cController) -> Result<()> {
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
    pub fn get(&self, id: u32) -> Result<&I2cController> {
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
    pub fn get_mut(&mut self, id: u32) -> Result<&mut I2cController> {
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

// ---------------------------------------------------------------------------
// I2cStats
// ---------------------------------------------------------------------------

/// Aggregated statistics across all controllers in the registry.
#[derive(Debug, Clone, Copy, Default)]
pub struct I2cStats {
    /// Total successful transfers across all controllers.
    pub total_transfers: u64,
    /// Total transfer errors across all controllers.
    pub total_errors: u64,
    /// Total number of registered devices across all controllers.
    pub total_devices: usize,
}

impl I2cControllerRegistry {
    /// Computes aggregated statistics across all registered controllers.
    pub fn stats(&self) -> I2cStats {
        let mut s = I2cStats::default();
        for ctrl in self.controllers.iter().flatten() {
            s.total_transfers += ctrl.transfer_count;
            s.total_errors += ctrl.error_count;
            s.total_devices += ctrl.device_count;
        }
        s
    }
}
