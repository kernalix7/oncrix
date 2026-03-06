// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! I2C bus controller abstraction for the ONCRIX hardware abstraction layer.
//!
//! Provides a comprehensive I2C master controller subsystem with support for
//! bus arbitration, clock stretching detection, multi-byte transfers, address
//! probing, and MMIO-based register access.
//!
//! # Architecture
//!
//! - **I2cSpeed** — bus clock speed mode (standard, fast, fast-plus, high-speed)
//! - **I2cAddrMode** — 7-bit or 10-bit addressing
//! - **I2cAddr** — I2C target device address with mode
//! - **TransferFlags** — per-transfer behaviour flags
//! - **I2cMessage** — a single read or write transfer descriptor
//! - **I2cBusConfig** — MMIO layout and timing configuration
//! - **I2cBusState** — runtime state of the controller
//! - **I2cBus** — a single I2C master controller with register-level operations
//! - **I2cBusRegistry** — manages up to [`MAX_BUSES`] I2C controllers
//!
//! # MMIO Access
//!
//! All register access uses volatile reads/writes via `read_mmio32` /
//! `write_mmio32` helpers, satisfying the hardware safety requirement for
//! memory-mapped I/O.
//!
//! # Reference
//!
//! Linux: `drivers/i2c/`, `include/linux/i2c.h`, `include/linux/i2c-dev.h`

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum number of I2C bus controllers in the registry.
const MAX_BUSES: usize = 8;

/// Maximum number of messages per transfer batch.
const MAX_MESSAGES: usize = 16;

/// Maximum transfer buffer size in bytes.
const MAX_TRANSFER_SIZE: usize = 4096;

/// Maximum number of known device addresses per bus.
const MAX_KNOWN_DEVICES: usize = 32;

/// I2C standard mode clock frequency: 100 kHz.
const I2C_STANDARD_HZ: u32 = 100_000;

/// I2C fast mode clock frequency: 400 kHz.
const I2C_FAST_HZ: u32 = 400_000;

/// I2C fast-plus mode clock frequency: 1 MHz.
const I2C_FAST_PLUS_HZ: u32 = 1_000_000;

/// I2C high-speed mode clock frequency: 3.4 MHz.
const I2C_HIGH_SPEED_HZ: u32 = 3_400_000;

/// Maximum 7-bit address (0x77 is typical upper bound for real devices).
const I2C_MAX_7BIT_ADDR: u16 = 0x7F;

/// Maximum 10-bit address.
const I2C_MAX_10BIT_ADDR: u16 = 0x3FF;

// ---------------------------------------------------------------------------
// MMIO register offsets (generic I2C controller, e.g. DesignWare I2C)
// ---------------------------------------------------------------------------

/// Control register offset.
const I2C_CTRL_OFF: usize = 0x00;

/// Target address register offset.
const I2C_TAR_OFF: usize = 0x04;

/// Data command register offset.
const I2C_DATA_CMD_OFF: usize = 0x10;

/// Standard-mode SCL high-count register offset.
const I2C_SS_SCL_HCNT_OFF: usize = 0x14;

/// Standard-mode SCL low-count register offset.
const I2C_SS_SCL_LCNT_OFF: usize = 0x18;

/// Fast-mode SCL high-count register offset.
const I2C_FS_SCL_HCNT_OFF: usize = 0x1C;

/// Fast-mode SCL low-count register offset.
const I2C_FS_SCL_LCNT_OFF: usize = 0x20;

/// Interrupt status register offset.
const I2C_INTR_STAT_OFF: usize = 0x2C;

/// Interrupt mask register offset.
const I2C_INTR_MASK_OFF: usize = 0x30;

/// Raw interrupt status register offset.
const I2C_RAW_INTR_STAT_OFF: usize = 0x34;

/// TX abort source register offset.
const I2C_TX_ABRT_SOURCE_OFF: usize = 0x80;

/// Enable register offset.
const I2C_ENABLE_OFF: usize = 0x6C;

/// Status register offset.
const I2C_STATUS_OFF: usize = 0x70;

/// TX FIFO level register offset.
const I2C_TXFLR_OFF: usize = 0x74;

/// RX FIFO level register offset.
const I2C_RXFLR_OFF: usize = 0x78;

/// Enable status register offset.
const I2C_ENABLE_STATUS_OFF: usize = 0x9C;

// ---------------------------------------------------------------------------
// Control register bits
// ---------------------------------------------------------------------------

/// Controller enable bit in the enable register.
const I2C_ENABLE_BIT: u32 = 1 << 0;

/// Master mode bit in the control register.
const I2C_CTRL_MASTER_MODE: u32 = 1 << 0;

/// Speed selection: standard mode (bits [2:1] = 01).
const I2C_CTRL_SPEED_STD: u32 = 1 << 1;

/// Speed selection: fast mode (bits [2:1] = 10).
const I2C_CTRL_SPEED_FAST: u32 = 2 << 1;

/// 10-bit addressing mode for master (bit 4).
const I2C_CTRL_10BIT_MASTER: u32 = 1 << 4;

/// Restart enable bit (bit 5).
const I2C_CTRL_RESTART_EN: u32 = 1 << 5;

/// Slave disable bit (bit 6).
const I2C_CTRL_SLAVE_DISABLE: u32 = 1 << 6;

// ---------------------------------------------------------------------------
// Data command register bits
// ---------------------------------------------------------------------------

/// Read command bit in DATA_CMD register.
const I2C_DATA_CMD_READ: u32 = 1 << 8;

/// Stop condition bit in DATA_CMD register.
const I2C_DATA_CMD_STOP: u32 = 1 << 9;

/// Restart condition bit in DATA_CMD register.
const I2C_DATA_CMD_RESTART: u32 = 1 << 10;

// ---------------------------------------------------------------------------
// Status register bits
// ---------------------------------------------------------------------------

/// Bus activity indicator (bit 0).
const I2C_STATUS_ACTIVITY: u32 = 1 << 0;

/// TX FIFO not full (bit 1).
const I2C_STATUS_TFNF: u32 = 1 << 1;

/// TX FIFO empty (bit 2).
const I2C_STATUS_TFE: u32 = 1 << 2;

/// RX FIFO not empty (bit 3).
const I2C_STATUS_RFNE: u32 = 1 << 3;

// ---------------------------------------------------------------------------
// Interrupt bits
// ---------------------------------------------------------------------------

/// TX abort interrupt bit.
const I2C_INTR_TX_ABRT: u32 = 1 << 6;

/// TX empty interrupt bit.
const I2C_INTR_TX_EMPTY: u32 = 1 << 4;

/// RX full interrupt bit.
const I2C_INTR_RX_FULL: u32 = 1 << 2;

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
    /// Fast-plus mode: 1 MHz.
    FastPlus,
    /// High-speed mode: 3.4 MHz.
    HighSpeed,
}

impl I2cSpeed {
    /// Returns the clock frequency in Hz for this speed mode.
    pub fn frequency_hz(self) -> u32 {
        match self {
            I2cSpeed::Standard => I2C_STANDARD_HZ,
            I2cSpeed::Fast => I2C_FAST_HZ,
            I2cSpeed::FastPlus => I2C_FAST_PLUS_HZ,
            I2cSpeed::HighSpeed => I2C_HIGH_SPEED_HZ,
        }
    }
}

// ---------------------------------------------------------------------------
// I2cAddrMode
// ---------------------------------------------------------------------------

/// I2C addressing mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum I2cAddrMode {
    /// Standard 7-bit addressing (most common).
    #[default]
    SevenBit,
    /// Extended 10-bit addressing.
    TenBit,
}

// ---------------------------------------------------------------------------
// I2cAddr
// ---------------------------------------------------------------------------

/// An I2C target device address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct I2cAddr {
    /// Raw address value (7-bit or 10-bit).
    pub addr: u16,
    /// Addressing mode.
    pub mode: I2cAddrMode,
}

impl I2cAddr {
    /// Creates a new 7-bit I2C address.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `addr` exceeds 0x7F.
    pub fn seven_bit(addr: u16) -> Result<Self> {
        if addr > I2C_MAX_7BIT_ADDR {
            return Err(Error::InvalidArgument);
        }
        Ok(Self {
            addr,
            mode: I2cAddrMode::SevenBit,
        })
    }

    /// Creates a new 10-bit I2C address.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `addr` exceeds 0x3FF.
    pub fn ten_bit(addr: u16) -> Result<Self> {
        if addr > I2C_MAX_10BIT_ADDR {
            return Err(Error::InvalidArgument);
        }
        Ok(Self {
            addr,
            mode: I2cAddrMode::TenBit,
        })
    }

    /// Returns the raw address value suitable for the target register.
    pub fn raw(self) -> u16 {
        self.addr
    }

    /// Returns `true` if this is a reserved I2C address.
    ///
    /// Addresses 0x00-0x07 and 0x78-0x7F are reserved in 7-bit mode.
    pub fn is_reserved(self) -> bool {
        if self.mode == I2cAddrMode::SevenBit {
            self.addr <= 0x07 || self.addr >= 0x78
        } else {
            false
        }
    }
}

// ---------------------------------------------------------------------------
// TransferFlags
// ---------------------------------------------------------------------------

/// Flags modifying the behaviour of an individual I2C transfer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TransferFlags {
    /// If set, issue a repeated START instead of STOP+START between messages.
    pub no_stop: bool,
    /// If set, do not send the target address (continuation of previous msg).
    pub no_start: bool,
    /// If set, use PEC (Packet Error Checking) — SMBus CRC-8.
    pub pec: bool,
    /// If set, reverse the data byte order (for big-endian register maps).
    pub rev_dir: bool,
}

impl TransferFlags {
    /// Creates default flags with no special behaviour.
    pub const fn new() -> Self {
        Self {
            no_stop: false,
            no_start: false,
            pec: false,
            rev_dir: false,
        }
    }
}

// ---------------------------------------------------------------------------
// I2cDirection
// ---------------------------------------------------------------------------

/// Direction of an I2C transfer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum I2cDirection {
    /// Write data to the target device.
    #[default]
    Write,
    /// Read data from the target device.
    Read,
}

// ---------------------------------------------------------------------------
// I2cMessage
// ---------------------------------------------------------------------------

/// A single I2C transfer message descriptor.
///
/// Describes one segment of a multi-message transfer: the target address,
/// direction (read/write), data buffer, and optional flags.
#[derive(Debug, Clone, Copy)]
pub struct I2cMessage {
    /// Target device address.
    pub addr: I2cAddr,
    /// Transfer direction.
    pub direction: I2cDirection,
    /// Data buffer (inline, fixed-size for no_std).
    pub data: [u8; 32],
    /// Number of valid bytes in [`data`](Self::data).
    pub len: usize,
    /// Per-transfer flags.
    pub flags: TransferFlags,
}

/// Constant empty message for array initialisation.
const EMPTY_MSG: I2cMessage = I2cMessage {
    addr: I2cAddr {
        addr: 0,
        mode: I2cAddrMode::SevenBit,
    },
    direction: I2cDirection::Write,
    data: [0u8; 32],
    len: 0,
    flags: TransferFlags::new(),
};

impl I2cMessage {
    /// Creates a new write message.
    pub fn write(addr: I2cAddr, data: &[u8]) -> Self {
        let copy_len = data.len().min(32);
        let mut buf = [0u8; 32];
        buf[..copy_len].copy_from_slice(&data[..copy_len]);
        Self {
            addr,
            direction: I2cDirection::Write,
            data: buf,
            len: copy_len,
            flags: TransferFlags::new(),
        }
    }

    /// Creates a new read message with the specified length.
    ///
    /// The data buffer is zeroed; it will be filled by the controller.
    pub fn read(addr: I2cAddr, read_len: usize) -> Self {
        let len = read_len.min(32);
        Self {
            addr,
            direction: I2cDirection::Read,
            data: [0u8; 32],
            len,
            flags: TransferFlags::new(),
        }
    }

    /// Sets flags on this message and returns it (builder pattern).
    pub fn with_flags(mut self, flags: TransferFlags) -> Self {
        self.flags = flags;
        self
    }
}

// ---------------------------------------------------------------------------
// I2cBusState
// ---------------------------------------------------------------------------

/// Runtime state of the I2C bus controller.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum I2cBusState {
    /// Controller is uninitialised.
    #[default]
    Uninitialised,
    /// Controller is idle and ready for transfers.
    Idle,
    /// A transfer is currently in progress.
    Busy,
    /// The bus is in an error state (requires reset).
    Error,
}

// ---------------------------------------------------------------------------
// I2cBusConfig
// ---------------------------------------------------------------------------

/// Hardware configuration for an I2C bus controller.
#[derive(Debug, Clone, Copy)]
pub struct I2cBusConfig {
    /// MMIO base address of the I2C controller registers.
    pub mmio_base: usize,
    /// MMIO region size in bytes.
    pub mmio_size: usize,
    /// Input clock frequency to the I2C controller (Hz).
    pub input_clk_hz: u32,
    /// Desired bus speed mode.
    pub speed: I2cSpeed,
    /// SCL high-count for standard mode.
    pub ss_hcnt: u16,
    /// SCL low-count for standard mode.
    pub ss_lcnt: u16,
    /// SCL high-count for fast mode.
    pub fs_hcnt: u16,
    /// SCL low-count for fast mode.
    pub fs_lcnt: u16,
    /// TX FIFO depth.
    pub tx_fifo_depth: u8,
    /// RX FIFO depth.
    pub rx_fifo_depth: u8,
}

impl Default for I2cBusConfig {
    fn default() -> Self {
        Self {
            mmio_base: 0,
            mmio_size: 0x100,
            input_clk_hz: 100_000_000, // 100 MHz typical
            speed: I2cSpeed::Standard,
            ss_hcnt: 0x0190, // standard counts for 100 MHz input
            ss_lcnt: 0x01D6,
            fs_hcnt: 0x003C,
            fs_lcnt: 0x0082,
            tx_fifo_depth: 16,
            rx_fifo_depth: 16,
        }
    }
}

impl I2cBusConfig {
    /// Creates a configuration for a DesignWare I2C controller.
    pub fn designware(mmio_base: usize, input_clk_hz: u32, speed: I2cSpeed) -> Self {
        let (ss_hcnt, ss_lcnt) = compute_scl_counts(input_clk_hz, I2C_STANDARD_HZ);
        let (fs_hcnt, fs_lcnt) = compute_scl_counts(input_clk_hz, I2C_FAST_HZ);
        Self {
            mmio_base,
            input_clk_hz,
            speed,
            ss_hcnt,
            ss_lcnt,
            fs_hcnt,
            fs_lcnt,
            ..Self::default()
        }
    }
}

/// Computes SCL high and low counts from input clock and target frequency.
fn compute_scl_counts(input_hz: u32, target_hz: u32) -> (u16, u16) {
    if target_hz == 0 {
        return (0, 0);
    }
    let period_counts = input_hz / target_hz;
    let hcnt = (period_counts / 2).min(u16::MAX as u32) as u16;
    let lcnt = (period_counts - hcnt as u32).min(u16::MAX as u32) as u16;
    (hcnt, lcnt)
}

// ---------------------------------------------------------------------------
// KnownDevice
// ---------------------------------------------------------------------------

/// A device discovered or registered on the I2C bus.
#[derive(Debug, Clone, Copy)]
pub struct KnownDevice {
    /// Device address.
    pub addr: I2cAddr,
    /// Human-readable label (UTF-8).
    pub label: [u8; 32],
    /// Number of valid bytes in [`label`](Self::label).
    pub label_len: usize,
    /// Whether the device responded to a probe.
    pub present: bool,
}

/// Constant empty known device for array initialisation.
const EMPTY_KNOWN: KnownDevice = KnownDevice {
    addr: I2cAddr {
        addr: 0,
        mode: I2cAddrMode::SevenBit,
    },
    label: [0u8; 32],
    label_len: 0,
    present: false,
};

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
// I2cBus
// ---------------------------------------------------------------------------

/// A single I2C master bus controller.
///
/// Wraps the hardware configuration and provides safe methods for
/// initialisation, single-byte read/write, multi-message transfers,
/// and device probing.
pub struct I2cBus {
    /// Unique bus identifier.
    pub id: u32,
    /// Human-readable bus label (UTF-8).
    pub label: [u8; 32],
    /// Number of valid bytes in [`label`](Self::label).
    pub label_len: usize,
    /// Hardware configuration.
    pub config: I2cBusConfig,
    /// Current bus state.
    pub state: I2cBusState,
    /// Known devices discovered or registered on this bus.
    known_devices: [KnownDevice; MAX_KNOWN_DEVICES],
    /// Number of known devices.
    known_count: usize,
    /// Transfer message queue (for batch operations).
    msg_queue: [I2cMessage; MAX_MESSAGES],
    /// Number of messages in the queue.
    msg_count: usize,
    /// Total bytes transferred (for statistics).
    pub bytes_transferred: u64,
    /// Total number of completed transfers.
    pub transfer_count: u64,
    /// Total number of NACK errors.
    pub nack_count: u64,
    /// Total number of arbitration loss events.
    pub arb_loss_count: u64,
    /// Whether the controller is registered and active.
    pub active: bool,
}

impl I2cBus {
    /// Creates a new I2C bus controller.
    pub fn new(id: u32, label: &[u8], config: I2cBusConfig) -> Self {
        let copy_len = label.len().min(32);
        let mut buf = [0u8; 32];
        buf[..copy_len].copy_from_slice(&label[..copy_len]);
        Self {
            id,
            label: buf,
            label_len: copy_len,
            config,
            state: I2cBusState::Uninitialised,
            known_devices: [EMPTY_KNOWN; MAX_KNOWN_DEVICES],
            known_count: 0,
            msg_queue: [EMPTY_MSG; MAX_MESSAGES],
            msg_count: 0,
            bytes_transferred: 0,
            transfer_count: 0,
            nack_count: 0,
            arb_loss_count: 0,
            active: false,
        }
    }

    /// Initialises the I2C controller hardware.
    ///
    /// Disables the controller, configures speed registers, and re-enables.
    ///
    /// # Errors
    ///
    /// Returns [`Error::IoError`] if the MMIO base is zero (unmapped).
    pub fn init(&mut self) -> Result<()> {
        if self.config.mmio_base == 0 {
            return Err(Error::IoError);
        }

        // Disable controller before configuration.
        // SAFETY: mmio_base checked non-zero; I2C controller MMIO is a valid
        // memory-mapped region provided by platform firmware.
        unsafe {
            write_mmio32(self.config.mmio_base, I2C_ENABLE_OFF, 0);
        }

        // Wait for disable to take effect.
        self.wait_disable()?;

        // Configure control register.
        let mut ctrl = I2C_CTRL_MASTER_MODE | I2C_CTRL_SLAVE_DISABLE | I2C_CTRL_RESTART_EN;

        ctrl |= match self.config.speed {
            I2cSpeed::Standard => I2C_CTRL_SPEED_STD,
            _ => I2C_CTRL_SPEED_FAST,
        };

        // SAFETY: mmio_base valid; CTRL register is a 32-bit RW register.
        unsafe {
            write_mmio32(self.config.mmio_base, I2C_CTRL_OFF, ctrl);
        }

        // Configure SCL timing.
        // SAFETY: mmio_base valid; SCL count registers are 32-bit RW.
        unsafe {
            write_mmio32(
                self.config.mmio_base,
                I2C_SS_SCL_HCNT_OFF,
                self.config.ss_hcnt as u32,
            );
            write_mmio32(
                self.config.mmio_base,
                I2C_SS_SCL_LCNT_OFF,
                self.config.ss_lcnt as u32,
            );
            write_mmio32(
                self.config.mmio_base,
                I2C_FS_SCL_HCNT_OFF,
                self.config.fs_hcnt as u32,
            );
            write_mmio32(
                self.config.mmio_base,
                I2C_FS_SCL_LCNT_OFF,
                self.config.fs_lcnt as u32,
            );
        }

        // Mask all interrupts initially.
        // SAFETY: mmio_base valid; INTR_MASK is a 32-bit RW register.
        unsafe {
            write_mmio32(self.config.mmio_base, I2C_INTR_MASK_OFF, 0);
        }

        // Enable the controller.
        // SAFETY: mmio_base valid; ENABLE register is a 32-bit RW register.
        unsafe {
            write_mmio32(self.config.mmio_base, I2C_ENABLE_OFF, I2C_ENABLE_BIT);
        }

        self.state = I2cBusState::Idle;
        self.active = true;
        Ok(())
    }

    /// Waits for the controller to become disabled.
    ///
    /// Polls the ENABLE_STATUS register with a bounded retry count.
    fn wait_disable(&self) -> Result<()> {
        let mut retries: u32 = 10_000;
        while retries > 0 {
            // SAFETY: mmio_base validated by caller; ENABLE_STATUS is RO.
            let status = unsafe { read_mmio32(self.config.mmio_base, I2C_ENABLE_STATUS_OFF) };
            if status & I2C_ENABLE_BIT == 0 {
                return Ok(());
            }
            retries -= 1;
            core::hint::spin_loop();
        }
        Err(Error::Busy)
    }

    /// Waits for the bus to become idle (no activity).
    fn wait_idle(&self) -> Result<()> {
        let mut retries: u32 = 100_000;
        while retries > 0 {
            // SAFETY: mmio_base validated; STATUS is a 32-bit RO register.
            let status = unsafe { read_mmio32(self.config.mmio_base, I2C_STATUS_OFF) };
            if status & I2C_STATUS_ACTIVITY == 0 {
                return Ok(());
            }
            retries -= 1;
            core::hint::spin_loop();
        }
        Err(Error::Busy)
    }

    /// Sets the target address for the next transfer.
    fn set_target(&self, addr: I2cAddr) -> Result<()> {
        if self.config.mmio_base == 0 {
            return Err(Error::IoError);
        }

        // Disable controller to change target address.
        // SAFETY: mmio_base valid; ENABLE is 32-bit RW.
        unsafe {
            write_mmio32(self.config.mmio_base, I2C_ENABLE_OFF, 0);
        }
        self.wait_disable()?;

        // Update control register for 10-bit addressing if needed.
        // SAFETY: mmio_base valid; CTRL is 32-bit RW.
        let ctrl = unsafe { read_mmio32(self.config.mmio_base, I2C_CTRL_OFF) };
        let new_ctrl = if addr.mode == I2cAddrMode::TenBit {
            ctrl | I2C_CTRL_10BIT_MASTER
        } else {
            ctrl & !I2C_CTRL_10BIT_MASTER
        };
        unsafe {
            write_mmio32(self.config.mmio_base, I2C_CTRL_OFF, new_ctrl);
        }

        // Set target address.
        // SAFETY: mmio_base valid; TAR is 32-bit RW.
        unsafe {
            write_mmio32(self.config.mmio_base, I2C_TAR_OFF, addr.addr as u32);
        }

        // Re-enable controller.
        // SAFETY: mmio_base valid; ENABLE is 32-bit RW.
        unsafe {
            write_mmio32(self.config.mmio_base, I2C_ENABLE_OFF, I2C_ENABLE_BIT);
        }

        Ok(())
    }

    /// Performs a single-byte write to a target device.
    ///
    /// Writes one byte and issues a STOP condition.
    ///
    /// # Errors
    ///
    /// Returns [`Error::IoError`] on hardware failure, [`Error::Busy`] if
    /// the bus is occupied, or [`Error::InvalidArgument`] if the bus is not
    /// initialised.
    pub fn write_byte(&mut self, addr: I2cAddr, byte: u8) -> Result<()> {
        self.check_ready()?;
        self.state = I2cBusState::Busy;

        self.set_target(addr)?;

        // Write the data byte with STOP condition.
        // SAFETY: mmio_base valid; DATA_CMD is 32-bit RW.
        unsafe {
            write_mmio32(
                self.config.mmio_base,
                I2C_DATA_CMD_OFF,
                byte as u32 | I2C_DATA_CMD_STOP,
            );
        }

        // Wait for TX FIFO to empty.
        self.wait_tx_empty()?;
        self.wait_idle()?;

        // Check for abort.
        self.check_abort()?;

        self.bytes_transferred += 1;
        self.transfer_count += 1;
        self.state = I2cBusState::Idle;
        Ok(())
    }

    /// Performs a single-byte read from a target device.
    ///
    /// Issues a read command and returns the received byte.
    ///
    /// # Errors
    ///
    /// Returns [`Error::IoError`] on hardware failure or timeout.
    pub fn read_byte(&mut self, addr: I2cAddr) -> Result<u8> {
        self.check_ready()?;
        self.state = I2cBusState::Busy;

        self.set_target(addr)?;

        // Issue read command with STOP.
        // SAFETY: mmio_base valid; DATA_CMD is 32-bit RW.
        unsafe {
            write_mmio32(
                self.config.mmio_base,
                I2C_DATA_CMD_OFF,
                I2C_DATA_CMD_READ | I2C_DATA_CMD_STOP,
            );
        }

        // Wait for data to arrive in RX FIFO.
        self.wait_rx_ready()?;

        // Read the byte.
        // SAFETY: mmio_base valid; DATA_CMD returns received data in bits [7:0].
        let val = unsafe { read_mmio32(self.config.mmio_base, I2C_DATA_CMD_OFF) };

        self.check_abort()?;

        self.bytes_transferred += 1;
        self.transfer_count += 1;
        self.state = I2cBusState::Idle;
        Ok((val & 0xFF) as u8)
    }

    /// Performs a multi-message transfer.
    ///
    /// Executes a sequence of I2C messages (reads and writes) in order.
    /// Messages to the same target address may use repeated START conditions.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `msgs` is empty or exceeds
    /// [`MAX_MESSAGES`], or [`Error::IoError`] on hardware failure.
    pub fn transfer(&mut self, msgs: &mut [I2cMessage]) -> Result<usize> {
        if msgs.is_empty() || msgs.len() > MAX_MESSAGES {
            return Err(Error::InvalidArgument);
        }
        self.check_ready()?;
        self.state = I2cBusState::Busy;

        let msg_count = msgs.len();
        let mut total_bytes: usize = 0;

        for (idx, msg) in msgs.iter_mut().enumerate() {
            let is_last = idx == msg_count - 1;

            self.set_target(msg.addr)?;

            match msg.direction {
                I2cDirection::Write => {
                    let len = msg.len;
                    for (bi, &byte) in msg.data[..len].iter().enumerate() {
                        let is_last_byte = bi == len - 1;
                        let mut cmd = byte as u32;
                        if is_last_byte && is_last && !msg.flags.no_stop {
                            cmd |= I2C_DATA_CMD_STOP;
                        }
                        if bi == 0 && msg.flags.no_start {
                            // Skip restart for continuation messages.
                        } else if bi == 0 && idx > 0 {
                            cmd |= I2C_DATA_CMD_RESTART;
                        }
                        // SAFETY: mmio_base valid; DATA_CMD is 32-bit RW.
                        unsafe {
                            write_mmio32(self.config.mmio_base, I2C_DATA_CMD_OFF, cmd);
                        }
                    }
                    total_bytes += len;
                }
                I2cDirection::Read => {
                    let len = msg.len;
                    for bi in 0..len {
                        let is_last_byte = bi == len - 1;
                        let mut cmd = I2C_DATA_CMD_READ;
                        if is_last_byte && is_last && !msg.flags.no_stop {
                            cmd |= I2C_DATA_CMD_STOP;
                        }
                        if bi == 0 && idx > 0 {
                            cmd |= I2C_DATA_CMD_RESTART;
                        }
                        // SAFETY: mmio_base valid; DATA_CMD is 32-bit RW.
                        unsafe {
                            write_mmio32(self.config.mmio_base, I2C_DATA_CMD_OFF, cmd);
                        }
                    }

                    // Read back the received bytes.
                    for bi in 0..len {
                        self.wait_rx_ready()?;
                        // SAFETY: mmio_base valid; DATA_CMD returns data.
                        let val = unsafe { read_mmio32(self.config.mmio_base, I2C_DATA_CMD_OFF) };
                        msg.data[bi] = (val & 0xFF) as u8;
                    }
                    total_bytes += len;
                }
            }

            self.check_abort()?;
        }

        self.wait_idle()?;
        self.bytes_transferred += total_bytes as u64;
        self.transfer_count += 1;
        self.state = I2cBusState::Idle;
        Ok(total_bytes)
    }

    /// Probes a device address to check if a device is present.
    ///
    /// Sends a zero-length write to the address and checks for ACK/NACK.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if no device responds (NACK), or
    /// [`Error::IoError`] on bus error.
    pub fn probe_device(&mut self, addr: I2cAddr) -> Result<bool> {
        self.check_ready()?;
        self.state = I2cBusState::Busy;

        self.set_target(addr)?;

        // Issue a write of zero bytes (just address phase) with STOP.
        // SAFETY: mmio_base valid; DATA_CMD is 32-bit RW.
        unsafe {
            write_mmio32(self.config.mmio_base, I2C_DATA_CMD_OFF, I2C_DATA_CMD_STOP);
        }

        self.wait_idle()?;

        // Check for abort (NACK = device not present).
        // SAFETY: mmio_base valid; RAW_INTR_STAT is 32-bit RO.
        let raw_intr = unsafe { read_mmio32(self.config.mmio_base, I2C_RAW_INTR_STAT_OFF) };

        self.state = I2cBusState::Idle;

        if raw_intr & I2C_INTR_TX_ABRT != 0 {
            // Clear abort status.
            // SAFETY: mmio_base valid; TX_ABRT_SOURCE is RO/clear-on-read.
            let _ = unsafe { read_mmio32(self.config.mmio_base, I2C_TX_ABRT_SOURCE_OFF) };
            self.nack_count += 1;
            Ok(false)
        } else {
            Ok(true)
        }
    }

    /// Scans the bus for devices on all non-reserved 7-bit addresses.
    ///
    /// Returns the number of devices found and stores their addresses in
    /// the known device list.
    ///
    /// # Errors
    ///
    /// Returns [`Error::IoError`] if the bus is not initialised.
    pub fn scan_bus(&mut self) -> Result<usize> {
        self.check_ready()?;
        self.known_count = 0;

        for raw_addr in 0x08..=0x77u16 {
            let addr = I2cAddr {
                addr: raw_addr,
                mode: I2cAddrMode::SevenBit,
            };
            if let Ok(true) = self.probe_device(addr) {
                if self.known_count < MAX_KNOWN_DEVICES {
                    self.known_devices[self.known_count] = KnownDevice {
                        addr,
                        label: [0u8; 32],
                        label_len: 0,
                        present: true,
                    };
                    self.known_count += 1;
                }
            }
        }

        Ok(self.known_count)
    }

    /// Returns the number of known devices on the bus.
    pub fn known_device_count(&self) -> usize {
        self.known_count
    }

    /// Returns a reference to a known device by index.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `index` is out of range.
    pub fn get_known_device(&self, index: usize) -> Result<&KnownDevice> {
        if index >= self.known_count {
            return Err(Error::InvalidArgument);
        }
        Ok(&self.known_devices[index])
    }

    /// Enqueues a message for a deferred batch transfer.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the queue is full.
    pub fn enqueue_message(&mut self, msg: I2cMessage) -> Result<()> {
        if self.msg_count >= MAX_MESSAGES {
            return Err(Error::OutOfMemory);
        }
        self.msg_queue[self.msg_count] = msg;
        self.msg_count += 1;
        Ok(())
    }

    /// Executes all enqueued messages and clears the queue.
    ///
    /// # Errors
    ///
    /// Returns any error from [`transfer`](Self::transfer).
    pub fn flush_queue(&mut self) -> Result<usize> {
        if self.msg_count == 0 {
            return Ok(0);
        }
        let count = self.msg_count;
        // Copy the queue to a local buffer for the transfer call.
        let mut msgs = [EMPTY_MSG; MAX_MESSAGES];
        msgs[..count].copy_from_slice(&self.msg_queue[..count]);
        self.msg_count = 0;
        self.transfer(&mut msgs[..count])
    }

    /// Resets the I2C controller hardware.
    ///
    /// Disables and re-enables the controller, clearing any pending state.
    ///
    /// # Errors
    ///
    /// Returns [`Error::IoError`] if the MMIO base is unmapped.
    pub fn reset(&mut self) -> Result<()> {
        if self.config.mmio_base == 0 {
            return Err(Error::IoError);
        }

        // SAFETY: mmio_base valid; ENABLE is 32-bit RW.
        unsafe {
            write_mmio32(self.config.mmio_base, I2C_ENABLE_OFF, 0);
        }
        self.wait_disable()?;

        self.state = I2cBusState::Uninitialised;
        self.msg_count = 0;
        self.init()
    }

    /// Returns the current interrupt status.
    pub fn interrupt_status(&self) -> u32 {
        if self.config.mmio_base == 0 {
            return 0;
        }
        // SAFETY: mmio_base checked; INTR_STAT is 32-bit RO.
        unsafe { read_mmio32(self.config.mmio_base, I2C_INTR_STAT_OFF) }
    }

    /// Acknowledges (clears) interrupt bits by reading relevant registers.
    pub fn acknowledge_interrupts(&self) {
        if self.config.mmio_base == 0 {
            return;
        }
        // SAFETY: mmio_base valid; TX_ABRT_SOURCE is clear-on-read.
        unsafe {
            let _ = read_mmio32(self.config.mmio_base, I2C_TX_ABRT_SOURCE_OFF);
        }
    }

    /// Checks that the bus is ready for a transfer.
    fn check_ready(&self) -> Result<()> {
        match self.state {
            I2cBusState::Idle => Ok(()),
            I2cBusState::Busy => Err(Error::Busy),
            I2cBusState::Error => Err(Error::IoError),
            I2cBusState::Uninitialised => Err(Error::InvalidArgument),
        }
    }

    /// Waits for the TX FIFO to become empty.
    fn wait_tx_empty(&self) -> Result<()> {
        let mut retries: u32 = 100_000;
        while retries > 0 {
            // SAFETY: mmio_base valid; STATUS is 32-bit RO.
            let status = unsafe { read_mmio32(self.config.mmio_base, I2C_STATUS_OFF) };
            if status & I2C_STATUS_TFE != 0 {
                return Ok(());
            }
            retries -= 1;
            core::hint::spin_loop();
        }
        Err(Error::Busy)
    }

    /// Waits for data to appear in the RX FIFO.
    fn wait_rx_ready(&self) -> Result<()> {
        let mut retries: u32 = 100_000;
        while retries > 0 {
            // SAFETY: mmio_base valid; STATUS is 32-bit RO.
            let status = unsafe { read_mmio32(self.config.mmio_base, I2C_STATUS_OFF) };
            if status & I2C_STATUS_RFNE != 0 {
                return Ok(());
            }
            retries -= 1;
            core::hint::spin_loop();
        }
        Err(Error::Busy)
    }

    /// Checks for a TX abort and updates error state.
    fn check_abort(&mut self) -> Result<()> {
        // SAFETY: mmio_base valid; RAW_INTR_STAT is 32-bit RO.
        let raw = unsafe { read_mmio32(self.config.mmio_base, I2C_RAW_INTR_STAT_OFF) };
        if raw & I2C_INTR_TX_ABRT != 0 {
            // SAFETY: mmio_base valid; TX_ABRT_SOURCE is clear-on-read.
            let source = unsafe { read_mmio32(self.config.mmio_base, I2C_TX_ABRT_SOURCE_OFF) };
            // Bit 0: 7BIT_ADDR_NOACK (device NACK)
            if source & 0x01 != 0 {
                self.nack_count += 1;
            }
            // Bit 12: ARB_LOST
            if source & (1 << 12) != 0 {
                self.arb_loss_count += 1;
            }
            self.state = I2cBusState::Error;
            return Err(Error::IoError);
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// I2cBusRegistry
// ---------------------------------------------------------------------------

/// Registry managing up to [`MAX_BUSES`] I2C bus controllers.
pub struct I2cBusRegistry {
    /// Registered I2C buses.
    buses: [Option<I2cBus>; MAX_BUSES],
    /// Number of registered buses.
    count: usize,
}

impl Default for I2cBusRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl I2cBusRegistry {
    /// Creates a new, empty I2C bus registry.
    pub const fn new() -> Self {
        Self {
            buses: [const { None }; MAX_BUSES],
            count: 0,
        }
    }

    /// Registers an I2C bus controller.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the registry is full, or
    /// [`Error::AlreadyExists`] if a bus with the same `id` exists.
    pub fn register(&mut self, bus: I2cBus) -> Result<()> {
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

    /// Unregisters an I2C bus by `id`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if no bus with that id exists,
    /// or [`Error::Busy`] if the bus is currently transferring.
    pub fn unregister(&mut self, id: u32) -> Result<()> {
        for slot in self.buses.iter_mut() {
            let busy = slot
                .as_ref()
                .is_some_and(|b| b.id == id && b.state == I2cBusState::Busy);
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
    pub fn get(&self, id: u32) -> Result<&I2cBus> {
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
    pub fn get_mut(&mut self, id: u32) -> Result<&mut I2cBus> {
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
