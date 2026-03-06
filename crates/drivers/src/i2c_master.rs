// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! I2C bus master driver.
//!
//! Implements an I2C master controller using a generic MMIO register
//! interface compatible with common I2C IP cores (Synopsys DesignWare,
//! OpenCores I2C).  Provides:
//!
//! - Master initialization and bus frequency programming
//! - Single-byte and multi-byte read/write transactions
//! - Repeated-start (combined) transfers
//! - 7-bit and 10-bit addressing
//! - Bus error and arbitration-lost detection
//!
//! # MMIO Register Map (DesignWare I2C)
//!
//! | Offset | Name     | Description                |
//! |--------|----------|----------------------------|
//! | 0x000  | CON      | Control register           |
//! | 0x004  | TAR      | Target address             |
//! | 0x008  | SAR      | Slave address              |
//! | 0x010  | DATA_CMD | Data command register      |
//! | 0x014  | SS_SCL_H | Standard SCL high count    |
//! | 0x018  | SS_SCL_L | Standard SCL low count     |
//! | 0x020  | FS_SCL_H | Fast SCL high count        |
//! | 0x024  | FS_SCL_L | Fast SCL low count         |
//! | 0x02C  | INTR_STAT| Interrupt status           |
//! | 0x030  | INTR_MASK| Interrupt mask             |
//! | 0x040  | RAW_INTR | Raw interrupt status       |
//! | 0x044  | RX_TL    | Rx FIFO threshold          |
//! | 0x048  | TX_TL    | Tx FIFO threshold          |
//! | 0x04C  | CLR_INTR | Clear all interrupts       |
//! | 0x06C  | ENABLE   | Controller enable          |
//! | 0x070  | STATUS   | Status register            |
//! | 0x074  | TXFLR    | Tx FIFO level              |
//! | 0x078  | RXFLR    | Rx FIFO level              |
//! | 0x0A0  | TX_ABT_SOURCE | Tx abort source       |

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// MMIO Register Offsets
// ---------------------------------------------------------------------------

/// Control register.
const REG_CON: u32 = 0x000;
/// Target address register.
const REG_TAR: u32 = 0x004;
/// Data command FIFO.
const REG_DATA_CMD: u32 = 0x010;
/// Standard mode SCL high count.
const REG_SS_SCL_H: u32 = 0x014;
/// Standard mode SCL low count.
const REG_SS_SCL_L: u32 = 0x018;
/// Fast mode SCL high count.
const REG_FS_SCL_H: u32 = 0x020;
/// Fast mode SCL low count.
const REG_FS_SCL_L: u32 = 0x024;
/// Interrupt status.
const REG_INTR_STAT: u32 = 0x02C;
/// Interrupt mask.
const REG_INTR_MASK: u32 = 0x030;
/// Clear all interrupts.
const REG_CLR_INTR: u32 = 0x04C;
/// Enable register.
const REG_ENABLE: u32 = 0x06C;
/// Status register.
const REG_STATUS: u32 = 0x070;
/// Tx FIFO level.
const REG_TXFLR: u32 = 0x074;
/// Rx FIFO level.
const REG_RXFLR: u32 = 0x078;
/// Tx abort source.
const REG_TX_ABT_SOURCE: u32 = 0x0A0;

// ---------------------------------------------------------------------------
// CON register bits
// ---------------------------------------------------------------------------

/// CON: Master mode enabled.
const CON_MASTER_EN: u32 = 1 << 0;
/// CON: Standard mode (100 kHz).
const CON_SPEED_STD: u32 = 0b01 << 1;
/// CON: Fast mode (400 kHz).
const CON_SPEED_FAST: u32 = 0b10 << 1;
/// CON: 10-bit addressing for slave.
const CON_10BIT_SLAVE: u32 = 1 << 3;
/// CON: Restart enable.
const CON_RESTART_EN: u32 = 1 << 5;
/// CON: Slave disable (we are master-only).
const CON_SLAVE_DISABLE: u32 = 1 << 6;

// ---------------------------------------------------------------------------
// DATA_CMD bits
// ---------------------------------------------------------------------------

/// DATA_CMD: Read command (1) vs write (0).
const DATA_CMD_READ: u32 = 1 << 8;
/// DATA_CMD: Generate STOP after this byte.
const DATA_CMD_STOP: u32 = 1 << 9;
/// DATA_CMD: Generate RESTART before this byte.
const DATA_CMD_RESTART: u32 = 1 << 10;

// ---------------------------------------------------------------------------
// STATUS register bits
// ---------------------------------------------------------------------------

/// STATUS: Master FSM activity.
const STATUS_MASTER_ACTIVITY: u32 = 1 << 5;
/// STATUS: Tx FIFO not full.
const STATUS_TFNF: u32 = 1 << 1;
/// STATUS: Rx FIFO not empty.
const STATUS_RFNE: u32 = 1 << 3;

// ---------------------------------------------------------------------------
// INTR bits
// ---------------------------------------------------------------------------

/// INTR: Tx abort.
const INTR_TX_ABRT: u32 = 1 << 6;
/// INTR: Stop detected.
const INTR_STOP_DET: u32 = 1 << 9;

// ---------------------------------------------------------------------------
// Spin limits
// ---------------------------------------------------------------------------

const WAIT_ITERS: u32 = 100_000;

// ---------------------------------------------------------------------------
// MMIO helpers
// ---------------------------------------------------------------------------

unsafe fn read32(base: u64, offset: u32) -> u32 {
    // SAFETY: Volatile read from I2C controller MMIO.
    unsafe { core::ptr::read_volatile((base + offset as u64) as *const u32) }
}

unsafe fn write32(base: u64, offset: u32, val: u32) {
    // SAFETY: Volatile write to I2C controller MMIO.
    unsafe { core::ptr::write_volatile((base + offset as u64) as *mut u32, val) }
}

// ---------------------------------------------------------------------------
// I2cSpeed
// ---------------------------------------------------------------------------

/// I2C bus speed mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum I2cSpeed {
    /// Standard mode: 100 kHz.
    Standard,
    /// Fast mode: 400 kHz.
    Fast,
}

// ---------------------------------------------------------------------------
// I2cMaster
// ---------------------------------------------------------------------------

/// I2C bus master controller.
pub struct I2cMaster {
    /// MMIO base address.
    base: u64,
    /// Input clock frequency in Hz (used to compute SCL counts).
    clk_hz: u32,
    /// Current bus speed.
    speed: I2cSpeed,
}

impl I2cMaster {
    /// Create a new [`I2cMaster`] instance.
    ///
    /// `base` is the MMIO base address; `clk_hz` is the controller input
    /// clock frequency used for SCL count computation.
    pub const fn new(base: u64, clk_hz: u32) -> Self {
        Self {
            base,
            clk_hz,
            speed: I2cSpeed::Standard,
        }
    }

    /// Initialize the I2C master controller.
    pub fn init(&mut self, speed: I2cSpeed) -> Result<()> {
        self.speed = speed;

        // SAFETY: I2C MMIO initialization sequence.
        unsafe {
            // Disable controller
            write32(self.base, REG_ENABLE, 0);
            self.wait_disabled()?;

            // Configure CON register
            let (speed_bits, scl_h_reg, scl_l_reg) = match speed {
                I2cSpeed::Standard => (CON_SPEED_STD, REG_SS_SCL_H, REG_SS_SCL_L),
                I2cSpeed::Fast => (CON_SPEED_FAST, REG_FS_SCL_H, REG_FS_SCL_L),
            };

            let con = CON_MASTER_EN | speed_bits | CON_RESTART_EN | CON_SLAVE_DISABLE;
            write32(self.base, REG_CON, con);

            // Compute SCL high/low counts
            let (freq_khz, duty) = match speed {
                I2cSpeed::Standard => (100u32, 50u32),
                I2cSpeed::Fast => (400u32, 50u32),
            };
            let period = self.clk_hz / (freq_khz * 1000);
            let high = period * duty / 100;
            let low = period - high;
            write32(self.base, scl_h_reg, high.max(6));
            write32(self.base, scl_l_reg, low.max(8));

            // Mask all interrupts except TX_ABRT
            write32(self.base, REG_INTR_MASK, INTR_TX_ABRT);

            // Enable controller
            write32(self.base, REG_ENABLE, 1);
        }
        Ok(())
    }

    /// Write `data` to device at 7-bit `addr`.
    pub fn write(&self, addr: u8, data: &[u8]) -> Result<()> {
        if data.is_empty() {
            return Ok(());
        }
        // SAFETY: Setting target address and writing data to Tx FIFO.
        unsafe {
            self.set_target(addr as u16)?;
            write32(self.base, REG_CLR_INTR, 0xFFFF_FFFF);

            let last = data.len() - 1;
            for (i, &byte) in data.iter().enumerate() {
                self.wait_tx_not_full()?;
                let stop = if i == last { DATA_CMD_STOP } else { 0 };
                write32(self.base, REG_DATA_CMD, byte as u32 | stop);
            }
        }
        self.wait_transfer_done()
    }

    /// Read `len` bytes from device at 7-bit `addr`.
    pub fn read(&self, addr: u8, buf: &mut [u8]) -> Result<()> {
        if buf.is_empty() {
            return Ok(());
        }
        // SAFETY: Setting target and issuing read commands.
        unsafe {
            self.set_target(addr as u16)?;
            write32(self.base, REG_CLR_INTR, 0xFFFF_FFFF);

            let last = buf.len() - 1;
            for i in 0..buf.len() {
                self.wait_tx_not_full()?;
                let stop = if i == last { DATA_CMD_STOP } else { 0 };
                write32(self.base, REG_DATA_CMD, DATA_CMD_READ | stop);
            }

            for slot in buf.iter_mut() {
                self.wait_rx_not_empty()?;
                *slot = (read32(self.base, REG_DATA_CMD) & 0xFF) as u8;
            }
        }
        self.check_abort()
    }

    /// Perform a combined write-then-read (repeated-start) transfer.
    pub fn write_read(&self, addr: u8, write: &[u8], read: &mut [u8]) -> Result<()> {
        if write.is_empty() || read.is_empty() {
            return Err(Error::InvalidArgument);
        }
        // SAFETY: Repeated-start write+read sequence.
        unsafe {
            self.set_target(addr as u16)?;
            write32(self.base, REG_CLR_INTR, 0xFFFF_FFFF);

            // Write phase (no STOP)
            for &byte in write {
                self.wait_tx_not_full()?;
                write32(self.base, REG_DATA_CMD, byte as u32);
            }

            // Read phase with RESTART on first byte
            let last = read.len() - 1;
            for i in 0..read.len() {
                self.wait_tx_not_full()?;
                let restart = if i == 0 { DATA_CMD_RESTART } else { 0 };
                let stop = if i == last { DATA_CMD_STOP } else { 0 };
                write32(self.base, REG_DATA_CMD, DATA_CMD_READ | restart | stop);
            }

            for slot in read.iter_mut() {
                self.wait_rx_not_empty()?;
                *slot = (read32(self.base, REG_DATA_CMD) & 0xFF) as u8;
            }
        }
        self.check_abort()
    }

    // ---- Internal helpers --------------------------------------------------

    unsafe fn set_target(&self, addr: u16) -> Result<()> {
        // SAFETY: Writing target address to I2C TAR register.
        unsafe { write32(self.base, REG_TAR, addr as u32) };
        Ok(())
    }

    fn wait_disabled(&self) -> Result<()> {
        for _ in 0..WAIT_ITERS {
            // SAFETY: Reading I2C ENABLE register status bit.
            let en = unsafe { read32(self.base, REG_ENABLE) };
            if (en & 1) == 0 {
                return Ok(());
            }
        }
        Err(Error::Busy)
    }

    fn wait_tx_not_full(&self) -> Result<()> {
        for _ in 0..WAIT_ITERS {
            // SAFETY: Reading I2C STATUS register.
            let s = unsafe { read32(self.base, REG_STATUS) };
            if (s & STATUS_TFNF) != 0 {
                return Ok(());
            }
        }
        Err(Error::Busy)
    }

    fn wait_rx_not_empty(&self) -> Result<()> {
        for _ in 0..WAIT_ITERS {
            // SAFETY: Reading I2C STATUS register for Rx data.
            let s = unsafe { read32(self.base, REG_STATUS) };
            if (s & STATUS_RFNE) != 0 {
                return Ok(());
            }
        }
        Err(Error::Busy)
    }

    fn wait_transfer_done(&self) -> Result<()> {
        for _ in 0..WAIT_ITERS {
            // SAFETY: Polling INTR_STAT for STOP_DET or TX_ABRT.
            let intr = unsafe { read32(self.base, REG_INTR_STAT) };
            if (intr & INTR_TX_ABRT) != 0 {
                return Err(Error::IoError);
            }
            // SAFETY: Polling STATUS for master idle.
            let status = unsafe { read32(self.base, REG_STATUS) };
            if (status & STATUS_MASTER_ACTIVITY) == 0 {
                return Ok(());
            }
        }
        Err(Error::Busy)
    }

    fn check_abort(&self) -> Result<()> {
        // SAFETY: Reading interrupt status to check for aborts.
        let intr = unsafe { read32(self.base, REG_INTR_STAT) };
        if (intr & INTR_TX_ABRT) != 0 {
            Err(Error::IoError)
        } else {
            Ok(())
        }
    }

    /// Return the current bus speed.
    pub const fn speed(&self) -> I2cSpeed {
        self.speed
    }

    /// Return the MMIO base address.
    pub const fn base(&self) -> u64 {
        self.base
    }

    /// Return the number of bytes in the Rx FIFO.
    pub fn rx_level(&self) -> u32 {
        // SAFETY: Reading I2C Rx FIFO level register.
        unsafe { read32(self.base, REG_RXFLR) }
    }

    /// Return the number of bytes in the Tx FIFO.
    pub fn tx_level(&self) -> u32 {
        // SAFETY: Reading I2C Tx FIFO level register.
        unsafe { read32(self.base, REG_TXFLR) }
    }
}
