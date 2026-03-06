// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! I2C bit-bang (GPIO-based) master driver.
//!
//! Implements a software I2C master using two GPIO pins: SDA (data)
//! and SCL (clock). This bit-banging approach works on any platform
//! with GPIO access, independent of dedicated I2C hardware.
//!
//! # Protocol
//!
//! I2C communication consists of:
//! - **START condition**: SDA falls while SCL is high.
//! - **Data bits**: 8 bits per byte, MSB first, sampled on SCL rising edge.
//! - **ACK/NACK**: one clock after each byte; receiver pulls SDA low for ACK.
//! - **STOP condition**: SDA rises while SCL is high.
//!
//! # Timing
//!
//! Standard mode (100 kHz): half-period ≈ 5 µs.
//! Fast mode (400 kHz): half-period ≈ 1.25 µs.
//!
//! Reference: NXP UM10204 — I2C-bus specification.

use oncrix_lib::{Error, Result};

// ── Timing constants (in loop iterations, platform-dependent) ────────────────

/// Half-period for standard-mode (100 kHz) — loop count for ~5 µs delay.
const HALF_PERIOD_STD: u32 = 500;

/// Half-period for fast-mode (400 kHz) — loop count for ~1.25 µs delay.
const HALF_PERIOD_FAST: u32 = 125;

/// Clock-stretch timeout — max iterations waiting for SCL release.
const STRETCH_TIMEOUT: u32 = 100_000;

/// Retry count for arbitration loss recovery.
const ARB_RETRIES: u32 = 3;

// ── I2C speed mode ────────────────────────────────────────────────────────────

/// I2C clock speed mode.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum I2cSpeed {
    /// Standard mode: 100 kHz.
    Standard,
    /// Fast mode: 400 kHz.
    Fast,
}

impl I2cSpeed {
    fn half_period(self) -> u32 {
        match self {
            I2cSpeed::Standard => HALF_PERIOD_STD,
            I2cSpeed::Fast => HALF_PERIOD_FAST,
        }
    }
}

// ── GPIO trait ────────────────────────────────────────────────────────────────

/// Platform-provided GPIO pin operations for bit-bang I2C.
///
/// Implementors provide the minimal set of GPIO operations needed:
/// set high/low and read the current line state.
pub trait GpioPin {
    /// Drive the pin high (open-drain: release the line).
    fn set_high(&mut self);
    /// Drive the pin low (pull the line to ground).
    fn set_low(&mut self);
    /// Read the current state of the pin (true = high).
    fn is_high(&self) -> bool;
}

// ── I2cBitbang ───────────────────────────────────────────────────────────────

/// Software I2C master via GPIO bit-banging.
///
/// Owns references to the SDA and SCL GPIO pins and the configured speed.
pub struct I2cBitbang<SDA: GpioPin, SCL: GpioPin> {
    sda: SDA,
    scl: SCL,
    speed: I2cSpeed,
    half_period: u32,
}

impl<SDA: GpioPin, SCL: GpioPin> I2cBitbang<SDA, SCL> {
    /// Create a new bit-bang I2C master.
    ///
    /// Both pins start in the high (released) state.
    pub fn new(mut sda: SDA, mut scl: SCL, speed: I2cSpeed) -> Self {
        sda.set_high();
        scl.set_high();
        Self {
            sda,
            scl,
            speed,
            half_period: speed.half_period(),
        }
    }

    /// Change the clock speed.
    pub fn set_speed(&mut self, speed: I2cSpeed) {
        self.speed = speed;
        self.half_period = speed.half_period();
    }

    // ── Private timing ───────────────────────────────────────────────────────

    /// Busy-wait for approximately one half-period.
    fn delay(&self) {
        let mut n = self.half_period;
        while n > 0 {
            // SAFETY: simple spin — no side effects.
            core::hint::spin_loop();
            n -= 1;
        }
    }

    /// Release SCL and wait for clock stretching to end.
    fn scl_high_with_stretch(&mut self) -> Result<()> {
        self.scl.set_high();
        let mut timeout = STRETCH_TIMEOUT;
        while !self.scl.is_high() {
            if timeout == 0 {
                return Err(Error::Busy);
            }
            timeout -= 1;
        }
        Ok(())
    }

    // ── I2C primitives ───────────────────────────────────────────────────────

    /// Generate a START condition: SDA falls while SCL is high.
    fn start(&mut self) -> Result<()> {
        // Ensure lines are idle.
        self.sda.set_high();
        self.scl_high_with_stretch()?;
        self.delay();

        // SDA low while SCL high = START.
        self.sda.set_low();
        self.delay();
        self.scl.set_low();
        self.delay();
        Ok(())
    }

    /// Generate a STOP condition: SDA rises while SCL is high.
    fn stop(&mut self) -> Result<()> {
        self.sda.set_low();
        self.delay();
        self.scl_high_with_stretch()?;
        self.delay();
        // SDA high while SCL high = STOP.
        self.sda.set_high();
        self.delay();
        Ok(())
    }

    /// Generate a REPEATED START condition.
    fn repeated_start(&mut self) -> Result<()> {
        // Release SDA while SCL is low.
        self.sda.set_high();
        self.delay();
        self.scl_high_with_stretch()?;
        self.delay();
        // Now generate START.
        self.sda.set_low();
        self.delay();
        self.scl.set_low();
        self.delay();
        Ok(())
    }

    /// Send one bit on the bus.
    fn write_bit(&mut self, bit: bool) -> Result<()> {
        if bit {
            self.sda.set_high();
        } else {
            self.sda.set_low();
        }
        self.delay();
        self.scl_high_with_stretch()?;
        self.delay();
        self.scl.set_low();
        Ok(())
    }

    /// Read one bit from the bus (release SDA first).
    fn read_bit(&mut self) -> Result<bool> {
        self.sda.set_high(); // release SDA for reading
        self.delay();
        self.scl_high_with_stretch()?;
        let bit = self.sda.is_high();
        self.delay();
        self.scl.set_low();
        Ok(bit)
    }

    /// Send one byte and return whether the slave acknowledged (true = ACK).
    fn write_byte(&mut self, byte: u8) -> Result<bool> {
        for i in 0..8u8 {
            let bit = (byte >> (7 - i)) & 1 != 0;
            self.write_bit(bit)?;
        }
        // Read ACK bit.
        let nack = self.read_bit()?;
        Ok(!nack) // ACK = SDA low = false from read_bit
    }

    /// Receive one byte and send ACK (ack=true) or NACK (ack=false).
    fn read_byte(&mut self, send_ack: bool) -> Result<u8> {
        let mut byte = 0u8;
        for _ in 0..8u8 {
            let bit = self.read_bit()?;
            byte = (byte << 1) | if bit { 1 } else { 0 };
        }
        // Send ACK/NACK.
        self.write_bit(!send_ack)?; // ACK = low = false
        Ok(byte)
    }

    // ── Public API ───────────────────────────────────────────────────────────

    /// Write `data` to the slave at 7-bit `addr`.
    ///
    /// Returns `Ok(())` on success, `Err(Error::IoError)` on NACK.
    pub fn write(&mut self, addr: u8, data: &[u8]) -> Result<()> {
        let mut last_err = Ok(());
        for _ in 0..ARB_RETRIES {
            last_err = self.do_write(addr, data);
            if last_err.is_ok() {
                return Ok(());
            }
        }
        last_err
    }

    fn do_write(&mut self, addr: u8, data: &[u8]) -> Result<()> {
        self.start()?;
        // Address byte: 7-bit addr + write bit (0).
        let addr_byte = (addr << 1) & 0xFE;
        if !self.write_byte(addr_byte)? {
            let _ = self.stop();
            return Err(Error::IoError);
        }
        for &b in data {
            if !self.write_byte(b)? {
                let _ = self.stop();
                return Err(Error::IoError);
            }
        }
        self.stop()
    }

    /// Read `buf.len()` bytes from the slave at 7-bit `addr`.
    ///
    /// Returns `Ok(())` on success, `Err(Error::IoError)` on NACK.
    pub fn read(&mut self, addr: u8, buf: &mut [u8]) -> Result<()> {
        self.start()?;
        // Address byte: 7-bit addr + read bit (1).
        let addr_byte = (addr << 1) | 0x01;
        if !self.write_byte(addr_byte)? {
            let _ = self.stop();
            return Err(Error::IoError);
        }
        let len = buf.len();
        for (i, slot) in buf.iter_mut().enumerate() {
            let send_ack = i + 1 < len;
            *slot = self.read_byte(send_ack)?;
        }
        self.stop()
    }

    /// Write then read (combined write-read with repeated-start).
    ///
    /// Writes `write_data` then issues a repeated START, reads `read_buf.len()` bytes.
    pub fn write_read(&mut self, addr: u8, write_data: &[u8], read_buf: &mut [u8]) -> Result<()> {
        self.start()?;

        // Write phase.
        let wr_addr = (addr << 1) & 0xFE;
        if !self.write_byte(wr_addr)? {
            let _ = self.stop();
            return Err(Error::IoError);
        }
        for &b in write_data {
            if !self.write_byte(b)? {
                let _ = self.stop();
                return Err(Error::IoError);
            }
        }

        // Repeated START.
        self.repeated_start()?;

        // Read phase.
        let rd_addr = (addr << 1) | 0x01;
        if !self.write_byte(rd_addr)? {
            let _ = self.stop();
            return Err(Error::IoError);
        }
        let len = read_buf.len();
        for (i, slot) in read_buf.iter_mut().enumerate() {
            let send_ack = i + 1 < len;
            *slot = self.read_byte(send_ack)?;
        }
        self.stop()
    }

    /// Scan the bus: return a bitmask of 7-bit addresses that ACK.
    ///
    /// Bit `n` is set if address `n` responded with ACK.
    /// The reserved range (0x00–0x07, 0x78–0x7F) is skipped.
    pub fn scan(&mut self) -> u128 {
        let mut found = 0u128;
        for addr in 0x08u8..=0x77 {
            if self.probe(addr).is_ok() {
                found |= 1u128 << addr;
            }
        }
        found
    }

    /// Probe a single address — START, send addr+W, check ACK, STOP.
    ///
    /// Returns `Ok(())` if the device ACKed, `Err(Error::NotFound)` otherwise.
    pub fn probe(&mut self, addr: u8) -> Result<()> {
        self.start()?;
        let addr_byte = (addr << 1) & 0xFE;
        let acked = self.write_byte(addr_byte)?;
        let _ = self.stop();
        if acked { Ok(()) } else { Err(Error::NotFound) }
    }
}
