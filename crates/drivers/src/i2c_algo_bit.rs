// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Bit-banging I2C algorithm.
//!
//! Implements the I2C bus protocol using GPIO-level SDA/SCL control
//! callbacks.  Any platform that can drive two GPIO lines can use this
//! driver to expose an I2C master adapter.
//!
//! # Protocol
//!
//! Standard I2C framing:
//! - START: SDA falls while SCL is high.
//! - STOP: SDA rises while SCL is high.
//! - Bit: data sampled on SCL rising edge; data changes while SCL is low.
//! - ACK: receiver pulls SDA low during the 9th clock pulse.
//!
//! # Clock stretching
//!
//! If the slave holds SCL low after the master releases it, we poll
//! until SCL is released (or a timeout expires).

use oncrix_lib::{Error, Result};

// ── Constants ────────────────────────────────────────────────────────────────

/// Maximum retries for clock-stretch polling.
const STRETCH_TIMEOUT: u32 = 100_000;

/// Number of retries for arbitration loss recovery.
const ARB_RETRIES: u8 = 3;

// ── Bit-bang GPIO callbacks ───────────────────────────────────────────────────

/// GPIO control function type: set a line high (true) or low (false).
pub type SetLineFn = fn(high: bool);

/// GPIO read function type: return the current logical level of a line.
pub type GetLineFn = fn() -> bool;

// ── BitBangAdapter ───────────────────────────────────────────────────────────

/// Bit-banging I2C adapter.
///
/// Callers provide four function pointers that directly drive/read the
/// SDA and SCL GPIO lines.
pub struct BitBangAdapter {
    /// Drive SDA high or low.
    sda_set: SetLineFn,
    /// Read SDA current level.
    sda_get: GetLineFn,
    /// Drive SCL high or low.
    scl_set: SetLineFn,
    /// Read SCL current level (for clock-stretch detection).
    scl_get: GetLineFn,
    /// Half-clock delay in loop iterations (approximates the clock period).
    half_period: u32,
    /// Whether the bus is currently owned (between START and STOP).
    bus_busy: bool,
}

impl BitBangAdapter {
    /// Create a new bit-bang adapter.
    ///
    /// `half_period` controls the clock frequency: a larger value slows
    /// the clock.  A typical value for 100 kHz on a 1 GHz bus is ~5000.
    pub const fn new(
        sda_set: SetLineFn,
        sda_get: GetLineFn,
        scl_set: SetLineFn,
        scl_get: GetLineFn,
        half_period: u32,
    ) -> Self {
        Self {
            sda_set,
            sda_get,
            scl_set,
            scl_get,
            half_period,
            bus_busy: false,
        }
    }

    // ── Low-level bit operations ─────────────────────────────────────────────

    /// Half-period busy-wait (delay).
    fn delay(&self) {
        let mut i = self.half_period;
        while i > 0 {
            // SAFETY: This is a bare spin loop used as a timing delay.
            // core::hint::spin_loop() signals to the CPU that this is
            // intentional spinning, reducing power consumption.
            core::hint::spin_loop();
            i -= 1;
        }
    }

    /// Raise SCL and wait for clock stretching to complete.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Busy`] if the slave holds SCL low beyond the
    /// stretch timeout.
    fn scl_high(&self) -> Result<()> {
        (self.scl_set)(true);
        for _ in 0..STRETCH_TIMEOUT {
            if (self.scl_get)() {
                return Ok(());
            }
            core::hint::spin_loop();
        }
        Err(Error::Busy)
    }

    /// Lower SCL.
    fn scl_low(&self) {
        (self.scl_set)(false);
    }

    /// Set SDA to `high`.
    fn sda(&self, high: bool) {
        (self.sda_set)(high);
    }

    /// Read SDA.
    fn sda_read(&self) -> bool {
        (self.sda_get)()
    }

    // ── I2C framing ──────────────────────────────────────────────────────────

    /// Generate an I2C START condition.
    ///
    /// SDA falls while SCL is high.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Busy`] if clock stretching times out, or
    /// [`Error::WouldBlock`] if another master won arbitration.
    pub fn start(&mut self) -> Result<()> {
        // SDA and SCL both high before START.
        self.sda(true);
        self.scl_high()?;
        self.delay();
        // Check for bus contention: SDA should be high.
        if !self.sda_read() {
            return Err(Error::WouldBlock);
        }
        // SDA → low while SCL is high.
        self.sda(false);
        self.delay();
        // SCL → low.
        self.scl_low();
        self.delay();
        self.bus_busy = true;
        Ok(())
    }

    /// Generate a repeated START condition.
    pub fn repeated_start(&mut self) -> Result<()> {
        self.sda(true);
        self.delay();
        self.scl_high()?;
        self.delay();
        self.sda(false);
        self.delay();
        self.scl_low();
        self.delay();
        Ok(())
    }

    /// Generate an I2C STOP condition.
    ///
    /// SDA rises while SCL is high.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Busy`] if clock stretching times out.
    pub fn stop(&mut self) -> Result<()> {
        self.sda(false);
        self.delay();
        self.scl_high()?;
        self.delay();
        self.sda(true);
        self.delay();
        self.bus_busy = false;
        Ok(())
    }

    /// Send one bit on the I2C bus.
    ///
    /// Sets SDA then toggles SCL high→low.  Returns `false` if the
    /// master loses arbitration (another master drives SDA opposite).
    ///
    /// # Errors
    ///
    /// Returns [`Error::Busy`] on clock stretch timeout, or
    /// [`Error::WouldBlock`] on arbitration loss.
    pub fn send_bit(&self, bit: bool) -> Result<()> {
        self.sda(bit);
        self.delay();
        self.scl_high()?;
        self.delay();
        // Arbitration: sample SDA while SCL is high.
        if bit && !self.sda_read() {
            self.scl_low();
            return Err(Error::WouldBlock); // arbitration lost
        }
        self.scl_low();
        self.delay();
        Ok(())
    }

    /// Receive one bit from the I2C bus.
    ///
    /// Releases SDA (high-Z), raises SCL, samples SDA, lowers SCL.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Busy`] on clock stretch timeout.
    pub fn recv_bit(&self) -> Result<bool> {
        self.sda(true); // release SDA
        self.delay();
        self.scl_high()?;
        self.delay();
        let bit = self.sda_read();
        self.scl_low();
        self.delay();
        Ok(bit)
    }

    /// Send one byte and return whether the slave acknowledged it.
    ///
    /// MSB first.  Returns `true` on ACK (SDA low during 9th clock).
    ///
    /// # Errors
    ///
    /// Propagates errors from [`send_bit`] / [`recv_bit`].
    pub fn send_byte(&self, byte: u8) -> Result<bool> {
        for i in (0..8).rev() {
            self.send_bit((byte >> i) & 1 != 0)?;
        }
        // Receive ACK/NACK bit.
        let ack = self.recv_bit()?;
        Ok(!ack) // ACK = SDA low = false; so !false = true
    }

    /// Receive one byte from the bus.
    ///
    /// MSB first.  `ack` controls whether the master sends ACK (true)
    /// or NACK (false) after the byte.
    ///
    /// # Errors
    ///
    /// Propagates errors from [`recv_bit`] / [`send_bit`].
    pub fn recv_byte(&self, ack: bool) -> Result<u8> {
        let mut byte = 0u8;
        for i in (0..8).rev() {
            if self.recv_bit()? {
                byte |= 1 << i;
            }
        }
        // Send ACK or NACK.
        self.send_bit(!ack)?; // ACK = SDA low = false
        Ok(byte)
    }

    // ── High-level transfer ──────────────────────────────────────────────────

    /// Write `data` bytes to the slave at 7-bit `addr`.
    ///
    /// Performs: START → address+W → data bytes → STOP.
    ///
    /// # Errors
    ///
    /// - [`Error::IoError`] if the slave NAKs the address or any data byte.
    /// - [`Error::WouldBlock`] if arbitration is lost.
    /// - [`Error::Busy`] on clock-stretch timeout.
    pub fn write(&mut self, addr: u8, data: &[u8]) -> Result<()> {
        for attempt in 0..=ARB_RETRIES {
            match self.start() {
                Ok(()) => break,
                Err(Error::WouldBlock) if attempt < ARB_RETRIES => continue,
                Err(e) => return Err(e),
            }
        }

        // Address byte: 7-bit addr shifted left, bit 0 = 0 (write).
        let addr_byte = (addr << 1) & 0xFE;
        if !self.send_byte(addr_byte)? {
            let _ = self.stop();
            return Err(Error::IoError);
        }

        for &byte in data {
            if !self.send_byte(byte)? {
                let _ = self.stop();
                return Err(Error::IoError);
            }
        }

        self.stop()
    }

    /// Read `len` bytes from the slave at 7-bit `addr` into `buf`.
    ///
    /// Performs: START → address+R → data bytes (ACK all but last) → STOP.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidArgument`] if `buf.len() < len`.
    /// - [`Error::IoError`] if the slave NAKs the address.
    /// - [`Error::WouldBlock`] on arbitration loss.
    /// - [`Error::Busy`] on clock-stretch timeout.
    pub fn read(&mut self, addr: u8, buf: &mut [u8]) -> Result<()> {
        if buf.is_empty() {
            return Ok(());
        }
        self.start()?;

        // Address byte: 7-bit addr shifted left, bit 0 = 1 (read).
        let addr_byte = ((addr << 1) & 0xFE) | 0x01;
        if !self.send_byte(addr_byte)? {
            let _ = self.stop();
            return Err(Error::IoError);
        }

        let last = buf.len() - 1;
        for (i, slot) in buf.iter_mut().enumerate() {
            *slot = self.recv_byte(i < last)?; // NACK on last byte
        }

        self.stop()
    }

    /// Return whether the bus is currently busy (between START and STOP).
    pub fn is_busy(&self) -> bool {
        self.bus_busy
    }
}
