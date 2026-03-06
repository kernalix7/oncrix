// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Early serial console for boot-time debugging.
//!
//! Provides a minimal polling UART driver that can be used before the
//! full interrupt-driven serial driver is initialised. Supports the
//! standard 8250/16550 UART found at COM1 (0x3F8) and COM2 (0x2F8).
//!
//! # Usage
//!
//! ```no_run
//! let mut con = EarlyConsole::new(COM1_BASE, 115200);
//! con.init(1843200).unwrap(); // 1.8432 MHz UART clock
//! con.write_str("booting ONCRIX\n");
//! ```

use oncrix_lib::{Error, Result};

// ── UART register offsets (relative to base I/O port) ───────────────────────

/// Receive Holding Register / Transmit Holding Register (DLAB=0).
const UART_RHR: u16 = 0;
/// Interrupt Enable Register (DLAB=0).
const UART_IER: u16 = 1;
/// FIFO Control Register (write) / IIR (read).
const UART_FCR: u16 = 2;
/// Line Control Register.
const UART_LCR: u16 = 3;
/// Modem Control Register.
const UART_MCR: u16 = 4;
/// Line Status Register.
const UART_LSR: u16 = 5;

/// Divisor Latch Low (DLAB=1, offset 0).
const UART_DLL: u16 = 0;
/// Divisor Latch High (DLAB=1, offset 1).
const UART_DLH: u16 = 1;

// ── LCR bit fields ───────────────────────────────────────────────────────────

/// LCR: 8 data bits, no parity, 1 stop bit (8N1).
const LCR_8N1: u8 = 0x03;
/// LCR: Divisor Latch Access Bit — enables baud rate divisor registers.
const LCR_DLAB: u8 = 0x80;

// ── LSR bit fields ───────────────────────────────────────────────────────────

/// LSR: Data Ready — at least one character in RHR.
const LSR_DR: u8 = 0x01;
/// LSR: Transmitter Holding Register Empty — THR can accept a character.
const LSR_THRE: u8 = 0x20;

// ── FCR values ───────────────────────────────────────────────────────────────

/// FCR: Enable FIFO, clear RX and TX FIFOs, 8-byte trigger level.
const FCR_FIFO_INIT: u8 = 0xC7;

// ── MCR values ───────────────────────────────────────────────────────────────

/// MCR: DTR + RTS asserted.
const MCR_DTR_RTS: u8 = 0x03;

// ── Common base port addresses ───────────────────────────────────────────────

/// COM1 I/O port base address.
pub const COM1_BASE: u16 = 0x3F8;
/// COM2 I/O port base address.
pub const COM2_BASE: u16 = 0x2F8;
/// COM3 I/O port base address.
pub const COM3_BASE: u16 = 0x3E8;
/// COM4 I/O port base address.
pub const COM4_BASE: u16 = 0x2E8;

/// Transmit polling timeout in iterations.
const TX_TIMEOUT: u32 = 100_000;

// ── EarlyConsole ─────────────────────────────────────────────────────────────

/// Early boot serial console.
pub struct EarlyConsole {
    /// Base I/O port of the UART (e.g. `COM1_BASE`).
    base: u16,
    /// Requested baud rate.
    baud: u32,
    /// Whether the console has been initialised.
    initialised: bool,
}

impl EarlyConsole {
    /// Create an uninitialised early console.
    ///
    /// `baud` is the desired baud rate (e.g. 115200).
    pub const fn new(base: u16, baud: u32) -> Self {
        Self {
            base,
            baud,
            initialised: false,
        }
    }

    /// Initialise the UART at the requested baud rate.
    ///
    /// `uart_clock_hz` is the UART base clock (typically 1843200 Hz for
    /// a standard PC UART, which uses a 1.8432 MHz crystal).
    ///
    /// Configures: 8N1 framing, FIFO enabled, DTR/RTS asserted,
    /// interrupts disabled (polling mode).
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidArgument`] if `base` is zero or `baud` is zero.
    /// - [`Error::InvalidArgument`] if the computed divisor would be zero.
    pub fn init(&mut self, uart_clock_hz: u32) -> Result<()> {
        if self.base == 0 || self.baud == 0 {
            return Err(Error::InvalidArgument);
        }
        let divisor = uart_clock_hz / (self.baud * 16);
        if divisor == 0 || divisor > 0xFFFF {
            return Err(Error::InvalidArgument);
        }

        // Disable all interrupts.
        self.write_reg(UART_IER, 0x00);

        // Enable DLAB and set baud rate divisor.
        self.write_reg(UART_LCR, LCR_DLAB);
        self.write_reg(UART_DLL, (divisor & 0xFF) as u8);
        self.write_reg(UART_DLH, ((divisor >> 8) & 0xFF) as u8);

        // 8N1, disable DLAB.
        self.write_reg(UART_LCR, LCR_8N1);

        // Enable and reset FIFO.
        self.write_reg(UART_FCR, FCR_FIFO_INIT);

        // Assert DTR and RTS.
        self.write_reg(UART_MCR, MCR_DTR_RTS);

        self.initialised = true;
        Ok(())
    }

    /// Write a single byte to the UART (polling TX).
    ///
    /// Waits for the Transmitter Holding Register to become empty
    /// before writing. Returns after the byte is accepted by the FIFO.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Busy`] if the THRE bit does not set within
    /// the polling timeout.
    pub fn write_byte(&self, byte: u8) -> Result<()> {
        for _ in 0..TX_TIMEOUT {
            if self.read_reg(UART_LSR) & LSR_THRE != 0 {
                self.write_reg(UART_RHR, byte);
                return Ok(());
            }
        }
        Err(Error::Busy)
    }

    /// Write a string to the UART.
    ///
    /// Translates `\n` to `\r\n` for terminal compatibility.
    ///
    /// Silently drops bytes that time out (best-effort early console).
    pub fn write_str(&self, s: &str) {
        for byte in s.bytes() {
            if byte == b'\n' {
                let _ = self.write_byte(b'\r');
            }
            let _ = self.write_byte(byte);
        }
    }

    /// Attempt to read a byte from the UART (non-blocking).
    ///
    /// Returns `Some(byte)` if a character is available, `None` otherwise.
    pub fn read_byte(&self) -> Option<u8> {
        if self.read_reg(UART_LSR) & LSR_DR != 0 {
            Some(self.read_reg(UART_RHR))
        } else {
            None
        }
    }

    /// Return whether the console has been initialised.
    pub fn is_initialised(&self) -> bool {
        self.initialised
    }

    /// Return the configured baud rate.
    pub fn baud(&self) -> u32 {
        self.baud
    }

    /// Return the I/O base port.
    pub fn base_port(&self) -> u16 {
        self.base
    }

    // ── Register access ───────────────────────────────────────────────────────

    /// Write to a UART register at `self.base + offset`.
    fn write_reg(&self, offset: u16, val: u8) {
        crate::io_port::outb(self.base + offset, val);
    }

    /// Read from a UART register at `self.base + offset`.
    fn read_reg(&self, offset: u16) -> u8 {
        crate::io_port::inb(self.base + offset)
    }
}

// ── Global early console ─────────────────────────────────────────────────────

/// Initialise the global early console on COM1 at 115200 baud.
///
/// Uses the standard UART clock of 1843200 Hz.
///
/// # Errors
///
/// Propagates errors from [`EarlyConsole::init`].
pub fn init_early_console(base: u16, baud: u32) -> Result<EarlyConsole> {
    let mut con = EarlyConsole::new(base, baud);
    con.init(1_843_200)?;
    Ok(con)
}
