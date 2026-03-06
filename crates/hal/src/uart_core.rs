// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Core UART abstraction layer.
//!
//! Provides a hardware-independent UART interface covering baud rate configuration,
//! data format settings, FIFO management, and flow control. Architecture-specific
//! implementations (16550A, PL011, etc.) implement the `UartHal` trait.
//!
//! # UART Frame Format
//!
//! Each UART frame consists of: [Start bit] [Data bits] [Parity bit?] [Stop bit(s)]
//!
//! # References
//!
//! - UART 16550A specification
//! - ARM PrimeCell UART (PL011) Technical Reference Manual

#![allow(dead_code)]

use oncrix_lib::{Error, Result};

/// Standard UART baud rates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BaudRate {
    /// 9600 bps.
    Baud9600 = 9_600,
    /// 19200 bps.
    Baud19200 = 19_200,
    /// 38400 bps.
    Baud38400 = 38_400,
    /// 57600 bps.
    Baud57600 = 57_600,
    /// 115200 bps (most common for console).
    Baud115200 = 115_200,
    /// 230400 bps.
    Baud230400 = 230_400,
    /// 460800 bps.
    Baud460800 = 460_800,
    /// 921600 bps.
    Baud921600 = 921_600,
}

impl BaudRate {
    /// Returns the baud rate as a plain integer.
    pub const fn as_u32(self) -> u32 {
        self as u32
    }
}

/// Number of data bits per frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DataBits {
    /// 5 data bits (rare).
    Five = 5,
    /// 6 data bits (rare).
    Six = 6,
    /// 7 data bits.
    Seven = 7,
    /// 8 data bits (most common).
    Eight = 8,
}

/// Parity check mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Parity {
    /// No parity bit.
    None,
    /// Even parity.
    Even,
    /// Odd parity.
    Odd,
    /// Parity bit always 1 (mark parity).
    Mark,
    /// Parity bit always 0 (space parity).
    Space,
}

/// Number of stop bits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StopBits {
    /// One stop bit.
    One,
    /// One and a half stop bits (5-bit data only).
    OneAndHalf,
    /// Two stop bits.
    Two,
}

/// Hardware flow control mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlowControl {
    /// No hardware flow control.
    None,
    /// RTS/CTS hardware flow control.
    RtsCts,
    /// XON/XOFF software flow control.
    XonXoff,
}

/// Complete UART configuration.
#[derive(Debug, Clone, Copy)]
pub struct UartConfig {
    /// Baud rate.
    pub baud: BaudRate,
    /// Number of data bits.
    pub data_bits: DataBits,
    /// Parity mode.
    pub parity: Parity,
    /// Number of stop bits.
    pub stop_bits: StopBits,
    /// Flow control mode.
    pub flow_control: FlowControl,
}

impl UartConfig {
    /// Creates a standard 8N1 (8 data bits, no parity, 1 stop bit) configuration.
    pub const fn standard_8n1(baud: BaudRate) -> Self {
        Self {
            baud,
            data_bits: DataBits::Eight,
            parity: Parity::None,
            stop_bits: StopBits::One,
            flow_control: FlowControl::None,
        }
    }
}

impl Default for UartConfig {
    fn default() -> Self {
        Self::standard_8n1(BaudRate::Baud115200)
    }
}

/// UART line status flags.
#[derive(Debug, Clone, Copy)]
pub struct LineStatus {
    /// Receive data available.
    pub rx_ready: bool,
    /// Transmit holding register empty (ready to send).
    pub tx_empty: bool,
    /// Overrun error: received data when FIFO was full.
    pub overrun_error: bool,
    /// Parity error detected.
    pub parity_error: bool,
    /// Framing error detected.
    pub framing_error: bool,
    /// Break interrupt received.
    pub break_interrupt: bool,
}

/// UART modem status flags.
#[derive(Debug, Clone, Copy)]
pub struct ModemStatus {
    /// Clear To Send signal state.
    pub cts: bool,
    /// Data Set Ready signal state.
    pub dsr: bool,
    /// Ring Indicator state.
    pub ri: bool,
    /// Data Carrier Detect state.
    pub dcd: bool,
}

/// Trait for hardware-specific UART implementations.
pub trait UartHal {
    /// Initializes the UART with the given configuration.
    fn configure(&mut self, config: &UartConfig) -> Result<()>;

    /// Writes a single byte, blocking until the transmit buffer is ready.
    fn write_byte(&mut self, byte: u8) -> Result<()>;

    /// Reads a single byte, returning `None` if no data is available.
    fn read_byte(&mut self) -> Option<u8>;

    /// Flushes the transmit FIFO (waits until all bytes are sent).
    fn flush(&mut self) -> Result<()>;

    /// Reads the current line status.
    fn line_status(&self) -> LineStatus;

    /// Returns whether the receive buffer has data.
    fn rx_ready(&self) -> bool {
        self.line_status().rx_ready
    }

    /// Returns whether the transmit buffer is ready for a new byte.
    fn tx_ready(&self) -> bool {
        self.line_status().tx_empty
    }

    /// Writes a slice of bytes to the UART.
    fn write_bytes(&mut self, data: &[u8]) -> Result<()> {
        for &byte in data {
            self.write_byte(byte)?;
        }
        Ok(())
    }

    /// Reads up to `buf.len()` bytes from the UART, returning the count read.
    fn read_bytes(&mut self, buf: &mut [u8]) -> usize {
        let mut count = 0;
        for slot in buf.iter_mut() {
            match self.read_byte() {
                Some(b) => {
                    *slot = b;
                    count += 1;
                }
                None => break,
            }
        }
        count
    }
}

/// Generic software FIFO buffer for UART receive buffering.
pub struct UartFifo<const N: usize> {
    buf: [u8; N],
    read_pos: usize,
    write_pos: usize,
    count: usize,
}

impl<const N: usize> UartFifo<N> {
    /// Creates an empty FIFO.
    pub const fn new() -> Self {
        Self {
            buf: [0u8; N],
            read_pos: 0,
            write_pos: 0,
            count: 0,
        }
    }

    /// Pushes a byte into the FIFO. Returns `Err(Busy)` if full.
    pub fn push(&mut self, byte: u8) -> Result<()> {
        if self.count >= N {
            return Err(Error::Busy);
        }
        self.buf[self.write_pos] = byte;
        self.write_pos = (self.write_pos + 1) % N;
        self.count += 1;
        Ok(())
    }

    /// Pops a byte from the FIFO. Returns `None` if empty.
    pub fn pop(&mut self) -> Option<u8> {
        if self.count == 0 {
            return None;
        }
        let byte = self.buf[self.read_pos];
        self.read_pos = (self.read_pos + 1) % N;
        self.count -= 1;
        Some(byte)
    }

    /// Returns the number of bytes in the FIFO.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Returns whether the FIFO is empty.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Returns the remaining capacity.
    pub fn available(&self) -> usize {
        N - self.count
    }

    /// Clears all data from the FIFO.
    pub fn clear(&mut self) {
        self.read_pos = 0;
        self.write_pos = 0;
        self.count = 0;
    }
}

impl<const N: usize> Default for UartFifo<N> {
    fn default() -> Self {
        Self::new()
    }
}

/// Divisor for 16550A-compatible UARTs given a clock and baud rate.
///
/// divisor = clock_hz / (16 * baud_rate)
pub fn divisor_16550(clock_hz: u32, baud: BaudRate) -> Result<u16> {
    let baud_val = baud.as_u32();
    if baud_val == 0 {
        return Err(Error::InvalidArgument);
    }
    let divisor = clock_hz / (16 * baud_val);
    if divisor == 0 || divisor > 0xFFFF {
        return Err(Error::InvalidArgument);
    }
    Ok(divisor as u16)
}
