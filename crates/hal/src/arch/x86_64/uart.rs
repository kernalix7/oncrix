// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! x86_64 UART 16550 serial port driver.

use super::io::{inb, outb};
use crate::serial::SerialPort;
use oncrix_lib::{Error, Result};

/// Standard COM port I/O base addresses.
pub const COM1: u16 = 0x3F8;
pub const COM2: u16 = 0x2F8;

/// UART 16550 register offsets from the base I/O port.
mod reg {
    /// Data register (read: receive, write: transmit).
    pub const DATA: u16 = 0;
    /// Interrupt Enable Register.
    pub const IER: u16 = 1;
    /// FIFO Control Register (write) / Interrupt ID (read).
    pub const FCR: u16 = 2;
    /// Line Control Register.
    pub const LCR: u16 = 3;
    /// Modem Control Register.
    pub const MCR: u16 = 4;
    /// Line Status Register.
    pub const LSR: u16 = 5;
    /// Divisor Latch Low (when DLAB=1).
    pub const DLL: u16 = 0;
    /// Divisor Latch High (when DLAB=1).
    pub const DLH: u16 = 1;
}

/// Line Status Register flags.
mod lsr {
    /// Data ready (receive buffer has data).
    pub const DATA_READY: u8 = 1 << 0;
    /// Transmitter holding register empty (safe to write).
    pub const TX_EMPTY: u8 = 1 << 5;
}

/// x86_64 UART 16550 serial port.
pub struct Uart16550 {
    /// Base I/O port address (e.g., 0x3F8 for COM1).
    base: u16,
}

impl Uart16550 {
    /// Create a new UART 16550 instance at the given base port.
    ///
    /// Does NOT initialize the hardware; call [`init`](Self::init) first.
    pub const fn new(base: u16) -> Self {
        Self { base }
    }

    /// Initialize the UART with 115200 baud, 8N1, FIFO enabled.
    pub fn init(&self) {
        // SAFETY: We are writing to well-known x86 I/O ports for
        // UART configuration. These ports are safe to access in Ring 0.
        unsafe {
            // Disable interrupts
            outb(self.base + reg::IER, 0x00);

            // Enable DLAB (set baud rate divisor)
            outb(self.base + reg::LCR, 0x80);

            // Set divisor to 1 (115200 baud)
            outb(self.base + reg::DLL, 0x01);
            outb(self.base + reg::DLH, 0x00);

            // 8 bits, no parity, one stop bit (8N1), disable DLAB
            outb(self.base + reg::LCR, 0x03);

            // Enable FIFO, clear buffers, 14-byte threshold
            outb(self.base + reg::FCR, 0xC7);

            // Enable IRQs, set RTS/DSR
            outb(self.base + reg::MCR, 0x0B);
        }
    }

    /// Check if the transmit buffer is empty.
    fn is_tx_empty(&self) -> bool {
        // SAFETY: Reading the LSR is always safe in Ring 0.
        unsafe { inb(self.base + reg::LSR) & lsr::TX_EMPTY != 0 }
    }

    /// Check if received data is available.
    fn is_data_ready(&self) -> bool {
        // SAFETY: Reading the LSR is always safe in Ring 0.
        unsafe { inb(self.base + reg::LSR) & lsr::DATA_READY != 0 }
    }
}

impl SerialPort for Uart16550 {
    fn write_byte(&mut self, byte: u8) -> Result<()> {
        // Busy-wait for the transmit buffer to be empty.
        // In a real kernel this would be interrupt-driven, but for
        // early boot output busy-waiting is acceptable.
        let mut timeout = 100_000u32;
        while !self.is_tx_empty() {
            timeout = timeout.saturating_sub(1);
            if timeout == 0 {
                return Err(Error::IoError);
            }
        }
        // SAFETY: Writing to the UART data register in Ring 0.
        unsafe {
            outb(self.base + reg::DATA, byte);
        }
        Ok(())
    }

    fn read_byte(&mut self) -> Result<u8> {
        if !self.is_data_ready() {
            return Err(Error::WouldBlock);
        }
        // SAFETY: Reading the UART data register in Ring 0.
        Ok(unsafe { inb(self.base + reg::DATA) })
    }
}
