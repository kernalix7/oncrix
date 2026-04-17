// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! ARM PL011 UART driver for aarch64.
//!
//! MMIO base for QEMU `virt` machine: 0x09000000.

use crate::serial::SerialPort;
use oncrix_lib::{Error, Result};

/// PL011 UART MMIO base address for QEMU virt machine.
pub const PL011_BASE: usize = 0x0900_0000;

/// PL011 register offsets (byte offsets from base, accessed as u32).
mod reg {
    /// Data register (read: receive, write: transmit).
    pub const DR: usize = 0x000;
    /// Flag register.
    pub const FR: usize = 0x018;
    /// Integer baud rate register.
    pub const IBRD: usize = 0x024;
    /// Fractional baud rate register.
    pub const FBRD: usize = 0x028;
    /// Line control register.
    pub const LCRH: usize = 0x02C;
    /// Control register.
    pub const CR: usize = 0x030;
    /// Interrupt mask set/clear register.
    pub const IMSC: usize = 0x038;
    /// Interrupt clear register.
    pub const ICR: usize = 0x044;
}

/// Flag register bits.
mod fr {
    /// Receive FIFO empty.
    pub const RXFE: u32 = 1 << 4;
    /// Transmit FIFO full.
    pub const TXFF: u32 = 1 << 5;
}

/// Line control register bits.
mod lcrh {
    /// Enable FIFOs.
    pub const FEN: u32 = 1 << 4;
    /// Word length 8 bits.
    pub const WLEN_8: u32 = 0b11 << 5;
}

/// Control register bits.
mod cr {
    /// UART enable.
    pub const UARTEN: u32 = 1 << 0;
    /// Transmit enable.
    pub const TXE: u32 = 1 << 8;
    /// Receive enable.
    pub const RXE: u32 = 1 << 9;
}

/// Read a 32-bit MMIO register.
///
/// # Safety
/// `addr` must be a valid, mapped MMIO address.
#[inline]
unsafe fn read32(addr: usize) -> u32 {
    // SAFETY: caller guarantees the address is a valid MMIO register.
    unsafe { core::ptr::read_volatile(addr as *const u32) }
}

/// Write a 32-bit MMIO register.
///
/// # Safety
/// `addr` must be a valid, mapped MMIO address.
#[inline]
unsafe fn write32(addr: usize, val: u32) {
    // SAFETY: caller guarantees the address is a valid MMIO register.
    unsafe { core::ptr::write_volatile(addr as *mut u32, val) }
}

/// ARM PL011 UART.
pub struct Pl011 {
    base: usize,
}

impl Pl011 {
    /// Create a new PL011 instance at the given MMIO base.
    ///
    /// Does NOT initialize the hardware; call [`init`](Self::init) first.
    pub const fn new(base: usize) -> Self {
        Self { base }
    }

    /// Initialize the PL011 for 115200 baud, 8N1 with FIFOs enabled.
    ///
    /// Assumes a 24 MHz UART reference clock (QEMU virt default).
    pub fn init(&self) {
        // SAFETY: We are writing to well-known MMIO registers for the
        // PL011 UART at a statically-known QEMU virt machine address.
        unsafe {
            // Disable UART before reconfiguring.
            write32(self.base + reg::CR, 0);

            // Clear all pending interrupts.
            write32(self.base + reg::ICR, 0x7FF);

            // Baud rate: 115200 @ 24 MHz clock.
            // Divisor = 24_000_000 / (16 * 115200) = 13.020833...
            // IBRD = 13, FBRD = round(0.020833 * 64) = 1
            write32(self.base + reg::IBRD, 13);
            write32(self.base + reg::FBRD, 1);

            // 8N1, FIFOs enabled.
            write32(self.base + reg::LCRH, lcrh::FEN | lcrh::WLEN_8);

            // Mask all interrupts.
            write32(self.base + reg::IMSC, 0);

            // Enable UART, TX, and RX.
            write32(self.base + reg::CR, cr::UARTEN | cr::TXE | cr::RXE);
        }
    }

    /// Return true if the transmit FIFO is full.
    fn is_tx_full(&self) -> bool {
        // SAFETY: Reading FR is always safe once the UART base is valid.
        unsafe { read32(self.base + reg::FR) & fr::TXFF != 0 }
    }

    /// Return true if the receive FIFO is empty.
    fn is_rx_empty(&self) -> bool {
        // SAFETY: Reading FR is always safe once the UART base is valid.
        unsafe { read32(self.base + reg::FR) & fr::RXFE != 0 }
    }
}

impl SerialPort for Pl011 {
    fn write_byte(&mut self, byte: u8) -> Result<()> {
        let mut timeout = 100_000u32;
        while self.is_tx_full() {
            timeout = timeout.saturating_sub(1);
            if timeout == 0 {
                return Err(Error::IoError);
            }
        }
        // SAFETY: Writing to the PL011 data register.
        unsafe {
            write32(self.base + reg::DR, byte as u32);
        }
        Ok(())
    }

    fn read_byte(&mut self) -> Result<u8> {
        if self.is_rx_empty() {
            return Err(Error::WouldBlock);
        }
        // SAFETY: Reading from the PL011 data register.
        Ok(unsafe { read32(self.base + reg::DR) as u8 })
    }
}
