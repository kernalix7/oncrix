// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! NS16550 UART driver for riscv64.
//!
//! MMIO base for QEMU `virt` machine: 0x10000000.
//! The NS16550A is register-compatible with the UART 16550 but uses MMIO
//! byte-wide registers instead of PIO on RISC-V platforms.

use crate::serial::SerialPort;
use oncrix_lib::{Error, Result};

/// NS16550 UART MMIO base for QEMU virt machine.
pub const NS16550_BASE: usize = 0x1000_0000;

/// Register offsets (1 byte each, accessed as u8).
mod reg {
    pub const RBR: usize = 0; // Receive Buffer Register (read)
    pub const THR: usize = 0; // Transmit Holding Register (write)
    pub const IER: usize = 1; // Interrupt Enable Register
    pub const FCR: usize = 2; // FIFO Control Register (write)
    pub const LCR: usize = 3; // Line Control Register
    pub const MCR: usize = 4; // Modem Control Register
    pub const LSR: usize = 5; // Line Status Register
    pub const DLL: usize = 0; // Divisor Latch Low (DLAB=1)
    pub const DLH: usize = 1; // Divisor Latch High (DLAB=1)
}

/// Line Status Register bits.
mod lsr {
    pub const DATA_READY: u8 = 1 << 0;
    pub const TX_EMPTY: u8 = 1 << 5;
}

/// Read an 8-bit MMIO register.
///
/// # Safety
/// `addr` must be a valid mapped MMIO address.
#[inline]
unsafe fn read8(addr: usize) -> u8 {
    // SAFETY: caller guarantees valid MMIO address.
    unsafe { core::ptr::read_volatile(addr as *const u8) }
}

/// Write an 8-bit MMIO register.
///
/// # Safety
/// `addr` must be a valid mapped MMIO address.
#[inline]
unsafe fn write8(addr: usize, val: u8) {
    // SAFETY: caller guarantees valid MMIO address.
    unsafe { core::ptr::write_volatile(addr as *mut u8, val) }
}

/// NS16550A UART driver (MMIO, RISC-V QEMU virt).
pub struct Ns16550 {
    base: usize,
}

impl Ns16550 {
    /// Create a new NS16550 instance at the given MMIO base.
    ///
    /// Does NOT initialize the hardware; call [`init`](Self::init) first.
    pub const fn new(base: usize) -> Self {
        Self { base }
    }

    /// Initialize the NS16550 for 115200 baud, 8N1, FIFO enabled.
    ///
    /// Assumes a 1.8432 MHz input clock (QEMU virt default: 3686400 Hz).
    /// Divisor = 3686400 / (16 × 115200) = 2.
    pub fn init(&self) {
        // SAFETY: Configuring well-known MMIO registers for the NS16550A
        // at the QEMU virt UART0 base address.
        unsafe {
            // Disable all interrupts.
            write8(self.base + reg::IER, 0x00);

            // Enable DLAB to set baud rate divisor.
            write8(self.base + reg::LCR, 0x80);

            // Divisor = 2 for 115200 baud @ 3.6864 MHz.
            write8(self.base + reg::DLL, 0x02);
            write8(self.base + reg::DLH, 0x00);

            // 8N1, disable DLAB.
            write8(self.base + reg::LCR, 0x03);

            // Enable FIFOs, clear TX/RX, 14-byte trigger.
            write8(self.base + reg::FCR, 0xC7);

            // Enable RTS/DSR.
            write8(self.base + reg::MCR, 0x0B);
        }
    }

    fn is_tx_empty(&self) -> bool {
        // SAFETY: Reading LSR is always safe once the UART base is valid.
        unsafe { read8(self.base + reg::LSR) & lsr::TX_EMPTY != 0 }
    }

    fn is_data_ready(&self) -> bool {
        // SAFETY: Reading LSR is always safe once the UART base is valid.
        unsafe { read8(self.base + reg::LSR) & lsr::DATA_READY != 0 }
    }
}

impl SerialPort for Ns16550 {
    fn write_byte(&mut self, byte: u8) -> Result<()> {
        let mut timeout = 100_000u32;
        while !self.is_tx_empty() {
            timeout = timeout.saturating_sub(1);
            if timeout == 0 {
                return Err(Error::IoError);
            }
        }
        // SAFETY: Writing to the NS16550 transmit holding register.
        unsafe { write8(self.base + reg::THR, byte) }
        Ok(())
    }

    fn read_byte(&mut self) -> Result<u8> {
        if !self.is_data_ready() {
            return Err(Error::WouldBlock);
        }
        // SAFETY: Reading from the NS16550 receive buffer register.
        Ok(unsafe { read8(self.base + reg::RBR) })
    }
}
