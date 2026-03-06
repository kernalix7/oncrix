// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! ARM PL011 UART driver.
//!
//! Implements the AMBA PrimeCell PL011 UART as used on ARM Versatile, Juno,
//! and many other SoCs. Provides basic polled and interrupt-driven I/O.
//!
//! Reference: ARM PrimeCell UART (PL011) Technical Reference Manual (ARM DDI 0183).

use oncrix_lib::{Error, Result};

// PL011 register offsets.
const UARTDR: usize = 0x000; // Data Register
const UARTRSR: usize = 0x004; // Receive Status / Error Clear
const UARTFR: usize = 0x018; // Flag Register
const UARTIBRD: usize = 0x024; // Integer Baud Rate Divisor
const UARTFBRD: usize = 0x028; // Fractional Baud Rate Divisor
const UARTLCR_H: usize = 0x02C; // Line Control Register
const UARTCR: usize = 0x030; // Control Register
const UARTIFLS: usize = 0x034; // Interrupt FIFO Level Select
const UARTIMSC: usize = 0x038; // Interrupt Mask Set/Clear
const UARTRIS: usize = 0x03C; // Raw Interrupt Status
const UARTMIS: usize = 0x040; // Masked Interrupt Status
const UARTICR: usize = 0x044; // Interrupt Clear Register

// UARTFR bits
const FR_TXFF: u32 = 1 << 5; // Transmit FIFO full
const FR_RXFE: u32 = 1 << 4; // Receive FIFO empty
const FR_BUSY: u32 = 1 << 3; // UART busy

// UARTCR bits
const CR_UARTEN: u32 = 1 << 0; // UART enable
const CR_TXE: u32 = 1 << 8; // Transmit enable
const CR_RXE: u32 = 1 << 9; // Receive enable

// UARTLCR_H bits
const LCR_H_WLEN_8: u32 = 0b11 << 5; // 8 data bits
const LCR_H_FEN: u32 = 1 << 4; // FIFO enable

// UARTIMSC interrupt bits
const IMSC_RXIM: u32 = 1 << 4; // Receive interrupt mask
const IMSC_TXIM: u32 = 1 << 5; // Transmit interrupt mask

/// PL011 UART configuration.
#[derive(Debug, Clone, Copy)]
pub struct Pl011Config {
    /// UART clock frequency in Hz.
    pub clk_hz: u32,
    /// Desired baud rate.
    pub baud: u32,
    /// Enable TX FIFO.
    pub fifo_en: bool,
}

impl Default for Pl011Config {
    fn default() -> Self {
        Self {
            clk_hz: 24_000_000,
            baud: 115_200,
            fifo_en: true,
        }
    }
}

/// ARM PL011 UART driver.
pub struct Pl011Uart {
    /// MMIO base address.
    base: usize,
    /// Current configuration.
    config: Pl011Config,
}

impl Pl011Uart {
    /// Creates a new PL011 UART driver.
    ///
    /// # Arguments
    ///
    /// * `base` — MMIO base address (must be mapped).
    /// * `config` — UART configuration.
    pub const fn new(base: usize, config: Pl011Config) -> Self {
        Self { base, config }
    }

    /// Initialises the UART with the configured baud rate.
    pub fn init(&self) -> Result<()> {
        // Disable UART while configuring.
        self.write32(UARTCR, 0);
        // Compute divisor: IBRD = clk / (16 * baud), FBRD = frac * 64 + 0.5
        let baud16 = self.config.baud.saturating_mul(16);
        if baud16 == 0 {
            return Err(Error::InvalidArgument);
        }
        let ibrd = self.config.clk_hz / baud16;
        let rem = self.config.clk_hz % baud16;
        let fbrd = ((rem * 8 + baud16 / 2) / baud16) as u32;
        self.write32(UARTIBRD, ibrd);
        self.write32(UARTFBRD, fbrd);
        // Set 8N1 + optional FIFO.
        let mut lcr = LCR_H_WLEN_8;
        if self.config.fifo_en {
            lcr |= LCR_H_FEN;
        }
        self.write32(UARTLCR_H, lcr);
        // Clear all interrupts.
        self.write32(UARTICR, 0x7FF);
        // Enable UART + TX + RX.
        self.write32(UARTCR, CR_UARTEN | CR_TXE | CR_RXE);
        Ok(())
    }

    /// Sends a single byte (busy-waits if TX FIFO is full).
    pub fn putc(&self, byte: u8) {
        while (self.read32(UARTFR) & FR_TXFF) != 0 {}
        self.write32(UARTDR, byte as u32);
    }

    /// Sends a byte slice.
    pub fn write(&self, data: &[u8]) {
        for &b in data {
            self.putc(b);
        }
    }

    /// Receives a single byte; returns `None` if the RX FIFO is empty.
    pub fn getc(&self) -> Option<u8> {
        if (self.read32(UARTFR) & FR_RXFE) != 0 {
            return None;
        }
        Some((self.read32(UARTDR) & 0xFF) as u8)
    }

    /// Receives a single byte, blocking until data arrives.
    pub fn getc_blocking(&self) -> u8 {
        loop {
            if let Some(b) = self.getc() {
                return b;
            }
        }
    }

    /// Flushes the transmit FIFO (waits until the UART is not busy).
    pub fn flush(&self) {
        while (self.read32(UARTFR) & FR_BUSY) != 0 {}
    }

    /// Enables receive and transmit interrupts.
    pub fn enable_irq(&self) {
        self.write32(UARTIMSC, IMSC_RXIM | IMSC_TXIM);
    }

    /// Disables all UART interrupts.
    pub fn disable_irq(&self) {
        self.write32(UARTIMSC, 0);
    }

    /// Returns the raw interrupt status register.
    pub fn raw_irq_status(&self) -> u32 {
        self.read32(UARTRIS)
    }

    /// Returns the masked interrupt status register.
    pub fn masked_irq_status(&self) -> u32 {
        self.read32(UARTMIS)
    }

    /// Clears pending interrupts identified by `mask`.
    pub fn clear_irq(&self, mask: u32) {
        self.write32(UARTICR, mask);
    }

    /// Sets the FIFO interrupt trigger level (0–7 for TX, 0–7 for RX).
    pub fn set_fifo_level(&self, tx_level: u8, rx_level: u8) -> Result<()> {
        if (tx_level as usize) > 7 || (rx_level as usize) > 7 {
            return Err(Error::InvalidArgument);
        }
        self.write32(UARTIFLS, ((rx_level as u32) << 3) | (tx_level as u32));
        Ok(())
    }

    /// Returns true if the RX FIFO has data available.
    pub fn rx_ready(&self) -> bool {
        (self.read32(UARTFR) & FR_RXFE) == 0
    }

    /// Returns true if the TX FIFO is not full.
    pub fn tx_ready(&self) -> bool {
        (self.read32(UARTFR) & FR_TXFF) == 0
    }

    // ---- private helpers ----

    fn read32(&self, offset: usize) -> u32 {
        let ptr = (self.base + offset) as *const u32;
        // SAFETY: base is a valid mapped PL011 MMIO region.
        unsafe { core::ptr::read_volatile(ptr) }
    }

    fn write32(&self, offset: usize, val: u32) {
        let ptr = (self.base + offset) as *mut u32;
        // SAFETY: base is a valid mapped PL011 MMIO region.
        unsafe { core::ptr::write_volatile(ptr, val) }
    }
}

impl Default for Pl011Uart {
    fn default() -> Self {
        Self::new(0, Pl011Config::default())
    }
}

/// Computes the PL011 baud rate divisors for a given clock and baud rate.
///
/// Returns `(ibrd, fbrd)` or `None` if the divisors are out of range.
pub fn compute_divisors(clk_hz: u32, baud: u32) -> Option<(u32, u32)> {
    let baud16 = baud.checked_mul(16)?;
    let ibrd = clk_hz / baud16;
    if ibrd == 0 || ibrd > 0xFFFF {
        return None;
    }
    let rem = clk_hz % baud16;
    let fbrd = ((rem * 8 + baud16 / 2) / baud16).min(63);
    Some((ibrd, fbrd))
}
