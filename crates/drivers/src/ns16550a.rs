// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! 16550A UART driver.
//!
//! Implements the industry-standard 16550A UART (and compatible: 16C550,
//! 16C650, etc.). Supports polled and interrupt-driven I/O, FIFO control,
//! and baud rate programming. Used for serial consoles on x86 and many
//! RISC-V/MIPS embedded platforms.
//!
//! Reference: Exar ST16C550 datasheet; TI TL16C550C datasheet.

use oncrix_lib::{Error, Result};

// 16550A register offsets (byte-wide, relative to UART base).
// When DLAB=0:
const RBR: usize = 0; // Receive Buffer Register (read)
const THR: usize = 0; // Transmit Holding Register (write)
const IER: usize = 1; // Interrupt Enable Register
// When DLAB=1:
const DLL: usize = 0; // Divisor Latch Low
const DLH: usize = 1; // Divisor Latch High
// Always accessible:
const IIR: usize = 2; // Interrupt Identification Register (read)
const FCR: usize = 2; // FIFO Control Register (write)
const LCR: usize = 3; // Line Control Register
const MCR: usize = 4; // Modem Control Register
const LSR: usize = 5; // Line Status Register
const MSR: usize = 6; // Modem Status Register

// LCR bits
const LCR_WLS_8: u8 = 0b11; // 8 data bits
const LCR_STB: u8 = 1 << 2; // 2 stop bits
const LCR_PEN: u8 = 1 << 3; // Parity enable
const LCR_DLAB: u8 = 1 << 7; // Divisor Latch Access Bit

// LSR bits
const LSR_DR: u8 = 1 << 0; // Data ready
const LSR_THRE: u8 = 1 << 5; // THR empty
const LSR_TEMT: u8 = 1 << 6; // Transmitter empty

// FCR bits
const FCR_FIFO_EN: u8 = 1 << 0; // FIFO enable
const FCR_RXSR: u8 = 1 << 1; // RX FIFO reset
const FCR_TXSR: u8 = 1 << 2; // TX FIFO reset
const FCR_TRIG_14: u8 = 0b11 << 6; // RX trigger: 14 bytes

// IER bits
const IER_ERBFI: u8 = 1 << 0; // Enable RX interrupt
const IER_ETBEI: u8 = 1 << 1; // Enable TX interrupt
const IER_ELSI: u8 = 1 << 2; // Enable Line Status interrupt

// MCR bits
const MCR_OUT2: u8 = 1 << 3; // Required for interrupt generation on PC hardware

/// Parity mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Parity {
    /// No parity bit.
    None,
    /// Odd parity.
    Odd,
    /// Even parity.
    Even,
}

/// Stop-bit count.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StopBits {
    /// 1 stop bit.
    One,
    /// 2 stop bits (1.5 for 5-bit data).
    Two,
}

/// 16550A UART configuration.
#[derive(Debug, Clone, Copy)]
pub struct Ns16550Config {
    /// UART input clock in Hz (e.g. 1_843_200 for 115200 baud × 16).
    pub clk_hz: u32,
    /// Desired baud rate.
    pub baud: u32,
    /// Parity mode.
    pub parity: Parity,
    /// Stop bits.
    pub stop_bits: StopBits,
    /// Enable the 16-byte FIFO.
    pub fifo: bool,
    /// Register stride: 1 for byte-packed, 4 for 32-bit-aligned MMIO.
    pub reg_stride: usize,
}

impl Default for Ns16550Config {
    fn default() -> Self {
        Self {
            clk_hz: 1_843_200,
            baud: 115_200,
            parity: Parity::None,
            stop_bits: StopBits::One,
            fifo: true,
            reg_stride: 1,
        }
    }
}

/// 16550A UART driver.
pub struct Ns16550Uart {
    /// MMIO / I/O base address.
    base: usize,
    /// Configuration.
    config: Ns16550Config,
    /// Whether we're in port-I/O (x86) or MMIO mode.
    mmio: bool,
}

impl Ns16550Uart {
    /// Creates a new MMIO-based 16550A driver.
    pub const fn new_mmio(base: usize, config: Ns16550Config) -> Self {
        Self {
            base,
            config,
            mmio: true,
        }
    }

    /// Creates a new port-I/O-based 16550A driver (x86 only).
    pub const fn new_pio(base: usize, config: Ns16550Config) -> Self {
        Self {
            base,
            config,
            mmio: false,
        }
    }

    /// Initialises the UART.
    pub fn init(&self) -> Result<()> {
        // Disable interrupts.
        self.write_reg(IER, 0);
        // Enable DLAB, set baud rate divisor.
        let divisor = self.compute_divisor()?;
        self.write_reg(LCR, LCR_DLAB);
        self.write_reg(DLL, (divisor & 0xFF) as u8);
        self.write_reg(DLH, ((divisor >> 8) & 0xFF) as u8);
        // Set line control: 8N1 (or configured).
        let mut lcr = LCR_WLS_8;
        if self.config.stop_bits == StopBits::Two {
            lcr |= LCR_STB;
        }
        match self.config.parity {
            Parity::None => {}
            Parity::Odd => lcr |= LCR_PEN,
            Parity::Even => lcr |= LCR_PEN | (1 << 4),
        }
        self.write_reg(LCR, lcr);
        // Enable FIFO if requested.
        if self.config.fifo {
            self.write_reg(FCR, FCR_FIFO_EN | FCR_RXSR | FCR_TXSR | FCR_TRIG_14);
        }
        // Enable OUT2 (necessary for IRQ on legacy PC hardware).
        self.write_reg(MCR, MCR_OUT2);
        Ok(())
    }

    /// Sends a single byte (polls until THR is empty).
    pub fn putc(&self, byte: u8) {
        while (self.read_reg(LSR) & LSR_THRE) == 0 {}
        self.write_reg(THR, byte);
    }

    /// Sends a byte slice.
    pub fn write(&self, data: &[u8]) {
        for &b in data {
            self.putc(b);
        }
    }

    /// Receives a byte; returns `None` if no data ready.
    pub fn getc(&self) -> Option<u8> {
        if (self.read_reg(LSR) & LSR_DR) == 0 {
            return None;
        }
        Some(self.read_reg(RBR))
    }

    /// Receives a byte, blocking until data is ready.
    pub fn getc_blocking(&self) -> u8 {
        loop {
            if let Some(b) = self.getc() {
                return b;
            }
        }
    }

    /// Flushes the transmitter (waits until TEMT).
    pub fn flush(&self) {
        while (self.read_reg(LSR) & LSR_TEMT) == 0 {}
    }

    /// Enables RX + TX + line-status interrupts.
    pub fn enable_irq(&self) {
        self.write_reg(IER, IER_ERBFI | IER_ETBEI | IER_ELSI);
    }

    /// Disables all UART interrupts.
    pub fn disable_irq(&self) {
        self.write_reg(IER, 0);
    }

    /// Returns the Interrupt Identification Register.
    pub fn irq_id(&self) -> u8 {
        self.read_reg(IIR)
    }

    /// Returns the Line Status Register.
    pub fn line_status(&self) -> u8 {
        self.read_reg(LSR)
    }

    /// Returns the Modem Status Register.
    pub fn modem_status(&self) -> u8 {
        self.read_reg(MSR)
    }

    /// Returns true if received data is available.
    pub fn rx_ready(&self) -> bool {
        (self.read_reg(LSR) & LSR_DR) != 0
    }

    /// Returns true if the transmitter is ready for data.
    pub fn tx_ready(&self) -> bool {
        (self.read_reg(LSR) & LSR_THRE) != 0
    }

    // ---- private helpers ----

    fn compute_divisor(&self) -> Result<u16> {
        let baud16 = self.config.baud.saturating_mul(16);
        if baud16 == 0 {
            return Err(Error::InvalidArgument);
        }
        let div = self.config.clk_hz / baud16;
        if div == 0 || div > 0xFFFF {
            return Err(Error::InvalidArgument);
        }
        Ok(div as u16)
    }

    fn reg_addr(&self, reg: usize) -> usize {
        self.base + reg * self.config.reg_stride
    }

    fn read_reg(&self, reg: usize) -> u8 {
        let addr = self.reg_addr(reg);
        if self.mmio {
            let ptr = addr as *const u8;
            // SAFETY: addr is a valid mapped MMIO register.
            unsafe { core::ptr::read_volatile(ptr) }
        } else {
            #[cfg(target_arch = "x86_64")]
            {
                let port = addr as u16;
                let val: u8;
                // SAFETY: Reading from a well-known 16550A I/O port.
                unsafe {
                    core::arch::asm!("in al, dx", out("al") val, in("dx") port,
                        options(nostack, nomem));
                }
                val
            }
            #[cfg(not(target_arch = "x86_64"))]
            0
        }
    }

    fn write_reg(&self, reg: usize, val: u8) {
        let addr = self.reg_addr(reg);
        if self.mmio {
            let ptr = addr as *mut u8;
            // SAFETY: addr is a valid mapped MMIO register.
            unsafe { core::ptr::write_volatile(ptr, val) }
        } else {
            #[cfg(target_arch = "x86_64")]
            {
                let port = addr as u16;
                // SAFETY: Writing to a well-known 16550A I/O port.
                unsafe {
                    core::arch::asm!("out dx, al", in("dx") port, in("al") val,
                        options(nostack, nomem));
                }
            }
        }
    }
}

impl Default for Ns16550Uart {
    fn default() -> Self {
        Self::new_mmio(0, Ns16550Config::default())
    }
}

/// Returns a description of an IIR interrupt cause.
pub fn iir_cause(iir: u8) -> &'static str {
    match (iir >> 1) & 0x7 {
        0b011 => "receiver line status",
        0b010 => "received data available",
        0b110 => "character timeout",
        0b001 => "transmitter empty",
        0b000 => "modem status",
        _ => "unknown",
    }
}
