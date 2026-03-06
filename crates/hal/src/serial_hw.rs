// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! 16550A UART hardware abstraction layer.
//!
//! Provides register-level access to the NS16550A (and compatible) UART,
//! which is the standard serial port controller in x86 PC systems.
//!
//! # Register Map
//!
//! All registers are accessed relative to the UART base port address:
//!
//! | Offset | DLAB=0 Read | DLAB=0 Write | DLAB=1       |
//! |--------|-------------|--------------|--------------|
//! | 0      | RBR (recv)  | THR (trans)  | DLL (baud lo)|
//! | 1      | IER         | IER          | DLH (baud hi)|
//! | 2      | IIR         | FCR          | —            |
//! | 3      | LCR         | LCR          | —            |
//! | 4      | MCR         | MCR          | —            |
//! | 5      | LSR         | —            | —            |
//! | 6      | MSR         | —            | —            |
//! | 7      | SCR         | SCR          | —            |
//!
//! # Standard COM port base addresses
//!
//! | Port | Base  | IRQ |
//! |------|-------|-----|
//! | COM1 | 0x3F8 |  4  |
//! | COM2 | 0x2F8 |  3  |
//! | COM3 | 0x3E8 |  4  |
//! | COM4 | 0x2E8 |  3  |
//!
//! Reference: NS16550A Universal Asynchronous Receiver/Transmitter Datasheet.

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Register offsets (relative to UART base port)
// ---------------------------------------------------------------------------

/// Receiver Buffer Register (DLAB=0, read).
pub const REG_RBR: u16 = 0;
/// Transmitter Holding Register (DLAB=0, write).
pub const REG_THR: u16 = 0;
/// Divisor Latch Low byte (DLAB=1, R/W).
pub const REG_DLL: u16 = 0;
/// Interrupt Enable Register (DLAB=0, R/W).
pub const REG_IER: u16 = 1;
/// Divisor Latch High byte (DLAB=1, R/W).
pub const REG_DLH: u16 = 1;
/// Interrupt Identification Register (read-only).
pub const REG_IIR: u16 = 2;
/// FIFO Control Register (write-only).
pub const REG_FCR: u16 = 2;
/// Line Control Register (R/W).
pub const REG_LCR: u16 = 3;
/// Modem Control Register (R/W).
pub const REG_MCR: u16 = 4;
/// Line Status Register (read-only).
pub const REG_LSR: u16 = 5;
/// Modem Status Register (read-only).
pub const REG_MSR: u16 = 6;
/// Scratch Register (R/W).
pub const REG_SCR: u16 = 7;

// ---------------------------------------------------------------------------
// Line Control Register (LCR) bits
// ---------------------------------------------------------------------------

/// LCR: 5-bit word length.
pub const LCR_WLEN5: u8 = 0x00;
/// LCR: 6-bit word length.
pub const LCR_WLEN6: u8 = 0x01;
/// LCR: 7-bit word length.
pub const LCR_WLEN7: u8 = 0x02;
/// LCR: 8-bit word length.
pub const LCR_WLEN8: u8 = 0x03;
/// LCR: 2 stop bits (or 1.5 stop bits for 5-bit word).
pub const LCR_STOP2: u8 = 0x04;
/// LCR: Enable parity.
pub const LCR_PAREN: u8 = 0x08;
/// LCR: Even parity.
pub const LCR_PAREVEN: u8 = 0x10;
/// LCR: Divisor latch access bit (DLAB).
pub const LCR_DLAB: u8 = 0x80;

// ---------------------------------------------------------------------------
// Line Status Register (LSR) bits
// ---------------------------------------------------------------------------

/// LSR: Data ready — at least one byte in receive buffer/FIFO.
pub const LSR_DR: u8 = 0x01;
/// LSR: Overrun error.
pub const LSR_OE: u8 = 0x02;
/// LSR: Parity error.
pub const LSR_PE: u8 = 0x04;
/// LSR: Framing error.
pub const LSR_FE: u8 = 0x08;
/// LSR: Break interrupt.
pub const LSR_BI: u8 = 0x10;
/// LSR: Transmit Holding Register empty (THRE).
pub const LSR_THRE: u8 = 0x20;
/// LSR: Transmitter empty (both THR and shift register empty).
pub const LSR_TEMT: u8 = 0x40;
/// LSR: Error in receive FIFO.
pub const LSR_FIFO_ERR: u8 = 0x80;

// ---------------------------------------------------------------------------
// FIFO Control Register (FCR) bits
// ---------------------------------------------------------------------------

/// FCR: Enable FIFO.
pub const FCR_ENABLE: u8 = 0x01;
/// FCR: Clear receive FIFO.
pub const FCR_RX_RESET: u8 = 0x02;
/// FCR: Clear transmit FIFO.
pub const FCR_TX_RESET: u8 = 0x04;
/// FCR: Trigger level 1 byte.
pub const FCR_TRIG1: u8 = 0x00;
/// FCR: Trigger level 4 bytes.
pub const FCR_TRIG4: u8 = 0x40;
/// FCR: Trigger level 8 bytes.
pub const FCR_TRIG8: u8 = 0x80;
/// FCR: Trigger level 14 bytes.
pub const FCR_TRIG14: u8 = 0xC0;

// ---------------------------------------------------------------------------
// Interrupt Enable Register (IER) bits
// ---------------------------------------------------------------------------

/// IER: Received data available interrupt.
pub const IER_RDA: u8 = 0x01;
/// IER: Transmitter holding register empty interrupt.
pub const IER_THRE: u8 = 0x02;
/// IER: Receiver line status interrupt.
pub const IER_RLS: u8 = 0x04;
/// IER: Modem status interrupt.
pub const IER_MS: u8 = 0x08;

// ---------------------------------------------------------------------------
// Modem Control Register (MCR) bits
// ---------------------------------------------------------------------------

/// MCR: Data Terminal Ready.
pub const MCR_DTR: u8 = 0x01;
/// MCR: Request To Send.
pub const MCR_RTS: u8 = 0x02;
/// MCR: Auxiliary output 2 (used to gate UART interrupts to CPU).
pub const MCR_OUT2: u8 = 0x08;
/// MCR: Loopback mode (diagnostic).
pub const MCR_LOOP: u8 = 0x10;

// ---------------------------------------------------------------------------
// Standard COM base addresses
// ---------------------------------------------------------------------------

/// COM1 base I/O port.
pub const COM1_BASE: u16 = 0x3F8;
/// COM2 base I/O port.
pub const COM2_BASE: u16 = 0x2F8;
/// COM3 base I/O port.
pub const COM3_BASE: u16 = 0x3E8;
/// COM4 base I/O port.
pub const COM4_BASE: u16 = 0x2E8;

/// Clock frequency fed into the UART baud rate generator (Hz).
pub const UART_CLOCK_HZ: u32 = 1_843_200;

/// Spin limit for waiting on THRE.
const TX_WAIT_ITERS: u32 = 1_000_000;

// ---------------------------------------------------------------------------
// Port I/O helpers
// ---------------------------------------------------------------------------

#[cfg(target_arch = "x86_64")]
unsafe fn outb(port: u16, val: u8) {
    // SAFETY: Caller ensures this is a valid UART I/O port.
    unsafe {
        core::arch::asm!(
            "out dx, al",
            in("dx") port,
            in("al") val,
            options(nomem, nostack, preserves_flags),
        );
    }
}

#[cfg(target_arch = "x86_64")]
unsafe fn inb(port: u16) -> u8 {
    // SAFETY: Caller ensures this is a valid UART I/O port.
    unsafe {
        let v: u8;
        core::arch::asm!(
            "in al, dx",
            out("al") v,
            in("dx") port,
            options(nomem, nostack, preserves_flags),
        );
        v
    }
}

// ---------------------------------------------------------------------------
// BaudRate
// ---------------------------------------------------------------------------

/// UART baud rate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BaudRate {
    /// 9600 baud.
    B9600,
    /// 19200 baud.
    B19200,
    /// 38400 baud.
    B38400,
    /// 57600 baud.
    B57600,
    /// 115200 baud.
    B115200,
    /// Custom divisor (raw 16-bit value).
    Custom(u16),
}

impl BaudRate {
    /// Convert to a 16-bit divisor value for the baud rate generator.
    ///
    /// Divisor = UART_CLOCK_HZ / (16 × baud).
    pub fn divisor(self) -> u16 {
        match self {
            BaudRate::B9600 => 12,
            BaudRate::B19200 => 6,
            BaudRate::B38400 => 3,
            BaudRate::B57600 => 2,
            BaudRate::B115200 => 1,
            BaudRate::Custom(d) => d,
        }
    }
}

// ---------------------------------------------------------------------------
// SerialHw
// ---------------------------------------------------------------------------

/// 16550A UART hardware controller.
pub struct SerialHw {
    /// Base I/O port address.
    base: u16,
}

impl SerialHw {
    /// Create a new [`SerialHw`] for the given base port.
    pub const fn new(base: u16) -> Self {
        Self { base }
    }

    /// Initialize the UART.
    ///
    /// Sets 8N1 framing at `baud`, enables and clears FIFOs, and
    /// enables the receiver-data-available interrupt.
    #[cfg(target_arch = "x86_64")]
    pub fn init(&self, baud: BaudRate) -> Result<()> {
        // SAFETY: All accesses are to standard 16550A UART registers.
        unsafe {
            // Disable interrupts
            outb(self.base + REG_IER, 0x00);

            // Enable DLAB, set baud divisor
            outb(self.base + REG_LCR, LCR_DLAB);
            let div = baud.divisor();
            outb(self.base + REG_DLL, div as u8);
            outb(self.base + REG_DLH, (div >> 8) as u8);

            // 8 data bits, no parity, 1 stop bit (8N1); clear DLAB
            outb(self.base + REG_LCR, LCR_WLEN8);

            // Enable and clear FIFOs, trigger at 14 bytes
            outb(
                self.base + REG_FCR,
                FCR_ENABLE | FCR_RX_RESET | FCR_TX_RESET | FCR_TRIG14,
            );

            // Enable loopback, test UART
            outb(self.base + REG_MCR, MCR_LOOP);
            outb(self.base + REG_THR, 0xAE);
            if inb(self.base + REG_RBR) != 0xAE {
                return Err(Error::IoError);
            }

            // Normal operation: DTR, RTS, OUT2
            outb(self.base + REG_MCR, MCR_DTR | MCR_RTS | MCR_OUT2);

            // Enable RDA interrupt
            outb(self.base + REG_IER, IER_RDA);
        }
        Ok(())
    }

    #[cfg(not(target_arch = "x86_64"))]
    pub fn init(&self, _baud: BaudRate) -> Result<()> {
        Err(Error::NotImplemented)
    }

    /// Read a byte from the receive buffer (blocking until data arrives).
    #[cfg(target_arch = "x86_64")]
    pub fn read_byte(&self) -> u8 {
        loop {
            // SAFETY: Reading LSR and RBR of a 16550A UART.
            let lsr = unsafe { inb(self.base + REG_LSR) };
            if (lsr & LSR_DR) != 0 {
                return unsafe { inb(self.base + REG_RBR) };
            }
        }
    }

    #[cfg(not(target_arch = "x86_64"))]
    pub fn read_byte(&self) -> u8 {
        0
    }

    /// Try to read a byte without blocking.
    ///
    /// Returns `None` if no data is available.
    #[cfg(target_arch = "x86_64")]
    pub fn try_read_byte(&self) -> Option<u8> {
        // SAFETY: Reading 16550A LSR then RBR.
        let lsr = unsafe { inb(self.base + REG_LSR) };
        if (lsr & LSR_DR) != 0 {
            Some(unsafe { inb(self.base + REG_RBR) })
        } else {
            None
        }
    }

    #[cfg(not(target_arch = "x86_64"))]
    pub fn try_read_byte(&self) -> Option<u8> {
        None
    }

    /// Write a byte, spinning until the transmitter is ready.
    #[cfg(target_arch = "x86_64")]
    pub fn write_byte(&self, byte: u8) -> Result<()> {
        for _ in 0..TX_WAIT_ITERS {
            // SAFETY: Reading 16550A LSR.
            let lsr = unsafe { inb(self.base + REG_LSR) };
            if (lsr & LSR_THRE) != 0 {
                // SAFETY: Writing 16550A THR.
                unsafe { outb(self.base + REG_THR, byte) };
                return Ok(());
            }
        }
        Err(Error::Busy)
    }

    #[cfg(not(target_arch = "x86_64"))]
    pub fn write_byte(&self, _byte: u8) -> Result<()> {
        Err(Error::NotImplemented)
    }

    /// Write a string (UTF-8 bytes) to the UART.
    pub fn write_str(&self, s: &str) -> Result<()> {
        for b in s.bytes() {
            // Emit CR before LF for terminals that expect CRLF
            if b == b'\n' {
                self.write_byte(b'\r')?;
            }
            self.write_byte(b)?;
        }
        Ok(())
    }

    /// Read the current Line Status Register.
    #[cfg(target_arch = "x86_64")]
    pub fn lsr(&self) -> u8 {
        // SAFETY: Reading 16550A LSR.
        unsafe { inb(self.base + REG_LSR) }
    }

    #[cfg(not(target_arch = "x86_64"))]
    pub fn lsr(&self) -> u8 {
        0
    }

    /// Check whether data is ready to be received.
    pub fn data_ready(&self) -> bool {
        (self.lsr() & LSR_DR) != 0
    }

    /// Return the base I/O port.
    pub const fn base_port(&self) -> u16 {
        self.base
    }
}
