// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! UART TTY driver.
//!
//! Implements a serial UART driver compatible with the 16550A UART,
//! supporting configurable baud rate, data bits, stop bits, parity,
//! FIFO operation, modem control lines, and break signal generation.
//!
//! # UART Register Layout (base I/O port or MMIO base)
//! | Offset | DLAB=0 (read) | DLAB=0 (write) | DLAB=1 |
//! |--------|---------------|----------------|--------|
//! | 0      | RBR (recv)    | THR (transmit) | DLL    |
//! | 1      | IER           | IER            | DLM    |
//! | 2      | IIR (read)    | FCR (write)    | -      |
//! | 3      | LCR           | LCR            | -      |
//! | 4      | MCR           | MCR            | -      |
//! | 5      | LSR           | -              | -      |
//! | 6      | MSR           | -              | -      |
//! | 7      | SCR           | SCR            | -      |
//!
//! Reference: UART 16550A Datasheet; Linux tty_port / serial_core documentation.

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Register Offsets
// ---------------------------------------------------------------------------

/// RBR/THR/DLL: Receiver Buffer / Transmit Holding / Divisor Latch Low.
const UART_RBR: u16 = 0;
/// IER/DLM: Interrupt Enable Register / Divisor Latch High.
const UART_IER: u16 = 1;
/// IIR/FCR: Interrupt Identification / FIFO Control.
const UART_IIR: u16 = 2;
/// LCR: Line Control Register.
const UART_LCR: u16 = 3;
/// MCR: Modem Control Register.
const UART_MCR: u16 = 4;
/// LSR: Line Status Register.
const UART_LSR: u16 = 5;
/// MSR: Modem Status Register.
const UART_MSR: u16 = 6;
/// SCR: Scratch Register (not used by hardware).
const UART_SCR: u16 = 7;

// ---------------------------------------------------------------------------
// LCR Bit Fields
// ---------------------------------------------------------------------------

/// LCR bits 1:0: Word length = 8 bits.
pub const LCR_WLS_8: u8 = 0x03;
/// LCR bits 1:0: Word length = 7 bits.
pub const LCR_WLS_7: u8 = 0x02;
/// LCR bits 1:0: Word length = 6 bits.
pub const LCR_WLS_6: u8 = 0x01;
/// LCR bits 1:0: Word length = 5 bits.
pub const LCR_WLS_5: u8 = 0x00;
/// LCR bit 2: 2 stop bits (1 = 2 stop bits; 0 = 1 stop bit).
pub const LCR_STB: u8 = 0x04;
/// LCR bit 3: Parity enable.
pub const LCR_PEN: u8 = 0x08;
/// LCR bit 4: Even parity select (0 = odd, 1 = even).
pub const LCR_EPS: u8 = 0x10;
/// LCR bit 6: Break control (set to send continuous break).
pub const LCR_BC: u8 = 0x40;
/// LCR bit 7: Divisor Latch Access Bit (DLAB).
pub const LCR_DLAB: u8 = 0x80;

// ---------------------------------------------------------------------------
// FCR Bit Fields
// ---------------------------------------------------------------------------

/// FCR bit 0: FIFO Enable.
pub const FCR_FIFO_EN: u8 = 0x01;
/// FCR bit 1: Receiver FIFO Reset.
pub const FCR_RX_RESET: u8 = 0x02;
/// FCR bit 2: Transmitter FIFO Reset.
pub const FCR_TX_RESET: u8 = 0x04;
/// FCR bits 7:6: Receiver trigger level 14 bytes.
pub const FCR_RX_TRIG_14: u8 = 0xC0;
/// FCR bits 7:6: Receiver trigger level 1 byte.
pub const FCR_RX_TRIG_1: u8 = 0x00;

// ---------------------------------------------------------------------------
// IER Bit Fields
// ---------------------------------------------------------------------------

/// IER bit 0: Received Data Available Interrupt enable.
pub const IER_RDAI: u8 = 0x01;
/// IER bit 1: Transmitter Holding Register Empty Interrupt enable.
pub const IER_THREI: u8 = 0x02;
/// IER bit 2: Receiver Line Status Interrupt enable.
pub const IER_RLSI: u8 = 0x04;
/// IER bit 3: Modem Status Interrupt enable.
pub const IER_MSI: u8 = 0x08;

// ---------------------------------------------------------------------------
// LSR Bit Fields
// ---------------------------------------------------------------------------

/// LSR bit 0: Data Ready.
pub const LSR_DR: u8 = 0x01;
/// LSR bit 1: Overrun Error.
pub const LSR_OE: u8 = 0x02;
/// LSR bit 2: Parity Error.
pub const LSR_PE: u8 = 0x04;
/// LSR bit 3: Framing Error.
pub const LSR_FE: u8 = 0x08;
/// LSR bit 4: Break Interrupt.
pub const LSR_BI: u8 = 0x10;
/// LSR bit 5: Transmitter Holding Register Empty.
pub const LSR_THRE: u8 = 0x20;
/// LSR bit 6: Transmitter Empty.
pub const LSR_TEMT: u8 = 0x40;

// ---------------------------------------------------------------------------
// MCR Bit Fields
// ---------------------------------------------------------------------------

/// MCR bit 0: Data Terminal Ready (DTR).
pub const MCR_DTR: u8 = 0x01;
/// MCR bit 1: Request To Send (RTS).
pub const MCR_RTS: u8 = 0x02;
/// MCR bit 2: Out1 (auxiliary output 1).
pub const MCR_OUT1: u8 = 0x04;
/// MCR bit 3: Out2 (enables interrupts through IRQ).
pub const MCR_OUT2: u8 = 0x08;
/// MCR bit 4: Loop-back mode.
pub const MCR_LOOP: u8 = 0x10;

// ---------------------------------------------------------------------------
// MSR Bit Fields
// ---------------------------------------------------------------------------

/// MSR bit 0: Delta CTS.
pub const MSR_DCTS: u8 = 0x01;
/// MSR bit 1: Delta DSR.
pub const MSR_DDSR: u8 = 0x02;
/// MSR bit 4: Clear To Send (CTS).
pub const MSR_CTS: u8 = 0x10;
/// MSR bit 5: Data Set Ready (DSR).
pub const MSR_DSR: u8 = 0x20;
/// MSR bit 7: Data Carrier Detect (DCD).
pub const MSR_DCD: u8 = 0x80;

// ---------------------------------------------------------------------------
// Parity Selection
// ---------------------------------------------------------------------------

/// Parity configuration.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Parity {
    /// No parity.
    None,
    /// Odd parity.
    Odd,
    /// Even parity.
    Even,
}

// ---------------------------------------------------------------------------
// Port I/O
// ---------------------------------------------------------------------------

/// Writes to an I/O port.
///
/// # Safety
/// Port I/O; caller must ensure `port` is a valid UART register port.
#[cfg(target_arch = "x86_64")]
unsafe fn outb(port: u16, val: u8) {
    // SAFETY: Port I/O instruction; caller guarantees port correctness.
    unsafe {
        core::arch::asm!("out dx, al", in("dx") port, in("al") val, options(nomem, nostack));
    }
}

/// Reads from an I/O port.
///
/// # Safety
/// See `outb`.
#[cfg(target_arch = "x86_64")]
unsafe fn inb(port: u16) -> u8 {
    let val: u8;
    // SAFETY: Port I/O read; caller guarantees port correctness.
    unsafe {
        core::arch::asm!("in al, dx", out("al") val, in("dx") port, options(nomem, nostack));
    }
    val
}

// ---------------------------------------------------------------------------
// UartPort
// ---------------------------------------------------------------------------

/// A UART serial port driver.
pub struct UartPort {
    /// I/O base address (e.g., 0x3F8 for COM1, 0x2F8 for COM2).
    base: u16,
    /// IRQ number for this port.
    pub irq: u8,
    /// Configured baud rate.
    pub baud: u32,
    /// Data bits per character (5–8).
    pub data_bits: u8,
    /// Stop bits (1 or 2).
    pub stop_bits: u8,
    /// Parity configuration.
    pub parity: Parity,
}

impl UartPort {
    /// Creates a new `UartPort` with the given I/O base and IRQ.
    pub const fn new(base: u16, irq: u8) -> Self {
        Self {
            base,
            irq,
            baud: 115200,
            data_bits: 8,
            stop_bits: 1,
            parity: Parity::None,
        }
    }

    /// Initializes the UART with the configured baud rate, data bits, stop bits, and parity.
    ///
    /// Enables the 16-byte FIFO and OUT2 (interrupt enable).
    ///
    /// # Safety
    /// `base` must be the correct I/O base for an existing UART on this system.
    #[cfg(target_arch = "x86_64")]
    pub unsafe fn init(&self) -> Result<()> {
        // SAFETY: Programming a UART via standard 16550A register sequence.
        unsafe {
            // Disable interrupts
            outb(self.base + UART_IER, 0x00);

            // Set divisor latch
            let divisor = 115200 / self.baud.max(1);
            let divisor = divisor.min(0xFFFF) as u16;
            outb(self.base + UART_LCR, LCR_DLAB);
            outb(self.base + UART_RBR, (divisor & 0xFF) as u8);
            outb(self.base + UART_IER, (divisor >> 8) as u8);

            // Build LCR: data bits + stop bits + parity
            let mut lcr = match self.data_bits {
                5 => LCR_WLS_5,
                6 => LCR_WLS_6,
                7 => LCR_WLS_7,
                _ => LCR_WLS_8,
            };
            if self.stop_bits >= 2 {
                lcr |= LCR_STB;
            }
            match self.parity {
                Parity::None => {}
                Parity::Odd => lcr |= LCR_PEN,
                Parity::Even => lcr |= LCR_PEN | LCR_EPS,
            }
            outb(self.base + UART_LCR, lcr);

            // Enable FIFO: clear RX/TX FIFO, set 14-byte RX trigger
            outb(
                self.base + UART_IIR,
                FCR_FIFO_EN | FCR_RX_RESET | FCR_TX_RESET | FCR_RX_TRIG_14,
            );

            // Enable modem control: DTR, RTS, OUT2 (enables interrupts)
            outb(self.base + UART_MCR, MCR_DTR | MCR_RTS | MCR_OUT2);

            // Enable RX interrupt
            outb(self.base + UART_IER, IER_RDAI | IER_RLSI);
        }
        Ok(())
    }

    /// Transmits a single byte, waiting for the THR to become empty.
    ///
    /// # Safety
    /// UART must be initialized.
    #[cfg(target_arch = "x86_64")]
    pub unsafe fn tx_byte(&self, byte: u8) -> Result<()> {
        // SAFETY: Polling LSR.THRE and writing THR.
        unsafe {
            let mut spin = 1_000_000u32;
            while inb(self.base + UART_LSR) & LSR_THRE == 0 {
                if spin == 0 {
                    return Err(Error::Busy);
                }
                spin -= 1;
                core::hint::spin_loop();
            }
            outb(self.base + UART_RBR, byte);
        }
        Ok(())
    }

    /// Reads a single byte from the UART if data is available.
    ///
    /// Returns `None` if no data is ready.
    ///
    /// # Safety
    /// UART must be initialized.
    #[cfg(target_arch = "x86_64")]
    pub unsafe fn rx_byte(&self) -> Option<u8> {
        // SAFETY: Checking LSR.DR before reading RBR.
        unsafe {
            if inb(self.base + UART_LSR) & LSR_DR != 0 {
                Some(inb(self.base + UART_RBR))
            } else {
                None
            }
        }
    }

    /// Updates the baud rate and reinitializes the divisor latch only.
    ///
    /// # Safety
    /// UART must be initialized.
    #[cfg(target_arch = "x86_64")]
    pub unsafe fn set_baud(&mut self, baud: u32) -> Result<()> {
        if baud == 0 {
            return Err(Error::InvalidArgument);
        }
        self.baud = baud;
        // SAFETY: Updating divisor latch with DLAB sequence.
        unsafe {
            let divisor = (115200 / baud).min(0xFFFF) as u16;
            let lcr = inb(self.base + UART_LCR);
            outb(self.base + UART_LCR, lcr | LCR_DLAB);
            outb(self.base + UART_RBR, (divisor & 0xFF) as u8);
            outb(self.base + UART_IER, (divisor >> 8) as u8);
            outb(self.base + UART_LCR, lcr & !LCR_DLAB);
        }
        Ok(())
    }

    /// Reconfigures the line parameters (data bits, stop bits, parity).
    ///
    /// # Safety
    /// UART must be initialized.
    #[cfg(target_arch = "x86_64")]
    pub unsafe fn set_termios(
        &mut self,
        data_bits: u8,
        stop_bits: u8,
        parity: Parity,
    ) -> Result<()> {
        if !(5..=8).contains(&data_bits) {
            return Err(Error::InvalidArgument);
        }
        self.data_bits = data_bits;
        self.stop_bits = stop_bits;
        self.parity = parity;
        // SAFETY: Writing LCR to update line parameters.
        unsafe {
            let mut lcr = match data_bits {
                5 => LCR_WLS_5,
                6 => LCR_WLS_6,
                7 => LCR_WLS_7,
                _ => LCR_WLS_8,
            };
            if stop_bits >= 2 {
                lcr |= LCR_STB;
            }
            match parity {
                Parity::None => {}
                Parity::Odd => lcr |= LCR_PEN,
                Parity::Even => lcr |= LCR_PEN | LCR_EPS,
            }
            outb(self.base + UART_LCR, lcr);
        }
        Ok(())
    }

    /// Sends a break signal by setting LCR.BC for a brief period.
    ///
    /// # Safety
    /// UART must be initialized.
    #[cfg(target_arch = "x86_64")]
    pub unsafe fn send_break(&self) {
        // SAFETY: Setting and clearing LCR.BC for a break signal.
        unsafe {
            let lcr = inb(self.base + UART_LCR);
            outb(self.base + UART_LCR, lcr | LCR_BC);
            let mut spin = 500_000u32;
            while spin > 0 {
                spin -= 1;
                core::hint::spin_loop();
            }
            outb(self.base + UART_LCR, lcr & !LCR_BC);
        }
    }

    /// Sets modem control outputs (DTR, RTS).
    ///
    /// # Safety
    /// UART must be initialized.
    #[cfg(target_arch = "x86_64")]
    pub unsafe fn set_modem_control(&self, dtr: bool, rts: bool) {
        // SAFETY: Writing MCR to assert/deassert DTR and RTS.
        unsafe {
            let mut mcr = inb(self.base + UART_MCR) & !(MCR_DTR | MCR_RTS);
            if dtr {
                mcr |= MCR_DTR;
            }
            if rts {
                mcr |= MCR_RTS;
            }
            outb(self.base + UART_MCR, mcr);
        }
    }

    /// Reads the modem status register.
    ///
    /// Returns (CTS, DSR, DCD).
    ///
    /// # Safety
    /// UART must be initialized.
    #[cfg(target_arch = "x86_64")]
    pub unsafe fn modem_status(&self) -> (bool, bool, bool) {
        // SAFETY: Reading MSR for modem line states.
        unsafe {
            let msr = inb(self.base + UART_MSR);
            (msr & MSR_CTS != 0, msr & MSR_DSR != 0, msr & MSR_DCD != 0)
        }
    }

    /// Reads the Line Status Register.
    ///
    /// # Safety
    /// UART must be initialized.
    #[cfg(target_arch = "x86_64")]
    pub unsafe fn line_status(&self) -> u8 {
        // SAFETY: Reading LSR for line error and buffer-empty status.
        unsafe { inb(self.base + UART_LSR) }
    }
}
