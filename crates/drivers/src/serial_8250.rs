// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! 8250/16550 UART serial driver.
//!
//! Implements the classic Intel 8250/16450/16550A serial UART found on virtually
//! every PC-compatible system. Supports standard baud rates, interrupt-driven
//! operation, FIFO management, and line control settings.

use oncrix_lib::{Error, Result};

/// Base port offsets relative to the UART base address.
/// These are the same for all 8250-family UARTs.
const REG_RBR: u16 = 0; // Receive Buffer Register (read)
const REG_THR: u16 = 0; // Transmit Holding Register (write)
const REG_DLL: u16 = 0; // Divisor Latch Low (DLAB=1)
const REG_DLM: u16 = 1; // Divisor Latch High (DLAB=1)
const REG_IER: u16 = 1; // Interrupt Enable Register
const REG_IIR: u16 = 2; // Interrupt Identification Register (read)
const REG_FCR: u16 = 2; // FIFO Control Register (write)
const REG_LCR: u16 = 3; // Line Control Register
const REG_MCR: u16 = 4; // Modem Control Register
const REG_LSR: u16 = 5; // Line Status Register
const REG_MSR: u16 = 6; // Modem Status Register
const REG_SCR: u16 = 7; // Scratch Register (16550+ only)

/// IER bits.
const IER_RDA: u8 = 1 << 0; // Received data available
const IER_THRE: u8 = 1 << 1; // Transmitter holding register empty
const IER_RLS: u8 = 1 << 2; // Receiver line status
const IER_MODEM: u8 = 1 << 3; // Modem status

/// FCR bits.
const FCR_FIFO_EN: u8 = 1 << 0; // Enable FIFO
const FCR_CLR_RX: u8 = 1 << 1; // Clear receive FIFO
const FCR_CLR_TX: u8 = 1 << 2; // Clear transmit FIFO
const FCR_TRIGGER_14: u8 = 0b11 << 6; // 14-byte FIFO trigger level

/// LCR bits.
const LCR_WORD_5: u8 = 0b00;
const LCR_WORD_6: u8 = 0b01;
const LCR_WORD_7: u8 = 0b10;
const LCR_WORD_8: u8 = 0b11;
const LCR_STOP_2: u8 = 1 << 2;
const LCR_PARITY_EN: u8 = 1 << 3;
const LCR_PARITY_EVEN: u8 = 1 << 4;
const LCR_BREAK: u8 = 1 << 6;
const LCR_DLAB: u8 = 1 << 7; // Divisor Latch Access Bit

/// MCR bits.
const MCR_DTR: u8 = 1 << 0;
const MCR_RTS: u8 = 1 << 1;
const MCR_OUT2: u8 = 1 << 3; // Enables IRQ output on PC hardware
const MCR_LOOP: u8 = 1 << 4; // Local loopback mode

/// LSR bits.
const LSR_DR: u8 = 1 << 0; // Data ready
const LSR_OE: u8 = 1 << 1; // Overrun error
const LSR_PE: u8 = 1 << 2; // Parity error
const LSR_FE: u8 = 1 << 3; // Framing error
const LSR_BI: u8 = 1 << 4; // Break interrupt
const LSR_THRE: u8 = 1 << 5; // Transmitter holding register empty
const LSR_TEMT: u8 = 1 << 6; // Transmitter empty

/// IIR interrupt cause codes (lower 4 bits).
const IIR_NO_INT: u8 = 0x01;
const IIR_RLS: u8 = 0x06; // Receiver line status
const IIR_RDA: u8 = 0x04; // Received data available
const IIR_CTI: u8 = 0x0C; // Character timeout (FIFO mode)
const IIR_THRE: u8 = 0x02; // Transmitter holding register empty
const IIR_MODEM: u8 = 0x00; // Modem status

/// UART clock frequency (1.8432 MHz crystal).
const UART_CLOCK_HZ: u32 = 1_843_200;

/// Baud rate divisor for common rates.
pub fn baud_divisor(baud: u32) -> Result<u16> {
    if baud == 0 {
        return Err(Error::InvalidArgument);
    }
    let divisor = UART_CLOCK_HZ / (16 * baud);
    if divisor == 0 || divisor > 0xFFFF {
        return Err(Error::InvalidArgument);
    }
    Ok(divisor as u16)
}

/// Word length setting.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WordLength {
    /// 5 data bits.
    Bits5,
    /// 6 data bits.
    Bits6,
    /// 7 data bits.
    Bits7,
    /// 8 data bits.
    Bits8,
}

/// Parity setting.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Parity {
    /// No parity bit.
    None,
    /// Odd parity.
    Odd,
    /// Even parity.
    Even,
}

/// Stop bit setting.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StopBits {
    /// 1 stop bit.
    One,
    /// 2 stop bits (or 1.5 for 5-bit words).
    Two,
}

/// UART line configuration.
#[derive(Clone, Copy, Debug)]
pub struct LineConfig {
    /// Baud rate.
    pub baud: u32,
    /// Word length.
    pub word_length: WordLength,
    /// Parity mode.
    pub parity: Parity,
    /// Stop bits.
    pub stop_bits: StopBits,
}

impl Default for LineConfig {
    /// Default: 115200 8N1.
    fn default() -> Self {
        Self {
            baud: 115200,
            word_length: WordLength::Bits8,
            parity: Parity::None,
            stop_bits: StopBits::One,
        }
    }
}

/// Interrupt cause decoded from IIR.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InterruptCause {
    /// No interrupt pending.
    None,
    /// Receiver line status (error or break).
    ReceiverLineStatus,
    /// Received data available.
    DataAvailable,
    /// Character timeout (FIFO receive timeout).
    CharacterTimeout,
    /// Transmitter holding register empty.
    TxEmpty,
    /// Modem status changed.
    ModemStatus,
}

/// 8250/16550A UART driver.
pub struct Serial8250 {
    /// Base I/O port.
    base_port: u16,
    /// FIFO is available and enabled.
    fifo_enabled: bool,
}

impl Serial8250 {
    /// Create a new UART driver with the given base I/O port.
    pub const fn new(base_port: u16) -> Self {
        Self {
            base_port,
            fifo_enabled: false,
        }
    }

    /// Initialize the UART with the given line configuration.
    pub fn init(&mut self, config: &LineConfig) -> Result<()> {
        // Disable all interrupts during setup.
        self.write_reg(REG_IER, 0x00);
        // Check if 16550 FIFO is available by writing to SCR.
        self.write_reg(REG_SCR, 0xA5);
        let scr_back = self.read_reg(REG_SCR);
        // Enable and reset FIFOs if chip supports them.
        if scr_back == 0xA5 {
            self.write_reg(
                REG_FCR,
                FCR_FIFO_EN | FCR_CLR_RX | FCR_CLR_TX | FCR_TRIGGER_14,
            );
            self.fifo_enabled = true;
        }
        self.set_line_config(config)?;
        // Enable DTR, RTS, and OUT2 (required for IRQ on PC).
        self.write_reg(REG_MCR, MCR_DTR | MCR_RTS | MCR_OUT2);
        // Enable RDA interrupt.
        self.write_reg(REG_IER, IER_RDA | IER_RLS);
        Ok(())
    }

    /// Apply a line configuration (baud rate, word length, parity, stop bits).
    pub fn set_line_config(&mut self, config: &LineConfig) -> Result<()> {
        let divisor = baud_divisor(config.baud)?;
        let word_bits: u8 = match config.word_length {
            WordLength::Bits5 => LCR_WORD_5,
            WordLength::Bits6 => LCR_WORD_6,
            WordLength::Bits7 => LCR_WORD_7,
            WordLength::Bits8 => LCR_WORD_8,
        };
        let stop_bit: u8 = if config.stop_bits == StopBits::Two {
            LCR_STOP_2
        } else {
            0
        };
        let parity_bits: u8 = match config.parity {
            Parity::None => 0,
            Parity::Odd => LCR_PARITY_EN,
            Parity::Even => LCR_PARITY_EN | LCR_PARITY_EVEN,
        };
        let lcr = word_bits | stop_bit | parity_bits;
        // Set DLAB to access divisor registers.
        self.write_reg(REG_LCR, lcr | LCR_DLAB);
        self.write_reg(REG_DLL, (divisor & 0xFF) as u8);
        self.write_reg(REG_DLM, ((divisor >> 8) & 0xFF) as u8);
        // Clear DLAB.
        self.write_reg(REG_LCR, lcr);
        Ok(())
    }

    /// Transmit a single byte, blocking until the THR is empty.
    pub fn write_byte(&mut self, byte: u8) -> Result<()> {
        self.wait_tx_empty()?;
        self.write_reg(REG_THR, byte);
        Ok(())
    }

    /// Transmit a slice of bytes.
    pub fn write_bytes(&mut self, bytes: &[u8]) -> Result<()> {
        for &b in bytes {
            self.write_byte(b)?;
        }
        Ok(())
    }

    /// Receive a single byte if one is available; returns `None` if not.
    pub fn read_byte(&mut self) -> Option<u8> {
        let lsr = self.read_reg(REG_LSR);
        if (lsr & LSR_DR) != 0 {
            Some(self.read_reg(REG_RBR))
        } else {
            None
        }
    }

    /// Handle a UART interrupt; returns the decoded cause.
    pub fn handle_interrupt(&mut self) -> InterruptCause {
        let iir = self.read_reg(REG_IIR);
        if (iir & IIR_NO_INT) != 0 {
            return InterruptCause::None;
        }
        match iir & 0x0F {
            IIR_RLS => InterruptCause::ReceiverLineStatus,
            IIR_RDA => InterruptCause::DataAvailable,
            IIR_CTI => InterruptCause::CharacterTimeout,
            IIR_THRE => InterruptCause::TxEmpty,
            _ => InterruptCause::ModemStatus,
        }
    }

    /// Read the Line Status Register.
    pub fn line_status(&self) -> u8 {
        self.read_reg(REG_LSR)
    }

    /// Return whether the FIFO is enabled.
    pub fn has_fifo(&self) -> bool {
        self.fifo_enabled
    }

    /// Wait until the Transmitter Holding Register is empty.
    fn wait_tx_empty(&self) -> Result<()> {
        let mut tries = 0u32;
        loop {
            if (self.read_reg(REG_LSR) & LSR_THRE) != 0 {
                return Ok(());
            }
            tries += 1;
            if tries > 100_000 {
                return Err(Error::Busy);
            }
            core::hint::spin_loop();
        }
    }

    // --- Port I/O helpers ---

    fn read_reg(&self, offset: u16) -> u8 {
        #[cfg(target_arch = "x86_64")]
        {
            let val: u8;
            // SAFETY: base_port is a valid 8250 UART I/O port range; offset
            // is at most 7, keeping us within the standard 8-register UART window.
            unsafe {
                core::arch::asm!(
                    "in al, dx",
                    in("dx") self.base_port + offset,
                    out("al") val,
                    options(nomem, nostack)
                );
            }
            return val;
        }
        #[allow(unreachable_code)]
        0
    }

    fn write_reg(&mut self, offset: u16, val: u8) {
        #[cfg(target_arch = "x86_64")]
        // SAFETY: Same port range as read_reg; volatile PIO write to hardware register.
        unsafe {
            core::arch::asm!(
                "out dx, al",
                in("dx") self.base_port + offset,
                in("al") val,
                options(nomem, nostack)
            );
        }
    }
}

/// Well-known COM port base addresses on PC hardware.
pub const COM1_PORT: u16 = 0x3F8;
pub const COM2_PORT: u16 = 0x2F8;
pub const COM3_PORT: u16 = 0x3E8;
pub const COM4_PORT: u16 = 0x2E8;
