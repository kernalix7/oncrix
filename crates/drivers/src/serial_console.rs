// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Serial console driver (early boot and kgdb).
//!
//! Provides a simple, polling-mode serial console suitable for:
//! - Early boot output before the full driver framework is ready.
//! - Kernel debugging via a serial terminal.
//! - Fallback console when graphical output is unavailable.
//!
//! # Supported hardware
//!
//! - 8250/16550A UART (standard PC serial port, COM1–COM4).
//! - Defaults to COM1 at I/O base 0x3F8, baud 115200, 8N1.
//!
//! # Design
//!
//! [`SerialConsole`] is entirely polling-based (no interrupts) to avoid
//! depending on the interrupt subsystem during early boot. For production
//! use, the full TTY layer should be used instead.
//!
//! Reference: National Semiconductor 16550A UART Datasheet;
//! Linux `drivers/tty/serial/8250/`.

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// COM1 base I/O port.
pub const COM1_BASE: u16 = 0x3F8;

/// COM2 base I/O port.
pub const COM2_BASE: u16 = 0x2F8;

/// COM3 base I/O port.
pub const COM3_BASE: u16 = 0x3E8;

/// COM4 base I/O port.
pub const COM4_BASE: u16 = 0x2E8;

/// UART register offsets from the base port.

/// Receive Buffer Register (read) / Transmit Holding Register (write).
pub const REG_RBR_THR: u16 = 0;

/// Interrupt Enable Register.
pub const REG_IER: u16 = 1;

/// FIFO Control Register (write).
pub const REG_FCR: u16 = 2;

/// Line Control Register.
pub const REG_LCR: u16 = 3;

/// Modem Control Register.
pub const REG_MCR: u16 = 4;

/// Line Status Register (read-only).
pub const REG_LSR: u16 = 5;

/// Modem Status Register (read-only).
pub const REG_MSR: u16 = 6;

/// Scratch register.
pub const REG_SCR: u16 = 7;

/// Divisor Latch Low (DLAB=1).
pub const REG_DLL: u16 = 0;

/// Divisor Latch High (DLAB=1).
pub const REG_DLH: u16 = 1;

/// LCR: Data length 8 bits.
pub const LCR_8N1: u8 = 0x03;

/// LCR: DLAB (Divisor Latch Access Bit).
pub const LCR_DLAB: u8 = 0x80;

/// FCR: Enable FIFO, clear RX/TX, trigger at 14 bytes.
pub const FCR_FIFO_ENABLE: u8 = 0xC7;

/// MCR: DTR + RTS + OUT2 (needed to enable IRQs, also useful polling mode).
pub const MCR_DTR_RTS_OUT2: u8 = 0x0B;

/// LSR bit 0: Data Ready (RX has data).
pub const LSR_DR: u8 = 0x01;

/// LSR bit 5: Transmitter Holding Register Empty (ready to send).
pub const LSR_THRE: u8 = 0x20;

/// Clock rate of the UART in Hz (1.8432 MHz).
pub const UART_CLOCK_HZ: u32 = 1_843_200;

/// Default baud rate.
pub const DEFAULT_BAUD: u32 = 115_200;

// ---------------------------------------------------------------------------
// Port I/O primitives
// ---------------------------------------------------------------------------

/// Write a byte to an I/O port.
///
/// # Safety
///
/// Ring 0. `port` must be a valid UART register port.
#[cfg(target_arch = "x86_64")]
#[inline]
unsafe fn outb(port: u16, val: u8) {
    // SAFETY: Port I/O to a UART register; ring-0 context.
    unsafe {
        core::arch::asm!("out dx, al", in("dx") port, in("al") val, options(nostack, nomem));
    }
}

/// Read a byte from an I/O port.
///
/// # Safety
///
/// Ring 0. `port` must be a valid UART register port.
#[cfg(target_arch = "x86_64")]
#[inline]
unsafe fn inb(port: u16) -> u8 {
    let v: u8;
    // SAFETY: Port I/O read from a UART register; ring-0 context.
    unsafe {
        core::arch::asm!("in al, dx", out("al") v, in("dx") port, options(nostack, nomem));
    }
    v
}

// ---------------------------------------------------------------------------
// BaudRate
// ---------------------------------------------------------------------------

/// Convert a baud rate to the UART 16-bit divisor.
///
/// `UART_CLOCK_HZ / (16 * baud) = divisor`.
pub const fn baud_divisor(baud: u32) -> u16 {
    if baud == 0 {
        return 1;
    }
    let d = UART_CLOCK_HZ / (16 * baud);
    if d == 0 {
        1
    } else if d > 0xFFFF {
        0xFFFF
    } else {
        d as u16
    }
}

// ---------------------------------------------------------------------------
// SerialConsole
// ---------------------------------------------------------------------------

/// Polling-mode serial console.
///
/// Suitable for early-boot logging and debugging. Does not use interrupts.
pub struct SerialConsole {
    /// Base I/O port of the UART (e.g., `COM1_BASE` = 0x3F8).
    base: u16,
    /// Whether the console has been successfully initialised.
    ready: bool,
}

impl SerialConsole {
    /// Create a new uninitialized serial console at `base_port`.
    pub const fn new(base_port: u16) -> Self {
        Self {
            base: base_port,
            ready: false,
        }
    }

    /// Create a default console on COM1 (0x3F8).
    pub const fn com1() -> Self {
        Self::new(COM1_BASE)
    }

    /// Initialise the UART: disable interrupts, set baud rate, enable FIFO.
    ///
    /// # Errors
    ///
    /// Returns [`Error::IoError`] if the scratch register loopback test fails
    /// (no UART present at `base_port`).
    /// Returns [`Error::NotImplemented`] on non-x86_64 targets.
    pub fn init(&mut self, baud: u32) -> Result<()> {
        #[cfg(target_arch = "x86_64")]
        {
            let divisor = baud_divisor(baud);
            // SAFETY: Standard 16550A UART initialisation sequence.
            unsafe {
                // Disable all interrupts.
                outb(self.base + REG_IER, 0x00);
                // Enable DLAB; set baud divisor.
                outb(self.base + REG_LCR, LCR_DLAB);
                outb(self.base + REG_DLL, (divisor & 0xFF) as u8);
                outb(self.base + REG_DLH, (divisor >> 8) as u8);
                // Clear DLAB; 8 data bits, no parity, 1 stop bit.
                outb(self.base + REG_LCR, LCR_8N1);
                // Enable FIFO, clear TX/RX, 14-byte trigger level.
                outb(self.base + REG_FCR, FCR_FIFO_ENABLE);
                // Enable DTR, RTS, and OUT2.
                outb(self.base + REG_MCR, MCR_DTR_RTS_OUT2);
                // Loopback test: write to scratch, read back.
                outb(self.base + REG_SCR, 0xAE);
                if inb(self.base + REG_SCR) != 0xAE {
                    return Err(Error::IoError);
                }
                // Disable loopback.
                outb(self.base + REG_MCR, MCR_DTR_RTS_OUT2 & !0x10);
            }
            self.ready = true;
            Ok(())
        }
        #[cfg(not(target_arch = "x86_64"))]
        {
            let _ = baud;
            Err(Error::NotImplemented)
        }
    }

    /// Return `true` if the console is ready to use.
    pub const fn is_ready(&self) -> bool {
        self.ready
    }

    /// Write a single byte, polling until the transmitter is ready.
    ///
    /// # Errors
    ///
    /// Returns [`Error::IoError`] if not initialised.
    /// Returns [`Error::NotImplemented`] on non-x86_64 targets.
    pub fn write_byte(&self, byte: u8) -> Result<()> {
        if !self.ready {
            return Err(Error::IoError);
        }
        #[cfg(target_arch = "x86_64")]
        {
            // SAFETY: Polling the UART LSR and writing to the THR.
            unsafe {
                let mut limit = 0x100_000u32;
                while inb(self.base + REG_LSR) & LSR_THRE == 0 {
                    if limit == 0 {
                        return Err(Error::Busy);
                    }
                    limit -= 1;
                    core::hint::spin_loop();
                }
                outb(self.base + REG_RBR_THR, byte);
            }
            Ok(())
        }
        #[cfg(not(target_arch = "x86_64"))]
        {
            let _ = byte;
            Err(Error::NotImplemented)
        }
    }

    /// Write a byte slice to the console.
    ///
    /// Translates `\n` to `\r\n` for terminal compatibility.
    ///
    /// # Errors
    ///
    /// Returns the first error from [`Self::write_byte`].
    pub fn write_bytes(&self, data: &[u8]) -> Result<()> {
        for &b in data {
            if b == b'\n' {
                self.write_byte(b'\r')?;
            }
            self.write_byte(b)?;
        }
        Ok(())
    }

    /// Read a single byte if the RX buffer has data.
    ///
    /// Returns `None` if no data is available (non-blocking).
    ///
    /// # Errors
    ///
    /// Returns [`Error::IoError`] if not initialised.
    pub fn read_byte(&self) -> Result<Option<u8>> {
        if !self.ready {
            return Err(Error::IoError);
        }
        #[cfg(target_arch = "x86_64")]
        {
            // SAFETY: Polling the LSR and reading from the RBR.
            let lsr = unsafe { inb(self.base + REG_LSR) };
            if lsr & LSR_DR != 0 {
                let b = unsafe { inb(self.base + REG_RBR_THR) };
                Ok(Some(b))
            } else {
                Ok(None)
            }
        }
        #[cfg(not(target_arch = "x86_64"))]
        Ok(None)
    }

    /// Read into `buf`, returning the number of bytes read.
    ///
    /// Non-blocking: reads up to `buf.len()` available bytes.
    ///
    /// # Errors
    ///
    /// Returns [`Error::IoError`] if not initialised.
    pub fn read_bytes(&self, buf: &mut [u8]) -> Result<usize> {
        let mut n = 0;
        for slot in buf.iter_mut() {
            match self.read_byte()? {
                Some(b) => {
                    *slot = b;
                    n += 1;
                }
                None => break,
            }
        }
        Ok(n)
    }

    /// Return the base I/O port.
    pub const fn base_port(&self) -> u16 {
        self.base
    }
}

// ---------------------------------------------------------------------------
// SerialConsoleRegistry
// ---------------------------------------------------------------------------

/// Maximum number of serial consoles.
const MAX_SERIAL_CONSOLES: usize = 4;

/// Registry of serial consoles (one per COM port).
pub struct SerialConsoleRegistry {
    consoles: [Option<SerialConsole>; MAX_SERIAL_CONSOLES],
    count: usize,
}

impl SerialConsoleRegistry {
    /// Create an empty registry.
    pub const fn new() -> Self {
        const NONE: Option<SerialConsole> = None;
        Self {
            consoles: [NONE; MAX_SERIAL_CONSOLES],
            count: 0,
        }
    }

    /// Register a console. Returns its index.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the registry is full.
    pub fn register(&mut self, console: SerialConsole) -> Result<usize> {
        if self.count >= MAX_SERIAL_CONSOLES {
            return Err(Error::OutOfMemory);
        }
        let id = self.count;
        self.consoles[id] = Some(console);
        self.count += 1;
        Ok(id)
    }

    /// Get a reference to a console by index.
    pub fn get(&self, id: usize) -> Option<&SerialConsole> {
        self.consoles.get(id)?.as_ref()
    }

    /// Get a mutable reference to a console by index.
    pub fn get_mut(&mut self, id: usize) -> Option<&mut SerialConsole> {
        self.consoles.get_mut(id)?.as_mut()
    }

    /// Return the number of registered consoles.
    pub const fn len(&self) -> usize {
        self.count
    }

    /// Return `true` if no consoles are registered.
    pub const fn is_empty(&self) -> bool {
        self.count == 0
    }
}

impl Default for SerialConsoleRegistry {
    fn default() -> Self {
        Self::new()
    }
}
