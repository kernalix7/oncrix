// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! 16550 UART serial port driver.
//!
//! Implements a driver for the 16550A-compatible UART found in most
//! x86 PC systems. The UART provides full-duplex serial communication
//! and is typically used for early kernel console output and debugging.
//!
//! # Features
//!
//! - Configurable baud rate (up to 115200).
//! - 16-byte transmit and receive FIFOs.
//! - Interrupt-driven or polled I/O.
//! - Modem control (RTS, DTR, loopback test).
//! - Line status error detection (overrun, parity, framing, break).
//!
//! # Standard I/O Port Addresses
//!
//! | Port | COM Name | IRQ |
//! |------|----------|-----|
//! | 0x3F8 | COM1    | IRQ 4 |
//! | 0x2F8 | COM2    | IRQ 3 |
//! | 0x3E8 | COM3    | IRQ 4 |
//! | 0x2E8 | COM4    | IRQ 3 |
//!
//! Reference: 16550D UART Technical Reference; PC16550D Datasheet.

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Register offsets (relative to base I/O port)
// ---------------------------------------------------------------------------

/// Transmitter Holding Register (write, DLAB=0).
const REG_THR: u16 = 0;

/// Receiver Buffer Register (read, DLAB=0).
const REG_RBR: u16 = 0;

/// Divisor Latch Low byte (read/write, DLAB=1).
const REG_DLL: u16 = 0;

/// Interrupt Enable Register (read/write, DLAB=0).
const REG_IER: u16 = 1;

/// Divisor Latch High byte (read/write, DLAB=1).
const REG_DLM: u16 = 1;

/// Interrupt Identification Register (read-only).
const REG_IIR: u16 = 2;

/// FIFO Control Register (write-only).
const REG_FCR: u16 = 2;

/// Line Control Register (read/write).
const REG_LCR: u16 = 3;

/// Modem Control Register (read/write).
const REG_MCR: u16 = 4;

/// Line Status Register (read-only).
const REG_LSR: u16 = 5;

/// Modem Status Register (read-only).
const REG_MSR: u16 = 6;

/// Scratch Register (read/write).
const _REG_SCR: u16 = 7;

// ---------------------------------------------------------------------------
// IER (Interrupt Enable Register) bits
// ---------------------------------------------------------------------------

/// IER bit 0: Enable Received Data Available interrupt.
const IER_RDA: u8 = 1 << 0;

/// IER bit 1: Enable Transmitter Holding Register Empty interrupt.
const IER_THRE: u8 = 1 << 1;

/// IER bit 2: Enable Receiver Line Status interrupt.
const IER_RLS: u8 = 1 << 2;

/// IER bit 3: Enable Modem Status interrupt.
const _IER_MS: u8 = 1 << 3;

// ---------------------------------------------------------------------------
// FCR (FIFO Control Register) bits
// ---------------------------------------------------------------------------

/// FCR bit 0: Enable FIFOs.
const FCR_ENABLE: u8 = 1 << 0;

/// FCR bit 1: Clear receive FIFO.
const FCR_CLEAR_RX: u8 = 1 << 1;

/// FCR bit 2: Clear transmit FIFO.
const FCR_CLEAR_TX: u8 = 1 << 2;

/// FCR bits 7:6: FIFO trigger level — 14 bytes.
const FCR_TRIGGER_14: u8 = 0xC0;

/// FCR bits 7:6: FIFO trigger level — 8 bytes.
const _FCR_TRIGGER_8: u8 = 0x80;

/// FCR bits 7:6: FIFO trigger level — 4 bytes.
const _FCR_TRIGGER_4: u8 = 0x40;

/// FCR bits 7:6: FIFO trigger level — 1 byte.
const _FCR_TRIGGER_1: u8 = 0x00;

// ---------------------------------------------------------------------------
// LCR (Line Control Register) bits
// ---------------------------------------------------------------------------

/// LCR bits 1:0: Word length 8 bits.
const LCR_WORD_8: u8 = 0x03;

/// LCR bits 1:0: Word length 7 bits.
const _LCR_WORD_7: u8 = 0x02;

/// LCR bit 2: Stop bits (0 = 1 stop bit, 1 = 2 stop bits).
const _LCR_STOP_2: u8 = 1 << 2;

/// LCR bit 3: Parity enable.
const _LCR_PARITY_EN: u8 = 1 << 3;

/// LCR bit 4: Even parity select (when parity enabled).
const _LCR_PARITY_EVEN: u8 = 1 << 4;

/// LCR bit 7: Divisor Latch Access Bit.
const LCR_DLAB: u8 = 1 << 7;

// ---------------------------------------------------------------------------
// MCR (Modem Control Register) bits
// ---------------------------------------------------------------------------

/// MCR bit 0: Data Terminal Ready.
const MCR_DTR: u8 = 1 << 0;

/// MCR bit 1: Request To Send.
const MCR_RTS: u8 = 1 << 1;

/// MCR bit 3: Auxiliary Output 2 (enables IRQ in PC architecture).
const MCR_OUT2: u8 = 1 << 3;

/// MCR bit 4: Loopback mode.
const MCR_LOOPBACK: u8 = 1 << 4;

// ---------------------------------------------------------------------------
// LSR (Line Status Register) bits
// ---------------------------------------------------------------------------

/// LSR bit 0: Data Ready (byte available in RBR).
const LSR_DR: u8 = 1 << 0;

/// LSR bit 1: Overrun Error.
const LSR_OE: u8 = 1 << 1;

/// LSR bit 2: Parity Error.
const LSR_PE: u8 = 1 << 2;

/// LSR bit 3: Framing Error.
const LSR_FE: u8 = 1 << 3;

/// LSR bit 4: Break Interrupt.
const _LSR_BI: u8 = 1 << 4;

/// LSR bit 5: Transmitter Holding Register Empty (can send).
const LSR_THRE: u8 = 1 << 5;

/// LSR bit 6: Transmitter Empty (THR + shift register empty).
const _LSR_TEMT: u8 = 1 << 6;

// ---------------------------------------------------------------------------
// IIR (Interrupt Identification Register) bits
// ---------------------------------------------------------------------------

/// IIR bit 0: No interrupt pending (1 = no interrupt).
const IIR_NO_INT: u8 = 1 << 0;

/// IIR bits 3:1 mask: interrupt identification.
const IIR_ID_MASK: u8 = 0x0E;

/// IIR: Modem Status interrupt.
const _IIR_MODEM_STATUS: u8 = 0x00;

/// IIR: Transmitter Holding Register Empty interrupt.
const IIR_THRE: u8 = 0x02;

/// IIR: Received Data Available interrupt.
const IIR_RDA: u8 = 0x04;

/// IIR: Receiver Line Status interrupt.
const IIR_RLS: u8 = 0x06;

/// IIR: Character Timeout interrupt.
const IIR_TIMEOUT: u8 = 0x0C;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// UART base clock frequency (1.8432 MHz).
const UART_CLOCK_HZ: u32 = 1_843_200;

/// Maximum baud rate divisor (16-bit).
const _MAX_DIVISOR: u16 = 0xFFFF;

/// Transmit timeout (polling iterations).
const TX_TIMEOUT: u32 = 100_000;

/// Receive timeout (polling iterations).
const RX_TIMEOUT: u32 = 100_000;

/// Maximum number of serial ports in the registry.
const MAX_SERIAL_PORTS: usize = 4;

/// Standard COM port base addresses.
pub const COM1_BASE: u16 = 0x3F8;
/// COM2 base address.
pub const COM2_BASE: u16 = 0x2F8;
/// COM3 base address.
pub const COM3_BASE: u16 = 0x3E8;
/// COM4 base address.
pub const COM4_BASE: u16 = 0x2E8;

// ---------------------------------------------------------------------------
// Port I/O helpers
// ---------------------------------------------------------------------------

/// Read a byte from an x86 I/O port.
#[cfg(target_arch = "x86_64")]
fn port_inb(port: u16) -> u8 {
    let val: u8;
    // SAFETY: Reading from UART I/O ports is a standard x86 operation
    // available in ring 0. The port addresses are well-known legacy
    // serial controller registers.
    unsafe {
        core::arch::asm!(
            "in al, dx",
            in("dx") port,
            out("al") val,
            options(nostack, nomem, preserves_flags),
        );
    }
    val
}

/// Write a byte to an x86 I/O port.
#[cfg(target_arch = "x86_64")]
fn port_outb(port: u16, val: u8) {
    // SAFETY: Writing to UART I/O ports is a standard x86 operation
    // available in ring 0. The port addresses are well-known legacy
    // serial controller registers.
    unsafe {
        core::arch::asm!(
            "out dx, al",
            in("dx") port,
            in("al") val,
            options(nostack, nomem, preserves_flags),
        );
    }
}

/// Stub for non-x86 targets.
#[cfg(not(target_arch = "x86_64"))]
fn port_inb(_port: u16) -> u8 {
    0
}

/// Stub for non-x86 targets.
#[cfg(not(target_arch = "x86_64"))]
fn port_outb(_port: u16, _val: u8) {}

// ---------------------------------------------------------------------------
// UartConfig
// ---------------------------------------------------------------------------

/// Configuration parameters for the 16550 UART.
#[derive(Debug, Clone, Copy)]
pub struct UartConfig {
    /// Baud rate (e.g., 9600, 115200).
    pub baud_rate: u32,
    /// Word length in bits (5, 6, 7, or 8).
    pub data_bits: u8,
    /// Number of stop bits (1 or 2).
    pub stop_bits: u8,
    /// Parity mode.
    pub parity: Parity,
    /// Whether to enable hardware FIFOs.
    pub fifo_enabled: bool,
}

impl UartConfig {
    /// Standard configuration: 115200 baud, 8N1, FIFOs enabled.
    pub const fn default_115200() -> Self {
        Self {
            baud_rate: 115_200,
            data_bits: 8,
            stop_bits: 1,
            parity: Parity::None,
            fifo_enabled: true,
        }
    }

    /// Compute the baud rate divisor.
    ///
    /// Returns `None` if the baud rate is zero or would produce a
    /// divisor of zero.
    pub fn divisor(&self) -> Option<u16> {
        if self.baud_rate == 0 {
            return None;
        }
        let div = (UART_CLOCK_HZ / 16) / self.baud_rate;
        if div == 0 || div > 0xFFFF {
            return None;
        }
        Some(div as u16)
    }

    /// Encode the LCR value for the word length, stop bits, and parity.
    fn lcr_value(&self) -> u8 {
        let mut lcr: u8 = 0;

        // Word length (bits 1:0).
        lcr |= match self.data_bits {
            5 => 0x00,
            6 => 0x01,
            7 => 0x02,
            _ => 0x03, // 8 bits default
        };

        // Stop bits (bit 2).
        if self.stop_bits >= 2 {
            lcr |= 1 << 2;
        }

        // Parity (bits 5:3).
        match self.parity {
            Parity::None => {}
            Parity::Odd => lcr |= 1 << 3,
            Parity::Even => lcr |= (1 << 3) | (1 << 4),
        }

        lcr
    }
}

impl Default for UartConfig {
    fn default() -> Self {
        Self::default_115200()
    }
}

// ---------------------------------------------------------------------------
// Parity
// ---------------------------------------------------------------------------

/// UART parity mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Parity {
    /// No parity bit.
    None,
    /// Odd parity.
    Odd,
    /// Even parity.
    Even,
}

// ---------------------------------------------------------------------------
// FifoControl
// ---------------------------------------------------------------------------

/// FIFO control configuration.
#[derive(Debug, Clone, Copy)]
pub struct FifoControl {
    /// Enable FIFOs.
    pub enabled: bool,
    /// Clear receive FIFO on configuration.
    pub clear_rx: bool,
    /// Clear transmit FIFO on configuration.
    pub clear_tx: bool,
    /// FIFO trigger level (1, 4, 8, or 14 bytes).
    pub trigger_level: u8,
}

impl FifoControl {
    /// Default: FIFOs enabled, cleared, trigger at 14 bytes.
    pub const fn default_enabled() -> Self {
        Self {
            enabled: true,
            clear_rx: true,
            clear_tx: true,
            trigger_level: 14,
        }
    }

    /// Encode the FCR value.
    fn to_fcr(&self) -> u8 {
        let mut fcr: u8 = 0;
        if self.enabled {
            fcr |= FCR_ENABLE;
        }
        if self.clear_rx {
            fcr |= FCR_CLEAR_RX;
        }
        if self.clear_tx {
            fcr |= FCR_CLEAR_TX;
        }
        fcr |= match self.trigger_level {
            1 => 0x00,
            4 => 0x40,
            8 => 0x80,
            _ => FCR_TRIGGER_14,
        };
        fcr
    }
}

impl Default for FifoControl {
    fn default() -> Self {
        Self::default_enabled()
    }
}

// ---------------------------------------------------------------------------
// LineStatus
// ---------------------------------------------------------------------------

/// Parsed line status register value.
#[derive(Debug, Clone, Copy)]
pub struct LineStatus {
    /// Data is available to read.
    pub data_ready: bool,
    /// Overrun error occurred.
    pub overrun_error: bool,
    /// Parity error detected.
    pub parity_error: bool,
    /// Framing error detected.
    pub framing_error: bool,
    /// Transmit holding register is empty (ready to send).
    pub tx_empty: bool,
}

impl LineStatus {
    /// Parse from the raw LSR register value.
    pub fn from_raw(raw: u8) -> Self {
        Self {
            data_ready: raw & LSR_DR != 0,
            overrun_error: raw & LSR_OE != 0,
            parity_error: raw & LSR_PE != 0,
            framing_error: raw & LSR_FE != 0,
            tx_empty: raw & LSR_THRE != 0,
        }
    }

    /// Return `true` if any error bit is set.
    pub fn has_error(&self) -> bool {
        self.overrun_error || self.parity_error || self.framing_error
    }
}

// ---------------------------------------------------------------------------
// Serial16550
// ---------------------------------------------------------------------------

/// 16550 UART serial port driver.
///
/// Provides polled and interrupt-driven serial I/O for the classic
/// 16550A UART. Supports configurable baud rates, FIFOs, and line
/// parameters.
///
/// # Usage
///
/// ```ignore
/// let mut serial = Serial16550::new(0x3F8); // COM1
/// serial.init(&UartConfig::default_115200())?;
/// serial.write_byte(b'H')?;
/// ```
pub struct Serial16550 {
    /// Base I/O port address.
    base: u16,
    /// Current configuration.
    config: UartConfig,
    /// Whether the port has been initialized.
    initialized: bool,
    /// Whether FIFOs are available (detected during init).
    fifo_available: bool,
}

impl Serial16550 {
    /// Create a new UART driver for the port at `base`.
    ///
    /// The port is not usable until [`init`](Self::init) is called.
    pub const fn new(base: u16) -> Self {
        Self {
            base,
            config: UartConfig {
                baud_rate: 0,
                data_bits: 8,
                stop_bits: 1,
                parity: Parity::None,
                fifo_enabled: false,
            },
            initialized: false,
            fifo_available: false,
        }
    }

    /// Initialize the UART with the specified configuration.
    ///
    /// Performs the following steps:
    /// 1. Disable all interrupts.
    /// 2. Set baud rate divisor (DLAB).
    /// 3. Configure line parameters (word length, stop bits, parity).
    /// 4. Enable and configure FIFOs.
    /// 5. Set modem control (DTR, RTS, OUT2).
    /// 6. Perform loopback self-test.
    /// 7. Enable interrupts if desired.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if the baud rate produces
    /// an invalid divisor. Returns [`Error::IoError`] if the loopback
    /// self-test fails.
    pub fn init(&mut self, config: &UartConfig) -> Result<()> {
        let divisor = config.divisor().ok_or(Error::InvalidArgument)?;

        // Step 1: Disable all interrupts.
        self.write_reg(REG_IER, 0x00);

        // Step 2: Set baud rate divisor.
        // Enable DLAB to access divisor latch.
        self.write_reg(REG_LCR, LCR_DLAB);
        self.write_reg(REG_DLL, divisor as u8);
        self.write_reg(REG_DLM, (divisor >> 8) as u8);

        // Step 3: Set line parameters and clear DLAB.
        self.write_reg(REG_LCR, config.lcr_value());

        // Step 4: Configure FIFOs.
        if config.fifo_enabled {
            let fifo = FifoControl::default_enabled();
            self.write_reg(REG_FCR, fifo.to_fcr());
        } else {
            self.write_reg(REG_FCR, 0);
        }

        // Check if FIFOs are available by reading IIR bits 7:6.
        let iir = self.read_reg(REG_IIR);
        self.fifo_available = iir & 0xC0 == 0xC0;

        // Step 5: Set modem control (DTR + RTS + OUT2).
        self.write_reg(REG_MCR, MCR_DTR | MCR_RTS | MCR_OUT2);

        // Step 6: Loopback self-test.
        self.write_reg(REG_MCR, MCR_LOOPBACK | MCR_DTR | MCR_RTS | MCR_OUT2);
        self.write_reg(REG_THR, 0xAE);

        // Wait for data to appear.
        let mut timeout = TX_TIMEOUT;
        while self.read_reg(REG_LSR) & LSR_DR == 0 {
            timeout = timeout.saturating_sub(1);
            if timeout == 0 {
                return Err(Error::IoError);
            }
        }

        let loopback_byte = self.read_reg(REG_RBR);
        if loopback_byte != 0xAE {
            return Err(Error::IoError);
        }

        // Exit loopback mode.
        self.write_reg(REG_MCR, MCR_DTR | MCR_RTS | MCR_OUT2);

        self.config = *config;
        self.initialized = true;
        Ok(())
    }

    // -- Register access ---------------------------------------------------

    /// Read a UART register.
    fn read_reg(&self, offset: u16) -> u8 {
        port_inb(self.base + offset)
    }

    /// Write a UART register.
    fn write_reg(&self, offset: u16, val: u8) {
        port_outb(self.base + offset, val);
    }

    // -- Data transfer -----------------------------------------------------

    /// Write a single byte, blocking until the transmitter is ready.
    ///
    /// # Errors
    ///
    /// Returns [`Error::IoError`] if the device is not initialized.
    /// Returns [`Error::Busy`] if the transmitter does not become
    /// ready within the timeout period.
    pub fn write_byte(&mut self, byte: u8) -> Result<()> {
        if !self.initialized {
            return Err(Error::IoError);
        }

        // Wait for THR to be empty.
        let mut timeout = TX_TIMEOUT;
        while self.read_reg(REG_LSR) & LSR_THRE == 0 {
            timeout = timeout.saturating_sub(1);
            if timeout == 0 {
                return Err(Error::Busy);
            }
        }

        self.write_reg(REG_THR, byte);
        Ok(())
    }

    /// Write a byte slice to the serial port.
    ///
    /// Sends each byte sequentially, blocking on each one.
    pub fn write_bytes(&mut self, data: &[u8]) -> Result<()> {
        for &b in data {
            self.write_byte(b)?;
        }
        Ok(())
    }

    /// Write a string to the serial port.
    ///
    /// Sends each byte of the UTF-8 string sequentially.
    pub fn write_str(&mut self, s: &str) -> Result<()> {
        self.write_bytes(s.as_bytes())
    }

    /// Read a single byte, blocking until data is available.
    ///
    /// # Errors
    ///
    /// Returns [`Error::IoError`] if the device is not initialized.
    /// Returns [`Error::Busy`] if no data arrives within the timeout.
    pub fn read_byte(&mut self) -> Result<u8> {
        if !self.initialized {
            return Err(Error::IoError);
        }

        let mut timeout = RX_TIMEOUT;
        while self.read_reg(REG_LSR) & LSR_DR == 0 {
            timeout = timeout.saturating_sub(1);
            if timeout == 0 {
                return Err(Error::Busy);
            }
        }

        Ok(self.read_reg(REG_RBR))
    }

    /// Try to read a byte without blocking.
    ///
    /// Returns `None` if no data is available.
    pub fn try_read_byte(&self) -> Option<u8> {
        if !self.initialized {
            return None;
        }
        if self.read_reg(REG_LSR) & LSR_DR != 0 {
            Some(self.read_reg(REG_RBR))
        } else {
            None
        }
    }

    // -- Interrupt handling ------------------------------------------------

    /// Enable receive data available and line status interrupts.
    pub fn enable_rx_interrupt(&mut self) {
        let ier = self.read_reg(REG_IER);
        self.write_reg(REG_IER, ier | IER_RDA | IER_RLS);
    }

    /// Enable transmitter holding register empty interrupt.
    pub fn enable_tx_interrupt(&mut self) {
        let ier = self.read_reg(REG_IER);
        self.write_reg(REG_IER, ier | IER_THRE);
    }

    /// Disable all UART interrupts.
    pub fn disable_interrupts(&mut self) {
        self.write_reg(REG_IER, 0x00);
    }

    /// Handle a UART interrupt.
    ///
    /// Reads the IIR to determine the interrupt cause and returns
    /// the cause as a bitmask. Reading IIR acknowledges the interrupt.
    ///
    /// Returns 0 if no interrupt was pending.
    pub fn handle_interrupt(&self) -> u8 {
        let iir = self.read_reg(REG_IIR);
        if iir & IIR_NO_INT != 0 {
            return 0;
        }
        iir & IIR_ID_MASK
    }

    // -- Status queries ----------------------------------------------------

    /// Read the current line status.
    pub fn line_status(&self) -> LineStatus {
        LineStatus::from_raw(self.read_reg(REG_LSR))
    }

    /// Read the raw modem status register.
    pub fn modem_status(&self) -> u8 {
        self.read_reg(REG_MSR)
    }

    /// Return `true` if data is available to read.
    pub fn data_available(&self) -> bool {
        self.read_reg(REG_LSR) & LSR_DR != 0
    }

    /// Return `true` if the transmitter is ready to accept data.
    pub fn tx_ready(&self) -> bool {
        self.read_reg(REG_LSR) & LSR_THRE != 0
    }

    /// Return whether the UART has been initialized.
    pub fn is_initialized(&self) -> bool {
        self.initialized
    }

    /// Return the base I/O port address.
    pub fn base_port(&self) -> u16 {
        self.base
    }

    /// Return whether FIFOs are available.
    pub fn has_fifo(&self) -> bool {
        self.fifo_available
    }

    /// Return the current configuration.
    pub fn config(&self) -> &UartConfig {
        &self.config
    }
}

impl core::fmt::Debug for Serial16550 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Serial16550")
            .field("base", &self.base)
            .field("initialized", &self.initialized)
            .field("fifo_available", &self.fifo_available)
            .field("baud_rate", &self.config.baud_rate)
            .finish()
    }
}

// ---------------------------------------------------------------------------
// Serial16550Registry
// ---------------------------------------------------------------------------

/// Registry for tracking multiple serial ports.
///
/// Supports up to [`MAX_SERIAL_PORTS`] concurrently registered ports.
pub struct Serial16550Registry {
    /// Registered base port addresses (0 = empty slot).
    bases: [u16; MAX_SERIAL_PORTS],
    /// Number of registered ports.
    count: usize,
}

impl Default for Serial16550Registry {
    fn default() -> Self {
        Self::new()
    }
}

impl Serial16550Registry {
    /// Create an empty registry.
    pub const fn new() -> Self {
        Self {
            bases: [0; MAX_SERIAL_PORTS],
            count: 0,
        }
    }

    /// Register a serial port by its base I/O address.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the registry is full.
    /// Returns [`Error::AlreadyExists`] if the port is already registered.
    /// Returns [`Error::InvalidArgument`] if the base address is zero.
    pub fn register(&mut self, base: u16) -> Result<()> {
        if base == 0 {
            return Err(Error::InvalidArgument);
        }
        if self.bases[..self.count].contains(&base) {
            return Err(Error::AlreadyExists);
        }
        if self.count >= MAX_SERIAL_PORTS {
            return Err(Error::OutOfMemory);
        }
        self.bases[self.count] = base;
        self.count += 1;
        Ok(())
    }

    /// Look up a registered port by base address.
    ///
    /// Returns the index, or [`Error::NotFound`].
    pub fn lookup(&self, base: u16) -> Result<usize> {
        self.bases[..self.count]
            .iter()
            .position(|&b| b == base)
            .ok_or(Error::NotFound)
    }

    /// Return the number of registered ports.
    pub fn count(&self) -> usize {
        self.count
    }

    /// Return the base address at the given index.
    pub fn get(&self, index: usize) -> Option<u16> {
        if index < self.count {
            Some(self.bases[index])
        } else {
            None
        }
    }

    /// Return `true` if no ports are registered.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
}

impl core::fmt::Debug for Serial16550Registry {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Serial16550Registry")
            .field("count", &self.count)
            .field("bases", &&self.bases[..self.count])
            .finish()
    }
}
