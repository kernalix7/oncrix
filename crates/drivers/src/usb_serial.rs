// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! USB-to-serial converter driver.
//!
//! Manages TTY-style serial communication over USB bulk endpoints
//! for adapters such as FTDI FT232, CH340, and CP2102. Provides
//! open/close lifecycle, baud rate configuration, flow control,
//! and buffered read/write operations.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────┐
//! │  User TTY    │
//! └──────┬──────┘
//!        │ read/write/ioctl
//! ┌──────▼──────┐
//! │  USB Serial  │ ← this module
//! └──────┬──────┘
//!        │ USB bulk IN/OUT
//! ┌──────▼──────┐
//! │  xHCI / EHCI │
//! └─────────────┘
//! ```
//!
//! The driver converts serial semantics (baud rate, parity, stop bits)
//! into USB control and bulk transfers. Each attached USB-serial adapter
//! is represented as a [`UsbSerial`] device with its own TX/RX buffers.
//!
//! Reference: FTDI Application Note AN232B-04,
//! USB CDC ACM Class Specification 1.2.

use oncrix_lib::{Error, Result};

// ── Constants ───────────────────────────────────────────────────

/// Maximum number of USB-serial devices tracked.
const MAX_USB_SERIAL_DEVICES: usize = 8;

/// TX buffer size in bytes.
const TX_BUF_SIZE: usize = 4096;

/// RX buffer size in bytes.
const RX_BUF_SIZE: usize = 4096;

/// Maximum USB bulk transfer size.
const MAX_BULK_SIZE: usize = 512;

/// Default baud rate.
const DEFAULT_BAUD: u32 = 115200;

/// Default data bits.
const DEFAULT_DATA_BITS: u8 = 8;

/// USB CDC class code.
pub const CDC_CLASS: u8 = 0x02;

/// USB CDC ACM subclass.
pub const CDC_ACM_SUBCLASS: u8 = 0x02;

/// USB vendor class code (for proprietary adapters like FTDI).
pub const VENDOR_CLASS: u8 = 0xFF;

// ── Vendor / Product IDs ────────────────────────────────────────

/// FTDI FT232R vendor ID.
pub const FTDI_VENDOR_ID: u16 = 0x0403;

/// FTDI FT232R product ID.
pub const FTDI_FT232_PRODUCT_ID: u16 = 0x6001;

/// CH340/CH341 vendor ID.
pub const CH340_VENDOR_ID: u16 = 0x1A86;

/// CH340 product ID.
pub const CH340_PRODUCT_ID: u16 = 0x7523;

/// CP2102 vendor ID (Silicon Labs).
pub const CP2102_VENDOR_ID: u16 = 0x10C4;

/// CP2102 product ID.
pub const CP2102_PRODUCT_ID: u16 = 0xEA60;

// ── Baud Rate ───────────────────────────────────────────────────

/// Standard baud rate values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum BaudRate {
    /// 300 baud.
    B300 = 300,
    /// 1200 baud.
    B1200 = 1200,
    /// 2400 baud.
    B2400 = 2400,
    /// 4800 baud.
    B4800 = 4800,
    /// 9600 baud.
    B9600 = 9600,
    /// 19200 baud.
    B19200 = 19200,
    /// 38400 baud.
    B38400 = 38400,
    /// 57600 baud.
    B57600 = 57600,
    /// 115200 baud.
    B115200 = 115200,
    /// 230400 baud.
    B230400 = 230400,
    /// 460800 baud.
    B460800 = 460800,
    /// 921600 baud.
    B921600 = 921600,
}

impl BaudRate {
    /// Return the baud rate as a u32 value.
    pub fn value(self) -> u32 {
        self as u32
    }
}

impl Default for BaudRate {
    fn default() -> Self {
        Self::B115200
    }
}

// ── Serial Configuration ────────────────────────────────────────

/// Parity configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Parity {
    /// No parity.
    #[default]
    None,
    /// Odd parity.
    Odd,
    /// Even parity.
    Even,
    /// Mark parity (always 1).
    Mark,
    /// Space parity (always 0).
    Space,
}

/// Stop bit configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum StopBits {
    /// One stop bit.
    #[default]
    One,
    /// One and a half stop bits.
    OnePointFive,
    /// Two stop bits.
    Two,
}

/// Flow control mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum FlowControl {
    /// No flow control.
    #[default]
    None,
    /// Hardware (RTS/CTS) flow control.
    RtsCts,
    /// Software (XON/XOFF) flow control.
    XonXoff,
    /// DTR/DSR flow control.
    DtrDsr,
}

/// Complete serial port configuration.
#[derive(Debug, Clone, Copy)]
pub struct SerialConfig {
    /// Baud rate.
    pub baud_rate: u32,
    /// Data bits (5, 6, 7, or 8).
    pub data_bits: u8,
    /// Parity mode.
    pub parity: Parity,
    /// Stop bits.
    pub stop_bits: StopBits,
    /// Flow control mode.
    pub flow_control: FlowControl,
}

impl SerialConfig {
    /// Create a default 115200 8N1 configuration.
    pub const fn default_config() -> Self {
        Self {
            baud_rate: DEFAULT_BAUD,
            data_bits: DEFAULT_DATA_BITS,
            parity: Parity::None,
            stop_bits: StopBits::One,
            flow_control: FlowControl::None,
        }
    }
}

impl Default for SerialConfig {
    fn default() -> Self {
        Self::default_config()
    }
}

// ── Modem Signals ───────────────────────────────────────────────

/// Modem control/status line state.
#[derive(Debug, Clone, Copy, Default)]
pub struct ModemSignals {
    /// Data Terminal Ready (output).
    pub dtr: bool,
    /// Request to Send (output).
    pub rts: bool,
    /// Clear to Send (input).
    pub cts: bool,
    /// Data Set Ready (input).
    pub dsr: bool,
    /// Ring Indicator (input).
    pub ri: bool,
    /// Data Carrier Detect (input).
    pub dcd: bool,
}

// ── USB Endpoint Info ───────────────────────────────────────────

/// USB endpoint descriptors for a serial port.
#[derive(Debug, Clone, Copy)]
struct UsbEndpoints {
    /// Bulk IN endpoint address.
    bulk_in: u8,
    /// Bulk OUT endpoint address.
    bulk_out: u8,
    /// Interrupt IN endpoint address (for modem status).
    interrupt_in: u8,
    /// Maximum packet size for bulk endpoints.
    max_packet_size: u16,
}

impl UsbEndpoints {
    const fn empty() -> Self {
        Self {
            bulk_in: 0,
            bulk_out: 0,
            interrupt_in: 0,
            max_packet_size: 64,
        }
    }
}

// ── Port State ──────────────────────────────────────────────────

/// State of a USB serial port.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PortState {
    /// Port is not attached to any device.
    #[default]
    Detached,
    /// Device is attached but port is closed.
    Closed,
    /// Port is open and ready for I/O.
    Open,
    /// Port is in an error state.
    Error,
}

// ── Chip Type ───────────────────────────────────────────────────

/// USB-serial converter chip type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ChipType {
    /// Unknown / generic CDC ACM.
    #[default]
    Generic,
    /// FTDI FT232 family.
    Ftdi,
    /// CH340/CH341.
    Ch340,
    /// CP2102/CP2104 (Silicon Labs).
    Cp210x,
    /// Prolific PL2303.
    Pl2303,
}

// ── Ring Buffer ─────────────────────────────────────────────────

/// A simple ring buffer for serial I/O.
struct RingBuffer {
    /// Backing storage.
    data: [u8; TX_BUF_SIZE],
    /// Read position.
    read_pos: usize,
    /// Write position.
    write_pos: usize,
    /// Number of bytes stored.
    count: usize,
}

impl RingBuffer {
    /// Create an empty ring buffer.
    const fn new() -> Self {
        Self {
            data: [0u8; TX_BUF_SIZE],
            read_pos: 0,
            write_pos: 0,
            count: 0,
        }
    }

    /// Return the number of bytes available to read.
    fn available(&self) -> usize {
        self.count
    }

    /// Return the number of free bytes.
    fn free_space(&self) -> usize {
        TX_BUF_SIZE - self.count
    }

    /// Write bytes into the buffer.
    ///
    /// Returns the number of bytes actually written.
    fn write(&mut self, data: &[u8]) -> usize {
        let space = self.free_space();
        let to_write = data.len().min(space);

        for i in 0..to_write {
            self.data[self.write_pos] = data[i];
            self.write_pos = (self.write_pos + 1) % TX_BUF_SIZE;
        }
        self.count += to_write;

        to_write
    }

    /// Read bytes from the buffer.
    ///
    /// Returns the number of bytes actually read.
    fn read(&mut self, buf: &mut [u8]) -> usize {
        let to_read = buf.len().min(self.count);

        for i in 0..to_read {
            buf[i] = self.data[self.read_pos];
            self.read_pos = (self.read_pos + 1) % TX_BUF_SIZE;
        }
        self.count -= to_read;

        to_read
    }

    /// Discard all buffered data.
    fn flush(&mut self) {
        self.read_pos = 0;
        self.write_pos = 0;
        self.count = 0;
    }
}

// ── USB Serial Port ─────────────────────────────────────────────

/// A USB-to-serial converter device.
///
/// Represents a single serial port backed by a USB adapter. Manages
/// the port lifecycle (open/close), configuration (baud, parity),
/// and buffered I/O (read/write).
pub struct UsbSerial {
    /// USB device address.
    usb_address: u8,
    /// USB interface number.
    interface: u8,
    /// Chip type.
    chip: ChipType,
    /// Vendor ID.
    vendor_id: u16,
    /// Product ID.
    product_id: u16,
    /// Endpoint descriptors.
    endpoints: UsbEndpoints,
    /// Current serial configuration.
    config: SerialConfig,
    /// Current modem signal state.
    modem: ModemSignals,
    /// Port state.
    state: PortState,
    /// Transmit ring buffer.
    tx_buf: RingBuffer,
    /// Receive ring buffer.
    rx_buf: RingBuffer,
    /// Total bytes transmitted.
    tx_count: u64,
    /// Total bytes received.
    rx_count: u64,
    /// Error count.
    error_count: u32,
}

impl UsbSerial {
    /// Create an uninitialised USB serial port.
    pub const fn new() -> Self {
        Self {
            usb_address: 0,
            interface: 0,
            chip: ChipType::Generic,
            vendor_id: 0,
            product_id: 0,
            endpoints: UsbEndpoints::empty(),
            config: SerialConfig::default_config(),
            modem: ModemSignals {
                dtr: false,
                rts: false,
                cts: false,
                dsr: false,
                ri: false,
                dcd: false,
            },
            state: PortState::Detached,
            tx_buf: RingBuffer::new(),
            rx_buf: RingBuffer::new(),
            tx_count: 0,
            rx_count: 0,
            error_count: 0,
        }
    }

    /// Attach a USB device to this serial port.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if the USB address is 0.
    pub fn attach(
        &mut self,
        usb_address: u8,
        interface: u8,
        vendor_id: u16,
        product_id: u16,
        bulk_in: u8,
        bulk_out: u8,
    ) -> Result<()> {
        if usb_address == 0 {
            return Err(Error::InvalidArgument);
        }

        self.usb_address = usb_address;
        self.interface = interface;
        self.vendor_id = vendor_id;
        self.product_id = product_id;
        self.endpoints.bulk_in = bulk_in;
        self.endpoints.bulk_out = bulk_out;

        // Detect chip type from vendor/product IDs.
        self.chip = match (vendor_id, product_id) {
            (FTDI_VENDOR_ID, _) => ChipType::Ftdi,
            (CH340_VENDOR_ID, _) => ChipType::Ch340,
            (CP2102_VENDOR_ID, _) => ChipType::Cp210x,
            _ => ChipType::Generic,
        };

        self.state = PortState::Closed;
        Ok(())
    }

    /// Open the serial port for I/O.
    ///
    /// Initialises the chip, sets the default baud rate, and
    /// asserts DTR/RTS.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if the port is not in the
    /// Closed state.
    pub fn open(&mut self) -> Result<()> {
        if self.state != PortState::Closed {
            return Err(Error::InvalidArgument);
        }

        // Flush buffers.
        self.tx_buf.flush();
        self.rx_buf.flush();

        // Set default configuration.
        self.config = SerialConfig::default_config();

        // Assert modem control lines.
        self.modem.dtr = true;
        self.modem.rts = true;

        self.state = PortState::Open;
        Ok(())
    }

    /// Close the serial port.
    ///
    /// Flushes buffers, de-asserts modem lines, and transitions
    /// to the Closed state.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if the port is not open.
    pub fn close(&mut self) -> Result<()> {
        if self.state != PortState::Open {
            return Err(Error::InvalidArgument);
        }

        self.tx_buf.flush();
        self.rx_buf.flush();
        self.modem.dtr = false;
        self.modem.rts = false;

        self.state = PortState::Closed;
        Ok(())
    }

    /// Write data to the serial port.
    ///
    /// Copies data into the TX ring buffer. The actual USB bulk
    /// transfer is driven by the interrupt/polling handler.
    ///
    /// Returns the number of bytes written (may be less than
    /// `data.len()` if the buffer is full).
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if the port is not open.
    pub fn write(&mut self, data: &[u8]) -> Result<usize> {
        if self.state != PortState::Open {
            return Err(Error::InvalidArgument);
        }

        let written = self.tx_buf.write(data);
        self.tx_count += written as u64;

        Ok(written)
    }

    /// Read data from the serial port.
    ///
    /// Copies available data from the RX ring buffer into `buf`.
    /// Returns the number of bytes read.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if the port is not open.
    pub fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        if self.state != PortState::Open {
            return Err(Error::InvalidArgument);
        }

        let count = self.rx_buf.read(buf);
        self.rx_count += count as u64;

        Ok(count)
    }

    /// Push received data into the RX buffer.
    ///
    /// Called by the USB interrupt/polling handler when bulk IN
    /// data arrives.
    ///
    /// Returns the number of bytes accepted.
    pub fn push_rx_data(&mut self, data: &[u8]) -> usize {
        self.rx_buf.write(data)
    }

    /// Pull data from the TX buffer for USB bulk OUT transmission.
    ///
    /// Called by the USB polling handler to get the next chunk of
    /// data to send.
    ///
    /// Returns the number of bytes read into `buf`.
    pub fn pull_tx_data(&mut self, buf: &mut [u8]) -> usize {
        self.tx_buf.read(buf)
    }

    /// Set the baud rate.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if the baud rate is zero.
    pub fn set_baud_rate(&mut self, baud: BaudRate) -> Result<()> {
        self.config.baud_rate = baud.value();
        Ok(())
    }

    /// Set the flow control mode.
    pub fn set_flow_control(&mut self, flow: FlowControl) {
        self.config.flow_control = flow;
    }

    /// Set the full serial configuration.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if data_bits is not in
    /// the range 5-8.
    pub fn set_config(&mut self, config: SerialConfig) -> Result<()> {
        if config.data_bits < 5 || config.data_bits > 8 {
            return Err(Error::InvalidArgument);
        }
        self.config = config;
        Ok(())
    }

    /// Return the current serial configuration.
    pub fn config(&self) -> &SerialConfig {
        &self.config
    }

    /// Return the current modem signal state.
    pub fn modem_signals(&self) -> &ModemSignals {
        &self.modem
    }

    /// Return the port state.
    pub fn state(&self) -> PortState {
        self.state
    }

    /// Return the chip type.
    pub fn chip_type(&self) -> ChipType {
        self.chip
    }

    /// Return the number of bytes available to read.
    pub fn rx_available(&self) -> usize {
        self.rx_buf.available()
    }

    /// Return the TX buffer free space.
    pub fn tx_free_space(&self) -> usize {
        self.tx_buf.free_space()
    }

    /// Return total bytes transmitted.
    pub fn tx_count(&self) -> u64 {
        self.tx_count
    }

    /// Return total bytes received.
    pub fn rx_count(&self) -> u64 {
        self.rx_count
    }

    /// Return the error count.
    pub fn error_count(&self) -> u32 {
        self.error_count
    }

    /// Return the USB device address.
    pub fn usb_address(&self) -> u8 {
        self.usb_address
    }
}

impl Default for UsbSerial {
    fn default() -> Self {
        Self::new()
    }
}

// ── USB Serial Registry ─────────────────────────────────────────

/// Registry of USB serial devices.
pub struct UsbSerialRegistry {
    /// Registered devices.
    devices: [Option<UsbSerial>; MAX_USB_SERIAL_DEVICES],
    /// Number of registered devices.
    count: usize,
}

impl UsbSerialRegistry {
    /// Create an empty registry.
    pub const fn new() -> Self {
        const NONE: Option<UsbSerial> = None;
        Self {
            devices: [NONE; MAX_USB_SERIAL_DEVICES],
            count: 0,
        }
    }

    /// Register a USB serial device.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the registry is full.
    pub fn register(&mut self, device: UsbSerial) -> Result<usize> {
        if self.count >= MAX_USB_SERIAL_DEVICES {
            return Err(Error::OutOfMemory);
        }
        let idx = self.count;
        self.devices[idx] = Some(device);
        self.count += 1;
        Ok(idx)
    }

    /// Return a reference to a device by index.
    pub fn get(&self, index: usize) -> Option<&UsbSerial> {
        if index < self.count {
            self.devices[index].as_ref()
        } else {
            None
        }
    }

    /// Return a mutable reference to a device by index.
    pub fn get_mut(&mut self, index: usize) -> Option<&mut UsbSerial> {
        if index < self.count {
            self.devices[index].as_mut()
        } else {
            None
        }
    }

    /// Return the number of registered devices.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Return whether the registry is empty.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
}

impl Default for UsbSerialRegistry {
    fn default() -> Self {
        Self::new()
    }
}
