// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! USB CDC ACM (Abstract Control Model) serial driver.
//!
//! Implements the USB Communications Device Class (CDC) Abstract Control
//! Model (ACM) for serial port emulation. CDC ACM is the class used by
//! USB-to-serial adapters, modems, and virtual serial ports on embedded
//! devices.
//!
//! # USB Interface Layout
//!
//! A CDC ACM function uses two USB interfaces:
//! - **Control Interface** (CDC class 0x02, subclass 0x02, protocol 0x01):
//!   - One interrupt-IN endpoint (`notifep`) for device status notifications
//!   - CDC class-specific descriptors (Header, Call Management, ACM, Union)
//! - **Data Interface** (CDC Data class 0x0A, subclass 0x00, protocol 0x00):
//!   - One bulk-IN endpoint (`datain`) — device → host
//!   - One bulk-OUT endpoint (`dataout`) — host → device
//!
//! # Supported CDC Requests (§6.2 of USB CDC 1.2)
//!
//! - `SET_LINE_CODING` (0x20) — baud rate, parity, stop bits, data bits
//! - `GET_LINE_CODING` (0x21) — read back current line coding
//! - `SET_CONTROL_LINE_STATE` (0x22) — DTR / RTS signals
//! - `SEND_BREAK` (0x23) — transmit RS-232 break condition
//!
//! # Architecture
//!
//! - [`LineCoding`] — serial line parameters (baud, format, parity, data bits)
//! - [`ControlLineState`] — DTR/RTS signal state
//! - [`AcmNotification`] — async notifications from device (SERIAL_STATE, …)
//! - [`CdcAcmDevice`] — a single CDC ACM interface pair
//! - [`CdcAcmRegistry`] — tracks up to [`MAX_CDC_ACM_DEVICES`] devices
//!
//! Reference: USB CDC 1.2 (PSTN120.pdf), USB 2.0 Specification §9.

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// USB CDC class / subclass / protocol codes
// ---------------------------------------------------------------------------

/// USB interface class for CDC Communications interfaces.
pub const CDC_COMM_CLASS: u8 = 0x02;

/// USB interface subclass for Abstract Control Model.
pub const CDC_ACM_SUBCLASS: u8 = 0x02;

/// USB interface protocol: AT commands (V.250).
pub const CDC_PROTOCOL_AT: u8 = 0x01;

/// USB interface class for CDC Data interfaces.
pub const CDC_DATA_CLASS: u8 = 0x0A;

// ---------------------------------------------------------------------------
// CDC class-specific descriptor types (§5.2.3)
// ---------------------------------------------------------------------------

/// CDC class-specific descriptor type byte.
pub const CDC_CS_INTERFACE: u8 = 0x24;

/// Header Functional Descriptor subtype.
pub const CDC_SUBTYPE_HEADER: u8 = 0x00;

/// Call Management Functional Descriptor subtype.
pub const CDC_SUBTYPE_CALL_MGMT: u8 = 0x01;

/// Abstract Control Management Functional Descriptor subtype.
pub const CDC_SUBTYPE_ACM: u8 = 0x02;

/// Union Functional Descriptor subtype.
pub const CDC_SUBTYPE_UNION: u8 = 0x06;

// ---------------------------------------------------------------------------
// CDC class requests (§6.2)
// ---------------------------------------------------------------------------

/// SET_LINE_CODING request code.
pub const REQ_SET_LINE_CODING: u8 = 0x20;

/// GET_LINE_CODING request code.
pub const REQ_GET_LINE_CODING: u8 = 0x21;

/// SET_CONTROL_LINE_STATE request code.
pub const REQ_SET_CONTROL_LINE_STATE: u8 = 0x22;

/// SEND_BREAK request code.
pub const REQ_SEND_BREAK: u8 = 0x23;

// ---------------------------------------------------------------------------
// CDC notification codes (§6.3)
// ---------------------------------------------------------------------------

/// NETWORK_CONNECTION notification code.
pub const NOTIF_NETWORK_CONNECTION: u8 = 0x00;

/// RESPONSE_AVAILABLE notification code.
pub const NOTIF_RESPONSE_AVAILABLE: u8 = 0x01;

/// SERIAL_STATE notification code.
pub const NOTIF_SERIAL_STATE: u8 = 0x20;

// ---------------------------------------------------------------------------
// SERIAL_STATE bits (§6.3.5)
// ---------------------------------------------------------------------------

/// DCD (Data Carrier Detect) signal active.
pub const SERIAL_STATE_DCD: u16 = 1 << 0;

/// DSR (Data Set Ready) signal active.
pub const SERIAL_STATE_DSR: u16 = 1 << 1;

/// Break signal received.
pub const SERIAL_STATE_BREAK: u16 = 1 << 2;

/// Ring signal (RI) active.
pub const SERIAL_STATE_RING: u16 = 1 << 3;

/// Framing error occurred.
pub const SERIAL_STATE_FRAMING: u16 = 1 << 4;

/// Parity error occurred.
pub const SERIAL_STATE_PARITY: u16 = 1 << 5;

/// Data overrun error occurred.
pub const SERIAL_STATE_OVERRUN: u16 = 1 << 6;

// ---------------------------------------------------------------------------
// ControlLineState bits (§6.2.14)
// ---------------------------------------------------------------------------

/// Data Terminal Ready (DTR) — activate carrier.
pub const CTRL_DTR: u16 = 1 << 0;

/// Request To Send (RTS) — activate half-duplex carrier.
pub const CTRL_RTS: u16 = 1 << 1;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum number of CDC ACM devices tracked simultaneously.
pub const MAX_CDC_ACM_DEVICES: usize = 8;

/// Size of the bulk RX ring buffer in bytes.
pub const RX_BUFFER_SIZE: usize = 4096;

/// Size of the bulk TX ring buffer in bytes.
pub const TX_BUFFER_SIZE: usize = 4096;

/// Maximum notification payload size (header 8 bytes + 2 bytes data).
const NOTIF_MAX_SIZE: usize = 10;

// ---------------------------------------------------------------------------
// LineCoding (§6.3.11 / Table 17)
// ---------------------------------------------------------------------------

/// Number of stop bits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u8)]
pub enum StopBits {
    /// 1 stop bit.
    #[default]
    One = 0,
    /// 1.5 stop bits.
    OnePointFive = 1,
    /// 2 stop bits.
    Two = 2,
}

/// Parity type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u8)]
pub enum Parity {
    /// No parity.
    #[default]
    None = 0,
    /// Odd parity.
    Odd = 1,
    /// Even parity.
    Even = 2,
    /// Mark parity.
    Mark = 3,
    /// Space parity.
    Space = 4,
}

/// CDC ACM line coding parameters.
///
/// Transferred as a 7-byte little-endian structure via SET_LINE_CODING and
/// returned by GET_LINE_CODING (see CDC spec Table 17).
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct LineCoding {
    /// Data terminal rate in bits per second (baud rate).
    pub baud_rate: u32,
    /// Number of stop bits.
    pub stop_bits: StopBits,
    /// Parity type.
    pub parity: Parity,
    /// Number of data bits (5, 6, 7, 8, or 16).
    pub data_bits: u8,
}

impl LineCoding {
    /// Create a standard 115200 8-N-1 line coding.
    pub const fn default_115200() -> Self {
        Self {
            baud_rate: 115_200,
            stop_bits: StopBits::One,
            parity: Parity::None,
            data_bits: 8,
        }
    }

    /// Serialize to the 7-byte wire format.
    pub fn to_bytes(self) -> [u8; 7] {
        let b = self.baud_rate.to_le_bytes();
        [
            b[0],
            b[1],
            b[2],
            b[3],
            self.stop_bits as u8,
            self.parity as u8,
            self.data_bits,
        ]
    }

    /// Deserialize from the 7-byte wire format.
    ///
    /// Returns `None` if the stop_bits or parity values are unrecognised.
    pub fn from_bytes(bytes: &[u8; 7]) -> Option<Self> {
        let baud_rate = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        let stop_bits = match bytes[4] {
            0 => StopBits::One,
            1 => StopBits::OnePointFive,
            2 => StopBits::Two,
            _ => return None,
        };
        let parity = match bytes[5] {
            0 => Parity::None,
            1 => Parity::Odd,
            2 => Parity::Even,
            3 => Parity::Mark,
            4 => Parity::Space,
            _ => return None,
        };
        Some(Self {
            baud_rate,
            stop_bits,
            parity,
            data_bits: bytes[6],
        })
    }
}

impl Default for LineCoding {
    fn default() -> Self {
        Self::default_115200()
    }
}

// ---------------------------------------------------------------------------
// ControlLineState
// ---------------------------------------------------------------------------

/// CDC ACM control line state (DTR / RTS).
#[derive(Debug, Clone, Copy, Default)]
pub struct ControlLineState {
    /// Raw bitmask value sent via SET_CONTROL_LINE_STATE.
    pub bits: u16,
}

impl ControlLineState {
    /// Returns `true` if DTR (Data Terminal Ready) is asserted.
    pub fn dtr(&self) -> bool {
        self.bits & CTRL_DTR != 0
    }

    /// Returns `true` if RTS (Request To Send) is asserted.
    pub fn rts(&self) -> bool {
        self.bits & CTRL_RTS != 0
    }

    /// Set DTR.
    pub fn set_dtr(&mut self, v: bool) {
        if v {
            self.bits |= CTRL_DTR;
        } else {
            self.bits &= !CTRL_DTR;
        }
    }

    /// Set RTS.
    pub fn set_rts(&mut self, v: bool) {
        if v {
            self.bits |= CTRL_RTS;
        } else {
            self.bits &= !CTRL_RTS;
        }
    }
}

// ---------------------------------------------------------------------------
// AcmNotification
// ---------------------------------------------------------------------------

/// Asynchronous notification received from the device via the interrupt-IN
/// endpoint.
#[derive(Debug, Clone, Copy)]
pub enum AcmNotification {
    /// SERIAL_STATE notification: modem-line state change.
    SerialState {
        /// Serial state bitmap (DCD, DSR, BREAK, RING, framing, parity, overrun).
        state: u16,
    },
    /// RESPONSE_AVAILABLE: device has a response ready (modem use).
    ResponseAvailable,
    /// Unknown or unhandled notification type.
    Unknown {
        /// Notification code byte.
        code: u8,
    },
}

impl AcmNotification {
    /// Parse a notification from the raw interrupt-IN payload.
    ///
    /// The CDC notification header is 8 bytes:
    /// `[bmRequestType, bNotificationCode, wValue(2), wIndex(2), wLength(2)]`
    /// followed by `wLength` bytes of data.
    pub fn parse(buf: &[u8]) -> Option<Self> {
        if buf.len() < 8 {
            return None;
        }
        let code = buf[1];
        let data_len = u16::from_le_bytes([buf[6], buf[7]]) as usize;
        match code {
            NOTIF_SERIAL_STATE => {
                if buf.len() < 8 + data_len || data_len < 2 {
                    return None;
                }
                let state = u16::from_le_bytes([buf[8], buf[9]]);
                Some(AcmNotification::SerialState { state })
            }
            NOTIF_RESPONSE_AVAILABLE => Some(AcmNotification::ResponseAvailable),
            _ => Some(AcmNotification::Unknown { code }),
        }
    }
}

// ---------------------------------------------------------------------------
// RingBuffer
// ---------------------------------------------------------------------------

/// A simple fixed-size byte ring buffer used for RX and TX data.
pub struct RingBuffer<const N: usize> {
    buf: [u8; N],
    read: usize,
    write: usize,
    full: bool,
}

impl<const N: usize> RingBuffer<N> {
    /// Create an empty ring buffer.
    pub const fn new() -> Self {
        Self {
            buf: [0u8; N],
            read: 0,
            write: 0,
            full: false,
        }
    }

    /// Number of bytes available to read.
    pub fn len(&self) -> usize {
        if self.full {
            N
        } else if self.write >= self.read {
            self.write - self.read
        } else {
            N - self.read + self.write
        }
    }

    /// Returns `true` if no bytes are available.
    pub fn is_empty(&self) -> bool {
        !self.full && self.read == self.write
    }

    /// Returns `true` if the buffer is full.
    pub fn is_full(&self) -> bool {
        self.full
    }

    /// Push a single byte, returning `Err(Error::OutOfMemory)` if full.
    pub fn push(&mut self, byte: u8) -> Result<()> {
        if self.full {
            return Err(Error::OutOfMemory);
        }
        self.buf[self.write] = byte;
        self.write = (self.write + 1) % N;
        if self.write == self.read {
            self.full = true;
        }
        Ok(())
    }

    /// Push `src` bytes into the buffer.
    ///
    /// Returns the number of bytes actually written (may be less than `src.len()`
    /// if the buffer fills up).
    pub fn push_slice(&mut self, src: &[u8]) -> usize {
        let mut count = 0;
        for &b in src {
            if self.push(b).is_err() {
                break;
            }
            count += 1;
        }
        count
    }

    /// Pop a single byte, returning `None` if empty.
    pub fn pop(&mut self) -> Option<u8> {
        if self.is_empty() {
            return None;
        }
        let byte = self.buf[self.read];
        self.read = (self.read + 1) % N;
        self.full = false;
        Some(byte)
    }

    /// Pop up to `dst.len()` bytes into `dst`.
    ///
    /// Returns the number of bytes actually read.
    pub fn pop_slice(&mut self, dst: &mut [u8]) -> usize {
        let mut count = 0;
        for slot in dst.iter_mut() {
            match self.pop() {
                Some(b) => {
                    *slot = b;
                    count += 1;
                }
                None => break,
            }
        }
        count
    }

    /// Discard all buffered data.
    pub fn clear(&mut self) {
        self.read = 0;
        self.write = 0;
        self.full = false;
    }
}

impl<const N: usize> Default for RingBuffer<N> {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// USB endpoint address helpers
// ---------------------------------------------------------------------------

/// Endpoint direction: IN (device to host), encoded in address bit 7.
pub const EP_DIR_IN: u8 = 0x80;

/// Endpoint direction: OUT (host to device).
pub const EP_DIR_OUT: u8 = 0x00;

/// USB endpoint descriptor.
#[derive(Debug, Clone, Copy, Default)]
pub struct EndpointDesc {
    /// Endpoint address (number | direction bit).
    pub address: u8,
    /// Endpoint attributes (transfer type).
    pub attributes: u8,
    /// Maximum packet size.
    pub max_packet_size: u16,
    /// Polling interval for interrupt endpoints (ms).
    pub interval: u8,
}

impl EndpointDesc {
    /// Returns the endpoint number (address & 0x0F).
    pub fn number(&self) -> u8 {
        self.address & 0x0F
    }

    /// Returns `true` if this is an IN (device→host) endpoint.
    pub fn is_in(&self) -> bool {
        self.address & EP_DIR_IN != 0
    }

    /// Returns the transfer type (bits 1:0 of attributes).
    pub fn transfer_type(&self) -> u8 {
        self.attributes & 0x03
    }
}

// ---------------------------------------------------------------------------
// CdcAcmDevice
// ---------------------------------------------------------------------------

/// State of a single CDC ACM device instance.
pub struct CdcAcmDevice {
    /// USB device address assigned by the host controller.
    pub device_addr: u8,
    /// Control interface number.
    pub ctrl_iface: u8,
    /// Data interface number.
    pub data_iface: u8,
    /// Interrupt-IN endpoint (notifications from device).
    pub notif_ep: EndpointDesc,
    /// Bulk-IN endpoint (data from device to host).
    pub bulk_in_ep: EndpointDesc,
    /// Bulk-OUT endpoint (data from host to device).
    pub bulk_out_ep: EndpointDesc,
    /// Current line coding.
    pub line_coding: LineCoding,
    /// Current control line state.
    pub ctrl_line: ControlLineState,
    /// Last serial state received from the device.
    pub serial_state: u16,
    /// Whether the device is open (DTR asserted).
    pub open: bool,
    /// Received data ring buffer.
    rx: RingBuffer<RX_BUFFER_SIZE>,
    /// Transmit data ring buffer.
    tx: RingBuffer<TX_BUFFER_SIZE>,
    /// Pending notification buffer.
    notif_buf: [u8; NOTIF_MAX_SIZE],
    /// Valid bytes in `notif_buf`.
    notif_len: usize,
}

impl CdcAcmDevice {
    /// Create a new CDC ACM device entry.
    pub fn new(
        device_addr: u8,
        ctrl_iface: u8,
        data_iface: u8,
        notif_ep: EndpointDesc,
        bulk_in_ep: EndpointDesc,
        bulk_out_ep: EndpointDesc,
    ) -> Self {
        Self {
            device_addr,
            ctrl_iface,
            data_iface,
            notif_ep,
            bulk_in_ep,
            bulk_out_ep,
            line_coding: LineCoding::default_115200(),
            ctrl_line: ControlLineState::default(),
            serial_state: 0,
            open: false,
            rx: RingBuffer::new(),
            tx: RingBuffer::new(),
            notif_buf: [0u8; NOTIF_MAX_SIZE],
            notif_len: 0,
        }
    }

    /// Build a SET_LINE_CODING control request payload.
    ///
    /// The host must send this as a class-specific OUT control transfer to
    /// the control interface.
    pub fn set_line_coding_payload(&self) -> [u8; 7] {
        self.line_coding.to_bytes()
    }

    /// Apply a new line coding received via a GET_LINE_CODING response.
    ///
    /// Returns [`Error::InvalidArgument`] if the 7-byte payload is invalid.
    pub fn apply_line_coding(&mut self, bytes: &[u8; 7]) -> Result<()> {
        let lc = LineCoding::from_bytes(bytes).ok_or(Error::InvalidArgument)?;
        self.line_coding = lc;
        Ok(())
    }

    /// Build the wValue for a SET_CONTROL_LINE_STATE request.
    pub fn control_line_state_value(&self) -> u16 {
        self.ctrl_line.bits
    }

    /// Open the serial port: asserts DTR and RTS.
    pub fn open(&mut self) {
        self.ctrl_line.set_dtr(true);
        self.ctrl_line.set_rts(true);
        self.open = true;
    }

    /// Close the serial port: de-asserts DTR and RTS.
    pub fn close(&mut self) {
        self.ctrl_line.set_dtr(false);
        self.ctrl_line.set_rts(false);
        self.open = false;
    }

    /// Feed received bytes from a bulk-IN transfer into the RX buffer.
    ///
    /// Returns the number of bytes accepted (may be less than `data.len()`
    /// if the RX buffer is full).
    pub fn receive(&mut self, data: &[u8]) -> usize {
        self.rx.push_slice(data)
    }

    /// Read up to `dst.len()` bytes from the RX buffer.
    ///
    /// Returns the number of bytes read.
    pub fn read(&mut self, dst: &mut [u8]) -> usize {
        self.rx.pop_slice(dst)
    }

    /// Queue up to `src.len()` bytes for TX.
    ///
    /// Returns the number of bytes queued (may be less than `src.len()`
    /// if the TX buffer is full).
    pub fn write(&mut self, src: &[u8]) -> usize {
        self.tx.push_slice(src)
    }

    /// Drain up to `dst.len()` bytes from the TX buffer for bulk-OUT transfer.
    ///
    /// Returns the number of bytes drained.
    pub fn drain_tx(&mut self, dst: &mut [u8]) -> usize {
        self.tx.pop_slice(dst)
    }

    /// Process a raw notification buffer received from the interrupt-IN endpoint.
    ///
    /// Parses the CDC notification and updates internal state accordingly.
    /// Returns the decoded [`AcmNotification`], or `None` if the data is
    /// too short or malformed.
    pub fn process_notification(&mut self, data: &[u8]) -> Option<AcmNotification> {
        let copy_len = data.len().min(NOTIF_MAX_SIZE);
        self.notif_buf[..copy_len].copy_from_slice(&data[..copy_len]);
        self.notif_len = copy_len;

        let notif = AcmNotification::parse(&self.notif_buf[..self.notif_len])?;
        if let AcmNotification::SerialState { state } = notif {
            self.serial_state = state;
        }
        Some(notif)
    }

    /// Returns the number of bytes available to read.
    pub fn rx_available(&self) -> usize {
        self.rx.len()
    }

    /// Returns the number of bytes queued for TX.
    pub fn tx_pending(&self) -> usize {
        self.tx.len()
    }

    /// Returns `true` if the device reports DCD asserted.
    pub fn carrier_detected(&self) -> bool {
        self.serial_state & SERIAL_STATE_DCD != 0
    }

    /// Returns `true` if the device reports DSR asserted.
    pub fn data_set_ready(&self) -> bool {
        self.serial_state & SERIAL_STATE_DSR != 0
    }

    /// Change baud rate only (keeps current stop bits / parity / data bits).
    pub fn set_baud_rate(&mut self, baud: u32) {
        self.line_coding.baud_rate = baud;
    }
}

impl core::fmt::Debug for CdcAcmDevice {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("CdcAcmDevice")
            .field("addr", &self.device_addr)
            .field("open", &self.open)
            .field("baud", &self.line_coding.baud_rate)
            .field("rx_avail", &self.rx.len())
            .field("tx_pending", &self.tx.len())
            .finish()
    }
}

// ---------------------------------------------------------------------------
// CdcAcmRegistry
// ---------------------------------------------------------------------------

/// Registry tracking up to [`MAX_CDC_ACM_DEVICES`] CDC ACM devices.
pub struct CdcAcmRegistry {
    /// Device slots; `None` = empty.
    devices: [Option<CdcAcmDevice>; MAX_CDC_ACM_DEVICES],
    /// Number of registered devices.
    count: usize,
}

impl Default for CdcAcmRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl CdcAcmRegistry {
    /// Create an empty registry.
    pub const fn new() -> Self {
        Self {
            devices: [const { None }; MAX_CDC_ACM_DEVICES],
            count: 0,
        }
    }

    /// Register a new CDC ACM device.
    ///
    /// Returns the slot index on success, or [`Error::OutOfMemory`] if the
    /// registry is full.
    pub fn register(&mut self, device: CdcAcmDevice) -> Result<usize> {
        for (i, slot) in self.devices.iter_mut().enumerate() {
            if slot.is_none() {
                *slot = Some(device);
                self.count += 1;
                return Ok(i);
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Unregister the device at `slot`.
    ///
    /// Returns [`Error::NotFound`] if the slot is empty.
    pub fn unregister(&mut self, slot: usize) -> Result<()> {
        if slot >= MAX_CDC_ACM_DEVICES || self.devices[slot].is_none() {
            return Err(Error::NotFound);
        }
        self.devices[slot] = None;
        self.count -= 1;
        Ok(())
    }

    /// Get a shared reference to the device at `slot`.
    pub fn get(&self, slot: usize) -> Result<&CdcAcmDevice> {
        if slot < MAX_CDC_ACM_DEVICES {
            self.devices[slot].as_ref().ok_or(Error::NotFound)
        } else {
            Err(Error::NotFound)
        }
    }

    /// Get an exclusive reference to the device at `slot`.
    pub fn get_mut(&mut self, slot: usize) -> Result<&mut CdcAcmDevice> {
        if slot < MAX_CDC_ACM_DEVICES {
            self.devices[slot].as_mut().ok_or(Error::NotFound)
        } else {
            Err(Error::NotFound)
        }
    }

    /// Find a device by USB device address.
    pub fn find_by_addr(&self, device_addr: u8) -> Option<usize> {
        self.devices
            .iter()
            .position(|s| s.as_ref().map_or(false, |d| d.device_addr == device_addr))
    }

    /// Number of registered devices.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Returns `true` if no devices are registered.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
}
