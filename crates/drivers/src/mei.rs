// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Intel Management Engine Interface (MEI/HECI) driver.
//!
//! Provides a host interface to the Intel ME firmware via the Host
//! Embedded Controller Interface (HECI). Supports client enumeration,
//! flow control, message passing, and bus operations for both fixed
//! and dynamic ME clients.
//!
//! # Architecture
//!
//! - [`MeiDevice`] — main device abstraction with MMIO registers
//! - [`MeiClient`] — a ME client (fixed or dynamic)
//! - [`MeiMessage`] — HECI message header and payload
//! - [`MeiFlowControl`] — flow control credit tracking
//! - [`MeiDeviceRegistry`] — system-wide MEI device registry
//!
//! Reference: Intel Management Engine Interface specification.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Maximum HECI message payload size.
const MAX_MESSAGE_SIZE: usize = 4096;

/// Maximum number of ME clients per device.
const MAX_CLIENTS: usize = 32;

/// Maximum number of MEI devices in the registry.
const MAX_MEI_DEVICES: usize = 4;

/// Circular buffer size (entries).
const CB_DEPTH: usize = 128;

/// HECI message header size (4 bytes).
const HECI_HEADER_SIZE: usize = 4;

/// Timeout for MEI operations (polling iterations).
const MEI_TIMEOUT: u32 = 100_000;

// -------------------------------------------------------------------
// MMIO Register Offsets (HECI)
// -------------------------------------------------------------------

/// Host-to-ME Circular Buffer Write Pointer.
const REG_H_CB_WW: u32 = 0x00;

/// Host Status Register.
const REG_H_CSR: u32 = 0x04;

/// ME-to-Host Circular Buffer Read Pointer.
const _REG_ME_CB_RW: u32 = 0x08;

/// ME Control/Status Register.
const REG_ME_CSR: u32 = 0x0C;

/// Host-to-ME Interrupt Enable.
const _REG_H_IGR: u32 = 0x10;

/// Host-to-ME Interrupt Status.
const _REG_H_IS: u32 = 0x14;

// -------------------------------------------------------------------
// Host CSR bits
// -------------------------------------------------------------------

/// H_CSR: Host interrupt enable.
const H_CSR_IE: u32 = 1 << 0;

/// H_CSR: Host interrupt status.
const H_CSR_IS: u32 = 1 << 1;

/// H_CSR: Host interrupt generate.
const H_CSR_IG: u32 = 1 << 2;

/// H_CSR: Host ready.
const H_CSR_RDY: u32 = 1 << 3;

/// H_CSR: Host reset.
const H_CSR_RST: u32 = 1 << 4;

/// H_CSR: Circular buffer read pointer (bits 15:8).
const H_CSR_CBRP_SHIFT: u32 = 8;

/// H_CSR: Circular buffer read pointer mask.
const H_CSR_CBRP_MASK: u32 = 0xFF << H_CSR_CBRP_SHIFT;

/// H_CSR: Circular buffer write pointer (bits 23:16).
const H_CSR_CBWP_SHIFT: u32 = 16;

/// H_CSR: Circular buffer write pointer mask.
const H_CSR_CBWP_MASK: u32 = 0xFF << H_CSR_CBWP_SHIFT;

/// H_CSR: Circular buffer depth (bits 31:24).
const H_CSR_CBD_SHIFT: u32 = 24;

/// H_CSR: Circular buffer depth mask.
const H_CSR_CBD_MASK: u32 = 0xFF << H_CSR_CBD_SHIFT;

// -------------------------------------------------------------------
// ME CSR bits
// -------------------------------------------------------------------

/// ME_CSR: ME interrupt enable.
const _ME_CSR_IE: u32 = 1 << 0;

/// ME_CSR: ME interrupt status.
const ME_CSR_IS: u32 = 1 << 1;

/// ME_CSR: ME interrupt generate.
const _ME_CSR_IG: u32 = 1 << 2;

/// ME_CSR: ME ready.
const ME_CSR_RDY: u32 = 1 << 3;

/// ME_CSR: ME reset.
const _ME_CSR_RST: u32 = 1 << 4;

// -------------------------------------------------------------------
// HECI message header layout
// -------------------------------------------------------------------

/// Message complete flag (bit 31 of header dword).
const HECI_MSG_COMPLETE: u32 = 1 << 31;

// -------------------------------------------------------------------
// ClientType
// -------------------------------------------------------------------

/// Type of ME client.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ClientType {
    /// Fixed address client (well-known ME functionality).
    #[default]
    Fixed,
    /// Dynamic client (discovered at runtime).
    Dynamic,
}

// -------------------------------------------------------------------
// ClientState
// -------------------------------------------------------------------

/// State of a ME client connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ClientState {
    /// Client not connected.
    #[default]
    Disconnected,
    /// Connecting (handshake in progress).
    Connecting,
    /// Connected and ready for messaging.
    Connected,
    /// Disconnecting.
    Disconnecting,
}

// -------------------------------------------------------------------
// MeiUuid
// -------------------------------------------------------------------

/// A 128-bit UUID identifying a ME client.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MeiUuid {
    /// UUID bytes (network byte order).
    pub bytes: [u8; 16],
}

impl Default for MeiUuid {
    fn default() -> Self {
        Self::ZERO
    }
}

impl MeiUuid {
    /// The zero UUID (no client).
    pub const ZERO: Self = Self { bytes: [0u8; 16] };

    /// AMTHI (Active Management Technology Host Interface) client UUID.
    pub const AMTHI: Self = Self {
        bytes: [
            0x12, 0xF8, 0x02, 0x28, 0x61, 0xA4, 0xD4, 0x01, 0xA2, 0x46, 0xA8, 0x40, 0x25, 0x19,
            0x09, 0x0A,
        ],
    };

    /// Watchdog client UUID.
    pub const WATCHDOG: Self = Self {
        bytes: [
            0x05, 0xB7, 0x9A, 0x6F, 0x44, 0x72, 0x86, 0x4F, 0xB4, 0x92, 0x47, 0x6E, 0xAA, 0xC0,
            0x57, 0x10,
        ],
    };

    /// Creates a UUID from raw bytes.
    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self { bytes }
    }

    /// Returns `true` if this is the zero UUID.
    pub fn is_zero(&self) -> bool {
        self.bytes == [0u8; 16]
    }
}

// -------------------------------------------------------------------
// MeiClientProperties
// -------------------------------------------------------------------

/// Properties of a ME client, discovered during enumeration.
pub struct MeiClientProperties {
    /// Protocol name / UUID.
    pub uuid: MeiUuid,
    /// Protocol version.
    pub protocol_version: u8,
    /// Maximum message length this client accepts.
    pub max_msg_length: u32,
    /// Fixed address (0 = dynamic client).
    pub fixed_address: u8,
    /// Maximum number of simultaneous connections.
    pub max_connections: u8,
    /// Single receive buffer flag.
    pub single_recv_buf: bool,
}

impl Default for MeiClientProperties {
    fn default() -> Self {
        Self {
            uuid: MeiUuid::ZERO,
            protocol_version: 0,
            max_msg_length: MAX_MESSAGE_SIZE as u32,
            fixed_address: 0,
            max_connections: 1,
            single_recv_buf: false,
        }
    }
}

// -------------------------------------------------------------------
// MeiClient
// -------------------------------------------------------------------

/// Represents a single ME client (fixed or dynamic).
pub struct MeiClient {
    /// Client address (ME-assigned).
    pub me_addr: u8,
    /// Host address (host-assigned).
    pub host_addr: u8,
    /// Client type.
    pub client_type: ClientType,
    /// Connection state.
    pub state: ClientState,
    /// Client properties.
    pub props: MeiClientProperties,
    /// Flow control credits available.
    pub flow_credits: u32,
    /// Messages sent.
    pub tx_count: u64,
    /// Messages received.
    pub rx_count: u64,
}

impl Default for MeiClient {
    fn default() -> Self {
        Self::new()
    }
}

impl MeiClient {
    /// Creates an empty client.
    pub const fn new() -> Self {
        Self {
            me_addr: 0,
            host_addr: 0,
            client_type: ClientType::Fixed,
            state: ClientState::Disconnected,
            props: MeiClientProperties {
                uuid: MeiUuid::ZERO,
                protocol_version: 0,
                max_msg_length: MAX_MESSAGE_SIZE as u32,
                fixed_address: 0,
                max_connections: 1,
                single_recv_buf: false,
            },
            flow_credits: 0,
            tx_count: 0,
            rx_count: 0,
        }
    }

    /// Returns `true` if this client slot is unused.
    pub fn is_empty(&self) -> bool {
        self.props.uuid.is_zero() && self.me_addr == 0
    }

    /// Connects this client.
    pub fn connect(&mut self) -> Result<()> {
        if self.state != ClientState::Disconnected {
            return Err(Error::Busy);
        }
        self.state = ClientState::Connecting;
        Ok(())
    }

    /// Marks the client as connected with initial flow credits.
    pub fn connected(&mut self, credits: u32) {
        self.state = ClientState::Connected;
        self.flow_credits = credits;
    }

    /// Disconnects this client.
    pub fn disconnect(&mut self) {
        self.state = ClientState::Disconnected;
        self.flow_credits = 0;
    }

    /// Consumes a flow control credit for sending.
    pub fn consume_credit(&mut self) -> Result<()> {
        if self.flow_credits == 0 {
            return Err(Error::WouldBlock);
        }
        self.flow_credits -= 1;
        Ok(())
    }

    /// Adds flow control credits (received from ME).
    pub fn add_credits(&mut self, credits: u32) {
        self.flow_credits = self.flow_credits.saturating_add(credits);
    }
}

// -------------------------------------------------------------------
// MeiFlowControl
// -------------------------------------------------------------------

/// Flow control message structure.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct MeiFlowControl {
    /// Host address.
    pub host_addr: u8,
    /// ME address.
    pub me_addr: u8,
    /// Reserved.
    pub _reserved: u16,
}

impl MeiFlowControl {
    /// Creates a flow control message for the given addresses.
    pub const fn new(host_addr: u8, me_addr: u8) -> Self {
        Self {
            host_addr,
            me_addr,
            _reserved: 0,
        }
    }
}

// -------------------------------------------------------------------
// HeciMessageHeader
// -------------------------------------------------------------------

/// HECI message header (4 bytes, packed into a u32).
///
/// Layout:
/// - bits [7:0]   — ME address
/// - bits [15:8]  — Host address
/// - bits [24:16] — Length (in bytes)
/// - bit  [31]    — Message complete flag
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct HeciMessageHeader {
    /// Raw header dword.
    pub raw: u32,
}

impl HeciMessageHeader {
    /// Creates a new header.
    pub fn new(me_addr: u8, host_addr: u8, length: u16, complete: bool) -> Self {
        let mut raw = (me_addr as u32) | ((host_addr as u32) << 8) | ((length as u32) << 16);
        if complete {
            raw |= HECI_MSG_COMPLETE;
        }
        Self { raw }
    }

    /// Returns the ME address.
    pub fn me_addr(&self) -> u8 {
        (self.raw & 0xFF) as u8
    }

    /// Returns the host address.
    pub fn host_addr(&self) -> u8 {
        ((self.raw >> 8) & 0xFF) as u8
    }

    /// Returns the payload length.
    pub fn length(&self) -> u16 {
        ((self.raw >> 16) & 0x1FF) as u16
    }

    /// Returns `true` if the message is complete.
    pub fn is_complete(&self) -> bool {
        self.raw & HECI_MSG_COMPLETE != 0
    }
}

// -------------------------------------------------------------------
// MeiMessage
// -------------------------------------------------------------------

/// A complete HECI message with header and payload.
pub struct MeiMessage {
    /// Message header.
    pub header: HeciMessageHeader,
    /// Payload data.
    pub data: [u8; MAX_MESSAGE_SIZE],
    /// Payload length.
    pub data_len: usize,
}

impl Default for MeiMessage {
    fn default() -> Self {
        Self::new()
    }
}

impl MeiMessage {
    /// Creates an empty message.
    pub const fn new() -> Self {
        Self {
            header: HeciMessageHeader { raw: 0 },
            data: [0u8; MAX_MESSAGE_SIZE],
            data_len: 0,
        }
    }

    /// Creates a message with the given addresses and payload.
    pub fn create(me_addr: u8, host_addr: u8, payload: &[u8]) -> Result<Self> {
        if payload.len() > MAX_MESSAGE_SIZE {
            return Err(Error::InvalidArgument);
        }
        let mut msg = Self::new();
        msg.header = HeciMessageHeader::new(me_addr, host_addr, payload.len() as u16, true);
        msg.data[..payload.len()].copy_from_slice(payload);
        msg.data_len = payload.len();
        Ok(msg)
    }

    /// Returns the payload as a slice.
    pub fn payload(&self) -> &[u8] {
        &self.data[..self.data_len]
    }
}

// -------------------------------------------------------------------
// BusMessageType
// -------------------------------------------------------------------

/// MEI bus message types (host bus commands).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum BusMessageType {
    /// Host version request.
    #[default]
    HostVersionReq,
    /// Host version response.
    HostVersionResp,
    /// Host stop request.
    HostStopReq,
    /// Host stop response.
    HostStopResp,
    /// ME stop request.
    MeStopReq,
    /// Host enumeration request.
    HostEnumReq,
    /// Host enumeration response.
    HostEnumResp,
    /// Host client properties request.
    HostClientPropReq,
    /// Host client properties response.
    HostClientPropResp,
    /// Client connect request.
    ClientConnectReq,
    /// Client connect response.
    ClientConnectResp,
    /// Client disconnect request.
    ClientDisconnectReq,
    /// Client disconnect response.
    ClientDisconnectResp,
    /// Flow control.
    FlowControl,
}

impl BusMessageType {
    /// Returns the wire command byte.
    pub fn to_byte(self) -> u8 {
        match self {
            Self::HostVersionReq => 0x01,
            Self::HostVersionResp => 0x02,
            Self::HostStopReq => 0x03,
            Self::HostStopResp => 0x04,
            Self::MeStopReq => 0x05,
            Self::HostEnumReq => 0x06,
            Self::HostEnumResp => 0x07,
            Self::HostClientPropReq => 0x08,
            Self::HostClientPropResp => 0x09,
            Self::ClientConnectReq => 0x0A,
            Self::ClientConnectResp => 0x0B,
            Self::ClientDisconnectReq => 0x0C,
            Self::ClientDisconnectResp => 0x0D,
            Self::FlowControl => 0x0E,
        }
    }
}

// -------------------------------------------------------------------
// DeviceState
// -------------------------------------------------------------------

/// MEI device lifecycle state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DeviceState {
    /// Device not initialized.
    #[default]
    Uninitialized,
    /// Initializing (reset sequence).
    Initializing,
    /// Enumerating ME clients.
    Enumerating,
    /// Ready for operation.
    Ready,
    /// Device in reset.
    Resetting,
    /// Device disabled or power down.
    Disabled,
}

// -------------------------------------------------------------------
// MMIO helpers
// -------------------------------------------------------------------

/// Reads a u32 from MMIO.
///
/// # Safety
///
/// The caller must ensure `addr` points to a valid MMIO register.
#[cfg(target_arch = "x86_64")]
unsafe fn mmio_read32(addr: u64) -> u32 {
    // SAFETY: caller guarantees addr is valid MMIO
    unsafe { core::ptr::read_volatile(addr as *const u32) }
}

/// Writes a u32 to MMIO.
///
/// # Safety
///
/// The caller must ensure `addr` points to a valid MMIO register.
#[cfg(target_arch = "x86_64")]
unsafe fn mmio_write32(addr: u64, val: u32) {
    // SAFETY: caller guarantees addr is valid MMIO
    unsafe { core::ptr::write_volatile(addr as *mut u32, val) }
}

// -------------------------------------------------------------------
// MeiDevice
// -------------------------------------------------------------------

/// Intel MEI (HECI) device abstraction.
///
/// Manages the host-side interface to the Intel Management Engine,
/// including client enumeration, message passing, and flow control.
pub struct MeiDevice {
    /// MMIO base address.
    pub mmio_base: u64,
    /// Device state.
    pub state: DeviceState,
    /// ME firmware version (major).
    pub fw_ver_major: u8,
    /// ME firmware version (minor).
    pub fw_ver_minor: u8,
    /// Host protocol version.
    pub host_version: u8,
    /// Enumerated ME clients.
    clients: [MeiClient; MAX_CLIENTS],
    /// Number of discovered clients.
    client_count: usize,
    /// Circular buffer depth (from H_CSR).
    cb_depth: u8,
    /// Host circular buffer write pointer.
    host_cbwp: u8,
    /// Host circular buffer read pointer.
    host_cbrp: u8,
    /// Next host address to assign.
    next_host_addr: u8,
}

impl MeiDevice {
    /// Creates a new MEI device at the given MMIO base.
    pub fn new(mmio_base: u64) -> Self {
        Self {
            mmio_base,
            state: DeviceState::Uninitialized,
            fw_ver_major: 0,
            fw_ver_minor: 0,
            host_version: 1,
            clients: [const { MeiClient::new() }; MAX_CLIENTS],
            client_count: 0,
            cb_depth: CB_DEPTH as u8,
            host_cbwp: 0,
            host_cbrp: 0,
            next_host_addr: 1,
        }
    }

    /// Returns the MMIO address for a register.
    fn reg_addr(&self, offset: u32) -> u64 {
        self.mmio_base.wrapping_add(offset as u64)
    }

    /// Initializes the MEI device: performs host reset and reads CSR.
    #[cfg(target_arch = "x86_64")]
    pub fn init(&mut self) -> Result<()> {
        self.state = DeviceState::Initializing;

        // Read host CSR to get circular buffer depth
        let h_csr_addr = self.reg_addr(REG_H_CSR);
        // SAFETY: h_csr_addr is a valid MEI MMIO register
        let h_csr = unsafe { mmio_read32(h_csr_addr) };
        self.cb_depth = ((h_csr & H_CSR_CBD_MASK) >> H_CSR_CBD_SHIFT) as u8;
        self.host_cbrp = ((h_csr & H_CSR_CBRP_MASK) >> H_CSR_CBRP_SHIFT) as u8;
        self.host_cbwp = ((h_csr & H_CSR_CBWP_MASK) >> H_CSR_CBWP_SHIFT) as u8;

        // Check ME readiness
        let me_csr_addr = self.reg_addr(REG_ME_CSR);
        // SAFETY: me_csr_addr is a valid MEI MMIO register
        let me_csr = unsafe { mmio_read32(me_csr_addr) };
        if me_csr & ME_CSR_RDY == 0 {
            // ME not ready — perform host reset
            // SAFETY: h_csr_addr is a valid MEI MMIO register
            unsafe { mmio_write32(h_csr_addr, h_csr | H_CSR_RST | H_CSR_IG) };

            // Wait for ME to become ready
            for _ in 0..MEI_TIMEOUT {
                // SAFETY: me_csr_addr is a valid MEI MMIO register
                let val = unsafe { mmio_read32(me_csr_addr) };
                if val & ME_CSR_RDY != 0 {
                    break;
                }
            }

            // Clear reset, set host ready
            // SAFETY: h_csr_addr is a valid MEI MMIO register
            let cur = unsafe { mmio_read32(h_csr_addr) };
            unsafe {
                mmio_write32(
                    h_csr_addr,
                    (cur & !H_CSR_RST) | H_CSR_RDY | H_CSR_IE | H_CSR_IG,
                )
            };
        }

        self.state = DeviceState::Ready;
        Ok(())
    }

    /// Non-x86_64 stub for init.
    #[cfg(not(target_arch = "x86_64"))]
    pub fn init(&mut self) -> Result<()> {
        self.state = DeviceState::Ready;
        Ok(())
    }

    /// Resets the MEI host interface.
    #[cfg(target_arch = "x86_64")]
    pub fn reset(&mut self) -> Result<()> {
        self.state = DeviceState::Resetting;
        let h_csr_addr = self.reg_addr(REG_H_CSR);
        // SAFETY: h_csr_addr is a valid MEI MMIO register
        let h_csr = unsafe { mmio_read32(h_csr_addr) };
        unsafe { mmio_write32(h_csr_addr, h_csr | H_CSR_RST | H_CSR_IG) };

        // Disconnect all clients
        for i in 0..self.client_count {
            self.clients[i].disconnect();
        }

        self.state = DeviceState::Initializing;
        Ok(())
    }

    /// Non-x86_64 stub for reset.
    #[cfg(not(target_arch = "x86_64"))]
    pub fn reset(&mut self) -> Result<()> {
        self.state = DeviceState::Resetting;
        for i in 0..self.client_count {
            self.clients[i].disconnect();
        }
        self.state = DeviceState::Initializing;
        Ok(())
    }

    /// Writes a HECI message to the host circular buffer.
    #[cfg(target_arch = "x86_64")]
    pub fn send_message(&mut self, msg: &MeiMessage) -> Result<()> {
        if self.state != DeviceState::Ready {
            return Err(Error::Busy);
        }

        // Check if host CB has space
        let h_csr_addr = self.reg_addr(REG_H_CSR);
        // SAFETY: h_csr_addr is a valid MEI MMIO register
        let h_csr = unsafe { mmio_read32(h_csr_addr) };
        let wp = ((h_csr & H_CSR_CBWP_MASK) >> H_CSR_CBWP_SHIFT) as u8;
        let rp = ((h_csr & H_CSR_CBRP_MASK) >> H_CSR_CBRP_SHIFT) as u8;
        let depth = ((h_csr & H_CSR_CBD_MASK) >> H_CSR_CBD_SHIFT) as u8;

        // Slots needed: header (1 dword) + ceil(data_len / 4) dwords
        let dwords_needed = 1 + (msg.data_len + 3) / 4;
        let used = wp.wrapping_sub(rp) as usize;
        let free = depth as usize - used;
        if dwords_needed > free {
            return Err(Error::WouldBlock);
        }

        // Write header dword
        let cb_addr = self.reg_addr(REG_H_CB_WW);
        // SAFETY: cb_addr is the HECI write data register
        unsafe { mmio_write32(cb_addr, msg.header.raw) };

        // Write payload dwords
        let mut offset = 0;
        while offset < msg.data_len {
            let mut dword = 0u32;
            for b in 0..4 {
                if offset + b < msg.data_len {
                    dword |= (msg.data[offset + b] as u32) << (b * 8);
                }
            }
            // SAFETY: cb_addr is the HECI write data register
            unsafe { mmio_write32(cb_addr, dword) };
            offset += 4;
        }

        // Set interrupt generate to signal ME
        // SAFETY: h_csr_addr is a valid MEI MMIO register
        let cur = unsafe { mmio_read32(h_csr_addr) };
        // SAFETY: h_csr_addr is a valid MEI MMIO register
        unsafe { mmio_write32(h_csr_addr, cur | H_CSR_IG) };

        Ok(())
    }

    /// Non-x86_64 stub for send_message.
    #[cfg(not(target_arch = "x86_64"))]
    pub fn send_message(&mut self, _msg: &MeiMessage) -> Result<()> {
        if self.state != DeviceState::Ready {
            return Err(Error::Busy);
        }
        Ok(())
    }

    /// Reads a HECI message from the ME circular buffer.
    #[cfg(target_arch = "x86_64")]
    pub fn recv_message(&mut self) -> Result<MeiMessage> {
        if self.state != DeviceState::Ready {
            return Err(Error::Busy);
        }

        // Check ME CSR for data available
        let me_csr_addr = self.reg_addr(REG_ME_CSR);
        // SAFETY: me_csr_addr is a valid MEI MMIO register
        let me_csr = unsafe { mmio_read32(me_csr_addr) };
        if me_csr & ME_CSR_IS == 0 {
            return Err(Error::WouldBlock);
        }

        // Read header dword from ME CB
        let cb_addr = self.reg_addr(_REG_ME_CB_RW);
        // SAFETY: cb_addr is the HECI read data register
        let header_raw = unsafe { mmio_read32(cb_addr) };
        let header = HeciMessageHeader { raw: header_raw };
        let length = header.length() as usize;

        if length > MAX_MESSAGE_SIZE {
            return Err(Error::IoError);
        }

        let mut msg = MeiMessage::new();
        msg.header = header;
        msg.data_len = length;

        // Read payload dwords
        let mut offset = 0;
        while offset < length {
            // SAFETY: cb_addr is the HECI read data register
            let dword = unsafe { mmio_read32(cb_addr) };
            for b in 0..4 {
                if offset + b < length {
                    msg.data[offset + b] = (dword >> (b * 8)) as u8;
                }
            }
            offset += 4;
        }

        // Acknowledge interrupt
        let h_csr_addr = self.reg_addr(REG_H_CSR);
        // SAFETY: h_csr_addr is a valid MEI MMIO register
        let h_csr = unsafe { mmio_read32(h_csr_addr) };
        unsafe { mmio_write32(h_csr_addr, h_csr | H_CSR_IS | H_CSR_IG) };

        Ok(msg)
    }

    /// Non-x86_64 stub for recv_message.
    #[cfg(not(target_arch = "x86_64"))]
    pub fn recv_message(&mut self) -> Result<MeiMessage> {
        if self.state != DeviceState::Ready {
            return Err(Error::Busy);
        }
        Err(Error::WouldBlock)
    }

    /// Enumerates ME clients by sending bus enumeration requests.
    pub fn enumerate_clients(&mut self) -> Result<usize> {
        self.state = DeviceState::Enumerating;
        self.client_count = 0;

        // In a real implementation we would send HostEnumReq and parse
        // HostEnumResp, then query each client's properties. Here we
        // set up the framework structure.

        self.state = DeviceState::Ready;
        Ok(self.client_count)
    }

    /// Registers a ME client discovered during enumeration.
    pub fn register_client(
        &mut self,
        me_addr: u8,
        uuid: MeiUuid,
        max_msg_len: u32,
        client_type: ClientType,
    ) -> Result<usize> {
        if self.client_count >= MAX_CLIENTS {
            return Err(Error::OutOfMemory);
        }
        let idx = self.client_count;
        let host_addr = self.next_host_addr;
        self.next_host_addr = self.next_host_addr.wrapping_add(1);
        if self.next_host_addr == 0 {
            self.next_host_addr = 1;
        }

        self.clients[idx].me_addr = me_addr;
        self.clients[idx].host_addr = host_addr;
        self.clients[idx].client_type = client_type;
        self.clients[idx].props.uuid = uuid;
        self.clients[idx].props.max_msg_length = max_msg_len;
        self.clients[idx].props.fixed_address = if client_type == ClientType::Fixed {
            me_addr
        } else {
            0
        };
        self.client_count += 1;
        Ok(idx)
    }

    /// Connects to a ME client by index.
    pub fn connect_client(&mut self, index: usize) -> Result<()> {
        if index >= self.client_count {
            return Err(Error::NotFound);
        }
        self.clients[index].connect()?;
        // In real code: send ClientConnectReq, wait for ClientConnectResp
        self.clients[index].connected(1); // 1 initial credit
        Ok(())
    }

    /// Disconnects a ME client by index.
    pub fn disconnect_client(&mut self, index: usize) -> Result<()> {
        if index >= self.client_count {
            return Err(Error::NotFound);
        }
        self.clients[index].disconnect();
        Ok(())
    }

    /// Sends a flow control credit to a ME client.
    pub fn send_flow_control(&mut self, index: usize) -> Result<()> {
        if index >= self.client_count {
            return Err(Error::NotFound);
        }
        let me_addr = self.clients[index].me_addr;
        let host_addr = self.clients[index].host_addr;
        let fc = MeiFlowControl::new(host_addr, me_addr);
        let fc_bytes = [fc.host_addr, fc.me_addr, 0, 0];
        let msg = MeiMessage::create(0, 0, &fc_bytes)?;
        self.send_message(&msg)
    }

    /// Sends data to a connected ME client.
    pub fn send_to_client(&mut self, index: usize, data: &[u8]) -> Result<()> {
        if index >= self.client_count {
            return Err(Error::NotFound);
        }
        if self.clients[index].state != ClientState::Connected {
            return Err(Error::InvalidArgument);
        }
        self.clients[index].consume_credit()?;

        let me_addr = self.clients[index].me_addr;
        let host_addr = self.clients[index].host_addr;
        let msg = MeiMessage::create(me_addr, host_addr, data)?;
        self.send_message(&msg)?;
        self.clients[index].tx_count += 1;
        Ok(())
    }

    /// Returns the number of discovered clients.
    pub fn client_count(&self) -> usize {
        self.client_count
    }

    /// Returns a reference to a client by index.
    pub fn get_client(&self, index: usize) -> Option<&MeiClient> {
        if index < self.client_count {
            Some(&self.clients[index])
        } else {
            None
        }
    }

    /// Finds a client by UUID.
    pub fn find_client_by_uuid(&self, uuid: &MeiUuid) -> Option<usize> {
        for i in 0..self.client_count {
            if self.clients[i].props.uuid == *uuid {
                return Some(i);
            }
        }
        None
    }

    /// Returns the current device state.
    pub fn device_state(&self) -> DeviceState {
        self.state
    }

    /// Handles an interrupt from the MEI device.
    #[cfg(target_arch = "x86_64")]
    pub fn handle_interrupt(&mut self) -> Result<u32> {
        let h_csr_addr = self.reg_addr(REG_H_CSR);
        // SAFETY: h_csr_addr is a valid MEI MMIO register
        let h_csr = unsafe { mmio_read32(h_csr_addr) };

        if h_csr & H_CSR_IS == 0 {
            return Ok(0); // Not our interrupt
        }

        // Acknowledge interrupt
        // SAFETY: h_csr_addr is a valid MEI MMIO register
        unsafe { mmio_write32(h_csr_addr, h_csr | H_CSR_IS) };

        Ok(h_csr & H_CSR_IS)
    }

    /// Non-x86_64 stub for handle_interrupt.
    #[cfg(not(target_arch = "x86_64"))]
    pub fn handle_interrupt(&mut self) -> Result<u32> {
        Ok(0)
    }
}

// -------------------------------------------------------------------
// MeiDeviceRegistry
// -------------------------------------------------------------------

/// System-wide registry of MEI devices.
pub struct MeiDeviceRegistry {
    /// Registered device MMIO bases.
    devices: [Option<u64>; MAX_MEI_DEVICES],
    /// Number of registered devices.
    count: usize,
}

impl Default for MeiDeviceRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl MeiDeviceRegistry {
    /// Creates an empty registry.
    pub const fn new() -> Self {
        Self {
            devices: [None; MAX_MEI_DEVICES],
            count: 0,
        }
    }

    /// Registers a MEI device by MMIO base.
    pub fn register(&mut self, mmio_base: u64) -> Result<usize> {
        if self.count >= MAX_MEI_DEVICES {
            return Err(Error::OutOfMemory);
        }
        for i in 0..self.count {
            if self.devices[i] == Some(mmio_base) {
                return Err(Error::AlreadyExists);
            }
        }
        let idx = self.count;
        self.devices[idx] = Some(mmio_base);
        self.count += 1;
        Ok(idx)
    }

    /// Returns the MMIO base at the given index.
    pub fn get(&self, index: usize) -> Option<u64> {
        if index < MAX_MEI_DEVICES {
            self.devices[index]
        } else {
            None
        }
    }

    /// Returns the number of registered devices.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Returns `true` if no devices are registered.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
}
