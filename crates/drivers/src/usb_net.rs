// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! USB CDC ECM/NCM network driver.
//!
//! Implements the USB Communications Device Class (CDC) Ethernet Control
//! Model (ECM, §3.3) and Network Control Model (NCM, §3.8) for USB network
//! adapters. CDC ECM/NCM is the class used by USB Ethernet adapters,
//! tethering on Android/iOS, and many embedded network devices.
//!
//! # USB Interface Layout (ECM/NCM)
//!
//! A CDC ECM/NCM function uses two USB interfaces:
//! - **Control Interface** (CDC class 0x02, ECM subclass 0x06 / NCM subclass 0x0D):
//!   - One interrupt-IN endpoint for network connection / speed change notifications.
//!   - CDC class-specific descriptors (Header, Union, Ethernet Networking).
//! - **Data Interface** (CDC Data class 0x0A, subclass 0x00):
//!   - One bulk-IN endpoint — device → host (receive).
//!   - One bulk-OUT endpoint — host → device (transmit).
//!   - For NCM: alternate setting 0 (inactive), alternate setting 1 (active).
//!
//! # ECM vs NCM
//!
//! - **ECM** wraps each Ethernet frame in a single USB bulk transfer.
//!   Simple but has overhead at high frame rates.
//! - **NCM** aggregates multiple frames in an NTB (Network Transfer Block)
//!   with an NDP (NTB Datagram Pointer) header for better throughput.
//!
//! # Architecture
//!
//! - [`EcmDescriptor`] — parsed CDC ECM Ethernet Functional Descriptor.
//! - [`NcmParams`] — NCM Transfer Block parameters.
//! - [`NtbHeader`] / [`NdpHeader`] / [`NdpDatagram`] — NCM NTB structures.
//! - [`CdcEcmDevice`] — ECM network interface state.
//! - [`CdcNcmDevice`] — NCM network interface state.
//! - [`UsbNetRegistry`] — fixed-size registry for both ECM and NCM devices.
//!
//! Reference: USB CDC 1.2 (ECM120.pdf, NCM10.pdf), USB 2.0 §9.

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// USB interface class / subclass / protocol codes
// ---------------------------------------------------------------------------

/// USB interface class: CDC Communications.
pub const CDC_COMM_CLASS: u8 = 0x02;

/// USB interface subclass: Ethernet Control Model.
pub const CDC_ECM_SUBCLASS: u8 = 0x06;

/// USB interface subclass: Network Control Model.
pub const CDC_NCM_SUBCLASS: u8 = 0x0D;

/// USB interface class: CDC Data.
pub const CDC_DATA_CLASS: u8 = 0x0A;

// ---------------------------------------------------------------------------
// CDC class-specific descriptor subtypes (§5.2.3)
// ---------------------------------------------------------------------------

/// CDC class-specific descriptor type.
pub const CDC_CS_INTERFACE: u8 = 0x24;

/// Header Functional Descriptor subtype.
pub const CDC_SUBTYPE_HEADER: u8 = 0x00;

/// Union Functional Descriptor subtype.
pub const CDC_SUBTYPE_UNION: u8 = 0x06;

/// Ethernet Networking Functional Descriptor subtype (ECM §5.4).
pub const CDC_SUBTYPE_ETHERNET: u8 = 0x0F;

/// NCM Functional Descriptor subtype (NCM §5.2.1).
pub const CDC_SUBTYPE_NCM: u8 = 0x1A;

// ---------------------------------------------------------------------------
// CDC class requests (ECM §6.2, NCM §6.2)
// ---------------------------------------------------------------------------

/// SET_ETHERNET_MULTICAST_FILTERS (ECM).
pub const REQ_SET_MULTICAST_FILTERS: u8 = 0x40;

/// SET_ETHERNET_POWER_MANAGEMENT_PATTERN_FILTER (ECM).
pub const REQ_SET_PM_FILTER: u8 = 0x41;

/// GET_ETHERNET_POWER_MANAGEMENT_PATTERN_FILTER (ECM).
pub const REQ_GET_PM_FILTER: u8 = 0x42;

/// SET_ETHERNET_PACKET_FILTER (ECM §6.2.4).
pub const REQ_SET_PACKET_FILTER: u8 = 0x43;

/// GET_ETHERNET_STATISTIC (ECM §6.2.5).
pub const REQ_GET_STATISTIC: u8 = 0x44;

/// GET_NTB_PARAMETERS (NCM §6.2.1).
pub const REQ_GET_NTB_PARAMS: u8 = 0x80;

/// GET_NET_ADDRESS (NCM §6.2.2).
pub const REQ_GET_NET_ADDRESS: u8 = 0x81;

/// SET_NET_ADDRESS (NCM §6.2.3).
pub const REQ_SET_NET_ADDRESS: u8 = 0x82;

/// GET_NTB_FORMAT (NCM §6.2.4).
pub const REQ_GET_NTB_FORMAT: u8 = 0x83;

/// SET_NTB_FORMAT (NCM §6.2.5).
pub const REQ_SET_NTB_FORMAT: u8 = 0x84;

/// GET_NTB_INPUT_SIZE (NCM §6.2.6).
pub const REQ_GET_NTB_INPUT_SIZE: u8 = 0x85;

/// SET_NTB_INPUT_SIZE (NCM §6.2.7).
pub const REQ_SET_NTB_INPUT_SIZE: u8 = 0x86;

// ---------------------------------------------------------------------------
// Packet filter bits (ECM §6.2.4)
// ---------------------------------------------------------------------------

/// Accept promiscuous — all packets regardless of destination.
pub const PACKET_FILTER_PROMISCUOUS: u16 = 1 << 0;

/// Accept all multicast packets.
pub const PACKET_FILTER_ALL_MULTICAST: u16 = 1 << 1;

/// Accept directed packets (unicast to this MAC address).
pub const PACKET_FILTER_DIRECTED: u16 = 1 << 2;

/// Accept broadcast packets.
pub const PACKET_FILTER_BROADCAST: u16 = 1 << 3;

/// Accept multicast packets matching the multicast filter list.
pub const PACKET_FILTER_MULTICAST: u16 = 1 << 4;

// ---------------------------------------------------------------------------
// CDC notifications (§6.3)
// ---------------------------------------------------------------------------

/// NETWORK_CONNECTION notification code.
pub const NOTIF_NETWORK_CONNECTION: u8 = 0x00;

/// CONNECTION_SPEED_CHANGE notification code.
pub const NOTIF_CONNECTION_SPEED_CHANGE: u8 = 0x2A;

// ---------------------------------------------------------------------------
// NCM constants (NCM10 §6.2)
// ---------------------------------------------------------------------------

/// NTB-16 signature in NTB header (`"NCMH"`).
pub const NTB16_SIGNATURE: u32 = 0x484D_434E;

/// NDP-16 signature for no FCS (`"NCM0"`).
pub const NDP16_SIGNATURE_NO_FCS: u32 = 0x304D_434E;

/// NDP-16 signature with FCS (`"NCM1"`).
pub const NDP16_SIGNATURE_WITH_FCS: u32 = 0x314D_434E;

/// Maximum NTB input size we will negotiate (64 KiB).
const NTB_MAX_IN_SIZE: u32 = 65_536;

/// Maximum datagrams per NDP we will process.
const MAX_DATAGRAMS_PER_NDP: usize = 32;

// ---------------------------------------------------------------------------
// Sizing
// ---------------------------------------------------------------------------

/// Ethernet MAC address length in bytes.
pub const MAC_ADDR_LEN: usize = 6;

/// Maximum Ethernet frame size (1514 bytes: 14 header + 1500 payload).
pub const MAX_FRAME_SIZE: usize = 1514;

/// Receive ring size (number of pre-allocated receive buffers).
const RX_RING_SIZE: usize = 16;

/// Transmit ring size.
const TX_RING_SIZE: usize = 16;

/// Maximum number of ECM devices in the registry.
const MAX_ECM_DEVICES: usize = 4;

/// Maximum number of NCM devices in the registry.
const MAX_NCM_DEVICES: usize = 4;

// ---------------------------------------------------------------------------
// EcmDescriptor (ECM §5.4)
// ---------------------------------------------------------------------------

/// Parsed CDC ECM Ethernet Networking Functional Descriptor.
///
/// The descriptor describes the MAC address string index, Ethernet
/// statistics capabilities, and maximum frame size.
#[derive(Debug, Clone, Copy, Default)]
pub struct EcmDescriptor {
    /// iMACAddress: index of a string descriptor holding the MAC address.
    pub mac_str_index: u8,
    /// bmEthernetStatistics: supported Ethernet statistics bitmask.
    pub eth_statistics: u32,
    /// wMaxSegmentSize: maximum Ethernet frame payload size (typ. 1514).
    pub max_segment_size: u16,
    /// wNumberMCFilters: number of multicast filters supported.
    pub num_mc_filters: u16,
    /// bNumberPowerFilters: number of wake-on-LAN patterns.
    pub num_power_filters: u8,
}

impl EcmDescriptor {
    /// Parse an ECM Ethernet Networking Functional Descriptor from bytes.
    ///
    /// `data` must point to the start of the descriptor (length byte first).
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `data` is shorter than 13 bytes.
    pub fn parse(data: &[u8]) -> Result<Self> {
        // Minimum size: bLength(1) + bDescriptorType(1) + bDescriptorSubtype(1)
        // + iMACAddress(1) + bmEthernetStatistics(4) + wMaxSegmentSize(2)
        // + wNumberMCFilters(2) + bNumberPowerFilters(1) = 13 bytes.
        if data.len() < 13 {
            return Err(Error::InvalidArgument);
        }
        if data[1] != CDC_CS_INTERFACE || data[2] != CDC_SUBTYPE_ETHERNET {
            return Err(Error::InvalidArgument);
        }

        let mac_str_index = data[3];
        let eth_statistics = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
        let max_segment_size = u16::from_le_bytes([data[8], data[9]]);
        let num_mc_filters = u16::from_le_bytes([data[10], data[11]]);
        let num_power_filters = data[12];

        Ok(Self {
            mac_str_index,
            eth_statistics,
            max_segment_size,
            num_mc_filters,
            num_power_filters,
        })
    }
}

// ---------------------------------------------------------------------------
// NcmParams (NCM §6.2.1)
// ---------------------------------------------------------------------------

/// NCM Transfer Block operational parameters reported by GET_NTB_PARAMETERS.
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct NcmParams {
    /// wLength: size of this structure (28 bytes for NCM 1.0).
    pub length: u16,
    /// bmNtbFormatsSupported: bit 0 = NTB-16 supported, bit 1 = NTB-32 supported.
    pub ntb_formats_supported: u16,
    /// dwNtbInMaxSize: maximum NTB size for IN direction (device → host).
    pub ntb_in_max_size: u32,
    /// wNdpInDivisor: NDP offset alignment divisor for IN NTBs.
    pub ndp_in_divisor: u16,
    /// wNdpInPayloadRemainder: NDP offset modulus remainder for IN NTBs.
    pub ndp_in_payload_remainder: u16,
    /// wNdpInAlignment: NDP alignment for IN NTBs.
    pub ndp_in_alignment: u16,
    /// Reserved.
    pub _reserved: u16,
    /// dwNtbOutMaxSize: maximum NTB size for OUT direction (host → device).
    pub ntb_out_max_size: u32,
    /// wNdpOutDivisor: NDP offset alignment divisor for OUT NTBs.
    pub ndp_out_divisor: u16,
    /// wNdpOutPayloadRemainder: NDP offset modulus remainder.
    pub ndp_out_payload_remainder: u16,
    /// wNdpOutAlignment: NDP alignment for OUT NTBs.
    pub ndp_out_alignment: u16,
    /// wNtbOutMaxDatagrams: max datagrams per OUT NTB (0 = no limit).
    pub ntb_out_max_datagrams: u16,
}

// ---------------------------------------------------------------------------
// NTB-16 structures (NCM §3.3)
// ---------------------------------------------------------------------------

/// NTB-16 Transfer Header.
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct NtbHeader {
    /// dwSignature: must be `NTB16_SIGNATURE`.
    pub signature: u32,
    /// wHeaderLength: length of this header in bytes (12).
    pub header_length: u16,
    /// wSequence: sequence number.
    pub sequence: u16,
    /// wBlockLength: total NTB length in bytes.
    pub block_length: u16,
    /// wNdpIndex: offset of the first NDP in this NTB.
    pub ndp_index: u16,
}

/// NTB-16 Datagram Pointer entry (within an NDP).
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct NdpDatagram {
    /// wDatagramIndex: offset of this datagram within the NTB (0 = end of list).
    pub index: u16,
    /// wDatagramLength: length of this datagram in bytes (0 = end of list).
    pub length: u16,
}

/// NTB-16 Datagram Pointer header.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct NdpHeader {
    /// dwSignature: NDP16_SIGNATURE_NO_FCS or _WITH_FCS.
    pub signature: u32,
    /// wLength: length of the NDP header in bytes.
    pub length: u16,
    /// wNextNdpIndex: offset of the next NDP, or 0 if last.
    pub next_ndp_index: u16,
    /// Datagram pointer entries (variable length, terminated by zero entry).
    pub datagrams: [NdpDatagram; MAX_DATAGRAMS_PER_NDP],
}

impl NdpHeader {
    /// Create an empty NDP header.
    pub const fn new() -> Self {
        Self {
            signature: NDP16_SIGNATURE_NO_FCS,
            length: 0,
            next_ndp_index: 0,
            datagrams: [NdpDatagram {
                index: 0,
                length: 0,
            }; MAX_DATAGRAMS_PER_NDP],
        }
    }
}

impl Default for NdpHeader {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// RxBuffer / TxBuffer
// ---------------------------------------------------------------------------

/// A single receive buffer slot.
#[derive(Clone, Copy)]
pub struct RxBuffer {
    /// Raw frame data.
    pub data: [u8; MAX_FRAME_SIZE],
    /// Number of valid bytes in `data`.
    pub len: usize,
    /// Whether this slot contains a valid received frame.
    pub valid: bool,
}

impl Default for RxBuffer {
    fn default() -> Self {
        Self {
            data: [0u8; MAX_FRAME_SIZE],
            len: 0,
            valid: false,
        }
    }
}

/// A single transmit buffer slot.
#[derive(Clone, Copy)]
pub struct TxBuffer {
    /// Frame data to be transmitted.
    pub data: [u8; MAX_FRAME_SIZE],
    /// Number of bytes to transmit.
    pub len: usize,
    /// Whether this slot is pending transmission.
    pub pending: bool,
}

impl Default for TxBuffer {
    fn default() -> Self {
        Self {
            data: [0u8; MAX_FRAME_SIZE],
            len: 0,
            pending: false,
        }
    }
}

// ---------------------------------------------------------------------------
// ConnectionStatus
// ---------------------------------------------------------------------------

/// Network connection state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ConnectionStatus {
    /// No link / disconnected.
    #[default]
    Disconnected,
    /// Link is up; operating at `speed_bps` bits per second.
    Connected {
        /// Current uplink speed in bits per second.
        uplink_bps: u32,
        /// Current downlink speed in bits per second.
        downlink_bps: u32,
    },
}

// ---------------------------------------------------------------------------
// CdcEcmDevice
// ---------------------------------------------------------------------------

/// CDC ECM Ethernet network device instance.
///
/// Manages a single ECM interface pair, frame ring buffers, and the
/// current link state.
pub struct CdcEcmDevice {
    /// Parsed ECM descriptor.
    descriptor: EcmDescriptor,
    /// MAC address of this interface.
    mac_addr: [u8; MAC_ADDR_LEN],
    /// Current packet filter bitmask.
    packet_filter: u16,
    /// Connection status.
    status: ConnectionStatus,
    /// Receive ring.
    rx_ring: [RxBuffer; RX_RING_SIZE],
    /// Head index (next slot to consume on receive).
    rx_head: usize,
    /// Tail index (next slot to fill on receive).
    rx_tail: usize,
    /// Number of frames in the receive ring.
    rx_count: usize,
    /// Transmit ring.
    tx_ring: [TxBuffer; TX_RING_SIZE],
    /// Head index (oldest pending transmit).
    tx_head: usize,
    /// Tail index (next free slot for transmit).
    tx_tail: usize,
    /// Number of frames pending in the transmit ring.
    tx_count: usize,
    /// Whether the device has been initialised.
    ready: bool,
}

impl CdcEcmDevice {
    /// Create a new ECM device instance.
    pub const fn new() -> Self {
        const EMPTY_RX: RxBuffer = RxBuffer {
            data: [0u8; MAX_FRAME_SIZE],
            len: 0,
            valid: false,
        };
        const EMPTY_TX: TxBuffer = TxBuffer {
            data: [0u8; MAX_FRAME_SIZE],
            len: 0,
            pending: false,
        };
        Self {
            descriptor: EcmDescriptor {
                mac_str_index: 0,
                eth_statistics: 0,
                max_segment_size: MAX_FRAME_SIZE as u16,
                num_mc_filters: 0,
                num_power_filters: 0,
            },
            mac_addr: [0u8; MAC_ADDR_LEN],
            packet_filter: PACKET_FILTER_DIRECTED | PACKET_FILTER_BROADCAST,
            status: ConnectionStatus::Disconnected,
            rx_ring: [EMPTY_RX; RX_RING_SIZE],
            rx_head: 0,
            rx_tail: 0,
            rx_count: 0,
            tx_ring: [EMPTY_TX; TX_RING_SIZE],
            tx_head: 0,
            tx_tail: 0,
            tx_count: 0,
            ready: false,
        }
    }

    /// Initialise the device with the parsed descriptor and MAC address.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if the descriptor max segment size
    /// exceeds [`MAX_FRAME_SIZE`].
    pub fn init(&mut self, descriptor: EcmDescriptor, mac_addr: [u8; MAC_ADDR_LEN]) -> Result<()> {
        if descriptor.max_segment_size as usize > MAX_FRAME_SIZE {
            return Err(Error::InvalidArgument);
        }
        self.descriptor = descriptor;
        self.mac_addr = mac_addr;
        self.ready = true;
        Ok(())
    }

    /// Handle a NETWORK_CONNECTION notification from the device.
    ///
    /// `connected` reflects the `wValue` field of the notification
    /// (1 = connected, 0 = disconnected).
    pub fn handle_network_connection(&mut self, connected: bool) {
        if !connected {
            self.status = ConnectionStatus::Disconnected;
        } else {
            // Speed will be updated by a subsequent CONNECTION_SPEED_CHANGE
            // notification. Default to 100 Mbps symmetric.
            self.status = ConnectionStatus::Connected {
                uplink_bps: 100_000_000,
                downlink_bps: 100_000_000,
            };
        }
    }

    /// Handle a CONNECTION_SPEED_CHANGE notification.
    pub fn handle_speed_change(&mut self, uplink_bps: u32, downlink_bps: u32) {
        if let ConnectionStatus::Connected {
            uplink_bps: ref mut up,
            downlink_bps: ref mut down,
        } = self.status
        {
            *up = uplink_bps;
            *down = downlink_bps;
        }
    }

    /// Enqueue a received Ethernet frame into the RX ring.
    ///
    /// Returns `true` if the frame was accepted; `false` if the ring is full.
    pub fn rx_enqueue(&mut self, frame: &[u8]) -> bool {
        if self.rx_count >= RX_RING_SIZE || frame.len() > MAX_FRAME_SIZE {
            return false;
        }
        let slot = &mut self.rx_ring[self.rx_tail];
        slot.data[..frame.len()].copy_from_slice(frame);
        slot.len = frame.len();
        slot.valid = true;
        self.rx_tail = (self.rx_tail + 1) % RX_RING_SIZE;
        self.rx_count += 1;
        true
    }

    /// Dequeue a received frame from the RX ring.
    ///
    /// Copies at most `buf.len()` bytes into `buf` and returns the
    /// actual frame length, or `None` if the ring is empty.
    pub fn rx_dequeue<'a>(&mut self, buf: &'a mut [u8]) -> Option<usize> {
        if self.rx_count == 0 {
            return None;
        }
        let slot = &mut self.rx_ring[self.rx_head];
        if !slot.valid {
            return None;
        }
        let copy_len = slot.len.min(buf.len());
        buf[..copy_len].copy_from_slice(&slot.data[..copy_len]);
        slot.valid = false;
        slot.len = 0;
        self.rx_head = (self.rx_head + 1) % RX_RING_SIZE;
        self.rx_count -= 1;
        Some(copy_len)
    }

    /// Enqueue a frame for transmission.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the TX ring is full.
    /// Returns [`Error::InvalidArgument`] if the frame exceeds [`MAX_FRAME_SIZE`].
    pub fn tx_enqueue(&mut self, frame: &[u8]) -> Result<()> {
        if frame.len() > MAX_FRAME_SIZE {
            return Err(Error::InvalidArgument);
        }
        if self.tx_count >= TX_RING_SIZE {
            return Err(Error::OutOfMemory);
        }
        let slot = &mut self.tx_ring[self.tx_tail];
        slot.data[..frame.len()].copy_from_slice(frame);
        slot.len = frame.len();
        slot.pending = true;
        self.tx_tail = (self.tx_tail + 1) % TX_RING_SIZE;
        self.tx_count += 1;
        Ok(())
    }

    /// Dequeue the oldest pending transmit frame.
    ///
    /// Copies at most `buf.len()` bytes into `buf`. Returns `None` if
    /// no frames are pending.
    pub fn tx_dequeue<'a>(&mut self, buf: &'a mut [u8]) -> Option<usize> {
        if self.tx_count == 0 {
            return None;
        }
        let slot = &mut self.tx_ring[self.tx_head];
        if !slot.pending {
            return None;
        }
        let copy_len = slot.len.min(buf.len());
        buf[..copy_len].copy_from_slice(&slot.data[..copy_len]);
        slot.pending = false;
        slot.len = 0;
        self.tx_head = (self.tx_head + 1) % TX_RING_SIZE;
        self.tx_count -= 1;
        Some(copy_len)
    }

    /// Return the MAC address.
    pub fn mac_addr(&self) -> &[u8; MAC_ADDR_LEN] {
        &self.mac_addr
    }

    /// Return the current connection status.
    pub fn status(&self) -> ConnectionStatus {
        self.status
    }

    /// Return the current packet filter bitmask.
    pub fn packet_filter(&self) -> u16 {
        self.packet_filter
    }

    /// Set a new packet filter bitmask.
    pub fn set_packet_filter(&mut self, filter: u16) {
        self.packet_filter = filter;
    }

    /// Return the descriptor.
    pub fn descriptor(&self) -> &EcmDescriptor {
        &self.descriptor
    }

    /// Return whether the device is ready.
    pub fn is_ready(&self) -> bool {
        self.ready
    }
}

impl Default for CdcEcmDevice {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// CdcNcmDevice
// ---------------------------------------------------------------------------

/// CDC NCM Ethernet network device instance.
///
/// Extends the ECM model by aggregating multiple Ethernet frames into
/// Network Transfer Blocks (NTBs) for improved USB bulk throughput.
pub struct CdcNcmDevice {
    /// Underlying ECM-style state (MAC, rings, status).
    ecm: CdcEcmDevice,
    /// NCM operational parameters from GET_NTB_PARAMETERS.
    params: NcmParams,
    /// NTB input size negotiated with the device.
    ntb_in_size: u32,
    /// Current NTB sequence number.
    sequence: u16,
    /// Whether NTB-32 format is in use (false = NTB-16).
    use_ntb32: bool,
}

impl CdcNcmDevice {
    /// Create a new NCM device instance.
    pub const fn new() -> Self {
        Self {
            ecm: CdcEcmDevice::new(),
            params: NcmParams {
                length: 28,
                ntb_formats_supported: 0x01, // NTB-16 only by default
                ntb_in_max_size: NTB_MAX_IN_SIZE,
                ndp_in_divisor: 4,
                ndp_in_payload_remainder: 0,
                ndp_in_alignment: 4,
                _reserved: 0,
                ntb_out_max_size: NTB_MAX_IN_SIZE,
                ndp_out_divisor: 4,
                ndp_out_payload_remainder: 0,
                ndp_out_alignment: 4,
                ntb_out_max_datagrams: 0,
            },
            ntb_in_size: NTB_MAX_IN_SIZE,
            sequence: 0,
            use_ntb32: false,
        }
    }

    /// Initialise the NCM device.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if the descriptor is invalid.
    pub fn init(&mut self, descriptor: EcmDescriptor, mac_addr: [u8; MAC_ADDR_LEN]) -> Result<()> {
        self.ecm.init(descriptor, mac_addr)
    }

    /// Apply NTB parameters returned by GET_NTB_PARAMETERS.
    pub fn apply_ntb_params(&mut self, params: NcmParams) {
        self.ntb_in_size = params.ntb_in_max_size.min(NTB_MAX_IN_SIZE);
        self.use_ntb32 = params.ntb_formats_supported & 0x02 != 0;
        self.params = params;
    }

    /// Parse an incoming NTB-16 and extract all datagrams into the RX ring.
    ///
    /// `ntb_data` is the complete NTB received from the device via bulk-IN.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if the NTB signature is invalid
    /// or the NTB is malformed.
    pub fn process_ntb(&mut self, ntb_data: &[u8]) -> Result<usize> {
        if ntb_data.len() < core::mem::size_of::<NtbHeader>() {
            return Err(Error::InvalidArgument);
        }

        // Parse NTB header.
        // SAFETY: ntb_data.len() >= size_of::<NtbHeader>() verified above.
        let ntb_sig = u32::from_le_bytes([ntb_data[0], ntb_data[1], ntb_data[2], ntb_data[3]]);
        if ntb_sig != NTB16_SIGNATURE {
            return Err(Error::InvalidArgument);
        }

        let block_length = u16::from_le_bytes([ntb_data[6], ntb_data[7]]) as usize;
        let ndp_index = u16::from_le_bytes([ntb_data[8], ntb_data[9]]) as usize;

        if block_length > ntb_data.len() || ndp_index + 8 > ntb_data.len() {
            return Err(Error::InvalidArgument);
        }

        let mut accepted = 0usize;
        let mut ndp_off = ndp_index;

        // Walk NDP chain.
        while ndp_off + 8 <= ntb_data.len() {
            let ndp_sig = u32::from_le_bytes([
                ntb_data[ndp_off],
                ntb_data[ndp_off + 1],
                ntb_data[ndp_off + 2],
                ntb_data[ndp_off + 3],
            ]);
            if ndp_sig != NDP16_SIGNATURE_NO_FCS && ndp_sig != NDP16_SIGNATURE_WITH_FCS {
                break;
            }

            let ndp_len =
                u16::from_le_bytes([ntb_data[ndp_off + 4], ntb_data[ndp_off + 5]]) as usize;
            let next_ndp =
                u16::from_le_bytes([ntb_data[ndp_off + 6], ntb_data[ndp_off + 7]]) as usize;

            // Datagram pointers start at NDP offset + 8, each is 4 bytes.
            let dp_start = ndp_off + 8;
            let dp_end = ndp_off + ndp_len;

            let mut dp_off = dp_start;
            while dp_off + 4 <= dp_end.min(ntb_data.len()) {
                let dg_index =
                    u16::from_le_bytes([ntb_data[dp_off], ntb_data[dp_off + 1]]) as usize;
                let dg_length =
                    u16::from_le_bytes([ntb_data[dp_off + 2], ntb_data[dp_off + 3]]) as usize;

                // Zero entry signals end of datagram list.
                if dg_index == 0 && dg_length == 0 {
                    break;
                }

                let dg_end = dg_index + dg_length;
                if dg_end <= ntb_data.len() && dg_length <= MAX_FRAME_SIZE {
                    if self.ecm.rx_enqueue(&ntb_data[dg_index..dg_end]) {
                        accepted += 1;
                    }
                }

                dp_off += 4;
            }

            if next_ndp == 0 {
                break;
            }
            ndp_off = next_ndp;
        }

        Ok(accepted)
    }

    /// Build an NTB-16 containing all pending TX frames and return its length.
    ///
    /// `buf` is the output buffer for the NTB. Returns the number of bytes
    /// written or an error if `buf` is too small.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if `buf` is too small for the NTB.
    pub fn build_ntb<'a>(&mut self, buf: &'a mut [u8]) -> Result<usize> {
        // NTB header: 12 bytes. NDP header: 8 + 4 * (datagrams + 1 terminator).
        // We need at least the header + NDP header to proceed.
        if buf.len() < 12 + 8 {
            return Err(Error::OutOfMemory);
        }

        let mut payload_off: usize = 12; // NTB header
        let mut datagram_count: usize = 0;
        let mut datagram_indices: [u16; TX_RING_SIZE] = [0; TX_RING_SIZE];
        let mut datagram_lengths: [u16; TX_RING_SIZE] = [0; TX_RING_SIZE];

        // Write payload frames after the NTB header + NDP placeholder.
        // Reserve space for NDP header after the NTB header.
        let ndp_reserve = 8 + 4 * (TX_RING_SIZE + 1);
        payload_off = payload_off.saturating_add(ndp_reserve);

        while self.ecm.tx_count > 0 && datagram_count < TX_RING_SIZE {
            let remaining = buf.len().saturating_sub(payload_off);
            if remaining < MAX_FRAME_SIZE {
                break;
            }
            if let Some(len) = self.ecm.tx_dequeue(&mut buf[payload_off..]) {
                datagram_indices[datagram_count] = payload_off as u16;
                datagram_lengths[datagram_count] = len as u16;
                datagram_count += 1;
                // Align next datagram to 4-byte boundary.
                payload_off = (payload_off + len + 3) & !3;
            } else {
                break;
            }
        }

        let block_length = payload_off as u16;

        // NDP starts right after the NTB header (offset 12).
        let ndp_offset: u16 = 12;
        let ndp_length = (8 + 4 * (datagram_count + 1)) as u16;

        // Write NTB header.
        buf[0..4].copy_from_slice(&NTB16_SIGNATURE.to_le_bytes());
        buf[4..6].copy_from_slice(&12u16.to_le_bytes());
        buf[6..8].copy_from_slice(&self.sequence.to_le_bytes());
        buf[8..10].copy_from_slice(&block_length.to_le_bytes());
        buf[10..12].copy_from_slice(&ndp_offset.to_le_bytes());

        // Write NDP header.
        let ndp_base = ndp_offset as usize;
        buf[ndp_base..ndp_base + 4].copy_from_slice(&NDP16_SIGNATURE_NO_FCS.to_le_bytes());
        buf[ndp_base + 4..ndp_base + 6].copy_from_slice(&ndp_length.to_le_bytes());
        buf[ndp_base + 6..ndp_base + 8].copy_from_slice(&0u16.to_le_bytes()); // next NDP = 0

        // Write datagram pointers.
        let dp_base = ndp_base + 8;
        for i in 0..datagram_count {
            let off = dp_base + i * 4;
            buf[off..off + 2].copy_from_slice(&datagram_indices[i].to_le_bytes());
            buf[off + 2..off + 4].copy_from_slice(&datagram_lengths[i].to_le_bytes());
        }
        // Terminating entry.
        let term_off = dp_base + datagram_count * 4;
        buf[term_off..term_off + 4].fill(0);

        self.sequence = self.sequence.wrapping_add(1);
        Ok(payload_off)
    }

    /// Delegate to the ECM receive queue.
    pub fn rx_enqueue(&mut self, frame: &[u8]) -> bool {
        self.ecm.rx_enqueue(frame)
    }

    /// Delegate to the ECM receive queue.
    pub fn rx_dequeue<'a>(&mut self, buf: &'a mut [u8]) -> Option<usize> {
        self.ecm.rx_dequeue(buf)
    }

    /// Delegate to the ECM transmit queue.
    pub fn tx_enqueue(&mut self, frame: &[u8]) -> Result<()> {
        self.ecm.tx_enqueue(frame)
    }

    /// Return the MAC address.
    pub fn mac_addr(&self) -> &[u8; MAC_ADDR_LEN] {
        self.ecm.mac_addr()
    }

    /// Return the current connection status.
    pub fn status(&self) -> ConnectionStatus {
        self.ecm.status()
    }

    /// Return the NTB input size in use.
    pub fn ntb_in_size(&self) -> u32 {
        self.ntb_in_size
    }

    /// Return the NCM parameters.
    pub fn params(&self) -> &NcmParams {
        &self.params
    }

    /// Return whether the device is ready.
    pub fn is_ready(&self) -> bool {
        self.ecm.is_ready()
    }
}

impl Default for CdcNcmDevice {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// UsbNetRegistry
// ---------------------------------------------------------------------------

/// Registry tracking ECM and NCM USB network devices.
pub struct UsbNetRegistry {
    ecm_devices: [Option<CdcEcmDevice>; MAX_ECM_DEVICES],
    ecm_count: usize,
    ncm_devices: [Option<CdcNcmDevice>; MAX_NCM_DEVICES],
    ncm_count: usize,
}

impl UsbNetRegistry {
    /// Create an empty registry.
    pub const fn new() -> Self {
        const EMPTY_ECM: Option<CdcEcmDevice> = None;
        const EMPTY_NCM: Option<CdcNcmDevice> = None;
        Self {
            ecm_devices: [EMPTY_ECM; MAX_ECM_DEVICES],
            ecm_count: 0,
            ncm_devices: [EMPTY_NCM; MAX_NCM_DEVICES],
            ncm_count: 0,
        }
    }

    /// Register a CDC ECM device.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the ECM registry is full.
    pub fn register_ecm(&mut self, dev: CdcEcmDevice) -> Result<usize> {
        if self.ecm_count >= MAX_ECM_DEVICES {
            return Err(Error::OutOfMemory);
        }
        let idx = self.ecm_count;
        self.ecm_devices[idx] = Some(dev);
        self.ecm_count += 1;
        Ok(idx)
    }

    /// Register a CDC NCM device.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the NCM registry is full.
    pub fn register_ncm(&mut self, dev: CdcNcmDevice) -> Result<usize> {
        if self.ncm_count >= MAX_NCM_DEVICES {
            return Err(Error::OutOfMemory);
        }
        let idx = self.ncm_count;
        self.ncm_devices[idx] = Some(dev);
        self.ncm_count += 1;
        Ok(idx)
    }

    /// Get an immutable reference to an ECM device by index.
    pub fn get_ecm(&self, idx: usize) -> Option<&CdcEcmDevice> {
        self.ecm_devices.get(idx).and_then(|d| d.as_ref())
    }

    /// Get a mutable reference to an ECM device by index.
    pub fn get_ecm_mut(&mut self, idx: usize) -> Option<&mut CdcEcmDevice> {
        self.ecm_devices.get_mut(idx).and_then(|d| d.as_mut())
    }

    /// Get an immutable reference to an NCM device by index.
    pub fn get_ncm(&self, idx: usize) -> Option<&CdcNcmDevice> {
        self.ncm_devices.get(idx).and_then(|d| d.as_ref())
    }

    /// Get a mutable reference to an NCM device by index.
    pub fn get_ncm_mut(&mut self, idx: usize) -> Option<&mut CdcNcmDevice> {
        self.ncm_devices.get_mut(idx).and_then(|d| d.as_mut())
    }

    /// Return the number of registered ECM devices.
    pub fn ecm_count(&self) -> usize {
        self.ecm_count
    }

    /// Return the number of registered NCM devices.
    pub fn ncm_count(&self) -> usize {
        self.ncm_count
    }

    /// Return `true` if no devices of either type are registered.
    pub fn is_empty(&self) -> bool {
        self.ecm_count == 0 && self.ncm_count == 0
    }
}

impl Default for UsbNetRegistry {
    fn default() -> Self {
        Self::new()
    }
}
