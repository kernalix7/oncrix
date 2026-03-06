// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! IPv6 protocol and Neighbor Discovery Protocol (NDP) for the ONCRIX kernel.
//!
//! Implements:
//! - [`Ipv6Addr`] — 128-bit address wrapper with classification helpers
//! - [`Ipv6Header`] — 40-byte fixed IPv6 header (repr(C))
//! - [`Icmpv6Type`] / [`Icmpv6Header`] — ICMPv6 message types
//! - [`NdpState`] / [`NeighborEntry`] / [`NeighborTable`] — NDP neighbor cache
//! - [`Ipv6Stack`] — packet processing and NDP message generation
//!
//! All multi-byte fields use network byte order (big-endian).

use oncrix_lib::{Error, Result};

// =========================================================================
// IPv6 Address
// =========================================================================

/// 128-bit IPv6 address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ipv6Addr {
    /// Raw address bytes in network byte order.
    octets: [u8; 16],
}

impl Ipv6Addr {
    /// Unspecified address (`::`).
    pub const UNSPECIFIED: Self = Self { octets: [0; 16] };

    /// Loopback address (`::1`).
    pub const LOOPBACK: Self = Self {
        octets: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
    };

    /// All-nodes multicast (`ff02::1`).
    pub const ALL_NODES: Self = Self {
        octets: [0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
    };

    /// All-routers multicast (`ff02::2`).
    pub const ALL_ROUTERS: Self = Self {
        octets: [0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2],
    };

    /// Creates an address from raw bytes.
    pub const fn from_bytes(octets: [u8; 16]) -> Self {
        Self { octets }
    }

    /// Returns the raw bytes.
    pub const fn to_bytes(self) -> [u8; 16] {
        self.octets
    }

    /// Returns `true` if the address is `::`.
    pub fn is_unspecified(&self) -> bool {
        self.octets == [0; 16]
    }

    /// Returns `true` if the address is `::1`.
    pub fn is_loopback(&self) -> bool {
        *self == Self::LOOPBACK
    }

    /// Returns `true` if the address is in `ff00::/8`.
    pub fn is_multicast(&self) -> bool {
        self.octets[0] == 0xff
    }

    /// Returns `true` if the address is in `fe80::/10`.
    pub fn is_link_local(&self) -> bool {
        self.octets[0] == 0xfe && (self.octets[1] & 0xc0) == 0x80
    }

    /// Returns `true` if the address is a solicited-node multicast (`ff02::1:ffXX:XXXX`).
    pub fn is_solicited_node_multicast(&self) -> bool {
        self.octets[0] == 0xff
            && self.octets[1] == 0x02
            && self.octets[2..11] == [0; 9]
            && self.octets[11] == 0x01
            && self.octets[12] == 0xff
    }

    /// Computes the solicited-node multicast address for this unicast address.
    pub fn solicited_node(&self) -> Self {
        let mut octets = [0u8; 16];
        octets[0] = 0xff;
        octets[1] = 0x02;
        // octets[2..11] = 0
        octets[11] = 0x01;
        octets[12] = 0xff;
        octets[13] = self.octets[13];
        octets[14] = self.octets[14];
        octets[15] = self.octets[15];
        Self { octets }
    }

    /// Formats the address into the provided buffer as colon-hex notation.
    /// Returns the number of bytes written.
    pub fn format(&self, buf: &mut [u8]) -> usize {
        let mut pos = 0;
        for i in 0..8 {
            if i > 0 && pos < buf.len() {
                buf[pos] = b':';
                pos += 1;
            }
            let word = u16::from_be_bytes([self.octets[i * 2], self.octets[i * 2 + 1]]);
            pos += format_hex_u16(word, &mut buf[pos..]);
        }
        pos
    }
}

impl Default for Ipv6Addr {
    fn default() -> Self {
        Self::UNSPECIFIED
    }
}

/// Formats a `u16` as lowercase hex into `buf`, returning bytes written.
fn format_hex_u16(val: u16, buf: &mut [u8]) -> usize {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let digits = [
        HEX[((val >> 12) & 0xf) as usize],
        HEX[((val >> 8) & 0xf) as usize],
        HEX[((val >> 4) & 0xf) as usize],
        HEX[(val & 0xf) as usize],
    ];
    // Skip leading zeros but always write at least one digit.
    let start = digits.iter().position(|&d| d != b'0').unwrap_or(3);
    let len = 4 - start;
    if buf.len() < len {
        return 0;
    }
    buf[..len].copy_from_slice(&digits[start..]);
    len
}

// =========================================================================
// IPv6 Header
// =========================================================================

/// IPv6 header length in bytes (always 40).
pub const IPV6_HEADER_LEN: usize = 40;

/// IPv6 next-header protocol numbers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum NextHeader {
    /// Hop-by-Hop Options.
    HopByHop = 0,
    /// ICMPv6.
    Icmpv6 = 58,
    /// TCP.
    Tcp = 6,
    /// UDP.
    Udp = 17,
    /// No Next Header.
    NoNext = 59,
}

impl NextHeader {
    /// Converts a raw byte to a `NextHeader`, if known.
    pub fn from_u8(val: u8) -> Option<Self> {
        match val {
            0 => Some(Self::HopByHop),
            6 => Some(Self::Tcp),
            17 => Some(Self::Udp),
            58 => Some(Self::Icmpv6),
            59 => Some(Self::NoNext),
            _ => None,
        }
    }
}

/// Fixed 40-byte IPv6 header.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct Ipv6Header {
    /// Version (4 bits), traffic class (8 bits), flow label (20 bits).
    pub version_tc_fl: u32,
    /// Payload length (not including this header).
    pub payload_length: u16,
    /// Next header protocol number.
    pub next_header: u8,
    /// Hop limit (TTL equivalent).
    pub hop_limit: u8,
    /// Source address.
    pub src: [u8; 16],
    /// Destination address.
    pub dst: [u8; 16],
}

impl Ipv6Header {
    /// Parses an IPv6 header from a byte slice.
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < IPV6_HEADER_LEN {
            return Err(Error::InvalidArgument);
        }
        let version_tc_fl = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
        let version = (version_tc_fl >> 28) & 0xf;
        if version != 6 {
            return Err(Error::InvalidArgument);
        }
        let payload_length = u16::from_be_bytes([data[4], data[5]]);
        let next_header = data[6];
        let hop_limit = data[7];
        let mut src = [0u8; 16];
        let mut dst = [0u8; 16];
        src.copy_from_slice(&data[8..24]);
        dst.copy_from_slice(&data[24..40]);
        Ok(Self {
            version_tc_fl,
            payload_length,
            next_header,
            hop_limit,
            src,
            dst,
        })
    }

    /// Returns the IP version (should be 6).
    pub fn version(&self) -> u8 {
        ((self.version_tc_fl >> 28) & 0xf) as u8
    }

    /// Returns the traffic class.
    pub fn traffic_class(&self) -> u8 {
        ((self.version_tc_fl >> 20) & 0xff) as u8
    }

    /// Returns the flow label.
    pub fn flow_label(&self) -> u32 {
        self.version_tc_fl & 0x000f_ffff
    }

    /// Source address.
    pub fn src_addr(&self) -> Ipv6Addr {
        Ipv6Addr::from_bytes(self.src)
    }

    /// Destination address.
    pub fn dst_addr(&self) -> Ipv6Addr {
        Ipv6Addr::from_bytes(self.dst)
    }

    /// Serializes the header into a byte buffer. Returns bytes written (40).
    pub fn serialize(&self, buf: &mut [u8]) -> Result<usize> {
        if buf.len() < IPV6_HEADER_LEN {
            return Err(Error::InvalidArgument);
        }
        let vtf = self.version_tc_fl.to_be_bytes();
        buf[0..4].copy_from_slice(&vtf);
        let pl = self.payload_length.to_be_bytes();
        buf[4..6].copy_from_slice(&pl);
        buf[6] = self.next_header;
        buf[7] = self.hop_limit;
        buf[8..24].copy_from_slice(&self.src);
        buf[24..40].copy_from_slice(&self.dst);
        Ok(IPV6_HEADER_LEN)
    }

    /// Creates a new header with default version=6 and given fields.
    pub fn new(
        src: Ipv6Addr,
        dst: Ipv6Addr,
        next_header: u8,
        hop_limit: u8,
        payload_length: u16,
    ) -> Self {
        let version_tc_fl = 6u32 << 28;
        Self {
            version_tc_fl,
            payload_length,
            next_header,
            hop_limit,
            src: src.to_bytes(),
            dst: dst.to_bytes(),
        }
    }
}

// =========================================================================
// ICMPv6
// =========================================================================

/// ICMPv6 message types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Icmpv6Type {
    /// Destination Unreachable.
    DestUnreachable = 1,
    /// Packet Too Big.
    PacketTooBig = 2,
    /// Time Exceeded.
    TimeExceeded = 3,
    /// Echo Request.
    EchoRequest = 128,
    /// Echo Reply.
    EchoReply = 129,
    /// Router Solicitation.
    RouterSolicitation = 133,
    /// Router Advertisement.
    RouterAdvertisement = 134,
    /// Neighbor Solicitation.
    NeighborSolicitation = 135,
    /// Neighbor Advertisement.
    NeighborAdvertisement = 136,
}

impl Icmpv6Type {
    /// Converts a raw byte to an `Icmpv6Type`, if known.
    pub fn from_u8(val: u8) -> Option<Self> {
        match val {
            1 => Some(Self::DestUnreachable),
            2 => Some(Self::PacketTooBig),
            3 => Some(Self::TimeExceeded),
            128 => Some(Self::EchoRequest),
            129 => Some(Self::EchoReply),
            133 => Some(Self::RouterSolicitation),
            134 => Some(Self::RouterAdvertisement),
            135 => Some(Self::NeighborSolicitation),
            136 => Some(Self::NeighborAdvertisement),
            _ => None,
        }
    }
}

/// ICMPv6 header (4 bytes common, rest is type-specific).
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct Icmpv6Header {
    /// Message type.
    pub icmp_type: u8,
    /// Type-specific code.
    pub code: u8,
    /// Internet checksum.
    pub checksum: u16,
}

/// Minimum ICMPv6 header length.
pub const ICMPV6_HEADER_LEN: usize = 4;

impl Icmpv6Header {
    /// Parses an ICMPv6 header from the payload portion of an IPv6 packet.
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < ICMPV6_HEADER_LEN {
            return Err(Error::InvalidArgument);
        }
        Ok(Self {
            icmp_type: data[0],
            code: data[1],
            checksum: u16::from_be_bytes([data[2], data[3]]),
        })
    }
}

/// NDP option types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum NdpOptionType {
    /// Source Link-Layer Address.
    SourceLinkLayerAddr = 1,
    /// Target Link-Layer Address.
    TargetLinkLayerAddr = 2,
    /// Prefix Information.
    PrefixInfo = 3,
    /// MTU.
    Mtu = 5,
}

/// Parsed NDP option.
#[derive(Debug, Clone, Copy)]
pub enum NdpOption {
    /// Source or target link-layer (MAC) address.
    LinkLayerAddr {
        /// Option type (source or target).
        kind: NdpOptionType,
        /// 6-byte MAC address.
        addr: [u8; 6],
    },
    /// Prefix information.
    PrefixInfo {
        /// Prefix length in bits.
        prefix_len: u8,
        /// On-link flag.
        on_link: bool,
        /// Autonomous address-configuration flag.
        autonomous: bool,
        /// Valid lifetime in seconds.
        valid_lifetime: u32,
        /// Preferred lifetime in seconds.
        preferred_lifetime: u32,
        /// The prefix (128 bits, upper `prefix_len` bits are significant).
        prefix: Ipv6Addr,
    },
    /// Link MTU.
    Mtu {
        /// MTU value.
        mtu: u32,
    },
}

/// Parses NDP options from a byte slice, appending to `out`. Returns count.
pub fn parse_ndp_options(data: &[u8], out: &mut [NdpOption], max: usize) -> usize {
    let mut offset = 0;
    let mut count = 0;
    while offset + 2 <= data.len() && count < max {
        let opt_type = data[offset];
        let opt_len_units = data[offset + 1] as usize;
        if opt_len_units == 0 {
            break;
        }
        let opt_len_bytes = opt_len_units * 8;
        if offset + opt_len_bytes > data.len() {
            break;
        }
        let opt_data = &data[offset..offset + opt_len_bytes];
        match opt_type {
            1 | 2 if opt_len_bytes >= 8 => {
                let mut addr = [0u8; 6];
                addr.copy_from_slice(&opt_data[2..8]);
                let kind = if opt_type == 1 {
                    NdpOptionType::SourceLinkLayerAddr
                } else {
                    NdpOptionType::TargetLinkLayerAddr
                };
                out[count] = NdpOption::LinkLayerAddr { kind, addr };
                count += 1;
            }
            3 if opt_len_bytes >= 32 => {
                let prefix_len = opt_data[2];
                let flags = opt_data[3];
                let on_link = (flags & 0x80) != 0;
                let autonomous = (flags & 0x40) != 0;
                let valid_lifetime =
                    u32::from_be_bytes([opt_data[4], opt_data[5], opt_data[6], opt_data[7]]);
                let preferred_lifetime =
                    u32::from_be_bytes([opt_data[8], opt_data[9], opt_data[10], opt_data[11]]);
                let mut prefix_bytes = [0u8; 16];
                prefix_bytes.copy_from_slice(&opt_data[16..32]);
                out[count] = NdpOption::PrefixInfo {
                    prefix_len,
                    on_link,
                    autonomous,
                    valid_lifetime,
                    preferred_lifetime,
                    prefix: Ipv6Addr::from_bytes(prefix_bytes),
                };
                count += 1;
            }
            5 if opt_len_bytes >= 8 => {
                let mtu = u32::from_be_bytes([opt_data[4], opt_data[5], opt_data[6], opt_data[7]]);
                out[count] = NdpOption::Mtu { mtu };
                count += 1;
            }
            _ => { /* skip unknown or too-short options */ }
        }
        offset += opt_len_bytes;
    }
    count
}

// =========================================================================
// Neighbor Discovery Protocol (NDP)
// =========================================================================

/// NDP neighbor cache entry state (RFC 4861 §7.3.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NdpState {
    /// Address resolution in progress; no link-layer address yet.
    Incomplete,
    /// Recently confirmed reachable.
    Reachable,
    /// Reachability timer expired; still usable but needs confirmation.
    Stale,
    /// Waiting before sending probe (traffic sent recently).
    Delay,
    /// Actively probing (sending Neighbor Solicitations).
    Probe,
}

/// A single neighbor cache entry.
#[derive(Debug, Clone, Copy)]
pub struct NeighborEntry {
    /// IPv6 address of the neighbor.
    pub addr: Ipv6Addr,
    /// Link-layer (MAC) address, valid when state != Incomplete.
    pub mac: [u8; 6],
    /// Current NDP state.
    pub state: NdpState,
    /// Tick at which this entry expires (state-dependent).
    pub expires_tick: u64,
    /// Number of solicitations sent (for Incomplete/Probe).
    pub retries: u8,
}

impl Default for NeighborEntry {
    fn default() -> Self {
        Self {
            addr: Ipv6Addr::UNSPECIFIED,
            mac: [0; 6],
            state: NdpState::Incomplete,
            expires_tick: 0,
            retries: 0,
        }
    }
}

/// Maximum neighbor cache entries.
const MAX_NEIGHBORS: usize = 64;

/// Reachable timeout in ticks (30 seconds at 100 Hz).
const REACHABLE_TIMEOUT: u64 = 3000;

/// Stale/delay timeout in ticks (5 seconds).
const DELAY_TIMEOUT: u64 = 500;

/// Maximum solicitation retries.
const MAX_RETRIES: u8 = 3;

/// Neighbor cache table.
pub struct NeighborTable {
    /// Neighbor entries.
    entries: [Option<NeighborEntry>; MAX_NEIGHBORS],
    /// Number of active entries.
    count: usize,
}

impl NeighborTable {
    /// Creates an empty neighbor table.
    pub const fn new() -> Self {
        const NONE: Option<NeighborEntry> = None;
        Self {
            entries: [NONE; MAX_NEIGHBORS],
            count: 0,
        }
    }

    /// Looks up a neighbor by IPv6 address.
    pub fn lookup(&self, addr: &Ipv6Addr) -> Option<&NeighborEntry> {
        self.entries.iter().flatten().find(|e| e.addr == *addr)
    }

    /// Inserts or updates a neighbor entry. Returns the slot index.
    pub fn insert(&mut self, addr: Ipv6Addr, mac: [u8; 6], current_tick: u64) -> Result<usize> {
        // Update existing entry if present.
        for (i, slot) in self.entries.iter_mut().enumerate() {
            if let Some(entry) = slot {
                if entry.addr == addr {
                    entry.mac = mac;
                    entry.state = NdpState::Reachable;
                    entry.expires_tick = current_tick + REACHABLE_TIMEOUT;
                    entry.retries = 0;
                    return Ok(i);
                }
            }
        }
        // Find free slot.
        let idx = self
            .entries
            .iter()
            .position(|e| e.is_none())
            .ok_or(Error::OutOfMemory)?;
        self.entries[idx] = Some(NeighborEntry {
            addr,
            mac,
            state: NdpState::Reachable,
            expires_tick: current_tick + REACHABLE_TIMEOUT,
            retries: 0,
        });
        self.count += 1;
        Ok(idx)
    }

    /// Inserts an incomplete entry (address resolution started).
    pub fn insert_incomplete(&mut self, addr: Ipv6Addr, current_tick: u64) -> Result<usize> {
        // Check if already present.
        for (i, slot) in self.entries.iter().enumerate() {
            if let Some(entry) = slot {
                if entry.addr == addr {
                    return Ok(i);
                }
            }
        }
        let idx = self
            .entries
            .iter()
            .position(|e| e.is_none())
            .ok_or(Error::OutOfMemory)?;
        self.entries[idx] = Some(NeighborEntry {
            addr,
            mac: [0; 6],
            state: NdpState::Incomplete,
            expires_tick: current_tick + DELAY_TIMEOUT,
            retries: 0,
        });
        self.count += 1;
        Ok(idx)
    }

    /// Removes a neighbor entry by address.
    pub fn remove(&mut self, addr: &Ipv6Addr) -> bool {
        for slot in &mut self.entries {
            if let Some(entry) = slot {
                if entry.addr == *addr {
                    *slot = None;
                    self.count -= 1;
                    return true;
                }
            }
        }
        false
    }

    /// Expires stale entries and advances states based on the current tick.
    pub fn expire(&mut self, current_tick: u64) {
        for slot in &mut self.entries {
            let should_remove = if let Some(entry) = slot {
                if current_tick >= entry.expires_tick {
                    match entry.state {
                        NdpState::Reachable => {
                            entry.state = NdpState::Stale;
                            entry.expires_tick = current_tick + DELAY_TIMEOUT * 60;
                            false
                        }
                        NdpState::Delay => {
                            entry.state = NdpState::Probe;
                            entry.expires_tick = current_tick + DELAY_TIMEOUT;
                            entry.retries = 0;
                            false
                        }
                        NdpState::Probe => entry.retries >= MAX_RETRIES,
                        NdpState::Incomplete => entry.retries >= MAX_RETRIES,
                        NdpState::Stale => true,
                    }
                } else {
                    false
                }
            } else {
                false
            };
            if should_remove {
                *slot = None;
                self.count = self.count.saturating_sub(1);
            }
        }
    }

    /// Returns the number of active entries.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Returns `true` if empty.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
}

impl Default for NeighborTable {
    fn default() -> Self {
        Self::new()
    }
}

// =========================================================================
// IPv6 Stack
// =========================================================================

/// Maximum packet buffer size.
const MAX_PKT_BUF: usize = 1500;

/// Maximum NDP options per message.
const MAX_NDP_OPTIONS: usize = 8;

/// IPv6 network stack with NDP support.
pub struct Ipv6Stack {
    /// Our link-local address.
    pub local_addr: Ipv6Addr,
    /// Our MAC address.
    pub local_mac: [u8; 6],
    /// Neighbor cache.
    pub neighbors: NeighborTable,
    /// Default hop limit.
    pub default_hop_limit: u8,
    /// Current tick (for neighbor expiry).
    pub current_tick: u64,
}

impl Ipv6Stack {
    /// Creates a new IPv6 stack.
    pub fn new(local_addr: Ipv6Addr, local_mac: [u8; 6]) -> Self {
        Self {
            local_addr,
            local_mac,
            neighbors: NeighborTable::new(),
            default_hop_limit: 64,
            current_tick: 0,
        }
    }

    /// Processes an incoming IPv6 packet.
    ///
    /// Returns `Ok(Some(response_buf, response_len))` if a response should be sent,
    /// or `Ok(None)` if no response is needed.
    pub fn process_packet(
        &mut self,
        data: &[u8],
        response: &mut [u8; MAX_PKT_BUF],
    ) -> Result<Option<usize>> {
        let hdr = Ipv6Header::parse(data)?;
        let payload_start = IPV6_HEADER_LEN;
        let payload_end = payload_start + hdr.payload_length as usize;
        if payload_end > data.len() {
            return Err(Error::InvalidArgument);
        }
        let payload = &data[payload_start..payload_end];

        match NextHeader::from_u8(hdr.next_header) {
            Some(NextHeader::Icmpv6) => self.handle_icmpv6(&hdr, payload, response),
            _ => Ok(None),
        }
    }

    /// Handles an ICMPv6 message.
    fn handle_icmpv6(
        &mut self,
        ip_hdr: &Ipv6Header,
        payload: &[u8],
        response: &mut [u8; MAX_PKT_BUF],
    ) -> Result<Option<usize>> {
        let icmp = Icmpv6Header::parse(payload)?;

        match Icmpv6Type::from_u8(icmp.icmp_type) {
            Some(Icmpv6Type::EchoRequest) => self.handle_echo_request(ip_hdr, payload, response),
            Some(Icmpv6Type::NeighborSolicitation) => {
                self.handle_neighbor_solicitation(ip_hdr, payload, response)
            }
            Some(Icmpv6Type::NeighborAdvertisement) => {
                self.handle_neighbor_advertisement(payload)?;
                Ok(None)
            }
            _ => Ok(None),
        }
    }

    /// Responds to an ICMPv6 Echo Request with an Echo Reply.
    fn handle_echo_request(
        &self,
        ip_hdr: &Ipv6Header,
        payload: &[u8],
        response: &mut [u8; MAX_PKT_BUF],
    ) -> Result<Option<usize>> {
        if payload.len() < ICMPV6_HEADER_LEN + 4 {
            return Err(Error::InvalidArgument);
        }
        let echo_payload = &payload[ICMPV6_HEADER_LEN..];
        let reply_payload_len = ICMPV6_HEADER_LEN + echo_payload.len();
        let total_len = IPV6_HEADER_LEN + reply_payload_len;
        if total_len > MAX_PKT_BUF {
            return Err(Error::InvalidArgument);
        }

        // Build IPv6 header.
        let reply_hdr = Ipv6Header::new(
            self.local_addr,
            Ipv6Addr::from_bytes(ip_hdr.src),
            NextHeader::Icmpv6 as u8,
            self.default_hop_limit,
            reply_payload_len as u16,
        );
        reply_hdr.serialize(&mut response[..IPV6_HEADER_LEN])?;

        // Build ICMPv6 Echo Reply.
        let icmp_start = IPV6_HEADER_LEN;
        response[icmp_start] = Icmpv6Type::EchoReply as u8;
        response[icmp_start + 1] = 0; // code
        response[icmp_start + 2] = 0; // checksum placeholder
        response[icmp_start + 3] = 0;
        response[icmp_start + ICMPV6_HEADER_LEN..icmp_start + reply_payload_len]
            .copy_from_slice(echo_payload);

        // Compute checksum.
        let checksum = icmpv6_checksum(
            &self.local_addr,
            &Ipv6Addr::from_bytes(ip_hdr.src),
            &response[icmp_start..icmp_start + reply_payload_len],
        );
        let ck_bytes = checksum.to_be_bytes();
        response[icmp_start + 2] = ck_bytes[0];
        response[icmp_start + 3] = ck_bytes[1];

        Ok(Some(total_len))
    }

    /// Handles a Neighbor Solicitation (NS) message.
    fn handle_neighbor_solicitation(
        &mut self,
        ip_hdr: &Ipv6Header,
        payload: &[u8],
        response: &mut [u8; MAX_PKT_BUF],
    ) -> Result<Option<usize>> {
        // NS: type(1) + code(1) + checksum(2) + reserved(4) + target(16) + options
        if payload.len() < ICMPV6_HEADER_LEN + 4 + 16 {
            return Err(Error::InvalidArgument);
        }
        let mut target_bytes = [0u8; 16];
        target_bytes.copy_from_slice(&payload[8..24]);
        let target = Ipv6Addr::from_bytes(target_bytes);

        // Only respond if the target is our address.
        if target != self.local_addr {
            return Ok(None);
        }

        // Parse options to learn source MAC.
        let opt_data = &payload[24..];
        let mut options = [NdpOption::Mtu { mtu: 0 }; MAX_NDP_OPTIONS];
        let opt_count = parse_ndp_options(opt_data, &mut options, MAX_NDP_OPTIONS);

        // Learn the source's MAC if provided.
        let src_addr = Ipv6Addr::from_bytes(ip_hdr.src);
        for opt in &options[..opt_count] {
            if let NdpOption::LinkLayerAddr {
                kind: NdpOptionType::SourceLinkLayerAddr,
                addr,
            } = opt
            {
                if !src_addr.is_unspecified() {
                    let _ = self.neighbors.insert(src_addr, *addr, self.current_tick);
                }
            }
        }

        // Send Neighbor Advertisement (NA).
        self.build_neighbor_advertisement(
            &src_addr,
            &self.local_addr,
            true, // solicited
            true, // override
            response,
        )
    }

    /// Handles a Neighbor Advertisement (NA) message — updates neighbor cache.
    fn handle_neighbor_advertisement(&mut self, payload: &[u8]) -> Result<()> {
        if payload.len() < ICMPV6_HEADER_LEN + 4 + 16 {
            return Err(Error::InvalidArgument);
        }
        let mut target_bytes = [0u8; 16];
        target_bytes.copy_from_slice(&payload[8..24]);
        let target = Ipv6Addr::from_bytes(target_bytes);

        // Parse options for target link-layer address.
        let opt_data = &payload[24..];
        let mut options = [NdpOption::Mtu { mtu: 0 }; MAX_NDP_OPTIONS];
        let opt_count = parse_ndp_options(opt_data, &mut options, MAX_NDP_OPTIONS);

        for opt in &options[..opt_count] {
            if let NdpOption::LinkLayerAddr {
                kind: NdpOptionType::TargetLinkLayerAddr,
                addr,
            } = opt
            {
                let _ = self.neighbors.insert(target, *addr, self.current_tick);
            }
        }
        Ok(())
    }

    /// Builds a Neighbor Advertisement packet.
    fn build_neighbor_advertisement(
        &self,
        dst_addr: &Ipv6Addr,
        target: &Ipv6Addr,
        solicited: bool,
        override_flag: bool,
        response: &mut [u8; MAX_PKT_BUF],
    ) -> Result<Option<usize>> {
        // NA: ICMPv6 header(4) + flags+reserved(4) + target(16) + option(8) = 32
        let icmpv6_len = 4 + 4 + 16 + 8;
        let total_len = IPV6_HEADER_LEN + icmpv6_len;
        if total_len > MAX_PKT_BUF {
            return Err(Error::InvalidArgument);
        }

        let real_dst = if dst_addr.is_unspecified() {
            Ipv6Addr::ALL_NODES
        } else {
            *dst_addr
        };

        let ip = Ipv6Header::new(
            self.local_addr,
            real_dst,
            NextHeader::Icmpv6 as u8,
            255,
            icmpv6_len as u16,
        );
        ip.serialize(&mut response[..IPV6_HEADER_LEN])?;

        let s = IPV6_HEADER_LEN;
        // ICMPv6 type + code
        response[s] = Icmpv6Type::NeighborAdvertisement as u8;
        response[s + 1] = 0;
        response[s + 2] = 0; // checksum placeholder
        response[s + 3] = 0;
        // Flags: R(0), S(solicited), O(override) in top 3 bits of byte
        let mut flags: u8 = 0;
        if solicited {
            flags |= 0x40;
        }
        if override_flag {
            flags |= 0x20;
        }
        response[s + 4] = flags;
        response[s + 5] = 0;
        response[s + 6] = 0;
        response[s + 7] = 0;
        // Target address
        response[s + 8..s + 24].copy_from_slice(&target.to_bytes());
        // Option: Target Link-Layer Address (type=2, len=1(8 bytes))
        response[s + 24] = NdpOptionType::TargetLinkLayerAddr as u8;
        response[s + 25] = 1; // length in units of 8 bytes
        response[s + 26..s + 32].copy_from_slice(&self.local_mac);

        // Checksum
        let checksum = icmpv6_checksum(&self.local_addr, &real_dst, &response[s..s + icmpv6_len]);
        let ck = checksum.to_be_bytes();
        response[s + 2] = ck[0];
        response[s + 3] = ck[1];

        Ok(Some(total_len))
    }

    /// Builds a Neighbor Solicitation (NS) packet for address resolution.
    pub fn build_neighbor_solicitation(
        &mut self,
        target: &Ipv6Addr,
        response: &mut [u8; MAX_PKT_BUF],
    ) -> Result<usize> {
        let _ = self.neighbors.insert_incomplete(*target, self.current_tick);

        // NS: ICMPv6 header(4) + reserved(4) + target(16) + option(8) = 32
        let icmpv6_len = 4 + 4 + 16 + 8;
        let total_len = IPV6_HEADER_LEN + icmpv6_len;
        if total_len > MAX_PKT_BUF {
            return Err(Error::InvalidArgument);
        }

        let dst = target.solicited_node();
        let ip = Ipv6Header::new(
            self.local_addr,
            dst,
            NextHeader::Icmpv6 as u8,
            255,
            icmpv6_len as u16,
        );
        ip.serialize(&mut response[..IPV6_HEADER_LEN])?;

        let s = IPV6_HEADER_LEN;
        response[s] = Icmpv6Type::NeighborSolicitation as u8;
        response[s + 1] = 0;
        response[s + 2] = 0; // checksum placeholder
        response[s + 3] = 0;
        // Reserved
        response[s + 4..s + 8].fill(0);
        // Target address
        response[s + 8..s + 24].copy_from_slice(&target.to_bytes());
        // Option: Source Link-Layer Address (type=1, len=1)
        response[s + 24] = NdpOptionType::SourceLinkLayerAddr as u8;
        response[s + 25] = 1;
        response[s + 26..s + 32].copy_from_slice(&self.local_mac);

        // Checksum
        let checksum = icmpv6_checksum(&self.local_addr, &dst, &response[s..s + icmpv6_len]);
        let ck = checksum.to_be_bytes();
        response[s + 2] = ck[0];
        response[s + 3] = ck[1];

        Ok(total_len)
    }

    /// Advances the tick counter and expires stale neighbor entries.
    pub fn tick(&mut self) {
        self.current_tick += 1;
        self.neighbors.expire(self.current_tick);
    }
}

impl Default for Ipv6Stack {
    fn default() -> Self {
        Self::new(Ipv6Addr::UNSPECIFIED, [0; 6])
    }
}

// =========================================================================
// ICMPv6 Checksum (RFC 2460 §8.1)
// =========================================================================

/// Computes the ICMPv6 checksum using the IPv6 pseudo-header.
fn icmpv6_checksum(src: &Ipv6Addr, dst: &Ipv6Addr, icmpv6_data: &[u8]) -> u16 {
    let mut sum: u32 = 0;

    // Pseudo-header: src(16) + dst(16) + upper-layer length(4) + zeros(3) + next-header(1)
    let src_bytes = src.to_bytes();
    let dst_bytes = dst.to_bytes();

    // Source address
    for chunk in src_bytes.chunks(2) {
        sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
    }
    // Destination address
    for chunk in dst_bytes.chunks(2) {
        sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
    }
    // Upper-layer length
    let length = icmpv6_data.len() as u32;
    sum += (length >> 16) & 0xffff;
    sum += length & 0xffff;
    // Next header (ICMPv6 = 58)
    sum += NextHeader::Icmpv6 as u32;

    // ICMPv6 data (with checksum field zeroed conceptually — caller should zero it before)
    let mut i = 0;
    while i + 1 < icmpv6_data.len() {
        // Skip the checksum field at offset 2-3.
        if i == 2 {
            i += 2;
            continue;
        }
        sum += u16::from_be_bytes([icmpv6_data[i], icmpv6_data[i + 1]]) as u32;
        i += 2;
    }
    // Odd trailing byte.
    if i < icmpv6_data.len() {
        sum += (icmpv6_data[i] as u32) << 8;
    }

    // Fold 32-bit sum to 16 bits.
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}
