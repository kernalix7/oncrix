// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Foundation of the TCP/IP network stack for the ONCRIX kernel.
//!
//! Provides Ethernet frame parsing, ARP table management, IPv4 header
//! parsing with checksum verification, ICMP echo (ping) handling, and
//! a top-level [`NetworkStack`] that dispatches incoming packets to
//! the appropriate protocol handler.
//!
//! All multi-byte network fields use network byte order (big-endian)
//! via [`u16::from_be_bytes`] / [`u16::to_be_bytes`].
//!
//! # Supported protocols
//!
//! | Layer     | Protocol          | Status            |
//! |-----------|-------------------|-------------------|
//! | L2        | Ethernet II       | Parse + generate  |
//! | L2.5      | ARP (IPv4/Ether)  | Request + reply   |
//! | L3        | IPv4              | Parse + checksum  |
//! | L3        | ICMP              | Echo reply (ping) |
//! | L4        | TCP               | Stateless admit  |
//! | L4        | UDP               | Rx checksum check |

use crate::ipv6::{Ipv6Addr, Ipv6Stack, MAX_PKT_BUF};
use oncrix_lib::{Error, Result};

// =========================================================================
// Ethernet
// =========================================================================

/// Ethernet header size in bytes (6 dst + 6 src + 2 type).
const ETHER_HEADER_LEN: usize = 14;

/// EtherType value for IPv4 (0x0800).
pub const ETHER_TYPE_IPV4: u16 = 0x0800;

/// EtherType value for ARP (0x0806).
pub const ETHER_TYPE_ARP: u16 = 0x0806;

/// EtherType value for IPv6 (0x86DD).
pub const ETHER_TYPE_IPV6: u16 = 0x86DD;

/// Parsed Ethernet II frame header.
///
/// Layout matches the on-wire format: destination MAC, source MAC,
/// and a two-byte EtherType field in network byte order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct EtherHeader {
    /// Destination MAC address (6 bytes).
    pub dst_mac: [u8; 6],
    /// Source MAC address (6 bytes).
    pub src_mac: [u8; 6],
    /// EtherType in host byte order.
    pub ether_type: u16,
}

/// Parse an Ethernet II frame from raw bytes.
///
/// Returns the parsed [`EtherHeader`] and a slice referencing the
/// payload (everything after the 14-byte header).
///
/// # Errors
///
/// Returns [`Error::InvalidArgument`] if `data` is shorter than
/// [`ETHER_HEADER_LEN`] (14 bytes).
pub fn parse_ether(data: &[u8]) -> Result<(EtherHeader, &[u8])> {
    if data.len() < ETHER_HEADER_LEN {
        return Err(Error::InvalidArgument);
    }

    let mut dst_mac = [0u8; 6];
    dst_mac.copy_from_slice(&data[..6]);

    let mut src_mac = [0u8; 6];
    src_mac.copy_from_slice(&data[6..12]);

    let ether_type = u16::from_be_bytes([data[12], data[13]]);

    let header = EtherHeader {
        dst_mac,
        src_mac,
        ether_type,
    };

    Ok((header, &data[ETHER_HEADER_LEN..]))
}

/// Write an Ethernet II header into `buf` and return the number of
/// bytes written (always [`ETHER_HEADER_LEN`] on success).
///
/// # Errors
///
/// Returns [`Error::InvalidArgument`] if `buf` is too small.
fn write_ether(
    buf: &mut [u8],
    dst_mac: &[u8; 6],
    src_mac: &[u8; 6],
    ether_type: u16,
) -> Result<usize> {
    if buf.len() < ETHER_HEADER_LEN {
        return Err(Error::InvalidArgument);
    }
    buf[..6].copy_from_slice(dst_mac);
    buf[6..12].copy_from_slice(src_mac);
    let et = ether_type.to_be_bytes();
    buf[12] = et[0];
    buf[13] = et[1];
    Ok(ETHER_HEADER_LEN)
}

// =========================================================================
// ARP
// =========================================================================

/// ARP packet size for IPv4-over-Ethernet (28 bytes).
const ARP_PACKET_LEN: usize = 28;

/// ARP operation: request.
pub const ARP_REQUEST: u16 = 1;

/// ARP operation: reply.
pub const ARP_REPLY: u16 = 2;

/// Hardware type for Ethernet in ARP.
const ARP_HTYPE_ETHERNET: u16 = 1;

/// Protocol type for IPv4 in ARP.
const ARP_PTYPE_IPV4: u16 = 0x0800;

/// Hardware address length for Ethernet in ARP (6 bytes).
const ARP_HLEN_ETHERNET: u8 = 6;

/// Protocol address length for IPv4 in ARP (4 bytes).
const ARP_PLEN_IPV4: u8 = 4;

/// ARP packet for IPv4-over-Ethernet.
///
/// Fields are stored in host byte order after parsing; serialisation
/// converts back to network byte order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct ArpPacket {
    /// Hardware type (1 = Ethernet).
    pub htype: u16,
    /// Protocol type (0x0800 = IPv4).
    pub ptype: u16,
    /// Hardware address length (6 for Ethernet).
    pub hlen: u8,
    /// Protocol address length (4 for IPv4).
    pub plen: u8,
    /// Operation (1 = request, 2 = reply).
    pub oper: u16,
    /// Sender hardware (MAC) address.
    pub sha: [u8; 6],
    /// Sender protocol (IP) address.
    pub spa: [u8; 4],
    /// Target hardware (MAC) address.
    pub tha: [u8; 6],
    /// Target protocol (IP) address.
    pub tpa: [u8; 4],
}

/// Parse an ARP packet from the Ethernet payload.
///
/// # Errors
///
/// Returns [`Error::InvalidArgument`] if `data` is shorter than
/// [`ARP_PACKET_LEN`] (28 bytes).
fn parse_arp(data: &[u8]) -> Result<ArpPacket> {
    if data.len() < ARP_PACKET_LEN {
        return Err(Error::InvalidArgument);
    }
    let htype = u16::from_be_bytes([data[0], data[1]]);
    let ptype = u16::from_be_bytes([data[2], data[3]]);
    let hlen = data[4];
    let plen = data[5];
    let oper = u16::from_be_bytes([data[6], data[7]]);

    let mut sha = [0u8; 6];
    sha.copy_from_slice(&data[8..14]);
    let mut spa = [0u8; 4];
    spa.copy_from_slice(&data[14..18]);
    let mut tha = [0u8; 6];
    tha.copy_from_slice(&data[18..24]);
    let mut tpa = [0u8; 4];
    tpa.copy_from_slice(&data[24..28]);

    Ok(ArpPacket {
        htype,
        ptype,
        hlen,
        plen,
        oper,
        sha,
        spa,
        tha,
        tpa,
    })
}

/// Serialise an [`ArpPacket`] into `buf`.
///
/// # Errors
///
/// Returns [`Error::InvalidArgument`] if `buf` is too small.
fn write_arp(buf: &mut [u8], pkt: &ArpPacket) -> Result<usize> {
    if buf.len() < ARP_PACKET_LEN {
        return Err(Error::InvalidArgument);
    }
    let ht = pkt.htype.to_be_bytes();
    buf[0] = ht[0];
    buf[1] = ht[1];
    let pt = pkt.ptype.to_be_bytes();
    buf[2] = pt[0];
    buf[3] = pt[1];
    buf[4] = pkt.hlen;
    buf[5] = pkt.plen;
    let op = pkt.oper.to_be_bytes();
    buf[6] = op[0];
    buf[7] = op[1];
    buf[8..14].copy_from_slice(&pkt.sha);
    buf[14..18].copy_from_slice(&pkt.spa);
    buf[18..24].copy_from_slice(&pkt.tha);
    buf[24..28].copy_from_slice(&pkt.tpa);
    Ok(ARP_PACKET_LEN)
}

// ---------------------------------------------------------------------------
// ARP table
// ---------------------------------------------------------------------------

/// Maximum number of entries in the ARP table.
const ARP_TABLE_SIZE: usize = 64;

/// A single ARP table entry mapping an IPv4 address to a MAC address.
#[derive(Debug, Clone, Copy, Default)]
struct ArpEntry {
    /// IPv4 address.
    ip: [u8; 4],
    /// Corresponding MAC address.
    mac: [u8; 6],
    /// Whether this entry is currently valid.
    valid: bool,
}

/// ARP cache mapping IPv4 addresses to Ethernet MAC addresses.
///
/// Fixed-size table with [`ARP_TABLE_SIZE`] (64) entries.  Insertion
/// overwrites the first invalid (empty) slot; if the table is full
/// the oldest valid entry (lowest index) is evicted.
pub struct ArpTable {
    /// Fixed-size array of ARP entries.
    entries: [ArpEntry; ARP_TABLE_SIZE],
}

impl Default for ArpTable {
    fn default() -> Self {
        Self::new()
    }
}

impl ArpTable {
    /// Create an empty ARP table.
    pub const fn new() -> Self {
        Self {
            entries: [ArpEntry {
                ip: [0; 4],
                mac: [0; 6],
                valid: false,
            }; ARP_TABLE_SIZE],
        }
    }

    /// Look up the MAC address for a given IPv4 address.
    ///
    /// Returns `Some(&mac)` if the entry exists, `None` otherwise.
    pub fn lookup(&self, ip: &[u8; 4]) -> Option<[u8; 6]> {
        for entry in &self.entries {
            if entry.valid && entry.ip == *ip {
                return Some(entry.mac);
            }
        }
        None
    }

    /// Insert or update an ARP entry.
    ///
    /// If an entry for the given IP already exists, its MAC is
    /// updated.  Otherwise the first free slot is used.  If the
    /// table is full, slot 0 is evicted.
    pub fn insert(&mut self, ip: [u8; 4], mac: [u8; 6]) {
        // Update existing entry if present.
        for entry in &mut self.entries {
            if entry.valid && entry.ip == ip {
                entry.mac = mac;
                return;
            }
        }
        // Find first free slot.
        for entry in &mut self.entries {
            if !entry.valid {
                entry.ip = ip;
                entry.mac = mac;
                entry.valid = true;
                return;
            }
        }
        // Table full — evict slot 0.
        self.entries[0] = ArpEntry {
            ip,
            mac,
            valid: true,
        };
    }

    /// Remove the entry for a given IPv4 address.
    ///
    /// Returns `true` if an entry was removed, `false` if no
    /// matching entry existed.
    pub fn remove(&mut self, ip: &[u8; 4]) -> bool {
        for entry in &mut self.entries {
            if entry.valid && entry.ip == *ip {
                entry.valid = false;
                return true;
            }
        }
        false
    }
}

// =========================================================================
// IPv4
// =========================================================================

/// Minimum IPv4 header size in bytes (no options).
const IPV4_HEADER_MIN_LEN: usize = 20;

/// IP protocol number for ICMP.
pub const PROTO_ICMP: u8 = 1;

/// IP protocol number for TCP.
pub const PROTO_TCP: u8 = 6;

/// IP protocol number for UDP.
pub const PROTO_UDP: u8 = 17;

/// IP protocol number for GRE (RFC 2784).
pub const PROTO_GRE: u8 = 47;

/// IP protocol number for SCTP (RFC 9260).
pub const PROTO_SCTP: u8 = 132;

/// Parsed IPv4 header.
///
/// Stored in host byte order; the raw on-wire format uses
/// big-endian for multi-byte fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct Ipv4Header {
    /// Version (upper 4 bits) and IHL (lower 4 bits).
    pub version_ihl: u8,
    /// Type of service / DSCP + ECN.
    pub tos: u8,
    /// Total length of the IP datagram (header + payload).
    pub total_len: u16,
    /// Identification field.
    pub id: u16,
    /// Flags (upper 3 bits) and fragment offset (lower 13 bits).
    pub flags_frag: u16,
    /// Time to live.
    pub ttl: u8,
    /// Upper-layer protocol number.
    pub protocol: u8,
    /// Header checksum.
    pub checksum: u16,
    /// Source IPv4 address.
    pub src_addr: [u8; 4],
    /// Destination IPv4 address.
    pub dst_addr: [u8; 4],
}

impl Ipv4Header {
    /// Return the IP version (should be 4).
    pub fn version(&self) -> u8 {
        self.version_ihl >> 4
    }

    /// Return the Internet Header Length in 32-bit words.
    pub fn ihl(&self) -> u8 {
        self.version_ihl & 0x0F
    }

    /// Return the header length in bytes.
    pub fn header_len(&self) -> usize {
        (self.ihl() as usize) * 4
    }
}

/// Parse an IPv4 header from raw bytes.
///
/// Validates that the version field is 4 and that the declared
/// header length (IHL) fits within the supplied data.  Returns the
/// parsed [`Ipv4Header`] and the payload slice.
///
/// # Errors
///
/// - [`Error::InvalidArgument`] if `data` is shorter than the
///   minimum IPv4 header (20 bytes), the version is not 4, the
///   IHL-declared header length exceeds the available data, or the
///   declared `total_len` is below the header length or beyond the
///   available data.
pub fn parse_ipv4(data: &[u8]) -> Result<(Ipv4Header, &[u8])> {
    if data.len() < IPV4_HEADER_MIN_LEN {
        return Err(Error::InvalidArgument);
    }

    let version_ihl = data[0];
    let version = version_ihl >> 4;
    if version != 4 {
        return Err(Error::InvalidArgument);
    }

    let ihl = (version_ihl & 0x0F) as usize;
    let hdr_len = ihl * 4;
    if hdr_len < IPV4_HEADER_MIN_LEN || data.len() < hdr_len {
        return Err(Error::InvalidArgument);
    }

    let header = Ipv4Header {
        version_ihl,
        tos: data[1],
        total_len: u16::from_be_bytes([data[2], data[3]]),
        id: u16::from_be_bytes([data[4], data[5]]),
        flags_frag: u16::from_be_bytes([data[6], data[7]]),
        ttl: data[8],
        protocol: data[9],
        checksum: u16::from_be_bytes([data[10], data[11]]),
        src_addr: [data[12], data[13], data[14], data[15]],
        dst_addr: [data[16], data[17], data[18], data[19]],
    };

    // SECURITY: `total_len` is attacker-controlled. Reject a datagram that
    // declares a length below its own header or beyond the received frame
    // rather than clamping, so bytes outside the declared datagram (e.g.
    // trailing Ethernet padding) can never reach protocol dispatch.
    let total = header.total_len as usize;
    if total < hdr_len || total > data.len() {
        return Err(Error::InvalidArgument);
    }

    Ok((header, &data[hdr_len..total]))
}

/// Compute the RFC 1071 internet checksum over `header` bytes.
///
/// The input should be the raw IPv4 header bytes (with the checksum
/// field set to zero for verification or computation).  Returns the
/// one's-complement checksum in host byte order.
pub fn ipv4_checksum(header: &[u8]) -> u16 {
    let mut sum: u32 = 0;

    // Sum 16-bit words.
    let mut i = 0;
    while i + 1 < header.len() {
        let word = u16::from_be_bytes([header[i], header[i + 1]]);
        sum = sum.wrapping_add(word as u32);
        i += 2;
    }

    // If odd length, pad the last byte with zero.
    if i < header.len() {
        sum = sum.wrapping_add((header[i] as u32) << 8);
    }

    // Fold 32-bit sum to 16 bits.
    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    !(sum as u16)
}

/// Serialise an [`Ipv4Header`] into `buf` and recompute the
/// checksum.
///
/// # Errors
///
/// Returns [`Error::InvalidArgument`] if `buf` is too small.
fn write_ipv4(buf: &mut [u8], hdr: &Ipv4Header) -> Result<usize> {
    let hdr_len = hdr.header_len();
    if buf.len() < hdr_len || hdr_len < IPV4_HEADER_MIN_LEN {
        return Err(Error::InvalidArgument);
    }
    buf[0] = hdr.version_ihl;
    buf[1] = hdr.tos;
    let tl = hdr.total_len.to_be_bytes();
    buf[2] = tl[0];
    buf[3] = tl[1];
    let id = hdr.id.to_be_bytes();
    buf[4] = id[0];
    buf[5] = id[1];
    let ff = hdr.flags_frag.to_be_bytes();
    buf[6] = ff[0];
    buf[7] = ff[1];
    buf[8] = hdr.ttl;
    buf[9] = hdr.protocol;
    // Checksum placeholder — filled after serialisation.
    buf[10] = 0;
    buf[11] = 0;
    buf[12..16].copy_from_slice(&hdr.src_addr);
    buf[16..20].copy_from_slice(&hdr.dst_addr);

    // Compute and write checksum.
    let cksum = ipv4_checksum(&buf[..hdr_len]);
    let ck = cksum.to_be_bytes();
    buf[10] = ck[0];
    buf[11] = ck[1];

    Ok(hdr_len)
}

// =========================================================================
// ICMP
// =========================================================================

/// ICMP header size in bytes.
const ICMP_HEADER_LEN: usize = 8;

/// ICMP type: echo reply.
pub const ICMP_ECHO_REPLY: u8 = 0;

/// ICMP type: echo request (ping).
pub const ICMP_ECHO_REQUEST: u8 = 8;

/// Parsed ICMP header.
///
/// The `rest` field contains the identifier and sequence number
/// for echo request/reply messages (or other type-specific data).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct IcmpHeader {
    /// ICMP message type.
    pub icmp_type: u8,
    /// Type-specific sub-code.
    pub code: u8,
    /// Checksum over the entire ICMP message.
    pub checksum: u16,
    /// Remaining 4 bytes (type-specific; for echo: id + seq).
    pub rest: u32,
}

/// Handle an incoming ICMP packet and, if it is an echo request,
/// build an echo reply in `reply_buf`.
///
/// Returns the total size of the reply packet (ICMP header +
/// payload) written to `reply_buf`.
///
/// # Errors
///
/// - [`Error::InvalidArgument`] if `data` is shorter than the ICMP
///   header, has an invalid checksum, or `reply_buf` is too small to
///   hold the reply.
/// - [`Error::NotImplemented`] if the ICMP type is not an echo
///   request.
pub fn handle_icmp(_header: &Ipv4Header, data: &[u8], reply_buf: &mut [u8]) -> Result<usize> {
    if data.len() < ICMP_HEADER_LEN {
        return Err(Error::InvalidArgument);
    }

    // SECURITY: ICMP carries an Internet checksum over the entire
    // message.  Drop corrupt or forged packets before we generate any
    // response; otherwise an attacker can make us answer traffic that
    // the receiver should have discarded at L4.
    if ipv4_checksum(data) != 0 {
        return Err(Error::InvalidArgument);
    }

    let icmp_type = data[0];
    if icmp_type != ICMP_ECHO_REQUEST {
        return Err(Error::NotImplemented);
    }

    let code = data[1];
    let _checksum = u16::from_be_bytes([data[2], data[3]]);
    let rest = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);

    let payload = &data[ICMP_HEADER_LEN..];
    let reply_len = ICMP_HEADER_LEN + payload.len();

    if reply_buf.len() < reply_len {
        return Err(Error::InvalidArgument);
    }

    // Build echo reply: type 0, same code, same id/seq, same
    // payload.
    reply_buf[0] = ICMP_ECHO_REPLY;
    reply_buf[1] = code;
    // Checksum placeholder.
    reply_buf[2] = 0;
    reply_buf[3] = 0;
    let rb = rest.to_be_bytes();
    reply_buf[4] = rb[0];
    reply_buf[5] = rb[1];
    reply_buf[6] = rb[2];
    reply_buf[7] = rb[3];
    reply_buf[ICMP_HEADER_LEN..reply_len].copy_from_slice(payload);

    // Compute ICMP checksum (same algorithm as IP).
    let cksum = ipv4_checksum(&reply_buf[..reply_len]);
    let ck = cksum.to_be_bytes();
    reply_buf[2] = ck[0];
    reply_buf[3] = ck[1];

    Ok(reply_len)
}

// =========================================================================
// NetworkStack
// =========================================================================

/// Top-level network stack aggregating L2/L3 protocol handling.
///
/// Holds the node's own network identity (MAC, IP, gateway, subnet)
/// and an [`ArpTable`] for address resolution.  Incoming frames are
/// dispatched via [`process_packet`](Self::process_packet); outgoing
/// ARP requests can be generated with
/// [`send_arp_request`](Self::send_arp_request).
pub struct NetworkStack {
    /// Local MAC address of this network interface.
    pub local_mac: [u8; 6],
    /// Local IPv4 address.
    pub local_ip: [u8; 4],
    /// Default gateway IPv4 address.
    pub gateway_ip: [u8; 4],
    /// Subnet mask.
    pub subnet_mask: [u8; 4],
    /// ARP cache.
    pub arp_table: ArpTable,
    /// IPv6 stack and NDP neighbor cache.
    pub ipv6: Ipv6Stack,
    /// Count of GRE frames admitted by [`crate::gre::validate_gre_packet`].
    gre_admitted: u64,
    /// Count of GRE frames rejected by [`crate::gre::validate_gre_packet`].
    gre_dropped: u64,
    /// Count of TCP segments admitted by the protocol-6 gate.
    tcp_admitted: u64,
    /// Count of TCP segments rejected by the protocol-6 gate.
    tcp_dropped: u64,
    /// Count of SCTP packets admitted by the protocol-132 gate.
    sctp_admitted: u64,
    /// Count of SCTP packets rejected by the protocol-132 gate.
    sctp_dropped: u64,
}

impl NetworkStack {
    /// Create a new network stack with the given identity.
    ///
    /// The IPv6 identity is not passed in: a node's `fe80::/64` address is
    /// derived from its MAC by RFC 4291 modified EUI-64, so `mac` already
    /// determines it and accepting a second, separately-supplied value would
    /// only allow the two to disagree.
    pub const fn new(mac: [u8; 6], ip: [u8; 4], gateway: [u8; 4], subnet: [u8; 4]) -> Self {
        Self {
            local_mac: mac,
            local_ip: ip,
            gateway_ip: gateway,
            subnet_mask: subnet,
            arp_table: ArpTable::new(),
            ipv6: Ipv6Stack::new(Ipv6Addr::link_local_from_mac(&mac), mac),
            gre_admitted: 0,
            gre_dropped: 0,
            tcp_admitted: 0,
            tcp_dropped: 0,
            sctp_admitted: 0,
            sctp_dropped: 0,
        }
    }

    /// Number of GRE frames admitted by the protocol-47 admission gate.
    pub const fn gre_admitted(&self) -> u64 {
        self.gre_admitted
    }

    /// Number of GRE frames dropped by the protocol-47 admission gate.
    pub const fn gre_dropped(&self) -> u64 {
        self.gre_dropped
    }

    /// Number of TCP segments admitted by the protocol-6 gate.
    pub const fn tcp_admitted(&self) -> u64 {
        self.tcp_admitted
    }

    /// Number of TCP segments dropped by the protocol-6 gate.
    pub const fn tcp_dropped(&self) -> u64 {
        self.tcp_dropped
    }

    /// Number of SCTP packets admitted by the protocol-132 gate.
    pub const fn sctp_admitted(&self) -> u64 {
        self.sctp_admitted
    }

    /// Number of SCTP packets dropped by the protocol-132 gate.
    pub const fn sctp_dropped(&self) -> u64 {
        self.sctp_dropped
    }

    /// Process an incoming Ethernet frame.
    ///
    /// Parses the Ethernet header and dispatches to the appropriate
    /// protocol handler (ARP, IPv4, or IPv6). If a reply is
    /// generated it is written into `reply_buf` as a complete
    /// Ethernet frame and the total frame length is returned.
    ///
    /// Returns `Ok(0)` when the packet is consumed but no reply is
    /// needed. This includes stateless TCP, GRE, and SCTP admission
    /// failures that are intentionally dropped silently.
    ///
    /// # Errors
    ///
    /// Returns an error when link or network-layer parsing fails, UDP
    /// framing or checksum validation fails, a dispatched protocol is
    /// unsupported, or a replying handler cannot encode its response.
    pub fn process_packet(&mut self, data: &[u8], reply_buf: &mut [u8]) -> Result<usize> {
        let (eth, payload) = parse_ether(data)?;

        match eth.ether_type {
            ETHER_TYPE_ARP => self.handle_arp(&eth, payload, reply_buf),
            ETHER_TYPE_IPV4 => self.handle_ipv4(&eth, payload, reply_buf),
            ETHER_TYPE_IPV6 => self.handle_ipv6(&eth, payload, reply_buf),
            _ => Err(Error::NotImplemented),
        }
    }

    /// Build and write an ARP request frame into `buf`.
    ///
    /// The frame asks "who has `target_ip`? tell `local_ip`".
    /// Returns the total frame length written.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `buf` is too small to
    /// hold an Ethernet + ARP frame.
    pub fn send_arp_request(&self, target_ip: &[u8; 4], buf: &mut [u8]) -> Result<usize> {
        let total = ETHER_HEADER_LEN + ARP_PACKET_LEN;
        if buf.len() < total {
            return Err(Error::InvalidArgument);
        }

        // Ethernet broadcast.
        let broadcast_mac = [0xFF; 6];
        let mut offset = write_ether(buf, &broadcast_mac, &self.local_mac, ETHER_TYPE_ARP)?;

        let arp = ArpPacket {
            htype: ARP_HTYPE_ETHERNET,
            ptype: ARP_PTYPE_IPV4,
            hlen: 6,
            plen: 4,
            oper: ARP_REQUEST,
            sha: self.local_mac,
            spa: self.local_ip,
            tha: [0; 6],
            tpa: *target_ip,
        };

        offset += write_arp(&mut buf[offset..], &arp)?;
        Ok(offset)
    }

    // -- private handlers -------------------------------------------------

    /// Handle an incoming ARP packet.
    ///
    /// For ARP requests targeting our IP, sends a reply.  Cache
    /// learning follows the RFC 826 merge-flag rule (see below).
    /// Returns the reply frame length, or 0 if no reply is needed.
    fn handle_arp(
        &mut self,
        eth: &EtherHeader,
        payload: &[u8],
        reply_buf: &mut [u8],
    ) -> Result<usize> {
        let arp = parse_arp(payload)?;

        // SECURITY (F3): reject anything that is not IPv4-over-Ethernet
        // before trusting the fixed 28-byte layout. A frame with a
        // different htype/ptype/hlen/plen is not addressed by this
        // handler's address model and must be dropped, not parsed as if
        // the 4-byte `spa`/`tpa` and 6-byte `sha`/`tha` offsets applied.
        if arp.htype != ARP_HTYPE_ETHERNET
            || arp.ptype != ARP_PTYPE_IPV4
            || arp.hlen != ARP_HLEN_ETHERNET
            || arp.plen != ARP_PLEN_IPV4
        {
            return Ok(0);
        }

        // SECURITY (F1): ARP cache poisoning prevention per RFC 826
        // merge-flag semantics. An unsolicited ARP from any on-link host
        // must NOT be allowed to create or hijack a mapping (e.g. the
        // gateway), which would enable MITM. The rule is:
        //   - If we already have an entry for `arp.spa`, refresh its MAC
        //     (this is the legitimate "merge" update; `insert` updates
        //     in place when the IP is already present).
        //   - Otherwise, only create a NEW entry when the packet is
        //     addressed to us (`arp.tpa == self.local_ip`), i.e. it is a
        //     solicited/targeted ARP that we asked for or that targets us.
        //   - Otherwise do not learn anything from this packet.
        let targeted = arp.tpa == self.local_ip;
        if self.arp_table.lookup(&arp.spa).is_some() {
            // Existing entry: refresh the MAC (merge flag = true).
            self.arp_table.insert(arp.spa, arp.sha);
        } else if targeted {
            // New entry only when the ARP is addressed to us.
            self.arp_table.insert(arp.spa, arp.sha);
        }
        // Else: unsolicited, non-targeted, unknown sender -> do NOT learn.

        match arp.oper {
            ARP_REQUEST => {
                if arp.tpa != self.local_ip {
                    // Not for us.
                    return Ok(0);
                }

                // Build ARP reply.
                let total = ETHER_HEADER_LEN + ARP_PACKET_LEN;
                if reply_buf.len() < total {
                    return Err(Error::InvalidArgument);
                }

                let mut offset =
                    write_ether(reply_buf, &eth.src_mac, &self.local_mac, ETHER_TYPE_ARP)?;

                let reply = ArpPacket {
                    htype: ARP_HTYPE_ETHERNET,
                    ptype: ARP_PTYPE_IPV4,
                    hlen: 6,
                    plen: 4,
                    oper: ARP_REPLY,
                    sha: self.local_mac,
                    spa: self.local_ip,
                    tha: arp.sha,
                    tpa: arp.spa,
                };
                offset += write_arp(&mut reply_buf[offset..], &reply)?;
                Ok(offset)
            }
            ARP_REPLY => {
                // Cache learning (if any) was handled above under the
                // RFC 826 merge-flag rule; nothing to reply to.
                Ok(0)
            }
            _ => Ok(0),
        }
    }

    /// Handle an incoming IPv4 packet.
    ///
    /// Dispatches by IP protocol after verifying the IPv4 header checksum and
    /// that the datagram is addressed to us: ICMP echo requests are answered
    /// (returning the reply frame length), TCP segments pass a stateless
    /// fragment, framing, and checksum admission gate, UDP datagrams pass a
    /// checksum and per-port framing admission gate, GRE (protocol 47) is
    /// validated with C-bit checksum verification, and SCTP (protocol 132)
    /// passes a stateless CRC32c and chunk-chain gate. Only ICMP produces a
    /// reply; TCP, UDP, GRE, and SCTP are consumed and return `Ok(0)`, including
    /// silently dropped malformed frames. Any other protocol returns
    /// [`Error::NotImplemented`].
    fn handle_ipv4(
        &mut self,
        eth: &EtherHeader,
        payload: &[u8],
        reply_buf: &mut [u8],
    ) -> Result<usize> {
        let (ip_hdr, ip_payload) = parse_ipv4(payload)?;

        // SECURITY (F2): verify the IPv4 header checksum BEFORE acting on
        // the packet (RFC 1071 / RFC 791). A correct header folds to
        // 0xFFFF including its own checksum field, so `ipv4_checksum`
        // returns 0; any other value means the header is corrupt or
        // forged and the datagram must be dropped before dispatch.
        //
        // `header_len()` is `ihl * 4`; `parse_ipv4` already guaranteed
        // `payload.len() >= header_len` and `header_len >=
        // IPV4_HEADER_MIN_LEN`, but we re-check the bounds here so the
        // slice can never panic on an attacker-controlled frame.
        let hdr_len = ip_hdr.header_len();
        if hdr_len < IPV4_HEADER_MIN_LEN
            || payload.len() < hdr_len
            || ipv4_checksum(&payload[..hdr_len]) != 0
        {
            return Ok(0);
        }

        // Only process packets addressed to us.
        if ip_hdr.dst_addr != self.local_ip {
            return Ok(0);
        }

        match ip_hdr.protocol {
            PROTO_ICMP => self.handle_icmp_packet(eth, &ip_hdr, ip_payload, reply_buf),
            PROTO_TCP => {
                match self.handle_tcp_packet(&ip_hdr, ip_payload) {
                    Ok(()) => self.tcp_admitted = self.tcp_admitted.saturating_add(1),
                    Err(_) => self.tcp_dropped = self.tcp_dropped.saturating_add(1),
                }
                Ok(0)
            }
            PROTO_UDP => self.handle_udp_packet(&ip_hdr, ip_payload),
            PROTO_GRE => {
                match self.handle_gre_packet(ip_payload) {
                    Ok(()) => self.gre_admitted = self.gre_admitted.saturating_add(1),
                    Err(_) => self.gre_dropped = self.gre_dropped.saturating_add(1),
                }
                Ok(0)
            }
            PROTO_SCTP => {
                match self.handle_sctp_packet(&ip_hdr, ip_payload) {
                    Ok(()) => self.sctp_admitted = self.sctp_admitted.saturating_add(1),
                    Err(_) => self.sctp_dropped = self.sctp_dropped.saturating_add(1),
                }
                Ok(0)
            }
            _ => Err(Error::NotImplemented),
        }
    }

    /// Handle an incoming IPv6 packet.
    ///
    /// Delegates to [`Ipv6Stack::process_packet`], which currently answers
    /// ICMPv6 echo requests and Neighbor Solicitations. Returns the total
    /// reply frame length (Ethernet + IPv6 + ICMPv6), or 0 when the packet was
    /// consumed without a reply — including every packet the stack drops as
    /// invalid, so a malformed or forged frame is never reported as an error
    /// the caller has to distinguish from a transport failure.
    fn handle_ipv6(
        &mut self,
        eth: &EtherHeader,
        payload: &[u8],
        reply_buf: &mut [u8],
    ) -> Result<usize> {
        // Scratch buffer for the IPv6 reply, mirroring handle_icmp_packet:
        // process_packet writes a bare IPv6 datagram, which is only framed
        // once its length is known.
        let mut ipv6_buf = [0u8; MAX_PKT_BUF];
        let Some(ipv6_len) = self.ipv6.process_packet(payload, &mut ipv6_buf)? else {
            return Ok(0);
        };

        let total = ETHER_HEADER_LEN + ipv6_len;
        if reply_buf.len() < total {
            return Err(Error::InvalidArgument);
        }

        let mut offset = write_ether(reply_buf, &eth.src_mac, &self.local_mac, ETHER_TYPE_IPV6)?;
        reply_buf[offset..offset + ipv6_len].copy_from_slice(&ipv6_buf[..ipv6_len]);
        offset += ipv6_len;

        Ok(offset)
    }

    /// Handle an incoming GRE packet (IP protocol 47, RFC 2784).
    ///
    /// Admission gate only: run the shared [`crate::gre::validate_gre_packet`],
    /// which structurally parses the GRE header (base + C/K/S optional fields,
    /// version 0, RFC 2784 §2.3 discard mask) and, when the C bit is set,
    /// verifies the whole-packet RFC 1071 checksum. A header-only GRE frame is
    /// valid framing. No tunnel decapsulation or inner-packet dispatch is
    /// performed here — that requires a tunnel table and is a separate concern.
    ///
    /// Returns `Ok(())` on a validated frame. The caller ([`handle_ipv4`])
    /// maps both this success and any validation error to the `Ok(0)` boundary
    /// contract so a malformed frame is dropped silently, never surfaced.
    ///
    /// # Errors
    ///
    /// Propagates [`Error::InvalidArgument`] from
    /// [`crate::gre::validate_gre_packet`] for a malformed header or a C-bit
    /// checksum that does not verify.
    fn handle_gre_packet(&self, gre_payload: &[u8]) -> Result<()> {
        crate::gre::validate_gre_packet(gre_payload)?;
        Ok(())
    }

    /// Validate a TCP segment before protocol-6 admission.
    ///
    /// This stack has no IPv4 reassembly, so MF or a nonzero fragment offset
    /// is rejected locally. DF and the reserved IPv4 flag remain admissible.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] for fragments, malformed TCP framing,
    /// or an invalid IPv4 TCP checksum.
    fn handle_tcp_packet(&self, ip_hdr: &Ipv4Header, segment: &[u8]) -> Result<()> {
        if ip_hdr.flags_frag & 0x3FFF != 0 {
            return Err(Error::InvalidArgument);
        }
        crate::tcp::parse_tcp(segment)?;
        crate::tcp::verify_tcp_checksum(ip_hdr.src_addr, ip_hdr.dst_addr, segment)?;
        Ok(())
    }

    /// Validate an SCTP packet before protocol-132 admission.
    ///
    /// This stack has no IPv4 reassembly, so MF or a nonzero fragment offset
    /// is rejected locally. DF is outside the mask and remains admissible.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] for fragments or malformed SCTP.
    fn handle_sctp_packet(&self, ip_hdr: &Ipv4Header, sctp_payload: &[u8]) -> Result<()> {
        if ip_hdr.flags_frag & 0x3FFF != 0 {
            return Err(Error::InvalidArgument);
        }
        crate::sctp_packet::validate_sctp_packet(sctp_payload)
    }

    /// Validate an incoming UDP datagram before delivery.
    ///
    /// Re-parses the datagram so the on-wire UDP `length` field — not
    /// the IP-layer payload length — bounds the bytes considered, then
    /// verifies the UDP checksum over that exact span using the real
    /// source/destination addresses from the enclosing IPv4 header.
    /// A zero checksum field is accepted ("not computed") per RFC 768;
    /// a non-zero field that fails to fold to zero causes the datagram
    /// to be dropped before it can reach a socket.
    ///
    /// Returns `Ok(0)`: the datagram is consumed at this layer and no
    /// Ethernet-level reply is produced.  Demultiplexing the validated
    /// payload to a bound [`crate::udp::UdpSocketTable`] is performed
    /// by the socket layer above.
    ///
    /// # Errors
    ///
    /// Propagates [`Error::InvalidArgument`] from
    /// [`crate::udp::parse_udp_datagram`] for a malformed length field,
    /// and from [`crate::udp::verify_udp_checksum`] for a datagram whose
    /// non-zero checksum does not verify.
    fn handle_udp_packet(&self, ip_hdr: &Ipv4Header, udp_payload: &[u8]) -> Result<usize> {
        // The UDP length field is authoritative; `datagram` is trimmed
        // to exactly that length so the checksum covers no trailing
        // bytes from the IP payload.
        let (hdr, datagram) = crate::udp::parse_udp_datagram(udp_payload)?;

        // Verify against the real IPs from the IP header; drop on a
        // checksum mismatch.
        crate::udp::verify_udp_checksum(&ip_hdr.src_addr, &ip_hdr.dst_addr, datagram)?;

        // DNS admission check: a datagram on the DNS port (query to us, or a
        // response from a server) must be a structurally well-formed DNS
        // message. This mirrors the file's parse-and-validate convention and
        // drops malformed frames silently (`Ok(0)`) rather than surfacing them
        // as errors. It is framing validation only — RDATA is not interpreted
        // and no resolver state is touched here.
        if hdr.src_port == crate::dns::DNS_PORT || hdr.dst_port == crate::dns::DNS_PORT {
            let Some(dns_payload) = datagram.get(crate::udp::UDP_HEADER_LEN..) else {
                return Ok(0);
            };
            if crate::dns::validate_message(dns_payload).is_err() {
                return Ok(0);
            }
        }

        // DHCP admission check, mirroring the DNS gate above. Unlike DNS (one
        // shared port), DHCP is directional: a server replies from port 67 to
        // the client on port 68, so only that exact pair is client-side
        // inbound traffic worth validating. This is framing validation only —
        // no DhcpClient state, lease, or transaction correlation is touched,
        // and malformed frames drop silently per the Ok(0) convention.
        if hdr.src_port == crate::dhcp::DHCP_SERVER_PORT
            && hdr.dst_port == crate::dhcp::DHCP_CLIENT_PORT
        {
            let Some(dhcp_payload) = datagram.get(crate::udp::UDP_HEADER_LEN..) else {
                return Ok(0);
            };
            if crate::dhcp::validate_message(dhcp_payload).is_err() {
                return Ok(0);
            }
        }

        Ok(0)
    }

    /// Build a full Ethernet+IPv4+ICMP echo reply frame.
    fn handle_icmp_packet(
        &self,
        eth: &EtherHeader,
        ip_hdr: &Ipv4Header,
        icmp_data: &[u8],
        reply_buf: &mut [u8],
    ) -> Result<usize> {
        // Scratch buffer for the ICMP reply portion.
        // Maximum ICMP payload: MTU (1500) minus headers.
        const MAX_ICMP: usize = 1500;
        let mut icmp_buf = [0u8; MAX_ICMP];

        let icmp_len = handle_icmp(ip_hdr, icmp_data, &mut icmp_buf)?;

        // Total frame: Ethernet + IPv4 header + ICMP.
        let ip_hdr_len = IPV4_HEADER_MIN_LEN;
        let total = ETHER_HEADER_LEN + ip_hdr_len + icmp_len;
        if reply_buf.len() < total {
            return Err(Error::InvalidArgument);
        }

        // Ethernet header: swap src/dst.
        let mut offset = write_ether(reply_buf, &eth.src_mac, &self.local_mac, ETHER_TYPE_IPV4)?;

        // IPv4 header: swap addresses, adjust length.
        let reply_ip = Ipv4Header {
            version_ihl: 0x45, // version 4, IHL 5
            tos: 0,
            total_len: (ip_hdr_len + icmp_len) as u16,
            id: ip_hdr.id,
            flags_frag: 0,
            ttl: 64,
            protocol: PROTO_ICMP,
            checksum: 0, // recomputed by write_ipv4
            src_addr: self.local_ip,
            dst_addr: ip_hdr.src_addr,
        };
        offset += write_ipv4(&mut reply_buf[offset..], &reply_ip)?;

        // Copy ICMP reply payload.
        reply_buf[offset..offset + icmp_len].copy_from_slice(&icmp_buf[..icmp_len]);
        offset += icmp_len;

        Ok(offset)
    }
}

#[cfg(test)]
#[path = "net_sctp_tests.rs"]
mod sctp_tests;

#[cfg(test)]
#[path = "net_tcp_test_support.rs"]
mod net_tcp_test_support;

#[cfg(test)]
#[path = "net_tcp_tests.rs"]
mod tcp_tests;

#[cfg(test)]
#[path = "net_tcp_counter_tests.rs"]
mod tcp_counter_tests;

// =========================================================================
// Tests
// =========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    const PEER_MAC: [u8; 6] = [0xBB; 6];

    fn ipv6_test_stack() -> NetworkStack {
        NetworkStack::new([0xAA; 6], [10, 0, 0, 2], [10, 0, 0, 1], [255, 255, 255, 0])
    }

    // Frames a Neighbor Solicitation built by a peer stack, so the checksum
    // and hop limit are produced by the very code that validates them rather
    // than hand-rolled in the test.
    fn solicitation_frame(
        target: &Ipv6Addr,
        peer: &mut Ipv6Stack,
        frame: &mut [u8; ETHER_HEADER_LEN + MAX_PKT_BUF],
    ) -> usize {
        let mut ns = [0u8; MAX_PKT_BUF];
        let ns_len = peer.build_neighbor_solicitation(target, &mut ns).unwrap();
        write_ether(frame, &[0xAA; 6], &PEER_MAC, ETHER_TYPE_IPV6).unwrap();
        frame[ETHER_HEADER_LEN..ETHER_HEADER_LEN + ns_len].copy_from_slice(&ns[..ns_len]);
        ETHER_HEADER_LEN + ns_len
    }

    // The IPv6 branch must carry a real NDP exchange end to end: a peer's
    // Neighbor Solicitation arrives as an Ethernet frame and leaves as a
    // framed Neighbor Advertisement.
    #[test]
    fn ipv6_frame_answers_neighbor_solicitation() {
        let mut stack = ipv6_test_stack();
        let our_addr = stack.ipv6.local_addr;
        let mut peer = Ipv6Stack::new(Ipv6Addr::link_local_from_mac(&PEER_MAC), PEER_MAC);

        let mut frame = [0u8; ETHER_HEADER_LEN + MAX_PKT_BUF];
        let frame_len = solicitation_frame(&our_addr, &mut peer, &mut frame);

        let mut reply = [0u8; ETHER_HEADER_LEN + MAX_PKT_BUF];
        let len = stack
            .process_packet(&frame[..frame_len], &mut reply)
            .unwrap();

        let ipv6_start = ETHER_HEADER_LEN + crate::ipv6::IPV6_HEADER_LEN;
        assert_eq!(len, ipv6_start + 32, "Ethernet + IPv6 + 32-byte NA");
        assert_eq!(&reply[..6], &PEER_MAC, "NA must go back to the solicitor");
        assert_eq!(&reply[6..12], &[0xAA; 6]);
        assert_eq!(u16::from_be_bytes([reply[12], reply[13]]), ETHER_TYPE_IPV6);
        assert_eq!(reply[ipv6_start], 136, "ICMPv6 Neighbor Advertisement");
        assert_eq!(
            stack.ipv6.neighbors.lookup(&peer.local_addr).unwrap().mac,
            PEER_MAC,
            "the solicitor's MAC must be learned"
        );
    }

    // SECURITY: wiring must not bypass the RFC 4861 hop-limit gate. The same
    // frame with a forwarded hop limit must be dropped silently. The checksum
    // is left untouched — the hop limit is not part of the ICMPv6
    // pseudo-header — so this isolates the gate rather than the checksum.
    #[test]
    fn ipv6_frame_with_forwarded_hop_limit_is_dropped() {
        let mut stack = ipv6_test_stack();
        let our_addr = stack.ipv6.local_addr;
        let mut peer = Ipv6Stack::new(Ipv6Addr::link_local_from_mac(&PEER_MAC), PEER_MAC);

        let mut frame = [0u8; ETHER_HEADER_LEN + MAX_PKT_BUF];
        let frame_len = solicitation_frame(&our_addr, &mut peer, &mut frame);
        // Hop limit is byte 7 of the IPv6 header.
        frame[ETHER_HEADER_LEN + 7] = 64;

        let mut reply = [0u8; ETHER_HEADER_LEN + MAX_PKT_BUF];
        let len = stack
            .process_packet(&frame[..frame_len], &mut reply)
            .unwrap();

        assert_eq!(len, 0, "an off-link NS must be dropped, not answered");
        assert!(
            stack.ipv6.neighbors.lookup(&peer.local_addr).is_none(),
            "an off-link NS must not populate the neighbor cache"
        );
    }

    #[test]
    fn test_parse_ether_valid() {
        let mut frame = [0u8; 20];
        // dst mac
        frame[..6].copy_from_slice(&[0xAA; 6]);
        // src mac
        frame[6..12].copy_from_slice(&[0xBB; 6]);
        // EtherType IPv4
        frame[12] = 0x08;
        frame[13] = 0x00;
        // payload
        frame[14..20].copy_from_slice(&[1, 2, 3, 4, 5, 6]);

        let (hdr, payload) = parse_ether(&frame).unwrap();
        assert_eq!(hdr.dst_mac, [0xAA; 6]);
        assert_eq!(hdr.src_mac, [0xBB; 6]);
        assert_eq!(hdr.ether_type, ETHER_TYPE_IPV4);
        assert_eq!(payload, &[1, 2, 3, 4, 5, 6]);
    }

    #[test]
    fn test_parse_ether_too_short() {
        let frame = [0u8; 10];
        assert!(parse_ether(&frame).is_err());
    }

    #[test]
    fn test_arp_table_insert_lookup_remove() {
        let mut table = ArpTable::new();
        let ip = [192, 168, 1, 1];
        let mac = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];

        assert!(table.lookup(&ip).is_none());

        table.insert(ip, mac);
        assert_eq!(table.lookup(&ip), Some(mac));

        let mac2 = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66];
        table.insert(ip, mac2);
        assert_eq!(table.lookup(&ip), Some(mac2));

        assert!(table.remove(&ip));
        assert!(table.lookup(&ip).is_none());
        assert!(!table.remove(&ip));
    }

    #[test]
    fn test_arp_table_full_eviction() {
        let mut table = ArpTable::new();
        // Fill all 64 slots.
        for i in 0..ARP_TABLE_SIZE {
            let ip = [10, 0, 0, i as u8];
            let mac = [0, 0, 0, 0, 0, i as u8];
            table.insert(ip, mac);
        }
        // 65th insert should evict slot 0.
        let new_ip = [10, 0, 1, 0];
        let new_mac = [0xFF; 6];
        table.insert(new_ip, new_mac);
        assert_eq!(table.lookup(&new_ip), Some(new_mac));
        // Original slot 0 entry should be gone.
        assert!(table.lookup(&[10, 0, 0, 0]).is_none());
    }

    #[test]
    fn test_ipv4_checksum_rfc1071() {
        // Example from RFC 1071: 20-byte header.
        let header: [u8; 20] = [
            0x45, 0x00, 0x00, 0x73, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11, 0x00, 0x00, 0xC0, 0xA8,
            0x00, 0x01, 0xC0, 0xA8, 0x00, 0xC7,
        ];
        let cksum = ipv4_checksum(&header);
        // Verify that applying the checksum to the header yields
        // zero.
        let mut verified = header;
        let ck = cksum.to_be_bytes();
        verified[10] = ck[0];
        verified[11] = ck[1];
        assert_eq!(ipv4_checksum(&verified), 0);
    }

    #[test]
    fn test_parse_ipv4_valid() {
        #[rustfmt::skip]
        let pkt: [u8; 24] = [
            0x45, 0x00, 0x00, 0x18, // ver/ihl, tos, len=24
            0x00, 0x01, 0x00, 0x00, // id, flags/frag
            0x40, 0x01, 0x00, 0x00, // ttl=64, proto=ICMP
            0x0A, 0x00, 0x00, 0x01, // src 10.0.0.1
            0x0A, 0x00, 0x00, 0x02, // dst 10.0.0.2
            0xDE, 0xAD, 0xBE, 0xEF, // payload
        ];
        let (hdr, payload) = parse_ipv4(&pkt).unwrap();
        assert_eq!(hdr.version(), 4);
        assert_eq!(hdr.ihl(), 5);
        assert_eq!(hdr.protocol, PROTO_ICMP);
        assert_eq!(hdr.src_addr, [10, 0, 0, 1]);
        assert_eq!(hdr.dst_addr, [10, 0, 0, 2]);
        assert_eq!(payload, &[0xDE, 0xAD, 0xBE, 0xEF]);
    }

    #[test]
    fn test_parse_ipv4_bad_version() {
        let mut pkt = [0u8; 20];
        pkt[0] = 0x65; // version 6
        assert!(parse_ipv4(&pkt).is_err());
    }

    #[test]
    fn test_parse_ipv4_rejects_total_len_below_header() {
        // IHL=5 (hdr_len=20) but total_len=19 (< hdr_len): fail closed.
        #[rustfmt::skip]
        let pkt: [u8; 20] = [
            0x45, 0x00, 0x00, 0x13, // ver/ihl, tos, len=19
            0x00, 0x01, 0x00, 0x00, // id, flags/frag
            0x40, 0x01, 0x00, 0x00, // ttl=64, proto=ICMP
            0x0A, 0x00, 0x00, 0x01, // src 10.0.0.1
            0x0A, 0x00, 0x00, 0x02, // dst 10.0.0.2
        ];
        assert_eq!(parse_ipv4(&pkt), Err(Error::InvalidArgument));
    }

    #[test]
    fn test_parse_ipv4_rejects_total_len_beyond_data() {
        // total_len=40 declared but only 24 bytes of frame available.
        #[rustfmt::skip]
        let pkt: [u8; 24] = [
            0x45, 0x00, 0x00, 0x28, // ver/ihl, tos, len=40
            0x00, 0x01, 0x00, 0x00, // id, flags/frag
            0x40, 0x01, 0x00, 0x00, // ttl=64, proto=ICMP
            0x0A, 0x00, 0x00, 0x01, // src 10.0.0.1
            0x0A, 0x00, 0x00, 0x02, // dst 10.0.0.2
            0xDE, 0xAD, 0xBE, 0xEF, // payload
        ];
        assert_eq!(parse_ipv4(&pkt), Err(Error::InvalidArgument));
    }

    #[test]
    fn test_parse_ipv4_slices_payload_to_total_len() {
        // total_len=22 (20 hdr + 2 payload); frame has 2 trailing bytes of
        // Ethernet padding that must be excluded from the payload slice.
        #[rustfmt::skip]
        let pkt: [u8; 24] = [
            0x45, 0x00, 0x00, 0x16, // ver/ihl, tos, len=22
            0x00, 0x01, 0x00, 0x00, // id, flags/frag
            0x40, 0x01, 0x00, 0x00, // ttl=64, proto=ICMP
            0x0A, 0x00, 0x00, 0x01, // src 10.0.0.1
            0x0A, 0x00, 0x00, 0x02, // dst 10.0.0.2
            0xDE, 0xAD, 0x00, 0x00, // 2 payload bytes + 2 padding bytes
        ];
        let (_hdr, payload) = parse_ipv4(&pkt).unwrap();
        assert_eq!(payload, &[0xDE, 0xAD]);
    }

    #[test]
    fn test_icmp_echo_reply() {
        let ip_hdr = Ipv4Header {
            version_ihl: 0x45,
            tos: 0,
            total_len: 28,
            id: 1,
            flags_frag: 0,
            ttl: 64,
            protocol: PROTO_ICMP,
            checksum: 0,
            src_addr: [10, 0, 0, 1],
            dst_addr: [10, 0, 0, 2],
        };
        // Echo request: type=8, code=0, id=1, seq=1.
        #[rustfmt::skip]
        let mut icmp_data: [u8; 12] = [
            0x08, 0x00, 0x00, 0x00,
            0x00, 0x01, 0x00, 0x01,
            0xAA, 0xBB, 0xCC, 0xDD,
        ];
        let checksum = ipv4_checksum(&icmp_data).to_be_bytes();
        icmp_data[2] = checksum[0];
        icmp_data[3] = checksum[1];
        let mut reply = [0u8; 64];
        let len = handle_icmp(&ip_hdr, &icmp_data, &mut reply).unwrap();
        assert_eq!(len, 12);
        // Type should be echo reply (0).
        assert_eq!(reply[0], ICMP_ECHO_REPLY);
        // Payload preserved.
        assert_eq!(&reply[8..12], &[0xAA, 0xBB, 0xCC, 0xDD]);
        // Checksum should verify to zero.
        assert_eq!(ipv4_checksum(&reply[..len]), 0);
    }

    #[test]
    fn test_icmp_bad_checksum_rejected() {
        let ip_hdr = Ipv4Header {
            version_ihl: 0x45,
            tos: 0,
            total_len: 28,
            id: 1,
            flags_frag: 0,
            ttl: 64,
            protocol: PROTO_ICMP,
            checksum: 0,
            src_addr: [10, 0, 0, 1],
            dst_addr: [10, 0, 0, 2],
        };
        #[rustfmt::skip]
        let icmp_data: [u8; 12] = [
            0x08, 0x00, 0x12, 0x34,
            0x00, 0x01, 0x00, 0x01,
            0xAA, 0xBB, 0xCC, 0xDD,
        ];
        let mut reply = [0u8; 64];

        assert!(handle_icmp(&ip_hdr, &icmp_data, &mut reply).is_err());
    }

    #[test]
    fn test_network_stack_arp_request() {
        let stack = NetworkStack::new(
            [0x02, 0x00, 0x00, 0x00, 0x00, 0x01],
            [192, 168, 1, 10],
            [192, 168, 1, 1],
            [255, 255, 255, 0],
        );
        let mut buf = [0u8; 128];
        let len = stack.send_arp_request(&[192, 168, 1, 1], &mut buf).unwrap();
        assert_eq!(len, ETHER_HEADER_LEN + ARP_PACKET_LEN);
        // Verify broadcast destination.
        assert_eq!(&buf[..6], &[0xFF; 6]);
        // Verify ARP operation is request (0x00 0x01).
        assert_eq!(
            &buf[ETHER_HEADER_LEN + 6..ETHER_HEADER_LEN + 8],
            &[0x00, 0x01]
        );
    }

    #[test]
    fn test_network_stack_process_arp_request() {
        let mut stack = NetworkStack::new(
            [0x02, 0x00, 0x00, 0x00, 0x00, 0x01],
            [192, 168, 1, 10],
            [192, 168, 1, 1],
            [255, 255, 255, 0],
        );

        // Build an ARP request frame asking for our IP.
        let mut frame = [0u8; 128];
        let sender_mac = [0x02, 0x00, 0x00, 0x00, 0x00, 0x99];
        // Ethernet header.
        frame[..6].copy_from_slice(&[0xFF; 6]); // broadcast
        frame[6..12].copy_from_slice(&sender_mac);
        frame[12] = 0x08;
        frame[13] = 0x06; // ARP
        // ARP payload.
        let arp_off = ETHER_HEADER_LEN;
        // htype=1, ptype=0x0800, hlen=6, plen=4, oper=1
        frame[arp_off..arp_off + 8]
            .copy_from_slice(&[0x00, 0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0x01]);
        frame[arp_off + 8..arp_off + 14].copy_from_slice(&sender_mac);
        frame[arp_off + 14..arp_off + 18].copy_from_slice(&[192, 168, 1, 99]);
        frame[arp_off + 18..arp_off + 24].copy_from_slice(&[0; 6]);
        frame[arp_off + 24..arp_off + 28].copy_from_slice(&[192, 168, 1, 10]);

        let frame_len = ETHER_HEADER_LEN + ARP_PACKET_LEN;
        let mut reply = [0u8; 128];
        let rlen = stack
            .process_packet(&frame[..frame_len], &mut reply)
            .unwrap();

        // Should produce an ARP reply.
        assert_eq!(rlen, ETHER_HEADER_LEN + ARP_PACKET_LEN);
        // Reply dst should be sender's MAC.
        assert_eq!(&reply[..6], &sender_mac);
        // ARP operation in reply should be 2.
        assert_eq!(
            &reply[ETHER_HEADER_LEN + 6..ETHER_HEADER_LEN + 8],
            &[0x00, 0x02]
        );
        // Sender was learned in ARP table.
        assert!(stack.arp_table.lookup(&[192, 168, 1, 99]).is_some());
    }

    #[test]
    fn test_network_stack_zero_addresses() {
        let stack = NetworkStack::new([0; 6], [0; 4], [0; 4], [0; 4]);
        assert_eq!(stack.local_mac, [0; 6]);
        assert_eq!(stack.local_ip, [0; 4]);
    }

    /// Build an Ethernet+IPv4+UDP frame addressed to `dst_ip`.
    ///
    /// When `good_checksum` is true a valid UDP checksum is written;
    /// otherwise the checksum is corrupted to a non-zero wrong value.
    fn build_udp_frame(
        src_ip: [u8; 4],
        dst_ip: [u8; 4],
        payload: &[u8],
        good_checksum: bool,
        frame: &mut [u8],
    ) -> usize {
        // UDP datagram into a scratch buffer.
        let mut udp = [0u8; 64];
        let udp_len = crate::udp::write_udp(1111, 2222, payload, &mut udp)
            .ok()
            .unwrap();
        let cksum = crate::udp::udp_checksum(&src_ip, &dst_ip, &udp[..udp_len]);
        let ck = if good_checksum {
            cksum.to_be_bytes()
        } else {
            (cksum ^ 0x0100).to_be_bytes() // wrong, still non-zero
        };
        udp[6] = ck[0];
        udp[7] = ck[1];

        // Ethernet header.
        frame[..6].copy_from_slice(&[0xAA; 6]);
        frame[6..12].copy_from_slice(&[0xBB; 6]);
        frame[12] = 0x08;
        frame[13] = 0x00; // IPv4

        // IPv4 header via the crate serialiser (fills checksum).
        let ip = Ipv4Header {
            version_ihl: 0x45,
            tos: 0,
            total_len: (IPV4_HEADER_MIN_LEN + udp_len) as u16,
            id: 0,
            flags_frag: 0,
            ttl: 64,
            protocol: PROTO_UDP,
            checksum: 0,
            src_addr: src_ip,
            dst_addr: dst_ip,
        };
        let ip_off = ETHER_HEADER_LEN;
        write_ipv4(&mut frame[ip_off..], &ip).ok().unwrap();

        let udp_off = ip_off + IPV4_HEADER_MIN_LEN;
        frame[udp_off..udp_off + udp_len].copy_from_slice(&udp[..udp_len]);
        udp_off + udp_len
    }

    #[test]
    fn test_udp_good_checksum_consumed() {
        let mut stack =
            NetworkStack::new([0xAA; 6], [10, 0, 0, 2], [10, 0, 0, 1], [255, 255, 255, 0]);
        let mut frame = [0u8; 128];
        let n = build_udp_frame(
            [10, 0, 0, 1],
            [10, 0, 0, 2],
            &[1, 2, 3, 4],
            true,
            &mut frame,
        );

        let mut reply = [0u8; 128];
        // Valid datagram for us: consumed, no L2 reply.
        let r = stack.process_packet(&frame[..n], &mut reply).ok().unwrap();
        assert_eq!(r, 0);
    }

    #[test]
    fn test_udp_bad_checksum_dropped() {
        let mut stack =
            NetworkStack::new([0xAA; 6], [10, 0, 0, 2], [10, 0, 0, 1], [255, 255, 255, 0]);
        let mut frame = [0u8; 128];
        let n = build_udp_frame(
            [10, 0, 0, 1],
            [10, 0, 0, 2],
            &[1, 2, 3, 4],
            false,
            &mut frame,
        );

        let mut reply = [0u8; 128];
        // Corrupt checksum: the datagram must be dropped (Err), not
        // silently delivered.
        assert!(stack.process_packet(&frame[..n], &mut reply).is_err());
    }

    #[test]
    fn test_udp_zero_checksum_accepted() {
        let mut stack =
            NetworkStack::new([0xAA; 6], [10, 0, 0, 2], [10, 0, 0, 1], [255, 255, 255, 0]);
        // write_udp leaves the checksum field zero ("not computed").
        let mut frame = [0u8; 128];
        let mut udp = [0u8; 64];
        let udp_len = crate::udp::write_udp(1, 2, &[0xAB, 0xCD], &mut udp)
            .ok()
            .unwrap();
        frame[..6].copy_from_slice(&[0xAA; 6]);
        frame[6..12].copy_from_slice(&[0xBB; 6]);
        frame[12] = 0x08;
        frame[13] = 0x00;
        let ip = Ipv4Header {
            version_ihl: 0x45,
            tos: 0,
            total_len: (IPV4_HEADER_MIN_LEN + udp_len) as u16,
            id: 0,
            flags_frag: 0,
            ttl: 64,
            protocol: PROTO_UDP,
            checksum: 0,
            src_addr: [10, 0, 0, 1],
            dst_addr: [10, 0, 0, 2],
        };
        write_ipv4(&mut frame[ETHER_HEADER_LEN..], &ip)
            .ok()
            .unwrap();
        let udp_off = ETHER_HEADER_LEN + IPV4_HEADER_MIN_LEN;
        frame[udp_off..udp_off + udp_len].copy_from_slice(&udp[..udp_len]);
        let n = udp_off + udp_len;

        let mut reply = [0u8; 128];
        let r = stack.process_packet(&frame[..n], &mut reply).ok().unwrap();
        assert_eq!(r, 0);
    }

    /// Build an Ethernet+IPv4+UDP frame for a specific destination port.
    ///
    /// Same construction as [`build_udp_frame`] but with caller-chosen ports,
    /// so DNS (port 53) traffic can be exercised.
    #[allow(clippy::too_many_arguments)]
    fn build_udp_frame_to_port(
        src_ip: [u8; 4],
        dst_ip: [u8; 4],
        src_port: u16,
        dst_port: u16,
        payload: &[u8],
        good_checksum: bool,
        frame: &mut [u8],
    ) -> usize {
        let mut udp = [0u8; 256];
        let udp_len = crate::udp::write_udp(src_port, dst_port, payload, &mut udp)
            .ok()
            .unwrap();
        let cksum = crate::udp::udp_checksum(&src_ip, &dst_ip, &udp[..udp_len]);
        let ck = if good_checksum {
            cksum.to_be_bytes()
        } else {
            (cksum ^ 0x0100).to_be_bytes()
        };
        udp[6] = ck[0];
        udp[7] = ck[1];

        frame[..6].copy_from_slice(&[0xAA; 6]);
        frame[6..12].copy_from_slice(&[0xBB; 6]);
        frame[12] = 0x08;
        frame[13] = 0x00;
        let ip = Ipv4Header {
            version_ihl: 0x45,
            tos: 0,
            total_len: (IPV4_HEADER_MIN_LEN + udp_len) as u16,
            id: 0,
            flags_frag: 0,
            ttl: 64,
            protocol: PROTO_UDP,
            checksum: 0,
            src_addr: src_ip,
            dst_addr: dst_ip,
        };
        let ip_off = ETHER_HEADER_LEN;
        write_ipv4(&mut frame[ip_off..], &ip).ok().unwrap();
        let udp_off = ip_off + IPV4_HEADER_MIN_LEN;
        frame[udp_off..udp_off + udp_len].copy_from_slice(&udp[..udp_len]);
        udp_off + udp_len
    }

    /// Build an Ethernet+IPv4 frame carrying a raw IP payload of a chosen
    /// protocol (no transport header). Used for GRE (protocol 47).
    fn build_ip_proto_frame(
        src_ip: [u8; 4],
        dst_ip: [u8; 4],
        protocol: u8,
        payload: &[u8],
        frame: &mut [u8],
    ) -> usize {
        frame[..6].copy_from_slice(&[0xAA; 6]);
        frame[6..12].copy_from_slice(&[0xBB; 6]);
        frame[12] = 0x08;
        frame[13] = 0x00;
        let ip = Ipv4Header {
            version_ihl: 0x45,
            tos: 0,
            total_len: (IPV4_HEADER_MIN_LEN + payload.len()) as u16,
            id: 0,
            flags_frag: 0,
            ttl: 64,
            protocol,
            checksum: 0,
            src_addr: src_ip,
            dst_addr: dst_ip,
        };
        let ip_off = ETHER_HEADER_LEN;
        write_ipv4(&mut frame[ip_off..], &ip).ok().unwrap();
        let p_off = ip_off + IPV4_HEADER_MIN_LEN;
        frame[p_off..p_off + payload.len()].copy_from_slice(payload);
        p_off + payload.len()
    }

    /// A network stack instance for direct handler-method tests.
    fn gre_stack() -> NetworkStack {
        NetworkStack::new([0xAA; 6], [10, 0, 0, 2], [10, 0, 0, 1], [255, 255, 255, 0])
    }

    // Direct handler call: a C-only GRE frame with a valid whole-packet
    // checksum (0x32ff over flags=0x8000, proto=IPv4, reserved1=0, payload
    // [0x45,0x00]) validates, so the handler returns Ok(()).
    #[test]
    fn gre_handler_accepts_valid_checksum() {
        let gre = [0x80u8, 0x00, 0x08, 0x00, 0x32, 0xff, 0x00, 0x00, 0x45, 0x00];
        assert_eq!(gre_stack().handle_gre_packet(&gre), Ok(()));
    }

    // Direct handler call: a corrupt checksum (0x32fe) fails validation, so the
    // handler propagates Err(InvalidArgument) — proving rejection at the source
    // rather than relying on the Ok(0) boundary mapping.
    #[test]
    fn gre_handler_rejects_corrupt_checksum() {
        let gre = [0x80u8, 0x00, 0x08, 0x00, 0x32, 0xfe, 0x00, 0x00, 0x45, 0x00];
        assert_eq!(
            gre_stack().handle_gre_packet(&gre),
            Err(Error::InvalidArgument)
        );
    }

    // Direct handler call: RFC 2784 §2.3 ignored Reserved0 bit 6 (0x0200) is
    // admitted by the validator, so the handler returns Ok(()).
    #[test]
    fn gre_handler_accepts_ignored_reserved0_bit() {
        let gre = [0x02u8, 0x00, 0x08, 0x00, 0x45, 0x00];
        assert_eq!(gre_stack().handle_gre_packet(&gre), Ok(()));
    }

    // Direct handler call: RFC 2784 §2.3 discard bit 4 / strict-source-route
    // (0x0800) is rejected by the validator, so the handler returns
    // Err(InvalidArgument).
    #[test]
    fn gre_handler_rejects_discard_bit() {
        let gre = [0x08u8, 0x00, 0x08, 0x00, 0x45, 0x00];
        assert_eq!(
            gre_stack().handle_gre_packet(&gre),
            Err(Error::InvalidArgument)
        );
    }

    // End-to-end dispatch: an unsupported IP protocol (99) returns
    // NotImplemented, while a byte-identical payload carried as PROTO_GRE (47)
    // is routed to the GRE gate and consumed (Ok(0)). The differing outcomes
    // prove protocol 47 reaches handle_gre_packet, not the fallthrough arm.
    #[test]
    fn gre_protocol_dispatched_distinctly_from_unsupported() {
        let gre = [0x80u8, 0x00, 0x08, 0x00, 0x32, 0xff, 0x00, 0x00, 0x45, 0x00];
        let mut frame = [0u8; 128];
        let mut reply = [0u8; 128];

        let mut stack = gre_stack();
        let n = build_ip_proto_frame([10, 0, 0, 1], [10, 0, 0, 2], 99, &gre, &mut frame);
        assert_eq!(
            stack.process_packet(&frame[..n], &mut reply),
            Err(Error::NotImplemented),
            "protocol 99 must hit the unsupported arm"
        );

        let mut stack = gre_stack();
        let n = build_ip_proto_frame([10, 0, 0, 1], [10, 0, 0, 2], PROTO_GRE, &gre, &mut frame);
        assert_eq!(
            stack.process_packet(&frame[..n], &mut reply),
            Ok(0),
            "PROTO_GRE must be dispatched to the gate and consumed"
        );
    }

    // End-to-end boundary contract: a malformed GRE frame (corrupt checksum)
    // whose handler returns Err is mapped by handle_ipv4 to Ok(0), so the
    // public boundary drops it silently and never surfaces the error.
    #[test]
    fn gre_malformed_frame_dropped_at_boundary() {
        let gre = [0x80u8, 0x00, 0x08, 0x00, 0x32, 0xfe, 0x00, 0x00, 0x45, 0x00];
        let mut stack = gre_stack();
        let mut frame = [0u8; 128];
        let n = build_ip_proto_frame([10, 0, 0, 1], [10, 0, 0, 2], PROTO_GRE, &gre, &mut frame);
        let mut reply = [0u8; 128];
        assert_eq!(stack.process_packet(&frame[..n], &mut reply), Ok(0));
    }

    // Given a valid C-only GRE frame dispatched through the public boundary,
    // When process_packet consumes it,
    // Then only the admitted counter advances and dropped stays zero, proving
    // validation has an observable effect on NetworkStack state.
    #[test]
    fn gre_valid_frame_increments_admitted_only() {
        let gre = [0x80u8, 0x00, 0x08, 0x00, 0x32, 0xff, 0x00, 0x00, 0x45, 0x00];
        let mut stack = gre_stack();
        let mut frame = [0u8; 128];
        let n = build_ip_proto_frame([10, 0, 0, 1], [10, 0, 0, 2], PROTO_GRE, &gre, &mut frame);
        let mut reply = [0u8; 128];
        assert_eq!(stack.process_packet(&frame[..n], &mut reply), Ok(0));
        assert_eq!(stack.gre_admitted(), 1);
        assert_eq!(stack.gre_dropped(), 0);
    }

    // Given a corrupt-checksum GRE frame dispatched through the public boundary,
    // When process_packet drops it,
    // Then only the dropped counter advances and admitted stays zero. This
    // fails if validate_gre_packet is bypassed, because a bypassed gate would
    // admit the corrupt frame and increment admitted instead.
    #[test]
    fn gre_corrupt_frame_increments_dropped_only() {
        let gre = [0x80u8, 0x00, 0x08, 0x00, 0x32, 0xfe, 0x00, 0x00, 0x45, 0x00];
        let mut stack = gre_stack();
        let mut frame = [0u8; 128];
        let n = build_ip_proto_frame([10, 0, 0, 1], [10, 0, 0, 2], PROTO_GRE, &gre, &mut frame);
        let mut reply = [0u8; 128];
        assert_eq!(stack.process_packet(&frame[..n], &mut reply), Ok(0));
        assert_eq!(stack.gre_dropped(), 1);
        assert_eq!(stack.gre_admitted(), 0);
    }

    // A structurally valid DNS query on port 53 must be admitted (consumed,
    // Ok(0)) — validation must not reject legitimate DNS traffic.
    #[test]
    fn dns_valid_query_on_port53_accepted() {
        let mut stack =
            NetworkStack::new([0xAA; 6], [10, 0, 0, 2], [10, 0, 0, 1], [255, 255, 255, 0]);
        let mut qbuf = [0u8; 128];
        let qlen = crate::dns::build_query(0x1234, b"example.com", crate::dns::TYPE_A, &mut qbuf)
            .ok()
            .unwrap();
        let mut frame = [0u8; 256];
        let n = build_udp_frame_to_port(
            [10, 0, 0, 1],
            [10, 0, 0, 2],
            12345,
            crate::dns::DNS_PORT,
            &qbuf[..qlen],
            true,
            &mut frame,
        );
        let mut reply = [0u8; 256];
        let r = stack.process_packet(&frame[..n], &mut reply).ok().unwrap();
        assert_eq!(r, 0, "valid DNS query must be consumed, not error");
    }

    // A DNS datagram with a valid UDP checksum but a malformed (forward-pointer)
    // message must be dropped silently by the admission gate, not error.
    #[test]
    fn dns_forward_pointer_on_port53_dropped_not_error() {
        let mut stack =
            NetworkStack::new([0xAA; 6], [10, 0, 0, 2], [10, 0, 0, 1], [255, 255, 255, 0]);
        // Hand-build a DNS message whose question name is a forward pointer.
        let mut msg = [0u8; 32];
        msg[5] = 1; // qd_count = 1
        msg[12] = 0xC0;
        msg[13] = 0x14; // forward pointer to offset 20
        msg[20] = 1;
        msg[21] = b'x';
        msg[22] = 0;
        let mut frame = [0u8; 256];
        let n = build_udp_frame_to_port(
            [10, 0, 0, 1],
            [10, 0, 0, 2],
            12345,
            crate::dns::DNS_PORT,
            &msg,
            true,
            &mut frame,
        );
        let mut reply = [0u8; 256];
        let r = stack.process_packet(&frame[..n], &mut reply).ok().unwrap();
        assert_eq!(r, 0, "malformed DNS must be dropped (Ok(0)), not an error");
    }

    // A structurally valid DHCP OFFER from server(67) to client(68) must be
    // admitted (consumed, Ok(0)) — the gate must not reject real DHCP traffic.
    #[test]
    fn dhcp_valid_offer_on_67_to_68_accepted() {
        let mut stack =
            NetworkStack::new([0xAA; 6], [10, 0, 0, 2], [10, 0, 0, 1], [255, 255, 255, 0]);
        // Build a minimal valid OFFER via the crate's own client builder is a
        // discover (BOOTREQUEST); instead construct the reply framing inline.
        let mut msg = [0u8; 240 + 4];
        msg[0] = 2; // BOOTREPLY
        msg[1] = 1; // htype Ethernet
        msg[2] = 6; // hlen 6
        msg[4..8].copy_from_slice(&0xAABBCCDDu32.to_be_bytes());
        msg[236..240].copy_from_slice(&crate::dhcp::DHCP_MAGIC_COOKIE);
        let o = 240;
        msg[o] = crate::dhcp::OPT_MSG_TYPE;
        msg[o + 1] = 1;
        msg[o + 2] = crate::dhcp::DHCPOFFER;
        msg[o + 3] = crate::dhcp::OPT_END;
        let mut frame = [0u8; 512];
        let n = build_udp_frame_to_port(
            [10, 0, 0, 1],
            [10, 0, 0, 2],
            crate::dhcp::DHCP_SERVER_PORT,
            crate::dhcp::DHCP_CLIENT_PORT,
            &msg[..o + 4],
            true,
            &mut frame,
        );
        let mut reply = [0u8; 512];
        let r = stack.process_packet(&frame[..n], &mut reply).ok().unwrap();
        assert_eq!(r, 0, "valid DHCP OFFER must be consumed, not error");
    }

    // A DHCP datagram on 67->68 with a bad magic cookie must be dropped
    // silently by the admission gate, not surfaced as an error.
    #[test]
    fn dhcp_bad_cookie_on_67_to_68_dropped_not_error() {
        let mut stack =
            NetworkStack::new([0xAA; 6], [10, 0, 0, 2], [10, 0, 0, 1], [255, 255, 255, 0]);
        let mut msg = [0u8; 240 + 4];
        msg[0] = 2; // BOOTREPLY
        msg[1] = 1;
        msg[2] = 6;
        msg[4..8].copy_from_slice(&0xAABBCCDDu32.to_be_bytes());
        msg[236] = 0xFF; // corrupt the magic cookie
        let o = 240;
        msg[o] = crate::dhcp::OPT_MSG_TYPE;
        msg[o + 1] = 1;
        msg[o + 2] = crate::dhcp::DHCPOFFER;
        msg[o + 3] = crate::dhcp::OPT_END;
        let mut frame = [0u8; 512];
        let n = build_udp_frame_to_port(
            [10, 0, 0, 1],
            [10, 0, 0, 2],
            crate::dhcp::DHCP_SERVER_PORT,
            crate::dhcp::DHCP_CLIENT_PORT,
            &msg[..o + 4],
            true,
            &mut frame,
        );
        let mut reply = [0u8; 512];
        let r = stack.process_packet(&frame[..n], &mut reply).ok().unwrap();
        assert_eq!(
            r, 0,
            "bad-cookie DHCP must be dropped (Ok(0)), not an error"
        );
    }

    // Traffic between two non-DHCP ports that happens to carry DHCP-shaped
    // bytes must NOT be validated as DHCP (wrong direction/ports) — it should
    // sail through untouched. Guards the `&&` direction predicate.
    #[test]
    fn dhcp_shaped_bytes_on_wrong_ports_not_validated() {
        let mut stack =
            NetworkStack::new([0xAA; 6], [10, 0, 0, 2], [10, 0, 0, 1], [255, 255, 255, 0]);
        // Deliberately malformed (bad cookie) but on wrong ports: no DHCP gate.
        let mut msg = [0u8; 240 + 4];
        msg[0] = 2;
        msg[1] = 1;
        msg[2] = 6;
        msg[236] = 0xFF; // bad cookie — would fail DHCP validation
        let o = 240;
        msg[o] = crate::dhcp::OPT_MSG_TYPE;
        msg[o + 1] = 1;
        msg[o + 2] = crate::dhcp::DHCPOFFER;
        msg[o + 3] = crate::dhcp::OPT_END;
        let mut frame = [0u8; 512];
        let n = build_udp_frame_to_port(
            [10, 0, 0, 1],
            [10, 0, 0, 2],
            12345,
            54321, // neither port is 67/68
            &msg[..o + 4],
            true,
            &mut frame,
        );
        let mut reply = [0u8; 512];
        let r = stack.process_packet(&frame[..n], &mut reply).ok().unwrap();
        assert_eq!(r, 0, "non-DHCP-port traffic must bypass the DHCP gate");
    }
}
