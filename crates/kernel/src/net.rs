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
//!
//! TCP and UDP are planned for future implementation.

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
///   minimum IPv4 header (20 bytes), the version is not 4, or the
///   IHL-declared length exceeds the available data.
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

    // Determine actual payload range.
    let total = header.total_len as usize;
    let payload_end = if total > 0 && total <= data.len() {
        total
    } else {
        data.len()
    };

    Ok((header, &data[hdr_len..payload_end]))
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
///   header or `reply_buf` is too small to hold the reply.
/// - [`Error::NotImplemented`] if the ICMP type is not an echo
///   request.
pub fn handle_icmp(_header: &Ipv4Header, data: &[u8], reply_buf: &mut [u8]) -> Result<usize> {
    if data.len() < ICMP_HEADER_LEN {
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
}

impl NetworkStack {
    /// Create a new network stack with the given identity.
    pub const fn new(mac: [u8; 6], ip: [u8; 4], gateway: [u8; 4], subnet: [u8; 4]) -> Self {
        Self {
            local_mac: mac,
            local_ip: ip,
            gateway_ip: gateway,
            subnet_mask: subnet,
            arp_table: ArpTable::new(),
        }
    }

    /// Process an incoming Ethernet frame.
    ///
    /// Parses the Ethernet header and dispatches to the appropriate
    /// protocol handler (ARP or IPv4/ICMP).  If a reply is
    /// generated it is written into `reply_buf` as a complete
    /// Ethernet frame and the total frame length is returned.
    ///
    /// Returns `Ok(0)` when the packet is consumed but no reply is
    /// needed (e.g., an ARP reply that merely updates the cache).
    ///
    /// # Errors
    ///
    /// Propagates errors from the individual protocol parsers.
    pub fn process_packet(&mut self, data: &[u8], reply_buf: &mut [u8]) -> Result<usize> {
        let (eth, payload) = parse_ether(data)?;

        match eth.ether_type {
            ETHER_TYPE_ARP => self.handle_arp(&eth, payload, reply_buf),
            ETHER_TYPE_IPV4 => self.handle_ipv4(&eth, payload, reply_buf),
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
    /// For ARP requests targeting our IP, sends a reply.  For ARP
    /// replies, updates the ARP table.  Returns the reply frame
    /// length, or 0 if no reply is needed.
    fn handle_arp(
        &mut self,
        eth: &EtherHeader,
        payload: &[u8],
        reply_buf: &mut [u8],
    ) -> Result<usize> {
        let arp = parse_arp(payload)?;

        // Learn the sender's MAC regardless of operation.
        self.arp_table.insert(arp.spa, arp.sha);

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
                // Already inserted above.
                Ok(0)
            }
            _ => Ok(0),
        }
    }

    /// Handle an incoming IPv4 packet.
    ///
    /// Currently only ICMP echo requests are processed.  Returns
    /// the total reply frame length (Ethernet + IP + ICMP), or 0
    /// if the packet was consumed silently.
    fn handle_ipv4(
        &mut self,
        eth: &EtherHeader,
        payload: &[u8],
        reply_buf: &mut [u8],
    ) -> Result<usize> {
        let (ip_hdr, ip_payload) = parse_ipv4(payload)?;

        // Only process packets addressed to us.
        if ip_hdr.dst_addr != self.local_ip {
            return Ok(0);
        }

        match ip_hdr.protocol {
            PROTO_ICMP => self.handle_icmp_packet(eth, &ip_hdr, ip_payload, reply_buf),
            _ => Err(Error::NotImplemented),
        }
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

// =========================================================================
// Tests
// =========================================================================

#[cfg(test)]
mod tests {
    use super::*;

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
        // Echo request: type=8, code=0, cksum=0, id=1, seq=1.
        #[rustfmt::skip]
        let icmp_data: [u8; 12] = [
            0x08, 0x00, 0x00, 0x00,
            0x00, 0x01, 0x00, 0x01,
            0xAA, 0xBB, 0xCC, 0xDD,
        ];
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
    fn test_network_stack_default() {
        let stack = NetworkStack::default();
        assert_eq!(stack.local_mac, [0; 6]);
        assert_eq!(stack.local_ip, [0; 4]);
    }
}
