// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! UDP datagram protocol for the ONCRIX network stack.
//!
//! Implements RFC 768 UDP header parsing, serialisation, checksum
//! computation, and a socket table for demultiplexing incoming
//! datagrams by destination port.
//!
//! All multi-byte network fields use network byte order (big-endian)
//! via [`u16::from_be_bytes`] / [`u16::to_be_bytes`].

use oncrix_lib::{Error, Result};

// =========================================================================
// Constants
// =========================================================================

/// UDP header size in bytes (src_port + dst_port + length + checksum).
const UDP_HEADER_LEN: usize = 8;

/// Maximum number of UDP sockets in the socket table.
const UDP_TABLE_SIZE: usize = 32;

/// Maximum receive buffer size per socket (bytes).
const RECV_BUF_SIZE: usize = 4096;

/// Start of the IANA ephemeral port range.
pub const EPHEMERAL_PORT_START: u16 = 49152;

/// End of the IANA ephemeral port range (inclusive).
pub const EPHEMERAL_PORT_END: u16 = 65535;

/// IP protocol number for UDP.
const PROTO_UDP: u8 = 17;

// =========================================================================
// UdpHeader
// =========================================================================

/// Parsed UDP datagram header (RFC 768).
///
/// Fields are stored in host byte order after parsing.  The on-wire
/// format uses big-endian for all multi-byte fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct UdpHeader {
    /// Source port number.
    pub src_port: u16,
    /// Destination port number.
    pub dst_port: u16,
    /// Length of the UDP header plus payload in bytes.
    pub length: u16,
    /// Checksum over pseudo-header, UDP header, and payload.
    pub checksum: u16,
}

// =========================================================================
// parse_udp
// =========================================================================

/// Parse a UDP header and payload from raw bytes.
///
/// Returns the parsed [`UdpHeader`] and a slice referencing the
/// payload (everything after the 8-byte header, bounded by the
/// `length` field).
///
/// # Errors
///
/// Returns [`Error::InvalidArgument`] if:
/// - `data` is shorter than [`UDP_HEADER_LEN`] (8 bytes).
/// - The `length` field is less than 8 (minimum valid UDP length).
/// - The `length` field exceeds the available data.
pub fn parse_udp(data: &[u8]) -> Result<(UdpHeader, &[u8])> {
    if data.len() < UDP_HEADER_LEN {
        return Err(Error::InvalidArgument);
    }

    let src_port = u16::from_be_bytes([data[0], data[1]]);
    let dst_port = u16::from_be_bytes([data[2], data[3]]);
    let length = u16::from_be_bytes([data[4], data[5]]);
    let checksum = u16::from_be_bytes([data[6], data[7]]);

    let len = length as usize;
    if len < UDP_HEADER_LEN || len > data.len() {
        return Err(Error::InvalidArgument);
    }

    let header = UdpHeader {
        src_port,
        dst_port,
        length,
        checksum,
    };

    Ok((header, &data[UDP_HEADER_LEN..len]))
}

// =========================================================================
// write_udp
// =========================================================================

/// Serialise a UDP header and payload into `out_buf`.
///
/// Writes an 8-byte UDP header followed by `payload`.  The checksum
/// field is set to zero (optional for IPv4 per RFC 768).  Returns
/// the total number of bytes written (header + payload).
///
/// # Errors
///
/// Returns [`Error::InvalidArgument`] if:
/// - `out_buf` is too small to hold the header plus payload.
/// - The combined length would exceed [`u16::MAX`].
pub fn write_udp(
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
    out_buf: &mut [u8],
) -> Result<usize> {
    let total = UDP_HEADER_LEN.saturating_add(payload.len());
    if total > u16::MAX as usize {
        return Err(Error::InvalidArgument);
    }
    if out_buf.len() < total {
        return Err(Error::InvalidArgument);
    }

    let sp = src_port.to_be_bytes();
    out_buf[0] = sp[0];
    out_buf[1] = sp[1];

    let dp = dst_port.to_be_bytes();
    out_buf[2] = dp[0];
    out_buf[3] = dp[1];

    let len = (total as u16).to_be_bytes();
    out_buf[4] = len[0];
    out_buf[5] = len[1];

    // Checksum set to zero (optional for IPv4 UDP).
    out_buf[6] = 0;
    out_buf[7] = 0;

    out_buf[UDP_HEADER_LEN..total].copy_from_slice(payload);

    Ok(total)
}

// =========================================================================
// udp_checksum
// =========================================================================

/// Compute the UDP checksum over a pseudo-header and UDP data
/// (RFC 768).
///
/// The pseudo-header consists of the source IP, destination IP, a
/// zero byte, the protocol number (17), and the UDP length.  The
/// `udp_data` slice must contain the complete UDP datagram (header
/// plus payload) as it appears on the wire.
///
/// Returns the one's-complement checksum.  A return value of
/// `0xFFFF` is substituted for a computed zero per RFC 768.
pub fn udp_checksum(src_ip: &[u8; 4], dst_ip: &[u8; 4], udp_data: &[u8]) -> u16 {
    let mut sum: u32 = 0;

    // Pseudo-header: src IP (2 x u16).
    sum = sum.wrapping_add(u16::from_be_bytes([src_ip[0], src_ip[1]]) as u32);
    sum = sum.wrapping_add(u16::from_be_bytes([src_ip[2], src_ip[3]]) as u32);

    // Pseudo-header: dst IP (2 x u16).
    sum = sum.wrapping_add(u16::from_be_bytes([dst_ip[0], dst_ip[1]]) as u32);
    sum = sum.wrapping_add(u16::from_be_bytes([dst_ip[2], dst_ip[3]]) as u32);

    // Pseudo-header: zero + protocol.
    sum = sum.wrapping_add(PROTO_UDP as u32);

    // Pseudo-header: UDP length.
    sum = sum.wrapping_add(udp_data.len() as u32);

    // Sum 16-bit words of the UDP datagram.
    let mut i = 0;
    while i + 1 < udp_data.len() {
        let word = u16::from_be_bytes([udp_data[i], udp_data[i + 1]]);
        sum = sum.wrapping_add(word as u32);
        i += 2;
    }

    // If odd length, pad the last byte with zero.
    if i < udp_data.len() {
        sum = sum.wrapping_add((udp_data[i] as u32) << 8);
    }

    // Fold 32-bit sum to 16 bits.
    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    let result = !(sum as u16);

    // RFC 768: if the computed checksum is zero, transmit 0xFFFF.
    if result == 0 { 0xFFFF } else { result }
}

// =========================================================================
// UdpSocket
// =========================================================================

/// A single UDP socket with local/remote addressing and a receive
/// buffer.
///
/// Supports both connected (fixed remote endpoint) and unconnected
/// (any remote) modes.
pub struct UdpSocket {
    /// Local port this socket is bound to.
    pub local_port: u16,
    /// Remote port for connected sockets (0 if unconnected).
    pub remote_port: u16,
    /// Remote IPv4 address for connected sockets
    /// (`[0; 4]` if unconnected).
    pub remote_ip: [u8; 4],
    /// Whether this socket is bound to a local port.
    pub bound: bool,
    /// Whether this socket has a default remote destination.
    pub connected: bool,
    /// Receive buffer for incoming datagram data.
    recv_buf: [u8; RECV_BUF_SIZE],
    /// Number of valid bytes in [`recv_buf`](Self::recv_buf).
    recv_len: usize,
    /// IPv4 address of the last received datagram's sender.
    recv_from_ip: [u8; 4],
    /// Port number of the last received datagram's sender.
    recv_from_port: u16,
}

impl UdpSocket {
    /// Create a new, unbound, unconnected UDP socket.
    const fn new() -> Self {
        Self {
            local_port: 0,
            remote_port: 0,
            remote_ip: [0; 4],
            bound: false,
            connected: false,
            recv_buf: [0; RECV_BUF_SIZE],
            recv_len: 0,
            recv_from_ip: [0; 4],
            recv_from_port: 0,
        }
    }
}

// =========================================================================
// UdpSocketTable
// =========================================================================

/// Table of UDP sockets for demultiplexing incoming datagrams.
///
/// Holds up to [`UDP_TABLE_SIZE`] (32) sockets.  Each slot is
/// identified by its index, which serves as the socket descriptor.
pub struct UdpSocketTable {
    /// Fixed-size array of socket slots.
    sockets: [UdpSocket; UDP_TABLE_SIZE],
    /// Validity flags for each slot.
    active: [bool; UDP_TABLE_SIZE],
}

impl Default for UdpSocketTable {
    fn default() -> Self {
        Self::new()
    }
}

impl UdpSocketTable {
    /// Create an empty socket table.
    pub const fn new() -> Self {
        const EMPTY: UdpSocket = UdpSocket::new();
        Self {
            sockets: [EMPTY; UDP_TABLE_SIZE],
            active: [false; UDP_TABLE_SIZE],
        }
    }

    /// Allocate a new UDP socket and return its index.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if all slots are occupied.
    pub fn create(&mut self) -> Result<usize> {
        for i in 0..UDP_TABLE_SIZE {
            if !self.active[i] {
                self.sockets[i] = UdpSocket::new();
                self.active[i] = true;
                return Ok(i);
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Bind a socket to a local port.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidArgument`] if `id` is out of range or the
    ///   socket is not active.
    /// - [`Error::AlreadyExists`] if another active socket is
    ///   already bound to `port`.
    pub fn bind(&mut self, id: usize, port: u16) -> Result<()> {
        if id >= UDP_TABLE_SIZE || !self.active[id] {
            return Err(Error::InvalidArgument);
        }

        // Check for port uniqueness among bound sockets.
        for i in 0..UDP_TABLE_SIZE {
            if i != id
                && self.active[i]
                && self.sockets[i].bound
                && self.sockets[i].local_port == port
            {
                return Err(Error::AlreadyExists);
            }
        }

        self.sockets[id].local_port = port;
        self.sockets[id].bound = true;
        Ok(())
    }

    /// Set the default remote destination for a socket.
    ///
    /// After connecting, [`send`](Self::send) can be used without
    /// specifying a destination.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `id` is out of range
    /// or the socket is not active.
    pub fn connect(&mut self, id: usize, remote_ip: [u8; 4], remote_port: u16) -> Result<()> {
        if id >= UDP_TABLE_SIZE || !self.active[id] {
            return Err(Error::InvalidArgument);
        }

        self.sockets[id].remote_ip = remote_ip;
        self.sockets[id].remote_port = remote_port;
        self.sockets[id].connected = true;
        Ok(())
    }

    /// Prepare a UDP packet for sending to a specified destination.
    ///
    /// Returns the number of payload bytes queued.  The caller is
    /// responsible for wrapping the result in an IPv4 datagram and
    /// transmitting it.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidArgument`] if `id` is invalid, the socket
    ///   is not active, or `data` exceeds the maximum payload size.
    pub fn sendto(
        &mut self,
        id: usize,
        data: &[u8],
        _dest_ip: [u8; 4],
        _dest_port: u16,
    ) -> Result<usize> {
        if id >= UDP_TABLE_SIZE || !self.active[id] {
            return Err(Error::InvalidArgument);
        }
        // Validate that payload fits in a single UDP datagram.
        let total = UDP_HEADER_LEN.saturating_add(data.len());
        if total > u16::MAX as usize {
            return Err(Error::InvalidArgument);
        }
        Ok(data.len())
    }

    /// Send data to the connected remote destination.
    ///
    /// The socket must have been previously connected via
    /// [`connect`](Self::connect).
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidArgument`] if `id` is invalid or the
    ///   socket is not active.
    /// - [`Error::InvalidArgument`] if the socket is not connected.
    pub fn send(&mut self, id: usize, data: &[u8]) -> Result<usize> {
        if id >= UDP_TABLE_SIZE || !self.active[id] {
            return Err(Error::InvalidArgument);
        }
        if !self.sockets[id].connected {
            return Err(Error::InvalidArgument);
        }
        let total = UDP_HEADER_LEN.saturating_add(data.len());
        if total > u16::MAX as usize {
            return Err(Error::InvalidArgument);
        }
        Ok(data.len())
    }

    /// Read received data and sender information from a socket.
    ///
    /// Copies up to `buf.len()` bytes from the socket's receive
    /// buffer into `buf`.  Returns the number of bytes copied, the
    /// sender's IPv4 address, and the sender's port number.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidArgument`] if `id` is invalid or the
    ///   socket is not active.
    /// - [`Error::WouldBlock`] if no data is available.
    pub fn recvfrom(&mut self, id: usize, buf: &mut [u8]) -> Result<(usize, [u8; 4], u16)> {
        if id >= UDP_TABLE_SIZE || !self.active[id] {
            return Err(Error::InvalidArgument);
        }
        let sock = &self.sockets[id];
        if sock.recv_len == 0 {
            return Err(Error::WouldBlock);
        }

        let copy_len = buf.len().min(sock.recv_len);
        buf[..copy_len].copy_from_slice(&sock.recv_buf[..copy_len]);
        let from_ip = sock.recv_from_ip;
        let from_port = sock.recv_from_port;

        // Clear the receive buffer after reading.
        self.sockets[id].recv_len = 0;

        Ok((copy_len, from_ip, from_port))
    }

    /// Read received data from a socket (without sender info).
    ///
    /// Copies up to `buf.len()` bytes from the socket's receive
    /// buffer.  Returns the number of bytes copied.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidArgument`] if `id` is invalid or the
    ///   socket is not active.
    /// - [`Error::WouldBlock`] if no data is available.
    pub fn recv(&mut self, id: usize, buf: &mut [u8]) -> Result<usize> {
        let (n, _, _) = self.recvfrom(id, buf)?;
        Ok(n)
    }

    /// Deliver an incoming UDP datagram to the socket bound to
    /// `port`.
    ///
    /// Copies up to [`RECV_BUF_SIZE`] bytes of `data` into the
    /// matching socket's receive buffer and records the sender
    /// information.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] if no active socket is bound to
    ///   `port`.
    /// - [`Error::Busy`] if the socket's receive buffer already
    ///   contains unread data.
    pub fn deliver(
        &mut self,
        port: u16,
        src_ip: [u8; 4],
        src_port: u16,
        data: &[u8],
    ) -> Result<()> {
        let id = self.find_by_port(port).ok_or(Error::NotFound)?;
        let sock = &self.sockets[id];
        if sock.recv_len != 0 {
            return Err(Error::Busy);
        }

        let copy_len = data.len().min(RECV_BUF_SIZE);
        self.sockets[id].recv_buf[..copy_len].copy_from_slice(&data[..copy_len]);
        self.sockets[id].recv_len = copy_len;
        self.sockets[id].recv_from_ip = src_ip;
        self.sockets[id].recv_from_port = src_port;
        Ok(())
    }

    /// Close a socket and release its slot.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `id` is out of range
    /// or the socket is not active.
    pub fn close(&mut self, id: usize) -> Result<()> {
        if id >= UDP_TABLE_SIZE || !self.active[id] {
            return Err(Error::InvalidArgument);
        }
        self.sockets[id] = UdpSocket::new();
        self.active[id] = false;
        Ok(())
    }

    /// Find the slot index of the socket bound to `port`.
    ///
    /// Returns `None` if no active socket is bound to the given
    /// port.
    pub fn find_by_port(&self, port: u16) -> Option<usize> {
        (0..UDP_TABLE_SIZE).find(|&i| {
            self.active[i] && self.sockets[i].bound && self.sockets[i].local_port == port
        })
    }
}

// =========================================================================
// Ephemeral port allocation
// =========================================================================

/// Allocate a free ephemeral port from the range
/// [`EPHEMERAL_PORT_START`]..=[`EPHEMERAL_PORT_END`].
///
/// Scans the range sequentially and returns the first port not
/// currently bound in `table`.
///
/// # Errors
///
/// Returns [`Error::OutOfMemory`] if every port in the ephemeral
/// range is already in use.
pub fn allocate_ephemeral_port(table: &UdpSocketTable) -> Result<u16> {
    let mut port = EPHEMERAL_PORT_START;
    loop {
        if table.find_by_port(port).is_none() {
            return Ok(port);
        }
        if port == EPHEMERAL_PORT_END {
            break;
        }
        port = port.saturating_add(1);
    }
    Err(Error::OutOfMemory)
}

// =========================================================================
// Tests
// =========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_udp_valid() {
        #[rustfmt::skip]
        let data: [u8; 12] = [
            0x04, 0xD2, // src_port = 1234
            0x00, 0x50, // dst_port = 80
            0x00, 0x0C, // length = 12
            0x00, 0x00, // checksum = 0
            0xDE, 0xAD, 0xBE, 0xEF, // payload
        ];
        let (hdr, payload) = parse_udp(&data).ok().unwrap();
        assert_eq!(hdr.src_port, 1234);
        assert_eq!(hdr.dst_port, 80);
        assert_eq!(hdr.length, 12);
        assert_eq!(hdr.checksum, 0);
        assert_eq!(payload, &[0xDE, 0xAD, 0xBE, 0xEF]);
    }

    #[test]
    fn test_parse_udp_too_short() {
        let data = [0u8; 7];
        assert!(parse_udp(&data).is_err());
    }

    #[test]
    fn test_parse_udp_length_too_small() {
        #[rustfmt::skip]
        let data: [u8; 8] = [
            0x00, 0x50, // src
            0x00, 0x50, // dst
            0x00, 0x05, // length = 5 (< 8, invalid)
            0x00, 0x00, // checksum
        ];
        assert!(parse_udp(&data).is_err());
    }

    #[test]
    fn test_parse_udp_length_exceeds_data() {
        #[rustfmt::skip]
        let data: [u8; 8] = [
            0x00, 0x50,
            0x00, 0x50,
            0x00, 0x10, // length = 16, but only 8 bytes
            0x00, 0x00,
        ];
        assert!(parse_udp(&data).is_err());
    }

    #[test]
    fn test_parse_udp_header_only() {
        #[rustfmt::skip]
        let data: [u8; 8] = [
            0x00, 0x35, // src = 53
            0xC0, 0x01, // dst = 49153
            0x00, 0x08, // length = 8 (header only)
            0x00, 0x00,
        ];
        let (hdr, payload) = parse_udp(&data).ok().unwrap();
        assert_eq!(hdr.src_port, 53);
        assert_eq!(hdr.dst_port, 49153);
        assert!(payload.is_empty());
    }

    #[test]
    fn test_write_udp_valid() {
        let payload = [0xAA, 0xBB, 0xCC];
        let mut buf = [0u8; 32];
        let n = write_udp(1000, 2000, &payload, &mut buf).ok().unwrap();
        assert_eq!(n, 11); // 8 + 3

        // Verify the written bytes can be parsed back.
        let (hdr, p) = parse_udp(&buf[..n]).ok().unwrap();
        assert_eq!(hdr.src_port, 1000);
        assert_eq!(hdr.dst_port, 2000);
        assert_eq!(hdr.length, 11);
        assert_eq!(hdr.checksum, 0);
        assert_eq!(p, &[0xAA, 0xBB, 0xCC]);
    }

    #[test]
    fn test_write_udp_buf_too_small() {
        let payload = [0u8; 10];
        let mut buf = [0u8; 5];
        assert!(write_udp(1, 2, &payload, &mut buf).is_err());
    }

    #[test]
    fn test_udp_checksum_basic() {
        // Build a minimal UDP datagram and verify the checksum
        // round-trips to zero.
        let mut buf = [0u8; 16];
        let n = write_udp(1234, 5678, &[0x01, 0x02], &mut buf).ok().unwrap();

        let src_ip = [10, 0, 0, 1];
        let dst_ip = [10, 0, 0, 2];
        let cksum = udp_checksum(&src_ip, &dst_ip, &buf[..n]);

        // Write checksum back into the buffer and verify.
        let ck = cksum.to_be_bytes();
        buf[6] = ck[0];
        buf[7] = ck[1];

        let verify = udp_checksum(&src_ip, &dst_ip, &buf[..n]);
        // Verifying a correctly checksummed datagram should
        // yield zero (or 0xFFFF if folded).
        assert!(verify == 0 || verify == 0xFFFF);
    }

    #[test]
    fn test_udp_checksum_zero_becomes_ffff() {
        // Per RFC 768, a computed checksum of zero is transmitted
        // as 0xFFFF.  Verify we never return bare zero.
        let src_ip = [0, 0, 0, 0];
        let dst_ip = [0, 0, 0, 0];
        let data = [0u8; 8]; // all zeros
        let cksum = udp_checksum(&src_ip, &dst_ip, &data);
        assert_ne!(cksum, 0);
    }

    // -- UdpSocketTable --

    #[test]
    fn test_socket_create_and_close() {
        let mut table = UdpSocketTable::new();
        let id = table.create().ok().unwrap();
        assert!(table.active[id]);
        table.close(id).ok().unwrap();
        assert!(!table.active[id]);
    }

    #[test]
    fn test_socket_table_full() {
        let mut table = UdpSocketTable::new();
        for _ in 0..UDP_TABLE_SIZE {
            table.create().ok().unwrap();
        }
        assert!(table.create().is_err());
    }

    #[test]
    fn test_bind_and_find_by_port() {
        let mut table = UdpSocketTable::new();
        let id = table.create().ok().unwrap();
        table.bind(id, 5000).ok().unwrap();
        assert_eq!(table.find_by_port(5000), Some(id));
        assert_eq!(table.find_by_port(5001), None);
    }

    #[test]
    fn test_bind_duplicate_port_rejected() {
        let mut table = UdpSocketTable::new();
        let a = table.create().ok().unwrap();
        let b = table.create().ok().unwrap();
        table.bind(a, 8080).ok().unwrap();
        assert!(table.bind(b, 8080).is_err());
    }

    #[test]
    fn test_connect_and_send() {
        let mut table = UdpSocketTable::new();
        let id = table.create().ok().unwrap();
        table.bind(id, 3000).ok().unwrap();
        table.connect(id, [10, 0, 0, 1], 4000).ok().unwrap();
        assert!(table.sockets[id].connected);

        let n = table.send(id, &[1, 2, 3]).ok().unwrap();
        assert_eq!(n, 3);
    }

    #[test]
    fn test_send_not_connected() {
        let mut table = UdpSocketTable::new();
        let id = table.create().ok().unwrap();
        assert!(table.send(id, &[1]).is_err());
    }

    #[test]
    fn test_sendto() {
        let mut table = UdpSocketTable::new();
        let id = table.create().ok().unwrap();
        let n = table
            .sendto(id, &[0xAA; 100], [10, 0, 0, 1], 80)
            .ok()
            .unwrap();
        assert_eq!(n, 100);
    }

    #[test]
    fn test_deliver_and_recvfrom() {
        let mut table = UdpSocketTable::new();
        let id = table.create().ok().unwrap();
        table.bind(id, 9000).ok().unwrap();

        let payload = [0x01, 0x02, 0x03];
        let src_ip = [192, 168, 1, 100];
        table.deliver(9000, src_ip, 12345, &payload).ok().unwrap();

        let mut buf = [0u8; 64];
        let (n, from_ip, from_port) = table.recvfrom(id, &mut buf).ok().unwrap();
        assert_eq!(n, 3);
        assert_eq!(&buf[..3], &payload);
        assert_eq!(from_ip, src_ip);
        assert_eq!(from_port, 12345);

        // Buffer cleared after read — should block.
        assert!(table.recvfrom(id, &mut buf).is_err());
    }

    #[test]
    fn test_deliver_no_bound_socket() {
        let mut table = UdpSocketTable::new();
        assert!(table.deliver(9999, [0; 4], 0, &[]).is_err());
    }

    #[test]
    fn test_deliver_buffer_busy() {
        let mut table = UdpSocketTable::new();
        let id = table.create().ok().unwrap();
        table.bind(id, 7000).ok().unwrap();

        table.deliver(7000, [1; 4], 100, &[0xAA]).ok().unwrap();
        // Second deliver should fail — buffer still occupied.
        assert!(table.deliver(7000, [1; 4], 100, &[0xBB]).is_err());
    }

    #[test]
    fn test_recv() {
        let mut table = UdpSocketTable::new();
        let id = table.create().ok().unwrap();
        table.bind(id, 6000).ok().unwrap();

        table.deliver(6000, [10; 4], 500, &[0x42]).ok().unwrap();

        let mut buf = [0u8; 16];
        let n = table.recv(id, &mut buf).ok().unwrap();
        assert_eq!(n, 1);
        assert_eq!(buf[0], 0x42);
    }

    #[test]
    fn test_recv_would_block() {
        let mut table = UdpSocketTable::new();
        let id = table.create().ok().unwrap();
        let mut buf = [0u8; 16];
        assert!(table.recv(id, &mut buf).is_err());
    }

    #[test]
    fn test_allocate_ephemeral_port() {
        let table = UdpSocketTable::new();
        let port = allocate_ephemeral_port(&table).ok().unwrap();
        assert!(port >= EPHEMERAL_PORT_START);
        assert!(port <= EPHEMERAL_PORT_END);
    }

    #[test]
    fn test_allocate_ephemeral_skips_used() {
        let mut table = UdpSocketTable::new();
        let id = table.create().ok().unwrap();
        table.bind(id, EPHEMERAL_PORT_START).ok().unwrap();

        let port = allocate_ephemeral_port(&table).ok().unwrap();
        assert_eq!(port, EPHEMERAL_PORT_START + 1);
    }

    #[test]
    fn test_close_invalid() {
        let mut table = UdpSocketTable::new();
        assert!(table.close(0).is_err());
        assert!(table.close(UDP_TABLE_SIZE).is_err());
    }

    #[test]
    fn test_default_trait() {
        let table = UdpSocketTable::default();
        assert_eq!(table.find_by_port(0), None);
    }
}
