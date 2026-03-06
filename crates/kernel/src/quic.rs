// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! QUIC protocol foundations for the ONCRIX network stack.
//!
//! Implements core QUIC (RFC 9000 / RFC 9369) data structures and
//! connection management: version negotiation, packet header
//! parsing, multiplexed streams, and a connection registry.
//!
//! QUIC is a UDP-based, multiplexed, secure transport protocol.
//! This module provides the foundational types and state machine
//! required to manage QUIC connections and streams.

use oncrix_lib::{Error, Result};

// =========================================================================
// Constants
// =========================================================================

/// Maximum connection ID length in bytes (RFC 9000 section 17.2).
const CID_MAX_LEN: usize = 20;

/// Maximum number of streams per connection.
const MAX_STREAMS: usize = 16;

/// Maximum number of concurrent QUIC connections.
const MAX_CONNECTIONS: usize = 32;

/// Stream send/receive buffer size in bytes.
const STREAM_BUF_SIZE: usize = 4096;

/// Minimum QUIC long header size: form(1) + version(4) + dcid_len(1) +
/// scid_len(1) = 7 bytes minimum before CID data.
const LONG_HEADER_MIN: usize = 7;

// =========================================================================
// QuicVersion
// =========================================================================

/// QUIC protocol version identifiers.
///
/// Covers RFC 9000 (v1) and RFC 9369 (v2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u32)]
pub enum QuicVersion {
    /// QUIC version 1 (RFC 9000).
    #[default]
    V1 = 1,
    /// QUIC version 2 (RFC 9369).
    V2 = 0x6b33_43cf,
}

impl QuicVersion {
    /// Try to convert a raw `u32` value into a [`QuicVersion`].
    ///
    /// Returns `None` if the value does not match a known version.
    pub const fn from_u32(v: u32) -> Option<Self> {
        match v {
            1 => Some(Self::V1),
            0x6b33_43cf => Some(Self::V2),
            _ => None,
        }
    }
}

// =========================================================================
// QuicPacketType
// =========================================================================

/// QUIC packet types (RFC 9000 section 17).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum QuicPacketType {
    /// Initial packet — starts connection handshake.
    #[default]
    Initial,
    /// 0-RTT packet — early data before handshake completes.
    ZeroRtt,
    /// Handshake packet — carries handshake messages.
    Handshake,
    /// Retry packet — server requests address validation.
    Retry,
    /// Short header packet — used after handshake completion.
    Short,
}

// =========================================================================
// QuicHeader
// =========================================================================

/// Parsed QUIC packet header.
///
/// Supports both long-form (Initial, Handshake, 0-RTT, Retry) and
/// short-form (post-handshake) headers.  Connection IDs are stored
/// in fixed-size arrays with explicit length fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct QuicHeader {
    /// Header form: 1 for long header, 0 for short header.
    pub form: u8,
    /// QUIC version (0 for short headers).
    pub version: u32,
    /// Length of the destination connection ID.
    pub dcid_len: u8,
    /// Destination connection ID (up to 20 bytes).
    pub dcid: [u8; CID_MAX_LEN],
    /// Length of the source connection ID.
    pub scid_len: u8,
    /// Source connection ID (up to 20 bytes).
    pub scid: [u8; CID_MAX_LEN],
    /// Packet number.
    pub packet_number: u64,
    /// Payload length in bytes.
    pub payload_len: u16,
}

impl Default for QuicHeader {
    fn default() -> Self {
        Self {
            form: 1,
            version: QuicVersion::V1 as u32,
            dcid_len: 0,
            dcid: [0; CID_MAX_LEN],
            scid_len: 0,
            scid: [0; CID_MAX_LEN],
            packet_number: 0,
            payload_len: 0,
        }
    }
}

// =========================================================================
// QuicStreamId
// =========================================================================

/// QUIC stream identifier.
///
/// The low 2 bits encode the stream type:
/// - Bit 0: initiator (0 = client, 1 = server)
/// - Bit 1: directionality (0 = bidirectional, 1 = unidirectional)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct QuicStreamId {
    /// Raw stream identifier.
    pub id: u64,
}

impl QuicStreamId {
    /// Create a new stream identifier.
    pub const fn new(id: u64) -> Self {
        Self { id }
    }

    /// Returns `true` if this stream was initiated by the client.
    pub const fn is_client_initiated(&self) -> bool {
        (self.id & 0x01) == 0
    }

    /// Returns `true` if this stream was initiated by the server.
    pub const fn is_server_initiated(&self) -> bool {
        (self.id & 0x01) != 0
    }

    /// Returns `true` if this is a bidirectional stream.
    pub const fn is_bidirectional(&self) -> bool {
        (self.id & 0x02) == 0
    }

    /// Returns `true` if this is a unidirectional stream.
    pub const fn is_unidirectional(&self) -> bool {
        (self.id & 0x02) != 0
    }
}

// =========================================================================
// QuicStream
// =========================================================================

/// A single QUIC stream with send and receive buffers.
///
/// Each stream supports independent bidirectional or unidirectional
/// data flow with flow-control offsets and FIN tracking.
pub struct QuicStream {
    /// Stream identifier.
    pub id: QuicStreamId,
    /// Send buffer.
    send_buf: [u8; STREAM_BUF_SIZE],
    /// Number of valid bytes in the send buffer.
    send_len: usize,
    /// Receive buffer.
    recv_buf: [u8; STREAM_BUF_SIZE],
    /// Number of valid bytes in the receive buffer.
    recv_len: usize,
    /// Cumulative send offset (total bytes sent on this stream).
    pub send_offset: u64,
    /// Cumulative receive offset (total bytes received on this stream).
    pub recv_offset: u64,
    /// Whether a FIN has been sent on this stream.
    pub fin_sent: bool,
    /// Whether a FIN has been received on this stream.
    pub fin_received: bool,
    /// Whether this stream slot is active.
    pub active: bool,
}

impl QuicStream {
    /// Create a new, inactive stream.
    const fn new() -> Self {
        Self {
            id: QuicStreamId { id: 0 },
            send_buf: [0; STREAM_BUF_SIZE],
            send_len: 0,
            recv_buf: [0; STREAM_BUF_SIZE],
            recv_len: 0,
            send_offset: 0,
            recv_offset: 0,
            fin_sent: false,
            fin_received: false,
            active: false,
        }
    }

    /// Write data into the stream's send buffer.
    ///
    /// Copies as many bytes as possible from `data` into the send
    /// buffer and advances the send offset.  Returns the number of
    /// bytes actually written.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidArgument`] if the stream is not active.
    /// - [`Error::InvalidArgument`] if `data` is empty.
    /// - [`Error::WouldBlock`] if the send buffer is full.
    pub fn write(&mut self, data: &[u8]) -> Result<usize> {
        if !self.active {
            return Err(Error::InvalidArgument);
        }
        if data.is_empty() {
            return Err(Error::InvalidArgument);
        }
        let avail = STREAM_BUF_SIZE.saturating_sub(self.send_len);
        if avail == 0 {
            return Err(Error::WouldBlock);
        }
        let copy_len = data.len().min(avail);
        let dst_start = self.send_len;
        self.send_buf[dst_start..dst_start + copy_len].copy_from_slice(&data[..copy_len]);
        self.send_len += copy_len;
        self.send_offset = self.send_offset.wrapping_add(copy_len as u64);
        Ok(copy_len)
    }

    /// Read data from the stream's receive buffer.
    ///
    /// Copies up to `buf.len()` bytes from the receive buffer and
    /// clears the consumed portion.  Returns the number of bytes
    /// copied.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidArgument`] if the stream is not active.
    /// - [`Error::WouldBlock`] if no data is available.
    pub fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        if !self.active {
            return Err(Error::InvalidArgument);
        }
        if self.recv_len == 0 {
            return Err(Error::WouldBlock);
        }
        let copy_len = buf.len().min(self.recv_len);
        buf[..copy_len].copy_from_slice(&self.recv_buf[..copy_len]);

        // Shift remaining data to the front.
        let remaining = self.recv_len - copy_len;
        if remaining > 0 {
            let mut i = 0;
            while i < remaining {
                self.recv_buf[i] = self.recv_buf[copy_len + i];
                i += 1;
            }
        }
        self.recv_len = remaining;

        Ok(copy_len)
    }
}

// =========================================================================
// QuicConnectionState
// =========================================================================

/// QUIC connection state machine states.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum QuicConnectionState {
    /// No connection established.
    #[default]
    Idle,
    /// TLS handshake in progress.
    Handshaking,
    /// Connection fully established.
    Connected,
    /// Connection is draining (closing gracefully).
    Draining,
    /// Connection is closed.
    Closed,
}

// =========================================================================
// QuicConnection
// =========================================================================

/// A single QUIC connection with multiplexed streams.
///
/// Manages connection state, connection IDs, stream table,
/// packet numbering, and peer addressing.
pub struct QuicConnection {
    /// Unique connection identifier (internal registry key).
    pub id: u64,
    /// Current connection state.
    pub state: QuicConnectionState,
    /// Local connection ID.
    pub local_cid: [u8; CID_MAX_LEN],
    /// Remote connection ID.
    pub remote_cid: [u8; CID_MAX_LEN],
    /// Length of the connection IDs in use.
    pub cid_len: u8,
    /// Stream table.
    streams: [QuicStream; MAX_STREAMS],
    /// Number of active streams.
    stream_count: usize,
    /// Negotiated QUIC version.
    pub version: QuicVersion,
    /// Next packet number to assign.
    pub next_packet_number: u64,
    /// Peer IPv4 address (host byte order).
    pub peer_addr: u32,
    /// Peer UDP port.
    pub peer_port: u16,
    /// Idle timeout in milliseconds (0 = no timeout).
    pub idle_timeout_ms: u64,
}

impl QuicConnection {
    /// Create a new connection in the [`Idle`](QuicConnectionState::Idle)
    /// state.
    const fn new() -> Self {
        const EMPTY_STREAM: QuicStream = QuicStream::new();
        Self {
            id: 0,
            state: QuicConnectionState::Idle,
            local_cid: [0; CID_MAX_LEN],
            remote_cid: [0; CID_MAX_LEN],
            cid_len: 0,
            streams: [EMPTY_STREAM; MAX_STREAMS],
            stream_count: 0,
            version: QuicVersion::V1,
            next_packet_number: 0,
            peer_addr: 0,
            peer_port: 0,
            idle_timeout_ms: 30_000,
        }
    }

    /// Open a new stream on this connection.
    ///
    /// `stream_type` encodes the low 2 bits of the stream ID
    /// (initiator + directionality).  Returns the assigned stream ID.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidArgument`] if the connection is not in the
    ///   [`Connected`](QuicConnectionState::Connected) state.
    /// - [`Error::OutOfMemory`] if the stream table is full.
    pub fn open_stream(&mut self, stream_type: u64) -> Result<u64> {
        if self.state != QuicConnectionState::Connected {
            return Err(Error::InvalidArgument);
        }

        let slot = self
            .streams
            .iter()
            .position(|s| !s.active)
            .ok_or(Error::OutOfMemory)?;

        // Stream ID = (stream_count * 4) | (stream_type & 0x03)
        let stream_id = ((self.stream_count as u64) << 2) | (stream_type & 0x03);

        self.streams[slot].id = QuicStreamId::new(stream_id);
        self.streams[slot].active = true;
        self.streams[slot].send_len = 0;
        self.streams[slot].recv_len = 0;
        self.streams[slot].send_offset = 0;
        self.streams[slot].recv_offset = 0;
        self.streams[slot].fin_sent = false;
        self.streams[slot].fin_received = false;
        self.stream_count += 1;

        Ok(stream_id)
    }

    /// Close a stream by its stream ID.
    ///
    /// Marks the stream as inactive and decrements the active stream
    /// count.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if no active stream matches
    /// `stream_id`.
    pub fn close_stream(&mut self, stream_id: u64) -> Result<()> {
        let slot = self
            .streams
            .iter()
            .position(|s| s.active && s.id.id == stream_id)
            .ok_or(Error::NotFound)?;

        self.streams[slot].active = false;
        self.stream_count = self.stream_count.saturating_sub(1);
        Ok(())
    }

    /// Send data on a specific stream.
    ///
    /// Writes `data` into the stream's send buffer.  Returns the
    /// number of bytes queued.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidArgument`] if the connection is not
    ///   [`Connected`](QuicConnectionState::Connected).
    /// - [`Error::NotFound`] if no active stream matches `stream_id`.
    /// - Propagates errors from [`QuicStream::write`].
    pub fn send(&mut self, stream_id: u64, data: &[u8]) -> Result<usize> {
        if self.state != QuicConnectionState::Connected {
            return Err(Error::InvalidArgument);
        }

        let slot = self
            .streams
            .iter()
            .position(|s| s.active && s.id.id == stream_id)
            .ok_or(Error::NotFound)?;

        self.streams[slot].write(data)
    }

    /// Receive data from a specific stream.
    ///
    /// Reads available data from the stream's receive buffer into
    /// `buf`.  Returns the number of bytes copied.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidArgument`] if the connection is not
    ///   [`Connected`](QuicConnectionState::Connected).
    /// - [`Error::NotFound`] if no active stream matches `stream_id`.
    /// - Propagates errors from [`QuicStream::read`].
    pub fn recv(&mut self, stream_id: u64, buf: &mut [u8]) -> Result<usize> {
        if self.state != QuicConnectionState::Connected {
            return Err(Error::InvalidArgument);
        }

        let slot = self
            .streams
            .iter()
            .position(|s| s.active && s.id.id == stream_id)
            .ok_or(Error::NotFound)?;

        self.streams[slot].read(buf)
    }

    /// Process an incoming QUIC packet.
    ///
    /// Handles connection state transitions based on the packet
    /// header.  For Initial packets, transitions from
    /// [`Idle`](QuicConnectionState::Idle) to
    /// [`Handshaking`](QuicConnectionState::Handshaking).  For
    /// Handshake packets, transitions to
    /// [`Connected`](QuicConnectionState::Connected).
    ///
    /// Payload data for Short packets is delivered to the first
    /// active stream's receive buffer.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidArgument`] if the connection is
    ///   [`Closed`](QuicConnectionState::Closed).
    pub fn process_packet(&mut self, header: &QuicHeader, payload: &[u8]) -> Result<()> {
        if self.state == QuicConnectionState::Closed {
            return Err(Error::InvalidArgument);
        }

        // Determine packet type from the header.
        let pkt_type = if header.form == 0 {
            QuicPacketType::Short
        } else {
            // Long header — use version + first two bits of form byte
            // to distinguish.  Simplified mapping for the foundation.
            match header.version {
                0 => QuicPacketType::Retry,
                _ => {
                    if self.state == QuicConnectionState::Idle {
                        QuicPacketType::Initial
                    } else {
                        QuicPacketType::Handshake
                    }
                }
            }
        };

        match pkt_type {
            QuicPacketType::Initial => {
                if self.state == QuicConnectionState::Idle {
                    self.state = QuicConnectionState::Handshaking;
                    // Store remote CID from the header.
                    let len = (header.scid_len as usize).min(CID_MAX_LEN);
                    self.remote_cid[..len].copy_from_slice(&header.scid[..len]);
                    self.cid_len = header.scid_len;
                }
            }
            QuicPacketType::Handshake => {
                if self.state == QuicConnectionState::Handshaking {
                    self.state = QuicConnectionState::Connected;
                }
            }
            QuicPacketType::Short => {
                // Deliver payload to the first active stream.
                if !payload.is_empty() {
                    if let Some(stream) = self.streams.iter_mut().find(|s| s.active) {
                        let avail = STREAM_BUF_SIZE.saturating_sub(stream.recv_len);
                        let copy_len = payload.len().min(avail);
                        if copy_len > 0 {
                            let start = stream.recv_len;
                            stream.recv_buf[start..start + copy_len]
                                .copy_from_slice(&payload[..copy_len]);
                            stream.recv_len += copy_len;
                            stream.recv_offset = stream.recv_offset.wrapping_add(copy_len as u64);
                        }
                    }
                }
            }
            QuicPacketType::Retry => {
                // Retry packets reset to handshaking state.
                if self.state == QuicConnectionState::Handshaking {
                    self.state = QuicConnectionState::Handshaking;
                }
            }
            QuicPacketType::ZeroRtt => {
                // 0-RTT data delivery — treat like Short for now.
            }
        }

        self.next_packet_number = self.next_packet_number.wrapping_add(1);
        Ok(())
    }

    /// Build a QUIC packet into `buf`.
    ///
    /// Serialises a long-form QUIC header using the connection's
    /// current state and drains data from the first active stream's
    /// send buffer as payload.  Returns the total number of bytes
    /// written.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidArgument`] if `buf` is too small for the
    ///   minimum header.
    pub fn build_packet(&mut self, buf: &mut [u8]) -> Result<usize> {
        // Minimum space: form(1) + version(4) + dcid_len(1) + dcid +
        // scid_len(1) + scid.
        let cid_len = self.cid_len as usize;
        let header_size = LONG_HEADER_MIN + cid_len + cid_len;
        if buf.len() < header_size {
            return Err(Error::InvalidArgument);
        }

        // Form byte: long header (bit 7 set) + fixed bit (bit 6 set).
        buf[0] = 0xC0;

        // Version.
        let ver = (self.version as u32).to_be_bytes();
        buf[1] = ver[0];
        buf[2] = ver[1];
        buf[3] = ver[2];
        buf[4] = ver[3];

        // DCID.
        buf[5] = self.cid_len;
        let dcid_end = 6 + cid_len;
        buf[6..dcid_end].copy_from_slice(&self.remote_cid[..cid_len]);

        // SCID.
        buf[dcid_end] = self.cid_len;
        let scid_end = dcid_end + 1 + cid_len;
        buf[dcid_end + 1..scid_end].copy_from_slice(&self.local_cid[..cid_len]);

        // Drain send data from first active stream.
        let mut payload_len: usize = 0;
        if let Some(stream) = self.streams.iter_mut().find(|s| s.active && s.send_len > 0) {
            let avail = buf.len().saturating_sub(scid_end);
            let copy_len = stream.send_len.min(avail);
            if copy_len > 0 {
                buf[scid_end..scid_end + copy_len].copy_from_slice(&stream.send_buf[..copy_len]);
                // Shift remaining data in send buffer.
                let remaining = stream.send_len - copy_len;
                let mut i = 0;
                while i < remaining {
                    stream.send_buf[i] = stream.send_buf[copy_len + i];
                    i += 1;
                }
                stream.send_len = remaining;
                payload_len = copy_len;
            }
        }

        self.next_packet_number = self.next_packet_number.wrapping_add(1);

        Ok(scid_end + payload_len)
    }

    /// Close this connection.
    ///
    /// Transitions the connection to
    /// [`Draining`](QuicConnectionState::Draining) if currently
    /// active, then to [`Closed`](QuicConnectionState::Closed).
    /// All streams are deactivated.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if the connection is
    /// already [`Closed`](QuicConnectionState::Closed).
    pub fn close(&mut self) -> Result<()> {
        if self.state == QuicConnectionState::Closed {
            return Err(Error::InvalidArgument);
        }

        // Deactivate all streams.
        self.streams.iter_mut().for_each(|s| {
            s.active = false;
        });
        self.stream_count = 0;
        self.state = QuicConnectionState::Closed;
        Ok(())
    }
}

// =========================================================================
// QuicRegistry
// =========================================================================

/// Registry of QUIC connections.
///
/// Manages up to [`MAX_CONNECTIONS`] (32) concurrent connections,
/// providing connection creation, lookup, and incoming packet
/// dispatch.
pub struct QuicRegistry {
    /// Fixed-size array of connection slots.
    connections: [QuicConnection; MAX_CONNECTIONS],
    /// Number of active connections.
    count: usize,
}

impl Default for QuicRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl QuicRegistry {
    /// Create an empty connection registry.
    pub const fn new() -> Self {
        const EMPTY: QuicConnection = QuicConnection::new();
        Self {
            connections: [EMPTY; MAX_CONNECTIONS],
            count: 0,
        }
    }

    /// Initiate a new outgoing connection to `peer_addr`:`peer_port`.
    ///
    /// Allocates a connection slot, assigns an ID, sets the peer
    /// address, and transitions the connection to
    /// [`Handshaking`](QuicConnectionState::Handshaking).
    /// Returns the connection ID.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the registry is full.
    pub fn connect(&mut self, peer_addr: u32, peer_port: u16) -> Result<u64> {
        let slot = self
            .connections
            .iter()
            .position(|c| {
                c.state == QuicConnectionState::Idle || c.state == QuicConnectionState::Closed
            })
            .ok_or(Error::OutOfMemory)?;

        let conn_id = (slot as u64).wrapping_add(1);
        self.connections[slot] = QuicConnection::new();
        self.connections[slot].id = conn_id;
        self.connections[slot].peer_addr = peer_addr;
        self.connections[slot].peer_port = peer_port;
        self.connections[slot].state = QuicConnectionState::Handshaking;
        self.count = self.count.saturating_add(1);
        Ok(conn_id)
    }

    /// Accept an incoming connection from a received Initial packet.
    ///
    /// Allocates a connection slot, copies connection IDs from the
    /// header, and transitions to
    /// [`Handshaking`](QuicConnectionState::Handshaking).
    /// Returns the connection ID.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the registry is full.
    pub fn accept(&mut self, header: &QuicHeader) -> Result<u64> {
        let slot = self
            .connections
            .iter()
            .position(|c| {
                c.state == QuicConnectionState::Idle || c.state == QuicConnectionState::Closed
            })
            .ok_or(Error::OutOfMemory)?;

        let conn_id = (slot as u64).wrapping_add(1);
        self.connections[slot] = QuicConnection::new();
        self.connections[slot].id = conn_id;
        self.connections[slot].state = QuicConnectionState::Handshaking;

        // Copy connection IDs from the incoming header.
        let dcid_len = (header.dcid_len as usize).min(CID_MAX_LEN);
        self.connections[slot].local_cid[..dcid_len].copy_from_slice(&header.dcid[..dcid_len]);
        let scid_len = (header.scid_len as usize).min(CID_MAX_LEN);
        self.connections[slot].remote_cid[..scid_len].copy_from_slice(&header.scid[..scid_len]);
        self.connections[slot].cid_len = header.dcid_len.max(header.scid_len);

        self.count = self.count.saturating_add(1);
        Ok(conn_id)
    }

    /// Get an immutable reference to a connection by ID.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if no connection with the given
    /// ID exists.
    pub fn get(&self, id: u64) -> Result<&QuicConnection> {
        self.connections
            .iter()
            .find(|c| c.id == id && c.state != QuicConnectionState::Idle)
            .ok_or(Error::NotFound)
    }

    /// Get a mutable reference to a connection by ID.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if no connection with the given
    /// ID exists.
    pub fn get_mut(&mut self, id: u64) -> Result<&mut QuicConnection> {
        self.connections
            .iter_mut()
            .find(|c| c.id == id && c.state != QuicConnectionState::Idle)
            .ok_or(Error::NotFound)
    }

    /// Close a connection by ID.
    ///
    /// Closes the connection and decrements the active count.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if no connection with the given
    /// ID exists.
    pub fn close(&mut self, id: u64) -> Result<()> {
        let conn = self
            .connections
            .iter_mut()
            .find(|c| c.id == id && c.state != QuicConnectionState::Idle)
            .ok_or(Error::NotFound)?;

        conn.close()?;
        self.count = self.count.saturating_sub(1);
        Ok(())
    }

    /// Dispatch an incoming packet to the matching connection.
    ///
    /// Looks up the connection by matching the destination connection
    /// ID in the header.  If found, delegates to
    /// [`QuicConnection::process_packet`].
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if no active connection matches
    /// the header's destination CID.
    pub fn process_incoming(&mut self, header: &QuicHeader, payload: &[u8]) -> Result<()> {
        let dcid_len = (header.dcid_len as usize).min(CID_MAX_LEN);

        let conn = self
            .connections
            .iter_mut()
            .find(|c| {
                c.state != QuicConnectionState::Idle
                    && c.state != QuicConnectionState::Closed
                    && c.local_cid[..dcid_len] == header.dcid[..dcid_len]
            })
            .ok_or(Error::NotFound)?;

        conn.process_packet(header, payload)
    }

    /// Return the number of active connections.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Return `true` if no connections are active.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
}
