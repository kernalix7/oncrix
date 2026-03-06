// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Stream Control Transmission Protocol (SCTP) for the ONCRIX network stack.
//!
//! Implements RFC 4960 SCTP header parsing, chunk encoding, multi-stream
//! association management, and a global endpoint registry.
//!
//! # Architecture
//!
//! ```text
//! SctpRegistry ──► SctpEndpoint (bound port)
//!                     └──► SctpAssociation (peer state machine)
//!                            └──► SctpStream (per-stream sequencing)
//! ```
//!
//! Key components:
//!
//! - [`SctpHeader`]: common SCTP header (12 bytes, `#[repr(C)]`).
//! - [`SctpChunkType`]: 13 chunk types covering connection, data, and
//!   shutdown lifecycle.
//! - [`SctpChunk`]: a single SCTP chunk with type, flags, length, and
//!   up to [`CHUNK_DATA_MAX`] bytes of payload.
//! - [`SctpStream`]: per-stream send and receive sequence numbers.
//! - [`SctpAssociation`]: association FSM with 8 states, 16 streams,
//!   and TSN tracking.
//! - [`SctpEndpoint`]: a local port binding holding up to 8
//!   associations.
//! - [`SctpRegistry`]: system-wide registry of up to 32 endpoints.
//!
//! Reference: RFC 4960, RFC 3286 (introduction).

use oncrix_lib::{Error, Result};

// =========================================================================
// Constants
// =========================================================================

/// SCTP common header size in bytes (src_port + dst_port + vtag + checksum).
const SCTP_HEADER_LEN: usize = 12;

/// Minimum chunk header size in bytes (type + flags + length).
const CHUNK_HEADER_LEN: usize = 4;

/// Maximum chunk data payload in bytes.
const CHUNK_DATA_MAX: usize = 512;

/// Maximum number of streams per association.
const MAX_STREAMS: usize = 16;

/// Maximum number of associations per endpoint.
const MAX_ASSOCIATIONS: usize = 8;

/// Maximum number of endpoints in the registry.
const MAX_ENDPOINTS: usize = 32;

/// Receive buffer size per association (bytes).
const RECV_BUF_SIZE: usize = 4096;

/// Send buffer size per association (bytes).
const SEND_BUF_SIZE: usize = 4096;

/// IP protocol number for SCTP.
const _PROTO_SCTP: u8 = 132;

// =========================================================================
// SctpHeader
// =========================================================================

/// Parsed SCTP common header (RFC 4960 section 3).
///
/// The 12-byte header precedes all chunks in an SCTP packet.  Fields
/// are stored in host byte order after parsing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct SctpHeader {
    /// Source port number.
    pub src_port: u16,
    /// Destination port number.
    pub dst_port: u16,
    /// Verification tag for association demultiplexing.
    pub verification_tag: u32,
    /// CRC-32c checksum over the entire SCTP packet.
    pub checksum: u32,
}

// =========================================================================
// parse_sctp_header
// =========================================================================

/// Parse an SCTP common header from raw bytes.
///
/// Returns the parsed [`SctpHeader`] and a slice referencing the
/// remaining chunk data.
///
/// # Errors
///
/// Returns [`Error::InvalidArgument`] if `data` is shorter than
/// [`SCTP_HEADER_LEN`] (12 bytes).
pub fn parse_sctp_header(data: &[u8]) -> Result<(SctpHeader, &[u8])> {
    if data.len() < SCTP_HEADER_LEN {
        return Err(Error::InvalidArgument);
    }

    let src_port = u16::from_be_bytes([data[0], data[1]]);
    let dst_port = u16::from_be_bytes([data[2], data[3]]);
    let verification_tag = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
    let checksum = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);

    let header = SctpHeader {
        src_port,
        dst_port,
        verification_tag,
        checksum,
    };

    Ok((header, &data[SCTP_HEADER_LEN..]))
}

/// Serialise an SCTP common header into `buf`.
///
/// Writes a 12-byte header.  Returns the number of bytes written.
///
/// # Errors
///
/// Returns [`Error::InvalidArgument`] if `buf` is too small.
pub fn write_sctp_header(header: &SctpHeader, buf: &mut [u8]) -> Result<usize> {
    if buf.len() < SCTP_HEADER_LEN {
        return Err(Error::InvalidArgument);
    }

    buf[0..2].copy_from_slice(&header.src_port.to_be_bytes());
    buf[2..4].copy_from_slice(&header.dst_port.to_be_bytes());
    buf[4..8].copy_from_slice(&header.verification_tag.to_be_bytes());
    buf[8..12].copy_from_slice(&header.checksum.to_be_bytes());

    Ok(SCTP_HEADER_LEN)
}

// =========================================================================
// SctpChunkType
// =========================================================================

/// SCTP chunk type identifiers (RFC 4960 section 3.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SctpChunkType {
    /// Payload data (DATA chunk).
    Data = 0,
    /// Initiate association (INIT chunk).
    Init = 1,
    /// Acknowledge initiation (INIT ACK chunk).
    InitAck = 2,
    /// Selective acknowledgement (SACK chunk).
    Sack = 3,
    /// Heartbeat request.
    Heartbeat = 4,
    /// Heartbeat acknowledgement.
    HeartbeatAck = 5,
    /// Abort association.
    Abort = 6,
    /// Initiate graceful shutdown.
    Shutdown = 7,
    /// Acknowledge shutdown.
    ShutdownAck = 8,
    /// Operational error notification.
    Error = 9,
    /// Cookie echo (state cookie from INIT ACK).
    CookieEcho = 10,
    /// Cookie acknowledgement.
    CookieAck = 11,
    /// Shutdown complete.
    ShutdownComplete = 14,
}

impl SctpChunkType {
    /// Convert a raw byte to an `SctpChunkType`.
    ///
    /// Returns [`Error::InvalidArgument`] for unrecognised types.
    pub fn from_raw(raw: u8) -> Result<Self> {
        match raw {
            0 => Ok(Self::Data),
            1 => Ok(Self::Init),
            2 => Ok(Self::InitAck),
            3 => Ok(Self::Sack),
            4 => Ok(Self::Heartbeat),
            5 => Ok(Self::HeartbeatAck),
            6 => Ok(Self::Abort),
            7 => Ok(Self::Shutdown),
            8 => Ok(Self::ShutdownAck),
            9 => Ok(Self::Error),
            10 => Ok(Self::CookieEcho),
            11 => Ok(Self::CookieAck),
            14 => Ok(Self::ShutdownComplete),
            _ => Err(Error::InvalidArgument),
        }
    }
}

// =========================================================================
// SctpChunk
// =========================================================================

/// A single SCTP chunk with header and payload.
///
/// Each SCTP packet may carry one or more chunks.  The chunk header
/// is 4 bytes (type + flags + 16-bit length) followed by up to
/// [`CHUNK_DATA_MAX`] bytes of type-specific data.
#[derive(Clone)]
#[repr(C)]
pub struct SctpChunk {
    /// Chunk type.
    pub chunk_type: SctpChunkType,
    /// Chunk-type-specific flags.
    pub flags: u8,
    /// Total chunk length including header (network order stores u16).
    pub length: u16,
    /// Chunk-specific data payload.
    pub data: [u8; CHUNK_DATA_MAX],
    /// Number of valid bytes in `data`.
    pub data_len: usize,
}

impl Default for SctpChunk {
    fn default() -> Self {
        Self::new(SctpChunkType::Data)
    }
}

impl SctpChunk {
    /// Create an empty chunk of the given type.
    pub const fn new(chunk_type: SctpChunkType) -> Self {
        Self {
            chunk_type,
            flags: 0,
            length: CHUNK_HEADER_LEN as u16,
            data: [0u8; CHUNK_DATA_MAX],
            data_len: 0,
        }
    }

    /// Parse a chunk from raw bytes.
    ///
    /// Returns the parsed chunk and the number of bytes consumed
    /// (rounded up to a 4-byte boundary per RFC 4960 section 3.2).
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if the data is too short
    /// or the chunk type is unrecognised.
    pub fn parse(data: &[u8]) -> Result<(Self, usize)> {
        if data.len() < CHUNK_HEADER_LEN {
            return Err(Error::InvalidArgument);
        }

        let chunk_type = SctpChunkType::from_raw(data[0])?;
        let flags = data[1];
        let length = u16::from_be_bytes([data[2], data[3]]);

        let len = length as usize;
        if len < CHUNK_HEADER_LEN || len > data.len() {
            return Err(Error::InvalidArgument);
        }

        let payload_len = len - CHUNK_HEADER_LEN;
        if payload_len > CHUNK_DATA_MAX {
            return Err(Error::InvalidArgument);
        }

        let mut chunk = Self::new(chunk_type);
        chunk.flags = flags;
        chunk.length = length;
        if payload_len > 0 {
            chunk.data[..payload_len].copy_from_slice(&data[CHUNK_HEADER_LEN..len]);
        }
        chunk.data_len = payload_len;

        // Chunks are padded to 4-byte boundaries.
        let padded = (len + 3) & !3;
        let consumed = if padded > data.len() {
            data.len()
        } else {
            padded
        };

        Ok((chunk, consumed))
    }

    /// Serialise this chunk into `buf`.
    ///
    /// Returns the number of bytes written (padded to 4-byte boundary).
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `buf` is too small.
    pub fn write(&self, buf: &mut [u8]) -> Result<usize> {
        let total = CHUNK_HEADER_LEN + self.data_len;
        let padded = (total + 3) & !3;
        if buf.len() < padded {
            return Err(Error::InvalidArgument);
        }

        buf[0] = self.chunk_type as u8;
        buf[1] = self.flags;
        buf[2..4].copy_from_slice(&(total as u16).to_be_bytes());
        if self.data_len > 0 {
            buf[CHUNK_HEADER_LEN..total].copy_from_slice(&self.data[..self.data_len]);
        }
        // Zero padding bytes.
        for b in buf[total..padded].iter_mut() {
            *b = 0;
        }

        Ok(padded)
    }
}

// =========================================================================
// SctpStream
// =========================================================================

/// Per-stream state within an SCTP association.
///
/// SCTP supports multiple independent streams inside a single
/// association.  Each stream maintains its own send and receive
/// sequence numbers for ordered delivery.
#[derive(Debug, Clone, Copy)]
pub struct SctpStream {
    /// Stream identifier (0..MAX_STREAMS-1).
    pub stream_id: u16,
    /// Next send stream sequence number.
    pub next_ssn: u16,
    /// Next expected receive stream sequence number.
    pub next_rsn: u16,
    /// Whether this stream slot is in use.
    pub active: bool,
}

impl Default for SctpStream {
    fn default() -> Self {
        Self::new(0)
    }
}

impl SctpStream {
    /// Create a new inactive stream with the given ID.
    pub const fn new(stream_id: u16) -> Self {
        Self {
            stream_id,
            next_ssn: 0,
            next_rsn: 0,
            active: false,
        }
    }

    /// Activate this stream and reset sequence numbers.
    pub fn activate(&mut self) {
        self.active = true;
        self.next_ssn = 0;
        self.next_rsn = 0;
    }

    /// Advance the send sequence number and return the previous value.
    pub fn advance_ssn(&mut self) -> u16 {
        let ssn = self.next_ssn;
        self.next_ssn = self.next_ssn.wrapping_add(1);
        ssn
    }

    /// Advance the receive sequence number and return the previous value.
    pub fn advance_rsn(&mut self) -> u16 {
        let rsn = self.next_rsn;
        self.next_rsn = self.next_rsn.wrapping_add(1);
        rsn
    }
}

// =========================================================================
// SctpAssociationState
// =========================================================================

/// SCTP association states (RFC 4960 section 4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SctpAssociationState {
    /// No association exists.
    Closed,
    /// INIT sent; awaiting INIT ACK.
    CookieWait,
    /// COOKIE ECHO sent; awaiting COOKIE ACK.
    CookieEchoed,
    /// Association fully established; data transfer active.
    Established,
    /// Local close requested; waiting for outstanding data.
    ShutdownPending,
    /// SHUTDOWN sent; awaiting SHUTDOWN ACK.
    ShutdownSent,
    /// SHUTDOWN received; draining local send queue.
    ShutdownReceived,
    /// SHUTDOWN ACK sent; awaiting SHUTDOWN COMPLETE.
    ShutdownAckSent,
}

// =========================================================================
// SctpAssociation
// =========================================================================

/// An SCTP association representing a connection to a single peer.
///
/// Manages the association state machine, up to [`MAX_STREAMS`]
/// streams, TSN tracking for reliability, and send/receive buffers.
pub struct SctpAssociation {
    /// Current association state.
    pub state: SctpAssociationState,
    /// Peer verification tag (sent in outgoing packets).
    pub peer_vtag: u32,
    /// Local verification tag (expected in incoming packets).
    pub local_vtag: u32,
    /// Next Transmission Sequence Number to assign.
    pub next_tsn: u32,
    /// Cumulative TSN acknowledged by the peer.
    pub cumulative_tsn_ack: u32,
    /// Remote port.
    pub peer_port: u16,
    /// Remote IPv4 address.
    pub peer_ip: [u8; 4],
    /// Whether this association slot is in use.
    pub active: bool,
    /// Per-stream state.
    streams: [SctpStream; MAX_STREAMS],
    /// Number of active streams.
    num_streams: usize,
    /// Send buffer.
    send_buf: [u8; SEND_BUF_SIZE],
    /// Valid bytes in the send buffer.
    send_len: usize,
    /// Receive buffer.
    recv_buf: [u8; RECV_BUF_SIZE],
    /// Valid bytes in the receive buffer.
    recv_len: usize,
}

impl Default for SctpAssociation {
    fn default() -> Self {
        Self::new()
    }
}

impl SctpAssociation {
    /// Create a new association in the `Closed` state.
    pub const fn new() -> Self {
        Self {
            state: SctpAssociationState::Closed,
            peer_vtag: 0,
            local_vtag: 0,
            next_tsn: 1,
            cumulative_tsn_ack: 0,
            peer_port: 0,
            peer_ip: [0; 4],
            active: false,
            streams: [const { SctpStream::new(0) }; MAX_STREAMS],
            num_streams: 0,
            send_buf: [0; SEND_BUF_SIZE],
            send_len: 0,
            recv_buf: [0; RECV_BUF_SIZE],
            recv_len: 0,
        }
    }

    /// Initiate an active open by sending INIT.
    ///
    /// Transitions from `Closed` to `CookieWait`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if not in the `Closed`
    /// state.
    pub fn initiate(
        &mut self,
        peer_ip: [u8; 4],
        peer_port: u16,
        local_vtag: u32,
    ) -> Result<SctpChunk> {
        if self.state != SctpAssociationState::Closed {
            return Err(Error::InvalidArgument);
        }

        self.peer_ip = peer_ip;
        self.peer_port = peer_port;
        self.local_vtag = local_vtag;
        self.active = true;
        self.state = SctpAssociationState::CookieWait;

        // Build INIT chunk with our initiate tag and initial TSN.
        let mut chunk = SctpChunk::new(SctpChunkType::Init);
        // INIT payload: initiate_tag (4) + a_rwnd (4) + num_outbound (2) +
        //               num_inbound (2) + initial_tsn (4) = 16 bytes.
        let tag_bytes = local_vtag.to_be_bytes();
        chunk.data[0..4].copy_from_slice(&tag_bytes);
        // a_rwnd = RECV_BUF_SIZE
        let rwnd = (RECV_BUF_SIZE as u32).to_be_bytes();
        chunk.data[4..8].copy_from_slice(&rwnd);
        // num outbound streams
        chunk.data[8..10].copy_from_slice(&(MAX_STREAMS as u16).to_be_bytes());
        // num inbound streams
        chunk.data[10..12].copy_from_slice(&(MAX_STREAMS as u16).to_be_bytes());
        // initial TSN
        chunk.data[12..16].copy_from_slice(&self.next_tsn.to_be_bytes());
        chunk.data_len = 16;
        chunk.length = (CHUNK_HEADER_LEN + 16) as u16;

        Ok(chunk)
    }

    /// Handle an incoming INIT chunk (passive open).
    ///
    /// Generates an INIT ACK in response.  The caller should extract
    /// the cookie and transition upon COOKIE ECHO receipt.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if the INIT payload is too
    /// short.
    pub fn handle_init(&mut self, chunk: &SctpChunk, local_vtag: u32) -> Result<SctpChunk> {
        if chunk.data_len < 16 {
            return Err(Error::InvalidArgument);
        }

        // Extract peer's initiate tag.
        self.peer_vtag =
            u32::from_be_bytes([chunk.data[0], chunk.data[1], chunk.data[2], chunk.data[3]]);
        self.local_vtag = local_vtag;
        self.active = true;

        // Build INIT ACK.
        let mut ack = SctpChunk::new(SctpChunkType::InitAck);
        ack.data[0..4].copy_from_slice(&local_vtag.to_be_bytes());
        let rwnd = (RECV_BUF_SIZE as u32).to_be_bytes();
        ack.data[4..8].copy_from_slice(&rwnd);
        ack.data[8..10].copy_from_slice(&(MAX_STREAMS as u16).to_be_bytes());
        ack.data[10..12].copy_from_slice(&(MAX_STREAMS as u16).to_be_bytes());
        ack.data[12..16].copy_from_slice(&self.next_tsn.to_be_bytes());
        // Simple state cookie (peer vtag + local vtag = 8 bytes).
        ack.data[16..20].copy_from_slice(&self.peer_vtag.to_be_bytes());
        ack.data[20..24].copy_from_slice(&local_vtag.to_be_bytes());
        ack.data_len = 24;
        ack.length = (CHUNK_HEADER_LEN + 24) as u16;

        Ok(ack)
    }

    /// Handle a COOKIE ECHO chunk and establish the association.
    ///
    /// Transitions to `Established` and activates streams.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if the cookie is too short.
    pub fn handle_cookie_echo(&mut self, chunk: &SctpChunk) -> Result<SctpChunk> {
        if chunk.data_len < 8 {
            return Err(Error::InvalidArgument);
        }

        self.state = SctpAssociationState::Established;
        self.init_streams();

        Ok(SctpChunk::new(SctpChunkType::CookieAck))
    }

    /// Handle a COOKIE ACK chunk, completing the handshake.
    ///
    /// Transitions from `CookieEchoed` to `Established`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if not in `CookieEchoed`.
    pub fn handle_cookie_ack(&mut self) -> Result<()> {
        if self.state != SctpAssociationState::CookieEchoed {
            return Err(Error::InvalidArgument);
        }
        self.state = SctpAssociationState::Established;
        self.init_streams();
        Ok(())
    }

    /// Handle a received INIT ACK: extract peer tag, send COOKIE ECHO.
    ///
    /// Transitions from `CookieWait` to `CookieEchoed`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if not in `CookieWait` or
    /// the payload is too short.
    pub fn handle_init_ack(&mut self, chunk: &SctpChunk) -> Result<SctpChunk> {
        if self.state != SctpAssociationState::CookieWait {
            return Err(Error::InvalidArgument);
        }
        if chunk.data_len < 16 {
            return Err(Error::InvalidArgument);
        }

        self.peer_vtag =
            u32::from_be_bytes([chunk.data[0], chunk.data[1], chunk.data[2], chunk.data[3]]);
        self.state = SctpAssociationState::CookieEchoed;

        // Extract cookie from INIT ACK (bytes 16..) and echo it.
        let cookie_len = chunk.data_len.saturating_sub(16);
        let mut echo = SctpChunk::new(SctpChunkType::CookieEcho);
        if cookie_len > 0 && cookie_len <= CHUNK_DATA_MAX {
            echo.data[..cookie_len].copy_from_slice(&chunk.data[16..16 + cookie_len]);
            echo.data_len = cookie_len;
            echo.length = (CHUNK_HEADER_LEN + cookie_len) as u16;
        }

        Ok(echo)
    }

    /// Buffer outgoing data on the given stream.
    ///
    /// Returns the number of bytes buffered.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if not `Established` or
    /// the stream ID is out of range.
    pub fn send(&mut self, stream_id: u16, data: &[u8]) -> Result<usize> {
        if self.state != SctpAssociationState::Established {
            return Err(Error::InvalidArgument);
        }
        let sid = stream_id as usize;
        if sid >= MAX_STREAMS || !self.streams[sid].active {
            return Err(Error::InvalidArgument);
        }

        let available = SEND_BUF_SIZE.saturating_sub(self.send_len);
        let count = if data.len() < available {
            data.len()
        } else {
            available
        };
        if count > 0 {
            self.send_buf[self.send_len..self.send_len + count].copy_from_slice(&data[..count]);
            self.send_len += count;
        }
        Ok(count)
    }

    /// Read received data from the receive buffer.
    ///
    /// Returns the number of bytes read.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if not `Established`.
    pub fn recv(&mut self, buf: &mut [u8]) -> Result<usize> {
        if self.state != SctpAssociationState::Established {
            return Err(Error::InvalidArgument);
        }

        let count = if buf.len() < self.recv_len {
            buf.len()
        } else {
            self.recv_len
        };
        if count > 0 {
            buf[..count].copy_from_slice(&self.recv_buf[..count]);
            // Shift remaining data forward.
            let remaining = self.recv_len - count;
            let mut i = 0;
            while i < remaining {
                self.recv_buf[i] = self.recv_buf[i + count];
                i += 1;
            }
            self.recv_len = remaining;
        }
        Ok(count)
    }

    /// Handle an incoming DATA chunk: buffer payload and generate SACK.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if not `Established` or
    /// the receive buffer is full.
    pub fn handle_data(&mut self, chunk: &SctpChunk) -> Result<SctpChunk> {
        if self.state != SctpAssociationState::Established {
            return Err(Error::InvalidArgument);
        }
        // DATA chunk value: TSN (4) + stream_id (2) + SSN (2) + PPI (4) +
        // user data.
        if chunk.data_len < 12 {
            return Err(Error::InvalidArgument);
        }

        let tsn = u32::from_be_bytes([chunk.data[0], chunk.data[1], chunk.data[2], chunk.data[3]]);
        let user_data = &chunk.data[12..chunk.data_len];

        // Buffer user data.
        let available = RECV_BUF_SIZE.saturating_sub(self.recv_len);
        let copy_len = if user_data.len() < available {
            user_data.len()
        } else {
            available
        };
        if copy_len > 0 {
            self.recv_buf[self.recv_len..self.recv_len + copy_len]
                .copy_from_slice(&user_data[..copy_len]);
            self.recv_len += copy_len;
        }

        // Advance cumulative TSN ack.
        self.cumulative_tsn_ack = tsn;

        // Build SACK.
        let mut sack = SctpChunk::new(SctpChunkType::Sack);
        sack.data[0..4].copy_from_slice(&self.cumulative_tsn_ack.to_be_bytes());
        // a_rwnd
        let rwnd = (RECV_BUF_SIZE.saturating_sub(self.recv_len) as u32).to_be_bytes();
        sack.data[4..8].copy_from_slice(&rwnd);
        // num gap ack blocks = 0
        sack.data[8..10].copy_from_slice(&0u16.to_be_bytes());
        // num dup TSNs = 0
        sack.data[10..12].copy_from_slice(&0u16.to_be_bytes());
        sack.data_len = 12;
        sack.length = (CHUNK_HEADER_LEN + 12) as u16;

        Ok(sack)
    }

    /// Handle a SACK chunk: advance cumulative TSN ack and free
    /// acknowledged send buffer space.
    pub fn handle_sack(&mut self, chunk: &SctpChunk) -> Result<()> {
        if chunk.data_len < 12 {
            return Err(Error::InvalidArgument);
        }

        let ack_tsn =
            u32::from_be_bytes([chunk.data[0], chunk.data[1], chunk.data[2], chunk.data[3]]);
        // Advance our record of what the peer has acknowledged.
        if ack_tsn >= self.cumulative_tsn_ack {
            self.cumulative_tsn_ack = ack_tsn;
        }

        Ok(())
    }

    /// Initiate graceful shutdown.
    ///
    /// Transitions from `Established` to `ShutdownPending`, then
    /// `ShutdownSent`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if not `Established`.
    pub fn shutdown(&mut self) -> Result<SctpChunk> {
        if self.state != SctpAssociationState::Established {
            return Err(Error::InvalidArgument);
        }

        self.state = SctpAssociationState::ShutdownPending;
        // If no outstanding data, move directly to ShutdownSent.
        if self.send_len == 0 {
            self.state = SctpAssociationState::ShutdownSent;
        }

        let mut chunk = SctpChunk::new(SctpChunkType::Shutdown);
        chunk.data[0..4].copy_from_slice(&self.cumulative_tsn_ack.to_be_bytes());
        chunk.data_len = 4;
        chunk.length = (CHUNK_HEADER_LEN + 4) as u16;

        Ok(chunk)
    }

    /// Handle incoming SHUTDOWN: send SHUTDOWN ACK.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if not in a state that
    /// accepts SHUTDOWN.
    pub fn handle_shutdown(&mut self) -> Result<SctpChunk> {
        if self.state != SctpAssociationState::Established
            && self.state != SctpAssociationState::ShutdownReceived
        {
            return Err(Error::InvalidArgument);
        }

        self.state = SctpAssociationState::ShutdownAckSent;

        Ok(SctpChunk::new(SctpChunkType::ShutdownAck))
    }

    /// Handle incoming SHUTDOWN ACK: send SHUTDOWN COMPLETE.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if not `ShutdownSent`.
    pub fn handle_shutdown_ack(&mut self) -> Result<SctpChunk> {
        if self.state != SctpAssociationState::ShutdownSent {
            return Err(Error::InvalidArgument);
        }

        self.state = SctpAssociationState::Closed;
        self.active = false;

        Ok(SctpChunk::new(SctpChunkType::ShutdownComplete))
    }

    /// Handle incoming SHUTDOWN COMPLETE: close association.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if not `ShutdownAckSent`.
    pub fn handle_shutdown_complete(&mut self) -> Result<()> {
        if self.state != SctpAssociationState::ShutdownAckSent {
            return Err(Error::InvalidArgument);
        }
        self.state = SctpAssociationState::Closed;
        self.active = false;
        Ok(())
    }

    /// Handle an ABORT chunk: immediately close the association.
    pub fn handle_abort(&mut self) {
        self.state = SctpAssociationState::Closed;
        self.active = false;
        self.send_len = 0;
        self.recv_len = 0;
    }

    /// Handle a HEARTBEAT chunk: reply with HEARTBEAT ACK.
    pub fn handle_heartbeat(&self, chunk: &SctpChunk) -> Result<SctpChunk> {
        let mut ack = SctpChunk::new(SctpChunkType::HeartbeatAck);
        // Echo back the heartbeat data.
        if chunk.data_len > 0 && chunk.data_len <= CHUNK_DATA_MAX {
            ack.data[..chunk.data_len].copy_from_slice(&chunk.data[..chunk.data_len]);
            ack.data_len = chunk.data_len;
            ack.length = (CHUNK_HEADER_LEN + chunk.data_len) as u16;
        }
        Ok(ack)
    }

    /// Initialise all streams for the association.
    fn init_streams(&mut self) {
        let mut i = 0;
        while i < MAX_STREAMS {
            self.streams[i].stream_id = i as u16;
            self.streams[i].activate();
            i += 1;
        }
        self.num_streams = MAX_STREAMS;
    }

    /// Return the number of active streams.
    pub const fn stream_count(&self) -> usize {
        self.num_streams
    }

    /// Return the current association state.
    pub const fn association_state(&self) -> SctpAssociationState {
        self.state
    }
}

// =========================================================================
// SctpEndpoint
// =========================================================================

/// An SCTP endpoint bound to a local port.
///
/// Holds up to [`MAX_ASSOCIATIONS`] associations.  Provides bind,
/// listen, connect, send, and receive operations.
pub struct SctpEndpoint {
    /// Local port number (0 = unbound).
    pub local_port: u16,
    /// Whether this endpoint is in listen mode.
    pub listening: bool,
    /// Whether this endpoint slot is in use.
    pub active: bool,
    /// Association table.
    associations: [SctpAssociation; MAX_ASSOCIATIONS],
}

impl Default for SctpEndpoint {
    fn default() -> Self {
        Self::new()
    }
}

impl SctpEndpoint {
    /// Create a new unbound endpoint.
    pub const fn new() -> Self {
        Self {
            local_port: 0,
            listening: false,
            active: false,
            associations: [const { SctpAssociation::new() }; MAX_ASSOCIATIONS],
        }
    }

    /// Bind to a local port.
    ///
    /// # Errors
    ///
    /// Returns [`Error::AlreadyExists`] if already bound.
    pub fn bind(&mut self, port: u16) -> Result<()> {
        if self.local_port != 0 {
            return Err(Error::AlreadyExists);
        }
        self.local_port = port;
        self.active = true;
        Ok(())
    }

    /// Enter listen mode for incoming associations.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if not bound.
    pub fn listen(&mut self) -> Result<()> {
        if self.local_port == 0 {
            return Err(Error::InvalidArgument);
        }
        self.listening = true;
        Ok(())
    }

    /// Initiate an association to a remote peer.
    ///
    /// Returns the index of the new association and the INIT chunk
    /// to send.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if no association slot is
    /// available.
    pub fn connect(
        &mut self,
        peer_ip: [u8; 4],
        peer_port: u16,
        local_vtag: u32,
    ) -> Result<(usize, SctpChunk)> {
        let idx = self.alloc_association()?;
        let chunk = self.associations[idx].initiate(peer_ip, peer_port, local_vtag)?;
        Ok((idx, chunk))
    }

    /// Send data on an association's stream.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if the association index
    /// is out of range or inactive.
    pub fn send(&mut self, assoc_idx: usize, stream_id: u16, data: &[u8]) -> Result<usize> {
        if assoc_idx >= MAX_ASSOCIATIONS || !self.associations[assoc_idx].active {
            return Err(Error::InvalidArgument);
        }
        self.associations[assoc_idx].send(stream_id, data)
    }

    /// Receive data from an association.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if the association index
    /// is out of range or inactive.
    pub fn receive(&mut self, assoc_idx: usize, buf: &mut [u8]) -> Result<usize> {
        if assoc_idx >= MAX_ASSOCIATIONS || !self.associations[assoc_idx].active {
            return Err(Error::InvalidArgument);
        }
        self.associations[assoc_idx].recv(buf)
    }

    /// Return a mutable reference to an association by index.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if the index is out of
    /// range.
    pub fn association_mut(&mut self, idx: usize) -> Result<&mut SctpAssociation> {
        if idx >= MAX_ASSOCIATIONS {
            return Err(Error::InvalidArgument);
        }
        Ok(&mut self.associations[idx])
    }

    /// Return a reference to an association by index.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if the index is out of
    /// range.
    pub fn association(&self, idx: usize) -> Result<&SctpAssociation> {
        if idx >= MAX_ASSOCIATIONS {
            return Err(Error::InvalidArgument);
        }
        Ok(&self.associations[idx])
    }

    /// Allocate a free association slot.
    fn alloc_association(&mut self) -> Result<usize> {
        let mut i = 0;
        while i < MAX_ASSOCIATIONS {
            if !self.associations[i].active {
                return Ok(i);
            }
            i += 1;
        }
        Err(Error::OutOfMemory)
    }
}

// =========================================================================
// SctpRegistry
// =========================================================================

/// System-wide SCTP endpoint registry.
///
/// Manages up to [`MAX_ENDPOINTS`] endpoints, providing create,
/// destroy, and lookup operations.
pub struct SctpRegistry {
    /// Endpoint table.
    endpoints: [SctpEndpoint; MAX_ENDPOINTS],
}

impl Default for SctpRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl SctpRegistry {
    /// Create an empty registry.
    pub const fn new() -> Self {
        Self {
            endpoints: [const { SctpEndpoint::new() }; MAX_ENDPOINTS],
        }
    }

    /// Create a new endpoint and return its index.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if no slot is available.
    pub fn create(&mut self) -> Result<usize> {
        let mut i = 0;
        while i < MAX_ENDPOINTS {
            if !self.endpoints[i].active {
                self.endpoints[i] = SctpEndpoint::new();
                self.endpoints[i].active = true;
                return Ok(i);
            }
            i += 1;
        }
        Err(Error::OutOfMemory)
    }

    /// Destroy an endpoint by index.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the index is out of range or
    /// the endpoint is not active.
    pub fn destroy(&mut self, idx: usize) -> Result<()> {
        if idx >= MAX_ENDPOINTS || !self.endpoints[idx].active {
            return Err(Error::NotFound);
        }
        self.endpoints[idx] = SctpEndpoint::new();
        Ok(())
    }

    /// Find an endpoint by local port.
    ///
    /// Returns the index of the first endpoint bound to `port`, or
    /// [`Error::NotFound`] if none exists.
    pub fn find_by_port(&self, port: u16) -> Result<usize> {
        let mut i = 0;
        while i < MAX_ENDPOINTS {
            if self.endpoints[i].active && self.endpoints[i].local_port == port {
                return Ok(i);
            }
            i += 1;
        }
        Err(Error::NotFound)
    }

    /// Return a mutable reference to an endpoint by index.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the index is out of range or
    /// the endpoint is not active.
    pub fn get_mut(&mut self, idx: usize) -> Result<&mut SctpEndpoint> {
        if idx >= MAX_ENDPOINTS || !self.endpoints[idx].active {
            return Err(Error::NotFound);
        }
        Ok(&mut self.endpoints[idx])
    }

    /// Return a reference to an endpoint by index.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the index is out of range or
    /// the endpoint is not active.
    pub fn get(&self, idx: usize) -> Result<&SctpEndpoint> {
        if idx >= MAX_ENDPOINTS || !self.endpoints[idx].active {
            return Err(Error::NotFound);
        }
        Ok(&self.endpoints[idx])
    }

    /// Return the number of active endpoints.
    pub fn active_count(&self) -> usize {
        let mut count = 0;
        let mut i = 0;
        while i < MAX_ENDPOINTS {
            if self.endpoints[i].active {
                count += 1;
            }
            i += 1;
        }
        count
    }
}
