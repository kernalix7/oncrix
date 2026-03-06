// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Generic Routing Encapsulation (GRE) tunnel for the ONCRIX kernel.
//!
//! Implements GRE tunnelling per RFC 2784 (base GRE) and RFC 2890
//! (key and sequence number extensions).  GRE encapsulates an
//! arbitrary inner protocol packet inside an outer IPv4 header,
//! enabling point-to-point virtual links across IP networks.
//!
//! # Architecture
//!
//! ```text
//! inner packet
//!      |
//!      v
//! GreTunnel::encapsulate()
//!      |
//!      v
//! [ outer IP | GRE header | inner packet ]
//!      |
//!      v
//! IP routing / transmit
//!
//! received outer packet
//!      |
//!      v
//! GreTunnel::decapsulate()
//!      |
//!      v
//! inner packet delivered to stack
//! ```
//!
//! Key components:
//!
//! - [`GreFlags`]: bitmask of optional GRE header fields (checksum,
//!   key, sequence number).
//! - [`GreHeader`]: on-wire GRE header with optional fields per
//!   RFC 2784/2890.
//! - [`GreTunnel`]: a single GRE tunnel endpoint with local/remote
//!   addresses, optional key, TTL/TOS, and a 4 KiB encapsulation
//!   buffer.
//! - [`GreRegistry`]: system-wide registry managing up to
//!   [`MAX_TUNNELS`] GRE tunnels.
//!
//! All multi-byte header fields use network byte order (big-endian).
//!
//! Reference: RFC 2784 (GRE), RFC 2890 (GRE Key and Sequence Number).

use oncrix_lib::{Error, Result};

// =========================================================================
// Constants
// =========================================================================

/// Maximum number of GRE tunnels in the system registry.
const MAX_TUNNELS: usize = 16;

/// Size of the encapsulation buffer in bytes (4 KiB).
const ENCAP_BUF_SIZE: usize = 4096;

/// Minimum GRE header size in bytes (flags_version + protocol_type).
const GRE_HEADER_MIN_LEN: usize = 4;

/// Size of the optional checksum + reserved field (4 bytes).
const GRE_CHECKSUM_FIELD_LEN: usize = 4;

/// Size of the optional key field (4 bytes).
const GRE_KEY_FIELD_LEN: usize = 4;

/// Size of the optional sequence number field (4 bytes).
const GRE_SEQUENCE_FIELD_LEN: usize = 4;

/// EtherType for IPv4 (used as default protocol type).
const ETHERTYPE_IPV4: u16 = 0x0800;

/// Default TTL for the outer IP header.
const DEFAULT_TTL: u8 = 64;

/// Maximum encapsulation depth to prevent infinite nesting.
const MAX_ENCAP_LIMIT: u8 = 4;

// =========================================================================
// GreFlags
// =========================================================================

/// Bitmask of optional GRE header fields.
///
/// Encoded in the upper 3 bits of the `flags_version` field in the
/// GRE header per RFC 2784 section 2.
///
/// ```text
/// Bit 15: Checksum Present (C)
/// Bit 13: Key Present (K)
/// Bit 12: Sequence Number Present (S)
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct GreFlags {
    /// Raw bitmask value.
    bits: u16,
}

impl GreFlags {
    /// Bit position for Checksum Present (C).
    const CHECKSUM_BIT: u16 = 1 << 15;

    /// Bit position for Key Present (K).
    const KEY_BIT: u16 = 1 << 13;

    /// Bit position for Sequence Number Present (S).
    const SEQUENCE_BIT: u16 = 1 << 12;

    /// Create empty flags (no optional fields).
    pub const fn empty() -> Self {
        Self { bits: 0 }
    }

    /// Create flags from a raw bitmask value.
    pub const fn from_bits(bits: u16) -> Self {
        Self { bits }
    }

    /// Return the raw bitmask value.
    pub const fn bits(self) -> u16 {
        self.bits
    }

    /// Return whether the Checksum Present bit is set.
    pub const fn checksum_present(self) -> bool {
        (self.bits & Self::CHECKSUM_BIT) != 0
    }

    /// Return whether the Key Present bit is set.
    pub const fn key_present(self) -> bool {
        (self.bits & Self::KEY_BIT) != 0
    }

    /// Return whether the Sequence Number Present bit is set.
    pub const fn sequence_present(self) -> bool {
        (self.bits & Self::SEQUENCE_BIT) != 0
    }

    /// Set the Checksum Present bit.
    pub const fn with_checksum(self) -> Self {
        Self {
            bits: self.bits | Self::CHECKSUM_BIT,
        }
    }

    /// Set the Key Present bit.
    pub const fn with_key(self) -> Self {
        Self {
            bits: self.bits | Self::KEY_BIT,
        }
    }

    /// Set the Sequence Number Present bit.
    pub const fn with_sequence(self) -> Self {
        Self {
            bits: self.bits | Self::SEQUENCE_BIT,
        }
    }

    /// Compute the total GRE header length implied by these flags.
    pub const fn header_len(self) -> usize {
        let mut len = GRE_HEADER_MIN_LEN;
        if self.checksum_present() {
            len += GRE_CHECKSUM_FIELD_LEN;
        }
        if self.key_present() {
            len += GRE_KEY_FIELD_LEN;
        }
        if self.sequence_present() {
            len += GRE_SEQUENCE_FIELD_LEN;
        }
        len
    }
}

// =========================================================================
// GreHeader
// =========================================================================

/// On-wire GRE header with optional fields.
///
/// Layout per RFC 2784 section 2 and RFC 2890:
///
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |C| |K|S| Reserved0       | Ver |         Protocol Type         |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |      Checksum (optional)      |       Reserved1 (optional)    |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                         Key (optional)                        |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                   Sequence Number (optional)                  |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct GreHeader {
    /// Flags and version field (upper byte = C/K/S/Reserved0,
    /// lower 3 bits = version, must be 0).
    pub flags_version: u16,
    /// Protocol type of the encapsulated payload (e.g., 0x0800 for
    /// IPv4).
    pub protocol_type: u16,
    /// Optional checksum (present when C bit is set).
    pub checksum: u16,
    /// Optional key (present when K bit is set).
    pub key: u32,
    /// Optional sequence number (present when S bit is set).
    pub sequence_number: u32,
}

impl GreHeader {
    /// Create a new GRE header with the given flags and protocol type.
    pub const fn new(flags: GreFlags, protocol_type: u16) -> Self {
        Self {
            flags_version: flags.bits(),
            protocol_type,
            checksum: 0,
            key: 0,
            sequence_number: 0,
        }
    }

    /// Return the flags decoded from `flags_version`.
    pub const fn flags(&self) -> GreFlags {
        GreFlags::from_bits(self.flags_version)
    }

    /// Return the GRE version (lower 3 bits of flags_version).
    pub const fn version(&self) -> u8 {
        (self.flags_version & 0x07) as u8
    }
}

/// Parse a GRE header from raw bytes.
///
/// Returns the parsed [`GreHeader`] and the offset past the header
/// (i.e., where the encapsulated payload begins).
///
/// # Errors
///
/// Returns [`Error::InvalidArgument`] if `data` is too short for
/// the indicated optional fields or if the GRE version is not 0.
pub fn parse_gre(data: &[u8]) -> Result<(GreHeader, usize)> {
    if data.len() < GRE_HEADER_MIN_LEN {
        return Err(Error::InvalidArgument);
    }

    let flags_version = u16::from_be_bytes([data[0], data[1]]);
    let protocol_type = u16::from_be_bytes([data[2], data[3]]);

    // Version must be 0.
    if (flags_version & 0x07) != 0 {
        return Err(Error::InvalidArgument);
    }

    let flags = GreFlags::from_bits(flags_version);
    let required_len = flags.header_len();
    if data.len() < required_len {
        return Err(Error::InvalidArgument);
    }

    let mut offset = GRE_HEADER_MIN_LEN;
    let mut header = GreHeader::new(flags, protocol_type);

    if flags.checksum_present() {
        header.checksum = u16::from_be_bytes([data[offset], data[offset + 1]]);
        // Skip reserved1 field as well.
        offset += GRE_CHECKSUM_FIELD_LEN;
    }

    if flags.key_present() {
        header.key = u32::from_be_bytes([
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
        ]);
        offset += GRE_KEY_FIELD_LEN;
    }

    if flags.sequence_present() {
        header.sequence_number = u32::from_be_bytes([
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
        ]);
        offset += GRE_SEQUENCE_FIELD_LEN;
    }

    Ok((header, offset))
}

/// Serialise a GRE header into `buf`.
///
/// Returns the number of bytes written (the header length).
///
/// # Errors
///
/// Returns [`Error::InvalidArgument`] if `buf` is too small for
/// the header with its optional fields.
pub fn write_gre(buf: &mut [u8], header: &GreHeader) -> Result<usize> {
    let flags = header.flags();
    let required_len = flags.header_len();
    if buf.len() < required_len {
        return Err(Error::InvalidArgument);
    }

    let fv_bytes = header.flags_version.to_be_bytes();
    buf[0] = fv_bytes[0];
    buf[1] = fv_bytes[1];

    let pt_bytes = header.protocol_type.to_be_bytes();
    buf[2] = pt_bytes[0];
    buf[3] = pt_bytes[1];

    let mut offset = GRE_HEADER_MIN_LEN;

    if flags.checksum_present() {
        let ck_bytes = header.checksum.to_be_bytes();
        buf[offset] = ck_bytes[0];
        buf[offset + 1] = ck_bytes[1];
        // Reserved1 = 0.
        buf[offset + 2] = 0;
        buf[offset + 3] = 0;
        offset += GRE_CHECKSUM_FIELD_LEN;
    }

    if flags.key_present() {
        let key_bytes = header.key.to_be_bytes();
        buf[offset] = key_bytes[0];
        buf[offset + 1] = key_bytes[1];
        buf[offset + 2] = key_bytes[2];
        buf[offset + 3] = key_bytes[3];
        offset += GRE_KEY_FIELD_LEN;
    }

    if flags.sequence_present() {
        let seq_bytes = header.sequence_number.to_be_bytes();
        buf[offset] = seq_bytes[0];
        buf[offset + 1] = seq_bytes[1];
        buf[offset + 2] = seq_bytes[2];
        buf[offset + 3] = seq_bytes[3];
        offset += GRE_SEQUENCE_FIELD_LEN;
    }

    Ok(offset)
}

// =========================================================================
// GreTunnel
// =========================================================================

/// A single GRE tunnel endpoint.
///
/// Encapsulates inner packets with a GRE header and an implied outer
/// IP header (local/remote addresses).  Supports optional key and
/// sequence number fields per RFC 2890.
pub struct GreTunnel {
    /// Unique tunnel identifier (assigned by [`GreRegistry`]).
    tunnel_id: u32,
    /// Local (source) IPv4 address for the outer header.
    pub local_addr: u32,
    /// Remote (destination) IPv4 address for the outer header.
    pub remote_addr: u32,
    /// Optional GRE key (present when `Some`).
    pub key: Option<u32>,
    /// TTL for the outer IP header.
    pub ttl: u8,
    /// TOS for the outer IP header.
    pub tos: u8,
    /// Maximum encapsulation depth.
    pub encap_limit: u8,
    /// Sequence number counter (incremented on each encapsulation
    /// when sequence numbering is enabled).
    sequence_counter: u32,
    /// Whether sequence numbering is enabled.
    pub sequence_enabled: bool,
    /// Encapsulation work buffer.
    encap_buf: [u8; ENCAP_BUF_SIZE],
    /// Whether this tunnel slot is in use.
    in_use: bool,
}

impl GreTunnel {
    /// Create a new GRE tunnel with default parameters.
    const fn new(tunnel_id: u32, local_addr: u32, remote_addr: u32, key: Option<u32>) -> Self {
        Self {
            tunnel_id,
            local_addr,
            remote_addr,
            key,
            ttl: DEFAULT_TTL,
            tos: 0,
            encap_limit: MAX_ENCAP_LIMIT,
            sequence_counter: 0,
            sequence_enabled: false,
            encap_buf: [0u8; ENCAP_BUF_SIZE],
            in_use: false,
        }
    }

    /// An empty, unused tunnel slot.
    const EMPTY: Self = Self::new(0, 0, 0, None);

    /// Return the tunnel identifier.
    pub const fn tunnel_id(&self) -> u32 {
        self.tunnel_id
    }

    /// Build the GRE flags for this tunnel's configuration.
    fn gre_flags(&self) -> GreFlags {
        let mut flags = GreFlags::empty();
        if self.key.is_some() {
            flags = flags.with_key();
        }
        if self.sequence_enabled {
            flags = flags.with_sequence();
        }
        flags
    }

    /// Encapsulate an inner packet with a GRE header.
    ///
    /// Writes the GRE header followed by `inner_packet` into
    /// the tunnel's internal encapsulation buffer and returns a
    /// slice referencing the complete encapsulated packet.
    ///
    /// The caller is responsible for prepending the outer IP header
    /// using [`local_addr`](Self::local_addr) and
    /// [`remote_addr`](Self::remote_addr).
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidArgument`] if `inner_packet` is empty.
    /// - [`Error::OutOfMemory`] if the encapsulated packet would
    ///   exceed the internal buffer size.
    pub fn encapsulate(&mut self, inner_packet: &[u8]) -> Result<&[u8]> {
        if inner_packet.is_empty() {
            return Err(Error::InvalidArgument);
        }

        let flags = self.gre_flags();
        let hdr_len = flags.header_len();
        let total_len = hdr_len + inner_packet.len();

        if total_len > ENCAP_BUF_SIZE {
            return Err(Error::OutOfMemory);
        }

        let mut header = GreHeader::new(flags, ETHERTYPE_IPV4);

        if let Some(k) = self.key {
            header.key = k;
        }

        if self.sequence_enabled {
            header.sequence_number = self.sequence_counter;
            self.sequence_counter = self.sequence_counter.wrapping_add(1);
        }

        let written = write_gre(&mut self.encap_buf, &header)?;
        self.encap_buf[written..written + inner_packet.len()].copy_from_slice(inner_packet);

        Ok(&self.encap_buf[..total_len])
    }

    /// Decapsulate a GRE packet, extracting the inner payload.
    ///
    /// Parses the GRE header from `outer_packet` and returns a slice
    /// referencing the encapsulated inner packet.  If this tunnel has
    /// a key configured, the key in the header must match.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidArgument`] if the GRE header is malformed
    ///   or the key does not match.
    pub fn decapsulate<'a>(&self, outer_packet: &'a [u8]) -> Result<&'a [u8]> {
        let (header, payload_offset) = parse_gre(outer_packet)?;

        // Validate key if configured.
        if let Some(expected_key) = self.key {
            if !header.flags().key_present() || header.key != expected_key {
                return Err(Error::InvalidArgument);
            }
        }

        if payload_offset >= outer_packet.len() {
            return Err(Error::InvalidArgument);
        }

        Ok(&outer_packet[payload_offset..])
    }
}

// =========================================================================
// GreRegistry
// =========================================================================

/// System-wide registry of GRE tunnels.
///
/// Manages up to [`MAX_TUNNELS`] GRE tunnel endpoints.  Each tunnel
/// is identified by a monotonically increasing tunnel ID.
pub struct GreRegistry {
    /// Tunnel slots.
    tunnels: [GreTunnel; MAX_TUNNELS],
    /// Next tunnel ID to assign.
    next_id: u32,
}

impl Default for GreRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl GreRegistry {
    /// Create an empty GRE tunnel registry.
    pub const fn new() -> Self {
        Self {
            tunnels: [GreTunnel::EMPTY; MAX_TUNNELS],
            next_id: 1,
        }
    }

    /// Create a new GRE tunnel.
    ///
    /// Returns the tunnel ID on success.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the registry is full.
    pub fn create(&mut self, local_addr: u32, remote_addr: u32, key: Option<u32>) -> Result<u32> {
        for i in 0..MAX_TUNNELS {
            if !self.tunnels[i].in_use {
                let id = self.next_id;
                self.next_id = self.next_id.wrapping_add(1);
                self.tunnels[i] = GreTunnel::new(id, local_addr, remote_addr, key);
                self.tunnels[i].in_use = true;
                return Ok(id);
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Destroy a GRE tunnel by ID.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the tunnel does not exist.
    pub fn destroy(&mut self, tunnel_id: u32) -> Result<()> {
        for i in 0..MAX_TUNNELS {
            if self.tunnels[i].in_use && self.tunnels[i].tunnel_id == tunnel_id {
                self.tunnels[i].in_use = false;
                return Ok(());
            }
        }
        Err(Error::NotFound)
    }

    /// Look up a tunnel by ID, returning a mutable reference.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the tunnel does not exist.
    pub fn find(&mut self, tunnel_id: u32) -> Result<&mut GreTunnel> {
        for i in 0..MAX_TUNNELS {
            if self.tunnels[i].in_use && self.tunnels[i].tunnel_id == tunnel_id {
                return Ok(&mut self.tunnels[i]);
            }
        }
        Err(Error::NotFound)
    }

    /// Find a tunnel by its GRE key.
    ///
    /// Returns the first matching tunnel.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if no tunnel has the given key.
    pub fn find_by_key(&mut self, key: u32) -> Result<&mut GreTunnel> {
        for i in 0..MAX_TUNNELS {
            if self.tunnels[i].in_use && self.tunnels[i].key == Some(key) {
                return Ok(&mut self.tunnels[i]);
            }
        }
        Err(Error::NotFound)
    }

    /// Find a tunnel by its local and remote endpoint addresses.
    ///
    /// Returns the first matching tunnel.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if no tunnel matches.
    pub fn find_by_endpoints(
        &mut self,
        local_addr: u32,
        remote_addr: u32,
    ) -> Result<&mut GreTunnel> {
        for i in 0..MAX_TUNNELS {
            if self.tunnels[i].in_use
                && self.tunnels[i].local_addr == local_addr
                && self.tunnels[i].remote_addr == remote_addr
            {
                return Ok(&mut self.tunnels[i]);
            }
        }
        Err(Error::NotFound)
    }

    /// Return the number of active tunnels.
    pub fn active_count(&self) -> usize {
        let mut count = 0;
        for i in 0..MAX_TUNNELS {
            if self.tunnels[i].in_use {
                count += 1;
            }
        }
        count
    }
}
