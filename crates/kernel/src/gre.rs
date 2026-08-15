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

/// EtherType for IPv6 (accepted as an inner protocol type).
const ETHERTYPE_IPV6: u16 = 0x86DD;

/// Protocol type indicating GRE-in-GRE (RFC 2784 transparent
/// encapsulation of another GRE packet).  Used to detect nesting on
/// the receive path.
const ETHERTYPE_GRE: u16 = 0x6558;

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
/// Returns [`Error::InvalidArgument`] if `data` is too short for the
/// indicated optional fields, if the GRE version is not 0, or if any
/// RFC 2784 §2.3 discard bit (`0x4c00`) is set.
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

    // RFC 2784 §2.3: a conformant receiver MUST discard a packet that sets a
    // bit whose RFC 1701 meaning implies extra header fields this parser does
    // not decode — RFC bit 1 (0x4000, Routing Present), bit 4 (0x0800, strict
    // source route), and bit 5 (0x0400, recursion control). Accepting any of
    // these would leave the payload offset computed only from C/K/S while the
    // sender intended additional fields, mis-aligning the payload. Reserved0
    // bits 6-12 (0x03f8) carry no length implication and MUST be ignored, so
    // they are deliberately absent from this discard mask.
    const GRE_DISCARD_BITS: u16 = 0x4c00;
    if (flags_version & GRE_DISCARD_BITS) != 0 {
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

/// Byte offset of the optional GRE checksum field within the header.
///
/// The checksum occupies the two bytes immediately after the
/// `flags_version`/`protocol_type` words (RFC 2784 section 2.1).
const GRE_CHECKSUM_OFFSET: usize = GRE_HEADER_MIN_LEN;

/// Verify the RFC 1071 one's-complement GRE checksum over a received
/// packet when the Checksum-Present (C) flag is set.
///
/// Per RFC 2784 section 2.1 the checksum covers the *entire* GRE
/// header (all optional fields included) plus the payload, with the
/// checksum field itself treated as zero during computation.  This
/// helper sums every 16-bit word across `[0, packet.len())` while
/// skipping the on-wire checksum field (equivalent to zeroing it),
/// folds the accumulator, and compares the one's-complement result
/// against the wire value.
///
/// `payload_offset` is the start of the encapsulated payload as
/// returned by [`parse_gre`]; it is used only to bound the sanity
/// checks — the checksum still spans through `packet.len()`.
///
/// # Errors
///
/// Returns [`Error::InvalidArgument`] if the packet is too short to
/// hold the checksum field, or if the computed checksum does not match
/// the value carried on the wire (the packet is forged or corrupt and
/// must be dropped before its payload is trusted).
//
// SECURITY: every inbound GRE frame is attacker-controlled.  A forged
// packet that sets the C flag but carries a bogus checksum must be
// dropped here, before `decapsulate_depth` hands the inner payload to
// the re-injection path.  All slice indices below are bounded against
// the *received* `packet` length (never an MTU-derived value) so a
// truncated or oversized frame cannot trigger an out-of-bounds panic
// in ring 0.
fn verify_gre_checksum(packet: &[u8], payload_offset: usize, wire_checksum: u16) -> Result<()> {
    // SECURITY: the checksum field must be fully present and must lie
    // within the parsed header (before the payload).  `parse_gre`
    // already guaranteed the header fits, but re-check here so this
    // helper is sound in isolation and cannot index past `packet`.
    if packet.len() < GRE_CHECKSUM_OFFSET + 2
        || payload_offset > packet.len()
        || GRE_CHECKSUM_OFFSET + 2 > payload_offset
    {
        return Err(Error::InvalidArgument);
    }

    let mut sum: u32 = 0;
    let mut i = 0;
    // SECURITY: bound the word loop strictly against the received
    // length so the final pair never reads past the slice end.
    while i + 1 < packet.len() {
        // Skip the on-wire checksum field, treating it as zero per
        // RFC 2784 (it is a 16-bit word aligned at GRE_CHECKSUM_OFFSET).
        if i == GRE_CHECKSUM_OFFSET {
            i += 2;
            continue;
        }
        let word = u16::from_be_bytes([packet[i], packet[i + 1]]);
        sum = sum.wrapping_add(word as u32);
        i += 2;
    }

    // Odd trailing byte is padded with zero on the right (RFC 1071).
    if i < packet.len() {
        sum = sum.wrapping_add((packet[i] as u32) << 8);
    }

    // Fold the 32-bit accumulator down to 16 bits.
    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    let computed = !(sum as u16);

    // SECURITY: drop on mismatch — never return / re-inject the inner
    // payload of a packet whose checksum does not verify.
    if computed != wire_checksum {
        return Err(Error::InvalidArgument);
    }

    Ok(())
}

/// Shared receive-side GRE gate: [`parse_gre`] plus, when C=1, an RFC 2784
/// §2.1 checksum over the whole header and payload (checksum field zeroed).
///
/// Header-only frames are valid; payload-requiring callers check that
/// separately. Nonzero Reserved1 is accepted (RFC 2784 mandates transmit
/// zero, not receiver discard) when the checksum that covers it verifies.
///
/// Returns the [`GreHeader`] and payload offset from [`parse_gre`].
///
/// # Errors
///
/// [`Error::InvalidArgument`] if the header is malformed (see [`parse_gre`])
/// or if C=1 and the checksum does not verify.
pub(crate) fn validate_gre_packet(packet: &[u8]) -> Result<(GreHeader, usize)> {
    let (header, payload_offset) = parse_gre(packet)?;
    if header.flags().checksum_present() {
        verify_gre_checksum(packet, payload_offset, header.checksum)?;
    }
    Ok((header, payload_offset))
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
    /// This is the single-level entry point used by the receive path.
    /// It starts the anti-nesting depth budget at [`MAX_ENCAP_LIMIT`]
    /// and delegates to [`decapsulate_depth`](Self::decapsulate_depth).
    /// A re-dispatcher peeling further GRE layers must thread the
    /// returned remaining budget back in so GRE-in-GRE nesting is
    /// bounded across the whole chain.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidArgument`] if the GRE header is malformed,
    ///   the key does not match, or the inner protocol type is not a
    ///   supported payload type.
    pub fn decapsulate<'a>(&self, outer_packet: &'a [u8]) -> Result<&'a [u8]> {
        let (inner, _remaining) = self.decapsulate_depth(outer_packet, MAX_ENCAP_LIMIT)?;
        Ok(inner)
    }

    /// Decapsulate a GRE packet while enforcing a nesting-depth budget.
    ///
    /// `depth_budget` is the number of GRE layers still permitted to be
    /// peeled on this receive chain (including this one).  It mirrors
    /// the encapsulate-side [`MAX_ENCAP_LIMIT`] cap, but on the receive
    /// path: a GRE-in-GRE packet is rejected once the budget is
    /// exhausted, bounding attacker-controlled recursion and the
    /// associated CPU/stack DoS once an inner GRE layer is re-dispatched.
    ///
    /// Returns the inner payload slice together with the remaining
    /// budget (decremented by one).  A caller that re-dispatches an
    /// inner GRE packet must pass the returned remaining budget back in
    /// rather than restarting from [`MAX_ENCAP_LIMIT`].
    ///
    /// The inner `protocol_type` is validated: only IPv4, IPv6, and a
    /// further (still-budgeted) GRE layer are accepted; any other type
    /// is rejected so it is never blindly re-injected into the stack.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidArgument`] if `depth_budget` is zero, the GRE
    ///   header is malformed, the key does not match, the payload is
    ///   empty, or the inner protocol type is unsupported.
    pub fn decapsulate_depth<'a>(
        &self,
        outer_packet: &'a [u8],
        depth_budget: u8,
    ) -> Result<(&'a [u8], u8)> {
        // Refuse to peel another layer once the receive-side encap cap
        // is reached — the anti-nesting guard that bounds attacker-chosen
        // GRE-in-GRE recursion depth.
        if depth_budget == 0 {
            return Err(Error::InvalidArgument);
        }

        // SECURITY: run the shared receive-side validator, which structurally
        // parses the header and — when C=1 — verifies the RFC 1071 checksum
        // over the full GRE header + payload before any of the packet is
        // trusted. A forged frame with C set and a bogus checksum is dropped
        // here, so its inner payload is never returned for re-injection.
        let (header, payload_offset) = validate_gre_packet(outer_packet)?;

        // Validate key if configured.
        if let Some(expected_key) = self.key
            && (!header.flags().key_present() || header.key != expected_key)
        {
            return Err(Error::InvalidArgument);
        }

        if payload_offset >= outer_packet.len() {
            return Err(Error::InvalidArgument);
        }

        let remaining = depth_budget - 1;

        // Validate the inner protocol type.  A nested GRE layer is only
        // acceptable while depth budget remains for the re-dispatcher to
        // consume; an unknown protocol type is rejected outright.
        match header.protocol_type {
            ETHERTYPE_IPV4 | ETHERTYPE_IPV6 => {}
            ETHERTYPE_GRE => {
                if remaining == 0 {
                    return Err(Error::InvalidArgument);
                }
            }
            _ => return Err(Error::InvalidArgument),
        }

        Ok((&outer_packet[payload_offset..], remaining))
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

// =========================================================================
// Tests
// =========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    const IPV4_PROTO: u16 = 0x0800;

    /// Build a GRE header+payload with the given raw flags_version word.
    fn frame(flags_version: u16, payload: &[u8]) -> ([u8; 64], usize) {
        let mut f = [0u8; 64];
        f[0..2].copy_from_slice(&flags_version.to_be_bytes());
        f[2..4].copy_from_slice(&IPV4_PROTO.to_be_bytes());
        f[4..4 + payload.len()].copy_from_slice(payload);
        (f, 4 + payload.len())
    }

    // A plain base header (no optional fields) must parse and return offset 4.
    #[test]
    fn parse_base_header_returns_offset_4() {
        let (f, n) = frame(0x0000, &[0x45, 0x00]);
        let (hdr, off) = parse_gre(&f[..n]).unwrap();
        assert_eq!(off, 4);
        assert_eq!(hdr.protocol_type, IPV4_PROTO);
        assert!(!hdr.flags().checksum_present());
    }

    // Truncated optional fields must be rejected before any read.
    #[test]
    fn parse_rejects_truncated_optional_field() {
        // K bit set but only 2 of the 4 key bytes present.
        let mut f = [0u8; 6];
        f[0..2].copy_from_slice(&GreFlags::KEY_BIT.to_be_bytes());
        f[2..4].copy_from_slice(&IPV4_PROTO.to_be_bytes());
        assert!(parse_gre(&f).is_err());
    }

    // RFC 2784 §2.3: Reserved0 bits 6-12 (0x03f8) MUST be ignored on receipt,
    // not rejected. Each such bit alone, and all of them together, must parse.
    #[test]
    fn parse_ignores_reserved0_bits_6_to_12() {
        for fv in [0x0200u16, 0x0008u16, 0x03f8u16] {
            let (f, n) = frame(fv, &[0x45, 0x00]);
            let (hdr, off) = parse_gre(&f[..n]).unwrap();
            assert_eq!(off, 4, "ignored bits must not shift payload offset");
            assert_eq!(hdr.protocol_type, IPV4_PROTO);
        }
    }

    // RFC 2784 §2.3 receive-discard bits: bit 1 (0x4000), bit 4 (0x0800,
    // strict source route), bit 5 (0x0400), and their union (0x4c00) each
    // require the packet to be discarded without RFC 1701 support.
    #[test]
    fn parse_rejects_each_discard_bit() {
        for fv in [0x4000u16, 0x0800u16, 0x0400u16, 0x4c00u16] {
            let (f, n) = frame(fv, &[0u8; 0]);
            assert!(parse_gre(&f[..n]).is_err(), "discard bit must be rejected");
        }
    }

    // Every nonzero GRE version (1..=7) must be rejected.
    #[test]
    fn parse_rejects_all_nonzero_versions() {
        for ver in 1u16..=7 {
            let (f, n) = frame(ver, &[0u8; 0]);
            assert!(parse_gre(&f[..n]).is_err(), "nonzero version must reject");
        }
    }

    // All eight C/K/S layouts must parse with the RFC-correct payload offset.
    #[test]
    fn parse_cks_layouts_have_correct_offsets() {
        let c = GreFlags::CHECKSUM_BIT;
        let k = GreFlags::KEY_BIT;
        let s = GreFlags::SEQUENCE_BIT;
        let cases: [(u16, usize); 8] = [
            (0, 4),
            (c, 8),
            (k, 8),
            (s, 8),
            (c | k, 12),
            (c | s, 12),
            (k | s, 12),
            (c | k | s, 16),
        ];
        for (fv, expected_off) in cases {
            let (f, n) = frame(fv, &[0u8; 12]);
            let (_hdr, off) = parse_gre(&f[..n]).unwrap();
            assert_eq!(off, expected_off, "offset for flags {fv:#06x}");
        }
    }

    /// Compute the RFC 2784 checksum over `packet` with its checksum field
    /// (bytes 4-5) treated as zero — an independent reference builder so the
    /// checksum tests below are not tautological against the parser's own path.
    fn build_gre_cksum(packet: &[u8]) -> u16 {
        let mut sum: u32 = 0;
        let mut i = 0;
        while i + 1 < packet.len() {
            let word = if i == 4 {
                0
            } else {
                u16::from_be_bytes([packet[i], packet[i + 1]])
            };
            sum = sum.wrapping_add(u32::from(word));
            i += 2;
        }
        if i < packet.len() {
            sum = sum.wrapping_add(u32::from(packet[i]) << 8);
        }
        while (sum >> 16) != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        !(sum as u16)
    }

    /// Build a C-flag GRE packet: flags=0x8000, proto=IPv4, `checksum`,
    /// reserved1, then `payload`. Length is header (8) + payload.
    fn c_frame(checksum: u16, reserved1: u16, payload: &[u8]) -> ([u8; 64], usize) {
        let mut f = [0u8; 64];
        f[0..2].copy_from_slice(&GreFlags::CHECKSUM_BIT.to_be_bytes());
        f[2..4].copy_from_slice(&IPV4_PROTO.to_be_bytes());
        f[4..6].copy_from_slice(&checksum.to_be_bytes());
        f[6..8].copy_from_slice(&reserved1.to_be_bytes());
        f[8..8 + payload.len()].copy_from_slice(payload);
        (f, 8 + payload.len())
    }

    // The validator must accept all eight C/K/S layouts. C-clear cases skip
    // checksum verification; each C-set case gets a real checksum computed
    // over its full optional-field layout and written at bytes 4-5, so the
    // C path is exercised end-to-end (not merely the C=0 skip).
    #[test]
    fn validate_accepts_all_cks_layouts() {
        let c = GreFlags::CHECKSUM_BIT;
        let k = GreFlags::KEY_BIT;
        let s = GreFlags::SEQUENCE_BIT;
        let cases: [(u16, usize); 8] = [
            (0, 4),
            (c, 8),
            (k, 8),
            (s, 8),
            (c | k, 12),
            (c | s, 12),
            (k | s, 12),
            (c | k | s, 16),
        ];
        for (fv, expected_off) in cases {
            let mut f = [0u8; 64];
            f[0..2].copy_from_slice(&fv.to_be_bytes());
            f[2..4].copy_from_slice(&IPV4_PROTO.to_be_bytes());
            let n = expected_off + 2;
            f[expected_off..n].copy_from_slice(&[0x45, 0x00]);
            if (fv & c) != 0 {
                let ck = build_gre_cksum(&f[..n]);
                f[4..6].copy_from_slice(&ck.to_be_bytes());
            }
            let (_hdr, off) = validate_gre_packet(&f[..n]).unwrap();
            assert_eq!(off, expected_off, "offset for flags {fv:#06x}");
        }
    }

    // A C-set packet whose checksum verifies must be accepted; the pinned
    // 0x32ff / 0x77ff constants match an independent builder (non-tautological).
    #[test]
    fn validate_accepts_valid_checksum() {
        let (f, n) = c_frame(0x32ff, 0x0000, &[0x45, 0x00]);
        assert_eq!(build_gre_cksum(&f[..n]), 0x32ff);
        let (hdr, off) = validate_gre_packet(&f[..n]).unwrap();
        assert_eq!(off, 8);
        assert_eq!(hdr.checksum, 0x32ff);

        // C-only header-only (no payload) still has a defined checksum 0x77ff.
        let (f, n) = c_frame(0x77ff, 0x0000, &[]);
        assert_eq!(build_gre_cksum(&f[..n]), 0x77ff);
        assert_eq!(validate_gre_packet(&f[..n]).unwrap().1, 8);
    }

    // A single-bit checksum corruption (0x32ff -> 0x32fe) must be rejected.
    #[test]
    fn validate_rejects_corrupt_checksum() {
        let (f, n) = c_frame(0x32fe, 0x0000, &[0x45, 0x00]);
        assert!(validate_gre_packet(&f[..n]).is_err());
    }

    /// Build a C|K GRE packet: flags=0xA000, proto=IPv4, `checksum`, reserved1,
    /// key=0xDEADBEEF, then `payload`. Length is header (12) + payload.
    fn ck_frame(checksum: u16, payload: &[u8]) -> ([u8; 64], usize) {
        let mut f = [0u8; 64];
        let flags = GreFlags::CHECKSUM_BIT | GreFlags::KEY_BIT;
        f[0..2].copy_from_slice(&flags.to_be_bytes());
        f[2..4].copy_from_slice(&IPV4_PROTO.to_be_bytes());
        f[4..6].copy_from_slice(&checksum.to_be_bytes());
        f[8..12].copy_from_slice(&0xDEAD_BEEFu32.to_be_bytes());
        f[12..12 + payload.len()].copy_from_slice(payload);
        (f, 12 + payload.len())
    }

    /// Build a C|K|S GRE packet: flags=0xB000, proto=IPv4, `checksum`,
    /// reserved1, key=0xDEADBEEF, sequence=1, then `payload`. Length is header
    /// (16) + payload.
    fn cks_frame(checksum: u16, payload: &[u8]) -> ([u8; 64], usize) {
        let mut f = [0u8; 64];
        let flags = GreFlags::CHECKSUM_BIT | GreFlags::KEY_BIT | GreFlags::SEQUENCE_BIT;
        f[0..2].copy_from_slice(&flags.to_be_bytes());
        f[2..4].copy_from_slice(&IPV4_PROTO.to_be_bytes());
        f[4..6].copy_from_slice(&checksum.to_be_bytes());
        f[8..12].copy_from_slice(&0xDEAD_BEEFu32.to_be_bytes());
        f[12..16].copy_from_slice(&1u32.to_be_bytes());
        f[16..16 + payload.len()].copy_from_slice(payload);
        (f, 16 + payload.len())
    }

    // A C|K frame with nonzero key 0xDEADBEEF and a checksum covering the key
    // must verify. The pinned 0x7561 matches build_gre_cksum (non-tautological),
    // and the payload offset is 12 (base 4 + checksum 4 + key 4).
    #[test]
    fn validate_accepts_ck_valid_checksum() {
        let (f, n) = ck_frame(0x7561, &[0x45, 0x00]);
        assert_eq!(build_gre_cksum(&f[..n]), 0x7561);
        let (hdr, off) = validate_gre_packet(&f[..n]).unwrap();
        assert_eq!(off, 12);
        assert_eq!(hdr.key, 0xDEAD_BEEF);
    }

    // A single-bit checksum corruption (0x7561 -> 0x7562) on the C|K frame must
    // be rejected, proving the checksum covers the key field.
    #[test]
    fn validate_rejects_ck_corrupt_checksum() {
        let (f, n) = ck_frame(0x7562, &[0x45, 0x00]);
        assert!(validate_gre_packet(&f[..n]).is_err());
    }

    // A C|K|S frame with nonzero key 0xDEADBEEF and sequence 1 and a checksum
    // covering both must verify. The pinned 0x6560 matches build_gre_cksum, and
    // the payload offset is 16 (base 4 + checksum 4 + key 4 + sequence 4).
    #[test]
    fn validate_accepts_cks_valid_checksum() {
        let (f, n) = cks_frame(0x6560, &[0x45, 0x00]);
        assert_eq!(build_gre_cksum(&f[..n]), 0x6560);
        let (hdr, off) = validate_gre_packet(&f[..n]).unwrap();
        assert_eq!(off, 16);
        assert_eq!(hdr.key, 0xDEAD_BEEF);
        assert_eq!(hdr.sequence_number, 1);
    }

    // A single-bit checksum corruption (0x6560 -> 0x6561) on the C|K|S frame
    // must be rejected, proving the checksum covers the sequence field.
    #[test]
    fn validate_rejects_cks_corrupt_checksum() {
        let (f, n) = cks_frame(0x6561, &[0x45, 0x00]);
        assert!(validate_gre_packet(&f[..n]).is_err());
    }

    // An odd-length payload ([0x45]) is right-padded with zero per RFC 1071,
    // yielding the same 0x32ff checksum as the even [0x45,0x00] case.
    #[test]
    fn validate_accepts_odd_length_payload() {
        let (f, n) = c_frame(0x32ff, 0x0000, &[0x45]);
        assert_eq!(build_gre_cksum(&f[..n]), 0x32ff);
        assert_eq!(validate_gre_packet(&f[..n]).unwrap().1, 8);
    }

    // A base (C-clear) header-only packet is structurally valid to the generic
    // validator: no payload requirement, no checksum to verify.
    #[test]
    fn validate_accepts_base_header_only() {
        let (f, n) = frame(0x0000, &[]);
        let (_hdr, off) = validate_gre_packet(&f[..n]).unwrap();
        assert_eq!(off, 4);
    }

    // C=0 must skip checksum verification entirely: a garbage checksum-field
    // value is irrelevant because the C-clear frame carries no checksum word.
    #[test]
    fn validate_c_clear_skips_checksum() {
        let (f, n) = frame(0x0000, &[0xFF, 0xFF]);
        assert!(validate_gre_packet(&f[..n]).is_ok());
    }

    // Structural errors from parse_gre propagate through the validator:
    // truncated optional field and nonzero version.
    #[test]
    fn validate_propagates_structural_errors() {
        let mut trunc = [0u8; 6];
        trunc[0..2].copy_from_slice(&GreFlags::KEY_BIT.to_be_bytes());
        trunc[2..4].copy_from_slice(&IPV4_PROTO.to_be_bytes());
        assert!(validate_gre_packet(&trunc).is_err());

        let (f, n) = frame(0x0001, &[0u8; 0]);
        assert!(validate_gre_packet(&f[..n]).is_err());
    }

    // RFC 2784 mandates Reserved1 transmit-zero but NOT receiver discard: a
    // nonzero Reserved1 must be accepted when it is covered by a valid
    // checksum (0x20cb over reserved1=0x1234 + [0x45,0x00]).
    #[test]
    fn validate_accepts_nonzero_reserved1() {
        let (f, n) = c_frame(0x20cb, 0x1234, &[0x45, 0x00]);
        assert_eq!(build_gre_cksum(&f[..n]), 0x20cb);
        assert!(validate_gre_packet(&f[..n]).is_ok());
    }

    // decapsulate_depth requires payload even though the generic validator
    // accepts header-only framing: a C-clear header-only packet validates
    // structurally but is rejected by tunnel decapsulation.
    #[test]
    fn decapsulate_rejects_header_only_packet() {
        let (f, n) = frame(0x0000, &[]);
        assert!(validate_gre_packet(&f[..n]).is_ok());
        let tunnel = GreTunnel::new(1, 0, 0, None);
        assert!(tunnel.decapsulate_depth(&f[..n], MAX_ENCAP_LIMIT).is_err());
    }
}
