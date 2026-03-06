// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Minimal DNS stub resolver for the ONCRIX kernel.
//!
//! Provides DNS wire-format encoding/decoding, query construction,
//! response parsing, a simple TTL-aware cache, and a resolver that
//! returns either a cached IP or a ready-to-send query buffer.
//!
//! All multi-byte fields use network byte order (big-endian) as
//! required by RFC 1035.

use oncrix_lib::{Error, Result};

// =========================================================================
// Constants
// =========================================================================

/// Standard DNS port number.
pub const DNS_PORT: u16 = 53;

/// DNS resource record type: A (IPv4 host address).
pub const TYPE_A: u16 = 1;

/// DNS resource record type: NS (authoritative name server).
pub const TYPE_NS: u16 = 2;

/// DNS resource record type: CNAME (canonical name alias).
pub const TYPE_CNAME: u16 = 5;

/// DNS resource record type: SOA (start of authority).
pub const TYPE_SOA: u16 = 6;

/// DNS resource record type: PTR (domain name pointer).
pub const TYPE_PTR: u16 = 12;

/// DNS resource record type: MX (mail exchange).
pub const TYPE_MX: u16 = 15;

/// DNS resource record type: TXT (text strings).
pub const TYPE_TXT: u16 = 16;

/// DNS resource record type: AAAA (IPv6 host address).
pub const TYPE_AAAA: u16 = 28;

/// DNS resource record class: IN (Internet).
pub const CLASS_IN: u16 = 1;

/// DNS response code: no error.
pub const RCODE_NOERROR: u8 = 0;

/// DNS response code: format error.
pub const RCODE_FORMERR: u8 = 1;

/// DNS response code: server failure.
pub const RCODE_SERVFAIL: u8 = 2;

/// DNS response code: non-existent domain.
pub const RCODE_NXDOMAIN: u8 = 3;

/// DNS response code: not implemented.
pub const RCODE_NOTIMP: u8 = 4;

/// DNS response code: query refused.
pub const RCODE_REFUSED: u8 = 5;

/// DNS flag: query/response bit (1 = response).
pub const DNS_FLAG_QR: u16 = 0x8000;

/// DNS flag: recursion desired.
pub const DNS_FLAG_RD: u16 = 0x0100;

/// DNS flag: recursion available.
pub const DNS_FLAG_RA: u16 = 0x0080;

/// DNS header size in bytes.
const DNS_HEADER_LEN: usize = 12;

/// Maximum label length in a domain name (RFC 1035).
const MAX_LABEL_LEN: usize = 63;

/// Maximum total domain name length (RFC 1035).
const MAX_DOMAIN_LEN: usize = 253;

/// Maximum number of pointer indirections to prevent loops.
const MAX_POINTERS: usize = 16;

/// Maximum number of answer records stored in a response.
const MAX_ANSWERS: usize = 8;

/// Maximum number of entries in the DNS cache.
const DNS_CACHE_SIZE: usize = 32;

// =========================================================================
// DnsHeader
// =========================================================================

/// DNS message header (RFC 1035 section 4.1.1).
///
/// All fields are stored in host byte order after parsing; wire
/// serialisation converts back to network byte order.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[repr(C)]
pub struct DnsHeader {
    /// Transaction identifier.
    pub id: u16,
    /// Flags and codes (QR, OPCODE, AA, TC, RD, RA, RCODE).
    pub flags: u16,
    /// Number of entries in the question section.
    pub qd_count: u16,
    /// Number of resource records in the answer section.
    pub an_count: u16,
    /// Number of name server resource records.
    pub ns_count: u16,
    /// Number of additional resource records.
    pub ar_count: u16,
}

impl DnsHeader {
    /// Returns `true` if the QR bit is set (this is a response).
    pub fn is_response(&self) -> bool {
        (self.flags & DNS_FLAG_QR) != 0
    }

    /// Returns the 4-bit OPCODE field.
    pub fn opcode(&self) -> u8 {
        ((self.flags >> 11) & 0x0F) as u8
    }

    /// Returns the 4-bit RCODE field.
    pub fn rcode(&self) -> u8 {
        (self.flags & 0x000F) as u8
    }

    /// Returns `true` if the TC (truncation) bit is set.
    pub fn is_truncated(&self) -> bool {
        (self.flags & 0x0200) != 0
    }

    /// Returns `true` if the RD (recursion desired) bit is set.
    pub fn recursion_desired(&self) -> bool {
        (self.flags & DNS_FLAG_RD) != 0
    }

    /// Returns `true` if the RA (recursion available) bit is set.
    pub fn recursion_available(&self) -> bool {
        (self.flags & DNS_FLAG_RA) != 0
    }
}

// =========================================================================
// DnsQuestion
// =========================================================================

/// A single DNS question entry.
///
/// The `qname` field stores the domain name in wire format
/// (length-prefixed labels terminated by a zero-length label).
#[derive(Clone)]
pub struct DnsQuestion {
    /// Domain name in DNS wire format.
    pub qname: [u8; 256],
    /// Number of valid bytes in `qname`.
    pub qname_len: usize,
    /// Query type (e.g., [`TYPE_A`]).
    pub qtype: u16,
    /// Query class (e.g., [`CLASS_IN`]).
    pub qclass: u16,
}

impl Default for DnsQuestion {
    fn default() -> Self {
        Self {
            qname: [0u8; 256],
            qname_len: 0,
            qtype: TYPE_A,
            qclass: CLASS_IN,
        }
    }
}

// =========================================================================
// DnsRecord
// =========================================================================

/// A single DNS resource record.
#[derive(Clone)]
pub struct DnsRecord {
    /// Owner name (decoded, dot-separated ASCII).
    pub name: [u8; 256],
    /// Number of valid bytes in `name`.
    pub name_len: usize,
    /// Record type (e.g., [`TYPE_A`]).
    pub rtype: u16,
    /// Record class (e.g., [`CLASS_IN`]).
    pub rclass: u16,
    /// Time-to-live in seconds.
    pub ttl: u32,
    /// Record data (format depends on `rtype`).
    pub rdata: [u8; 256],
    /// Number of valid bytes in `rdata`.
    pub rdata_len: usize,
}

#[allow(clippy::derivable_impls)]
impl Default for DnsRecord {
    fn default() -> Self {
        Self {
            name: [0u8; 256],
            name_len: 0,
            rtype: 0,
            rclass: 0,
            ttl: 0,
            rdata: [0u8; 256],
            rdata_len: 0,
        }
    }
}

// =========================================================================
// DnsResponse
// =========================================================================

/// Parsed DNS response containing header and answer records.
#[derive(Default)]
pub struct DnsResponse {
    /// DNS message header.
    pub header: DnsHeader,
    /// Answer records (up to [`MAX_ANSWERS`]).
    pub answers: [Option<DnsRecord>; MAX_ANSWERS],
    /// Number of answer records parsed.
    pub answer_count: usize,
}

// =========================================================================
// Domain name encoding / decoding
// =========================================================================

/// Encode a dot-separated domain name into DNS wire format.
///
/// Converts a human-readable name like `b"example.com"` into the
/// length-prefixed label sequence `\x07example\x03com\x00`.
///
/// # Errors
///
/// Returns [`Error::InvalidArgument`] if:
/// - `name` is empty or exceeds [`MAX_DOMAIN_LEN`] (253) bytes
/// - Any label exceeds [`MAX_LABEL_LEN`] (63) bytes
/// - Any label is empty (consecutive dots)
/// - `out` is too small to hold the encoded name
pub fn encode_domain_name(name: &[u8], out: &mut [u8]) -> Result<usize> {
    if name.is_empty() || name.len() > MAX_DOMAIN_LEN {
        return Err(Error::InvalidArgument);
    }

    // Strip trailing dot if present (FQDN notation).
    let name = if name.last() == Some(&b'.') {
        &name[..name.len().saturating_sub(1)]
    } else {
        name
    };

    if name.is_empty() {
        return Err(Error::InvalidArgument);
    }

    let mut pos: usize = 0;
    let mut label_start: usize = 0;

    let mut i: usize = 0;
    while i <= name.len() {
        let at_end = i == name.len();
        let is_dot = !at_end && name[i] == b'.';

        if at_end || is_dot {
            let label_len = i.saturating_sub(label_start);
            if label_len == 0 || label_len > MAX_LABEL_LEN {
                return Err(Error::InvalidArgument);
            }

            // Need space for length byte + label + final NUL.
            if pos.saturating_add(1).saturating_add(label_len) > out.len() {
                return Err(Error::InvalidArgument);
            }

            out[pos] = label_len as u8;
            pos = pos.saturating_add(1);

            out[pos..pos.saturating_add(label_len)].copy_from_slice(&name[label_start..i]);
            pos = pos.saturating_add(label_len);

            label_start = i.saturating_add(1);
        }

        i = i.saturating_add(1);
    }

    // Terminating zero-length label.
    if pos >= out.len() {
        return Err(Error::InvalidArgument);
    }
    out[pos] = 0;
    pos = pos.saturating_add(1);

    Ok(pos)
}

/// Decode a DNS wire-format domain name with pointer compression.
///
/// Reads from `data` starting at `offset`.  The decoded
/// dot-separated name is written to `out`.  Returns
/// `(bytes_consumed, name_length)` where `bytes_consumed` is the
/// number of bytes consumed from the original offset (not following
/// pointers) and `name_length` is the number of bytes written to
/// `out`.
///
/// # Errors
///
/// Returns [`Error::InvalidArgument`] if the data is malformed,
/// a pointer loop is detected, or `out` is too small.
pub fn decode_domain_name(data: &[u8], offset: usize, out: &mut [u8]) -> Result<(usize, usize)> {
    let mut cur = offset;
    let mut out_pos: usize = 0;
    let mut jumped = false;
    let mut consumed: usize = 0;
    let mut pointer_count: usize = 0;

    loop {
        if cur >= data.len() {
            return Err(Error::InvalidArgument);
        }

        let len_byte = data[cur];

        // Check for pointer (top two bits set).
        if (len_byte & 0xC0) == 0xC0 {
            if cur.saturating_add(1) >= data.len() {
                return Err(Error::InvalidArgument);
            }
            if !jumped {
                consumed = cur.saturating_sub(offset).saturating_add(2);
            }
            let ptr = u16::from_be_bytes([len_byte & 0x3F, data[cur.saturating_add(1)]]) as usize;
            if ptr >= data.len() {
                return Err(Error::InvalidArgument);
            }
            cur = ptr;
            jumped = true;
            pointer_count = pointer_count.saturating_add(1);
            if pointer_count > MAX_POINTERS {
                return Err(Error::InvalidArgument);
            }
            continue;
        }

        // Zero-length label terminates the name.
        if len_byte == 0 {
            if !jumped {
                consumed = cur.saturating_sub(offset).saturating_add(1);
            }
            break;
        }

        let label_len = len_byte as usize;
        if label_len > MAX_LABEL_LEN {
            return Err(Error::InvalidArgument);
        }

        let label_end = cur.saturating_add(1).saturating_add(label_len);
        if label_end > data.len() {
            return Err(Error::InvalidArgument);
        }

        // Add dot separator between labels.
        if out_pos > 0 {
            if out_pos >= out.len() {
                return Err(Error::InvalidArgument);
            }
            out[out_pos] = b'.';
            out_pos = out_pos.saturating_add(1);
        }

        // Copy label bytes.
        let dst_end = out_pos.saturating_add(label_len);
        if dst_end > out.len() {
            return Err(Error::InvalidArgument);
        }
        out[out_pos..dst_end].copy_from_slice(&data[cur.saturating_add(1)..label_end]);
        out_pos = dst_end;

        cur = label_end;
    }

    Ok((consumed, out_pos))
}

// =========================================================================
// Query builder
// =========================================================================

/// Build a complete DNS query packet.
///
/// Constructs a standard recursive query for the given
/// `domain_name` (dot-separated ASCII) with the specified `qtype`.
/// The packet is written to `buf` and the total length is returned.
///
/// # Errors
///
/// Returns [`Error::InvalidArgument`] if the domain name is invalid
/// or `buf` is too small to hold the query.
pub fn build_query(id: u16, domain_name: &[u8], qtype: u16, buf: &mut [u8]) -> Result<usize> {
    if buf.len() < DNS_HEADER_LEN {
        return Err(Error::InvalidArgument);
    }

    // Write header.
    let id_bytes = id.to_be_bytes();
    buf[0] = id_bytes[0];
    buf[1] = id_bytes[1];

    // Flags: RD=1 (recursion desired).
    let flags = DNS_FLAG_RD.to_be_bytes();
    buf[2] = flags[0];
    buf[3] = flags[1];

    // QDCOUNT = 1.
    buf[4] = 0;
    buf[5] = 1;

    // ANCOUNT, NSCOUNT, ARCOUNT = 0.
    buf[6] = 0;
    buf[7] = 0;
    buf[8] = 0;
    buf[9] = 0;
    buf[10] = 0;
    buf[11] = 0;

    let mut pos = DNS_HEADER_LEN;

    // Encode the question name.
    let name_len = encode_domain_name(domain_name, &mut buf[pos..])?;
    pos = pos.saturating_add(name_len);

    // QTYPE and QCLASS (4 bytes).
    if pos.saturating_add(4) > buf.len() {
        return Err(Error::InvalidArgument);
    }

    let qt = qtype.to_be_bytes();
    buf[pos] = qt[0];
    buf[pos.saturating_add(1)] = qt[1];
    pos = pos.saturating_add(2);

    let qc = CLASS_IN.to_be_bytes();
    buf[pos] = qc[0];
    buf[pos.saturating_add(1)] = qc[1];
    pos = pos.saturating_add(2);

    Ok(pos)
}

// =========================================================================
// Response parser
// =========================================================================

/// Parse the DNS header from the first 12 bytes of `data`.
fn parse_header(data: &[u8]) -> Result<DnsHeader> {
    if data.len() < DNS_HEADER_LEN {
        return Err(Error::InvalidArgument);
    }
    Ok(DnsHeader {
        id: u16::from_be_bytes([data[0], data[1]]),
        flags: u16::from_be_bytes([data[2], data[3]]),
        qd_count: u16::from_be_bytes([data[4], data[5]]),
        an_count: u16::from_be_bytes([data[6], data[7]]),
        ns_count: u16::from_be_bytes([data[8], data[9]]),
        ar_count: u16::from_be_bytes([data[10], data[11]]),
    })
}

/// Skip a wire-format domain name at `offset`, returning the new
/// offset past the name.
fn skip_name(data: &[u8], offset: usize) -> Result<usize> {
    let mut cur = offset;
    let mut pointer_count: usize = 0;

    loop {
        if cur >= data.len() {
            return Err(Error::InvalidArgument);
        }
        let b = data[cur];
        if (b & 0xC0) == 0xC0 {
            // Pointer: 2 bytes total, then we are done.
            return Ok(cur.saturating_add(2));
        }
        if b == 0 {
            return Ok(cur.saturating_add(1));
        }
        let label_len = b as usize;
        cur = cur.saturating_add(1).saturating_add(label_len);
        pointer_count = pointer_count.saturating_add(1);
        if pointer_count > MAX_POINTERS {
            return Err(Error::InvalidArgument);
        }
    }
}

/// Parse a DNS response packet.
///
/// Extracts the header and up to [`MAX_ANSWERS`] (8) answer
/// resource records.
///
/// # Errors
///
/// Returns [`Error::InvalidArgument`] if the packet is malformed
/// or too short, or [`Error::IoError`] if the response code
/// indicates a server error.
pub fn parse_response(data: &[u8]) -> Result<DnsResponse> {
    let header = parse_header(data)?;

    if !header.is_response() {
        return Err(Error::InvalidArgument);
    }

    if header.rcode() != RCODE_NOERROR {
        return Err(Error::IoError);
    }

    let mut response = DnsResponse {
        header,
        answers: Default::default(),
        answer_count: 0,
    };

    // Skip past question section.
    let mut pos = DNS_HEADER_LEN;
    let mut qi: u16 = 0;
    while qi < header.qd_count {
        pos = skip_name(data, pos)?;
        // QTYPE + QCLASS = 4 bytes.
        pos = pos.saturating_add(4);
        if pos > data.len() {
            return Err(Error::InvalidArgument);
        }
        qi = qi.saturating_add(1);
    }

    // Parse answer records.
    let count = if (header.an_count as usize) < MAX_ANSWERS {
        header.an_count as usize
    } else {
        MAX_ANSWERS
    };

    let mut ai: usize = 0;
    while ai < count {
        if pos >= data.len() {
            break;
        }

        let mut record = DnsRecord::default();

        // Decode the owner name.
        let (name_consumed, name_len) = decode_domain_name(data, pos, &mut record.name)?;
        record.name_len = name_len;
        pos = pos.saturating_add(name_consumed);

        // TYPE(2) + CLASS(2) + TTL(4) + RDLENGTH(2) = 10 bytes.
        if pos.saturating_add(10) > data.len() {
            return Err(Error::InvalidArgument);
        }

        record.rtype = u16::from_be_bytes([data[pos], data[pos.saturating_add(1)]]);
        pos = pos.saturating_add(2);

        record.rclass = u16::from_be_bytes([data[pos], data[pos.saturating_add(1)]]);
        pos = pos.saturating_add(2);

        record.ttl = u32::from_be_bytes([
            data[pos],
            data[pos.saturating_add(1)],
            data[pos.saturating_add(2)],
            data[pos.saturating_add(3)],
        ]);
        pos = pos.saturating_add(4);

        let rdlength = u16::from_be_bytes([data[pos], data[pos.saturating_add(1)]]) as usize;
        pos = pos.saturating_add(2);

        if pos.saturating_add(rdlength) > data.len() {
            return Err(Error::InvalidArgument);
        }

        let copy_len = if rdlength < record.rdata.len() {
            rdlength
        } else {
            record.rdata.len()
        };
        record.rdata[..copy_len].copy_from_slice(&data[pos..pos.saturating_add(copy_len)]);
        record.rdata_len = copy_len;

        pos = pos.saturating_add(rdlength);

        response.answers[ai] = Some(record);
        response.answer_count = response.answer_count.saturating_add(1);

        ai = ai.saturating_add(1);
    }

    Ok(response)
}

// =========================================================================
// DnsCache
// =========================================================================

/// A single DNS cache entry mapping a domain name to an IPv4 address.
#[derive(Clone)]
struct CacheEntry {
    /// Domain name (dot-separated ASCII).
    name: [u8; 128],
    /// Number of valid bytes in `name`.
    name_len: usize,
    /// Resolved IPv4 address.
    ip: [u8; 4],
    /// Time-to-live in seconds.
    ttl: u32,
    /// Tick count when this entry was inserted.
    insert_tick: u64,
    /// Whether this entry is in use.
    valid: bool,
}

impl Default for CacheEntry {
    fn default() -> Self {
        Self {
            name: [0u8; 128],
            name_len: 0,
            ip: [0u8; 4],
            ttl: 0,
            insert_tick: 0,
            valid: false,
        }
    }
}

/// TTL-aware DNS cache with a fixed capacity of [`DNS_CACHE_SIZE`]
/// entries.
///
/// Entries expire when the current tick exceeds
/// `insert_tick + ttl * ticks_per_second`.  For simplicity, TTL is
/// compared directly against elapsed ticks (caller must ensure ticks
/// represent seconds or adjust accordingly).
pub struct DnsCache {
    /// Fixed-size array of cache entries.
    entries: [CacheEntry; DNS_CACHE_SIZE],
}

impl Default for DnsCache {
    fn default() -> Self {
        Self::new()
    }
}

impl DnsCache {
    /// Create an empty DNS cache.
    pub const fn new() -> Self {
        // const fn cannot use Default::default() for arrays, so we
        // initialise manually.
        const EMPTY: CacheEntry = CacheEntry {
            name: [0u8; 128],
            name_len: 0,
            ip: [0u8; 4],
            ttl: 0,
            insert_tick: 0,
            valid: false,
        };
        Self {
            entries: [EMPTY; DNS_CACHE_SIZE],
        }
    }

    /// Look up an IPv4 address for `name`, returning `None` if the
    /// entry is missing or has expired.
    pub fn lookup(&self, name: &[u8], current_tick: u64) -> Option<[u8; 4]> {
        for entry in &self.entries {
            if !entry.valid || entry.name_len != name.len() {
                continue;
            }
            if entry.name[..entry.name_len] != *name {
                continue;
            }
            // Check expiry: insert_tick + ttl (in ticks).
            let expiry = entry.insert_tick.saturating_add(entry.ttl as u64);
            if current_tick > expiry {
                // Expired.
                return None;
            }
            return Some(entry.ip);
        }
        None
    }

    /// Insert or update a cache entry.
    ///
    /// If an entry for `name` already exists it is updated.
    /// Otherwise the first free or expired slot is used.  If no
    /// slot is available, slot 0 is evicted.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `name` is too long
    /// to fit in a cache entry (128 bytes).
    pub fn insert(&mut self, name: &[u8], ip: [u8; 4], ttl: u32, current_tick: u64) -> Result<()> {
        if name.len() > 128 {
            return Err(Error::InvalidArgument);
        }

        // Update existing entry if present.
        for entry in &mut self.entries {
            if entry.valid && entry.name_len == name.len() && entry.name[..entry.name_len] == *name
            {
                entry.ip = ip;
                entry.ttl = ttl;
                entry.insert_tick = current_tick;
                return Ok(());
            }
        }

        // Find first free slot.
        for entry in &mut self.entries {
            if !entry.valid {
                Self::write_entry(entry, name, ip, ttl, current_tick);
                return Ok(());
            }
        }

        // Evict slot 0.
        Self::write_entry(&mut self.entries[0], name, ip, ttl, current_tick);
        Ok(())
    }

    /// Remove all entries whose TTL has expired.
    pub fn evict_expired(&mut self, current_tick: u64) {
        for entry in &mut self.entries {
            if !entry.valid {
                continue;
            }
            let expiry = entry.insert_tick.saturating_add(entry.ttl as u64);
            if current_tick > expiry {
                entry.valid = false;
            }
        }
    }

    /// Write fields into a single cache entry.
    fn write_entry(entry: &mut CacheEntry, name: &[u8], ip: [u8; 4], ttl: u32, current_tick: u64) {
        entry.name[..name.len()].copy_from_slice(name);
        entry.name_len = name.len();
        entry.ip = ip;
        entry.ttl = ttl;
        entry.insert_tick = current_tick;
        entry.valid = true;
    }
}

// =========================================================================
// ResolveAction
// =========================================================================

/// Action returned by [`DnsResolver::resolve`].
///
/// Either the name was found in the cache and the IP is returned
/// immediately, or a DNS query packet has been built and must be
/// sent to the configured server.
#[allow(clippy::large_enum_variant)]
pub enum ResolveAction {
    /// The name was resolved from the cache.
    CacheHit {
        /// Resolved IPv4 address.
        ip: [u8; 4],
    },
    /// A query must be sent to the DNS server.
    SendQuery {
        /// Buffer containing the DNS query packet.
        buf: [u8; 512],
        /// Number of valid bytes in `buf`.
        len: usize,
    },
}

// =========================================================================
// DnsResolver
// =========================================================================

/// Minimal DNS stub resolver.
///
/// Maintains a cache and builds query packets.  The caller is
/// responsible for the actual UDP transport (sending the query and
/// feeding the response back via
/// [`process_response`](Self::process_response)).
pub struct DnsResolver {
    /// IPv4 address of the upstream DNS server.
    pub server_ip: [u8; 4],
    /// DNS record cache.
    pub cache: DnsCache,
    /// Next transaction ID to use.
    next_id: u16,
}

impl DnsResolver {
    /// Create a new resolver pointing at the given DNS server.
    pub const fn new(server_ip: [u8; 4]) -> Self {
        Self {
            server_ip,
            cache: DnsCache::new(),
            next_id: 1,
        }
    }

    /// Resolve a domain name to an IPv4 address.
    ///
    /// Checks the cache first.  On a miss, builds a DNS A-record
    /// query packet and returns it as a [`ResolveAction::SendQuery`]
    /// for the caller to transmit via UDP.
    ///
    /// The `current_tick` is used for cache TTL checks.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if the domain name is
    /// invalid or too long.
    pub fn resolve(&mut self, name: &[u8], current_tick: u64) -> Result<ResolveAction> {
        // Check cache first.
        if let Some(ip) = self.cache.lookup(name, current_tick) {
            return Ok(ResolveAction::CacheHit { ip });
        }

        // Build a query.
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);

        let mut buf = [0u8; 512];
        let len = build_query(id, name, TYPE_A, &mut buf)?;

        Ok(ResolveAction::SendQuery { buf, len })
    }

    /// Process a DNS response packet.
    ///
    /// Parses the response, caches any A records found, and returns
    /// the first A-record IPv4 address (if any).
    ///
    /// # Errors
    ///
    /// Propagates parsing errors from [`parse_response`].
    pub fn process_response(&mut self, data: &[u8], current_tick: u64) -> Result<Option<[u8; 4]>> {
        let response = parse_response(data)?;
        let mut result_ip: Option<[u8; 4]> = None;

        let mut i: usize = 0;
        while i < response.answer_count {
            if let Some(ref record) = response.answers[i] {
                if record.rtype == TYPE_A && record.rclass == CLASS_IN && record.rdata_len == 4 {
                    let ip = [
                        record.rdata[0],
                        record.rdata[1],
                        record.rdata[2],
                        record.rdata[3],
                    ];

                    // Cache using the decoded owner name.
                    let name = &record.name[..record.name_len];
                    let _ = self.cache.insert(name, ip, record.ttl, current_tick);

                    if result_ip.is_none() {
                        result_ip = Some(ip);
                    }
                }
            }
            i = i.saturating_add(1);
        }

        Ok(result_ip)
    }
}

// =========================================================================
// Tests
// =========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_domain_name_simple() {
        let mut buf = [0u8; 64];
        let len = encode_domain_name(b"example.com", &mut buf).unwrap();
        // \x07example\x03com\x00
        assert_eq!(len, 13);
        assert_eq!(buf[0], 7);
        assert_eq!(&buf[1..8], b"example");
        assert_eq!(buf[8], 3);
        assert_eq!(&buf[9..12], b"com");
        assert_eq!(buf[12], 0);
    }

    #[test]
    fn test_encode_domain_name_trailing_dot() {
        let mut buf = [0u8; 64];
        let len = encode_domain_name(b"example.com.", &mut buf).unwrap();
        assert_eq!(len, 13);
    }

    #[test]
    fn test_encode_domain_name_empty_label_rejected() {
        let mut buf = [0u8; 64];
        assert!(encode_domain_name(b"example..com", &mut buf).is_err());
    }

    #[test]
    fn test_encode_domain_name_empty_rejected() {
        let mut buf = [0u8; 64];
        assert!(encode_domain_name(b"", &mut buf).is_err());
    }

    #[test]
    fn test_decode_domain_name_simple() {
        // Wire format: \x07example\x03com\x00
        let data: [u8; 13] = [
            7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0,
        ];
        let mut out = [0u8; 256];
        let (consumed, name_len) = decode_domain_name(&data, 0, &mut out).unwrap();
        assert_eq!(consumed, 13);
        assert_eq!(name_len, 11);
        assert_eq!(&out[..name_len], b"example.com");
    }

    #[test]
    fn test_decode_domain_name_pointer() {
        // Build a packet with a name at offset 0, then a pointer
        // at offset 13.
        let mut data = [0u8; 16];
        // "example.com" at offset 0.
        data[0] = 7;
        data[1..8].copy_from_slice(b"example");
        data[8] = 3;
        data[9..12].copy_from_slice(b"com");
        data[12] = 0;
        // Pointer to offset 0 at position 13.
        data[13] = 0xC0;
        data[14] = 0x00;

        let mut out = [0u8; 256];
        let (consumed, name_len) = decode_domain_name(&data, 13, &mut out).unwrap();
        assert_eq!(consumed, 2);
        assert_eq!(&out[..name_len], b"example.com");
    }

    #[test]
    fn test_build_query() {
        let mut buf = [0u8; 512];
        let len = build_query(0x1234, b"example.com", TYPE_A, &mut buf).unwrap();

        // Header: 12 bytes, question name: 13, qtype: 2, qclass: 2
        assert_eq!(len, 12 + 13 + 4);

        // Check ID.
        assert_eq!(buf[0], 0x12);
        assert_eq!(buf[1], 0x34);

        // Check flags (RD=1).
        assert_eq!(buf[2], 0x01);
        assert_eq!(buf[3], 0x00);

        // QDCOUNT=1.
        assert_eq!(buf[4], 0x00);
        assert_eq!(buf[5], 0x01);
    }

    #[test]
    fn test_parse_response_a_record() {
        // Minimal DNS response for example.com -> 93.184.216.34
        #[rustfmt::skip]
        let response: [u8; 43] = [
            // Header
            0x12, 0x34, // ID
            0x81, 0x80, // QR=1, RD=1, RA=1
            0x00, 0x01, // QDCOUNT=1
            0x00, 0x01, // ANCOUNT=1
            0x00, 0x00, // NSCOUNT=0
            0x00, 0x00, // ARCOUNT=0
            // Question: example.com, A, IN
            0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e',
            0x03, b'c', b'o', b'm', 0x00,
            0x00, 0x01, // QTYPE=A
            0x00, 0x01, // QCLASS=IN
            // Answer: pointer to name at offset 12
            0xC0, 0x0C,
            0x00, 0x01, // TYPE=A
            0x00, 0x01, // CLASS=IN
            0x00, 0x00, 0x01, 0x2C, // TTL=300
            0x00, 0x04, // RDLENGTH=4
            93, 184, 216, 34, // RDATA
        ];

        let resp = parse_response(&response).unwrap();
        assert_eq!(resp.header.id, 0x1234);
        assert!(resp.header.is_response());
        assert_eq!(resp.header.rcode(), RCODE_NOERROR);
        assert_eq!(resp.answer_count, 1);

        let record = resp.answers[0].as_ref().unwrap();
        assert_eq!(record.rtype, TYPE_A);
        assert_eq!(record.rdata_len, 4);
        assert_eq!(&record.rdata[..4], &[93, 184, 216, 34]);
    }

    #[test]
    fn test_dns_cache_insert_lookup() {
        let mut cache = DnsCache::new();
        let name = b"example.com";
        let ip = [93, 184, 216, 34];

        assert!(cache.lookup(name, 0).is_none());

        cache.insert(name, ip, 300, 0).unwrap();
        assert_eq!(cache.lookup(name, 0), Some(ip));
        assert_eq!(cache.lookup(name, 300), Some(ip));

        // Expired after TTL.
        assert!(cache.lookup(name, 301).is_none());
    }

    #[test]
    fn test_dns_cache_evict_expired() {
        let mut cache = DnsCache::new();
        cache.insert(b"a.com", [1, 2, 3, 4], 10, 0).unwrap();
        cache.insert(b"b.com", [5, 6, 7, 8], 100, 0).unwrap();

        cache.evict_expired(50);

        // a.com (TTL=10) should be evicted.
        assert!(cache.lookup(b"a.com", 50).is_none());
        // b.com (TTL=100) should still be valid.
        assert_eq!(cache.lookup(b"b.com", 50), Some([5, 6, 7, 8]));
    }

    #[test]
    fn test_resolver_cache_hit() {
        let mut resolver = DnsResolver::new([8, 8, 8, 8]);
        resolver
            .cache
            .insert(b"cached.com", [1, 1, 1, 1], 300, 0)
            .unwrap();

        match resolver.resolve(b"cached.com", 0).unwrap() {
            ResolveAction::CacheHit { ip } => {
                assert_eq!(ip, [1, 1, 1, 1]);
            }
            ResolveAction::SendQuery { .. } => {
                panic!("expected cache hit");
            }
        }
    }

    #[test]
    fn test_resolver_cache_miss() {
        let mut resolver = DnsResolver::new([8, 8, 8, 8]);

        match resolver.resolve(b"miss.com", 0).unwrap() {
            ResolveAction::CacheHit { .. } => {
                panic!("expected cache miss");
            }
            ResolveAction::SendQuery { buf, len } => {
                assert!(len > DNS_HEADER_LEN);
                // Verify it is a valid query (QR=0).
                let flags = u16::from_be_bytes([buf[2], buf[3]]);
                assert_eq!(flags & DNS_FLAG_QR, 0);
            }
        }
    }

    #[test]
    fn test_resolver_process_response() {
        let mut resolver = DnsResolver::new([8, 8, 8, 8]);

        #[rustfmt::skip]
        let response: [u8; 43] = [
            0x00, 0x01,
            0x81, 0x80,
            0x00, 0x01,
            0x00, 0x01,
            0x00, 0x00,
            0x00, 0x00,
            0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e',
            0x03, b'c', b'o', b'm', 0x00,
            0x00, 0x01,
            0x00, 0x01,
            0xC0, 0x0C,
            0x00, 0x01,
            0x00, 0x01,
            0x00, 0x00, 0x01, 0x2C,
            0x00, 0x04,
            93, 184, 216, 34,
        ];

        let ip = resolver.process_response(&response, 100).unwrap().unwrap();
        assert_eq!(ip, [93, 184, 216, 34]);

        // Should now be cached.
        assert_eq!(
            resolver.cache.lookup(b"example.com", 100),
            Some([93, 184, 216, 34])
        );
    }

    #[test]
    fn test_header_flag_methods() {
        let hdr = DnsHeader {
            id: 0,
            flags: DNS_FLAG_QR | DNS_FLAG_RD | DNS_FLAG_RA,
            qd_count: 0,
            an_count: 0,
            ns_count: 0,
            ar_count: 0,
        };
        assert!(hdr.is_response());
        assert!(hdr.recursion_desired());
        assert!(hdr.recursion_available());
        assert!(!hdr.is_truncated());
        assert_eq!(hdr.opcode(), 0);
        assert_eq!(hdr.rcode(), RCODE_NOERROR);
    }

    #[test]
    fn test_header_truncated() {
        let hdr = DnsHeader {
            id: 0,
            flags: 0x0200, // TC bit
            qd_count: 0,
            an_count: 0,
            ns_count: 0,
            ar_count: 0,
        };
        assert!(hdr.is_truncated());
    }
}
