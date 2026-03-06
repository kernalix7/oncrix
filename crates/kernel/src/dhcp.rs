// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Minimal DHCP client for the ONCRIX network stack.
//!
//! Implements DHCP message construction and parsing as defined in
//! RFC 2131 (DHCP) and RFC 2132 (DHCP Options).  The client builds
//! DHCPDISCOVER and DHCPREQUEST packets, parses DHCPOFFER, DHCPACK,
//! and DHCPNAK responses, and tracks lease state.
//!
//! Transport is the caller's responsibility: the client produces raw
//! DHCP payloads suitable for encapsulation in UDP datagrams
//! (port 68 -> port 67).

use oncrix_lib::{Error, Result};

// =========================================================================
// Constants
// =========================================================================

/// UDP port used by DHCP servers.
pub const DHCP_SERVER_PORT: u16 = 67;

/// UDP port used by DHCP clients.
pub const DHCP_CLIENT_PORT: u16 = 68;

/// DHCP magic cookie (RFC 2131 section 3).
pub const DHCP_MAGIC_COOKIE: [u8; 4] = [99, 130, 83, 99];

/// DHCP message type: DHCPDISCOVER.
pub const DHCPDISCOVER: u8 = 1;

/// DHCP message type: DHCPOFFER.
pub const DHCPOFFER: u8 = 2;

/// DHCP message type: DHCPREQUEST.
pub const DHCPREQUEST: u8 = 3;

/// DHCP message type: DHCPACK.
pub const DHCPACK: u8 = 5;

/// DHCP message type: DHCPNAK.
pub const DHCPNAK: u8 = 6;

/// DHCP message type: DHCPRELEASE.
pub const DHCPRELEASE: u8 = 7;

/// DHCP option: subnet mask.
pub const OPT_SUBNET_MASK: u8 = 1;

/// DHCP option: router (default gateway).
pub const OPT_ROUTER: u8 = 3;

/// DHCP option: DNS server.
pub const OPT_DNS: u8 = 6;

/// DHCP option: requested IP address.
pub const OPT_REQUESTED_IP: u8 = 50;

/// DHCP option: IP address lease time.
pub const OPT_LEASE_TIME: u8 = 51;

/// DHCP option: DHCP message type.
pub const OPT_MSG_TYPE: u8 = 53;

/// DHCP option: server identifier.
pub const OPT_SERVER_ID: u8 = 54;

/// DHCP option: end of options.
pub const OPT_END: u8 = 255;

/// DHCP option: padding.
pub const OPT_PAD: u8 = 0;

/// BOOTP request operation code.
const BOOTREQUEST: u8 = 1;

/// BOOTP reply operation code.
const BOOTREPLY: u8 = 2;

/// Hardware type: Ethernet (10 Mb).
const HTYPE_ETHERNET: u8 = 1;

/// Ethernet hardware address length.
const HLEN_ETHERNET: u8 = 6;

/// Fixed DHCP header size in bytes (excluding options).
///
/// op(1) + htype(1) + hlen(1) + hops(1) + xid(4) + secs(2) +
/// flags(2) + ciaddr(4) + yiaddr(4) + siaddr(4) + giaddr(4) +
/// chaddr(16) + sname(64) + file(128) = 236
const DHCP_HEADER_LEN: usize = 236;

/// Broadcast flag (bit 15 of the flags field).
const DHCP_FLAG_BROADCAST: u16 = 0x8000;

// =========================================================================
// DhcpHeader
// =========================================================================

/// DHCP/BOOTP message header (RFC 2131 section 2).
///
/// The fixed portion of every DHCP message, excluding the
/// variable-length options field.  Fields are stored in host byte
/// order after parsing; serialisation converts back to network
/// byte order.
#[derive(Clone, Copy)]
#[repr(C)]
pub struct DhcpHeader {
    /// Message op code: 1 = BOOTREQUEST, 2 = BOOTREPLY.
    pub op: u8,
    /// Hardware address type (1 = Ethernet).
    pub htype: u8,
    /// Hardware address length (6 for Ethernet).
    pub hlen: u8,
    /// Relay agent hops.
    pub hops: u8,
    /// Transaction ID chosen by the client.
    pub xid: u32,
    /// Seconds elapsed since the client started the process.
    pub secs: u16,
    /// Flags (bit 15 = broadcast).
    pub flags: u16,
    /// Client IP address (filled if client is in BOUND state).
    pub ciaddr: [u8; 4],
    /// "Your" (client) IP address offered by the server.
    pub yiaddr: [u8; 4],
    /// Server IP address.
    pub siaddr: [u8; 4],
    /// Relay agent IP address.
    pub giaddr: [u8; 4],
    /// Client hardware address (padded to 16 bytes).
    pub chaddr: [u8; 16],
    /// Optional server host name.
    pub sname: [u8; 64],
    /// Boot file name.
    pub file: [u8; 128],
}

impl Default for DhcpHeader {
    fn default() -> Self {
        Self {
            op: 0,
            htype: 0,
            hlen: 0,
            hops: 0,
            xid: 0,
            secs: 0,
            flags: 0,
            ciaddr: [0; 4],
            yiaddr: [0; 4],
            siaddr: [0; 4],
            giaddr: [0; 4],
            chaddr: [0; 16],
            sname: [0; 64],
            file: [0; 128],
        }
    }
}

// =========================================================================
// DhcpState
// =========================================================================

/// DHCP client state machine states (RFC 2131 section 4.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DhcpState {
    /// Initial state; no lease, no outstanding requests.
    Init,
    /// DHCPDISCOVER sent; waiting for DHCPOFFER.
    Selecting,
    /// DHCPREQUEST sent; waiting for DHCPACK.
    Requesting,
    /// Lease obtained and active.
    Bound,
    /// Lease renewal in progress (T1 expired).
    Renewing,
    /// Lease rebinding in progress (T2 expired).
    Rebinding,
}

// =========================================================================
// DhcpLease
// =========================================================================

/// Active DHCP lease information.
///
/// Stores the assigned network parameters and timing data needed
/// to determine when the lease expires.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DhcpLease {
    /// Assigned client IPv4 address.
    pub client_ip: [u8; 4],
    /// DHCP server that granted the lease.
    pub server_ip: [u8; 4],
    /// Subnet mask for the assigned address.
    pub subnet_mask: [u8; 4],
    /// Default gateway IPv4 address.
    pub gateway: [u8; 4],
    /// DNS server IPv4 address.
    pub dns_server: [u8; 4],
    /// Lease duration in seconds.
    pub lease_time_secs: u32,
    /// Tick count when the lease was obtained.
    pub start_tick: u64,
}

// =========================================================================
// DhcpOptions
// =========================================================================

/// Parsed DHCP options extracted from a DHCP message.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DhcpOptions {
    /// DHCP message type (option 53).
    pub msg_type: u8,
    /// Subnet mask (option 1).
    pub subnet_mask: [u8; 4],
    /// Router / default gateway (option 3).
    pub router: [u8; 4],
    /// DNS server (option 6).
    pub dns: [u8; 4],
    /// Server identifier (option 54).
    pub server_id: [u8; 4],
    /// IP address lease time in seconds (option 51).
    pub lease_time: u32,
    /// Requested IP address (option 50).
    pub requested_ip: [u8; 4],
}

// =========================================================================
// DhcpEvent
// =========================================================================

/// Events produced by parsing DHCP server responses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DhcpEvent {
    /// A DHCPOFFER was received from a server.
    Offer {
        /// DHCP server IP address.
        server_ip: [u8; 4],
        /// IP address offered to the client.
        offered_ip: [u8; 4],
        /// Subnet mask.
        subnet: [u8; 4],
        /// Default gateway.
        gateway: [u8; 4],
        /// DNS server.
        dns: [u8; 4],
        /// Lease time in seconds.
        lease_time: u32,
    },
    /// A DHCPACK was received; the lease is confirmed.
    Ack {
        /// The confirmed lease.
        lease: DhcpLease,
    },
    /// A DHCPNAK was received; the request was rejected.
    Nak,
}

// =========================================================================
// parse_dhcp_options
// =========================================================================

/// Parse DHCP options from the data following the magic cookie.
///
/// Iterates over the TLV-encoded option list and extracts known
/// options into a [`DhcpOptions`] structure.  Unknown options are
/// silently skipped.
///
/// # Errors
///
/// Returns [`Error::InvalidArgument`] if the options data is
/// truncated or an option's declared length exceeds the remaining
/// data.
pub fn parse_dhcp_options(data: &[u8]) -> Result<DhcpOptions> {
    let mut opts = DhcpOptions::default();
    let mut pos: usize = 0;

    while pos < data.len() {
        let code = data[pos];

        if code == OPT_END {
            break;
        }

        if code == OPT_PAD {
            pos = pos.saturating_add(1);
            continue;
        }

        // TLV: code(1) + len(1) + value(len).
        pos = pos.saturating_add(1);
        if pos >= data.len() {
            return Err(Error::InvalidArgument);
        }
        let opt_len = data[pos] as usize;
        pos = pos.saturating_add(1);

        if pos.saturating_add(opt_len) > data.len() {
            return Err(Error::InvalidArgument);
        }

        match code {
            OPT_MSG_TYPE if opt_len >= 1 => {
                opts.msg_type = data[pos];
            }
            OPT_SUBNET_MASK if opt_len >= 4 => {
                opts.subnet_mask
                    .copy_from_slice(&data[pos..pos.saturating_add(4)]);
            }
            OPT_ROUTER if opt_len >= 4 => {
                opts.router
                    .copy_from_slice(&data[pos..pos.saturating_add(4)]);
            }
            OPT_DNS if opt_len >= 4 => {
                opts.dns.copy_from_slice(&data[pos..pos.saturating_add(4)]);
            }
            OPT_REQUESTED_IP if opt_len >= 4 => {
                opts.requested_ip
                    .copy_from_slice(&data[pos..pos.saturating_add(4)]);
            }
            OPT_LEASE_TIME if opt_len >= 4 => {
                opts.lease_time = u32::from_be_bytes([
                    data[pos],
                    data[pos.saturating_add(1)],
                    data[pos.saturating_add(2)],
                    data[pos.saturating_add(3)],
                ]);
            }
            OPT_SERVER_ID if opt_len >= 4 => {
                opts.server_id
                    .copy_from_slice(&data[pos..pos.saturating_add(4)]);
            }
            _ => { /* skip unknown or too-short options */ }
        }

        pos = pos.saturating_add(opt_len);
    }

    Ok(opts)
}

// =========================================================================
// DhcpClient
// =========================================================================

/// Minimal DHCP client.
///
/// Builds DHCP packets and processes server responses.  The caller
/// is responsible for UDP transport (wrapping packets with UDP/IP
/// headers, sending on port 68, and feeding received data back).
pub struct DhcpClient {
    /// Current state of the DHCP state machine.
    pub state: DhcpState,
    /// Client's Ethernet MAC address.
    pub mac: [u8; 6],
    /// Transaction identifier for the current exchange.
    pub xid: u32,
    /// Active lease, if any.
    pub lease: Option<DhcpLease>,
}

impl DhcpClient {
    /// Create a new DHCP client with the given MAC address and
    /// transaction ID.
    pub const fn new(mac: [u8; 6], xid: u32) -> Self {
        Self {
            state: DhcpState::Init,
            mac,
            xid,
            lease: None,
        }
    }

    /// Build a DHCPDISCOVER packet into `buf`.
    ///
    /// Constructs a broadcast DHCPDISCOVER message containing the
    /// client's MAC address and a message-type option.  Returns the
    /// total number of bytes written.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `buf` is too small to
    /// hold the DHCP header, magic cookie, and options (minimum 244
    /// bytes).
    pub fn build_discover(&self, buf: &mut [u8]) -> Result<usize> {
        // Header(236) + cookie(4) + msg_type option(3) + end(1)
        let min_len = DHCP_HEADER_LEN
            .saturating_add(4)
            .saturating_add(3)
            .saturating_add(1);
        if buf.len() < min_len {
            return Err(Error::InvalidArgument);
        }

        let mut pos = write_header(buf, self.xid, &self.mac)?;

        // Magic cookie.
        buf[pos..pos.saturating_add(4)].copy_from_slice(&DHCP_MAGIC_COOKIE);
        pos = pos.saturating_add(4);

        // Option 53: DHCP Message Type = DHCPDISCOVER.
        pos = write_option_u8(buf, pos, OPT_MSG_TYPE, DHCPDISCOVER)?;

        // End option.
        if pos >= buf.len() {
            return Err(Error::InvalidArgument);
        }
        buf[pos] = OPT_END;
        pos = pos.saturating_add(1);

        Ok(pos)
    }

    /// Build a DHCPREQUEST packet into `buf`.
    ///
    /// Constructs a DHCPREQUEST message that selects the offered IP
    /// address from the specified server.  Returns the total number
    /// of bytes written.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `buf` is too small to
    /// hold the header, magic cookie, and all required options.
    pub fn build_request(
        &self,
        server_ip: [u8; 4],
        offered_ip: [u8; 4],
        buf: &mut [u8],
    ) -> Result<usize> {
        // Header(236) + cookie(4) + msg_type(3) +
        // requested_ip(6) + server_id(6) + end(1) = 256
        let min_len = DHCP_HEADER_LEN
            .saturating_add(4)
            .saturating_add(3)
            .saturating_add(6)
            .saturating_add(6)
            .saturating_add(1);
        if buf.len() < min_len {
            return Err(Error::InvalidArgument);
        }

        let mut pos = write_header(buf, self.xid, &self.mac)?;

        // Magic cookie.
        buf[pos..pos.saturating_add(4)].copy_from_slice(&DHCP_MAGIC_COOKIE);
        pos = pos.saturating_add(4);

        // Option 53: DHCP Message Type = DHCPREQUEST.
        pos = write_option_u8(buf, pos, OPT_MSG_TYPE, DHCPREQUEST)?;

        // Option 50: Requested IP Address.
        pos = write_option_ip(buf, pos, OPT_REQUESTED_IP, &offered_ip)?;

        // Option 54: Server Identifier.
        pos = write_option_ip(buf, pos, OPT_SERVER_ID, &server_ip)?;

        // End option.
        if pos >= buf.len() {
            return Err(Error::InvalidArgument);
        }
        buf[pos] = OPT_END;
        pos = pos.saturating_add(1);

        Ok(pos)
    }

    /// Process a DHCP server response.
    ///
    /// Parses the DHCP header and options from `data` and returns
    /// the corresponding [`DhcpEvent`].  Ignores messages whose
    /// transaction ID does not match the client's `xid`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `data` is too short to
    /// contain a valid DHCP message (header + magic cookie), or if
    /// the options are malformed.
    pub fn process_response(&self, data: &[u8]) -> Result<DhcpEvent> {
        let cookie_end = DHCP_HEADER_LEN.saturating_add(4);
        if data.len() < cookie_end {
            return Err(Error::InvalidArgument);
        }

        // Verify operation is BOOTREPLY.
        if data[0] != BOOTREPLY {
            return Err(Error::InvalidArgument);
        }

        // Verify transaction ID.
        let xid = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
        if xid != self.xid {
            return Err(Error::InvalidArgument);
        }

        // Verify magic cookie.
        if data[DHCP_HEADER_LEN..cookie_end] != DHCP_MAGIC_COOKIE {
            return Err(Error::InvalidArgument);
        }

        // Extract yiaddr (offered IP) and siaddr (server IP).
        let mut yiaddr = [0u8; 4];
        yiaddr.copy_from_slice(&data[16..20]);
        let mut siaddr = [0u8; 4];
        siaddr.copy_from_slice(&data[20..24]);

        // Parse options.
        let opts = parse_dhcp_options(&data[cookie_end..])?;

        // Prefer server_id from options; fall back to siaddr.
        let server_ip = if opts.server_id != [0; 4] {
            opts.server_id
        } else {
            siaddr
        };

        match opts.msg_type {
            DHCPOFFER => Ok(DhcpEvent::Offer {
                server_ip,
                offered_ip: yiaddr,
                subnet: opts.subnet_mask,
                gateway: opts.router,
                dns: opts.dns,
                lease_time: opts.lease_time,
            }),
            DHCPACK => Ok(DhcpEvent::Ack {
                lease: DhcpLease {
                    client_ip: yiaddr,
                    server_ip,
                    subnet_mask: opts.subnet_mask,
                    gateway: opts.router,
                    dns_server: opts.dns,
                    lease_time_secs: opts.lease_time,
                    start_tick: 0,
                },
            }),
            DHCPNAK => Ok(DhcpEvent::Nak),
            _ => Err(Error::InvalidArgument),
        }
    }

    /// Check whether the current lease has expired.
    ///
    /// Returns `true` if no lease is held or if the elapsed time
    /// since `start_tick` exceeds the lease duration.  The caller
    /// must provide a consistent `ticks_per_sec` so that the lease
    /// time (in seconds) can be converted to tick units.
    pub fn is_lease_expired(&self, current_tick: u64, ticks_per_sec: u64) -> bool {
        match self.lease {
            None => true,
            Some(ref lease) => {
                let elapsed = current_tick.saturating_sub(lease.start_tick);
                let lease_ticks = (lease.lease_time_secs as u64).saturating_mul(ticks_per_sec);
                elapsed >= lease_ticks
            }
        }
    }
}

// =========================================================================
// Internal helpers
// =========================================================================

/// Write the fixed 236-byte DHCP header into `buf`.
///
/// Sets op=BOOTREQUEST, htype=Ethernet, hlen=6, broadcast flag,
/// and the client's MAC in chaddr.  Returns the position after
/// the header (236).
fn write_header(buf: &mut [u8], xid: u32, mac: &[u8; 6]) -> Result<usize> {
    if buf.len() < DHCP_HEADER_LEN {
        return Err(Error::InvalidArgument);
    }

    // Zero the entire header region first.
    let mut i: usize = 0;
    while i < DHCP_HEADER_LEN {
        buf[i] = 0;
        i = i.saturating_add(1);
    }

    buf[0] = BOOTREQUEST;
    buf[1] = HTYPE_ETHERNET;
    buf[2] = HLEN_ETHERNET;
    // hops = 0 (already zeroed).

    let xid_bytes = xid.to_be_bytes();
    buf[4] = xid_bytes[0];
    buf[5] = xid_bytes[1];
    buf[6] = xid_bytes[2];
    buf[7] = xid_bytes[3];

    // secs = 0 (already zeroed).

    // flags: broadcast.
    let flags = DHCP_FLAG_BROADCAST.to_be_bytes();
    buf[10] = flags[0];
    buf[11] = flags[1];

    // ciaddr, yiaddr, siaddr, giaddr = 0 (already zeroed).

    // chaddr: MAC address in first 6 bytes, rest zeroed.
    buf[28..34].copy_from_slice(mac);

    Ok(DHCP_HEADER_LEN)
}

/// Write a single-byte DHCP option (code + len=1 + value).
///
/// Returns the new position after the option.
fn write_option_u8(buf: &mut [u8], pos: usize, code: u8, value: u8) -> Result<usize> {
    if pos.saturating_add(3) > buf.len() {
        return Err(Error::InvalidArgument);
    }
    buf[pos] = code;
    buf[pos.saturating_add(1)] = 1;
    buf[pos.saturating_add(2)] = value;
    Ok(pos.saturating_add(3))
}

/// Write a 4-byte IP address DHCP option (code + len=4 + addr).
///
/// Returns the new position after the option.
fn write_option_ip(buf: &mut [u8], pos: usize, code: u8, ip: &[u8; 4]) -> Result<usize> {
    if pos.saturating_add(6) > buf.len() {
        return Err(Error::InvalidArgument);
    }
    buf[pos] = code;
    buf[pos.saturating_add(1)] = 4;
    buf[pos.saturating_add(2)..pos.saturating_add(6)].copy_from_slice(ip);
    Ok(pos.saturating_add(6))
}

// =========================================================================
// Tests
// =========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_discover() {
        let mac = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
        let client = DhcpClient::new(mac, 0xDEADBEEF);
        let mut buf = [0u8; 512];
        let len = client.build_discover(&mut buf).unwrap();

        // Verify BOOTREQUEST.
        assert_eq!(buf[0], BOOTREQUEST);
        // Verify htype/hlen.
        assert_eq!(buf[1], HTYPE_ETHERNET);
        assert_eq!(buf[2], HLEN_ETHERNET);
        // Verify xid.
        assert_eq!(&buf[4..8], &0xDEADBEEFu32.to_be_bytes());
        // Verify broadcast flag.
        assert_eq!(&buf[10..12], &DHCP_FLAG_BROADCAST.to_be_bytes());
        // Verify MAC in chaddr.
        assert_eq!(&buf[28..34], &mac);
        // Verify magic cookie.
        assert_eq!(
            &buf[DHCP_HEADER_LEN..DHCP_HEADER_LEN + 4],
            &DHCP_MAGIC_COOKIE
        );
        // Verify message type option.
        let opt_start = DHCP_HEADER_LEN + 4;
        assert_eq!(buf[opt_start], OPT_MSG_TYPE);
        assert_eq!(buf[opt_start + 1], 1);
        assert_eq!(buf[opt_start + 2], DHCPDISCOVER);
        // Verify end option.
        assert_eq!(buf[opt_start + 3], OPT_END);
        // Total length check.
        assert_eq!(len, opt_start + 4);
    }

    #[test]
    fn test_build_request() {
        let mac = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
        let client = DhcpClient::new(mac, 0x12345678);
        let server_ip = [192, 168, 1, 1];
        let offered_ip = [192, 168, 1, 100];
        let mut buf = [0u8; 512];
        let len = client
            .build_request(server_ip, offered_ip, &mut buf)
            .unwrap();

        assert_eq!(buf[0], BOOTREQUEST);
        // Verify magic cookie.
        assert_eq!(
            &buf[DHCP_HEADER_LEN..DHCP_HEADER_LEN + 4],
            &DHCP_MAGIC_COOKIE
        );

        // Parse the options to verify.
        let opts = parse_dhcp_options(&buf[DHCP_HEADER_LEN + 4..len]).unwrap();
        assert_eq!(opts.msg_type, DHCPREQUEST);
        assert_eq!(opts.requested_ip, offered_ip);
        assert_eq!(opts.server_id, server_ip);
    }

    #[test]
    fn test_build_discover_buf_too_small() {
        let client = DhcpClient::new([0; 6], 1);
        let mut buf = [0u8; 10];
        assert!(client.build_discover(&mut buf).is_err());
    }

    #[test]
    fn test_build_request_buf_too_small() {
        let client = DhcpClient::new([0; 6], 1);
        let mut buf = [0u8; 10];
        assert!(client.build_request([0; 4], [0; 4], &mut buf).is_err());
    }

    #[test]
    fn test_parse_dhcp_options_basic() {
        #[rustfmt::skip]
        let data: [u8; 20] = [
            OPT_MSG_TYPE, 1, DHCPOFFER,
            OPT_SUBNET_MASK, 4, 255, 255, 255, 0,
            OPT_ROUTER, 4, 192, 168, 1, 1,
            OPT_LEASE_TIME, 4, 0, 0, 0x0E, 0x10, // 3600
            OPT_END,
        ];

        let opts = parse_dhcp_options(&data).unwrap();
        assert_eq!(opts.msg_type, DHCPOFFER);
        assert_eq!(opts.subnet_mask, [255, 255, 255, 0]);
        assert_eq!(opts.router, [192, 168, 1, 1]);
        assert_eq!(opts.lease_time, 3600);
    }

    #[test]
    fn test_parse_dhcp_options_with_pad() {
        #[rustfmt::skip]
        let data: [u8; 5] = [
            OPT_PAD,
            OPT_MSG_TYPE, 1, DHCPACK,
            OPT_END,
        ];
        let opts = parse_dhcp_options(&data).unwrap();
        assert_eq!(opts.msg_type, DHCPACK);
    }

    #[test]
    fn test_parse_dhcp_options_truncated() {
        // Length says 4 bytes but only 2 available.
        let data: [u8; 4] = [OPT_SUBNET_MASK, 4, 255, 255];
        assert!(parse_dhcp_options(&data).is_err());
    }

    #[test]
    fn test_parse_dhcp_options_unknown_skipped() {
        // Unknown option code 200, length 2, then end.
        #[rustfmt::skip]
        let data: [u8; 8] = [
            200, 2, 0xAA, 0xBB,
            OPT_MSG_TYPE, 1, DHCPDISCOVER,
            OPT_END,
        ];
        let opts = parse_dhcp_options(&data).unwrap();
        assert_eq!(opts.msg_type, DHCPDISCOVER);
    }

    #[test]
    fn test_process_response_offer() {
        let mac = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
        let xid: u32 = 0xAABBCCDD;
        let client = DhcpClient::new(mac, xid);

        let mut pkt = [0u8; 300];
        // op = BOOTREPLY.
        pkt[0] = BOOTREPLY;
        pkt[1] = HTYPE_ETHERNET;
        pkt[2] = HLEN_ETHERNET;
        // xid.
        let xid_bytes = xid.to_be_bytes();
        pkt[4..8].copy_from_slice(&xid_bytes);
        // yiaddr = 192.168.1.100.
        pkt[16..20].copy_from_slice(&[192, 168, 1, 100]);
        // siaddr = 192.168.1.1.
        pkt[20..24].copy_from_slice(&[192, 168, 1, 1]);
        // Magic cookie.
        pkt[DHCP_HEADER_LEN..DHCP_HEADER_LEN + 4].copy_from_slice(&DHCP_MAGIC_COOKIE);
        // Options.
        let opt_start = DHCP_HEADER_LEN + 4;
        pkt[opt_start] = OPT_MSG_TYPE;
        pkt[opt_start + 1] = 1;
        pkt[opt_start + 2] = DHCPOFFER;
        pkt[opt_start + 3] = OPT_SUBNET_MASK;
        pkt[opt_start + 4] = 4;
        pkt[opt_start + 5..opt_start + 9].copy_from_slice(&[255, 255, 255, 0]);
        pkt[opt_start + 9] = OPT_ROUTER;
        pkt[opt_start + 10] = 4;
        pkt[opt_start + 11..opt_start + 15].copy_from_slice(&[192, 168, 1, 1]);
        pkt[opt_start + 15] = OPT_DNS;
        pkt[opt_start + 16] = 4;
        pkt[opt_start + 17..opt_start + 21].copy_from_slice(&[8, 8, 8, 8]);
        pkt[opt_start + 21] = OPT_LEASE_TIME;
        pkt[opt_start + 22] = 4;
        pkt[opt_start + 23..opt_start + 27].copy_from_slice(&3600u32.to_be_bytes());
        pkt[opt_start + 27] = OPT_END;

        let pkt_len = opt_start + 28;
        let event = client.process_response(&pkt[..pkt_len]).unwrap();

        match event {
            DhcpEvent::Offer {
                server_ip,
                offered_ip,
                subnet,
                gateway,
                dns,
                lease_time,
            } => {
                assert_eq!(server_ip, [192, 168, 1, 1]);
                assert_eq!(offered_ip, [192, 168, 1, 100]);
                assert_eq!(subnet, [255, 255, 255, 0]);
                assert_eq!(gateway, [192, 168, 1, 1]);
                assert_eq!(dns, [8, 8, 8, 8]);
                assert_eq!(lease_time, 3600);
            }
            _ => panic!("expected DhcpEvent::Offer"),
        }
    }

    #[test]
    fn test_process_response_ack() {
        let mac = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
        let xid: u32 = 0x11223344;
        let client = DhcpClient::new(mac, xid);

        let mut pkt = [0u8; 260];
        pkt[0] = BOOTREPLY;
        pkt[1] = HTYPE_ETHERNET;
        pkt[2] = HLEN_ETHERNET;
        pkt[4..8].copy_from_slice(&xid.to_be_bytes());
        pkt[16..20].copy_from_slice(&[10, 0, 0, 50]);

        pkt[DHCP_HEADER_LEN..DHCP_HEADER_LEN + 4].copy_from_slice(&DHCP_MAGIC_COOKIE);
        let opt = DHCP_HEADER_LEN + 4;
        pkt[opt] = OPT_MSG_TYPE;
        pkt[opt + 1] = 1;
        pkt[opt + 2] = DHCPACK;
        pkt[opt + 3] = OPT_SUBNET_MASK;
        pkt[opt + 4] = 4;
        pkt[opt + 5..opt + 9].copy_from_slice(&[255, 255, 0, 0]);
        pkt[opt + 9] = OPT_LEASE_TIME;
        pkt[opt + 10] = 4;
        pkt[opt + 11..opt + 15].copy_from_slice(&7200u32.to_be_bytes());
        pkt[opt + 15] = OPT_END;

        let event = client.process_response(&pkt[..opt + 16]).unwrap();

        match event {
            DhcpEvent::Ack { lease } => {
                assert_eq!(lease.client_ip, [10, 0, 0, 50]);
                assert_eq!(lease.subnet_mask, [255, 255, 0, 0]);
                assert_eq!(lease.lease_time_secs, 7200);
            }
            _ => panic!("expected DhcpEvent::Ack"),
        }
    }

    #[test]
    fn test_process_response_nak() {
        let mac = [0; 6];
        let xid: u32 = 0x55667788;
        let client = DhcpClient::new(mac, xid);

        let mut pkt = [0u8; 250];
        pkt[0] = BOOTREPLY;
        pkt[4..8].copy_from_slice(&xid.to_be_bytes());
        pkt[DHCP_HEADER_LEN..DHCP_HEADER_LEN + 4].copy_from_slice(&DHCP_MAGIC_COOKIE);
        let opt = DHCP_HEADER_LEN + 4;
        pkt[opt] = OPT_MSG_TYPE;
        pkt[opt + 1] = 1;
        pkt[opt + 2] = DHCPNAK;
        pkt[opt + 3] = OPT_END;

        let event = client.process_response(&pkt[..opt + 4]).unwrap();
        assert_eq!(event, DhcpEvent::Nak);
    }

    #[test]
    fn test_process_response_wrong_xid() {
        let client = DhcpClient::new([0; 6], 0x1111);
        let mut pkt = [0u8; 250];
        pkt[0] = BOOTREPLY;
        // Different xid.
        pkt[4..8].copy_from_slice(&0x2222u32.to_be_bytes());
        pkt[DHCP_HEADER_LEN..DHCP_HEADER_LEN + 4].copy_from_slice(&DHCP_MAGIC_COOKIE);

        assert!(client.process_response(&pkt[..244]).is_err());
    }

    #[test]
    fn test_process_response_too_short() {
        let client = DhcpClient::new([0; 6], 1);
        let pkt = [0u8; 100];
        assert!(client.process_response(&pkt).is_err());
    }

    #[test]
    fn test_is_lease_expired_no_lease() {
        let client = DhcpClient::new([0; 6], 1);
        assert!(client.is_lease_expired(0, 1000));
    }

    #[test]
    fn test_is_lease_expired_active() {
        let mut client = DhcpClient::new([0; 6], 1);
        client.lease = Some(DhcpLease {
            client_ip: [10, 0, 0, 1],
            server_ip: [10, 0, 0, 254],
            subnet_mask: [255, 255, 255, 0],
            gateway: [10, 0, 0, 254],
            dns_server: [8, 8, 8, 8],
            lease_time_secs: 3600,
            start_tick: 1000,
        });

        // 1000 ticks/sec, lease=3600s -> expires at tick
        // 1000 + 3_600_000.
        let tps: u64 = 1000;
        assert!(!client.is_lease_expired(1000, tps));
        assert!(!client.is_lease_expired(3_600_999, tps));
        assert!(client.is_lease_expired(3_601_000, tps));
        assert!(client.is_lease_expired(5_000_000, tps));
    }

    #[test]
    fn test_dhcp_state_enum() {
        let s = DhcpState::Init;
        assert_eq!(s, DhcpState::Init);
        assert_ne!(s, DhcpState::Bound);
    }

    #[test]
    fn test_dhcp_header_default() {
        let hdr = DhcpHeader::default();
        assert_eq!(hdr.op, 0);
        assert_eq!(hdr.xid, 0);
        assert_eq!(hdr.chaddr, [0; 16]);
    }

    #[test]
    fn test_roundtrip_discover_parse() {
        let mac = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
        let client = DhcpClient::new(mac, 0x42424242);
        let mut buf = [0u8; 512];
        let len = client.build_discover(&mut buf).unwrap();

        // Verify the options can be parsed back.
        let opts = parse_dhcp_options(&buf[DHCP_HEADER_LEN + 4..len]).unwrap();
        assert_eq!(opts.msg_type, DHCPDISCOVER);
    }
}
