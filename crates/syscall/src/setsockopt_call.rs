// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `setsockopt(2)` syscall handler.
//!
//! Sets options on a socket.  Options are organised by `level`:
//! - `SOL_SOCKET`  — generic socket-layer options (SO_REUSEPORT, SO_KEEPALIVE…)
//! - `IPPROTO_TCP` — TCP-specific options (TCP_NODELAY, TCP_KEEPIDLE…)
//! - `IPPROTO_IP`  — IPv4-specific options (IP_TTL…)
//! - `IPPROTO_IPV6`— IPv6-specific options
//!
//! # POSIX Conformance
//!
//! Follows POSIX.1-2024 `setsockopt()` specification.  Key behaviours:
//! - `ENOPROTOOPT` for unrecognised `optname`.
//! - `EINVAL` for invalid `optlen` (too small for the expected value type).
//! - `ENOTSOCK` for non-socket file descriptors (handled by caller).
//!
//! # References
//!
//! - POSIX.1-2024: `setsockopt()`
//! - Linux man pages: `setsockopt(2)`, `socket(7)`, `tcp(7)`, `ip(7)`

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Level constants
// ---------------------------------------------------------------------------

/// Socket-level options.
pub const SOL_SOCKET: i32 = 1;
/// TCP protocol options.
pub const IPPROTO_TCP: i32 = 6;
/// IPv4 protocol options.
pub const IPPROTO_IP: i32 = 0;
/// IPv6 protocol options.
pub const IPPROTO_IPV6: i32 = 41;

// ---------------------------------------------------------------------------
// SOL_SOCKET option names
// ---------------------------------------------------------------------------

/// Allow reuse of local addresses.
pub const SO_REUSEADDR: i32 = 2;
/// Enable/disable periodic keep-alive probes.
pub const SO_KEEPALIVE: i32 = 9;
/// Enable/disable broadcast.
pub const SO_BROADCAST: i32 = 6;
/// Enable/disable receive of out-of-band data inline.
pub const SO_OOBINLINE: i32 = 10;
/// Receive buffer size.
pub const SO_RCVBUF: i32 = 8;
/// Send buffer size.
pub const SO_SNDBUF: i32 = 7;
/// Allow multiple sockets to bind to the same port.
pub const SO_REUSEPORT: i32 = 15;

// ---------------------------------------------------------------------------
// IPPROTO_TCP option names
// ---------------------------------------------------------------------------

/// Disable Nagle's algorithm (send small packets immediately).
pub const TCP_NODELAY: i32 = 1;
/// Maximum segment size.
pub const TCP_MAXSEG: i32 = 2;
/// TCP keep-alive idle time (seconds before first probe).
pub const TCP_KEEPIDLE: i32 = 4;
/// TCP keep-alive interval between probes (seconds).
pub const TCP_KEEPINTVL: i32 = 5;
/// TCP keep-alive number of probes before dropping the connection.
pub const TCP_KEEPCNT: i32 = 6;
/// Connection timeout (seconds).
pub const TCP_USER_TIMEOUT: i32 = 18;

// ---------------------------------------------------------------------------
// IPPROTO_IP option names
// ---------------------------------------------------------------------------

/// Time-to-live for outgoing unicast packets.
pub const IP_TTL: i32 = 2;
/// Type of service field.
pub const IP_TOS: i32 = 1;

// ---------------------------------------------------------------------------
// IPPROTO_IPV6 option names
// ---------------------------------------------------------------------------

/// Hop limit for outgoing packets (analogue of IP_TTL for IPv6).
pub const IPV6_UNICAST_HOPS: i32 = 16;

// ---------------------------------------------------------------------------
// Socket option store
// ---------------------------------------------------------------------------

/// Collects all socket options that can be set via `setsockopt`.
#[derive(Debug, Clone, Copy)]
pub struct SocketOptions {
    // SOL_SOCKET
    /// SO_REUSEADDR
    pub reuseaddr: bool,
    /// SO_REUSEPORT
    pub reuseport: bool,
    /// SO_KEEPALIVE
    pub keepalive: bool,
    /// SO_BROADCAST
    pub broadcast: bool,
    /// SO_OOBINLINE
    pub oobinline: bool,
    /// SO_RCVBUF (bytes)
    pub rcvbuf: u32,
    /// SO_SNDBUF (bytes)
    pub sndbuf: u32,

    // IPPROTO_TCP
    /// TCP_NODELAY
    pub tcp_nodelay: bool,
    /// TCP_MAXSEG
    pub tcp_maxseg: u32,
    /// TCP_KEEPIDLE (seconds)
    pub tcp_keepidle: u32,
    /// TCP_KEEPINTVL (seconds)
    pub tcp_keepintvl: u32,
    /// TCP_KEEPCNT
    pub tcp_keepcnt: u32,
    /// TCP_USER_TIMEOUT (milliseconds)
    pub tcp_user_timeout: u32,

    // IPPROTO_IP
    /// IP_TTL
    pub ip_ttl: u8,
    /// IP_TOS
    pub ip_tos: u8,

    // IPPROTO_IPV6
    /// IPV6_UNICAST_HOPS
    pub ipv6_unicast_hops: u8,
}

impl Default for SocketOptions {
    fn default() -> Self {
        Self {
            reuseaddr: false,
            reuseport: false,
            keepalive: false,
            broadcast: false,
            oobinline: false,
            rcvbuf: 87380,
            sndbuf: 16384,
            tcp_nodelay: false,
            tcp_maxseg: 536,
            tcp_keepidle: 7200,
            tcp_keepintvl: 75,
            tcp_keepcnt: 9,
            tcp_user_timeout: 0,
            ip_ttl: 64,
            ip_tos: 0,
            ipv6_unicast_hops: 64,
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Interpret `optval` as an `i32` (requires at least 4 bytes).
fn read_i32(optval: &[u8]) -> Result<i32> {
    if optval.len() < 4 {
        return Err(Error::InvalidArgument);
    }
    let arr: [u8; 4] = [optval[0], optval[1], optval[2], optval[3]];
    Ok(i32::from_ne_bytes(arr))
}

/// Interpret `optval` as a boolean (non-zero i32 = true).
fn read_bool(optval: &[u8]) -> Result<bool> {
    Ok(read_i32(optval)? != 0)
}

/// Interpret `optval` as a `u32`.
fn read_u32(optval: &[u8]) -> Result<u32> {
    read_i32(optval).map(|v| v as u32)
}

// ---------------------------------------------------------------------------
// Core handler
// ---------------------------------------------------------------------------

/// Handler for `setsockopt(2)`.
///
/// Applies the option to `opts`.  The caller has already validated that `fd`
/// refers to a socket.
///
/// # Errors
///
/// | `Error`      | Condition                                      |
/// |--------------|------------------------------------------------|
/// | `InvalidArg` | `optval` too short for the option type (`EINVAL`)|
/// | `NotFound`   | Unrecognised `level`/`optname` (`ENOPROTOOPT`) |
pub fn do_setsockopt(
    opts: &mut SocketOptions,
    level: i32,
    optname: i32,
    optval: &[u8],
) -> Result<()> {
    match level {
        SOL_SOCKET => match optname {
            SO_REUSEADDR => opts.reuseaddr = read_bool(optval)?,
            SO_REUSEPORT => opts.reuseport = read_bool(optval)?,
            SO_KEEPALIVE => opts.keepalive = read_bool(optval)?,
            SO_BROADCAST => opts.broadcast = read_bool(optval)?,
            SO_OOBINLINE => opts.oobinline = read_bool(optval)?,
            SO_RCVBUF => opts.rcvbuf = read_u32(optval)?,
            SO_SNDBUF => opts.sndbuf = read_u32(optval)?,
            _ => return Err(Error::NotFound),
        },
        IPPROTO_TCP => match optname {
            TCP_NODELAY => opts.tcp_nodelay = read_bool(optval)?,
            TCP_MAXSEG => opts.tcp_maxseg = read_u32(optval)?,
            TCP_KEEPIDLE => opts.tcp_keepidle = read_u32(optval)?,
            TCP_KEEPINTVL => opts.tcp_keepintvl = read_u32(optval)?,
            TCP_KEEPCNT => opts.tcp_keepcnt = read_u32(optval)?,
            TCP_USER_TIMEOUT => opts.tcp_user_timeout = read_u32(optval)?,
            _ => return Err(Error::NotFound),
        },
        IPPROTO_IP => match optname {
            IP_TTL => {
                let v = read_i32(optval)?;
                if !(1..=255).contains(&v) {
                    return Err(Error::InvalidArgument);
                }
                opts.ip_ttl = v as u8;
            }
            IP_TOS => {
                let v = read_u32(optval)?;
                opts.ip_tos = (v & 0xFF) as u8;
            }
            _ => return Err(Error::NotFound),
        },
        IPPROTO_IPV6 => match optname {
            IPV6_UNICAST_HOPS => {
                let v = read_i32(optval)?;
                if !(-1..=255).contains(&v) {
                    return Err(Error::InvalidArgument);
                }
                opts.ipv6_unicast_hops = if v == -1 { 64 } else { v as u8 };
            }
            _ => return Err(Error::NotFound),
        },
        _ => return Err(Error::NotFound),
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn val(v: i32) -> [u8; 4] {
        v.to_ne_bytes()
    }

    #[test]
    fn tcp_nodelay() {
        let mut o = SocketOptions::default();
        do_setsockopt(&mut o, IPPROTO_TCP, TCP_NODELAY, &val(1)).unwrap();
        assert!(o.tcp_nodelay);
    }

    #[test]
    fn so_reuseport() {
        let mut o = SocketOptions::default();
        do_setsockopt(&mut o, SOL_SOCKET, SO_REUSEPORT, &val(1)).unwrap();
        assert!(o.reuseport);
    }

    #[test]
    fn ip_ttl_range() {
        let mut o = SocketOptions::default();
        assert!(do_setsockopt(&mut o, IPPROTO_IP, IP_TTL, &val(128)).is_ok());
        assert_eq!(o.ip_ttl, 128);
        assert_eq!(
            do_setsockopt(&mut o, IPPROTO_IP, IP_TTL, &val(0)),
            Err(Error::InvalidArgument)
        );
        assert_eq!(
            do_setsockopt(&mut o, IPPROTO_IP, IP_TTL, &val(256)),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn unknown_option_error() {
        let mut o = SocketOptions::default();
        assert_eq!(
            do_setsockopt(&mut o, SOL_SOCKET, 9999, &val(1)),
            Err(Error::NotFound)
        );
    }

    #[test]
    fn short_optval_error() {
        let mut o = SocketOptions::default();
        assert_eq!(
            do_setsockopt(&mut o, SOL_SOCKET, SO_REUSEADDR, &[1u8]),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn tcp_keepidle_keepintvl_keepcnt() {
        let mut o = SocketOptions::default();
        do_setsockopt(&mut o, IPPROTO_TCP, TCP_KEEPIDLE, &val(600)).unwrap();
        do_setsockopt(&mut o, IPPROTO_TCP, TCP_KEEPINTVL, &val(30)).unwrap();
        do_setsockopt(&mut o, IPPROTO_TCP, TCP_KEEPCNT, &val(5)).unwrap();
        assert_eq!(o.tcp_keepidle, 600);
        assert_eq!(o.tcp_keepintvl, 30);
        assert_eq!(o.tcp_keepcnt, 5);
    }
}
