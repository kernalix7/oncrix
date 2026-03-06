// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Socket address validation and parsing helpers.
//!
//! Provides type-safe wrappers for the various `sockaddr` families used
//! across socket syscalls: `bind(2)`, `connect(2)`, `sendto(2)`,
//! `recvfrom(2)`, `getsockname(2)`, `getpeername(2)`.
//!
//! This module does NOT duplicate those syscall entry points; it provides
//! the shared address-validation layer they all call.
//!
//! # POSIX reference
//!
//! POSIX.1-2024 §socket — `<sys/socket.h>`, `<netinet/in.h>`, `<sys/un.h>`.
//!
//! # References
//!
//! - Linux: `net/socket.c` `move_addr_to_kernel()`
//! - `bind(2)` man page

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Address family constants
// ---------------------------------------------------------------------------

/// IPv4 address family.
pub const AF_INET: u16 = 2;
/// IPv6 address family.
pub const AF_INET6: u16 = 10;
/// Unix domain socket.
pub const AF_UNIX: u16 = 1;
/// Netlink.
pub const AF_NETLINK: u16 = 16;
/// Unspecified.
pub const AF_UNSPEC: u16 = 0;
/// Packet socket.
pub const AF_PACKET: u16 = 17;

/// Minimum `sockaddr` size (family field only).
const SOCKADDR_MIN_LEN: usize = 2;
/// Maximum `sockaddr` size (enough for any standard type).
const SOCKADDR_MAX_LEN: usize = 128;
/// `struct sockaddr_un` path field size.
const UNIX_PATH_MAX: usize = 108;

// ---------------------------------------------------------------------------
// SockAddrIn — IPv4 socket address
// ---------------------------------------------------------------------------

/// IPv4 socket address (`struct sockaddr_in`).
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SockAddrIn {
    /// Address family (must be `AF_INET`).
    pub sin_family: u16,
    /// Port in network byte order.
    pub sin_port: u16,
    /// IPv4 address in network byte order.
    pub sin_addr: u32,
    /// Padding.
    pub sin_zero: [u8; 8],
}

/// Expected size of `struct sockaddr_in`.
pub const SOCKADDR_IN_SIZE: usize = 16;

// ---------------------------------------------------------------------------
// SockAddrIn6 — IPv6 socket address
// ---------------------------------------------------------------------------

/// IPv6 socket address (`struct sockaddr_in6`).
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SockAddrIn6 {
    /// Address family (must be `AF_INET6`).
    pub sin6_family: u16,
    /// Port in network byte order.
    pub sin6_port: u16,
    /// Flow label.
    pub sin6_flowinfo: u32,
    /// IPv6 address (16 bytes, network byte order).
    pub sin6_addr: [u8; 16],
    /// Scope ID.
    pub sin6_scope_id: u32,
}

impl Default for SockAddrIn6 {
    fn default() -> Self {
        Self {
            sin6_family: AF_INET6,
            sin6_port: 0,
            sin6_flowinfo: 0,
            sin6_addr: [0; 16],
            sin6_scope_id: 0,
        }
    }
}

/// Expected size of `struct sockaddr_in6`.
pub const SOCKADDR_IN6_SIZE: usize = 28;

// ---------------------------------------------------------------------------
// SockAddrUn — Unix domain socket address
// ---------------------------------------------------------------------------

/// Unix domain socket address (`struct sockaddr_un`).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct SockAddrUn {
    /// Address family (must be `AF_UNIX`).
    pub sun_family: u16,
    /// Path (NUL-terminated; abstract sockets start with '\0').
    pub sun_path: [u8; UNIX_PATH_MAX],
}

impl Default for SockAddrUn {
    fn default() -> Self {
        Self {
            sun_family: AF_UNIX,
            sun_path: [0; UNIX_PATH_MAX],
        }
    }
}

impl core::fmt::Debug for SockAddrUn {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SockAddrUn")
            .field("sun_family", &self.sun_family)
            .field("sun_path", &&self.sun_path[..])
            .finish()
    }
}

// ---------------------------------------------------------------------------
// ParsedSockAddr — discriminated union of parsed addresses
// ---------------------------------------------------------------------------

/// Parsed and validated socket address.
#[derive(Debug, Clone, Copy)]
pub enum ParsedSockAddr {
    /// IPv4 address.
    Inet(SockAddrIn),
    /// IPv6 address.
    Inet6(SockAddrIn6),
    /// Unix domain socket path.
    Unix { abstract_ns: bool, path_len: usize },
    /// Netlink socket.
    Netlink { pid: u32, groups: u32 },
    /// Any other family stored as raw bytes.
    Raw { family: u16, len: usize },
}

// ---------------------------------------------------------------------------
// Parsing and validation
// ---------------------------------------------------------------------------

/// Validate `addrlen` against the expected minimum.
fn check_addrlen(len: usize, min: usize) -> Result<()> {
    if len < min || len > SOCKADDR_MAX_LEN {
        return Err(Error::InvalidArgument);
    }
    Ok(())
}

/// Parse a raw `sockaddr` byte slice into a [`ParsedSockAddr`].
///
/// The `addr` slice is the user-supplied address structure.  Its length
/// is `addrlen`.
///
/// # Errors
///
/// [`Error::InvalidArgument`] if:
/// - `addrlen` is less than 2 (cannot read family).
/// - `addrlen` is too small for the declared address family.
/// - The family is `AF_UNSPEC`.
pub fn parse_sockaddr(addr: &[u8], addrlen: usize) -> Result<ParsedSockAddr> {
    if addrlen < SOCKADDR_MIN_LEN || addrlen > SOCKADDR_MAX_LEN {
        return Err(Error::InvalidArgument);
    }
    if addr.len() < addrlen {
        return Err(Error::InvalidArgument);
    }

    let family = u16::from_ne_bytes([addr[0], addr[1]]);

    match family {
        AF_UNSPEC => Err(Error::InvalidArgument),

        AF_INET => {
            check_addrlen(addrlen, SOCKADDR_IN_SIZE)?;
            let port = u16::from_be_bytes([addr[2], addr[3]]);
            let ip = u32::from_be_bytes([addr[4], addr[5], addr[6], addr[7]]);
            let mut zero = [0u8; 8];
            zero.copy_from_slice(&addr[8..16]);
            Ok(ParsedSockAddr::Inet(SockAddrIn {
                sin_family: AF_INET,
                sin_port: port.to_be(),
                sin_addr: ip.to_be(),
                sin_zero: zero,
            }))
        }

        AF_INET6 => {
            check_addrlen(addrlen, SOCKADDR_IN6_SIZE)?;
            let port = u16::from_be_bytes([addr[2], addr[3]]);
            let flowinfo = u32::from_be_bytes([addr[4], addr[5], addr[6], addr[7]]);
            let mut sa6 = SockAddrIn6 {
                sin6_family: AF_INET6,
                sin6_port: port.to_be(),
                sin6_flowinfo: flowinfo,
                sin6_addr: [0; 16],
                sin6_scope_id: 0,
            };
            sa6.sin6_addr.copy_from_slice(&addr[8..24]);
            if addrlen >= 28 {
                sa6.sin6_scope_id = u32::from_ne_bytes([addr[24], addr[25], addr[26], addr[27]]);
            }
            Ok(ParsedSockAddr::Inet6(sa6))
        }

        AF_UNIX => {
            check_addrlen(addrlen, 2)?;
            let path_len = addrlen - 2;
            let abstract_ns = path_len > 0 && addr[2] == 0;
            if path_len > UNIX_PATH_MAX {
                return Err(Error::InvalidArgument);
            }
            Ok(ParsedSockAddr::Unix {
                abstract_ns,
                path_len,
            })
        }

        AF_NETLINK => {
            check_addrlen(addrlen, 12)?;
            let pid = u32::from_ne_bytes([addr[4], addr[5], addr[6], addr[7]]);
            let groups = u32::from_ne_bytes([addr[8], addr[9], addr[10], addr[11]]);
            Ok(ParsedSockAddr::Netlink { pid, groups })
        }

        other => Ok(ParsedSockAddr::Raw {
            family: other,
            len: addrlen,
        }),
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn inet_addr(port: u16, ip: [u8; 4]) -> [u8; 16] {
        let mut b = [0u8; 16];
        b[0..2].copy_from_slice(&AF_INET.to_ne_bytes());
        b[2..4].copy_from_slice(&port.to_be_bytes());
        b[4..8].copy_from_slice(&ip);
        b
    }

    #[test]
    fn parse_ipv4() {
        let raw = inet_addr(80, [127, 0, 0, 1]);
        let p = parse_sockaddr(&raw, 16).unwrap();
        assert!(matches!(p, ParsedSockAddr::Inet(_)));
    }

    #[test]
    fn ipv4_too_small() {
        let raw = [AF_INET.to_ne_bytes()[0], AF_INET.to_ne_bytes()[1]];
        assert_eq!(parse_sockaddr(&raw, 2), Err(Error::InvalidArgument));
    }

    #[test]
    fn parse_unix() {
        let mut raw = [0u8; 20];
        raw[0..2].copy_from_slice(&AF_UNIX.to_ne_bytes());
        raw[2..7].copy_from_slice(b"/tmp/");
        let p = parse_sockaddr(&raw, 20).unwrap();
        assert!(matches!(
            p,
            ParsedSockAddr::Unix {
                abstract_ns: false,
                path_len: 18
            }
        ));
    }

    #[test]
    fn af_unspec_rejected() {
        let raw = [0u8; 16];
        assert_eq!(parse_sockaddr(&raw, 16), Err(Error::InvalidArgument));
    }

    #[test]
    fn addrlen_too_small() {
        let raw = [AF_INET.to_ne_bytes()[0], AF_INET.to_ne_bytes()[1]];
        assert_eq!(parse_sockaddr(&raw, 1), Err(Error::InvalidArgument));
    }
}
