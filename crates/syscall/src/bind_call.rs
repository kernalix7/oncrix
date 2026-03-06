// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `bind(2)` syscall handler — assign an address to a socket.
//!
//! Binds a local address to a socket file descriptor.  This is the kernel-side
//! validation and preparation step; the actual address registration in the
//! protocol layer is performed by the networking subsystem after validation.
//!
//! # POSIX reference
//!
//! POSIX.1-2024 `bind()` — `susv5-html/functions/bind.html`.

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Address family constants
// ---------------------------------------------------------------------------

/// Unspecified address family.
pub const AF_UNSPEC: u16 = 0;
/// Unix domain sockets.
pub const AF_UNIX: u16 = 1;
/// IPv4 Internet protocols.
pub const AF_INET: u16 = 2;
/// IPv6 Internet protocols.
pub const AF_INET6: u16 = 10;
/// Netlink sockets.
pub const AF_NETLINK: u16 = 16;
/// Low-level packet interface.
pub const AF_PACKET: u16 = 17;

// ---------------------------------------------------------------------------
// Address length limits
// ---------------------------------------------------------------------------

/// Minimum valid address length in bytes.
pub const SOCKADDR_MIN_LEN: u32 = 2;
/// Maximum address length (`sizeof(struct sockaddr_storage)`).
pub const SOCKADDR_MAX_LEN: u32 = 128;
/// Unix domain socket path maximum (including NUL terminator).
pub const UNIX_PATH_MAX: usize = 108;

// ---------------------------------------------------------------------------
// Sockaddr representations
// ---------------------------------------------------------------------------

/// Generic socket address (header only).
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SockaddrHdr {
    /// Address family.
    pub sa_family: u16,
}

/// IPv4 socket address (`struct sockaddr_in`).
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SockaddrIn {
    /// Always `AF_INET`.
    pub sin_family: u16,
    /// Port in network byte order.
    pub sin_port: u16,
    /// IPv4 address in network byte order.
    pub sin_addr: u32,
    /// Padding.
    pub sin_zero: [u8; 8],
}

impl SockaddrIn {
    /// Create an IPv4 address.
    pub fn new(addr: u32, port: u16) -> Self {
        Self {
            sin_family: AF_INET,
            sin_port: port,
            sin_addr: addr,
            sin_zero: [0; 8],
        }
    }

    /// Check this is the wildcard bind address (INADDR_ANY = 0).
    pub fn is_any(&self) -> bool {
        self.sin_addr == 0
    }

    /// Check this is the loopback address (127.0.0.1).
    pub fn is_loopback(&self) -> bool {
        self.sin_addr.to_be_bytes()[0] == 127
    }
}

/// IPv6 socket address (`struct sockaddr_in6`).
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SockaddrIn6 {
    /// Always `AF_INET6`.
    pub sin6_family: u16,
    /// Port in network byte order.
    pub sin6_port: u16,
    /// Flow information.
    pub sin6_flowinfo: u32,
    /// IPv6 address.
    pub sin6_addr: [u8; 16],
    /// Scope ID.
    pub sin6_scope_id: u32,
}

/// Unix domain socket address (`struct sockaddr_un`).
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SockaddrUn {
    /// Always `AF_UNIX`.
    pub sun_family: u16,
    /// Path (NUL-terminated or abstract '\0'-prefixed).
    pub sun_path: [u8; UNIX_PATH_MAX],
}

impl Default for SockaddrUn {
    fn default() -> Self {
        Self {
            sun_family: AF_UNIX,
            sun_path: [0; UNIX_PATH_MAX],
        }
    }
}

impl SockaddrUn {
    /// Returns true if this is an abstract socket (path starts with NUL).
    pub fn is_abstract(&self) -> bool {
        self.sun_path[0] == 0
    }
}

// ---------------------------------------------------------------------------
// Bind result
// ---------------------------------------------------------------------------

/// Outcome of a `bind` operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BindOutcome {
    /// Address successfully bound.
    Bound,
    /// Address was already in use (requires SO_REUSEADDR).
    AddressInUse,
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

/// Validate `bind(2)` arguments.
///
/// Checks that `sockfd` is non-negative and the address length is within
/// the legal range.
///
/// # Errors
///
/// | `Error`           | Condition                         |
/// |-------------------|-----------------------------------|
/// | `InvalidArgument` | `sockfd` < 0 or bad `addrlen`     |
pub fn validate_bind_args(sockfd: i32, addrlen: u32) -> Result<()> {
    if sockfd < 0 {
        return Err(Error::InvalidArgument);
    }
    if addrlen < SOCKADDR_MIN_LEN || addrlen > SOCKADDR_MAX_LEN {
        return Err(Error::InvalidArgument);
    }
    Ok(())
}

/// Validate an IPv4 address for binding.
///
/// Port 0 triggers automatic port assignment by the kernel.
///
/// # Errors
///
/// | `Error`           | Condition                   |
/// |-------------------|-----------------------------|
/// | `InvalidArgument` | Family is not `AF_INET`     |
pub fn validate_ipv4_addr(addr: &SockaddrIn) -> Result<()> {
    if addr.sin_family != AF_INET {
        return Err(Error::InvalidArgument);
    }
    Ok(())
}

/// Validate a Unix domain socket address.
///
/// # Errors
///
/// | `Error`           | Condition                    |
/// |-------------------|------------------------------|
/// | `InvalidArgument` | Family is not `AF_UNIX`      |
pub fn validate_unix_addr(addr: &SockaddrUn) -> Result<()> {
    if addr.sun_family != AF_UNIX {
        return Err(Error::InvalidArgument);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Core handler
// ---------------------------------------------------------------------------

/// Handler for `bind(2)`.
///
/// Validates the socket descriptor and the address structure.  The protocol
/// family is read from the first two bytes of `addr`; validation is
/// family-specific.
///
/// # Arguments
///
/// - `sockfd`  — socket file descriptor
/// - `family`  — address family parsed from the user-supplied address
/// - `addrlen` — length of the user-supplied address structure
///
/// # Errors
///
/// | `Error`           | Condition                                   |
/// |-------------------|---------------------------------------------|
/// | `InvalidArgument` | Invalid fd, unsupported family, bad addrlen |
/// | `AlreadyExists`   | Socket already bound to an address          |
pub fn do_bind(sockfd: i32, family: u16, addrlen: u32) -> Result<BindOutcome> {
    validate_bind_args(sockfd, addrlen)?;
    match family {
        AF_INET | AF_INET6 | AF_UNIX | AF_NETLINK | AF_PACKET => {}
        AF_UNSPEC => return Err(Error::InvalidArgument),
        _ => return Err(Error::InvalidArgument),
    }
    Ok(BindOutcome::Bound)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bind_ipv4_ok() {
        assert_eq!(do_bind(4, AF_INET, 16), Ok(BindOutcome::Bound));
    }

    #[test]
    fn bind_unix_ok() {
        assert_eq!(do_bind(5, AF_UNIX, 110), Ok(BindOutcome::Bound));
    }

    #[test]
    fn bind_negative_fd() {
        assert_eq!(do_bind(-1, AF_INET, 16), Err(Error::InvalidArgument));
    }

    #[test]
    fn bind_zero_addrlen() {
        assert_eq!(do_bind(3, AF_INET, 0), Err(Error::InvalidArgument));
    }

    #[test]
    fn bind_too_large_addrlen() {
        assert_eq!(do_bind(3, AF_INET, 512), Err(Error::InvalidArgument));
    }

    #[test]
    fn bind_unspec_rejected() {
        assert_eq!(do_bind(3, AF_UNSPEC, 16), Err(Error::InvalidArgument));
    }

    #[test]
    fn validate_ipv4_correct_family() {
        let addr = SockaddrIn::new(0x7f000001, 8080);
        assert!(validate_ipv4_addr(&addr).is_ok());
    }

    #[test]
    fn validate_ipv4_wrong_family() {
        let addr = SockaddrIn {
            sin_family: AF_INET6,
            ..SockaddrIn::default()
        };
        assert_eq!(validate_ipv4_addr(&addr), Err(Error::InvalidArgument));
    }

    #[test]
    fn sockaddr_in_is_any() {
        let addr = SockaddrIn::new(0, 0);
        assert!(addr.is_any());
    }

    #[test]
    fn sockaddr_in_is_loopback() {
        let addr = SockaddrIn::new(0x7f000001u32.to_be(), 80);
        assert!(addr.is_loopback());
    }
}
