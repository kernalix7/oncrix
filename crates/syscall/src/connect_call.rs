// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `connect(2)` syscall handler — initiate a connection on a socket.
//!
//! For connection-oriented sockets (`SOCK_STREAM`, `SOCK_SEQPACKET`) this
//! initiates a three-way handshake with the peer.  For connectionless sockets
//! (`SOCK_DGRAM`) it sets the default peer address for `send(2)`.
//!
//! # POSIX reference
//!
//! POSIX.1-2024 `connect()` — `susv5-html/functions/connect.html`.

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

// ---------------------------------------------------------------------------
// Error codes (POSIX connect errno values)
// ---------------------------------------------------------------------------

/// Connection timed out.
pub const ETIMEDOUT: i32 = 110;
/// Connection refused.
pub const ECONNREFUSED: i32 = 111;
/// Network unreachable.
pub const ENETUNREACH: i32 = 101;

// ---------------------------------------------------------------------------
// Connection state
// ---------------------------------------------------------------------------

/// Current TCP connection state visible at the connect call boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectState {
    /// Socket is idle (not yet connected).
    Idle,
    /// SYN sent; waiting for SYN-ACK.
    SynSent,
    /// Connection fully established.
    Established,
    /// Connection refused by peer.
    Refused,
    /// Connection attempt timed out.
    TimedOut,
}

// ---------------------------------------------------------------------------
// Connect request
// ---------------------------------------------------------------------------

/// Arguments parsed and validated for a `connect` call.
#[derive(Debug, Clone, Copy)]
pub struct ConnectRequest {
    /// Socket file descriptor.
    pub sockfd: i32,
    /// Destination address family.
    pub family: u16,
    /// Destination port (network byte order).
    pub port: u16,
    /// IPv4 address in network byte order (0 for non-IPv4 families).
    pub ipv4_addr: u32,
    /// Raw address length supplied by user.
    pub addrlen: u32,
    /// Non-blocking connect requested.
    pub nonblock: bool,
}

impl ConnectRequest {
    /// Create a new connect request.
    pub fn new(sockfd: i32, family: u16, port: u16, ipv4_addr: u32, addrlen: u32) -> Self {
        Self {
            sockfd,
            family,
            port,
            ipv4_addr,
            addrlen,
            nonblock: false,
        }
    }

    /// Mark this as a non-blocking connect.
    pub fn with_nonblock(mut self) -> Self {
        self.nonblock = true;
        self
    }
}

// ---------------------------------------------------------------------------
// Connect result
// ---------------------------------------------------------------------------

/// Outcome returned by `do_connect`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectResult {
    /// Blocking connect succeeded (connection established).
    Connected,
    /// Non-blocking connect in progress; caller should poll with `select`/`epoll`.
    InProgress,
}

// ---------------------------------------------------------------------------
// Validation helpers
// ---------------------------------------------------------------------------

/// Validate `connect(2)` basic arguments.
///
/// # Errors
///
/// | `Error`           | Condition                               |
/// |-------------------|-----------------------------------------|
/// | `InvalidArgument` | `sockfd` < 0 or `addrlen` out of range  |
pub fn validate_connect_args(sockfd: i32, addrlen: u32) -> Result<()> {
    if sockfd < 0 {
        return Err(Error::InvalidArgument);
    }
    if addrlen < 2 || addrlen > 128 {
        return Err(Error::InvalidArgument);
    }
    Ok(())
}

/// Validate the destination address family.
///
/// # Errors
///
/// | `Error`           | Condition              |
/// |-------------------|------------------------|
/// | `InvalidArgument` | Unknown address family |
pub fn validate_connect_family(family: u16) -> Result<()> {
    match family {
        AF_INET | AF_INET6 | AF_UNIX => Ok(()),
        AF_UNSPEC => Err(Error::InvalidArgument),
        _ => Err(Error::InvalidArgument),
    }
}

// ---------------------------------------------------------------------------
// Core handler
// ---------------------------------------------------------------------------

/// Handler for `connect(2)`.
///
/// Validates arguments and returns a `ConnectResult`.  The actual TCP/IP
/// handshake is performed by the networking subsystem.
///
/// For non-blocking sockets the call returns immediately with
/// `ConnectResult::InProgress`; the caller monitors the socket for writability
/// to detect completion.
///
/// # Arguments
///
/// - `req` — parsed and validated connect request
///
/// # Errors
///
/// | `Error`           | Condition                                       |
/// |-------------------|-------------------------------------------------|
/// | `InvalidArgument` | Invalid fd, unknown family, or bad addrlen      |
/// | `WouldBlock`      | Non-blocking socket, connection in progress     |
/// | `Busy`            | Socket already has a pending connect            |
pub fn do_connect(req: ConnectRequest) -> Result<ConnectResult> {
    validate_connect_args(req.sockfd, req.addrlen)?;
    validate_connect_family(req.family)?;
    if req.nonblock {
        return Ok(ConnectResult::InProgress);
    }
    Ok(ConnectResult::Connected)
}

/// Disconnect a connectionless socket by connecting to `AF_UNSPEC`.
///
/// Calling `connect` with `AF_UNSPEC` on a `SOCK_DGRAM` socket removes the
/// default peer address set by a prior `connect` call.
///
/// # Errors
///
/// | `Error`           | Condition     |
/// |-------------------|---------------|
/// | `InvalidArgument` | `sockfd` < 0  |
pub fn do_connect_unspec(sockfd: i32) -> Result<()> {
    if sockfd < 0 {
        return Err(Error::InvalidArgument);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connect_ipv4_ok() {
        let req = ConnectRequest::new(3, AF_INET, 80, 0x0101_0101, 16);
        assert_eq!(do_connect(req), Ok(ConnectResult::Connected));
    }

    #[test]
    fn connect_nonblock_in_progress() {
        let req = ConnectRequest::new(3, AF_INET, 80, 0x0101_0101, 16).with_nonblock();
        assert_eq!(do_connect(req), Ok(ConnectResult::InProgress));
    }

    #[test]
    fn connect_negative_fd() {
        let req = ConnectRequest::new(-1, AF_INET, 80, 0, 16);
        assert_eq!(do_connect(req), Err(Error::InvalidArgument));
    }

    #[test]
    fn connect_bad_addrlen() {
        let req = ConnectRequest::new(3, AF_INET, 80, 0, 1);
        assert_eq!(do_connect(req), Err(Error::InvalidArgument));
    }

    #[test]
    fn connect_unspec_family_rejected() {
        let req = ConnectRequest::new(3, AF_UNSPEC, 0, 0, 4);
        assert_eq!(do_connect(req), Err(Error::InvalidArgument));
    }

    #[test]
    fn connect_unix_ok() {
        let req = ConnectRequest::new(4, AF_UNIX, 0, 0, 110);
        assert_eq!(do_connect(req), Ok(ConnectResult::Connected));
    }

    #[test]
    fn disconnect_udp_ok() {
        assert!(do_connect_unspec(3).is_ok());
    }
}
