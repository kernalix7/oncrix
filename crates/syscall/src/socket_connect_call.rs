// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `connect(2)` syscall handler.
//!
//! Initiates a connection on a socket.  For connection-oriented sockets
//! (`SOCK_STREAM`, `SOCK_SEQPACKET`) the call initiates the TCP/transport
//! three-way handshake.  For connectionless sockets (`SOCK_DGRAM`) it sets
//! the default destination address without sending any packets.
//!
//! # POSIX Conformance
//!
//! Follows POSIX.1-2024 `connect()` specification.  Key behaviours:
//! - For non-blocking TCP sockets, returns `EINPROGRESS` if the handshake
//!   cannot be completed immediately.
//! - `ECONNREFUSED` when the remote peer actively refuses the connection.
//! - `ETIMEDOUT` when the connection attempt times out.
//! - `EISCONN` if the socket is already connected.
//! - For `SOCK_DGRAM`, a second `connect` with `AF_UNSPEC` family clears the
//!   default peer (i.e. disconnects the UDP socket).
//!
//! # References
//!
//! - POSIX.1-2024: `connect()`
//! - Linux man pages: `connect(2)`

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Unspecified address family (used to disconnect UDP sockets).
pub const AF_UNSPEC: u16 = 0;
/// IPv4 Internet protocols.
pub const AF_INET: u16 = 2;
/// IPv6 Internet protocols.
pub const AF_INET6: u16 = 10;
/// Unix domain sockets.
pub const AF_UNIX: u16 = 1;

/// Stream socket type (TCP).
pub const SOCK_STREAM: i32 = 1;
/// Datagram socket type (UDP).
pub const SOCK_DGRAM: i32 = 2;
/// Sequenced packet socket type.
pub const SOCK_SEQPACKET: i32 = 5;

// ---------------------------------------------------------------------------
// TCP connection state machine
// ---------------------------------------------------------------------------

/// TCP connection state relevant to `connect(2)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpConnectState {
    /// Initial state — no connection attempt in progress.
    Closed,
    /// SYN has been sent; waiting for SYN-ACK (`EINPROGRESS`).
    SynSent,
    /// Three-way handshake completed; connection is active.
    Established,
    /// Connection attempt failed with `ECONNREFUSED`.
    Refused,
    /// Connection attempt timed out.
    TimedOut,
}

// ---------------------------------------------------------------------------
// Address types
// ---------------------------------------------------------------------------

/// Peer address supplied to `connect`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerAddress {
    /// IPv4 peer (family, port, addr).
    Inet {
        /// Port in network byte order.
        port: u16,
        /// IPv4 address in network byte order.
        addr: u32,
    },
    /// IPv6 peer.
    Inet6 {
        /// Port in network byte order.
        port: u16,
        /// IPv6 address.
        addr: [u8; 16],
        /// Scope ID.
        scope_id: u32,
    },
    /// Unix domain socket peer path.
    Unix([u8; 108]),
    /// AF_UNSPEC — used to disconnect a UDP socket.
    Unspec,
}

// ---------------------------------------------------------------------------
// Socket state for connect
// ---------------------------------------------------------------------------

/// Mutable state associated with a socket for connect operations.
#[derive(Debug)]
pub struct ConnectSocket {
    /// Socket type (`SOCK_STREAM`, `SOCK_DGRAM`, `SOCK_SEQPACKET`).
    pub sock_type: i32,
    /// Whether the socket is in non-blocking mode.
    pub nonblocking: bool,
    /// Current TCP connection state (only meaningful for stream sockets).
    pub tcp_state: TcpConnectState,
    /// Bound local address family (0 = unbound).
    pub local_family: u16,
    /// Connected peer address (for stream sockets after ESTABLISHED,
    /// or for UDP default destination).
    pub peer: Option<PeerAddress>,
}

impl ConnectSocket {
    /// Create a new unconnected socket.
    pub const fn new(sock_type: i32, nonblocking: bool) -> Self {
        Self {
            sock_type,
            nonblocking,
            tcp_state: TcpConnectState::Closed,
            local_family: 0,
            peer: None,
        }
    }

    /// Returns `true` if this socket is connection-oriented.
    pub fn is_connection_oriented(&self) -> bool {
        self.sock_type == SOCK_STREAM || self.sock_type == SOCK_SEQPACKET
    }
}

// ---------------------------------------------------------------------------
// Connect outcome
// ---------------------------------------------------------------------------

/// Outcome returned by [`do_connect`] when the operation succeeds or is
/// deferred.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectOutcome {
    /// Connection is fully established.
    Connected,
    /// Non-blocking socket: handshake in progress (`EINPROGRESS`).
    InProgress,
    /// UDP socket: default peer address set (no handshake needed).
    UdpPeerSet,
    /// UDP socket disconnected (AF_UNSPEC).
    UdpDisconnected,
}

// ---------------------------------------------------------------------------
// Core handler
// ---------------------------------------------------------------------------

/// Handler for `connect(2)`.
///
/// Updates `sock` to reflect the new connection state.
///
/// # Errors
///
/// | `Error`         | Condition                                            |
/// |-----------------|-------------------------------------------------------|
/// | `InvalidArg`    | `addrlen` too small for the address family            |
/// | `InvalidArg`    | Address family mismatch                               |
/// | `AlreadyExists` | Socket is already connected (`EISCONN`)               |
/// | `ConnRefused`   | Remote peer actively refused (`ECONNREFUSED`)         |
/// | `TimedOut`      | Connection attempt timed out (`ETIMEDOUT`)            |
pub fn do_connect(
    sock: &mut ConnectSocket,
    peer: PeerAddress,
    addrlen: u32,
    refused: bool,
    timed_out: bool,
) -> Result<ConnectOutcome> {
    // Validate addrlen for known families.
    match peer {
        PeerAddress::Inet { .. } => {
            if (addrlen as usize) < 8 {
                return Err(Error::InvalidArgument);
            }
        }
        PeerAddress::Inet6 { .. } => {
            if (addrlen as usize) < 28 {
                return Err(Error::InvalidArgument);
            }
        }
        PeerAddress::Unix(_) => {
            if (addrlen as usize) < 3 {
                return Err(Error::InvalidArgument);
            }
        }
        PeerAddress::Unspec => {}
    }

    if sock.is_connection_oriented() {
        // Already fully connected.
        if sock.tcp_state == TcpConnectState::Established {
            return Err(Error::AlreadyExists);
        }

        // Simulate transport-layer outcome.
        if refused {
            sock.tcp_state = TcpConnectState::Refused;
            return Err(Error::IoError);
        }
        if timed_out {
            sock.tcp_state = TcpConnectState::TimedOut;
            return Err(Error::IoError);
        }

        if sock.nonblocking {
            // Non-blocking: SYN sent, caller polls for completion.
            sock.tcp_state = TcpConnectState::SynSent;
            sock.peer = Some(peer);
            return Ok(ConnectOutcome::InProgress);
        }

        // Blocking: handshake completes inline.
        sock.tcp_state = TcpConnectState::Established;
        sock.peer = Some(peer);
        Ok(ConnectOutcome::Connected)
    } else {
        // SOCK_DGRAM — just set or clear default peer.
        if peer == PeerAddress::Unspec {
            sock.peer = None;
            return Ok(ConnectOutcome::UdpDisconnected);
        }
        sock.peer = Some(peer);
        Ok(ConnectOutcome::UdpPeerSet)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn inet_peer() -> PeerAddress {
        PeerAddress::Inet {
            port: u16::to_be(80),
            addr: 0x7f000001,
        }
    }

    #[test]
    fn tcp_blocking_connect() {
        let mut s = ConnectSocket::new(SOCK_STREAM, false);
        let out = do_connect(&mut s, inet_peer(), 16, false, false).unwrap();
        assert_eq!(out, ConnectOutcome::Connected);
        assert_eq!(s.tcp_state, TcpConnectState::Established);
    }

    #[test]
    fn tcp_nonblocking_einprogress() {
        let mut s = ConnectSocket::new(SOCK_STREAM, true);
        let out = do_connect(&mut s, inet_peer(), 16, false, false).unwrap();
        assert_eq!(out, ConnectOutcome::InProgress);
        assert_eq!(s.tcp_state, TcpConnectState::SynSent);
    }

    #[test]
    fn tcp_refused() {
        let mut s = ConnectSocket::new(SOCK_STREAM, false);
        assert_eq!(
            do_connect(&mut s, inet_peer(), 16, true, false),
            Err(Error::IoError)
        );
    }

    #[test]
    fn udp_set_peer() {
        let mut s = ConnectSocket::new(SOCK_DGRAM, false);
        let out = do_connect(&mut s, inet_peer(), 16, false, false).unwrap();
        assert_eq!(out, ConnectOutcome::UdpPeerSet);
        assert!(s.peer.is_some());
    }

    #[test]
    fn udp_disconnect() {
        let mut s = ConnectSocket::new(SOCK_DGRAM, false);
        do_connect(&mut s, inet_peer(), 16, false, false).unwrap();
        let out = do_connect(&mut s, PeerAddress::Unspec, 2, false, false).unwrap();
        assert_eq!(out, ConnectOutcome::UdpDisconnected);
        assert!(s.peer.is_none());
    }

    #[test]
    fn already_connected_fails() {
        let mut s = ConnectSocket::new(SOCK_STREAM, false);
        do_connect(&mut s, inet_peer(), 16, false, false).unwrap();
        assert_eq!(
            do_connect(&mut s, inet_peer(), 16, false, false),
            Err(Error::AlreadyExists)
        );
    }
}
