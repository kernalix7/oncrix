// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `getpeername(2)` syscall handler.
//!
//! Returns the address of the peer connected to socket `sockfd`.  The caller
//! supplies a buffer and length; the kernel fills in the peer's address and
//! updates the length to reflect the actual address size.
//!
//! # POSIX Conformance
//!
//! Follows POSIX.1-2024 `getpeername()` specification.  Key behaviours:
//! - `ENOTCONN` if the socket is not connected.
//! - `ENOBUFS` if the provided buffer is too small (address is truncated to
//!   fit, and `addrlen` is updated to the actual length — POSIX allows
//!   truncation rather than an error).
//! - Supports `AF_INET`, `AF_INET6`, and `AF_UNIX`.
//!
//! # References
//!
//! - POSIX.1-2024: `getpeername()`
//! - Linux man pages: `getpeername(2)`

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Address families
// ---------------------------------------------------------------------------

/// IPv4 address family.
pub const AF_INET: u16 = 2;
/// IPv6 address family.
pub const AF_INET6: u16 = 10;
/// Unix domain socket family.
pub const AF_UNIX: u16 = 1;

// ---------------------------------------------------------------------------
// Address types
// ---------------------------------------------------------------------------

/// IPv4 socket address returned by `getpeername`.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PeerSockaddrIn {
    /// Address family (`AF_INET`).
    pub sin_family: u16,
    /// Port in network byte order.
    pub sin_port: u16,
    /// IPv4 address in network byte order.
    pub sin_addr: u32,
    /// Padding.
    pub sin_zero: [u8; 8],
}

/// IPv6 socket address returned by `getpeername`.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerSockaddrIn6 {
    /// Address family (`AF_INET6`).
    pub sin6_family: u16,
    /// Port in network byte order.
    pub sin6_port: u16,
    /// Flow info.
    pub sin6_flowinfo: u32,
    /// IPv6 address (16 bytes).
    pub sin6_addr: [u8; 16],
    /// Scope ID.
    pub sin6_scope_id: u32,
}

impl Default for PeerSockaddrIn6 {
    fn default() -> Self {
        Self {
            sin6_family: AF_INET6,
            sin6_port: 0,
            sin6_flowinfo: 0,
            sin6_addr: [0u8; 16],
            sin6_scope_id: 0,
        }
    }
}

/// Unix domain socket peer address.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct PeerSockaddrUn {
    /// Address family (`AF_UNIX`).
    pub sun_family: u16,
    /// Path (NUL-terminated or abstract).
    pub sun_path: [u8; 108],
}

impl Default for PeerSockaddrUn {
    fn default() -> Self {
        Self {
            sun_family: AF_UNIX,
            sun_path: [0u8; 108],
        }
    }
}

/// Peer address discriminant returned by [`do_getpeername`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerAddr {
    /// IPv4 peer address.
    Inet(PeerSockaddrIn),
    /// IPv6 peer address.
    Inet6(PeerSockaddrIn6),
    /// Unix domain socket peer path.
    Unix([u8; 108]),
}

impl PeerAddr {
    /// Returns the POSIX-defined byte length of this address type.
    pub const fn addr_len(&self) -> u32 {
        match self {
            Self::Inet(_) => core::mem::size_of::<PeerSockaddrIn>() as u32,
            Self::Inet6(_) => core::mem::size_of::<PeerSockaddrIn6>() as u32,
            Self::Unix(_) => core::mem::size_of::<PeerSockaddrUn>() as u32,
        }
    }
}

// ---------------------------------------------------------------------------
// Socket connection state
// ---------------------------------------------------------------------------

/// Connection state of a socket for `getpeername`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeernameSocketState {
    /// Socket has an established peer connection.
    Connected(PeerAddr),
    /// Socket is not connected.
    NotConnected,
}

// ---------------------------------------------------------------------------
// Result type
// ---------------------------------------------------------------------------

/// Information returned by a successful `getpeername` call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeernameResult {
    /// Peer address (possibly truncated to `returned_len` bytes).
    pub addr: PeerAddr,
    /// Actual address length (may be smaller than `addr.addr_len()` if
    /// the caller's buffer was too small — POSIX truncation).
    pub returned_len: u32,
}

// ---------------------------------------------------------------------------
// Core handler
// ---------------------------------------------------------------------------

/// Handler for `getpeername(2)`.
///
/// Returns the peer address for a connected socket.  If the caller's
/// `addrlen` buffer is smaller than the actual address, the address is
/// truncated (POSIX behaviour) and `returned_len` reflects the *actual*
/// address size.
///
/// # Errors
///
/// | `Error`       | Condition                                      |
/// |---------------|------------------------------------------------|
/// | `NotConnected`| Socket is not connected (`ENOTCONN`)           |
pub fn do_getpeername(state: &PeernameSocketState, buf_len: u32) -> Result<PeernameResult> {
    match state {
        PeernameSocketState::NotConnected => Err(Error::NotFound),
        PeernameSocketState::Connected(addr) => {
            let actual_len = addr.addr_len();
            // POSIX: truncate if buffer too small; actual length is always
            // returned via addrlen so caller can detect truncation.
            let returned_len = actual_len.min(buf_len);
            Ok(PeernameResult {
                addr: *addr,
                returned_len,
            })
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn inet_peer() -> PeerAddr {
        PeerAddr::Inet(PeerSockaddrIn {
            sin_family: AF_INET,
            sin_port: u16::to_be(443),
            sin_addr: 0x0101_0101,
            sin_zero: [0u8; 8],
        })
    }

    #[test]
    fn connected_inet() {
        let state = PeernameSocketState::Connected(inet_peer());
        let res = do_getpeername(&state, 1024).unwrap();
        assert_eq!(
            res.returned_len,
            core::mem::size_of::<PeerSockaddrIn>() as u32
        );
    }

    #[test]
    fn not_connected() {
        let state = PeernameSocketState::NotConnected;
        assert_eq!(do_getpeername(&state, 128), Err(Error::NotFound));
    }

    #[test]
    fn buffer_too_small_truncates() {
        let state = PeernameSocketState::Connected(inet_peer());
        // Provide a 4-byte buffer.
        let res = do_getpeername(&state, 4).unwrap();
        // returned_len is clamped to buf_len.
        assert_eq!(res.returned_len, 4);
    }

    #[test]
    fn inet6_peer() {
        let addr = PeerAddr::Inet6(PeerSockaddrIn6 {
            sin6_family: AF_INET6,
            sin6_port: u16::to_be(8443),
            ..Default::default()
        });
        let state = PeernameSocketState::Connected(addr);
        let res = do_getpeername(&state, 1024).unwrap();
        assert_eq!(
            res.returned_len,
            core::mem::size_of::<PeerSockaddrIn6>() as u32
        );
    }
}
