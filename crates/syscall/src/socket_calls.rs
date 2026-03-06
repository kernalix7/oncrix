// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! POSIX socket syscall handlers.
//!
//! Implements `socket`, `bind`, `listen`, `accept`, `connect`,
//! `sendto`, `recvfrom`, `setsockopt`, `getsockopt`, `shutdown`,
//! `socketpair`, `getpeername`, and `getsockname` per POSIX.1-2024.

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Address family constants
// ---------------------------------------------------------------------------

/// Unspecified address family.
pub const AF_UNSPEC: i32 = 0;
/// Local (Unix domain) sockets.
pub const AF_LOCAL: i32 = 1;
/// Alias for [`AF_LOCAL`].
pub const AF_UNIX: i32 = 1;
/// IPv4 Internet protocols.
pub const AF_INET: i32 = 2;
/// IPv6 Internet protocols.
pub const AF_INET6: i32 = 10;
/// Netlink sockets.
pub const AF_NETLINK: i32 = 16;
/// Low-level packet interface.
pub const AF_PACKET: i32 = 17;

// ---------------------------------------------------------------------------
// Socket type constants
// ---------------------------------------------------------------------------

/// Sequenced, reliable, two-way byte streams.
pub const SOCK_STREAM: i32 = 1;
/// Connectionless, unreliable datagrams.
pub const SOCK_DGRAM: i32 = 2;
/// Raw network protocol access.
pub const SOCK_RAW: i32 = 3;
/// Sequenced, reliable, connection-based datagrams.
pub const SOCK_SEQPACKET: i32 = 5;
/// Set non-blocking mode on the new socket.
pub const SOCK_NONBLOCK: i32 = 0x800;
/// Set close-on-exec on the new socket.
pub const SOCK_CLOEXEC: i32 = 0x80000;

/// Mask covering the base socket type bits (low 4 bits).
const _SOCK_TYPE_MASK: i32 = 0xF;

// ---------------------------------------------------------------------------
// Socket option constants
// ---------------------------------------------------------------------------

/// Socket-level options.
pub const SOL_SOCKET: i32 = 1;
/// Enable local address reuse.
pub const SO_REUSEADDR: i32 = 2;
/// Retrieve and clear pending socket error.
pub const SO_ERROR: i32 = 4;
/// Enable keep-alive probes.
pub const SO_KEEPALIVE: i32 = 9;
/// Receive buffer size.
pub const SO_RCVBUF: i32 = 8;
/// Send buffer size.
pub const SO_SNDBUF: i32 = 7;
/// Receive timeout.
pub const SO_RCVTIMEO: i32 = 20;
/// Send timeout.
pub const SO_SNDTIMEO: i32 = 21;
/// Linger on close.
pub const SO_LINGER: i32 = 13;
/// Enable broadcast.
pub const SO_BROADCAST: i32 = 6;

/// TCP protocol number.
pub const IPPROTO_TCP: i32 = 6;
/// Disable Nagle algorithm.
pub const TCP_NODELAY: i32 = 1;

// ---------------------------------------------------------------------------
// Shutdown constants
// ---------------------------------------------------------------------------

/// Shut down the reading side.
pub const SHUT_RD: i32 = 0;
/// Shut down the writing side.
pub const SHUT_WR: i32 = 1;
/// Shut down both sides.
pub const SHUT_RDWR: i32 = 2;

// ---------------------------------------------------------------------------
// SockaddrIn — IPv4 socket address
// ---------------------------------------------------------------------------

/// IPv4 socket address (`struct sockaddr_in`).
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SockaddrIn {
    /// Address family (always [`AF_INET`]).
    pub family: u16,
    /// Port number in network byte order.
    pub port: u16,
    /// IPv4 address in network byte order.
    pub addr: u32,
    /// Padding to match C struct size.
    pub zero: [u8; 8],
}

impl Default for SockaddrIn {
    fn default() -> Self {
        Self::new(0, 0)
    }
}

impl SockaddrIn {
    /// Create a new IPv4 socket address.
    pub fn new(addr: u32, port: u16) -> Self {
        Self {
            family: AF_INET as u16,
            port,
            addr,
            zero: [0; 8],
        }
    }

    /// Return the IPv4 address as four octets.
    pub fn ip_octets(&self) -> [u8; 4] {
        self.addr.to_be_bytes()
    }
}

// ---------------------------------------------------------------------------
// SockaddrIn6 — IPv6 socket address
// ---------------------------------------------------------------------------

/// IPv6 socket address (`struct sockaddr_in6`).
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SockaddrIn6 {
    /// Address family (always [`AF_INET6`]).
    pub family: u16,
    /// Port number in network byte order.
    pub port: u16,
    /// IPv6 flow information.
    pub flowinfo: u32,
    /// IPv6 address (16 bytes).
    pub addr: [u8; 16],
    /// Scope identifier.
    pub scope_id: u32,
}

impl Default for SockaddrIn6 {
    fn default() -> Self {
        Self::new([0; 16], 0)
    }
}

impl SockaddrIn6 {
    /// Create a new IPv6 socket address.
    pub fn new(addr: [u8; 16], port: u16) -> Self {
        Self {
            family: AF_INET6 as u16,
            port,
            addr,
            flowinfo: 0,
            scope_id: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// SockaddrUn — Unix domain socket address
// ---------------------------------------------------------------------------

/// Unix domain socket address (`struct sockaddr_un`).
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SockaddrUn {
    /// Address family (always [`AF_UNIX`]).
    pub family: u16,
    /// Null-terminated pathname.
    pub path: [u8; 108],
}

impl Default for SockaddrUn {
    fn default() -> Self {
        Self {
            family: AF_UNIX as u16,
            path: [0; 108],
        }
    }
}

impl SockaddrUn {
    /// Create a new Unix domain socket address from a path.
    ///
    /// Returns `Err(InvalidArgument)` if `path` is empty or
    /// too long (>= 108 bytes including null terminator).
    pub fn new(path: &[u8]) -> Result<Self> {
        if path.is_empty() || path.len() >= 108 {
            return Err(Error::InvalidArgument);
        }
        let mut addr = Self {
            family: AF_UNIX as u16,
            path: [0; 108],
        };
        addr.path[..path.len()].copy_from_slice(path);
        Ok(addr)
    }
}

// ---------------------------------------------------------------------------
// SockaddrStorage — generic socket address storage
// ---------------------------------------------------------------------------

/// Generic socket address storage (`struct sockaddr_storage`).
///
/// Large enough to hold any socket address type.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SockaddrStorage {
    /// Address family.
    family: u16,
    /// Opaque data (interpretation depends on `family`).
    data: [u8; 126],
}

impl Default for SockaddrStorage {
    fn default() -> Self {
        Self {
            family: AF_UNSPEC as u16,
            data: [0; 126],
        }
    }
}

impl SockaddrStorage {
    /// Return the address family stored in this structure.
    pub fn family(&self) -> u16 {
        self.family
    }
}

// ---------------------------------------------------------------------------
// MsgHdr — message header for sendmsg/recvmsg
// ---------------------------------------------------------------------------

/// POSIX `struct msghdr` for scatter/gather I/O on sockets.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct MsgHdr {
    /// Pointer to the destination/source address.
    pub name_ptr: u64,
    /// Length of the address.
    pub name_len: u32,
    /// Pointer to the iovec array.
    pub iov_ptr: u64,
    /// Number of iovec entries.
    pub iov_len: u32,
    /// Pointer to ancillary data.
    pub control_ptr: u64,
    /// Length of ancillary data.
    pub control_len: u32,
    /// Flags on received message.
    pub flags: i32,
}

// ---------------------------------------------------------------------------
// Validation helpers
// ---------------------------------------------------------------------------

/// Validate that the file descriptor is non-negative.
fn validate_fd(fd: i32) -> Result<()> {
    if fd < 0 {
        return Err(Error::InvalidArgument);
    }
    Ok(())
}

/// Validate a base socket type (excluding flag bits).
fn validate_socket_type(base_type: i32) -> Result<()> {
    match base_type {
        SOCK_STREAM | SOCK_DGRAM | SOCK_RAW | SOCK_SEQPACKET => Ok(()),
        _ => Err(Error::InvalidArgument),
    }
}

/// Validate an address family.
fn validate_domain(domain: i32) -> Result<()> {
    match domain {
        AF_UNSPEC | AF_LOCAL | AF_INET | AF_INET6 | AF_NETLINK | AF_PACKET => Ok(()),
        _ => Err(Error::InvalidArgument),
    }
}

// ---------------------------------------------------------------------------
// Syscall handlers
// ---------------------------------------------------------------------------

/// `socket` — create a communication endpoint.
///
/// Validates the address `domain` and socket `sock_type`
/// (including `SOCK_NONBLOCK` / `SOCK_CLOEXEC` flags).
/// Returns a new file descriptor on success.
pub fn do_socket(domain: i32, sock_type: i32, protocol: i32) -> Result<i32> {
    validate_domain(domain)?;

    let base_type = sock_type & _SOCK_TYPE_MASK;
    let flags = sock_type & !_SOCK_TYPE_MASK;

    validate_socket_type(base_type)?;

    // Only SOCK_NONBLOCK and SOCK_CLOEXEC are valid flags.
    if flags & !(SOCK_NONBLOCK | SOCK_CLOEXEC) != 0 {
        return Err(Error::InvalidArgument);
    }

    // Protocol 0 means auto-select; other values are
    // protocol-specific and accepted without further check.
    let _ = protocol;

    // Stub: real implementation allocates a socket object.
    Err(Error::NotImplemented)
}

/// `bind` — assign an address to a socket.
pub fn do_bind(fd: i32, addr: &SockaddrStorage, addr_len: u32) -> Result<()> {
    validate_fd(fd)?;

    if addr_len == 0 {
        return Err(Error::InvalidArgument);
    }

    let _ = addr.family();

    // Stub: real implementation binds the address.
    Err(Error::NotImplemented)
}

/// `listen` — mark a socket as a passive socket.
///
/// `backlog` is clamped to a kernel-defined maximum.
pub fn do_listen(fd: i32, backlog: i32) -> Result<()> {
    validate_fd(fd)?;

    // POSIX allows 0; negative treated as 0.
    let _ = if backlog < 0 { 0 } else { backlog };

    // Stub: real implementation marks socket as listening.
    Err(Error::NotImplemented)
}

/// `accept` — accept a connection on a socket.
///
/// Returns `(new_fd, peer_address)` on success.
pub fn do_accept(fd: i32) -> Result<(i32, SockaddrStorage)> {
    validate_fd(fd)?;

    // Stub: real implementation dequeues a pending connection.
    Err(Error::NotImplemented)
}

/// `connect` — initiate a connection on a socket.
pub fn do_connect(fd: i32, addr: &SockaddrStorage, addr_len: u32) -> Result<()> {
    validate_fd(fd)?;

    if addr_len == 0 {
        return Err(Error::InvalidArgument);
    }

    let _ = addr.family();

    // Stub: real implementation initiates the connection.
    Err(Error::NotImplemented)
}

/// `sendto` — send a message on a socket.
///
/// If `dest` is `None`, the socket must be connected.
pub fn do_sendto(fd: i32, buf: &[u8], flags: i32, dest: Option<&SockaddrStorage>) -> Result<usize> {
    validate_fd(fd)?;

    let _ = flags;
    let _ = dest;

    if buf.is_empty() {
        return Ok(0);
    }

    // Stub: real implementation sends data.
    Err(Error::NotImplemented)
}

/// `recvfrom` — receive a message from a socket.
///
/// Returns `(bytes_read, source_address)` on success.
pub fn do_recvfrom(fd: i32, buf: &mut [u8], flags: i32) -> Result<(usize, SockaddrStorage)> {
    validate_fd(fd)?;

    let _ = flags;

    if buf.is_empty() {
        return Ok((0, SockaddrStorage::default()));
    }

    // Stub: real implementation receives data.
    Err(Error::NotImplemented)
}

/// `setsockopt` — set a socket option.
pub fn do_setsockopt(fd: i32, level: i32, optname: i32, optval: u64) -> Result<()> {
    validate_fd(fd)?;

    let _ = optval;

    // Validate well-known levels and option names.
    match level {
        SOL_SOCKET => match optname {
            SO_REUSEADDR | SO_KEEPALIVE | SO_RCVBUF | SO_SNDBUF | SO_RCVTIMEO | SO_SNDTIMEO
            | SO_LINGER | SO_BROADCAST => {}
            _ => return Err(Error::InvalidArgument),
        },
        IPPROTO_TCP => match optname {
            TCP_NODELAY => {}
            _ => return Err(Error::InvalidArgument),
        },
        _ => return Err(Error::InvalidArgument),
    }

    // Stub: real implementation sets the option.
    Err(Error::NotImplemented)
}

/// `getsockopt` — get a socket option.
///
/// Returns the option value as a `u64`.
pub fn do_getsockopt(fd: i32, level: i32, optname: i32) -> Result<u64> {
    validate_fd(fd)?;

    // Validate well-known levels and option names.
    match level {
        SOL_SOCKET => match optname {
            SO_REUSEADDR | SO_ERROR | SO_KEEPALIVE | SO_RCVBUF | SO_SNDBUF | SO_RCVTIMEO
            | SO_SNDTIMEO | SO_LINGER | SO_BROADCAST => {}
            _ => return Err(Error::InvalidArgument),
        },
        IPPROTO_TCP => match optname {
            TCP_NODELAY => {}
            _ => return Err(Error::InvalidArgument),
        },
        _ => return Err(Error::InvalidArgument),
    }

    // Stub: real implementation retrieves the option.
    Err(Error::NotImplemented)
}

/// `shutdown` — shut down part of a full-duplex connection.
///
/// `how` must be one of [`SHUT_RD`], [`SHUT_WR`], or [`SHUT_RDWR`].
pub fn do_shutdown(fd: i32, how: i32) -> Result<()> {
    validate_fd(fd)?;

    match how {
        SHUT_RD | SHUT_WR | SHUT_RDWR => {}
        _ => return Err(Error::InvalidArgument),
    }

    // Stub: real implementation shuts down the socket.
    Err(Error::NotImplemented)
}

/// `socketpair` — create a pair of connected sockets.
///
/// Returns `(fd1, fd2)` on success.
pub fn do_socketpair(domain: i32, sock_type: i32) -> Result<(i32, i32)> {
    validate_domain(domain)?;

    let base_type = sock_type & _SOCK_TYPE_MASK;
    validate_socket_type(base_type)?;

    // Stub: real implementation creates a connected pair.
    Err(Error::NotImplemented)
}

/// `getpeername` — get the address of the connected peer.
pub fn do_getpeername(fd: i32) -> Result<SockaddrStorage> {
    validate_fd(fd)?;

    // Stub: real implementation queries peer address.
    Err(Error::NotImplemented)
}

/// `getsockname` — get the local address of a socket.
pub fn do_getsockname(fd: i32) -> Result<SockaddrStorage> {
    validate_fd(fd)?;

    // Stub: real implementation queries local address.
    Err(Error::NotImplemented)
}
