// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `socket(2)` syscall handler.
//!
//! Creates an endpoint for communication and returns a file descriptor.
//! This module validates socket domain, type, and protocol before the kernel
//! allocates the socket object and installs it into the file-descriptor table.
//!
//! # Syscall signature
//!
//! ```text
//! int socket(int domain, int type, int protocol);
//! ```
//!
//! # POSIX reference
//!
//! POSIX.1-2024 §socket — `<sys/socket.h>`.
//!
//! # References
//!
//! - Linux: `net/socket.c` `__sys_socket()`
//! - `socket(2)` man page

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Address family / domain constants
// ---------------------------------------------------------------------------

/// Unspecified.
pub const AF_UNSPEC: i32 = 0;
/// Unix domain sockets.
pub const AF_UNIX: i32 = 1;
/// IPv4.
pub const AF_INET: i32 = 2;
/// IPv6.
pub const AF_INET6: i32 = 10;
/// Netlink (kernel↔userspace).
pub const AF_NETLINK: i32 = 16;
/// Packet socket (raw L2 frames).
pub const AF_PACKET: i32 = 17;
/// Bluetooth.
pub const AF_BLUETOOTH: i32 = 31;
/// vsock (VM host↔guest).
pub const AF_VSOCK: i32 = 40;

// ---------------------------------------------------------------------------
// Socket type constants
// ---------------------------------------------------------------------------

/// Stream socket (reliable, connection-oriented).
pub const SOCK_STREAM: i32 = 1;
/// Datagram socket (unreliable, connectionless).
pub const SOCK_DGRAM: i32 = 2;
/// Raw socket.
pub const SOCK_RAW: i32 = 3;
/// Reliable datagram (Linux-specific).
pub const SOCK_RDM: i32 = 4;
/// Sequenced datagram.
pub const SOCK_SEQPACKET: i32 = 5;

/// Set close-on-exec flag on the returned fd.
pub const SOCK_CLOEXEC: i32 = 0x0008_0000;
/// Set non-blocking mode.
pub const SOCK_NONBLOCK: i32 = 0x0000_0800;

/// Mask of all recognised socket type flags.
const SOCK_FLAGS_MASK: i32 = SOCK_CLOEXEC | SOCK_NONBLOCK;

/// Maximum recognised domain value.
const AF_MAX: i32 = 45;

// ---------------------------------------------------------------------------
// Protocol constants (common subset)
// ---------------------------------------------------------------------------

/// Default / unspecified protocol (kernel picks).
pub const IPPROTO_IP: i32 = 0;
/// TCP.
pub const IPPROTO_TCP: i32 = 6;
/// UDP.
pub const IPPROTO_UDP: i32 = 17;
/// Raw IP.
pub const IPPROTO_RAW: i32 = 255;
/// ICMPv6.
pub const IPPROTO_ICMPV6: i32 = 58;

// ---------------------------------------------------------------------------
// SocketType — decoded socket type
// ---------------------------------------------------------------------------

/// Decoded socket type (base type without flags).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SocketType {
    /// Connection-oriented stream.
    Stream,
    /// Connectionless datagram.
    Dgram,
    /// Raw socket.
    Raw,
    /// Reliable datagram.
    Rdm,
    /// Sequenced-packet.
    SeqPacket,
}

impl SocketType {
    /// Parse the base socket type from the `type` argument (strips flags).
    ///
    /// # Errors
    ///
    /// [`Error::InvalidArgument`] for unrecognised type values.
    pub fn from_raw(raw: i32) -> Result<Self> {
        match raw & !SOCK_FLAGS_MASK {
            SOCK_STREAM => Ok(Self::Stream),
            SOCK_DGRAM => Ok(Self::Dgram),
            SOCK_RAW => Ok(Self::Raw),
            SOCK_RDM => Ok(Self::Rdm),
            SOCK_SEQPACKET => Ok(Self::SeqPacket),
            _ => Err(Error::InvalidArgument),
        }
    }

    /// Return the raw integer value (without flags).
    pub const fn as_raw(self) -> i32 {
        match self {
            Self::Stream => SOCK_STREAM,
            Self::Dgram => SOCK_DGRAM,
            Self::Raw => SOCK_RAW,
            Self::Rdm => SOCK_RDM,
            Self::SeqPacket => SOCK_SEQPACKET,
        }
    }
}

// ---------------------------------------------------------------------------
// SocketDomain — validated address family
// ---------------------------------------------------------------------------

/// Validated socket domain (address family).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SocketDomain {
    Unix,
    Inet,
    Inet6,
    Netlink,
    Packet,
    Bluetooth,
    Vsock,
    Other(i32),
}

impl SocketDomain {
    /// Validate and categorise an `AF_*` value.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidArgument`] for `AF_UNSPEC` or values outside the
    /// recognised range.
    pub fn from_raw(raw: i32) -> Result<Self> {
        if raw <= AF_UNSPEC || raw > AF_MAX {
            return Err(Error::InvalidArgument);
        }
        Ok(match raw {
            AF_UNIX => Self::Unix,
            AF_INET => Self::Inet,
            AF_INET6 => Self::Inet6,
            AF_NETLINK => Self::Netlink,
            AF_PACKET => Self::Packet,
            AF_BLUETOOTH => Self::Bluetooth,
            AF_VSOCK => Self::Vsock,
            v => Self::Other(v),
        })
    }
}

// ---------------------------------------------------------------------------
// SocketCreateArgs — validated argument set
// ---------------------------------------------------------------------------

/// Validated arguments for a `socket(2)` call.
#[derive(Debug, Clone, Copy)]
pub struct SocketCreateArgs {
    /// Validated address family.
    pub domain: SocketDomain,
    /// Decoded socket type (without flags).
    pub sock_type: SocketType,
    /// Raw protocol number.
    pub protocol: i32,
    /// Whether to set `O_CLOEXEC` on the fd.
    pub cloexec: bool,
    /// Whether to set `O_NONBLOCK`.
    pub nonblock: bool,
}

// ---------------------------------------------------------------------------
// validate_socket — entry-point validation
// ---------------------------------------------------------------------------

/// Validate arguments to `socket(2)`.
///
/// # Arguments
///
/// * `domain`   — Address family (`AF_*`).
/// * `type_raw` — Socket type + flags (`SOCK_*`).
/// * `protocol` — Protocol number (0 = kernel default).
///
/// # Errors
///
/// * [`Error::InvalidArgument`] — unrecognised domain, type, or invalid
///   flag bits.
pub fn validate_socket(domain: i32, type_raw: i32, protocol: i32) -> Result<SocketCreateArgs> {
    let dom = SocketDomain::from_raw(domain)?;
    let sock_type = SocketType::from_raw(type_raw)?;

    // Check that no unknown flag bits are set above the type bits.
    let extra = type_raw & !SOCK_FLAGS_MASK & !0x0F;
    if extra != 0 {
        return Err(Error::InvalidArgument);
    }

    Ok(SocketCreateArgs {
        domain: dom,
        sock_type,
        protocol,
        cloexec: type_raw & SOCK_CLOEXEC != 0,
        nonblock: type_raw & SOCK_NONBLOCK != 0,
    })
}

// ---------------------------------------------------------------------------
// SocketDescriptor — kernel-side socket record
// ---------------------------------------------------------------------------

/// Kernel-side record for an open socket.
#[derive(Debug, Clone, Copy)]
pub struct SocketDescriptor {
    /// File descriptor number.
    pub fd: i32,
    /// Validated creation arguments.
    pub args: SocketCreateArgs,
    /// Whether the socket is currently connected.
    pub connected: bool,
    /// Whether the socket is bound to an address.
    pub bound: bool,
    /// Whether the socket is listening.
    pub listening: bool,
}

impl SocketDescriptor {
    /// Create a new socket descriptor.
    pub const fn new(fd: i32, args: SocketCreateArgs) -> Self {
        Self {
            fd,
            args,
            connected: false,
            bound: false,
            listening: false,
        }
    }
}

// ---------------------------------------------------------------------------
// SocketTable — open socket tracking
// ---------------------------------------------------------------------------

/// Maximum tracked open sockets.
const MAX_SOCKETS: usize = 256;

/// Table of open sockets in the process.
pub struct SocketTable {
    sockets: [Option<SocketDescriptor>; MAX_SOCKETS],
    next_fd: i32,
}

impl SocketTable {
    /// Create an empty socket table.
    pub const fn new() -> Self {
        Self {
            sockets: [const { None }; MAX_SOCKETS],
            next_fd: 3,
        }
    }

    /// Allocate a new socket and return its file descriptor.
    pub fn allocate(&mut self, args: SocketCreateArgs) -> Result<i32> {
        let slot = self
            .sockets
            .iter()
            .position(|s| s.is_none())
            .ok_or(Error::OutOfMemory)?;
        let fd = self.next_fd;
        self.next_fd = self.next_fd.saturating_add(1);
        self.sockets[slot] = Some(SocketDescriptor::new(fd, args));
        Ok(fd)
    }

    /// Look up a socket by fd.
    pub fn get(&self, fd: i32) -> Option<&SocketDescriptor> {
        self.sockets
            .iter()
            .filter_map(|s| s.as_ref())
            .find(|s| s.fd == fd)
    }

    /// Look up a socket mutably by fd.
    pub fn get_mut(&mut self, fd: i32) -> Option<&mut SocketDescriptor> {
        self.sockets
            .iter_mut()
            .filter_map(|s| s.as_mut())
            .find(|s| s.fd == fd)
    }

    /// Close (remove) a socket by fd.
    pub fn close(&mut self, fd: i32) -> bool {
        for slot in &mut self.sockets {
            if slot.as_ref().map(|s| s.fd) == Some(fd) {
                *slot = None;
                return true;
            }
        }
        false
    }
}

impl Default for SocketTable {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// sys_socket — entry point
// ---------------------------------------------------------------------------

/// Handler for `socket(2)`.
///
/// Validates arguments and allocates a new socket file descriptor.
///
/// # Arguments
///
/// * `table`    — Socket table for the process.
/// * `domain`   — Address family (`AF_*`).
/// * `type_raw` — Socket type + optional flags.
/// * `protocol` — Protocol (0 = default for the domain/type).
///
/// # Returns
///
/// The new file descriptor on success.
///
/// # Errors
///
/// * [`Error::InvalidArgument`] — bad domain, type, or protocol.
/// * [`Error::OutOfMemory`]     — socket table full.
pub fn sys_socket(
    table: &mut SocketTable,
    domain: i32,
    type_raw: i32,
    protocol: i32,
) -> Result<i32> {
    let args = validate_socket(domain, type_raw, protocol)?;
    table.allocate(args)
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_tcp_socket() {
        let mut t = SocketTable::new();
        let fd = sys_socket(&mut t, AF_INET, SOCK_STREAM, IPPROTO_TCP).unwrap();
        assert!(fd >= 0);
        let sock = t.get(fd).unwrap();
        assert_eq!(sock.args.sock_type.as_raw(), SOCK_STREAM);
    }

    #[test]
    fn create_udp_socket_nonblock() {
        let mut t = SocketTable::new();
        let fd = sys_socket(&mut t, AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, IPPROTO_UDP).unwrap();
        let sock = t.get(fd).unwrap();
        assert!(sock.args.nonblock);
        assert!(!sock.args.cloexec);
    }

    #[test]
    fn cloexec_flag() {
        let mut t = SocketTable::new();
        let fd = sys_socket(&mut t, AF_INET6, SOCK_STREAM | SOCK_CLOEXEC, 0).unwrap();
        assert!(t.get(fd).unwrap().args.cloexec);
    }

    #[test]
    fn af_unspec_rejected() {
        let mut t = SocketTable::new();
        assert_eq!(
            sys_socket(&mut t, AF_UNSPEC, SOCK_STREAM, 0),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn bad_type_rejected() {
        let mut t = SocketTable::new();
        assert_eq!(
            sys_socket(&mut t, AF_INET, 99, 0),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn unix_dgram() {
        let mut t = SocketTable::new();
        let fd = sys_socket(&mut t, AF_UNIX, SOCK_DGRAM, 0).unwrap();
        let sock = t.get(fd).unwrap();
        assert!(matches!(sock.args.domain, SocketDomain::Unix));
    }

    #[test]
    fn close_socket() {
        let mut t = SocketTable::new();
        let fd = sys_socket(&mut t, AF_INET, SOCK_STREAM, 0).unwrap();
        assert!(t.close(fd));
        assert!(t.get(fd).is_none());
    }

    #[test]
    fn multiple_sockets_unique_fds() {
        let mut t = SocketTable::new();
        let fd1 = sys_socket(&mut t, AF_INET, SOCK_STREAM, 0).unwrap();
        let fd2 = sys_socket(&mut t, AF_INET, SOCK_DGRAM, 0).unwrap();
        assert_ne!(fd1, fd2);
    }
}
