// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `socket(2)` and `socketpair(2)` syscall handlers.
//!
//! `socket` creates a communication endpoint (a socket) and returns a file
//! descriptor referring to it.  `socketpair` creates a pair of connected
//! sockets and returns two file descriptors, one for each end of the pair.
//!
//! # POSIX Conformance
//!
//! Follows POSIX.1-2024 `socket()` and `socketpair()` specifications.
//! `SOCK_NONBLOCK` and `SOCK_CLOEXEC` flag extensions follow Linux semantics.
//!
//! Key behaviours:
//! - `domain` selects the communication domain (address family).
//! - `type` selects the communication semantics (stream, datagram, etc.)
//!   and optionally ORs in `SOCK_NONBLOCK` / `SOCK_CLOEXEC`.
//! - `protocol` selects the specific protocol within the domain; `0` means
//!   the system chooses the default protocol for the given domain and type.
//! - `socketpair` requires a domain that supports it (typically `AF_UNIX`).
//!
//! # References
//!
//! - POSIX.1-2024: `socket()`, `socketpair()`
//! - Linux man pages: `socket(2)`, `socketpair(2)`
//! - Linux source: `net/socket.c` (`__sys_socket`, `__sys_socketpair`)

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Address family constants
// ---------------------------------------------------------------------------

/// Unspecified address family.
pub const AF_UNSPEC: i32 = 0;
/// Local (Unix domain) sockets.  Same as [`AF_LOCAL`].
pub const AF_UNIX: i32 = 1;
/// Alias for [`AF_UNIX`].
pub const AF_LOCAL: i32 = 1;
/// IPv4 Internet protocols.
pub const AF_INET: i32 = 2;
/// IPv6 Internet protocols.
pub const AF_INET6: i32 = 10;
/// Netlink socket for kernel/userspace messaging.
pub const AF_NETLINK: i32 = 16;
/// Low-level packet interface (raw Ethernet).
pub const AF_PACKET: i32 = 17;
/// Bluetooth sockets.
pub const AF_BLUETOOTH: i32 = 31;
/// Kernel-user interface device protocol.
pub const AF_ALG: i32 = 38;
/// Vsock (virtual machine sockets).
pub const AF_VSOCK: i32 = 40;

// ---------------------------------------------------------------------------
// Socket type constants
// ---------------------------------------------------------------------------

/// Stream socket: sequenced, reliable, two-way byte streams.
pub const SOCK_STREAM: i32 = 1;
/// Datagram socket: connectionless, unreliable datagrams.
pub const SOCK_DGRAM: i32 = 2;
/// Raw socket: raw network protocol access.
pub const SOCK_RAW: i32 = 3;
/// Reliably-delivered message socket (RDM).
pub const SOCK_RDM: i32 = 4;
/// Sequential packet socket: sequenced, reliable, connection-based datagrams.
pub const SOCK_SEQPACKET: i32 = 5;
/// Set non-blocking mode on the new socket.
pub const SOCK_NONBLOCK: i32 = 0x800;
/// Set close-on-exec on the new socket.
pub const SOCK_CLOEXEC: i32 = 0x80000;

/// Mask to extract the base socket type from a combined type+flags value.
pub const SOCK_TYPE_MASK: i32 = 0xF;

// ---------------------------------------------------------------------------
// Protocol constants
// ---------------------------------------------------------------------------

/// Default protocol: let the kernel choose.
pub const IPPROTO_DEFAULT: i32 = 0;
/// Internet Control Message Protocol.
pub const IPPROTO_ICMP: i32 = 1;
/// Transmission Control Protocol.
pub const IPPROTO_TCP: i32 = 6;
/// User Datagram Protocol.
pub const IPPROTO_UDP: i32 = 17;
/// Internet Control Message Protocol for IPv6.
pub const IPPROTO_ICMPV6: i32 = 58;
/// Raw IP.
pub const IPPROTO_RAW: i32 = 255;

// ---------------------------------------------------------------------------
// Socket descriptor representation
// ---------------------------------------------------------------------------

/// Properties of a newly created socket.
///
/// In the real kernel, this would be backed by a `struct socket` object
/// and an inode in the socket filesystem.  Here we represent it as a
/// lightweight record of the socket's configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SocketDescriptor {
    /// The address family / communication domain.
    pub domain: i32,
    /// Base socket type (without flag bits).
    pub sock_type: i32,
    /// Protocol number (0 = auto-selected).
    pub protocol: i32,
    /// Whether `O_NONBLOCK` is set.
    pub nonblocking: bool,
    /// Whether `O_CLOEXEC` (`FD_CLOEXEC`) is set.
    pub cloexec: bool,
    /// Assigned file descriptor number.
    pub fd: i32,
}

/// A pair of socket descriptors as returned by `socketpair(2)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SocketPairDescriptor {
    /// First socket of the pair.
    pub socket0: SocketDescriptor,
    /// Second socket of the pair.
    pub socket1: SocketDescriptor,
}

// ---------------------------------------------------------------------------
// Socket file descriptor table
// ---------------------------------------------------------------------------

/// Maximum number of simultaneously open file descriptors per process.
const MAX_OPEN_FDS: usize = 1024;

/// Slot type in the socket fd table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SocketFdSlot {
    Empty,
    Socket(SocketDescriptor),
}

impl SocketFdSlot {
    fn is_open(self) -> bool {
        !matches!(self, SocketFdSlot::Empty)
    }
}

/// Per-process file descriptor table for socket allocation.
pub struct SocketFdTable {
    slots: [SocketFdSlot; MAX_OPEN_FDS],
    open_count: usize,
}

impl SocketFdTable {
    /// Create an empty socket file descriptor table.
    pub const fn new() -> Self {
        Self {
            slots: [SocketFdSlot::Empty; MAX_OPEN_FDS],
            open_count: 0,
        }
    }

    /// Allocate the lowest-numbered free slot and install `desc`.
    ///
    /// Returns the assigned fd number, or `Err(OutOfMemory)` if the table
    /// is full (`EMFILE`).
    pub fn alloc(&mut self, desc: SocketDescriptor) -> Result<usize> {
        let idx = self
            .slots
            .iter()
            .position(|s| !s.is_open())
            .ok_or(Error::OutOfMemory)?;
        self.slots[idx] = SocketFdSlot::Socket(desc);
        self.open_count += 1;
        Ok(idx)
    }

    /// Look up a socket descriptor by fd number.
    ///
    /// Returns `None` if the fd is out of range or the slot is empty.
    pub fn get(&self, fd: usize) -> Option<SocketDescriptor> {
        if fd >= MAX_OPEN_FDS {
            return None;
        }
        match self.slots[fd] {
            SocketFdSlot::Socket(desc) => Some(desc),
            SocketFdSlot::Empty => None,
        }
    }

    /// Close (free) a socket file descriptor.
    ///
    /// Returns `Err(NotFound)` if the fd is not open.
    pub fn close(&mut self, fd: usize) -> Result<()> {
        if fd >= MAX_OPEN_FDS || !self.slots[fd].is_open() {
            return Err(Error::NotFound);
        }
        self.slots[fd] = SocketFdSlot::Empty;
        self.open_count -= 1;
        Ok(())
    }

    /// Return the number of open socket file descriptors.
    pub const fn open_count(&self) -> usize {
        self.open_count
    }
}

// ---------------------------------------------------------------------------
// Validation helpers
// ---------------------------------------------------------------------------

/// Validate that `domain` is a known address family.
pub fn validate_domain(domain: i32) -> Result<()> {
    match domain {
        AF_UNSPEC | AF_UNIX | AF_INET | AF_INET6 | AF_NETLINK | AF_PACKET | AF_BLUETOOTH
        | AF_ALG | AF_VSOCK => Ok(()),
        _ => Err(Error::InvalidArgument),
    }
}

/// Validate a base socket type (after stripping flag bits).
pub fn validate_base_type(base_type: i32) -> Result<()> {
    match base_type {
        SOCK_STREAM | SOCK_DGRAM | SOCK_RAW | SOCK_RDM | SOCK_SEQPACKET => Ok(()),
        _ => Err(Error::InvalidArgument),
    }
}

/// Validate the `type` argument of `socket(2)` / `socketpair(2)`.
///
/// The `type` argument encodes the base socket type in the low nibble plus
/// optional `SOCK_NONBLOCK` and `SOCK_CLOEXEC` flags in higher bits.
pub fn validate_socket_type(sock_type: i32) -> Result<()> {
    let base = sock_type & SOCK_TYPE_MASK;
    validate_base_type(base)?;
    let flags = sock_type & !SOCK_TYPE_MASK;
    if flags & !(SOCK_NONBLOCK | SOCK_CLOEXEC) != 0 {
        return Err(Error::InvalidArgument);
    }
    Ok(())
}

/// Validate a protocol number for the given domain and type combination.
///
/// Returns `Err(InvalidArgument)` only for combinations that are known to be
/// invalid.  Unknown (domain, type, protocol) tuples are passed through so
/// that future protocol families can be added without changing validation.
pub fn validate_protocol(domain: i32, base_type: i32, protocol: i32) -> Result<()> {
    // Protocol 0 is always valid: kernel selects the default.
    if protocol == IPPROTO_DEFAULT {
        return Ok(());
    }

    // RAW sockets can carry any numeric protocol.
    if base_type == SOCK_RAW {
        if protocol < 0 || protocol > 255 {
            return Err(Error::InvalidArgument);
        }
        return Ok(());
    }

    // For well-known families, enforce sensible protocol mappings.
    match domain {
        AF_INET | AF_INET6 => match base_type {
            SOCK_STREAM => {
                if protocol != IPPROTO_TCP {
                    return Err(Error::InvalidArgument);
                }
            }
            SOCK_DGRAM => {
                if protocol != IPPROTO_UDP {
                    return Err(Error::InvalidArgument);
                }
            }
            _ => {}
        },
        // Unix/Netlink/etc. accept protocol 0 only (already handled above).
        AF_UNIX => {
            if protocol != 0 {
                return Err(Error::InvalidArgument);
            }
        }
        _ => {}
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Core handlers
// ---------------------------------------------------------------------------

/// Handler for `socket(2)`.
///
/// Creates a new socket and allocates a file descriptor for it.  The new
/// descriptor is the lowest-numbered free slot in `table`.
///
/// # Arguments
///
/// * `table`    — Per-process socket file descriptor table.
/// * `domain`   — Address family (e.g., `AF_INET`, `AF_UNIX`).
/// * `sock_type` — Socket type, optionally ORed with `SOCK_NONBLOCK` / `SOCK_CLOEXEC`.
/// * `protocol` — Protocol number (0 = auto-select).
///
/// # Errors
///
/// - `Error::InvalidArgument` — unknown domain, type, or protocol (`EINVAL`).
/// - `Error::OutOfMemory` — no free fd slots remain (`EMFILE`).
///
/// # POSIX conformance
///
/// - An unsupported `domain` returns `EAFNOSUPPORT` (mapped to
///   `InvalidArgument`).
/// - An invalid `type` returns `EINVAL`.
/// - An unsupported protocol returns `EPROTONOSUPPORT` (mapped to
///   `InvalidArgument`).
pub fn do_socket(
    table: &mut SocketFdTable,
    domain: i32,
    sock_type: i32,
    protocol: i32,
) -> Result<SocketDescriptor> {
    validate_domain(domain)?;
    validate_socket_type(sock_type)?;

    let base_type = sock_type & SOCK_TYPE_MASK;
    validate_protocol(domain, base_type, protocol)?;

    let nonblocking = sock_type & SOCK_NONBLOCK != 0;
    let cloexec = sock_type & SOCK_CLOEXEC != 0;

    let mut desc = SocketDescriptor {
        domain,
        sock_type: base_type,
        protocol,
        nonblocking,
        cloexec,
        fd: 0,
    };

    let fd = table.alloc(desc)?;
    desc.fd = fd as i32;

    // Update stored descriptor with assigned fd.
    table.slots[fd] = SocketFdSlot::Socket(desc);

    Ok(desc)
}

/// Handler for `socketpair(2)`.
///
/// Creates a pair of connected sockets in the same domain.  Both descriptors
/// are allocated from `table`.
///
/// # Arguments
///
/// * `table`    — Per-process socket file descriptor table.
/// * `domain`   — Address family; typically `AF_UNIX` for local pairs.
/// * `sock_type` — Socket type, optionally ORed with `SOCK_NONBLOCK` / `SOCK_CLOEXEC`.
/// * `protocol` — Protocol number (0 = auto-select; usually the only valid value).
///
/// # Errors
///
/// - `Error::InvalidArgument` — unknown domain/type/protocol, or `domain`
///   does not support `socketpair` (`EOPNOTSUPP` mapped to `InvalidArgument`).
/// - `Error::OutOfMemory` — insufficient free fd slots (`EMFILE`).
///
/// # POSIX conformance
///
/// POSIX requires `domain`, `type`, and `protocol` to be validated the same
/// way as `socket(2)`.  The `domain` must support connected-pair semantics.
/// Only `AF_UNIX` (and a small number of other local domains) typically
/// support `socketpair`; address families that require external routing
/// (e.g., `AF_INET`, `AF_INET6`) do not support `socketpair`.
pub fn do_socketpair(
    table: &mut SocketFdTable,
    domain: i32,
    sock_type: i32,
    protocol: i32,
) -> Result<SocketPairDescriptor> {
    validate_domain(domain)?;
    validate_socket_type(sock_type)?;

    let base_type = sock_type & SOCK_TYPE_MASK;
    validate_protocol(domain, base_type, protocol)?;

    // Only local/Unix-style domains support socketpair.
    match domain {
        AF_UNIX => {}
        _ => return Err(Error::InvalidArgument), // EOPNOTSUPP
    }

    let nonblocking = sock_type & SOCK_NONBLOCK != 0;
    let cloexec = sock_type & SOCK_CLOEXEC != 0;

    let mut desc0 = SocketDescriptor {
        domain,
        sock_type: base_type,
        protocol,
        nonblocking,
        cloexec,
        fd: 0,
    };
    let mut desc1 = desc0;

    let fd0 = table.alloc(desc0)?;
    desc0.fd = fd0 as i32;
    table.slots[fd0] = SocketFdSlot::Socket(desc0);

    let fd1 = table.alloc(desc1)?;
    desc1.fd = fd1 as i32;
    table.slots[fd1] = SocketFdSlot::Socket(desc1);

    Ok(SocketPairDescriptor {
        socket0: desc0,
        socket1: desc1,
    })
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn fresh() -> SocketFdTable {
        SocketFdTable::new()
    }

    // --- validate_domain ---

    #[test]
    fn validate_domain_accepts_known_families() {
        assert!(validate_domain(AF_INET).is_ok());
        assert!(validate_domain(AF_INET6).is_ok());
        assert!(validate_domain(AF_UNIX).is_ok());
        assert!(validate_domain(AF_NETLINK).is_ok());
    }

    #[test]
    fn validate_domain_rejects_unknown() {
        assert_eq!(validate_domain(999), Err(Error::InvalidArgument));
        assert_eq!(validate_domain(-1), Err(Error::InvalidArgument));
    }

    // --- validate_socket_type ---

    #[test]
    fn validate_socket_type_accepts_valid() {
        assert!(validate_socket_type(SOCK_STREAM).is_ok());
        assert!(validate_socket_type(SOCK_DGRAM).is_ok());
        assert!(validate_socket_type(SOCK_STREAM | SOCK_CLOEXEC).is_ok());
        assert!(validate_socket_type(SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC).is_ok());
    }

    #[test]
    fn validate_socket_type_rejects_unknown_base() {
        assert_eq!(validate_socket_type(7), Err(Error::InvalidArgument));
    }

    #[test]
    fn validate_socket_type_rejects_unknown_flags() {
        assert_eq!(
            validate_socket_type(SOCK_STREAM | 0x1000),
            Err(Error::InvalidArgument)
        );
    }

    // --- do_socket ---

    #[test]
    fn do_socket_creates_tcp_socket() {
        let mut t = fresh();
        let desc = do_socket(&mut t, AF_INET, SOCK_STREAM, IPPROTO_TCP).unwrap();
        assert_eq!(desc.domain, AF_INET);
        assert_eq!(desc.sock_type, SOCK_STREAM);
        assert_eq!(desc.protocol, IPPROTO_TCP);
        assert!(!desc.nonblocking);
        assert!(!desc.cloexec);
        assert_eq!(desc.fd, 0);
    }

    #[test]
    fn do_socket_with_cloexec_and_nonblock() {
        let mut t = fresh();
        let desc = do_socket(
            &mut t,
            AF_UNIX,
            SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK,
            0,
        )
        .unwrap();
        assert!(desc.cloexec);
        assert!(desc.nonblocking);
    }

    #[test]
    fn do_socket_rejects_invalid_domain() {
        let mut t = fresh();
        assert_eq!(
            do_socket(&mut t, 999, SOCK_STREAM, 0),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn do_socket_rejects_invalid_type() {
        let mut t = fresh();
        assert_eq!(
            do_socket(&mut t, AF_INET, 7, 0),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn do_socket_rejects_wrong_protocol() {
        let mut t = fresh();
        // TCP socket with UDP protocol is invalid.
        assert_eq!(
            do_socket(&mut t, AF_INET, SOCK_STREAM, IPPROTO_UDP),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn do_socket_assigns_incremental_fds() {
        let mut t = fresh();
        let d0 = do_socket(&mut t, AF_UNIX, SOCK_STREAM, 0).unwrap();
        let d1 = do_socket(&mut t, AF_UNIX, SOCK_DGRAM, 0).unwrap();
        assert_eq!(d0.fd, 0);
        assert_eq!(d1.fd, 1);
        assert_eq!(t.open_count(), 2);
    }

    // --- do_socketpair ---

    #[test]
    fn do_socketpair_creates_pair() {
        let mut t = fresh();
        let pair = do_socketpair(&mut t, AF_UNIX, SOCK_STREAM, 0).unwrap();
        assert_eq!(pair.socket0.domain, AF_UNIX);
        assert_eq!(pair.socket1.domain, AF_UNIX);
        assert_eq!(pair.socket0.fd, 0);
        assert_eq!(pair.socket1.fd, 1);
        assert_eq!(t.open_count(), 2);
    }

    #[test]
    fn do_socketpair_with_cloexec() {
        let mut t = fresh();
        let pair = do_socketpair(&mut t, AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0).unwrap();
        assert!(pair.socket0.cloexec);
        assert!(pair.socket1.cloexec);
    }

    #[test]
    fn do_socketpair_rejects_inet() {
        let mut t = fresh();
        // AF_INET does not support socketpair.
        assert_eq!(
            do_socketpair(&mut t, AF_INET, SOCK_STREAM, IPPROTO_TCP),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn do_socketpair_rejects_invalid_type() {
        let mut t = fresh();
        assert_eq!(
            do_socketpair(&mut t, AF_UNIX, 9, 0),
            Err(Error::InvalidArgument)
        );
    }

    // --- SocketFdTable ---

    #[test]
    fn fd_table_close_returns_not_found() {
        let mut t = fresh();
        assert_eq!(t.close(0), Err(Error::NotFound));
    }

    #[test]
    fn fd_table_get_after_close() {
        let mut t = fresh();
        do_socket(&mut t, AF_UNIX, SOCK_STREAM, 0).unwrap();
        t.close(0).unwrap();
        assert!(t.get(0).is_none());
        assert_eq!(t.open_count(), 0);
    }
}
